#!/usr/bin/env python3
import argparse
import base64
import contextlib
import concurrent.futures
import datetime as dt
import functools
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import shutil
import socket
import sqlite3
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

from flask import Flask, abort, flash, jsonify, redirect, render_template_string, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

VERSION = "2.0.0"
BASE = Path("/etc/iranlink")
DB_PATH = BASE / "iranlink.db"
SETTINGS_PATH = BASE / "settings.json"
AGENT_PATH = BASE / "agent.json"
PORTS_CACHE = BASE / "agent-ports.json"
PRIVATE_KEY = BASE / "private.key"
PUBLIC_KEY = BASE / "public.key"
WG_CONF = Path("/etc/wireguard/iranlink.conf")
WG_IF = "iranlink0"
PANEL_TUNNEL_IP = "10.88.0.1"
AGENT_PORT = 9700
TABLE_FILTER = "iranlink_filter"
TABLE_NAT = "iranlink_nat"
TABLE_AGENT = "iranlink_agent"
LOCK = threading.RLock()


def run(cmd, check=True, capture=True, input_text=None):
    kwargs = {
        "text": True,
        "check": check,
        "input": input_text,
    }
    if capture:
        kwargs.update({"stdout": subprocess.PIPE, "stderr": subprocess.PIPE})
    return subprocess.run(cmd, **kwargs)


def atomic_write(path: Path, data: str, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)


def load_json(path: Path, default=None):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return {} if default is None else default


def save_json(path: Path, value, mode=0o600):
    atomic_write(path, json.dumps(value, ensure_ascii=False, indent=2) + "\n", mode)


def valid_ip(value):
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def valid_port(value):
    try:
        n = int(value)
    except (TypeError, ValueError):
        return None
    return n if 1 <= n <= 65535 else None


def valid_wg_key(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9+/]{43}=", value):
        return False
    try:
        return len(base64.b64decode(value, validate=True)) == 32
    except Exception:
        return False


def detect_wan_if():
    result = run(["ip", "-4", "route", "show", "default"], capture=True)
    for line in result.stdout.splitlines():
        parts = line.split()
        if "dev" in parts:
            return parts[parts.index("dev") + 1]
    raise RuntimeError("کارت شبکه اینترنت پیدا نشد")


def detect_public_ip():
    for url in ("https://api.ipify.org", "https://ifconfig.me/ip"):
        try:
            with urllib.request.urlopen(url, timeout=6) as r:
                ip = r.read(100).decode().strip()
            if valid_ip(ip):
                return ip
        except Exception:
            pass
    result = run(["ip", "-4", "addr", "show", "scope", "global"], capture=True, check=False)
    for token in result.stdout.split():
        if "/" in token:
            ip = token.split("/", 1)[0]
            if valid_ip(ip):
                return ip
    return ""


def ensure_keys():
    BASE.mkdir(parents=True, exist_ok=True)
    if PRIVATE_KEY.exists() and PUBLIC_KEY.exists():
        return
    private = run(["wg", "genkey"]).stdout.strip()
    public = run(["wg", "pubkey"], input_text=private + "\n").stdout.strip()
    atomic_write(PRIVATE_KEY, private + "\n", 0o600)
    atomic_write(PUBLIC_KEY, public + "\n", 0o644)


def nft_apply(script: str):
    with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as f:
        f.write(script)
        name = f.name
    try:
        run(["nft", "-c", "-f", name])
        run(["nft", "-f", name])
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(name)


def nft_delete_table(family, name):
    run(["nft", "delete", "table", family, name], check=False)


def ufw_active():
    if not shutil.which("ufw"):
        return False
    r = run(["ufw", "status"], check=False)
    return "Status: active" in r.stdout


def ufw_add_panel_rules(wan_if, wg_port, panel_port):
    if not ufw_active():
        return
    run(["ufw", "allow", f"{wg_port}/udp", "comment", "IranLink-WG"], check=False)
    run(["ufw", "allow", f"{panel_port}/tcp", "comment", "IranLink-Panel"], check=False)
    run(["ufw", "route", "allow", "in", "on", wan_if, "out", "on", WG_IF], check=False)


def ufw_add_agent_rules():
    if not ufw_active():
        return
    run(["ufw", "allow", "in", "on", WG_IF, "from", PANEL_TUNNEL_IP, "comment", "IranLink-Agent"], check=False)


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    BASE.mkdir(parents=True, exist_ok=True)
    with db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS nodes (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              name TEXT NOT NULL,
              endpoint_ip TEXT,
              endpoint_port INTEGER NOT NULL DEFAULT 51820,
              tunnel_ip TEXT NOT NULL UNIQUE,
              public_key TEXT,
              agent_token TEXT,
              bootstrap_token TEXT NOT NULL UNIQUE,
              registered INTEGER NOT NULL DEFAULT 0,
              enabled INTEGER NOT NULL DEFAULT 1,
              last_seen INTEGER NOT NULL DEFAULT 0,
              created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS ports (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              node_id INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
              protocol TEXT NOT NULL CHECK(protocol IN ('tcp','udp')),
              public_port INTEGER NOT NULL,
              target_port INTEGER NOT NULL,
              enabled INTEGER NOT NULL DEFAULT 1,
              created_at INTEGER NOT NULL,
              UNIQUE(protocol, public_port)
            );
            """
        )


def panel_settings():
    value = load_json(SETTINGS_PATH)
    if value.get("role") != "iran":
        raise RuntimeError("این سرور به‌عنوان پنل ایران نصب نشده است")
    return value


def agent_settings():
    value = load_json(AGENT_PATH)
    if value.get("role") != "foreign":
        raise RuntimeError("این سرور به‌عنوان نود خارج نصب نشده است")
    return value


def allocate_tunnel_ip(conn):
    used = {row[0] for row in conn.execute("SELECT tunnel_ip FROM nodes")}
    for x in range(2, 255):
        candidate = f"10.88.0.{x}"
        if candidate not in used:
            return candidate
    raise RuntimeError("ظرفیت آدرس تونل پر شده است")


def render_panel_wg():
    settings = panel_settings()
    ensure_keys()
    lines = [
        "[Interface]",
        f"Address = {PANEL_TUNNEL_IP}/24",
        f"ListenPort = {settings['wg_port']}",
        f"PrivateKey = {PRIVATE_KEY.read_text().strip()}",
        f"MTU = {settings['mtu']}",
        "SaveConfig = false",
        "",
    ]
    with db() as conn:
        rows = conn.execute(
            "SELECT * FROM nodes WHERE enabled=1 AND registered=1 ORDER BY id"
        ).fetchall()
    for node in rows:
        lines.extend(
            [
                "[Peer]",
                f"# {node['name']}",
                f"PublicKey = {node['public_key']}",
                f"AllowedIPs = {node['tunnel_ip']}/32",
                f"Endpoint = {node['endpoint_ip']}:{node['endpoint_port']}",
                "PersistentKeepalive = 25",
                "",
            ]
        )
    atomic_write(WG_CONF, "\n".join(lines), 0o600)


def sync_wg():
    render_panel_wg()
    if run(["ip", "link", "show", WG_IF], check=False).returncode != 0:
        run(["systemctl", "restart", f"wg-quick@{WG_IF}.service"])
        return
    stripped = run(["wg-quick", "strip", str(WG_CONF)]).stdout
    with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as f:
        f.write(stripped)
        name = f.name
    try:
        run(["wg", "syncconf", WG_IF, name])
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(name)


def panel_rules_script():
    settings = panel_settings()
    wan = settings["wan_if"]
    wg_port = int(settings["wg_port"])
    panel_port = int(settings["panel_port"])
    with db() as conn:
        rows = conn.execute(
            """
            SELECT p.*, n.tunnel_ip
            FROM ports p JOIN nodes n ON n.id=p.node_id
            WHERE p.enabled=1 AND n.enabled=1 AND n.registered=1
            ORDER BY p.id
            """
        ).fetchall()
    filter_rules = []
    nat_pre = []
    nat_post = []
    for p in rows:
        proto = p["protocol"]
        ip = p["tunnel_ip"]
        public_port = p["public_port"]
        target_port = p["target_port"]
        filter_rules.append(
            f'    iifname "{wan}" oifname "{WG_IF}" ip daddr {ip} {proto} dport {target_port} accept'
        )
        nat_pre.append(
            f'    iifname "{wan}" {proto} dport {public_port} dnat to {ip}:{target_port}'
        )
        nat_post.append(
            f'    oifname "{WG_IF}" ip daddr {ip} {proto} dport {target_port} masquerade'
        )
    return f"""
flush table inet {TABLE_FILTER}
flush table ip {TABLE_NAT}
table inet {TABLE_FILTER} {{
  chain input_guard {{
    type filter hook input priority -50; policy accept;
    ct state invalid drop
    iifname \"{wan}\" udp dport {wg_port} accept
    iifname \"{wan}\" tcp dport {panel_port} accept
  }}
  chain forward_guard {{
    type filter hook forward priority -50; policy accept;
    ct state invalid drop
    ct state established,related accept
{os.linesep.join(filter_rules)}
    iifname \"{wan}\" oifname \"{WG_IF}\" drop
    iifname \"{WG_IF}\" oifname \"{wan}\" ct state established,related accept
  }}
}}
table ip {TABLE_NAT} {{
  chain prerouting {{
    type nat hook prerouting priority dstnat; policy accept;
{os.linesep.join(nat_pre)}
  }}
  chain postrouting {{
    type nat hook postrouting priority srcnat; policy accept;
{os.linesep.join(nat_post)}
  }}
}}
"""


def apply_panel_rules():
    with LOCK:
        nft_delete_table("inet", TABLE_FILTER)
        nft_delete_table("ip", TABLE_NAT)
        script = panel_rules_script().replace(f"flush table inet {TABLE_FILTER}\n", "").replace(
            f"flush table ip {TABLE_NAT}\n", ""
        )
        nft_apply(script)
        settings = panel_settings()
        ufw_add_panel_rules(settings["wan_if"], settings["wg_port"], settings["panel_port"])


def render_agent_wg(data):
    ensure_keys()
    content = f"""[Interface]
Address = {data['tunnel_ip']}/32
ListenPort = {data['foreign_wg_port']}
PrivateKey = {PRIVATE_KEY.read_text().strip()}
MTU = {data['mtu']}
SaveConfig = false

[Peer]
PublicKey = {data['panel_public_key']}
AllowedIPs = {PANEL_TUNNEL_IP}/32
Endpoint = {data['iran_ip']}:{data['iran_wg_port']}
PersistentKeepalive = 25
"""
    atomic_write(WG_CONF, content, 0o600)


def agent_rules_script(ports):
    settings = agent_settings()
    wan = settings["wan_if"]
    tcp = sorted({int(x) for x in ports.get("tcp", []) if valid_port(x)})
    udp = sorted({int(x) for x in ports.get("udp", []) if valid_port(x)})
    tcp_rule = f"    iifname \"{WG_IF}\" ip saddr {PANEL_TUNNEL_IP} tcp dport {{ {', '.join(map(str, tcp))} }} accept" if tcp else ""
    udp_rule = f"    iifname \"{WG_IF}\" ip saddr {PANEL_TUNNEL_IP} udp dport {{ {', '.join(map(str, udp))} }} accept" if udp else ""
    return f"""
table inet {TABLE_AGENT} {{
  set blocked_v4 {{
    type ipv4_addr
    flags interval
    elements = {{ 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8,
                 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24,
                 192.0.2.0/24, 192.168.0.0/16, 198.18.0.0/15,
                 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/4, 240.0.0.0/4 }}
  }}
  chain input_guard {{
    type filter hook input priority -60; policy accept;
    ct state invalid drop
    ct state established,related accept
    iifname \"{WG_IF}\" ip saddr {PANEL_TUNNEL_IP} tcp dport {AGENT_PORT} accept
{tcp_rule}
{udp_rule}
    iifname \"{WG_IF}\" drop
  }}
  chain output_guard {{
    type filter hook output priority -60; policy accept;
    oifname \"{wan}\" ip daddr @blocked_v4 drop
    oifname \"{wan}\" tcp dport 25 drop
    oifname \"{wan}\" ct state new tcp flags syn limit rate over 500/second burst 1000 packets drop
    oifname \"{wan}\" ct state new meta l4proto udp limit rate over 1200/second burst 2400 packets drop
  }}
}}
"""


def apply_agent_rules(ports=None):
    with LOCK:
        if ports is None:
            ports = load_json(PORTS_CACHE, {"tcp": [], "udp": []})
        clean = {
            "tcp": sorted({valid_port(x) for x in ports.get("tcp", []) if valid_port(x)}),
            "udp": sorted({valid_port(x) for x in ports.get("udp", []) if valid_port(x)}),
        }
        save_json(PORTS_CACHE, clean)
        nft_delete_table("inet", TABLE_AGENT)
        nft_apply(agent_rules_script(clean))
        ufw_add_agent_rules()


def api_call(url, token=None, method="GET", payload=None, timeout=5):
    headers = {"User-Agent": f"IranLink/{VERSION}"}
    body = None
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if payload is not None:
        body = json.dumps(payload).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def sync_node_ports(node_id):
    with db() as conn:
        node = conn.execute("SELECT * FROM nodes WHERE id=?", (node_id,)).fetchone()
        if not node or not node["registered"] or not node["agent_token"]:
            return False, "نود هنوز ثبت نشده است"
        rows = conn.execute(
            "SELECT protocol,target_port FROM ports WHERE node_id=? AND enabled=1", (node_id,)
        ).fetchall()
    payload = {"tcp": [], "udp": []}
    for row in rows:
        payload[row["protocol"]].append(row["target_port"])
    try:
        result = api_call(
            f"http://{node['tunnel_ip']}:{AGENT_PORT}/agent/apply",
            token=node["agent_token"],
            method="POST",
            payload=payload,
            timeout=6,
        )
        return bool(result.get("ok")), result.get("message", "")
    except Exception as exc:
        return False, str(exc)


def sync_all_ports():
    with db() as conn:
        ids = [r[0] for r in conn.execute("SELECT id FROM nodes WHERE registered=1 AND enabled=1")]
    for node_id in ids:
        sync_node_ports(node_id)


def node_status(node):
    if not node["registered"]:
        return "در انتظار نصب", False
    try:
        result = api_call(
            f"http://{node['tunnel_ip']}:{AGENT_PORT}/agent/status",
            token=node["agent_token"],
            timeout=2,
        )
        if result.get("ok"):
            with db() as conn:
                conn.execute("UPDATE nodes SET last_seen=? WHERE id=?", (int(time.time()), node["id"]))
            return "متصل", True
    except Exception:
        pass
    return "قطع", False


def create_panel_app():
    app = Flask(__name__)
    settings = panel_settings()
    app.secret_key = settings["session_secret"]
    app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")

    def csrf_token():
        token = session.get("csrf")
        if not token:
            token = secrets.token_urlsafe(24)
            session["csrf"] = token
        return token

    app.jinja_env.globals["csrf_token"] = csrf_token

    def login_required(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            if not session.get("logged_in"):
                return redirect(url_for("login"))
            return fn(*args, **kwargs)
        return wrapper

    @app.before_request
    def csrf_guard():
        if request.method == "POST" and request.endpoint not in {"bootstrap_complete", "agent_apply"}:
            if not hmac.compare_digest(request.form.get("csrf", ""), session.get("csrf", "!")):
                abort(400, "CSRF نامعتبر")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            if check_password_hash(settings["admin_password_hash"], request.form.get("password", "")):
                session.clear()
                session["logged_in"] = True
                csrf_token()
                return redirect(url_for("dashboard"))
            flash("رمز اشتباه است", "danger")
        return render_page("ورود", LOGIN_BODY, logged_in=False)

    @app.route("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.route("/")
    @login_required
    def dashboard():
        with db() as conn:
            nodes = conn.execute("SELECT * FROM nodes ORDER BY id DESC").fetchall()
            ports = conn.execute(
                "SELECT p.*,n.name AS node_name FROM ports p JOIN nodes n ON n.id=p.node_id ORDER BY p.id DESC"
            ).fetchall()
        enriched = []
        statuses = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, max(1, len(nodes)))) as pool:
            future_map = {pool.submit(node_status, n): n["id"] for n in nodes}
            for future, node_id in future_map.items():
                try:
                    statuses[node_id] = future.result(timeout=3)
                except Exception:
                    statuses[node_id] = ("قطع", False)
        for n in nodes:
            status, online = statuses.get(n["id"], ("قطع", False))
            command = (
                f"curl -fsSL https://raw.githubusercontent.com/golb4212-design/iranlink/main/install.sh "
                f"| sudo bash -s -- foreign --panel-url http://{settings['public_ip']}:{settings['panel_port']} "
                f"--bootstrap {n['bootstrap_token']}"
            )
            enriched.append({**dict(n), "status_text": status, "online": online, "command": command})
        return render_page(
            "مدیریت تونل پاسارگارد",
            DASHBOARD_BODY,
            nodes=enriched,
            ports=ports,
            settings=settings,
            public_key=PUBLIC_KEY.read_text().strip(),
        )

    @app.route("/nodes/add", methods=["POST"])
    @login_required
    def add_node():
        name = request.form.get("name", "").strip()[:80]
        endpoint_ip = valid_ip(request.form.get("endpoint_ip", "").strip())
        endpoint_port = 51820
        if not name or not endpoint_ip:
            flash("نام و IP نود خارج را درست وارد کن", "danger")
            return redirect(url_for("dashboard"))
        with db() as conn:
            tunnel_ip = allocate_tunnel_ip(conn)
            token = secrets.token_urlsafe(28)
            conn.execute(
                "INSERT INTO nodes(name,endpoint_ip,endpoint_port,tunnel_ip,bootstrap_token,created_at) VALUES(?,?,?,?,?,?)",
                (name, endpoint_ip, endpoint_port, tunnel_ip, token, int(time.time())),
            )
        flash("نود ساخته شد؛ دستور نصب نود را اجرا کن", "success")
        return redirect(url_for("dashboard"))

    @app.route("/nodes/<int:node_id>/edit", methods=["POST"])
    @login_required
    def edit_node(node_id):
        name = request.form.get("name", "").strip()[:80]
        endpoint_ip = valid_ip(request.form.get("endpoint_ip", "").strip())
        if not name or not endpoint_ip:
            flash("اطلاعات نود نامعتبر است", "danger")
            return redirect(url_for("dashboard"))
        with db() as conn:
            conn.execute(
                "UPDATE nodes SET name=?,endpoint_ip=? WHERE id=?",
                (name, endpoint_ip, node_id),
            )
        sync_wg()
        flash("اطلاعات نود و IP خارج بروزرسانی شد", "success")
        return redirect(url_for("dashboard"))

    @app.route("/nodes/<int:node_id>/delete", methods=["POST"])
    @login_required
    def delete_node(node_id):
        with db() as conn:
            conn.execute("DELETE FROM nodes WHERE id=?", (node_id,))
        sync_wg()
        apply_panel_rules()
        flash("نود حذف شد", "success")
        return redirect(url_for("dashboard"))

    @app.route("/nodes/<int:node_id>/sync", methods=["POST"])
    @login_required
    def sync_node(node_id):
        ok, message = sync_node_ports(node_id)
        flash("پورت‌ها با نود هماهنگ شدند" if ok else f"هماهنگ‌سازی ناموفق: {message}", "success" if ok else "danger")
        return redirect(url_for("dashboard"))

    @app.route("/ports/add", methods=["POST"])
    @login_required
    def add_port():
        node_id = request.form.get("node_id", type=int)
        protocol = request.form.get("protocol", "")
        public_port = valid_port(request.form.get("public_port"))
        target_port = valid_port(request.form.get("target_port"))
        if protocol not in {"tcp", "udp", "both"} or not node_id or not public_port or not target_port:
            flash("اطلاعات پورت نامعتبر است", "danger")
            return redirect(url_for("dashboard"))
        protocols = ["tcp", "udp"] if protocol == "both" else [protocol]
        try:
            with db() as conn:
                node = conn.execute("SELECT * FROM nodes WHERE id=?", (node_id,)).fetchone()
                if not node:
                    raise ValueError("نود پیدا نشد")
                for proto in protocols:
                    conn.execute(
                        "INSERT INTO ports(node_id,protocol,public_port,target_port,created_at) VALUES(?,?,?,?,?)",
                        (node_id, proto, public_port, target_port, int(time.time())),
                    )
        except sqlite3.IntegrityError:
            flash("این پورت ورودی برای همین پروتکل قبلاً استفاده شده", "danger")
            return redirect(url_for("dashboard"))
        apply_panel_rules()
        ok, message = sync_node_ports(node_id)
        flash("پورت اضافه شد" + (" و روی نود فعال شد" if ok else f"؛ نود فعلاً پاسخ نداد: {message}"), "success" if ok else "warning")
        return redirect(url_for("dashboard"))

    @app.route("/ports/<int:port_id>/delete", methods=["POST"])
    @login_required
    def delete_port(port_id):
        with db() as conn:
            row = conn.execute("SELECT node_id FROM ports WHERE id=?", (port_id,)).fetchone()
            if row:
                node_id = row["node_id"]
                conn.execute("DELETE FROM ports WHERE id=?", (port_id,))
            else:
                node_id = None
        apply_panel_rules()
        if node_id:
            sync_node_ports(node_id)
        flash("پورت حذف شد", "success")
        return redirect(url_for("dashboard"))

    @app.route("/settings", methods=["POST"])
    @login_required
    def update_settings():
        mtu = request.form.get("mtu", type=int)
        if not mtu or not 1280 <= mtu <= 1420:
            flash("MTU نامعتبر است", "danger")
            return redirect(url_for("dashboard"))
        settings["mtu"] = mtu
        save_json(SETTINGS_PATH, settings)
        render_panel_wg()
        run(["systemctl", "restart", f"wg-quick@{WG_IF}.service"], check=False)
        apply_panel_rules()
        flash("MTU ذخیره شد", "success")
        return redirect(url_for("dashboard"))

    @app.route("/api/bootstrap/<token>")
    def bootstrap_info(token):
        with db() as conn:
            node = conn.execute("SELECT * FROM nodes WHERE bootstrap_token=?", (token,)).fetchone()
        if not node or node["registered"]:
            return jsonify(ok=False, message="کد نصب نامعتبر یا استفاده‌شده است"), 404
        return jsonify(
            ok=True,
            iran_ip=settings["public_ip"],
            iran_wg_port=settings["wg_port"],
            panel_public_key=PUBLIC_KEY.read_text().strip(),
            tunnel_ip=node["tunnel_ip"],
            foreign_wg_port=node["endpoint_port"],
            mtu=settings["mtu"],
            agent_port=AGENT_PORT,
        )

    @app.route("/api/bootstrap/<token>/complete", methods=["POST"])
    def bootstrap_complete(token):
        data = request.get_json(silent=True) or {}
        public_key = data.get("public_key", "")
        agent_token = data.get("agent_token", "")
        endpoint_ip = valid_ip(data.get("endpoint_ip", ""))
        if not valid_wg_key(public_key) or len(agent_token) < 32 or not endpoint_ip:
            return jsonify(ok=False, message="اطلاعات ثبت نود نامعتبر است"), 400
        with db() as conn:
            node = conn.execute("SELECT * FROM nodes WHERE bootstrap_token=?", (token,)).fetchone()
            if not node or node["registered"]:
                return jsonify(ok=False, message="کد نصب نامعتبر یا استفاده‌شده است"), 404
            conn.execute(
                "UPDATE nodes SET public_key=?,agent_token=?,endpoint_ip=?,registered=1,last_seen=? WHERE id=?",
                (public_key, agent_token, endpoint_ip, int(time.time()), node["id"]),
            )
        sync_wg()
        apply_panel_rules()
        return jsonify(ok=True, message="نود با موفقیت ثبت شد")

    return app


def auth_agent():
    settings = agent_settings()
    header = request.headers.get("Authorization", "")
    expected = f"Bearer {settings['agent_token']}"
    if not hmac.compare_digest(header, expected):
        abort(401)
    return settings


def create_agent_app():
    app = Flask(__name__)

    @app.get("/agent/status")
    def agent_status():
        settings = auth_agent()
        handshake = 0
        r = run(["wg", "show", WG_IF, "latest-handshakes"], check=False)
        for line in r.stdout.splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[1].isdigit():
                handshake = max(handshake, int(parts[1]))
        return jsonify(
            ok=True,
            version=VERSION,
            tunnel_ip=settings["tunnel_ip"],
            handshake=handshake,
            ports=load_json(PORTS_CACHE, {"tcp": [], "udp": []}),
        )

    @app.post("/agent/apply")
    def agent_apply():
        auth_agent()
        data = request.get_json(silent=True) or {}
        apply_agent_rules(data)
        return jsonify(ok=True, message="پورت‌ها اعمال شدند")

    return app


BASE_HTML = r"""
<!doctype html><html lang="fa" dir="rtl"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{ title }} | IranLink</title>
<style>
:root{--bg:#09111f;--card:#111d31;--muted:#91a4be;--text:#eef5ff;--blue:#4a8dff;--green:#2ed39b;--red:#ff657a;--yellow:#f2bd55;--border:#21324c}*{box-sizing:border-box}body{margin:0;background:linear-gradient(145deg,#07101d,#0c1728);color:var(--text);font-family:Tahoma,Arial,sans-serif;min-height:100vh}.wrap{max-width:1180px;margin:auto;padding:22px}.top{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:18px}.brand{font-weight:800;font-size:22px}.sub{color:var(--muted);font-size:13px}.grid{display:grid;grid-template-columns:repeat(12,1fr);gap:15px}.card{grid-column:span 12;background:rgba(17,29,49,.96);border:1px solid var(--border);border-radius:18px;padding:18px;box-shadow:0 12px 35px #0003}.half{grid-column:span 6}.third{grid-column:span 4}@media(max-width:850px){.half,.third{grid-column:span 12}.top{align-items:flex-start;flex-direction:column}}h1,h2,h3{margin:0 0 12px}h2{font-size:18px}p{line-height:1.8}.row{display:flex;gap:10px;flex-wrap:wrap;align-items:end}.field{flex:1;min-width:145px}label{display:block;color:var(--muted);font-size:13px;margin-bottom:7px}input,select{width:100%;border:1px solid var(--border);border-radius:12px;background:#0b1525;color:var(--text);padding:12px;outline:none}input:focus,select:focus{border-color:var(--blue)}button,.btn{border:0;border-radius:12px;padding:11px 15px;color:white;background:var(--blue);cursor:pointer;text-decoration:none;display:inline-block;font-weight:700}.danger{background:var(--red)}.ghost{background:#263751}.green{background:var(--green);color:#06140f}.tag{display:inline-flex;border-radius:999px;padding:5px 9px;font-size:12px;background:#24344d;color:#c9d8ec}.online{background:#123b30;color:#70efc3}.offline{background:#442433;color:#ff9aab}.warning{background:#4b3a17;color:#ffd37a}.table{width:100%;border-collapse:collapse}.table th,.table td{text-align:right;padding:11px;border-bottom:1px solid var(--border);font-size:13px;vertical-align:top}.table th{color:var(--muted)}.code{direction:ltr;text-align:left;background:#07101d;border:1px solid var(--border);padding:12px;border-radius:12px;overflow:auto;white-space:pre-wrap;word-break:break-all;font-family:monospace;font-size:12px}.flash{padding:12px 14px;border-radius:12px;margin-bottom:12px;background:#17355d}.flash.danger{background:#522434}.flash.warning{background:#4b3a17}.stat{font-size:26px;font-weight:800}.muted{color:var(--muted)}.actions{display:flex;gap:7px;flex-wrap:wrap}.small{padding:8px 10px;font-size:12px}.login{max-width:420px;margin:12vh auto}.sep{height:1px;background:var(--border);margin:15px 0}.ltr{direction:ltr;text-align:left}
</style></head><body><div class="wrap">
<div class="top"><div><div class="brand">IranLink • Pasargad Nodes</div><div class="sub">مدیریت IP ایران، نودهای خارج و پورت‌ها</div></div>{% if logged_in %}<a class="btn ghost" href="{{ url_for('logout') }}">خروج</a>{% endif %}</div>
{% with messages=get_flashed_messages(with_categories=true) %}{% for category,message in messages %}<div class="flash {{ category }}">{{ message }}</div>{% endfor %}{% endwith %}
{{ body|safe }}
</div></body></html>
"""

LOGIN_BODY = r"""
<div class="card login"><h2>ورود به پنل</h2><form method="post"><input type="hidden" name="csrf" value="{{ csrf_token() }}"><div class="field"><label>رمز مدیریت</label><input type="password" name="password" autofocus required></div><br><button style="width:100%">ورود</button></form></div>
"""

DASHBOARD_BODY = r"""
<div class="grid">
<div class="card third"><div class="muted">IP قابل استفاده در کانفیگ‌ها</div><div class="stat ltr">{{ settings.public_ip }}</div></div>
<div class="card third"><div class="muted">تعداد نودها</div><div class="stat">{{ nodes|length }}</div></div>
<div class="card third"><div class="muted">تعداد نگاشت پورت</div><div class="stat">{{ ports|length }}</div></div>

<div class="card half"><h2>افزودن نود خارج</h2><p class="muted">برای هر نود پاسارگارد یک‌بار اضافه کن؛ بعد دستور نصب آماده نمایش داده می‌شود.</p><form method="post" action="{{ url_for('add_node') }}"><input type="hidden" name="csrf" value="{{ csrf_token() }}"><div class="row"><div class="field"><label>نام نود</label><input name="name" placeholder="Germany-1" required></div><div class="field"><label>IP سرور خارج</label><input class="ltr" name="endpoint_ip" placeholder="1.2.3.4" required></div><button>ساخت نود</button></div></form></div>

<div class="card half"><h2>افزودن پورت پاسارگارد</h2><form method="post" action="{{ url_for('add_port') }}"><input type="hidden" name="csrf" value="{{ csrf_token() }}"><div class="row"><div class="field"><label>نود مقصد</label><select name="node_id" required><option value="">انتخاب</option>{% for n in nodes %}<option value="{{ n.id }}">{{ n.name }} — {{ n.tunnel_ip }}</option>{% endfor %}</select></div><div class="field"><label>نوع</label><select name="protocol"><option value="tcp">TCP</option><option value="udp">UDP</option><option value="both">TCP + UDP</option></select></div><div class="field"><label>پورت روی IP ایران</label><input name="public_port" placeholder="443" required></div><div class="field"><label>پورت نود خارج</label><input name="target_port" placeholder="443" required></div><button class="green">افزودن</button></div></form></div>

<div class="card"><h2>نودهای خارج</h2>{% if nodes %}<div style="overflow:auto"><table class="table"><tr><th>نود</th><th>وضعیت</th><th>IP خارج</th><th>IP تونل</th><th>دستور نصب</th><th>عملیات</th></tr>{% for n in nodes %}<tr><td><b>{{ n.name }}</b></td><td><span class="tag {{ 'online' if n.online else ('warning' if not n.registered else 'offline') }}">{{ n.status_text }}</span></td><td class="ltr">{{ n.endpoint_ip }}:{{ n.endpoint_port }}</td><td class="ltr">{{ n.tunnel_ip }}</td><td>{% if not n.registered %}<div class="code">{{ n.command }}</div>{% else %}<span class="tag online">نصب شده</span>{% endif %}</td><td><div class="actions"><form method="post" action="{{ url_for('sync_node',node_id=n.id) }}"><input type="hidden" name="csrf" value="{{ csrf_token() }}"><button class="small ghost">همگام‌سازی</button></form><details><summary class="btn small ghost">ویرایش IP</summary><form method="post" action="{{ url_for('edit_node',node_id=n.id) }}" style="margin-top:8px;min-width:250px"><input type="hidden" name="csrf" value="{{ csrf_token() }}"><input name="name" value="{{ n.name }}"><br><br><input class="ltr" name="endpoint_ip" value="{{ n.endpoint_ip }}"><br><br><button class="small">ذخیره</button></form></details><form method="post" action="{{ url_for('delete_node',node_id=n.id) }}" onsubmit="return confirm('نود حذف شود؟')"><input type="hidden" name="csrf" value="{{ csrf_token() }}"><button class="small danger">حذف</button></form></div></td></tr>{% endfor %}</table></div>{% else %}<p class="muted">هنوز نودی ساخته نشده.</p>{% endif %}</div>

<div class="card"><h2>پورت‌های فعال</h2>{% if ports %}<div style="overflow:auto"><table class="table"><tr><th>IP ایران</th><th>پروتکل</th><th>پورت ایران</th><th>نود خارج</th><th>پورت مقصد</th><th></th></tr>{% for p in ports %}<tr><td class="ltr">{{ settings.public_ip }}</td><td><span class="tag">{{ p.protocol|upper }}</span></td><td>{{ p.public_port }}</td><td>{{ p.node_name }}</td><td>{{ p.target_port }}</td><td><form method="post" action="{{ url_for('delete_port',port_id=p.id) }}"><input type="hidden" name="csrf" value="{{ csrf_token() }}"><button class="small danger">حذف</button></form></td></tr>{% endfor %}</table></div>{% else %}<p class="muted">هیچ پورتی تعریف نشده.</p>{% endif %}</div>

<div class="card half"><h2>تنظیمات تونل</h2><form method="post" action="{{ url_for('update_settings') }}"><input type="hidden" name="csrf" value="{{ csrf_token() }}"><div class="row"><div class="field"><label>IP عمومی ایران</label><input class="ltr" value="{{ settings.public_ip }}" readonly></div><div class="field"><label>MTU</label><input name="mtu" value="{{ settings.mtu }}"></div><button>ذخیره MTU</button></div></form></div>
<div class="card half"><h2>اطلاعات تونل ایران</h2><div class="muted">WireGuard Public Key</div><div class="code">{{ public_key }}</div><p class="muted">در کانفیگ پاسارگارد فقط IP ایران و پورتی که اینجا تعریف کرده‌ای قرار می‌گیرد. SNI/Host و تنظیمات پروتکل نود تغییر نمی‌کند.</p></div>
</div>
"""


def render_page(title, body_template, logged_in=True, **ctx):
    body = render_template_string(body_template, **ctx)
    return render_template_string(BASE_HTML, title=title, body=body, logged_in=logged_in)


def init_panel(args):
    BASE.mkdir(parents=True, exist_ok=True)
    ensure_keys()
    wan = detect_wan_if()
    public_ip = valid_ip(args.public_ip) or detect_public_ip()
    if not public_ip:
        raise SystemExit("IP عمومی ایران تشخیص داده نشد")
    settings = {
        "role": "iran",
        "public_ip": public_ip,
        "wan_if": wan,
        "wg_port": args.wg_port,
        "panel_port": args.panel_port,
        "mtu": args.mtu,
        "admin_password_hash": generate_password_hash(args.admin_password),
        "session_secret": secrets.token_hex(32),
    }
    save_json(SETTINGS_PATH, settings)
    init_db()
    render_panel_wg()
    print(json.dumps({"ok": True, "public_ip": public_ip, "public_key": PUBLIC_KEY.read_text().strip()}, ensure_ascii=False))


def init_agent(args):
    ensure_keys()
    info = api_call(f"{args.panel_url.rstrip('/')}/api/bootstrap/{args.bootstrap}", timeout=12)
    if not info.get("ok"):
        raise SystemExit(info.get("message", "کد نصب نامعتبر است"))
    public_ip = detect_public_ip()
    if not public_ip:
        raise SystemExit("IP عمومی سرور خارج تشخیص داده نشد")
    token = secrets.token_urlsafe(40)
    data = {
        "role": "foreign",
        "panel_url": args.panel_url.rstrip("/"),
        "bootstrap": args.bootstrap,
        "iran_ip": info["iran_ip"],
        "iran_wg_port": int(info["iran_wg_port"]),
        "panel_public_key": info["panel_public_key"],
        "tunnel_ip": info["tunnel_ip"],
        "foreign_wg_port": int(info["foreign_wg_port"]),
        "mtu": int(info["mtu"]),
        "agent_token": token,
        "agent_port": AGENT_PORT,
        "wan_if": detect_wan_if(),
        "public_ip": public_ip,
    }
    save_json(AGENT_PATH, data)
    save_json(PORTS_CACHE, {"tcp": [], "udp": []})
    render_agent_wg(data)
    payload = {
        "public_key": PUBLIC_KEY.read_text().strip(),
        "agent_token": token,
        "endpoint_ip": public_ip,
    }
    result = api_call(
        f"{args.panel_url.rstrip('/')}/api/bootstrap/{args.bootstrap}/complete",
        method="POST",
        payload=payload,
        timeout=15,
    )
    if not result.get("ok"):
        raise SystemExit(result.get("message", "ثبت نود ناموفق بود"))
    print(json.dumps({"ok": True, "tunnel_ip": data["tunnel_ip"], "public_ip": public_ip}, ensure_ascii=False))


def cli():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("init-panel")
    p.add_argument("--public-ip", default="")
    p.add_argument("--wg-port", type=int, default=51820)
    p.add_argument("--panel-port", type=int, default=8088)
    p.add_argument("--mtu", type=int, default=1380)
    p.add_argument("--admin-password", required=True)
    a = sub.add_parser("init-agent")
    a.add_argument("--panel-url", required=True)
    a.add_argument("--bootstrap", required=True)
    sub.add_parser("apply-panel")
    sub.add_parser("apply-agent")
    args = parser.parse_args()
    if args.cmd == "init-panel":
        init_panel(args)
    elif args.cmd == "init-agent":
        init_agent(args)
    elif args.cmd == "apply-panel":
        init_db(); apply_panel_rules(); sync_all_ports()
    elif args.cmd == "apply-agent":
        apply_agent_rules()


MODE = os.environ.get("IRANLINK_MODE", "")
if MODE == "panel":
    app = create_panel_app()
elif MODE == "agent":
    app = create_agent_app()
else:
    app = Flask(__name__)

if __name__ == "__main__":
    cli()
