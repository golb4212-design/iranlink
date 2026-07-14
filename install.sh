#!/usr/bin/env bash
set -Eeuo pipefail

REPO_RAW="https://raw.githubusercontent.com/golb4212-design/iranlink/main"
APP_DIR="/opt/iranlink"
VENV="$APP_DIR/venv"
APP="$APP_DIR/app.py"
WG_IF="iranlink0"
ROLE="${1:-}"
shift || true
PANEL_URL=""
BOOTSTRAP=""
PUBLIC_IP=""
PANEL_PORT="8088"
WG_PORT="51820"
MTU="1380"
ADMIN_PASSWORD=""

blue(){ printf '\033[1;34m%s\033[0m\n' "$*"; }
green(){ printf '\033[1;32m%s\033[0m\n' "$*"; }
red(){ printf '\033[1;31m%s\033[0m\n' "$*" >&2; exit 1; }
[[ ${EUID:-$(id -u)} -eq 0 ]] || red "دستور را با sudo یا root اجرا کن."

while (($#)); do
  case "$1" in
    --panel-url) PANEL_URL="${2:-}"; shift 2 ;;
    --bootstrap) BOOTSTRAP="${2:-}"; shift 2 ;;
    --public-ip) PUBLIC_IP="${2:-}"; shift 2 ;;
    --panel-port) PANEL_PORT="${2:-}"; shift 2 ;;
    --wg-port) WG_PORT="${2:-}"; shift 2 ;;
    --mtu) MTU="${2:-}"; shift 2 ;;
    --password) ADMIN_PASSWORD="${2:-}"; shift 2 ;;
    *) red "گزینه ناشناخته: $1" ;;
  esac
done

if [[ -z "$ROLE" ]]; then
  echo "1) نصب پنل روی سرور ایران"
  echo "2) نصب نود روی سرور خارج"
  read -rp "انتخاب: " choice
  [[ "$choice" == 1 ]] && ROLE="iran"
  [[ "$choice" == 2 ]] && ROLE="foreign"
fi
[[ "$ROLE" == "iran" || "$ROLE" == "foreign" ]] || red "نقش باید iran یا foreign باشد."

if ! command -v apt-get >/dev/null 2>&1; then
  red "این نسخه برای Ubuntu 22.04/24.04 و Debian 12 ساخته شده است."
fi

blue "نصب بسته‌های لازم..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y --no-install-recommends wireguard-tools nftables python3 python3-venv python3-pip curl ca-certificates iproute2 jq

install -d -m 755 "$APP_DIR" /etc/iranlink /etc/wireguard
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || true)"
if [[ -n "$SCRIPT_DIR" && -f "$SCRIPT_DIR/iranlink.sh" ]]; then
  install -m 755 "$SCRIPT_DIR/iranlink.sh" "$APP"
else
  curl -fsSL "$REPO_RAW/iranlink.sh" -o "$APP"
  chmod 755 "$APP"
fi

if [[ ! -x "$VENV/bin/python" ]]; then
  python3 -m venv "$VENV"
fi
"$VENV/bin/pip" install --disable-pip-version-check --no-cache-dir -q --upgrade pip
"$VENV/bin/pip" install --disable-pip-version-check --no-cache-dir -q flask gunicorn

cat >/etc/sysctl.d/99-iranlink.conf <<'EOF'
net.ipv4.ip_forward=1
net.ipv4.conf.all.rp_filter=2
net.ipv4.conf.default.rp_filter=2
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.tcp_syncookies=1
net.core.default_qdisc=fq
EOF
if modprobe tcp_bbr 2>/dev/null && sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -qw bbr; then
  echo 'net.ipv4.tcp_congestion_control=bbr' >> /etc/sysctl.d/99-iranlink.conf
fi
# فقط تنظیمات خود IranLink اعمال می‌شود؛ خطاهای فایل‌های قدیمی سیستم نصب را متوقف نمی‌کنند.
sysctl -p /etc/sysctl.d/99-iranlink.conf >/dev/null 2>&1 || true

if [[ "$ROLE" == "iran" ]]; then
  if [[ -z "$ADMIN_PASSWORD" ]]; then
    while :; do
      read -rsp "رمز ورود پنل (حداقل 8 کاراکتر): " ADMIN_PASSWORD; echo
      [[ ${#ADMIN_PASSWORD} -ge 8 ]] && break
      echo "رمز کوتاه است."
    done
  fi
  if [[ -z "$PUBLIC_IP" ]]; then
    PUBLIC_IP="$(curl -4fsS --max-time 8 https://api.ipify.org 2>/dev/null || true)"
    read -rp "IP عمومی سرور ایران [${PUBLIC_IP:-وارد کن}]: " typed
    PUBLIC_IP="${typed:-$PUBLIC_IP}"
  fi
  read -rp "پورت پنل وب [$PANEL_PORT]: " typed; PANEL_PORT="${typed:-$PANEL_PORT}"
  read -rp "پورت WireGuard [$WG_PORT]: " typed; WG_PORT="${typed:-$WG_PORT}"

  blue "ساخت پنل ایران..."
  "$VENV/bin/python" "$APP" init-panel \
    --public-ip "$PUBLIC_IP" \
    --panel-port "$PANEL_PORT" \
    --wg-port "$WG_PORT" \
    --mtu "$MTU" \
    --admin-password "$ADMIN_PASSWORD"

  cat >/etc/systemd/system/iranlink-panel.service <<EOF
[Unit]
Description=IranLink web panel for Pasargad nodes
After=network-online.target wg-quick@${WG_IF}.service
Wants=network-online.target
Requires=wg-quick@${WG_IF}.service

[Service]
Type=simple
WorkingDirectory=$APP_DIR
Environment=IRANLINK_MODE=panel
ExecStartPre=$VENV/bin/python $APP apply-panel
ExecStart=$VENV/bin/gunicorn --workers 1 --threads 4 --timeout 30 --bind 0.0.0.0:$PANEL_PORT --access-logfile - --error-logfile - app:app
Restart=always
RestartSec=3
NoNewPrivileges=false

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now "wg-quick@${WG_IF}.service"
  systemctl enable --now iranlink-panel.service

  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
    ufw allow "${PANEL_PORT}/tcp" comment 'IranLink-Panel' >/dev/null || true
    ufw allow "${WG_PORT}/udp" comment 'IranLink-WG' >/dev/null || true
  fi

  green "پنل نصب شد ✅"
  echo
  echo "آدرس پنل: http://$PUBLIC_IP:$PANEL_PORT"
  echo "از داخل پنل نود خارج را بساز و دستور آماده نصب را کپی کن."

else
  if [[ -z "$PANEL_URL" ]]; then read -rp "آدرس پنل ایران، مثل http://1.2.3.4:8088: " PANEL_URL; fi
  if [[ -z "$BOOTSTRAP" ]]; then read -rp "کد نصب نود که پنل داده: " BOOTSTRAP; fi
  [[ -n "$PANEL_URL" && -n "$BOOTSTRAP" ]] || red "آدرس پنل و کد نصب لازم است."

  blue "دریافت مشخصات نود از پنل ایران..."
  "$VENV/bin/python" "$APP" init-agent --panel-url "$PANEL_URL" --bootstrap "$BOOTSTRAP"
  TUNNEL_IP="$(jq -r '.tunnel_ip' /etc/iranlink/agent.json)"
  FOREIGN_WG_PORT="$(jq -r '.foreign_wg_port' /etc/iranlink/agent.json)"

  cat >/etc/systemd/system/iranlink-agent.service <<EOF
[Unit]
Description=IranLink foreign node agent
After=network-online.target wg-quick@${WG_IF}.service
Wants=network-online.target
Requires=wg-quick@${WG_IF}.service

[Service]
Type=simple
WorkingDirectory=$APP_DIR
Environment=IRANLINK_MODE=agent
ExecStartPre=$VENV/bin/python $APP apply-agent
ExecStart=$VENV/bin/gunicorn --workers 1 --threads 2 --timeout 30 --bind $TUNNEL_IP:9700 --access-logfile - --error-logfile - app:app
Restart=always
RestartSec=3
NoNewPrivileges=false

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now "wg-quick@${WG_IF}.service"
  systemctl enable --now iranlink-agent.service

  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
    ufw allow "${FOREIGN_WG_PORT}/udp" comment 'IranLink-WG' >/dev/null || true
    ufw allow in on "$WG_IF" from 10.88.0.1 comment 'IranLink-Agent' >/dev/null || true
  fi

  green "نود خارج نصب و به پنل ایران متصل شد ✅"
  echo "حالا از پنل ایران پورت‌های پاسارگارد را اضافه کن."
fi
