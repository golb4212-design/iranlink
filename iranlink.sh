#!/usr/bin/env bash
set -Eeuo pipefail

VERSION="1.1.0"
CONFIG_DIR="/etc/iranlink"
CONFIG_FILE="$CONFIG_DIR/config.env"
PORTS_FILE="$CONFIG_DIR/ports.conf"
SERVICES_FILE="$CONFIG_DIR/services.conf"
UFW_STATE_FILE="$CONFIG_DIR/ufw-managed.conf"
PRIVATE_KEY_FILE="$CONFIG_DIR/private.key"
PUBLIC_KEY_FILE="$CONFIG_DIR/public.key"
PEER_KEY_FILE="$CONFIG_DIR/peer.pub"
SERVICE_FILE="/etc/systemd/system/iranlink.service"
BIN_PATH="/usr/local/sbin/iranlink"
NETNS_NAME="iranlink"
WG_IF="ilwg0"
VETH_HOST="il-host"
VETH_NS="il-ns"
VETH_HOST_ADDR="10.203.0.1/30"
VETH_NS_ADDR="10.203.0.2/30"
VETH_NS_IP="10.203.0.2"
WG_EXIT_ADDR="10.66.66.1/30"
WG_IRAN_ADDR="10.66.66.2/30"
WG_IRAN_IP="10.66.66.2"

log()  { printf '\033[1;34m[IranLink]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[IranLink]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[IranLink]\033[0m %s\n' "$*" >&2; exit 1; }
require_root() { [[ ${EUID:-$(id -u)} -eq 0 ]] || die "این دستور باید با sudo یا root اجرا شود."; }
command_exists() { command -v "$1" >/dev/null 2>&1; }
load_config() { [[ -r "$CONFIG_FILE" ]] || die "IranLink هنوز نصب نشده است."; source "$CONFIG_FILE"; }
validate_port() { [[ ${1:-} =~ ^[0-9]+$ ]] && (( $1 >= 1 && $1 <= 65535 )); }
validate_ipv4() {
  local ip=${1:-} x
  [[ $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  IFS=. read -r -a parts <<< "$ip"
  for x in "${parts[@]}"; do ((10#$x >= 0 && 10#$x <= 255)) || return 1; done
}
validate_wg_key() { local key=${1:-}; [[ ${#key} -eq 44 && $key =~ ^[A-Za-z0-9+/]{43}=$ ]]; }
detect_public_ipv4() {
  local ip=""
  command_exists curl && ip=$(curl -4fsS --max-time 6 https://api.ipify.org 2>/dev/null || true)
  if validate_ipv4 "$ip"; then printf '%s\n' "$ip"; else ip -4 addr show scope global | awk '/inet / {sub(/\/.*/,"",$2); print $2; exit}'; fi
}
restart_service() { systemctl daemon-reload; systemctl restart iranlink.service; }

ufw_active() { command_exists ufw && ufw status 2>/dev/null | grep -q '^Status: active'; }
ufw_state_add() { touch "$UFW_STATE_FILE"; chmod 600 "$UFW_STATE_FILE"; grep -Fxq -- "$1" "$UFW_STATE_FILE" || echo "$1" >> "$UFW_STATE_FILE"; }
ufw_state_remove() {
  [[ -f "$UFW_STATE_FILE" ]] || return 0
  local t; t=$(mktemp); grep -Fvx -- "$1" "$UFW_STATE_FILE" > "$t" || true; install -m 600 "$t" "$UFW_STATE_FILE"; rm -f "$t"
}
ufw_allow_exit() {
  ufw_active || return 0
  local p=$1 wan=$2
  if ! ufw show added 2>/dev/null | grep -Fq "ufw allow ${p}/udp"; then ufw allow "${p}/udp" comment 'IranLink WireGuard' >/dev/null; ufw_state_add "exit-input|$p"; fi
  if ! ufw show added 2>/dev/null | grep -Fq "ufw route allow in on $WG_IF out on $wan"; then ufw route allow in on "$WG_IF" out on "$wan" >/dev/null; ufw_state_add "exit-route|$wan"; fi
}
ufw_add_publish() {
  ufw_active || return 0
  local proto=$1 hp=$2 tp=$3 wan=$4
  if ! ufw show added 2>/dev/null | grep -Fq "ufw allow ${hp}/${proto}"; then ufw allow "${hp}/${proto}" comment 'IranLink port' >/dev/null; ufw_state_add "publish-input|$proto|$hp"; fi
  if ! ufw show added 2>/dev/null | grep -Fq "ufw route allow in on $wan out on $VETH_HOST to $VETH_NS_IP port $tp proto $proto"; then
    ufw route allow in on "$wan" out on "$VETH_HOST" to "$VETH_NS_IP" port "$tp" proto "$proto" >/dev/null
    ufw_state_add "publish-route|$proto|$tp|$wan"
  fi
}
ufw_remove_publish() {
  command_exists ufw || return 0
  local proto=$1 hp=$2 tp=$3 wan=$4 remove_input=${5:-1} remove_route=${6:-1} key
  key="publish-input|$proto|$hp"
  if [[ $remove_input == 1 ]] && grep -Fxq "$key" "$UFW_STATE_FILE" 2>/dev/null; then ufw --force delete allow "${hp}/${proto}" >/dev/null 2>&1 || true; ufw_state_remove "$key"; fi
  key="publish-route|$proto|$tp|$wan"
  if [[ $remove_route == 1 ]] && grep -Fxq "$key" "$UFW_STATE_FILE" 2>/dev/null; then ufw --force route delete allow in on "$wan" out on "$VETH_HOST" to "$VETH_NS_IP" port "$tp" proto "$proto" >/dev/null 2>&1 || true; ufw_state_remove "$key"; fi
}
ufw_cleanup() {
  command_exists ufw || return 0
  [[ -s "$UFW_STATE_FILE" ]] || return 0
  local kind a b c
  while IFS='|' read -r kind a b c; do
    case "$kind" in
      exit-input) ufw --force delete allow "${a}/udp" >/dev/null 2>&1 || true ;;
      exit-route) ufw --force route delete allow in on "$WG_IF" out on "$a" >/dev/null 2>&1 || true ;;
      publish-input) ufw --force delete allow "${b}/${a}" >/dev/null 2>&1 || true ;;
      publish-route) ufw --force route delete allow in on "$c" out on "$VETH_HOST" to "$VETH_NS_IP" port "$b" proto "$a" >/dev/null 2>&1 || true ;;
    esac
  done < "$UFW_STATE_FILE"
  : > "$UFW_STATE_FILE"
}

render_exit_nft() {
  cat <<NFT
table inet iranlink_exit_filter {
  set blocked_v4 {
    type ipv4_addr
    flags interval
    elements = { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8,
                 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24,
                 192.0.2.0/24, 192.168.0.0/16, 198.18.0.0/15,
                 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/4, 240.0.0.0/4 }
  }
  chain input_guard {
    type filter hook input priority -5; policy accept;
    iifname "$WAN_IF" udp dport $WG_PORT accept
  }
  chain forward_guard {
    type filter hook forward priority -5; policy accept;
    ct state invalid drop
    ct state established,related accept
    iifname "$WG_IF" oifname "$WAN_IF" ip daddr @blocked_v4 drop
    iifname "$WG_IF" oifname "$WAN_IF" tcp dport 25 drop
    iifname "$WG_IF" oifname "$WAN_IF" ct state new tcp flags syn limit rate over 350/second burst 700 packets drop
    iifname "$WG_IF" oifname "$WAN_IF" ct state new meta l4proto udp limit rate over 900/second burst 1800 packets drop
    iifname "$WG_IF" oifname "$WAN_IF" accept
    iifname "$WAN_IF" oifname "$WG_IF" ct state established,related accept
  }
}
table ip iranlink_exit_nat {
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    oifname "$WAN_IF" ip saddr $WG_IRAN_IP masquerade
  }
}
NFT
}

render_iran_host_nft() {
  cat <<NFT
table inet iranlink_iran_filter {
  chain forward_guard {
    type filter hook forward priority -5; policy accept;
    ct state invalid drop
    ct state established,related accept
    iifname "$VETH_HOST" oifname "$WAN_IF" ip saddr $VETH_NS_IP drop
  }
}
table ip iranlink_iran_nat {
  chain prerouting {
    type nat hook prerouting priority dstnat; policy accept;
NFT
  if [[ -s "$PORTS_FILE" ]]; then
    while read -r proto hp tp; do
      [[ -n ${proto:-} && ${proto:0:1} != '#' ]] || continue
      [[ $proto == tcp ]] && echo "    iifname \"$WAN_IF\" tcp dport $hp dnat to $VETH_NS_IP:$tp"
      [[ $proto == udp ]] && echo "    iifname \"$WAN_IF\" udp dport $hp dnat to $VETH_NS_IP:$tp"
    done < "$PORTS_FILE"
  fi
  cat <<'NFT'
  }
}
NFT
}

render_iran_ns_nft() {
  cat <<NFT
table inet iranlink_ns_filter {
  chain preroute_mark {
    type filter hook prerouting priority mangle; policy accept;
    iifname "$VETH_NS" ct state new ct mark set 0x1
    ct mark 0x1 meta mark set ct mark
  }
  chain input_guard {
    type filter hook input priority filter; policy drop;
    iifname "lo" accept
    ct state invalid drop
    ct state established,related accept
    iifname "$VETH_NS" accept
  }
  chain output_guard {
    type filter hook output priority filter; policy drop;
    oifname "lo" accept
    ct state invalid drop
    ct state established,related accept
    oifname "$WG_IF" accept
    oifname "$VETH_NS" meta mark 0x1 accept
  }
}
table ip iranlink_ns_route {
  chain output_mark {
    type route hook output priority mangle; policy accept;
    ct mark 0x1 meta mark set ct mark
  }
}
NFT
}

nft_load_host() { local f; f=$(mktemp); "$1" > "$f"; nft -c -f "$f"; nft -f "$f"; rm -f "$f"; }
nft_load_ns() { local f; f=$(mktemp); "$1" > "$f"; ip netns exec "$NETNS_NAME" nft -c -f "$f"; ip netns exec "$NETNS_NAME" nft -f "$f"; rm -f "$f"; }

internal_down() {
  [[ -r "$CONFIG_FILE" ]] || exit 0
  load_config
  if [[ $ROLE == exit ]]; then
    nft delete table inet iranlink_exit_filter 2>/dev/null || true
    nft delete table ip iranlink_exit_nat 2>/dev/null || true
    ip link del "$WG_IF" 2>/dev/null || true
  else
    nft delete table inet iranlink_iran_filter 2>/dev/null || true
    nft delete table ip iranlink_iran_nat 2>/dev/null || true
    ip netns del "$NETNS_NAME" 2>/dev/null || true
    ip link del "$VETH_HOST" 2>/dev/null || true
    ip link del "$WG_IF" 2>/dev/null || true
  fi
}

up_exit() {
  internal_down || true
  ip link add "$WG_IF" type wireguard
  ip address add "$WG_EXIT_ADDR" dev "$WG_IF"
  ip link set mtu "$MTU" dev "$WG_IF"
  wg set "$WG_IF" private-key "$PRIVATE_KEY_FILE" listen-port "$WG_PORT"
  [[ -s "$PEER_KEY_FILE" ]] && wg set "$WG_IF" peer "$(cat "$PEER_KEY_FILE")" allowed-ips "$WG_IRAN_IP/32"
  ip link set up dev "$WG_IF"
  nft_load_host render_exit_nft
}

up_iran() {
  internal_down || true
  [[ -s "$PEER_KEY_FILE" ]] || die "کلید سرور خارج پیدا نشد."
  ip netns add "$NETNS_NAME"
  ip link add "$VETH_HOST" type veth peer name "$VETH_NS"
  ip link set "$VETH_NS" netns "$NETNS_NAME"
  ip address add "$VETH_HOST_ADDR" dev "$VETH_HOST"
  ip link set up dev "$VETH_HOST"
  ip netns exec "$NETNS_NAME" ip link set lo up
  ip netns exec "$NETNS_NAME" ip address add "$VETH_NS_ADDR" dev "$VETH_NS"
  ip netns exec "$NETNS_NAME" ip link set up dev "$VETH_NS"

  ip link add "$WG_IF" type wireguard
  ip link set "$WG_IF" netns "$NETNS_NAME"
  ip netns exec "$NETNS_NAME" ip address add "$WG_IRAN_ADDR" dev "$WG_IF"
  ip netns exec "$NETNS_NAME" ip link set mtu "$MTU" dev "$WG_IF"
  ip netns exec "$NETNS_NAME" wg set "$WG_IF" private-key "$PRIVATE_KEY_FILE" peer "$(cat "$PEER_KEY_FILE")" endpoint "$EXIT_IP:$WG_PORT" allowed-ips 0.0.0.0/0 persistent-keepalive 25
  ip netns exec "$NETNS_NAME" ip link set up dev "$WG_IF"
  ip netns exec "$NETNS_NAME" ip route add default dev "$WG_IF"
  ip netns exec "$NETNS_NAME" ip route add default via 10.203.0.1 dev "$VETH_NS" table 100
  ip netns exec "$NETNS_NAME" ip rule add fwmark 0x1 lookup 100 priority 100

  install -d -m 755 "/etc/netns/$NETNS_NAME"
  printf 'nameserver %s\noptions timeout:2 attempts:2\n' "$DNS_SERVER" > "/etc/netns/$NETNS_NAME/resolv.conf"
  cp "/etc/netns/$NETNS_NAME/resolv.conf" "$CONFIG_DIR/resolv.conf"
  ip netns exec "$NETNS_NAME" sysctl -qw net.ipv6.conf.all.disable_ipv6=1 || true
  ip netns exec "$NETNS_NAME" sysctl -qw net.ipv6.conf.default.disable_ipv6=1 || true
  nft_load_ns render_iran_ns_nft
  nft_load_host render_iran_host_nft
}

internal_up() {
  load_config
  case "$ROLE" in
    exit) up_exit ;;
    iran) up_iran ;;
    *) die "نقش سرور نامعتبر است." ;;
  esac
}

usage() {
  cat <<'HELP'
IranLink commands:
  iranlink status
  iranlink show-key
  iranlink peer add PUBLIC_KEY       # روی سرور خارج
  iranlink test
  iranlink service attach xray.service
  iranlink service detach xray.service
  iranlink publish tcp 443           # روی سرور ایران
  iranlink publish udp 443
  iranlink unpublish tcp 443
  iranlink ports
  iranlink exec -- curl -4 ifconfig.me
  iranlink mtu 1380
  iranlink restart
  iranlink logs
  iranlink uninstall
HELP
}

status_cmd() {
  load_config
  echo "version: $VERSION"
  echo "role: $ROLE"
  echo "wan: $WAN_IF"
  echo "mtu: $MTU"
  systemctl --no-pager --full status iranlink.service || true
  echo
  if [[ $ROLE == exit ]]; then wg show "$WG_IF" 2>/dev/null || true; else ip netns exec "$NETNS_NAME" wg show "$WG_IF" 2>/dev/null || true; fi
}
show_key_cmd() { [[ -s "$PUBLIC_KEY_FILE" ]] || die "کلید پیدا نشد."; cat "$PUBLIC_KEY_FILE"; }
peer_add_cmd() {
  load_config; [[ $ROLE == exit ]] || die "این دستور فقط روی سرور خارج اجرا می‌شود."
  validate_wg_key "${1:-}" || die "Public Key نامعتبر است."
  printf '%s\n' "$1" > "$PEER_KEY_FILE"; chmod 600 "$PEER_KEY_FILE"; restart_service; log "کلید ایران ثبت شد."
}
parse_mapping() {
  local m=$1
  if [[ $m == *:* ]]; then HOST_PORT=${m%%:*}; TARGET_PORT=${m##*:}; else HOST_PORT=$m; TARGET_PORT=$m; fi
  validate_port "$HOST_PORT" || die "پورت ورودی نامعتبر است."
  validate_port "$TARGET_PORT" || die "پورت مقصد نامعتبر است."
}
publish_cmd() {
  load_config; [[ $ROLE == iran ]] || die "این دستور فقط روی سرور ایران اجرا می‌شود."
  local proto=${1:-} m=${2:-}; [[ $proto == tcp || $proto == udp ]] || die "tcp یا udp را وارد کن."; [[ -n $m ]] || die "پورت را وارد کن."
  parse_mapping "$m"; touch "$PORTS_FILE"; chmod 600 "$PORTS_FILE"
  grep -Eq "^$proto[[:space:]]+$HOST_PORT[[:space:]]+$TARGET_PORT$" "$PORTS_FILE" && { warn "این پورت قبلاً ثبت شده."; return; }
  echo "$proto $HOST_PORT $TARGET_PORT" >> "$PORTS_FILE"; ufw_add_publish "$proto" "$HOST_PORT" "$TARGET_PORT" "$WAN_IF"; restart_service; log "پورت منتشر شد."
}
unpublish_cmd() {
  load_config; [[ $ROLE == iran ]] || die "این دستور فقط روی سرور ایران اجرا می‌شود."
  local proto=${1:-} m=${2:-}; [[ $proto == tcp || $proto == udp ]] || die "tcp یا udp را وارد کن."; parse_mapping "$m"
  [[ -f "$PORTS_FILE" ]] || return 0
  local t remove_input=1 remove_route=1; t=$(mktemp)
  awk -v p="$proto" -v h="$HOST_PORT" -v x="$TARGET_PORT" '!( $1==p && $2==h && $3==x )' "$PORTS_FILE" > "$t"; install -m 600 "$t" "$PORTS_FILE"; rm -f "$t"
  grep -Eq "^$proto[[:space:]]+$HOST_PORT[[:space:]]+" "$PORTS_FILE" && remove_input=0
  awk -v p="$proto" -v x="$TARGET_PORT" '$1==p && $3==x {f=1} END{exit !f}' "$PORTS_FILE" && remove_route=0
  ufw_remove_publish "$proto" "$HOST_PORT" "$TARGET_PORT" "$WAN_IF" "$remove_input" "$remove_route"; restart_service; log "پورت حذف شد."
}
ports_cmd() { load_config; [[ -s "$PORTS_FILE" ]] && cat "$PORTS_FILE" || echo "هیچ پورتی ثبت نشده است."; }
exec_cmd() { load_config; [[ $ROLE == iran ]] || die "فقط روی سرور ایران."; [[ ${1:-} == -- ]] && shift; (($#)) || die "فرمان وارد نشده."; ip netns exec "$NETNS_NAME" "$@"; }
service_attach_cmd() {
  load_config; [[ $ROLE == iran ]] || die "فقط روی سرور ایران."
  local unit=${1:-}; [[ $unit =~ ^[A-Za-z0-9_.@-]+\.service$ ]] || die "نام سرویس باید با .service تمام شود."
  systemctl cat "$unit" >/dev/null 2>&1 || die "سرویس پیدا نشد: $unit"
  local d="/etc/systemd/system/${unit}.d"; install -d -m 755 "$d"
  cat > "$d/90-iranlink.conf" <<EOF
[Unit]
Requires=iranlink.service
BindsTo=iranlink.service
After=iranlink.service
[Service]
PrivateNetwork=false
NetworkNamespacePath=/run/netns/$NETNS_NAME
BindReadOnlyPaths=$CONFIG_DIR/resolv.conf:/etc/resolv.conf
EOF
  systemctl daemon-reload
  if ! systemctl restart "$unit"; then rm -f "$d/90-iranlink.conf"; systemctl daemon-reload; die "اتصال سرویس ناموفق بود."; fi
  touch "$SERVICES_FILE"; chmod 600 "$SERVICES_FILE"; grep -Fxq "$unit" "$SERVICES_FILE" || echo "$unit" >> "$SERVICES_FILE"; log "$unit به تونل وصل شد."
}
service_detach_cmd() {
  local unit=${1:-}; [[ $unit =~ ^[A-Za-z0-9_.@-]+\.service$ ]] || die "نام سرویس نامعتبر است."
  rm -f "/etc/systemd/system/${unit}.d/90-iranlink.conf"; rmdir "/etc/systemd/system/${unit}.d" 2>/dev/null || true; systemctl daemon-reload; systemctl restart "$unit"
  if [[ -f "$SERVICES_FILE" ]]; then local t; t=$(mktemp); grep -Fvx "$unit" "$SERVICES_FILE" > "$t" || true; install -m 600 "$t" "$SERVICES_FILE"; rm -f "$t"; fi
  log "$unit از تونل جدا شد."
}
mtu_cmd() { load_config; local x=${1:-}; [[ $x =~ ^[0-9]+$ ]] && ((x>=1280 && x<=1420)) || die "MTU باید 1280 تا 1420 باشد."; sed -i -E "s/^MTU=.*/MTU=$x/" "$CONFIG_FILE"; restart_service; }
test_cmd() {
  load_config
  if [[ $ROLE == exit ]]; then
    [[ -n $(wg show "$WG_IF" peers 2>/dev/null) ]] || die "هنوز کلید ایران ثبت نشده است."
    wg show "$WG_IF"; echo "EXIT OK"
  else
    local hs host_ip out_ip
    hs=$(ip netns exec "$NETNS_NAME" wg show "$WG_IF" latest-handshakes 2>/dev/null | awk 'BEGIN{m=0}{if($2>m)m=$2}END{print m}')
    [[ ${hs:-0} -gt 0 ]] || die "Handshake برقرار نیست؛ کلید ایران را روی خارج ثبت کن و UDP را باز نگه دار."
    host_ip=$(detect_public_ipv4 || true)
    out_ip=$(ip netns exec "$NETNS_NAME" curl -4fsS --max-time 10 https://api.ipify.org || true)
    [[ -n $out_ip ]] || die "اینترنت داخل تونل برقرار نیست."
    echo "IP ایران: ${host_ip:-unknown}"
    echo "IP خروجی تونل: $out_ip"
    [[ -z $host_ip || $host_ip != "$out_ip" ]] || die "نشت IP تشخیص داده شد."
    echo "LEAK TEST: OK"
  fi
}
uninstall_cmd() {
  ufw_cleanup
  local units=() u
  [[ -s "$SERVICES_FILE" ]] && mapfile -t units < "$SERVICES_FILE"
  for u in "${units[@]}"; do rm -f "/etc/systemd/system/${u}.d/90-iranlink.conf"; rmdir "/etc/systemd/system/${u}.d" 2>/dev/null || true; done
  systemctl disable --now iranlink.service 2>/dev/null || true; internal_down 2>/dev/null || true
  rm -f "$SERVICE_FILE" "$BIN_PATH" /etc/sysctl.d/99-iranlink.conf /etc/sysctl.d/99-iranlink-bbr.conf
  rm -rf "$CONFIG_DIR" "/etc/netns/$NETNS_NAME"
  systemctl daemon-reload; sysctl --system >/dev/null 2>&1 || true
  for u in "${units[@]}"; do systemctl restart "$u" 2>/dev/null || true; done
  log "IranLink حذف شد."
}

require_root
case ${1:-} in
  internal-up) internal_up ;;
  internal-down) internal_down ;;
  status) status_cmd ;;
  show-key) show_key_cmd ;;
  peer) [[ ${2:-} == add ]] || die "iranlink peer add PUBLIC_KEY"; peer_add_cmd "${3:-}" ;;
  test) test_cmd ;;
  publish) publish_cmd "${2:-}" "${3:-}" ;;
  unpublish) unpublish_cmd "${2:-}" "${3:-}" ;;
  ports) ports_cmd ;;
  exec) shift; exec_cmd "$@" ;;
  service)
    case ${2:-} in
      attach) service_attach_cmd "${3:-}" ;;
      detach) service_detach_cmd "${3:-}" ;;
      *) die "iranlink service attach|detach UNIT.service" ;;
    esac
    ;;
  mtu) mtu_cmd "${2:-}" ;;
  restart) restart_service ;;
  logs) journalctl -u iranlink.service -n 100 --no-pager ;;
  uninstall) uninstall_cmd ;;
  help|-h|--help|"") usage ;;
  *) usage; exit 1 ;;
esac
