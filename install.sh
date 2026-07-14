#!/usr/bin/env bash
set -Eeuo pipefail

REPO="https://github.com/golb4212-design/iranlink"
DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
CONFIG_DIR="/etc/iranlink"
CONFIG_FILE="$CONFIG_DIR/config.env"
BIN_PATH="/usr/local/sbin/iranlink"
SERVICE_FILE="/etc/systemd/system/iranlink.service"

blue() { printf '\033[1;34m%s\033[0m\n' "$*"; }
red() { printf '\033[1;31m%s\033[0m\n' "$*" >&2; exit 1; }
[[ ${EUID:-$(id -u)} -eq 0 ]] || red "این دستور را با sudo اجرا کن."
[[ -f "$DIR/iranlink.sh" ]] || red "فایل iranlink.sh کنار install.sh نیست. هر سه فایل را در صفحه اصلی GitHub بگذار."

clear 2>/dev/null || true
blue "================================="
blue "       نصب ساده IranLink"
blue "================================="
echo "1) این سرور خارج است"
echo "2) این سرور ایران است"
read -rp "عدد 1 یا 2: " CHOICE
[[ $CHOICE == 1 || $CHOICE == 2 ]] || red "فقط 1 یا 2 وارد کن."

read -rp "پورت WireGuard [51820]: " WG_PORT
WG_PORT=${WG_PORT:-51820}
[[ $WG_PORT =~ ^[0-9]+$ ]] && ((WG_PORT>=1 && WG_PORT<=65535)) || red "پورت نامعتبر است."
read -rp "MTU [1380]: " MTU
MTU=${MTU:-1380}
[[ $MTU =~ ^[0-9]+$ ]] && ((MTU>=1280 && MTU<=1420)) || red "MTU باید بین 1280 و 1420 باشد."

EXIT_IP=""; EXIT_KEY=""; DNS_SERVER="1.1.1.1"
if [[ $CHOICE == 2 ]]; then
  read -rp "IP سرور خارج: " EXIT_IP
  [[ $EXIT_IP =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || red "IP نامعتبر است."
  read -rp "Public Key سرور خارج: " EXIT_KEY
  [[ ${#EXIT_KEY} -eq 44 ]] || red "Public Key نامعتبر است."
fi

export DEBIAN_FRONTEND=noninteractive
if command -v apt-get >/dev/null 2>&1; then
  apt-get update -y
  apt-get install -y --no-install-recommends wireguard-tools nftables iproute2 iputils-ping curl ca-certificates procps
elif command -v dnf >/dev/null 2>&1; then
  dnf install -y wireguard-tools nftables iproute iputils curl ca-certificates procps-ng
elif command -v yum >/dev/null 2>&1; then
  yum install -y epel-release || true
  yum install -y wireguard-tools nftables iproute iputils curl ca-certificates procps-ng
else
  red "فقط Ubuntu/Debian و AlmaLinux/Rocky پشتیبانی می‌شوند."
fi

command -v wg >/dev/null || red "WireGuard نصب نشد."
command -v nft >/dev/null || red "nftables نصب نشد."
WAN_IF=$(ip -4 route show default | awk 'NR==1{print $5}')
[[ -n $WAN_IF ]] || red "کارت شبکه اینترنت پیدا نشد."

systemctl stop iranlink.service 2>/dev/null || true
install -d -m 700 "$CONFIG_DIR"
install -m 755 "$DIR/iranlink.sh" "$BIN_PATH"

if [[ ! -s "$CONFIG_DIR/private.key" ]]; then
  umask 077
  wg genkey | tee "$CONFIG_DIR/private.key" | wg pubkey > "$CONFIG_DIR/public.key"
fi
chmod 600 "$CONFIG_DIR/private.key"
chmod 644 "$CONFIG_DIR/public.key"
touch "$CONFIG_DIR/ports.conf" "$CONFIG_DIR/services.conf" "$CONFIG_DIR/ufw-managed.conf"
chmod 600 "$CONFIG_DIR/ports.conf" "$CONFIG_DIR/services.conf" "$CONFIG_DIR/ufw-managed.conf"

cat > /etc/sysctl.d/99-iranlink.conf <<'EOF'
net.ipv4.ip_forward = 1
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2
net.ipv4.conf.all.src_valid_mark = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.tcp_syncookies = 1
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.netdev_max_backlog = 16384
EOF

if modprobe tcp_bbr 2>/dev/null && sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -qw bbr; then
  cat > /etc/sysctl.d/99-iranlink-bbr.conf <<'EOF'
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF
fi
sysctl --system >/dev/null

if [[ $CHOICE == 1 ]]; then
  cat > "$CONFIG_FILE" <<EOF
ROLE=exit
WAN_IF=$WAN_IF
WG_PORT=$WG_PORT
MTU=$MTU
EOF
else
  printf '%s\n' "$EXIT_KEY" > "$CONFIG_DIR/peer.pub"
  chmod 600 "$CONFIG_DIR/peer.pub"
  cat > "$CONFIG_FILE" <<EOF
ROLE=iran
WAN_IF=$WAN_IF
WG_PORT=$WG_PORT
MTU=$MTU
EXIT_IP=$EXIT_IP
DNS_SERVER=$DNS_SERVER
EOF
fi
chmod 600 "$CONFIG_FILE"

cat > "$SERVICE_FILE" <<'EOF'
[Unit]
Description=IranLink isolated WireGuard tunnel
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/iranlink internal-up
ExecStop=/usr/local/sbin/iranlink internal-down
TimeoutStartSec=45
TimeoutStopSec=20
[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now iranlink.service

PUBLIC_KEY=$(cat "$CONFIG_DIR/public.key")
PUBLIC_IP=$(curl -4fsS --max-time 6 https://api.ipify.org 2>/dev/null || true)
echo
blue "نصب تمام شد ✅"
echo "Public Key این سرور:"
echo "$PUBLIC_KEY"
echo
if [[ $CHOICE == 1 ]]; then
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
    ufw allow "${WG_PORT}/udp" comment 'IranLink WireGuard' >/dev/null
    grep -Fxq "exit-input|$WG_PORT" "$CONFIG_DIR/ufw-managed.conf" || echo "exit-input|$WG_PORT" >> "$CONFIG_DIR/ufw-managed.conf"
    ufw route allow in on ilwg0 out on "$WAN_IF" >/dev/null || true
    grep -Fxq "exit-route|$WAN_IF" "$CONFIG_DIR/ufw-managed.conf" || echo "exit-route|$WAN_IF" >> "$CONFIG_DIR/ufw-managed.conf"
  fi
  echo "این دو مورد را برای نصب ایران نگه دار:"
  echo "IP خارج: ${PUBLIC_IP:-IP_SERVER_KHAREJ}"
  echo "Public Key خارج: $PUBLIC_KEY"
else
  echo "حالا این دستور را روی سرور خارج بزن:"
  echo "sudo iranlink peer add $PUBLIC_KEY"
  echo
  echo "بعد روی همین سرور ایران تست بگیر:"
  echo "sudo iranlink test"
fi
