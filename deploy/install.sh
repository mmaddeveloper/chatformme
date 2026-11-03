#!/usr/bin/env bash
# chatformme installer, written to be safe on a server that already runs other things.
#
# What it does, and nothing else:
#   - copies the app into /opt/chatformme (refuses if that folder belongs to something else)
#   - uses the system Node.js if it is v18 or newer; otherwise downloads a private
#     Node.js into /opt/chatformme/node (the system's own Node.js is left untouched)
#   - picks a free TCP port (3000, or the next free one); never takes a port in use
#   - creates /etc/chatformme.env with a random ADMIN_KEY (an existing file is kept)
#   - installs and starts the systemd service "chatformme", sandboxed with its own
#     throwaway user, a read-only view of the system and a memory cap
#   - opens that one port in ufw or firewalld, but only if one of them is active
# It does not touch nginx, apache, other services, system packages or existing firewall rules.
#
# Usage, as root, from a copy of this repository:
#   bash deploy/install.sh
# Optional settings (environment variables):
#   PORT=3005 CHAT_TITLE='پیام به ما' CHAT_PASSWORD='...' bash deploy/install.sh
# Remove everything it installed (messages are kept unless you delete them):
#   bash deploy/install.sh --uninstall

set -euo pipefail

APP_DIR=/opt/chatformme
STATE_DIR=/var/lib/chatformme
ENV_FILE=/etc/chatformme.env
UNIT=/etc/systemd/system/chatformme.service
SERVICE=chatformme
MARKER='# managed-by: chatformme-install'
NODE_MIN=18
NODE_LINE=22
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

say()  { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!!\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31mError:\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "run this as root:  sudo bash deploy/install.sh"
command -v systemctl >/dev/null 2>&1 || die "this installer needs systemd"

ours_unit() { [ -f "$UNIT" ] && grep -qF "$MARKER" "$UNIT"; }
ours_dir()  { [ -f "$APP_DIR/.chatformme" ]; }

# ---------------------------------------------------------------- uninstall
if [ "${1:-}" = "--uninstall" ]; then
  if ours_unit; then
    systemctl disable --now "$SERVICE" >/dev/null 2>&1 || true
    rm -f "$UNIT"
    systemctl daemon-reload
    say "service removed"
  fi
  if ours_dir; then
    if [ -f "$APP_DIR/.firewall" ]; then
      read -r fw port < "$APP_DIR/.firewall" || true
      case "$fw" in
        ufw) ufw delete allow "$port/tcp" >/dev/null 2>&1 || true ;;
        firewalld) firewall-cmd --permanent --remove-port="$port/tcp" >/dev/null 2>&1 && firewall-cmd --reload >/dev/null 2>&1 || true ;;
      esac
      say "closed port $port in $fw"
    fi
    rm -rf "$APP_DIR"
    say "removed $APP_DIR"
  fi
  echo "Kept the settings in $ENV_FILE and the messages in $STATE_DIR."
  echo "To delete those too:  rm -rf $ENV_FILE /var/lib/private/chatformme $STATE_DIR"
  exit 0
fi

# ---------------------------------------------------------------- checks
[ -f "$SRC_DIR/server.js" ] && [ -d "$SRC_DIR/public" ] || die "run this from a copy of the chatformme repository"
if [ -e "$APP_DIR" ] && ! ours_dir; then
  die "$APP_DIR already exists and was not created by this installer; not touching it"
fi
if [ -f "$UNIT" ] && ! ours_unit; then
  die "$UNIT already exists and was not created by this installer; not touching it"
fi

# ---------------------------------------------------------------- Node.js
node_major() { "$1" -p 'process.versions.node.split(".")[0]' 2>/dev/null; }
usable_node() {
  # The service cannot see /home or /root (ProtectHome), so Node installed there
  # (for example with nvm) is not usable by it.
  case "$1" in /home/*|/root/*) return 1 ;; esac
  local v; v="$(node_major "$1")" || return 1
  [ -n "$v" ] && [ "$v" -ge "$NODE_MIN" ]
}
fetch() {
  if command -v curl >/dev/null 2>&1; then curl -fsSL --retry 3 --connect-timeout 20 -o "$2" "$1"
  elif command -v wget >/dev/null 2>&1; then wget -q -O "$2" "$1"
  else die "neither curl nor wget is installed"; fi
}

NODE_BIN=""
if [ -x "$APP_DIR/node/bin/node" ] && usable_node "$APP_DIR/node/bin/node"; then
  NODE_BIN="$APP_DIR/node/bin/node"
else
  SYS_NODE="$(command -v node 2>/dev/null || true)"
  if [ -n "$SYS_NODE" ] && usable_node "$(readlink -f "$SYS_NODE")"; then
    NODE_BIN="$(readlink -f "$SYS_NODE")"
  fi
fi

if [ -z "$NODE_BIN" ]; then
  case "$(uname -m)" in
    x86_64) ARCH=x64 ;;
    aarch64|arm64) ARCH=arm64 ;;
    *) die "no Node.js $NODE_MIN+ found and no download for CPU $(uname -m); install Node.js $NODE_MIN+ and run again" ;;
  esac
  say "downloading a private Node.js $NODE_LINE for this app (the system is not changed)"
  TMP="$(mktemp -d)"
  trap 'rm -rf "$TMP"' EXIT
  BASE="https://nodejs.org/dist/latest-v${NODE_LINE}.x"
  fetch "$BASE/SHASUMS256.txt" "$TMP/SHASUMS256.txt" \
    || die "could not reach nodejs.org; install Node.js $NODE_MIN+ yourself and run again"
  FILE="$(grep -oE "node-v[0-9.]+-linux-${ARCH}\.tar\.gz" "$TMP/SHASUMS256.txt" | head -n 1)"
  [ -n "$FILE" ] || die "could not find a Node.js build for linux-$ARCH"
  fetch "$BASE/$FILE" "$TMP/$FILE" || die "download of $FILE failed"
  (cd "$TMP" && grep "  $FILE\$" SHASUMS256.txt | sha256sum -c - >/dev/null) || die "checksum of $FILE does not match"
  mkdir -p "$APP_DIR/node"
  touch "$APP_DIR/.chatformme"
  tar -xzf "$TMP/$FILE" -C "$APP_DIR/node" --strip-components=1
  NODE_BIN="$APP_DIR/node/bin/node"
fi
say "Node.js $("$NODE_BIN" -v) at $NODE_BIN"

# ---------------------------------------------------------------- port
port_in_use() {
  if command -v ss >/dev/null 2>&1; then
    ss -tln 2>/dev/null | awk 'NR > 1 {print $4}' | grep -qE "[:.]$1\$"
  elif command -v netstat >/dev/null 2>&1; then
    netstat -tln 2>/dev/null | awk 'NR > 2 {print $4}' | grep -qE "[:.]$1\$"
  else
    (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null
  fi
}

env_get() {
  if [ -f "$ENV_FILE" ]; then grep -E "^$1=" "$ENV_FILE" | tail -n 1 | cut -d= -f2- || true; fi
}

# Re-runs keep the port already chosen. A port our own running service holds is
# not "in use by another program"; everything is checked before the service is touched.
CUR_PORT="$(env_get PORT)"
WANT_PORT="${PORT:-$CUR_PORT}"
if [ -n "$WANT_PORT" ]; then
  if ! { ours_unit && [ "$WANT_PORT" = "$CUR_PORT" ]; } && port_in_use "$WANT_PORT"; then
    die "port $WANT_PORT is already used by another program; choose another: PORT=3005 bash deploy/install.sh"
  fi
  APP_PORT="$WANT_PORT"
else
  APP_PORT=""
  for p in $(seq 3000 3100); do
    if ! port_in_use "$p"; then APP_PORT="$p"; break; fi
  done
  [ -n "$APP_PORT" ] || die "no free port between 3000 and 3100"
fi
say "using port $APP_PORT"

# ---------------------------------------------------------------- app files
mkdir -p "$APP_DIR"
touch "$APP_DIR/.chatformme"
rm -rf "$APP_DIR/app.new"
mkdir -p "$APP_DIR/app.new"
cp -r "$SRC_DIR/server.js" "$SRC_DIR/package.json" "$SRC_DIR/public" "$APP_DIR/app.new/"
chmod -R a+rX "$APP_DIR"
rm -rf "$APP_DIR/app.old"
if [ -d "$APP_DIR/app" ]; then mv "$APP_DIR/app" "$APP_DIR/app.old"; fi
mv "$APP_DIR/app.new" "$APP_DIR/app"
rm -rf "$APP_DIR/app.old"
say "app copied to $APP_DIR/app"

# ---------------------------------------------------------------- settings
# Double quotes keep spaces intact for systemd (and for anyone who sources the file).
quote() { local v="${1//\\/\\\\}"; printf '"%s"' "${v//\"/\\\"}"; }

if [ ! -f "$ENV_FILE" ]; then
  ADMIN_KEY="$(head -c 32 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 24)"
  (
    umask 077
    {
      echo "# chatformme settings. After editing:  systemctl restart chatformme"
      echo "PORT=$APP_PORT"
      echo "ADMIN_KEY=$ADMIN_KEY"
      echo "CHAT_TITLE=$(quote "${CHAT_TITLE:-ارتباط با ما}")"
      if [ -n "${CHAT_PASSWORD:-}" ]; then echo "CHAT_PASSWORD=$(quote "$CHAT_PASSWORD")"; fi
    } > "$ENV_FILE"
  )
  say "created $ENV_FILE with a new admin key"
else
  # Keep the admin's settings; only record the port and any value passed on the command line.
  set_env() {
    local tmp; tmp="$(mktemp)"
    grep -vE "^$1=" "$ENV_FILE" > "$tmp" || true
    printf '%s=%s\n' "$1" "$2" >> "$tmp"
    cat "$tmp" > "$ENV_FILE"
    rm -f "$tmp"
  }
  set_env PORT "$APP_PORT"
  if [ -n "${CHAT_TITLE:-}" ]; then set_env CHAT_TITLE "$(quote "$CHAT_TITLE")"; fi
  if [ -n "${CHAT_PASSWORD:-}" ]; then set_env CHAT_PASSWORD "$(quote "$CHAT_PASSWORD")"; fi
  if [ -z "$(env_get ADMIN_KEY)" ]; then
    set_env ADMIN_KEY "$(head -c 32 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 24)"
  fi
  chmod 600 "$ENV_FILE"
  say "kept existing settings in $ENV_FILE"
fi

# ---------------------------------------------------------------- service
cat > "$UNIT" <<EOF
$MARKER
[Unit]
Description=chatformme (message us site)
After=network.target

[Service]
ExecStart=$NODE_BIN $APP_DIR/app/server.js
WorkingDirectory=$APP_DIR/app
Environment=HOST=0.0.0.0
Environment=DATA_DIR=$STATE_DIR
EnvironmentFile=$ENV_FILE
Restart=always
RestartSec=2

# Sandbox: a throwaway user that can only write its own data folder,
# so this app cannot affect anything else running on the server.
DynamicUser=yes
StateDirectory=chatformme
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryMax=300M

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable "$SERVICE" >/dev/null 2>&1
systemctl restart "$SERVICE"

ok=""
for _ in $(seq 1 30); do
  if "$NODE_BIN" -e "require('http').get('http://127.0.0.1:$APP_PORT/api/config', r => process.exit(r.statusCode === 200 ? 0 : 1)).on('error', () => process.exit(1))" 2>/dev/null; then
    ok=1; break
  fi
  sleep 0.5
done
if [ -z "$ok" ]; then
  journalctl -u "$SERVICE" -n 30 --no-pager || true
  die "the service did not start; the log is above"
fi
say "service is running"

# ---------------------------------------------------------------- firewall
FW=""
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
  ufw allow "$APP_PORT/tcp" comment chatformme >/dev/null
  FW=ufw
elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
  firewall-cmd --permanent --add-port="$APP_PORT/tcp" >/dev/null && firewall-cmd --reload >/dev/null
  FW=firewalld
fi
if [ -n "$FW" ]; then
  echo "$FW $APP_PORT" > "$APP_DIR/.firewall"
  say "opened port $APP_PORT in $FW"
fi

# ---------------------------------------------------------------- done
echo
say "Done."
echo "Addresses (give the public one to people):"
for ip in $(hostname -I 2>/dev/null); do
  case "$ip" in *:*) echo "  http://[$ip]:$APP_PORT" ;; *) echo "  http://$ip:$APP_PORT" ;; esac
done
echo
echo "Admin key (use it on the site under «ورود مدیر»; keep it secret):"
echo "  $(env_get ADMIN_KEY)"
echo
echo "Settings: $ENV_FILE    Messages: $STATE_DIR"
echo "Logs:     journalctl -u $SERVICE -f"
echo "Remove:   bash $SRC_DIR/deploy/install.sh --uninstall"
if [ -z "$FW" ]; then
  echo
  warn "No active ufw/firewalld found. If the site does not open from outside, allow TCP port $APP_PORT"
  warn "in your hosting provider's firewall panel."
fi
