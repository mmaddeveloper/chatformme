#!/usr/bin/env bash
# chatformme installer, written to be safe on a server that already runs other things.
#
# What it does:
#   - copies the app into /opt/chatformme (refuses if that folder belongs to something else)
#   - uses the system Node.js if it is v18 or newer; otherwise downloads a private
#     Node.js into /opt/chatformme/node (the system's own Node.js is left untouched)
#   - picks a free TCP port (3000, or the next free one); never takes a port in use
#   - creates /etc/chatformme.env with a random ADMIN_KEY (an existing file is kept)
#   - installs and starts the systemd service "chatformme", sandboxed with its own
#     throwaway user, a read-only view of the system and a memory cap
#   - opens only the ports it uses in ufw or firewalld, and only if one is active
#   - installs the command "chatformme-update" for later updates
#   - if the new version does not start, puts the previous version back
# Optional HTTPS:
#   - DOMAIN=chat.example.ir  free Let's Encrypt certificate, renewed automatically.
#     If nginx already serves port 80, it adds one separate nginx site for that domain
#     (checked with "nginx -t" first and removed again if anything fails); otherwise the
#     app serves HTTPS itself. Never edits other sites.
#   - SSL=self-signed  HTTPS without a domain (browsers show a warning once).
# It does not touch apache, other services or existing firewall rules, and installs
# no system packages except certbot when DOMAIN is used and certbot is missing.
#
# Usage, as root, from a copy of this repository:
#   bash deploy/install.sh
#   DOMAIN=chat.example.ir bash deploy/install.sh
#   SSL=self-signed bash deploy/install.sh
# Other optional settings:
#   PORT=3005  HTTPS_PORT=8443  ACME_EMAIL=you@example.com  CHAT_TITLE='...'  CHAT_PASSWORD='...'
#   SSL=off (go back to plain HTTP)
# Remove everything it installed (messages are kept unless you delete them):
#   bash deploy/install.sh --uninstall

set -euo pipefail

APP_DIR=/opt/chatformme
STATE_DIR=/var/lib/chatformme
ENV_FILE=/etc/chatformme.env
UNIT=/etc/systemd/system/chatformme.service
SERVICE=chatformme
CONF="$APP_DIR/install.conf"          # what the installer chose (mode, ports, source)
RUNTIME="$APP_DIR/runtime.env"        # settings the installer manages for the service
TLS_DIR=/etc/chatformme/tls
TLS_GROUP=chatformme-tls
ACME_ROOT=/var/lib/chatformme-acme
UPDATE_CMD=/usr/local/sbin/chatformme-update
MARKER='# managed-by: chatformme-install'
NODE_MIN=18
NODE_LINE=22
DEFAULT_REPO=mmaddeveloper/chatformme
DEFAULT_BRANCH=claude/tender-albattani-bgu8mb
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

say()  { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!!\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31mError:\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "run this as root:  sudo bash deploy/install.sh"
command -v systemctl >/dev/null 2>&1 || die "this installer needs systemd"

ours_unit() { [ -f "$UNIT" ] && grep -qF "$MARKER" "$UNIT"; }
ours_dir()  { [ -f "$APP_DIR/.chatformme" ]; }
ours_file() { [ -f "$1" ] && grep -qF "$MARKER" "$1"; }
conf_get()  { if [ -f "$CONF" ]; then grep -E "^$1=" "$CONF" | tail -n 1 | cut -d= -f2- || true; fi; }
env_get()   { if [ -f "$ENV_FILE" ]; then grep -E "^$1=" "$ENV_FILE" | tail -n 1 | cut -d= -f2- || true; fi; }

close_firewall() {
  [ -f "$APP_DIR/.firewall" ] || return 0
  while read -r fw port; do
    case "$fw" in
      ufw) ufw delete allow "$port/tcp" >/dev/null 2>&1 || true ;;
      firewalld) firewall-cmd --permanent --remove-port="$port/tcp" >/dev/null 2>&1 || true ;;
    esac
  done < "$APP_DIR/.firewall"
  if command -v firewall-cmd >/dev/null 2>&1; then firewall-cmd --reload >/dev/null 2>&1 || true; fi
  rm -f "$APP_DIR/.firewall"
}

reload_nginx() { nginx -t >/dev/null 2>&1 && systemctl reload nginx >/dev/null 2>&1; }

# ---------------------------------------------------------------- uninstall
if [ "${1:-}" = "--uninstall" ]; then
  if ours_unit; then
    systemctl disable --now "$SERVICE" >/dev/null 2>&1 || true
    rm -f "$UNIT"
    systemctl daemon-reload
    say "service removed"
  fi
  for f in /etc/nginx/conf.d/chatformme-*.conf /etc/nginx/sites-available/chatformme-*; do
    if ours_file "$f"; then
      rm -f "$f" "/etc/nginx/sites-enabled/$(basename "$f")"
      reload_nginx || warn "nginx did not reload; check it with: nginx -t"
      say "removed nginx site $f"
    fi
  done
  OLD_DOMAIN="$(conf_get DOMAIN)"
  if [ "$(conf_get SSL_MODE)" = letsencrypt ] && [ -n "$OLD_DOMAIN" ] && command -v certbot >/dev/null 2>&1; then
    certbot delete --cert-name "$OLD_DOMAIN" --non-interactive >/dev/null 2>&1 || true
    say "removed the certificate for $OLD_DOMAIN"
  fi
  rm -rf "$TLS_DIR" "$ACME_ROOT"
  rmdir /etc/chatformme 2>/dev/null || true
  if getent group "$TLS_GROUP" >/dev/null 2>&1; then groupdel "$TLS_GROUP" 2>/dev/null || true; fi
  if ours_file "$UPDATE_CMD"; then rm -f "$UPDATE_CMD"; fi
  if ours_dir; then
    close_firewall
    rm -rf "$APP_DIR"
    say "removed $APP_DIR"
  fi
  echo "Kept the settings in $ENV_FILE and the messages and accounts in $STATE_DIR."
  echo "To delete those too:  rm -rf $ENV_FILE /var/lib/private/chatformme $STATE_DIR"
  exit 0
fi

# ---------------------------------------------------------------- checks
[ -f "$SRC_DIR/server.js" ] && [ -d "$SRC_DIR/lib" ] && [ -d "$SRC_DIR/public" ] || die "run this from a copy of the chatformme repository"
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
  NTMP="$(mktemp -d)"
  BASE="https://nodejs.org/dist/latest-v${NODE_LINE}.x"
  fetch "$BASE/SHASUMS256.txt" "$NTMP/SHASUMS256.txt" \
    || die "could not reach nodejs.org; install Node.js $NODE_MIN+ yourself and run again"
  FILE="$(grep -oE "node-v[0-9.]+-linux-${ARCH}\.tar\.gz" "$NTMP/SHASUMS256.txt" | head -n 1)"
  [ -n "$FILE" ] || die "could not find a Node.js build for linux-$ARCH"
  fetch "$BASE/$FILE" "$NTMP/$FILE" || die "download of $FILE failed"
  (cd "$NTMP" && grep "  $FILE\$" SHASUMS256.txt | sha256sum -c - >/dev/null) || die "checksum of $FILE does not match"
  mkdir -p "$APP_DIR/node"
  touch "$APP_DIR/.chatformme"
  tar -xzf "$NTMP/$FILE" -C "$APP_DIR/node" --strip-components=1
  rm -rf "$NTMP"
  NODE_BIN="$APP_DIR/node/bin/node"
fi
say "Node.js $("$NODE_BIN" -v) at $NODE_BIN"

# ---------------------------------------------------------------- ports
OUR_PID="$(systemctl show -p MainPID --value "$SERVICE" 2>/dev/null || echo 0)"
# Prints "<program> <pid>" for whatever listens on the port, nothing if it is free.
port_owner() { "$NODE_BIN" "$SRC_DIR/deploy/port-owner.js" "$1" 2>/dev/null || true; }
port_ok() {   # free, or held by this app's own running service
  local o; o="$(port_owner "$1")"
  [ -z "$o" ] || { [ "${OUR_PID:-0}" != 0 ] && [ "${o##* }" = "$OUR_PID" ]; }
}
first_free() { local p; for p in $(seq "$1" "$2"); do if port_ok "$p"; then echo "$p"; return 0; fi; done; return 1; }

WANT_PORT="${PORT:-$(env_get PORT)}"
if [ -n "$WANT_PORT" ]; then
  port_ok "$WANT_PORT" || die "port $WANT_PORT is already used by another program ($(port_owner "$WANT_PORT")); choose another: PORT=3005 bash deploy/install.sh"
  APP_PORT="$WANT_PORT"
else
  APP_PORT="$(first_free 3000 3100)" || die "no free port between 3000 and 3100"
fi
say "app port $APP_PORT"

# ---------------------------------------------------------------- HTTPS mode
DOMAIN="${DOMAIN:-}"
case "${SSL:-}" in
  off) SSL_MODE=none; DOMAIN="" ;;
  self-signed) SSL_MODE=self-signed; DOMAIN="" ;;
  "") if [ -n "$DOMAIN" ]; then SSL_MODE=letsencrypt
      else SSL_MODE="$(conf_get SSL_MODE)"; SSL_MODE="${SSL_MODE:-none}"; DOMAIN="$(conf_get DOMAIN)"; fi ;;
  *) die "SSL must be 'self-signed' or 'off' (for a real certificate use DOMAIN=your.domain)" ;;
esac
if [ "$SSL_MODE" = letsencrypt ]; then
  DOMAIN="$(printf '%s' "$DOMAIN" | tr 'A-Z' 'a-z')"
  echo "$DOMAIN" | grep -qE '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$' || die "\"$DOMAIN\" does not look like a domain name"
fi

# ---------------------------------------------------------------- app files (old copy kept for rollback)
mkdir -p "$APP_DIR"
touch "$APP_DIR/.chatformme"
rm -rf "$APP_DIR/app.new" "$APP_DIR/app.prev"
mkdir -p "$APP_DIR/app.new"
cp -r "$SRC_DIR/server.js" "$SRC_DIR/package.json" "$SRC_DIR/lib" "$SRC_DIR/public" "$APP_DIR/app.new/"
mkdir -p "$APP_DIR/app.new/deploy"
cp "$SRC_DIR/deploy/port-owner.js" "$APP_DIR/app.new/deploy/"
if [ -d "$APP_DIR/app" ]; then mv "$APP_DIR/app" "$APP_DIR/app.prev"; fi
mv "$APP_DIR/app.new" "$APP_DIR/app"
for f in "$UNIT" "$RUNTIME"; do
  if [ -f "$f" ]; then cp "$f" "$f.prev"; else rm -f "$f.prev"; fi
done
chmod -R a+rX "$APP_DIR"
say "app copied to $APP_DIR/app"

# ---------------------------------------------------------------- settings
# Double quotes keep spaces intact for systemd (and for anyone who sources the file).
quote() { local v="${1//\\/\\\\}"; printf '"%s"' "${v//\"/\\\"}"; }
new_key() { head -c 32 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 24; }

if [ ! -f "$ENV_FILE" ]; then
  (
    umask 077
    {
      echo "# chatformme settings. After editing:  systemctl restart chatformme"
      echo "PORT=$APP_PORT"
      echo "ADMIN_KEY=$(new_key)"
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
  # Older installs may have a key the server now refuses as too short.
  KEY="$(env_get ADMIN_KEY)"
  if [ "${#KEY}" -lt 12 ]; then
    set_env ADMIN_KEY "$(new_key)"
    warn "the admin key was missing or shorter than 12 characters; a new one was made (printed at the end)"
  fi
  chmod 600 "$ENV_FILE"
  say "kept existing settings in $ENV_FILE"
fi

# ---------------------------------------------------------------- service
# write_service <tls group yes/no> <bind low ports yes/no> then KEY=VALUE lines for the runtime file
write_service() {
  local tls_group="$1" low_ports="$2"
  shift 2
  ( umask 022; printf '%s\n' "$MARKER" "$@" > "$RUNTIME" )
  {
    echo "$MARKER"
    echo "[Unit]"
    echo "Description=chatformme (message us site)"
    echo "After=network.target"
    echo
    echo "[Service]"
    echo "ExecStart=$NODE_BIN $APP_DIR/app/server.js"
    echo "ExecReload=/bin/kill -HUP \$MAINPID"
    echo "WorkingDirectory=$APP_DIR/app"
    echo "Environment=DATA_DIR=$STATE_DIR"
    echo "EnvironmentFile=$ENV_FILE"
    echo "# Managed by the installer; values here win over $ENV_FILE."
    echo "EnvironmentFile=$RUNTIME"
    echo "Restart=always"
    echo "RestartSec=2"
    echo
    echo "# Sandbox: a throwaway user that can only write its own data folder,"
    echo "# so this app cannot affect anything else running on the server."
    echo "DynamicUser=yes"
    echo "StateDirectory=chatformme"
    echo "NoNewPrivileges=yes"
    echo "ProtectSystem=strict"
    echo "ProtectHome=yes"
    echo "PrivateTmp=yes"
    echo "PrivateDevices=yes"
    echo "ProtectKernelTunables=yes"
    echo "ProtectKernelModules=yes"
    echo "ProtectControlGroups=yes"
    echo "RestrictSUIDSGID=yes"
    echo "LockPersonality=yes"
    echo "MemoryMax=300M"
    if [ "$tls_group" = yes ]; then echo "SupplementaryGroups=$TLS_GROUP"; fi
    if [ "$low_ports" = yes ]; then
      echo "AmbientCapabilities=CAP_NET_BIND_SERVICE"
      echo "CapabilityBoundingSet=CAP_NET_BIND_SERVICE"
    else
      echo "CapabilityBoundingSet="
    fi
    echo
    echo "[Install]"
    echo "WantedBy=multi-user.target"
  } > "$UNIT"
  systemctl daemon-reload
  systemctl enable "$SERVICE" >/dev/null 2>&1
}

# health <http|https> <port> [server name] [CA file]
health() {
  local i
  for i in $(seq 1 30); do
    if "$NODE_BIN" -e '
      const [scheme, port, name, ca] = process.argv.slice(1);
      const mod = require(scheme);
      const o = { host: "127.0.0.1", port: +port, path: "/api/config", timeout: 3000 };
      if (scheme === "https") { o.servername = name || "localhost"; if (ca) o.ca = require("fs").readFileSync(ca); }
      mod.get(o, (r) => process.exit(r.statusCode === 200 ? 0 : 1)).on("error", () => process.exit(1));
    ' "$1" "$2" "${3:-}" "${4:-}" 2>/dev/null; then
      return 0
    fi
    sleep 0.5
  done
  return 1
}

# Health check for the previous install, using what it recorded in install.conf.
previous_health() {
  case "$(conf_get SSL_MODE)" in
    self-signed) health https "$(conf_get APP_PORT)" localhost "$TLS_DIR/cert.pem" ;;
    letsencrypt)
      if [ "$(conf_get PROXY)" = nginx ]; then health http "$(conf_get APP_PORT)"
      else health https "$(conf_get HTTPS_PORT)" "$(conf_get DOMAIN)"; fi ;;
    *) health http "$(conf_get APP_PORT)" ;;
  esac
}

rollback() {
  warn "$1"
  journalctl -u "$SERVICE" -n 25 --no-pager 2>/dev/null || true
  if [ -d "$APP_DIR/app.prev" ]; then
    rm -rf "$APP_DIR/app.failed"
    mv "$APP_DIR/app" "$APP_DIR/app.failed"
    mv "$APP_DIR/app.prev" "$APP_DIR/app"
    for f in "$UNIT" "$RUNTIME"; do if [ -f "$f.prev" ]; then cp "$f.prev" "$f"; fi; done
    systemctl daemon-reload
    systemctl restart "$SERVICE" || true
    if previous_health; then
      die "the new version did not start, so the previous version was put back and is running again (the failed copy is in $APP_DIR/app.failed)"
    fi
    die "the new version did not start; the previous version was put back but is not answering either. Check: journalctl -u $SERVICE"
  fi
  die "the service did not start; the log is above"
}

ensure_tls_group() {
  getent group "$TLS_GROUP" >/dev/null 2>&1 || groupadd --system "$TLS_GROUP"
  install -d -m 750 -o root -g "$TLS_GROUP" "$TLS_DIR"
}

# Opens the ports in open_ports in an active ufw/firewalld (only rules it adds are recorded).
apply_firewall() {
close_firewall
FW=""
for p in "${open_ports[@]}"; do
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
    if ! ufw status 2>/dev/null | grep -qE "^$p(/tcp)?\s+ALLOW"; then
      ufw allow "$p/tcp" comment chatformme >/dev/null && echo "ufw $p" >> "$APP_DIR/.firewall"
    fi
    FW=ufw
  elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
    if ! firewall-cmd --query-port="$p/tcp" >/dev/null 2>&1; then
      firewall-cmd --permanent --add-port="$p/tcp" >/dev/null && echo "firewalld $p" >> "$APP_DIR/.firewall"
    fi
    FW=firewalld
  fi
done
if [ "$FW" = firewalld ]; then firewall-cmd --reload >/dev/null 2>&1 || true; fi
if [ -n "$FW" ]; then say "port(s) ${open_ports[*]} open in $FW"; fi
}

open_ports=()
public_url=""
note=""

case "$SSL_MODE" in
  none)
    write_service no no "HOST=0.0.0.0"
    systemctl restart "$SERVICE"
    health http "$APP_PORT" || rollback "the service did not answer on port $APP_PORT"
    open_ports=("$APP_PORT")
    ;;

  self-signed)
    ensure_tls_group
    if [ ! -s "$TLS_DIR/cert.pem" ] || [ "$(conf_get SSL_MODE)" != self-signed ]; then
      command -v openssl >/dev/null 2>&1 || die "openssl is needed to make a certificate"
      san="DNS:localhost,IP:127.0.0.1"
      for ip in $(hostname -I 2>/dev/null) ${PUBLIC_IP:-}; do san="$san,IP:$ip"; done
      openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 3650 -subj "/CN=chatformme" \
        -addext "subjectAltName=$san" -keyout "$TLS_DIR/key.pem" -out "$TLS_DIR/cert.pem" >/dev/null 2>&1 \
        || die "openssl could not make a certificate"
      say "made a self-signed certificate (valid 10 years)"
    fi
    chown root:"$TLS_GROUP" "$TLS_DIR/cert.pem" "$TLS_DIR/key.pem"
    chmod 640 "$TLS_DIR/cert.pem" "$TLS_DIR/key.pem"
    write_service yes no "HOST=0.0.0.0" "TLS_CERT=$TLS_DIR/cert.pem" "TLS_KEY=$TLS_DIR/key.pem"
    systemctl restart "$SERVICE"
    health https "$APP_PORT" localhost "$TLS_DIR/cert.pem" || rollback "the service did not answer on https port $APP_PORT"
    open_ports=("$APP_PORT")
    note="self-signed"
    ;;

  letsencrypt)
    LIVE="/etc/letsencrypt/live/$DOMAIN"
    # Who answers on port 80 decides how certificates are validated and who serves HTTPS.
    OWNER80="$(port_owner 80)"
    if port_ok 80; then
      PROXY=node
    elif [ "${OWNER80%% *}" = nginx ]; then
      PROXY=nginx
    else
      die "port 80 is used by \"${OWNER80%% *}\"; a free certificate needs port 80. Free it, or use SSL=self-signed"
    fi
    if [ -n "${HTTPS_PORT:-}" ]; then
      TLS_PORT="$HTTPS_PORT"
    elif [ -n "$(conf_get HTTPS_PORT)" ] && [ "$(conf_get PROXY)" = "$PROXY" ]; then
      TLS_PORT="$(conf_get HTTPS_PORT)"
    else
      TLS_PORT=443
    fi
    OWNER_TLS="$(port_owner "$TLS_PORT")"
    if ! port_ok "$TLS_PORT" && ! { [ "$PROXY" = nginx ] && [ "${OWNER_TLS%% *}" = nginx ]; }; then
      [ -z "${HTTPS_PORT:-}" ] || die "port $TLS_PORT is used by \"${OWNER_TLS%% *}\"; choose another HTTPS_PORT"
      warn "port 443 is used by \"${OWNER_TLS%% *}\"; using another port for HTTPS"
      TLS_PORT="$(first_free 8443 8499)" || die "no free port for HTTPS between 8443 and 8499"
    fi
    if [ "$TLS_PORT" = 443 ]; then HTTPS_URL="https://$DOMAIN"; else HTTPS_URL="https://$DOMAIN:$TLS_PORT"; fi
    say "HTTPS for $DOMAIN on port $TLS_PORT (served by $PROXY)"

    if ! getent ahosts "$DOMAIN" >/dev/null 2>&1; then
      warn "$DOMAIN does not resolve yet; point its DNS (A record) at this server first"
    fi

    install -d -m 755 "$ACME_ROOT/.well-known/acme-challenge"

    if [ "$PROXY" = nginx ]; then
      command -v nginx >/dev/null 2>&1 || die "nginx is listening on port 80 but the nginx command is missing"
      nginx -t >/dev/null 2>&1 || die "nginx's configuration already has errors (see: nginx -t); not touching it"
      DUMP="$(nginx -T 2>/dev/null || true)"
      if grep -qE '^\s*include\s+/etc/nginx/conf\.d/\*\.conf' <<<"$DUMP" && [ -d /etc/nginx/conf.d ]; then
        NGINX_FILE="/etc/nginx/conf.d/chatformme-$DOMAIN.conf"; NGINX_LINK=""
      elif grep -qE '^\s*include\s+/etc/nginx/sites-enabled/' <<<"$DUMP" && [ -d /etc/nginx/sites-available ]; then
        NGINX_FILE="/etc/nginx/sites-available/chatformme-$DOMAIN"; NGINX_LINK="/etc/nginx/sites-enabled/chatformme-$DOMAIN"
      else
        die "could not find where nginx loads its sites (conf.d or sites-enabled)"
      fi
      # Another site already using this domain name? Then it is not ours to change.
      NAMES="$(grep -E '^\s*server_name\s' <<<"$DUMP" || true)"
      DOMAIN_RE="$(printf '%s' "$DOMAIN" | sed 's/\./\\./g')"
      if grep -qE "\s${DOMAIN_RE}(\s|;|\$)" <<<"$NAMES" && ! ours_file "$NGINX_FILE"; then
        die "nginx already has a site for $DOMAIN; not touching it"
      fi
      IPV6_LISTEN=""
      if [ -f /proc/net/if_inet6 ]; then IPV6_LISTEN=yes; fi

      # nginx_site <with https: yes/no>
      nginx_site() {
        echo "$MARKER"
        echo "# chatformme for $DOMAIN. Removed by: bash deploy/install.sh --uninstall"
        echo "server {"
        echo "    listen 80;"
        if [ -n "$IPV6_LISTEN" ]; then echo "    listen [::]:80;"; fi
        echo "    server_name $DOMAIN;"
        echo "    location ^~ /.well-known/acme-challenge/ { root $ACME_ROOT; default_type text/plain; }"
        if [ "$1" = yes ]; then
          echo "    location / { return 301 $HTTPS_URL\$request_uri; }"
          echo "}"
          echo "server {"
          echo "    listen $TLS_PORT ssl;"
          if [ -n "$IPV6_LISTEN" ]; then echo "    listen [::]:$TLS_PORT ssl;"; fi
          echo "    server_name $DOMAIN;"
          echo "    ssl_certificate $LIVE/fullchain.pem;"
          echo "    ssl_certificate_key $LIVE/privkey.pem;"
          echo "    ssl_protocols TLSv1.2 TLSv1.3;"
        fi
        echo "    client_max_body_size 64k;"
        echo "    location / {"
        echo "        proxy_pass http://127.0.0.1:$APP_PORT;"
        echo "        proxy_http_version 1.1;"
        echo "        proxy_set_header Host \$host;"
        echo "        proxy_set_header X-Forwarded-For \$remote_addr;"
        if [ "$1" = yes ]; then echo "        proxy_set_header X-Forwarded-Proto https;"; fi
        echo "        proxy_set_header Connection \"\";"
        echo "        proxy_buffering off;"
        echo "        proxy_cache off;"
        echo "        proxy_read_timeout 1h;"
        echo "    }"
        echo "}"
      }
      # Write our site, test the whole nginx configuration, and undo our change if it fails.
      apply_nginx() {
        local backup=""
        if [ -f "$NGINX_FILE" ]; then backup="$(mktemp)"; cp "$NGINX_FILE" "$backup"; fi
        nginx_site "$1" > "$NGINX_FILE"
        if [ -n "$NGINX_LINK" ]; then ln -sfn "$NGINX_FILE" "$NGINX_LINK"; fi
        if reload_nginx; then rm -f "$backup"; return 0; fi
        if [ -n "$backup" ]; then cp "$backup" "$NGINX_FILE"; rm -f "$backup"
        else rm -f "$NGINX_FILE"; if [ -n "$NGINX_LINK" ]; then rm -f "$NGINX_LINK"; fi; fi
        reload_nginx || true
        return 1
      }
      write_service no no "HOST=127.0.0.1" "TRUST_PROXY=1"
      systemctl restart "$SERVICE"
      health http "$APP_PORT" || rollback "the service did not answer on port $APP_PORT"
      if [ ! -s "$LIVE/fullchain.pem" ]; then
        apply_nginx no || die "nginx rejected the site for $DOMAIN; nothing was changed"
      fi
    else
      # The app itself answers on port 80 for validation and redirects; HTTPS comes once the certificate exists.
      write_service no yes "HOST=0.0.0.0" "HTTP_PORT=80" "ACME_WEBROOT=$ACME_ROOT"
      systemctl restart "$SERVICE"
      health http "$APP_PORT" || rollback "the service did not answer on port $APP_PORT"
    fi

    # The renewal hook runs on every renewal (certbot's own timer) and once now.
    cat > "$APP_DIR/tls-deploy.sh" <<EOF
#!/bin/sh
$MARKER
# Run by certbot after it renews the certificate for $DOMAIN.
set -e
if [ "$PROXY" = nginx ]; then
  nginx -t >/dev/null 2>&1 && systemctl reload nginx
else
  install -m 640 -o root -g $TLS_GROUP "$LIVE/fullchain.pem" "$TLS_DIR/cert.pem"
  install -m 640 -o root -g $TLS_GROUP "$LIVE/privkey.pem" "$TLS_DIR/key.pem"
  systemctl reload $SERVICE || systemctl restart $SERVICE
fi
EOF
    chmod 755 "$APP_DIR/tls-deploy.sh"
    if [ "$PROXY" = node ]; then ensure_tls_group; fi

    open_ports=(80 "$TLS_PORT")
    if [ "$PROXY" = node ]; then open_ports+=("$APP_PORT"); fi
    apply_firewall   # validation needs port 80 reachable from outside
    if [ ! -s "$LIVE/fullchain.pem" ]; then
      if ! command -v certbot >/dev/null 2>&1; then
        say "installing certbot (the Let's Encrypt client)"
        if command -v apt-get >/dev/null 2>&1; then
          DEBIAN_FRONTEND=noninteractive apt-get install -y certbot >/dev/null 2>&1 \
            || { apt-get update >/dev/null 2>&1 && DEBIAN_FRONTEND=noninteractive apt-get install -y certbot >/dev/null 2>&1; } \
            || die "could not install certbot"
        elif command -v dnf >/dev/null 2>&1; then dnf install -y certbot >/dev/null 2>&1 || die "could not install certbot"
        elif command -v yum >/dev/null 2>&1; then yum install -y certbot >/dev/null 2>&1 || die "could not install certbot"
        else die "certbot is not installed and no apt/dnf/yum was found to install it"; fi
      fi
      say "asking Let's Encrypt for a certificate for $DOMAIN"
      if [ -n "${ACME_EMAIL:-}" ]; then EMAIL_ARGS=(--email "$ACME_EMAIL"); else EMAIL_ARGS=(--register-unsafely-without-email); fi
      if ! certbot certonly --webroot -w "$ACME_ROOT" -d "$DOMAIN" --non-interactive --agree-tos \
           "${EMAIL_ARGS[@]}" --keep-until-expiring --deploy-hook "$APP_DIR/tls-deploy.sh"; then
        if [ "$PROXY" = nginx ]; then HTTP_URL="http://$DOMAIN"; else HTTP_URL="http://$DOMAIN:$APP_PORT"; fi
        warn "no certificate yet. The site keeps working over plain HTTP: $HTTP_URL"
        warn "Usual causes: the domain's DNS does not point at this server yet, or port 80 is blocked"
        warn "by the hosting provider's firewall. Fix that and run this installer again."
        rm -f "$APP_DIR/app.prev" "$UNIT.prev" "$RUNTIME.prev"
        exit 1
      fi
    fi
    "$APP_DIR/tls-deploy.sh" || true

    if [ "$PROXY" = nginx ]; then
      apply_nginx yes || die "nginx rejected the HTTPS site for $DOMAIN; your other sites were left as they were"
      health https "$TLS_PORT" "$DOMAIN" || warn "nginx did not answer over HTTPS yet; check: nginx -t and journalctl -u nginx"
      open_ports=(80 "$TLS_PORT")
    else
      write_service yes yes "HOST=0.0.0.0" "PORT=$TLS_PORT" "TLS_CERT=$TLS_DIR/cert.pem" "TLS_KEY=$TLS_DIR/key.pem" \
        "HTTP_PORT=80" "ACME_WEBROOT=$ACME_ROOT" "HTTPS_URL=$HTTPS_URL"
      systemctl restart "$SERVICE"
      health https "$TLS_PORT" "$DOMAIN" || rollback "the service did not answer over HTTPS on port $TLS_PORT"
      open_ports=(80 "$TLS_PORT")
    fi
    public_url="$HTTPS_URL"
    ;;
esac

rm -rf "$APP_DIR/app.prev" "$APP_DIR/app.failed"
rm -f "$UNIT.prev" "$RUNTIME.prev"

# Switching away from a domain: remove our nginx site and certificate for the old one.
OLD_DOMAIN="$(conf_get DOMAIN)"
if [ -n "$OLD_DOMAIN" ] && [ "$OLD_DOMAIN" != "$DOMAIN" ]; then
  for f in "/etc/nginx/conf.d/chatformme-$OLD_DOMAIN.conf" "/etc/nginx/sites-available/chatformme-$OLD_DOMAIN"; do
    if ours_file "$f"; then rm -f "$f" "/etc/nginx/sites-enabled/chatformme-$OLD_DOMAIN"; reload_nginx || true; fi
  done
fi

# ---------------------------------------------------------------- firewall
apply_firewall

# ---------------------------------------------------------------- update command and record
install -m 755 "$SRC_DIR/deploy/update.sh" "$UPDATE_CMD"
{
  echo "$MARKER"
  echo "SSL_MODE=$SSL_MODE"
  echo "DOMAIN=$DOMAIN"
  echo "PROXY=${PROXY:-}"
  echo "HTTPS_PORT=${TLS_PORT:-}"
  echo "APP_PORT=$APP_PORT"
  echo "REPO=${CHATFORMME_REPO:-$(conf_get REPO)}"
  echo "BRANCH=${CHATFORMME_BRANCH:-$(conf_get BRANCH)}"
  echo "COMMIT=${CHATFORMME_COMMIT:-}"
  echo "INSTALLED=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} > "$CONF.new"
sed -i "s#^REPO=\$#REPO=$DEFAULT_REPO#; s#^BRANCH=\$#BRANCH=$DEFAULT_BRANCH#" "$CONF.new"
mv "$CONF.new" "$CONF"

# ---------------------------------------------------------------- done
echo
say "Done."
if [ -n "$public_url" ]; then
  echo "Address: $public_url"
else
  scheme=http
  if [ "$SSL_MODE" = self-signed ]; then scheme=https; fi
  echo "Addresses (give the public one to people):"
  for ip in $(hostname -I 2>/dev/null); do
    case "$ip" in *:*) echo "  $scheme://[$ip]:$APP_PORT" ;; *) echo "  $scheme://$ip:$APP_PORT" ;; esac
  done
fi
if [ "$note" = self-signed ]; then
  echo
  warn "The certificate is self-signed: browsers show a warning the first time. That is expected;"
  warn "people can check they reached the right site by comparing this fingerprint:"
  openssl x509 -noout -fingerprint -sha256 -in "$TLS_DIR/cert.pem" | sed 's/^/   /'
fi
echo
echo "Admin key (use it on the site under «ورود مدیر»; keep it secret):"
echo "  $(env_get ADMIN_KEY)"
echo
echo "Update later:  chatformme-update"
echo "Settings: $ENV_FILE    Messages and accounts: $STATE_DIR"
echo "Logs:     journalctl -u $SERVICE -f"
echo "Remove:   bash $SRC_DIR/deploy/install.sh --uninstall"
if [ -z "$FW" ]; then
  echo
  warn "No active ufw/firewalld found. If the site does not open from outside, allow TCP port(s)"
  warn "${open_ports[*]} in your hosting provider's firewall panel."
fi
