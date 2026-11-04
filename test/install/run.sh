#!/usr/bin/env bash
# End-to-end tests for deploy/install.sh and chatformme-update, using stand-ins
# for systemctl, certbot, nginx and GitHub (test/install/bin) and a test CA.
#
# DESTRUCTIVE: it installs into and then deletes /opt/chatformme, /etc/chatformme*,
# /var/lib/chatformme*, /etc/letsencrypt, /etc/nginx and the chatformme service.
# Run it only as root in a throwaway container or VM:
#   CHATFORMME_ITEST_OK=1 bash test/install/run.sh
[ "${CHATFORMME_ITEST_OK:-}" = 1 ] || { echo "Refusing to run: read the warning at the top of $0"; exit 2; }
[ "$(id -u)" = 0 ] || { echo "run as root (in a throwaway container)"; exit 2; }
T="$(mktemp -d)"; export CHATFORMME_ITEST="$T"
mkdir -p "$T/ca"
openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj "/CN=Test CA" -keyout "$T/ca/ca.key" -out "$T/ca/ca.pem" >/dev/null 2>&1
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export PATH="$REPO/test/install/bin:$PATH"
export NODE_EXTRA_CA_CERTS="$T/ca/ca.pem"   # lets the installer's health check trust the test CA
pass=0; fail=0
check() { if eval "$2"; then echo "PASS $1"; pass=$((pass+1)); else echo "FAIL $1"; fail=$((fail+1)); fi; }
clean() {
  systemctl stop chatformme >/dev/null 2>&1
  rm -rf /opt/chatformme /etc/chatformme /etc/chatformme.env /etc/systemd/system/chatformme.service* /var/lib/chatformme /var/lib/chatformme-acme /etc/letsencrypt /usr/local/sbin/chatformme-update /etc/nginx
  groupdel chatformme-tls 2>/dev/null; rm -f $T/calls.log $T/app.log
}
code() { curl --noproxy '*' -s -o /dev/null -w '%{http_code}' "$@"; }
tls() { curl --noproxy '*' -s --cacert "$1" --resolve "$2:${4:-443}:127.0.0.1" -o /dev/null -w '%{http_code}' "https://$2:${4:-443}$3"; }
serial() { echo | openssl s_client -connect 127.0.0.1:443 -servername chat.test.ir 2>/dev/null | openssl x509 -noout -serial; }

clean
echo "== A: plain install"
bash $REPO/deploy/install.sh > $T/a.log 2>&1; check "install exit 0" "[ $? = 0 ]"
check "http on 3000" "[ \$(code http://127.0.0.1:3000/api/config) = 200 ]"
check "update command installed" "[ -x /usr/local/sbin/chatformme-update ]"
check "source recorded" "grep -q '^BRANCH=claude/tender-albattani-bgu8mb' /opt/chatformme/install.conf"
KEY1=$(grep ^ADMIN_KEY= /etc/chatformme.env)

echo "== B: self-signed"
SSL=self-signed bash $REPO/deploy/install.sh > $T/b.log 2>&1; check "install exit 0" "[ $? = 0 ]"
check "https on 3000 verifies against its own cert" "[ \$(tls /etc/chatformme/tls/cert.pem localhost /api/config 3000) = 200 ]"
check "plain http refused on 3000" "[ \$(code http://127.0.0.1:3000/api/config) != 200 ]"
check "fingerprint printed" "grep -qi 'sha256 Fingerprint' $T/b.log"
check "admin key kept" "[ \"$KEY1\" = \"\$(grep ^ADMIN_KEY= /etc/chatformme.env)\" ]"
check "key readable only by root and the service group" "[ \"\$(stat -c %a:%G /etc/chatformme/tls/key.pem)\" = 640:chatformme-tls ]"

echo "== C: Let's Encrypt, app serves HTTPS itself (port 80 free)"
DOMAIN=chat.test.ir bash $REPO/deploy/install.sh > $T/c.log 2>&1; check "install exit 0" "[ $? = 0 ]"
check "certbot used webroot with deploy hook" "grep -q 'certbot certonly --webroot -w /var/lib/chatformme-acme -d chat.test.ir' $T/calls.log"
check "https on 443 with the domain" "[ \$(tls $T/ca/ca.pem chat.test.ir /api/config) = 200 ]"
check "port 80 redirects to https" "[ \"\$(curl -s -o /dev/null -w '%{redirect_url}' http://127.0.0.1/abc?x=1)\" = 'https://chat.test.ir/abc?x=1' ]"
check "unit can bind low ports" "grep -q 'AmbientCapabilities=CAP_NET_BIND_SERVICE' /etc/systemd/system/chatformme.service"
check "address printed" "grep -q 'Address: https://chat.test.ir' $T/c.log"
S1=$(serial)
DAYS=60 certbot certonly --webroot -w /var/lib/chatformme-acme -d chat.test.ir --deploy-hook /opt/chatformme/tls-deploy.sh >/dev/null 2>&1
sleep 0.5
check "renewal served without restart" "[ \"$S1\" != \"\$(serial)\" ] && grep -q 'Reloaded the TLS certificate' $T/app.log"
: > $T/calls.log
bash $REPO/deploy/install.sh > $T/c2.log 2>&1; check "re-run keeps HTTPS" "[ $? = 0 ] && [ \$(tls $T/ca/ca.pem chat.test.ir /api/config) = 200 ]"
check "re-run does not ask for a new certificate" "! grep -q 'certbot certonly' $T/calls.log"

echo "== D: chatformme-update and rollback"
SRC=$T/src-good; rm -rf $SRC; mkdir -p $SRC; (cd $REPO && tar --exclude=.git --exclude=node_modules -cf - .) | tar -xf - -C $SRC
echo "// version 2" >> $SRC/server.js
tar -czf $T/next.tar.gz -C $T src-good --transform 's#^src-good#chatformme-abc#'
printf '%040d' 2 > $T/next-sha
chatformme-update > $T/d1.log 2>&1; check "update exit 0" "[ $? = 0 ]"
check "new code installed" "tail -1 /opt/chatformme/app/server.js | grep -q 'version 2'"
check "commit recorded" "grep -q \"^COMMIT=\$(cat $T/next-sha)\" /opt/chatformme/install.conf"
check "still serving https" "[ \$(tls $T/ca/ca.pem chat.test.ir /api/config) = 200 ]"
chatformme-update > $T/d2.log 2>&1; check "second run says up to date" "grep -q 'already up to date' $T/d2.log"
SRC=$T/src-bad; rm -rf $SRC; cp -r $T/src-good $SRC; echo 'this is not javascript (' >> $SRC/server.js
tar -czf $T/next.tar.gz -C $T src-bad --transform 's#^src-bad#chatformme-def#'
printf '%040d' 3 > $T/next-sha
chatformme-update > $T/d3.log 2>&1; check "broken update fails" "[ $? != 0 ] && grep -q \"previous version was put back and is running again\" $T/d3.log"
check "previous version restored and serving" "tail -1 /opt/chatformme/app/server.js | grep -q 'version 2' && [ \$(tls $T/ca/ca.pem chat.test.ir /api/config) = 200 ]"
check "commit not advanced" "grep -q \"^COMMIT=\$(printf '%040d' 2)\" /opt/chatformme/install.conf"

echo "== E: uninstall"
bash $REPO/deploy/install.sh --uninstall > $T/e.log 2>&1
check "all removed" "[ ! -e /opt/chatformme ] && [ ! -e /etc/chatformme/tls ] && [ ! -e /usr/local/sbin/chatformme-update ] && [ ! -e /etc/letsencrypt/live/chat.test.ir ] && ! getent group chatformme-tls >/dev/null"
check "messages kept" "[ -e /var/lib/chatformme/journal.log ]"

clean
echo "== F: nginx already on port 80"
mkdir -p /etc/nginx/conf.d
node $REPO/test/install/fakenginx.js & NGX=$!; sleep 0.5
printf 'server {\n    server_name sub.chat.test.ir other.ir;\n}\n' > /etc/nginx/conf.d/other.conf
DOMAIN=chat.test.ir bash $REPO/deploy/install.sh > $T/f.log 2>&1; check "install exit 0" "[ $? = 0 ]"
F=/etc/nginx/conf.d/chatformme-chat.test.ir.conf
check "own nginx site written" "grep -q 'managed-by: chatformme-install' $F && grep -q 'listen 443 ssl' $F && grep -q 'proxy_pass http://127.0.0.1:3000' $F && grep -q 'proxy_buffering off' $F"
check "other site untouched" "[ \"\$(cat /etc/nginx/conf.d/other.conf)\" = \"\$(printf 'server {\n    server_name sub.chat.test.ir other.ir;\n}')\" ]"
check "app only on localhost behind the proxy" "grep -q '^HOST=127.0.0.1' /opt/chatformme/runtime.env && grep -q '^TRUST_PROXY=1' /opt/chatformme/runtime.env"
check "nginx tested before reload" "grep -q 'nginx -t' $T/calls.log"
bash $REPO/deploy/install.sh --uninstall > /dev/null 2>&1
check "uninstall removed our nginx site only" "[ ! -e $F ] && [ -e /etc/nginx/conf.d/other.conf ]"

echo "== G: another nginx site already has the domain"
printf 'server {\n    server_name chat.test.ir;\n}\n' > /etc/nginx/conf.d/taken.conf
DOMAIN=chat.test.ir bash $REPO/deploy/install.sh > $T/g.log 2>&1
check "refuses" "grep -q 'already has a site for chat.test.ir' $T/g.log && [ ! -e $F ]"
rm -f /etc/nginx/conf.d/taken.conf
bash $REPO/deploy/install.sh --uninstall > /dev/null 2>&1

echo "== H: nginx rejects the HTTPS site"
rm -rf /etc/letsencrypt
NGINX_REJECT_SSL=1 DOMAIN=chat.test.ir bash $REPO/deploy/install.sh > $T/h.log 2>&1
check "fails cleanly" "grep -q 'your other sites were left as they were' $T/h.log"
check "our site rolled back to the working HTTP version" "[ -e $F ] && ! grep -q ssl_certificate $F"
kill $NGX 2>/dev/null
bash $REPO/deploy/install.sh --uninstall > /dev/null 2>&1

echo "== I: certificate request fails"
clean
CERTBOT_FAIL=1 DOMAIN=chat.test.ir bash $REPO/deploy/install.sh > $T/i.log 2>&1
check "explains and keeps the site on http" "[ $? != 0 ] && grep -q 'keeps working over plain HTTP: http://chat.test.ir:3000' $T/i.log && [ \$(code http://127.0.0.1:3000/api/config) = 200 ]"
clean
echo "passed $pass, failed $fail"
rm -rf "$T"
[ "$fail" = 0 ]
