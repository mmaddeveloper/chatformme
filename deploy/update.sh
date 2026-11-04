#!/usr/bin/env bash
# managed-by: chatformme-install
#
# chatformme-update: bring an installed chatformme up to the latest code.
# Messages, accounts, settings and the HTTPS setup are kept. If the new version
# does not start, the installer puts the previous version back automatically.
#
#   chatformme-update                 update from the branch it was installed from
#   chatformme-update --check         only say whether an update is available
#   chatformme-update --branch main   switch to another branch and update
#   chatformme-update --force         reinstall even if already up to date
#
# Note: this runs the installer from the downloaded code as root, so only point
# it at a repository and branch you control.

set -euo pipefail

CONF=/opt/chatformme/install.conf
say()  { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31mError:\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "run this as root:  sudo chatformme-update"
[ -f "$CONF" ] || die "chatformme does not seem to be installed ($CONF is missing)"

conf_get() { grep -E "^$1=" "$CONF" | tail -n 1 | cut -d= -f2- || true; }

REPO="$(conf_get REPO)"
BRANCH="$(conf_get BRANCH)"
CURRENT="$(conf_get COMMIT)"
CHECK=""
FORCE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --check) CHECK=1 ;;
    --force) FORCE=1 ;;
    --branch) shift; BRANCH="${1:-}" ;;
    --branch=*) BRANCH="${1#--branch=}" ;;
    *) die "unknown option: $1" ;;
  esac
  shift
done
[ -n "$REPO" ] && [ -n "$BRANCH" ] || die "no source recorded in $CONF; run the installer from a fresh copy once"
case "$REPO$BRANCH" in *[!A-Za-z0-9._/-]*) die "unexpected repository or branch name" ;; esac

fetch() {
  if command -v curl >/dev/null 2>&1; then curl -fsSL --retry 3 --connect-timeout 20 -o "$2" "$1"
  elif command -v wget >/dev/null 2>&1; then wget -q -O "$2" "$1"
  else die "neither curl nor wget is installed"; fi
}

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# Which commit is the newest on that branch? (Not fatal if GitHub's API is unreachable.)
LATEST=""
if fetch "https://api.github.com/repos/$REPO/commits/$BRANCH" "$TMP/commit.json" 2>/dev/null; then
  LATEST="$(grep -m 1 -oE '"sha": *"[0-9a-f]{40}"' "$TMP/commit.json" | grep -oE '[0-9a-f]{40}' || true)"
fi

if [ -n "$LATEST" ] && [ "$LATEST" = "$CURRENT" ] && [ -z "$FORCE" ]; then
  say "already up to date (${CURRENT:0:7} on $BRANCH)"
  exit 0
fi
if [ -n "$CHECK" ]; then
  if [ -n "$LATEST" ]; then
    say "update available: ${CURRENT:0:7} -> ${LATEST:0:7} on $BRANCH. Run: chatformme-update"
  else
    say "could not ask GitHub for the latest version; run chatformme-update to update anyway"
  fi
  exit 0
fi

if [ -n "$LATEST" ]; then REF="$LATEST"; else REF="refs/heads/$BRANCH"; fi
say "downloading $REPO ($BRANCH${LATEST:+, ${LATEST:0:7}})"
fetch "https://codeload.github.com/$REPO/tar.gz/$REF" "$TMP/src.tar.gz" || die "download failed; is GitHub reachable from this server?"
mkdir -p "$TMP/src"
tar -xzf "$TMP/src.tar.gz" -C "$TMP/src" --strip-components=1
[ -f "$TMP/src/deploy/install.sh" ] || die "the download does not look like chatformme"

CHATFORMME_REPO="$REPO" CHATFORMME_BRANCH="$BRANCH" CHATFORMME_COMMIT="$LATEST" \
  bash "$TMP/src/deploy/install.sh"
