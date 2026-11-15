#!/usr/bin/env bash
# FUZZY installer — installs ffuf, puredns, massdns, resolvers, and the fuzzy CLI.
# Author: Kalmux

set -euo pipefail

VERSION="1.0.0"
FUZZY_HOME="${FUZZY_HOME:-$HOME/.local/share/fuzzy}"
FUZZY_BIN="${FUZZY_BIN:-$HOME/.local/bin}"
FUZZY_CONFIG="${FUZZY_CONFIG:-$HOME/.config/fuzzy}"
RESOLVER_URL="https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt"
GO_VERSION="1.22.5"
GO_MIN_MAJOR=1
GO_MIN_MINOR=21

# ── colours ──────────────────────────────────────────────────────────────
if [ -t 1 ]; then
  R=$'\033[0;31m'; G=$'\033[0;32m'; Y=$'\033[0;33m'
  C=$'\033[0;36m'; M=$'\033[0;35m'; W=$'\033[1m'; N=$'\033[0m'
else
  R=''; G=''; Y=''; C=''; M=''; W=''; N=''
fi
say()  { printf "${C}[*]${N} %s\n" "$*"; }
ok()   { printf "${G}[+]${N} %s\n" "$*"; }
warn() { printf "${Y}[!]${N} %s\n" "$*"; }
err()  { printf "${R}[x]${N} %s\n" "$*" >&2; }

banner() {
  printf "${C}"
  cat <<'EOF'
███████╗██╗   ██╗███████╗███████╗██╗   ██╗
██╔════╝██║   ██║╚══███╔╝╚══███╔╝╚██╗ ██╔╝
█████╗  ██║   ██║  ███╔╝   ███╔╝  ╚████╔╝ 
██╔══╝  ██║   ██║ ███╔╝   ███╔╝    ╚██╔╝  
██║     ╚██████╔╝███████╗███████╗   ██║   
╚═╝      ╚═════╝ ╚══════╝╚══════╝   ╚═╝   
EOF
  printf "${N}"
  printf "${M}  installer  ·  v%s  ·  by Kalmux${N}\n\n" "$VERSION"
}

banner

# ── OS / arch ────────────────────────────────────────────────────────────
case "$(uname -s)" in
  Linux)  OS="linux";;
  Darwin) OS="macos";;
  *) err "Unsupported OS: $(uname -s)"; exit 1;;
esac
case "$(uname -m)" in
  x86_64|amd64)  ARCH="amd64";;
  aarch64|arm64) ARCH="arm64";;
  *) err "Unsupported arch: $(uname -m)"; exit 1;;
esac

# ── package manager ──────────────────────────────────────────────────────
PM=""
if   command -v apt-get >/dev/null 2>&1; then PM="apt"
elif command -v dnf     >/dev/null 2>&1; then PM="dnf"
elif command -v pacman  >/dev/null 2>&1; then PM="pacman"
elif command -v brew    >/dev/null 2>&1; then PM="brew"
fi
[ -n "$PM" ] || warn "no package manager detected — falling back to Go/manual"

have() { command -v "$1" >/dev/null 2>&1; }

install_pkg() {
  local pkg="$1"
  case "$PM" in
    apt)    sudo apt-get update -qq && sudo apt-get install -y "$pkg";;
    dnf)    sudo dnf install -y "$pkg";;
    pacman) sudo pacman -S --noconfirm "$pkg";;
    brew)   brew install "$pkg";;
    *)      return 1;;
  esac
}

# ── shell rc / PATH helpers ──────────────────────────────────────────────
detect_rc() {
  case "${SHELL##*/}" in
    zsh)  echo "$HOME/.zshrc";;
    bash) echo "$HOME/.bashrc";;
    *)    echo "$HOME/.profile";;
  esac
}

ensure_path_in() {
  local dir="$1" rc="${2:-$(detect_rc)}"
  [ -f "$rc" ] || return 0
  grep -qF "export PATH=\"$dir:\$PATH\"" "$rc" 2>/dev/null && return 0
  printf '\n# Added by FUZZY installer\nexport PATH="%s:$PATH"\n' "$dir" >> "$rc"
  ok "added $dir to PATH in $rc"
}

# ── system prerequisites ─────────────────────────────────────────────────
for c in curl git make; do
  if ! have "$c"; then
    say "installing $c"
    install_pkg "$c" || { err "cannot install $c"; exit 1; }
  fi
done
have gcc || { say "installing compiler"; install_pkg build-essential 2>/dev/null \
              || install_pkg gcc 2>/dev/null || warn "no compiler — massdns build may fail"; }

mkdir -p "$FUZZY_HOME" "$FUZZY_BIN" "$FUZZY_CONFIG" "$HOME/.local"

# ── Go ───────────────────────────────────────────────────────────────────
go_ok() {
  have go || return 1
  local v; v=$(go version 2>/dev/null | awk '{print $3}' | sed 's/^go//')
  [ -n "$v" ] || return 1
  local maj min; IFS=. read -r maj min _ <<< "$v"
  [ "$maj" -ge "$GO_MIN_MAJOR" ] && [ "$min" -ge "$GO_MIN_MINOR" ]
}

if ! go_ok; then
  say "installing Go $GO_VERSION"
  tmp="/tmp/go${GO_VERSION}.${OS}-${ARCH}.tar.gz"
  url="https://go.dev/dl/go${GO_VERSION}.${OS}-${ARCH}.tar.gz"
  curl -fsSL "$url" -o "$tmp" || { err "Go download failed"; exit 1; }
  tar -C "$HOME/.local" -xzf "$tmp"
  rm -f "$tmp"
  export PATH="$HOME/.local/go/bin:$PATH"
  ensure_path_in "$HOME/.local/go/bin"
  go_ok || { err "Go install verification failed"; exit 1; }
fi
ok "Go: $(go version | awk '{print $3}')"

# ── ffuf ─────────────────────────────────────────────────────────────────
if ! have ffuf; then
  say "installing ffuf"
  if install_pkg ffuf 2>/dev/null; then
    ok "ffuf via $PM"
  else
    GOBIN="$FUZZY_BIN" go install github.com/ffuf/ffuf/v2@latest
    ok "ffuf via go"
  fi
fi

# ── massdns ──────────────────────────────────────────────────────────────
if ! have massdns; then
  say "building massdns from source"
  tmpdir=$(mktemp -d)
  git clone --depth 1 https://github.com/blechschmidt/massdns.git \
    "$tmpdir/massdns" >/dev/null 2>&1 || { err "massdns clone failed"; rm -rf "$tmpdir"; exit 1; }
  ( cd "$tmpdir/massdns" && make >/dev/null 2>&1 ) \
    || { err "massdns build failed"; rm -rf "$tmpdir"; exit 1; }
  install -m 755 "$tmpdir/massdns/bin/massdns" "$FUZZY_BIN/massdns"
  rm -rf "$tmpdir"
  ok "massdns: $FUZZY_BIN/massdns"
fi
ensure_path_in "$FUZZY_BIN"

# ── puredns ──────────────────────────────────────────────────────────────
if ! have puredns; then
  say "installing puredns"
  GOBIN="$FUZZY_BIN" go install github.com/d3mondev/puredns/v2@latest
  ok "puredns installed"
fi
ensure_path_in "$FUZZY_BIN"

# ── resolvers ────────────────────────────────────────────────────────────
RESOLVER_FILE="$FUZZY_CONFIG/resolvers.txt"
if [ -s "$RESOLVER_FILE" ]; then
  ok "resolvers already present: $RESOLVER_FILE ($(wc -l < "$RESOLVER_FILE") lines)"
else
  say "downloading resolvers"
  curl -fsSL "$RESOLVER_URL" -o "$RESOLVER_FILE"
  ok "resolvers: $RESOLVER_FILE ($(wc -l < "$RESOLVER_FILE") lines)"
fi

# ── fuzzy CLI ────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SRC_PY="$SCRIPT_DIR/fuzzy.py"
[ -f "$SRC_PY" ] || { err "fuzzy.py not found next to install.sh"; exit 1; }

say "installing fuzzy CLI"
cp "$SRC_PY" "$FUZZY_HOME/fuzzy.py"
chmod +x "$FUZZY_HOME/fuzzy.py"
ln -sf "$FUZZY_HOME/fuzzy.py" "$FUZZY_BIN/fuzzy"
ok "symlink: $FUZZY_BIN/fuzzy"

# shell alias (works in interactive shells; symlink covers scripts / sudo)
RC="$(detect_rc)"
if ! grep -qF "# FUZZY alias" "$RC" 2>/dev/null; then
  printf '\n# FUZZY alias\nalias fuzzy="%s/fuzzy.py"\n' "$FUZZY_HOME" >> "$RC"
  ok "alias added to $RC"
fi
ensure_path_in "$FUZZY_BIN" "$RC"

# ── verify ───────────────────────────────────────────────────────────────
export PATH="$FUZZY_BIN:$PATH"
echo
for tool in fuzzy ffuf puredns massdns; do
  if p=$(command -v "$tool" 2>/dev/null); then
    ok "$(printf '%-8s' "$tool") $p"
  else
    warn "$(printf '%-8s' "$tool") not found"
  fi
done

echo
printf "${G}${W}Install complete.${N}\n"
printf "  Reload shell:  ${C}exec \$SHELL${N}   (or open a new terminal)\n"
printf "  Try it:        ${C}fuzzy -i scope.txt -w /path/to/n0kovo.txt -o out.csv${N}\n"
printf "  Help:          ${C}fuzzy --help${N}\n"