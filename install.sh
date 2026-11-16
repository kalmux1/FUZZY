#!/usr/bin/env bash
# FUZZY installer - installs ffuf, puredns, massdns, resolvers, and the fuzzy CLI.
# Author: Kalmux
# License: MIT

set -euo pipefail

VERSION="1.0.0"
FUZZY_HOME="${FUZZY_HOME:-$HOME/.local/share/fuzzy}"
FUZZY_BIN="${FUZZY_BIN:-$HOME/.local/bin}"
FUZZY_CONFIG="${FUZZY_CONFIG:-$HOME/.config/fuzzy}"
RESOLVER_URL="https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt"

GO_VERSION="${GO_VERSION:-1.22.5}"
GO_MIN_MAJOR=1
GO_MIN_MINOR=21

FFUF_VERSION="${FFUF_VERSION:-v2.1.0}"
PUREDNS_VERSION="${PUREDNS_VERSION:-v2.1.6}"
MASSDNS_REF="${MASSDNS_REF:-master}"


# ---------------------------------------------------------------- colours

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  R=$'\033[0;31m'; G=$'\033[0;32m'; Y=$'\033[0;33m'
  C=$'\033[0;36m'; M=$'\033[0;35m'; B=$'\033[0;34m'
  W=$'\033[1m';    GR=$'\033[0;90m'; N=$'\033[0m'
else
  R=''; G=''; Y=''; C=''; M=''; B=''; W=''; GR=''; N=''
fi

say()  { printf "${C}[*]${N} %s\n" "$*"; }
ok()   { printf "${G}[+]${N} %s\n" "$*"; }
warn() { printf "${Y}[!]${N} %s\n" "$*"; }
err()  { printf "${R}[x]${N} %s\n" "$*" >&2; }


# ---------------------------------------------------------------- UTF-8 detect

detect_utf8() {
  for var in LC_ALL LC_CTYPE LANG; do
    eval "val=\${$var:-}"
    if [ -n "$val" ]; then
      case "$val" in
        *[Uu][Tt][Ff]-8*|*[Uu][Tt][Ff]8*) return 0 ;;
        *) return 1 ;;
      esac
    fi
  done
  return 1
}

if detect_utf8; then
  UTF8=1
  TL=$'\u256d'; TR=$'\u256e'; BL=$'\u2570'; BR=$'\u256f'
  H=$'\u2500';  V=$'\u2502'
else
  UTF8=0
  TL='+'; TR='+'; BL='+'; BR='+'; H='-'; V='|'
fi


# ---------------------------------------------------------------- banner

banner() {
  local W=44
  local title="F U Z Z Y"
  local l1="Multi-Domain Subdomain Reconnaissance"
  local a="Puredns x Ffuf"
  local sep="  |  "
  local b="By Kalmux"
  local l2="${a}${sep}${b}"
  local l3="installer v${VERSION}"

  local hline
  hline=$(printf "%0.s${H}" $(seq 1 "$W"))

  printf "  ${C}%s%s%s${N}\n" "$TL" "$hline" "$TR"

  local tlen=${#title}
  local lpad=$(( (W - tlen) / 2 ))
  local rpad=$(( W - tlen - lpad ))
  printf "  ${C}%s${N}%*s%s%*s${C}%s${N}\n" \
    "$V" "$lpad" "" "$title" "$rpad" "" "$V"

  printf "  ${C}%s%s%s${N}\n" "$BL" "$hline" "$BR"

  local len lpad rpad2
  len=${#l1}
  lpad=$(( (W - len) / 2 )); rpad2=$(( W - len - lpad ))
  printf "  %*s${C}%s${N}%*s\n" "$lpad" "" "$l1" "$rpad2" ""

  len=${#l2}
  lpad=$(( (W - len) / 2 )); rpad2=$(( W - len - lpad ))
  printf "  %*s${M}%s${N}${GR}%s${N}${Y}%s${N}%*s\n" \
    "$lpad" "" "$a" "$sep" "$b" "$rpad2" ""

  len=${#l3}
  lpad=$(( (W - len) / 2 )); rpad2=$(( W - len - lpad ))
  printf "  %*s${GR}%s${N}%*s\n\n" "$lpad" "" "$l3" "$rpad2" ""
}

banner


# ---------------------------------------------------------------- OS / arch

case "$(uname -s)" in
  Linux)  OS="linux";;
  Darwin) OS="darwin";;
  *) err "Unsupported OS: $(uname -s)"; exit 1;;
esac

case "$(uname -m)" in
  x86_64|amd64)  ARCH="amd64";;
  aarch64|arm64) ARCH="arm64";;
  *) err "Unsupported arch: $(uname -m)"; exit 1;;
esac


# ---------------------------------------------------------------- package manager

PM=""
if   command -v apt-get >/dev/null 2>&1; then PM="apt"
elif command -v dnf     >/dev/null 2>&1; then PM="dnf"
elif command -v pacman  >/dev/null 2>&1; then PM="pacman"
elif command -v brew    >/dev/null 2>&1; then PM="brew"
fi
[ -n "$PM" ] || warn "no package manager detected - falling back to Go/manual"


# ---------------------------------------------------------------- sudo

SUDO=""
if [ "$(id -u)" -eq 0 ]; then
  SUDO=""
elif command -v sudo >/dev/null 2>&1; then
  SUDO="sudo"
else
  err "not root and 'sudo' is not installed"
  err "re-run as root or install sudo"
  exit 1
fi


# ---------------------------------------------------------------- helpers

have() { command -v "$1" >/dev/null 2>&1; }

install_pkg() {
  local pkg="$1"
  case "$PM" in
    apt)    $SUDO apt-get update -qq && $SUDO apt-get install -y "$pkg";;
    dnf)    $SUDO dnf install -y "$pkg";;
    pacman) $SUDO pacman -S --noconfirm "$pkg";;
    brew)   brew install "$pkg";;
    *)      return 1;;
  esac
}

install_python() {
  have python3 && return 0
  case "$PM" in
    apt)    $SUDO apt-get update -qq && $SUDO apt-get install -y python3;;
    dnf)    $SUDO dnf install -y python3;;
    pacman) $SUDO pacman -S --noconfirm python;;
    brew)   brew install python@3.12 2>/dev/null || brew install python;;
    *)      return 1;;
  esac
}

ensure_compiler() {
  if have gcc || have cc || have clang; then return 0; fi
  case "$OS" in
    darwin)
      warn "no C compiler found - install Xcode Command Line Tools:"
      warn "  xcode-select --install"
      return 1
      ;;
    linux)
      case "$PM" in
        apt)    install_pkg build-essential ;;
        dnf)    install_pkg gcc && install_pkg make ;;
        pacman) install_pkg base-devel ;;
        *)      warn "no compiler - massdns build may fail"; return 1 ;;
      esac
      ;;
  esac
}

detect_rc() {
  case "${SHELL##*/}" in
    zsh)  echo "$HOME/.zshrc";;
    bash) echo "$HOME/.bashrc";;
    fish) echo "$HOME/.config/fish/config.fish";;
    ksh)  echo "$HOME/.kshrc";;
    *)    echo "$HOME/.profile";;
  esac
}

ensure_path_in() {
  local dir="$1" rc="${2:-$(detect_rc)}"
  [ -d "$(dirname "$rc")" ] || mkdir -p "$(dirname "$rc")" 2>/dev/null || return 0
  [ -f "$rc" ] || touch "$rc" 2>/dev/null || return 0
  case "$rc" in
    *fish*)
      grep -qF "set -gx PATH $dir" "$rc" 2>/dev/null && return 0
      printf '\n# Added by FUZZY installer\nset -gx PATH %s $PATH\n' "$dir" >> "$rc"
      ;;
    *)
      grep -qF "export PATH=\"$dir:\$PATH\"" "$rc" 2>/dev/null && return 0
      printf '\n# Added by FUZZY installer\nexport PATH="%s:$PATH"\n' "$dir" >> "$rc"
      ;;
  esac
  ok "added $dir to PATH in $rc"
}

sha256_of() {
  if have sha256sum; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}


# ---------------------------------------------------------------- prerequisites

say "checking system prerequisites"
install_python || { err "cannot install python3"; exit 1; }

for c in curl git make; do
  if ! have "$c"; then
    say "installing $c"
    install_pkg "$c" || { err "cannot install $c"; exit 1; }
  fi
done
ok "python3: $(python3 --version 2>&1)"

if ! ensure_compiler; then
  warn "compiler missing - massdns build will likely fail"
fi

mkdir -p "$FUZZY_HOME" "$FUZZY_BIN" "$FUZZY_CONFIG" "$HOME/.local"


# ---------------------------------------------------------------- Go

go_ok() {
  have go || return 1
  local v; v=$(go version 2>/dev/null | awk '{print $3}' | sed 's/^go//')
  [ -n "$v" ] || return 1
  local maj min; IFS=. read -r maj min _ <<< "$v"
  if [ "$maj" -gt "$GO_MIN_MAJOR" ]; then return 0; fi
  [ "$maj" -eq "$GO_MIN_MAJOR" ] && [ "$min" -ge "$GO_MIN_MINOR" ]
}

if ! go_ok; then
  say "installing Go ${GO_VERSION}"
  gtmp=$(mktemp -d)
  tarball="$gtmp/go${GO_VERSION}.${OS}-${ARCH}.tar.gz"
  url="https://go.dev/dl/go${GO_VERSION}.${OS}-${ARCH}.tar.gz"

  curl -fsSL "$url"           -o "$tarball"        || { err "Go download failed"; rm -rf "$gtmp"; exit 1; }
  curl -fsSL "${url}.sha256"  -o "${tarball}.sha"  || { err "Go checksum download failed"; rm -rf "$gtmp"; exit 1; }

  expected=$(awk '{print $1}' "${tarball}.sha")
  actual=$(sha256_of "$tarball")
  if [ "$expected" != "$actual" ]; then
    err "Go checksum mismatch"
    err "  expected: $expected"
    err "  actual:   $actual"
    rm -rf "$gtmp"; exit 1
  fi
  ok "Go tarball verified (sha256)"

  rm -rf "$HOME/.local/go"
  tar -C "$HOME/.local" -xzf "$tarball"
  rm -rf "$gtmp"

  export PATH="$HOME/.local/go/bin:$PATH"
  ensure_path_in "$HOME/.local/go/bin"
  go_ok || { err "Go install verification failed"; exit 1; }
fi
ok "Go: $(go version | awk '{print $3}')"


# ---------------------------------------------------------------- ffuf

if ! have ffuf; then
  say "installing ffuf (${FFUF_VERSION})"
  if install_pkg ffuf 2>/dev/null; then
    ok "ffuf via $PM"
  else
    GOBIN="$FUZZY_BIN" go install "github.com/ffuf/ffuf/v2@${FFUF_VERSION}"
    ok "ffuf via go"
  fi
fi


# ---------------------------------------------------------------- massdns

if ! have massdns; then
  say "building massdns from source (${MASSDNS_REF})"
  mtmp=$(mktemp -d)
  if ! git clone --depth 1 --branch "$MASSDNS_REF" \
        https://github.com/blechschmidt/massdns.git \
        "$mtmp/massdns" >/dev/null 2>&1; then
    err "massdns clone failed"
    rm -rf "$mtmp"; exit 1
  fi
  if ! ( cd "$mtmp/massdns" && make >/dev/null 2>&1 ); then
    err "massdns build failed"
    rm -rf "$mtmp"; exit 1
  fi
  install -m 755 "$mtmp/massdns/bin/massdns" "$FUZZY_BIN/massdns"
  rm -rf "$mtmp"
  ok "massdns: $FUZZY_BIN/massdns"
fi
ensure_path_in "$FUZZY_BIN"


# ---- massdns capabilities ------------------------------------------------
if [ -f "$FUZZY_BIN/massdns" ]; then
  if [ "$OS" = "darwin" ]; then
    warn "macOS: massdns needs sudo or root to run (setcap not available)"
  elif [ "$(id -u)" -eq 0 ]; then
    ok "massdns capabilities - running as root"
  else
    if ! have setcap; then
      say "installing setcap (libcap)"
      case "$PM" in
        apt)    install_pkg libcap2-bin >/dev/null 2>&1 || true ;;
        dnf)    install_pkg libcap       >/dev/null 2>&1 || true ;;
        pacman) install_pkg libcap       >/dev/null 2>&1 || true ;;
      esac
    fi

    if have setcap && have getcap; then
      current_caps=$(getcap "$FUZZY_BIN/massdns" 2>/dev/null || true)
      if echo "$current_caps" | grep -q "cap_net_raw"; then
        ok "massdns capabilities already set"
      elif $SUDO setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip \
            "$FUZZY_BIN/massdns" 2>/dev/null; then
        ok "massdns capabilities set (setcap)"
      else
        warn "could not set massdns capabilities - run manually:"
        warn "  sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip $FUZZY_BIN/massdns"
        warn "or run fuzzy as root"
      fi
    else
      warn "setcap/getcap unavailable - massdns will fail as non-root user"
      warn "install libcap2-bin (Debian) or libcap (Fedora/Arch) and re-run"
    fi
  fi
fi


# ---------------------------------------------------------------- puredns

if ! have puredns; then
  say "installing puredns (${PUREDNS_VERSION})"
  GOBIN="$FUZZY_BIN" go install "github.com/d3mondev/puredns/v2@${PUREDNS_VERSION}"
  ok "puredns installed"
fi
ensure_path_in "$FUZZY_BIN"


# ---------------------------------------------------------------- resolvers
# v1.0.1 fix: normalize before validating (handles CRLF, BOM, trailing
# whitespace, IPv6-with-brackets, and format drift on the upstream list).

RESOLVER_FILE="$FUZZY_CONFIG/resolvers.txt"

normalize_resolvers() {
  local f="$1" tmp
  tmp=$(mktemp)
  tr -d '\r' < "$f" \
    | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' \
    | grep -vE '^[[:space:]]*(#|$)' > "$tmp" || true
  mv "$tmp" "$f"
}

count_strict_resolvers() {
  local f="$1" n
  n=$(grep -cE \
        '^([0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]+$|^\[?[0-9a-fA-F:]+\]?:[0-9]+$' \
        "$f" 2>/dev/null || true)
  echo "${n:-0}"
}

download_resolvers() {
  say "downloading resolvers"
  local rtmp bytes lines strict total
  rtmp=$(mktemp)
  if ! curl -fsSL "$RESOLVER_URL" -o "$rtmp"; then
    err "resolver download failed"
    rm -f "$rtmp"; return 1
  fi
  bytes=$(wc -c < "$rtmp")
  lines=$(wc -l < "$rtmp" 2>/dev/null || echo 0)
  say "  fetched ${bytes} bytes, ${lines} lines"
  normalize_resolvers "$rtmp"

  total=$(wc -l < "$rtmp" 2>/dev/null || echo 0)
  strict=$(count_strict_resolvers "$rtmp")

  if [ "$total" -lt 10 ]; then
    err "downloaded resolver file looks unusable (${total} non-comment lines)"
    err "  raw size:  ${bytes} bytes, ${lines} lines"
    err "  first 3 lines:"
    head -3 "$rtmp" 2>/dev/null | sed 's/^/    /' >&2
    rm -f "$rtmp"; return 1
  fi

  if [ "$strict" -lt 10 ]; then
    warn "resolver file has ${strict} strict IP:port lines out of ${total} total"
    warn "using anyway - some entries may be rejected by puredns"
  fi

  mv "$rtmp" "$RESOLVER_FILE"
  ok "resolvers: $RESOLVER_FILE ($(wc -l < "$RESOLVER_FILE") lines)"
  return 0
}

if [ -s "$RESOLVER_FILE" ]; then
  normalize_resolvers "$RESOLVER_FILE"
  existing=$(wc -l < "$RESOLVER_FILE" 2>/dev/null || echo 0)
  if [ "$existing" -ge 10 ]; then
    ok "resolvers already present: $RESOLVER_FILE (${existing} lines)"
  else
    warn "existing resolver file is too small (${existing} lines), re-downloading"
    rm -f "$RESOLVER_FILE"
    download_resolvers || exit 1
  fi
else
  download_resolvers || exit 1
fi


# ---------------------------------------------------------------- fuzzy CLI

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SRC_PY="$SCRIPT_DIR/fuzzy.py"
[ -f "$SRC_PY" ] || { err "fuzzy.py not found next to install.sh"; exit 1; }

say "installing fuzzy CLI"
install -m 755 "$SRC_PY" "$FUZZY_HOME/fuzzy.py"

if [ -e "$FUZZY_BIN/fuzzy" ] && [ ! -L "$FUZZY_BIN/fuzzy" ]; then
  warn "$FUZZY_BIN/fuzzy exists and is not a symlink - backing up"
  mv "$FUZZY_BIN/fuzzy" "$FUZZY_BIN/fuzzy.bak.$(date +%s)"
fi

ln -sf "$FUZZY_HOME/fuzzy.py" "$FUZZY_BIN/fuzzy"
ok "symlink: $FUZZY_BIN/fuzzy"


# ---------------------------------------------------------------- shell config

RC="$(detect_rc)"
mkdir -p "$(dirname "$RC")" 2>/dev/null || true
touch "$RC" 2>/dev/null || true

case "$RC" in
  *fish*)
    if ! grep -qF "# FUZZY alias" "$RC" 2>/dev/null; then
      {
        printf '\n# FUZZY alias\n'
        printf 'alias fuzzy="%s/fuzzy.py"\n' "$FUZZY_HOME"
      } >> "$RC"
      ok "alias added to $RC"
    fi
    ;;
  *)
    if ! grep -qF "# FUZZY alias" "$RC" 2>/dev/null; then
      {
        printf '\n# FUZZY alias\n'
        printf 'alias fuzzy="%s/fuzzy.py"\n' "$FUZZY_HOME"
      } >> "$RC"
      ok "alias added to $RC"
    fi
    ;;
esac
ensure_path_in "$FUZZY_BIN" "$RC"


# ---------------------------------------------------------------- verify

export PATH="$FUZZY_BIN:$PATH"

printf "\n"
printf "  ${C}%s%s%s${N}\n" "$TL" "$(printf "%0.s${H}" $(seq 1 44))" "$TR"
printf "  ${C}%s${N}  ${W}%-40s${N}${C}%s${N}\n" "$V" "toolchain" "$V"
printf "  ${C}%s%s%s${N}\n" "$BL" "$(printf "%0.s${H}" $(seq 1 44))" "$BR"

for tool in fuzzy ffuf puredns massdns; do
  if p=$(command -v "$tool" 2>/dev/null); then
    printf "  ${G}[+]${N} %-10s ${GR}%s${N}\n" "$tool" "$p"
  else
    printf "  ${Y}[!]${N} %-10s ${Y}not found${N}\n" "$tool"
  fi
done

printf "\n"
printf "${G}${W}Install complete.${N}\n"
printf "  Reload shell:  ${C}exec \$SHELL${N}   (or open a new terminal)\n"
printf "  Try it:        ${C}fuzzy -i scope.txt -w /path/to/n0kovo.txt -o out.csv${N}\n"
printf "  Help:          ${C}fuzzy --help${N}\n"
printf "  Dry run:       ${C}fuzzy -i scope.txt -w wordlist.txt -o out.csv --dry-run${N}\n"
printf "\n"

if [ "$UTF8" != "1" ]; then
  warn "terminal locale is not UTF-8 - FUZZY will fall back to ASCII art"
  warn "to enable Unicode banner:  export LANG=en_US.UTF-8"
fi

if [ "$OS" = "linux" ] && ! getcap "$FUZZY_BIN/massdns" 2>/dev/null | grep -q cap_net_raw; then
  if [ "$(id -u)" -ne 0 ]; then
    warn "massdns capabilities not set - puredns will fail as non-root user"
    warn "  sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip $FUZZY_BIN/massdns"
  fi
fi
