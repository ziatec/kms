#!/usr/bin/env bash
# https://github.com/outline/outline/releases/tag/v1.11.0
# VERSION: 11.6 (2026-10-16)  11.6: two install modes, asked first (default: customer; KMS_MODE=customer|admin
#   skips the question). Customer: License management plugin default NO, sources deleted after the
#   build (also the old patched trees in archive/ and assets/patches.zip.bak-*), refuses to run from a
#   kit that still holds Admin/ (vendor private keys). Admin: the plugin default is YES, sources kept;
#   the default is Admin when the kit holds Admin/kms-license-data/private.json.
#   11.5 (2026-10-16)  11.5: hardening for customer servers. The Outline image no longer
#   holds the TypeScript sources of server/ (license code) nor source maps; new step 12 asks
#   (default yes) to delete the sources after a successful build: build/ and, in the kit,
#   assets/outline-*.zip, patches/, patches.zip, ssozia.zip, plugins/*.zip. Never done on a vendor
#   kit (Admin/, .git or the License management plugin) or when the verification failed.
#   11.4 (2026-10-16)  11.4: the SSO login test runs by default again (11.1 skipped
#   it when the question timed out) and asks the admin password; the password waits 60 s
#   for the first key, without one the test is skipped (the installation goes on).
#   11.3 (2026-10-16)  11.3: a question longer than the terminal line was printed
#   again every second of the countdown; now only the countdown is redrawn.
#   11.2 (2026-10-16)  11.2: the wipe question also takes its default (No) after
#   the timeout; only answering Yes leads to the typed 'yes' confirmation, which still waits.
#   11.1 (2026-10-16)  11.1: every question answers itself with its default after
#   10 seconds without a key (a countdown is shown; the first key stops it and the answer
#   is typed as before). Not timed: the typed 'yes' confirmations (wiping kms/data,
#   formatting a disk) and passwords. KMS_PROMPT_TIMEOUT=N sets the seconds, 0 waits for ever.
#   11.0 (2026-10-15)  11.0: the Outline source is no longer fixed to 1.10.1: the newest
#   assets/outline-X.Y.Z.zip or assets/vX.Y.Z.zip is used (OUTLINE_VERSION=X.Y.Z picks one);
#   Yarn version comes from the source's package.json (packageManager), kept in build/yarn-<ver>.
#   10.9: step 2 no longer stops when an extra apt source fails
#   (e.g. download.docker.com answers 403): apt update is run again without the sources of
#   the failing hosts, only for this run (/etc/apt is not changed), with a warning.
#   10.8: step P compares only the patch files of assets/patches/
#   and patches.zip, uses the newer copy of each (VERSION, then modification time), rebuilds
#   the zip from the result; PATCHES.txt is gone (an old one goes to archive/).
#   10.7: step 9 no longer fails on archive/<time> made by root when
#   the vendor keys were archived first ("cp: Permission denied").
#   10.6: default workspace name "Knowledge management" in Persian;
#   step 10 renames a workspace still called "Outline" to APP_NAME (needs patch 0009 v2.1).
#   10.5: License management plugin (kms-licenses-plugin-X.zip, id
#   subscribers) opens from Settings > License; a full plugin zip replaces older files.
#   10.4: step 11 checks the admin password before the SSO login
#   test (wrong password / rate limit reported, 3 tries); warning for SERVER_IP 127.x.
#   10.3: admin plugins from the kit's plugins/ (Customers =
#   kms-subscribers, Users = ssozia-users): chosen and built in step 7, keys in step 9,
#   database in step 10, checks in step 11.
#   10.2: step 9 asks the workspace name (APP_NAME, default
#   "Aflak knowledge management" in Persian) instead of "Outline"; patch set merged to 0001..0011.
#   10.1: any Linux host (apt, pacman, dnf, zypper); images stay Debian.
#   10.0: runs only from the source kit (e.g. ~/kms); the install folder
#   (e.g. /srv/kms) gets no copy of install.sh or assets/. 9.9: license checks as non-root, data/ owner.
#   Outline (newest in assets/) RTL + ssozia + PostgreSQL + Redis + Caddy, all images built locally
#   (Debian base from your apt mirror via debootstrap), compilers on the host, one
#   docker-compose.yml and all data inside the kms folder. Every step asks first.
# =============================================================================
#  Two folders: the source kit (e.g. ~/kms) and the install folder (e.g. /srv/kms).
#  Always run the kit's install.sh; step 0 picks the install folder once and keeps it in
#  <kit>/.kms-target. Kit:
#    install.sh
#    assets/        inputs, never changed:
#                   outline-X.Y.Z.zip (or vX.Y.Z.zip)  patches/ + patches.zip  fonts.zip  ssozia.zip (or an ssozia/ folder)
#                   patches/ holds NNNN-name.patch files (with a VERSION: line); step P uses the
#                   newer copy of each patch from patches/ or patches.zip and rebuilds the zip,
#                   so dropping a patch into patches/ is enough (no PATCHES.txt)
#                   license/vendor-public.json   your public license key (kms-license.mjs keygen)
#    plugins/       optional admin plugins, built into Outline when chosen in step 7:
#                   kms-licenses-plugin-X.zip (License management; older name kms-subscribers-plugin),
#                   ssozia-users-plugin-X.zip (Users);
#                   a ...-X-changes.zip is laid over the full package of an earlier version
#    Admin/kms-license-data/   vendor keys and ledger for the License management plugin (vendor only)
#  Install folder:
#    build/         host builds: outline-X.Y.Z/ (patched source), ssozia/, node/, yarn/
#    images/        Dockerfiles and build contexts of the local images
#    config/        outline.env  postgres.env  secrets.env  Caddyfile  ssozia/{users,clients}.toml
#                   license/ (server identity for the license: install ID, key pair, hardware hashes)
#                   license/vendor/ (vendor keys, only with the License management plugin)  plugins.conf
#    certs/         ca/ (local CA, mkcert)  site/ (certificate for both domains)
#    data/          postgres/  redis/  outline/  ssozia/  caddy/      <- all persistent data
#    docker-compose.yml   (project "kms")
#    logs/          install-<time>.log (mode 600)
#
#  Mode (asked first): customer (default) or admin; KMS_MODE=customer|admin answers it.
#  Usage: bash install.sh [--yes] [--from N] [--version] [--help]
#    (step P, the patch sync, runs first on every start; then step 0/1 and the rest)
#    --yes      use the default answer everywhere (never wipes data; a new admin needs
#               KMS_ADMIN_EMAIL and KMS_ADMIN_PASSWORD in the environment)
#    --from N   start at step N (earlier steps are skipped)
#    Questions take their default after 10 s without a key (KMS_PROMPT_TIMEOUT=N, 0 = wait);
#    never for the typed 'yes' confirmations (wipe, format) or passwords.
# =============================================================================
set -Eeuo pipefail

VERSION="11.6"
SELF="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
KIT="$(dirname "$SELF")"; ASSETS="$KIT/assets"; TARGET_FILE="$KIT/.kms-target"
# Outline source: newest outline-X.Y.Z.zip / vX.Y.Z.zip in assets/ (OUTLINE_VERSION=X.Y.Z forces one)
TAG=""; SRC_ZIP=""
for _f in "$KIT"/assets/outline-[0-9]*.zip "$KIT"/assets/v[0-9]*.zip; do
  [[ -f $_f ]] || continue; _v="${_f##*/}"; _v="${_v%.zip}"; _v="${_v#outline-}"; _v="${_v#v}"
  [[ $_v =~ ^[0-9]+(\.[0-9]+)*$ ]] || continue
  if [[ -n ${OUTLINE_VERSION:-} ]]; then [[ $_v == "$OUTLINE_VERSION" ]] && { TAG="$_v"; SRC_ZIP="$_f"; break; }; continue; fi
  if [[ -z $TAG || ( $_v != "$TAG" && $(printf '%s\n%s\n' "$TAG" "$_v" | sort -V | tail -n1) == "$_v" ) ]]; then TAG="$_v"; SRC_ZIP="$_f"; fi
done
if [[ -z $TAG ]]; then
  echo "No Outline source in $KIT/assets: put outline-X.Y.Z.zip (or vX.Y.Z.zip) there${OUTLINE_VERSION:+ for version $OUTLINE_VERSION}." >&2
  _t="$(head -n1 "$KIT/.kms-target" 2>/dev/null || true)"
  [[ -n $_t && -f $_t/.kms-sources-removed ]] && echo "The sources of this installation were deleted on purpose ($(cat "$_t/.kms-sources-removed")); a rebuild needs a complete kit from your supplier." >&2
  exit 1
fi
SRC_NAME="outline-$TAG"; SRC_ZIP_NAME="${SRC_ZIP##*/}"
set_kms() { # set_kms <install folder> : all paths of the installation
  KMS="$1"; BUILD="$KMS/build"; IMAGES="$KMS/images"; CONFIG="$KMS/config"
  CERTS="$KMS/certs"; DATA="$KMS/data"; LOGS="$KMS/logs"; ARCHIVE="$KMS/archive"; SRC="$BUILD/$SRC_NAME"
}
if [[ ! -d $ASSETS ]]; then
  echo "No assets/ next to $SELF: run install.sh from the source kit (e.g. bash ~/kms/install.sh), not from the install folder." >&2; exit 1
fi
if [[ -f $TARGET_FILE ]]; then
  set_kms "$(head -n1 "$TARGET_FILE")"
  [[ $KMS == /* && -d $KMS ]] || { echo "Install folder '$KMS' (from $TARGET_FILE) does not exist; remove $TARGET_FILE to choose again." >&2; exit 1; }
else set_kms "$KIT"; fi
PROJECT="kms"; NET="kms-net"
IMG_BASE="kms/base:local"; IMG_PG="kms/postgres:local"; IMG_REDIS="kms/redis:local"
IMG_CADDY="kms/caddy:local"; IMG_SSOZIA="kms/ssozia:local"; IMG_OUTLINE="kms/outline:$TAG"
YARN_VER="4.11.0"; NODE_TARBALL_VER="${NODE_VER:-26.3.0}"
NPM_REGISTRY="${NPM_REGISTRY:-https://registry.npmjs.org}"
EXPECTED_FONTS=(
  Vazirmatn-VF.woff2
  Sahel-Light.woff2 Sahel.woff2 Sahel-SemiBold.woff2 Sahel-Bold.woff2
  Shabnam-Thin.woff2 Shabnam-Light.woff2 Shabnam.woff2 Shabnam-Medium.woff2 Shabnam-Bold.woff2
  Samim.woff2 Samim-Medium.woff2 Samim-Bold.woff2
  Parastoo.woff2 Parastoo-Bold.woff2
)
STEPS=12
# One locale for the whole run (avoids perl/apt locale warnings from SSH-forwarded LC_* values).
export LANG=C.UTF-8 LC_ALL=C.UTF-8; unset LANGUAGE

# ----------------------------- options ---------------------------------------
ORIG_ARGS=("$@")
ASSUME_YES=0; FROM=1
for arg in "$@"; do
  case "$arg" in
    -y|--yes) ASSUME_YES=1 ;;
    --from=*) FROM="${arg#*=}" ;;
    --version) echo "install.sh $VERSION"; exit 0 ;;
    -h|--help) sed -n '2,26p' "$SELF" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) if [[ ${PREV_ARG:-} == --from ]]; then FROM="$arg"
       elif [[ $arg == --from ]]; then :
       else echo "Unknown option: $arg (see --help)" >&2; exit 2; fi ;;
  esac
  PREV_ARG="$arg"
done
[[ $FROM =~ ^[0-9]+$ ]] || { echo "--from needs a step number" >&2; exit 2; }

# ----------------------------- output ----------------------------------------
TS="$(date +%Y%m%d-%H%M%S)"
mkdir -p "$LOGS"; LOG="$LOGS/install-$TS.log"; touch "$LOG"; chmod 600 "$LOG"
if [[ -t 1 ]]; then
  C_R=$'\e[31m'; C_G=$'\e[32m'; C_Y=$'\e[33m'; C_B=$'\e[34m'; C_BOLD=$'\e[1m'; C_0=$'\e[0m'
else C_R=; C_G=; C_Y=; C_B=; C_BOLD=; C_0=; fi
exec > >(tee >(sed -u 's/\x1b\[[0-9;]*m//g' >>"$LOG")) 2>&1

SUMMARY=()
section() { printf '\n%s==== %s ====%s\n' "$C_BOLD$C_B" "$*" "$C_0"; }
ok()   { printf '  [%sOK%s]   %s\n' "$C_G" "$C_0" "$*"; SUMMARY+=("OK   $*"); }
warn() { printf '  [%sWARN%s] %s\n' "$C_Y" "$C_0" "$*"; SUMMARY+=("WARN $*"); }
info() { printf '  [....] %s\n' "$*"; }
fail() { printf '  [%sFAIL%s] %s\n' "$C_R" "$C_0" "$*"; printf '\nLog: %s\nRe-run from this step: bash %s --from %s\n' "$LOG" "$SELF" "${CUR_STEP:-1}"; exit 1; }
# Only the main shell reports; a failing $( ) inside a message just shortens that message.
trap 'rc=$?; [[ $BASHPID == "$$" ]] && fail "Unexpected error on line $LINENO (exit $rc): $BASH_COMMAND"' ERR
STAGE=""; trap '[[ -n $STAGE && -d $STAGE ]] && { rm -rf "$STAGE" 2>/dev/null || ${SUDO:-} rm -rf "$STAGE"; }; [[ -n ${SUDO_KEEPALIVE:-} ]] && kill "$SUDO_KEEPALIVE" 2>/dev/null; true' EXIT

if [[ $ASSUME_YES == 0 ]] && ! { : </dev/tty; } 2>/dev/null; then
  echo "No terminal for prompts; run in a terminal or pass --yes." >&2; exit 2
fi

# apt without debconf dialogs (they cannot read keys while output goes through the log); defaults are used.
APT_OPTS=()   # set by apt_update when sources are skipped for this run
apt_() { $SUDO env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a apt-get "${APT_OPTS[@]}" -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold "$@"; }
apt_update() { # apt-get update; the sources of hosts that fail (403, unreachable, unsigned) are skipped for this run
  local out hosts=() h f d skipped=()
  out="$(apt_ update 2>&1)" && { printf '%s\n' "$out"; return 0; }
  printf '%s\n' "$out"
  mapfile -t hosts < <(grep -oE "^(E|W): (Failed to fetch |The repository ')https?://[^/ ']+" <<<"$out" \
    | sed -E 's#.*https?://##' | sort -u)
  ((${#hosts[@]})) || fail "apt-get update failed (output above); fix the apt sources and run --from ${CUR_STEP:-2}."
  d="$(mktemp -d "${TMPDIR:-/tmp}/kms-apt.XXXXXX")"; mkdir -p "$d/parts"
  if [[ -f /etc/apt/sources.list ]]; then
    awk -v hs="${hosts[*]}" 'BEGIN{n=split(hs,H," ")}
      {for(i=1;i<=n;i++) if(index($0,"://" H[i] "/") || index($0,"://" H[i] " ")){print "# kms: skipped " $0; next}; print}' \
      /etc/apt/sources.list >"$d/sources.list"
  else : >"$d/sources.list"; fi
  for f in /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources; do
    [[ -f $f ]] || continue
    for h in "${hosts[@]}"; do grep -qF "://$h" "$f" && { skipped+=("$f"); continue 2; }; done
    cp "$f" "$d/parts/"
  done
  chmod -R a+rX "$d"
  APT_OPTS=(-o "Dir::Etc::sourcelist=$d/sources.list" -o "Dir::Etc::sourceparts=$d/parts")
  warn "apt source(s) not reachable: ${hosts[*]} - skipped for this run${skipped:+ (${skipped[*]})}."
  [[ -n ${skipped[0]:-} ]] && info "To disable it for good: sudo mv ${skipped[0]} ${skipped[0]}.disabled"
  apt_ update || fail "apt-get update still fails without ${hosts[*]} (output above); fix the apt sources and run --from ${CUR_STEP:-2}."
}

# ---- package manager of the host (apt-get, pacman, dnf or zypper) --------------------------
# Only the HOST tools differ; the Docker images are always Debian (see step 8).
PM=""
for _pm in apt-get pacman dnf zypper; do command -v "$_pm" >/dev/null 2>&1 && { PM="$_pm"; break; }; done
pm_install() { # pm_install PKG... : install packages (already installed ones are kept)
  local s=""; [[ $EUID -eq 0 ]] || s="sudo"
  case "$PM" in
    apt-get) $s env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a apt-get install -y --no-install-recommends "$@" ;;
    pacman)  $s pacman -S --needed --noconfirm "$@" ;;
    dnf)     $s dnf install -y "$@" ;;
    zypper)  $s zypper --non-interactive install --no-recommends "$@" ;;
    *) return 1 ;;
  esac
}

# Persian (U+06F0-06F9) / Arabic-Indic (U+0660-0669) digits -> 0-9; Persian-layout y/n keys.
norm_input() {
  local s="$1" i
  for i in 0 1 2 3 4 5 6 7 8 9; do
    s="${s//$(printf "\xdb\xb$i")/$i}"; s="${s//$(printf "\xd9\xa$i")/$i}"
  done
  s="${s//$(printf '\xd8\xba')/y}"; s="${s//$(printf '\xd8\xaf')/n}"
  printf '%s' "$s"
}
# Seconds a question waits before its default is taken (0 = wait for ever).
PROMPT_TIMEOUT="${KMS_PROMPT_TIMEOUT:-10}"
[[ $PROMPT_TIMEOUT =~ ^[0-9]+$ ]] || PROMPT_TIMEOUT=10
ASK_TIMED_OUT=0
# timed_read "prompt" [wait|hidden] [seconds] -> REPLY_LINE; returns 2 when no key came
# in time (take the default). A countdown is shown until the first key; then the line is
# read as usual. "wait" (or PROMPT_TIMEOUT=0) waits for ever; "hidden" does not echo
# (passwords).
timed_read() {
  local p="$1" mode="${2:-}" c="" rest="" s rc secs="${3:-$PROMPT_TIMEOUT}" hide=()
  REPLY_LINE=""
  [[ $mode == hidden ]] && hide=(-s)
  if [[ $mode == wait ]] || (( secs == 0 )); then
    read -r "${hide[@]}" -p "$p" REPLY_LINE </dev/tty || REPLY_LINE=""
    [[ $mode == hidden ]] && printf '\n' >&2
    return 0
  fi
  # The question is written once and only the countdown after it is redrawn (cursor
  # saved/restored): redrawing a question longer than the terminal line (\r only goes back
  # to the start of the last screen line) printed it again every second.
  printf '%s\0337' "$p" >&2
  for ((s = secs; s > 0; s--)); do
    printf '\0338\033[K(%ds) ' "$s" >&2
    if IFS= read -r "${hide[@]}" -n 1 -t 1 c </dev/tty; then
      [[ -z $c ]] && { [[ $mode == hidden ]] && printf '\n' >&2; return 0; }   # Enter
      IFS= read -r "${hide[@]}" rest </dev/tty || rest=""  # the rest of the answer
      [[ $mode == hidden ]] && printf '\n' >&2
      REPLY_LINE="$c$rest"
      return 0
    else
      rc=$?
      (( rc > 128 )) || { printf '\n' >&2; return 0; }   # no terminal: the default
    fi
  done
  printf '\0338\033[K\n' >&2
  return 2
}
ask_yn() { # ask_yn "question" default(y|n) [wait] ; "wait": no timeout
  local q="$1" d="$2" a hint rc; [[ $d == y ]] && hint="[Y/n]" || hint="[y/N]"
  ASK_TIMED_OUT=0
  if [[ $ASSUME_YES == 1 ]]; then printf '  ? %s %s -> %s (--yes)\n' "$q" "$hint" "$d"; [[ $d == y ]]; return; fi
  while true; do
    rc=0; timed_read "  ? $q $hint " "${3:-}" || rc=$?
    if (( rc == 2 )); then
      ASK_TIMED_OUT=1
      printf '    -> %s (no answer in %d s, default)\n' "$d" "$PROMPT_TIMEOUT" >&2
      [[ $d == y ]]; return
    fi
    a="$(norm_input "${REPLY_LINE:-$d}")"; case "${a,,}" in y|yes) return 0;; n|no) return 1;; esac
  done
}
ask_choice() { # ask_choice "question" default "opt1" ... -> echoes 1-based index
  local q="$1" d="$2"; shift 2; local i=1 a rc
  printf '  ? %s\n' "$q" >&2
  for o in "$@"; do printf '      [%d] %s%s\n' "$i" "$o" "$( [[ $i == "$d" ]] && echo ' (default)' || true)" >&2; i=$((i+1)); done
  if [[ $ASSUME_YES == 1 ]]; then printf '    choice [%s] -> %s (--yes)\n' "$d" "$d" >&2; echo "$d"; return; fi
  while true; do
    rc=0; timed_read "    choice [$d]: " || rc=$?
    if (( rc == 2 )); then
      printf '    -> %s (no answer in %d s, default)\n' "$d" "$PROMPT_TIMEOUT" >&2
      echo "$d"; return
    fi
    a="$(norm_input "${REPLY_LINE:-$d}")"
    [[ $a =~ ^[0123456789]+$ ]] && (( 10#$a>=1 && 10#$a<=$# )) && { echo "$((10#$a))"; return; }
    printf '    please type a number from 1 to %d\n' "$#" >&2
  done
}
ask_text() { # ask_text "question" default -> echoes answer
  local rc=0
  if [[ $ASSUME_YES == 1 ]]; then echo "$2"; return; fi
  timed_read "  ? $1 [$2]: " || rc=$?
  if (( rc == 2 )); then
    printf '    -> %s (no answer in %d s, default)\n' "$2" "$PROMPT_TIMEOUT" >&2
    echo "$2"; return
  fi
  echo "${REPLY_LINE:-$2}"
}
confirm_typed() { # confirm_typed "what" item... ; requires typing yes
  local what="$1"; shift
  printf '\n  %s!! %s%s\n' "$C_R$C_BOLD" "$what" "$C_0"
  for x in "$@"; do printf '       - %s\n' "$x"; done
  [[ $ASSUME_YES == 1 ]] && { info "--yes never confirms this"; return 1; }
  local a; read -r -p "  Type 'yes' to proceed [no]: " a </dev/tty || a=""; [[ $a == yes ]]
}
has_line() { grep -Fx -- "$1" >/dev/null; }
env_get() { [[ -f $2 ]] || return 0; grep -E "^$1=" "$2" | tail -n1 | cut -d= -f2- || true; }

# Each step: title + what it does, then Run / Skip / Quit.
CUR_STEP=0
step() { # step "title" default(1=run|2=skip) "description line" ...
  local title="$1" def="$2"; shift 2
  CUR_STEP=$((CUR_STEP+1))
  stty sane 2>/dev/null </dev/tty || true
  section "Step $CUR_STEP/$STEPS: $title"
  for l in "$@"; do printf '         %s\n' "$l"; done
  if (( CUR_STEP < FROM )); then
    if [[ ${FORCE_STEP:-0} == 1 ]]; then warn "Step $CUR_STEP runs although --from $FROM: ${FORCE_REASON:-required}"; def=1
    else info "skipped (--from $FROM)"; return 1; fi
  fi
  FORCE_STEP=0; FORCE_REASON=""
  case "$(ask_choice "Run step $CUR_STEP?" "$def" "Run" "Skip this step" "Quit (nothing more is changed)")" in
    1) return 0 ;;
    2) warn "Step $CUR_STEP skipped by you: $title"; return 1 ;;
    3) info "Stopped at step $CUR_STEP. Continue later with: bash $SELF --from $CUR_STEP"; exit 0 ;;
  esac
}

# ============================================================================
section "kms installer $VERSION"
info "Folder: $KMS"
info "Log: $LOG"

# ----------------------------------------------------------------------------
# Install mode (asked first, before anything is changed)
#   customer (default): a customer's server. License management plugin: default NO.
#                       The sources are deleted after a verified build (step 12).
#   admin:              the vendor's own server. License management plugin: default YES.
#                       The sources are never deleted.
#   The mode is a convenience, not a security boundary: what protects the vendor keys is that
#   a customer kit does not contain Admin/. Hence customer mode refuses to run from a kit that
#   still holds it. KMS_MODE=customer|admin answers the question (needed with --yes on a vendor kit).
# ----------------------------------------------------------------------------
VENDOR_FILES=0; [[ -f $KIT/Admin/kms-license-data/private.json ]] && VENDOR_FILES=1
KMS_MODE="${KMS_MODE:-}"
case "${KMS_MODE,,}" in
  customer|admin) KMS_MODE="${KMS_MODE,,}" ;;
  "") ;;
  *) fail "KMS_MODE must be 'customer' or 'admin' (got '$KMS_MODE')." ;;
esac
section "Install mode"
if [[ -z $KMS_MODE ]]; then
  MODE_DEF=1; (( VENDOR_FILES )) && MODE_DEF=2   # a kit with the vendor keys is the vendor's own
  case "$(ask_choice "Who is this installation for?" "$MODE_DEF" \
      "Customer server (License management plugin: default No; sources deleted after the build)" \
      "Admin / vendor server (License management plugin: default Yes; sources kept)")" in
    1) KMS_MODE=customer ;;
    2) KMS_MODE=admin ;;
  esac
fi
if [[ $KMS_MODE == customer && -d $KIT/Admin ]]; then
  printf '  [%sFAIL%s] %s\n' "$C_R" "$C_0" "Customer mode, but this kit holds Admin/ (the vendor's private license keys, ledger and tool)." >&2
  printf '         %s\n' "A customer must never receive Admin/. Take it out of the kit (or choose Admin mode if this is your own server)." >&2
  exit 1
fi
if [[ $KMS_MODE == admin ]] && (( ! VENDOR_FILES )); then
  warn "Admin mode, but the kit has no Admin/kms-license-data/private.json: the License management plugin will have no vendor keys."
fi
ok "Install mode: $KMS_MODE"

# ----------------------------------------------------------------------------
# Step P: sync assets/patches/ and assets/patches.zip (first, on every run)
#   Only the patch files are compared: for every patch number the newer copy of
#   the folder and the zip is used (higher VERSION line; same or missing
#   VERSION: later modification time; still equal: the folder copy). The folder
#   gets the final set and patches.zip is rebuilt from it when it differs, so
#   both always hold the same, newest patches. There is no PATCHES.txt (an old
#   one is moved to archive/). Nothing here is tied to patch names or counts.
#   To drop a patch for good, delete it from the folder and from the zip.
# ----------------------------------------------------------------------------
PATCH_RE='^[0-9]{4}-[a-z0-9._-]+\.patch$'
PATCH_DIR="$ASSETS/patches"; PATCH_ZIP="$ASSETS/patches.zip"
PATCH_SET_CHANGED=0; PATCH_ZIP_REBUILT=0; RECONCILE_RESULT="unchanged"

sha() { sha256sum "$1" | cut -c1-64; }
patch_version() { # patch_version FILE -> x.y[.z] from the first header line "VERSION: ..." (empty if none/bad)
  local v
  v="$(awk '/^diff --git /{exit} /^VERSION:/{sub(/^VERSION:[ \t]*/, ""); print $1; exit}' "$1" 2>/dev/null || true)"
  if [[ $v =~ ^[0-9]+\.[0-9]+(\.[0-9]+)?$ ]]; then printf '%s' "$v"; fi
}
ver_cmp() { # ver_cmp A B -> -1, 0 or 1, numeric per component (1.10 > 1.9, 1.0 = 1.0.0)
  local IFS=. i a b; local -a x=($1) y=($2)
  for i in 0 1 2; do
    a=$((10#${x[i]:-0})); b=$((10#${y[i]:-0}))
    if (( a < b )); then echo -1; return; fi
    if (( a > b )); then echo 1; return; fi
  done
  echo 0
}
list_patches() { # list_patches DIR -> the valid patch file names, sorted
  local f n
  for f in "$1"/*.patch; do
    [[ -f $f ]] || continue
    n="${f##*/}"; [[ $n =~ $PATCH_RE ]] && printf '%s\n' "$n"
  done | LC_ALL=C sort
}
patch_newer() { # patch_newer A B -> 0 when file A is newer than file B (VERSION first, then mtime; within 2 s = equal)
  local va vb c ta tb
  va="$(patch_version "$1")"; vb="$(patch_version "$2")"
  if [[ -n $va && -n $vb ]]; then
    c="$(ver_cmp "$va" "$vb")"
    [[ $c == 1 ]] && return 0
    [[ $c == -1 ]] && return 1
  elif [[ -n $va ]]; then return 0
  elif [[ -n $vb ]]; then return 1
  fi
  ta="$(stat -c %Y "$1")"; tb="$(stat -c %Y "$2")"
  (( ta > tb + 2 ))
}
reconcile_tools() { # unzip, zip and sha256sum are needed before step 2 installs the rest
  local miss=() t s=""
  for t in unzip zip sha256sum stat; do command -v "$t" >/dev/null || miss+=("$t"); done
  ((${#miss[@]})) || return 0
  [[ $EUID -eq 0 ]] || s="sudo"
  info "Installing ${miss[*]} (needed to sync the patches)"
  [[ -n $PM ]] || fail "No supported package manager (apt-get, pacman, dnf, zypper). Install ${miss[*]} by hand and run again."
  pm_install zip unzip coreutils >/dev/null \
    || fail "Could not install ${miss[*]}; install them with your package manager (Arch: sudo pacman -Syu first, then pacman -S zip unzip) and run again."
}

reconcile_patches() {
  local tmp zd wd arch f n num best bside c has_zip=0
  local -A BYNUM=() SIDE=() R_SRC=() R_ACT=() R_VER=()
  local -a BAD=() CANDS=() FINAL=()

  [[ -d $PATCH_DIR || -f $PATCH_ZIP ]] \
    || fail "Neither assets/patches/ nor assets/patches.zip exists: put the patch files (NNNN-name.patch) into assets/patches/."
  reconcile_tools
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/kms-patches.XXXXXX")"
  # Decisions are made on copies; assets/ is only changed at the end.
  zd="$tmp/zip"; wd="$tmp/final"; arch="$tmp/archive"; mkdir -p "$zd" "$wd" "$arch"

  # the two sources: every valid patch file, grouped by its number
  if [[ -d $PATCH_DIR ]]; then
    for f in "$PATCH_DIR"/*.patch; do
      [[ -f $f ]] || continue; n="${f##*/}"
      if [[ $n =~ $PATCH_RE ]]; then BYNUM[${n:0:4}]+="$f"$'\n'; SIDE[$f]=folder
      else BAD+=("assets/patches/$n"); fi
    done
  fi
  if [[ -f $PATCH_ZIP ]]; then
    has_zip=1
    # unzip keeps each file's modification time, used when the VERSION lines are equal
    unzip -q -o -j "$PATCH_ZIP" -d "$zd" >/dev/null 2>&1 || fail "assets/patches.zip cannot be read (damaged zip?)."
    for f in "$zd"/*.patch; do
      [[ -f $f ]] || continue; n="${f##*/}"
      if [[ $n =~ $PATCH_RE ]]; then BYNUM[${n:0:4}]+="$f"$'\n'; SIDE[$f]=zip
      else BAD+=("patches.zip:$n"); fi
    done
  else
    info "assets/patches.zip is missing: it is built from assets/patches/."
  fi
  ((${#BAD[@]})) && warn "Ignored, the name must be NNNN-name.patch in lower case: ${BAD[*]}"
  ((${#BYNUM[@]})) || { rm -rf "$tmp"; fail "No patches in assets/patches/ or assets/patches.zip."; }

  # per number: the newest copy wins; the other copies go to archive/
  for num in $(printf '%s\n' "${!BYNUM[@]}" | LC_ALL=C sort); do
    mapfile -t CANDS < <(printf '%s' "${BYNUM[$num]}")
    best="${CANDS[0]}"
    for f in "${CANDS[@]:1}"; do
      if [[ $(sha "$f") == "$(sha "$best")" && ${f##*/} == "${best##*/}" ]]; then
        [[ ${SIDE[$f]} == folder ]] && best="$f"      # identical: keep the folder copy
      elif patch_newer "$f" "$best"; then best="$f"
      elif ! patch_newer "$best" "$f" && [[ ${SIDE[$f]} == folder && ${SIDE[$best]} == zip ]]; then best="$f"
      fi
    done
    n="${best##*/}"; bside="${SIDE[$best]}"
    cp -p "$best" "$wd/$n"; FINAL+=("$n"); R_VER[$n]="$(patch_version "$best")"

    local in_folder=0 in_zip=0 same=1
    for f in "${CANDS[@]}"; do
      [[ ${SIDE[$f]} == folder ]] && in_folder=1 || in_zip=1
      [[ ${f##*/} == "$n" && $(sha "$f") == "$(sha "$best")" ]] && continue
      same=0
      c="${f##*/}"
      cp -p "$f" "$arch/${SIDE[$f]}-$c"
      warn "${c%.patch} v$(patch_version "$f" || true) (${SIDE[$f]}) replaced by the newer ${n%.patch} v${R_VER[$n]:-?} ($bside)"
    done
    R_SRC[$n]="$bside"
    if (( in_folder && in_zip )); then
      if (( same )); then R_ACT[$n]=ok; else R_ACT[$n]=updated; R_SRC[$n]="$bside (newer)"; fi
    elif (( in_folder )); then
      if (( has_zip )); then R_ACT[$n]=new; info "new patch ${n%.patch} v${R_VER[$n]:-?}"; else R_ACT[$n]=ok; fi
      (( same )) || R_ACT[$n]=updated
    else
      R_ACT[$n]=restored; (( same )) || R_ACT[$n]=updated
    fi
  done

  local prev=0 gaps=()
  for n in "${FINAL[@]}"; do
    num=$((10#${n:0:4}))
    (( num == prev + 1 )) || gaps+=("$(printf '%04d' "$num") after $(printf '%04d' "$prev")")
    prev=$num
  done
  ((${#gaps[@]})) && warn "Patch numbering has gaps (${gaps[*]}); the patches are applied in sorted order."

  # commit the folder: exactly the final set; an old PATCHES.txt and replaced copies go to archive/
  mkdir -p "$PATCH_DIR"
  for n in $(list_patches "$PATCH_DIR"); do
    printf '%s\n' "${FINAL[@]}" | has_line "$n" || rm -f "$PATCH_DIR/$n"   # its copy is in archive/
  done
  for n in "${FINAL[@]}"; do cmp -s "$wd/$n" "$PATCH_DIR/$n" 2>/dev/null || cp -p "$wd/$n" "$PATCH_DIR/$n"; done
  if [[ -f $PATCH_DIR/PATCHES.txt ]]; then
    mv -f "$PATCH_DIR/PATCHES.txt" "$arch/folder-PATCHES.txt"; info "assets/patches/PATCHES.txt is no longer used: moved to archive/"
  fi
  if [[ -n $(ls -A "$arch") ]]; then
    mkdir -p "$ARCHIVE/$TS/patches"; mv -f "$arch"/* "$ARCHIVE/$TS/patches/"
    info "Replaced copies kept in archive/$TS/patches/"
  fi

  # is the zip already the same as the folder (flat, exactly the final patches, same contents)?
  local same_zip=1 want got
  if (( has_zip )); then
    want="$(printf '%s\n' "${FINAL[@]}" | LC_ALL=C sort)"
    got="$(unzip -Z1 "$PATCH_ZIP" 2>/dev/null | LC_ALL=C sort || true)"
    if [[ $want != "$got" ]]; then same_zip=0
    else
      for n in "${FINAL[@]}"; do
        [[ $(unzip -p "$PATCH_ZIP" "$n" | sha256sum | cut -c1-64) == "$(sha "$PATCH_DIR/$n")" ]] || { same_zip=0; break; }
      done
    fi
  else same_zip=0; fi

  if (( ! same_zip )); then
    # the files keep their modification times (and the zip stores them in UTC) for the next comparison
    (cd "$PATCH_DIR" && zip -q -D "$tmp/patches.zip" "${FINAL[@]}") || fail "Could not build patches.zip."
    if (( has_zip )); then mv "$PATCH_ZIP" "$ASSETS/patches.zip.bak-$TS"; info "Previous zip kept as assets/patches.zip.bak-$TS"; fi
    mv "$tmp/patches.zip" "$PATCH_ZIP"
    # verify: the new zip and the folder are identical
    rm -rf "$tmp/verify"; mkdir -p "$tmp/verify"
    unzip -q "$PATCH_ZIP" -d "$tmp/verify"
    [[ $(cd "$tmp/verify" && find . -type f | sed 's|^\./||' | LC_ALL=C sort) == "$(printf '%s\n' "${FINAL[@]}" | LC_ALL=C sort)" ]] \
      || fail "The rebuilt patches.zip does not hold the same files as assets/patches/."
    for n in "${FINAL[@]}"; do
      [[ $(sha "$tmp/verify/$n") == "$(sha "$PATCH_DIR/$n")" ]] || fail "The rebuilt patches.zip differs from assets/patches/ in $n."
    done
    PATCH_ZIP_REBUILT=1
    ok "assets/patches.zip rebuilt from assets/patches/ and verified (${#FINAL[@]} patches)"
  fi

  # summary table
  printf '         %-36s %-8s %-15s %s\n' "patch" "version" "source" "action"
  for n in "${FINAL[@]}"; do
    printf '         %-36s %-8s %-15s %s\n' "${n%.patch}" "${R_VER[$n]:-?}" "${R_SRC[$n]}" "${R_ACT[$n]}"
    case "${R_ACT[$n]}" in new|updated) PATCH_SET_CHANGED=1 ;; esac
  done
  if (( PATCH_SET_CHANGED )); then
    RECONCILE_RESULT="changed"; warn "patch set changed: step 4 applies it again and step 7 rebuilds Outline"
  elif (( PATCH_ZIP_REBUILT )) || printf '%s\n' "${R_ACT[@]}" | has_line restored; then
    RECONCILE_RESULT="synced"; ok "Patches: folder and zip synced (${#FINAL[@]} patches, set unchanged)"
  else
    ok "Patches: folder and zip identical (${#FINAL[@]} patches)"
  fi
  rm -rf "$tmp"
}

CUR_STEP=1   # a failure here is fixed by running the installer again
section "Step P: Sync assets/patches/ and assets/patches.zip"
reconcile_patches
CUR_STEP=0

# ----------------------------------------------------------------------------
# Step 0: place for the kms service (only while the kit has no install folder yet)
#   The kit (install.sh, assets/) stays where it is, e.g. ~/kms, and is the only source.
#   Step 0 picks the install folder (an existing installation, an empty disk formatted
#   and mounted, or the file system with most free space), adds swap if memory is
#   short and writes the folder to <kit>/.kms-target; old install.sh/assets copies in
#   the install folder go to its archive/.
# ----------------------------------------------------------------------------
MARK="$KMS/.kms-install"
if [[ ! -f $MARK && ! -f $KMS/config/secrets.env && ${KMS_NO_RELOCATE:-0} != 1 ]]; then
  section "Step 0/$STEPS: Place for the kms service (disk, folder, swap)"
  info "Started from the setup kit in $KMS."
  [[ -d $ASSETS ]] || fail "No assets/ folder next to install.sh ($ASSETS)."
  if [[ $EUID -eq 0 ]]; then SUDO=""; else SUDO="sudo"; command -v sudo >/dev/null || fail "sudo is required."; sudo -v || fail "sudo access is required."; fi
  ROOT_SRC="$(findmnt -no SOURCE / 2>/dev/null || true)"
  ROOT_DISK="$(lsblk -no PKNAME "$ROOT_SRC" 2>/dev/null | head -n1 || true)"
  # empty disks: no partitions, no file system, not mounted, not the system disk
  EMPTY=()
  while read -r d sz; do
    case "$(basename "$d")" in sr*|loop*|zram*|ram*|"$ROOT_DISK") continue ;; esac
    [[ $(lsblk -no NAME "$d" 2>/dev/null | wc -l) -eq 1 ]] || continue
    [[ -z $(lsblk -dno FSTYPE "$d" 2>/dev/null) && -z $(lsblk -dno MOUNTPOINT "$d" 2>/dev/null) ]] || continue
    EMPTY+=("$d|$sz")
  done < <(lsblk -dnpo NAME,TYPE,SIZE 2>/dev/null | awk '$2=="disk"{print $1, $3}')
  # mounted file systems with room (largest first)
  MOUNTS=()
  while read -r m av; do
    case "$m" in /boot*|/efi*|/run*|/dev*|/proc*|/sys*|/snap*|/var/lib/docker*) continue ;; esac
    (( av >= 10*1024*1024 )) || continue
    MOUNTS+=("$m|$av")
  done < <(df -P -k -l -x tmpfs -x devtmpfs -x overlay -x squashfs -x iso9660 -x vfat 2>/dev/null | awk 'NR>1{print $6, $4}' | sort -k2,2nr)
  OPTS=(); ACT=()
  for c in /srv/kms /opt/kms /srv/kmsdata; do
    [[ -f $c/config/secrets.env ]] && { OPTS+=("Use the existing installation in $c (data and secrets kept)"); ACT+=("dir:$c"); }
  done
  for e in "${EMPTY[@]}"; do OPTS+=("Format the empty disk ${e%%|*} (${e#*|}) as ext4, mount it on /srv, install in /srv/kms"); ACT+=("format:${e%%|*}"); done
  for e in "${MOUNTS[@]}"; do
    m="${e%%|*}"; t="$m/kms"
    if [[ $m == / ]]; then t="/srv/kms"; mountpoint -q /srv 2>/dev/null && t="/opt/kms"; fi
    printf '%s\n' "${ACT[@]}" | has_line "dir:$t" && continue
    OPTS+=("Install in $t ($(( ${e#*|} / 1024 / 1024 )) GB free on $m)"); ACT+=("dir:$t")
  done
  OPTS+=("Another folder (you type it)"); ACT+=("ask:")
  OPTS+=("Install right here ($KMS)"); ACT+=("here:")
  DEF=1; [[ $ASSUME_YES == 1 && ${#EMPTY[@]} -gt 0 ]] && DEF=$(( ${#EMPTY[@]} + 1 ))
  info "Disks:"; lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINTS 2>/dev/null | sed 's/^/           /' || true
  TARGET=""
  while [[ -z $TARGET ]]; do
    c="$(ask_choice "Where should the kms service (data, images, builds) live?" "$DEF" "${OPTS[@]}")"
    a="${ACT[$((c-1))]}"
    case "$a" in
      format:*)
        d="${a#format:}"; MNT="/srv"
        if mountpoint -q /srv || [[ -n $(ls -A /srv 2>/dev/null) ]]; then MNT="/srv/kmsdata"; fi
        MNT="$(ask_text "Mount point for $d" "$MNT")"
        [[ $ASSUME_YES == 1 ]] && fail "--yes never formats a disk; run without --yes or choose a folder."
        confirm_typed "Format $d: everything on this disk is erased" "$(lsblk -dno SIZE,MODEL "$d" 2>/dev/null) $d -> ext4 'kmsdata' on $MNT" || { warn "Not formatted."; continue; }
        $SUDO mkfs.ext4 -F -L kmsdata "$d" >/dev/null
        UUID="$($SUDO blkid -s UUID -o value "$d")"
        $SUDO mkdir -p "$MNT"
        $SUDO cp -p /etc/fstab "/etc/fstab.kms-bak-$TS"
        echo "UUID=$UUID $MNT ext4 defaults,nofail 0 2" | $SUDO tee -a /etc/fstab >/dev/null
        $SUDO systemctl daemon-reload 2>/dev/null || true
        $SUDO mount "$MNT" || fail "Could not mount $d on $MNT."
        ok "$d formatted and mounted on $MNT (fstab: UUID=$UUID, backup /etc/fstab.kms-bak-$TS)"
        TARGET="$MNT/kms"; [[ $MNT == /srv ]] || TARGET="$MNT"
        TARGET="$(ask_text "Install folder" "$TARGET")" ;;
      dir:*) TARGET="$(ask_text "Install folder" "${a#dir:}")" ;;
      ask:)  TARGET="$(ask_text "Install folder (absolute path)" "/srv/kms")" ;;
      here:) TARGET="$KMS" ;;
    esac
    [[ $TARGET == /* ]] || { warn "Use an absolute path."; TARGET=""; }
  done
  # swap: the Outline build needs about 6 GB of RAM + swap
  MEM_MB="$(awk '/MemTotal/{print int($2/1024)}' /proc/meminfo)"; SWAP_MB="$(awk '/SwapTotal/{print int($2/1024)}' /proc/meminfo)"
  if (( MEM_MB + SWAP_MB < 6000 )); then
    $SUDO mkdir -p "$TARGET"
    TMNT="$(df -P "$TARGET" | awk 'NR==2{print $6}')"; SWF="${TMNT%/}/swapfile"
    NEED_G=$(( (6144 - MEM_MB - SWAP_MB + 1023) / 1024 )); (( NEED_G >= 2 )) || NEED_G=2
    if [[ -e $SWF ]]; then info "$SWF exists already."
    elif ask_yn "RAM ${MEM_MB} MB + swap ${SWAP_MB} MB is short for the Outline build. Add a ${NEED_G} GB swap file $SWF?" y; then
      $SUDO fallocate -l "${NEED_G}G" "$SWF" 2>/dev/null || $SUDO dd if=/dev/zero of="$SWF" bs=1M count=$((NEED_G*1024)) status=none
      $SUDO chmod 600 "$SWF"; $SUDO mkswap "$SWF" >/dev/null; $SUDO swapon "$SWF"
      grep -qsF "$SWF " /etc/fstab || echo "$SWF none swap sw,nofail 0 0" | $SUDO tee -a /etc/fstab >/dev/null
      ok "Swap file $SWF (${NEED_G} GB) active and in /etc/fstab"
    fi
  else ok "Memory: ${MEM_MB} MB RAM + ${SWAP_MB} MB swap"; fi
  if [[ $TARGET == "$KMS" ]]; then
    touch "$MARK"; ok "Installing in $KMS"
  else
    $SUDO mkdir -p "$TARGET"; $SUDO chown "$(id -u):$(id -g)" "$TARGET"
    [[ -f $TARGET/config/secrets.env ]] && info "$TARGET is an existing installation: its data and secrets are kept."
    # only the kit is used: older copies of the installer and assets there are retired
    for f in install.sh INSTALL.md assets; do
      if [[ -e $TARGET/$f ]]; then
        mkdir -p "$TARGET/archive/$TS"; mv "$TARGET/$f" "$TARGET/archive/$TS/"
        info "Old $TARGET/$f moved to $TARGET/archive/$TS/ (the kit $KIT is the only source)"
      fi
    done
    touch "$TARGET/.kms-install"; printf '%s\n' "$TARGET" >"$TARGET_FILE"
    set_kms "$TARGET"; mkdir -p "$LOGS"
    ok "Install folder: $TARGET (kept in $TARGET_FILE). Always run: bash $SELF"
  fi
fi

CUR_STEP=1; section "Step 1/$STEPS: Check the system and the assets (read only)"
[[ $(uname -s) == Linux && -r /etc/os-release ]] || fail "Linux with /etc/os-release required."
# read in a subshell: /etc/os-release defines VERSION too
osr() { (. /etc/os-release; eval "printf '%s' \"\${$1:-}\""); }
OS_ID="$(osr ID)"; SUITE="$(osr VERSION_CODENAME)"
ARCH="$(dpkg --print-architecture 2>/dev/null || true)"
if [[ -z $ARCH ]]; then case "$(uname -m)" in x86_64) ARCH=amd64 ;; aarch64|arm64) ARCH=arm64 ;; *) ARCH="$(uname -m)" ;; esac; fi
info "OS: $(osr PRETTY_NAME) | suite: ${SUITE:-?} | arch: $ARCH | kernel: $(uname -r)"
[[ -n $PM ]] || fail "No supported package manager found (apt-get, pacman, dnf or zypper)."
if [[ $OS_ID == debian ]]; then
  [[ -n $SUITE ]] || fail "Cannot read the Debian codename (VERSION_CODENAME) from /etc/os-release."
else
  info "Host is '$OS_ID' ($PM): host tools come from its own repositories; the Docker images are still built on Debian."
fi
if [[ $EUID -eq 0 ]]; then SUDO=""; warn "Running as root; files in $KMS will be owned by root. Recommended: a normal user with sudo."
else
  SUDO="sudo"; command -v sudo >/dev/null || fail "sudo is required (install sudo and allow $USER to use it)."
  sudo -v || fail "sudo access is required."
  ( while true; do sleep 50; sudo -n true 2>/dev/null || exit; done ) & SUDO_KEEPALIVE=$!
  ok "sudo access confirmed (kept alive during the run)"
fi
CPU="$(nproc)"; MEM_MB="$(awk '/MemTotal/{print int($2/1024)}' /proc/meminfo)"
SWAP_MB="$(awk '/SwapTotal/{print int($2/1024)}' /proc/meminfo)"
mkdir -p "$KMS"; DISK_GB="$(df -Pk "$KMS" | awk 'NR==2{print int($4/1024/1024)}')"
info "CPU: $CPU | RAM: ${MEM_MB} MB | swap: ${SWAP_MB} MB | free disk: ${DISK_GB} GB"
(( DISK_GB >= 6 )) || fail "Less than 6 GB free disk in $KMS."
if (( DISK_GB < 15 )); then warn "Less than 15 GB free: the Outline build and images need about 10 GB."; else ok "Disk space"; fi
if (( MEM_MB + SWAP_MB < 6000 )); then warn "Less than 6 GB RAM+swap: the Outline frontend build may run out of memory."; else ok "Memory"; fi

# assets
[[ -d $ASSETS ]] || fail "No assets/ folder next to install.sh ($ASSETS)."
for f in "$SRC_ZIP_NAME" fonts.zip; do [[ -f $ASSETS/$f ]] || fail "Missing assets/$f"; done
SSOZIA_ASSET=""
for c in "$ASSETS/ssozia.zip" "$ASSETS/ssozia"; do [[ -e $c ]] && { SSOZIA_ASSET="$c"; break; }; done
[[ -n $SSOZIA_ASSET ]] || fail "Missing assets/ssozia.zip (or an assets/ssozia/ folder)."
command -v unzip >/dev/null || { info "Installing unzip to read the assets"; pm_install unzip >/dev/null || fail "Could not install unzip."; }
unzip -Z1 "$SRC_ZIP" | has_line "$SRC_NAME/package.json" || fail "assets/$SRC_ZIP_NAME has no $SRC_NAME/package.json."
# patches: whatever step P left in assets/patches/ (no names, counts or versions are fixed here)
mapfile -t ZP < <(list_patches "$PATCH_DIR")
((${#ZP[@]})) || fail "assets/patches/ holds no patch (NNNN-name.patch)."
PV=(); NOVER=()
for p in "${ZP[@]}"; do v="$(patch_version "$PATCH_DIR/$p")"; PV+=("${p%%-*}:${v:-?}"); [[ -n $v ]] || NOVER+=("$p"); done
info "Patches (${#ZP[@]}): ${PV[*]}"
((${#NOVER[@]})) && warn "No parsable VERSION line (x.y or x.y.z) in: ${NOVER[*]}"
mapfile -t ZF < <(unzip -Z1 "$ASSETS/fonts.zip" | awk -F/ 'NF && $NF!="" {print $NF}' | sort -u)
MISSING_FONTS=(); for f in "${EXPECTED_FONTS[@]}"; do printf '%s\n' "${ZF[@]}" | has_line "$f" || MISSING_FONTS+=("$f"); done
((${#MISSING_FONTS[@]})) && warn "fonts.zip lacks: ${MISSING_FONTS[*]}" || ok "fonts.zip has all ${#EXPECTED_FONTS[@]} fonts"
if [[ -d $SSOZIA_ASSET ]]; then [[ -f $SSOZIA_ASSET/Cargo.toml ]] || fail "assets/ssozia/ has no Cargo.toml"
else unzip -Z1 "$SSOZIA_ASSET" | grep -E '(^|/)Cargo\.toml$' >/dev/null || fail "assets/ssozia.zip has no Cargo.toml"; fi
ok "Assets: $SRC_ZIP_NAME (Outline $TAG), patches (${#ZP[@]}), fonts.zip, $(basename "$SSOZIA_ASSET")"
VENDOR_KEY="$ASSETS/license/vendor-public.json"
if [[ -f $VENDOR_KEY ]] && grep -q '"sign"' "$VENDOR_KEY" && grep -q '"box"' "$VENDOR_KEY"; then
  ok "License: vendor public key assets/license/vendor-public.json"
  grep -q '"d"' "$VENDOR_KEY" && fail "assets/license/vendor-public.json contains a PRIVATE key; use the vendor-public.json made by kms-license.mjs keygen."
else
  warn "assets/license/vendor-public.json is missing: licenses cannot be checked and Outline stays read-only."
fi
[[ -f $CONFIG/secrets.env ]] && info "Existing installation found in $KMS (config/secrets.env): data and secrets are kept unless you choose otherwise."
ask_yn "Continue with the installation?" y || { info "Nothing changed."; exit 0; }

# ----------------------------------------------------------------------------
# Docker access helper (works before and after the docker group applies)
# ----------------------------------------------------------------------------
# DK_MODE is fixed once docker runs (a docker group added now only applies after the next login).
DK_MODE=""
dk_mode() { if [[ -z $SUDO ]] || docker info >/dev/null 2>&1; then DK_MODE=direct; else DK_MODE=sudo; fi; }
dk() {
  [[ -n $DK_MODE ]] || dk_mode
  if [[ $DK_MODE == direct ]]; then docker "$@"; else $SUDO --preserve-env=DOCKER_BUILDKIT docker "$@"; fi
}
dc() { (cd "$KMS" && dk compose -p "$PROJECT" -f "$KMS/docker-compose.yml" "$@"); }

# ----------------------------------------------------------------------------
# Step 2: dependencies
# ----------------------------------------------------------------------------
node_ok() { # node_ok VERSION: Outline engines + vite (20.19+ <21, 22.12+, 24 <24.17, 26 <26.3.1)
  local v="$1" ma mi pa; IFS=. read -r ma mi pa <<<"$v"; mi="${mi:-0}"; pa="${pa:-0}"
  [[ $ma =~ ^[0-9]+$ && $mi =~ ^[0-9]+$ && $pa =~ ^[0-9]+$ ]] || return 1
  case "$ma" in
    20) (( mi >= 19 )) ;; 22) (( mi >= 12 )) ;; 24) (( mi < 17 )) ;;
    26) (( mi < 3 || (mi == 3 && pa < 1) )) ;; *) return 1 ;;
  esac
}
APT_PKGS=(ca-certificates curl git unzip zip rsync jq openssl xz-utils file iproute2 debootstrap
          build-essential pkg-config mkcert libnss3-tools python3)
# Host tools on other distributions (same roles as APT_PKGS; Rust comes from the distribution too).
case "$PM" in
  pacman) FOREIGN_PKGS=(ca-certificates curl git unzip zip rsync jq openssl xz file iproute2 base-devel pkgconf nss python rust) ;;
  dnf)    FOREIGN_PKGS=(ca-certificates curl git unzip zip rsync jq openssl xz file iproute pkgconf-pkg-config gcc gcc-c++ make nss-tools python3 cargo rust) ;;
  zypper) FOREIGN_PKGS=(ca-certificates curl git unzip zip rsync jq openssl xz file iproute2 pkg-config gcc gcc-c++ make mozilla-nss-tools python3 cargo rust) ;;
  *)      FOREIGN_PKGS=() ;;
esac
NODE_MODE=""; DOCKER_FROM=""
apt_mirror() { # first Debian URI configured on this host
  { grep -hE '^URIs:' /etc/apt/sources.list.d/*.sources 2>/dev/null | awk '{print $2}'
    grep -hE '^deb ' /etc/apt/sources.list /etc/apt/sources.list.d/*.list 2>/dev/null | awk '{for(i=2;i<=NF;i++) if($i ~ /^https?:/){print $i; break}}'
  } | grep -v -e security -e docker -e dietpi | head -n1 || true
}
apt_security() { # the host's Debian security URI, if any
  { grep -hE '^URIs:' /etc/apt/sources.list.d/*.sources 2>/dev/null | awk '{print $2}'
    grep -hE '^deb ' /etc/apt/sources.list /etc/apt/sources.list.d/*.list 2>/dev/null | awk '{for(i=2;i<=NF;i++) if($i ~ /^https?:/){print $i; break}}'
  } | grep -e debian-security | head -n1 || true
}
apt_ok() { # does an apt source provide the installed libc6? (else apt cannot install anything)
  LANG=C apt-cache policy libc6 2>/dev/null | awk '
    /^ \*\*\* /{inb=1; next}
    /^     [^ ]/{inb=0; next}
    inb && NF>=2 && $2 !~ /dpkg\/status/ {ok=1}
    END{exit !ok}'
}
apt_suite() { # the Debian suite apt installs libc6 from (sid, forky, trixie, ...)
  LANG=C apt-cache policy libc6 2>/dev/null | awk '
    /^ \*\*\* /{inb=1; next}
    /^     [^ ]/{inb=0; next}
    inb && NF>=3 && $2 !~ /dpkg\/status/ {split($3,a,"/"); print a[1]; exit}' \
  | sed -E 's/-(updates|security|backports|proposed-updates)$//; s/^unstable$/sid/' || true
}
write_sources() { # write_sources SUITE MIRROR : backs up the old apt sources, writes one sources.list
  local suite="$1" mirror="$2" sec bk="/etc/apt/sources-backup-$TS"
  sec="$(apt_security)"; [[ -n $sec ]] || sec="${mirror%/debian}/debian-security"
  $SUDO mkdir -p "$bk"
  for f in /etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources; do
    [[ -f $f ]] || continue
    grep -q -e download.docker.com "$f" && continue
    $SUDO mv "$f" "$bk/"
  done
  {
    echo "# VERSION: $VERSION - written by kms install.sh (old files: $bk)"
    echo "deb $mirror $suite main contrib non-free-firmware"
    if [[ $suite != sid && $suite != unstable ]]; then
      echo "deb $mirror $suite-updates main contrib non-free-firmware"
      echo "deb $sec $suite-security main contrib non-free-firmware"
    fi
  } | $SUDO tee /etc/apt/sources.list >/dev/null
  ok "apt sources: $suite from $mirror (old files in $bk)"
}
if step "Install missing dependencies (package manager: ${PM:-none})" 1 \
   "Tools: $([[ $PM == apt-get ]] && echo "${APT_PKGS[*]}" || echo "${FOREIGN_PKGS[*]} mkcert")" \
   "Rust (cargo, rustc) and Node.js for the host builds; Docker Engine + Compose v2."; then
  if [[ $PM == apt-get ]]; then apt_update; fi
  # apt sources must match the installed system (a sid system with trixie sources installs nothing)
  if [[ $PM != apt-get || $OS_ID != debian ]]; then :
  elif ! apt_ok; then
    LIBC_V="$(dpkg-query -W -f='${Version}' libc6 2>/dev/null || echo '?')"
    warn "No apt source provides the installed libc6 $LIBC_V: the apt sources do not match this system."
    MIRROR="$(apt_mirror)"; MIRROR="${MIRROR:-http://deb.debian.org/debian}"
    TRY=("$SUITE" sid); [[ $SUITE == sid ]] && TRY=(sid)
    for s in "${TRY[@]}"; do
      ask_yn "Write apt sources for '$s' from $MIRROR (old files are kept in a backup folder)?" y \
        || fail "apt cannot install packages with the current sources; fix /etc/apt/sources.list and run --from 2."
      MIRROR="$(ask_text "Debian mirror" "$MIRROR")"
      write_sources "$s" "$MIRROR"
      apt_update
      if apt_ok; then ok "apt sources now match the system (libc6 $LIBC_V from '$s')"; break; fi
      warn "Still no source for libc6 $LIBC_V with '$s'."
    done
    apt_ok || fail "No suite matched; check 'apt-cache policy libc6' and /etc/apt/sources.list, then --from 2."
  else ok "apt sources match the system ($(apt_suite))"; fi
  MISS=()
  if [[ $PM == apt-get ]]; then for p in "${APT_PKGS[@]}"; do dpkg -s "$p" >/dev/null 2>&1 || MISS+=("$p"); done
  else MISS=("${FOREIGN_PKGS[@]}"); fi
  # Rust: an existing cargo (e.g. rustup) is kept; otherwise the distribution's.
  [[ -f $HOME/.cargo/env ]] && . "$HOME/.cargo/env"
  if command -v cargo >/dev/null; then ok "Rust on host: $(cargo --version)"
    if [[ $PM != apt-get ]]; then   # a rustup cargo is kept: do not install the distribution's rust
      _m=(); for p in "${MISS[@]}"; do [[ $p == rust || $p == cargo ]] || _m+=("$p"); done; MISS=("${_m[@]}")
    fi
  elif [[ $PM == apt-get ]]; then MISS+=(cargo rustc); fi
  # Node: Debian's if it fits Outline, else the official build (downloaded in step 7).
  NODE_CAND=""; NODE_CAND_V=""
  if [[ $PM == apt-get && $OS_ID == debian ]]; then
    NODE_CAND="$(apt-cache policy nodejs 2>/dev/null | awk '/Candidate:/{print $2}')"
    NODE_CAND_V="$(sed -E 's/^[0-9]+://; s/[+~-].*//' <<<"$NODE_CAND")"
  fi
  if [[ $PM != apt-get || $OS_ID != debian ]]; then
    NODE_MODE=tarball
    info "Node.js: the official build $NODE_TARBALL_VER is downloaded in step 7 (the images are Debian, the host is '$OS_ID')."
  elif [[ -n $NODE_CAND && $NODE_CAND != "(none)" ]] && node_ok "$NODE_CAND_V"; then
    NODE_MODE=debian; dpkg -s nodejs >/dev/null 2>&1 || MISS+=(nodejs)
    ok "Node.js: Debian package $NODE_CAND (fits Outline)"
  else
    NODE_MODE=tarball
    warn "Debian nodejs ${NODE_CAND:-none} does not fit Outline (needs 20.19+, 22.12+, 24.0-24.16 or 26.0-26.3.0): the official Node $NODE_TARBALL_VER is downloaded in step 7."
  fi
  if [[ $PM == apt-get ]]; then
    if ((${#MISS[@]})); then
      info "Installing: ${MISS[*]}"
      apt_ install -y --no-install-recommends "${MISS[@]}"
    fi
  else
    mapfile -t MISS < <(printf '%s\n' "${MISS[@]}" | awk 'NF')
    if ((${#MISS[@]})); then
      info "Installing: ${MISS[*]}"
      pm_install "${MISS[@]}" || fail "Installing the host tools failed (Arch/Manjaro: run 'sudo pacman -Syu' first, then --from 2)."
    fi
    command -v mkcert >/dev/null || pm_install mkcert || warn "mkcert is not in your repositories: install it by hand (https://github.com/FiloSottile/mkcert) before step 5."
  fi
  ok "Tools present"
  # Docker
  KMS_MNT="$(df -P "$KMS" | awk 'NR==2{print $6}')"
  if ! command -v docker >/dev/null && [[ ! -f /etc/docker/daemon.json && $KMS_MNT != / ]] \
     && [[ $(df -P /var/lib | awk 'NR==2{print $6}') != "$KMS_MNT" ]]; then
    if ask_yn "kms is on its own disk ($KMS_MNT). Store Docker images there too ($KMS_MNT/docker)?" y; then
      $SUDO mkdir -p /etc/docker "$KMS_MNT/docker"
      printf '{ "data-root": "%s/docker" }\n' "$KMS_MNT" | $SUDO tee /etc/docker/daemon.json >/dev/null
      ok "Docker data-root: $KMS_MNT/docker"
    fi
  fi
  if ! command -v docker >/dev/null && [[ $PM != apt-get ]]; then
    DOCKER_FROM=distro
    case "$PM" in
      pacman) pm_install docker docker-compose docker-buildx ;;
      dnf)    pm_install moby-engine docker-compose || pm_install docker docker-compose ;;
      zypper) pm_install docker docker-compose ;;
    esac || fail "Docker could not be installed from the distribution packages; install Docker Engine + Compose v2 by hand and run --from 2."
    if [[ $PM == dnf ]]; then pm_install docker-buildx >/dev/null 2>&1 || true; fi
  elif ! command -v docker >/dev/null; then
    case "$(ask_choice "Docker is not installed. Install it from:" 1 \
            "Debian packages (docker.io, docker-compose, docker-buildx) from your mirror" \
            "Docker's official repository (download.docker.com)")" in
      1) DOCKER_FROM=debian
         apt_ install -y docker.io docker-compose || apt_ install -y docker.io
         apt_ install -y docker-buildx 2>/dev/null || warn "docker-buildx not available; the classic builder is used." ;;
      2) DOCKER_FROM=official; DOCKER_OS=debian; [[ $OS_ID == ubuntu ]] && DOCKER_OS=ubuntu
         $SUDO install -m 0755 -d /etc/apt/keyrings
         $SUDO curl -fsSL "https://download.docker.com/linux/${DOCKER_OS}/gpg" -o /etc/apt/keyrings/docker.asc
         $SUDO chmod a+r /etc/apt/keyrings/docker.asc
         echo "deb [arch=$ARCH signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/${DOCKER_OS} $SUITE stable" \
           | $SUDO tee /etc/apt/sources.list.d/docker.list >/dev/null
         apt_update
         apt_ install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin \
           || fail "Docker could not be installed from download.docker.com (blocked?); run --from 2 and choose the Debian packages." ;;
    esac
  fi
  $SUDO systemctl enable --now docker >/dev/null 2>&1 || $SUDO service docker start || true
  for _ in $(seq 1 20); do $SUDO docker info >/dev/null 2>&1 && break; sleep 2; done
  DK_MODE=""; dk_mode
  dk info >/dev/null 2>&1 || fail "Docker daemon is not running."
  dk compose version >/dev/null 2>&1 || fail "Docker Compose v2 ('docker compose') is missing; install docker-compose (Debian) or docker-compose-plugin (Docker repo)."
  ok "Docker $(dk version --format '{{.Server.Version}}') | Compose $(dk compose version --short)"
  if [[ $EUID -ne 0 ]] && ! id -nG "$USER" | tr ' ' '\n' | has_line docker; then
    if ask_yn "Add $USER to the docker group (docker without sudo after the next login)?" y; then
      $SUDO usermod -aG docker "$USER"; ok "Added $USER to group docker (this run uses sudo)"
    fi
  fi
else
  [[ -f $HOME/.cargo/env ]] && . "$HOME/.cargo/env"
fi
# Decide the Node mode also when step 2 was skipped.
if [[ -z $NODE_MODE ]]; then
  if [[ $PM == apt-get && $OS_ID == debian ]] && command -v node >/dev/null && [[ $(command -v node) == /usr/bin/node ]] && node_ok "$(node -v | tr -d v)"; then NODE_MODE=debian
  else NODE_MODE=tarball; fi
fi
DOCKER_BUILD=(build --network host)
dk buildx version >/dev/null 2>&1 || export DOCKER_BUILDKIT=0

# ----------------------------------------------------------------------------
# Step 3: stop the running system
# ----------------------------------------------------------------------------
declare -A STOP_PROJ=(); STOP_CT=()
if command -v docker >/dev/null && dk info >/dev/null 2>&1; then
  for n in $(dk ps --format '{{.Names}}'); do
    proj="$(dk inspect -f '{{index .Config.Labels "com.docker.compose.project"}}' "$n" 2>/dev/null || true)"
    wd="$(dk inspect -f '{{index .Config.Labels "com.docker.compose.project.working_dir"}}' "$n" 2>/dev/null || true)"
    hit=0
    case "$n" in outline|outline-*|ssozia|ssozia-*|kms-*) hit=1 ;; esac
    [[ $proj == "$PROJECT" ]] && hit=1
    dk port "$n" 2>/dev/null | grep -E ':(80|443|3000)$' >/dev/null && hit=1
    (( hit )) || continue
    if [[ -n $proj ]]; then STOP_PROJ["$proj"]="${wd:-?}"; else STOP_CT+=("$n"); fi
  done
fi
STOP_DESC=()
for p in "${!STOP_PROJ[@]}"; do STOP_DESC+=("compose project $p (${STOP_PROJ[$p]}): docker compose -p $p down (volumes and data kept)"); done
for c in "${STOP_CT[@]}"; do STOP_DESC+=("container $c: docker stop"); done
((${#STOP_DESC[@]})) || STOP_DESC=("nothing of Outline/ssozia/kms is running")
if step "Stop the running system" "$( ((${#STOP_PROJ[@]} + ${#STOP_CT[@]})) && echo 1 || echo 2)" "${STOP_DESC[@]}"; then
  for p in "${!STOP_PROJ[@]}"; do dk compose -p "$p" down; ok "Stopped $p (data kept)"; done
  for c in "${STOP_CT[@]}"; do dk stop "$c" >/dev/null; ok "Stopped container $c"; done
  # checked after stopping, as root (to see the program); Docker's own proxy is not a conflict
  HOST_PORTS="$( ($SUDO ss -ltnpH 2>/dev/null || true) | awk '$4 ~ /:(80|443)$/' | grep -v -e docker-proxy -e dockerd || true)"
  if [[ -n $HOST_PORTS ]]; then
    warn "Host programs listen on port 80/443 (Caddy needs them):"; printf '         %s\n' "$HOST_PORTS"
    warn "Stop them (e.g. sudo systemctl disable --now nginx apache2 caddy) before step 10."
  fi
  if [[ -d $DATA ]] && [[ -n $(ls -A "$DATA" 2>/dev/null) ]]; then
    if [[ $ASSUME_YES == 0 ]] && ask_yn "Wipe kms/data (database, Redis, uploads, SSO keys) for a completely new start?" n; then
      if confirm_typed "Delete ALL data in $DATA" "$DATA/postgres" "$DATA/redis" "$DATA/outline" "$DATA/ssozia" "$DATA/caddy"; then
        mkdir -p "$ARCHIVE"
        # the license (activation code, trial start) is not workspace data: it is kept
        [[ -d $DATA/license ]] && $SUDO mv "$DATA/license" "$KMS/.license-keep"
        $SUDO rm -rf "$DATA"; ok "Deleted $DATA (license kept)"
        [[ -d $KMS/.license-keep ]] && { mkdir -p "$DATA"; $SUDO mv "$KMS/.license-keep" "$DATA/license"; }
        WIPED=1
      fi
    fi
  fi
fi

# ----------------------------------------------------------------------------
# Step 4: Outline source, patches, fonts
# ----------------------------------------------------------------------------
patches_applied() { # pristine copies of the touched files + every patch in assets/patches/ == the files in build/?
  local chk="$STAGE/chk" p f
  rm -rf "$chk"; mkdir -p "$chk/$SRC_NAME"
  unzip -q -o "$SRC_ZIP" "${PATCHED_FILES[@]/#/$SRC_NAME/}" -d "$chk" 2>/dev/null || true
  for p in "${PATCH_FILES[@]}"; do
    git -C "$chk/$SRC_NAME" apply "$PATCH_DIR/$p" 2>/dev/null || return 1
  done
  for f in "${PATCHED_FILES[@]}"; do
    if [[ -e $chk/$SRC_NAME/$f ]]; then cmp -s "$chk/$SRC_NAME/$f" "$SRC/$f" || return 1
    else [[ ! -e $SRC/$f ]] || return 1; fi
  done
}
# The patch set fingerprint: the patch files (name + sha256) + the Outline source zip. build/.kms-patches records the
# set applied in step 4; images/outline/app/.kms-patches the set built in step 7;
# images/outline/.kms-patches-image the set inside the image of step 8.
patch_fp() {
  local p
  { for p in $(list_patches "$PATCH_DIR"); do printf '%s  %s\n' "$(sha "$PATCH_DIR/$p")" "$p"; done
    sha "$SRC_ZIP"; } | sha256sum | cut -c1-64
}
marker_fp() { if [[ -f $1 ]]; then awk '$1=="fingerprint"{print $2; exit}' "$1"; fi; }
write_patch_marker() { # write_patch_marker FILE
  local p
  {
    echo "# kms applied patch set - VERSION: install.sh $VERSION, written after step 4 on $(date '+%Y-%m-%d %H:%M')"
    echo "fingerprint $PATCH_FP"
    echo "source $(sha "$SRC_ZIP") $SRC_ZIP_NAME"
    for p in "${PATCH_FILES[@]}"; do echo "patch $p $(patch_version "$PATCH_DIR/$p") $(sha "$PATCH_DIR/$p")"; done
  } >"$1"
}
STAGE="$(mktemp -d "$KMS/.stage.XXXXXX")"
mapfile -t PATCH_FILES < <(list_patches "$PATCH_DIR")
((${#PATCH_FILES[@]})) || fail "assets/patches/ holds no patch."
mapfile -t PATCHED_FILES < <(for p in "${PATCH_FILES[@]}"; do sed -n 's#^+++ b/##p; s#^--- a/##p' "$PATCH_DIR/$p"; done | sort -u)
PATCH_FP="$(patch_fp)"
export GIT_CEILING_DIRECTORIES="$BUILD"
SRC_STATE="missing"
if [[ -f $SRC/package.json ]]; then
  if [[ $(marker_fp "$BUILD/.kms-patches") == "$PATCH_FP" ]] && patches_applied; then SRC_STATE="patched"
  elif patches_applied; then SRC_STATE="patched"; write_patch_marker "$BUILD/.kms-patches"; info "build/.kms-patches written for the existing patched tree"
  else SRC_STATE="present, not patched with the current patch set"; fi
fi
PATCHES_REAPPLIED=0
if [[ $SRC_STATE != patched ]] && (( FROM > 4 )); then
  FORCE_STEP=1; FORCE_REASON="build/$SRC_NAME is not patched with the current patch set"
fi
if step "Outline source: unzip, apply the patches, check them, unzip fonts" "$([[ $SRC_STATE == patched ]] && echo 2 || echo 1)" \
   "Current: build/$SRC_NAME is $SRC_STATE." \
   "Unzips assets/$SRC_ZIP_NAME into build/$SRC_NAME (a previous tree is moved to archive/)," \
   "applies the ${#PATCH_FILES[@]} patches of assets/patches/ in order (each checked first), verifies them," \
   "and unzips the fonts into build/$SRC_NAME/public/fonts/."; then
  mkdir -p "$BUILD"
  rm -f "$BUILD/.kms-patches"
  if [[ -e $SRC ]]; then
    mkdir -p "$ARCHIVE/$TS"; mv "$SRC" "$ARCHIVE/$TS/$SRC_NAME"; ok "Previous source moved to archive/$TS/$SRC_NAME"
  fi
  unzip -q "$SRC_ZIP" -d "$STAGE/src"
  [[ -f $STAGE/src/$SRC_NAME/package.json ]] || fail "assets/$SRC_ZIP_NAME: no $SRC_NAME/ folder."
  mv "$STAGE/src/$SRC_NAME" "$SRC"
  ok "Unzipped Outline $TAG into build/$SRC_NAME"
  for p in "${PATCH_FILES[@]}"; do
    v="$(patch_version "$PATCH_DIR/$p")"
    info "Applying $p v${v:-?}"
    git -C "$SRC" apply --check "$PATCH_DIR/$p" 2>"$STAGE/apply.log" \
      || { cat "$STAGE/apply.log"; fail "$p (v${v:-?}) does not apply to a clean $TAG with the patches before it (git output above)."; }
    git -C "$SRC" apply "$PATCH_DIR/$p" 2>"$STAGE/apply.log" || { cat "$STAGE/apply.log"; fail "Applying $p failed (git output above)."; }
    ok "Applied $p v${v:-?}"
  done
  patches_applied || fail "Verification failed: not every patch is present in build/$SRC_NAME."
  ok "Verified: all ${#PATCH_FILES[@]} patches are applied"
  # fonts
  mkdir -p "$SRC/public/fonts" "$STAGE/fonts"
  unzip -q -o "$ASSETS/fonts.zip" -d "$STAGE/fonts"
  find "$STAGE/fonts" -type f -iname '*.woff2' -exec cp -f {} "$SRC/public/fonts/" \;
  # names.json from fonts.zip only when no patch provides it (a patched file must stay as patched)
  if printf '%s\n' "${PATCHED_FILES[@]}" | has_line "public/fonts/names.json"; then
    info "public/fonts/names.json comes from the patches (fonts.zip's copy is not used)"
  else
    find "$STAGE/fonts" -type f -name names.json -exec cp -f {} "$SRC/public/fonts/" \;
  fi
  MISSING=()
  while IFS= read -r f; do [[ -f $SRC/public/fonts/$f ]] || MISSING+=("$f"); done < <(grep -o '{cdn-url}/fonts/[^")]*' "$SRC/server/static/index.html" | sed 's|{cdn-url}/fonts/||' | sort -u)
  if ((${#MISSING[@]})); then warn "Fonts used by index.html but missing: ${MISSING[*]}"
  else ok "Fonts: $(find "$SRC/public/fonts" -name '*.woff2' | wc -l) files in public/fonts, every font in index.html present"; fi
  write_patch_marker "$BUILD/.kms-patches"
  PATCHES_REAPPLIED=1
  ok "build/.kms-patches: ${#PATCH_FILES[@]} patches, fingerprint ${PATCH_FP:0:12}"
fi

# ----------------------------------------------------------------------------
# License identity of this server (KMS patch 0008-license): created once by the
# installer (as root), read-only inside the Outline container.
#   config/license/install.json     random installation ID
#   config/license/server-key.pem   Ed25519 private key (signs renewal requests)
#   config/license/server-pub.pem   its public key (named in the license)
#   config/license/server-box.pem   X25519 private key: activation codes are encrypted to it
#   config/license/trial.json       when the trial started (kept across reinstalls)
#   config/license/hardware.json    sha256 of hardware identifiers, refreshed each run
# ----------------------------------------------------------------------------
LIC_DIR="$CONFIG/license"; LIC_DATA="$DATA/license"; OUTLINE_UID=1001
hw_hash() { printf 'kms-hw-v1|%s|%s' "$1" "$2" | sha256sum | cut -c1-64; }
hw_clean() { tr -d '\000\r\n\t ' | tr 'A-Z' 'a-z'; }
hw_placeholder() { # ids that many boards share are useless for binding
  [[ -z $1 || $1 =~ ^[0f-]+$ || $1 == 03000200-0400-0500-0006-000700080009 || $1 == "not settable" || $1 == "default string" ]]
}
hw_collect() { # prints "name value" lines for the identifiers this machine has
  local v ifc
  v="$( { $SUDO cat /sys/class/dmi/id/product_uuid 2>/dev/null || true; } | hw_clean)"
  if hw_placeholder "$v"; then v="$( { tr -d '\000' 2>/dev/null </proc/device-tree/serial-number || true; } | hw_clean)"; fi
  if hw_placeholder "$v"; then v="$(awk -F': *' '/^Serial/{print $2; exit}' /proc/cpuinfo 2>/dev/null | hw_clean || true)"; fi
  hw_placeholder "$v" || echo "machine $v"
  v="$( { cat /etc/machine-id 2>/dev/null || true; } | hw_clean)"
  hw_placeholder "$v" || echo "machineid $v"
  v="$( { findmnt -no UUID / 2>/dev/null || true; } | hw_clean)"
  if [[ -z $v ]]; then v="$( { $SUDO blkid -s UUID -o value "$(findmnt -no SOURCE / 2>/dev/null)" 2>/dev/null || true; } | hw_clean)"; fi
  hw_placeholder "$v" || echo "disk $v"
  ifc="$(ip -4 route show default 2>/dev/null | awk '{for(i=1;i<NF;i++) if($i=="dev"){print $(i+1); exit}}' || true)"
  if [[ -n $ifc && -r /sys/class/net/$ifc/address ]]; then
    v="$(hw_clean </sys/class/net/"$ifc"/address)"
    hw_placeholder "${v//:/}" || echo "mac $v"
  fi
}
license_trial_sync() { # the trial start lives in data/license/state.json (written by Outline); keep a copy in config
  local st="$LIC_DATA/state.json" keep="$LIC_DIR/trial.json" t=""
  $SUDO test -f "$st" && t="$($SUDO sed -n 's/.*"trialStartedAt":"\([^"]*\)".*/\1/p' "$st" | head -n1)"
  if [[ -n $t ]] && ! $SUDO test -f "$keep"; then
    printf '{ "trialStartedAt": "%s" }\n' "$t" | $SUDO tee "$keep" >/dev/null; $SUDO chmod 644 "$keep"
  elif [[ -z $t ]] && $SUDO test -f "$keep"; then
    t="$($SUDO sed -n 's/.*"trialStartedAt": *"\([^"]*\)".*/\1/p' "$keep" | head -n1)"
    if [[ -n $t ]]; then
      mkdir -p "$DATA"; $SUDO mkdir -p "$LIC_DATA"
      printf '{"trialStartedAt":"%s"}\n' "$t" | $SUDO tee "$st" >/dev/null
      $SUDO chown "$OUTLINE_UID:$OUTLINE_UID" "$st"
      info "License: trial start $t restored from config/license/trial.json"
    fi
  fi
}
write_license_identity() { # write_license_identity : keys and install ID once, hardware.json every time
  local tmp n v comps="" count=0
  $SUDO mkdir -p "$LIC_DIR"
  # config/license is 750 root:outline, so a normal user checks files with sudo
  if ! $SUDO test -f "$LIC_DIR/install.json"; then
    printf '{ "VERSION": "install.sh %s", "installId": "%s", "created": "%s" }\n' \
      "$VERSION" "$(openssl rand -hex 16)" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" | $SUDO tee "$LIC_DIR/install.json" >/dev/null
    ok "License identity: new installation ID"
  fi
  if ! $SUDO test -f "$LIC_DIR/server-key.pem"; then
    tmp="$(mktemp)"; openssl genpkey -algorithm ed25519 -out "$tmp" 2>/dev/null || fail "openssl cannot create an Ed25519 key."
    $SUDO install -m 640 -o 0 -g "$OUTLINE_UID" "$tmp" "$LIC_DIR/server-key.pem"
    openssl pkey -in "$tmp" -pubout 2>/dev/null | $SUDO tee "$LIC_DIR/server-pub.pem" >/dev/null
    rm -f "$tmp"
    ok "License identity: server key pair created (config/license/server-key.pem)"
  fi
  if ! $SUDO test -f "$LIC_DIR/server-box.pem"; then
    tmp="$(mktemp)"; openssl genpkey -algorithm X25519 -out "$tmp" 2>/dev/null || fail "openssl cannot create an X25519 key."
    $SUDO install -m 640 -o 0 -g "$OUTLINE_UID" "$tmp" "$LIC_DIR/server-box.pem"
    rm -f "$tmp"
    ok "License identity: encryption key created (config/license/server-box.pem)"
  fi
  license_trial_sync
  while read -r n v; do
    [[ -n $n ]] || continue
    comps+="${comps:+, }\"$n\": \"$(hw_hash "$n" "$v")\""; count=$((count + 1))
  done < <(hw_collect)
  printf '{ "VERSION": "install.sh %s", "v": 1, "updated": "%s", "components": { %s } }\n' \
    "$VERSION" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$comps" | $SUDO tee "$LIC_DIR/hardware.json" >/dev/null
  (( count >= 2 )) || warn "Only $count hardware identifier(s) found; licenses need 2 to match."
  $SUDO chown 0:"$OUTLINE_UID" "$LIC_DIR" "$LIC_DIR/server-key.pem" "$LIC_DIR/server-box.pem"
  $SUDO chmod 750 "$LIC_DIR"; $SUDO chmod 644 "$LIC_DIR/install.json" "$LIC_DIR/server-pub.pem" "$LIC_DIR/hardware.json"
  mkdir -p "$DATA" 2>/dev/null || $SUDO chown "$(id -u):$(id -g)" "$DATA"   # data/ itself stays the user's
  $SUDO mkdir -p "$LIC_DATA"; $SUDO chown "$OUTLINE_UID:$OUTLINE_UID" "$LIC_DATA"; $SUDO chmod 750 "$LIC_DATA"
  ok "License identity: installation $($SUDO sed -n 's/.*"installId": "\([0-9a-f]*\)".*/\1/p' "$LIC_DIR/install.json" | cut -c1-12)..., $count hardware identifiers"
}

# ----------------------------------------------------------------------------
# Step 5: domains, secrets, admin account, certificates
# ----------------------------------------------------------------------------
# ----------------------------------------------------------------------------
# Name resolution: server IP, /etc/hosts, client kit (hosts, DNS records, CA)
# ----------------------------------------------------------------------------
detect_ip() { # the IPv4 address other machines reach this server on (source of the default route)
  { ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<NF;i++) if($i=="src"){print $(i+1); exit}}'
    hostname -I 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9]+(\.[0-9]+){3}$'; } | head -n1 || true
}
is_local_ip() { [[ $1 == 127.* || $1 == ::1 ]] || hostname -I 2>/dev/null | tr ' ' '\n' | has_line "$1"; }
hosts_strip() { # hosts_strip name... : /etc/hosts on stdin without these names (other names on a line stay)
  awk -v names="$*" 'BEGIN{n=split(names,a," "); for(i=1;i<=n;i++) drop[a[i]]=1}
    /^[[:space:]]*(#|$)/ {print; next}
    { hit=0; for(i=2;i<=NF;i++){ if($i ~ /^#/) break; if($i in drop) hit=1 }
      if(!hit){print; next}
      out=$1; k=0; rest=""
      for(i=2;i<=NF;i++){ if($i ~ /^#/){ for(j=i;j<=NF;j++) rest=rest" "$j; break }
                          if(!($i in drop)){ out=out" "$i; k++ } }
      if(k>0) print out rest }'
}
hosts_set() { # hosts_set IP name... : backup /etc/hosts, remove the names everywhere, add "IP names"
  local ip="$1"; shift; local tmp; tmp="$(mktemp)"
  hosts_strip "$@" </etc/hosts >"$tmp"; printf '%s %s   # kms\n' "$ip" "$*" >>"$tmp"
  $SUDO cp -p /etc/hosts "/etc/hosts.kms-bak-$TS"; $SUDO cp "$tmp" /etc/hosts; rm -f "$tmp"
  ok "/etc/hosts: $ip $* (backup /etc/hosts.kms-bak-$TS)"
}
write_client_kit() { # client/: setup script for Linux PCs, CA files, hosts line and DNS records
  local d="$KMS/client" names="$KMS_HOST" n
  [[ $SSO_HOST != "$KMS_HOST" ]] && names="$KMS_HOST $SSO_HOST"
  [[ -n ${SERVER_IP:-} && -f $CERTS/ca/rootCA.pem ]] || return 0
  mkdir -p "$d"
  cp -f "$CERTS/ca/rootCA.pem" "$d/rootCA.pem"; cp -f "$CERTS/ca/rootCA.pem" "$d/rootCA.crt"
  cat >"$d/kms-client-setup.sh" <<'EOF'
#!/usr/bin/env bash
# VERSION: __VER__ - kms client setup, generated by install.sh on __TS__
# Run as your normal user (not with sudo) on a Linux PC that should use the wiki:
#   bash kms-client-setup.sh            names -> __IP__ in /etc/hosts, trust the kms CA (system + browsers)
#   bash kms-client-setup.sh --remove   undo both
set -euo pipefail
IP="__IP__"; NAMES="__NAMES__"; NICK="kms local CA (__IP__)"
DIR="$(cd "$(dirname "$0")" && pwd)"; CA="$DIR/rootCA.pem"; MODE="${1:-}"
SUDO=""; [[ $EUID -ne 0 ]] && SUDO="sudo"
TS="$(date +%Y%m%d-%H%M%S)"
hosts_strip() {
  awk -v names="$*" 'BEGIN{n=split(names,a," "); for(i=1;i<=n;i++) drop[a[i]]=1}
    /^[[:space:]]*(#|$)/ {print; next}
    { hit=0; for(i=2;i<=NF;i++){ if($i ~ /^#/) break; if($i in drop) hit=1 }
      if(!hit){print; next}
      out=$1; k=0; rest=""
      for(i=2;i<=NF;i++){ if($i ~ /^#/){ for(j=i;j<=NF;j++) rest=rest" "$j; break }
                          if(!($i in drop)){ out=out" "$i; k++ } }
      if(k>0) print out rest }'
}
# 1. /etc/hosts
tmp="$(mktemp)"; set -- $NAMES; hosts_strip "$@" </etc/hosts >"$tmp"
[[ $MODE == --remove ]] || printf '%s %s   # kms\n' "$IP" "$NAMES" >>"$tmp"
$SUDO cp -p /etc/hosts "/etc/hosts.kms-bak-$TS"; $SUDO cp "$tmp" /etc/hosts; rm -f "$tmp"
echo "[OK] /etc/hosts updated (backup /etc/hosts.kms-bak-$TS)"
# 2. system trust store
if [[ -d /usr/local/share/ca-certificates ]]; then
  if [[ $MODE == --remove ]]; then $SUDO rm -f /usr/local/share/ca-certificates/kms-local-ca.crt
  else $SUDO install -m 644 "$CA" /usr/local/share/ca-certificates/kms-local-ca.crt; fi
  $SUDO update-ca-certificates >/dev/null && echo "[OK] system trust store"
elif [[ -d /etc/pki/ca-trust/source/anchors ]]; then
  if [[ $MODE == --remove ]]; then $SUDO rm -f /etc/pki/ca-trust/source/anchors/kms-local-ca.pem
  else $SUDO install -m 644 "$CA" /etc/pki/ca-trust/source/anchors/kms-local-ca.pem; fi
  $SUDO update-ca-trust && echo "[OK] system trust store"
elif [[ -d /etc/ca-certificates/trust-source/anchors ]]; then
  if [[ $MODE == --remove ]]; then $SUDO rm -f /etc/ca-certificates/trust-source/anchors/kms-local-ca.crt
  else $SUDO install -m 644 "$CA" /etc/ca-certificates/trust-source/anchors/kms-local-ca.crt; fi
  $SUDO trust extract-all && echo "[OK] system trust store"
else echo "[WARN] unknown system trust store: import $CA by hand"; fi
# 3. browsers (Chrome/Chromium: ~/.pki/nssdb, Firefox profiles)
if ! command -v certutil >/dev/null; then
  if command -v apt-get >/dev/null; then $SUDO apt-get install -y libnss3-tools >/dev/null 2>&1 || true
  elif command -v pacman >/dev/null; then $SUDO pacman -S --needed --noconfirm nss >/dev/null 2>&1 || true
  elif command -v dnf >/dev/null; then $SUDO dnf install -y nss-tools >/dev/null 2>&1 || true
  elif command -v zypper >/dev/null; then $SUDO zypper --non-interactive install mozilla-nss-tools >/dev/null 2>&1 || true; fi
fi
if command -v certutil >/dev/null; then
  mkdir -p "$HOME/.pki/nssdb"
  [[ -f $HOME/.pki/nssdb/cert9.db ]] || certutil -N -d "sql:$HOME/.pki/nssdb" --empty-password
  for db in "$HOME/.pki/nssdb" "$HOME"/.mozilla/firefox/*/ "$HOME"/snap/firefox/common/.mozilla/firefox/*/; do
    [[ -f $db/cert9.db ]] || continue
    certutil -D -d "sql:$db" -n "$NICK" >/dev/null 2>&1 || true
    [[ $MODE == --remove ]] || certutil -A -d "sql:$db" -t "C,," -n "$NICK" -i "$CA"
    echo "[OK] browser store $db"
  done
  echo "     restart the browser"
else echo "[WARN] certutil missing (libnss3-tools): browsers must import $CA by hand"; fi
# 4. check
[[ $MODE == --remove ]] && exit 0
for n in $NAMES; do echo "     $n -> $(getent hosts "$n" | awk '{print $1; exit}')"; done
set -- $NAMES
if curl -fsS --max-time 8 -o /dev/null "https://$1/_health" 2>/dev/null; then echo "[OK] https://$1 answers with a trusted certificate"
else echo "[WARN] https://$1 not reachable or not trusted yet (is the server running? firewall?)"; fi
EOF
  sed -i "s|__VER__|$VERSION|; s|__TS__|$TS|; s|__IP__|$SERVER_IP|g; s|__NAMES__|$names|" "$d/kms-client-setup.sh"
  chmod 755 "$d/kms-client-setup.sh"
  {
    echo "# VERSION: $VERSION - name resolution for kms, generated by install.sh on $TS"
    echo "# Server IP: $SERVER_IP   Names: $names"
    echo
    echo "## Linux PC: copy this folder and run (as your normal user):"
    echo "##   scp -r $USER@$SERVER_IP:$d ~/kms-client && bash ~/kms-client/kms-client-setup.sh"
    echo
    echo "## hosts file line (Linux/macOS: /etc/hosts, Windows: C:\\Windows\\System32\\drivers\\etc\\hosts as Administrator)"
    echo "$SERVER_IP $names"
    echo
    echo "## Windows: trust the CA (Administrator command prompt, in this folder)"
    echo "certutil -addstore -f Root rootCA.crt"
    echo "## Firefox (any OS): Settings > Privacy & Security > Certificates > View Certificates > Authorities > Import rootCA.pem"
    echo
    echo "## DNS server instead of hosts files (one of these):"
    echo "# BIND zone file:"
    for n in $names; do echo "#   zone ${n#*.}:   ${n%%.*}  IN A  $SERVER_IP"; done
    echo "# dnsmasq / Pi-hole (dnsmasq.d/kms.conf):"
    for n in $names; do echo "address=/$n/$SERVER_IP"; done
    echo "# Unbound:"
    for n in $names; do echo "#   local-data: \"$n. A $SERVER_IP\""; done
    echo "# MikroTik:"
    for n in $names; do echo "#   /ip dns static add name=$n address=$SERVER_IP"; done
    echo "# Windows DNS server (PowerShell):"
    for n in $names; do echo "#   Add-DnsServerResourceRecordA -ZoneName ${n#*.} -Name ${n%%.*} -IPv4Address $SERVER_IP"; done
    echo "# libvirt network on the VM host (for other VMs on that network; run on the host):"
    printf "#   virsh net-update default add dns-host \"<host ip='%s'>" "$SERVER_IP"
    for n in $names; do printf '<hostname>%s</hostname>' "$n"; done
    echo "</host>\" --live --config"
  } >"$d/dns-records.txt"
  ok "Client kit: client/ (kms-client-setup.sh, rootCA.pem/.crt, dns-records.txt) for $SERVER_IP"
}

SECRETS="$CONFIG/secrets.env"
KMS_HOST="$(env_get KMS_HOST "$SECRETS")"; KMS_HOST="${KMS_HOST:-kms.imamreza.ir}"
SSO_HOST="$(env_get SSO_HOST "$SECRETS")"; SSO_HOST="${SSO_HOST:-sso.imamreza.ir}"
ADMIN_EMAIL="$(env_get ADMIN_EMAIL "$SECRETS")"; ADMIN_PASSWORD=""
SERVER_IP="$(env_get SERVER_IP "$SECRETS")"
if step "Domains, security keys, admin account, TLS certificates" 1 \
   "Asks the two domain names, creates the secrets (database password, Outline keys," \
   "OIDC client secret) in config/secrets.env (mode 600), asks the admin email and" \
   "password (stored only as an argon2 hash), creates a local CA and a certificate."; then
  mkdir -p "$CONFIG/ssozia" "$CERTS"; chmod 700 "$CONFIG"
  KMS_HOST="$(ask_text "Wiki domain" "$KMS_HOST")"; SSO_HOST="$(ask_text "SSO domain" "$SSO_HOST")"
  [[ $KMS_HOST =~ ^[a-z0-9.-]+$ && $SSO_HOST =~ ^[a-z0-9.-]+$ ]] || fail "Domains may only contain a-z, 0-9, dots and hyphens."
  info "IPv4 addresses of this server: $(hostname -I 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9]+(\.[0-9]+){3}$' | tr '\n' ' ')"
  while true; do
    SERVER_IP="$(ask_text "IP address the other computers use for this server" "${SERVER_IP:-$(detect_ip)}")"
    if [[ $SERVER_IP =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
      [[ $SERVER_IP == 127.* ]] && warn "SERVER_IP $SERVER_IP works only on this computer; other computers need its LAN address."
      break
    fi
    [[ $ASSUME_YES == 1 ]] && fail "No usable IPv4 address found; set it in config/secrets.env (SERVER_IP=)."
    warn "'$SERVER_IP' is not an IPv4 address; try again."
  done
  # secrets
  GEN=1
  if [[ -f $SECRETS ]]; then
    GEN=0
    if ask_yn "Keep the existing secrets (recommended; new ones log everybody out)?" y; then ok "Secrets kept"
    else
      if $SUDO test -s "$DATA/postgres/PG_VERSION" && [[ -z ${WIPED:-} ]]; then
        warn "The database in data/postgres keeps its password; only the Outline keys and the OIDC secret are renewed."
        GEN=2
      else GEN=1; fi
      mkdir -p "$ARCHIVE/$TS"; cp -p "$SECRETS" "$ARCHIVE/$TS/secrets.env"; chmod 600 "$ARCHIVE/$TS/secrets.env"
    fi
  fi
  if (( GEN )); then
    PGP="$(env_get POSTGRES_PASSWORD "$SECRETS")"
    (( GEN == 1 )) && PGP="$(openssl rand -hex 24)"
    umask 077
    {
      echo "# kms secrets - generated by install.sh $VERSION on $TS - keep private"
      echo "POSTGRES_PASSWORD=$PGP"
      echo "SECRET_KEY=$(openssl rand -hex 32)"
      echo "UTILS_SECRET=$(openssl rand -hex 32)"
      echo "OIDC_CLIENT_SECRET=$(openssl rand -hex 32)"
    } >"$SECRETS.new"
    umask 022
    mv "$SECRETS.new" "$SECRETS"; ok "Secrets created in config/secrets.env (mode 600)"
  fi
  sed -i '/^KMS_HOST=/d; /^SSO_HOST=/d; /^SERVER_IP=/d' "$SECRETS"
  { echo "KMS_HOST=$KMS_HOST"; echo "SSO_HOST=$SSO_HOST"; echo "SERVER_IP=$SERVER_IP"; } >>"$SECRETS"
  # admin account
  NEW_ADMIN=1
  if [[ -f $CONFIG/ssozia/users.toml && -n $ADMIN_EMAIL ]]; then
    ask_yn "Keep the admin account $ADMIN_EMAIL and its password?" y && NEW_ADMIN=0
  fi
  if (( NEW_ADMIN )); then
    while true; do
      if [[ $ASSUME_YES == 1 ]]; then
        ADMIN_EMAIL="${KMS_ADMIN_EMAIL:-}"; ADMIN_PASSWORD="${KMS_ADMIN_PASSWORD:-}"
        [[ -n $ADMIN_EMAIL && -n $ADMIN_PASSWORD ]] || fail "--yes needs KMS_ADMIN_EMAIL and KMS_ADMIN_PASSWORD for a new admin."
      else
        while true; do
          ADMIN_EMAIL="$(ask_text "Admin email (login name)" "${ADMIN_EMAIL:-admin@$KMS_HOST}")"
          [[ $ADMIN_EMAIL =~ ^[^[:space:]@\"]+@[^[:space:]@\"]+\.[^[:space:]@\"]+$ ]] && break
          warn "'$ADMIN_EMAIL' is not an email address; try again."
        done
        while true; do
          read -r -s -p "  ? Admin password (8+ characters recommended, hidden): " p1 </dev/tty; echo
          [[ -n $p1 ]] || { warn "Empty password; try again."; continue; }
          if (( ${#p1} < 8 )); then warn "Short password (${#p1} characters)."; ask_yn "Use it anyway?" n || continue; fi
          read -r -s -p "  ? Repeat the password: " p2 </dev/tty; echo
          [[ $p1 == "$p2" ]] && break
          warn "The two passwords do not match; try again."
        done
        ADMIN_PASSWORD="$p1"; unset p1 p2
        info "Admin: $ADMIN_EMAIL, password of ${#ADMIN_PASSWORD} characters"
        ask_yn "Is this correct?" y || continue
      fi
      break
    done
    sed -i '/^ADMIN_EMAIL=/d' "$SECRETS"; echo "ADMIN_EMAIL=$ADMIN_EMAIL" >>"$SECRETS"
    ok "Admin account: $ADMIN_EMAIL (hashed in step 6)"
  fi
  # certificates (mkcert, own CA inside certs/ca)
  export CAROOT="$CERTS/ca"; mkdir -p "$CAROOT" "$CERTS/site"
  if [[ ! -f $CAROOT/rootCA.pem ]]; then
    if [[ -f $HOME/.local/share/mkcert/rootCA.pem && -f $HOME/.local/share/mkcert/rootCA-key.pem ]] \
       && ask_yn "Use your existing local CA (~/.local/share/mkcert), already trusted by your browsers?" y; then
      cp -p "$HOME/.local/share/mkcert/rootCA.pem" "$HOME/.local/share/mkcert/rootCA-key.pem" "$CAROOT/"
    fi
  fi
  CRT="$CERTS/site/cert.pem"; KEY="$CERTS/site/key.pem"; need=1
  if [[ -f $CRT && -f $KEY ]] && openssl verify -CAfile "$CAROOT/rootCA.pem" "$CRT" >/dev/null 2>&1 \
     && openssl x509 -in "$CRT" -noout -checkend 2592000 >/dev/null \
     && openssl x509 -in "$CRT" -noout -ext subjectAltName | grep -F "DNS:$KMS_HOST" >/dev/null \
     && openssl x509 -in "$CRT" -noout -ext subjectAltName | grep -F "DNS:$SSO_HOST" >/dev/null; then need=0; fi
  if (( need )); then
    [[ -f $CAROOT/rootCA.pem ]] || info "Creating a new local CA in certs/ca"
    mkcert -cert-file "$CRT" -key-file "$KEY" "$KMS_HOST" "$SSO_HOST" >/dev/null 2>&1 || fail "mkcert could not create the certificate."
    [[ -f $CAROOT/rootCA.pem ]] || fail "mkcert did not create a CA in $CAROOT."
    chmod 644 "$CRT"; chmod 640 "$KEY"; ok "Certificate for $KMS_HOST + $SSO_HOST (certs/site/)"
  else ok "Certificate for $KMS_HOST + $SSO_HOST is valid"; fi
  if ask_yn "Trust this CA on this machine (system + Firefox/Chrome; may ask for sudo)?" y; then
    mkcert -install && ok "CA trusted on this machine" || warn "mkcert -install failed; import certs/ca/rootCA.pem in your browser."
  fi
  # this server: both names must reach this machine (Outline's containers use Caddy's aliases anyway)
  for h in "$KMS_HOST" "$SSO_HOST"; do
    hip="$(getent hosts "$h" | awk '{print $1; exit}' || true)"
    if [[ -n $hip ]] && is_local_ip "$hip"; then info "$h resolves to $hip (this machine)"; continue; fi
    if [[ -z $hip ]]; then q="$h does not resolve here."; else q="$h resolves to $hip, not to this machine."; fi
    if ask_yn "$q Point it to 127.0.0.1 in this server's /etc/hosts?" y; then hosts_set 127.0.0.1 "$h"; fi
  done
  # other computers: hosts line / DNS records / CA in client/
  write_client_kit
  info "Other computers: $SERVER_IP $KMS_HOST $SSO_HOST (hosts file or DNS), and trust the CA: see client/dns-records.txt"
  write_license_identity
fi
[[ -f $SECRETS ]] || fail "config/secrets.env is missing; run step 5 (bash $SELF --from 5)."
export CAROOT="$CERTS/ca"

# ----------------------------------------------------------------------------
# Step 6: build ssozia on the host
# ----------------------------------------------------------------------------
SZ="$BUILD/ssozia"
if step "Build ssozia on the host (cargo --release) and write its users/clients" 1 \
   "Copies the ssozia source from $(basename "$SSOZIA_ASSET") to build/ssozia (keeps target/ for fast rebuilds)," \
   "compiles it with the host's Rust, then writes config/ssozia/users.toml and clients.toml" \
   "with argon2 hashes of the admin password and of the OIDC client secret."; then
  [[ -f $HOME/.cargo/env ]] && . "$HOME/.cargo/env"
  command -v cargo >/dev/null || fail "cargo not found (step 2 installs it)."
  mkdir -p "$SZ" "$STAGE/ssozia"
  if [[ -d $SSOZIA_ASSET ]]; then cp -a "$SSOZIA_ASSET/." "$STAGE/ssozia/"
  else unzip -q "$SSOZIA_ASSET" -d "$STAGE/ssozia"; fi
  SROOT="$(dirname "$(find "$STAGE/ssozia" -maxdepth 3 -name Cargo.toml -print -quit)")"
  rsync -a --delete --exclude target/ --exclude data/ --exclude '*.bak*' "$SROOT/" "$SZ/"
  (cd "$SZ" && cargo build --release --locked) \
    || fail "cargo build failed ($(cargo --version)). ssozia needs Rust 1.82+; for a newer Rust use rustup, then: bash $SELF --from 6"
  [[ -x $SZ/target/release/ssozia ]] || fail "build/ssozia/target/release/ssozia missing after the build."
  ok "ssozia built: $(file -b "$SZ/target/release/ssozia" 2>/dev/null | cut -d, -f1-2)"
  hash_pw() { printf '%s' "$1" | "$SZ/target/release/ssozia" hash-password | grep -m1 '^\$argon2id\$'; }
  KMS_URL="https://$KMS_HOST"
  if [[ -n $ADMIN_PASSWORD ]]; then
    AH="$(hash_pw "$ADMIN_PASSWORD")" || fail "Could not hash the admin password."
    AU="${ADMIN_EMAIL%%@*}"; AU="$(tr -cd 'A-Za-z0-9._-' <<<"$AU")"; AU="${AU:-admin}"
    umask 077
    cat >"$CONFIG/ssozia/users.toml" <<EOF
# generated by install.sh $VERSION on $TS
[[users]]
id = "u_1"
email = "$ADMIN_EMAIL"
name = "Admin"
preferred_username = "$AU"
password_hash = "$AH"
is_admin = true
EOF
    umask 022; ok "config/ssozia/users.toml: $ADMIN_EMAIL (argon2)"
  else
    [[ -f $CONFIG/ssozia/users.toml ]] || fail "No admin yet: run step 5 to set the admin email and password."
    ok "config/ssozia/users.toml kept"
  fi
  CS="$(env_get OIDC_CLIENT_SECRET "$SECRETS")"
  if ! grep -qF "\"$KMS_URL/auth/oidc.callback\"" "$CONFIG/ssozia/clients.toml" 2>/dev/null \
     || [[ $(env_get CLIENT_HASH_OF "$SECRETS") != "$(printf '%s' "$CS" | sha256sum | cut -c1-16)" ]]; then
    CH="$(hash_pw "$CS")" || fail "Could not hash the OIDC client secret."
    umask 077
    cat >"$CONFIG/ssozia/clients.toml" <<EOF
# generated by install.sh $VERSION on $TS
[[clients]]
client_id = "outline"
name = "Outline"
client_secret_hash = "$CH"
redirect_uris = ["$KMS_URL/auth/oidc.callback"]
post_logout_redirect_uris = ["$KMS_URL"]
require_pkce = true
EOF
    umask 022
    sed -i '/^CLIENT_HASH_OF=/d' "$SECRETS"; echo "CLIENT_HASH_OF=$(printf '%s' "$CS" | sha256sum | cut -c1-16)" >>"$SECRETS"
    ok "config/ssozia/clients.toml: client outline (argon2)"
  else ok "config/ssozia/clients.toml kept"; fi
  chmod 644 "$CONFIG/ssozia/users.toml" "$CONFIG/ssozia/clients.toml"   # read by uid 10001 in the container
  chmod 755 "$CONFIG/ssozia"
fi

# ----------------------------------------------------------------------------
# Admin plugins from the kit's plugins/ folder (chosen and built in step 7)
# ----------------------------------------------------------------------------
PLUGIN_DIR="$KIT/plugins"; PLUGINS_CONF="$CONFIG/plugins.conf"; VENDOR_SRC="$KIT/Admin/kms-license-data"
PLUGIN_IDS=(ssozia-users subscribers)
has_word() { [[ " $2 " == *" $1 "* ]]; }
plugin_pkg() { case "$1" in subscribers) echo kms-licenses-plugin kms-subscribers-plugin ;; ssozia-users) echo ssozia-users-plugin ;; esac; }
plugin_title() {
  case "$1" in
    subscribers) echo "License management (kms-licenses: customers and licenses; only on the vendor's own server)" ;;
    ssozia-users) echo "Users (ssozia-users: users and organization chart in ssozia; needs ssozia 0.2.0+)" ;;
  esac
}
plugin_zips() { # plugin_zips id -> its zips, oldest first, a full package before the -changes of its version
  local f b v k pkg
  for pkg in $(plugin_pkg "$1"); do
    for f in "$PLUGIN_DIR/$pkg"-*.zip; do
      [[ -f $f ]] || continue; b="${f##*/}"; v="${b#"$pkg"-}"; v="${v%.zip}"; k=0
      if [[ $v == *-changes ]]; then k=1; v="${v%-changes}"; fi
      printf '%s\t%s\t%s\n' "$v" "$k" "$f"
    done
  done | sort -t$'\t' -k1,1V -k2,2n | cut -f3
}
plugin_stage() { # plugin_stage id dir -> the plugin's files in dir, all its zips laid over each other
  local id="$1" d="$2" z t p n=0
  rm -rf "$d"; mkdir -p "$d"
  while IFS= read -r z; do
    t="$(mktemp -d "$STAGE/plg.XXXXXX")"
    unzip -q -o "$z" -d "$t" || { rm -rf "$t"; fail "plugins/${z##*/} cannot be read (damaged zip?)."; }
    p="$(find "$t" -path "*/plugin/$id/plugin.json" -print -quit)"
    if [[ -n $p ]]; then
      [[ $z == *-changes.zip ]] || { rm -rf "$d"; mkdir -p "$d"; }   # a full package replaces older files
      cp -a "$(dirname "$p")/." "$d/"; n=$((n+1))
    fi
    rm -rf "$t"
  done < <(plugin_zips "$id")
  (( n > 0 ))
}
plugin_missing() { # plugin_missing dir target -> files the plugin needs but does not have
  # (type-only imports are erased by the build; a path leaving the plugin is checked in the source tree)
  local d="$1" t="$2" f s b c hit r
  [[ -f $d/plugin.json ]] || echo "plugin.json"
  [[ -f $d/server/index.ts || -f $d/client/index.tsx ]] || echo "server/index.ts or client/index.tsx"
  while IFS= read -r f; do
    while IFS= read -r s; do
      r="$(realpath -m "$t/$(dirname "${f#"$d"/}")/$s")"; hit=0
      if [[ $r == "$t"/* ]]; then b="$d/${r#"$t"/}"; else b="$r"; fi
      for c in "$b" "$b.ts" "$b.tsx" "$b.json" "$b/index.ts" "$b/index.tsx"; do [[ -f $c ]] && { hit=1; break; }; done
      (( hit )) || echo "${f#"$d"/} -> $s"
    done < <(grep -vE '^[[:space:]]*(import|export) type ' "$f" | grep -oE "(from|require\(|import) *['\"]\.\.?/[^'\"]+['\"]" | sed -E "s/^[^'\"]*['\"]//; s/['\"]$//" || true)
  done < <(find "$d" -type f \( -name '*.ts' -o -name '*.tsx' \) | LC_ALL=C sort)
  true
}
plugin_log_ok() { ! dk logs kms-outline 2>&1 | grep -qi "Failed to load plugin.*$1"; }
plugins_fp() { # plugins_fp "ids" -> fingerprint of the chosen plugins and their zips ("none" without plugins)
  local id z out=""
  for id in $1; do out+="$id"$'\n'; while IFS= read -r z; do out+="$(sha "$z")"$'\n'; done < <(plugin_zips "$id"); done
  if [[ -z $out ]]; then echo none; else printf '%s' "$out" | sha256sum | cut -c1-16; fi
}
PLUGINS="$( [[ -f $PLUGINS_CONF ]] && sed -n 's/^PLUGINS=//p' "$PLUGINS_CONF" | tail -n1 || true)"
plugins_choose() { # asks which admin plugins go into the build; sets PLUGINS and writes config/plugins.conf
  local id d sel="" asked=0
  for id in "${PLUGIN_IDS[@]}"; do
    if [[ -z $(plugin_zips "$id") ]]; then
      has_word "$id" "$PLUGINS" && warn "Plugin $id was chosen before, but plugins/ has no $(plugin_pkg "$id" | sed 's/ /-*.zip or /')-*.zip: left out."
      continue
    fi
    if [[ -n ${KMS_PLUGINS+x} ]]; then has_word "$id" "$KMS_PLUGINS" && sel+=" $id"; continue; fi
    if [[ $id == subscribers ]]; then [[ $KMS_MODE == admin ]] && d=y || d=n   # mode decides: admin Yes, customer No
    elif [[ -f $PLUGINS_CONF ]]; then has_word "$id" "$PLUGINS" && d=y || d=n
    elif [[ -d $SRC/plugins/$id ]]; then d=y          # attached earlier with its own install script
    else d=y; fi
    (( asked )) || { info "Admin plugins in the kit's plugins/ folder:"; asked=1; }
    ask_yn "Install the admin plugin $(plugin_title "$id")?" "$d" && sel+=" $id"
  done
  PLUGINS="${sel# }"
  mkdir -p "$CONFIG"
  printf '# VERSION: %s - written by install.sh step 7 (admin plugins built into Outline)\nPLUGINS=%s\n' "$VERSION" "$PLUGINS" >"$PLUGINS_CONF"
}
plugins_sync() { # puts the chosen plugins into build/$SRC_NAME/plugins and takes the others out
  local id d f miss keep=""
  if [[ -n $PLUGINS ]] && ! grep -q 'SidebarLink = "sidebarLink"' "$SRC/app/utils/PluginManager.ts"; then
    fail "build/$SRC_NAME lacks the plugin hooks (patch 0010-plugin-hooks): run step 4 with the current patches."
  fi
  for id in "${PLUGIN_IDS[@]}"; do
    rm -rf "$SRC/plugins/$id"
    has_word "$id" "$PLUGINS" || continue
    d="$STAGE/plugin-$id"
    plugin_stage "$id" "$d" || fail "plugins/ has no $(plugin_pkg "$id" | sed 's/ / or /') package with plugin/$id/plugin.json."
    miss="$(plugin_missing "$d" "$SRC/plugins/$id")"
    if [[ -n $miss ]]; then
      warn "Plugin $id is incomplete: $(plugin_zips "$id" | xargs -n1 basename | tr '\n' ' ')lacks these files:"
      while IFS= read -r f; do printf '         %s\n' "$f"; done < <(head -n 12 <<<"$miss")
      info "A ...-changes.zip holds only the changed files: put the full package of an earlier version into plugins/ too."
      [[ $(ask_choice "Plugin $id cannot be built." 1 "Build Outline without it" "Quit (nothing more is changed)") == 1 ]] || fail "Stopped: complete plugins/ and run install.sh --from 7."
      continue
    fi
    cp -a "$d" "$SRC/plugins/$id"
    keep+=" $id"
    ok "Plugin $id $(jq -r '.version // "?"' "$d/plugin.json" 2>/dev/null) in build/$SRC_NAME/plugins/$id"
  done
  if [[ ${keep# } != "$PLUGINS" ]]; then
    PLUGINS="${keep# }"
    printf '# VERSION: %s - written by install.sh step 7 (admin plugins built into Outline)\nPLUGINS=%s\n' "$VERSION" "$PLUGINS" >"$PLUGINS_CONF"
  fi
  [[ -n $PLUGINS ]] || info "No admin plugins in this build."
}

# ----------------------------------------------------------------------------
# Step 7: build Outline on the host
# ----------------------------------------------------------------------------
NODE_DIR="$BUILD/node"
node_bin() { if [[ $NODE_MODE == tarball ]]; then echo "$NODE_DIR/bin/node"; else command -v node; fi; }
# Rebuild whenever the applied patch set differs from the one the runtime files were built from.
APPLIED_FP="$(marker_fp "$BUILD/.kms-patches")"; BUILT_FP="$(marker_fp "$IMAGES/outline/app/.kms-patches")"
if [[ -n $APPLIED_FP && $APPLIED_FP != "$BUILT_FP" ]] && (( FROM > 7 )); then
  FORCE_STEP=1; FORCE_REASON="the patch set in build/$SRC_NAME (${APPLIED_FP:0:12}) differs from the last Outline build (${BUILT_FP:0:12})"
fi
BUILT_PLUGINS_FP="$(cat "$IMAGES/outline/app/.kms-plugins" 2>/dev/null || echo none)"
if [[ -d $IMAGES/outline/app/build && $(plugins_fp "$PLUGINS") != "$BUILT_PLUGINS_FP" ]] && (( FROM > 7 )); then
  FORCE_STEP=1; FORCE_REASON="the admin plugins in config/plugins.conf or plugins/ differ from the last Outline build"
fi
# Patch 0023: the vendor public key is compiled into the server, so a changed key needs a new build.
VENDOR_KEY_FP="$([[ -f $ASSETS/license/vendor-public.json ]] && sha "$ASSETS/license/vendor-public.json" || echo none)"
BUILT_VKEY_FP="$(cat "$IMAGES/outline/app/.kms-vendor-key" 2>/dev/null || echo none)"
if [[ -d $IMAGES/outline/app/build && $VENDOR_KEY_FP != "$BUILT_VKEY_FP" ]] && (( FROM > 7 )); then
  FORCE_STEP=1; FORCE_REASON="the vendor license key (assets/license/vendor-public.json) differs from the one compiled into the last Outline build"
fi
if [[ -f $SRC/package.json ]]; then
  _pm="$(sed -n 's/.*"packageManager"[^"]*"yarn@\([0-9][0-9.]*\).*/\1/p' "$SRC/package.json" | head -n1)"
  [[ -n $_pm ]] && YARN_VER="$_pm"
fi
if step "Build Outline on the host (Node.js + Yarn $YARN_VER), then its runtime files" 1 \
   "Node: $([[ $NODE_MODE == debian ]] && echo "Debian nodejs" || echo "official Node $NODE_TARBALL_VER into build/node")." \
   "Yarn $YARN_VER from $NPM_REGISTRY into build/yarn-$YARN_VER; packages from $NPM_REGISTRY." \
   "yarn install --immutable, yarn build in build/$SRC_NAME, then the production files" \
   "(build, server, public, production node_modules) into images/outline/app." \
   "First asks which admin plugins (License management, Users) from the kit's plugins/ go into the build."; then
  [[ -f $SRC/package.json ]] || fail "No source in build/$SRC_NAME; run step 4."
  plugins_choose
  plugins_sync
  if [[ $NODE_MODE == tarball && ! -x $NODE_DIR/bin/node ]]; then
    case "$ARCH" in arm64|aarch64) NA=arm64 ;; amd64|x86_64) NA=x64 ;; *) fail "No official Node build for $ARCH." ;; esac
    NODE_DIST="$(ask_text "Node.js download site (official or a mirror)" "${NODE_DIST:-https://nodejs.org/dist}")"
    U="${NODE_DIST%/}/v$NODE_TARBALL_VER/node-v$NODE_TARBALL_VER-linux-$NA.tar.xz"
    info "Downloading $U"
    mkdir -p "$NODE_DIR"; curl -fL --retry 3 "$U" | tar xJ -C "$NODE_DIR" --strip-components=1 \
      || fail "Node download failed (set NODE_DIST to a mirror and run --from 7)."
  fi
  NODE="$(node_bin)"; [[ -x $NODE ]] || fail "node not found."
  node_ok "$("$NODE" -v | tr -d v)" || fail "Node $("$NODE" -v) does not fit Outline."
  ok "Node $("$NODE" -v) ($NODE)"
  YJS="$BUILD/yarn-$YARN_VER/package/bin/yarn.js"
  if [[ ! -f $YJS ]]; then
    mkdir -p "$BUILD/yarn-$YARN_VER"
    curl -fsSL --retry 3 "$NPM_REGISTRY/@yarnpkg/cli-dist/-/cli-dist-$YARN_VER.tgz" | tar xz -C "$BUILD/yarn-$YARN_VER" \
      || fail "Could not download Yarn $YARN_VER from $NPM_REGISTRY."
  fi
  export PATH="$(dirname "$NODE"):$PATH" YARN_NPM_REGISTRY_SERVER="$NPM_REGISTRY" YARN_ENABLE_TELEMETRY=0
  yarn_() { "$NODE" "$YJS" "$@"; }
  ok "Yarn $(cd "$SRC" && yarn_ --version)"
  (cd "$SRC" && yarn_ install --immutable) || fail "yarn install failed."
  ok "yarn install done"
  # Patch 0023: compile the vendor public key into the server (no runtime file, no env override).
  VK="$SRC/server/license/vendorKey.ts"
  if [[ -f $ASSETS/license/vendor-public.json ]]; then
    jq -e '.sign.crv == "Ed25519" and .box.crv == "X25519" and (has("d") | not) and (.sign | has("d") | not) and (.box | has("d") | not)' \
      "$ASSETS/license/vendor-public.json" >/dev/null 2>&1 \
      || fail "assets/license/vendor-public.json is not a public-only kms-license key file."
    { echo '// Generated by install.sh (patch 0023) from assets/license/vendor-public.json. Do not edit.'
      echo 'import type { VendorPublicKeys } from "./format";'
      echo "export const VENDOR_PUBLIC_KEY: VendorPublicKeys | null = $(jq -c . "$ASSETS/license/vendor-public.json");"
    } >"$VK"
    ok "Vendor license key written into server/license/vendorKey.ts (compiled into the build)"
  else
    printf '%s\n' 'import type { VendorPublicKeys } from "./format";' 'export const VENDOR_PUBLIC_KEY: VendorPublicKeys | null = null;' >"$VK"
    warn "No assets/license/vendor-public.json: this build cannot check licenses (read-only)."
  fi
  (cd "$SRC" && NODE_OPTIONS="--max-old-space-size=${BUILD_MEM_MB:-4096}" yarn_ build) || fail "yarn build failed."
  [[ -f $SRC/build/server/index.js ]] || fail "yarn build produced no build/server/index.js."
  for id in $PLUGINS; do
    [[ -f $SRC/build/plugins/$id/server/index.js ]] || fail "yarn build produced no build/plugins/$id (plugin $id)."
  done
  # runtime files with production dependencies only
  APP="$IMAGES/outline/app"; mkdir -p "$APP"
  rsync -a --delete --exclude node_modules/ \
    --include '/build/***' --include '/server/***' --include '/public/***' \
    --include '/package.json' --include '/yarn.lock' --include '/.yarnrc.yml' --include '/.sequelizerc' \
    --exclude '*' "$SRC/" "$APP/"
  (cd "$APP" && yarn_ workspaces focus --production) || fail "Production install in images/outline/app failed."
  # Hardening: only compiled code goes into the image (no TypeScript sources of server/, no source maps).
  # server/ keeps what runs: config/database.js, migrations/*.js, static/*.
  find "$APP/server" -type f \( -name '*.ts' -o -name '*.tsx' \) -delete
  find "$APP/build" "$APP/public" -type f -name '*.map' -delete 2>/dev/null || true
  rm -rf "$APP/kms-license"   # patch 0023: no runtime key file any more; the key is inside build/
  echo "$VENDOR_KEY_FP" >"$APP/.kms-vendor-key"
  ok "Runtime files ready: images/outline/app ($(du -sh "$APP" | cut -f1))"
  plugins_fp "$PLUGINS" >"$APP/.kms-plugins"
  [[ -n $PLUGINS ]] && ok "Admin plugins built in: $PLUGINS"
  if [[ $NODE_MODE == tarball ]]; then mkdir -p "$IMAGES/outline/node"; cp -f "$NODE_DIR/bin/node" "$IMAGES/outline/node/node"; fi
  if [[ -f $BUILD/.kms-patches ]]; then cp -f "$BUILD/.kms-patches" "$APP/.kms-patches"; ok "Runtime files built with patch set ${APPLIED_FP:0:12}"
  else rm -f "$APP/.kms-patches"; warn "build/.kms-patches is missing: the patch set of this build is unknown (run step 4)."; fi
fi

# ----------------------------------------------------------------------------
# Step 8: build the Docker images locally
# ----------------------------------------------------------------------------
write_images() {
  mkdir -p "$IMAGES"/{postgres,redis,caddy,ssozia,outline}
  # postgres
  cat >"$IMAGES/postgres/Dockerfile" <<'EOF'
# VERSION: __KMSV__ - generated by install.sh
FROM kms/base:local
RUN groupadd -r -g 999 postgres && useradd -r -u 999 -g postgres -d /var/lib/postgresql -s /bin/bash postgres \
 && mkdir -p /etc/postgresql-common && echo "create_main_cluster = false" > /etc/postgresql-common/createcluster.conf \
 && apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends postgresql \
 && rm -rf /var/lib/apt/lists/* \
 && ln -s "$(ls -d /usr/lib/postgresql/*/bin | sort -V | tail -n1)" /usr/local/pgbin \
 && mkdir -p /var/run/postgresql /var/lib/postgresql/data && chown -R postgres:postgres /var/run/postgresql /var/lib/postgresql
COPY entrypoint.sh /usr/local/bin/kms-postgres
ENV PGDATA=/var/lib/postgresql/data
USER postgres
EXPOSE 5432
CMD ["/usr/local/bin/kms-postgres"]
EOF
  cat >"$IMAGES/postgres/entrypoint.sh" <<'EOF'
#!/bin/bash
# VERSION: __KMSV__ - first start: initdb + user/database from POSTGRES_* ; then postgres
set -euo pipefail
BIN=/usr/local/pgbin
if [ ! -s "$PGDATA/PG_VERSION" ]; then
  : "${POSTGRES_PASSWORD:?POSTGRES_PASSWORD is required}" "${POSTGRES_USER:=outline}" "${POSTGRES_DB:=outline}"
  "$BIN/initdb" -D "$PGDATA" -U postgres -E UTF8 --locale=C.UTF-8 --auth-local=trust --auth-host=scram-sha-256
  echo "listen_addresses = '*'" >> "$PGDATA/postgresql.conf"
  printf 'host all all 0.0.0.0/0 scram-sha-256\nhost all all ::/0 scram-sha-256\n' >> "$PGDATA/pg_hba.conf"
  "$BIN/pg_ctl" -D "$PGDATA" -o "-c listen_addresses=''" -w start
  "$BIN/psql" -v ON_ERROR_STOP=1 -U postgres -d postgres -v u="$POSTGRES_USER" -v p="$POSTGRES_PASSWORD" -v d="$POSTGRES_DB" <<'SQL'
CREATE USER :"u" WITH PASSWORD :'p';
CREATE DATABASE :"d" OWNER :"u";
SQL
  "$BIN/pg_ctl" -D "$PGDATA" -m fast -w stop
fi
exec "$BIN/postgres" -D "$PGDATA"
EOF
  chmod 755 "$IMAGES/postgres/entrypoint.sh"
  # redis (or valkey, whichever the Debian mirror has)
  cat >"$IMAGES/redis/Dockerfile" <<'EOF'
# VERSION: __KMSV__ - generated by install.sh
FROM kms/base:local
RUN groupadd -r -g 998 redis && useradd -r -u 998 -g redis -d /data -s /usr/sbin/nologin redis \
 && apt-get update \
 && (DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends redis-server \
     || DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends valkey-server) \
 && rm -rf /var/lib/apt/lists/* \
 && ln -s "$(command -v redis-server || command -v valkey-server)" /usr/local/bin/kms-redis-server \
 && ln -s "$(command -v redis-cli || command -v valkey-cli)" /usr/local/bin/kms-redis-cli \
 && mkdir -p /data && chown redis:redis /data
USER redis
EXPOSE 6379
CMD ["/usr/local/bin/kms-redis-server", "--bind", "0.0.0.0", "--protected-mode", "no", "--dir", "/data", "--appendonly", "yes"]
EOF
  # caddy
  cat >"$IMAGES/caddy/Dockerfile" <<'EOF'
# VERSION: __KMSV__ - generated by install.sh
FROM kms/base:local
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends caddy \
 && rm -rf /var/lib/apt/lists/*
ENV XDG_DATA_HOME=/data XDG_CONFIG_HOME=/config
EXPOSE 80 443
CMD ["caddy", "run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]
EOF
  # ssozia (binary built on the host in step 6)
  cat >"$IMAGES/ssozia/Dockerfile" <<'EOF'
# VERSION: __KMSV__ - generated by install.sh
FROM kms/base:local
RUN useradd --system --uid 10001 --user-group --no-create-home --shell /usr/sbin/nologin ssozia \
 && mkdir -p /app/data && chown -R ssozia:ssozia /app
COPY ssozia /usr/local/bin/ssozia
WORKDIR /app
USER ssozia
EXPOSE 4000
ENV BIND_ADDR=0.0.0.0:4000 DATA_DIR=/app/data USERS_FILE=/app/users.toml CLIENTS_FILE=/app/clients.toml RUST_LOG=info
CMD ["ssozia", "serve"]
EOF
  # outline (built on the host in step 7)
  {
    echo "# VERSION: $VERSION - generated by install.sh (node: $NODE_MODE)"
    echo "FROM kms/base:local"
    if [[ $NODE_MODE == debian ]]; then
      echo 'RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends nodejs \'
      echo ' && rm -rf /var/lib/apt/lists/*'
    else
      echo 'RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends libatomic1 libstdc++6 \'
      echo ' && rm -rf /var/lib/apt/lists/*'
      echo 'COPY node/node /usr/local/bin/node'
    fi
    cat <<'EOF'
RUN groupadd -g 1001 nodejs && useradd -u 1001 -g nodejs -m -d /home/nodejs -s /bin/bash nodejs \
 && mkdir -p /var/lib/outline/data /opt/outline && chown -R nodejs:nodejs /var/lib/outline /opt/outline
WORKDIR /opt/outline
COPY --chown=nodejs:nodejs app/ ./
ENV NODE_ENV=production MALLOC_ARENA_MAX=2 FILE_STORAGE_LOCAL_ROOT_DIR=/var/lib/outline/data
USER nodejs
EXPOSE 3000
CMD ["node", "build/server/index.js"]
EOF
  } >"$IMAGES/outline/Dockerfile"
  printf '# VERSION: %s\n*\n!app\n!node\n' "$VERSION" >"$IMAGES/outline/.dockerignore"
  sed -i "s/__KMSV__/$VERSION/" "$IMAGES"/*/Dockerfile "$IMAGES/postgres/entrypoint.sh"
}
img_exists() { dk image inspect "$1" >/dev/null 2>&1; }
APP_FP="$(marker_fp "$IMAGES/outline/app/.kms-patches")"; IMG_FP="$(marker_fp "$IMAGES/outline/.kms-patches-image")"
if [[ -n $APP_FP && $APP_FP != "$IMG_FP" ]] && (( FROM > 8 )); then
  FORCE_STEP=1; FORCE_REASON="the Outline image was built from another patch set than images/outline/app"
fi
if [[ -f $IMAGES/outline/app/.kms-plugins ]] && ! cmp -s "$IMAGES/outline/app/.kms-plugins" "$IMAGES/outline/.kms-plugins-image" && (( FROM > 8 )); then
  FORCE_STEP=1; FORCE_REASON="the Outline image was built with other admin plugins than images/outline/app"
fi
if step "Build the Docker images locally (nothing pulled from Docker Hub)" 1 \
   "kms/base: a minimal Debian (debootstrap from your mirror; on hosts without it, a Debian image is pulled once)," \
   "then kms/postgres, kms/redis, kms/caddy (Debian packages), kms/ssozia (host binary)" \
   "and kms/outline (host build). Builds use the host network for apt."; then
  BASE_ACT=1
  if img_exists "$IMG_BASE"; then
    [[ $(ask_choice "The base image $IMG_BASE exists." 1 "Keep it" "Rebuild it with debootstrap") == 2 ]] || BASE_ACT=0
  fi
  if (( BASE_ACT )); then
    if [[ $PM == apt-get && $OS_ID == debian ]]; then
      MIRROR="$(apt_mirror)"; MIRROR="${MIRROR:-http://deb.debian.org/debian}"
      IMG_SUITE="$(apt_suite)"; IMG_SUITE="${IMG_SUITE:-$SUITE}"
    else
      MIRROR="http://deb.debian.org/debian"
      # a rolling host (Arch/Manjaro) gets a rolling image so binaries built on the host find their glibc
      IMG_SUITE="trixie"; [[ $PM == pacman ]] && IMG_SUITE="sid"
    fi
    MIRROR="$(ask_text "Debian mirror for the base image" "$MIRROR")"
    IMG_SUITE="$(ask_text "Debian suite for the images" "$IMG_SUITE")"
    BASE_HOW=2
    if command -v debootstrap >/dev/null && [[ -s /usr/share/keyrings/debian-archive-keyring.gpg || $OS_ID == debian ]]; then BASE_HOW=1; fi
    if [[ $BASE_HOW == 1 && $OS_ID != debian ]] || [[ $BASE_HOW == 2 ]]; then
      [[ $(ask_choice "How to make the Debian base image?" "$BASE_HOW" \
          "debootstrap from $MIRROR (needs debootstrap and the Debian archive keyring)" \
          "Pull a Debian image once (debian:$IMG_SUITE-slim from Docker Hub or your registry)") == 1 ]] && BASE_HOW=1 || BASE_HOW=2
    fi
    if [[ $BASE_HOW == 1 ]]; then
      ROOTFS="$STAGE/rootfs"
      info "debootstrap --variant=minbase $IMG_SUITE from $MIRROR (a few minutes)"
      $SUDO debootstrap --variant=minbase --include=ca-certificates "$IMG_SUITE" "$ROOTFS" "$MIRROR" \
        || fail "debootstrap failed (mirror $MIRROR, suite $IMG_SUITE)."
      # apt inside the images: the same mirror (+ security, if the host has it); no service starts during builds
      SEC=""; [[ $PM == apt-get && $OS_ID == debian ]] && SEC="$(apt_security)"
      {
        echo "# VERSION: $VERSION - written by install.sh"
        echo "deb $MIRROR $IMG_SUITE main"
        if [[ $IMG_SUITE != sid && $IMG_SUITE != unstable ]]; then
          echo "deb $MIRROR $IMG_SUITE-updates main"
          [[ -n $SEC ]] && echo "deb $SEC $IMG_SUITE-security main"
        fi
        true
      } | $SUDO tee "$ROOTFS/etc/apt/sources.list" >/dev/null
      $SUDO rm -f "$ROOTFS"/etc/apt/sources.list.d/*
      info "Image apt sources: $MIRROR${SEC:+ + $SEC}"
      printf '#!/bin/sh\nexit 101\n' | $SUDO tee "$ROOTFS/usr/sbin/policy-rc.d" >/dev/null; $SUDO chmod 755 "$ROOTFS/usr/sbin/policy-rc.d"
      $SUDO rm -rf "$ROOTFS"/var/lib/apt/lists/* "$ROOTFS"/var/cache/apt/archives/*.deb
      $SUDO tar -C "$ROOTFS" -c . | dk import -c 'CMD ["bash"]' -c 'ENV LANG=C.UTF-8' - "$IMG_BASE" >/dev/null
      $SUDO rm -rf "$ROOTFS"
    else
      BASE_SRC="$(ask_text "Debian image to start from" "debian:$IMG_SUITE-slim")"
      info "docker pull $BASE_SRC"
      dk pull "$BASE_SRC" || fail "Could not pull $BASE_SRC (use a registry mirror, or install debootstrap + debian-archive-keyring and run --from 8)."
      mkdir -p "$STAGE/basectx"
      printf 'FROM %s\nRUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*\nENV LANG=C.UTF-8\n' "$BASE_SRC" >"$STAGE/basectx/Dockerfile"
      dk build --network host -t "$IMG_BASE" "$STAGE/basectx" || fail "Building $IMG_BASE from $BASE_SRC failed."
      rm -rf "$STAGE/basectx"
    fi
    ok "Base image $IMG_BASE ($(dk image inspect -f '{{.Size}}' "$IMG_BASE" | awk '{printf "%d MB", $1/1048576}'))"
  else ok "Base image $IMG_BASE kept"; fi
  write_images
  [[ -x $SZ/target/release/ssozia ]] || fail "No ssozia binary; run step 6."
  [[ -d $IMAGES/outline/app/build ]] || fail "No Outline runtime files; run step 7."
  cp -f "$SZ/target/release/ssozia" "$IMAGES/ssozia/ssozia"
  for i in postgres:"$IMG_PG" redis:"$IMG_REDIS" caddy:"$IMG_CADDY" ssozia:"$IMG_SSOZIA" outline:"$IMG_OUTLINE"; do
    d="${i%%:*}"; t="${i#*:}"
    info "docker build $t"
    dk "${DOCKER_BUILD[@]}" -t "$t" "$IMAGES/$d" || fail "Building $t failed."
    ok "Image $t"
  done
  # the binaries must start inside their images (missing shared libraries show up here, not at step 10)
  v="$(dk run --rm --network none "$IMG_OUTLINE" node -v 2>&1)" || { printf '%s\n' "$v"; fail "node does not start in $IMG_OUTLINE."; }
  ok "node $v runs in $IMG_OUTLINE"
  v="$(dk run --rm --network none "$IMG_SSOZIA" ssozia --version 2>&1)" || { printf '%s\n' "$v"; fail "ssozia does not start in $IMG_SSOZIA."; }
  ok "$v runs in $IMG_SSOZIA"
  if [[ -f $IMAGES/outline/app/.kms-patches ]]; then cp -f "$IMAGES/outline/app/.kms-patches" "$IMAGES/outline/.kms-patches-image"
  else rm -f "$IMAGES/outline/.kms-patches-image"; fi
  if [[ -f $IMAGES/outline/app/.kms-plugins ]]; then cp -f "$IMAGES/outline/app/.kms-plugins" "$IMAGES/outline/.kms-plugins-image"
  else rm -f "$IMAGES/outline/.kms-plugins-image"; fi
fi

# ----------------------------------------------------------------------------
# Step 9: configuration files and data folders
# ----------------------------------------------------------------------------
vendor_keys() { # License management plugin: vendor keys and ledger -> config/license/vendor (/etc/kms-license/vendor)
  local v="$LIC_DIR/vendor" src have=0 f d
  $SUDO test -f "$v/private.json" && have=1
  src="$VENDOR_SRC"
  if [[ ! -f $src/private.json ]]; then
    if (( have )); then ok "License management plugin: vendor keys kept in config/license/vendor"; return 0; fi
    src="$(ask_text "kms-license data folder with private.json (License management plugin)" "$src")"
  fi
  if [[ ! -f $src/private.json ]]; then
    warn "License management plugin: no private.json in $src; the plugin stays off until config/license/vendor has the keys."; return 0
  fi
  jq -e '.sign.crv == "Ed25519" and .box.crv == "X25519" and ((.product // "kms-outline") == "kms-outline")' "$src/private.json" >/dev/null 2>&1 \
    || fail "$src/private.json is not a kms-license key file (kms-license.mjs keygen)."
  if (( have )); then
    if $SUDO cmp -s "$src/private.json" "$v/private.json"; then
      ask_yn "License management plugin: refresh the ledger and issued files from $src?" n || { ok "License management plugin: vendor keys kept in config/license/vendor"; return 0; }
    else
      warn "License management plugin: $src/private.json differs from config/license/vendor; licenses already issued stay tied to the installed keys."
      ask_yn "Replace the installed vendor keys?" n || { ok "License management plugin: installed vendor keys kept"; return 0; }
    fi
    mkdir -p "$ARCHIVE/$TS" 2>/dev/null || { $SUDO mkdir -p "$ARCHIVE/$TS"; $SUDO chown "$(id -u):$(id -g)" "$ARCHIVE/$TS"; }
    $SUDO cp -a "$v" "$ARCHIVE/$TS/kms-vendor"; info "Previous vendor keys kept in archive/$TS/kms-vendor"
  fi
  $SUDO mkdir -p "$v"
  for f in private.json vendor-public.json ledger.json; do
    [[ -f $src/$f ]] && $SUDO install -m 640 -o 0 -g "$OUTLINE_UID" "$src/$f" "$v/$f"
  done
  for d in issued requests; do
    if [[ -d $src/$d ]]; then
      $SUDO rm -rf "$v/$d"; $SUDO cp -r "$src/$d" "$v/$d"; $SUDO chown -R 0:"$OUTLINE_UID" "$v/$d"
      $SUDO find "$v/$d" -type d -exec chmod 750 {} +; $SUDO find "$v/$d" -type f -exec chmod 640 {} +
    fi
  done
  $SUDO chown 0:"$OUTLINE_UID" "$v"; $SUDO chmod 750 "$v"
  ok "License management plugin: vendor keys and ledger in config/license/vendor (from $src)"
}
if step "Write the configuration and docker-compose.yml, prepare data folders" 1 \
   "config/outline.env, config/postgres.env, config/Caddyfile and docker-compose.yml" \
   "(previous versions go to archive/), data/{postgres,redis,outline,ssozia,caddy} with" \
   "the owners the containers run as."; then
  write_license_identity   # refreshes hardware.json; keys and install ID are kept
  has_word subscribers "$PLUGINS" && vendor_keys   # License management plugin: config/license/vendor
  MACHINE_ID_MOUNT=""
  [[ -s /etc/machine-id ]] && MACHINE_ID_MOUNT="      - /etc/machine-id:/etc/kms-host-machine-id:ro
"
  mkdir -p "$ARCHIVE/$TS" 2>/dev/null || $SUDO mkdir -p "$ARCHIVE/$TS"
  [[ -w $ARCHIVE/$TS ]] || $SUDO chown "$(id -u):$(id -g)" "$ARCHIVE/$TS"   # made by root in 10.3-10.6
  for f in "$KMS/docker-compose.yml" "$CONFIG/outline.env" "$CONFIG/postgres.env" "$CONFIG/Caddyfile"; do
    if [[ -f $f ]]; then cp -p "$f" "$ARCHIVE/$TS/" 2>/dev/null || $SUDO cp -p "$f" "$ARCHIVE/$TS/"; fi
  done
  PGP="$(env_get POSTGRES_PASSWORD "$SECRETS")"
  # workspace / product name: the name of a new workspace on first sign-in, page titles, e-mails
  # (default "Knowledge management" in Persian, as UTF-8 bytes; this script stays ASCII;
  #  the earlier default "Aflak knowledge management" is replaced by it)
  APP_NAME_DEFAULT="$(printf '\xd9\x85\xd8\xaf\xdb\x8c\xd8\xb1\xdb\x8c\xd8\xaa \xd8\xaf\xd8\xa7\xd9\x86\xd8\xb4')"
  APP_NAME="${KMS_APP_NAME:-$(env_get APP_NAME "$CONFIG/outline.env")}"
  [[ -z $APP_NAME || $APP_NAME == "$APP_NAME_DEFAULT $(printf '\xd8\xa7\xd9\x81\xd9\x84\xd8\xa7\xda\xa9')" ]] && APP_NAME="$APP_NAME_DEFAULT"
  APP_NAME="$(ask_text "Workspace name (first sign-in, page titles, e-mails)" "$APP_NAME")"
  APP_NAME="$(printf '%s' "$APP_NAME" | tr -d '\r\n')"
  info "Step 10 renames a workspace still called \"Outline\"; any other name is kept (Settings > Details)."
  umask 077
  printf '# generated by install.sh %s\nPOSTGRES_PASSWORD=%s\n' "$VERSION" "$PGP" >"$CONFIG/postgres.env"
  {
    echo "# generated by install.sh $VERSION on $TS - change values in config/secrets.env and re-run step 9"
    echo "NODE_ENV=production"
    echo "URL=https://$KMS_HOST"
    echo "PORT=3000"
    echo "SECRET_KEY=$(env_get SECRET_KEY "$SECRETS")"
    echo "UTILS_SECRET=$(env_get UTILS_SECRET "$SECRETS")"
    echo "DATABASE_URL=postgres://outline:$PGP@postgres:5432/outline"
    echo "PGSSLMODE=disable"
    echo "REDIS_URL=redis://redis:6379"
    echo "FILE_STORAGE=local"
    echo "FILE_STORAGE_LOCAL_ROOT_DIR=/var/lib/outline/data"
    echo "FILE_STORAGE_UPLOAD_MAX_SIZE=262144000"
    echo "FORCE_HTTPS=false"
    echo "DEFAULT_LANGUAGE=fa_IR"
    echo "APP_NAME=$APP_NAME"
    echo "NODE_EXTRA_CA_CERTS=/certs/rootCA.pem"
    echo "OIDC_CLIENT_ID=outline"
    echo "OIDC_CLIENT_SECRET=$(env_get OIDC_CLIENT_SECRET "$SECRETS")"
    echo "OIDC_ISSUER_URL=https://$SSO_HOST"
    echo "OIDC_LOGOUT_URI=https://$SSO_HOST/logout"
    echo "OIDC_USERNAME_CLAIM=preferred_username"
    # "Sign in with SSO" in Persian, as UTF-8 bytes (this script stays ASCII)
    printf 'OIDC_DISPLAY_NAME=\xd9\x88\xd8\xb1\xd9\x88\xd8\xaf \xd8\xa8\xd8\xa7 SSO\n'
    echo "OIDC_SCOPES=openid profile email"
  } >"$CONFIG/outline.env"
  umask 022
  chmod 600 "$CONFIG/outline.env" "$CONFIG/postgres.env"
  cat >"$CONFIG/Caddyfile" <<EOF
# generated by install.sh $VERSION on $TS
{
    auto_https disable_certs
}

:80 {
    respond 404
}

https://$SSO_HOST {
    tls /certs/cert.pem /certs/key.pem
    request_body {
        max_size 100MB
    }
    reverse_proxy ssozia:4000 {
        header_up X-Forwarded-For {remote_host}
        header_up Host {host}
    }
}

https://$KMS_HOST {
    tls /certs/cert.pem /certs/key.pem
    request_body {
        max_size 300MB
    }
    reverse_proxy /realtime* outline:3000 {
        header_up X-Forwarded-For {remote_host}
        header_up Host {host}
        transport http {
            read_timeout 3600s
            write_timeout 3600s
        }
    }
    reverse_proxy outline:3000 {
        header_up X-Forwarded-For {remote_host}
        header_up Host {host}
    }
}
EOF
  cat >"$KMS/docker-compose.yml" <<EOF
# generated by install.sh $VERSION on $TS - all images are local (see images/), all data in data/
name: $PROJECT

services:
  postgres:
    image: $IMG_PG
    container_name: kms-postgres
    restart: unless-stopped
    environment:
      POSTGRES_USER: outline
      POSTGRES_DB: outline
    env_file: ./config/postgres.env
    volumes:
      - ./data/postgres:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD", "/usr/local/pgbin/pg_isready", "-h", "127.0.0.1", "-U", "outline", "-d", "outline"]
      interval: 5s
      timeout: 5s
      retries: 30
    networks: [kms]

  redis:
    image: $IMG_REDIS
    container_name: kms-redis
    restart: unless-stopped
    volumes:
      - ./data/redis:/data
    healthcheck:
      test: ["CMD", "/usr/local/bin/kms-redis-cli", "ping"]
      interval: 5s
      timeout: 5s
      retries: 30
    networks: [kms]

  ssozia:
    image: $IMG_SSOZIA
    container_name: kms-ssozia
    restart: unless-stopped
    environment:
      PUBLIC_BASE_URL: "https://$SSO_HOST"
      COOKIE_SECURE: "true"
    volumes:
      - ./data/ssozia:/app/data
      - ./config/ssozia/users.toml:/app/users.toml:ro
      - ./config/ssozia/clients.toml:/app/clients.toml:ro
    healthcheck:
      test: ["CMD", "bash", "-c", "exec 3<>/dev/tcp/127.0.0.1/4000"]
      interval: 5s
      timeout: 5s
      retries: 30
    networks: [kms]

  caddy:
    image: $IMG_CADDY
    container_name: kms-caddy
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./config/Caddyfile:/etc/caddy/Caddyfile:ro
      - ./certs/site:/certs:ro
      - ./data/caddy:/data
    networks:
      kms:
        # Outline reaches the SSO through Caddy under its public name.
        aliases: [$SSO_HOST, $KMS_HOST]

  outline:
    image: $IMG_OUTLINE
    container_name: kms-outline
    restart: unless-stopped
    env_file: ./config/outline.env
    ports:
      - "127.0.0.1:3000:3000"
    volumes:
      - ./data/outline:/var/lib/outline/data
      - ./certs/ca/rootCA.pem:/certs/rootCA.pem:ro
      - ./config/license:/etc/kms-license:ro
      - ./data/license:/var/lib/kms-license
$MACHINE_ID_MOUNT    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "node", "-e", "fetch('http://127.0.0.1:3000/_health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"]
      interval: 10s
      timeout: 5s
      retries: 6
      start_period: 900s
    networks: [kms]

networks:
  kms:
    name: $NET
EOF
  [[ -w $DATA ]] || $SUDO chown "$(id -u):$(id -g)" "$DATA"
  mkdir -p "$DATA"/{postgres,redis,outline,ssozia,caddy}
  $SUDO chown 999:999 "$DATA/postgres"; $SUDO chmod 700 "$DATA/postgres"
  $SUDO chown 998:998 "$DATA/redis"; $SUDO chown 1001:1001 "$DATA/outline"; $SUDO chown 10001:10001 "$DATA/ssozia"
  $SUDO chown 0:0 "$DATA/caddy"
  chmod 640 "$CERTS/site/key.pem" 2>/dev/null || true; $SUDO chgrp 0 "$CERTS/site/key.pem" 2>/dev/null || true
  dc config --quiet || fail "docker-compose.yml is not valid."
  ok "Configuration written; docker-compose.yml valid; data folders ready in data/"
  if [[ -z $SERVER_IP ]]; then
    SERVER_IP="$(ask_text "IP address the other computers use for this server" "$(detect_ip)")"
    [[ $SERVER_IP =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || fail "Not an IPv4 address: $SERVER_IP"
    sed -i '/^SERVER_IP=/d' "$SECRETS"; echo "SERVER_IP=$SERVER_IP" >>"$SECRETS"
  fi
  write_client_kit
fi

# ----------------------------------------------------------------------------
# Step 10: start step by step
# ----------------------------------------------------------------------------
wait_healthy() { # wait_healthy service seconds
  local s="$1" max="$2" end=$((SECONDS+$2)) st h c
  c="kms-$s"
  while (( SECONDS < end )); do
    st="$(dk inspect -f '{{.State.Status}}' "$c" 2>/dev/null || echo missing)"
    h="$(dk inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$c" 2>/dev/null || echo none)"
    [[ $h == healthy || ( $h == none && $st == running ) ]] && return 0
    if [[ $st == exited || $st == dead || $h == unhealthy ]]; then dc logs --tail 40 "$s"; return 1; fi
    sleep 3
  done
  dc logs --tail 40 "$s"; return 1
}
if step "Start the services one by one" 1 \
   "postgres -> redis -> ssozia -> caddy -> outline; each must be healthy before the next." \
   "Outline is started once and never restarted while it migrates the database."; then
  [[ -f $KMS/docker-compose.yml ]] || fail "No docker-compose.yml; run step 9."
  dk network inspect "$NET" >/dev/null 2>&1 || true
  for s in postgres redis ssozia caddy; do
    out="$(dc up -d --no-deps --pull never "$s" 2>&1)" || { printf '%s\n' "$out"; fail "Could not start $s."; }
    wait_healthy "$s" 180 || fail "$s did not become healthy (logs above)."
    ok "$s is running$( [[ $s != caddy ]] && echo ' and healthy' || true)"
  done
  if has_word subscribers "$PLUGINS"; then   # License management plugin: its own database on the same server
    PSQL=(exec -T postgres /usr/local/pgbin/psql -v ON_ERROR_STOP=1 -U postgres -d postgres -tA)
    if [[ $(dc "${PSQL[@]}" -c "SELECT 1 FROM pg_database WHERE datname='kms_subscribers'" 2>/dev/null | tr -d '[:space:]') == 1 ]]; then
      ok "License management plugin: database kms_subscribers exists (kept)"
    else
      dc "${PSQL[@]}" -c "CREATE DATABASE \"kms_subscribers\" OWNER \"outline\" ENCODING 'UTF8'" >/dev/null \
        || fail "Could not create the database kms_subscribers (License management plugin)."
      ok "License management plugin: database kms_subscribers created (the plugin makes its tables on first use)"
    fi
  fi
  # A migration lock left by an interrupted Outline would block the start.
  dc stop outline >/dev/null 2>&1 || true
  if [[ $(dc exec -T redis /usr/local/bin/kms-redis-cli del migrations 2>/dev/null || true) == 1 ]]; then
    info "Removed a stale migration lock from Redis"
  fi
  out="$(dc up -d --no-deps --pull never --force-recreate outline 2>&1)" || { printf '%s\n' "$out"; fail "Could not start outline."; }
  info "Waiting for Outline (first start migrates the database: a few minutes)"
  end=$((SECONDS+900)); code=000
  while (( SECONDS < end )); do
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 http://127.0.0.1:3000/_health || true)"
    [[ $code == 200 ]] && break
    st="$(dk inspect -f '{{.State.Status}}' kms-outline 2>/dev/null || echo missing)"
    [[ $st == running ]] || { dc logs --tail 60 outline; fail "outline is $st (logs above)."; }
    printf '         %s\n' "$(dc logs --tail 1 outline 2>/dev/null | sed 's/^[^|]*| //' | cut -c1-110)"
    sleep 10
  done
  [[ $code == 200 ]] || { dc logs --tail 60 outline; fail "Outline did not answer within 15 minutes (logs above)."; }
  ok "outline is running and healthy"
  # A workspace created while APP_NAME was ignored (patch 0009 < 2.1) is still called "Outline".
  AN="$(env_get APP_NAME "$CONFIG/outline.env")"
  if [[ -n $AN && $AN != Outline ]]; then
    n="$(printf '%s\n' "UPDATE teams SET name = :'name' WHERE name = 'Outline' AND \"deletedAt\" IS NULL;" \
      | dc exec -T postgres /usr/local/pgbin/psql -v ON_ERROR_STOP=1 -U postgres -d outline -v name="$AN" 2>/dev/null | awk '/^UPDATE/{print $2}' || true)"
    if [[ ${n:-0} =~ ^[1-9] ]]; then ok "Workspace renamed from \"Outline\" to \"$AN\""; fi
  fi
fi

# ----------------------------------------------------------------------------
# Step 11: verify
# ----------------------------------------------------------------------------
if step "Verify the installation" 1 \
   "Health of all services, HTTPS through Caddy, TLS trust from Outline to the SSO," \
   "patches inside the running Outline, and optionally a full SSO login test."; then
  VFAIL=0; chk() { if "$@" >/dev/null 2>&1; then ok "$CHK"; else warn "FAILED: $CHK"; VFAIL=1; fi; }
  for s in postgres redis ssozia outline; do
    CHK="$s healthy"; chk test "$(dk inspect -f '{{.State.Health.Status}}' "kms-$s" 2>/dev/null)" = healthy
  done
  CA="$CERTS/ca/rootCA.pem"
  CHK="https://$SSO_HOST/health via Caddy (TLS)"; chk curl -fsS --cacert "$CA" --resolve "$SSO_HOST:443:127.0.0.1" "https://$SSO_HOST/health"
  CHK="https://$KMS_HOST/_health via Caddy (TLS)"; chk curl -fsS --cacert "$CA" --resolve "$KMS_HOST:443:127.0.0.1" "https://$KMS_HOST/_health"
  if [[ -n $SERVER_IP ]]; then
    CHK="https://$KMS_HOST via the LAN address $SERVER_IP (what other computers use)"
    chk curl -fsS --cacert "$CA" --resolve "$KMS_HOST:443:$SERVER_IP" "https://$KMS_HOST/_health"
  fi
  CHK="OIDC discovery issuer = https://$SSO_HOST"
  chk bash -c "curl -fsS --cacert '$CA' --resolve '$SSO_HOST:443:127.0.0.1' 'https://$SSO_HOST/.well-known/openid-configuration' | jq -e '.issuer == \"https://$SSO_HOST\"'"
  CHK="Outline container trusts the SSO certificate"
  chk dk exec kms-outline node -e "fetch('https://$SSO_HOST/.well-known/openid-configuration').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
  if [[ -f $BUILD/.kms-patches ]]; then
    PL=(); while read -r _ p pv _; do PL+=("${p%.patch} v${pv:-?}"); done < <(grep '^patch ' "$BUILD/.kms-patches")
    ok "patches: ${#PL[@]} applied (fingerprint $(marker_fp "$BUILD/.kms-patches" | cut -c1-12))"
    printf '         %s\n' "${PL[@]}"
    CHK="The running Outline was built with this patch set"
    chk test "$(dk exec kms-outline awk '$1=="fingerprint"{print $2; exit}' .kms-patches 2>/dev/null)" = "$(marker_fp "$BUILD/.kms-patches")"
  else
    warn "patches: build/.kms-patches is missing (run step 4)"; VFAIL=1
  fi
  CHK="Fonts in the running Outline"; chk dk exec kms-outline test -f public/fonts/Vazirmatn-VF.woff2
  CHK="License: vendor key compiled into the running Outline (patch 0023)"; chk dk exec kms-outline grep -q -- "$(jq -r .sign.x "$ASSETS/license/vendor-public.json" 2>/dev/null || echo NOKEY)" build/server/license/vendorKey.js
  CHK="Hardening: no TypeScript sources in the running Outline"; chk dk exec kms-outline sh -c '! find server -type f \( -name "*.ts" -o -name "*.tsx" \) | grep -q .'
  CHK="Hardening: no source maps in the running Outline"; chk dk exec kms-outline sh -c '! find build public -type f -name "*.map" | grep -q .'
  CHK="License: server identity readable in the container"; chk dk exec kms-outline test -r /etc/kms-license/server-key.pem -a -s /etc/kms-license/hardware.json
  CHK="License: data folder writable in the container"; chk dk exec kms-outline sh -c 'touch /var/lib/kms-license/.w && rm /var/lib/kms-license/.w'
  if [[ -f $DATA/license/license.kmslic ]]; then ok "License: applied (status in Settings -> License)"
  else warn "License: not activated yet. The first admin activates it in Settings -> License (Outline is read-only until then)."; fi
  CHK="Data stored in kms/data (postgres)"; chk $SUDO test -s "$DATA/postgres/PG_VERSION"
  for id in $PLUGINS; do
    CHK="Plugin $id in the running Outline"; chk dk exec kms-outline test -f "build/plugins/$id/server/index.js"
    CHK="Plugin $id loaded without errors"; chk plugin_log_ok "$id"
  done
  if has_word subscribers "$PLUGINS"; then
    CHK="License management plugin: vendor keys readable in the container"; chk dk exec kms-outline test -r /etc/kms-license/vendor/private.json
  fi
  if has_word ssozia-users "$PLUGINS"; then
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 --cacert "$CA" --resolve "$SSO_HOST:443:127.0.0.1" "https://$SSO_HOST/admin/api/users" || true)"
    case "$code" in
      401|403) ok "Users plugin: ssozia offers the admin API" ;;
      404) warn "Users plugin: ssozia has no admin API (needs ssozia 0.2.0+: new assets/ssozia.zip, then --from 6)"; VFAIL=1 ;;
      *) warn "Users plugin: ssozia admin API answered HTTP $code" ;;
    esac
  fi
  SSO_IP="$(getent hosts "$SSO_HOST" | awk '{print $1; exit}' || true)"
  if [[ -f $SZ/scripts/e2e.sh && -n $SSO_IP ]] && { [[ $SSO_IP == 127.* || $SSO_IP == ::1 ]] || hostname -I | tr ' ' '\n' | has_line "$SSO_IP"; }; then
    if [[ $ASSUME_YES == 0 ]] && ask_yn "Run the full SSO login test (ssozia e2e.sh; asks the admin password)?" y; then
      AE="$(env_get ADMIN_EMAIL "$SECRETS")"; EP=""; PW_SKIPPED=0
      for try in 1 2 3; do   # the password is checked first: a typo would fail half of e2e.sh
        # The password waits 60 s for the first key; without one the test is skipped.
        rc=0; timed_read "  ? Admin password for $AE (hidden): " hidden 60 || rc=$?
        if (( rc == 2 )); then PW_SKIPPED=1; EP=""; break; fi
        EP="$REPLY_LINE"; REPLY_LINE=""
        code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 15 --cacert "$CA" --resolve "$SSO_HOST:443:127.0.0.1" \
          --data-urlencode "email=$AE" --data-urlencode "password=$EP" --data-urlencode "authorize_query=" \
          "https://$SSO_HOST/login" || true)"
        case "$code" in
          302|303) ok "SSO: admin password accepted"; break ;;
          401) warn "SSO: wrong password for $AE (try $try of 3)"; EP="" ;;
          429) warn "SSO: too many failed logins; ssozia blocks this address/account for 5 minutes"; EP=""; break ;;
          *) warn "SSO: /login answered HTTP $code"; EP=""; break ;;
        esac
      done
      if (( PW_SKIPPED )); then
        info "SSO login test skipped: no password typed in 60 s."
      elif [[ -z $EP ]]; then
        info "The password is the one set when the admin was created (config/ssozia/users.toml keeps only its hash)."
        info "New password: bash $SELF --from 5, answer n to 'Keep the admin account', then let steps 6-11 run."
        VFAIL=1
      else
      (cd "$SZ" && CURL_CA_BUNDLE="$CA" SSL_CERT_FILE="$CA" BASE="https://$SSO_HOST" EXPECT_ISSUER="https://$SSO_HOST" \
        E2E_EMAIL="$(env_get ADMIN_EMAIL "$SECRETS")" E2E_PASSWORD="$EP" E2E_CLIENT_SECRET="$(env_get OIDC_CLIENT_SECRET "$SECRETS")" \
        E2E_REDIRECT_URI="https://$KMS_HOST/auth/oidc.callback" E2E_EXPECT_USERNAME="$(grep -m1 '^preferred_username' "$CONFIG/ssozia/users.toml" | cut -d'"' -f2)" \
        bash scripts/e2e.sh) && ok "SSO login test passed" || { warn "SSO login test reported failures"; VFAIL=1; }
      fi
      unset EP
    fi
  fi
  (( VFAIL )) && warn "Some checks failed (see above)." || ok "All checks passed"
fi

# ----------------------------------------------------------------------------
# Step 12: delete the sources (customer servers)
#   The images are built; the sources are not needed to run them. Not done on a vendor kit.
# ----------------------------------------------------------------------------
if step "Delete the sources" 1 \
   "The Outline image is built, so the sources are removed: $BUILD (patched Outline, ssozia," \
   "node, yarn) and in the kit assets/outline-*.zip, patches/, patches.zip, ssozia.zip, plugins/*.zip." \
   "Kept: install.sh, fonts.zip, the vendor public key, images, data, config. A rebuild later needs a new kit."; then
  RM_OK=1
  [[ ${VFAIL:-1} == 0 ]] || { RM_OK=0; info "Not deleted: the verification (step 11) did not run or reported failures."; }
  [[ $KMS_MODE == admin ]] && { RM_OK=0; info "Not deleted: Admin mode (the vendor's server keeps its sources)."; }
  [[ -d $KIT/Admin || -d $KIT/.git ]] && { RM_OK=0; info "Not deleted: this is a vendor kit (Admin/ or .git found)."; }
  has_word subscribers "$PLUGINS" && { RM_OK=0; info "Not deleted: the License management plugin is built in (vendor server)."; }
  dk image inspect "$IMG_OUTLINE" >/dev/null 2>&1 || { RM_OK=0; info "Not deleted: image $IMG_OUTLINE does not exist."; }
  if (( RM_OK )); then
    if ask_yn "Delete the sources now (build/, outline zip, patches, ssozia.zip, plugins)?" y; then
      $SUDO rm -rf "$BUILD" "$KIT"/assets/outline-[0-9]*.zip "$KIT"/assets/v[0-9]*.zip \
        "$KIT/assets/patches" "$KIT/assets/patches.zip" "$KIT"/assets/patches.zip.bak-* "$KIT/assets/ssozia.zip" "$KIT/assets/ssozia" "$KIT"/plugins/*.zip
      # earlier runs moved old patched source trees and replaced patches into archive/: they hold the same code
      $SUDO rm -rf "$ARCHIVE"/*/outline-[0-9]* "$ARCHIVE"/*/patches
      rmdir "$KIT/plugins" 2>/dev/null || true
      date '+%Y-%m-%d %H:%M' | $SUDO tee "$KMS/.kms-sources-removed" >/dev/null
      ok "Sources deleted (build/, assets sources, patches, plugin zips)"
    else
      warn "Sources kept on this server by your choice."
    fi
  else
    warn "Sources kept on this server."
  fi
fi

# ----------------------------------------------------------------------------
section "Summary"
printf '  %s\n' "${SUMMARY[@]}"
printf '\n  Mode:        %s\n' "$KMS_MODE"
printf '  Patches:     step P: %s%s\n' "$RECONCILE_RESULT" "$( (( PATCH_ZIP_REBUILT )) && echo ', patches.zip rebuilt' || true)"
printf '               source kit: %s  install folder: %s\n' "$KIT" "$KMS"
if (( PATCH_ZIP_REBUILT )) && [[ -d $KIT/.git ]]; then
  printf '               hint: commit assets/patches.zip and assets/patches/ to the kit repo (%s)\n' "$KIT"
fi
cat <<EOF

  Wiki:        https://$KMS_HOST   (log in with the SSO admin: $(env_get ADMIN_EMAIL "$SECRETS" 2>/dev/null))
  SSO:         https://$SSO_HOST
  First visit: the first SSO login creates the Outline workspace and makes you its admin.
  Plugins:     ${PLUGINS:-none}$(has_word subscribers "$PLUGINS" && printf '\n               License management: Settings -> License -> Open (/subscribers)' || true)$(has_word ssozia-users "$PLUGINS" && printf '\n               Users: sidebar -> Users (/ssozia-users), for admins who are also ssozia admins' || true)
  License:     Settings -> License: download the request file, send it to your supplier,
               apply the license you get back (until then Outline is read-only).
  Browser:     press Ctrl+Shift+R once (the service worker caches the old app).
  Other PCs:   names -> ${SERVER_IP:-<server IP>} and trust the CA. Linux PC (as your user):
                 scp -r $USER@${SERVER_IP:-<server IP>}:$KMS/client ~/kms-client && bash ~/kms-client/kms-client-setup.sh
               Windows, DNS server (BIND, dnsmasq, MikroTik, ...): $KMS/client/dns-records.txt

  Manage:      cd $KMS && docker compose ps | logs -f outline | restart outline | down
  Re-run:      bash $SELF              (keeps data and secrets; every step asks)
               bash $SELF --from 7     (after editing build/$SRC_NAME: rebuild Outline -> images -> start)
  Data:        $DATA     Secrets: $CONFIG/secrets.env (mode 600)
  Log:         $LOG
EOF
