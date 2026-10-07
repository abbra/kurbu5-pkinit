#!/usr/bin/env bash
# build-mit-pqc.sh -- build MIT krb5 with the draft-bokovoy-kitten-pkinit-pqc
# pkinit.so, for interop testing against kurbu5-pkinit.
#
# Clones (or updates) the MIT implementation of the draft, applies the local
# interop patches in contrib/ci/mit-krb5-pqc/ that upstream does not carry
# yet, and installs the result into a private prefix. The system krb5 is
# never touched; point the system tests at the prefix instead:
#
#   bash tests/system/pkinit/run.sh --krb5-prefix <prefix> --mit-pqc
#
# Usage:
#   contrib/ci/build-mit-pqc.sh [--dir DIR] [--repo URL] [--branch NAME]
#
#   --dir DIR      work directory (default: target/mit-krb5-pqc); the
#                  checkout goes to DIR/src, the installation to DIR/prefix
#   --repo URL     git repository (default: https://github.com/jrisc/krb5.git)
#   --branch NAME  branch (default: draft-bokovoy-kitten-pkinit-pqc)
#
# The build is skipped when the upstream commit and the local patches are
# unchanged since the last successful build. Prints the prefix on success.
#
# Build requirements: git, autoconf, bison, gcc, make, openssl-devel,
# keyutils-libs-devel, libcom_err-devel, libverto-devel.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
PATCH_DIR="$SCRIPT_DIR/mit-krb5-pqc"

WORK_DIR="$REPO_ROOT/target/mit-krb5-pqc"
REPO_URL="https://github.com/jrisc/krb5.git"
BRANCH="draft-bokovoy-kitten-pkinit-pqc"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dir) WORK_DIR="$2"; shift 2 ;;
        --repo) REPO_URL="$2"; shift 2 ;;
        --branch) BRANCH="$2"; shift 2 ;;
        --help|-h) sed -n '2,26p' "$0"; exit 0 ;;
        *) echo "build-mit-pqc: unknown option: $1" >&2; exit 2 ;;
    esac
done

mkdir -p "$WORK_DIR"
WORK_DIR="$(cd "$WORK_DIR" && pwd)"
SRC="$WORK_DIR/src"
PREFIX="$WORK_DIR/prefix"
STAMP="$PREFIX/.build-stamp"
LOG="$WORK_DIR/build.log"

log() { echo "[build-mit-pqc] $*" >&2; }

if [[ -d "$SRC/.git" ]]; then
    log "updating $REPO_URL $BRANCH"
    git -C "$SRC" fetch --quiet "$REPO_URL" "$BRANCH"
else
    log "cloning $REPO_URL $BRANCH"
    git clone --quiet --branch "$BRANCH" --single-branch "$REPO_URL" "$SRC"
    git -C "$SRC" fetch --quiet "$REPO_URL" "$BRANCH"
fi
UPSTREAM="$(git -C "$SRC" rev-parse FETCH_HEAD)"

patches=()
if compgen -G "$PATCH_DIR/*.patch" >/dev/null; then
    patches=("$PATCH_DIR"/*.patch)
fi
want_stamp="$UPSTREAM $(cat "${patches[@]}" /dev/null | sha256sum | cut -d' ' -f1)"

if [[ -f "$STAMP" && "$(cat "$STAMP")" == "$want_stamp" ]]; then
    log "up to date ($UPSTREAM)"
    echo "$PREFIX"
    exit 0
fi

# Start from a pristine upstream tree: earlier patches and generated
# autotools files would otherwise collide with this run's.
git -C "$SRC" checkout --quiet --force --detach "$UPSTREAM"
git -C "$SRC" clean --quiet -fdx

for p in "${patches[@]}"; do
    name="$(basename "$p")"
    if git -C "$SRC" apply --check "$p" 2>/dev/null; then
        git -C "$SRC" apply "$p"
        log "applied $name"
    elif git -C "$SRC" apply --reverse --check "$p" 2>/dev/null; then
        log "skipped $name (already upstream)"
    else
        log "cannot apply $name to $UPSTREAM; update or drop it"
        exit 1
    fi
done

log "building $UPSTREAM into $PREFIX (log: $LOG)"
rm -rf "$PREFIX"
(
    cd "$SRC/src"
    autoreconf -fi
    ./configure --prefix="$PREFIX" --with-crypto-impl=openssl \
        --with-tls-impl=openssl --without-lmdb --disable-rpath --enable-pkinit
    make -j"$(nproc)"
    # MIT's recursive make can leave a library unrelinked after a parallel
    # rebuild of one of its objects; a serial pass catches that up.
    make
    make install
) >"$LOG" 2>&1 || { log "build failed; see $LOG"; tail -20 "$LOG" >&2; exit 1; }

echo "$want_stamp" >"$STAMP"
log "installed $(LD_LIBRARY_PATH="$PREFIX/lib" "$PREFIX/bin/klist" -V)"
echo "$PREFIX"
