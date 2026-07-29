#!/usr/bin/env bash
# tests/system/pkinit/run.sh -- PKINIT system integration test
#
# Starts an ephemeral MIT KDC with the kurbu5-pkinit plugin,
# generates PKINIT certs, and verifies kinit works with both
# normal and anonymous PKINIT.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

KDC_PORTBASE="${KDC_PORTBASE:-63100}"
REALM="${REALM:-PKINIT.TEST}"
PRINCIPAL="${PRINCIPAL:-user}"

TESTDIR="$(mktemp -d /tmp/pkinit-test.XXXXXXXXXX)"
ENV_FILE="$TESTDIR/env.sh"
SETUP_PID=""
PASS=0
FAIL=0

# -- Helpers --

cleanup() {
    if [[ -n "$SETUP_PID" ]]; then
        kill "$SETUP_PID" 2>/dev/null || true
        wait "$SETUP_PID" 2>/dev/null || true
    fi
    rm -rf "$TESTDIR"
}
trap cleanup EXIT INT TERM

require_tools() {
    local missing=()
    for tool in "$@"; do
        command -v "$tool" &>/dev/null || missing+=("$tool")
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        echo "FATAL: missing required tools: ${missing[*]}" >&2
        exit 1
    fi
}

report() {
    local label="$1" result="$2"
    if [[ "$result" == "PASS" ]]; then
        echo "  PASS: $label"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $label"
        FAIL=$((FAIL + 1))
    fi
}

# -- Prereqs --

require_tools python3 openssl krb5kdc kdb5_util kadmin.local kinit klist

# -- Build plugin if needed --

PLUGIN_SO="$REPO_ROOT/target/release/libkurbu5_pkinit.so"
if [[ ! -f "$PLUGIN_SO" ]]; then
    echo "Building plugin (release)..."
    cargo build --release --manifest-path "$REPO_ROOT/Cargo.toml" -p kurbu5-pkinit
fi

# -- Start ephemeral KDC with PKINIT --

echo "Starting ephemeral KDC (realm=$REALM, port=$KDC_PORTBASE)..."
python3 "$SCRIPT_DIR/setup.py" \
    --testdir "$TESTDIR/kdc" \
    --portbase "$KDC_PORTBASE" \
    --realm "$REALM" \
    --principal "$PRINCIPAL" \
    --plugin-so "$PLUGIN_SO" \
    --env-file "$ENV_FILE" &
SETUP_PID=$!

for i in $(seq 1 60); do
    [[ -f "$ENV_FILE" ]] && break
    if ! kill -0 "$SETUP_PID" 2>/dev/null; then
        echo "FATAL: KDC setup process died before producing env file." >&2
        cat "$TESTDIR/kdc/kdc.log" 2>/dev/null || true
        exit 1
    fi
    sleep 0.5
done

if [[ ! -f "$ENV_FILE" ]]; then
    echo "FATAL: KDC setup did not produce env file within 30s." >&2
    exit 1
fi

# shellcheck disable=SC1090
source "$ENV_FILE"
echo "KDC running, env sourced."

# -- Test 1: Normal PKINIT kinit --

echo
echo "Test 1: kinit with PKINIT (normal)"
if KRB5_CONFIG="$KRB5_CONFIG" \
   KRB5CCNAME="$KRB5CCNAME" \
   kinit "${PKINIT_PRINCIPAL}@${PKINIT_REALM}" </dev/null 2>&1; then
    report "kinit succeeded" "PASS"
else
    report "kinit failed" "FAIL"
fi

# -- Test 2: Validate TGT --

echo
echo "Test 2: klist shows valid ticket"
KLIST_OUTPUT=$(KRB5_CONFIG="$KRB5_CONFIG" KRB5CCNAME="$KRB5CCNAME" klist 2>&1) || true
if echo "$KLIST_OUTPUT" | grep -q "krbtgt/${PKINIT_REALM}@${PKINIT_REALM}"; then
    report "TGT present" "PASS"
else
    report "TGT not found" "FAIL"
    echo "$KLIST_OUTPUT"
fi

# -- Test 3: Anonymous PKINIT --

echo
echo "Test 3: kinit with anonymous PKINIT"
ANON_CCACHE="FILE:$TESTDIR/ccache-anon"
if KRB5_CONFIG="$KRB5_CONFIG" \
   KRB5CCNAME="$ANON_CCACHE" \
   kinit -n "@${PKINIT_REALM}" </dev/null 2>&1; then
    report "anonymous kinit succeeded" "PASS"
else
    report "anonymous kinit failed" "FAIL"
fi

# -- Test 4: Validate anonymous TGT --

echo
echo "Test 4: klist shows anonymous TGT"
ANON_KLIST=$(KRB5_CONFIG="$KRB5_CONFIG" KRB5CCNAME="$ANON_CCACHE" klist 2>&1) || true
if echo "$ANON_KLIST" | grep -q "WELLKNOWN/ANONYMOUS"; then
    report "anonymous TGT present" "PASS"
else
    report "anonymous TGT not found" "FAIL"
    echo "$ANON_KLIST"
fi

# -- Summary --

echo
echo "Results: $PASS passed, $FAIL failed"
if [[ "$FAIL" -gt 0 ]]; then
    echo
    echo "KDC log:"
    cat "$TESTDIR/kdc/kdc.log" 2>/dev/null || true
    exit 1
fi
