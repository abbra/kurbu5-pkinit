#!/usr/bin/env bash
# tests/system/pkinit/run.sh -- PKINIT system integration test
#
# Starts an ephemeral MIT KDC and verifies kinit works with both
# normal and anonymous PKINIT across plugin combinations.
#
# Combos:
#   us-us   -- kurbu5-pkinit KDC + kurbu5-pkinit client
#   us-mit  -- kurbu5-pkinit KDC + MIT pkinit client
#   mit-us  -- MIT pkinit KDC   + kurbu5-pkinit client
#   mit-mit -- MIT pkinit KDC   + MIT pkinit client (baseline)
#
# Usage:
#   bash run.sh                    # run all combos (MIT combos skipped if pkinit.so missing)
#   bash run.sh --combo us-mit     # run a single combo
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

KDC_PORTBASE="${KDC_PORTBASE:-63100}"
REALM="${REALM:-PKINIT.TEST}"
PRINCIPAL="${PRINCIPAL:-user}"
MIT_PKINIT_SO="${MIT_PKINIT_SO:-/usr/lib64/krb5/plugins/preauth/pkinit.so}"

COMBO_ARG="all"
KEY_TYPE="ec:P-256"
PQC_MIN_ALGORITHM=""
TOTAL_PASS=0
TOTAL_FAIL=0
TOTAL_SKIP=0

display_help() {
# Key types: keep in sync with SUPPORTED_KEY_TYPES in setup.py.
# PQC algorithms: keep in sync with KemAlgorithm::from_name in
# pkinit-core/src/constants.rs -- these are the only pkinit_pqc_min_algorithm
# values the plugin currently recognizes; anything else is silently ignored.
local message=$(cat <<-END
Usage:
$(basename $0) [--combo combo] [--key-type type] [--pqc-min-algorithm alg]

where
  --combo combo        -- combination to run [us-us, us-mit, mit-us, mit-mit]
  --key-type key       -- algorithm to use for certificate generation
                           [ec:P-256, ec:P-384, ec:P-521,
                            rsa:2048, rsa:3072, rsa:4096,
                            mldsa44, mldsa65, mldsa87]
                           (default: ec:P-256)
  --pqc-min-algorithm  -- minimal PQC algorithm to require; enables the KEM
                           path instead of DH/ECDH when set
                           [ML-KEM-512, ML-KEM-768, ML-KEM-1024,
                            ML-KEM-768-X25519, ML-KEM-768-ECDH-P256,
                            ML-KEM-1024-ECDH-P384]
                           (default: unset -- classic DH/ECDH path)

MIT combinations skipped if pkinit.so is not available
END
)
echo -e "$message"
}

# -- Argument parsing --

while [[ $# -gt 0 ]]; do
    case "$1" in
        --combo) COMBO_ARG="$2"; shift 2 ;;
        --key-type) KEY_TYPE="$2"; shift 2 ;;
        --pqc-min-algorithm) PQC_MIN_ALGORITHM="$2"; shift 2 ;;
        --help) display_help ; exit 0 ;;
        *) echo "Unknown argument: $1" >&2; exit 1 ;;
    esac
done

# -- Helpers --

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
    local combo="$1" label="$2" result="$3"
    if [[ "$result" == "PASS" ]]; then
        echo "  [$combo] PASS: $label"
        TOTAL_PASS=$((TOTAL_PASS + 1))
    elif [[ "$result" == "SKIP" ]]; then
        echo "  [$combo] SKIP: $label"
        TOTAL_SKIP=$((TOTAL_SKIP + 1))
    else
        echo "  [$combo] FAIL: $label"
        TOTAL_FAIL=$((TOTAL_FAIL + 1))
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

# -- Determine combos to run --

ALL_COMBOS=(us-us us-mit mit-us mit-mit)
if [[ "$COMBO_ARG" == "all" ]]; then
    COMBOS=("${ALL_COMBOS[@]}")
else
    COMBOS=("$COMBO_ARG")
fi

HAS_MIT_PKINIT=false
if [[ -f "$MIT_PKINIT_SO" ]]; then
    HAS_MIT_PKINIT=true
fi

# -- Per-combo test runner --

run_combo() {
    local combo="$1" kdc_so="$2" client_so="$3" port_offset="$4"
    local port=$((KDC_PORTBASE + port_offset))
    local TESTDIR
    TESTDIR="$(mktemp -d /tmp/pkinit-test-${combo}.XXXXXXXXXX)"
    local ENV_FILE="$TESTDIR/env.sh"
    local SETUP_PID=""
    local FAIL_BEFORE=$TOTAL_FAIL

    echo
    echo "=== Combo: $combo (KDC=$(basename "$kdc_so"), Client=$(basename "$client_so"), KeyType=$KEY_TYPE${PQC_MIN_ALGORITHM:+, PQC=$PQC_MIN_ALGORITHM}) ==="

    # Build optional PQ args
    local pqc_args=()
    if [[ -n "$PQC_MIN_ALGORITHM" ]]; then
        pqc_args+=(--pqc-min-algorithm "$PQC_MIN_ALGORITHM")
    fi

    # Start ephemeral KDC
    python3 "$SCRIPT_DIR/setup.py" \
        --testdir "$TESTDIR/kdc" \
        --portbase "$port" \
        --realm "$REALM" \
        --principal "$PRINCIPAL" \
        --kdc-plugin-so "$kdc_so" \
        --client-plugin-so "$client_so" \
        --key-type "$KEY_TYPE" \
        "${pqc_args[@]}" \
        --env-file "$ENV_FILE" &
    SETUP_PID=$!

    for i in $(seq 1 60); do
        [[ -f "$ENV_FILE" ]] && break
        if ! kill -0 "$SETUP_PID" 2>/dev/null; then
            echo "  [$combo] FATAL: KDC setup process died before producing env file." >&2
            cat "$TESTDIR/kdc/kdc.log" 2>/dev/null || true
            report "$combo" "KDC startup" "FAIL"
            report "$combo" "klist TGT" "FAIL"
            report "$combo" "anonymous kinit" "FAIL"
            report "$combo" "anonymous TGT" "FAIL"
            return
        fi
        sleep 0.5
    done

    if [[ ! -f "$ENV_FILE" ]]; then
        echo "  [$combo] FATAL: KDC setup did not produce env file within 30s." >&2
        report "$combo" "KDC startup" "FAIL"
        report "$combo" "klist TGT" "FAIL"
        report "$combo" "anonymous kinit" "FAIL"
        report "$combo" "anonymous TGT" "FAIL"
        return
    fi

    # shellcheck disable=SC1090
    source "$ENV_FILE"

    # Test 1: Normal PKINIT kinit (identity via -X, anchors from krb5.conf)
    if KRB5_CONFIG="$KRB5_CONFIG" \
       KRB5CCNAME="$KRB5CCNAME" \
       kinit -X "X509_user_identity=FILE:${PKINIT_CLIENT_CERT},${PKINIT_CLIENT_KEY}" \
             "${PKINIT_PRINCIPAL}@${PKINIT_REALM}" </dev/null 2>&1; then
        report "$combo" "kinit succeeded" "PASS"
    else
        report "$combo" "kinit failed" "FAIL"
    fi

    # Test 2: Validate TGT
    KLIST_OUTPUT=$(KRB5_CONFIG="$KRB5_CONFIG" KRB5CCNAME="$KRB5CCNAME" klist 2>&1) || true
    if echo "$KLIST_OUTPUT" | grep -q "krbtgt/${PKINIT_REALM}@${PKINIT_REALM}"; then
        report "$combo" "TGT present" "PASS"
    else
        report "$combo" "TGT not found" "FAIL"
        echo "$KLIST_OUTPUT"
    fi

    # Test 3: Anonymous PKINIT (no identity needed, anchors from krb5.conf)
    ANON_CCACHE="FILE:$TESTDIR/ccache-anon"
    if KRB5_CONFIG="$KRB5_CONFIG" \
       KRB5CCNAME="$ANON_CCACHE" \
       kinit -n "@${PKINIT_REALM}" </dev/null 2>&1; then
        report "$combo" "anonymous kinit succeeded" "PASS"
    else
        report "$combo" "anonymous kinit failed" "FAIL"
    fi

    # Test 4: Validate anonymous TGT
    ANON_KLIST=$(KRB5_CONFIG="$KRB5_CONFIG" KRB5CCNAME="$ANON_CCACHE" klist 2>&1) || true
    if echo "$ANON_KLIST" | grep -q "WELLKNOWN/ANONYMOUS"; then
        report "$combo" "anonymous TGT present" "PASS"
    else
        report "$combo" "anonymous TGT not found" "FAIL"
        echo "$ANON_KLIST"
    fi

    # Dump KDC log and KRB5_TRACE output on per-combo failure. KRB5_TRACE is
    # sourced from ENV_FILE and covers both the KDC process and the kinit
    # invocations above, so it carries pkinit_trace!() output from whichever
    # side (client or KDC) actually failed.
    if [[ $TOTAL_FAIL -gt $FAIL_BEFORE ]]; then
        echo
        echo "  [$combo] KDC log:"
        cat "$TESTDIR/kdc/kdc.log" 2>/dev/null || true
        echo
        echo "  [$combo] KRB5_TRACE:"
        cat "${KRB5_TRACE:-}" 2>/dev/null || true
    fi

    # Cleanup
    if [[ -n "$SETUP_PID" ]]; then
        kill "$SETUP_PID" 2>/dev/null || true
        wait "$SETUP_PID" 2>/dev/null || true
    fi
    rm -rf "$TESTDIR"
}

# -- Run selected combos --

COMBO_INDEX=0
for combo in "${COMBOS[@]}"; do
    case "$combo" in
        us-us)
            run_combo "$combo" "$PLUGIN_SO" "$PLUGIN_SO" $((COMBO_INDEX * 10))
            ;;
        us-mit)
            if $HAS_MIT_PKINIT; then
                run_combo "$combo" "$PLUGIN_SO" "$MIT_PKINIT_SO" $((COMBO_INDEX * 10))
            else
                echo
                echo "=== Combo: $combo -- SKIP (MIT pkinit.so not found at $MIT_PKINIT_SO) ==="
                report "$combo" "kinit" "SKIP"
                report "$combo" "klist" "SKIP"
                report "$combo" "anonymous kinit" "SKIP"
                report "$combo" "anonymous TGT" "SKIP"
            fi
            ;;
        mit-us)
            if $HAS_MIT_PKINIT; then
                run_combo "$combo" "$MIT_PKINIT_SO" "$PLUGIN_SO" $((COMBO_INDEX * 10))
            else
                echo
                echo "=== Combo: $combo -- SKIP (MIT pkinit.so not found at $MIT_PKINIT_SO) ==="
                report "$combo" "kinit" "SKIP"
                report "$combo" "klist" "SKIP"
                report "$combo" "anonymous kinit" "SKIP"
                report "$combo" "anonymous TGT" "SKIP"
            fi
            ;;
        mit-mit)
            if $HAS_MIT_PKINIT; then
                run_combo "$combo" "$MIT_PKINIT_SO" "$MIT_PKINIT_SO" $((COMBO_INDEX * 10))
            else
                echo
                echo "=== Combo: $combo -- SKIP (MIT pkinit.so not found at $MIT_PKINIT_SO) ==="
                report "$combo" "kinit" "SKIP"
                report "$combo" "klist" "SKIP"
                report "$combo" "anonymous kinit" "SKIP"
                report "$combo" "anonymous TGT" "SKIP"
            fi
            ;;
        *)
            echo "Unknown combo: $combo" >&2
            echo "Valid combos: us-us, us-mit, mit-us, mit-mit, all" >&2
            exit 1
            ;;
    esac
    COMBO_INDEX=$((COMBO_INDEX + 1))
done

# -- Summary --

echo
echo "Results: $TOTAL_PASS passed, $TOTAL_FAIL failed, $TOTAL_SKIP skipped"
if [[ "$TOTAL_FAIL" -gt 0 ]]; then
    exit 1
fi
