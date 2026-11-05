#!/usr/bin/env bash
# tests/system/pkinit/tofu.sh -- PKINIT KDC-CA trust-on-first-use system test
#
# Exercises the client TOFU flow end to end against a kurbu5-pkinit KDC and the
# reference pkinit-trust-brokerd, then renders an HTML report of the scenarios.
# Under GitHub Actions (GITHUB_STEP_SUMMARY set), the same manifest is also
# rendered straight into the job summary, so the report is visible on the
# run's Summary tab without downloading and unpacking the HTML artifact.
#
# Scenarios (each fully independent -- own KDC, own broker, own socket/state):
#   happy-path  broker auto-approves: the anonymous exchange pins the KDC CA and
#               the authenticated kinit validates against it              -> PASS
#   denial      broker auto-denies the unknown realm: kinit fails closed  -> PASS
#   mitm        broker pre-seeded with a different CA for the realm: the
#               presented CA mismatches the pin and is denied             -> PASS
#   pq-happy-path  same as happy-path, but the CA/KDC/client chain is
#                  ML-DSA-65 (FIPS 204) instead of ECDSA -- trust-broker
#                  chain validation must not assume the anchor's algorithm -> PASS
#   pq-tty-1day    same as pq-happy-path, but the broker runs with --ui tty
#                  and the "user" confirms trust for 1 day by answering the
#                  prompt on kinit's own controlling terminal (a real pty --
#                  see pty_kinit.py), not --auto approve                   -> PASS
#   pq-token-flow  a fully post-quantum chain whose client identity lives on
#                  a local kryoptic PKCS#11 token (ML-DSA-65 key generated
#                  inside the token, certificate issued by the test CA and
#                  imported onto it). The client's PKCS#11 traffic runs
#                  through the OpenSC pkcs11-spy so the report carries the
#                  exact PKCS#11 API call sequence the plugin made (the
#                  crypto-auditing feed; see docs/local-ci.md). Skipped when
#                  kryoptic / pkcs11-spy / pkcs11-tool are not installed.   -> PASS
#
# Usage:
#   bash tofu.sh [--report FILE]
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

REALM="${REALM:-PKINIT.TEST}"
PRINCIPAL="${PRINCIPAL:-user}"
REPORT_HTML="${TOFU_REPORT:-$REPO_ROOT/pkinit-tofu-report.html}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --report) REPORT_HTML="$2"; shift 2 ;;
        --help|-h)
            sed -n '2,33p' "$0"; exit 0 ;;
        *) echo "Unknown argument: $1" >&2; exit 1 ;;
    esac
done

# -- Prereqs --

require_tools() {
    local missing=()
    for t in "$@"; do command -v "$t" >/dev/null 2>&1 || missing+=("$t"); done
    if [[ ${#missing[@]} -gt 0 ]]; then
        echo "error: missing required tools: ${missing[*]}" >&2
        exit 1
    fi
}
require_tools python3 openssl krb5kdc kdb5_util kadmin.local kinit klist

# The report embeds the parsed PKCS#11 call sequence in every CI run, even
# where the token scenario itself is skipped; check the parser up front so a
# broken parser fails the job instead of the report.
python3 "$SCRIPT_DIR/pkcs11_sequence.py" --selftest

# -- Build plugin + broker daemon (release) --

PLUGIN_SO="$REPO_ROOT/target/release/libkurbu5_pkinit.so"
BROKERD="$REPO_ROOT/target/release/pkinit-trust-brokerd"
if [[ ! -f "$PLUGIN_SO" || ! -x "$BROKERD" ]]; then
    echo "Building plugin and broker daemon (release)..."
    cargo build --release --manifest-path "$REPO_ROOT/Cargo.toml" \
        -p kurbu5-pkinit -p pkinit-trust-brokerd
fi
[[ -f "$PLUGIN_SO" ]] || { echo "error: $PLUGIN_SO not built" >&2; exit 1; }
[[ -x "$BROKERD" ]]  || { echo "error: $BROKERD not built"  >&2; exit 1; }

WORK="$(mktemp -d /tmp/pkinit-tofu.XXXXXXXXXX)"
REPORTDIR="$WORK/report"
mkdir -p "$REPORTDIR"
cleanup() { [[ -n "${KEEP_WORK:-}" ]] && { echo "KEEP_WORK set; leaving $WORK"; return; }; rm -rf "$WORK"; }
trap cleanup EXIT

# -- PKCS#11 token (pq-token-flow prereqs) --
#
# The token scenario needs a local software token, not hardware: kryoptic is
# the one the rest of the suite uses (same module discovery and provisioning
# recipe as pkinit-core/tests/pkcs11_identity.rs). Any piece missing --
# including a runner whose container lacks the packages -- skips that one
# scenario rather than failing the run.

first_existing() {
    local p
    for p in "$@"; do
        [[ -f "$p" ]] && { echo "$p"; return; }
    done
}

KRYOPTIC_MODULE="$(first_existing \
    /usr/lib64/pkcs11/libkryoptic_pkcs11.so \
    /usr/lib/x86_64-linux-gnu/pkcs11/libkryoptic_pkcs11.so \
    /usr/lib/aarch64-linux-gnu/pkcs11/libkryoptic_pkcs11.so)"
PKCS11_SPY_MODULE="$(first_existing \
    /usr/lib64/pkcs11/pkcs11-spy.so \
    /usr/lib/x86_64-linux-gnu/pkcs11/pkcs11-spy.so \
    /usr/lib/aarch64-linux-gnu/pkcs11/pkcs11-spy.so)"
PKCS11_PROVIDER_MODULE="$(first_existing \
    /usr/lib64/ossl-modules/pkcs11.so \
    /usr/lib/x86_64-linux-gnu/ossl-modules/pkcs11.so \
    /usr/lib/aarch64-linux-gnu/ossl-modules/pkcs11.so)"

TOKEN_LABEL="PKINIT-TOFU"
TOKEN_OBJECT="clientkey"
TOKEN_USER_PIN="123456"
TOKEN_SO_PIN="sopin12"
TOKEN_URI="pkcs11:token=${TOKEN_LABEL};object=${TOKEN_OBJECT};type=private?pin-value=${TOKEN_USER_PIN}"

token_flow_supported() {
    [[ -n "$KRYOPTIC_MODULE" && -n "$PKCS11_SPY_MODULE" &&
       -n "$PKCS11_PROVIDER_MODULE" ]] && command -v pkcs11-tool >/dev/null
}

provision_kryoptic_token() {
    export KRYOPTIC_CONF="$WORK/kryoptic.conf"
    cat > "$KRYOPTIC_CONF" <<EOF
[ec_point_encoding]
encoding = "Bytes"
[[slots]]
slot = 1
description = "$TOKEN_LABEL"
dbtype = "sqlite"
dbargs = "$WORK/kryoptic.db"
EOF
    pkcs11-tool --module "$KRYOPTIC_MODULE" \
        --init-token --label "$TOKEN_LABEL" --so-pin "$TOKEN_SO_PIN" &&
    pkcs11-tool --module "$KRYOPTIC_MODULE" \
        --init-pin --token-label "$TOKEN_LABEL" --so-pin "$TOKEN_SO_PIN" \
        --pin "$TOKEN_USER_PIN"
}

PASS=0
FAIL=0
SKIP=0

ca_fingerprint() {
    # Plain lowercase hex SHA-256 of the CA certificate DER (matches the
    # broker's fingerprint format).
    openssl x509 -in "$1" -outform DER 2>/dev/null \
        | openssl dgst -sha256 2>/dev/null | awk '{print $NF}'
}

# run_scenario NAME TITLE EXPECTED MODE [SEED_BOGUS] [KEY_TYPE] [ANSWER] [TOKEN]
#   EXPECTED   success | failure
#   MODE       approve | deny | interactive
#              approve/deny: --auto value for the broker (non-interactive).
#              interactive: broker runs with --ui tty instead, and kinit is
#              given a real pty (via pty_kinit.py) so the client-tty
#              prompter can find and use it; ANSWER is typed into it.
#   SEED_BOGUS "seed" to pre-pin a bogus CA for the realm (MITM)
#   KEY_TYPE   certificate algorithm for setup.py (default: ec:P-256; see
#              SUPPORTED_KEY_TYPES in setup.py for the full list, including
#              mldsa44/mldsa65/mldsa87 for a post-quantum CA/KDC/client chain)
#   ANSWER     line to type at the broker's tty prompt when MODE is
#              interactive (e.g. "3" for the "1 day" grant preset); ignored
#              otherwise
#   TOKEN      the PKCS#11 URI of a provisioned token, given to setup.py as
#              --client-token with --client-token-generate: the client's key
#              is generated inside the token by KEY_TYPE and the certificate
#              issued by this run's CA and imported onto it. The client's
#              PKCS#11 traffic is then wrapped in the pkcs11-spy, and the
#              resulting call sequence is attached to the report.
run_scenario() {
    local name="$1" title="$2" expected="$3" mode="$4" seed="${5:-}" \
          key_type="${6:-ec:P-256}" answer="${7:-}" token_uri="${8:-}"
    local dir="$REPORTDIR/$name"
    mkdir -p "$dir"

    local sock="$WORK/$name.sock"
    local state="$WORK/$name.state.json"
    local broker_log="$dir/broker.log"
    local testdir="$WORK/$name-kdc"
    local env_file="$testdir/env.sh"

    echo
    echo "=== Scenario: $name ($title) ==="

    if [[ "$seed" == "seed" ]]; then
        # Pre-seed a pin with a fingerprint that cannot match any real CA.
        local zeros="0000000000000000000000000000000000000000000000000000000000000000"
        printf '{"%s":{"ca_b64":"Ym9ndXM=","fingerprint":"%s"}}\n' \
            "$REALM" "$zeros" > "$state"
    fi

    # Start the broker daemon. Interactive mode forces the client-tty
    # prompter (rather than --auto) so the scenario actually exercises a
    # human answering the prompt, not a pre-baked decision.
    local broker_args=(--state "$state")
    if [[ "$mode" == "interactive" ]]; then
        broker_args+=(--ui tty)
    else
        broker_args+=(--auto "$mode")
    fi
    "$BROKERD" "$sock" "${broker_args[@]}" >"$broker_log" 2>&1 &
    local broker_pid=$!
    for _ in $(seq 1 40); do
        [[ -S "$sock" ]] && break
        kill -0 "$broker_pid" 2>/dev/null || break
        sleep 0.1
    done

    # Start the ephemeral KDC with a TOFU client configuration.
    local token_args=()
    local spy_log=""
    if [[ -n "$token_uri" ]]; then
        spy_log="$dir/pkcs11-spy.log"
        token_args=(
            --client-token "$token_uri" --client-token-generate
            --pkcs11-module "$KRYOPTIC_MODULE"
            --pkcs11-spy "$spy_log"
        )
    fi
    python3 "$SCRIPT_DIR/setup.py" \
        --testdir "$testdir" \
        --realm "$REALM" \
        --principal "$PRINCIPAL" \
        --plugin-so "$PLUGIN_SO" \
        --tofu-broker "$sock" \
        --key-type "$key_type" \
        "${token_args[@]}" \
        --env-file "$env_file" &
    local setup_pid=$!
    local ready=false
    for _ in $(seq 1 60); do
        [[ -f "$env_file" ]] && { ready=true; break; }
        kill -0 "$setup_pid" 2>/dev/null || break
        sleep 0.5
    done

    local outcome="failure"
    if [[ "$ready" == true ]]; then
        # shellcheck disable=SC1090
        source "$env_file"
        # File mode passes the identity on the command line; token mode has
        # it configured as pkinit_identities = PKCS11:<URI> in krb5.conf and
        # OPENSSL_CONF/PKCS11SPY* exported by the env file, so a plain
        # kinit already uses the token.
        local identity_args=()
        if [[ -z "$token_uri" ]]; then
            identity_args=(-X "X509_user_identity=FILE:${PKINIT_CLIENT_CERT},${PKINIT_CLIENT_KEY}")
        fi
        if [[ "$mode" == "interactive" ]]; then
            # Give kinit a real pty so the broker's client-tty prompter has
            # something to find via SO_PEERCRED + /proc/<pid>/fd/*, and
            # "type" the answer into it -- plain </dev/null redirection (the
            # non-interactive branch below) can't reach that code path at all.
            if KRB5_CONFIG="$KRB5_CONFIG" KRB5CCNAME="$KRB5CCNAME" \
               python3 "$SCRIPT_DIR/pty_kinit.py" \
                       --answer "$answer" --transcript "$dir/client-tty.log" \
                       -- kinit "${identity_args[@]}" \
                               "${PKINIT_PRINCIPAL}@${PKINIT_REALM}" \
               >"$dir/kinit.out" 2>&1; then
                outcome="success"
            fi
        elif KRB5_CONFIG="$KRB5_CONFIG" KRB5CCNAME="$KRB5CCNAME" \
           kinit "${identity_args[@]}" \
                 "${PKINIT_PRINCIPAL}@${PKINIT_REALM}" </dev/null >"$dir/kinit.out" 2>&1; then
            outcome="success"
        fi
        cp -f "${KRB5_TRACE:-/dev/null}" "$dir/client-trace.log" 2>/dev/null || true
        cp -f "$testdir/kdc-trace.log" "$dir/kdc-trace.log" 2>/dev/null || true
        # The PKCS#11 API call sequence the plugin made, from the spy log:
        # the crypto-auditing feed for the token-backed flow.
        if [[ -n "$spy_log" ]]; then
            python3 "$SCRIPT_DIR/pkcs11_sequence.py" "$spy_log" \
                > "$dir/pkcs11_sequence.txt" 2>&1 || true
        fi
        local fp
        fp="$(ca_fingerprint "${PKINIT_CA_CERT:-}")"
        printf 'ca_fingerprint=%s\n' "$fp" >> "$dir/meta.env"
    else
        echo "  FATAL: KDC setup did not become ready" >&2
        cat "$testdir/kdc.log" 2>/dev/null || true
    fi

    # Broker decision (last one logged for this run), for the report.
    local decision
    decision="$(grep -oE 'decision=[A-Za-z]+' "$broker_log" 2>/dev/null | tail -1 | cut -d= -f2)"
    [[ -n "$decision" ]] || decision="(unknown)"

    # Teardown.
    [[ -n "${setup_pid:-}" ]] && { kill "$setup_pid" 2>/dev/null || true; wait "$setup_pid" 2>/dev/null || true; }
    [[ -n "${broker_pid:-}" ]] && { kill "$broker_pid" 2>/dev/null || true; wait "$broker_pid" 2>/dev/null || true; }

    # Record scenario metadata + timeline.
    {
        printf 'name=%s\n' "$name"
        printf 'title=%s\n' "$title"
        printf 'expected=%s\n' "$expected"
        printf 'outcome=%s\n' "$outcome"
        printf 'broker_mode=%s\n' "${seed:+seeded }$mode"
        printf 'broker_decision=%s\n' "$decision"
    } >> "$dir/meta.env"

    write_steps "$name" > "$dir/steps.txt"

    local status
    if [[ "$outcome" == "$expected" ]]; then
        status="PASS"; PASS=$((PASS + 1))
    else
        status="FAIL"; FAIL=$((FAIL + 1))
    fi
    echo "  -> expected=$expected outcome=$outcome decision=$decision [$status]"
}

write_steps() {
    case "$1" in
        happy-path)
            cat <<'EOF'
Client sends anonymous AS-REQ (WELLKNOWN/ANONYMOUS) for FAST armor
KDC replies with AS-REP carrying its certificate and issuing CA
Client has no configured KDC-CA anchor; consults the broker (interactive)
Broker approves and returns the CA; client pins and validates the chain
Client sends the authenticated AS-REQ with its user certificate
KDC reply validates against the just-pinned CA; kinit succeeds
EOF
            ;;
        denial)
            cat <<'EOF'
Client sends anonymous AS-REQ for FAST armor
KDC replies with its certificate and issuing CA
Client consults the broker for the unknown realm (interactive)
Broker denies; no CA is trusted
Trust cannot be established; kinit fails closed
EOF
            ;;
        mitm)
            cat <<'EOF'
Broker already has a pin for the realm (a different CA)
Client sends anonymous AS-REQ for FAST armor
KDC replies with its certificate and issuing CA
Client consults the broker; presented CA does not match the pin
Broker denies (CA changed for a known realm); kinit fails closed
EOF
            ;;
        pq-happy-path)
            cat <<'EOF'
Client sends anonymous AS-REQ (WELLKNOWN/ANONYMOUS) for FAST armor
KDC replies with its ML-DSA-65-signed certificate and issuing CA
Client has no configured KDC-CA anchor; consults the broker (interactive)
Broker approves and returns the post-quantum CA; client pins and validates
the chain without assuming an ECDSA/RSA anchor
Client sends the authenticated AS-REQ with its ML-DSA-65 client certificate
KDC reply validates against the just-pinned post-quantum CA; kinit succeeds
EOF
            ;;
        pq-tty-1day)
            cat <<'EOF'
Client sends anonymous AS-REQ (WELLKNOWN/ANONYMOUS) for FAST armor
KDC replies with its ML-DSA-65-signed certificate and issuing CA
Client has no configured KDC-CA anchor; consults the broker (interactive)
Broker runs with --ui tty: it resolves kinit's own pid via SO_PEERCRED and
prompts directly on kinit's controlling terminal, not the broker's own
User answers "3" (1 day) at the prompt; broker pins the CA with that grant
Client sends the authenticated AS-REQ with its ML-DSA-65 client certificate
KDC reply validates against the newly-pinned post-quantum CA; kinit succeeds
EOF
            ;;
        pq-token-flow)
            cat <<'EOF'
KDC setup generates the client's ML-DSA-65 key inside the kryoptic token
(openssl genpkey through the pkcs11 provider), issues a client certificate
for it with this run's CA, and imports it onto the token
Client sends anonymous AS-REQ (WELLKNOWN/ANONYMOUS) for FAST armor
KDC replies with its ML-DSA-65-signed certificate and issuing CA
Client consults the broker; broker approves and pins the post-quantum CA
Client sends the authenticated AS-REQ; the plugin loads the identity from
the token (C_Login, C_FindObjects/C_GetAttributeValue) and the authPack is
signed by C_SignInit/C_Sign with CKM_ML_DSA, inside the token
KDC reply validates against the pinned CA; kinit succeeds
The PKCS#11 API sequence block is the plugin's exact Cryptoki call order,
captured by the OpenSC pkcs11-spy (crypto-auditing feed)
EOF
            ;;
        *) echo "(no timeline)";;
    esac
}

# -- Run scenarios --

run_scenario happy-path    "Trust on first use (happy path)"                     success approve
run_scenario denial        "Broker denies (fail closed)"                         failure deny
run_scenario mitm          "Changed CA detected (MITM)"                          failure approve seed
run_scenario pq-happy-path "Trust on first use with a post-quantum CA (ML-DSA-65)" success approve "" mldsa65
run_scenario pq-tty-1day   "Post-quantum CA, confirmed on the client's tty (1 day)" success interactive "" mldsa65 3

if token_flow_supported && provision_kryoptic_token >/dev/null 2>&1; then
    run_scenario pq-token-flow "Post-quantum client identity on a kryoptic token (ML-DSA-65, PKCS#11 audit)" \
        success approve "" mldsa65 "" "$TOKEN_URI"
else
    # Not a failure: the runner simply lacks the PKCS#11 stack (kryoptic,
    # pkcs11-provider, opensc's spy + pkcs11-tool). Recorded as a skipped
    # scenario so it shows up in the report instead of silently missing.
    SKIP=$((SKIP + 1))
    local_dir="$REPORTDIR/pq-token-flow"
    mkdir -p "$local_dir"
    {
        printf 'name=%s\n' pq-token-flow
        printf 'title=%s\n' "Post-quantum client identity on a kryoptic token (ML-DSA-65, PKCS#11 audit)"
        printf 'expected=%s\n' skipped
        printf 'outcome=%s\n' skipped
        printf 'broker_mode=%s\n' n/a
        printf 'broker_decision=%s\n' "(not run)"
    } > "$local_dir/meta.env"
    echo "PKCS#11 token stack unavailable (kryoptic / pkcs11-provider / opensc)" \
        > "$local_dir/steps.txt"
    echo
    echo "=== Scenario: pq-token-flow -- SKIPPED (PKCS#11 token stack unavailable) ==="
fi

# -- Render the report --

MANIFEST="$WORK/manifest.json"
python3 "$SCRIPT_DIR/tofu_manifest.py" "$REPORTDIR" "$REALM" "$MANIFEST"
python3 "$SCRIPT_DIR/tofu_report.py" "$MANIFEST" "$REPORT_HTML"

# Also render straight into the GitHub Actions job summary, when running as
# a workflow step (GITHUB_STEP_SUMMARY is unset locally): the uploaded HTML
# artifact is always zipped, so seeing it means downloading and unpacking --
# this puts the same content right on the run's Summary tab instead.
if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
    python3 "$SCRIPT_DIR/tofu_summary.py" "$MANIFEST" >> "$GITHUB_STEP_SUMMARY"
fi

echo
echo "TOFU report: $REPORT_HTML"
if [[ "$SKIP" -gt 0 ]]; then
    echo "Scenarios: $PASS passed, $FAIL failed, $SKIP skipped"
else
    echo "Scenarios: $PASS passed, $FAIL failed"
fi
[[ "$FAIL" -eq 0 ]]
