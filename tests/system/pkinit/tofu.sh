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
#
# Usage:
#   bash tofu.sh [--report FILE]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

REALM="${REALM:-PKINIT.TEST}"
PRINCIPAL="${PRINCIPAL:-user}"
PORTBASE="${KDC_PORTBASE:-63200}"
REPORT_HTML="${TOFU_REPORT:-$REPO_ROOT/pkinit-tofu-report.html}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --report) REPORT_HTML="$2"; shift 2 ;;
        --help|-h)
            sed -n '2,20p' "$0"; exit 0 ;;
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

PASS=0
FAIL=0

ca_fingerprint() {
    # Plain lowercase hex SHA-256 of the CA certificate DER (matches the
    # broker's fingerprint format).
    openssl x509 -in "$1" -outform DER 2>/dev/null \
        | openssl dgst -sha256 2>/dev/null | awk '{print $NF}'
}

# run_scenario NAME TITLE EXPECTED MODE [SEED_BOGUS] [KEY_TYPE] [ANSWER]
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
run_scenario() {
    local name="$1" title="$2" expected="$3" mode="$4" seed="${5:-}" \
          key_type="${6:-ec:P-256}" answer="${7:-}"
    local dir="$REPORTDIR/$name"
    mkdir -p "$dir"

    local sock="$WORK/$name.sock"
    local state="$WORK/$name.state.json"
    local broker_log="$dir/broker.log"
    local testdir="$WORK/$name-kdc"
    local env_file="$testdir/env.sh"
    local port=$((PORTBASE))
    PORTBASE=$((PORTBASE + 10))

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
    python3 "$SCRIPT_DIR/setup.py" \
        --testdir "$testdir" \
        --portbase "$port" \
        --realm "$REALM" \
        --principal "$PRINCIPAL" \
        --plugin-so "$PLUGIN_SO" \
        --tofu-broker "$sock" \
        --key-type "$key_type" \
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
        if [[ "$mode" == "interactive" ]]; then
            # Give kinit a real pty so the broker's client-tty prompter has
            # something to find via SO_PEERCRED + /proc/<pid>/fd/*, and
            # "type" the answer into it -- plain </dev/null redirection (the
            # non-interactive branch below) can't reach that code path at all.
            if KRB5_CONFIG="$KRB5_CONFIG" KRB5CCNAME="$KRB5CCNAME" \
               python3 "$SCRIPT_DIR/pty_kinit.py" \
                       --answer "$answer" --transcript "$dir/client-tty.log" \
                       -- kinit -X "X509_user_identity=FILE:${PKINIT_CLIENT_CERT},${PKINIT_CLIENT_KEY}" \
                                "${PKINIT_PRINCIPAL}@${PKINIT_REALM}" \
               >"$dir/kinit.out" 2>&1; then
                outcome="success"
            fi
        elif KRB5_CONFIG="$KRB5_CONFIG" KRB5CCNAME="$KRB5CCNAME" \
           kinit -X "X509_user_identity=FILE:${PKINIT_CLIENT_CERT},${PKINIT_CLIENT_KEY}" \
                 "${PKINIT_PRINCIPAL}@${PKINIT_REALM}" </dev/null >"$dir/kinit.out" 2>&1; then
            outcome="success"
        fi
        cp -f "${KRB5_TRACE:-/dev/null}" "$dir/client-trace.log" 2>/dev/null || true
        cp -f "$testdir/kdc-trace.log" "$dir/kdc-trace.log" 2>/dev/null || true
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
        *) echo "(no timeline)";;
    esac
}

# -- Run scenarios --

run_scenario happy-path    "Trust on first use (happy path)"                     success approve
run_scenario denial        "Broker denies (fail closed)"                         failure deny
run_scenario mitm          "Changed CA detected (MITM)"                          failure approve seed
run_scenario pq-happy-path "Trust on first use with a post-quantum CA (ML-DSA-65)" success approve "" mldsa65
run_scenario pq-tty-1day   "Post-quantum CA, confirmed on the client's tty (1 day)" success interactive "" mldsa65 3

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
echo "Scenarios: $PASS passed, $FAIL failed"
[[ "$FAIL" -eq 0 ]]
