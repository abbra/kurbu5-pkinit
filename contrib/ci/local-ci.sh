#!/usr/bin/env bash
# local-ci.sh — run the CI pipeline locally, mirroring .github/workflows/ci.yml
#
# Usage:
#   ./contrib/ci/local-ci.sh all                 # run all jobs
#   ./contrib/ci/local-ci.sh build fmt clippy    # run specific jobs
#   ./contrib/ci/local-ci.sh --list              # print available job names
#   ./contrib/ci/local-ci.sh --no-color all      # disable ANSI colours
#   ./contrib/ci/local-ci.sh --valgrind test     # run tests under Valgrind
#   CARGO_TARGET_DIR=/tmp/kurbu5-pkinit-target ./contrib/ci/local-ci.sh all

# Require bash 4+
if [ "${BASH_VERSINFO:-0}" -lt 4 ]; then
    echo "error: bash 4 or later is required (you have ${BASH_VERSION:-unknown})" >&2
    exit 1
fi

set -euo pipefail

# ── Colour helpers ──────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# NO_COLOR env var baseline (flags may override below).
if [[ "${NO_COLOR:-}" == "1" ]]; then
    RED=''; GREEN=''; YELLOW=''; BLUE=''; CYAN=''; BOLD=''; NC=''
fi

# ── Flag parsing ─────────────────────────────────────────────────────────────
VALGRIND=0
NO_DEPS=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-color)
            RED=''; GREEN=''; YELLOW=''; BLUE=''; CYAN=''; BOLD=''; NC=''
            shift ;;
        --valgrind)
            VALGRIND=1
            shift ;;
        --no-deps)
            NO_DEPS=1
            shift ;;
        *) break ;;
    esac
done

# ── Locate repo root ────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

if [[ ! -f "$REPO_ROOT/Cargo.toml" ]]; then
    echo "error: must be run from the repository root (Cargo.toml not found)" >&2
    exit 1
fi

cd "$REPO_ROOT"

# ── Optional isolated target directory ──────────────────────────────────────
if [[ -n "${CARGO_TARGET_DIR:-}" ]]; then
    export CARGO_TARGET_DIR
    echo -e "${CYAN}Using CARGO_TARGET_DIR=${CARGO_TARGET_DIR}${NC}"
fi

export CARGO_TERM_COLOR=always
export RUSTDOCFLAGS="-D warnings"

# ── Tool detection ───────────────────────────────────────────────────────────

has_cargo=0
has_rustfmt=0
has_clippy=0
has_valgrind=0
has_actionlint=0
has_yamllint=0
has_krb5kdc=0
has_openssl=0
has_python3=0

detect_tools() {
    echo -e "${BOLD}${CYAN}Tool availability check:${NC}"

    # Core Rust toolchain
    if command -v cargo >/dev/null 2>&1; then
        has_cargo=1
        echo -e "  ${GREEN}✓${NC} cargo $(cargo --version | cut -d' ' -f2)"
    else
        echo -e "  ${YELLOW}○${NC} cargo (install from https://rustup.rs/)"
    fi

    if cargo fmt --version >/dev/null 2>&1; then
        has_rustfmt=1
        echo -e "  ${GREEN}✓${NC} rustfmt $(cargo fmt --version | cut -d' ' -f2)"
    else
        echo -e "  ${YELLOW}○${NC} rustfmt (install with: rustup component add rustfmt)"
    fi

    if cargo clippy --version >/dev/null 2>&1; then
        has_clippy=1
        echo -e "  ${GREEN}✓${NC} clippy $(cargo clippy --version | cut -d' ' -f2)"
    else
        echo -e "  ${YELLOW}○${NC} clippy (install with: rustup component add clippy)"
    fi

    if command -v valgrind >/dev/null 2>&1; then
        has_valgrind=1
        echo -e "  ${GREEN}✓${NC} valgrind $(valgrind --version | cut -d' ' -f2)"
    else
        echo -e "  ${YELLOW}○${NC} valgrind (optional, needed for --valgrind flag)"
    fi

    if command -v actionlint >/dev/null 2>&1; then
        has_actionlint=1
        echo -e "  ${GREEN}✓${NC} actionlint $(actionlint --version | cut -d' ' -f3)"
    else
        echo -e "  ${YELLOW}○${NC} actionlint (optional, for workflow validation)"
    fi

    if command -v yamllint >/dev/null 2>&1; then
        has_yamllint=1
    fi

    # System-test prerequisites (real KDC + kinit + PKI tooling)
    if command -v krb5kdc >/dev/null 2>&1; then
        has_krb5kdc=1
        echo -e "  ${GREEN}✓${NC} krb5kdc (system-test)"
    else
        echo -e "  ${YELLOW}○${NC} krb5kdc (optional, needed for the system-test job; install krb5-server + krb5-workstation)"
    fi

    if command -v openssl >/dev/null 2>&1; then
        has_openssl=1
        echo -e "  ${GREEN}✓${NC} openssl (system-test)"
    else
        echo -e "  ${YELLOW}○${NC} openssl (optional, needed for the system-test job)"
    fi

    if command -v python3 >/dev/null 2>&1; then
        has_python3=1
        echo -e "  ${GREEN}✓${NC} python3 $(python3 --version | cut -d' ' -f2)"
    else
        echo -e "  ${YELLOW}○${NC} python3 (optional, needed for the system-test job)"
    fi

    echo ""
}

# Run tool detection unless --list or --help
if [[ "${1:-}" != "--list" && "${1:-}" != "--help" && "${1:-}" != "-h" && $# -gt 0 ]]; then
    detect_tools
fi

# ── Valgrind setup ───────────────────────────────────────────────────────────
if [[ "$VALGRIND" == "1" ]]; then
    if [[ $has_valgrind -eq 0 ]]; then
        echo "error: --valgrind requested but valgrind is not installed" >&2
        exit 1
    fi
    # Configure Cargo to run test binaries through Valgrind for the host target.
    # CARGO_TARGET_<TRIPLE>_RUNNER is the standard mechanism; Cargo passes each
    # test binary to the runner instead of executing it directly.
    _VALGRIND_OPTS="--error-exitcode=1 --leak-check=full --show-leak-kinds=all --suppressions=$SCRIPT_DIR/rust-valgrind.supp"
    _TARGET_TRIPLE=$(rustc --print host-tuple)
    _TARGET_RUNNER_VAR="CARGO_TARGET_$(printf '%s' "$_TARGET_TRIPLE" | tr '[:lower:]-' '[:upper:]_')_RUNNER"
    export "${_TARGET_RUNNER_VAR}=valgrind ${_VALGRIND_OPTS}"
    echo -e "${CYAN}Valgrind enabled (${_TARGET_TRIPLE}) — Rust test binaries will run under valgrind${NC}"
    unset _VALGRIND_OPTS _TARGET_TRIPLE _TARGET_RUNNER_VAR
fi

# ── Job tracking ────────────────────────────────────────────────────────────
declare -A JOB_STATUS=()
declare -A JOB_SECS=()
FAILED_JOBS=()

ALL_JOBS=(build fmt lint-workflows clippy doc test system-test tofu-test)

# Job dependencies — mirrors the 'needs:' fields in .github/workflows/ci.yml.
# Value is a space-separated list of prerequisite job names.
# Jobs absent from the map have no dependencies.
declare -A JOB_DEPS=(
    [clippy]="build"
    [doc]="build"
    [test]="build"
    [system-test]="build"
    [tofu-test]="build"
)

# ── Utilities ───────────────────────────────────────────────────────────────
step() { echo -e "\n${BOLD}${BLUE}▶ $*${NC}"; }
ok()   { echo -e "${GREEN}✔  $*${NC}"; }
fail() { echo -e "${RED}✘  $*${NC}"; }
warn() { echo -e "${YELLOW}!  $*${NC}"; }

run_job() {
    local name="$1"
    shift

    # Ensure all prerequisites have been executed, running them on demand if
    # they haven't been dispatched yet; then skip this job if any dep failed.
    # Skipped entirely when --no-deps is set (e.g. inside GitHub Actions, where
    # the workflow already enforces the dependency ordering via 'needs:').
    if [[ "$NO_DEPS" == "0" ]]; then
        local dep
        for dep in ${JOB_DEPS[$name]:-}; do
            if [[ -z "${JOB_STATUS[$dep]:-}" ]]; then
                dispatch_job "$dep"
            fi
            if [[ "${JOB_STATUS[$dep]}" != "PASS" ]]; then
                JOB_STATUS[$name]="SKIP"
                warn "[$name] skipped — '$dep' did not pass"
                return 0
            fi
        done
    fi

    local t0; t0=$(date +%s)
    step "[$name]"
    local _rc=0
    "$@" || _rc=$?
    local t1; t1=$(date +%s)
    JOB_SECS[$name]=$((t1 - t0))
    if [[ $_rc -eq 0 ]]; then
        JOB_STATUS[$name]="PASS"
        ok "[$name] passed (${JOB_SECS[$name]}s)"
    else
        JOB_STATUS[$name]="FAIL"
        FAILED_JOBS+=("$name")
        fail "[$name] FAILED (${JOB_SECS[$name]}s)"
    fi
}

# ── Individual job implementations ──────────────────────────────────────────

require_cargo() {
    if [[ $has_cargo -eq 0 ]]; then
        fail "cargo is required but not found (install from https://rustup.rs/)"
        return 1
    fi
}

job_build() {
    require_cargo || return 1

    echo "Building workspace (debug)…"
    cargo build --workspace
}

job_fmt() {
    require_cargo || return 1
    if [[ $has_rustfmt -eq 0 ]]; then
        fail "rustfmt is required (install with: rustup component add rustfmt)"
        return 1
    fi

    echo "Checking formatting…"
    cargo fmt --all -- --check
}

job_lint_workflows() {
    echo "Validating GitHub Actions workflow files…"

    local workflows=()
    while IFS= read -r -d '' f; do
        workflows+=("$f")
    done < <(find .github/workflows -name '*.yml' -print0 2>/dev/null)

    if [[ ${#workflows[@]} -eq 0 ]]; then
        warn "No workflow files found in .github/workflows/"
        return 0
    fi

    echo "Found ${#workflows[@]} workflow file(s)"

    # Prefer actionlint — validates GitHub Actions expression syntax,
    # runner labels, action inputs, step references, etc.
    if [[ $has_actionlint -eq 1 ]]; then
        echo "Using actionlint…"
        actionlint "${workflows[@]}"
        return
    fi

    warn "actionlint not found — falling back to yamllint (install from: https://github.com/rhysd/actionlint)"

    # Fall back to yamllint for structural / style validation.
    # Disable 'truthy' (GitHub Actions uses bare 'on:' keys) and relax
    # line-length to accommodate ci.yml step definitions.
    if [[ $has_yamllint -eq 1 ]]; then
        yamllint \
            -d "{extends: default, rules: {truthy: disable, line-length: {max: 120}}}" \
            "${workflows[@]}"
    else
        warn "yamllint not found — skipping workflow validation"
        warn "Install actionlint: https://github.com/rhysd/actionlint"
        warn "Install yamllint:   pip install yamllint"
        return 0
    fi
}

job_clippy() {
    require_cargo || return 1
    if [[ $has_clippy -eq 0 ]]; then
        fail "clippy is required (install with: rustup component add clippy)"
        return 1
    fi

    echo "Running Clippy…"
    cargo clippy --workspace --all-features -- -D warnings
}

job_doc() {
    require_cargo || return 1

    echo "Building documentation…"
    cargo doc --workspace --no-deps --all-features
}

job_test() {
    require_cargo || return 1

    echo "Running test suite…"
    cargo test --workspace --all-features
}

job_system_test() {
    require_cargo || return 1
    if [[ $has_krb5kdc -eq 0 || $has_openssl -eq 0 || $has_python3 -eq 0 ]]; then
        fail "system-test requires krb5kdc, openssl, and python3 (install krb5-server, krb5-workstation, openssl, python3)"
        return 1
    fi

    echo "Running PKINIT system integration tests…"
    bash tests/system/pkinit/run.sh
}

job_tofu_test() {
    require_cargo || return 1
    if [[ $has_krb5kdc -eq 0 || $has_openssl -eq 0 || $has_python3 -eq 0 ]]; then
        fail "tofu-test requires krb5kdc, openssl, and python3 (install krb5-server, krb5-workstation, openssl, python3)"
        return 1
    fi

    echo "Running PKINIT KDC-CA trust-on-first-use test (with HTML report)…"
    bash tests/system/pkinit/tofu.sh
}

print_interactive_help() {
    cat <<EOF
Usage: $(basename "$0") interactive [OPTIONS]

Start an ephemeral Kerberos realm and KDC preconfigured for kurbu5-pkinit
(plus, unless --no-tofu, the reference trust-broker daemon), then drop you
into a shell inside it: run kinit/klist, inspect the generated certificates,
watch a trust prompt arrive on your own terminal or as a desktop
notification -- whatever you like. Exiting the shell (exit, Ctrl-D) tears
everything down: KDC, broker, socket, temp files.

--key-type and --pqc-min-algorithm are independent: one is about the
certificates, the other about the key exchange. Setting one does not imply
or affect the other -- pass --pqc-min-algorithm too if you want a fully
post-quantum exchange, not just a post-quantum CA.

Options:
  --key-type TYPE          Certificate algorithm for the CA/KDC/client
                            certs (default: ec:P-256) -- what signs them,
                            unrelated to the key exchange used to get a
                            ticket. See SUPPORTED_KEY_TYPES in
                            tests/system/pkinit/setup.py: ec:P-256,
                            ec:P-384, ec:P-521, rsa:2048, rsa:3072,
                            rsa:4096, mldsa44, mldsa65, mldsa87.
  --pqc-min-algorithm ALG  Minimum ML-KEM strength to require, switching
                            the key exchange itself to the KEM path
                            instead of classical DH/ECDH (default: unset,
                            i.e. DH/ECDH regardless of --key-type). E.g.
                            ML-KEM-768, ML-KEM-1024, ML-KEM-768-X25519.
  --realm REALM             Kerberos realm name (default: PKINIT.TEST)
  --principal NAME          Client principal name (default: user)
  --no-tofu                 Skip the trust broker; give the client a static
                            pkinit_anchors instead of trust-on-first-use
  --ui MODE                 pkinit-trust-brokerd's --ui, when not --no-tofu
                            (default: auto; auto|gui|tty -- see the module
                            docs at the top of pkinit-trust-brokerd/src/main.rs)

Examples:
  $(basename "$0") interactive
  $(basename "$0") interactive --key-type mldsa65
                                    # post-quantum CA/KDC/client certs;
                                    # key exchange is still classical DH
  $(basename "$0") interactive --key-type mldsa65 --pqc-min-algorithm ML-KEM-768
                                    # ... and a post-quantum key exchange too
  $(basename "$0") interactive --no-tofu --key-type rsa:2048
  $(basename "$0") interactive --ui tty
EOF
}

run_interactive_playground() {
    require_cargo || return 1
    if [[ $has_krb5kdc -eq 0 || $has_openssl -eq 0 || $has_python3 -eq 0 ]]; then
        fail "interactive requires krb5kdc, openssl, and python3 (install krb5-server, krb5-workstation, openssl, python3)"
        return 1
    fi

    local key_type="ec:P-256" pqc_min="" realm="PKINIT.TEST" principal="user" \
          tofu=1 ui="auto"
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --key-type) key_type="$2"; shift 2 ;;
            --pqc-min-algorithm) pqc_min="$2"; shift 2 ;;
            --realm) realm="$2"; shift 2 ;;
            --principal) principal="$2"; shift 2 ;;
            --no-tofu) tofu=0; shift ;;
            --ui) ui="$2"; shift 2 ;;
            --help|-h) print_interactive_help; return 0 ;;
            *) echo "interactive: unknown option: $1" >&2; print_interactive_help; return 2 ;;
        esac
    done

    step "[interactive] building plugin + broker daemon + ctl (release)"
    cargo build --release --manifest-path "$REPO_ROOT/Cargo.toml" \
        -p kurbu5-pkinit -p pkinit-trust-brokerd -p pkinit-trust-ctl

    local plugin_so="$REPO_ROOT/target/release/libkurbu5_pkinit.so"
    local brokerd="$REPO_ROOT/target/release/pkinit-trust-brokerd"
    local ctl="$REPO_ROOT/target/release/pkinit-trust-ctl"
    [[ -f "$plugin_so" ]] || { fail "$plugin_so not built"; return 1; }
    [[ -x "$brokerd" ]]  || { fail "$brokerd not built"; return 1; }

    # Cleanup is called explicitly at every exit point below (rather than
    # relying solely on a trap surviving to script exit): this function's
    # `local`s would already be gone by the time a plain EXIT trap fires at
    # the outer script's own exit, and referencing them then would be a
    # hard error under `set -u`. INT/TERM are still trapped, since a signal
    # delivered while this function is running (e.g. during KDC startup)
    # fires while its locals are very much still in scope.
    local work="" setup_pid="" broker_pid="" cleaned=0
    playground_cleanup() {
        [[ "$cleaned" == 1 ]] && return
        cleaned=1
        echo
        echo "Tearing down playground…"
        [[ -n "$setup_pid" ]] && { kill "$setup_pid" 2>/dev/null || true; wait "$setup_pid" 2>/dev/null || true; }
        [[ -n "$broker_pid" ]] && { kill "$broker_pid" 2>/dev/null || true; wait "$broker_pid" 2>/dev/null || true; }
        [[ -n "$work" ]] && rm -rf "$work"
    }
    trap playground_cleanup INT TERM

    work="$(mktemp -d /tmp/pkinit-playground.XXXXXXXXXX)"
    local testdir="$work/kdc"
    local env_file="$testdir/env.sh"
    local sock="$work/trust.sock"
    local state="$work/trust.state.json"

    local setup_args=(
        --testdir "$testdir" --realm "$realm" --principal "$principal"
        --plugin-so "$plugin_so" --key-type "$key_type" --env-file "$env_file"
    )
    [[ -n "$pqc_min" ]] && setup_args+=(--pqc-min-algorithm "$pqc_min")

    if [[ "$tofu" == 1 ]]; then
        # setsid: without this, the broker shares this script's process
        # group, which stops being the terminal's foreground group the
        # moment the interactive shell below claims it for a foreground
        # command (kinit) -- the broker's read from that command's tty then
        # either blocks the whole job until `fg` (in a real login session)
        # or fails outright with EIO (in an already-orphaned one). A new
        # session sidesteps that job-control interaction entirely, matching
        # how the broker runs for real (systemd, its own session).
        #
        # setsid forks rather than exec'ing in place here, so $! is its own
        # (short-lived) pid, not the broker's -- broker_pid is looked up
        # below, once the broker is confirmed listening, via the socket
        # path on its command line (unique to this invocation).
        setsid "$brokerd" "$sock" --ui "$ui" --state "$state" &
        for _ in $(seq 1 40); do
            [[ -S "$sock" ]] && break
            sleep 0.1
        done
        if [[ ! -S "$sock" ]]; then
            playground_cleanup
            fail "pkinit-trust-brokerd did not start listening in time"
            return 1
        fi
        broker_pid="$(pgrep -f "$sock" | head -1)"
        if [[ -z "$broker_pid" ]]; then
            playground_cleanup
            fail "pkinit-trust-brokerd is listening but its process could not be found"
            return 1
        fi
        setup_args+=(--tofu-broker "$sock")
    fi

    python3 "$REPO_ROOT/tests/system/pkinit/setup.py" "${setup_args[@]}" &
    setup_pid=$!
    local ready=false
    for _ in $(seq 1 60); do
        [[ -f "$env_file" ]] && { ready=true; break; }
        kill -0 "$setup_pid" 2>/dev/null || break
        sleep 0.5
    done
    if [[ "$ready" != true ]]; then
        cat "$testdir/kdc.log" 2>/dev/null || true
        playground_cleanup
        fail "KDC did not become ready; see the log above"
        return 1
    fi

    # shellcheck disable=SC1090
    source "$env_file"

    echo
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}kurbu5-pkinit playground ready${NC}"
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo "  realm:          $realm"
    echo "  principal:      $principal@$realm"
    echo "  cert algorithm: $key_type (CA/KDC/client cert signing -- independent of key exchange below)"
    if [[ -n "$pqc_min" ]]; then
        echo "  key exchange:   $pqc_min (post-quantum)"
    else
        echo "  key exchange:   DH/ECDH (classical -- pass --pqc-min-algorithm for ML-KEM instead)"
    fi
    if [[ "$tofu" == 1 ]]; then
        echo "  trust:          TOFU via broker at $sock (--ui $ui)"
    else
        echo "  trust:          static pkinit_anchors (no broker)"
    fi
    echo
    echo "  Try:"
    echo "    kinit -X X509_user_identity=FILE:\$PKINIT_CLIENT_CERT,\$PKINIT_CLIENT_KEY $principal@$realm"
    echo "    klist"
    [[ "$tofu" == 1 && -x "$ctl" ]] && echo "    $ctl --socket $sock list"
    echo
    echo "  Exit this shell (exit or Ctrl-D) to tear the playground down."
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo

    PS1="[pkinit-playground] \W \$ " "${SHELL:-bash}" -i || true

    playground_cleanup
    trap - INT TERM
}

# ── Dispatch table ───────────────────────────────────────────────────────────
dispatch_job() {
    case "$1" in
        build)          run_job build          job_build ;;
        fmt)            run_job fmt            job_fmt ;;
        lint-workflows) run_job lint-workflows job_lint_workflows ;;
        clippy)         run_job clippy         job_clippy ;;
        doc)            run_job doc            job_doc ;;
        test)           run_job test           job_test ;;
        system-test)    run_job system-test    job_system_test ;;
        tofu-test)      run_job tofu-test      job_tofu_test ;;
        *)
            echo "Unknown job: $1" >&2
            echo "Run '$0 --list' for available jobs." >&2
            exit 1
            ;;
    esac
}

# ── Summary ──────────────────────────────────────────────────────────────────
print_summary() {
    local total_start="$1"
    local total_end; total_end=$(date +%s)

    echo
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}CI Summary${NC}"
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

    local display_jobs=("${ALL_JOBS[@]}")
    local all_jobs_str=" ${ALL_JOBS[*]} "
    local job
    for job in "${REQUESTED_JOBS[@]}"; do
        [[ "$all_jobs_str" == *" $job "* ]] || display_jobs+=("$job")
    done

    for job in "${display_jobs[@]}"; do
        local status="${JOB_STATUS[$job]:-}"
        [[ -z "$status" ]] && continue
        local secs="${JOB_SECS[$job]:-0}"
        if [[ "$status" == "PASS" ]]; then
            printf "  ${GREEN}%-20s PASS${NC}  (%ds)\n" "$job" "$secs"
        elif [[ "$status" == "FAIL" ]]; then
            printf "  ${RED}%-20s FAIL${NC}  (%ds)\n" "$job" "$secs"
        else
            printf "  ${YELLOW}%-20s SKIP${NC}  (dep failed)\n" "$job"
        fi
    done

    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "Total time: $((total_end - total_start))s"

    if [[ ${#FAILED_JOBS[@]} -gt 0 ]]; then
        echo -e "${RED}${BOLD}FAILED: ${FAILED_JOBS[*]}${NC}"
        return 1
    else
        echo -e "${GREEN}${BOLD}All jobs passed.${NC}"
        return 0
    fi
}

# ── Help ─────────────────────────────────────────────────────────────────────
print_help() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS] <job> [job ...]

Run CI jobs locally, mirroring .github/workflows/ci.yml.

Special targets:
  all          Run every job in order
  interactive  Start an ephemeral KDC (and, unless --no-tofu, the trust
               broker), then drop you into a shell to play with them;
               torn down when the shell exits. Run
               '$(basename "$0") interactive --help' for its own options.

Available jobs:
$(printf '  %s\n' "${ALL_JOBS[@]}")

Options:
  --list         Print available job names and exit
  --no-color     Disable ANSI colour output (also: NO_COLOR=1)
  --no-deps      Skip prerequisite checks and auto-runs.  Useful inside
                 GitHub Actions (or any other CI system) where the workflow
                 already enforces job ordering via 'needs:' so that running
                 a single job via local-ci.sh does not trigger its deps.
  --valgrind     Run Rust test binaries under Valgrind (test job).
                 Uses CARGO_TARGET_<TRIPLE>_RUNNER=valgrind with full leak
                 checking and the suppression file at contrib/ci/rust-valgrind.supp.
                 Valgrind must be installed; exits with an error otherwise.

Environment:
  CARGO_TARGET_DIR   Redirect Cargo build output to an isolated directory.

Examples:
  $(basename "$0") all
  $(basename "$0") build test
  $(basename "$0") --no-color all
  $(basename "$0") --valgrind test
  CARGO_TARGET_DIR=/tmp/kurbu5-pkinit-target $(basename "$0") all
EOF
}

# ── Entry point ──────────────────────────────────────────────────────────────
if [[ $# -eq 0 ]]; then
    print_help
    exit 0
fi

if [[ "${1:-}" == "--list" ]]; then
    printf '%s\n' all "${ALL_JOBS[@]}"
    exit 0
fi

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    print_help
    exit 0
fi

if [[ "${1:-}" == "interactive" ]]; then
    shift
    run_interactive_playground "$@"
    exit $?
fi

# Determine which jobs to run; 'all' expands to every job in order.
REQUESTED_JOBS=()
for arg in "$@"; do
    if [[ "$arg" == "all" ]]; then
        REQUESTED_JOBS+=("${ALL_JOBS[@]}")
    else
        REQUESTED_JOBS+=("$arg")
    fi
done

T0=$(date +%s)

for job in "${REQUESTED_JOBS[@]}"; do
    dispatch_job "$job"
done

print_summary "$T0"
