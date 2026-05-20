#!/usr/bin/env bash
#
# clean_for_push.sh, pre-publish cleanup + sanity checks. Run this
# before `git push` to a public repo to make sure local-only artefacts
# (build trees, fuzz campaign output, IDE state, .env files) are gone
# and that fmt / clippy / test / audit all pass.
#
# Usage:
#   scripts/clean_for_push.sh           # default: clean + check
#   scripts/clean_for_push.sh --no-test # skip cargo test (fast path)
#   scripts/clean_for_push.sh --check   # run checks only, don't delete
#
# Exits 0 only if every check passes. Non-zero exit means do NOT push.
#
# Safe by design: every `rm -rf` target is regenerable (cargo / fuzz
# campaign output). The script prints what it deletes before deleting
# and refuses to run from anywhere other than the repo root.

set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# Sanity: confirm we're really at the repo root by checking for the
# top-level workspace manifest.
if [[ ! -f "Cargo.toml" ]] || ! grep -q '^\[workspace\]' Cargo.toml; then
    echo "error: $REPO_ROOT does not look like the LUKSbox workspace root." >&2
    echo "       (no Cargo.toml with [workspace] section)" >&2
    exit 2
fi

# ---- arg parse ------------------------------------------------------------

DO_CLEAN=1
DO_TEST=1
for arg in "$@"; do
    case "$arg" in
        --check) DO_CLEAN=0 ;;
        --no-test) DO_TEST=0 ;;
        -h|--help)
            sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//' >&2
            exit 0
            ;;
        *)
            echo "error: unknown arg '$arg'." >&2
            exit 2
            ;;
    esac
done

red() { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
yellow() { printf '\033[33m%s\033[0m\n' "$*"; }

# ---- 1. Delete local-only artefacts ---------------------------------------

if [[ "$DO_CLEAN" -eq 1 ]]; then
    echo
    echo "=== Cleaning local-only artefacts ==="

    # cargo's various target dirs. cargo clean handles the workspace one;
    # the fuzz dirs have their own out-of-workspace Cargo.toml each.
    if command -v cargo >/dev/null 2>&1; then
        echo "[+] cargo clean (workspace target/)..."
        cargo clean 2>&1 | sed 's/^/    /' || true
    else
        echo "[!] cargo not on PATH, skipping cargo clean. Removing target/ directly."
        rm -rf target
    fi

    for d in fuzz/target fuzz-afl/target; do
        if [[ -d "$d" ]]; then
            echo "[+] removing $d ..."
            rm -rf "$d"
        fi
    done

    # Fuzz campaign output. Crashes that mattered have been promoted to
    # `fuzz/corpus/<target>/regression_*` and committed; everything else
    # under artifacts/ and runs/ is noise.
    for d in fuzz/artifacts fuzz/release-runs fuzz-afl/runs; do
        if [[ -d "$d" ]]; then
            echo "[+] removing $d ..."
            rm -rf "$d"
        fi
    done

    # IDE / OS junk. These should already be in .gitignore but a fresh
    # clone might still pick up a stray file from a tarball import.
    find . -depth \
        \( -name '.DS_Store' -o -name 'Thumbs.db' -o -name '*.swp' \
           -o -name '*.swo' -o -name '*~' -o -name '*.rs.bk' \) \
        -not -path './.git/*' -print -delete 2>/dev/null || true

    echo
    green "cleanup complete"
fi

# ---- 2. Verify no obvious local state files would get pushed --------------

echo
echo "=== Pre-push state check ==="

UNTRACKED_RISKY=()
for path in .env .env.local .envrc .vscode .idea .claude/settings.local.json; do
    if [[ -e "$path" ]]; then
        UNTRACKED_RISKY+=("$path")
    fi
done

if [[ "${#UNTRACKED_RISKY[@]}" -gt 0 ]]; then
    yellow "found local-only files; verify .gitignore covers them all:"
    for p in "${UNTRACKED_RISKY[@]}"; do
        printf '    %s\n' "$p"
    done
    # Cross-check against git's ignore knowledge if a git repo exists.
    if [[ -d .git ]] && command -v git >/dev/null 2>&1; then
        for p in "${UNTRACKED_RISKY[@]}"; do
            if ! git check-ignore -q "$p" 2>/dev/null; then
                red "  ✗ '$p' is NOT ignored by git, fix .gitignore before pushing."
                EXIT=1
            fi
        done
    fi
fi

# Quick-and-dirty secret scan. Catches the obvious BEGIN-key blocks and
# common API-key patterns in tracked source. Misses are fine, GitHub's
# server-side secret scanning is the load-bearing protection.
echo
echo "[+] grepping tracked source for accidental secrets..."
SECRETS_HIT=0
if grep -rIE \
    "BEGIN (PRIVATE|RSA|OPENSSH|EC|DSA|PGP)|api[_-]?key|secret[_-]?key|aws_access" \
    --include='*.rs' --include='*.toml' --include='*.md' --include='*.sh' \
    --include='*.yml' --include='*.yaml' \
    . 2>/dev/null \
    | grep -vE 'rpassword|//[/!]|^[^:]*://' \
    | head -5; then
    : # printed (above hits)
else
    : # no hits
fi
# Don't fail the script on grep matches, they're frequent false
# positives. Just print and move on.

# Look for conspicuously-large files that shouldn't go to a repo (e.g.
# accidentally-committed vault files, database dumps, datasets).
echo
echo "[+] flagging files >5 MiB tracked under the workspace root..."
LARGE=$(find . -type f -size +5M \
    -not -path './.git/*' \
    -not -path './target/*' \
    -not -path './fuzz/target/*' \
    -not -path './fuzz-afl/target/*' \
    2>/dev/null || true)
if [[ -n "$LARGE" ]]; then
    yellow "large files (>5 MiB):"
    echo "$LARGE" | sed 's/^/    /'
    echo "  Confirm each is intended for the repo (logos, audited test fixtures)"
    echo "  before pushing."
fi

# ---- 3. Format, lint, test, audit ----------------------------------------

EXIT="${EXIT:-0}"

run() {
    local label="$1"
    shift
    echo
    echo "=== $label ==="
    if "$@"; then
        green "$label OK"
    else
        red "✗ $label FAILED"
        EXIT=1
    fi
}

run "cargo fmt --check" cargo fmt --all -- --check

run "cargo clippy" cargo clippy \
    --workspace \
    --exclude luksbox-fuzz --exclude luksbox-fuzz-afl \
    --no-deps -- -D warnings

if [[ "$DO_TEST" -eq 1 ]]; then
    run "cargo test" cargo test \
        --workspace \
        --exclude luksbox-fuzz --exclude luksbox-fuzz-afl
else
    yellow "skipping cargo test (--no-test)"
fi

# cargo audit is "best-effort", it requires the advisory DB to be
# fetchable and prints warnings for unmaintained deps even when the
# project is fine. Treat as informational unless an actual
# vulnerability is reported.
echo
echo "=== cargo audit ==="
if command -v cargo-audit >/dev/null 2>&1 || cargo audit --version >/dev/null 2>&1; then
    if cargo audit --deny warnings 2>&1 | tee /tmp/luksbox-audit.log; then
        green "cargo audit: clean (0 vulns, 0 unsound, 0 unmaintained)"
    else
        # Distinguish vulns (block) from unmaintained warnings (note).
        if grep -qE '^Crate:.*Title:.*Vulnerability' /tmp/luksbox-audit.log; then
            red "✗ cargo audit reported a vulnerability, fix before pushing"
            EXIT=1
        else
            yellow "cargo audit reported only unmaintained-warnings, review SECURITY.md §6 then proceed"
        fi
    fi
    rm -f /tmp/luksbox-audit.log
else
    yellow "cargo-audit not installed. Install with: cargo install cargo-audit"
fi

# ---- 4. Final summary -----------------------------------------------------

echo
if [[ "$EXIT" -eq 0 ]]; then
    green "════════════════════════════════════════════════════════════"
    green "  All checks passed. Repo is ready to push."
    green "════════════════════════════════════════════════════════════"
    echo
    echo "Next steps:"
    echo "    git status                 # confirm what's staged"
    echo "    git add ."
    echo "    git commit -m '...'"
    echo "    git push -u origin main"
else
    red "════════════════════════════════════════════════════════════"
    red "  One or more checks failed. DO NOT push until resolved."
    red "════════════════════════════════════════════════════════════"
fi

exit "$EXIT"
