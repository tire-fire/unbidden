#!/bin/sh
# Runs every cargo-fuzz target, one per CPU at a time, and fails if any
# target finds a crash, a hang or unbounded memory.
#
# The binaries `cargo fuzz build -O` left are run directly, with the corpus
# and artifact directories cargo-fuzz would have given them: running
# `cargo fuzz run` in parallel would queue every target on cargo's build lock.
#
# Usage: fuzz-all.sh <seconds for the §13 names> <seconds for the rest>
set -eu

long="${1:?seconds for the §13 names}"
short="${2:?seconds for every other target}"
bin=fuzz/target/x86_64-unknown-linux-gnu/release
logs=$(mktemp -d)

# Since cc 1.9 the bundled C (SQLite, tree-sitter) is built with
# -fsanitize=address too. SQLite has two function-local `static const aiOff[]`
# tables with the same contents; they end up at one address, and ASan's
# default ODR check (level 2) reports that as a violation in every target
# before any input is run. Neither table has external linkage, so there is no
# ODR to violate. Level 1 still reports a same-named global whose size
# differs, the real bug. A caller's own ASAN_OPTIONS come later and win.
export ASAN_OPTIONS="detect_odr_violation=1${ASAN_OPTIONS:+:$ASAN_OPTIONS}"

# -timeout turns a hang into a reported crash rather than a job that runs
# until GitHub kills it; the two memory limits are how "no unbounded memory"
# gets checked at all.
status=0
cargo +nightly fuzz list | xargs -P "$(nproc)" -I{} sh -c '
    t=$1
    case "$t" in
        unit_file|crontab|desktop_file|udev_rules|pam_config|shell_text) secs=$2 ;;
        *) secs=$3 ;;
    esac
    mkdir -p "fuzz/corpus/$t" "fuzz/artifacts/$t"
    if "$4/$t" -max_total_time="$secs" -timeout=10 -rss_limit_mb=2048 -malloc_limit_mb=512 \
        -artifact_prefix="fuzz/artifacts/$t/" "fuzz/corpus/$t" > "$5/$t.log" 2>&1; then
        echo "ok    $t (${secs}s)"
    else
        mv "$5/$t.log" "$5/$t.fail"
        echo "FAIL  $t (${secs}s)"
        exit 1
    fi
' _ {} "$long" "$short" "$bin" "$logs" || status=$?

for f in "$logs"/*.fail; do
    [ -e "$f" ] || continue
    echo "::group::$(basename "$f" .fail)"
    tail -n 60 "$f"
    echo "::endgroup::"
done
rm -rf "$logs"
exit "$status"
