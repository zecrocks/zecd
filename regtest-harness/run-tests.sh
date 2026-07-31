#!/usr/bin/env bash
#
# Drive the regtest harness test binaries, up to $REGTEST_JOBS of them at a time.
#
# Why this exists: every harness test binary brings up its own zebrad (+ lightwalletd, + zecd)
# stack and then spends most of its wall clock *waiting* on that stack - mining blocks, polling for
# a sync to catch up, waiting out a confirmation. Run one at a time, the tier's ~15 binaries add up
# to ~22 minutes of mostly-idle CPU. They are fully independent (tempdir datadirs, no shared
# fixture), so the only thing that stopped them overlapping was the runner having two cores.
#
# `cargo test --test a --test b` will NOT do this: cargo runs test *binaries* strictly one after
# another, and `--test-threads` only parallelises tests *within* a binary - which does nothing here,
# where almost every binary holds exactly one test. So we build once with `--no-run`, ask cargo for
# the compiled binary paths, and run those ourselves.
#
# Each binary gets a disjoint slice of the loopback port range (ZECD_REGTEST_PORT_LO/_SPAN, see
# `pick_port`) so concurrent stacks can't race for the same port, and its own node-log file. Output
# is captured per binary and replayed in collapsed groups at the end, so interleaved stacks stay
# readable; a summary table of per-binary wall clock is printed last (that table is how the
# concurrency was tuned - keep an eye on it when adding a heavy test).
#
# Usage:  REGTEST_JOBS=6 regtest-harness/run-tests.sh --test regtest_e2e --test regtest_funded ...
# Env:
#   REGTEST_JOBS          how many binaries to run at once (default 1 - the old serial behaviour)
#   REGTEST_TEST_THREADS  threads within each binary (default 1); see the note on it below
#   REGTEST_LOG_DIR       where per-binary logs land (default $RUNNER_TEMP/regtest-logs, else ./regtest-logs)
# Everything else (ZECD_BIN, ZEBRAD_BIN, ...) is inherited by each binary unchanged.

set -uo pipefail

manifest="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/Cargo.toml"
jobs="${REGTEST_JOBS:-1}"
# Threads *within* one binary. Only two binaries hold more than one test, and only one of them
# (regtest_coinbase) is slow - but with everything else overlapped it is the tier's critical path,
# so letting its two tests run side by side is what moves the total. Harmless for the rest: a
# one-test binary cannot use the second thread. Both stacks share the binary's port slice, which
# is safe only because pick_port claims each probe with a single atomic read-modify-write; the
# first attempt at this raised the setting without that fix and regtest_coinbase's two stacks were
# handed the same port ("Address already in use"). Keep the two in lockstep.
test_threads="${REGTEST_TEST_THREADS:-1}"
logdir="${REGTEST_LOG_DIR:-${RUNNER_TEMP:-$PWD}/regtest-logs}"
mkdir -p "$logdir"

# Build every requested target once, up front, and collect the binary paths. Doing this here (not
# lazily per binary) also keeps `cargo`'s build-directory lock out of the parallel phase - N cargo
# processes would serialise on it instead of running.
command -v jq >/dev/null || { echo "::error::run-tests.sh needs jq to read cargo's artifact JSON"; exit 1; }

echo "::group::Build the harness test binaries"
artifacts="$logdir/cargo-artifacts.json"
# Note the status check is on cargo itself, not on the pipeline/mapfile that consumes it: a build
# failure here must stop the run rather than quietly yield an empty binary list.
if ! cargo test --locked --no-run --message-format=json --manifest-path "$manifest" "$@" >"$artifacts"; then
  echo "::endgroup::"
  echo "::error::failed to build the harness test binaries"
  exit 1
fi
echo "::endgroup::"

mapfile -t binaries < <(
  jq -r 'select(.reason == "compiler-artifact" and .profile.test == true and .target.kind[0] == "test")
         | [.target.name, .executable] | @tsv' "$artifacts" | sort
)
if [ "${#binaries[@]}" -eq 0 ]; then
  echo "::error::no test binaries matched $*"
  exit 1
fi

n="${#binaries[@]}"
# Slice the non-ephemeral loopback range (20000..32000) evenly, one slice per binary, so no two
# concurrent stacks ever probe the same port. Per *binary*, not per concurrency slot: slots get
# reused as binaries finish, and a lingering socket from a finished stack could still collide.
span=$(( 12000 / n ))
if [ "$span" -lt 64 ]; then
  echo "::error::$n test binaries leaves only $span ports each; widen the range or split the tier"
  exit 1
fi

echo "Running $n harness test binaries, $jobs at a time, $test_threads thread(s) each ($span ports each)"

declare -A pid_name=()
declare -A started=()
declare -A elapsed=()
declare -A status=()
failed=0
idx=0

reap() {
  local pid="$1" name="${pid_name[$1]}" rc
  wait "$pid"
  rc=$?
  status["$name"]=$rc
  elapsed["$name"]=$(( SECONDS - started[$name] ))
  [ "$rc" -ne 0 ] && failed=1
  printf '%s %-46s %4ds\n' "$([ "$rc" -eq 0 ] && echo 'PASS' || echo 'FAIL')" \
    "$name" "${elapsed[$name]}"
  unset 'pid_name[$pid]'
}

for entry in "${binaries[@]}"; do
  name="${entry%%$'\t'*}"
  exe="${entry#*$'\t'}"

  # Wait for a free slot.
  while [ "${#pid_name[@]}" -ge "$jobs" ]; do
    # Reap whichever finishes first; -n needs the pids to still be children of this shell.
    for pid in "${!pid_name[@]}"; do
      if ! kill -0 "$pid" 2>/dev/null; then reap "$pid"; fi
    done
    [ "${#pid_name[@]}" -ge "$jobs" ] && sleep 1
  done

  started["$name"]=$SECONDS
  ZECD_REGTEST_PORT_LO=$(( 20000 + idx * span )) \
  ZECD_REGTEST_PORT_SPAN="$span" \
  ZEBRAD_STDERR="$logdir/$name.node.log" \
    "$exe" --nocapture --test-threads="$test_threads" >"$logdir/$name.log" 2>&1 &
  pid_name[$!]="$name"
  idx=$(( idx + 1 ))
done

# Drain.
while [ "${#pid_name[@]}" -gt 0 ]; do
  for pid in "${!pid_name[@]}"; do
    if ! kill -0 "$pid" 2>/dev/null; then reap "$pid"; fi
  done
  [ "${#pid_name[@]}" -gt 0 ] && sleep 1
done

# Replay the captured output. Failures go last and uncollapsed, so the interesting one is what you
# land on when you open the run.
for entry in "${binaries[@]}"; do
  name="${entry%%$'\t'*}"
  [ "${status[$name]:-1}" -eq 0 ] || continue
  echo "::group::$name (${elapsed[$name]}s, passed)"
  cat "$logdir/$name.log"
  echo "::endgroup::"
done
for entry in "${binaries[@]}"; do
  name="${entry%%$'\t'*}"
  [ "${status[$name]:-1}" -ne 0 ] || continue
  echo "===== $name FAILED (${elapsed[$name]}s) ====="
  cat "$logdir/$name.log"
  echo "----- $name node log (last 200 lines) -----"
  tail -n 200 "$logdir/$name.node.log" 2>/dev/null || echo "(no node log was written)"
done

# Summary table: the input for tuning REGTEST_JOBS. Slowest first - the top row is the tier's
# critical path once everything else overlaps.
echo
echo "== harness wall clock (${jobs}-way concurrency, ${test_threads} thread(s)/binary) =="
for entry in "${binaries[@]}"; do
  name="${entry%%$'\t'*}"
  printf '%6ds  %-46s %s\n' "${elapsed[$name]:-0}" "$name" \
    "$([ "${status[$name]:-1}" -eq 0 ] && echo ok || echo FAILED)"
done | sort -rn
echo "total elapsed: $(( SECONDS / 60 ))m $(( SECONDS % 60 ))s"

exit "$failed"
