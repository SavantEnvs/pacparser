#!/usr/bin/env bash
#
# mayhem/test.sh — RUN (never build) pacparser's own functional oracle: /mayhem/pactester-oracle,
# built by mayhem/build.sh with the project's NORMAL (unsanitized) flags via its own Makefile
# (`make -C src pactester`) — a dynamically linked binary the sabotage/neuter shim can intercept.
#
# Drives it exactly the way the project's own tests/runtests.sh does: read tests/testdata (a
# "<pactester CLI params>|<expected proxy string>" table, one row per known-answer case) and
# tests/logging.pac (alert()/console.log() -> stderr), asserting EXACT stdout (and, for the logging
# case, stderr) against the fixtures' own known-good values -- not just "exited 0" / "didn't crash".
# Runs fully offline: the one INTERNET_REQUIRED row in testdata (a live DNS lookup of google.com) is
# skipped, same as upstream's own NO_INTERNET=1 mode.
#
# A neutered pactester-oracle (LD_PRELOAD _exit(0) shim) prints nothing on stdout/stderr, which
# mismatches every asserted value below -- this fails loudly, not silently.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
cd "${SRC:-/mayhem}"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

PACTESTER=/mayhem/pactester-oracle
PASSED=0
FAILED=0
SKIPPED=0

if [ ! -x "$PACTESTER" ]; then
  echo "missing $PACTESTER — run mayhem/build.sh first" >&2
  emit_ctrf pactester-oracle 0 1 0
  exit $?
fi

# Regression guard: the oracle must be a real dynamically linked ELF (against libc) so the
# sabotage/neuter LD_PRELOAD shim can actually intercept it -- a statically linked binary would
# silently defeat the whole anti-reward-hack check.
if ! file "$PACTESTER" | grep -q "dynamically linked"; then
  echo "$PACTESTER is not dynamically linked — sabotage/neuter check would be defeated:" >&2
  file "$PACTESTER" >&2
  FAILED=$((FAILED + 1))
fi

pacfile="tests/proxy.pac"
testdata="tests/testdata"

while IFS= read -r line; do
  comment="${line#*#}"
  raw="${line%%#*}"
  # Trim trailing whitespace left after stripping the comment.
  raw="${raw%"${raw##*[![:space:]]}"}"
  [ -z "$raw" ] && continue

  if [ "${comment}" != "${line}" ] && [[ "$comment" == *INTERNET_REQUIRED* ]]; then
    SKIPPED=$((SKIPPED + 1))
    echo "SKIP (INTERNET_REQUIRED): $raw"
    continue
  fi

  params="${raw%%|*}"
  expected="${raw##*|}"
  # shellcheck disable=SC2086
  result="$("$PACTESTER" -p "$pacfile" $params 2>/tmp/pactester_stderr)"
  rc=$?
  if [ "$rc" -ne 0 ]; then
    echo "FAIL: pactester exited $rc for params [$params]" >&2
    cat /tmp/pactester_stderr >&2
    FAILED=$((FAILED + 1))
  elif [ "$result" != "$expected" ]; then
    echo "FAIL: params [$params] got \"$result\", expected \"$expected\"" >&2
    FAILED=$((FAILED + 1))
  else
    echo "OK: params [$params] -> \"$result\""
    PASSED=$((PASSED + 1))
  fi
done < "$testdata"

# Logging test: alert()/console.log() land on stderr with the expected prefixes; the proxy result on
# stdout (from logging.pac's FindProxyForURL, which always returns "DIRECT") is unaffected.
# tests/logging.pac does not exist at this backport's frozen commit (added upstream later) — skip.
logging_pac="tests/logging.pac"
if [ ! -f "$logging_pac" ]; then
  SKIPPED=$((SKIPPED + 1))
  echo "SKIP (no $logging_pac at this backport's commit)"
else
  logging_stderr="$(mktemp)"
  logging_stdout="$("$PACTESTER" -p "$logging_pac" -u http://example.com/ -h example.com 2>"$logging_stderr")"
  expected_stderr=$'ALERT: checking example.com\nLOG: url: http://example.com/\nLOG: single arg'
  actual_stderr="$(cat "$logging_stderr")"
  rm -f "$logging_stderr"
  if [ "$logging_stdout" = "DIRECT" ] && [ "$actual_stderr" = "$expected_stderr" ]; then
    echo "OK: logging test -> stdout=\"$logging_stdout\""
    PASSED=$((PASSED + 1))
  else
    echo "FAIL: logging test — stdout=\"$logging_stdout\" (want DIRECT), stderr mismatch:" >&2
    echo "--- expected stderr ---" >&2; printf '%s\n' "$expected_stderr" >&2
    echo "--- actual stderr ---"   >&2; printf '%s\n' "$actual_stderr"   >&2
    FAILED=$((FAILED + 1))
  fi
fi

emit_ctrf pactester-oracle "$PASSED" "$FAILED" "$SKIPPED"
