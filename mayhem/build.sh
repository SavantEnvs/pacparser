#!/usr/bin/env bash
#
# mayhem/build.sh — build pacparser's fuzz harness + its oracle binary.
#
# pacparser is a small C library (src/pacparser.c) that evaluates proxy auto-config (PAC)
# JavaScript against a vendored, amalgamated QuickJS-ng engine (src/quickjs/quickjs.c, a single
# self-contained ~84k-line .c file with no other dependencies -- see src/quickjs/update.sh) and
# exposes the PAC-specific extensions (dnsResolve, myIpAddress, ...) plus pac_utils.h's own
# hand-written FindProxyForURL helper library (dnsDomainIs, isInNet*, shExpMatch, weekdayRange,
# dateRange, timeRange, ...). The fuzzed surface is pacparser.c + the whole vendored QuickJS engine
# (not just the harness translation unit), so both are compiled with $SANITIZER_FLAGS +
# -fsanitize=fuzzer-no-link below.
#
# One target: fuzz_pac_parse (mayhem/fuzz_pac_parse.c) -- feeds raw fuzzer bytes as a PAC script to
# pacparser_parse_pac_string(), then exercises pacparser_find_proxy() with fixed url/host pairs. No
# file I/O in the harness.
#
# Oracle: pacparser's OWN pactester CLI (src/pactester.c), built with the project's normal (Makefile,
# unsanitized) flags via `make -C src pactester` -- a completely independent, honest, dynamically
# linked binary (mayhem/test.sh drives it against tests/testdata + tests/logging.pac, the project's
# own known-answer fixtures).
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — it must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}"
: "${CXX:=clang++}"
: "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${SRC:=/mayhem}"
export CC CXX MAYHEM_JOBS
cd "$SRC"

# ---------------------------------------------------------------------------------------------
# 1) ORACLE build: pacparser's own `make -C src pactester` — normal flags (no sanitizer, no
#    $DEBUG_FLAGS), an independent honest functional build. Builds quickjs/libquickjs.a,
#    pacparser.o, libpacparser.a and finally pactester, all via the project's checked-in
#    src/Makefile (VERSION is derived from `git describe`, same as any normal build from this repo).
#    This is idempotent: re-running `make` on an already-built tree just no-ops on up-to-date targets.
make -C src pactester CC="$CC"
install -m0755 src/pactester /mayhem/pactester-oracle

# ---------------------------------------------------------------------------------------------
# 2) FUZZ build: compile the vendored QuickJS engine + pacparser.c directly with clang (bypassing
#    the project Makefile) into a SEPARATE object dir so this never collides with step 1's
#    src/*.o / src/quickjs/*.o|*.a (no `make clean` / stash dance needed between the two builds).
#    -fsanitize=fuzzer-no-link is applied to BOTH translation units unconditionally (including when
#    $SANITIZER_FLAGS is empty) so the fuzzed LIBRARY code carries SanCov coverage, not just the
#    harness TU (docs/netnew-worker-prompt.md §6 "instrument the LIBRARY, not just the harness TU").
FUZZOBJ=/tmp/pacparser-fuzz-obj
rm -rf "$FUZZOBJ"
mkdir -p "$FUZZOBJ"
FUZZ_CFLAGS="-I$SRC/src -I$SRC/src/quickjs -fsanitize=fuzzer-no-link $SANITIZER_FLAGS $DEBUG_FLAGS -O1 -DVERSION=fuzz_build"

# shellcheck disable=SC2086
$CC $FUZZ_CFLAGS -c "$SRC/src/quickjs/quickjs.c" -o "$FUZZOBJ/quickjs.o"
# shellcheck disable=SC2086
$CC $FUZZ_CFLAGS -c "$SRC/src/pacparser.c" -o "$FUZZOBJ/pacparser.o"

# ---------------------------------------------------------------------------------------------
# 3) The harness, twice: the libFuzzer binary (Mayhem target) and a standalone run-once reproducer
#    (no fuzzing engine — one input file, natural crash, easy local repro). Both link the SAME
#    sanitized objects from step 2. -lpthread: the vendored QuickJS references pthread_* (Atomics
#    support); harmless/no-op to pass explicitly on glibc where it has since merged into libc.
# shellcheck disable=SC2086
$CC -I"$SRC/src" $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE \
    "$SRC/mayhem/fuzz_pac_parse.c" "$FUZZOBJ/pacparser.o" "$FUZZOBJ/quickjs.o" \
    -lm -lpthread -o /mayhem/fuzz_pac_parse
# shellcheck disable=SC2086
$CC -I"$SRC/src" $SANITIZER_FLAGS $DEBUG_FLAGS "$STANDALONE_FUZZ_MAIN" \
    "$SRC/mayhem/fuzz_pac_parse.c" "$FUZZOBJ/pacparser.o" "$FUZZOBJ/quickjs.o" \
    -lm -lpthread -o /mayhem/fuzz_pac_parse-standalone

echo "mayhem/build.sh: done -- /mayhem/fuzz_pac_parse, /mayhem/fuzz_pac_parse-standalone, /mayhem/pactester-oracle"
