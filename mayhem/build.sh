#!/usr/bin/env bash
#
# mayhem/build.sh — BACKPORT (repro-ba807d6, mayhemheroes/pacparser run 17) build.
#
# At this commit pacparser vendors the OLD Mozilla SpiderMonkey JS engine (src/spidermonkey/, a
# ~30-file 2007-era Makefile.ref/NSPR-style build), not the later QuickJS-ng rewrite the LIVE
# `savantenvs/pacparser` env fuzzes. The bug this backport reproduces (assertion in a regexp
# backreference, src/spidermonkey/js/src/jsregexp.c:1229) only exists in this old engine, so this
# script builds spidermonkey instead of quickjs; mayhem/fuzz_pac_parse.c is unchanged (it only calls
# pacparser's public API, which is stable across both engines).
#
# Oracle: pacparser's OWN pactester CLI (src/pactester.c), built with the project's normal
# (Makefile, unsanitized) flags via `make -C src pactester` -- a completely independent, honest,
# dynamically linked binary (mayhem/test.sh drives it against tests/testdata + tests/proxy.pac).
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
export MAYHEM_JOBS
cd "$SRC/src"

# Force both steps below to always compile from scratch (never reuse a stale .o from a PREVIOUS
# invocation of this script) so build.sh stays idempotent: re-running it on an already-built tree
# must not silently relink yesterday's sanitized spidermonkey objects into today's unsanitized
# oracle (or vice versa) just because make sees an up-to-date-looking .o sitting in the one shared
# OBJDIR this old build uses for both.
clean_engine_objs() {
  rm -f pacparser.o pactester jsapi_buildstamp pymod/pacparser_o_buildstamp
  rm -rf spidermonkey/js/src/*.OBJ spidermonkey/libjs.a spidermonkey/js-buildstamp spidermonkey/js/src/jsautocfg.h
}

# ---------------------------------------------------------------------------------------------
# 1) ORACLE build: pacparser's own `make pactester` — normal flags (no sanitizer, no
#    $DEBUG_FLAGS), an independent honest functional build via the project's checked-in
#    src/Makefile (VERSION is derived from `git describe`, same as any normal build from this
#    repo). This also builds spidermonkey/libjs.a unsanitized — step 2 rebuilds it sanitized.
#
#    -j1: `pactester` depends on BOTH pacparser.o (via jsapi_buildstamp -> spidermonkey `make
#    jsapi`) and spidermonkey/libjs.a (via spidermonkey `make jslib`) as separate top-level
#    prerequisites, and both recipes are opaque `cd spidermonkey && $(MAKE) ...` shell-outs GNU
#    Make can't see share the same js/src/$(OBJDIR) — under -j>1 make starts both submakes
#    concurrently and they race on the same object dir (observed: `ar` corrupting a half-written
#    libjs.a, "Error 2" with no readable cause). The whole engine is ~30 files, so serial is still
#    fast; $(MAYHEM_JOBS) isn't worth the risk here.
clean_engine_objs
make CC="$CC" -j1 pactester
install -m0755 pactester /mayhem/pactester-oracle

# ---------------------------------------------------------------------------------------------
# 2) FUZZ build: rebuild pacparser.o + the vendored spidermonkey engine (spidermonkey/libjs.a)
#    WITH sanitizer + coverage instrumentation, still via the project's OWN Makefiles, so the
#    fuzzed LIBRARY code carries SanCov coverage, not just the harness TU
#    (docs/netnew-worker-prompt.md §6 "instrument the LIBRARY, not just the harness TU").
#
#    IMPORTANT: sanitizer flags are injected through a CC wrapper below, NOT through
#    `make CFLAGS=...` on the command line. js/src/Makefile.ref computes its real compile flags as
#    `CFLAGS += $(OPTIMIZER) $(OS_CFLAGS) $(DEFINES) $(INCLUDES) ...` (rules.mk) — GNU Make ignores
#    a makefile's own `+=` onto a variable that arrived as a *command-line* argument, so
#    `make CFLAGS="-fsanitize=..."` silently DROPS -DXP_UNIX/-I$(OBJDIR)/etc. and breaks the build
#    in confusing ways (jsautocfg.h picks the wrong branch, missing basic typedefs). Passing the
#    flags via CC (never touched by `+=`, so a command-line override there is fine) avoids this.
#
#    Clean the step-1 outputs first (not `make clean` — its pymod sub-target shells out to
#    `python setup.py clean`, which needs setuptools and isn't installed/needed in this image);
#    steps 1 and 2 share the same object dir (this old build has no separate release/sanitizer
#    tree).
clean_engine_objs

# This 2007-era engine leans on plenty of technically-UB, deliberate low-level tricks that are not
# the bug we're chasing (jsregexp.c:1229's JS_ASSERT, a plain abort() any build catches) — each of
# these was found by running the seeded corpus and reading where UBSan aborted before the real
# assertion did, and is disabled for that one documented reason, ASan stays on throughout:
#   shift                 tagged-jsval packing shifts a negative value left (jsapi.h's
#                          INT_TO_JSVAL/JSVAL_VOID macros) — the representation's whole point.
#   float-cast-overflow   ECMA ToInt32 double->int truncation (jsnum.c) is spec-defined wraparound,
#                          expressed as a C cast.
#   signed-integer-overflow  same family of wraparound arithmetic elsewhere in the numeric code.
#   pointer-overflow       arena/string-buffer growth checks compare `ptr + n <= limit` while
#                          ptr/limit are still NULL before first allocation (jsscan.c) — never
#                          dereferenced, just an over-eager bounds check.
#   nonnull-attribute      `memcpy(dst, NULL, 0)` when a script has an empty prolog/main (jsscript.c)
#                          — a standard, harmless no-op memcpy libc itself special-cases.
#   function               GC finalizers are stored in one function-pointer table and called through
#                          a common signature (jsgc.c) — deliberate type erasure, not a real CFI bug.
FUZZ_SAN="$SANITIZER_FLAGS -fno-sanitize=shift,float-cast-overflow,signed-integer-overflow,pointer-overflow,nonnull-attribute,nullability-arg,function"

FUZZCC="$(mktemp)"
cat >"$FUZZCC" <<WRAP
#!/bin/sh
# jscpucfg is a build-time-only host tool (Mozilla's old struct-alignment prober, deliberately
# dereferencing offsets off a null pointer to compute alignment); it never ships in the fuzzed
# library or the harness, so build it plain (no sanitizers) to dodge the deliberate-UB false hit.
case "\$*" in
  *jscpucfg*) exec $CC "\$@" ;;
  *) exec $CC -fsanitize=fuzzer-no-link $FUZZ_SAN $DEBUG_FLAGS -O1 "\$@" ;;
esac
WRAP
chmod +x "$FUZZCC"

make CC="$FUZZCC" -j1 pacparser.o spidermonkey/libjs.a

# ---------------------------------------------------------------------------------------------
# 3) The harness, twice: the libFuzzer binary (Mayhem target) and a standalone run-once reproducer
#    (no fuzzing engine — one input file, natural crash, easy local repro). Both link the SAME
#    sanitized pacparser.o + spidermonkey/libjs.a from step 2.
# shellcheck disable=SC2086
$CC -I"$SRC/src" -I"$SRC/src/spidermonkey/js/src" $FUZZ_SAN $DEBUG_FLAGS $LIB_FUZZING_ENGINE \
    "$SRC/mayhem/fuzz_pac_parse.c" pacparser.o spidermonkey/libjs.a \
    -lm -o /mayhem/fuzz_pac_parse
# shellcheck disable=SC2086
$CC -I"$SRC/src" -I"$SRC/src/spidermonkey/js/src" $FUZZ_SAN $DEBUG_FLAGS "$STANDALONE_FUZZ_MAIN" \
    "$SRC/mayhem/fuzz_pac_parse.c" pacparser.o spidermonkey/libjs.a \
    -lm -o /mayhem/fuzz_pac_parse-standalone

echo "mayhem/build.sh: done -- /mayhem/fuzz_pac_parse, /mayhem/fuzz_pac_parse-standalone, /mayhem/pactester-oracle"
