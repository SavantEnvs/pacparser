# syntax=docker/dockerfile:1.7
#
# Commit-image Dockerfile (SMALL form) for pacparser (PAC/proxy-auto-config JS parser, vendoring
# QuickJS-ng). Builds on top of the org C/C++ base image (ghcr.io/savantenvs/base), which already
# provides debian + clang/llvm + libFuzzer/afl++ + the identities + the build-contract ENV.
FROM ghcr.io/savantenvs/base:20260621

ARG COMMIT
ARG REPO_URL
ARG SOURCE_DATE_EPOCH

ARG SANITIZER_FLAGS
ARG COVERAGE_FLAGS=
ARG MAYHEM_JOBS=

# pacparser's own PAC extensions (dnsResolve/dnsResolveEx/myIpAddress/myIpAddressEx) call
# getaddrinfo() with hostnames that, once fuzzing starts, come straight from the fuzzer-controlled
# PAC script (see mayhem/fuzz_pac_parse.c for the full rationale). /etc/resolv.conf is a Docker-
# managed bind mount (read-only at build AND run time — `docker build` proved this: writing it fails
# with "Read-only file system"), so it cannot be pinned in-image. Instead cap glibc's own resolver
# via the RES_OPTIONS environment variable (the documented runtime equivalent of a resolv.conf
# `options` line, honored by every process without touching the file): a real but unresponsive
# resolver now costs at most ~1s per lookup instead of glibc's default (5s x multiple attempts x
# multiple configured nameservers). This is a second, independent bound alongside the harness's own
# process-level watchdog (mayhem/fuzz_pac_parse.c) -- neither alone is assumed sufficient.
ENV RES_OPTIONS="timeout:1 attempts:1"

# Source enters from the build CONTEXT (the CI checkout): the FULL repo (incl. .git history) is
# copied to /mayhem as `mayhem`; build.sh builds in place.
USER mayhem
WORKDIR /mayhem
COPY --chown=2000:2000 . /mayhem

RUN bash mayhem/build.sh

RUN if [ -f mayhem/test.sh ]; then bash mayhem/test.sh; else echo "no mayhem/test.sh — repo ships no functional tests"; fi

LABEL org.opencontainers.image.source="${REPO_URL}" \
      org.opencontainers.image.revision="${COMMIT}" \
      rlenv.tier="commit" \
      rlenv.source_date_epoch="${SOURCE_DATE_EPOCH}" \
      rlenv.user="mayhem"

USER mayhem
WORKDIR /mayhem
