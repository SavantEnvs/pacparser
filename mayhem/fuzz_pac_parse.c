// mayhem/fuzz_pac_parse.c
//
// libFuzzer harness for pacparser: feeds raw fuzzer bytes directly as a PAC (proxy auto-config)
// JavaScript script text to pacparser_parse_pac_string(), then -- if the script parsed -- drives
// pacparser_find_proxy() with a handful of FIXED url/host pairs to also exercise the
// findProxyForURL() code path: pacparser's own PAC-specific JS extensions implemented partly in
// pac_utils.h (dnsDomainIs, isInNet[Ex[4|6]], shExpMatch, weekdayRange, dateRange, timeRange, ...)
// and partly in pacparser.c (dnsResolve[Ex], myIpAddress[Ex]), plus the vendored QuickJS engine
// underneath. No file I/O -- every byte the harness touches comes from libFuzzer's data/size
// argument or from the small fixed C string constants below (see
// docs/netnew-worker-prompt.md §3).
//
// Watchdog. dnsResolve()/dnsResolveEx()/myIpAddress[Ex]() call getaddrinfo() with a
// FUZZER-CONTROLLED hostname whenever the script itself invokes them from FindProxyForURL. Under a
// slow/unreachable resolver that syscall can block for many seconds -- a host-implemented builtin
// that no in-VM interrupt can bound (see docs/netnew-worker-prompt.md's goja/wazero note: engine
// interrupts only fire between bytecode instructions, never inside a blocking libc call). pacparser
// keeps all engine state in file-scope statics reachable only through its public API, so there is no
// JSContext handle available here to wire QuickJS's own JS_SetInterruptHandler -- the only lever
// from OUTSIDE pacparser.c is a hard process-level watchdog. mayhem/Dockerfile also pins
// /etc/resolv.conf to a fast-failing (unreachable server, timeout:1 attempts:1) resolver so a normal
// run never needs this for DNS specifically, but the watchdog stays as an independent second bound
// (also covers e.g. pathological regex backtracking in the vendored QuickJS engine).
//
// We arm an INDEPENDENT POSIX per-process timer (timer_create on CLOCK_MONOTONIC, delivering
// SIGRTMIN+5) around each LLVMFuzzerTestOneInput call -- deliberately NOT alarm()/setitimer
// (ITIMER_REAL)/SIGALRM, which libFuzzer owns for its own -timeout handling; a harness-installed
// alarm()-based watchdog silently swallows libFuzzer's timeout detection for the rest of the process
// (see docs/netnew-worker-prompt.md, "do NOT build that watchdog on alarm()").
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "pacparser.h"

#define WATCHDOG_SECONDS 5
#define WATCHDOG_SIGNAL (SIGRTMIN + 5)

static timer_t watchdog_timer;
static int watchdog_armed = 0;

static void
watchdog_fire(int sig)
{
  (void)sig;
  static const char msg[] =
      "fuzz_pac_parse: watchdog fired -- iteration exceeded the bound, exiting\n";
  ssize_t ignore = write(2, msg, sizeof(msg) - 1);
  (void)ignore;
  _exit(70);
}

// Silence pacparser's default stderr error printer (invalid PAC scripts are the overwhelming
// majority of fuzzer inputs, and printing every one of them slows the campaign for no benefit --
// this does not hide crashes/UB, only the library's own textual "could not parse" diagnostics).
static int
quiet_error_printer(const char *fmt, va_list argp)
{
  (void)fmt;
  (void)argp;
  return 0;
}

int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
  (void)argc;
  (void)argv;

  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = watchdog_fire;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;
  if (sigaction(WATCHDOG_SIGNAL, &sa, NULL) != 0) {
    perror("fuzz_pac_parse: sigaction");
    _exit(1);
  }

  struct sigevent sev;
  memset(&sev, 0, sizeof(sev));
  sev.sigev_notify = SIGEV_SIGNAL;
  sev.sigev_signo = WATCHDOG_SIGNAL;
  sev.sigev_value.sival_ptr = &watchdog_timer;
  if (timer_create(CLOCK_MONOTONIC, &sev, &watchdog_timer) != 0) {
    perror("fuzz_pac_parse: timer_create");
    _exit(1);
  }
  watchdog_armed = 1;

  pacparser_set_error_printer(quiet_error_printer);
  return 0;
}

static void
arm_watchdog(void)
{
  if (!watchdog_armed) return;
  struct itimerspec its;
  memset(&its, 0, sizeof(its));
  its.it_value.tv_sec = WATCHDOG_SECONDS;
  timer_settime(watchdog_timer, 0, &its, NULL);
}

static void
disarm_watchdog(void)
{
  if (!watchdog_armed) return;
  struct itimerspec its;
  memset(&its, 0, sizeof(its));  // all-zero it_value disarms the timer
  timer_settime(watchdog_timer, 0, &its, NULL);
}

// Fixed url/host pairs that vary control-flow shape (scheme, IP-literal host vs. plain host vs.
// dotted domain) a hand-written FindProxyForURL commonly branches on -- deliberately NOT derived
// from the fuzzer input, so the harness keeps exactly one input channel (the PAC script text) per
// docs/netnew-worker-prompt.md §3 ("bytes only from the fuzzer, no file I/O").
static const struct {
  const char *url;
  const char *host;
} kProbes[] = {
  {"http://example.com/path?x=1", "example.com"},
  {"https://sub.example.org/", "sub.example.org"},
  {"http://192.168.1.5:8080/", "192.168.1.5"},
  {"ftp://plainhost/", "plainhost"},
};

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  char *script = (char *)malloc(size + 1);
  if (!script) return 0;
  memcpy(script, data, size);
  script[size] = '\0';

  arm_watchdog();

  if (pacparser_init()) {
    if (pacparser_parse_pac_string(script)) {
      for (size_t i = 0; i < sizeof(kProbes) / sizeof(kProbes[0]); i++) {
        char *proxy = pacparser_find_proxy(kProbes[i].url, kProbes[i].host);
        (void)proxy;  // owned by pacparser (valid until the next call / cleanup); do not free here
      }
    }
    pacparser_cleanup();
  }

  disarm_watchdog();
  free(script);
  return 0;
}
