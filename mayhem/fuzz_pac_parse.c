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
// dnsResolve()/dnsResolveEx()/myIpAddress[Ex]() call getaddrinfo() with a FUZZER-CONTROLLED
// hostname whenever the script itself invokes them from FindProxyForURL. mayhem/Dockerfile pins
// /etc/resolv.conf to a fast-failing (unreachable server, timeout:1 attempts:1) resolver so that
// syscall never blocks for long, and the Mayhemfile's `timeout: 30` (per-exec, Mayhem-owned) bounds
// the rest -- no harness-level timer/watchdog (PORTING.md: "Mayhem owns timeouts").
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "pacparser.h"

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

  pacparser_set_error_printer(quiet_error_printer);
  return 0;
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

  if (pacparser_init()) {
    if (pacparser_parse_pac_string(script)) {
      for (size_t i = 0; i < sizeof(kProbes) / sizeof(kProbes[0]); i++) {
        char *proxy = pacparser_find_proxy(kProbes[i].url, kProbes[i].host);
        (void)proxy;  // owned by pacparser (valid until the next call / cleanup); do not free here
      }
    }
    pacparser_cleanup();
  }

  free(script);
  return 0;
}
