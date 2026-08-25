// Hand-written seed exercising isInNetEx()/isInNetEx6()/isInNetEx4() and shExpMatch() (pac_utils.h),
// including IPv6 CIDR matching, none of which the other bundled fixtures reach.
function FindProxyForURL(url, host) {
  if (isInNetEx("2001:db8::1", "2001:db8::/32"))
    return "V6-MATCH";
  if (isInNetEx("10.1.2.3", "10.0.0.0/8"))
    return "V4-EX-MATCH";
  if (shExpMatch(url, "*.example.com/*"))
    return "SHEXP-MATCH";
  if (shExpMatch(host, "www.?.com"))
    return "SHEXP-WILDCARD";
  if (dnsDomainLevels(host) > 2)
    return "DEEP-DOMAIN";
  return "DIRECT";
}
