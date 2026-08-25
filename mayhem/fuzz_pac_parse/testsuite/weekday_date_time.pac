// Hand-written seed exercising weekdayRange()/dateRange()/timeRange() (pac_utils.h), none of which
// the other bundled fixtures reach.
function FindProxyForURL(url, host) {
  if (weekdayRange("MON", "FRI"))
    return "WEEKDAY";
  if (weekdayRange("SAT", "GMT"))
    return "WEEKEND-GMT";
  if (dateRange("JAN", "MAR"))
    return "Q1";
  if (dateRange(1, 15))
    return "FIRST-HALF";
  if (dateRange(2024, 2026))
    return "YEAR-RANGE";
  if (timeRange(9, 17))
    return "BUSINESS-HOURS";
  if (timeRange(0, 0, 0, 12, 0, 0))
    return "MORNING";
  return "DIRECT";
}
