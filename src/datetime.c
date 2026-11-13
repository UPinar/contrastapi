#include <assert.h>
#include <ctype.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include "datetime.h"

#define DATETIME_TM_YEAR_BASE      1900
#define DATETIME_DIGITS_MAX_COUNT  9

static const int DAYS_IN_MONTH[12] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };

static bool        static_tryReadDate     (const char* text, int* year_out, int* month_out, int* day_out);
static const char* static_skipFraction    (const char* position, const char* text_end);
static bool        static_tryReadZone     (const char* zone_start, const char* text_end, int64_t* offset_seconds_out);
static int64_t     static_epochOf         (int year, int month, int day, int hour, int minute, int second);
static int         static_lastDayOfMonth  (int year, int month);
static bool        static_isLeapYear      (int year);

bool datetime_tryReadDateTime(const char* text_start, const char* text_end, int64_t* epoch_out)
{
  assert(text_start != NULL);
  assert(text_end   >= text_start);
  assert(epoch_out  != NULL);

  const char* text = text_start;
  if ((size_t)(text_end - text) < DATETIME_DATE_TIME_LEN ||
      tolower((unsigned char)text[10]) != 't'            ||
      text[13] != ':' || text[16] != ':')
  {
    return false;
  }

  int year  = 0;
  int month = 0;
  int day   = 0;
  if (!static_tryReadDate(text, &year, &month, &day))
    return false;

  int hour   = 0;
  int minute = 0;
  int second = 0;
  if (!datetime_tryReadDigits(text + 11, 2, &hour)    ||
      !datetime_tryReadDigits(text + 14, 2, &minute)  ||
      !datetime_tryReadDigits(text + 17, 2, &second))
  {
    return false;
  }
  if (hour > 23 || minute > 59 || second > 60)
    return false;

  const char* zone_start = static_skipFraction(text + DATETIME_DATE_TIME_LEN, text_end);
  int64_t offset_seconds = 0;
  if (zone_start == NULL || !static_tryReadZone(zone_start, text_end, &offset_seconds))
    return false;

  *epoch_out = static_epochOf(year, month, day, hour, minute, second) - offset_seconds;
  return true;
}

bool datetime_tryReadFullDate(const char* text_start, const char* text_end, int64_t* epoch_out)
{
  assert(text_start != NULL);
  assert(text_end   >= text_start);
  assert(epoch_out  != NULL);

  if ((size_t)(text_end - text_start) != DATETIME_FULL_DATE_LEN)
    return false;

  int year  = 0;
  int month = 0;
  int day   = 0;
  if (!static_tryReadDate(text_start, &year, &month, &day))
    return false;

  *epoch_out = static_epochOf(year, month, day, 0, 0, 0);
  return true;
}

int datetime_daysUntil(int64_t end_epoch, int64_t now_epoch)
{
  return (int)((end_epoch - now_epoch) / DATETIME_SECONDS_PER_DAY);
}

bool datetime_tryReadDigits(const char* digits, int digit_count, int* value_out)
{
  assert(digits    != NULL);
  assert(value_out != NULL);
  assert(digit_count >= 1 && digit_count <= DATETIME_DIGITS_MAX_COUNT);

  int value = 0;
  for (int i = 0; i < digit_count; i++)
  {
    if (!isdigit((unsigned char)digits[i]))
      return false;
    value = value * 10 + (digits[i] - '0');
  }
  *value_out = value;
  return true;
}

static bool static_tryReadDate(const char* text, int* year_out, int* month_out, int* day_out)
{
  if (text[4] != '-' || text[7] != '-')
    return false;

  int year  = 0;
  int month = 0;
  int day   = 0;
  if (!datetime_tryReadDigits(text, 4, &year)       ||
      !datetime_tryReadDigits(text + 5, 2, &month)  ||
      !datetime_tryReadDigits(text + 8, 2, &day))
  {
    return false;
  }
  if (month < 1 || month > 12 || day < 1 || day > static_lastDayOfMonth(year, month))
    return false;

  *year_out  = year;
  *month_out = month;
  *day_out   = day;
  return true;
}

static const char* static_skipFraction(const char* position, const char* text_end)
{
  if (position == text_end || *position != '.')
    return position;
  const char* first_digit  = position + 1;
  const char* after_digits = first_digit;
  while (after_digits < text_end && isdigit((unsigned char)*after_digits))
    after_digits++;

  return after_digits == first_digit ? NULL : after_digits;
}

static bool static_tryReadZone(const char* zone_start, const char* text_end, int64_t* offset_seconds_out)
{
  size_t zone_len = (size_t)(text_end - zone_start);
  if (zone_len == 1 && tolower((unsigned char)zone_start[0]) == 'z')
  {
    *offset_seconds_out = 0;
    return true;
  }

  if (zone_len != 6 || (zone_start[0] != '+' && zone_start[0] != '-') || zone_start[3] != ':')
    return false;
  int hour   = 0;
  int minute = 0;
  if (!datetime_tryReadDigits(zone_start + 1, 2, &hour)   ||
      !datetime_tryReadDigits(zone_start + 4, 2, &minute) ||
      hour > 23 || minute > 59)
  {
    return false;
  }

  int64_t offset_seconds = (int64_t)hour * 3600 + minute * 60;
  *offset_seconds_out = zone_start[0] == '-' ? -offset_seconds : offset_seconds;
  return true;
}

static int64_t static_epochOf(int year, int month, int day, int hour, int minute, int second)
{
  struct tm when;
  memset(&when, 0, sizeof(when));
  when.tm_year = year - DATETIME_TM_YEAR_BASE;
  when.tm_mon  = month - 1;
  when.tm_mday = day;
  when.tm_hour = hour;
  when.tm_min  = minute;
  when.tm_sec  = second;
  return (int64_t)timegm(&when);
}

static int static_lastDayOfMonth(int year, int month)
{
  assert(month >= 1 && month <= 12);
  return DAYS_IN_MONTH[month - 1] + (month == 2 && static_isLeapYear(year) ? 1 : 0);
}

static bool static_isLeapYear(int year)
{
  return (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
}
