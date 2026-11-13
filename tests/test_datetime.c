#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "unity/unity.h"
#include "datetime.h"

#define JANUARY_FIRST_EPOCH      1767225600
#define NOVEMBER_TWENTIETH_EPOCH 1795132800
#define UNTOUCHED_EPOCH          (-12345)

void setUp(void)    {}
void tearDown(void) {}

static char* static_copyExact(const char* text, size_t len)
{
  char* copy = malloc(len == 0 ? 1 : len);
  TEST_ASSERT_NOT_NULL(copy);
  memcpy(copy, text, len);
  return copy;
}

static bool static_readDateTime(const char* text, int64_t* epoch_out)
{
  size_t len     = strlen(text);
  char*  copy    = static_copyExact(text, len);
  bool   is_read = datetime_tryReadDateTime(copy, copy + len, epoch_out);
  free(copy);
  return is_read;
}

static bool static_readFullDate(const char* text, int64_t* epoch_out)
{
  size_t len     = strlen(text);
  char*  copy    = static_copyExact(text, len);
  bool   is_read = datetime_tryReadFullDate(copy, copy + len, epoch_out);
  free(copy);
  return is_read;
}

static void static_assertDateTime(const char* text, int64_t expected_epoch)
{
  int64_t epoch = UNTOUCHED_EPOCH;
  TEST_ASSERT_TRUE_MESSAGE(static_readDateTime(text, &epoch), text);
  TEST_ASSERT_EQUAL_INT64_MESSAGE(expected_epoch, epoch, text);
}

static void static_assertDateTimeRefused(const char* text)
{
  int64_t epoch = UNTOUCHED_EPOCH;
  TEST_ASSERT_FALSE_MESSAGE(static_readDateTime(text, &epoch), text);
  TEST_ASSERT_EQUAL_INT64_MESSAGE(UNTOUCHED_EPOCH, epoch, text);
}

static void static_assertFullDateRefused(const char* text)
{
  int64_t epoch = UNTOUCHED_EPOCH;
  TEST_ASSERT_FALSE_MESSAGE(static_readFullDate(text, &epoch), text);
  TEST_ASSERT_EQUAL_INT64_MESSAGE(UNTOUCHED_EPOCH, epoch, text);
}

void test_tryReadDateTime_reads_each_form_securitytxt_reads(void)
{
  static_assertDateTime("2026-01-01T00:00:00Z", JANUARY_FIRST_EPOCH);
  static_assertDateTime("2026-01-01t00:00:00z", JANUARY_FIRST_EPOCH);
  static_assertDateTime("2026-01-01T00:00:00.5Z", JANUARY_FIRST_EPOCH);
  static_assertDateTime("2026-01-01T00:00:00.123456789Z", JANUARY_FIRST_EPOCH);
  static_assertDateTime("2026-01-01T01:00:00+01:00", JANUARY_FIRST_EPOCH);
  static_assertDateTime("2025-12-31T21:30:00-02:30", JANUARY_FIRST_EPOCH);
  static_assertDateTime("2026-01-01T00:00:00.9+00:00", JANUARY_FIRST_EPOCH);
  static_assertDateTime("2026-06-30T12:34:56Z", 1782822896);
  static_assertDateTime("2026-12-31T23:59:59Z", 1798761599);
}

void test_tryReadDateTime_reads_each_field_at_its_bound(void)
{
  static_assertDateTime("2016-12-31T23:59:60Z", 1483228800);
  static_assertDateTime("2026-01-01T23:59:00+23:59", JANUARY_FIRST_EPOCH);
  static_assertDateTime("2025-12-31T00:01:00-23:59", JANUARY_FIRST_EPOCH);
  static_assertDateTime("2026-01-31T00:00:00Z", JANUARY_FIRST_EPOCH + 30 * DATETIME_SECONDS_PER_DAY);
  static_assertDateTime("2024-02-29T00:00:00Z", 1709164800);
}

void test_tryReadDateTime_refuses_each_field_past_its_bound(void)
{
  static_assertDateTimeRefused("2026-00-01T00:00:00Z");
  static_assertDateTimeRefused("2026-13-01T00:00:00Z");
  static_assertDateTimeRefused("2026-01-00T00:00:00Z");
  static_assertDateTimeRefused("2026-01-32T00:00:00Z");
  static_assertDateTimeRefused("2026-02-29T00:00:00Z");
  static_assertDateTimeRefused("2026-01-01T24:00:00Z");
  static_assertDateTimeRefused("2026-01-01T00:60:00Z");
  static_assertDateTimeRefused("2026-01-01T00:00:61Z");
  static_assertDateTimeRefused("2026-01-01T00:00:00+24:00");
  static_assertDateTimeRefused("2026-01-01T00:00:00+00:60");
  static_assertDateTimeRefused("2026-01-01T00:00:00");
  static_assertDateTimeRefused("2026-01-01T00:00:00.Z");
  static_assertDateTimeRefused("2026-01-01T00:00:00Zx");
  static_assertDateTimeRefused("2026-01-01T00:00:00+0100");
  static_assertDateTimeRefused("2026-01-01T00:00:00*01:00");
  static_assertDateTimeRefused("2026-01-01T00:00:00+01-00");
  static_assertDateTimeRefused("2026-01-01T00:00:00+0a:00");
  static_assertDateTimeRefused("2026-01-01X00:00:00Z");
  static_assertDateTimeRefused("2026/01-01T00:00:00Z");
  static_assertDateTimeRefused("2026-01/01T00:00:00Z");
  static_assertDateTimeRefused("2026-01-01T00-00:00Z");
  static_assertDateTimeRefused("2026-01-01T00:00-00Z");
  static_assertDateTimeRefused("20a6-01-01T00:00:00Z");
  static_assertDateTimeRefused("2026-01-01T0a:00:00Z");
  static_assertDateTimeRefused("2026-01-01");
  static_assertDateTimeRefused("");
}

void test_tryReadFullDate_reads_a_day_as_midnight_utc(void)
{
  int64_t epoch = UNTOUCHED_EPOCH;
  TEST_ASSERT_TRUE(static_readFullDate("2026-11-20", &epoch));
  TEST_ASSERT_EQUAL_INT64(NOVEMBER_TWENTIETH_EPOCH, epoch);
  TEST_ASSERT_TRUE(static_readFullDate("2026-01-01", &epoch));
  TEST_ASSERT_EQUAL_INT64(JANUARY_FIRST_EPOCH, epoch);
  TEST_ASSERT_TRUE(static_readFullDate("2024-02-29", &epoch));
  TEST_ASSERT_EQUAL_INT64(1709164800, epoch);
  TEST_ASSERT_TRUE(static_readFullDate("2000-02-29", &epoch));
  TEST_ASSERT_EQUAL_INT64(951782400, epoch);
}

void test_tryRead_takes_the_last_day_of_each_month(void)
{
  static const int LAST_DAYS[12] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
  for (int month = 1; month <= 12; month++)
  {
    char    text[32];
    int64_t epoch = UNTOUCHED_EPOCH;
    snprintf(text, sizeof(text), "2026-%02d-%02d", month, LAST_DAYS[month - 1]);
    TEST_ASSERT_TRUE_MESSAGE(static_readFullDate(text, &epoch), text);
    snprintf(text, sizeof(text), "2026-%02d-%02d", month, LAST_DAYS[month - 1] + 1);
    static_assertFullDateRefused(text);
    snprintf(text, sizeof(text), "2026-%02d-%02dT00:00:00Z", month, LAST_DAYS[month - 1]);
    TEST_ASSERT_TRUE_MESSAGE(static_readDateTime(text, &epoch), text);
    snprintf(text, sizeof(text), "2026-%02d-%02dT00:00:00Z", month, LAST_DAYS[month - 1] + 1);
    static_assertDateTimeRefused(text);
  }
}

void test_tryReadFullDate_refuses_a_day_that_does_not_exist(void)
{
  static_assertFullDateRefused("2026-02-29");
  static_assertFullDateRefused("2023-02-29");
  static_assertFullDateRefused("2100-02-29");
  static_assertFullDateRefused("2024-02-30");
  static_assertFullDateRefused("2026-13-01");
  static_assertFullDateRefused("2026-00-10");
  static_assertFullDateRefused("2026-01-00");
  static_assertFullDateRefused("2026-04-31");
  static_assertFullDateRefused("2026-1-01");
  static_assertFullDateRefused("2026-01-011");
  static_assertFullDateRefused("2026-01-01T00:00:00Z");
  static_assertFullDateRefused("2026-0a-01");
  static_assertFullDateRefused("2026-01-0a");
  static_assertFullDateRefused("a026-01-01");
  static_assertFullDateRefused("2026/01-01");
  static_assertFullDateRefused("2026-01/01");
  static_assertFullDateRefused("2026-01-01 ");
  static_assertFullDateRefused("");
}

void test_tryRead_reads_nothing_past_the_end(void)
{
  int64_t epoch = UNTOUCHED_EPOCH;
  const char* full_date = "2026-01-01";
  TEST_ASSERT_FALSE(datetime_tryReadFullDate(full_date, full_date + 9, &epoch));
  const char* date_time = "2026-01-01T00:00:00Z";
  TEST_ASSERT_FALSE(datetime_tryReadDateTime(date_time, date_time + 19, &epoch));
  TEST_ASSERT_FALSE(datetime_tryReadDateTime(date_time, date_time + 18, &epoch));
  const char* offset = "2026-01-01T00:00:00+01:00";
  TEST_ASSERT_FALSE(datetime_tryReadDateTime(offset, offset + 24, &epoch));
  const char* fraction = "2026-01-01T00:00:00.5Z";
  TEST_ASSERT_FALSE(datetime_tryReadDateTime(fraction, fraction + 20, &epoch));
  TEST_ASSERT_EQUAL_INT64(UNTOUCHED_EPOCH, epoch);

  static_assertFullDateRefused("2026");
  static_assertDateTimeRefused("2026-01-01T00:00");
  static_assertDateTimeRefused("2026-01-01T00:00:0");
  static_assertDateTimeRefused("2");
}

void test_daysUntil_cuts_toward_zero(void)
{
  TEST_ASSERT_EQUAL_INT(0,  datetime_daysUntil(JANUARY_FIRST_EPOCH, JANUARY_FIRST_EPOCH));
  TEST_ASSERT_EQUAL_INT(0,  datetime_daysUntil(JANUARY_FIRST_EPOCH + 86399, JANUARY_FIRST_EPOCH));
  TEST_ASSERT_EQUAL_INT(1,  datetime_daysUntil(JANUARY_FIRST_EPOCH + 86400, JANUARY_FIRST_EPOCH));
  TEST_ASSERT_EQUAL_INT(0,  datetime_daysUntil(JANUARY_FIRST_EPOCH - 86399, JANUARY_FIRST_EPOCH));
  TEST_ASSERT_EQUAL_INT(-1, datetime_daysUntil(JANUARY_FIRST_EPOCH - 86400, JANUARY_FIRST_EPOCH));
  TEST_ASSERT_EQUAL_INT(30, datetime_daysUntil(JANUARY_FIRST_EPOCH + 30 * 86400 + 5, JANUARY_FIRST_EPOCH));
  TEST_ASSERT_EQUAL_INT(DATETIME_SECONDS_PER_DAY, 86400);
}

void test_tryReadDigits_reads_only_ascii_digits(void)
{
  int value = -1;
  TEST_ASSERT_TRUE(datetime_tryReadDigits("0042", 4, &value));
  TEST_ASSERT_EQUAL_INT(42, value);
  TEST_ASSERT_TRUE(datetime_tryReadDigits("9", 1, &value));
  TEST_ASSERT_EQUAL_INT(9, value);
  TEST_ASSERT_TRUE(datetime_tryReadDigits("1234x", 4, &value));
  TEST_ASSERT_EQUAL_INT(1234, value);
  TEST_ASSERT_TRUE(datetime_tryReadDigits("999999999", 9, &value));
  TEST_ASSERT_EQUAL_INT(999999999, value);

  value = -1;
  TEST_ASSERT_FALSE(datetime_tryReadDigits("12a", 3, &value));
  TEST_ASSERT_FALSE(datetime_tryReadDigits("1/", 2, &value));
  TEST_ASSERT_FALSE(datetime_tryReadDigits(":1", 2, &value));
  TEST_ASSERT_FALSE(datetime_tryReadDigits("1 2", 3, &value));
  TEST_ASSERT_FALSE(datetime_tryReadDigits("-1", 2, &value));
  TEST_ASSERT_EQUAL_INT(-1, value);
}

void test_registration_gate_test_count(void)
{
  TEST_ASSERT_EQUAL_INT_MESSAGE(10, (int)Unity.NumberOfTests,
    "RUN_TEST list and test definitions have drifted apart - a test may be unregistered");
}

int main(void)
{
  UNITY_BEGIN();
  RUN_TEST(test_tryReadDateTime_reads_each_form_securitytxt_reads);
  RUN_TEST(test_tryReadDateTime_reads_each_field_at_its_bound);
  RUN_TEST(test_tryReadDateTime_refuses_each_field_past_its_bound);
  RUN_TEST(test_tryReadFullDate_reads_a_day_as_midnight_utc);
  RUN_TEST(test_tryRead_takes_the_last_day_of_each_month);
  RUN_TEST(test_tryReadFullDate_refuses_a_day_that_does_not_exist);
  RUN_TEST(test_tryRead_reads_nothing_past_the_end);
  RUN_TEST(test_daysUntil_cuts_toward_zero);
  RUN_TEST(test_tryReadDigits_reads_only_ascii_digits);
  RUN_TEST(test_registration_gate_test_count);
  return UNITY_END();
}
