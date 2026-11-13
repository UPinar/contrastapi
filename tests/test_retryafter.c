#include <stddef.h>

#include "unity/unity.h"
#include "retryafter.h"

void setUp(void)    {}
void tearDown(void) {}

void test_null_value_answers_the_default(void)
{
  TEST_ASSERT_EQUAL_UINT(60, retryafter_parseSeconds(NULL));
}

void test_empty_value_answers_the_default(void)
{
  TEST_ASSERT_EQUAL_UINT(60, retryafter_parseSeconds(""));
}

void test_digits_answer_their_seconds(void)
{
  TEST_ASSERT_EQUAL_UINT(120, retryafter_parseSeconds("120"));
}

void test_zero_rises_to_the_minimum(void)
{
  TEST_ASSERT_EQUAL_UINT(1, retryafter_parseSeconds("0"));
}

void test_nine_answers_nine(void)
{
  TEST_ASSERT_EQUAL_UINT(9, retryafter_parseSeconds("9"));
}

void test_values_beside_the_maximum(void)
{
  TEST_ASSERT_EQUAL_UINT(3599, retryafter_parseSeconds("3599"));
  TEST_ASSERT_EQUAL_UINT(3600, retryafter_parseSeconds("3600"));
  TEST_ASSERT_EQUAL_UINT(3600, retryafter_parseSeconds("3601"));
}

void test_value_that_would_wrap_answers_the_maximum(void)
{
  TEST_ASSERT_EQUAL_UINT(3600, retryafter_parseSeconds("4294967296"));
}

void test_twenty_digits_answer_the_maximum(void)
{
  TEST_ASSERT_EQUAL_UINT(3600, retryafter_parseSeconds("99999999999999999999"));
}

void test_leading_zeros_are_read(void)
{
  TEST_ASSERT_EQUAL_UINT(7, retryafter_parseSeconds("007"));
}

void test_signed_values_answer_the_default(void)
{
  TEST_ASSERT_EQUAL_UINT(60, retryafter_parseSeconds("-5"));
  TEST_ASSERT_EQUAL_UINT(60, retryafter_parseSeconds("+5"));
}

void test_values_with_a_space_answer_the_default(void)
{
  TEST_ASSERT_EQUAL_UINT(60, retryafter_parseSeconds(" 5"));
  TEST_ASSERT_EQUAL_UINT(60, retryafter_parseSeconds("5 "));
}

void test_bytes_beside_the_digits_answer_the_default(void)
{
  TEST_ASSERT_EQUAL_UINT(60, retryafter_parseSeconds("/"));
  TEST_ASSERT_EQUAL_UINT(60, retryafter_parseSeconds(":"));
  TEST_ASSERT_EQUAL_UINT(60, retryafter_parseSeconds("1/"));
  TEST_ASSERT_EQUAL_UINT(60, retryafter_parseSeconds("1:"));
}

void test_letter_after_the_digits_answers_the_default(void)
{
  TEST_ASSERT_EQUAL_UINT(60, retryafter_parseSeconds("12a"));
}

void test_http_date_answers_the_default(void)
{
  TEST_ASSERT_EQUAL_UINT(60, retryafter_parseSeconds("Fri, 31 Dec 1999 23:59:59 GMT"));
}

void test_bounds_hold_their_values(void)
{
  TEST_ASSERT_EQUAL_UINT(60, RETRYAFTER_DEFAULT_SECONDS);
  TEST_ASSERT_EQUAL_UINT(1, RETRYAFTER_MIN_SECONDS);
  TEST_ASSERT_EQUAL_UINT(3600, RETRYAFTER_MAX_SECONDS);
}

void test_letter_after_a_value_past_the_maximum_answers_the_default(void)
{
  TEST_ASSERT_EQUAL_UINT(60, retryafter_parseSeconds("36000a"));
}

void test_bytes_from_0x80_answer_the_default(void)
{
  TEST_ASSERT_EQUAL_UINT(60, retryafter_parseSeconds("\x80"));
  TEST_ASSERT_EQUAL_UINT(60, retryafter_parseSeconds("\xb9"));
  TEST_ASSERT_EQUAL_UINT(60, retryafter_parseSeconds("1\xff"));
}

#define RESET_NOW ((time_t)1800000000)

static bool static_tryReadReset(const char* header_value, unsigned int* seconds_out)
{
  return retryafter_tryReadResetSeconds(header_value, RESET_NOW, seconds_out);
}

void test_reset_time_ahead_answers_its_distance(void)
{
  unsigned int seconds = 0;
  TEST_ASSERT_TRUE(static_tryReadReset("1800000001", &seconds));
  TEST_ASSERT_EQUAL_UINT(1, seconds);
  TEST_ASSERT_TRUE(static_tryReadReset("1800000002", &seconds));
  TEST_ASSERT_EQUAL_UINT(2, seconds);
  TEST_ASSERT_TRUE(static_tryReadReset("1800000120", &seconds));
  TEST_ASSERT_EQUAL_UINT(120, seconds);
}

void test_reset_time_at_or_before_now_answers_the_minimum(void)
{
  unsigned int seconds = 0;
  TEST_ASSERT_TRUE(static_tryReadReset("1800000000", &seconds));
  TEST_ASSERT_EQUAL_UINT(1, seconds);
  seconds = 0;
  TEST_ASSERT_TRUE(static_tryReadReset("1799999999", &seconds));
  TEST_ASSERT_EQUAL_UINT(1, seconds);
  seconds = 0;
  TEST_ASSERT_TRUE(static_tryReadReset("0", &seconds));
  TEST_ASSERT_EQUAL_UINT(1, seconds);
}

void test_reset_time_past_a_day_answers_the_maximum(void)
{
  unsigned int seconds = 0;
  TEST_ASSERT_EQUAL_UINT(86400, RETRYAFTER_RESET_MAX_SECONDS);
  TEST_ASSERT_TRUE(static_tryReadReset("1800086399", &seconds));
  TEST_ASSERT_EQUAL_UINT(86399, seconds);
  TEST_ASSERT_TRUE(static_tryReadReset("1800086400", &seconds));
  TEST_ASSERT_EQUAL_UINT(86400, seconds);
  seconds = 0;
  TEST_ASSERT_TRUE(static_tryReadReset("1800086401", &seconds));
  TEST_ASSERT_EQUAL_UINT(86400, seconds);
  seconds = 0;
  TEST_ASSERT_TRUE(static_tryReadReset("999999999999999999999999999999", &seconds));
  TEST_ASSERT_EQUAL_UINT(86400, seconds);
  seconds = 0;
  TEST_ASSERT_TRUE(static_tryReadReset("18446744073709551616", &seconds));
  TEST_ASSERT_EQUAL_UINT(86400, seconds);
}

void test_reset_time_counts_from_now(void)
{
  unsigned int seconds = 0;
  TEST_ASSERT_TRUE(retryafter_tryReadResetSeconds("50", 0, &seconds));
  TEST_ASSERT_EQUAL_UINT(50, seconds);
  TEST_ASSERT_TRUE(retryafter_tryReadResetSeconds("50", 40, &seconds));
  TEST_ASSERT_EQUAL_UINT(10, seconds);
}

void test_reset_time_against_a_failed_clock_answers_false(void)
{
  unsigned int seconds = 7;
  TEST_ASSERT_FALSE(retryafter_tryReadResetSeconds("50", -1, &seconds));
  TEST_ASSERT_EQUAL_UINT(7, seconds);
}

void test_reset_time_that_is_not_digits_answers_false(void)
{
  static const char* const values[] = {
    NULL, "", "-5", "+5", " 1800000005", "1800000005 ", "1800000005x",
    "99999999999999999999x", "Wed, 21 Oct 2015 07:28:00 GMT", "1\xff", "/", ":"
  };
  for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++)
  {
    unsigned int seconds = 7;
    TEST_ASSERT_FALSE_MESSAGE(static_tryReadReset(values[i], &seconds), values[i] ? values[i] : "NULL");
    TEST_ASSERT_EQUAL_UINT(7, seconds);
  }
}

void test_registration_gate_test_count(void)
{
  TEST_ASSERT_EQUAL_INT_MESSAGE(24, (int)Unity.NumberOfTests,
    "RUN_TEST list and test definitions have drifted apart - a test may be unregistered");
}

int main(void)
{
  UNITY_BEGIN();
  RUN_TEST(test_null_value_answers_the_default);
  RUN_TEST(test_empty_value_answers_the_default);
  RUN_TEST(test_digits_answer_their_seconds);
  RUN_TEST(test_zero_rises_to_the_minimum);
  RUN_TEST(test_nine_answers_nine);
  RUN_TEST(test_values_beside_the_maximum);
  RUN_TEST(test_value_that_would_wrap_answers_the_maximum);
  RUN_TEST(test_twenty_digits_answer_the_maximum);
  RUN_TEST(test_leading_zeros_are_read);
  RUN_TEST(test_signed_values_answer_the_default);
  RUN_TEST(test_values_with_a_space_answer_the_default);
  RUN_TEST(test_bytes_beside_the_digits_answer_the_default);
  RUN_TEST(test_letter_after_the_digits_answers_the_default);
  RUN_TEST(test_http_date_answers_the_default);
  RUN_TEST(test_bounds_hold_their_values);
  RUN_TEST(test_letter_after_a_value_past_the_maximum_answers_the_default);
  RUN_TEST(test_bytes_from_0x80_answer_the_default);
  RUN_TEST(test_reset_time_ahead_answers_its_distance);
  RUN_TEST(test_reset_time_at_or_before_now_answers_the_minimum);
  RUN_TEST(test_reset_time_past_a_day_answers_the_maximum);
  RUN_TEST(test_reset_time_counts_from_now);
  RUN_TEST(test_reset_time_against_a_failed_clock_answers_false);
  RUN_TEST(test_reset_time_that_is_not_digits_answers_false);
  RUN_TEST(test_registration_gate_test_count);
  return UNITY_END();
}
