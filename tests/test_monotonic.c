#include <time.h>

#include "unity/unity.h"
#include "monotonic.h"

static struct timespec g_now;
static clockid_t       g_lastClockId;
static int             g_clockReadCount;

int __wrap_clock_gettime(clockid_t clock_id, struct timespec* time_out);

int __wrap_clock_gettime(clockid_t clock_id, struct timespec* time_out)
{
  g_lastClockId = clock_id;
  g_clockReadCount++;
  *time_out = g_now;
  return 0;
}

void setUp(void)
{
  g_now.tv_sec     = 0;
  g_now.tv_nsec    = 0;
  g_lastClockId    = (clockid_t)-1;
  g_clockReadCount = 0;
}

void tearDown(void) {}

void test_now_ms_reads_seconds_and_whole_milliseconds(void)
{
  g_now.tv_sec  = 3;
  g_now.tv_nsec = 5999999;

  TEST_ASSERT_EQUAL_INT64(3005, monotonic_nowMs());
  TEST_ASSERT_EQUAL_INT((int)CLOCK_MONOTONIC, (int)g_lastClockId);
}

void test_deadline_adds_seconds_and_milliseconds(void)
{
  g_now.tv_sec  = 100;
  g_now.tv_nsec = 1000;
  struct timespec deadline = { 0 };

  monotonic_writeDeadlineAfterMs(2500, &deadline);

  TEST_ASSERT_EQUAL_INT64(102, (int64_t)deadline.tv_sec);
  TEST_ASSERT_EQUAL_INT64(500001000, (int64_t)deadline.tv_nsec);
  TEST_ASSERT_EQUAL_INT((int)CLOCK_MONOTONIC, (int)g_lastClockId);
  TEST_ASSERT_EQUAL_INT(1, g_clockReadCount);
}

void test_deadline_carries_at_exactly_one_second(void)
{
  g_now.tv_sec  = 7;
  g_now.tv_nsec = 999000000;
  struct timespec deadline = { 0 };

  monotonic_writeDeadlineAfterMs(1, &deadline);

  TEST_ASSERT_EQUAL_INT64(8, (int64_t)deadline.tv_sec);
  TEST_ASSERT_EQUAL_INT64(0, (int64_t)deadline.tv_nsec);
}

void test_deadline_does_not_carry_below_one_second(void)
{
  g_now.tv_sec  = 7;
  g_now.tv_nsec = 998999999;
  struct timespec deadline = { 0 };

  monotonic_writeDeadlineAfterMs(1, &deadline);

  TEST_ASSERT_EQUAL_INT64(7, (int64_t)deadline.tv_sec);
  TEST_ASSERT_EQUAL_INT64(999999999, (int64_t)deadline.tv_nsec);
}

void test_deadline_adds_whole_seconds_and_a_carry(void)
{
  g_now.tv_sec  = 7;
  g_now.tv_nsec = 999999999;
  struct timespec deadline = { 0 };

  monotonic_writeDeadlineAfterMs(1999, &deadline);

  TEST_ASSERT_EQUAL_INT64(9, (int64_t)deadline.tv_sec);
  TEST_ASSERT_EQUAL_INT64(998999999, (int64_t)deadline.tv_nsec);
}

void test_registration_gate_test_count(void)
{
  TEST_ASSERT_EQUAL_INT_MESSAGE(6, (int)Unity.NumberOfTests,
    "RUN_TEST list and test definitions have drifted apart - a test may be unregistered");
}

int main(void)
{
  UNITY_BEGIN();
  RUN_TEST(test_now_ms_reads_seconds_and_whole_milliseconds);
  RUN_TEST(test_deadline_adds_seconds_and_milliseconds);
  RUN_TEST(test_deadline_carries_at_exactly_one_second);
  RUN_TEST(test_deadline_does_not_carry_below_one_second);
  RUN_TEST(test_deadline_adds_whole_seconds_and_a_carry);
  RUN_TEST(test_registration_gate_test_count);
  return UNITY_END();
}
