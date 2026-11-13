#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <libpq-fe.h>

#include "unity/unity.h"
#include "maintenance.h"
#include "db.h"

#define FAKE_CONN ((PGconn*)1)

#define SHORT_INTERVAL_MS 10u

#define WAIT_LIMIT_MS 5000L

#define SLOW_JOB_MS 200L

#define RUN_LOG_BUF_SIZE 64

static unsigned long g_openCount;
static unsigned long g_openFailuresLeft;
static unsigned long g_closeCount;
static unsigned long g_otherCloseCount;
static bool          g_isConnBad;
static unsigned long g_resetCount;

static unsigned long g_firstJobRunCount;
static unsigned long g_secondJobRunCount;
static unsigned long g_wrongConnRunCount;
static unsigned long g_slowJobStartCount;
static unsigned long g_slowJobDoneCount;

static char         g_runLog[RUN_LOG_BUF_SIZE];
static unsigned int g_runLogLength;

ConnStatusType __wrap_PQstatus(const PGconn* conn);
void           __wrap_PQreset(PGconn* conn);

void setUp(void)
{
  __atomic_store_n(&g_openCount,         0, __ATOMIC_SEQ_CST);
  __atomic_store_n(&g_openFailuresLeft,  0, __ATOMIC_SEQ_CST);
  __atomic_store_n(&g_closeCount,        0, __ATOMIC_SEQ_CST);
  __atomic_store_n(&g_otherCloseCount,   0, __ATOMIC_SEQ_CST);
  __atomic_store_n(&g_isConnBad,     false, __ATOMIC_SEQ_CST);
  __atomic_store_n(&g_resetCount,        0, __ATOMIC_SEQ_CST);
  __atomic_store_n(&g_firstJobRunCount,  0, __ATOMIC_SEQ_CST);
  __atomic_store_n(&g_secondJobRunCount, 0, __ATOMIC_SEQ_CST);
  __atomic_store_n(&g_wrongConnRunCount, 0, __ATOMIC_SEQ_CST);
  __atomic_store_n(&g_slowJobStartCount, 0, __ATOMIC_SEQ_CST);
  __atomic_store_n(&g_slowJobDoneCount,  0, __ATOMIC_SEQ_CST);
  memset(g_runLog, 0, sizeof(g_runLog));
  g_runLogLength = 0;
}

void tearDown(void) {}

PGconn* db_open(const char* conninfo)
{
  (void)conninfo;
  __atomic_add_fetch(&g_openCount, 1, __ATOMIC_SEQ_CST);
  unsigned long failures_left = __atomic_load_n(&g_openFailuresLeft, __ATOMIC_SEQ_CST);
  if (failures_left > 0)
  {
    __atomic_store_n(&g_openFailuresLeft, failures_left - 1, __ATOMIC_SEQ_CST);
    return NULL;
  }
  return FAKE_CONN;
}

void db_close(PGconn* conn)
{
  if (conn == FAKE_CONN)
    __atomic_add_fetch(&g_closeCount, 1, __ATOMIC_SEQ_CST);
  else
    __atomic_add_fetch(&g_otherCloseCount, 1, __ATOMIC_SEQ_CST);
}

ConnStatusType __wrap_PQstatus(const PGconn* conn)
{
  (void)conn;
  return __atomic_load_n(&g_isConnBad, __ATOMIC_SEQ_CST) ? CONNECTION_BAD : CONNECTION_OK;
}

void __wrap_PQreset(PGconn* conn)
{
  (void)conn;
  __atomic_add_fetch(&g_resetCount, 1, __ATOMIC_SEQ_CST);
  __atomic_store_n(&g_isConnBad, false, __ATOMIC_SEQ_CST);
}

static void static_recordRun(char letter, const PGconn* conn)
{
  if (g_runLogLength < RUN_LOG_BUF_SIZE - 1)
    g_runLog[g_runLogLength++] = letter;
  if (conn != FAKE_CONN)
    __atomic_add_fetch(&g_wrongConnRunCount, 1, __ATOMIC_SEQ_CST);
}

static bool static_firstJob(PGconn* conn)
{
  static_recordRun('A', conn);
  __atomic_add_fetch(&g_firstJobRunCount, 1, __ATOMIC_SEQ_CST);
  return true;
}

static bool static_secondJob(PGconn* conn)
{
  static_recordRun('B', conn);
  __atomic_add_fetch(&g_secondJobRunCount, 1, __ATOMIC_SEQ_CST);
  return true;
}

static bool static_failingJob(PGconn* conn)
{
  static_recordRun('F', conn);
  __atomic_add_fetch(&g_firstJobRunCount, 1, __ATOMIC_SEQ_CST);
  return false;
}

static void static_sleepMs(long milliseconds)
{
  struct timespec pause = { .tv_sec = milliseconds / 1000, .tv_nsec = (milliseconds % 1000) * 1000000L };
  nanosleep(&pause, NULL);
}

static bool static_slowJob(PGconn* conn)
{
  (void)conn;
  __atomic_add_fetch(&g_slowJobStartCount, 1, __ATOMIC_SEQ_CST);
  static_sleepMs(SLOW_JOB_MS);
  __atomic_add_fetch(&g_slowJobDoneCount, 1, __ATOMIC_SEQ_CST);
  return true;
}

static bool static_waitForCount(const unsigned long* counter, unsigned long target)
{
  struct timespec pause = { .tv_sec = 0, .tv_nsec = 1000000L };
  for (long waited_ms = 0; waited_ms < WAIT_LIMIT_MS; waited_ms++)
  {
    if (__atomic_load_n(counter, __ATOMIC_SEQ_CST) >= target)
      return true;
    nanosleep(&pause, NULL);
  }
  return __atomic_load_n(counter, __ATOMIC_SEQ_CST) >= target;
}

static long static_nowMs(void)
{
  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);
  return (long)now.tv_sec * 1000L + now.tv_nsec / 1000000L;
}

void test_jobs_run_in_list_order_on_each_run(void)
{
  static const MaintenanceJob_t jobs[] = {
    { "first",  static_firstJob },
    { "second", static_secondJob },
  };
  MaintenanceThread_t* maintenance_thread = maintenance_start("fake", SHORT_INTERVAL_MS, jobs, 2);
  TEST_ASSERT_NOT_NULL(maintenance_thread);

  bool has_run_three_times = static_waitForCount(&g_secondJobRunCount, 3);
  maintenance_stop(maintenance_thread);

  TEST_ASSERT_TRUE_MESSAGE(has_run_three_times, "the jobs did not run three times");
  TEST_ASSERT_EQUAL_STRING_LEN("ABABAB", g_runLog, 6);
  TEST_ASSERT_EQUAL_UINT(0, __atomic_load_n(&g_wrongConnRunCount, __ATOMIC_SEQ_CST));
}

void test_no_job_runs_before_the_first_interval(void)
{
  static const MaintenanceJob_t jobs[] = { { "first", static_firstJob } };
  MaintenanceThread_t* maintenance_thread = maintenance_start("fake", 999u, jobs, 1);
  TEST_ASSERT_NOT_NULL(maintenance_thread);

  static_sleepMs(300);
  maintenance_stop(maintenance_thread);

  TEST_ASSERT_EQUAL_UINT(0, __atomic_load_n(&g_firstJobRunCount, __ATOMIC_SEQ_CST));
}

void test_stop_does_not_wait_out_the_interval(void)
{
  static const MaintenanceJob_t jobs[] = { { "first", static_firstJob } };
  MaintenanceThread_t* maintenance_thread = maintenance_start("fake", 60000u, jobs, 1);
  TEST_ASSERT_NOT_NULL(maintenance_thread);

  static_sleepMs(50);
  long stop_start_ms = static_nowMs();
  maintenance_stop(maintenance_thread);
  long stop_duration_ms = static_nowMs() - stop_start_ms;

  TEST_ASSERT_LESS_THAN_INT32(1000, stop_duration_ms);
  TEST_ASSERT_EQUAL_UINT(0, __atomic_load_n(&g_firstJobRunCount, __ATOMIC_SEQ_CST));
  TEST_ASSERT_EQUAL_UINT(0, __atomic_load_n(&g_openCount, __ATOMIC_SEQ_CST));
}

void test_each_run_waits_one_interval(void)
{
  static const MaintenanceJob_t jobs[] = { { "first", static_firstJob } };
  long start_ms = static_nowMs();
  MaintenanceThread_t* maintenance_thread = maintenance_start("fake", 100u, jobs, 1);
  TEST_ASSERT_NOT_NULL(maintenance_thread);

  bool has_run_three_times = static_waitForCount(&g_firstJobRunCount, 3);
  long elapsed_ms = static_nowMs() - start_ms;
  maintenance_stop(maintenance_thread);

  TEST_ASSERT_TRUE_MESSAGE(has_run_three_times, "the job did not run three times");
  TEST_ASSERT_GREATER_OR_EQUAL_INT32(290, elapsed_ms);
}

void test_each_run_waits_no_more_than_one_interval(void)
{
  static const MaintenanceJob_t jobs[] = { { "first", static_firstJob } };
  long start_ms = static_nowMs();
  MaintenanceThread_t* maintenance_thread = maintenance_start("fake", 300u, jobs, 1);
  TEST_ASSERT_NOT_NULL(maintenance_thread);

  bool has_run_three_times = static_waitForCount(&g_firstJobRunCount, 3);
  long elapsed_ms = static_nowMs() - start_ms;
  maintenance_stop(maintenance_thread);

  TEST_ASSERT_TRUE_MESSAGE(has_run_three_times, "the job did not run three times");
  TEST_ASSERT_LESS_THAN_INT32(1500, elapsed_ms);
}

void test_no_job_runs_before_an_interval_over_one_second(void)
{
  static const MaintenanceJob_t jobs[] = { { "first", static_firstJob } };
  MaintenanceThread_t* maintenance_thread = maintenance_start("fake", 1001u, jobs, 1);
  TEST_ASSERT_NOT_NULL(maintenance_thread);

  static_sleepMs(300);
  maintenance_stop(maintenance_thread);

  TEST_ASSERT_EQUAL_UINT(0, __atomic_load_n(&g_firstJobRunCount, __ATOMIC_SEQ_CST));
}

void test_stop_waits_for_the_run_in_progress(void)
{
  static const MaintenanceJob_t jobs[] = { { "slow", static_slowJob } };
  MaintenanceThread_t* maintenance_thread = maintenance_start("fake", SHORT_INTERVAL_MS, jobs, 1);
  TEST_ASSERT_NOT_NULL(maintenance_thread);

  bool has_begun = static_waitForCount(&g_slowJobStartCount, 1);
  maintenance_stop(maintenance_thread);

  TEST_ASSERT_TRUE_MESSAGE(has_begun, "the job never began");
  TEST_ASSERT_EQUAL_UINT(__atomic_load_n(&g_slowJobStartCount, __ATOMIC_SEQ_CST), __atomic_load_n(&g_slowJobDoneCount, __ATOMIC_SEQ_CST));
  TEST_ASSERT_EQUAL_UINT(1, __atomic_load_n(&g_closeCount, __ATOMIC_SEQ_CST));
}

void test_failed_job_stops_neither_the_next_job_nor_the_next_run(void)
{
  static const MaintenanceJob_t jobs[] = {
    { "failing", static_failingJob },
    { "second",  static_secondJob },
  };
  MaintenanceThread_t* maintenance_thread = maintenance_start("fake", SHORT_INTERVAL_MS, jobs, 2);
  TEST_ASSERT_NOT_NULL(maintenance_thread);

  bool has_run_twice = static_waitForCount(&g_secondJobRunCount, 2);
  maintenance_stop(maintenance_thread);

  TEST_ASSERT_TRUE_MESSAGE(has_run_twice, "the second job did not run twice");
  TEST_ASSERT_EQUAL_STRING_LEN("FBFB", g_runLog, 4);
}

void test_jobs_wait_for_a_connection(void)
{
  __atomic_store_n(&g_openFailuresLeft, 2, __ATOMIC_SEQ_CST);
  static const MaintenanceJob_t jobs[] = { { "first", static_firstJob } };
  MaintenanceThread_t* maintenance_thread = maintenance_start("fake", SHORT_INTERVAL_MS, jobs, 1);
  TEST_ASSERT_NOT_NULL(maintenance_thread);

  bool has_run = static_waitForCount(&g_firstJobRunCount, 1);
  maintenance_stop(maintenance_thread);

  TEST_ASSERT_TRUE_MESSAGE(has_run, "the job never ran");
  TEST_ASSERT_EQUAL_UINT(3, __atomic_load_n(&g_openCount, __ATOMIC_SEQ_CST));
  TEST_ASSERT_EQUAL_UINT(0, __atomic_load_n(&g_wrongConnRunCount, __ATOMIC_SEQ_CST));
}

void test_connection_opens_once_and_closes_at_stop(void)
{
  static const MaintenanceJob_t jobs[] = { { "first", static_firstJob } };
  MaintenanceThread_t* maintenance_thread = maintenance_start("fake", SHORT_INTERVAL_MS, jobs, 1);
  TEST_ASSERT_NOT_NULL(maintenance_thread);

  bool has_run_three_times = static_waitForCount(&g_firstJobRunCount, 3);
  maintenance_stop(maintenance_thread);

  TEST_ASSERT_TRUE_MESSAGE(has_run_three_times, "the job did not run three times");
  TEST_ASSERT_EQUAL_UINT(1, __atomic_load_n(&g_openCount, __ATOMIC_SEQ_CST));
  TEST_ASSERT_EQUAL_UINT(1, __atomic_load_n(&g_closeCount, __ATOMIC_SEQ_CST));
  TEST_ASSERT_EQUAL_UINT(0, __atomic_load_n(&g_otherCloseCount, __ATOMIC_SEQ_CST));
  TEST_ASSERT_EQUAL_UINT(0, __atomic_load_n(&g_resetCount, __ATOMIC_SEQ_CST));
}

void test_bad_connection_is_reset_before_the_jobs_run(void)
{
  static const MaintenanceJob_t jobs[] = { { "first", static_firstJob } };
  MaintenanceThread_t* maintenance_thread = maintenance_start("fake", SHORT_INTERVAL_MS, jobs, 1);
  TEST_ASSERT_NOT_NULL(maintenance_thread);

  bool has_run_once = static_waitForCount(&g_firstJobRunCount, 1);
  __atomic_store_n(&g_isConnBad, true, __ATOMIC_SEQ_CST);
  bool has_reset = static_waitForCount(&g_resetCount, 1);
  unsigned long run_count_at_reset = __atomic_load_n(&g_firstJobRunCount, __ATOMIC_SEQ_CST);
  bool has_run_after_reset = static_waitForCount(&g_firstJobRunCount, run_count_at_reset + 1);
  maintenance_stop(maintenance_thread);

  TEST_ASSERT_TRUE_MESSAGE(has_run_once, "the job never ran");
  TEST_ASSERT_TRUE_MESSAGE(has_reset, "the bad connection was not reset");
  TEST_ASSERT_TRUE_MESSAGE(has_run_after_reset, "the job did not run after the reset");
  TEST_ASSERT_EQUAL_UINT(1, __atomic_load_n(&g_resetCount, __ATOMIC_SEQ_CST));
  TEST_ASSERT_EQUAL_UINT(1, __atomic_load_n(&g_openCount, __ATOMIC_SEQ_CST));
}

void test_start_refuses_bad_arguments(void)
{
  static const MaintenanceJob_t jobs[]          = { { "first", static_firstJob } };
  static const MaintenanceJob_t unnamed_jobs[]  = { { NULL, static_firstJob } };
  static const MaintenanceJob_t functionless_jobs[] = { { "first", NULL } };

  TEST_ASSERT_NULL(maintenance_start(NULL,   SHORT_INTERVAL_MS, jobs, 1));
  TEST_ASSERT_NULL(maintenance_start("fake", 0u,                jobs, 1));
  TEST_ASSERT_NULL(maintenance_start("fake", SHORT_INTERVAL_MS, NULL, 1));
  TEST_ASSERT_NULL(maintenance_start("fake", SHORT_INTERVAL_MS, jobs, 0));
  TEST_ASSERT_NULL(maintenance_start("fake", SHORT_INTERVAL_MS, jobs, -1));
  TEST_ASSERT_NULL(maintenance_start("fake", SHORT_INTERVAL_MS, unnamed_jobs, 1));
  TEST_ASSERT_NULL(maintenance_start("fake", SHORT_INTERVAL_MS, functionless_jobs, 1));
  maintenance_stop(NULL);

  TEST_ASSERT_EQUAL_UINT(0, __atomic_load_n(&g_openCount, __ATOMIC_SEQ_CST));
}

void test_start_refuses_a_bad_job_past_the_first(void)
{
  static const MaintenanceJob_t functionless_second[] = { { "first", static_firstJob }, { "second", NULL } };
  static const MaintenanceJob_t unnamed_second[] = { { "first", static_firstJob }, { NULL, static_secondJob } };

  TEST_ASSERT_NULL(maintenance_start("fake", SHORT_INTERVAL_MS, functionless_second, 2));
  TEST_ASSERT_NULL(maintenance_start("fake", SHORT_INTERVAL_MS, unnamed_second, 2));
}

void test_registration_gate_test_count(void)
{
  TEST_ASSERT_EQUAL_INT_MESSAGE(14, (int)Unity.NumberOfTests,
    "RUN_TEST list and test definitions have drifted apart - a test may be unregistered");
}

int main(void)
{
  UNITY_BEGIN();
  RUN_TEST(test_jobs_run_in_list_order_on_each_run);
  RUN_TEST(test_no_job_runs_before_the_first_interval);
  RUN_TEST(test_stop_does_not_wait_out_the_interval);
  RUN_TEST(test_each_run_waits_one_interval);
  RUN_TEST(test_each_run_waits_no_more_than_one_interval);
  RUN_TEST(test_no_job_runs_before_an_interval_over_one_second);
  RUN_TEST(test_stop_waits_for_the_run_in_progress);
  RUN_TEST(test_failed_job_stops_neither_the_next_job_nor_the_next_run);
  RUN_TEST(test_jobs_wait_for_a_connection);
  RUN_TEST(test_connection_opens_once_and_closes_at_stop);
  RUN_TEST(test_bad_connection_is_reset_before_the_jobs_run);
  RUN_TEST(test_start_refuses_bad_arguments);
  RUN_TEST(test_start_refuses_a_bad_job_past_the_first);
  RUN_TEST(test_registration_gate_test_count);
  return UNITY_END();
}
