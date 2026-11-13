#define _GNU_SOURCE

#include <errno.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "unity/unity.h"
#include "worker.h"
#include "db.h"
#include "usagelog.h"

#define EXACT_JOBS 500
#define FIFO_JOBS  64

#define FAKE_CONN ((PGconn*)1)

#define RECONNECT_JOBS 2

#define EVENT_MAX 8

static unsigned long g_openCount;
static unsigned long g_closeCount;
static bool          g_isConnBad;
static bool          g_isOpenFailing;
static unsigned int  g_eventCount;
static UsageLogEvent_t g_events[EVENT_MAX];
static PGconn*       g_handlerConns[RECONNECT_JOBS];

ConnStatusType __wrap_PQstatus(const PGconn* conn);

static unsigned long g_processed;
static unsigned int  g_seen[EXACT_JOBS];
static unsigned long g_payloadMismatches;
static int           g_order[FIFO_JOBS];
static unsigned int  g_orderCount;
static sem_t         g_arrivedSem;
static sem_t         g_releaseSem;
static bool          g_producerEnqueueOk;

void setUp(void)
{
  __atomic_store_n(&g_openCount,  0,     __ATOMIC_SEQ_CST);
  __atomic_store_n(&g_closeCount, 0,     __ATOMIC_SEQ_CST);
  __atomic_store_n(&g_isConnBad,  false, __ATOMIC_SEQ_CST);
  __atomic_store_n(&g_isOpenFailing, false, __ATOMIC_SEQ_CST);
  __atomic_store_n(&g_eventCount, 0,     __ATOMIC_SEQ_CST);
  memset(g_events, 0, sizeof(g_events));
  memset(g_handlerConns, 0, sizeof(g_handlerConns));
  g_processed         = 0;
  g_payloadMismatches = 0;
  g_orderCount        = 0;
  g_producerEnqueueOk = false;
  memset(g_seen,  0, sizeof(g_seen));
  memset(g_order, 0, sizeof(g_order));
}

void tearDown(void) {}

PGconn* db_open(const char* conninfo)
{
  (void)conninfo;
  __atomic_add_fetch(&g_openCount, 1, __ATOMIC_SEQ_CST);
  if (__atomic_load_n(&g_isOpenFailing, __ATOMIC_SEQ_CST))
    return NULL;
  __atomic_store_n(&g_isConnBad, false, __ATOMIC_SEQ_CST);
  return FAKE_CONN;
}

void usagelog_writeEvent(UsageLogEvent_t event)
{
  unsigned int event_index = __atomic_fetch_add(&g_eventCount, 1, __ATOMIC_SEQ_CST);
  if (event_index < EVENT_MAX)
    g_events[event_index] = event;
}

void db_close(PGconn* conn)
{
  if (conn == FAKE_CONN)
    __atomic_add_fetch(&g_closeCount, 1, __ATOMIC_SEQ_CST);
}

ConnStatusType __wrap_PQstatus(const PGconn* conn)
{
  (void)conn;
  return __atomic_load_n(&g_isConnBad, __ATOMIC_SEQ_CST) ? CONNECTION_BAD : CONNECTION_OK;
}

static void static_makeJob(WorkerJob_t* job, int fd)
{
  job->m_fd = fd;
  snprintf(job->ma_clientIp, sizeof(job->ma_clientIp), "%d.%d.0.1", (fd / 256) % 256, fd % 256);
}

static void static_countHandler(const WorkerJob_t* job, PGconn* conn)
{
  (void)job;
  (void)conn;
  __atomic_add_fetch(&g_processed, 1, __ATOMIC_SEQ_CST);
}

static void static_seenHandler(const WorkerJob_t* job, PGconn* conn)
{
  (void)conn;
  char expected_ip[INET_ADDRSTRLEN];
  snprintf(expected_ip, sizeof(expected_ip), "%d.%d.0.1", (job->m_fd / 256) % 256, job->m_fd % 256);

  if (strcmp(expected_ip, job->ma_clientIp) != 0)
    __atomic_add_fetch(&g_payloadMismatches, 1, __ATOMIC_SEQ_CST);

  if (job->m_fd >= 0 && job->m_fd < EXACT_JOBS)
    __atomic_add_fetch(&g_seen[job->m_fd], 1, __ATOMIC_SEQ_CST);
  else
    __atomic_add_fetch(&g_payloadMismatches, 1, __ATOMIC_SEQ_CST);
}

static void static_orderHandler(const WorkerJob_t* job, PGconn* conn)
{
  (void)conn;
  if (g_orderCount < FIFO_JOBS)
    g_order[g_orderCount++] = job->m_fd;
}

static void static_gateHandler(const WorkerJob_t* job, PGconn* conn)
{
  (void)job;
  (void)conn;
  sem_post(&g_arrivedSem);
  sem_wait(&g_releaseSem);
  __atomic_add_fetch(&g_processed, 1, __ATOMIC_SEQ_CST);
}

static void static_connHandler(const WorkerJob_t* job, PGconn* conn)
{
  if (job->m_fd >= 0 && job->m_fd < RECONNECT_JOBS)
    __atomic_store_n(&g_handlerConns[job->m_fd], conn, __ATOMIC_SEQ_CST);
  sem_post(&g_arrivedSem);
}

static void static_enqueueN(WorkerPool_t* pool, int n)
{
  for (int i = 0; i < n; i++)
  {
    WorkerJob_t job;
    static_makeJob(&job, i);
    TEST_ASSERT_TRUE(worker_enqueue(pool, &job));
  }
}

static bool static_semAcquiredWithin(sem_t* sem, int seconds)
{
  struct timespec deadline;
  clock_gettime(CLOCK_REALTIME, &deadline);
  deadline.tv_sec += seconds;
  return sem_timedwait(sem, &deadline) == 0;
}

static void* producer_run(void* pool_arg)
{
  WorkerJob_t job;
  static_makeJob(&job, FIFO_JOBS);
  g_producerEnqueueOk = worker_enqueue((WorkerPool_t*)pool_arg, &job);
  return NULL;
}

void test_all_jobs_processed(void)
{
  WorkerPool_t* pool = worker_createPool(4, NULL, static_countHandler);
  TEST_ASSERT_NOT_NULL(pool);
  static_enqueueN(pool, 200);
  worker_shutdown(pool);
  TEST_ASSERT_EQUAL_UINT64(200, g_processed);
}

void test_wraparound_under_backpressure(void)
{
  WorkerPool_t* pool = worker_createPool(8, NULL, static_countHandler);
  TEST_ASSERT_NOT_NULL(pool);
  static_enqueueN(pool, 1000);
  worker_shutdown(pool);
  TEST_ASSERT_EQUAL_UINT64(1000, g_processed);
}

void test_each_job_exactly_once(void)
{
  WorkerPool_t* pool = worker_createPool(4, NULL, static_seenHandler);
  TEST_ASSERT_NOT_NULL(pool);
  static_enqueueN(pool, EXACT_JOBS);
  worker_shutdown(pool);

  for (int i = 0; i < EXACT_JOBS; i++)
    TEST_ASSERT_EQUAL_UINT(1, g_seen[i]);
  TEST_ASSERT_EQUAL_UINT64(0, g_payloadMismatches);
}

void test_workers_run_concurrently(void)
{
  sem_init(&g_arrivedSem, 0, 0);
  sem_init(&g_releaseSem, 0, 0);

  WorkerPool_t* pool = worker_createPool(2, NULL, static_gateHandler);
  TEST_ASSERT_NOT_NULL(pool);
  static_enqueueN(pool, 2);

  bool is_first_arrived  = static_semAcquiredWithin(&g_arrivedSem, 5);
  bool is_second_arrived = static_semAcquiredWithin(&g_arrivedSem, 5);

  sem_post(&g_releaseSem);
  sem_post(&g_releaseSem);
  worker_shutdown(pool);
  sem_destroy(&g_arrivedSem);
  sem_destroy(&g_releaseSem);

  TEST_ASSERT_TRUE(is_first_arrived);
  TEST_ASSERT_TRUE(is_second_arrived);
  TEST_ASSERT_EQUAL_UINT64(2, g_processed);
}

void test_fifo_order_single_worker(void)
{
  WorkerPool_t* pool = worker_createPool(1, NULL, static_orderHandler);
  TEST_ASSERT_NOT_NULL(pool);
  static_enqueueN(pool, FIFO_JOBS);
  worker_shutdown(pool);

  TEST_ASSERT_EQUAL_UINT(FIFO_JOBS, g_orderCount);
  for (int i = 0; i < FIFO_JOBS; i++)
    TEST_ASSERT_EQUAL_INT(i, g_order[i]);
}

void test_queue_full_blocks_then_resumes(void)
{
  sem_init(&g_arrivedSem, 0, 0);
  sem_init(&g_releaseSem, 0, 0);

  WorkerPool_t* pool = worker_createPool(1, NULL, static_gateHandler);
  TEST_ASSERT_NOT_NULL(pool);

  WorkerJob_t job;
  static_makeJob(&job, 0);
  TEST_ASSERT_TRUE(worker_enqueue(pool, &job));
  TEST_ASSERT_TRUE(static_semAcquiredWithin(&g_arrivedSem, 5));

  for (int i = 0; i < WORKER_QUEUE_CAPACITY; i++)
  {
    static_makeJob(&job, i + 1);
    TEST_ASSERT_TRUE(worker_enqueue(pool, &job));
  }

  pthread_t producer;
  TEST_ASSERT_EQUAL_INT(0, pthread_create(&producer, NULL, producer_run, pool));
  struct timespec deadline;
  clock_gettime(CLOCK_REALTIME, &deadline);
  deadline.tv_sec += 1;
  TEST_ASSERT_EQUAL_INT(ETIMEDOUT, pthread_timedjoin_np(producer, NULL, &deadline));

  for (int i = 0; i < WORKER_QUEUE_CAPACITY + 2; i++)
    sem_post(&g_releaseSem);

  clock_gettime(CLOCK_REALTIME, &deadline);
  deadline.tv_sec += 10;
  TEST_ASSERT_EQUAL_INT(0, pthread_timedjoin_np(producer, NULL, &deadline));
  TEST_ASSERT_TRUE(g_producerEnqueueOk);

  worker_shutdown(pool);
  sem_destroy(&g_arrivedSem);
  sem_destroy(&g_releaseSem);
  TEST_ASSERT_EQUAL_UINT64(WORKER_QUEUE_CAPACITY + 2, g_processed);
}

void test_shutdown_wakes_idle_workers(void)
{
  WorkerPool_t* pool = worker_createPool(4, NULL, static_countHandler);
  TEST_ASSERT_NOT_NULL(pool);
  worker_shutdown(pool);
  TEST_ASSERT_EQUAL_UINT64(0, g_processed);
}

void test_single_worker(void)
{
  WorkerPool_t* pool = worker_createPool(1, NULL, static_countHandler);
  TEST_ASSERT_NOT_NULL(pool);
  static_enqueueN(pool, 50);
  worker_shutdown(pool);
  TEST_ASSERT_EQUAL_UINT64(50, g_processed);
}

void test_enqueue_after_shutdown_request_returns_false(void)
{
  WorkerPool_t* pool = worker_createPool(2, NULL, static_countHandler);
  TEST_ASSERT_NOT_NULL(pool);

  worker_requestShutdown(pool);

  WorkerJob_t job;
  static_makeJob(&job, 0);
  TEST_ASSERT_FALSE(worker_enqueue(pool, &job));

  worker_destroy(pool);
  TEST_ASSERT_EQUAL_UINT64(0, g_processed);
}

void test_request_shutdown_then_destroy_drains(void)
{
  WorkerPool_t* pool = worker_createPool(4, NULL, static_countHandler);
  TEST_ASSERT_NOT_NULL(pool);
  static_enqueueN(pool, 100);
  worker_requestShutdown(pool);
  worker_destroy(pool);
  TEST_ASSERT_EQUAL_UINT64(100, g_processed);
}

void test_shutdown_null_pool_is_noop(void)
{
  worker_shutdown(NULL);
  worker_requestShutdown(NULL);
  worker_destroy(NULL);
  TEST_ASSERT_EQUAL_UINT64(0, g_processed);
}

void test_dropped_connection_is_closed_and_reopened_through_the_backoff(void)
{
  sem_init(&g_arrivedSem, 0, 0);
  WorkerPool_t* pool = worker_createPool(1, "fake", static_connHandler);
  TEST_ASSERT_NOT_NULL(pool);

  for (int waited_ms = 0; __atomic_load_n(&g_openCount, __ATOMIC_SEQ_CST) == 0 && waited_ms < 5000; waited_ms++)
  {
    struct timespec pause = { .tv_sec = 0, .tv_nsec = 1000000L };
    nanosleep(&pause, NULL);
  }
  TEST_ASSERT_EQUAL_UINT64(1, g_openCount);

  for (int i = 0; i < RECONNECT_JOBS; i++)
  {
    __atomic_store_n(&g_isConnBad, true, __ATOMIC_SEQ_CST);
    WorkerJob_t job;
    static_makeJob(&job, i);
    TEST_ASSERT_TRUE(worker_enqueue(pool, &job));
    TEST_ASSERT_TRUE(static_semAcquiredWithin(&g_arrivedSem, 5));
  }
  worker_shutdown(pool);
  sem_destroy(&g_arrivedSem);

  TEST_ASSERT_EQUAL_PTR(FAKE_CONN, g_handlerConns[0]);
  TEST_ASSERT_NULL(g_handlerConns[1]);
  TEST_ASSERT_EQUAL_UINT64(2, g_openCount);
  TEST_ASSERT_EQUAL_UINT64(2, g_closeCount);
  TEST_ASSERT_EQUAL_UINT(3, g_eventCount);
  TEST_ASSERT_EQUAL_INT(USAGELOG_EVENT_DB_DOWN, g_events[0]);
  TEST_ASSERT_EQUAL_INT(USAGELOG_EVENT_DB_UP,   g_events[1]);
  TEST_ASSERT_EQUAL_INT(USAGELOG_EVENT_DB_DOWN, g_events[2]);
}

void test_first_open_that_fails_writes_db_down_once(void)
{
  __atomic_store_n(&g_isOpenFailing, true, __ATOMIC_SEQ_CST);
  sem_init(&g_arrivedSem, 0, 0);
  WorkerPool_t* pool = worker_createPool(1, "fake", static_connHandler);
  TEST_ASSERT_NOT_NULL(pool);

  WorkerJob_t job;
  static_makeJob(&job, 0);
  __atomic_store_n(&g_handlerConns[0], FAKE_CONN, __ATOMIC_SEQ_CST);
  TEST_ASSERT_TRUE(worker_enqueue(pool, &job));
  TEST_ASSERT_TRUE(static_semAcquiredWithin(&g_arrivedSem, 5));
  worker_shutdown(pool);
  sem_destroy(&g_arrivedSem);

  TEST_ASSERT_EQUAL_UINT64(2, g_openCount);
  TEST_ASSERT_NULL(g_handlerConns[0]);
  TEST_ASSERT_EQUAL_UINT(1, g_eventCount);
  TEST_ASSERT_EQUAL_INT(USAGELOG_EVENT_DB_DOWN, g_events[0]);
}

void test_request_shutdown_releases_a_blocked_producer(void)
{
  sem_init(&g_arrivedSem, 0, 0);
  sem_init(&g_releaseSem, 0, 0);

  WorkerPool_t* pool = worker_createPool(1, NULL, static_gateHandler);
  TEST_ASSERT_NOT_NULL(pool);

  WorkerJob_t job;
  static_makeJob(&job, 0);
  TEST_ASSERT_TRUE(worker_enqueue(pool, &job));
  TEST_ASSERT_TRUE(static_semAcquiredWithin(&g_arrivedSem, 5));
  for (int i = 0; i < WORKER_QUEUE_CAPACITY; i++)
  {
    static_makeJob(&job, i + 1);
    TEST_ASSERT_TRUE(worker_enqueue(pool, &job));
  }

  g_producerEnqueueOk = true;
  pthread_t producer;
  TEST_ASSERT_EQUAL_INT(0, pthread_create(&producer, NULL, producer_run, pool));
  struct timespec deadline;
  clock_gettime(CLOCK_REALTIME, &deadline);
  deadline.tv_nsec += 200000000L;
  if (deadline.tv_nsec >= 1000000000L)
  {
    deadline.tv_sec  += 1;
    deadline.tv_nsec -= 1000000000L;
  }
  TEST_ASSERT_EQUAL_INT(ETIMEDOUT, pthread_timedjoin_np(producer, NULL, &deadline));

  worker_requestShutdown(pool);
  clock_gettime(CLOCK_REALTIME, &deadline);
  deadline.tv_sec += 1;
  int join_status = pthread_timedjoin_np(producer, NULL, &deadline);

  for (int i = 0; i < WORKER_QUEUE_CAPACITY + 1; i++)
    sem_post(&g_releaseSem);
  worker_destroy(pool);
  sem_destroy(&g_arrivedSem);
  sem_destroy(&g_releaseSem);

  TEST_ASSERT_EQUAL_INT(0, join_status);
  TEST_ASSERT_FALSE(g_producerEnqueueOk);
  TEST_ASSERT_EQUAL_UINT64(WORKER_QUEUE_CAPACITY + 1, g_processed);
}

void test_bad_args_return_null(void)
{
  TEST_ASSERT_NULL(worker_createPool(0, NULL, static_countHandler));
  TEST_ASSERT_NULL(worker_createPool(-1, NULL, static_countHandler));
  TEST_ASSERT_NULL(worker_createPool(4, NULL, NULL));
}

void test_pool_without_a_database_writes_no_event(void)
{
  WorkerPool_t* pool = worker_createPool(1, NULL, static_countHandler);
  TEST_ASSERT_NOT_NULL(pool);
  static_enqueueN(pool, 3);
  worker_shutdown(pool);
  TEST_ASSERT_EQUAL_UINT64(3, g_processed);
  TEST_ASSERT_EQUAL_UINT(0, g_eventCount);
}

int main(void)
{
  UNITY_BEGIN();
  RUN_TEST(test_all_jobs_processed);
  RUN_TEST(test_wraparound_under_backpressure);
  RUN_TEST(test_each_job_exactly_once);
  RUN_TEST(test_workers_run_concurrently);
  RUN_TEST(test_fifo_order_single_worker);
  RUN_TEST(test_queue_full_blocks_then_resumes);
  RUN_TEST(test_shutdown_wakes_idle_workers);
  RUN_TEST(test_single_worker);
  RUN_TEST(test_enqueue_after_shutdown_request_returns_false);
  RUN_TEST(test_request_shutdown_then_destroy_drains);
  RUN_TEST(test_shutdown_null_pool_is_noop);
  RUN_TEST(test_bad_args_return_null);
  RUN_TEST(test_dropped_connection_is_closed_and_reopened_through_the_backoff);
  RUN_TEST(test_first_open_that_fails_writes_db_down_once);
  RUN_TEST(test_request_shutdown_releases_a_blocked_producer);
  RUN_TEST(test_pool_without_a_database_writes_no_event);
  return UNITY_END();
}
