#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/eventfd.h>

#include "unity/unity.h"
#include "acceptor.h"
#include "db.h"

#define CLIENT_IP_BUF_SIZE 16

static unsigned long g_processed;
static char          g_clientIp[CLIENT_IP_BUF_SIZE];
static sem_t         g_arrivedSem;
static sem_t         g_releaseSem;
static sigset_t      g_shutdownSignals;

typedef struct {
  int           m_listenFd;
  int           m_wakeFd;
  WorkerPool_t* mp_workerPool;
} AcceptorRun_t;

void setUp(void)
{
  __atomic_store_n(&g_processed, 0, __ATOMIC_SEQ_CST);
  memset(g_clientIp, 0, sizeof(g_clientIp));
  sem_init(&g_arrivedSem, 0, 0);
  sem_init(&g_releaseSem, 0, 0);
}

void tearDown(void)
{
  sem_destroy(&g_arrivedSem);
  sem_destroy(&g_releaseSem);
}

PGconn* db_open(const char* conninfo)
{
  (void)conninfo;
  return NULL;
}

void db_close(PGconn* conn)
{
  (void)conn;
}

static void static_recordHandler(const WorkerJob_t* job, PGconn* conn)
{
  (void)conn;
  memcpy(g_clientIp, job->ma_clientIp, sizeof(g_clientIp) - 1);
  if (job->m_fd >= 0)
    close(job->m_fd);
  __atomic_add_fetch(&g_processed, 1, __ATOMIC_SEQ_CST);
  sem_post(&g_arrivedSem);
}

static void static_gateHandler(const WorkerJob_t* job, PGconn* conn)
{
  (void)conn;
  sem_post(&g_arrivedSem);
  sem_wait(&g_releaseSem);
  if (job->m_fd >= 0)
    close(job->m_fd);
  __atomic_add_fetch(&g_processed, 1, __ATOMIC_SEQ_CST);
}

static void* static_acceptorThread(void* run_arg)
{
  const AcceptorRun_t* run = (const AcceptorRun_t*)run_arg;
  acceptor_acceptUntilShutdown(run->m_listenFd, run->m_wakeFd, run->mp_workerPool);
  return NULL;
}

static int static_openListener(struct sockaddr_in* addr_out)
{
  int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
  TEST_ASSERT_TRUE(listen_fd >= 0);
  memset(addr_out, 0, sizeof(*addr_out));
  addr_out->sin_family      = AF_INET;
  addr_out->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr_out->sin_port        = 0;
  TEST_ASSERT_EQUAL_INT(0, bind(listen_fd, (struct sockaddr*)addr_out, sizeof(*addr_out)));
  TEST_ASSERT_EQUAL_INT(0, listen(listen_fd, 16));
  socklen_t addr_len = sizeof(*addr_out);
  TEST_ASSERT_EQUAL_INT(0, getsockname(listen_fd, (struct sockaddr*)addr_out, &addr_len));
  int listen_flags = fcntl(listen_fd, F_GETFL, 0);
  TEST_ASSERT_TRUE(listen_flags >= 0);
  TEST_ASSERT_EQUAL_INT(0, fcntl(listen_fd, F_SETFL, listen_flags | O_NONBLOCK));
  return listen_fd;
}

static int static_connectClient(const struct sockaddr_in* addr)
{
  int client_fd = socket(AF_INET, SOCK_STREAM, 0);
  TEST_ASSERT_TRUE(client_fd >= 0);
  TEST_ASSERT_EQUAL_INT(0, connect(client_fd, (const struct sockaddr*)addr, sizeof(*addr)));
  return client_fd;
}

static int static_joinWithin(pthread_t thread, long timeout_ms)
{
  struct timespec deadline;
  clock_gettime(CLOCK_REALTIME, &deadline);
  deadline.tv_sec  += timeout_ms / 1000;
  deadline.tv_nsec += (timeout_ms % 1000) * 1000000L;
  if (deadline.tv_nsec >= 1000000000L)
  {
    deadline.tv_sec  += 1;
    deadline.tv_nsec -= 1000000000L;
  }
  return pthread_timedjoin_np(thread, NULL, &deadline);
}

static bool static_semAcquiredWithin(sem_t* sem, long timeout_ms)
{
  struct timespec deadline;
  clock_gettime(CLOCK_REALTIME, &deadline);
  deadline.tv_sec  += timeout_ms / 1000;
  deadline.tv_nsec += (timeout_ms % 1000) * 1000000L;
  if (deadline.tv_nsec >= 1000000000L)
  {
    deadline.tv_sec  += 1;
    deadline.tv_nsec -= 1000000000L;
  }
  return sem_timedwait(sem, &deadline) == 0;
}

void test_wake_descriptor_ends_an_idle_acceptor(void)
{
  struct sockaddr_in addr;
  int listen_fd = static_openListener(&addr);
  int wake_fd   = eventfd(0, 0);
  TEST_ASSERT_TRUE(wake_fd >= 0);
  WorkerPool_t* pool = worker_createPool(1, NULL, static_recordHandler);
  TEST_ASSERT_NOT_NULL(pool);

  AcceptorRun_t run = { listen_fd, wake_fd, pool };
  pthread_t acceptor;
  TEST_ASSERT_EQUAL_INT(0, pthread_create(&acceptor, NULL, static_acceptorThread, &run));
  uint64_t wake_count = 1;
  TEST_ASSERT_EQUAL_INT((int)sizeof(wake_count), (int)write(wake_fd, &wake_count, sizeof(wake_count)));
  int join_status = static_joinWithin(acceptor, 1000);

  worker_shutdown(pool);
  close(wake_fd);
  close(listen_fd);
  TEST_ASSERT_EQUAL_INT(0, join_status);
  TEST_ASSERT_EQUAL_UINT64(0, g_processed);
}

void test_accepted_connection_reaches_the_pool_with_its_address(void)
{
  struct sockaddr_in addr;
  int listen_fd = static_openListener(&addr);
  int wake_fd   = eventfd(0, 0);
  TEST_ASSERT_TRUE(wake_fd >= 0);
  WorkerPool_t* pool = worker_createPool(1, NULL, static_recordHandler);
  TEST_ASSERT_NOT_NULL(pool);

  AcceptorRun_t run = { listen_fd, wake_fd, pool };
  pthread_t acceptor;
  TEST_ASSERT_EQUAL_INT(0, pthread_create(&acceptor, NULL, static_acceptorThread, &run));
  int client_fd = static_connectClient(&addr);
  bool is_served = static_semAcquiredWithin(&g_arrivedSem, 5000);

  uint64_t wake_count = 1;
  TEST_ASSERT_EQUAL_INT((int)sizeof(wake_count), (int)write(wake_fd, &wake_count, sizeof(wake_count)));
  int join_status = static_joinWithin(acceptor, 1000);
  worker_shutdown(pool);
  close(client_fd);
  close(wake_fd);
  close(listen_fd);

  TEST_ASSERT_TRUE(is_served);
  TEST_ASSERT_EQUAL_INT(0, join_status);
  TEST_ASSERT_EQUAL_UINT64(1, g_processed);
  TEST_ASSERT_EQUAL_STRING("127.0.0.1", g_clientIp);
}

void test_sigterm_ends_the_acceptor_and_stops_the_pool(void)
{
  struct sockaddr_in addr;
  int listen_fd = static_openListener(&addr);
  int wake_fd   = eventfd(0, 0);
  TEST_ASSERT_TRUE(wake_fd >= 0);
  WorkerPool_t* pool = worker_createPool(1, NULL, static_recordHandler);
  TEST_ASSERT_NOT_NULL(pool);
  AcceptorShutdownSignalThread_t* signal_thread = acceptor_startShutdownSignalThread(&g_shutdownSignals, wake_fd, pool);
  TEST_ASSERT_NOT_NULL(signal_thread);

  AcceptorRun_t run = { listen_fd, wake_fd, pool };
  pthread_t acceptor;
  TEST_ASSERT_EQUAL_INT(0, pthread_create(&acceptor, NULL, static_acceptorThread, &run));
  TEST_ASSERT_EQUAL_INT(0, kill(getpid(), SIGTERM));
  int join_status = static_joinWithin(acceptor, 1000);

  WorkerJob_t job = { .m_fd = -1, .ma_clientIp = "" };
  bool is_enqueued = worker_enqueue(pool, &job);
  acceptor_stopShutdownSignalThread(signal_thread);
  worker_destroy(pool);
  close(wake_fd);
  close(listen_fd);

  TEST_ASSERT_EQUAL_INT(0, join_status);
  TEST_ASSERT_FALSE(is_enqueued);
}

void test_shutdown_ends_an_acceptor_that_waits_on_a_full_queue(void)
{
  struct sockaddr_in addr;
  int listen_fd = static_openListener(&addr);
  int wake_fd   = eventfd(0, 0);
  TEST_ASSERT_TRUE(wake_fd >= 0);
  WorkerPool_t* pool = worker_createPool(1, NULL, static_gateHandler);
  TEST_ASSERT_NOT_NULL(pool);

  WorkerJob_t job = { .m_fd = -1, .ma_clientIp = "" };
  TEST_ASSERT_TRUE(worker_enqueue(pool, &job));
  TEST_ASSERT_TRUE(static_semAcquiredWithin(&g_arrivedSem, 5000));
  for (int i = 0; i < WORKER_QUEUE_CAPACITY; i++)
    TEST_ASSERT_TRUE(worker_enqueue(pool, &job));

  AcceptorShutdownSignalThread_t* signal_thread = acceptor_startShutdownSignalThread(&g_shutdownSignals, wake_fd, pool);
  TEST_ASSERT_NOT_NULL(signal_thread);
  AcceptorRun_t run = { listen_fd, wake_fd, pool };
  pthread_t acceptor;
  TEST_ASSERT_EQUAL_INT(0, pthread_create(&acceptor, NULL, static_acceptorThread, &run));
  int client_fd = static_connectClient(&addr);
  int early_join_status = static_joinWithin(acceptor, 200);

  TEST_ASSERT_EQUAL_INT(0, kill(getpid(), SIGTERM));
  int join_status = early_join_status == 0 ? 0 : static_joinWithin(acceptor, 1000);
  struct timeval read_timeout = { .tv_sec = 1, .tv_usec = 0 };
  setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &read_timeout, sizeof(read_timeout));
  char byte;
  ssize_t read_len = read(client_fd, &byte, 1);

  for (int i = 0; i < WORKER_QUEUE_CAPACITY + 1; i++)
    sem_post(&g_releaseSem);
  acceptor_stopShutdownSignalThread(signal_thread);
  worker_destroy(pool);
  close(client_fd);
  close(wake_fd);
  close(listen_fd);

  TEST_ASSERT_EQUAL_INT(ETIMEDOUT, early_join_status);
  TEST_ASSERT_EQUAL_INT(0, join_status);
  TEST_ASSERT_EQUAL_INT(0, (int)read_len);
  TEST_ASSERT_EQUAL_UINT64(WORKER_QUEUE_CAPACITY + 1, g_processed);
}

static void* static_stopThread(void* signal_thread_arg)
{
  acceptor_stopShutdownSignalThread((AcceptorShutdownSignalThread_t*)signal_thread_arg);
  return NULL;
}

void test_stop_ends_a_signal_thread_that_got_no_signal(void)
{
  int wake_fd = eventfd(0, 0);
  TEST_ASSERT_TRUE(wake_fd >= 0);
  WorkerPool_t* pool = worker_createPool(1, NULL, static_recordHandler);
  TEST_ASSERT_NOT_NULL(pool);
  AcceptorShutdownSignalThread_t* signal_thread = acceptor_startShutdownSignalThread(&g_shutdownSignals, wake_fd, pool);
  TEST_ASSERT_NOT_NULL(signal_thread);

  pthread_t stopper;
  TEST_ASSERT_EQUAL_INT(0, pthread_create(&stopper, NULL, static_stopThread, signal_thread));
  int join_status = static_joinWithin(stopper, 1000);

  worker_shutdown(pool);
  close(wake_fd);
  TEST_ASSERT_EQUAL_INT(0, join_status);
}

void test_start_refuses_a_bad_argument(void)
{
  int wake_fd = eventfd(0, 0);
  TEST_ASSERT_TRUE(wake_fd >= 0);
  WorkerPool_t* pool = worker_createPool(1, NULL, static_recordHandler);
  TEST_ASSERT_NOT_NULL(pool);

  TEST_ASSERT_NULL(acceptor_startShutdownSignalThread(NULL, wake_fd, pool));
  TEST_ASSERT_NULL(acceptor_startShutdownSignalThread(&g_shutdownSignals, -1, pool));
  TEST_ASSERT_NULL(acceptor_startShutdownSignalThread(&g_shutdownSignals, wake_fd, NULL));

  worker_shutdown(pool);
  close(wake_fd);
}

void test_registration_gate_test_count(void)
{
  TEST_ASSERT_EQUAL_INT_MESSAGE(7, (int)Unity.NumberOfTests,
    "RUN_TEST list and test definitions have drifted apart - a test may be unregistered");
}

int main(void)
{
  sigemptyset(&g_shutdownSignals);
  sigaddset(&g_shutdownSignals, SIGINT);
  sigaddset(&g_shutdownSignals, SIGTERM);
  pthread_sigmask(SIG_BLOCK, &g_shutdownSignals, NULL);

  UNITY_BEGIN();
  RUN_TEST(test_wake_descriptor_ends_an_idle_acceptor);
  RUN_TEST(test_accepted_connection_reaches_the_pool_with_its_address);
  RUN_TEST(test_sigterm_ends_the_acceptor_and_stops_the_pool);
  RUN_TEST(test_shutdown_ends_an_acceptor_that_waits_on_a_full_queue);
  RUN_TEST(test_stop_ends_a_signal_thread_that_got_no_signal);
  RUN_TEST(test_start_refuses_a_bad_argument);
  RUN_TEST(test_registration_gate_test_count);
  return UNITY_END();
}
