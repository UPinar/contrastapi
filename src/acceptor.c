#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "acceptor.h"

struct AcceptorShutdownSignalThread {
  sigset_t      m_shutdownSignals;
  int           m_wakeFd;
  WorkerPool_t* mp_workerPool;
  pthread_t     m_thread;
  bool          m_isSignalReceived;
};

static void* static_waitForShutdownSignal      (void* signal_thread_arg);
static void  static_acceptAndEnqueueConnection (int listen_fd, WorkerPool_t* worker_pool);

AcceptorShutdownSignalThread_t* acceptor_startShutdownSignalThread(const sigset_t* signals, int wake_fd, WorkerPool_t* worker_pool)
{
  if (!signals || wake_fd < 0 || !worker_pool)
    return NULL;

  AcceptorShutdownSignalThread_t* signal_thread = calloc(1, sizeof(*signal_thread));
  if (!signal_thread)
    return NULL;

  signal_thread->m_shutdownSignals = *signals;
  signal_thread->m_wakeFd          = wake_fd;
  signal_thread->mp_workerPool     = worker_pool;
  if (pthread_create(&signal_thread->m_thread, NULL, static_waitForShutdownSignal, signal_thread) != 0)
  {
    fprintf(stderr, "acceptor_startShutdownSignalThread: pthread_create failed\n");
    free(signal_thread);
    return NULL;
  }
  return signal_thread;
}

void acceptor_stopShutdownSignalThread(AcceptorShutdownSignalThread_t* signal_thread)
{
  if (!signal_thread)
    return;

  if (!__atomic_load_n(&signal_thread->m_isSignalReceived, __ATOMIC_SEQ_CST))
  {
    for (int signal_number = 1; signal_number < NSIG; signal_number++)
    {
      if (sigismember(&signal_thread->m_shutdownSignals, signal_number) == 1)
      {
        pthread_kill(signal_thread->m_thread, signal_number);
        break;
      }
    }
  }
  pthread_join(signal_thread->m_thread, NULL);
  free(signal_thread);
}

void acceptor_acceptUntilShutdown(int listen_fd, int wake_fd, WorkerPool_t* worker_pool)
{
  assert(listen_fd >= 0);
  assert(wake_fd >= 0);
  assert(worker_pool != NULL);

  struct pollfd poll_fds[2] = {
    { .fd = listen_fd, .events = POLLIN },
    { .fd = wake_fd,   .events = POLLIN },
  };
  for (;;)
  {
    if (poll(poll_fds, 2, -1) < 0)
    {
      if (errno == EINTR)
        continue;
      perror("acceptor_acceptUntilShutdown: poll");
      return;
    }
    if (poll_fds[1].revents != 0)
      return;
    if (poll_fds[0].revents != 0)
      static_acceptAndEnqueueConnection(listen_fd, worker_pool);
  }
}

static void* static_waitForShutdownSignal(void* signal_thread_arg)
{
  assert(signal_thread_arg != NULL);

  AcceptorShutdownSignalThread_t* signal_thread = (AcceptorShutdownSignalThread_t*)signal_thread_arg;
  int signal_number = 0;
  if (sigwait(&signal_thread->m_shutdownSignals, &signal_number) != 0)
    fprintf(stderr, "static_waitForShutdownSignal: sigwait failed\n");

  __atomic_store_n(&signal_thread->m_isSignalReceived, true, __ATOMIC_SEQ_CST);

  worker_requestShutdown(signal_thread->mp_workerPool);
  uint64_t wake_count = 1;
  if (write(signal_thread->m_wakeFd, &wake_count, sizeof(wake_count)) != (ssize_t)sizeof(wake_count))
    perror("static_waitForShutdownSignal: write");

  return NULL;
}

static void static_acceptAndEnqueueConnection(int listen_fd, WorkerPool_t* worker_pool)
{
  struct sockaddr_in client_addr;
  socklen_t client_addr_len = sizeof(client_addr);
  int client_fd = accept(listen_fd, (struct sockaddr*)&client_addr, &client_addr_len);
  if (client_fd < 0)
  {
    if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
      return;
    else if (errno == EMFILE || errno == ENFILE)
    {
      static time_t last_report_time = 0;
      time_t now = time(NULL);
      if (now != last_report_time)
      {
        perror("static_acceptAndEnqueueConnection: accept");
        last_report_time = now;
      }
      struct timespec backoff = { .tv_sec = 0, .tv_nsec = ACCEPTOR_BACKOFF_NSEC };
      nanosleep(&backoff, NULL);
    }
    else
      perror("static_acceptAndEnqueueConnection: accept");
    
    return;
  }

  WorkerJob_t worker_job;
  worker_job.m_fd = client_fd;
  if (!inet_ntop(AF_INET, &client_addr.sin_addr, worker_job.ma_clientIp, sizeof(worker_job.ma_clientIp)))
  {
    close(client_fd);
    return;
  }

  if (!worker_enqueue(worker_pool, &worker_job))
    close(client_fd);
}
