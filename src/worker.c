#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <time.h>

#include "worker.h"
#include "db.h"
#include "usagelog.h"

#define DB_RECONNECT_BACKOFF_SEC 5

struct WorkerPool {
  unsigned int            m_threadCount;
  pthread_t*              mp_threads;
  const char*             mp_dbConninfo;
  WorkerHandlerFunction_t m_workerHandlerFunction;

  pthread_mutex_t         m_mutex;
  pthread_cond_t          m_threadCondNotEmpty;
  pthread_cond_t          m_threadCondNotFull;

  WorkerJob_t*            mp_workerJobs;
  unsigned int            m_capacity;
  unsigned int            m_head;
  unsigned int            m_tail;
  unsigned int            m_count;

  bool                    m_shutdown;
};

static void* static_workerRun(void* worker_pool_arg);


WorkerPool_t* worker_createPool(int thread_count, const char* db_conninfo, WorkerHandlerFunction_t handler_function)
{
  if (thread_count <= 0 || handler_function == NULL)
    return NULL;

  WorkerPool_t* worker_pool = calloc(1, sizeof(*worker_pool));
  if (!worker_pool)
    return NULL;

  worker_pool->m_capacity    = WORKER_QUEUE_CAPACITY;
  worker_pool->mp_workerJobs = calloc((size_t)worker_pool->m_capacity, sizeof(WorkerJob_t));
  worker_pool->mp_threads    = calloc((size_t)thread_count, sizeof(pthread_t));
  if (!worker_pool->mp_workerJobs || !worker_pool->mp_threads)
  {
    free(worker_pool->mp_workerJobs);
    free(worker_pool->mp_threads);
    free(worker_pool);
    return NULL;
  }

  worker_pool->mp_dbConninfo           = db_conninfo;
  worker_pool->m_workerHandlerFunction = handler_function;
  pthread_mutex_init(&worker_pool->m_mutex, NULL);
  pthread_cond_init(&worker_pool->m_threadCondNotEmpty, NULL);
  pthread_cond_init(&worker_pool->m_threadCondNotFull, NULL);

  for (int i = 0; i < thread_count; i++)
  {
    if (pthread_create(&worker_pool->mp_threads[i], NULL, static_workerRun, worker_pool) != 0)
    {
      fprintf(stderr, "worker_createPool: pthread_create failed at %d/%d\n", i, thread_count);
      worker_pool->m_threadCount = i;
      worker_shutdown(worker_pool);
      return NULL;
    }
  }
  worker_pool->m_threadCount = thread_count;
  return worker_pool;
}

bool worker_enqueue(WorkerPool_t* worker_pool, const WorkerJob_t* job)
{
  assert(worker_pool != NULL);
  assert(job  != NULL);

  pthread_mutex_lock(&worker_pool->m_mutex);
  while (worker_pool->m_count == worker_pool->m_capacity && !worker_pool->m_shutdown)
    pthread_cond_wait(&worker_pool->m_threadCondNotFull, &worker_pool->m_mutex);

  if (worker_pool->m_shutdown)
  {
    pthread_mutex_unlock(&worker_pool->m_mutex);
    return false;
  }

  worker_pool->mp_workerJobs[worker_pool->m_tail] = *job;
  worker_pool->m_tail = (worker_pool->m_tail + 1) % worker_pool->m_capacity;
  worker_pool->m_count++;
  pthread_cond_signal(&worker_pool->m_threadCondNotEmpty);
  pthread_mutex_unlock(&worker_pool->m_mutex);
  return true;
}

void worker_requestShutdown(WorkerPool_t* worker_pool)
{
  if (!worker_pool)
    return;

  pthread_mutex_lock(&worker_pool->m_mutex);
  worker_pool->m_shutdown = true;
  pthread_cond_broadcast(&worker_pool->m_threadCondNotEmpty);
  pthread_cond_broadcast(&worker_pool->m_threadCondNotFull);
  pthread_mutex_unlock(&worker_pool->m_mutex);
}

void worker_destroy(WorkerPool_t* worker_pool)
{
  if (!worker_pool)
    return;

  assert(worker_pool->m_shutdown);

  for (unsigned int i = 0; i < worker_pool->m_threadCount; i++)
    pthread_join(worker_pool->mp_threads[i], NULL);

  pthread_mutex_destroy(&worker_pool->m_mutex);
  pthread_cond_destroy(&worker_pool->m_threadCondNotEmpty);
  pthread_cond_destroy(&worker_pool->m_threadCondNotFull);
  free(worker_pool->mp_workerJobs);
  free(worker_pool->mp_threads);
  free(worker_pool);
}

void worker_shutdown(WorkerPool_t* worker_pool)
{
  worker_requestShutdown(worker_pool);
  worker_destroy(worker_pool);
}

static void* static_workerRun(void* worker_pool_arg)
{
  assert(worker_pool_arg != NULL);

  WorkerPool_t* worker_pool = (WorkerPool_t*)worker_pool_arg;
  PGconn* conn = worker_pool->mp_dbConninfo ? db_open(worker_pool->mp_dbConninfo) : NULL;
  if (worker_pool->mp_dbConninfo && !conn)
  {
    fprintf(stderr, "static_workerRun: db_open failed; serving with degraded connection\n");
    usagelog_writeEvent(USAGELOG_EVENT_DB_DOWN);
  }

  struct timespec last_db_attempt_time = { 0, 0 };

  for (;;)
  {
    pthread_mutex_lock(&worker_pool->m_mutex);
    while (worker_pool->m_count == 0 && !worker_pool->m_shutdown)
      pthread_cond_wait(&worker_pool->m_threadCondNotEmpty, &worker_pool->m_mutex);

    if (worker_pool->m_count == 0 && worker_pool->m_shutdown)
    {
      pthread_mutex_unlock(&worker_pool->m_mutex);
      break;
    }

    WorkerJob_t job = worker_pool->mp_workerJobs[worker_pool->m_head];
    worker_pool->m_head = (worker_pool->m_head + 1) % worker_pool->m_capacity;
    worker_pool->m_count--;
    pthread_cond_signal(&worker_pool->m_threadCondNotFull);
    pthread_mutex_unlock(&worker_pool->m_mutex);

    if (conn && PQstatus(conn) == CONNECTION_BAD)
    {
      db_close(conn);
      conn = NULL;
      usagelog_writeEvent(USAGELOG_EVENT_DB_DOWN);
    }
    if (!conn)
    {
      struct timespec now;
      clock_gettime(CLOCK_MONOTONIC, &now);
      if (worker_pool->mp_dbConninfo && now.tv_sec - last_db_attempt_time.tv_sec >= DB_RECONNECT_BACKOFF_SEC)
      {
        last_db_attempt_time = now;
        conn = db_open(worker_pool->mp_dbConninfo);
        if (conn)
          usagelog_writeEvent(USAGELOG_EVENT_DB_UP);
      }
    }

    worker_pool->m_workerHandlerFunction(&job, conn);
  }

  db_close(conn);
  return NULL;
}
