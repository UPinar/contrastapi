#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <time.h>

#include "maintenance.h"
#include "db.h"
#include "monotonic.h"

struct MaintenanceThread {
  const char*             mp_dbConninfo;
  unsigned int            m_intervalMs;
  const MaintenanceJob_t* mp_jobs;
  int                     m_jobCount;

  pthread_t               m_thread;
  pthread_mutex_t         m_mutex;
  pthread_cond_t          m_stopCond;
  bool                    m_isStopRequested;
};

static void* static_maintenanceRun   (void* maintenance_thread_arg);
static void  static_runJobs          (const MaintenanceThread_t* maintenance_thread, PGconn** conn_inout);

MaintenanceThread_t* maintenance_start(const char* db_conninfo, unsigned int interval_ms, const MaintenanceJob_t* jobs, int job_count)
{
  if (!db_conninfo || interval_ms == 0 || !jobs || job_count <= 0)
    return NULL;

  for (int i = 0; i < job_count; i++)
  {
    if (!jobs[i].mp_name || !jobs[i].m_jobFunction)
      return NULL;
  }

  MaintenanceThread_t* maintenance_thread = calloc(1, sizeof(*maintenance_thread));
  if (!maintenance_thread)
    return NULL;

  maintenance_thread->mp_dbConninfo = db_conninfo;
  maintenance_thread->m_intervalMs  = interval_ms;
  maintenance_thread->mp_jobs       = jobs;
  maintenance_thread->m_jobCount    = job_count;

  pthread_condattr_t cond_attr;
  if (pthread_condattr_init(&cond_attr) != 0)
  {
    free(maintenance_thread);
    return NULL;
  }
  bool is_cond_ready =  pthread_condattr_setclock(&cond_attr, CLOCK_MONOTONIC) == 0 && 
                        pthread_cond_init(&maintenance_thread->m_stopCond, &cond_attr) == 0;
  pthread_condattr_destroy(&cond_attr);
  if (!is_cond_ready)
  {
    free(maintenance_thread);
    return NULL;
  }
  pthread_mutex_init(&maintenance_thread->m_mutex, NULL);

  if (pthread_create(&maintenance_thread->m_thread, NULL, static_maintenanceRun, maintenance_thread) != 0)
  {
    fprintf(stderr, "maintenance_start: pthread_create failed\n");
    pthread_mutex_destroy(&maintenance_thread->m_mutex);
    pthread_cond_destroy(&maintenance_thread->m_stopCond);
    free(maintenance_thread);
    return NULL;
  }
  return maintenance_thread;
}

void maintenance_stop(MaintenanceThread_t* maintenance_thread)
{
  if (!maintenance_thread)
    return;

  pthread_mutex_lock(&maintenance_thread->m_mutex);
  maintenance_thread->m_isStopRequested = true;
  pthread_cond_signal(&maintenance_thread->m_stopCond);
  pthread_mutex_unlock(&maintenance_thread->m_mutex);

  pthread_join(maintenance_thread->m_thread, NULL);
  pthread_mutex_destroy(&maintenance_thread->m_mutex);
  pthread_cond_destroy(&maintenance_thread->m_stopCond);
  free(maintenance_thread);
}

static void* static_maintenanceRun(void* maintenance_thread_arg)
{
  assert(maintenance_thread_arg != NULL);

  MaintenanceThread_t* maintenance_thread = (MaintenanceThread_t*)maintenance_thread_arg;
  PGconn* conn = NULL;

  pthread_mutex_lock(&maintenance_thread->m_mutex);
  while (!maintenance_thread->m_isStopRequested)
  {
    struct timespec deadline;
    monotonic_writeDeadlineAfterMs(maintenance_thread->m_intervalMs, &deadline);

    int wait_status = 0;
    while (!maintenance_thread->m_isStopRequested && wait_status == 0)
      wait_status = pthread_cond_timedwait(&maintenance_thread->m_stopCond, &maintenance_thread->m_mutex, &deadline);
    if (maintenance_thread->m_isStopRequested)
      break;

    pthread_mutex_unlock(&maintenance_thread->m_mutex);
    static_runJobs(maintenance_thread, &conn);
    pthread_mutex_lock(&maintenance_thread->m_mutex);
  }
  pthread_mutex_unlock(&maintenance_thread->m_mutex);

  db_close(conn);
  return NULL;
}

static void static_runJobs(const MaintenanceThread_t* maintenance_thread, PGconn** conn_inout)
{
  assert(maintenance_thread != NULL);
  assert(conn_inout != NULL);

  if (!*conn_inout)
  {
    *conn_inout = db_open(maintenance_thread->mp_dbConninfo);
    if (!*conn_inout)
    {
      fprintf(stderr, "static_runJobs: no database connection; no job ran\n");
      return;
    }
  }
  else if (PQstatus(*conn_inout) == CONNECTION_BAD)
    PQreset(*conn_inout);

  for (int i = 0; i < maintenance_thread->m_jobCount; i++)
  {
    const MaintenanceJob_t* job = &maintenance_thread->mp_jobs[i];
    if (!job->m_jobFunction(*conn_inout))
      fprintf(stderr, "static_runJobs: job %s failed\n", job->mp_name);
  }
}
