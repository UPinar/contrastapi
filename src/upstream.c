#include <assert.h>
#include <stdatomic.h>

#include "upstream.h"

static atomic_int g_upstreamThreadCount = 0;

static atomic_int g_upstreamThreadsInUse = 0;

void upstream_setThreadCount(int thread_count)
{
  assert(thread_count >= 0);
  atomic_store(&g_upstreamThreadCount, thread_count);
}

bool upstream_tryEnter(void)
{
  int threads_in_use = atomic_load(&g_upstreamThreadsInUse);
  while (threads_in_use < atomic_load(&g_upstreamThreadCount))
  {
    if (atomic_compare_exchange_weak(&g_upstreamThreadsInUse, &threads_in_use, threads_in_use + 1))
      return true;
  }
  return false;
}

void upstream_leave(void)
{
  int threads_before = atomic_fetch_sub(&g_upstreamThreadsInUse, 1);
  assert(threads_before > 0);
  (void)threads_before;
}
