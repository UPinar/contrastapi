#include <assert.h>
#include <stdatomic.h>

#include "rawbody.h"

static atomic_int g_rawBodyThreadCount = 0;

static atomic_int g_rawBodyThreadsInUse = 0;

static _Thread_local bool g_isThisThreadEntered = false;

void rawbody_setThreadCount(int thread_count)
{
  assert(thread_count >= 0);
  atomic_store(&g_rawBodyThreadCount, thread_count);
}

bool rawbody_tryEnter(void)
{
  assert(!g_isThisThreadEntered);

  int threads_in_use = atomic_load(&g_rawBodyThreadsInUse);
  while (threads_in_use < atomic_load(&g_rawBodyThreadCount))
  {
    if (atomic_compare_exchange_weak(&g_rawBodyThreadsInUse, &threads_in_use, threads_in_use + 1))
    {
      g_isThisThreadEntered = true;
      return true;
    }
  }
  return false;
}

void rawbody_leaveIfEntered(void)
{
  if (!g_isThisThreadEntered)
    return;

  g_isThisThreadEntered = false;
  int threads_before = atomic_fetch_sub(&g_rawBodyThreadsInUse, 1);
  assert(threads_before > 0);
  (void)threads_before;
}
