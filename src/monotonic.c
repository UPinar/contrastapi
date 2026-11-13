#include <assert.h>
#include <time.h>

#include "monotonic.h"

#define MONOTONIC_MSEC_PER_SEC   1000u
#define MONOTONIC_NSEC_PER_MSEC  1000000L
#define MONOTONIC_NSEC_PER_SEC   1000000000L

int64_t monotonic_nowMs(void)
{
  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);
  return (int64_t)now.tv_sec * MONOTONIC_MSEC_PER_SEC + now.tv_nsec / MONOTONIC_NSEC_PER_MSEC;
}

void monotonic_writeDeadlineAfterMs(unsigned int interval_ms, struct timespec* deadline_out)
{
  assert(deadline_out != NULL);

  clock_gettime(CLOCK_MONOTONIC, deadline_out);
  deadline_out->tv_sec  += (time_t)(interval_ms / MONOTONIC_MSEC_PER_SEC);
  deadline_out->tv_nsec += (long)(interval_ms % MONOTONIC_MSEC_PER_SEC) * MONOTONIC_NSEC_PER_MSEC;
  if (deadline_out->tv_nsec >= MONOTONIC_NSEC_PER_SEC)
  {
    deadline_out->tv_sec  += 1;
    deadline_out->tv_nsec -= MONOTONIC_NSEC_PER_SEC;
  }
}
