#ifndef MONOTONIC_H
#define MONOTONIC_H

#include <stdint.h>
#include <time.h>

int64_t monotonic_nowMs                (void);
void    monotonic_writeDeadlineAfterMs (unsigned int interval_ms, struct timespec* deadline_out);

#endif
