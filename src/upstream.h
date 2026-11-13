#ifndef UPSTREAM_H
#define UPSTREAM_H

#include <stdbool.h>

void upstream_setThreadCount (int thread_count);
bool upstream_tryEnter       (void);
void upstream_leave          (void);

#endif
