#ifndef RAWBODY_H
#define RAWBODY_H

#include <stdbool.h>

void rawbody_setThreadCount  (int thread_count);
bool rawbody_tryEnter        (void);
void rawbody_leaveIfEntered  (void);

#endif
