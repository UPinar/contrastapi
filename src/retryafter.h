#ifndef RETRYAFTER_H
#define RETRYAFTER_H

#include <stdbool.h>
#include <time.h>

#define RETRYAFTER_DEFAULT_SECONDS  60u
#define RETRYAFTER_MIN_SECONDS      1u
#define RETRYAFTER_MAX_SECONDS      3600u

#define RETRYAFTER_HEADER_NAME  "Retry-After"

#define RETRYAFTER_RESET_HEADER_NAME   "X-RateLimit-Reset"
#define RETRYAFTER_RESET_MAX_SECONDS   86400u

unsigned int retryafter_parseSeconds         (const char* header_value);
bool         retryafter_tryReadResetSeconds (const char* header_value, time_t now, unsigned int* seconds_out);

#endif
