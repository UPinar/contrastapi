#include <assert.h>
#include <ctype.h>
#include <stddef.h>
#include <stdint.h>

#include "retryafter.h"

unsigned int retryafter_parseSeconds(const char* header_value)
{
  if (header_value == NULL || header_value[0] == '\0')
    return RETRYAFTER_DEFAULT_SECONDS;

  unsigned int seconds = 0;
  for (const char* digit = header_value; *digit != '\0'; digit++)
  {
    if (!isdigit((unsigned char)*digit))
      return RETRYAFTER_DEFAULT_SECONDS;
    if (seconds <= RETRYAFTER_MAX_SECONDS)
      seconds = seconds * 10u + (unsigned int)(*digit - '0');
  }

  if (seconds < RETRYAFTER_MIN_SECONDS)
    return RETRYAFTER_MIN_SECONDS;
  else if (seconds > RETRYAFTER_MAX_SECONDS)
    return RETRYAFTER_MAX_SECONDS;
  return seconds;
}

bool retryafter_tryReadResetSeconds(const char* header_value, time_t now, unsigned int* seconds_out)
{
  assert(seconds_out != NULL);

  if (now < 0 || header_value == NULL || header_value[0] == '\0')
    return false;

  uint64_t now_seconds   = (uint64_t)now;
  uint64_t latest_reset  = now_seconds + RETRYAFTER_RESET_MAX_SECONDS;
  uint64_t reset_seconds = 0;
  for (const char* digit = header_value; *digit != '\0'; digit++)
  {
    if (!isdigit((unsigned char)*digit))
      return false;
    if (reset_seconds <= latest_reset)
      reset_seconds = reset_seconds * 10u + (uint64_t)(*digit - '0');
  }

  if (reset_seconds <= now_seconds)
    *seconds_out = RETRYAFTER_MIN_SECONDS;
  else if (reset_seconds > latest_reset)
    *seconds_out = RETRYAFTER_RESET_MAX_SECONDS;
  else
    *seconds_out = (unsigned int)(reset_seconds - now_seconds);
  return true;
}
