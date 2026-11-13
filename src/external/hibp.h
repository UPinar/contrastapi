#ifndef HIBP_H
#define HIBP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "validate.h"

#define HIBP_PREFIX_LEN   5
#define HIBP_SUFFIX_LEN   (VALIDATE_SHA1_HEX_LEN - HIBP_PREFIX_LEN)

typedef enum {
  HIBP_OK = 0,
  HIBP_RATE_LIMITED,
  HIBP_UPSTREAM_ERROR,
  HIBP_INVALID_HASH,
} HibpStatus_t;

typedef struct {
  char     ma_hashPrefix[HIBP_PREFIX_LEN + 1];
  uint64_t m_breachCount;
} PASSWORDCHECKRecord_t;

typedef struct {
  char ma_sha1Hash[VALIDATE_SHA1_HEX_LEN + 1];
} PASSWORDCHECKParams_t;

bool         hibp_tryReadBreachCount  (const char* body, size_t body_len, const char* suffix, uint64_t* breach_count_out);
HibpStatus_t hibp_check               (const char* sha1_hex, PASSWORDCHECKRecord_t* record_out, unsigned int* retry_after_seconds_out);

#endif
