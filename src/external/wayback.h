#ifndef WAYBACK_H
#define WAYBACK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "validate.h"

#define WAYBACK_TIMESTAMP_LEN 14

#define WAYBACK_MEDIA_TYPE_MAX_LEN 127

#define WAYBACK_LATEST_CAPTURE_MAX_COUNT 10

#define WAYBACK_LOOKUP_DEADLINE_MS 10000

typedef struct {
  char  ma_timestamp[WAYBACK_TIMESTAMP_LEN + 1];
  int   m_httpStatus;
  char  ma_mediaType[WAYBACK_MEDIA_TYPE_MAX_LEN + 1];
} WaybackCapture_t;

typedef enum {
  WAYBACK_ORDER_NEWEST_FIRST,
  WAYBACK_ORDER_OLDEST_FIRST,
} WaybackOrder_t;

typedef enum {
  WAYBACK_OK = 0,
  WAYBACK_RATE_LIMITED,
  WAYBACK_UPSTREAM_ERROR,
  WAYBACK_INVALID_NAME,
} WaybackStatus_t;

typedef enum {
  WAYBACKLOOKUP_UNAVAILABLE_NONE = 0,
  WAYBACKLOOKUP_UNAVAILABLE_QUOTA_EXHAUSTED,
} WAYBACKLOOKUPUnavailableReason_t;

typedef struct {
  char  ma_domain[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
} WAYBACKLOOKUPParams_t;

typedef struct {
  char                              ma_domain[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
  WAYBACKLOOKUPUnavailableReason_t  m_unavailableReason;
  unsigned int                      m_retryAfterSeconds;
  WaybackCapture_t                  ma_latestCaptures[WAYBACK_LATEST_CAPTURE_MAX_COUNT];
  int                               m_latestCaptureCount;
  WaybackCapture_t                  m_firstCapture;
} WAYBACKLOOKUPRecord_t;

bool            wayback_tryReadCaptures (const char* body, size_t body_len, WaybackCapture_t* captures_out, int max_count, int* count_out);
WaybackStatus_t wayback_lookupCaptures  (const char* host_name, WaybackOrder_t order, int capture_limit, int64_t deadline_ms, WaybackCapture_t* captures_out, int* count_out, unsigned int* retry_after_seconds_out);

#endif
