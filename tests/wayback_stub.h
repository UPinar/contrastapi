#ifndef WAYBACK_STUB_H
#define WAYBACK_STUB_H

#include "external/wayback.h"

#define WAYBACK_STUB_CALL_MAX_COUNT 2

typedef struct {
  WaybackStatus_t  m_status;
  WaybackCapture_t ma_captures[WAYBACK_LATEST_CAPTURE_MAX_COUNT];
  int              m_captureCount;
  unsigned int     m_retryAfterSeconds;
} WaybackStubAnswer_t;

#endif
