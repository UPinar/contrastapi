#ifndef USAGELOG_H
#define USAGELOG_H

#include <stdbool.h>
#include <stddef.h>

#include "endpoint.h"
#include "pages.h"

#define USAGELOG_LOG_FORMAT_VERSION    1

#define USAGELOG_UNKNOWN_NAME_MAX_LEN  32

#define USAGELOG_LINE_MAX_LEN          512

#define USAGELOG_BUFFER_SIZE           65536

#define USAGELOG_DRAIN_BUF_SIZE        (USAGELOG_BUFFER_SIZE + USAGELOG_LINE_MAX_LEN)

#define USAGELOG_WRITE_INTERVAL_MS     1000

#define USAGELOG_RETENTION_DAYS        90

typedef enum {
  USAGELOG_SURFACE_CONNECTION = 0,
  USAGELOG_SURFACE_REST,
  USAGELOG_SURFACE_MCP,
  USAGELOG_SURFACE_WEB
} UsageLogSurface_t;

typedef enum {
  USAGELOG_TIER_FREE = 0,
  USAGELOG_TIER_PRO,
  USAGELOG_TIER_PRO_REFUSED,
  USAGELOG_TIER_X402
} UsageLogTier_t;

typedef enum {
  USAGELOG_EVENT_START = 0,
  USAGELOG_EVENT_STOP,
  USAGELOG_EVENT_DB_DOWN,
  USAGELOG_EVENT_DB_UP,
  USAGELOG_EVENT_DNS_SCAN_CAP_REACHED,
  USAGELOG_EVENT_TLS_SCAN_CAP_REACHED,
  USAGELOG_EVENT_RDAP_WHOIS_SCAN_CAP_REACHED,
  USAGELOG_EVENT_HEADERS_SCAN_CAP_REACHED,
  USAGELOG_EVENT_CT_SCAN_CAP_REACHED
} UsageLogEvent_t;

void   usagelog_start           (int instance_port);
size_t usagelog_drainLines      (char* lines_out, size_t lines_out_size);
bool   usagelog_startFileWriter (const char* log_path, unsigned int interval_ms);
void   usagelog_stopFileWriter  (void);
void   usagelog_writeEvent      (UsageLogEvent_t event);

void   usagelog_beginRequest    (void);
void   usagelog_writeRequest   (void);

void   usagelog_setSurface      (UsageLogSurface_t surface);
void   usagelog_setEndpointName (const Endpoint_t* endpoint);
void   usagelog_setWebFileName  (const PagesFile_t* file);
void   usagelog_setMcpMethodName(const char* method_name);
void   usagelog_setUnknownName  (const char* name, size_t name_len);
void   usagelog_setTier         (UsageLogTier_t tier);
void   usagelog_setCreditCount  (unsigned int credit_count);
void   usagelog_setItemCount    (int item_count);
void   usagelog_setRunStatus    (EndpointRunStatus_t run_status);
void   usagelog_setGateRefused  (void);
void   usagelog_setResponse     (int status_code, size_t body_byte_count);
void   usagelog_setSendFailed   (void);

#endif
