#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "usagelog.h"
#include "monotonic.h"
#include "version.h"

#define USAGELOG_UNKNOWN_NAME    "unknown"

#define USAGELOG_TIME_TEXT_SIZE  sizeof("2026-10-25T00:26:13Z")

#define USAGELOG_FILE_MODE       0644

typedef struct {
  int64_t             m_startMs;
  UsageLogSurface_t   m_surface;
  const char*         mp_endpointName;
  size_t              m_endpointNameLen;
  bool                m_isEndpointFound;
  char                ma_unknownName[USAGELOG_UNKNOWN_NAME_MAX_LEN];
  UsageLogTier_t      m_tier;
  int                 m_statusCode;
  size_t              m_bodyByteCount;
  const char*         mp_runStatus;
  unsigned int        m_creditCount;
  int                 m_itemCount;
  bool                m_isSendFailed;
} UsageLogRecord_t;

static __thread UsageLogRecord_t g_record;

static atomic_bool g_isStarted    = false;
static atomic_int  g_instancePort = 0;

typedef struct {
  pthread_mutex_t   m_mutex;
  char              ma_bytes[USAGELOG_BUFFER_SIZE];
  size_t            m_byteCount;
  unsigned long     m_lostLineCount;
} UsageLogBuffer_t;

static UsageLogBuffer_t g_lineBuffer = { .m_mutex = PTHREAD_MUTEX_INITIALIZER };

typedef struct {
  bool              m_isRunning;
  pthread_t         m_thread;
  pthread_mutex_t   m_mutex;
  pthread_cond_t    m_stopCond;
  bool              m_isStopping;
  const char*       mp_logFilePath;
  unsigned int      m_intervalMs;
  char              ma_buffer[USAGELOG_DRAIN_BUF_SIZE];
  bool              m_isWriteFailing;
  bool              m_isLineCut;
} UsageLogFileWriter_t;

static UsageLogFileWriter_t g_fileWriter = { .m_mutex = PTHREAD_MUTEX_INITIALIZER };

static void           static_appendFormat       (char* line, size_t line_size, size_t* line_len, const char* format, ...) __attribute__((format(printf, 4, 5)));
static void           static_formatTime         (time_t now, char time_out[USAGELOG_TIME_TEXT_SIZE]);
static size_t         static_formatRequestLine  (const UsageLogRecord_t* record, time_t now, int64_t now_ms, char* line, size_t line_size);
static size_t         static_formatLostLine     (unsigned long lost_line_count, time_t now, char* line, size_t line_size);
static size_t         static_formatEventLine    (UsageLogEvent_t event, time_t now, char* line, size_t line_size);
static void           static_appendLine         (const char* line, size_t line_len);
static size_t         static_drainBuffer        (char* lines_out, unsigned long* lost_line_count_out);
static void           static_addLostLines       (unsigned long lost_line_count);
static void*          static_fileWriterRun      (void* unused_arg);
static void           static_writeWaitingLines  (void);
static size_t         static_appendToFile       (const char* bytes, size_t byte_count);
static unsigned long  static_countNewlines      (const char* bytes, size_t byte_count);
static bool           static_isNameLoggable     (const char* name, size_t name_len);
static const char*    static_surfaceName        (UsageLogSurface_t surface);
static const char*    static_tierName           (UsageLogTier_t tier);
static const char*    static_runStatusName      (EndpointRunStatus_t run_status);
static const char*    static_eventName          (UsageLogEvent_t event);

void usagelog_start(int instance_port)
{
  assert(instance_port > 0 && instance_port <= 65535);

  atomic_store(&g_instancePort, instance_port);
  atomic_store(&g_isStarted, true);
}

size_t usagelog_drainLines(char* lines_out, size_t lines_out_size)
{
  assert(lines_out != NULL);
  assert(lines_out_size >= USAGELOG_DRAIN_BUF_SIZE);

  unsigned long lost_line_count = 0;
  size_t line_byte_count = static_drainBuffer(lines_out, &lost_line_count);
  if (lost_line_count > 0)
    line_byte_count += static_formatLostLine(lost_line_count, time(NULL), lines_out + line_byte_count, lines_out_size - line_byte_count);
  lines_out[line_byte_count] = '\0';

  return line_byte_count;
}

void usagelog_beginRequest(void)
{
  memset(&g_record, 0, sizeof(g_record));
  g_record.m_itemCount = -1;
  g_record.m_startMs   = monotonic_nowMs();
}

void usagelog_writeRequest(void)
{
  if (!atomic_load(&g_isStarted))
    return;

  char line[USAGELOG_LINE_MAX_LEN];
  size_t line_len = static_formatRequestLine(&g_record, time(NULL), monotonic_nowMs(), line, sizeof(line));
  static_appendLine(line, line_len);
}

void usagelog_writeEvent(UsageLogEvent_t event)
{
  if (!atomic_load(&g_isStarted))
    return;

  char line[USAGELOG_LINE_MAX_LEN];
  size_t line_len = static_formatEventLine(event, time(NULL), line, sizeof(line));
  static_appendLine(line, line_len);
}

bool usagelog_startFileWriter(const char* log_path, unsigned int interval_ms)
{
  assert(log_path != NULL);
  assert(interval_ms > 0);
  assert(!g_fileWriter.m_isRunning);

  pthread_condattr_t cond_attr;
  if (pthread_condattr_init(&cond_attr) != 0)
    return false;

  bool is_cond_ready = pthread_condattr_setclock(&cond_attr, CLOCK_MONOTONIC) == 0 &&
                       pthread_cond_init(&g_fileWriter.m_stopCond, &cond_attr) == 0;
  pthread_condattr_destroy(&cond_attr);
  if (!is_cond_ready)
    return false;

  g_fileWriter.mp_logFilePath   = log_path;
  g_fileWriter.m_intervalMs     = interval_ms;
  g_fileWriter.m_isStopping     = false;
  g_fileWriter.m_isWriteFailing = false;
  g_fileWriter.m_isLineCut      = false;
  if (pthread_create(&g_fileWriter.m_thread, NULL, static_fileWriterRun, NULL) != 0)
  {
    pthread_cond_destroy(&g_fileWriter.m_stopCond);
    return false;
  }
  g_fileWriter.m_isRunning = true;
  
  return true;
}

void usagelog_stopFileWriter(void)
{
  if (!g_fileWriter.m_isRunning)
    return;

  pthread_mutex_lock(&g_fileWriter.m_mutex);
  g_fileWriter.m_isStopping = true;
  pthread_cond_signal(&g_fileWriter.m_stopCond);
  pthread_mutex_unlock(&g_fileWriter.m_mutex);

  pthread_join(g_fileWriter.m_thread, NULL);
  pthread_cond_destroy(&g_fileWriter.m_stopCond);
  g_fileWriter.m_isRunning = false;
}

void usagelog_setSurface(UsageLogSurface_t surface)
{
  g_record.m_surface = surface;
}

void usagelog_setEndpointName(const Endpoint_t* endpoint)
{
  assert(endpoint != NULL);
  assert(endpoint->mp_httpPath != NULL && endpoint->mp_httpPath[0] == '/');

  const char* endpoint_name = endpoint->mp_httpPath + 1;
  size_t endpoint_name_len  = strlen(endpoint_name);
  assert(endpoint_name_len > 0);
  if (endpoint_name[endpoint_name_len - 1] == '/')
    endpoint_name_len--;

  g_record.mp_endpointName   = endpoint_name;
  g_record.m_endpointNameLen = endpoint_name_len;
  g_record.m_isEndpointFound = true;
}

void usagelog_setWebFileName(const PagesFile_t* file)
{
  assert(file != NULL);
  assert(file->mp_httpPath != NULL);

  g_record.mp_endpointName   = file->mp_httpPath;
  g_record.m_endpointNameLen = strlen(file->mp_httpPath);
  g_record.m_isEndpointFound = true;
}

void usagelog_setMcpMethodName(const char* method_name)
{
  assert(method_name != NULL);

  g_record.mp_endpointName   = method_name;
  g_record.m_endpointNameLen = strlen(method_name);
  g_record.m_isEndpointFound = true;
}

void usagelog_setUnknownName(const char* name, size_t name_len)
{
  assert(name != NULL || name_len == 0);

  g_record.m_isEndpointFound = false;
  if (!static_isNameLoggable(name, name_len))
  {
    g_record.mp_endpointName   = USAGELOG_UNKNOWN_NAME;
    g_record.m_endpointNameLen = sizeof(USAGELOG_UNKNOWN_NAME) - 1;
    return;
  }

  memcpy(g_record.ma_unknownName, name, name_len);
  g_record.mp_endpointName   = g_record.ma_unknownName;
  g_record.m_endpointNameLen = name_len;
}

void usagelog_setTier(UsageLogTier_t tier)
{
  g_record.m_tier = tier;
}

void usagelog_setCreditCount(unsigned int credit_count)
{
  g_record.m_creditCount = credit_count;
}

void usagelog_setItemCount(int item_count)
{
  assert(item_count >= 0);

  g_record.m_itemCount = item_count;
}

void usagelog_setRunStatus(EndpointRunStatus_t run_status)
{
  g_record.mp_runStatus = static_runStatusName(run_status);
}

void usagelog_setGateRefused(void)
{
  g_record.mp_runStatus = "gate_refused";
}

void usagelog_setResponse(int status_code, size_t body_byte_count)
{
  g_record.m_statusCode    = status_code;
  g_record.m_bodyByteCount = body_byte_count;
}

void usagelog_setSendFailed(void)
{
  g_record.m_isSendFailed = true;
}

static void static_appendFormat(char* line, size_t line_size, size_t* line_len, const char* format, ...)
{
  assert(*line_len <= line_size);

  size_t room = line_size - *line_len;
  va_list args;
  va_start(args, format);
  int written = vsnprintf(line + *line_len, room, format, args);
  va_end(args);
  *line_len = (size_t)written < room ? *line_len + (size_t)written : line_size;
}

static void static_formatTime(time_t now, char time_out[USAGELOG_TIME_TEXT_SIZE])
{
  struct tm utc_time;
  if (gmtime_r(&now, &utc_time) == NULL || strftime(time_out, USAGELOG_TIME_TEXT_SIZE, "%Y-%m-%dT%H:%M:%SZ", &utc_time) == 0)
    time_out[0] = '\0';
}

static size_t static_formatRequestLine(const UsageLogRecord_t* record, time_t now, int64_t now_ms, char* line, size_t line_size)
{
  char time_text[USAGELOG_TIME_TEXT_SIZE];
  static_formatTime(now, time_text);

  size_t line_len = 0;
  static_appendFormat(line, line_size, &line_len, "{\"log_format_version\":%d,\"type\":\"request\",\"time\":\"%s\",\"instance_port\":%d,\"surface\":\"%s\"",
                      USAGELOG_LOG_FORMAT_VERSION, time_text, atomic_load(&g_instancePort), static_surfaceName(record->m_surface));
  if (record->mp_endpointName != NULL)
    static_appendFormat(line, line_size, &line_len, ",\"endpoint\":\"%.*s\",\"endpoint_exists\":%s",
                        (int)record->m_endpointNameLen, record->mp_endpointName, record->m_isEndpointFound ? "true" : "false");
  static_appendFormat(line, line_size, &line_len, ",\"tier\":\"%s\",\"status\":%d",
                      static_tierName(record->m_tier), record->m_statusCode);
  if (record->mp_runStatus != NULL)
    static_appendFormat(line, line_size, &line_len, ",\"run_status\":\"%s\"", record->mp_runStatus);
  static_appendFormat(line, line_size, &line_len, ",\"duration_ms\":%lld,\"body_byte_count\":%zu,\"credit_count\":%u",
                      (long long)(now_ms - record->m_startMs), record->m_bodyByteCount, record->m_creditCount);
  if (record->m_itemCount >= 0)
    static_appendFormat(line, line_size, &line_len, ",\"item_count\":%d", record->m_itemCount);
  if (record->m_isSendFailed)
    static_appendFormat(line, line_size, &line_len, ",\"is_send_failed\":true");
  static_appendFormat(line, line_size, &line_len, "}\n");

  return line_len < line_size ? line_len : 0;
}

static size_t static_formatLostLine(unsigned long lost_line_count, time_t now, char* line, size_t line_size)
{
  char time_text[USAGELOG_TIME_TEXT_SIZE];
  static_formatTime(now, time_text);

  size_t line_len = 0;
  static_appendFormat(line, line_size, &line_len, "{\"log_format_version\":%d,\"type\":\"lost\",\"time\":\"%s\",\"instance_port\":%d,\"lost_line_count\":%lu}\n",
                      USAGELOG_LOG_FORMAT_VERSION, time_text, atomic_load(&g_instancePort), lost_line_count);
  return line_len < line_size ? line_len : 0;
}

static size_t static_formatEventLine(UsageLogEvent_t event, time_t now, char* line, size_t line_size)
{
  char time_text[USAGELOG_TIME_TEXT_SIZE];
  static_formatTime(now, time_text);

  size_t line_len = 0;
  static_appendFormat(line, line_size, &line_len, "{\"log_format_version\":%d,\"type\":\"%s\",\"time\":\"%s\",\"instance_port\":%d",
                      USAGELOG_LOG_FORMAT_VERSION, static_eventName(event), time_text, atomic_load(&g_instancePort));
  if (event == USAGELOG_EVENT_START)
    static_appendFormat(line, line_size, &line_len, ",\"version\":\"%s\"", CONTRASTAPI_VERSION);
  static_appendFormat(line, line_size, &line_len, "}\n");

  return line_len < line_size ? line_len : 0;
}

static void static_appendLine(const char* line, size_t line_len)
{
  pthread_mutex_lock(&g_lineBuffer.m_mutex);
  if (line_len == 0 || line_len > USAGELOG_BUFFER_SIZE - g_lineBuffer.m_byteCount)
    g_lineBuffer.m_lostLineCount++;
  else
  {
    memcpy(g_lineBuffer.ma_bytes + g_lineBuffer.m_byteCount, line, line_len);
    g_lineBuffer.m_byteCount += line_len;
  }
  pthread_mutex_unlock(&g_lineBuffer.m_mutex);
}

static size_t static_drainBuffer(char* lines_out, unsigned long* lost_line_count_out)
{
  pthread_mutex_lock(&g_lineBuffer.m_mutex);
  size_t line_byte_count = g_lineBuffer.m_byteCount;
  memcpy(lines_out, g_lineBuffer.ma_bytes, line_byte_count);
  
  *lost_line_count_out = g_lineBuffer.m_lostLineCount;
  g_lineBuffer.m_byteCount     = 0;
  g_lineBuffer.m_lostLineCount = 0;
  pthread_mutex_unlock(&g_lineBuffer.m_mutex);

  return line_byte_count;
}

static void static_addLostLines(unsigned long lost_line_count)
{
  pthread_mutex_lock(&g_lineBuffer.m_mutex);
  g_lineBuffer.m_lostLineCount += lost_line_count;
  pthread_mutex_unlock(&g_lineBuffer.m_mutex);
}

static void* static_fileWriterRun(void* unused_arg)
{
  (void)unused_arg;

  bool is_stopping = false;
  while (!is_stopping)
  {
    struct timespec deadline;
    monotonic_writeDeadlineAfterMs(g_fileWriter.m_intervalMs, &deadline);

    pthread_mutex_lock(&g_fileWriter.m_mutex);
    int wait_status = 0;
    while (!g_fileWriter.m_isStopping && wait_status == 0)
      wait_status = pthread_cond_timedwait(&g_fileWriter.m_stopCond, &g_fileWriter.m_mutex, &deadline);
    is_stopping = g_fileWriter.m_isStopping;
    pthread_mutex_unlock(&g_fileWriter.m_mutex);

    static_writeWaitingLines();
  }
  return NULL;
}

static void static_writeWaitingLines(void)
{
  unsigned long lost_line_count = 0;
  size_t line_byte_count = static_drainBuffer(g_fileWriter.ma_buffer, &lost_line_count);
  size_t byte_count = line_byte_count;
  if (lost_line_count > 0)
  {
    byte_count += static_formatLostLine(lost_line_count, 
                                        time(NULL), 
                                        g_fileWriter.ma_buffer + byte_count, 
                                        sizeof(g_fileWriter.ma_buffer) - byte_count);
  }
  if (byte_count == 0)
    return;

  if (g_fileWriter.m_isLineCut && static_appendToFile("\n", 1) == 1)
    g_fileWriter.m_isLineCut = false;

  size_t written_byte_count = static_appendToFile(g_fileWriter.ma_buffer, byte_count);
  if (written_byte_count > 0)
    g_fileWriter.m_isLineCut = g_fileWriter.ma_buffer[written_byte_count - 1] != '\n';
  if (written_byte_count == byte_count)
  {
    g_fileWriter.m_isWriteFailing = false;
    return;
  }

  unsigned long unwritten_line_count = 0;
  if (written_byte_count < line_byte_count)
    unwritten_line_count = static_countNewlines(g_fileWriter.ma_buffer + written_byte_count, line_byte_count - written_byte_count);
  static_addLostLines(unwritten_line_count + lost_line_count);

  if (!g_fileWriter.m_isWriteFailing)
    fprintf(stderr, "static_writeWaitingLines: cannot write %s: %m\n", g_fileWriter.mp_logFilePath);
  g_fileWriter.m_isWriteFailing = true;
}

static size_t static_appendToFile(const char* bytes, size_t byte_count)
{
  int fd = open(g_fileWriter.mp_logFilePath, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK, USAGELOG_FILE_MODE);
  if (fd < 0)
    return 0;

  size_t written_byte_count = 0;
  while (written_byte_count < byte_count)
  {
    ssize_t write_count = write(fd, bytes + written_byte_count, byte_count - written_byte_count);
    if (write_count < 0 && errno == EINTR)
      continue;
    if (write_count <= 0)
    {
      if (write_count == 0)
        errno = EIO;
      break;
    }
    written_byte_count += (size_t)write_count;
  }

  int write_errno = errno;
  close(fd);
  errno = write_errno;
  return written_byte_count;
}

static unsigned long static_countNewlines(const char* bytes, size_t byte_count)
{
  unsigned long newline_count = 0;
  const char* end = bytes + byte_count;
  for (const char* newline = memchr(bytes, '\n', byte_count); newline != NULL; newline = memchr(newline + 1, '\n', (size_t)(end - newline - 1)))
    newline_count++;
  
  return newline_count;
}

static bool static_isNameLoggable(const char* name, size_t name_len)
{
  if (name_len == 0 || name_len > USAGELOG_UNKNOWN_NAME_MAX_LEN)
    return false;
  if (name[0] < 'a' || name[0] > 'z')
    return false;

  for (size_t i = 1; i < name_len; i++)
  {
    char c = name[i];
    bool is_allowed = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_';
    if (!is_allowed)
      return false;
  }
  return true;
}

static const char* static_surfaceName(UsageLogSurface_t surface)
{
  switch (surface)
  {
    case USAGELOG_SURFACE_CONNECTION: return "connection";
    case USAGELOG_SURFACE_REST:       return "rest";
    case USAGELOG_SURFACE_MCP:        return "mcp";
    case USAGELOG_SURFACE_WEB:        return "web";
  }
  assert(false && "every surface has a case above");
  return "connection";
}

static const char* static_tierName(UsageLogTier_t tier)
{
  switch (tier)
  {
    case USAGELOG_TIER_FREE:        return "free";
    case USAGELOG_TIER_PRO:         return "pro";
    case USAGELOG_TIER_PRO_REFUSED: return "pro_refused";
    case USAGELOG_TIER_X402:        return "x402";
  }
  assert(false && "every tier has a case above");
  return "free";
}

static const char* static_runStatusName(EndpointRunStatus_t run_status)
{
  switch (run_status)
  {
    case ENDPOINT_RUN_OK:                 return "ok";
    case ENDPOINT_RUN_NOT_FOUND:          return "not_found";
    case ENDPOINT_RUN_REFUSED:            return "refused";
    case ENDPOINT_RUN_REFUSED_WITH_BODY:  return "refused_with_body";
    case ENDPOINT_RUN_DEGRADED:           return "degraded";
    case ENDPOINT_RUN_DB_ERROR:           return "db_error";
    case ENDPOINT_RUN_UPSTREAM_ERROR:     return "upstream_error";
    case ENDPOINT_RUN_TARGET_UNREACHABLE: return "target_unreachable";
    case ENDPOINT_RUN_NO_MEMORY:          return "no_memory";
    case ENDPOINT_RUN_NO_CONNECTION:      return "no_connection";
    case ENDPOINT_RUN_NO_CREDIT_BUDGET:   return "no_credit_budget";
    case ENDPOINT_RUN_UNAUTHORIZED:       return "unauthorized";
    case ENDPOINT_RUN_GONE:               return "gone";
  }
  assert(false && "every run status has a case above");
  return "ok";
}

static const char* static_eventName(UsageLogEvent_t event)
{
  switch (event)
  {
    case USAGELOG_EVENT_START:                       return "start";
    case USAGELOG_EVENT_STOP:                        return "stop";
    case USAGELOG_EVENT_DB_DOWN:                     return "db_down";
    case USAGELOG_EVENT_DB_UP:                       return "db_up";
    case USAGELOG_EVENT_DNS_SCAN_CAP_REACHED:        return "dns_scan_cap_reached";
    case USAGELOG_EVENT_TLS_SCAN_CAP_REACHED:        return "tls_scan_cap_reached";
    case USAGELOG_EVENT_RDAP_WHOIS_SCAN_CAP_REACHED: return "rdap_whois_scan_cap_reached";
    case USAGELOG_EVENT_HEADERS_SCAN_CAP_REACHED:    return "headers_scan_cap_reached";
    case USAGELOG_EVENT_CT_SCAN_CAP_REACHED:         return "ct_scan_cap_reached";
  }
  assert(false && "every event has a case above");
  return "start";
}
