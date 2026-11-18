#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "unity/unity.h"
#include "usagelog.h"
#include "version.h"

#define TEST_TIME             ((time_t)1761352000)
#define TEST_TIME_TEXT        "2025-10-25T00:26:40Z"
#define TEST_DAY_START        ((time_t)1761350400)
#define TEST_SECONDS_PER_DAY  86400
#define TEST_INSTANCE_PORT    8002

#define THREAD_COUNT          4
#define LINES_PER_THREAD      50

static int64_t g_nowMs = 0;

static time_t g_nowEpoch = TEST_TIME;

static atomic_bool        g_isClockBarrierArmed = false;
static pthread_barrier_t  g_clockBarrier;
static __thread bool      t_hasWaitedAtClock    = false;

time_t __wrap_time(time_t* time_out)
{
  if (atomic_load(&g_isClockBarrierArmed) && !t_hasWaitedAtClock)
  {
    t_hasWaitedAtClock = true;
    pthread_barrier_wait(&g_clockBarrier);
  }
  if (time_out != NULL)
    *time_out = g_nowEpoch;
  return g_nowEpoch;
}

int64_t __wrap_monotonic_nowMs(void)
{
  return g_nowMs;
}

static char g_lines[USAGELOG_DRAIN_BUF_SIZE];

static atomic_int  g_nextWriteErrno     = 0;
static atomic_long g_nextWriteByteLimit = -1;
static atomic_int  g_writeErrno         = 0;

static atomic_int  g_overflowLineCount  = 0;

static atomic_int  g_writeCallCount     = 0;

static void static_writeHealthLine(void);

ssize_t __real_write(int fd, const void* bytes, size_t byte_count);

ssize_t __wrap_write(int fd, const void* bytes, size_t byte_count)
{
  atomic_fetch_add(&g_writeCallCount, 1);
  int overflow_line_count = atomic_exchange(&g_overflowLineCount, 0);
  if (overflow_line_count > 0)
  {
    for (int i = 0; i < overflow_line_count; i++)
      static_writeHealthLine();
    errno = EIO;
    return -1;
  }
  int next_errno = atomic_exchange(&g_nextWriteErrno, 0);
  if (next_errno != 0)
  {
    errno = next_errno;
    return -1;
  }
  long byte_limit = atomic_exchange(&g_nextWriteByteLimit, -1);
  if (byte_limit >= 0)
    return __real_write(fd, bytes, byte_count < (size_t)byte_limit ? byte_count : (size_t)byte_limit);
  int write_errno = atomic_load(&g_writeErrno);
  if (write_errno != 0)
  {
    errno = write_errno;
    return -1;
  }
  return __real_write(fd, bytes, byte_count);
}

#define TEST_LOG_DIR_TEMPLATE  "/tmp/test_usagelog_XXXXXX"
static char g_logDir[sizeof(TEST_LOG_DIR_TEMPLATE)];
static char g_logFilePath[sizeof(TEST_LOG_DIR_TEMPLATE) + sizeof("/usage.jsonl")];
static char g_stderrPath[sizeof(TEST_LOG_DIR_TEMPLATE) + sizeof("/stderr.txt")];
static int  g_savedStderrFd = -1;

static char g_fileText[USAGELOG_DRAIN_BUF_SIZE];

static const Endpoint_t CVE_LOOKUP_ROW = { .mp_httpPath = "/cve_lookup/" };
static const Endpoint_t HEALTH_ROW     = { .mp_httpPath = "/health" };

static void static_startLog(void)
{
  usagelog_start(TEST_INSTANCE_PORT);
}

static void static_beginAt(int64_t start_ms)
{
  g_nowMs = start_ms;
  usagelog_beginRequest();
}

static size_t static_writeAt(int64_t now_ms)
{
  g_nowMs = now_ms;
  usagelog_writeRequest();
  return usagelog_drainLines(g_lines, sizeof(g_lines));
}

static int static_countLines(const char* lines)
{
  int line_count = 0;
  for (const char* c = lines; *c != '\0'; c++)
    line_count += *c == '\n';
  return line_count;
}

static void static_writeHealthLine(void)
{
  static_beginAt(0);
  usagelog_setEndpointName(&HEALTH_ROW);
  usagelog_writeRequest();
}

static long static_readFile(const char* path)
{
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0)
    return -1;
  ssize_t byte_count = read(fd, g_fileText, sizeof(g_fileText) - 1);
  close(fd);
  if (byte_count < 0)
    byte_count = 0;
  g_fileText[byte_count] = '\0';
  return (long)byte_count;
}

static void static_sleepMs(long ms)
{
  struct timespec pause = { .tv_sec = ms / 1000, .tv_nsec = (ms % 1000) * 1000000L };
  nanosleep(&pause, NULL);
}

static bool static_waitForFileLines(const char* path, int line_count)
{
  for (int waited_ms = 0; waited_ms < 2000; waited_ms++)
  {
    if (static_readFile(path) > 0 && static_countLines(g_fileText) == line_count)
      return true;
    static_sleepMs(1);
  }
  return false;
}

static void static_captureStderr(void)
{
  fflush(stderr);
  g_savedStderrFd = dup(STDERR_FILENO);
  int fd = open(g_stderrPath, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
  TEST_ASSERT_TRUE(g_savedStderrFd >= 0 && fd >= 0);
  dup2(fd, STDERR_FILENO);
  close(fd);
}

static void static_restoreStderr(void)
{
  if (g_savedStderrFd < 0)
    return;
  fflush(stderr);
  dup2(g_savedStderrFd, STDERR_FILENO);
  close(g_savedStderrFd);
  g_savedStderrFd = -1;
}

void setUp(void)
{
  g_nowEpoch = TEST_TIME;
  memset(g_lines, 0, sizeof(g_lines));
  atomic_store(&g_nextWriteErrno, 0);
  atomic_store(&g_nextWriteByteLimit, -1);
  atomic_store(&g_writeErrno, 0);
  atomic_store(&g_overflowLineCount, 0);
  atomic_store(&g_writeCallCount, 0);
  memcpy(g_logDir, TEST_LOG_DIR_TEMPLATE, sizeof(TEST_LOG_DIR_TEMPLATE));
  TEST_ASSERT_NOT_NULL(mkdtemp(g_logDir));
  snprintf(g_logFilePath, sizeof(g_logFilePath), "%s/usage.jsonl", g_logDir);
  snprintf(g_stderrPath, sizeof(g_stderrPath), "%s/stderr.txt", g_logDir);
}

void tearDown(void)
{
  usagelog_stopFileWriter();
  static_restoreStderr();
  usagelog_drainLines(g_lines, sizeof(g_lines));
  unlink(g_logFilePath);
  unlink(g_stderrPath);
  rmdir(g_logDir);
}

void test_commit_before_start_writes_no_line(void)
{
  static_beginAt(1000);
  usagelog_setEndpointName(&HEALTH_ROW);
  TEST_ASSERT_EQUAL_size_t(0, static_writeAt(1001));
  TEST_ASSERT_EQUAL_STRING("", g_lines);
}

void test_event_before_start_writes_no_line(void)
{
  usagelog_writeEvent(USAGELOG_EVENT_START);
  TEST_ASSERT_EQUAL_size_t(0, usagelog_drainLines(g_lines, sizeof(g_lines)));
  TEST_ASSERT_EQUAL_STRING("", g_lines);
}

void test_x402_step_before_start_writes_no_line(void)
{
  usagelog_writeX402Step(USAGELOG_X402_STEP_SETTLE, USAGELOG_X402_OUTCOME_PAID, 12, 345);
  TEST_ASSERT_EQUAL_size_t(0, usagelog_drainLines(g_lines, sizeof(g_lines)));
  TEST_ASSERT_EQUAL_STRING("", g_lines);
}

void test_each_x402_step_and_outcome_becomes_one_exact_line(void)
{
  static_startLog();
  usagelog_writeX402Step(USAGELOG_X402_STEP_VERIFY,         USAGELOG_X402_OUTCOME_VALID,                     41,   999);
  usagelog_writeX402Step(USAGELOG_X402_STEP_VERIFY,         USAGELOG_X402_OUTCOME_INVALID,                   42,   999);
  usagelog_writeX402Step(USAGELOG_X402_STEP_VERIFY,         USAGELOG_X402_OUTCOME_UNAVAILABLE,               5001, 999);
  usagelog_writeX402Step(USAGELOG_X402_STEP_SETTLE,         USAGELOG_X402_OUTCOME_PAID,                      1830, 2400);
  usagelog_writeX402Step(USAGELOG_X402_STEP_SETTLE,         USAGELOG_X402_OUTCOME_REFUSED,                   210,  700);
  usagelog_writeX402Step(USAGELOG_X402_STEP_SETTLE,         USAGELOG_X402_OUTCOME_PENDING_WITH_SIGNATURE,    30002, 31000);
  usagelog_writeX402Step(USAGELOG_X402_STEP_SETTLE,         USAGELOG_X402_OUTCOME_PENDING_WITHOUT_SIGNATURE, 0,    0);
  usagelog_writeX402Step(USAGELOG_X402_STEP_STATUS_ASK,     USAGELOG_X402_OUTCOME_CONFIRMED,                 88,   999);
  usagelog_writeX402Step(USAGELOG_X402_STEP_STATUS_ASK,     USAGELOG_X402_OUTCOME_FAILED,                    89,   999);
  usagelog_writeX402Step(USAGELOG_X402_STEP_STATUS_ASK,     USAGELOG_X402_OUTCOME_PROCESSED,                 90,   999);
  usagelog_writeX402Step(USAGELOG_X402_STEP_STATUS_ASK,     USAGELOG_X402_OUTCOME_NOT_FOUND,                 91,   999);
  usagelog_writeX402Step(USAGELOG_X402_STEP_STATUS_ASK,     USAGELOG_X402_OUTCOME_UNAVAILABLE,               92,   999);
  usagelog_writeX402Step(USAGELOG_X402_STEP_SIGNATURE_FIND, USAGELOG_X402_OUTCOME_CONFIRMED,                 120,  999);
  usagelog_writeX402Step(USAGELOG_X402_STEP_SIGNATURE_FIND, USAGELOG_X402_OUTCOME_NOT_FOUND,                 9223372036854775807LL, 999);

  size_t line_byte_count = usagelog_drainLines(g_lines, sizeof(g_lines));
  const char* expected =
    "{\"log_format_version\":1,\"type\":\"x402_step\",\"time\":\"" TEST_TIME_TEXT "\",\"instance_port\":8002,\"step\":\"verify\",\"outcome\":\"valid\",\"duration_ms\":41}\n"
    "{\"log_format_version\":1,\"type\":\"x402_step\",\"time\":\"" TEST_TIME_TEXT "\",\"instance_port\":8002,\"step\":\"verify\",\"outcome\":\"invalid\",\"duration_ms\":42}\n"
    "{\"log_format_version\":1,\"type\":\"x402_step\",\"time\":\"" TEST_TIME_TEXT "\",\"instance_port\":8002,\"step\":\"verify\",\"outcome\":\"unavailable\",\"duration_ms\":5001}\n"
    "{\"log_format_version\":1,\"type\":\"x402_step\",\"time\":\"" TEST_TIME_TEXT "\",\"instance_port\":8002,\"step\":\"settle\",\"outcome\":\"paid\",\"duration_ms\":1830,\"reserve_age_ms\":2400}\n"
    "{\"log_format_version\":1,\"type\":\"x402_step\",\"time\":\"" TEST_TIME_TEXT "\",\"instance_port\":8002,\"step\":\"settle\",\"outcome\":\"refused\",\"duration_ms\":210,\"reserve_age_ms\":700}\n"
    "{\"log_format_version\":1,\"type\":\"x402_step\",\"time\":\"" TEST_TIME_TEXT "\",\"instance_port\":8002,\"step\":\"settle\",\"outcome\":\"pending_with_signature\",\"duration_ms\":30002,\"reserve_age_ms\":31000}\n"
    "{\"log_format_version\":1,\"type\":\"x402_step\",\"time\":\"" TEST_TIME_TEXT "\",\"instance_port\":8002,\"step\":\"settle\",\"outcome\":\"pending_without_signature\",\"duration_ms\":0,\"reserve_age_ms\":0}\n"
    "{\"log_format_version\":1,\"type\":\"x402_step\",\"time\":\"" TEST_TIME_TEXT "\",\"instance_port\":8002,\"step\":\"status_ask\",\"outcome\":\"confirmed\",\"duration_ms\":88}\n"
    "{\"log_format_version\":1,\"type\":\"x402_step\",\"time\":\"" TEST_TIME_TEXT "\",\"instance_port\":8002,\"step\":\"status_ask\",\"outcome\":\"failed\",\"duration_ms\":89}\n"
    "{\"log_format_version\":1,\"type\":\"x402_step\",\"time\":\"" TEST_TIME_TEXT "\",\"instance_port\":8002,\"step\":\"status_ask\",\"outcome\":\"processed\",\"duration_ms\":90}\n"
    "{\"log_format_version\":1,\"type\":\"x402_step\",\"time\":\"" TEST_TIME_TEXT "\",\"instance_port\":8002,\"step\":\"status_ask\",\"outcome\":\"not_found\",\"duration_ms\":91}\n"
    "{\"log_format_version\":1,\"type\":\"x402_step\",\"time\":\"" TEST_TIME_TEXT "\",\"instance_port\":8002,\"step\":\"status_ask\",\"outcome\":\"unavailable\",\"duration_ms\":92}\n"
    "{\"log_format_version\":1,\"type\":\"x402_step\",\"time\":\"" TEST_TIME_TEXT "\",\"instance_port\":8002,\"step\":\"signature_find\",\"outcome\":\"confirmed\",\"duration_ms\":120}\n"
    "{\"log_format_version\":1,\"type\":\"x402_step\",\"time\":\"" TEST_TIME_TEXT "\",\"instance_port\":8002,\"step\":\"signature_find\",\"outcome\":\"not_found\",\"duration_ms\":9223372036854775807}\n";
  TEST_ASSERT_EQUAL_STRING(expected, g_lines);
  TEST_ASSERT_EQUAL_size_t(strlen(expected), line_byte_count);
}

void test_x402_step_line_that_does_not_fit_the_buffer_is_lost(void)
{
  static_startLog();
  usagelog_writeX402Step(USAGELOG_X402_STEP_SETTLE, USAGELOG_X402_OUTCOME_PAID, 1830, 2400);
  size_t line_len = usagelog_drainLines(g_lines, sizeof(g_lines));
  TEST_ASSERT_TRUE(line_len > 0);

  size_t fitting_line_count = USAGELOG_BUFFER_SIZE / line_len;
  for (size_t i = 0; i < fitting_line_count + 1; i++)
    usagelog_writeX402Step(USAGELOG_X402_STEP_SETTLE, USAGELOG_X402_OUTCOME_PAID, 1830, 2400);

  size_t line_byte_count = usagelog_drainLines(g_lines, sizeof(g_lines));
  const char* lost_line = "{\"log_format_version\":1,\"type\":\"lost\",\"time\":\"" TEST_TIME_TEXT "\",\"instance_port\":8002,\"lost_line_count\":1}\n";
  TEST_ASSERT_EQUAL_size_t(fitting_line_count * line_len + strlen(lost_line), line_byte_count);
  TEST_ASSERT_EQUAL_STRING(lost_line, g_lines + fitting_line_count * line_len);
  TEST_ASSERT_EQUAL_INT((int)fitting_line_count + 1, static_countLines(g_lines));
}

void test_each_event_becomes_one_exact_line(void)
{
  static_startLog();
  usagelog_writeEvent(USAGELOG_EVENT_START);
  usagelog_writeEvent(USAGELOG_EVENT_STOP);
  usagelog_writeEvent(USAGELOG_EVENT_DB_DOWN);
  usagelog_writeEvent(USAGELOG_EVENT_DB_UP);
  usagelog_writeEvent(USAGELOG_EVENT_DNS_SCAN_CAP_REACHED);
  usagelog_writeEvent(USAGELOG_EVENT_TLS_SCAN_CAP_REACHED);
  usagelog_writeEvent(USAGELOG_EVENT_RDAP_WHOIS_SCAN_CAP_REACHED);
  usagelog_writeEvent(USAGELOG_EVENT_HEADERS_SCAN_CAP_REACHED);
  usagelog_writeEvent(USAGELOG_EVENT_CT_SCAN_CAP_REACHED);
  usagelog_writeEvent(USAGELOG_EVENT_CVE_SERVICES_CAP_REACHED);

  size_t line_byte_count = usagelog_drainLines(g_lines, sizeof(g_lines));
  const char* expected =
    "{\"log_format_version\":1,\"type\":\"start\",\"time\":\"" TEST_TIME_TEXT "\",\"instance_port\":8002,\"version\":\"" CONTRASTAPI_VERSION "\"}\n"
    "{\"log_format_version\":1,\"type\":\"stop\",\"time\":\"" TEST_TIME_TEXT "\",\"instance_port\":8002}\n"
    "{\"log_format_version\":1,\"type\":\"db_down\",\"time\":\"" TEST_TIME_TEXT "\",\"instance_port\":8002}\n"
    "{\"log_format_version\":1,\"type\":\"db_up\",\"time\":\"" TEST_TIME_TEXT "\",\"instance_port\":8002}\n"
    "{\"log_format_version\":1,\"type\":\"dns_scan_cap_reached\",\"time\":\"" TEST_TIME_TEXT "\",\"instance_port\":8002}\n"
    "{\"log_format_version\":1,\"type\":\"tls_scan_cap_reached\",\"time\":\"" TEST_TIME_TEXT "\",\"instance_port\":8002}\n"
    "{\"log_format_version\":1,\"type\":\"rdap_whois_scan_cap_reached\",\"time\":\"" TEST_TIME_TEXT "\",\"instance_port\":8002}\n"
    "{\"log_format_version\":1,\"type\":\"headers_scan_cap_reached\",\"time\":\"" TEST_TIME_TEXT "\",\"instance_port\":8002}\n"
    "{\"log_format_version\":1,\"type\":\"ct_scan_cap_reached\",\"time\":\"" TEST_TIME_TEXT "\",\"instance_port\":8002}\n"
    "{\"log_format_version\":1,\"type\":\"cve_services_cap_reached\",\"time\":\"" TEST_TIME_TEXT "\",\"instance_port\":8002}\n";
  TEST_ASSERT_EQUAL_STRING(expected, g_lines);
  TEST_ASSERT_EQUAL_size_t(strlen(expected), line_byte_count);
}

void test_event_once_per_day_writes_one_line_a_day(void)
{
  static_startLog();
  g_nowEpoch = TEST_DAY_START + 10 * TEST_SECONDS_PER_DAY;

  usagelog_writeEventOncePerDay(USAGELOG_EVENT_CVE_SERVICES_CAP_REACHED);
  usagelog_drainLines(g_lines, sizeof(g_lines));
  TEST_ASSERT_EQUAL_STRING("{\"log_format_version\":1,\"type\":\"cve_services_cap_reached\",\"time\":\"2025-11-04T00:00:00Z\",\"instance_port\":8002}\n", g_lines);

  usagelog_writeEventOncePerDay(USAGELOG_EVENT_CVE_SERVICES_CAP_REACHED);
  TEST_ASSERT_EQUAL_size_t(0, usagelog_drainLines(g_lines, sizeof(g_lines)));
}

void test_event_once_per_day_keeps_a_day_for_each_kind(void)
{
  static const struct {
    UsageLogEvent_t m_event;
    const char*     mp_type;
  } kinds[] = {
    { USAGELOG_EVENT_START,                       "start"                       },
    { USAGELOG_EVENT_STOP,                        "stop"                        },
    { USAGELOG_EVENT_DB_DOWN,                     "db_down"                     },
    { USAGELOG_EVENT_DB_UP,                       "db_up"                       },
    { USAGELOG_EVENT_DNS_SCAN_CAP_REACHED,        "dns_scan_cap_reached"        },
    { USAGELOG_EVENT_TLS_SCAN_CAP_REACHED,        "tls_scan_cap_reached"        },
    { USAGELOG_EVENT_RDAP_WHOIS_SCAN_CAP_REACHED, "rdap_whois_scan_cap_reached" },
    { USAGELOG_EVENT_HEADERS_SCAN_CAP_REACHED,    "headers_scan_cap_reached"    },
    { USAGELOG_EVENT_CT_SCAN_CAP_REACHED,         "ct_scan_cap_reached"         },
    { USAGELOG_EVENT_CVE_SERVICES_CAP_REACHED,    "cve_services_cap_reached"    },
  };
  enum { KIND_COUNT = sizeof(kinds) / sizeof(kinds[0]) };
  static_startLog();
  g_nowEpoch = TEST_DAY_START + 12 * TEST_SECONDS_PER_DAY;

  for (int i = 0; i < KIND_COUNT; i++)
    usagelog_writeEventOncePerDay(kinds[i].m_event);
  usagelog_drainLines(g_lines, sizeof(g_lines));
  TEST_ASSERT_EQUAL_INT(KIND_COUNT, static_countLines(g_lines));
  int i = 0;
  for (char* line = strtok(g_lines, "\n"); line != NULL; line = strtok(NULL, "\n"), i++)
  {
    char expected[64];
    snprintf(expected, sizeof(expected), "\"type\":\"%s\",", kinds[i].mp_type);
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(line, expected), line);
  }

  for (int k = 0; k < KIND_COUNT; k++)
    usagelog_writeEventOncePerDay(kinds[k].m_event);
  TEST_ASSERT_EQUAL_size_t(0, usagelog_drainLines(g_lines, sizeof(g_lines)));
}

void test_event_once_per_day_writes_again_on_the_next_utc_day(void)
{
  static const struct {
    time_t m_secondOfDays;
    int    m_lineCount;
  } calls[] = {
    { 0,                         1 },
    { TEST_SECONDS_PER_DAY - 1,  0 },
    { TEST_SECONDS_PER_DAY,      1 },
    { TEST_SECONDS_PER_DAY + 60, 0 },
  };
  static_startLog();
  time_t first_day = TEST_DAY_START + 14 * TEST_SECONDS_PER_DAY;
  for (size_t c = 0; c < sizeof(calls) / sizeof(calls[0]); c++)
  {
    g_nowEpoch = first_day + calls[c].m_secondOfDays;
    usagelog_writeEventOncePerDay(USAGELOG_EVENT_DNS_SCAN_CAP_REACHED);
    usagelog_drainLines(g_lines, sizeof(g_lines));
    char message[32];
    snprintf(message, sizeof(message), "call %zu", c);
    TEST_ASSERT_EQUAL_INT_MESSAGE(calls[c].m_lineCount, static_countLines(g_lines), message);
  }
}

static void* static_writeEventOncePerDayLines(void* unused_arg)
{
  (void)unused_arg;
  for (int i = 0; i < LINES_PER_THREAD; i++)
    usagelog_writeEventOncePerDay(USAGELOG_EVENT_TLS_SCAN_CAP_REACHED);
  return NULL;
}

void test_threads_write_one_event_line_on_a_new_day(void)
{
  static_startLog();
  g_nowEpoch = TEST_DAY_START + 16 * TEST_SECONDS_PER_DAY;
  TEST_ASSERT_EQUAL_INT(0, pthread_barrier_init(&g_clockBarrier, NULL, THREAD_COUNT));
  atomic_store(&g_isClockBarrierArmed, true);

  pthread_t threads[THREAD_COUNT];
  for (int i = 0; i < THREAD_COUNT; i++)
    TEST_ASSERT_EQUAL_INT(0, pthread_create(&threads[i], NULL, static_writeEventOncePerDayLines, NULL));
  for (int i = 0; i < THREAD_COUNT; i++)
    pthread_join(threads[i], NULL);
  atomic_store(&g_isClockBarrierArmed, false);
  pthread_barrier_destroy(&g_clockBarrier);

  usagelog_drainLines(g_lines, sizeof(g_lines));
  TEST_ASSERT_EQUAL_INT(1, static_countLines(g_lines));
  TEST_ASSERT_NOT_NULL(strstr(g_lines, "\"type\":\"tls_scan_cap_reached\","));
}

void test_rest_record_becomes_one_exact_line(void)
{
  static_startLog();
  static_beginAt(1000);
  usagelog_setSurface(USAGELOG_SURFACE_REST);
  usagelog_setEndpointName(&CVE_LOOKUP_ROW);
  usagelog_setTier(USAGELOG_TIER_PRO);
  usagelog_setCreditCount(3);
  usagelog_setRunStatus(ENDPOINT_RUN_NOT_FOUND);
  usagelog_setResponse(404, 77);

  size_t line_byte_count = static_writeAt(1012);
  const char* expected =
    "{\"log_format_version\":1,\"type\":\"request\",\"time\":\"" TEST_TIME_TEXT "\",\"instance_port\":8002,\"surface\":\"rest\","
    "\"endpoint\":\"cve_lookup\",\"endpoint_exists\":true,\"tier\":\"pro\",\"status\":404,\"run_status\":\"not_found\","
    "\"duration_ms\":12,\"body_byte_count\":77,\"credit_count\":3}\n";
  TEST_ASSERT_EQUAL_STRING(expected, g_lines);
  TEST_ASSERT_EQUAL_size_t(strlen(expected), line_byte_count);
}

void test_bulk_record_writes_item_count_and_is_send_failed(void)
{
  static_startLog();
  static_beginAt(500);
  usagelog_setSurface(USAGELOG_SURFACE_MCP);
  usagelog_setMcpMethodName("tools/call");
  usagelog_setItemCount(7);
  usagelog_setCreditCount(5);
  usagelog_setRunStatus(ENDPOINT_RUN_OK);
  usagelog_setResponse(200, 4096);
  usagelog_setSendFailed();

  static_writeAt(503);
  TEST_ASSERT_EQUAL_STRING(
    "{\"log_format_version\":1,\"type\":\"request\",\"time\":\"" TEST_TIME_TEXT "\",\"instance_port\":8002,\"surface\":\"mcp\","
    "\"endpoint\":\"tools/call\",\"endpoint_exists\":true,\"tier\":\"free\",\"status\":200,\"run_status\":\"ok\","
    "\"duration_ms\":3,\"body_byte_count\":4096,\"credit_count\":5,\"item_count\":7,\"is_send_failed\":true}\n",
    g_lines);
}

void test_bulk_record_with_no_item_writes_item_count_0(void)
{
  static_startLog();
  static_beginAt(0);
  usagelog_setItemCount(0);
  static_writeAt(0);
  TEST_ASSERT_NOT_NULL(strstr(g_lines, ",\"credit_count\":0,\"item_count\":0}\n"));
}

void test_record_without_name_or_run_status_leaves_both_out(void)
{
  static_startLog();
  static_beginAt(70);

  static_writeAt(70);
  TEST_ASSERT_EQUAL_STRING(
    "{\"log_format_version\":1,\"type\":\"request\",\"time\":\"" TEST_TIME_TEXT "\",\"instance_port\":8002,\"surface\":\"connection\","
    "\"tier\":\"free\",\"status\":0,\"duration_ms\":0,\"body_byte_count\":0,\"credit_count\":0}\n",
    g_lines);
}

void test_endpoint_name_drops_the_slashes(void)
{
  static_startLog();
  static_beginAt(0);
  usagelog_setEndpointName(&CVE_LOOKUP_ROW);
  static_writeAt(0);
  TEST_ASSERT_NOT_NULL(strstr(g_lines, ",\"endpoint\":\"cve_lookup\",\"endpoint_exists\":true,"));

  static_beginAt(0);
  usagelog_setEndpointName(&HEALTH_ROW);
  static_writeAt(0);
  TEST_ASSERT_NOT_NULL(strstr(g_lines, ",\"endpoint\":\"health\",\"endpoint_exists\":true,"));
}

void test_web_file_name_is_its_whole_path(void)
{
  static const PagesFile_t STYLE_FILE = { .mp_httpPath = "/static/style.css" };
  static_startLog();
  static_beginAt(0);
  usagelog_setSurface(USAGELOG_SURFACE_WEB);
  usagelog_setWebFileName(&STYLE_FILE);
  static_writeAt(0);
  TEST_ASSERT_NOT_NULL(strstr(g_lines, "\"surface\":\"web\",\"endpoint\":\"/static/style.css\",\"endpoint_exists\":true,"));
}

static void static_writeUnknownName(const char* name, size_t name_len)
{
  static_beginAt(0);
  usagelog_setUnknownName(name, name_len);
  static_writeAt(0);
}

void test_unknown_name_that_passes_the_filter_is_written(void)
{
  static_startLog();
  const char* names[] = { "a", "z", "ba", "a0", "a9", "a_", "az09_", "old_tool",
                          "abcdefghijklmnopqrstuvwxyz012345" };
  TEST_ASSERT_EQUAL_size_t(USAGELOG_UNKNOWN_NAME_MAX_LEN, strlen(names[8]));
  for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++)
  {
    static_writeUnknownName(names[i], strlen(names[i]));
    char expected[128];
    snprintf(expected, sizeof(expected), ",\"endpoint\":\"%s\",\"endpoint_exists\":false,", names[i]);
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(g_lines, expected), names[i]);
  }
}

void test_unknown_name_that_fails_the_filter_is_unknown(void)
{
  static_startLog();
  const char* names[] = { "", "abcdefghijklmnopqrstuvwxyz0123456", "`a", "{a", "0a", "_a", "Aa",
                          "a@b.c", "a-b", "a/b", "a.b", "aZ", "a{", "a`", "a:", "a/", "cc_00ff" "\x7f" };
  TEST_ASSERT_EQUAL_size_t(USAGELOG_UNKNOWN_NAME_MAX_LEN + 1, strlen(names[1]));
  for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++)
  {
    static_writeUnknownName(names[i], strlen(names[i]));
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(g_lines, ",\"endpoint\":\"unknown\",\"endpoint_exists\":false,"), names[i]);
  }
}

void test_unknown_name_reads_only_its_length(void)
{
  static_startLog();
  static_writeUnknownName("old_tool@x", 8);
  TEST_ASSERT_NOT_NULL(strstr(g_lines, ",\"endpoint\":\"old_tool\",\"endpoint_exists\":false,"));
  TEST_ASSERT_NULL(strstr(g_lines, "@"));
}

void test_unknown_name_after_a_known_name_does_not_exist(void)
{
  static_startLog();
  static_beginAt(0);
  usagelog_setEndpointName(&HEALTH_ROW);
  usagelog_setUnknownName("old_tool", 8);
  static_writeAt(0);
  TEST_ASSERT_NOT_NULL(strstr(g_lines, ",\"endpoint\":\"old_tool\",\"endpoint_exists\":false,"));
}

void test_every_tier_has_its_text(void)
{
  static_startLog();
  const struct { UsageLogTier_t m_tier; const char* mp_text; } tiers[] = {
    { USAGELOG_TIER_FREE,        ",\"tier\":\"free\","        },
    { USAGELOG_TIER_PRO,         ",\"tier\":\"pro\","         },
    { USAGELOG_TIER_PRO_REFUSED, ",\"tier\":\"pro_refused\"," },
    { USAGELOG_TIER_X402,        ",\"tier\":\"x402\","        },
  };
  for (size_t i = 0; i < sizeof(tiers) / sizeof(tiers[0]); i++)
  {
    static_beginAt(0);
    usagelog_setTier(tiers[i].m_tier);
    static_writeAt(0);
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(g_lines, tiers[i].mp_text), tiers[i].mp_text);
  }
}

void test_every_surface_has_its_text(void)
{
  static_startLog();
  const struct { UsageLogSurface_t m_surface; const char* mp_text; } surfaces[] = {
    { USAGELOG_SURFACE_CONNECTION, ",\"surface\":\"connection\"," },
    { USAGELOG_SURFACE_REST,    ",\"surface\":\"rest\","    },
    { USAGELOG_SURFACE_MCP,     ",\"surface\":\"mcp\","     },
    { USAGELOG_SURFACE_WEB,     ",\"surface\":\"web\","     },
  };
  for (size_t i = 0; i < sizeof(surfaces) / sizeof(surfaces[0]); i++)
  {
    static_beginAt(0);
    usagelog_setSurface(surfaces[i].m_surface);
    static_writeAt(0);
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(g_lines, surfaces[i].mp_text), surfaces[i].mp_text);
  }
}

void test_every_run_status_has_its_text(void)
{
  static_startLog();
  const struct { EndpointRunStatus_t m_status; const char* mp_text; } run_statuses[] = {
    { ENDPOINT_RUN_OK,                  ",\"run_status\":\"ok\","                  },
    { ENDPOINT_RUN_NOT_FOUND,           ",\"run_status\":\"not_found\","           },
    { ENDPOINT_RUN_NOT_FOUND_WITH_BODY, ",\"run_status\":\"not_found_with_body\"," },
    { ENDPOINT_RUN_REFUSED,             ",\"run_status\":\"refused\","             },
    { ENDPOINT_RUN_REFUSED_WITH_BODY,   ",\"run_status\":\"refused_with_body\","   },
    { ENDPOINT_RUN_DEGRADED,            ",\"run_status\":\"degraded\","            },
    { ENDPOINT_RUN_DB_ERROR,            ",\"run_status\":\"db_error\","            },
    { ENDPOINT_RUN_UPSTREAM_ERROR,      ",\"run_status\":\"upstream_error\","      },
    { ENDPOINT_RUN_TARGET_UNREACHABLE,  ",\"run_status\":\"target_unreachable\","  },
    { ENDPOINT_RUN_NO_MEMORY,           ",\"run_status\":\"no_memory\","           },
    { ENDPOINT_RUN_NO_CONNECTION,       ",\"run_status\":\"no_connection\","       },
    { ENDPOINT_RUN_NO_CREDIT_BUDGET,    ",\"run_status\":\"no_credit_budget\","    },
    { ENDPOINT_RUN_UNAUTHORIZED,        ",\"run_status\":\"unauthorized\","        },
    { ENDPOINT_RUN_GONE,                ",\"run_status\":\"gone\","                },
  };
  for (size_t i = 0; i < sizeof(run_statuses) / sizeof(run_statuses[0]); i++)
  {
    static_beginAt(0);
    usagelog_setRunStatus(run_statuses[i].m_status);
    static_writeAt(0);
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(g_lines, run_statuses[i].mp_text), run_statuses[i].mp_text);
  }

  static_beginAt(0);
  usagelog_setGateRefused();
  static_writeAt(0);
  TEST_ASSERT_NOT_NULL(strstr(g_lines, ",\"run_status\":\"gate_refused\","));
}

void test_begin_clears_the_previous_record(void)
{
  static_startLog();
  static_beginAt(0);
  usagelog_setSurface(USAGELOG_SURFACE_WEB);
  usagelog_setUnknownName("old_tool", 8);
  usagelog_setTier(USAGELOG_TIER_PRO_REFUSED);
  usagelog_setCreditCount(9);
  usagelog_setItemCount(4);
  usagelog_setGateRefused();
  usagelog_setResponse(400, 30);
  usagelog_setSendFailed();

  static_beginAt(40);
  static_writeAt(41);
  TEST_ASSERT_EQUAL_STRING(
    "{\"log_format_version\":1,\"type\":\"request\",\"time\":\"" TEST_TIME_TEXT "\",\"instance_port\":8002,\"surface\":\"connection\","
    "\"tier\":\"free\",\"status\":0,\"duration_ms\":1,\"body_byte_count\":0,\"credit_count\":0}\n",
    g_lines);
}

void test_drain_takes_every_line_once(void)
{
  static_startLog();
  static_beginAt(0);
  usagelog_setEndpointName(&HEALTH_ROW);
  usagelog_writeRequest();
  static_beginAt(0);
  usagelog_setEndpointName(&CVE_LOOKUP_ROW);
  usagelog_writeRequest();

  size_t line_byte_count = usagelog_drainLines(g_lines, sizeof(g_lines));
  TEST_ASSERT_EQUAL_size_t(strlen(g_lines), line_byte_count);
  TEST_ASSERT_EQUAL_INT(2, static_countLines(g_lines));
  const char* health = strstr(g_lines, "\"endpoint\":\"health\"");
  const char* cve    = strstr(g_lines, "\"endpoint\":\"cve_lookup\"");
  TEST_ASSERT_NOT_NULL(health);
  TEST_ASSERT_NOT_NULL(cve);
  TEST_ASSERT_TRUE(health < cve);

  TEST_ASSERT_EQUAL_size_t(0, usagelog_drainLines(g_lines, sizeof(g_lines)));
  TEST_ASSERT_EQUAL_STRING("", g_lines);
}

void test_full_buffer_loses_lines_and_the_drain_counts_them(void)
{
  static_startLog();
  static_beginAt(0);
  usagelog_setEndpointName(&HEALTH_ROW);
  size_t line_len = static_writeAt(0);
  TEST_ASSERT_TRUE(line_len > 0);

  size_t fitting_line_count = USAGELOG_BUFFER_SIZE / line_len;
  for (size_t i = 0; i < fitting_line_count + 3; i++)
    usagelog_writeRequest();

  size_t line_byte_count = usagelog_drainLines(g_lines, sizeof(g_lines));
  const char* lost_line = "{\"log_format_version\":1,\"type\":\"lost\",\"time\":\"" TEST_TIME_TEXT "\",\"instance_port\":8002,\"lost_line_count\":3}\n";
  TEST_ASSERT_EQUAL_size_t(fitting_line_count * line_len + strlen(lost_line), line_byte_count);
  TEST_ASSERT_EQUAL_STRING(lost_line, g_lines + fitting_line_count * line_len);
  TEST_ASSERT_EQUAL_INT((int)fitting_line_count + 1, static_countLines(g_lines));

  TEST_ASSERT_EQUAL_size_t(0, usagelog_drainLines(g_lines, sizeof(g_lines)));
}

void test_drain_frees_the_whole_buffer(void)
{
  static_startLog();
  static_beginAt(0);
  usagelog_setEndpointName(&HEALTH_ROW);
  size_t line_len = static_writeAt(0);
  TEST_ASSERT_TRUE(line_len > 0);
  for (size_t i = 0; i < USAGELOG_BUFFER_SIZE / line_len; i++)
    usagelog_writeRequest();
  usagelog_drainLines(g_lines, sizeof(g_lines));

  usagelog_writeRequest();
  TEST_ASSERT_EQUAL_size_t(line_len, usagelog_drainLines(g_lines, sizeof(g_lines)));
  TEST_ASSERT_NULL(strstr(g_lines, "\"type\":\"lost\""));
}

void test_line_that_does_not_fit_is_lost(void)
{
  static char long_path[USAGELOG_LINE_MAX_LEN + 2];
  memset(long_path, 'a', sizeof(long_path) - 1);
  long_path[0] = '/';
  long_path[sizeof(long_path) - 1] = '\0';
  const Endpoint_t long_row = { .mp_httpPath = long_path };

  static_startLog();
  static_beginAt(0);
  usagelog_setEndpointName(&long_row);
  static_writeAt(0);
  TEST_ASSERT_EQUAL_STRING("{\"log_format_version\":1,\"type\":\"lost\",\"time\":\"" TEST_TIME_TEXT "\",\"instance_port\":8002,\"lost_line_count\":1}\n", g_lines);
}

static size_t static_writeNamedLine(size_t name_len)
{
  static char path[USAGELOG_LINE_MAX_LEN + 2];
  TEST_ASSERT_TRUE(name_len + 2 <= sizeof(path));
  path[0] = '/';
  memset(path + 1, 'a', name_len);
  path[name_len + 1] = '\0';
  const Endpoint_t row = { .mp_httpPath = path };

  static_beginAt(0);
  usagelog_setEndpointName(&row);
  return static_writeAt(0);
}

void test_line_one_byte_under_the_line_size_fits_and_the_line_size_is_lost(void)
{
  static_startLog();
  size_t one_byte_line_len = static_writeNamedLine(1);
  size_t name_len_of_longest = 1 + (USAGELOG_LINE_MAX_LEN - 1) - one_byte_line_len;

  TEST_ASSERT_EQUAL_size_t(USAGELOG_LINE_MAX_LEN - 1, static_writeNamedLine(name_len_of_longest));
  TEST_ASSERT_EQUAL_CHAR('\n', g_lines[USAGELOG_LINE_MAX_LEN - 2]);
  TEST_ASSERT_NULL(strstr(g_lines, "\"type\":\"lost\""));

  static_writeNamedLine(name_len_of_longest + 1);
  TEST_ASSERT_EQUAL_STRING("{\"log_format_version\":1,\"type\":\"lost\",\"time\":\"" TEST_TIME_TEXT "\",\"instance_port\":8002,\"lost_line_count\":1}\n", g_lines);
}

void test_lines_that_exactly_fill_the_buffer_all_fit(void)
{
  static_startLog();
  size_t one_byte_line_len = static_writeNamedLine(1);
  size_t line_len          = static_writeNamedLine(1 + 256 - one_byte_line_len);
  TEST_ASSERT_EQUAL_size_t(256, line_len);
  TEST_ASSERT_EQUAL_size_t(0, USAGELOG_BUFFER_SIZE % line_len);

  for (size_t i = 0; i < USAGELOG_BUFFER_SIZE / line_len; i++)
    usagelog_writeRequest();
  TEST_ASSERT_EQUAL_size_t(USAGELOG_BUFFER_SIZE, usagelog_drainLines(g_lines, sizeof(g_lines)));
  TEST_ASSERT_NULL(strstr(g_lines, "\"type\":\"lost\""));
}

static void* static_writeLines(void* row_arg)
{
  const Endpoint_t* row = (const Endpoint_t*)row_arg;
  for (int i = 0; i < LINES_PER_THREAD; i++)
  {
    usagelog_beginRequest();
    usagelog_setEndpointName(row);
    usagelog_writeRequest();
  }
  return NULL;
}

void test_threads_commit_whole_lines_at_once(void)
{
  static const Endpoint_t rows[THREAD_COUNT] = {
    { .mp_httpPath = "/row_a" }, { .mp_httpPath = "/row_b" }, { .mp_httpPath = "/row_c" }, { .mp_httpPath = "/row_d" },
  };
  static_startLog();

  pthread_t threads[THREAD_COUNT];
  for (int i = 0; i < THREAD_COUNT; i++)
    TEST_ASSERT_EQUAL_INT(0, pthread_create(&threads[i], NULL, static_writeLines, (void*)&rows[i]));
  for (int i = 0; i < THREAD_COUNT; i++)
    pthread_join(threads[i], NULL);

  usagelog_drainLines(g_lines, sizeof(g_lines));
  TEST_ASSERT_EQUAL_INT(THREAD_COUNT * LINES_PER_THREAD, static_countLines(g_lines));

  int row_line_counts[THREAD_COUNT] = { 0 };
  for (char* line = strtok(g_lines, "\n"); line != NULL; line = strtok(NULL, "\n"))
  {
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, strncmp(line, "{\"log_format_version\":1,\"type\":\"request\",", 24), line);
    TEST_ASSERT_EQUAL_CHAR_MESSAGE('}', line[strlen(line) - 1], line);
    for (int i = 0; i < THREAD_COUNT; i++)
    {
      char expected[64];
      snprintf(expected, sizeof(expected), "\"endpoint\":\"%s\"", rows[i].mp_httpPath + 1);
      row_line_counts[i] += strstr(line, expected) != NULL;
    }
  }
  for (int i = 0; i < THREAD_COUNT; i++)
    TEST_ASSERT_EQUAL_INT(LINES_PER_THREAD, row_line_counts[i]);
}

void test_stop_writes_the_waiting_lines_to_a_new_file(void)
{
  static_startLog();
  static_writeHealthLine();
  size_t line_len = usagelog_drainLines(g_lines, sizeof(g_lines));
  TEST_ASSERT_TRUE(line_len > 0);

  TEST_ASSERT_TRUE(usagelog_startFileWriter(g_logFilePath, 60000));
  static_writeHealthLine();
  static_sleepMs(50);
  TEST_ASSERT_EQUAL_INT(-1, static_readFile(g_logFilePath));
  struct timespec stop_start;
  struct timespec stop_end;
  clock_gettime(CLOCK_MONOTONIC, &stop_start);
  usagelog_stopFileWriter();
  clock_gettime(CLOCK_MONOTONIC, &stop_end);
  long stop_ms = (long)(stop_end.tv_sec - stop_start.tv_sec) * 1000L
                + (stop_end.tv_nsec - stop_start.tv_nsec) / 1000000L;
  TEST_ASSERT_TRUE(stop_ms < 1000);

  TEST_ASSERT_EQUAL_INT((long)line_len, static_readFile(g_logFilePath));
  TEST_ASSERT_EQUAL_STRING(g_lines, g_fileText);
  TEST_ASSERT_EQUAL_size_t(0, usagelog_drainLines(g_lines, sizeof(g_lines)));
}

void test_file_writer_writes_at_each_interval(void)
{
  static_startLog();
  TEST_ASSERT_TRUE(usagelog_startFileWriter(g_logFilePath, 10));
  static_writeHealthLine();
  TEST_ASSERT_TRUE(static_waitForFileLines(g_logFilePath, 1));
  usagelog_stopFileWriter();
}

void test_file_writer_appends_to_the_file(void)
{
  static_startLog();
  static_writeHealthLine();
  usagelog_drainLines(g_lines, sizeof(g_lines));

  int fd = open(g_logFilePath, O_WRONLY | O_CREAT | O_CLOEXEC, 0600);
  TEST_ASSERT_TRUE(fd >= 0);
  TEST_ASSERT_EQUAL_INT(9, (int)__real_write(fd, "old line\n", 9));
  close(fd);

  static_writeHealthLine();
  TEST_ASSERT_TRUE(usagelog_startFileWriter(g_logFilePath, 60000));
  usagelog_stopFileWriter();

  TEST_ASSERT_EQUAL_INT((long)(9 + strlen(g_lines)), static_readFile(g_logFilePath));
  TEST_ASSERT_EQUAL_STRING_LEN("old line\n", g_fileText, 9);
  TEST_ASSERT_EQUAL_STRING(g_lines, g_fileText + 9);
}

void test_file_writer_creates_the_file_with_mode_0644(void)
{
  static_startLog();
  mode_t old_umask = umask(0);
  static_writeHealthLine();
  TEST_ASSERT_TRUE(usagelog_startFileWriter(g_logFilePath, 60000));
  usagelog_stopFileWriter();
  umask(old_umask);

  struct stat file_stat;
  TEST_ASSERT_EQUAL_INT(0, stat(g_logFilePath, &file_stat));
  TEST_ASSERT_EQUAL_UINT32(0644, (unsigned int)(file_stat.st_mode & 0777));
}

void test_file_writer_with_no_line_creates_no_file(void)
{
  static_startLog();
  TEST_ASSERT_TRUE(usagelog_startFileWriter(g_logFilePath, 10));
  static_sleepMs(50);
  usagelog_stopFileWriter();

  struct stat file_stat;
  TEST_ASSERT_EQUAL_INT(-1, stat(g_logFilePath, &file_stat));
  TEST_ASSERT_EQUAL_INT(ENOENT, errno);
}

void test_stop_without_a_file_writer_takes_no_line(void)
{
  static_startLog();
  static_writeHealthLine();
  usagelog_stopFileWriter();
  usagelog_drainLines(g_lines, sizeof(g_lines));
  TEST_ASSERT_EQUAL_INT(1, static_countLines(g_lines));
}

void test_lines_the_file_refuses_are_lost_and_counted(void)
{
  static_startLog();
  char missing_path[sizeof(g_logDir) + sizeof("/missing/usage.jsonl")];
  snprintf(missing_path, sizeof(missing_path), "%s/missing/usage.jsonl", g_logDir);
  static_captureStderr();

  for (int i = 0; i < 3; i++)
    static_writeHealthLine();
  TEST_ASSERT_TRUE(usagelog_startFileWriter(missing_path, 10));
  TEST_ASSERT_TRUE(static_waitForFileLines(g_stderrPath, 1));
  static_writeHealthLine();
  usagelog_stopFileWriter();
  static_restoreStderr();

  usagelog_drainLines(g_lines, sizeof(g_lines));
  TEST_ASSERT_EQUAL_STRING("{\"log_format_version\":1,\"type\":\"lost\",\"time\":\"" TEST_TIME_TEXT "\",\"instance_port\":8002,\"lost_line_count\":4}\n", g_lines);
  TEST_ASSERT_TRUE(static_readFile(g_stderrPath) > 0);
  TEST_ASSERT_EQUAL_INT(1, static_countLines(g_fileText));
  TEST_ASSERT_NOT_NULL(strstr(g_fileText, missing_path));
}

void test_cut_write_counts_the_unwritten_lines_lost(void)
{
  static_startLog();
  static_writeHealthLine();
  size_t line_len = usagelog_drainLines(g_lines, sizeof(g_lines));
  for (int i = 0; i < 3; i++)
    static_writeHealthLine();

  static_captureStderr();
  atomic_store(&g_nextWriteByteLimit, (long)line_len + 5);
  atomic_store(&g_writeErrno, ENOSPC);
  TEST_ASSERT_TRUE(usagelog_startFileWriter(g_logFilePath, 60000));
  usagelog_stopFileWriter();
  static_restoreStderr();

  TEST_ASSERT_EQUAL_INT((long)line_len + 5, static_readFile(g_logFilePath));
  TEST_ASSERT_EQUAL_STRING_LEN(g_lines, g_fileText, line_len);
  TEST_ASSERT_EQUAL_STRING_LEN(g_lines, g_fileText + line_len, 5);

  usagelog_drainLines(g_lines, sizeof(g_lines));
  TEST_ASSERT_EQUAL_STRING("{\"log_format_version\":1,\"type\":\"lost\",\"time\":\"" TEST_TIME_TEXT "\",\"instance_port\":8002,\"lost_line_count\":2}\n", g_lines);
}

void test_write_after_a_cut_line_starts_on_a_new_line(void)
{
  static_startLog();
  static_writeHealthLine();
  size_t line_len = usagelog_drainLines(g_lines, sizeof(g_lines));
  for (int i = 0; i < 3; i++)
    static_writeHealthLine();

  static_captureStderr();
  atomic_store(&g_nextWriteByteLimit, (long)line_len + 5);
  atomic_store(&g_writeErrno, ENOSPC);
  TEST_ASSERT_TRUE(usagelog_startFileWriter(g_logFilePath, 10));
  TEST_ASSERT_TRUE(static_waitForFileLines(g_stderrPath, 1));
  atomic_store(&g_writeErrno, 0);
  static_writeHealthLine();
  TEST_ASSERT_TRUE(static_waitForFileLines(g_logFilePath, 4));
  usagelog_stopFileWriter();
  static_restoreStderr();

  static char expected[3 * USAGELOG_DRAIN_BUF_SIZE + USAGELOG_LINE_MAX_LEN];
  static char expected_lost_first[3 * USAGELOG_DRAIN_BUF_SIZE + USAGELOG_LINE_MAX_LEN];
  snprintf(expected, sizeof(expected), "%s%.5s\n%s{\"log_format_version\":1,\"type\":\"lost\",\"time\":\"" TEST_TIME_TEXT "\",\"instance_port\":8002,\"lost_line_count\":2}\n",
           g_lines, g_lines, g_lines);
  snprintf(expected_lost_first, sizeof(expected_lost_first), "%s%.5s\n{\"log_format_version\":1,\"type\":\"lost\",\"time\":\"" TEST_TIME_TEXT "\",\"instance_port\":8002,\"lost_line_count\":2}\n%s",
           g_lines, g_lines, g_lines);
  TEST_ASSERT_TRUE(static_readFile(g_logFilePath) > 0);
  if (strcmp(expected_lost_first, g_fileText) != 0)
    TEST_ASSERT_EQUAL_STRING(expected, g_fileText);
}

void test_cut_write_goes_on_with_the_rest(void)
{
  static_startLog();
  static_writeHealthLine();
  size_t line_len = usagelog_drainLines(g_lines, sizeof(g_lines));
  for (int i = 0; i < 3; i++)
    static_writeHealthLine();

  atomic_store(&g_nextWriteByteLimit, (long)line_len + 5);
  TEST_ASSERT_TRUE(usagelog_startFileWriter(g_logFilePath, 60000));
  usagelog_stopFileWriter();

  TEST_ASSERT_EQUAL_INT((long)(3 * line_len), static_readFile(g_logFilePath));
  TEST_ASSERT_EQUAL_INT(3, static_countLines(g_fileText));
  TEST_ASSERT_EQUAL_size_t(0, usagelog_drainLines(g_lines, sizeof(g_lines)));
}

void test_lines_lost_during_a_failed_write_add_to_the_count(void)
{
  static_startLog();
  static_writeHealthLine();
  size_t line_len = usagelog_drainLines(g_lines, sizeof(g_lines));
  size_t fitting_line_count = USAGELOG_BUFFER_SIZE / line_len;
  static_writeHealthLine();

  static_captureStderr();
  atomic_store(&g_overflowLineCount, (int)fitting_line_count + 2);
  TEST_ASSERT_TRUE(usagelog_startFileWriter(g_logFilePath, 60000));
  usagelog_stopFileWriter();
  static_restoreStderr();

  usagelog_drainLines(g_lines, sizeof(g_lines));
  TEST_ASSERT_EQUAL_STRING("{\"log_format_version\":1,\"type\":\"lost\",\"time\":\"" TEST_TIME_TEXT "\",\"instance_port\":8002,\"lost_line_count\":3}\n", g_lines + fitting_line_count * line_len);
}

void test_interrupted_write_is_tried_again(void)
{
  static_startLog();
  static_writeHealthLine();
  size_t line_len = usagelog_drainLines(g_lines, sizeof(g_lines));
  static_writeHealthLine();
  static_writeHealthLine();

  atomic_store(&g_nextWriteErrno, EINTR);
  TEST_ASSERT_TRUE(usagelog_startFileWriter(g_logFilePath, 60000));
  usagelog_stopFileWriter();

  TEST_ASSERT_EQUAL_INT((long)(2 * line_len), static_readFile(g_logFilePath));
  TEST_ASSERT_EQUAL_INT(2, static_countLines(g_fileText));
  TEST_ASSERT_EQUAL_size_t(0, usagelog_drainLines(g_lines, sizeof(g_lines)));
}

void test_failure_after_a_good_write_is_named_again(void)
{
  static_startLog();
  static_captureStderr();
  atomic_store(&g_writeErrno, EIO);
  TEST_ASSERT_TRUE(usagelog_startFileWriter(g_logFilePath, 10));
  static_writeHealthLine();
  TEST_ASSERT_TRUE(static_waitForFileLines(g_stderrPath, 1));

  atomic_store(&g_writeErrno, 0);
  static_writeHealthLine();
  TEST_ASSERT_TRUE(static_waitForFileLines(g_logFilePath, 2));

  atomic_store(&g_writeErrno, EIO);
  static_writeHealthLine();
  usagelog_stopFileWriter();
  static_restoreStderr();

  TEST_ASSERT_TRUE(static_readFile(g_stderrPath) > 0);
  TEST_ASSERT_EQUAL_INT(2, static_countLines(g_fileText));
}

void test_two_good_writes_leave_no_blank_line(void)
{
  static_startLog();
  static_writeHealthLine();
  size_t line_len = usagelog_drainLines(g_lines, sizeof(g_lines));

  TEST_ASSERT_TRUE(usagelog_startFileWriter(g_logFilePath, 10));
  static_writeHealthLine();
  TEST_ASSERT_TRUE(static_waitForFileLines(g_logFilePath, 1));
  static_writeHealthLine();
  TEST_ASSERT_TRUE(static_waitForFileLines(g_logFilePath, 2));
  usagelog_stopFileWriter();

  TEST_ASSERT_EQUAL_INT((long)(2 * line_len), static_readFile(g_logFilePath));
}

void test_cut_at_a_line_end_adds_no_newline(void)
{
  static_startLog();
  static_writeHealthLine();
  size_t line_len = usagelog_drainLines(g_lines, sizeof(g_lines));
  static_writeHealthLine();
  static_writeHealthLine();

  static_captureStderr();
  atomic_store(&g_nextWriteByteLimit, (long)line_len);
  atomic_store(&g_writeErrno, ENOSPC);
  TEST_ASSERT_TRUE(usagelog_startFileWriter(g_logFilePath, 10));
  TEST_ASSERT_TRUE(static_waitForFileLines(g_stderrPath, 1));
  atomic_store(&g_writeErrno, 0);
  TEST_ASSERT_TRUE(static_waitForFileLines(g_logFilePath, 2));
  usagelog_stopFileWriter();
  static_restoreStderr();

  static char expected[2 * USAGELOG_DRAIN_BUF_SIZE];
  snprintf(expected, sizeof(expected), "%s{\"log_format_version\":1,\"type\":\"lost\",\"time\":\"" TEST_TIME_TEXT "\",\"instance_port\":8002,\"lost_line_count\":1}\n", g_lines);
  TEST_ASSERT_TRUE(static_readFile(g_logFilePath) > 0);
  TEST_ASSERT_EQUAL_STRING(expected, g_fileText);
}

void test_failed_newline_is_tried_again(void)
{
  static_startLog();
  static_writeHealthLine();
  usagelog_drainLines(g_lines, sizeof(g_lines));
  static_writeHealthLine();
  static_writeHealthLine();

  static_captureStderr();
  atomic_store(&g_nextWriteByteLimit, (long)strlen(g_lines) + 5);
  atomic_store(&g_writeErrno, ENOSPC);
  TEST_ASSERT_TRUE(usagelog_startFileWriter(g_logFilePath, 10));
  TEST_ASSERT_TRUE(static_waitForFileLines(g_stderrPath, 1));
  for (int waited_ms = 0; waited_ms < 2000 && atomic_load(&g_writeCallCount) < 4; waited_ms++)
    static_sleepMs(1);
  TEST_ASSERT_TRUE(atomic_load(&g_writeCallCount) >= 4);
  atomic_store(&g_writeErrno, 0);
  TEST_ASSERT_TRUE(static_waitForFileLines(g_logFilePath, 3));
  usagelog_stopFileWriter();
  static_restoreStderr();

  static char expected[2 * USAGELOG_DRAIN_BUF_SIZE];
  snprintf(expected, sizeof(expected), "%s%.5s\n{\"log_format_version\":1,\"type\":\"lost\",\"time\":\"" TEST_TIME_TEXT "\",\"instance_port\":8002,\"lost_line_count\":1}\n", g_lines, g_lines);
  TEST_ASSERT_TRUE(static_readFile(g_logFilePath) > 0);
  TEST_ASSERT_EQUAL_STRING(expected, g_fileText);
}

void test_file_writer_closes_the_file(void)
{
  static_startLog();
  int fd_before = open("/dev/null", O_RDONLY | O_CLOEXEC);
  TEST_ASSERT_TRUE(fd_before >= 0);
  close(fd_before);

  static_writeHealthLine();
  TEST_ASSERT_TRUE(usagelog_startFileWriter(g_logFilePath, 60000));
  usagelog_stopFileWriter();

  int fd_after = open("/dev/null", O_RDONLY | O_CLOEXEC);
  close(fd_after);
  TEST_ASSERT_EQUAL_INT(fd_before, fd_after);
}

void test_file_writer_waits_out_an_interval_below_one_second(void)
{
  static_startLog();
  struct timespec start;
  struct timespec written;
  clock_gettime(CLOCK_MONOTONIC, &start);
  TEST_ASSERT_TRUE(usagelog_startFileWriter(g_logFilePath, 300));
  static_writeHealthLine();
  static_sleepMs(50);
  TEST_ASSERT_EQUAL_INT(-1, static_readFile(g_logFilePath));
  TEST_ASSERT_TRUE(static_waitForFileLines(g_logFilePath, 1));
  clock_gettime(CLOCK_MONOTONIC, &written);
  usagelog_stopFileWriter();
  long elapsed_ms = (long)(written.tv_sec - start.tv_sec) * 1000L
                  + (written.tv_nsec - start.tv_nsec) / 1000000L;
  TEST_ASSERT_GREATER_OR_EQUAL_INT32(290, elapsed_ms);
}

void test_refused_lost_line_after_whole_lines_keeps_its_count(void)
{
  static_startLog();
  static_writeHealthLine();
  size_t line_len = usagelog_drainLines(g_lines, sizeof(g_lines));

  static_captureStderr();
  static_writeHealthLine();
  atomic_store(&g_nextWriteErrno, EIO);
  TEST_ASSERT_TRUE(usagelog_startFileWriter(g_logFilePath, 60000));
  usagelog_stopFileWriter();

  static_writeHealthLine();
  atomic_store(&g_nextWriteByteLimit, (long)line_len);
  atomic_store(&g_writeErrno, ENOSPC);
  TEST_ASSERT_TRUE(usagelog_startFileWriter(g_logFilePath, 60000));
  usagelog_stopFileWriter();
  static_restoreStderr();

  TEST_ASSERT_EQUAL_INT((long)line_len, static_readFile(g_logFilePath));
  usagelog_drainLines(g_lines, sizeof(g_lines));
  TEST_ASSERT_EQUAL_STRING("{\"log_format_version\":1,\"type\":\"lost\",\"time\":\"" TEST_TIME_TEXT "\",\"instance_port\":8002,\"lost_line_count\":1}\n", g_lines);
}

void test_file_writer_does_not_wait_for_a_fifo_reader(void)
{
  static_startLog();
  TEST_ASSERT_EQUAL_INT(0, mkfifo(g_logFilePath, 0600));
  static_captureStderr();
  static_writeHealthLine();
  TEST_ASSERT_TRUE(usagelog_startFileWriter(g_logFilePath, 10));
  bool is_named = static_waitForFileLines(g_stderrPath, 1);
  int reader_fd = -1;
  if (!is_named)
    reader_fd = open(g_logFilePath, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
  usagelog_stopFileWriter();
  if (reader_fd >= 0)
    close(reader_fd);
  static_restoreStderr();

  TEST_ASSERT_TRUE(is_named);
  usagelog_drainLines(g_lines, sizeof(g_lines));
  TEST_ASSERT_EQUAL_STRING("{\"log_format_version\":1,\"type\":\"lost\",\"time\":\"" TEST_TIME_TEXT "\",\"instance_port\":8002,\"lost_line_count\":1}\n", g_lines);
}

void test_file_writer_does_not_follow_a_symlink(void)
{
  static char target_path[sizeof(g_logFilePath) + 16];
  snprintf(target_path, sizeof(target_path), "%s/target.jsonl", g_logDir);
  static_startLog();
  TEST_ASSERT_EQUAL_INT(0, symlink(target_path, g_logFilePath));
  static_captureStderr();
  static_writeHealthLine();
  TEST_ASSERT_TRUE(usagelog_startFileWriter(g_logFilePath, 60000));
  usagelog_stopFileWriter();
  static_restoreStderr();

  long target_byte_count = static_readFile(target_path);
  unlink(target_path);
  TEST_ASSERT_EQUAL_INT(-1, target_byte_count);
  usagelog_drainLines(g_lines, sizeof(g_lines));
  TEST_ASSERT_EQUAL_STRING("{\"log_format_version\":1,\"type\":\"lost\",\"time\":\"" TEST_TIME_TEXT "\",\"instance_port\":8002,\"lost_line_count\":1}\n", g_lines);
}

void test_retention_days_are_90(void)
{
  TEST_ASSERT_EQUAL_INT(90, USAGELOG_RETENTION_DAYS);
}

void test_registration_gate_test_count(void)
{
  TEST_ASSERT_EQUAL_INT_MESSAGE(54, (int)Unity.NumberOfTests,
    "RUN_TEST list and test definitions have drifted apart - a test may be unregistered");
}

int main(void)
{
  setenv("TZ", "UTC-14", 1);
  tzset();

  UNITY_BEGIN();
  RUN_TEST(test_commit_before_start_writes_no_line);
  RUN_TEST(test_event_before_start_writes_no_line);
  RUN_TEST(test_x402_step_before_start_writes_no_line);
  RUN_TEST(test_rest_record_becomes_one_exact_line);
  RUN_TEST(test_bulk_record_writes_item_count_and_is_send_failed);
  RUN_TEST(test_bulk_record_with_no_item_writes_item_count_0);
  RUN_TEST(test_record_without_name_or_run_status_leaves_both_out);
  RUN_TEST(test_endpoint_name_drops_the_slashes);
  RUN_TEST(test_web_file_name_is_its_whole_path);
  RUN_TEST(test_unknown_name_that_passes_the_filter_is_written);
  RUN_TEST(test_unknown_name_that_fails_the_filter_is_unknown);
  RUN_TEST(test_unknown_name_reads_only_its_length);
  RUN_TEST(test_unknown_name_after_a_known_name_does_not_exist);
  RUN_TEST(test_every_tier_has_its_text);
  RUN_TEST(test_every_surface_has_its_text);
  RUN_TEST(test_every_run_status_has_its_text);
  RUN_TEST(test_begin_clears_the_previous_record);
  RUN_TEST(test_drain_takes_every_line_once);
  RUN_TEST(test_full_buffer_loses_lines_and_the_drain_counts_them);
  RUN_TEST(test_drain_frees_the_whole_buffer);
  RUN_TEST(test_line_that_does_not_fit_is_lost);
  RUN_TEST(test_line_one_byte_under_the_line_size_fits_and_the_line_size_is_lost);
  RUN_TEST(test_lines_that_exactly_fill_the_buffer_all_fit);
  RUN_TEST(test_threads_commit_whole_lines_at_once);
  RUN_TEST(test_each_event_becomes_one_exact_line);
  RUN_TEST(test_event_once_per_day_writes_one_line_a_day);
  RUN_TEST(test_event_once_per_day_keeps_a_day_for_each_kind);
  RUN_TEST(test_event_once_per_day_writes_again_on_the_next_utc_day);
  RUN_TEST(test_threads_write_one_event_line_on_a_new_day);
  RUN_TEST(test_each_x402_step_and_outcome_becomes_one_exact_line);
  RUN_TEST(test_x402_step_line_that_does_not_fit_the_buffer_is_lost);
  RUN_TEST(test_stop_writes_the_waiting_lines_to_a_new_file);
  RUN_TEST(test_file_writer_writes_at_each_interval);
  RUN_TEST(test_file_writer_appends_to_the_file);
  RUN_TEST(test_file_writer_creates_the_file_with_mode_0644);
  RUN_TEST(test_file_writer_with_no_line_creates_no_file);
  RUN_TEST(test_stop_without_a_file_writer_takes_no_line);
  RUN_TEST(test_lines_the_file_refuses_are_lost_and_counted);
  RUN_TEST(test_cut_write_counts_the_unwritten_lines_lost);
  RUN_TEST(test_write_after_a_cut_line_starts_on_a_new_line);
  RUN_TEST(test_cut_write_goes_on_with_the_rest);
  RUN_TEST(test_lines_lost_during_a_failed_write_add_to_the_count);
  RUN_TEST(test_interrupted_write_is_tried_again);
  RUN_TEST(test_failure_after_a_good_write_is_named_again);
  RUN_TEST(test_two_good_writes_leave_no_blank_line);
  RUN_TEST(test_cut_at_a_line_end_adds_no_newline);
  RUN_TEST(test_failed_newline_is_tried_again);
  RUN_TEST(test_file_writer_closes_the_file);
  RUN_TEST(test_file_writer_waits_out_an_interval_below_one_second);
  RUN_TEST(test_refused_lost_line_after_whole_lines_keeps_its_count);
  RUN_TEST(test_file_writer_does_not_wait_for_a_fifo_reader);
  RUN_TEST(test_file_writer_does_not_follow_a_symlink);
  RUN_TEST(test_retention_days_are_90);
  RUN_TEST(test_registration_gate_test_count);
  return UNITY_END();
}
