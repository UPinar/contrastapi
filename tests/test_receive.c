#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/time.h>

#include "unity/unity.h"
#include "receive.h"

#define SAFETY_TIMEOUT_MS   1000
#define SILENT_TIMEOUT_MS   100
#define TEST_BUF_SIZE       256

#define BIG_BODY_BYTE_COUNT 1000


static int g_fds[2] = { -1, -1 };

static bool   g_isMmapFailing  = false;
static void*  g_mmapAddress    = NULL;
static size_t g_mmapLength     = 0;
static void*  g_madviseAddress = NULL;
static size_t g_madviseLength  = 0;
static int    g_madviseAdvice  = 0;
static void*  g_munmapAddress  = NULL;
static size_t g_munmapLength   = 0;
static int    g_munmapCount    = 0;

void* __real_mmap(void* address, size_t length, int protection, int flags, int fd, off_t offset);
int   __real_madvise(void* address, size_t length, int advice);
int   __real_munmap(void* address, size_t length);

void* __wrap_mmap(void* address, size_t length, int protection, int flags, int fd, off_t offset)
{
  if (g_isMmapFailing)
  {
    g_isMmapFailing = false;
    return MAP_FAILED;
  }
  g_mmapAddress = __real_mmap(address, length, protection, flags, fd, offset);
  g_mmapLength  = length;
  return g_mmapAddress;
}

int __wrap_madvise(void* address, size_t length, int advice)
{
  g_madviseAddress = address;
  g_madviseLength  = length;
  g_madviseAdvice  = advice;
  return __real_madvise(address, length, advice);
}

int __wrap_munmap(void* address, size_t length)
{
  g_munmapAddress = address;
  g_munmapLength  = length;
  g_munmapCount++;
  return __real_munmap(address, length);
}

void setUp(void)
{
  g_fds[0] = -1;
  g_fds[1] = -1;
  g_isMmapFailing  = false;
  g_mmapAddress    = NULL;
  g_mmapLength     = 0;
  g_madviseAddress = NULL;
  g_madviseLength  = 0;
  g_madviseAdvice  = 0;
  g_munmapAddress  = NULL;
  g_munmapLength   = 0;
  g_munmapCount    = 0;
}

static void static_closePair(void)
{
  for (int i = 0; i < 2; i++)
  {
    if (g_fds[i] >= 0)
      close(g_fds[i]);
    g_fds[i] = -1;
  }
}

void tearDown(void)
{
  static_closePair();
}

static void static_openPair(int type, int timeout_ms)
{
  TEST_ASSERT_EQUAL_INT(0, socketpair(AF_UNIX, type, 0, g_fds));
  struct timeval timeout = { .tv_sec = timeout_ms / 1000, .tv_usec = (timeout_ms % 1000) * 1000 };
  TEST_ASSERT_EQUAL_INT(0, setsockopt(g_fds[0], SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)));
}

static void static_send(const char* bytes, size_t len)
{
  TEST_ASSERT_EQUAL_INT((int)len, (int)write(g_fds[1], bytes, len));
}

static void static_sendText(const char* text)
{
  static_send(text, strlen(text));
}

static ReceiveStatus_t static_readRequest(char* buf, size_t buf_size, size_t max_body_byte_count, ReceiveResult_t* result)
{
  ReceiveStatus_t status = receive_readHead(g_fds[0], buf, buf_size, result);
  if (status == RECEIVE_OK)
    status = receive_readBodyLength(max_body_byte_count, result);
  if (status == RECEIVE_OK)
    status = receive_readBody(g_fds[0], buf, buf_size, result);
  return status;
}

static void static_assertHeadEndsTheRead(const char* head)
{
  static_openPair(SOCK_STREAM, SAFETY_TIMEOUT_MS);
  static_sendText(head);

  char buf[TEST_BUF_SIZE];
  ReceiveResult_t result = { 0 };
  TEST_ASSERT_EQUAL_INT(RECEIVE_OK, static_readRequest(buf, sizeof(buf), sizeof(buf), &result));
  TEST_ASSERT_EQUAL_STRING(head, buf);
  TEST_ASSERT_EQUAL_size_t(strlen(head), result.m_requestLen);
}

void test_crlf_blank_line_ends_the_head(void)
{
  static_assertHeadEndsTheRead("GET / HTTP/1.1\r\nHost: x\r\n\r\n");
}

void test_lf_only_blank_line_ends_the_head(void)
{
  static_assertHeadEndsTheRead("GET / HTTP/1.1\nHost: x\n\n");
}

void test_mixed_blank_line_ends_the_head(void)
{
  static_assertHeadEndsTheRead("GET / HTTP/1.1\r\nHost: x\r\n\n");
}

void test_body_that_arrives_with_the_head_is_kept(void)
{
  static const char head[] = "POST /mcp HTTP/1.1\r\nContent-Length: 4\r\n\r\n";
  static_assertHeadEndsTheRead("POST /mcp HTTP/1.1\r\nContent-Length: 4\r\n\r\nabcd");
  static_closePair();

  static_openPair(SOCK_STREAM, SAFETY_TIMEOUT_MS);
  static_sendText("POST /mcp HTTP/1.1\r\nContent-Length: 4\r\n\r\nabcd");
  char buf[TEST_BUF_SIZE];
  ReceiveResult_t result = { 0 };
  TEST_ASSERT_EQUAL_INT(RECEIVE_OK, static_readRequest(buf, sizeof(buf), sizeof(buf), &result));
  TEST_ASSERT_EQUAL_size_t(strlen(head), result.m_headLen);
  TEST_ASSERT_EQUAL_size_t(4, result.m_bodyLen);
  TEST_ASSERT_NULL(result.mp_largeBuf);
}

void test_head_sent_one_byte_per_read_is_read_whole(void)
{
  static const char head[] = "GET /cve_lookup/CVE-2024-0001 HTTP/1.1\r\nHost: x\r\n\r\n";
  static_openPair(SOCK_SEQPACKET, SAFETY_TIMEOUT_MS);
  for (size_t i = 0; i < strlen(head); i++)
    static_send(&head[i], 1);

  char buf[TEST_BUF_SIZE];
  ReceiveResult_t result = { 0 };
  TEST_ASSERT_EQUAL_INT(RECEIVE_OK, static_readRequest(buf, sizeof(buf), sizeof(buf), &result));
  TEST_ASSERT_EQUAL_STRING(head, buf);
  TEST_ASSERT_EQUAL_size_t(strlen(head), result.m_requestLen);
}

void test_nothing_after_the_head_is_read(void)
{
  static const char head[] = "POST /mcp HTTP/1.1\r\n\r\n";
  static_openPair(SOCK_SEQPACKET, SAFETY_TIMEOUT_MS);
  static_sendText(head);
  static_sendText("later");

  char buf[TEST_BUF_SIZE];
  ReceiveResult_t result = { 0 };
  TEST_ASSERT_EQUAL_INT(RECEIVE_OK, static_readRequest(buf, sizeof(buf), sizeof(buf), &result));
  TEST_ASSERT_EQUAL_size_t(strlen(head), result.m_requestLen);

  char rest[16] = "";
  TEST_ASSERT_EQUAL_INT(5, (int)read(g_fds[0], rest, sizeof(rest) - 1));
  TEST_ASSERT_EQUAL_STRING("later", rest);
}

void test_read_bytes_end_with_a_nul(void)
{
  static const char head[] = "GET / HTTP/1.1\r\n\r\n";
  static_openPair(SOCK_STREAM, SAFETY_TIMEOUT_MS);
  static_sendText(head);

  char buf[64];
  memset(buf, 'x', sizeof(buf) - 1);
  buf[sizeof(buf) - 1] = '\0';
  ReceiveResult_t result = { 0 };
  TEST_ASSERT_EQUAL_INT(RECEIVE_OK, static_readRequest(buf, sizeof(buf), sizeof(buf), &result));
  TEST_ASSERT_EQUAL_STRING(head, buf);
}

void test_buffer_full_stops_the_read_inside_the_buffer(void)
{
  static_openPair(SOCK_STREAM, SAFETY_TIMEOUT_MS);
  static_sendText("GET /aaaaaaaaaaaaaaa");

  char area[32];
  memset(area, 'C', sizeof(area));
  ReceiveResult_t result = { .m_requestLen = 99 };
  TEST_ASSERT_EQUAL_INT(RECEIVE_ERR_URI_TOO_LONG, static_readRequest(area, 16, 16, &result));
  TEST_ASSERT_EQUAL_size_t(0, result.m_requestLen);
  TEST_ASSERT_EQUAL_STRING("GET /aaaaaaaaaa", area);
  for (size_t i = 16; i < sizeof(area); i++)
    TEST_ASSERT_EQUAL_CHAR('C', area[i]);
}

void test_head_that_ends_on_the_last_byte_that_fits_is_read(void)
{
  static const char fits[] = "GET / HTTP/1.1\r\n\r\n";
  TEST_ASSERT_EQUAL_size_t(18, strlen(fits));
  static_openPair(SOCK_STREAM, SAFETY_TIMEOUT_MS);
  static_sendText(fits);
  char buf[19];
  ReceiveResult_t result = { 0 };
  TEST_ASSERT_EQUAL_INT(RECEIVE_OK, static_readRequest(buf, sizeof(buf), sizeof(buf), &result));
  TEST_ASSERT_EQUAL_size_t(18, result.m_requestLen);
  static_closePair();

  static const char too_long[] = "GET /a HTTP/1.1\r\n\r\n";
  TEST_ASSERT_EQUAL_size_t(19, strlen(too_long));
  static_openPair(SOCK_STREAM, SAFETY_TIMEOUT_MS);
  static_sendText(too_long);
  TEST_ASSERT_EQUAL_INT(RECEIVE_ERR_HEAD_TOO_LARGE, static_readRequest(buf, sizeof(buf), sizeof(buf), &result));
}

void test_client_that_closes_answers_closed(void)
{
  static_openPair(SOCK_STREAM, SAFETY_TIMEOUT_MS);
  static_sendText("GET / HTTP/1.1\r\n");
  TEST_ASSERT_EQUAL_INT(0, shutdown(g_fds[1], SHUT_WR));
  char buf[TEST_BUF_SIZE];
  ReceiveResult_t result = { 0 };
  TEST_ASSERT_EQUAL_INT(RECEIVE_ERR_CLOSED, static_readRequest(buf, sizeof(buf), sizeof(buf), &result));
  static_closePair();

  static_openPair(SOCK_STREAM, SAFETY_TIMEOUT_MS);
  TEST_ASSERT_EQUAL_INT(0, shutdown(g_fds[1], SHUT_WR));
  TEST_ASSERT_EQUAL_INT(RECEIVE_ERR_CLOSED, static_readRequest(buf, sizeof(buf), sizeof(buf), &result));
}

void test_silent_client_answers_read(void)
{
  static_openPair(SOCK_STREAM, SILENT_TIMEOUT_MS);
  static_sendText("GET / HTTP/1.1\r\n");
  char buf[TEST_BUF_SIZE];
  ReceiveResult_t result = { 0 };
  TEST_ASSERT_EQUAL_INT(RECEIVE_ERR_READ, static_readRequest(buf, sizeof(buf), sizeof(buf), &result));
  static_closePair();

  static_openPair(SOCK_STREAM, SILENT_TIMEOUT_MS);
  TEST_ASSERT_EQUAL_INT(RECEIVE_ERR_READ, static_readRequest(buf, sizeof(buf), sizeof(buf), &result));
}

void test_nul_in_the_head_is_malformed(void)
{
  static const char head[] = "GET /\0 HTTP/1.1\r\n\r\n";
  static_openPair(SOCK_STREAM, SAFETY_TIMEOUT_MS);
  static_send(head, sizeof(head) - 1);
  char buf[TEST_BUF_SIZE];
  ReceiveResult_t result = { 0 };
  TEST_ASSERT_EQUAL_INT(RECEIVE_ERR_MALFORMED, static_readRequest(buf, sizeof(buf), sizeof(buf), &result));
}

#define CLOCK_SCRIPT_CAPACITY 8
static struct timespec g_clockScript[CLOCK_SCRIPT_CAPACITY];
static int             g_clockScriptLen              = 0;
static int             g_clockReadCount              = 0;
static int             g_nonMonotonicClockReadCount  = 0;
static int             g_unreadByteCountAtClockStart = -1;

int __real_clock_gettime(clockid_t clock_id, struct timespec* time_out);

int __wrap_clock_gettime(clockid_t clock_id, struct timespec* time_out)
{
  if (g_clockScriptLen > 0)
  {
    if (clock_id != CLOCK_MONOTONIC)
      g_nonMonotonicClockReadCount++;
    if (g_clockReadCount == 0 && ioctl(g_fds[0], FIONREAD, &g_unreadByteCountAtClockStart) != 0)
      g_unreadByteCountAtClockStart = -1;
    int index = g_clockReadCount < g_clockScriptLen ? g_clockReadCount : g_clockScriptLen - 1;
    g_clockReadCount++;
    *time_out = g_clockScript[index];
    return 0;
  }
  return __real_clock_gettime(clock_id, time_out);
}

#define DEADLINE_US 10000000LL

static struct timespec static_timeAfterUs(struct timespec start_time, long long elapsed_us)
{
  long long nsec = start_time.tv_nsec + elapsed_us * 1000LL;
  struct timespec later = { .tv_sec = start_time.tv_sec + (time_t)(nsec / 1000000000LL), .tv_nsec = (long)(nsec % 1000000000LL) };
  return later;
}

static ReceiveStatus_t static_readRequestWithClockScript(char* buf, size_t buf_size, const struct timespec* readings, int reading_count, ReceiveResult_t* result)
{
  TEST_ASSERT_TRUE(reading_count >= 1 && reading_count <= CLOCK_SCRIPT_CAPACITY);
  memcpy(g_clockScript, readings, (size_t)reading_count * sizeof(readings[0]));
  g_clockReadCount              = 0;
  g_nonMonotonicClockReadCount  = 0;
  g_unreadByteCountAtClockStart = -1;
  g_clockScriptLen              = reading_count;

  ReceiveStatus_t status = static_readRequest(buf, buf_size, buf_size, result);
  int clock_read_count = g_clockReadCount;
  g_clockScriptLen = 0;
  TEST_ASSERT_EQUAL_INT(reading_count, clock_read_count);
  TEST_ASSERT_EQUAL_INT(0, g_nonMonotonicClockReadCount);
  return status;
}

void test_deadline_passed_when_reached_exactly(void)
{
  static_openPair(SOCK_SEQPACKET, SAFETY_TIMEOUT_MS);
  static_sendText("GET / HTTP/1.1\r\n");
  static_sendText("\r\n");
  struct timespec start_time  = { .tv_sec = 10, .tv_nsec = 990000000L };
  struct timespec readings[2] = { start_time, static_timeAfterUs(start_time, DEADLINE_US) };

  char buf[TEST_BUF_SIZE];
  ReceiveResult_t result = { 0 };
  TEST_ASSERT_EQUAL_INT(RECEIVE_ERR_DEADLINE, static_readRequestWithClockScript(buf, sizeof(buf), readings, 2, &result));
  TEST_ASSERT_EQUAL_INT(18, g_unreadByteCountAtClockStart);

  char rest[8] = "";
  TEST_ASSERT_EQUAL_INT(2, (int)read(g_fds[0], rest, sizeof(rest) - 1));
}

void test_deadline_not_passed_just_under_across_a_second(void)
{
  static_openPair(SOCK_SEQPACKET, SAFETY_TIMEOUT_MS);
  static_sendText("GET / HTTP/1.1\r\n");
  static_sendText("\r\n");
  struct timespec start_time  = { .tv_sec = 10, .tv_nsec = 999950000L };
  struct timespec readings[2] = { start_time, static_timeAfterUs(start_time, DEADLINE_US - 50) };
  TEST_ASSERT_TRUE(readings[1].tv_nsec < start_time.tv_nsec);

  char buf[TEST_BUF_SIZE];
  ReceiveResult_t result = { 0 };
  TEST_ASSERT_EQUAL_INT(RECEIVE_OK, static_readRequestWithClockScript(buf, sizeof(buf), readings, 2, &result));
}

void test_reads_that_end_the_head_and_the_body_skip_the_deadline_check(void)
{
  static_openPair(SOCK_SEQPACKET, SAFETY_TIMEOUT_MS);
  static_sendText("POST /mcp HTTP/1.1\r\nContent-Length: 1\r\n\r\n");
  static_sendText("a");
  struct timespec readings[1] = { { .tv_sec = 10, .tv_nsec = 0 } };

  char buf[TEST_BUF_SIZE];
  ReceiveResult_t result = { 0 };
  TEST_ASSERT_EQUAL_INT(RECEIVE_OK, static_readRequestWithClockScript(buf, sizeof(buf), readings, 1, &result));
}

#define DRIP_LINE_COUNT 8
#define DRIP_STEP_US    (RECEIVE_DEADLINE_MS * 1000LL / 4)

void test_deadline_bounds_the_whole_head_not_each_gap(void)
{
  static_openPair(SOCK_SEQPACKET, SAFETY_TIMEOUT_MS);
  static_sendText("GET / HTTP/1.1\r\n");
  for (int i = 0; i < DRIP_LINE_COUNT; i++)
  {
    char line[16];
    snprintf(line, sizeof(line), "X%d: y\r\n", i + 1);
    static_sendText(line);
  }
  static_sendText("\r\n");

  struct timespec start_time = { .tv_sec = 10, .tv_nsec = 0 };
  struct timespec readings[5];
  for (int i = 0; i < 5; i++)
    readings[i] = static_timeAfterUs(start_time, i * DRIP_STEP_US);

  char buf[TEST_BUF_SIZE];
  ReceiveResult_t result = { 0 };
  TEST_ASSERT_EQUAL_INT(RECEIVE_ERR_DEADLINE, static_readRequestWithClockScript(buf, sizeof(buf), readings, 5, &result));

  char rest[16] = "";
  TEST_ASSERT_EQUAL_INT(7, (int)read(g_fds[0], rest, sizeof(rest) - 1));
  TEST_ASSERT_EQUAL_STRING("X4: y\r\n", rest);
}

static void static_fillTwoHeaders(ReceiveResult_t* request)
{
  memset(request, 0, sizeof(*request));
  request->ma_headers[0] = (struct phr_header){ "Host",      4, "x",         1 };
  request->ma_headers[1] = (struct phr_header){ "X-Real-IP", 9, "192.0.2.1", 9 };
  request->m_headerCount = 2;
}

static void static_assertHeaderNone(ReceiveHeader_t header)
{
  TEST_ASSERT_EQUAL_INT(RECEIVE_HEADER_NONE, header.m_status);
  TEST_ASSERT_NULL(header.mp_value);
  TEST_ASSERT_EQUAL_size_t(0, header.m_len);
}

static void static_assertHeaderFound(ReceiveHeader_t header, const char* expected, size_t len)
{
  TEST_ASSERT_EQUAL_INT(RECEIVE_HEADER_FOUND, header.m_status);
  TEST_ASSERT_NOT_NULL(header.mp_value);
  TEST_ASSERT_EQUAL_size_t(len, header.m_len);
  TEST_ASSERT_EQUAL_MEMORY(expected, header.mp_value, len);
}

void test_find_header_finds_a_header_by_its_name_in_any_case(void)
{
  ReceiveResult_t request;
  static_fillTwoHeaders(&request);

  static_assertHeaderFound(receive_findHeader(&request, "x-real-ip"), "192.0.2.1", 9);
  static_assertHeaderFound(receive_findHeader(&request, "HOST"), "x", 1);
  static_assertHeaderNone(receive_findHeader(&request, "x-api-key"));
}

void test_find_header_answers_the_first_of_two_headers(void)
{
  ReceiveResult_t request;
  memset(&request, 0, sizeof(request));
  request.ma_headers[0] = (struct phr_header){ "PAYMENT-SIGNATURE", 17, "v0", 2 };
  request.ma_headers[1] = (struct phr_header){ "Host",               4, "x",  1 };
  request.ma_headers[2] = (struct phr_header){ "payment-signature", 17, "v2", 2 };
  request.m_headerCount = 3;

  static_assertHeaderFound(receive_findHeader(&request, "payment-signature"), "v0", 2);
}

void test_find_header_skips_a_folded_continuation_line(void)
{
  ReceiveResult_t request;
  memset(&request, 0, sizeof(request));
  request.ma_headers[0] = (struct phr_header){ NULL,   0, "folded", 6 };
  request.ma_headers[1] = (struct phr_header){ "Host", 4, "x",      1 };
  request.m_headerCount = 2;

  static_assertHeaderFound(receive_findHeader(&request, "host"), "x", 1);
  static_assertHeaderNone(receive_findHeader(&request, ""));
}

static void static_fillPaymentHeaders(ReceiveResult_t* request, const char* const* names, size_t header_count)
{
  static const char* const values[] = { "v0", "v1", "v2", "v3", "v4" };
  TEST_ASSERT_TRUE(header_count <= sizeof(values) / sizeof(values[0]));
  memset(request, 0, sizeof(*request));
  for (size_t i = 0; i < header_count; i++)
    request->ma_headers[i] = (struct phr_header){ names[i], strlen(names[i]), values[i], 2 };
  request->m_headerCount = header_count;
}

static void static_assertHeaderRepeated(ReceiveHeader_t header)
{
  TEST_ASSERT_EQUAL_INT(RECEIVE_HEADER_REPEATED, header.m_status);
  TEST_ASSERT_NULL(header.mp_value);
  TEST_ASSERT_EQUAL_size_t(0, header.m_len);
}

void test_find_unique_header_answers_none_when_no_header_has_the_name(void)
{
  ReceiveResult_t request;
  static_fillTwoHeaders(&request);

  static_assertHeaderNone(receive_findUniqueHeader(&request, "payment-signature"));
}

void test_find_unique_header_finds_the_one_header_with_the_name(void)
{
  static const char* const names[] = { "Host", "X-Real-IP", "PAYMENT-SIGNATURE" };
  ReceiveResult_t request;
  static_fillPaymentHeaders(&request, names, 3);

  static_assertHeaderFound(receive_findUniqueHeader(&request, "payment-signature"), "v2", 2);
}

void test_find_unique_header_refuses_two_headers_of_one_name(void)
{
  static const char* const same_case[]  = { "PAYMENT-SIGNATURE", "Host", "PAYMENT-SIGNATURE" };
  static const char* const other_case[] = { "PAYMENT-SIGNATURE", "Host", "payment-signature" };
  ReceiveResult_t request;

  static_fillPaymentHeaders(&request, same_case, 3);
  static_assertHeaderRepeated(receive_findUniqueHeader(&request, "Payment-Signature"));

  static_fillPaymentHeaders(&request, other_case, 3);
  static_assertHeaderRepeated(receive_findUniqueHeader(&request, "Payment-Signature"));
}

void test_find_unique_header_refuses_three_headers_of_one_name(void)
{
  static const char* const names[] = { "PAYMENT-SIGNATURE", "Host", "Payment-Signature", "X-Real-IP", "payment-signature" };
  ReceiveResult_t request;
  static_fillPaymentHeaders(&request, names, 5);

  static_assertHeaderRepeated(receive_findUniqueHeader(&request, "payment-signature"));
}

void test_find_unique_header_counts_no_header_whose_name_only_shares_a_prefix(void)
{
  static const char* const names[] = { "PAYMENT-SIGNATURE-V2", "PAYMENT", "PAYMENT-SIGNATURE" };
  ReceiveResult_t request;
  static_fillPaymentHeaders(&request, names, 3);

  static_assertHeaderFound(receive_findUniqueHeader(&request, "payment-signature"), "v2", 2);
  static_assertHeaderNone(receive_findUniqueHeader(&request, "payment-signature-v"));
}

static void static_assertFramingStatus(const char* text, ReceiveStatus_t expected)
{
  static_openPair(SOCK_STREAM, SAFETY_TIMEOUT_MS);
  static_sendText(text);
  char buf[TEST_BUF_SIZE];
  ReceiveResult_t result = { 0 };
  TEST_ASSERT_EQUAL_INT_MESSAGE(expected, static_readRequest(buf, sizeof(buf), sizeof(buf), &result), text);
  TEST_ASSERT_EQUAL_size_t_MESSAGE(0, result.m_requestLen, text);
  static_closePair();
}

void test_body_sent_after_the_head_is_read_to_its_length(void)
{
  static const char head[] = "POST /mcp HTTP/1.1\r\nContent-Length: 10\r\n\r\n";
  static_openPair(SOCK_SEQPACKET, SAFETY_TIMEOUT_MS);
  static_sendText(head);
  static_sendText("abcde");
  static_sendText("fghij");

  char buf[TEST_BUF_SIZE];
  ReceiveResult_t result = { 0 };
  TEST_ASSERT_EQUAL_INT(RECEIVE_OK, static_readRequest(buf, sizeof(buf), sizeof(buf), &result));
  TEST_ASSERT_EQUAL_size_t(strlen(head), result.m_headLen);
  TEST_ASSERT_EQUAL_size_t(10, result.m_bodyLen);
  TEST_ASSERT_EQUAL_size_t(strlen(head) + 10, result.m_requestLen);
  TEST_ASSERT_EQUAL_STRING("abcdefghij", buf + result.m_headLen);
}

void test_body_sent_one_byte_per_read_is_read_whole(void)
{
  static_openPair(SOCK_SEQPACKET, SAFETY_TIMEOUT_MS);
  static_sendText("POST /mcp HTTP/1.1\r\nContent-Length: 4\r\n\r\n");
  static_sendText("w");
  static_sendText("x");
  static_sendText("y");
  static_sendText("z");

  char buf[TEST_BUF_SIZE];
  ReceiveResult_t result = { 0 };
  TEST_ASSERT_EQUAL_INT(RECEIVE_OK, static_readRequest(buf, sizeof(buf), sizeof(buf), &result));
  TEST_ASSERT_EQUAL_STRING("wxyz", buf + result.m_headLen);
}

void test_bytes_after_the_body_are_not_part_of_the_request(void)
{
  static const char head[] = "POST /mcp HTTP/1.1\r\nContent-Length: 4\r\n\r\n";
  static_openPair(SOCK_STREAM, SAFETY_TIMEOUT_MS);
  static_sendText("POST /mcp HTTP/1.1\r\nContent-Length: 4\r\n\r\nabcdEXTRA");

  char buf[TEST_BUF_SIZE];
  ReceiveResult_t result = { 0 };
  TEST_ASSERT_EQUAL_INT(RECEIVE_OK, static_readRequest(buf, sizeof(buf), sizeof(buf), &result));
  TEST_ASSERT_EQUAL_size_t(strlen(head) + 4, result.m_requestLen);
  TEST_ASSERT_EQUAL_STRING("abcd", buf + result.m_headLen);
}

void test_client_that_closes_inside_the_body_answers_closed(void)
{
  static_openPair(SOCK_STREAM, SAFETY_TIMEOUT_MS);
  static_sendText("POST /mcp HTTP/1.1\r\nContent-Length: 10\r\n\r\nabc");
  TEST_ASSERT_EQUAL_INT(0, shutdown(g_fds[1], SHUT_WR));

  char buf[TEST_BUF_SIZE];
  ReceiveResult_t result = { 0 };
  TEST_ASSERT_EQUAL_INT(RECEIVE_ERR_CLOSED, static_readRequest(buf, sizeof(buf), sizeof(buf), &result));
  TEST_ASSERT_EQUAL_size_t(0, result.m_requestLen);
}

void test_deadline_keeps_running_while_the_body_arrives(void)
{
  static_openPair(SOCK_SEQPACKET, SAFETY_TIMEOUT_MS);
  static_sendText("POST /mcp HTTP/1.1\r\nContent-Length: 4\r\n\r\n");
  static_sendText("a");
  static_sendText("b");
  struct timespec start_time  = { .tv_sec = 10, .tv_nsec = 0 };
  struct timespec readings[2] = { start_time, static_timeAfterUs(start_time, RECEIVE_DEADLINE_MS * 1000LL) };

  char buf[TEST_BUF_SIZE];
  ReceiveResult_t result = { 0 };
  TEST_ASSERT_EQUAL_INT(RECEIVE_ERR_DEADLINE, static_readRequestWithClockScript(buf, sizeof(buf), readings, 2, &result));

  char rest[8] = "";
  TEST_ASSERT_EQUAL_INT(1, (int)read(g_fds[0], rest, sizeof(rest) - 1));
  TEST_ASSERT_EQUAL_STRING("b", rest);
}

#define BODY_LIMIT 20

void test_body_as_long_as_its_limit_is_read_and_one_byte_more_is_refused(void)
{
  char body[BODY_LIMIT + 1];
  memset(body, 'b', sizeof(body));
  for (int extra = 0; extra <= 1; extra++)
  {
    size_t body_len = BODY_LIMIT + (size_t)extra;
    char   head[64];
    snprintf(head, sizeof(head), "POST /mcp HTTP/1.1\r\nContent-Length: %zu\r\n\r\n", body_len);

    static_openPair(SOCK_SEQPACKET, SAFETY_TIMEOUT_MS);
    static_sendText(head);
    static_send(body, body_len);
    char buf[TEST_BUF_SIZE];
    ReceiveResult_t result = { 0 };
    ReceiveStatus_t status = static_readRequest(buf, sizeof(buf), BODY_LIMIT, &result);
    if (extra == 0)
    {
      TEST_ASSERT_EQUAL_INT(RECEIVE_OK, status);
      TEST_ASSERT_EQUAL_size_t(BODY_LIMIT, result.m_bodyLen);
    }
    else
    {
      TEST_ASSERT_EQUAL_INT(RECEIVE_ERR_CONTENT_TOO_LARGE, status);
      char rest[64];
      TEST_ASSERT_EQUAL_INT((int)body_len, (int)read(g_fds[0], rest, sizeof(rest)));
    }
    static_closePair();
  }
}

void test_content_length_too_wide_for_a_size_is_too_large(void)
{
  static_assertFramingStatus("POST /mcp HTTP/1.1\r\nContent-Length: 18446744073709551617000\r\n\r\n", RECEIVE_ERR_CONTENT_TOO_LARGE);
}

void test_malformed_content_length_is_refused(void)
{
  static const char* const heads[] = {
    "POST /mcp HTTP/1.1\r\nContent-Length: \r\n\r\n",
    "POST /mcp HTTP/1.1\r\nContent-Length: 5, 5\r\n\r\n",
    "POST /mcp HTTP/1.1\r\nContent-Length: +5\r\n\r\n",
    "POST /mcp HTTP/1.1\r\nContent-Length: -1\r\n\r\n",
    "POST /mcp HTTP/1.1\r\nContent-Length: 5a\r\n\r\n",
    "POST /mcp HTTP/1.1\r\nContent-Length: 0x5\r\n\r\n",
    "POST /mcp HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\n",
  };
  for (size_t i = 0; i < sizeof(heads) / sizeof(heads[0]); i++)
    static_assertFramingStatus(heads[i], RECEIVE_ERR_BAD_CONTENT_LENGTH);
}

void test_transfer_encoding_is_refused(void)
{
  static_assertFramingStatus("POST /mcp HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n", RECEIVE_ERR_TRANSFER_ENCODING);
  static_assertFramingStatus("POST /mcp HTTP/1.1\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\nabcd", RECEIVE_ERR_LENGTH_AND_TRANSFER_ENCODING);
  static_assertFramingStatus("POST /mcp HTTP/1.1\r\nTRANSFER-ENCODING: chunked\r\n\r\n", RECEIVE_ERR_TRANSFER_ENCODING);
}

void test_transfer_encoding_check_runs_before_the_second_length_check(void)
{
  static_assertFramingStatus("POST /mcp HTTP/1.1\r\nContent-Length: 4\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\nabcd", RECEIVE_ERR_LENGTH_AND_TRANSFER_ENCODING);
}

void test_folded_header_line_is_malformed(void)
{
  static_assertFramingStatus("POST /mcp HTTP/1.1\r\nContent-Length: 2\r\n 5\r\n\r\nab", RECEIVE_ERR_MALFORMED);
  static_assertFramingStatus("POST /mcp HTTP/1.1\r\nContent-Length: 2\r\n 5\r\nHost: x\r\n\r\nab", RECEIVE_ERR_MALFORMED);
  static_assertFramingStatus("POST /mcp HTTP/1.1\r\nX-A: a\r\n Content-Length: 5\r\n\r\nabcde", RECEIVE_ERR_MALFORMED);
  static_assertFramingStatus("POST /mcp HTTP/1.1\r\nTransfer-Encoding: chunked\r\n x\r\n\r\n", RECEIVE_ERR_MALFORMED);
}

void test_bare_cr_in_a_header_line_is_malformed(void)
{
  static_assertFramingStatus("GET / HTTP/1.1\r\nX-API-Key: a\rb\r\n\r\n", RECEIVE_ERR_MALFORMED);
  static_assertFramingStatus("GET / HTTP/1.1\r\nX-A: a\rHost: x\r\n\r\n", RECEIVE_ERR_MALFORMED);
}

static void static_buildHeadWithHeaders(char* head, size_t head_size, int header_count, bool is_last_malformed)
{
  size_t pos = (size_t)snprintf(head, head_size, "GET / HTTP/1.1\r\n");
  for (int i = 0; i < header_count; i++)
    pos += (size_t)snprintf(head + pos, head_size - pos, "%s", (is_last_malformed && i == header_count - 1) ? "bad\r\n" : "X: y\r\n");
  snprintf(head + pos, head_size - pos, "\r\n");
}

void test_header_lines_past_the_cap_are_too_many(void)
{
  TEST_ASSERT_EQUAL_INT(64, HTTP_MAX_HEADERS);
  static char head[4096];
  static char buf[4096];
  static const struct { int m_count; bool m_isLastMalformed; ReceiveStatus_t m_status; } cases[] = {
    { HTTP_MAX_HEADERS,     false, RECEIVE_OK },
    { HTTP_MAX_HEADERS + 1, false, RECEIVE_ERR_TOO_MANY_HEADERS },
    { HTTP_MAX_HEADERS,     true,  RECEIVE_ERR_MALFORMED },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    static_buildHeadWithHeaders(head, sizeof(head), cases[i].m_count, cases[i].m_isLastMalformed);
    static_openPair(SOCK_STREAM, SAFETY_TIMEOUT_MS);
    static_sendText(head);
    ReceiveResult_t result = { 0 };
    TEST_ASSERT_EQUAL_INT(cases[i].m_status, static_readRequest(buf, sizeof(buf), sizeof(buf), &result));
    static_closePair();
  }
}

typedef struct {
  int         m_fd;
  bool        m_isWaitingForContinue;
  const char* mp_body;
  ssize_t     m_continueLen;
  char        ma_continue[64];
} ContinueClient_t;

static void* static_continueClient(void* client_arg)
{
  ContinueClient_t* client = client_arg;
  if (client->m_isWaitingForContinue)
  {
    client->m_continueLen = read(client->m_fd, client->ma_continue, sizeof(client->ma_continue) - 1);
    if (client->m_continueLen > 0)
      client->ma_continue[client->m_continueLen] = '\0';
  }
  if (write(client->m_fd, client->mp_body, strlen(client->mp_body)) < 0)
    return NULL;
  return NULL;
}

static ssize_t static_readWithContinueClient(const char* head, char* continue_out, size_t continue_out_size)
{
  static_openPair(SOCK_STREAM, SAFETY_TIMEOUT_MS);
  struct timeval timeout = { .tv_sec = 0, .tv_usec = SILENT_TIMEOUT_MS * 1000 };
  TEST_ASSERT_EQUAL_INT(0, setsockopt(g_fds[1], SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)));
  static_sendText(head);
  ContinueClient_t client = { .m_fd = g_fds[1], .m_isWaitingForContinue = true, .mp_body = "abcd", .m_continueLen = -1 };
  pthread_t client_thread;
  TEST_ASSERT_EQUAL_INT(0, pthread_create(&client_thread, NULL, static_continueClient, &client));

  char buf[TEST_BUF_SIZE];
  ReceiveResult_t result = { 0 };
  TEST_ASSERT_EQUAL_INT(RECEIVE_OK, static_readRequest(buf, sizeof(buf), sizeof(buf), &result));
  TEST_ASSERT_EQUAL_INT(0, pthread_join(client_thread, NULL));
  TEST_ASSERT_EQUAL_STRING("abcd", buf + result.m_headLen);
  snprintf(continue_out, continue_out_size, "%s", client.m_continueLen > 0 ? client.ma_continue : "");
  return client.m_continueLen;
}

void test_expect_continue_gets_100_before_the_body(void)
{
  char continue_text[64];
  static_readWithContinueClient("POST /mcp HTTP/1.1\r\nExpect: 100-continue\r\nContent-Length: 4\r\n\r\n", continue_text, sizeof(continue_text));
  TEST_ASSERT_EQUAL_STRING("HTTP/1.1 100 Continue\r\n\r\n", continue_text);
}

void test_expect_continue_gets_no_100_on_http_1_0_or_with_the_body_sent(void)
{
  char continue_text[64];
  TEST_ASSERT_TRUE(static_readWithContinueClient("POST /mcp HTTP/1.0\r\nExpect: 100-continue\r\nContent-Length: 4\r\n\r\n", continue_text, sizeof(continue_text)) < 0);
  static_closePair();

  static_openPair(SOCK_STREAM, SAFETY_TIMEOUT_MS);
  static_sendText("POST /mcp HTTP/1.1\r\nExpect: 100-continue\r\nContent-Length: 4\r\n\r\nabcd");
  char buf[TEST_BUF_SIZE];
  ReceiveResult_t result = { 0 };
  TEST_ASSERT_EQUAL_INT(RECEIVE_OK, static_readRequest(buf, sizeof(buf), sizeof(buf), &result));
  TEST_ASSERT_EQUAL_INT(0, shutdown(g_fds[0], SHUT_WR));
  char answer[8];
  TEST_ASSERT_EQUAL_INT(0, (int)read(g_fds[1], answer, sizeof(answer)));
}

void test_expect_value_is_compared_whole_and_in_any_case(void)
{
  char continue_text[64];
  static_readWithContinueClient("POST /mcp HTTP/1.1\r\nExpect: 100-Continue\r\nContent-Length: 4\r\n\r\n", continue_text, sizeof(continue_text));
  TEST_ASSERT_EQUAL_STRING("HTTP/1.1 100 Continue\r\n\r\n", continue_text);
  static_closePair();

  TEST_ASSERT_TRUE(static_readWithContinueClient("POST /mcp HTTP/1.1\r\nExpect: 100\r\nContent-Length: 4\r\n\r\n", continue_text, sizeof(continue_text)) < 0);
  static_closePair();

  TEST_ASSERT_TRUE(static_readWithContinueClient("POST /mcp HTTP/1.1\r\nExpect: 100-continues\r\nContent-Length: 4\r\n\r\n", continue_text, sizeof(continue_text)) < 0);
}

void test_header_named_a_prefix_of_a_framing_header_frames_nothing(void)
{
  static const char* const requests[] = {
    "POST /mcp HTTP/1.1\r\nContent: 9\r\nContent-Length: 4\r\n\r\nabcd",
    "POST /mcp HTTP/1.1\r\nTransfer: chunked\r\nContent-Length: 4\r\n\r\nabcd",
  };
  for (size_t i = 0; i < sizeof(requests) / sizeof(requests[0]); i++)
  {
    static_openPair(SOCK_STREAM, SAFETY_TIMEOUT_MS);
    static_sendText(requests[i]);
    char buf[TEST_BUF_SIZE];
    ReceiveResult_t result = { 0 };
    TEST_ASSERT_EQUAL_INT_MESSAGE(RECEIVE_OK, static_readRequest(buf, sizeof(buf), sizeof(buf), &result), requests[i]);
    TEST_ASSERT_EQUAL_size_t_MESSAGE(4, result.m_bodyLen, requests[i]);
    static_closePair();
  }
}

void test_expect_continue_gets_no_100_for_an_empty_body(void)
{
  static_openPair(SOCK_STREAM, SAFETY_TIMEOUT_MS);
  static_sendText("POST /mcp HTTP/1.1\r\nExpect: 100-continue\r\nContent-Length: 0\r\n\r\n");
  char buf[TEST_BUF_SIZE];
  ReceiveResult_t result = { 0 };
  TEST_ASSERT_EQUAL_INT(RECEIVE_OK, static_readRequest(buf, sizeof(buf), sizeof(buf), &result));
  TEST_ASSERT_EQUAL_INT(0, shutdown(g_fds[0], SHUT_WR));
  char answer[8];
  TEST_ASSERT_EQUAL_INT(0, (int)read(g_fds[1], answer, sizeof(answer)));
}

void test_max_body_byte_count_lets_a_body_grow_into_a_mapping(void)
{
  static char body[BIG_BODY_BYTE_COUNT + 1];
  memset(body, 'b', sizeof(body));
  for (size_t body_len = BIG_BODY_BYTE_COUNT; body_len <= BIG_BODY_BYTE_COUNT + 1; body_len++)
  {
    char head[96];
    snprintf(head, sizeof(head), "POST /big HTTP/1.1\r\nContent-Length: %zu\r\n\r\n", body_len);
    static_openPair(SOCK_STREAM, SAFETY_TIMEOUT_MS);
    static_sendText(head);
    static_send(body, body_len);
    char buf[128];
    ReceiveResult_t result = { 0 };
    ReceiveStatus_t status = static_readRequest(buf, sizeof(buf), BIG_BODY_BYTE_COUNT, &result);
    if (body_len == BIG_BODY_BYTE_COUNT)
    {
      TEST_ASSERT_EQUAL_INT(RECEIVE_OK, status);
      TEST_ASSERT_NOT_NULL(result.mp_largeBuf);
      TEST_ASSERT_EQUAL_size_t(strlen(head) + BIG_BODY_BYTE_COUNT, result.m_requestLen);
      TEST_ASSERT_EQUAL_MEMORY(head, result.mp_largeBuf, strlen(head));
      TEST_ASSERT_EQUAL_MEMORY(body, result.mp_largeBuf + result.m_headLen, BIG_BODY_BYTE_COUNT);
      TEST_ASSERT_EQUAL_CHAR('\0', result.mp_largeBuf[result.m_requestLen]);
      receive_releaseLargeBuf(&result);
    }
    else
    {
      TEST_ASSERT_EQUAL_INT(RECEIVE_ERR_CONTENT_TOO_LARGE, status);
      TEST_ASSERT_NULL(result.mp_largeBuf);
    }
    static_closePair();
  }
}

void test_head_and_body_length_are_read_without_the_body(void)
{
  static_openPair(SOCK_STREAM, SAFETY_TIMEOUT_MS);
  static_sendText("POST / HTTP/1.1\r\nExpect: 100-continue\r\nContent-Length: 4\r\n\r\n");
  char buf[TEST_BUF_SIZE];
  ReceiveResult_t result = { 0 };
  TEST_ASSERT_EQUAL_INT(RECEIVE_OK, receive_readHead(g_fds[0], buf, sizeof(buf), &result));
  TEST_ASSERT_EQUAL_INT(RECEIVE_OK, receive_readBodyLength(sizeof(buf), &result));
  TEST_ASSERT_EQUAL_size_t(4, result.m_bodyLen);
  TEST_ASSERT_TRUE(result.m_isContinueExpected);
  TEST_ASSERT_EQUAL_size_t(result.m_headLen, result.m_readLen);
  TEST_ASSERT_NULL(result.mp_body);
  TEST_ASSERT_EQUAL_INT(0, shutdown(g_fds[0], SHUT_WR));
  char answer[8];
  TEST_ASSERT_EQUAL_INT(0, (int)read(g_fds[1], answer, sizeof(answer)));
  static_closePair();

  static_openPair(SOCK_STREAM, SAFETY_TIMEOUT_MS);
  static_sendText("POST / HTTP/1.1\r\nContent-Length: 4\r\n\r\nab");
  TEST_ASSERT_EQUAL_INT(RECEIVE_OK, receive_readHead(g_fds[0], buf, sizeof(buf), &result));
  TEST_ASSERT_EQUAL_INT(RECEIVE_OK, receive_readBodyLength(sizeof(buf), &result));
  TEST_ASSERT_EQUAL_size_t(4, result.m_bodyLen);
  TEST_ASSERT_FALSE(result.m_isContinueExpected);
  TEST_ASSERT_EQUAL_size_t(result.m_headLen + 2, result.m_readLen);
  TEST_ASSERT_NULL(result.mp_body);
  static_sendText("cd");
  TEST_ASSERT_EQUAL_INT(0, shutdown(g_fds[1], SHUT_WR));
  char unread[8];
  TEST_ASSERT_EQUAL_INT(2, (int)read(g_fds[0], unread, sizeof(unread)));
  TEST_ASSERT_EQUAL_MEMORY("cd", unread, 2);
}

void test_mapping_that_cannot_be_made_answers_no_memory(void)
{
  static char body[1000];
  memset(body, 'b', sizeof(body));
  static_openPair(SOCK_STREAM, SAFETY_TIMEOUT_MS);
  static_sendText("POST /big HTTP/1.1\r\nContent-Length: 1000\r\n\r\n");
  static_send(body, sizeof(body));

  g_isMmapFailing = true;
  char buf[128];
  ReceiveResult_t result = { 0 };
  ReceiveStatus_t status = static_readRequest(buf, sizeof(buf), BIG_BODY_BYTE_COUNT, &result);
  g_isMmapFailing = false;
  TEST_ASSERT_EQUAL_INT(RECEIVE_ERR_LARGE_BODY_NO_MEMORY, status);
  TEST_ASSERT_NULL(result.mp_largeBuf);
  TEST_ASSERT_EQUAL_size_t(0, result.m_largeBufSize);
}

void test_mapping_is_kept_out_of_a_core_dump_and_unmapped_once(void)
{
  static char body[1000];
  memset(body, 'b', sizeof(body));
  static const char head[] = "POST /big HTTP/1.1\r\nContent-Length: 1000\r\n\r\n";
  char first_write[sizeof(head) - 1 + 50];
  memcpy(first_write, head, sizeof(head) - 1);
  memcpy(first_write + sizeof(head) - 1, body, 50);
  static_openPair(SOCK_STREAM, SAFETY_TIMEOUT_MS);
  static_send(first_write, sizeof(first_write));
  static_send(body + 50, sizeof(body) - 50);

  char buf[128];
  ReceiveResult_t result = { 0 };
  TEST_ASSERT_EQUAL_INT(RECEIVE_OK, static_readRequest(buf, sizeof(buf), BIG_BODY_BYTE_COUNT, &result));
  TEST_ASSERT_EQUAL_size_t(sizeof(head) - 1, result.m_headLen);
  TEST_ASSERT_NULL(memchr(buf + result.m_headLen, 'b', sizeof(buf) - result.m_headLen));
  TEST_ASSERT_EQUAL_MEMORY(head, buf, result.m_headLen);
  TEST_ASSERT_EQUAL_size_t(result.m_requestLen + 1, g_mmapLength);
  TEST_ASSERT_TRUE(result.mp_largeBuf == g_mmapAddress);
  TEST_ASSERT_EQUAL_size_t(g_mmapLength, result.m_largeBufSize);
  TEST_ASSERT_TRUE(g_madviseAddress == g_mmapAddress);
  TEST_ASSERT_EQUAL_size_t(g_mmapLength, g_madviseLength);
  TEST_ASSERT_EQUAL_INT(MADV_DONTDUMP, g_madviseAdvice);
  TEST_ASSERT_EQUAL_INT(0, g_munmapCount);

  receive_releaseLargeBuf(&result);
  TEST_ASSERT_EQUAL_INT(1, g_munmapCount);
  TEST_ASSERT_TRUE(g_munmapAddress == g_mmapAddress);
  TEST_ASSERT_EQUAL_size_t(g_mmapLength, g_munmapLength);
  TEST_ASSERT_NULL(result.mp_largeBuf);
  TEST_ASSERT_EQUAL_size_t(0, result.m_largeBufSize);
  TEST_ASSERT_NULL(result.mp_body);
  TEST_ASSERT_EQUAL_size_t(0, result.m_bodyLen);
  TEST_ASSERT_TRUE(result.mp_method == buf);

  receive_releaseLargeBuf(&result);
  TEST_ASSERT_EQUAL_INT(1, g_munmapCount);
}

void test_body_that_does_not_arrive_unmaps_its_mapping(void)
{
  static char body[500];
  memset(body, 'b', sizeof(body));
  static_openPair(SOCK_STREAM, SAFETY_TIMEOUT_MS);
  static_sendText("POST /big HTTP/1.1\r\nContent-Length: 1000\r\n\r\n");
  static_send(body, sizeof(body));
  TEST_ASSERT_EQUAL_INT(0, shutdown(g_fds[1], SHUT_WR));

  char buf[128];
  ReceiveResult_t result = { 0 };
  TEST_ASSERT_EQUAL_INT(RECEIVE_ERR_CLOSED, static_readRequest(buf, sizeof(buf), BIG_BODY_BYTE_COUNT, &result));
  TEST_ASSERT_NULL(result.mp_largeBuf);
  TEST_ASSERT_NOT_NULL(g_mmapAddress);
  TEST_ASSERT_EQUAL_INT(1, g_munmapCount);
  TEST_ASSERT_TRUE(g_munmapAddress == g_mmapAddress);
  TEST_ASSERT_EQUAL_size_t(g_mmapLength, g_munmapLength);
  static_closePair();

  static_openPair(SOCK_STREAM, SAFETY_TIMEOUT_MS);
  static_sendText("POST / HTTP/1.1\r\nContent-Length: 4\r\n\r\nab");
  TEST_ASSERT_EQUAL_INT(0, shutdown(g_fds[1], SHUT_WR));
  TEST_ASSERT_EQUAL_INT(RECEIVE_ERR_CLOSED, static_readRequest(buf, sizeof(buf), sizeof(buf), &result));
  TEST_ASSERT_NULL(result.mp_largeBuf);
  TEST_ASSERT_EQUAL_INT(1, g_munmapCount);
}

void test_ok_result_holds_the_parsed_head(void)
{
  static_openPair(SOCK_STREAM, SAFETY_TIMEOUT_MS);
  static_sendText("POST /mcp?x=1 HTTP/1.1\r\nHost: a\r\nContent-Length: 2\r\n\r\nab");

  char buf[TEST_BUF_SIZE];
  ReceiveResult_t result = { 0 };
  TEST_ASSERT_EQUAL_INT(RECEIVE_OK, static_readRequest(buf, sizeof(buf), sizeof(buf), &result));
  TEST_ASSERT_TRUE(result.mp_method == buf);
  TEST_ASSERT_EQUAL_size_t(4, result.m_methodLen);
  TEST_ASSERT_TRUE(result.mp_requestTarget == buf + 5);
  TEST_ASSERT_EQUAL_size_t(8, result.m_requestTargetLen);
  TEST_ASSERT_EQUAL_INT(1, result.m_httpMinorVersion);
  TEST_ASSERT_EQUAL_size_t(2, result.m_headerCount);
  TEST_ASSERT_EQUAL_MEMORY("Host", result.ma_headers[0].name, 4);
  TEST_ASSERT_EQUAL_MEMORY("2", result.ma_headers[1].value, 1);
  TEST_ASSERT_TRUE(result.mp_body == buf + result.m_headLen);
  TEST_ASSERT_EQUAL_STRING("ab", result.mp_body);
}

void test_body_of_a_mapped_request_is_read_from_the_mapping(void)
{
  static char body[1000];
  memset(body, 'b', sizeof(body));
  static_openPair(SOCK_STREAM, SAFETY_TIMEOUT_MS);
  static_sendText("POST /big HTTP/1.1\r\nContent-Length: 1000\r\n\r\n");
  static_send(body, sizeof(body));

  char buf[128];
  ReceiveResult_t result = { 0 };
  TEST_ASSERT_EQUAL_INT(RECEIVE_OK, static_readRequest(buf, sizeof(buf), BIG_BODY_BYTE_COUNT, &result));
  TEST_ASSERT_NOT_NULL(result.mp_largeBuf);
  TEST_ASSERT_TRUE(result.mp_body == result.mp_largeBuf + result.m_headLen);
  TEST_ASSERT_EQUAL_MEMORY(body, result.mp_body, sizeof(body));
  TEST_ASSERT_TRUE(result.mp_method == buf);
  TEST_ASSERT_TRUE(result.ma_headers[0].name > buf && result.ma_headers[0].name < buf + sizeof(buf));
  receive_releaseLargeBuf(&result);
}

void test_request_that_fills_the_buffer_exactly_is_not_mapped(void)
{
  char text[256];
  for (size_t request_len = 127; request_len <= 128; request_len++)
  {
    int head_len = snprintf(text, sizeof(text), "POST /big HTTP/1.1\r\nContent-Length: %zu\r\n\r\n", request_len - 42);
    TEST_ASSERT_EQUAL_INT(42, head_len);
    memset(text + head_len, 'b', request_len - (size_t)head_len);
    g_mmapAddress = NULL;
    g_mmapLength  = 0;
    static_openPair(SOCK_STREAM, SAFETY_TIMEOUT_MS);
    static_send(text, request_len);
    char buf[128];
    ReceiveResult_t result = { 0 };
    TEST_ASSERT_EQUAL_INT(RECEIVE_OK, static_readRequest(buf, sizeof(buf), BIG_BODY_BYTE_COUNT, &result));
    TEST_ASSERT_EQUAL_size_t(request_len, result.m_requestLen);
    if (request_len == 127)
    {
      TEST_ASSERT_FALSE(receive_isRequestTooLargeForBuffer(&result, sizeof(buf)));
      TEST_ASSERT_NULL(result.mp_largeBuf);
      TEST_ASSERT_NULL(g_mmapAddress);
      TEST_ASSERT_TRUE(result.mp_body == buf + head_len);
    }
    else
    {
      TEST_ASSERT_TRUE(receive_isRequestTooLargeForBuffer(&result, sizeof(buf)));
      TEST_ASSERT_NOT_NULL(result.mp_largeBuf);
      TEST_ASSERT_EQUAL_size_t(request_len + 1, g_mmapLength);
    }
    TEST_ASSERT_EQUAL_MEMORY(text + head_len, result.mp_body, request_len - (size_t)head_len);
    receive_releaseLargeBuf(&result);
    if (request_len == 127)
    {
      TEST_ASSERT_TRUE(result.mp_body == buf + head_len);
      TEST_ASSERT_EQUAL_size_t(request_len - (size_t)head_len, result.m_bodyLen);
    }
    static_closePair();
  }
}

static void static_assertResultEmpty(const ReceiveResult_t* result)
{
  TEST_ASSERT_NULL(result->mp_method);
  TEST_ASSERT_NULL(result->mp_requestTarget);
  TEST_ASSERT_EQUAL_size_t(0, result->m_headerCount);
  TEST_ASSERT_EQUAL_size_t(0, result->m_bodyLen);
  TEST_ASSERT_NULL(result->mp_body);
  TEST_ASSERT_NULL(result->mp_largeBuf);
  TEST_ASSERT_EQUAL_size_t(0, result->m_largeBufSize);
}

void test_refused_request_leaves_the_head_fields_empty(void)
{
  static_openPair(SOCK_STREAM, SAFETY_TIMEOUT_MS);
  static_sendText("POST / HTTP/1.1\r\nContent-Length: x\r\n\r\n");
  char buf[TEST_BUF_SIZE];
  ReceiveResult_t result;
  memset(&result, 0xff, sizeof(result));
  TEST_ASSERT_EQUAL_INT(RECEIVE_ERR_BAD_CONTENT_LENGTH, static_readRequest(buf, sizeof(buf), sizeof(buf), &result));
  static_assertResultEmpty(&result);
  static_closePair();

  static_openPair(SOCK_STREAM, SAFETY_TIMEOUT_MS);
  static_sendText("POST / HTTP/1.1\r\nContent-Length: 4\r\n\r\nab");
  TEST_ASSERT_EQUAL_INT(0, shutdown(g_fds[1], SHUT_WR));
  memset(&result, 0xff, sizeof(result));
  TEST_ASSERT_EQUAL_INT(RECEIVE_ERR_CLOSED, static_readRequest(buf, sizeof(buf), sizeof(buf), &result));
  static_assertResultEmpty(&result);
}

void test_discard_reads_what_is_left_and_shuts_the_sending_side(void)
{
  char filler[100];
  memset(filler, 'f', sizeof(filler));
  static_openPair(SOCK_STREAM, SAFETY_TIMEOUT_MS);
  static_send(filler, sizeof(filler));
  TEST_ASSERT_EQUAL_INT(0, shutdown(g_fds[1], SHUT_WR));

  receive_discardRefusedBodyBeforeClose(g_fds[0]);

  struct timeval timeout = { .tv_sec = SAFETY_TIMEOUT_MS / 1000, .tv_usec = 0 };
  TEST_ASSERT_EQUAL_INT(0, setsockopt(g_fds[1], SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)));
  char rest[8];
  TEST_ASSERT_EQUAL_INT(0, (int)read(g_fds[0], rest, sizeof(rest)));
  TEST_ASSERT_EQUAL_INT(0, (int)read(g_fds[1], rest, sizeof(rest)));
}

void test_discard_stops_after_its_byte_limit(void)
{
  static char filler[RECEIVE_REFUSED_BODY_DISCARD_MAX_BYTE_COUNT + 1000];
  memset(filler, 'f', sizeof(filler));
  static_openPair(SOCK_STREAM, SAFETY_TIMEOUT_MS);
  int send_size = (int)sizeof(filler) * 2;
  TEST_ASSERT_EQUAL_INT(0, setsockopt(g_fds[1], SOL_SOCKET, SO_SNDBUF, &send_size, sizeof(send_size)));
  static_send(filler, sizeof(filler));

  receive_discardRefusedBodyBeforeClose(g_fds[0]);

  size_t left = 0;
  char   rest[4096];
  ssize_t n;
  while ((n = read(g_fds[0], rest, sizeof(rest))) > 0)
    left += (size_t)n;
  TEST_ASSERT_EQUAL_size_t(1000, left);
}

void test_discard_stops_after_its_time_limit(void)
{
  static_openPair(SOCK_STREAM, 5000);
  struct timespec start_time, end_time;
  clock_gettime(CLOCK_MONOTONIC, &start_time);
  receive_discardRefusedBodyBeforeClose(g_fds[0]);
  clock_gettime(CLOCK_MONOTONIC, &end_time);
  long elapsed_ms = (long)(end_time.tv_sec - start_time.tv_sec) * 1000 + (end_time.tv_nsec - start_time.tv_nsec) / 1000000L;
  TEST_ASSERT_TRUE(elapsed_ms >= RECEIVE_REFUSED_BODY_DISCARD_MAX_MS - 10);
  TEST_ASSERT_TRUE(elapsed_ms < 2 * RECEIVE_REFUSED_BODY_DISCARD_MAX_MS);
}

void test_registration_gate_test_count(void)
{
  TEST_ASSERT_EQUAL_INT_MESSAGE(55, (int)Unity.NumberOfTests,
    "RUN_TEST list and test definitions have drifted apart - a test may be unregistered");
}

int main(void)
{
  UNITY_BEGIN();
  RUN_TEST(test_crlf_blank_line_ends_the_head);
  RUN_TEST(test_lf_only_blank_line_ends_the_head);
  RUN_TEST(test_mixed_blank_line_ends_the_head);
  RUN_TEST(test_body_that_arrives_with_the_head_is_kept);
  RUN_TEST(test_head_sent_one_byte_per_read_is_read_whole);
  RUN_TEST(test_nothing_after_the_head_is_read);
  RUN_TEST(test_read_bytes_end_with_a_nul);
  RUN_TEST(test_buffer_full_stops_the_read_inside_the_buffer);
  RUN_TEST(test_head_that_ends_on_the_last_byte_that_fits_is_read);
  RUN_TEST(test_client_that_closes_answers_closed);
  RUN_TEST(test_silent_client_answers_read);
  RUN_TEST(test_reads_that_end_the_head_and_the_body_skip_the_deadline_check);
  RUN_TEST(test_nul_in_the_head_is_malformed);
  RUN_TEST(test_deadline_bounds_the_whole_head_not_each_gap);
  RUN_TEST(test_deadline_not_passed_just_under_across_a_second);
  RUN_TEST(test_deadline_passed_when_reached_exactly);
  RUN_TEST(test_find_header_finds_a_header_by_its_name_in_any_case);
  RUN_TEST(test_find_header_answers_the_first_of_two_headers);
  RUN_TEST(test_find_header_skips_a_folded_continuation_line);
  RUN_TEST(test_find_unique_header_answers_none_when_no_header_has_the_name);
  RUN_TEST(test_find_unique_header_finds_the_one_header_with_the_name);
  RUN_TEST(test_find_unique_header_refuses_two_headers_of_one_name);
  RUN_TEST(test_find_unique_header_refuses_three_headers_of_one_name);
  RUN_TEST(test_find_unique_header_counts_no_header_whose_name_only_shares_a_prefix);
  RUN_TEST(test_body_sent_after_the_head_is_read_to_its_length);
  RUN_TEST(test_body_sent_one_byte_per_read_is_read_whole);
  RUN_TEST(test_bytes_after_the_body_are_not_part_of_the_request);
  RUN_TEST(test_client_that_closes_inside_the_body_answers_closed);
  RUN_TEST(test_deadline_keeps_running_while_the_body_arrives);
  RUN_TEST(test_body_as_long_as_its_limit_is_read_and_one_byte_more_is_refused);
  RUN_TEST(test_content_length_too_wide_for_a_size_is_too_large);
  RUN_TEST(test_malformed_content_length_is_refused);
  RUN_TEST(test_transfer_encoding_is_refused);
  RUN_TEST(test_transfer_encoding_check_runs_before_the_second_length_check);
  RUN_TEST(test_folded_header_line_is_malformed);
  RUN_TEST(test_bare_cr_in_a_header_line_is_malformed);
  RUN_TEST(test_header_lines_past_the_cap_are_too_many);
  RUN_TEST(test_expect_continue_gets_100_before_the_body);
  RUN_TEST(test_expect_continue_gets_no_100_on_http_1_0_or_with_the_body_sent);
  RUN_TEST(test_expect_value_is_compared_whole_and_in_any_case);
  RUN_TEST(test_header_named_a_prefix_of_a_framing_header_frames_nothing);
  RUN_TEST(test_expect_continue_gets_no_100_for_an_empty_body);
  RUN_TEST(test_max_body_byte_count_lets_a_body_grow_into_a_mapping);
  RUN_TEST(test_head_and_body_length_are_read_without_the_body);
  RUN_TEST(test_mapping_that_cannot_be_made_answers_no_memory);
  RUN_TEST(test_mapping_is_kept_out_of_a_core_dump_and_unmapped_once);
  RUN_TEST(test_body_that_does_not_arrive_unmaps_its_mapping);
  RUN_TEST(test_ok_result_holds_the_parsed_head);
  RUN_TEST(test_body_of_a_mapped_request_is_read_from_the_mapping);
  RUN_TEST(test_request_that_fills_the_buffer_exactly_is_not_mapped);
  RUN_TEST(test_refused_request_leaves_the_head_fields_empty);
  RUN_TEST(test_discard_reads_what_is_left_and_shuts_the_sending_side);
  RUN_TEST(test_discard_stops_after_its_byte_limit);
  RUN_TEST(test_discard_stops_after_its_time_limit);
  RUN_TEST(test_registration_gate_test_count);
  return UNITY_END();
}
