#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <time.h>

#include "unity/unity.h"
#include "response.h"
#include "usagelog.h"

#define RESP_BUF 4096

void setUp(void)    {}
void tearDown(void)
{
  response_clearRateLimitInfo();
  response_setHeadRequest(false);
}

static void static_captureSend(char* buf, size_t len, int status_code, const char* body)
{
  int fds[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) < 0) 
  { 
    buf[0] = '\0'; 
    return; 
  }
  response_send(fds[1], status_code, "OK", body);
  close(fds[1]);
  ssize_t n = read(fds[0], buf, len - 1);
  buf[n > 0 ? n : 0] = '\0';
  close(fds[0]);
}

static void static_captureSend405(char* buf, size_t len, const char* allow_value, const char* body)
{
  int fds[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) < 0) 
  { 
    buf[0] = '\0'; 
    return; 
  }
  response_sendMethodNotAllowed405(fds[1], allow_value, body);
  close(fds[1]);
  ssize_t n = read(fds[0], buf, len - 1);
  buf[n > 0 ? n : 0] = '\0';
  close(fds[0]);
}

static size_t static_captureSendContent(char* buf, size_t len, const char* extra_headers, const void* body, size_t body_byte_count)
{
  int fds[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) < 0)
  {
    buf[0] = '\0';
    return 0;
  }
  response_sendContent(fds[1], "text/css; charset=utf-8", "public, max-age=3600", extra_headers, body, body_byte_count);
  close(fds[1]);
  ssize_t n = read(fds[0], buf, len - 1);
  buf[n > 0 ? n : 0] = '\0';
  close(fds[0]);
  return n > 0 ? (size_t)n : 0;
}

static void static_captureSend503(char* buf, size_t len, unsigned int retry_after_sec, const char* body)
{
  int fds[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) < 0)
  {
    buf[0] = '\0';
    return;
  }
  response_sendServiceUnavailable503(fds[1], retry_after_sec, body);
  close(fds[1]);
  ssize_t n = read(fds[0], buf, len - 1);
  buf[n > 0 ? n : 0] = '\0';
  close(fds[0]);
}

void test_ratelimit_headers_present_when_set(void)
{
  response_setRateLimitInfo(500, 480, time(NULL) + 3600);
  char buf[RESP_BUF];
  static_captureSend(buf, sizeof(buf), 200, "{\"ok\":true}");
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 200"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "X-RateLimit-Limit: 500"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "X-RateLimit-Remaining: 480"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "X-RateLimit-Reset-Machine:"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "X-RateLimit-Reset-Human:"));
}

void test_ratelimit_headers_absent_after_clear(void)
{
  response_setRateLimitInfo(500, 480, time(NULL) + 3600);
  response_clearRateLimitInfo();
  char buf[RESP_BUF];
  static_captureSend(buf, sizeof(buf), 200, "{\"ok\":true}");
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 200"));
  TEST_ASSERT_NULL(strstr(buf, "X-RateLimit-"));
}

void test_ratelimit_headers_absent_when_never_set(void)
{
  char buf[RESP_BUF];
  static_captureSend(buf, sizeof(buf), 404, "{\"error\":\"not found\"}");
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 404"));
  TEST_ASSERT_NULL(strstr(buf, "X-RateLimit-"));
}

void test_send405_includes_allow_and_ratelimit(void)
{
  response_setRateLimitInfo(30, 29, time(NULL) + 3600);
  char buf[RESP_BUF];
  static_captureSend405(buf, sizeof(buf), "GET, POST", "{\"error\":\"method\"}");
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 405"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "Allow: GET, POST"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "X-RateLimit-Limit: 30"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\r\nContent-Length: 18\r\n"));
}

void test_ratelimit_reset_human_format_nonzero(void)
{
  time_t reset = time(NULL) + 3661;
  response_setRateLimitInfo(500, 480, reset);
  char buf[RESP_BUF];
  static_captureSend(buf, sizeof(buf), 200, "{\"ok\":true}");

  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 200"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "X-RateLimit-Reset-Human: 01:01:0"));

  char expected_machine[64];
  snprintf(expected_machine, sizeof(expected_machine),
           "X-RateLimit-Reset-Machine: %lld", (long long)reset);
  TEST_ASSERT_NOT_NULL(strstr(buf, expected_machine));
}

void test_send503_includes_retry_after_and_ratelimit(void)
{
  response_setRateLimitInfo(30, 29, time(NULL) + 3600);
  char buf[RESP_BUF];
  static_captureSend503(buf, sizeof(buf), 17, "{\"status\":\"unavailable\"}");
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 503 Service Unavailable\r\n"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\r\nRetry-After: 17\r\n"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "X-RateLimit-Limit: 30"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\r\n\r\n{\"status\":\"unavailable\"}"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\r\nContent-Length: 24\r\n"));
}

void test_plain_response_carries_no_extra_header(void)
{
  char buf[RESP_BUF];
  static_captureSend(buf, sizeof(buf), 200, "{}");
  TEST_ASSERT_NULL(strstr(buf, "Allow:"));
  TEST_ASSERT_NULL(strstr(buf, "Retry-After:"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "Cache-Control: no-store\r\nConnection: close\r\n\r\n{}"));
}

void test_json_senders_carry_noindex_and_content_does_not(void)
{
  char buf[RESP_BUF];
  static_captureSend405(buf, sizeof(buf), "GET", "{}");
  TEST_ASSERT_NOT_NULL(strstr(buf, "\r\nX-Robots-Tag: noindex\r\n"));

  static_captureSend503(buf, sizeof(buf), 17, "{}");
  TEST_ASSERT_NOT_NULL(strstr(buf, "\r\nX-Robots-Tag: noindex\r\n"));

  static_captureSendContent(buf, sizeof(buf), "", "body{}", 6);
  TEST_ASSERT_NULL(strstr(buf, "X-Robots-Tag"));
}

void test_json_response_keeps_its_bytes(void)
{
  char buf[RESP_BUF];
  static_captureSend(buf, sizeof(buf), 200, "{}");
  TEST_ASSERT_EQUAL_STRING("HTTP/1.1 200 OK\r\n"
                           "Content-Type: application/json\r\n"
                           "Content-Length: 2\r\n"
                           "X-Content-Type-Options: nosniff\r\n"
                           "X-Frame-Options: DENY\r\n"
                           "Referrer-Policy: no-referrer\r\n"
                           "X-Robots-Tag: noindex\r\n"
                           "Cache-Control: no-store\r\n"
                           "Connection: close\r\n"
                           "\r\n"
                           "{}", buf);
}

void test_content_carries_its_type_cache_rule_and_extra_lines(void)
{
  char buf[RESP_BUF];
  static_captureSendContent(buf, sizeof(buf), "X-Test: 1\r\n", "body{}", 6);
  TEST_ASSERT_EQUAL_STRING("HTTP/1.1 200 OK\r\n"
                           "Content-Type: text/css; charset=utf-8\r\n"
                           "Content-Length: 6\r\n"
                           "X-Content-Type-Options: nosniff\r\n"
                           "X-Frame-Options: DENY\r\n"
                           "Referrer-Policy: no-referrer\r\n"
                           "Cache-Control: public, max-age=3600\r\n"
                           "X-Test: 1\r\n"
                           "Connection: close\r\n"
                           "\r\n"
                           "body{}", buf);
}

void test_content_body_with_a_nul_goes_out_whole(void)
{
  static const unsigned char body[] = { 'a', '\0', 'b' };
  char buf[RESP_BUF];
  size_t bytes_read = static_captureSendContent(buf, sizeof(buf), "", body, sizeof(body));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\r\nContent-Length: 3\r\n"));
  const char* head_end = strstr(buf, "\r\n\r\n");
  TEST_ASSERT_NOT_NULL(head_end);
  size_t head_byte_count = (size_t)(head_end - buf) + 4;
  TEST_ASSERT_EQUAL_UINT(head_byte_count + sizeof(body), bytes_read);
  TEST_ASSERT_EQUAL_MEMORY(body, buf + head_byte_count, sizeof(body));
}

static size_t static_captureSendWithExtraHeaders(char* buf, size_t len, const char* extra_headers, const char* body)
{
  int fds[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) < 0)
  {
    buf[0] = '\0';
    return 0;
  }
  response_sendWithExtraHeaders(fds[1], 402, "Payment Required", extra_headers, body);
  close(fds[1]);
  size_t bytes_read = 0;
  while (bytes_read < len - 1)
  {
    ssize_t n = read(fds[0], buf + bytes_read, len - 1 - bytes_read);
    if (n <= 0)
      break;
    bytes_read += (size_t)n;
  }
  buf[bytes_read] = '\0';
  close(fds[0]);
  return bytes_read;
}

void test_extra_headers_go_into_the_head_of_a_json_response(void)
{
  char buf[RESP_BUF];
  static_captureSendWithExtraHeaders(buf, sizeof(buf), "PAYMENT-REQUIRED: e30=\r\nX-Test: 1\r\n", "{}");
  TEST_ASSERT_EQUAL_STRING("HTTP/1.1 402 Payment Required\r\n"
                           "Content-Type: application/json\r\n"
                           "Content-Length: 2\r\n"
                           "X-Content-Type-Options: nosniff\r\n"
                           "X-Frame-Options: DENY\r\n"
                           "Referrer-Policy: no-referrer\r\n"
                           "X-Robots-Tag: noindex\r\n"
                           "Cache-Control: no-store\r\n"
                           "PAYMENT-REQUIRED: e30=\r\n"
                           "X-Test: 1\r\n"
                           "Connection: close\r\n"
                           "\r\n"
                           "{}", buf);
}

#define EXTRA_LINE_BYTE_COUNT 1500

void test_long_extra_line_beside_the_rate_limit_lines_goes_out_whole(void)
{
  char extra_line[EXTRA_LINE_BYTE_COUNT + 1];
  memset(extra_line, 'A', EXTRA_LINE_BYTE_COUNT);
  memcpy(extra_line, "PAYMENT-REQUIRED: ", 18);
  memcpy(extra_line + EXTRA_LINE_BYTE_COUNT - 2, "\r\n", 2);
  extra_line[EXTRA_LINE_BYTE_COUNT] = '\0';

  response_setRateLimitInfo(4294967295u, -2147483647, (time_t)9999999999LL);
  char buf[RESP_BUF];
  size_t bytes_read = static_captureSendWithExtraHeaders(buf, sizeof(buf), extra_line, "{\"error\":\"payment_required\"}");

  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 402 Payment Required\r\n"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\r\nX-RateLimit-Limit: 4294967295\r\n"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\r\nX-RateLimit-Remaining: -2147483647\r\n"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\r\nX-RateLimit-Reset-Machine: 9999999999\r\n"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\r\nX-RateLimit-Reset-Human: "));
  const char* extra_at = strstr(buf, extra_line);
  TEST_ASSERT_NOT_NULL(extra_at);
  TEST_ASSERT_EQUAL_STRING("Connection: close\r\n\r\n{\"error\":\"payment_required\"}", extra_at + EXTRA_LINE_BYTE_COUNT);
  TEST_ASSERT_EQUAL_UINT(strlen(buf), bytes_read);
}

void test_extra_headers_too_long_for_the_head_send_nothing(void)
{
  char extra_line[2048 + 1];
  memset(extra_line, 'A', 2048);
  memcpy(extra_line, "PAYMENT-REQUIRED: ", 18);
  memcpy(extra_line + 2048 - 2, "\r\n", 2);
  extra_line[2048] = '\0';

  char buf[RESP_BUF];
  TEST_ASSERT_EQUAL_UINT(0, static_captureSendWithExtraHeaders(buf, sizeof(buf), extra_line, "{}"));
  TEST_ASSERT_EQUAL_STRING("", buf);
}

void test_head_request_gets_the_extra_headers_without_the_body(void)
{
  response_setHeadRequest(true);
  char buf[RESP_BUF];
  size_t bytes_read = static_captureSendWithExtraHeaders(buf, sizeof(buf), "PAYMENT-REQUIRED: e30=\r\n", "{\"error\":\"x\"}");
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 402 Payment Required\r\n"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\r\nContent-Length: 13\r\n"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\r\nPAYMENT-REQUIRED: e30=\r\nConnection: close\r\n\r\n"));
  TEST_ASSERT_EQUAL_UINT(strlen(buf), bytes_read);
  TEST_ASSERT_EQUAL_STRING("\r\n\r\n", buf + bytes_read - 4);
}

void test_head_request_gets_the_head_without_the_body(void)
{
  char buf[RESP_BUF];
  response_setHeadRequest(true);

  static_captureSend(buf, sizeof(buf), 404, "{\"error\":\"x\"}");
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 404"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\r\nContent-Length: 13\r\n"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\r\n\r\n"));
  TEST_ASSERT_EQUAL_STRING("\r\n\r\n", buf + strlen(buf) - 4);

  static_captureSend405(buf, sizeof(buf), "GET, HEAD", "{\"error\":\"method\"}");
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 405"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\r\nAllow: GET, HEAD\r\n"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\r\nContent-Length: 18\r\n"));
  TEST_ASSERT_EQUAL_STRING("\r\n\r\n", buf + strlen(buf) - 4);

  static_captureSend503(buf, sizeof(buf), 17, "{\"status\":\"unavailable\"}");
  TEST_ASSERT_NOT_NULL(strstr(buf, "\r\nContent-Length: 24\r\n"));
  TEST_ASSERT_EQUAL_STRING("\r\n\r\n", buf + strlen(buf) - 4);

  size_t bytes_read = static_captureSendContent(buf, sizeof(buf), "", "body{}", 6);
  TEST_ASSERT_NOT_NULL(strstr(buf, "\r\nContent-Length: 6\r\n"));
  TEST_ASSERT_EQUAL_UINT(strlen(buf), bytes_read);
  TEST_ASSERT_EQUAL_STRING("\r\n\r\n", buf + bytes_read - 4);

  response_setHeadRequest(false);
  static_captureSend(buf, sizeof(buf), 404, "{\"error\":\"x\"}");
  TEST_ASSERT_EQUAL_STRING("\r\n\r\n{\"error\":\"x\"}", buf + strlen(buf) - 17);
}

static void* static_markHeadRequest(void* unused)
{
  (void)unused;
  response_setHeadRequest(true);
  return NULL;
}

void test_head_mark_of_another_thread_keeps_this_body(void)
{
  pthread_t thread;
  TEST_ASSERT_EQUAL_INT(0, pthread_create(&thread, NULL, static_markHeadRequest, NULL));
  TEST_ASSERT_EQUAL_INT(0, pthread_join(thread, NULL));
  char buf[RESP_BUF];
  static_captureSend(buf, sizeof(buf), 404, "{\"error\":\"x\"}");
  TEST_ASSERT_EQUAL_STRING("\r\n\r\n{\"error\":\"x\"}", buf + strlen(buf) - 17);
}

void test_format_reset_countdown_counts_from_now(void)
{
  char countdown[RESPONSE_RESET_COUNTDOWN_BUF_SIZE];
  response_formatResetCountdown(1760004000, 1760004000 - 2378, countdown, sizeof(countdown));
  TEST_ASSERT_EQUAL_STRING("00:39:38", countdown);
  response_formatResetCountdown(1760004000, 1760004000 - 3661, countdown, sizeof(countdown));
  TEST_ASSERT_EQUAL_STRING("01:01:01", countdown);
  response_formatResetCountdown(1760004000, 1760004000 - 3600, countdown, sizeof(countdown));
  TEST_ASSERT_EQUAL_STRING("01:00:00", countdown);
  response_formatResetCountdown(1760004000, 1760004000 - 59, countdown, sizeof(countdown));
  TEST_ASSERT_EQUAL_STRING("00:00:59", countdown);
  response_formatResetCountdown(1760004000, 1760004000 - 60, countdown, sizeof(countdown));
  TEST_ASSERT_EQUAL_STRING("00:01:00", countdown);
  response_formatResetCountdown(1760004000, 1760004000, countdown, sizeof(countdown));
  TEST_ASSERT_EQUAL_STRING("00:00:00", countdown);
  response_formatResetCountdown(1760004000, 1760004000 + 5, countdown, sizeof(countdown));
  TEST_ASSERT_EQUAL_STRING("00:00:00", countdown);

  char exact[9];
  response_formatResetCountdown(1760004000, 1760004000 - 2378, exact, sizeof(exact));
  TEST_ASSERT_EQUAL_STRING("00:39:38", exact);

  char too_small[8];
  response_formatResetCountdown(1760004000, 1760004000 - 2378, too_small, sizeof(too_small));
  TEST_ASSERT_EQUAL_STRING("", too_small);
}

#define USAGELOG_TEST_INSTANCE_PORT 8002

static char g_usageLines[USAGELOG_DRAIN_BUF_SIZE];

static void static_beginUsageRecord(void)
{
  usagelog_start(USAGELOG_TEST_INSTANCE_PORT);
  usagelog_drainLines(g_usageLines, sizeof(g_usageLines));
  usagelog_beginRequest();
}

static int static_writeUsageRecord(void)
{
  usagelog_writeRequest();
  usagelog_drainLines(g_usageLines, sizeof(g_usageLines));
  int line_count = 0;
  for (const char* c = g_usageLines; *c != '\0'; c++)
    line_count += *c == '\n';
  return line_count;
}

void test_usage_line_holds_the_status_and_the_body_length(void)
{
  static_beginUsageRecord();
  int fds[2];
  TEST_ASSERT_EQUAL_INT(0, socketpair(AF_UNIX, SOCK_STREAM, 0, fds));
  response_send(fds[1], 404, "Not Found", "{}");
  close(fds[1]);
  close(fds[0]);
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, static_writeUsageRecord(), g_usageLines);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(g_usageLines, "\"status\":404,"), g_usageLines);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(g_usageLines, ",\"body_byte_count\":2,"), g_usageLines);
  TEST_ASSERT_NULL_MESSAGE(strstr(g_usageLines, "is_send_failed"), g_usageLines);
}

void test_usage_line_of_a_head_answer_counts_the_body_left_out(void)
{
  static_beginUsageRecord();
  response_setHeadRequest(true);
  char buf[RESP_BUF];
  size_t bytes_read = static_captureSendContent(buf, sizeof(buf), "", "body!", 5);
  response_setHeadRequest(false);
  TEST_ASSERT_EQUAL_STRING("\r\n\r\n", buf + bytes_read - 4);
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, static_writeUsageRecord(), g_usageLines);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(g_usageLines, "\"status\":200,"), g_usageLines);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(g_usageLines, ",\"body_byte_count\":5,"), g_usageLines);
}

void test_usage_line_marks_a_head_that_could_not_be_sent(void)
{
  static_beginUsageRecord();
  int fds[2];
  TEST_ASSERT_EQUAL_INT(0, socketpair(AF_UNIX, SOCK_STREAM, 0, fds));
  close(fds[0]);
  response_send(fds[1], 404, "Not Found", "{}");
  close(fds[1]);
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, static_writeUsageRecord(), g_usageLines);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(g_usageLines, "\"status\":404,"), g_usageLines);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(g_usageLines, ",\"is_send_failed\":true}\n"), g_usageLines);
}

#define LARGE_BODY_BYTE_COUNT (1024 * 1024)

static void* static_readHeadThenClose(void* fd_arg)
{
  int  fd = *(const int*)fd_arg;
  char last_bytes[4] = { 0 };
  char c;
  while (read(fd, &c, 1) == 1)
  {
    memmove(last_bytes, last_bytes + 1, 3);
    last_bytes[3] = c;
    if (memcmp(last_bytes, "\r\n\r\n", 4) == 0)
      break;
  }
  close(fd);
  return NULL;
}

void test_usage_line_marks_a_body_that_could_not_be_sent(void)
{
  static char body[LARGE_BODY_BYTE_COUNT];
  memset(body, 'b', sizeof(body));
  static_beginUsageRecord();
  int fds[2];
  TEST_ASSERT_EQUAL_INT(0, socketpair(AF_UNIX, SOCK_STREAM, 0, fds));
  int send_buffer_size = 4096;
  TEST_ASSERT_EQUAL_INT(0, setsockopt(fds[1], SOL_SOCKET, SO_SNDBUF, &send_buffer_size, sizeof(send_buffer_size)));
  pthread_t peer;
  TEST_ASSERT_EQUAL_INT(0, pthread_create(&peer, NULL, static_readHeadThenClose, &fds[0]));
  response_sendContent(fds[1], "text/plain; charset=utf-8", "no-store", "", body, sizeof(body));
  TEST_ASSERT_EQUAL_INT(0, pthread_join(peer, NULL));
  close(fds[1]);
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, static_writeUsageRecord(), g_usageLines);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(g_usageLines, "\"status\":200,"), g_usageLines);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(g_usageLines, ",\"body_byte_count\":1048576,"), g_usageLines);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(g_usageLines, ",\"is_send_failed\":true}\n"), g_usageLines);
}

int main(void)
{
  UNITY_BEGIN();

  RUN_TEST(test_ratelimit_headers_present_when_set);
  RUN_TEST(test_ratelimit_headers_absent_after_clear);
  RUN_TEST(test_ratelimit_headers_absent_when_never_set);
  RUN_TEST(test_send405_includes_allow_and_ratelimit);
  RUN_TEST(test_ratelimit_reset_human_format_nonzero);
  RUN_TEST(test_send503_includes_retry_after_and_ratelimit);
  RUN_TEST(test_plain_response_carries_no_extra_header);
  RUN_TEST(test_format_reset_countdown_counts_from_now);
  RUN_TEST(test_json_senders_carry_noindex_and_content_does_not);
  RUN_TEST(test_json_response_keeps_its_bytes);
  RUN_TEST(test_content_carries_its_type_cache_rule_and_extra_lines);
  RUN_TEST(test_content_body_with_a_nul_goes_out_whole);
  RUN_TEST(test_extra_headers_go_into_the_head_of_a_json_response);
  RUN_TEST(test_long_extra_line_beside_the_rate_limit_lines_goes_out_whole);
  RUN_TEST(test_extra_headers_too_long_for_the_head_send_nothing);
  RUN_TEST(test_head_request_gets_the_extra_headers_without_the_body);
  RUN_TEST(test_head_request_gets_the_head_without_the_body);
  RUN_TEST(test_head_mark_of_another_thread_keeps_this_body);
  RUN_TEST(test_usage_line_holds_the_status_and_the_body_length);
  RUN_TEST(test_usage_line_of_a_head_answer_counts_the_body_left_out);
  RUN_TEST(test_usage_line_marks_a_head_that_could_not_be_sent);
  RUN_TEST(test_usage_line_marks_a_body_that_could_not_be_sent);
  
  return UNITY_END();
}
