#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <sys/socket.h>
#include <assert.h>

#include "response.h"
#include "usagelog.h"

#define RESPONSE_RATELIMIT_HEADERS_BUF_SIZE  256
#define RESPONSE_EXTRA_HEADER_BUF_SIZE        64
#define RESPONSE_HEAD_BUF_SIZE              2048

#define RESPONSE_JSON_CONTENT_TYPE   "application/json"
#define RESPONSE_JSON_CACHE_CONTROL  "no-store"

#define RESPONSE_JSON_ROBOTS_LINE    "X-Robots-Tag: noindex\r\n"

static __thread bool         g_rl_set       = false;
static __thread unsigned int g_rl_limit     = 0;
static __thread int          g_rl_remaining = 0;
static __thread time_t       g_rl_reset     = 0;

static __thread bool         g_isHeadRequest = false;

#define RESPONSE_DEADLINE_SEC 30

static void static_sendResponse(int client_fd, int status_code, const char* status_text, const char* content_type, const char* cache_control, const char* robots_line, const char* extra_headers, const void* body, size_t body_byte_count);
static bool static_sendAllBytes(int client_fd, const char* send_buf, size_t bytes_to_send,
                                const struct timespec* response_start_time);

void response_setRateLimitInfo(unsigned int limit, int remaining_credit_count, time_t reset)
{
  g_rl_limit     = limit;
  g_rl_remaining = remaining_credit_count;
  g_rl_reset     = reset;
  g_rl_set       = true;
}

void response_clearRateLimitInfo(void)
{
  g_rl_set = false;
}

void response_setHeadRequest(bool is_head_request)
{
  g_isHeadRequest = is_head_request;
}

void response_formatResetCountdown(time_t reset, time_t now, char* countdown_out, size_t countdown_size)
{
  assert(countdown_out != NULL);
  assert(countdown_size > 0);

  long remaining_seconds = (long)reset - (long)now;
  if (remaining_seconds < 0)
    remaining_seconds = 0;

  int countdown_len = snprintf(countdown_out, countdown_size, "%02d:%02d:%02d", (int)(remaining_seconds / 3600), (int)((remaining_seconds % 3600) / 60), (int)(remaining_seconds % 60));
  if (countdown_len < 0 || (size_t)countdown_len >= countdown_size)
    countdown_out[0] = '\0';
}

void response_send(int client_fd, int status_code, const char* status_text, const char* response_body)
{
  assert(response_body != NULL);

  static_sendResponse(client_fd, status_code, status_text, RESPONSE_JSON_CONTENT_TYPE, RESPONSE_JSON_CACHE_CONTROL, RESPONSE_JSON_ROBOTS_LINE, "", response_body, strlen(response_body));
}

void response_sendMethodNotAllowed405(int client_fd, const char* allow_value, const char* response_body)
{
  assert(allow_value   != NULL);
  assert(response_body != NULL);

  char allow_header[RESPONSE_EXTRA_HEADER_BUF_SIZE];
  int allow_header_len = snprintf(allow_header, sizeof(allow_header), "Allow: %s\r\n", allow_value);
  if (allow_header_len < 0 || (size_t)allow_header_len >= sizeof(allow_header))
    allow_header[0] = '\0';

  static_sendResponse(client_fd, 405, "Method Not Allowed", RESPONSE_JSON_CONTENT_TYPE, RESPONSE_JSON_CACHE_CONTROL, RESPONSE_JSON_ROBOTS_LINE, allow_header, response_body, strlen(response_body));
}

void response_sendServiceUnavailable503(int client_fd, unsigned int retry_after_sec, const char* response_body)
{
  response_sendWithRetryAfter(client_fd, 503, "Service Unavailable", retry_after_sec, response_body);
}

void response_sendTooManyRequests429(int client_fd, unsigned int retry_after_sec, const char* response_body)
{
  response_sendWithRetryAfter(client_fd, 429, "Too Many Requests", retry_after_sec, response_body);
}

void response_sendContent(int client_fd, const char* content_type, const char* cache_control, const char* extra_headers, const void* body, size_t body_byte_count)
{
  static_sendResponse(client_fd, 200, "OK", content_type, cache_control, "", extra_headers, body, body_byte_count);
}

void response_sendWithExtraHeaders(int client_fd, int status_code, const char* status_text, const char* extra_headers, const char* response_body)
{
  assert(response_body != NULL);

  static_sendResponse(client_fd, status_code, status_text, RESPONSE_JSON_CONTENT_TYPE, RESPONSE_JSON_CACHE_CONTROL, RESPONSE_JSON_ROBOTS_LINE, extra_headers, response_body, strlen(response_body));
}

void response_sendWithRetryAfter(int client_fd, int status_code, const char* status_text, unsigned int retry_after_sec, const char* response_body)
{
  _Static_assert(RESPONSE_EXTRA_HEADER_BUF_SIZE >= sizeof("Retry-After: 4294967295\r\n"),
                 "RESPONSE_EXTRA_HEADER_BUF_SIZE must fit the longest Retry-After line");
  char retry_after_header[RESPONSE_EXTRA_HEADER_BUF_SIZE];
  int retry_after_header_len = snprintf(retry_after_header, sizeof(retry_after_header), "Retry-After: %u\r\n", retry_after_sec);
  assert(retry_after_header_len > 0 && (size_t)retry_after_header_len < sizeof(retry_after_header));
  (void)retry_after_header_len;

  assert(response_body != NULL);

  static_sendResponse(client_fd, status_code, status_text, RESPONSE_JSON_CONTENT_TYPE, RESPONSE_JSON_CACHE_CONTROL, RESPONSE_JSON_ROBOTS_LINE, retry_after_header, response_body, strlen(response_body));
}

static void static_sendResponse(int client_fd, int status_code, const char* status_text, const char* content_type, const char* cache_control, const char* robots_line, const char* extra_headers, const void* body, size_t body_byte_count)
{
  assert(client_fd     >= 0);
  assert(status_text   != NULL);
  assert(content_type  != NULL);
  assert(cache_control != NULL);
  assert(robots_line   != NULL);
  assert(extra_headers != NULL);
  assert(body != NULL || body_byte_count == 0);

  char rl_headers[RESPONSE_RATELIMIT_HEADERS_BUF_SIZE] = "";
  if (g_rl_set)
  {
    char reset_countdown[RESPONSE_RESET_COUNTDOWN_BUF_SIZE];
    response_formatResetCountdown(g_rl_reset, time(NULL), reset_countdown, sizeof(reset_countdown));

    int rl_headers_len = snprintf(rl_headers, sizeof(rl_headers),
      "X-RateLimit-Limit: %u\r\n"
      "X-RateLimit-Remaining: %d\r\n"
      "X-RateLimit-Reset-Machine: %lld\r\n"
      "X-RateLimit-Reset-Human: %s\r\n",
      g_rl_limit, g_rl_remaining, (long long)g_rl_reset, reset_countdown);
    if (rl_headers_len < 0 || (size_t)rl_headers_len >= sizeof(rl_headers))
      rl_headers[0] = '\0';
  }

  char response_head[RESPONSE_HEAD_BUF_SIZE];
  int headers_len = snprintf(response_head, sizeof(response_head),
    "HTTP/1.1 %d %s\r\n"
    "Content-Type: %s\r\n"
    "Content-Length: %zu\r\n"
    "X-Content-Type-Options: nosniff\r\n"
    "X-Frame-Options: DENY\r\n"
    "Referrer-Policy: no-referrer\r\n"
    "%s"
    "Cache-Control: %s\r\n"
    "%s"
    "%s"
    "Connection: close\r\n"
    "\r\n",
    status_code, status_text, content_type, body_byte_count, robots_line, cache_control, rl_headers, extra_headers);

  if (headers_len > 0 && headers_len < (int)sizeof(response_head))
  {
    usagelog_setResponse(status_code, body_byte_count);

    struct timespec response_start_time;
    clock_gettime(CLOCK_MONOTONIC, &response_start_time);

    if (!static_sendAllBytes(client_fd, response_head, (size_t)headers_len, &response_start_time))
    {
      perror("send head");
      usagelog_setSendFailed();
      return;
    }
    if (!g_isHeadRequest && !static_sendAllBytes(client_fd, body, body_byte_count, &response_start_time))
    {
      perror("send body");
      usagelog_setSendFailed();
    }
  }
}

static bool static_sendAllBytes(int client_fd, const char* send_buf, size_t bytes_to_send, const struct timespec* response_start_time)
{
  assert(client_fd           >= 0);
  assert(send_buf            != NULL);
  assert(response_start_time != NULL);

  size_t total_bytes_sent = 0;
  while (total_bytes_sent < bytes_to_send)
  {
    ssize_t bytes_sent = send(client_fd, send_buf + total_bytes_sent, bytes_to_send - total_bytes_sent, MSG_NOSIGNAL);
    if (bytes_sent <= 0)
    {
      if (bytes_sent < 0 && errno == EINTR)
        continue;
      return false;
    }
    total_bytes_sent += (size_t)bytes_sent;

    if (total_bytes_sent < bytes_to_send)
    {
      struct timespec now;
      clock_gettime(CLOCK_MONOTONIC, &now);
      if (now.tv_sec - response_start_time->tv_sec >= RESPONSE_DEADLINE_SEC)
        return false;
    }
  }
  return true;
}
