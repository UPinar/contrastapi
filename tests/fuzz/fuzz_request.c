#define _GNU_SOURCE

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "auth.h"
#include "endpoint.h"
#include "mcp.h"
#include "pages.h"
#include "receive.h"
#include "request.h"

#define FUZZ_REQUEST_MAX_INPUT_BYTE_COUNT (1 + REQUEST_BUFFER_SIZE + ENDPOINT_MCP_MAX_BODY_BYTE_COUNT)

#define FUZZ_REQUEST_KEY_MARKER     "cc_KEY"
#define FUZZ_REQUEST_KEY_MARKER_LEN (sizeof(FUZZ_REQUEST_KEY_MARKER) - 1)

#define FUZZ_REQUEST_KEY "contrastapi_" "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" "a0382b56"
_Static_assert(sizeof(FUZZ_REQUEST_KEY) - 1 == API_KEY_TOTAL_LEN, "FUZZ_REQUEST_KEY length");

#define FUZZ_REQUEST_KEY_GROWTH_BYTE_COUNT (API_KEY_TOTAL_LEN - FUZZ_REQUEST_KEY_MARKER_LEN)

static int g_cappedFd = -1;

static size_t g_readCap = 0;

ssize_t __real_read(int fd, void* buf, size_t count);
ssize_t __wrap_read(int fd, void* buf, size_t count);

ssize_t __wrap_read(int fd, void* buf, size_t count)
{
  if (fd == g_cappedFd && g_readCap > 0 && count > g_readCap)
    count = g_readCap;
  return __real_read(fd, buf, count);
}

static uint8_t* static_copyWithKey(const uint8_t* bytes, size_t len, size_t* len_out)
{
  uint8_t* copy = malloc(len + FUZZ_REQUEST_KEY_GROWTH_BYTE_COUNT + 1);
  if (copy == NULL)
    abort();
  const uint8_t* marker = memmem(bytes, len, FUZZ_REQUEST_KEY_MARKER, FUZZ_REQUEST_KEY_MARKER_LEN);
  if (marker == NULL)
  {
    memcpy(copy, bytes, len);
    *len_out = len;
    return copy;
  }

  size_t before_len  = (size_t)(marker - bytes);
  size_t after_start = before_len + FUZZ_REQUEST_KEY_MARKER_LEN;
  memcpy(copy, bytes, before_len);
  memcpy(copy + before_len, FUZZ_REQUEST_KEY, API_KEY_TOTAL_LEN);
  memcpy(copy + before_len + API_KEY_TOTAL_LEN, bytes + after_start, len - after_start);
  *len_out = len + FUZZ_REQUEST_KEY_GROWTH_BYTE_COUNT;
  return copy;
}

static void static_readRequestHeaders(const ReceiveResult_t* request, const RequestHead_t* head)
{
  (void)receive_findHeader(request, "x-real-ip");

  const char* path_segment = NULL;
  if (endpoint_findByHttpPath(head->ma_path, &path_segment) == NULL)
    (void)pages_findServedFile(head->ma_path);

  (void)auth_parseApiKey(request->ma_headers, request->m_headerCount);

  McpRoutingHeaders_t routing_headers;
  mcp_readRoutingHeaders(request->ma_headers, request->m_headerCount, &routing_headers);
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
  if (size < 1 || size > FUZZ_REQUEST_MAX_INPUT_BYTE_COUNT)
    return -1;

  size_t   client_len   = 0;
  uint8_t* client_bytes = static_copyWithKey(data + 1, size - 1, &client_len);

  int fds[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0)
    abort();
  int buf_size = 2 * FUZZ_REQUEST_MAX_INPUT_BYTE_COUNT;
  if (setsockopt(fds[1], SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size)) != 0 ||
      setsockopt(fds[0], SOL_SOCKET, SO_RCVBUF, &buf_size, sizeof(buf_size)) != 0)
    abort();
  if (client_len > 0 && write(fds[1], client_bytes, client_len) != (ssize_t)client_len)
    abort();
  if (shutdown(fds[1], SHUT_WR) != 0)
    abort();
  free(client_bytes);

  g_cappedFd = fds[0];
  g_readCap  = data[0];

  char            request_buf[REQUEST_BUFFER_SIZE];
  ReceiveResult_t receive_result = { 0 };
  RequestHead_t   head           = { 0 };
  ReceiveStatus_t receive_status = receive_readHead(fds[0], request_buf, sizeof(request_buf), &receive_result);
  if (receive_status == RECEIVE_OK)
  {
    request_readHead(&receive_result, &head);
    size_t max_body_byte_count = request_maxBodyByteCount(&head, receive_result.m_headLen);
    receive_status = receive_readBodyLength(max_body_byte_count, &receive_result);
  }
  if (receive_status == RECEIVE_OK)
    receive_status = receive_readBody(fds[0], request_buf, sizeof(request_buf), &receive_result);

  if (receive_status == RECEIVE_OK && head.m_status == REQUEST_HEAD_OK)
    static_readRequestHeaders(&receive_result, &head);

  g_cappedFd = -1;
  receive_releaseLargeBuf(&receive_result);
  close(fds[0]);
  close(fds[1]);
  return 0;
}
