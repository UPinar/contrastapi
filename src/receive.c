#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <poll.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/socket.h>

#include "receive.h"
#include "bytes.h"

#define RECEIVE_NSEC_PER_MSEC 1000000LL
#define RECEIVE_NSEC_PER_SEC  1000000000LL

#define RECEIVE_CONTINUE_RESPONSE "HTTP/1.1 100 Continue\r\n\r\n"

#define RECEIVE_PARSE_PARTIAL (-2)
#define RECEIVE_PARSE_FAILED  (-1)

typedef struct {
  size_t m_contentLength;
  bool   m_isContinueExpected;
} ReceiveBodyLength_t;

static bool            static_isHeaderNamed             (const struct phr_header* header, const char* name);
static bool            static_isDeadlinePassed          (const struct timespec* start_time);
static ReceiveStatus_t static_readBodyIntoResult        (int client_fd, char* request_buf, size_t request_buf_size, ReceiveResult_t* result);
static char*           static_makeLargeBuf              (char* request_buf, size_t head_len, size_t read_len, size_t large_buf_size);
static ReceiveStatus_t static_readBodyLengthFromHeaders (const struct phr_header* headers, size_t header_count, size_t body_length_limit, ReceiveBodyLength_t* body_length_out);
static ReceiveStatus_t static_readBody                  (int client_fd, char* whole_request_buf, size_t* read_len_inout, size_t request_len, const struct timespec* start_time);

ReceiveStatus_t receive_readHead(int client_fd, char* request_buf, size_t request_buf_size, ReceiveResult_t* result_out)
{
  assert(request_buf != NULL);
  assert(request_buf_size >= 2);
  assert(result_out != NULL);

  memset(result_out, 0, sizeof(*result_out));

  struct timespec start_time;
  clock_gettime(CLOCK_MONOTONIC, &start_time);

  size_t            read_len  = 0;
  size_t            last_len  = 0;
  int               head_len  = RECEIVE_PARSE_PARTIAL;
  const char*       method;
  const char*       request_target;
  size_t            method_len, request_target_len;
  int               http_minor_version;
  struct phr_header headers[HTTP_MAX_HEADERS];
  size_t            header_count = 0;
  while (head_len == RECEIVE_PARSE_PARTIAL)
  {
    if (read_len == request_buf_size - 1)
      return memchr(request_buf, '\n', read_len) ? RECEIVE_ERR_HEAD_TOO_LARGE : RECEIVE_ERR_URI_TOO_LONG;
    
    ssize_t bytes_read = read(client_fd, request_buf + read_len, request_buf_size - 1 - read_len);
    if (bytes_read == 0)
      return RECEIVE_ERR_CLOSED;
    else if (bytes_read < 0)
      return RECEIVE_ERR_READ;
    read_len += (size_t)bytes_read;
    request_buf[read_len] = '\0';

    header_count = HTTP_MAX_HEADERS;
    head_len = phr_parse_request(request_buf, read_len, &method, &method_len, &request_target, &request_target_len, &http_minor_version, headers, &header_count, last_len);
    if (head_len == RECEIVE_PARSE_FAILED)
      return header_count == HTTP_MAX_HEADERS ? RECEIVE_ERR_TOO_MANY_HEADERS : RECEIVE_ERR_MALFORMED;

    last_len = read_len;

    if (head_len == RECEIVE_PARSE_PARTIAL && static_isDeadlinePassed(&start_time))
      return RECEIVE_ERR_DEADLINE;
  }

  for (size_t i = 0; i < header_count; i++)
  {
    if (!headers[i].name)
      return RECEIVE_ERR_MALFORMED;
  }

  result_out->m_startTime          = start_time;
  result_out->m_readLen            = read_len;
  result_out->m_headLen            = (size_t)head_len;
  result_out->mp_method            = method;
  result_out->m_methodLen          = method_len;
  result_out->mp_requestTarget     = request_target;
  result_out->m_requestTargetLen   = request_target_len;
  result_out->m_httpMinorVersion   = http_minor_version;
  memcpy(result_out->ma_headers, headers, header_count * sizeof(headers[0]));
  result_out->m_headerCount        = header_count;
  
  return RECEIVE_OK;
}

ReceiveStatus_t receive_readBodyLength(size_t max_body_byte_count, ReceiveResult_t* result_inout)
{
  assert(result_inout != NULL);
  assert(result_inout->m_headLen > 0);
  assert(result_inout->mp_body == NULL);

  ReceiveBodyLength_t body_length = { 0 };
  ReceiveStatus_t status = static_readBodyLengthFromHeaders(result_inout->ma_headers, result_inout->m_headerCount, max_body_byte_count, &body_length);
  if (status != RECEIVE_OK)
  {
    memset(result_inout, 0, sizeof(*result_inout));
    return status;
  }

  result_inout->m_bodyLen            = body_length.m_contentLength;
  result_inout->m_isContinueExpected = body_length.m_isContinueExpected;
  
  return RECEIVE_OK;
}

bool receive_isRequestTooLargeForBuffer(const ReceiveResult_t* request, size_t request_buf_size)
{
  assert(request != NULL);
  assert(request_buf_size >= 2);

  return request->m_headLen + request->m_bodyLen > request_buf_size - 1;
}

ReceiveStatus_t receive_readBody(int client_fd, char* request_buf, size_t request_buf_size, ReceiveResult_t* result_inout)
{
  assert(request_buf != NULL);
  assert(result_inout != NULL);
  assert(result_inout->m_headLen > 0);
  assert(result_inout->m_readLen < request_buf_size);
  assert(result_inout->mp_body == NULL);

  ReceiveStatus_t status = static_readBodyIntoResult(client_fd, request_buf, request_buf_size, result_inout);
  if (status != RECEIVE_OK)
    memset(result_inout, 0, sizeof(*result_inout));

  return status;
}

void receive_releaseLargeBuf(ReceiveResult_t* result)
{
  assert(result != NULL);

  if (result->mp_largeBuf == NULL)
    return;

  munmap(result->mp_largeBuf, result->m_largeBufSize);
  result->mp_largeBuf    = NULL;
  result->m_largeBufSize = 0;
  result->mp_body        = NULL;
  result->m_bodyLen      = 0;
}

void receive_discardRefusedBodyBeforeClose(int client_fd)
{
  shutdown(client_fd, SHUT_WR);

  struct timespec start_time;
  clock_gettime(CLOCK_MONOTONIC, &start_time);

  size_t discarded = 0;
  char discard_buf[RECEIVE_REFUSED_BODY_DISCARD_CHUNK_SIZE];

  while (discarded < RECEIVE_REFUSED_BODY_DISCARD_MAX_BYTE_COUNT)
  {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    long long elapsed_ms = ((long long)(now.tv_sec - start_time.tv_sec) * RECEIVE_NSEC_PER_SEC + (now.tv_nsec - start_time.tv_nsec)) / RECEIVE_NSEC_PER_MSEC;
    if (elapsed_ms >= RECEIVE_REFUSED_BODY_DISCARD_MAX_MS)
      return;

    struct pollfd poll_fd = { .fd = client_fd, .events = POLLIN };
    int ready = poll(&poll_fd, 1, (int)(RECEIVE_REFUSED_BODY_DISCARD_MAX_MS - elapsed_ms));
    if (ready < 0 && errno == EINTR)
      continue;
    if (ready <= 0)
      return;

    size_t chunk = RECEIVE_REFUSED_BODY_DISCARD_MAX_BYTE_COUNT - discarded < sizeof(discard_buf) ? RECEIVE_REFUSED_BODY_DISCARD_MAX_BYTE_COUNT - discarded : sizeof(discard_buf);
    ssize_t bytes_read = read(client_fd, discard_buf, chunk);
    if (bytes_read <= 0)
      return;
    discarded += (size_t)bytes_read;
  }
}

ReceiveHeader_t receive_findHeader(const ReceiveResult_t* request, const char* header_name)
{
  assert(request != NULL);
  assert(header_name != NULL);

  ReceiveHeader_t found = { .m_status = RECEIVE_HEADER_NONE, .mp_value = NULL, .m_len = 0 };
  for (size_t i = 0; i < request->m_headerCount; i++)
  {
    const struct phr_header* header = &request->ma_headers[i];
    if (static_isHeaderNamed(header, header_name))
    {
      found.m_status = RECEIVE_HEADER_FOUND;
      found.mp_value = header->value;
      found.m_len    = header->value_len;
      return found;
    }
  }
  return found;
}

ReceiveHeader_t receive_findUniqueHeader(const ReceiveResult_t* request, const char* header_name)
{
  assert(request != NULL);
  assert(header_name != NULL);

  ReceiveHeader_t found = { .m_status = RECEIVE_HEADER_NONE, .mp_value = NULL, .m_len = 0 };
  for (size_t i = 0; i < request->m_headerCount; i++)
  {
    const struct phr_header* header = &request->ma_headers[i];
    if (!static_isHeaderNamed(header, header_name))
      continue;
    if (found.m_status == RECEIVE_HEADER_FOUND)
    {
      found = (ReceiveHeader_t){ .m_status = RECEIVE_HEADER_REPEATED, .mp_value = NULL, .m_len = 0 };
      return found;
    }
    found.m_status = RECEIVE_HEADER_FOUND;
    found.mp_value = header->value;
    found.m_len    = header->value_len;
  }
  return found;
}

static bool static_isHeaderNamed(const struct phr_header* header, const char* name)
{
  return header->name != NULL && bytes_isEqual(header->name, header->name_len, name, true);
}

static bool static_isDeadlinePassed(const struct timespec* start_time)
{
  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);
  long long elapsed_nsec = (long long)(now.tv_sec - start_time->tv_sec) * RECEIVE_NSEC_PER_SEC + (now.tv_nsec - start_time->tv_nsec);
  
  return elapsed_nsec / RECEIVE_NSEC_PER_MSEC >= (long long)RECEIVE_DEADLINE_MS;
}

static ReceiveStatus_t static_readBodyIntoResult(int client_fd, char* request_buf, size_t request_buf_size, ReceiveResult_t* result)
{
  size_t head_len = result->m_headLen;
  size_t read_len = result->m_readLen;

  if (result->m_isContinueExpected && result->m_httpMinorVersion == 1 && result->m_bodyLen > 0 && read_len == head_len)
  {
    size_t continue_len = sizeof(RECEIVE_CONTINUE_RESPONSE) - 1;
    if (send(client_fd, RECEIVE_CONTINUE_RESPONSE, continue_len, MSG_NOSIGNAL) != (ssize_t)continue_len)
      return RECEIVE_ERR_WRITE;
  }

  size_t request_len       = head_len + result->m_bodyLen;
  char*  large_buf         = NULL;
  size_t large_buf_size    = 0;
  char*  whole_request_buf = request_buf;
  if (receive_isRequestTooLargeForBuffer(result, request_buf_size))
  {
    large_buf_size = request_len + 1;
    large_buf      = static_makeLargeBuf(request_buf, head_len, read_len, large_buf_size);
    if (large_buf == NULL)
      return RECEIVE_ERR_LARGE_BODY_NO_MEMORY;
    
    whole_request_buf = large_buf;
  }
  ReceiveStatus_t body_status = static_readBody(client_fd, whole_request_buf, &read_len, request_len, &result->m_startTime);
  if (body_status != RECEIVE_OK)
  {
    if (large_buf != NULL)
      munmap(large_buf, large_buf_size);
    return body_status;
  }
  whole_request_buf[request_len] = '\0';

  result->m_requestLen   = request_len;
  result->mp_largeBuf    = large_buf;
  result->m_largeBufSize = large_buf_size;
  result->mp_body        = whole_request_buf + head_len;

  return RECEIVE_OK;
}

static char* static_makeLargeBuf(char* request_buf, size_t head_len, size_t read_len, size_t large_buf_size)
{
  char* large_buf = mmap(NULL, large_buf_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (large_buf == MAP_FAILED)
    return NULL;

  (void)madvise(large_buf, large_buf_size, MADV_DONTDUMP);

  memcpy(large_buf, request_buf, read_len);
  explicit_bzero(request_buf + head_len, read_len - head_len);
  return large_buf;
}

static ReceiveStatus_t static_readBodyLengthFromHeaders(const struct phr_header* headers, size_t header_count, size_t body_length_limit, ReceiveBodyLength_t* body_length_out)
{
  const struct phr_header* content_length_header = NULL;
  int  content_length_count   = 0;
  bool has_transfer_encoding  = false;
  bool is_continue_expected   = false;
  for (size_t i = 0; i < header_count; i++)
  {
    if (static_isHeaderNamed(&headers[i], "content-length"))
    {
      content_length_header = &headers[i];
      content_length_count++;
    }
    else if (static_isHeaderNamed(&headers[i], "transfer-encoding"))
      has_transfer_encoding = true;
    else if (static_isHeaderNamed(&headers[i], "expect"))
      is_continue_expected = bytes_isEqual(headers[i].value, headers[i].value_len, "100-continue", true);
  }

  if (has_transfer_encoding && content_length_count > 0)
    return RECEIVE_ERR_LENGTH_AND_TRANSFER_ENCODING;
  else if (has_transfer_encoding)
    return RECEIVE_ERR_TRANSFER_ENCODING;
  else if (content_length_count > 1)
    return RECEIVE_ERR_BAD_CONTENT_LENGTH;

  size_t content_length = 0;
  if (content_length_header)
  {
    if (content_length_header->value_len == 0)
      return RECEIVE_ERR_BAD_CONTENT_LENGTH;

    for (size_t i = 0; i < content_length_header->value_len; i++)
    {
      if (!isdigit((unsigned char)content_length_header->value[i]))
        return RECEIVE_ERR_BAD_CONTENT_LENGTH;
    }

    for (size_t i = 0; i < content_length_header->value_len; i++)
    {
      content_length = content_length * 10 + (size_t)(content_length_header->value[i] - '0');
      if (content_length > body_length_limit)
        return RECEIVE_ERR_CONTENT_TOO_LARGE;
    }
  }

  body_length_out->m_contentLength = content_length;
  body_length_out->m_isContinueExpected = is_continue_expected;
  
  return RECEIVE_OK;
}

static ReceiveStatus_t static_readBody(int client_fd, char* whole_request_buf, size_t* read_len_inout, size_t request_len, const struct timespec* start_time)
{
  while (*read_len_inout < request_len)
  {
    ssize_t bytes_read = read(client_fd, whole_request_buf + *read_len_inout, request_len - *read_len_inout);
    if (bytes_read == 0)
      return RECEIVE_ERR_CLOSED;
    else if (bytes_read < 0)
      return RECEIVE_ERR_READ;

    *read_len_inout += (size_t)bytes_read;
    if (*read_len_inout < request_len && static_isDeadlinePassed(start_time))
      return RECEIVE_ERR_DEADLINE;
  }
  
  return RECEIVE_OK;
}
