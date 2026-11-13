#ifndef RECEIVE_H
#define RECEIVE_H

#include <stdbool.h>
#include <stddef.h>
#include <time.h>

#include "picohttpparser.h"

#define RECEIVE_DEADLINE_MS  10000u

#define RECEIVE_REFUSED_BODY_DISCARD_MAX_MS          1000
#define RECEIVE_REFUSED_BODY_DISCARD_MAX_BYTE_COUNT  65536
#define RECEIVE_REFUSED_BODY_DISCARD_CHUNK_SIZE      4096

typedef enum {
  RECEIVE_OK = 0,
  RECEIVE_ERR_CLOSED,
  RECEIVE_ERR_READ,
  RECEIVE_ERR_DEADLINE,
  RECEIVE_ERR_MALFORMED,
  RECEIVE_ERR_URI_TOO_LONG,
  RECEIVE_ERR_HEAD_TOO_LARGE,
  RECEIVE_ERR_TOO_MANY_HEADERS,
  RECEIVE_ERR_BAD_CONTENT_LENGTH,
  RECEIVE_ERR_LENGTH_AND_TRANSFER_ENCODING,
  RECEIVE_ERR_TRANSFER_ENCODING,
  RECEIVE_ERR_CONTENT_TOO_LARGE,
  RECEIVE_ERR_WRITE,
  RECEIVE_ERR_LARGE_BODY_NO_MEMORY,
} ReceiveStatus_t;

typedef struct {
  struct timespec   m_startTime;
  size_t            m_readLen;
  size_t            m_headLen;
  const char*       mp_method;
  size_t            m_methodLen;
  const char*       mp_requestTarget;
  size_t            m_requestTargetLen;
  int               m_httpMinorVersion;
  struct phr_header ma_headers[HTTP_MAX_HEADERS];
  size_t            m_headerCount;

  const char*       mp_body;
  size_t            m_bodyLen;
  bool              m_isContinueExpected;
  size_t            m_requestLen;
  char*             mp_largeBuf;
  size_t            m_largeBufSize;
} ReceiveResult_t;

typedef enum {
  RECEIVE_HEADER_NONE,
  RECEIVE_HEADER_FOUND,
  RECEIVE_HEADER_REPEATED
} ReceiveHeaderStatus_t;

typedef struct {
  ReceiveHeaderStatus_t m_status;
  const char*           mp_value;
  size_t                m_len;
} ReceiveHeader_t;

ReceiveStatus_t receive_readHead                      (int client_fd, char* request_buf, size_t request_buf_size, ReceiveResult_t* result_out);
ReceiveStatus_t receive_readBodyLength                (size_t max_body_byte_count, ReceiveResult_t* result_inout);
bool            receive_isRequestTooLargeForBuffer    (const ReceiveResult_t* request, size_t request_buf_size);
ReceiveStatus_t receive_readBody                      (int client_fd, char* request_buf, size_t request_buf_size, ReceiveResult_t* result_inout);
void            receive_releaseLargeBuf               (ReceiveResult_t* result);
void            receive_discardRefusedBodyBeforeClose (int client_fd);
ReceiveHeader_t receive_findHeader                    (const ReceiveResult_t* request, const char* header_name);
ReceiveHeader_t receive_findUniqueHeader              (const ReceiveResult_t* request, const char* header_name);

#endif
