#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>

#include "connection.h"
#include "receive.h"
#include "request.h"
#include "handler.h"
#include "response.h"
#include "rawbody.h"
#include "usagelog.h"

ConnectionServeStatus_t connection_serveRequest(int client_fd, const char* client_ip, const char* ip_secret, PGconn* conn)
{
  assert(client_fd >= 0);
  assert(client_ip != NULL);

  usagelog_beginRequest();
  response_clearRateLimitInfo();

  struct timeval receive_timeout = { .tv_sec = CONNECTION_READ_TIMEOUT_SEC, .tv_usec = 0 };
  struct timeval send_timeout    = { .tv_sec = CONNECTION_SEND_TIMEOUT_SEC, .tv_usec = 0 };
  if (setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &receive_timeout, sizeof(receive_timeout)) != 0 ||
      setsockopt(client_fd, SOL_SOCKET, SO_SNDTIMEO, &send_timeout, sizeof(send_timeout)) != 0)
  {
    close(client_fd);
    usagelog_writeRequest();
    return CONNECTION_SERVE_DROPPED;
  }

  char request_buf[REQUEST_BUFFER_SIZE];
  ReceiveResult_t receive_result = { 0 };
  RequestHead_t   head           = { 0 };
  size_t max_body_byte_count = 0;
  ReceiveStatus_t receive_status = receive_readHead(client_fd, request_buf, sizeof(request_buf), &receive_result);
  if (receive_status == RECEIVE_OK)
  {
    request_readHead(&receive_result, &head);
    max_body_byte_count = request_maxBodyByteCount(&head, receive_result.m_headLen);
    receive_status = receive_readBodyLength(max_body_byte_count, &receive_result);
  }

  bool is_raw_body_place_needed = receive_status == RECEIVE_OK && request_isRawBodyPlaceNeeded(&head);
  if (is_raw_body_place_needed && !rawbody_tryEnter())
  {
    handler_rawBodyBusy(client_fd);
    receive_discardRefusedBodyBeforeClose(client_fd);
    close(client_fd);
    explicit_bzero(request_buf, sizeof(request_buf));
    usagelog_writeRequest();

    return CONNECTION_SERVE_HANDLED;
  }
  if (receive_status == RECEIVE_OK)
    receive_status = receive_readBody(client_fd, request_buf, sizeof(request_buf), &receive_result);

  ConnectionServeStatus_t serve_status = CONNECTION_SERVE_HANDLED;
  switch (receive_status)
  {
    case RECEIVE_OK:
      break;
    case RECEIVE_ERR_CLOSED:
    case RECEIVE_ERR_READ:
    case RECEIVE_ERR_DEADLINE:
    case RECEIVE_ERR_MALFORMED:
    case RECEIVE_ERR_WRITE:
      serve_status = CONNECTION_SERVE_DROPPED;
      break;
    case RECEIVE_ERR_URI_TOO_LONG:
      handler_uriTooLong(client_fd);
      break;
    case RECEIVE_ERR_HEAD_TOO_LARGE:
    case RECEIVE_ERR_TOO_MANY_HEADERS:
      handler_headerFieldsTooLarge(client_fd);
      break;
    case RECEIVE_ERR_BAD_CONTENT_LENGTH:
      handler_badRequest(client_fd, "Content-Length must be one decimal number");
      break;
    case RECEIVE_ERR_LENGTH_AND_TRANSFER_ENCODING:
      handler_badRequest(client_fd, "send Content-Length or Transfer-Encoding, not both");
      break;
    case RECEIVE_ERR_TRANSFER_ENCODING:
      handler_transferEncodingNotImplemented(client_fd);
      break;
    case RECEIVE_ERR_CONTENT_TOO_LARGE:
      handler_contentTooLarge(client_fd);
      receive_discardRefusedBodyBeforeClose(client_fd);
      break;
    case RECEIVE_ERR_LARGE_BODY_NO_MEMORY:
      handler_internalError(client_fd);
      break;
  }

  if (receive_status != RECEIVE_OK)
    close(client_fd);
  else
    request_handle(&receive_result, &head, client_fd, client_ip, ip_secret, conn);

  receive_releaseLargeBuf(&receive_result);
  rawbody_leaveIfEntered();
  explicit_bzero(request_buf, sizeof(request_buf));
  usagelog_writeRequest();

  return serve_status;
}
