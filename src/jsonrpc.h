#ifndef JSONRPC_H
#define JSONRPC_H

#include <stddef.h>
#include <stdbool.h>

#include "jsonread.h"
#include "jsonbuf.h"

#define JSONRPC_ERR_PARSE          -32700
#define JSONRPC_ERR_INVALID_REQ    -32600
#define JSONRPC_ERR_METHOD         -32601
#define JSONRPC_ERR_PARAMS         -32602
#define JSONRPC_ERR_INTERNAL       -32603

#define JSONRPC_ERR_HEADER_MISMATCH      -32020
#define JSONRPC_ERR_UNSUPPORTED_VERSION  -32022

#define JSONRPC_ERR_RATE_LIMITED      -32000
#define JSONRPC_ERR_UNAUTHORIZED      -32001
#define JSONRPC_ERR_UPSTREAM_BUSY     -32003
#define JSONRPC_ERR_API_KEY_INACTIVE  -32004

#define JSONRPC_METHOD_MAX_LEN  64
#define JSONRPC_ID_MAX_LEN      64

typedef enum {
  JSONRPC_OK = 0,
  JSONRPC_MALFORMED,
  JSONRPC_INVALID,
} JsonRpcStatus_t;

typedef struct {
  char           ma_rpcMethod[JSONRPC_METHOD_MAX_LEN + 1];
  char           ma_id[JSONRPC_ID_MAX_LEN + 1];
  bool           m_hasId;
  JsonReadSpan_t m_params;
  bool           m_hasParams;
} JsonRpcRequest_t;

JsonRpcStatus_t jsonrpc_parse(const char* body, size_t len, JsonRpcRequest_t* request_out);

void jsonrpc_serializeResult(const char* id_raw, const char* result_json, JsonBuf_t* json_buf);

void jsonrpc_serializeError(const char* id_raw, int code, const char* message, const char* data_json, JsonBuf_t* json_buf);

#endif
