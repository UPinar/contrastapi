#ifndef X402_REQUEST_H
#define X402_REQUEST_H

#include <stdbool.h>
#include <stddef.h>
#include <libpq-fe.h>

#include "auth.h"
#include "config.h"
#include "endpoint.h"
#include "jsonbuf.h"
#include "x402.h"
#include "x402_ledger.h"
#include "x402_solana.h"

#define X402_REQUEST_PAYMENT_HEADER_NAME             "PAYMENT-SIGNATURE"

#define X402_REQUEST_MAX_SETTLE_COUNT                2

#define X402_REQUEST_BUSY_RETRY_AFTER_SEC            5

#define X402_REQUEST_UNAVAILABLE_RETRY_AFTER_SEC     5

#define X402_REQUEST_PENDING_RETRY_AFTER_SEC         10

#define X402_REQUEST_PAYMENT_REQUIRED_LINE_BUF_SIZE  1152

#define X402_REQUEST_RECEIPT_LINE_BUF_SIZE           384

typedef enum {
  X402_REQUEST_PAYMENT_SOURCE_HEADER_BASE64,
  X402_REQUEST_PAYMENT_SOURCE_JSON
} X402RequestPaymentSourceKind_t;

typedef struct {
  X402RequestPaymentSourceKind_t  m_kind;
  const char*                     mp_text;
  size_t                          m_len;
} X402RequestPaymentSource_t;

typedef struct {
  char  ma_network[X402_NETWORK_BUF_SIZE];
  char  ma_signature[X402_SOLANA_SIGNATURE_TEXT_BUF_SIZE];
} X402RequestReceipt_t;

typedef enum {
  X402_REQUEST_START_OFF,
  X402_REQUEST_START_ON,
  X402_REQUEST_START_INVALID,
  X402_REQUEST_START_MISMATCH,
  X402_REQUEST_START_UNAVAILABLE
} X402RequestStartStatus_t;

typedef enum {
  X402_REQUEST_PAYMENT_FRESH,
  X402_REQUEST_PAYMENT_CONFIRMED
} X402RequestPaymentKind_t;

typedef struct X402RequestPayment {
  X402RequestPaymentKind_t m_kind;
  bool                     m_isOpen;
  X402Requirements_t       m_requirements;
  X402Payment_t            m_payment;
  X402LedgerHashes_t       m_hashes;
  char                     ma_ipHash[SHA256_HEX_LEN + 1];
  char                     ma_signature[X402_SOLANA_SIGNATURE_TEXT_BUF_SIZE];
} X402RequestPayment_t;

typedef enum {
  X402_REQUEST_OPEN_OK,
  X402_REQUEST_OPEN_MALFORMED,
  X402_REQUEST_OPEN_REFUSED,
  X402_REQUEST_OPEN_ALREADY_USED,
  X402_REQUEST_OPEN_PENDING,
  X402_REQUEST_OPEN_BUSY,
  X402_REQUEST_OPEN_LIMITED,
  X402_REQUEST_OPEN_UNAVAILABLE,
  X402_REQUEST_OPEN_ERROR
} X402RequestOpenStatus_t;

typedef struct {
  X402RequestOpenStatus_t m_status;
  unsigned int            m_retryAfterSec;
} X402RequestOpenResult_t;

typedef enum {
  X402_REQUEST_UNSERVED_REFUSED_REQUEST,
  X402_REQUEST_UNSERVED_FAILED_RUN
} X402RequestUnservedKind_t;

typedef enum {
  X402_REQUEST_CLOSE_SERVE,
  X402_REQUEST_CLOSE_REFUSED,
  X402_REQUEST_CLOSE_PENDING
} X402RequestCloseStatus_t;

X402RequestStartStatus_t  x402_request_start                    (const ConfigX402_t* config);
bool                      x402_request_isOn                     (void);
X402RequestOpenResult_t   x402_request_dbOpenPayment            (PGconn* conn, const X402RequestPaymentSource_t* source, unsigned int credit_count, const char* ip_secret, const char* ip_hash, X402RequestPayment_t* payment_out);
X402RequestCloseStatus_t  x402_request_dbCloseAfterRun          (PGconn* conn, X402RequestPayment_t* payment, X402RequestReceipt_t* receipt_out);
void                      x402_request_dbReleaseUnserved        (PGconn* conn, X402RequestPayment_t* payment, X402RequestUnservedKind_t unserved_kind);
X402RequestUnservedKind_t x402_request_findUnservedKind         (EndpointRunStatus_t run_status);
X402RequestOpenResult_t   x402_request_dbCheckBeforeWeigh       (PGconn* conn, const X402RequestPaymentSource_t* source, const char* ip_hash);
X402RequestOpenResult_t   x402_request_dbThrottleWeigh          (PGconn* conn, const char* ip_hash);
bool                      x402_request_tryWritePaymentRequired  (const Endpoint_t* endpoint, unsigned int credit_count, const char* error_text, char* line_out, size_t line_size);
bool                      x402_request_appendPaymentRequired    (JsonBuf_t* json_buf, const char* resource_url, unsigned int credit_count, const char* error_text);
bool                      x402_request_tryWriteReceiptLine      (const X402RequestReceipt_t* receipt, char* line_out, size_t line_size);
bool                      x402_request_appendReceipt            (JsonBuf_t* json_buf, const X402RequestReceipt_t* receipt);

#endif
