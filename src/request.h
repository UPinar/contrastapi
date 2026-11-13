#ifndef REQUEST_H
#define REQUEST_H

#include <stdbool.h>
#include <stddef.h>
#include <libpq-fe.h>

#include "receive.h"
#include "auth.h"
#include "ratelimit.h"
#include "dbapikey.h"

struct X402RequestPayment;

#define REQUEST_BUFFER_SIZE 4096

#define REQUEST_METHOD_MAX_LEN      7
#define REQUEST_TARGET_MAX_LEN      1023

typedef enum {
  REQUEST_HEAD_OK = 0,
  REQUEST_HEAD_ERR_METHODTOOLONG,
  REQUEST_HEAD_ERR_TARGETTOOLONG
} RequestHeadStatus_t;

typedef struct {
  RequestHeadStatus_t m_status;
  char                ma_method[REQUEST_METHOD_MAX_LEN + 1];
  char                ma_path[REQUEST_TARGET_MAX_LEN + 1];
  const char*         mp_query;
} RequestHead_t;

typedef enum {
  REQUEST_TIER_FREE,
  REQUEST_TIER_PRO,
  REQUEST_TIER_X402,
} RequestTier_t;

typedef struct {
  char              ma_budgetHash[SHA256_HEX_LEN + 1];
  RequestTier_t     m_tier;
  DbApiKeyExpiry_t  m_keyExpiry;
  RateLimitInfo_t   m_rateLimitInfo;
} RequestCreditBudget_t;

typedef struct {
  unsigned int                 m_chargedCreditCount;
  const RequestCreditBudget_t* mp_creditBudget;
  struct X402RequestPayment*   mp_x402Payment;
} RequestCharge_t;

void   request_readHead             (const ReceiveResult_t* request, RequestHead_t* head_out);
bool   request_isRawBodyPlaceNeeded (const RequestHead_t* head);
size_t request_maxBodyByteCount     (const RequestHead_t* head, size_t head_len);
void   request_handle               (const ReceiveResult_t* request, const RequestHead_t* head, int client_fd, const char* client_ip, const char* ip_secret, PGconn* conn);

#endif
