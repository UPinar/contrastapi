#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "http_stub.h"
#include "x402_solana.h"
#include "x402_solana_rpc.h"

static const int FUZZ_STATUSES[] = { 200, 429, 500, 302, 0 };

#define FUZZ_SIGNATURE_TEXT "67rpwLCuS5DGA8KGZXKsVQ7dnPb9goRLoKfgGbLfQg9WoLUgNY77E2jT11fem3coV9nAkguBACzrU1iyZM4B8roQ"

#define FUZZ_FEE_PAYER_BYTE 0x11
#define FUZZ_TX_BYTE_COUNT  (1 + 64 + 3 + 1 + 32 + 32 + 1)

static bool static_isKnownStatus(X402SolanaRpcSignatureStatus_t status)
{
  return status == X402_SOLANA_RPC_SIGNATURE_CONFIRMED || status == X402_SOLANA_RPC_SIGNATURE_FAILED
         || status == X402_SOLANA_RPC_SIGNATURE_PROCESSED || status == X402_SOLANA_RPC_SIGNATURE_NOT_FOUND
         || status == X402_SOLANA_RPC_SIGNATURE_UNAVAILABLE;
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
  if (size == 0)
    return 0;

  int status = FUZZ_STATUSES[data[0] % (sizeof(FUZZ_STATUSES) / sizeof(FUZZ_STATUSES[0]))];
  size_t body_len = size - 1;
  char*  body     = malloc(body_len + 1);
  if (body == NULL)
    abort();
  memcpy(body, data + 1, body_len);
  body[body_len] = '\0';

  g_stub_answers        = NULL;
  g_stub_next_body_null = false;
  g_stub_next_status    = status;
  g_stub_next_body      = body;
  g_stub_next_error     = HTTP_ERROR_NONE;
  if (status == 0)
    g_stub_next_error = HTTP_ERROR_TIMEOUT;
  else if (body_len > X402_SOLANA_RPC_MAX_ANSWER_BYTE_COUNT)
    g_stub_next_error = HTTP_ERROR_BODY_TOO_LARGE;

  X402SolanaRpcSignatureStatus_t found = x402_solana_rpc_askSignatureStatus("https://rpc.example.com/", FUZZ_SIGNATURE_TEXT);
  if (!static_isKnownStatus(found))
    abort();

  uint8_t fee_payer[X402_SOLANA_ADDRESS_BYTE_COUNT];
  memset(fee_payer, FUZZ_FEE_PAYER_BYTE, sizeof(fee_payer));
  uint8_t tx[FUZZ_TX_BYTE_COUNT] = { 1 };
  size_t  tx_len = 1 + 64;
  tx[tx_len++] = 1;
  tx[tx_len++] = 0;
  tx[tx_len++] = 0;
  tx[tx_len++] = 1;
  memcpy(tx + tx_len, fee_payer, sizeof(fee_payer));
  tx_len += sizeof(fee_payer);
  memset(tx + tx_len, 0x44, 32);
  tx_len += 32;
  tx[tx_len++] = 0;

  g_stub_next_error = HTTP_ERROR_NONE;
  if (status == 0)
    g_stub_next_error = HTTP_ERROR_TIMEOUT;
  else if (body_len > X402_SOLANA_RPC_MAX_LIST_ANSWER_BYTE_COUNT)
    g_stub_next_error = HTTP_ERROR_BODY_TOO_LARGE;
  char signature_text[X402_SOLANA_SIGNATURE_TEXT_BUF_SIZE];
  found = x402_solana_rpc_findFeePayerSignature("https://rpc.example.com/", fee_payer, tx, tx_len, fee_payer, signature_text);
  if (!static_isKnownStatus(found) || strnlen(signature_text, sizeof(signature_text)) == sizeof(signature_text))
    abort();
  if (signature_text[0] != '\0' && found != X402_SOLANA_RPC_SIGNATURE_CONFIRMED && found != X402_SOLANA_RPC_SIGNATURE_FAILED
      && found != X402_SOLANA_RPC_SIGNATURE_PROCESSED)
    abort();

  g_stub_next_body = NULL;
  free(body);
  return 0;
}
