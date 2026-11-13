#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "http_stub.h"
#include "x402_solana_rpc.h"

static const int FUZZ_STATUSES[] = { 200, 429, 500, 302, 0 };

#define FUZZ_SIGNATURE_TEXT "67rpwLCuS5DGA8KGZXKsVQ7dnPb9goRLoKfgGbLfQg9WoLUgNY77E2jT11fem3coV9nAkguBACzrU1iyZM4B8roQ"

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
  if (found != X402_SOLANA_RPC_SIGNATURE_CONFIRMED && found != X402_SOLANA_RPC_SIGNATURE_FAILED && found != X402_SOLANA_RPC_SIGNATURE_PROCESSED
      && found != X402_SOLANA_RPC_SIGNATURE_NOT_FOUND && found != X402_SOLANA_RPC_SIGNATURE_UNAVAILABLE)
    abort();

  g_stub_next_body = NULL;
  free(body);
  return 0;
}
