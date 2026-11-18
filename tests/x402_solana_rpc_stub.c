#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "x402_solana_rpc.h"
#include "x402_solana_rpc_stub.h"

X402SolanaRpcSignatureStatus_t g_stub_X402_SOLANA_RPC_status = X402_SOLANA_RPC_SIGNATURE_NOT_FOUND;
int                            g_stub_X402_SOLANA_RPC_count  = 0;
char                           g_stub_X402_SOLANA_RPC_last_url[X402_SOLANA_RPC_STUB_URL_BUF_SIZE]             = "";
char                           g_stub_X402_SOLANA_RPC_last_signature[X402_SOLANA_SIGNATURE_TEXT_BUF_SIZE]     = "";
X402SolanaRpcSignatureStatus_t g_stub_X402_SOLANA_RPC_find_status                                           = X402_SOLANA_RPC_SIGNATURE_NOT_FOUND;
char                           g_stub_X402_SOLANA_RPC_find_signature[X402_SOLANA_SIGNATURE_TEXT_BUF_SIZE]     = "";
int                            g_stub_X402_SOLANA_RPC_find_count                                            = 0;
char                           g_stub_X402_SOLANA_RPC_find_last_url[X402_SOLANA_RPC_STUB_URL_BUF_SIZE]        = "";
uint8_t                        g_stub_X402_SOLANA_RPC_find_last_source[X402_SOLANA_ADDRESS_BYTE_COUNT]        = { 0 };
uint8_t                        g_stub_X402_SOLANA_RPC_find_last_tx[X402_SOLANA_MAX_TRANSACTION_BYTE_COUNT]    = { 0 };
size_t                         g_stub_X402_SOLANA_RPC_find_last_tx_len                                      = 0;
uint8_t                        g_stub_X402_SOLANA_RPC_find_last_fee_payer[X402_SOLANA_ADDRESS_BYTE_COUNT]     = { 0 };

X402SolanaRpcSignatureStatus_t x402_solana_rpc_askSignatureStatus(const char* rpc_url, const char* signature_text)
{
  g_stub_X402_SOLANA_RPC_count++;
  snprintf(g_stub_X402_SOLANA_RPC_last_url, sizeof(g_stub_X402_SOLANA_RPC_last_url), "%s", rpc_url);
  snprintf(g_stub_X402_SOLANA_RPC_last_signature, sizeof(g_stub_X402_SOLANA_RPC_last_signature), "%s", signature_text);
  return g_stub_X402_SOLANA_RPC_status;
}

X402SolanaRpcSignatureStatus_t x402_solana_rpc_findFeePayerSignature(const char* rpc_url, const uint8_t source[X402_SOLANA_ADDRESS_BYTE_COUNT], const uint8_t* tx, size_t tx_len, const uint8_t fee_payer[X402_SOLANA_ADDRESS_BYTE_COUNT], char signature_out[X402_SOLANA_SIGNATURE_TEXT_BUF_SIZE])
{
  g_stub_X402_SOLANA_RPC_find_count++;
  snprintf(g_stub_X402_SOLANA_RPC_find_last_url, sizeof(g_stub_X402_SOLANA_RPC_find_last_url), "%s", rpc_url);
  memcpy(g_stub_X402_SOLANA_RPC_find_last_source, source, sizeof(g_stub_X402_SOLANA_RPC_find_last_source));
  g_stub_X402_SOLANA_RPC_find_last_tx_len = tx_len;
  memcpy(g_stub_X402_SOLANA_RPC_find_last_tx, tx, tx_len < sizeof(g_stub_X402_SOLANA_RPC_find_last_tx) ? tx_len : sizeof(g_stub_X402_SOLANA_RPC_find_last_tx));
  memcpy(g_stub_X402_SOLANA_RPC_find_last_fee_payer, fee_payer, sizeof(g_stub_X402_SOLANA_RPC_find_last_fee_payer));
  bool is_found = g_stub_X402_SOLANA_RPC_find_status == X402_SOLANA_RPC_SIGNATURE_CONFIRMED
                  || g_stub_X402_SOLANA_RPC_find_status == X402_SOLANA_RPC_SIGNATURE_FAILED
                  || g_stub_X402_SOLANA_RPC_find_status == X402_SOLANA_RPC_SIGNATURE_PROCESSED;
  snprintf(signature_out, X402_SOLANA_SIGNATURE_TEXT_BUF_SIZE, "%s", is_found ? g_stub_X402_SOLANA_RPC_find_signature : "");
  return g_stub_X402_SOLANA_RPC_find_status;
}
