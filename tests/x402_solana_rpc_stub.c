#include <stdio.h>

#include "x402_solana_rpc.h"
#include "x402_solana_rpc_stub.h"

X402SolanaRpcSignatureStatus_t g_stub_X402_SOLANA_RPC_status = X402_SOLANA_RPC_SIGNATURE_NOT_FOUND;
int                            g_stub_X402_SOLANA_RPC_count  = 0;
char                           g_stub_X402_SOLANA_RPC_last_url[X402_SOLANA_RPC_STUB_URL_BUF_SIZE]             = "";
char                           g_stub_X402_SOLANA_RPC_last_signature[X402_SOLANA_SIGNATURE_TEXT_BUF_SIZE]     = "";

X402SolanaRpcSignatureStatus_t x402_solana_rpc_askSignatureStatus(const char* rpc_url, const char* signature_text)
{
  g_stub_X402_SOLANA_RPC_count++;
  snprintf(g_stub_X402_SOLANA_RPC_last_url, sizeof(g_stub_X402_SOLANA_RPC_last_url), "%s", rpc_url);
  snprintf(g_stub_X402_SOLANA_RPC_last_signature, sizeof(g_stub_X402_SOLANA_RPC_last_signature), "%s", signature_text);
  return g_stub_X402_SOLANA_RPC_status;
}
