#ifndef X402_SOLANA_RPC_H
#define X402_SOLANA_RPC_H

#include <stddef.h>
#include <stdint.h>

#include "x402_solana.h"

#define X402_SOLANA_RPC_TIMEOUT_MS            5000

#define X402_SOLANA_RPC_MAX_ANSWER_BYTE_COUNT 16384

#define X402_SOLANA_RPC_SIGNATURE_LIST_LIMIT  20

#define X402_SOLANA_RPC_MAX_LIST_ANSWER_BYTE_COUNT 65536

typedef enum {
  X402_SOLANA_RPC_SIGNATURE_CONFIRMED,
  X402_SOLANA_RPC_SIGNATURE_FAILED,
  X402_SOLANA_RPC_SIGNATURE_PROCESSED,
  X402_SOLANA_RPC_SIGNATURE_NOT_FOUND,
  X402_SOLANA_RPC_SIGNATURE_UNAVAILABLE
} X402SolanaRpcSignatureStatus_t;

X402SolanaRpcSignatureStatus_t x402_solana_rpc_askSignatureStatus    (const char* rpc_url, const char* signature_text);
X402SolanaRpcSignatureStatus_t x402_solana_rpc_findFeePayerSignature (const char* rpc_url, const uint8_t source[X402_SOLANA_ADDRESS_BYTE_COUNT], const uint8_t* tx, size_t tx_len, const uint8_t fee_payer[X402_SOLANA_ADDRESS_BYTE_COUNT], char signature_out[X402_SOLANA_SIGNATURE_TEXT_BUF_SIZE]);

#endif
