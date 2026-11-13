#ifndef X402_SOLANA_H
#define X402_SOLANA_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define X402_SOLANA_ADDRESS_BYTE_COUNT          32

#define X402_SOLANA_SIGNATURE_BYTE_COUNT        64

#define X402_SOLANA_SIGNATURE_TEXT_BUF_SIZE     89

#define X402_SOLANA_MAX_TRANSACTION_BYTE_COUNT  1232

#define X402_SOLANA_MAX_INSTRUCTION_COUNT       7

#define X402_SOLANA_MAX_COMPUTE_UNIT_LIMIT      200000

#define X402_SOLANA_MAX_COMPUTE_UNIT_PRICE      50000

#define X402_SOLANA_USDC_DECIMALS               6

typedef struct {
  uint8_t  ma_feePayer[X402_SOLANA_ADDRESS_BYTE_COUNT];
  uint8_t  ma_mint[X402_SOLANA_ADDRESS_BYTE_COUNT];
  uint8_t  ma_destination[X402_SOLANA_ADDRESS_BYTE_COUNT];
  uint64_t m_amount;
} X402SolanaPolicy_t;

typedef enum {
  X402_SOLANA_OK,
  X402_SOLANA_MALFORMED,
  X402_SOLANA_SIGNERS_REFUSED,
  X402_SOLANA_COMPUTE_REFUSED,
  X402_SOLANA_TRANSFER_REFUSED,
  X402_SOLANA_INSTRUCTION_REFUSED,
  X402_SOLANA_FEE_PAYER_IN_USE,
  X402_SOLANA_SIGNATURE_INVALID
} X402SolanaStatus_t;

#define X402_SOLANA_MESSAGE_HASH_BYTE_COUNT     32

typedef struct {
  uint8_t   ma_messageHash[X402_SOLANA_MESSAGE_HASH_BYTE_COUNT];
  uint8_t   ma_source[X402_SOLANA_ADDRESS_BYTE_COUNT];
} X402SolanaCheck_t;

X402SolanaStatus_t x402_solana_checkTransaction         (const uint8_t* tx, size_t tx_len, const X402SolanaPolicy_t* policy, X402SolanaCheck_t* check_out);
bool               x402_solana_tryDecodeAddress         (const char* text, uint8_t out[X402_SOLANA_ADDRESS_BYTE_COUNT]);
bool               x402_solana_tryDecodeSignature       (const char* text, uint8_t out[X402_SOLANA_SIGNATURE_BYTE_COUNT]);
bool               x402_solana_isFeePayerSignatureValid (const uint8_t* tx, size_t tx_len, const uint8_t fee_payer[X402_SOLANA_ADDRESS_BYTE_COUNT], const uint8_t signature[X402_SOLANA_SIGNATURE_BYTE_COUNT]);

#endif
