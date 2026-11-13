#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "x402_solana.h"

#define FUZZ_X402_SOLANA_AMOUNT 1234567u

static const uint8_t USDC_MINT[X402_SOLANA_ADDRESS_BYTE_COUNT] = {
  0xc6, 0xfa, 0x7a, 0xf3, 0xbe, 0xdb, 0xad, 0x3a, 0x3d, 0x65, 0xf3, 0x6a, 0xab, 0xc9, 0x74, 0x31,
  0xb1, 0xbb, 0xe4, 0xc2, 0xd2, 0xf6, 0xe0, 0xe4, 0x7c, 0xa6, 0x02, 0x03, 0x45, 0x2f, 0x5d, 0x61
};

static void static_fillKey(uint8_t key[X402_SOLANA_ADDRESS_BYTE_COUNT], uint8_t seed)
{
  for (int i = 0; i < X402_SOLANA_ADDRESS_BYTE_COUNT; i++)
    key[i] = (uint8_t)(seed + i * 13);
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
  X402SolanaPolicy_t policy = { 0 };
  static_fillKey(policy.ma_feePayer, 0x11);
  memcpy(policy.ma_mint, USDC_MINT, sizeof(USDC_MINT));
  static_fillKey(policy.ma_destination, 0x33);
  policy.m_amount = FUZZ_X402_SOLANA_AMOUNT;

  uint8_t* exact = malloc(size > 0 ? size : 1);
  if (exact == NULL)
    abort();
  memcpy(exact, data, size);
  X402SolanaCheck_t check;
  memset(&check, 0, sizeof(check));
  (void)x402_solana_checkTransaction(size > 0 ? exact : NULL, size, &policy, &check);
  free(exact);

  char* text = malloc(size + 1);
  if (text == NULL)
    abort();
  memcpy(text, data, size);
  text[size] = '\0';
  uint8_t address[X402_SOLANA_ADDRESS_BYTE_COUNT];
  (void)x402_solana_tryDecodeAddress(text, address);
  free(text);

  return 0;
}
