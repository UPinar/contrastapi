#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <openssl/evp.h>

#include "unity/unity.h"
#include "x402_solana.h"

#define COMPUTE_BUDGET_TEXT "ComputeBudget111111111111111111111111111111"
#define TOKEN_TEXT          "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
#define TOKEN_2022_TEXT     "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
#define MEMO_TEXT           "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"
#define LIGHTHOUSE_TEXT     "L2TExMFKdjpN9kozasaurPirfHy9P8sbXoAN1qA3S95"
#define ATA_TEXT            "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"
#define USDC_TEXT           "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"

static const uint8_t COMPUTE_BUDGET_BYTES[32] = {
  0x03, 0x06, 0x46, 0x6f, 0xe5, 0x21, 0x17, 0x32, 0xff, 0xec, 0xad, 0xba, 0x72, 0xc3, 0x9b, 0xe7,
  0xbc, 0x8c, 0xe5, 0xbb, 0xc5, 0xf7, 0x12, 0x6b, 0x2c, 0x43, 0x9b, 0x3a, 0x40, 0x00, 0x00, 0x00
};
static const uint8_t TOKEN_BYTES[32] = {
  0x06, 0xdd, 0xf6, 0xe1, 0xd7, 0x65, 0xa1, 0x93, 0xd9, 0xcb, 0xe1, 0x46, 0xce, 0xeb, 0x79, 0xac,
  0x1c, 0xb4, 0x85, 0xed, 0x5f, 0x5b, 0x37, 0x91, 0x3a, 0x8c, 0xf5, 0x85, 0x7e, 0xff, 0x00, 0xa9
};
static const uint8_t TOKEN_2022_BYTES[32] = {
  0x06, 0xdd, 0xf6, 0xe1, 0xee, 0x75, 0x8f, 0xde, 0x18, 0x42, 0x5d, 0xbc, 0xe4, 0x6c, 0xcd, 0xda,
  0xb6, 0x1a, 0xfc, 0x4d, 0x83, 0xb9, 0x0d, 0x27, 0xfe, 0xbd, 0xf9, 0x28, 0xd8, 0xa1, 0x8b, 0xfc
};
static const uint8_t MEMO_BYTES[32] = {
  0x05, 0x4a, 0x53, 0x5a, 0x99, 0x29, 0x21, 0x06, 0x4d, 0x24, 0xe8, 0x71, 0x60, 0xda, 0x38, 0x7c,
  0x7c, 0x35, 0xb5, 0xdd, 0xbc, 0x92, 0xbb, 0x81, 0xe4, 0x1f, 0xa8, 0x40, 0x41, 0x05, 0x44, 0x8d
};
static const uint8_t LIGHTHOUSE_BYTES[32] = {
  0x04, 0xdf, 0xad, 0x79, 0x62, 0xff, 0xb1, 0xdd, 0x92, 0x5d, 0x0a, 0x9f, 0xb5, 0xe6, 0xd0, 0x0c,
  0xe6, 0x19, 0x5b, 0xa8, 0xbb, 0x3a, 0x91, 0xfd, 0x07, 0xef, 0x98, 0x60, 0xc5, 0xe9, 0x7b, 0xb8
};
static const uint8_t ATA_BYTES[32] = {
  0x8c, 0x97, 0x25, 0x8f, 0x4e, 0x24, 0x89, 0xf1, 0xbb, 0x3d, 0x10, 0x29, 0x14, 0x8e, 0x0d, 0x83,
  0x0b, 0x5a, 0x13, 0x99, 0xda, 0xff, 0x10, 0x84, 0x04, 0x8e, 0x7b, 0xd8, 0xdb, 0xe9, 0xf8, 0x59
};
static const uint8_t USDC_BYTES[32] = {
  0xc6, 0xfa, 0x7a, 0xf3, 0xbe, 0xdb, 0xad, 0x3a, 0x3d, 0x65, 0xf3, 0x6a, 0xab, 0xc9, 0x74, 0x31,
  0xb1, 0xbb, 0xe4, 0xc2, 0xd2, 0xf6, 0xe0, 0xe4, 0x7c, 0xa6, 0x02, 0x03, 0x45, 0x2f, 0x5d, 0x61
};

#define KEY_FEE_PAYER      0
#define KEY_AUTHORITY      1
#define KEY_SOURCE         2
#define KEY_DESTINATION    3
#define KEY_MINT           4
#define KEY_TOKEN          5
#define KEY_COMPUTE_BUDGET 6
#define KEY_EXTRA          7
#define KEY_LIGHTHOUSE     8

#define VALID_COMPUTE_UNIT_LIMIT 123457u
#define VALID_COMPUTE_UNIT_PRICE 7777u
#define VALID_AMOUNT             1234567u

#define TEST_MAX_KEY_COUNT          12
#define TEST_MAX_INSTRUCTION_COUNT  10
#define TEST_MAX_ACCOUNT_COUNT      8
#define TEST_MAX_DATA_BYTE_COUNT    1300
#define TEST_TX_BUF_SIZE            4096

#define CHECK_SENTINEL 0x5a

#define OVERREAD_FILL       0x06
#define OVERREAD_FILL_COUNT 16

typedef struct {
  uint8_t m_programIndex;
  int     m_accountCount;
  uint8_t ma_accounts[TEST_MAX_ACCOUNT_COUNT];
  size_t  m_dataLen;
  uint8_t ma_data[TEST_MAX_DATA_BYTE_COUNT];
  uint8_t ma_dataLenRaw[3];
  size_t  m_dataLenRawLen;
} TestInstruction_t;

typedef struct {
  bool              m_isV0;
  uint8_t           m_versionByte;
  uint8_t           ma_header[3];
  int               m_keyCount;
  uint8_t           ma_keys[TEST_MAX_KEY_COUNT][32];
  uint8_t           ma_blockhash[32];
  int               m_instructionCount;
  TestInstruction_t ma_instructions[TEST_MAX_INSTRUCTION_COUNT];
  int               m_signatureCount;
  uint8_t           ma_signatureCountRaw[3];
  size_t            m_signatureCountRawLen;
  uint8_t           ma_tableCountRaw[3];
  size_t            m_tableCountRawLen;
  uint8_t           ma_tableBytes[64];
  size_t            m_tableByteCount;
  EVP_PKEY*         mp_signingKey;
  size_t            m_trailingByteCount;
} TestTransaction_t;

static EVP_PKEY*          g_authorityKey;
static EVP_PKEY*          g_otherKey;
static EVP_PKEY*          g_feePayerKey;
static uint8_t            g_feePayerPublicKey[32];
static uint8_t            g_authorityPublicKey[32];
static TestTransaction_t  g_spec;
static X402SolanaPolicy_t g_policy;
static uint8_t            g_tx[TEST_TX_BUF_SIZE];
static size_t             g_txLen;
static size_t             g_messageOffset;
static X402SolanaCheck_t  g_check;
static uint8_t            g_runCopy[TEST_TX_BUF_SIZE + OVERREAD_FILL_COUNT];

static void static_fillKey(uint8_t key[32], uint8_t seed)
{
  for (int i = 0; i < 32; i++)
    key[i] = (uint8_t)(seed + i * 13);
}

static void static_decode(const char* text, uint8_t out[32])
{
  TEST_ASSERT_TRUE_MESSAGE(x402_solana_tryDecodeAddress(text, out), text);
}

static void static_putLe(uint8_t* data, uint64_t value, int byte_count)
{
  for (int i = 0; i < byte_count; i++)
    data[i] = (uint8_t)(value >> (8 * i));
}

static void static_setLimitInstruction(TestInstruction_t* ix, uint32_t limit)
{
  ix->m_programIndex = KEY_COMPUTE_BUDGET;
  ix->m_accountCount = 0;
  ix->m_dataLen      = 5;
  ix->ma_data[0]     = 2;
  static_putLe(ix->ma_data + 1, limit, 4);
}

static void static_setPriceInstruction(TestInstruction_t* ix, uint64_t price)
{
  ix->m_programIndex = KEY_COMPUTE_BUDGET;
  ix->m_accountCount = 0;
  ix->m_dataLen      = 9;
  ix->ma_data[0]     = 3;
  static_putLe(ix->ma_data + 1, price, 8);
}

static void static_setTransferInstruction(TestInstruction_t* ix, uint64_t amount)
{
  ix->m_programIndex   = KEY_TOKEN;
  ix->m_accountCount   = 4;
  ix->ma_accounts[0]   = KEY_SOURCE;
  ix->ma_accounts[1]   = KEY_MINT;
  ix->ma_accounts[2]   = KEY_DESTINATION;
  ix->ma_accounts[3]   = KEY_AUTHORITY;
  ix->m_dataLen        = 10;
  ix->ma_data[0]       = 12;
  static_putLe(ix->ma_data + 1, amount, 8);
  ix->ma_data[9]       = 6;
}

static TestInstruction_t* static_addMemo(size_t data_len)
{
  TEST_ASSERT_TRUE(g_spec.m_instructionCount < TEST_MAX_INSTRUCTION_COUNT);
  TEST_ASSERT_TRUE(data_len <= TEST_MAX_DATA_BYTE_COUNT);
  TestInstruction_t* ix = &g_spec.ma_instructions[g_spec.m_instructionCount++];
  memset(ix, 0, sizeof(*ix));
  ix->m_programIndex = KEY_EXTRA;
  ix->m_dataLen      = data_len;
  for (size_t i = 0; i < data_len; i++)
    ix->ma_data[i] = (uint8_t)('a' + i % 26);
  return ix;
}

static void static_resetValid(void)
{
  memset(&g_spec, 0, sizeof(g_spec));
  g_spec.ma_header[0] = 2;
  g_spec.ma_header[1] = 1;
  g_spec.ma_header[2] = 4;
  g_spec.m_keyCount   = 8;
  static_fillKey(g_spec.ma_keys[KEY_FEE_PAYER], 0x11);
  memcpy(g_spec.ma_keys[KEY_AUTHORITY], g_authorityPublicKey, 32);
  static_fillKey(g_spec.ma_keys[KEY_SOURCE], 0x22);
  static_fillKey(g_spec.ma_keys[KEY_DESTINATION], 0x33);
  static_decode(USDC_TEXT, g_spec.ma_keys[KEY_MINT]);
  static_decode(TOKEN_TEXT, g_spec.ma_keys[KEY_TOKEN]);
  static_decode(COMPUTE_BUDGET_TEXT, g_spec.ma_keys[KEY_COMPUTE_BUDGET]);
  static_decode(MEMO_TEXT, g_spec.ma_keys[KEY_EXTRA]);
  static_fillKey(g_spec.ma_blockhash, 0x44);
  g_spec.m_instructionCount = 3;
  static_setLimitInstruction(&g_spec.ma_instructions[0], VALID_COMPUTE_UNIT_LIMIT);
  static_setPriceInstruction(&g_spec.ma_instructions[1], VALID_COMPUTE_UNIT_PRICE);
  static_setTransferInstruction(&g_spec.ma_instructions[2], VALID_AMOUNT);
  g_spec.m_signatureCount = 2;
  g_spec.mp_signingKey    = g_authorityKey;

  memset(&g_policy, 0, sizeof(g_policy));
  memcpy(g_policy.ma_feePayer, g_spec.ma_keys[KEY_FEE_PAYER], 32);
  memcpy(g_policy.ma_mint, USDC_BYTES, 32);
  memcpy(g_policy.ma_destination, g_spec.ma_keys[KEY_DESTINATION], 32);
  g_policy.m_amount = VALID_AMOUNT;
}

static void static_addLighthouseKey(void)
{
  static_decode(LIGHTHOUSE_TEXT, g_spec.ma_keys[KEY_LIGHTHOUSE]);
  g_spec.m_keyCount     = 9;
  g_spec.ma_header[2]  += 1;
}

static void static_putByte(uint8_t value)
{
  TEST_ASSERT_TRUE(g_txLen < TEST_TX_BUF_SIZE);
  g_tx[g_txLen++] = value;
}

static void static_putBytes(const uint8_t* bytes, size_t byte_count)
{
  TEST_ASSERT_TRUE(g_txLen + byte_count <= TEST_TX_BUF_SIZE);
  memcpy(g_tx + g_txLen, bytes, byte_count);
  g_txLen += byte_count;
}

static void static_putCompactU16(unsigned value)
{
  TEST_ASSERT_TRUE(value <= 0xffff);
  while (value >= 0x80)
  {
    static_putByte((uint8_t)(value | 0x80));
    value >>= 7;
  }
  static_putByte((uint8_t)value);
}

static void static_putRawOrCompact(const uint8_t* raw, size_t raw_len, unsigned value)
{
  if (raw_len > 0)
    static_putBytes(raw, raw_len);
  else
    static_putCompactU16(value);
}

static void static_sign(EVP_PKEY* key, const uint8_t* message, size_t message_len, uint8_t* signature_out)
{
  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  TEST_ASSERT_NOT_NULL(ctx);
  size_t signature_len = 64;
  TEST_ASSERT_EQUAL_INT(1, EVP_DigestSignInit(ctx, NULL, NULL, NULL, key));
  TEST_ASSERT_EQUAL_INT(1, EVP_DigestSign(ctx, signature_out, &signature_len, message, message_len));
  TEST_ASSERT_EQUAL_size_t(64, signature_len);
  EVP_MD_CTX_free(ctx);
}

static void static_build(void)
{
  g_txLen = 0;
  static_putRawOrCompact(g_spec.ma_signatureCountRaw, g_spec.m_signatureCountRawLen, (unsigned)g_spec.m_signatureCount);
  size_t signatures_offset = g_txLen;
  for (int i = 0; i < g_spec.m_signatureCount; i++)
    for (int j = 0; j < 64; j++)
      static_putByte(i == 0 ? 0xab : 0xcd);

  g_messageOffset = g_txLen;
  if (g_spec.m_isV0)
    static_putByte(g_spec.m_versionByte);
  static_putBytes(g_spec.ma_header, 3);
  static_putCompactU16((unsigned)g_spec.m_keyCount);
  for (int i = 0; i < g_spec.m_keyCount; i++)
    static_putBytes(g_spec.ma_keys[i], 32);
  static_putBytes(g_spec.ma_blockhash, 32);
  static_putCompactU16((unsigned)g_spec.m_instructionCount);
  for (int i = 0; i < g_spec.m_instructionCount; i++)
  {
    const TestInstruction_t* ix = &g_spec.ma_instructions[i];
    static_putByte(ix->m_programIndex);
    static_putCompactU16((unsigned)ix->m_accountCount);
    static_putBytes(ix->ma_accounts, (size_t)ix->m_accountCount);
    static_putRawOrCompact(ix->ma_dataLenRaw, ix->m_dataLenRawLen, (unsigned)ix->m_dataLen);
    static_putBytes(ix->ma_data, ix->m_dataLen);
  }
  if (g_spec.m_isV0)
  {
    static_putRawOrCompact(g_spec.ma_tableCountRaw, g_spec.m_tableCountRawLen, 0);
    static_putBytes(g_spec.ma_tableBytes, g_spec.m_tableByteCount);
  }
  size_t message_len = g_txLen - g_messageOffset;

  if (g_spec.m_signatureCount >= 2)
    static_sign(g_spec.mp_signingKey, g_tx + g_messageOffset, message_len, g_tx + signatures_offset + 64);

  for (size_t i = 0; i < g_spec.m_trailingByteCount; i++)
    static_putByte(0x00);
}

static X402SolanaStatus_t static_run(void)
{
  memcpy(g_runCopy, g_tx, g_txLen);
  memset(g_runCopy + g_txLen, OVERREAD_FILL, OVERREAD_FILL_COUNT);
  memset(&g_check, CHECK_SENTINEL, sizeof(g_check));
  return x402_solana_checkTransaction(g_runCopy, g_txLen, &g_policy, &g_check);
}

static void static_expectRefusedAt(X402SolanaStatus_t expected, int line)
{
  X402SolanaStatus_t status = static_run();
  UNITY_TEST_ASSERT_EQUAL_INT(expected, status, line, "status");
  uint8_t sentinel[sizeof(g_check)];
  memset(sentinel, CHECK_SENTINEL, sizeof(sentinel));
  UNITY_TEST_ASSERT_EQUAL_MEMORY(sentinel, &g_check, sizeof(g_check), line, "check output changed on refusal");
}

static void static_expectAcceptedAt(int line)
{
  X402SolanaStatus_t status = static_run();
  UNITY_TEST_ASSERT_EQUAL_INT(X402_SOLANA_OK, status, line, "status");
  uint8_t      digest[32];
  unsigned int digest_len = 0;
  TEST_ASSERT_EQUAL_INT(1, EVP_Digest(g_tx + g_messageOffset, g_txLen - g_messageOffset - g_spec.m_trailingByteCount, digest, &digest_len, EVP_sha256(), NULL));
  UNITY_TEST_ASSERT_EQUAL_MEMORY(digest, g_check.ma_messageHash, 32, line, "message hash");
  UNITY_TEST_ASSERT_EQUAL_MEMORY(g_spec.ma_keys[g_spec.ma_instructions[2].ma_accounts[0]], g_check.ma_source, 32, line, "source");
}

#define EXPECT_REFUSED(status) static_expectRefusedAt((status), __LINE__)
#define EXPECT_ACCEPTED()      static_expectAcceptedAt(__LINE__)
#define BUILD_REFUSED(status)  do { static_build(); EXPECT_REFUSED(status); } while (0)
#define BUILD_ACCEPTED()       do { static_build(); EXPECT_ACCEPTED(); } while (0)

static void static_padTo(size_t target)
{
  (void)static_addMemo(0);
  static_build();
  TEST_ASSERT_TRUE(g_txLen < target);
  size_t data_len = target - g_txLen;
  if (data_len >= 128)
    data_len -= 1;
  g_spec.m_instructionCount -= 1;
  (void)static_addMemo(data_len);
  static_build();
  TEST_ASSERT_EQUAL_size_t(target, g_txLen);
}

void setUp(void)
{
  static_resetValid();
}

void tearDown(void)
{
}

void test_validLegacyTransactionIsAccepted(void)
{
  BUILD_ACCEPTED();
}

void test_validV0TransactionIsAccepted(void)
{
  g_spec.m_isV0        = true;
  g_spec.m_versionByte = 0x80;
  BUILD_ACCEPTED();
}

void test_memoAndLighthouseInstructionsAreAccepted(void)
{
  static_addLighthouseKey();
  static_addMemo(11);
  static_addMemo(0)->m_programIndex = KEY_LIGHTHOUSE;
  BUILD_ACCEPTED();
  g_spec.m_instructionCount = 3;
  static_addMemo(3)->m_programIndex = KEY_LIGHTHOUSE;
  BUILD_ACCEPTED();
}

void test_feePayerSignatureSlotIsNotChecked(void)
{
  static_build();
  memset(g_tx + 1, 0, 64);
  EXPECT_ACCEPTED();
}

void test_emptyTransactionIsMalformed(void)
{
  memset(&g_check, CHECK_SENTINEL, sizeof(g_check));
  TEST_ASSERT_EQUAL_INT(X402_SOLANA_MALFORMED, x402_solana_checkTransaction(g_tx, 0, &g_policy, &g_check));
  TEST_ASSERT_EQUAL_INT(X402_SOLANA_MALFORMED, x402_solana_checkTransaction(NULL, 0, &g_policy, &g_check));
  uint8_t sentinel[sizeof(g_check)];
  memset(sentinel, CHECK_SENTINEL, sizeof(sentinel));
  TEST_ASSERT_EQUAL_MEMORY(sentinel, &g_check, sizeof(g_check));
}

static void static_expectEveryPrefixMalformed(void)
{
  size_t full_len = g_txLen;
  for (size_t len = 1; len < full_len; len++)
  {
    g_txLen = len;
    EXPECT_REFUSED(X402_SOLANA_MALFORMED);
  }
  g_txLen = full_len;
}

void test_everyTruncatedPrefixIsMalformed(void)
{
  static_addMemo(130);
  static_build();
  static_expectEveryPrefixMalformed();
  g_spec.m_isV0        = true;
  g_spec.m_versionByte = 0x80;
  static_build();
  static_expectEveryPrefixMalformed();
}

void test_trailingByteIsMalformed(void)
{
  g_spec.m_trailingByteCount = 1;
  BUILD_REFUSED(X402_SOLANA_MALFORMED);
  g_spec.m_isV0        = true;
  g_spec.m_versionByte = 0x80;
  BUILD_REFUSED(X402_SOLANA_MALFORMED);
}

void test_transactionOf1232BytesIsAccepted(void)
{
  static_padTo(1232);
  EXPECT_ACCEPTED();
}

void test_transactionOf1233BytesIsMalformed(void)
{
  static_padTo(1233);
  EXPECT_REFUSED(X402_SOLANA_MALFORMED);
}

void test_versionOtherThanV0IsMalformed(void)
{
  g_spec.m_isV0        = true;
  g_spec.m_versionByte = 0x81;
  BUILD_REFUSED(X402_SOLANA_MALFORMED);
  g_spec.m_versionByte = 0xff;
  BUILD_REFUSED(X402_SOLANA_MALFORMED);
}

void test_v0AddressTableLookupIsMalformed(void)
{
  g_spec.m_isV0        = true;
  g_spec.m_versionByte = 0x80;
  g_spec.ma_tableCountRaw[0]  = 1;
  g_spec.m_tableCountRawLen   = 1;
  static_fillKey(g_spec.ma_tableBytes, 0x55);
  g_spec.ma_tableBytes[32]    = 0;
  g_spec.ma_tableBytes[33]    = 0;
  g_spec.m_tableByteCount     = 34;
  BUILD_REFUSED(X402_SOLANA_MALFORMED);
  g_spec.m_tableByteCount     = 0;
  BUILD_REFUSED(X402_SOLANA_MALFORMED);
}

void test_readonlySignedAtRequiredIsMalformed(void)
{
  g_spec.ma_header[1] = 2;
  BUILD_REFUSED(X402_SOLANA_MALFORMED);
}

void test_readonlyUnsignedPastKeyCountIsMalformed(void)
{
  g_spec.ma_header[2] = 6;
  BUILD_ACCEPTED();
  g_spec.ma_header[2] = 7;
  BUILD_REFUSED(X402_SOLANA_MALFORMED);
}

void test_duplicateKeyIsMalformed(void)
{
  memcpy(g_spec.ma_keys[KEY_EXTRA], g_spec.ma_keys[KEY_FEE_PAYER], 32);
  BUILD_REFUSED(X402_SOLANA_MALFORMED);
  static_resetValid();
  memcpy(g_spec.ma_keys[KEY_EXTRA], g_spec.ma_keys[KEY_COMPUTE_BUDGET], 32);
  BUILD_REFUSED(X402_SOLANA_MALFORMED);
}

void test_programIndexAtKeyCountIsMalformed(void)
{
  static_addMemo(1)->m_programIndex = 8;
  BUILD_REFUSED(X402_SOLANA_MALFORMED);
}

void test_accountIndexAtKeyCountIsMalformed(void)
{
  TestInstruction_t* memo = static_addMemo(1);
  memo->m_accountCount   = 2;
  memo->ma_accounts[0]   = KEY_EXTRA;
  memo->ma_accounts[1]   = KEY_EXTRA;
  BUILD_ACCEPTED();
  memo->ma_accounts[1]   = 8;
  BUILD_REFUSED(X402_SOLANA_MALFORMED);
}

void test_signatureCountPastTheBytesIsMalformed(void)
{
  static_build();
  g_tx[0] = 20;
  EXPECT_REFUSED(X402_SOLANA_MALFORMED);
}

void test_compactU16Of127And128IsRead(void)
{
  static_addMemo(127);
  BUILD_ACCEPTED();
  g_spec.m_instructionCount = 3;
  static_addMemo(128);
  BUILD_ACCEPTED();
}

void test_compactU16Of16383And16384WithoutTheBytesIsMalformed(void)
{
  TestInstruction_t* memo = static_addMemo(4);
  memo->ma_dataLenRaw[0] = 0xff;
  memo->ma_dataLenRaw[1] = 0x7f;
  memo->m_dataLenRawLen  = 2;
  BUILD_REFUSED(X402_SOLANA_MALFORMED);
  memo->ma_dataLenRaw[0] = 0x80;
  memo->ma_dataLenRaw[1] = 0x80;
  memo->ma_dataLenRaw[2] = 0x01;
  memo->m_dataLenRawLen  = 3;
  BUILD_REFUSED(X402_SOLANA_MALFORMED);
}

void test_overlongCompactU16IsMalformed(void)
{
  g_spec.ma_signatureCountRaw[0] = 0x82;
  g_spec.ma_signatureCountRaw[1] = 0x00;
  g_spec.m_signatureCountRawLen  = 2;
  BUILD_REFUSED(X402_SOLANA_MALFORMED);

  static_resetValid();
  TestInstruction_t* memo = static_addMemo(127);
  memo->ma_dataLenRaw[0] = 0xff;
  memo->ma_dataLenRaw[1] = 0x00;
  memo->m_dataLenRawLen  = 2;
  BUILD_REFUSED(X402_SOLANA_MALFORMED);

  static_resetValid();
  memo = static_addMemo(1);
  memo->ma_dataLenRaw[0] = 0x81;
  memo->ma_dataLenRaw[1] = 0x80;
  memo->ma_dataLenRaw[2] = 0x00;
  memo->m_dataLenRawLen  = 3;
  BUILD_REFUSED(X402_SOLANA_MALFORMED);

  static_resetValid();
  g_spec.m_isV0        = true;
  g_spec.m_versionByte = 0x80;
  g_spec.ma_tableCountRaw[0] = 0x80;
  g_spec.ma_tableCountRaw[1] = 0x00;
  g_spec.m_tableCountRawLen  = 2;
  BUILD_REFUSED(X402_SOLANA_MALFORMED);
  g_spec.ma_tableCountRaw[1] = 0x80;
  g_spec.ma_tableCountRaw[2] = 0x00;
  g_spec.m_tableCountRawLen  = 3;
  BUILD_REFUSED(X402_SOLANA_MALFORMED);
}

void test_compactU16ThirdByteAboveTwoBitsIsMalformed(void)
{
  g_spec.m_isV0        = true;
  g_spec.m_versionByte = 0x80;
  g_spec.ma_tableCountRaw[0] = 0x80;
  g_spec.ma_tableCountRaw[1] = 0x80;
  g_spec.ma_tableCountRaw[2] = 0x04;
  g_spec.m_tableCountRawLen  = 3;
  BUILD_REFUSED(X402_SOLANA_MALFORMED);
  g_spec.ma_tableCountRaw[2] = 0x84;
  BUILD_REFUSED(X402_SOLANA_MALFORMED);
  g_spec.ma_tableCountRaw[2] = 0x02;
  BUILD_REFUSED(X402_SOLANA_MALFORMED);
}

void test_compactU16ContinuationReadsThirdByte(void)
{
  TestInstruction_t* memo = static_addMemo(0);
  memo->ma_dataLenRaw[0] = 0x80;
  memo->ma_dataLenRaw[1] = 0x80;
  memo->m_dataLenRawLen  = 2;
  TEST_ASSERT_EQUAL_INT(KEY_EXTRA, static_addMemo(0)->m_programIndex);
  BUILD_REFUSED(X402_SOLANA_MALFORMED);
}

void test_signatureCountOneIsRefused(void)
{
  g_spec.m_signatureCount = 1;
  BUILD_REFUSED(X402_SOLANA_SIGNERS_REFUSED);
  g_spec.m_instructionCount = 2;
  BUILD_REFUSED(X402_SOLANA_SIGNERS_REFUSED);
}

void test_signatureCountThreeIsRefused(void)
{
  g_spec.m_signatureCount = 3;
  BUILD_REFUSED(X402_SOLANA_SIGNERS_REFUSED);
}

void test_requiredSignaturesOtherThanTwoIsRefused(void)
{
  g_spec.ma_header[0]     = 3;
  g_spec.m_signatureCount = 3;
  BUILD_REFUSED(X402_SOLANA_SIGNERS_REFUSED);
  g_spec.ma_header[0]     = 1;
  g_spec.ma_header[1]     = 0;
  g_spec.m_signatureCount = 1;
  BUILD_REFUSED(X402_SOLANA_SIGNERS_REFUSED);
}

void test_feePayerKeyMismatchIsRefused(void)
{
  g_policy.ma_feePayer[31] ^= 0x01;
  BUILD_REFUSED(X402_SOLANA_SIGNERS_REFUSED);
  g_policy.ma_feePayer[31] ^= 0x01;
  g_policy.ma_feePayer[0]  ^= 0x80;
  BUILD_REFUSED(X402_SOLANA_SIGNERS_REFUSED);
}

void test_instructionCountBoundaries(void)
{
  g_spec.m_instructionCount = 2;
  BUILD_REFUSED(X402_SOLANA_INSTRUCTION_REFUSED);
  g_spec.m_instructionCount = 3;
  BUILD_ACCEPTED();
  for (int i = 0; i < 4; i++)
    static_addMemo((size_t)i);
  TEST_ASSERT_EQUAL_INT(7, g_spec.m_instructionCount);
  BUILD_ACCEPTED();
  static_addMemo(4);
  BUILD_REFUSED(X402_SOLANA_INSTRUCTION_REFUSED);
}

void test_otherProgramAfterTransferIsRefused(void)
{
  static_addMemo(1)->m_programIndex = KEY_TOKEN;
  BUILD_REFUSED(X402_SOLANA_INSTRUCTION_REFUSED);
  static_resetValid();
  static_addMemo(1);
  static_addMemo(1);
  static_addMemo(1);
  static_addMemo(1)->m_programIndex = KEY_COMPUTE_BUDGET;
  BUILD_REFUSED(X402_SOLANA_INSTRUCTION_REFUSED);
}

void test_ataProgramIsRefusedAnywhere(void)
{
  static_decode(ATA_TEXT, g_spec.ma_keys[KEY_EXTRA]);
  g_spec.ma_instructions[2].m_programIndex = KEY_EXTRA;
  BUILD_REFUSED(X402_SOLANA_INSTRUCTION_REFUSED);
  g_spec.ma_instructions[2].m_programIndex = KEY_TOKEN;
  g_spec.ma_instructions[0].m_programIndex = KEY_EXTRA;
  BUILD_REFUSED(X402_SOLANA_INSTRUCTION_REFUSED);
  g_spec.ma_instructions[0].m_programIndex = KEY_COMPUTE_BUDGET;
  g_spec.ma_instructions[1].m_programIndex = KEY_EXTRA;
  BUILD_REFUSED(X402_SOLANA_INSTRUCTION_REFUSED);
}

void test_computeLimitBoundaries(void)
{
  static_setLimitInstruction(&g_spec.ma_instructions[0], 199999);
  BUILD_ACCEPTED();
  static_setLimitInstruction(&g_spec.ma_instructions[0], 200000);
  BUILD_ACCEPTED();
  static_setLimitInstruction(&g_spec.ma_instructions[0], 200001);
  BUILD_REFUSED(X402_SOLANA_COMPUTE_REFUSED);
  g_spec.ma_instructions[2].ma_data[1] ^= 0x01;
  BUILD_REFUSED(X402_SOLANA_COMPUTE_REFUSED);
}

void test_computeLimitHighByteIsRead(void)
{
  static_setLimitInstruction(&g_spec.ma_instructions[0], 0x01000000u + 5u);
  BUILD_REFUSED(X402_SOLANA_COMPUTE_REFUSED);
}

void test_computePriceBoundaries(void)
{
  static_setPriceInstruction(&g_spec.ma_instructions[1], 49999);
  BUILD_ACCEPTED();
  static_setPriceInstruction(&g_spec.ma_instructions[1], 50000);
  BUILD_ACCEPTED();
  static_setPriceInstruction(&g_spec.ma_instructions[1], 50001);
  BUILD_REFUSED(X402_SOLANA_COMPUTE_REFUSED);
}

void test_computePriceHighBytesAreRead(void)
{
  static_setPriceInstruction(&g_spec.ma_instructions[1], ((uint64_t)1 << 32) + 5u);
  BUILD_REFUSED(X402_SOLANA_COMPUTE_REFUSED);
  static_setPriceInstruction(&g_spec.ma_instructions[1], ((uint64_t)1 << 56) + 5u);
  BUILD_REFUSED(X402_SOLANA_COMPUTE_REFUSED);
}

void test_computeLimitInstructionShapeIsRefused(void)
{
  g_spec.ma_instructions[0].m_programIndex = KEY_EXTRA;
  BUILD_REFUSED(X402_SOLANA_COMPUTE_REFUSED);
  static_resetValid();
  g_spec.ma_instructions[0].m_dataLen = 4;
  BUILD_REFUSED(X402_SOLANA_COMPUTE_REFUSED);
  g_spec.ma_instructions[0].m_dataLen = 6;
  BUILD_REFUSED(X402_SOLANA_COMPUTE_REFUSED);
  static_resetValid();
  g_spec.ma_instructions[0].ma_data[0] = 3;
  BUILD_REFUSED(X402_SOLANA_COMPUTE_REFUSED);

  static_resetValid();
  uint8_t swap[sizeof(g_spec.ma_keys[0])];
  memcpy(swap, g_spec.ma_keys[KEY_SOURCE], sizeof(swap));
  memcpy(g_spec.ma_keys[KEY_SOURCE], g_spec.ma_keys[KEY_COMPUTE_BUDGET], sizeof(swap));
  memcpy(g_spec.ma_keys[KEY_COMPUTE_BUDGET], swap, sizeof(swap));
  g_spec.ma_instructions[0].m_programIndex = KEY_SOURCE;
  g_spec.ma_instructions[1].m_programIndex = KEY_SOURCE;
  g_spec.ma_instructions[2].ma_accounts[0] = KEY_COMPUTE_BUDGET;
  BUILD_ACCEPTED();
  g_spec.ma_instructions[0].m_dataLen  = 3;
  g_spec.ma_instructions[0].ma_data[1] = 0xe8;
  g_spec.ma_instructions[0].ma_data[2] = 0x03;
  BUILD_REFUSED(X402_SOLANA_COMPUTE_REFUSED);
}

void test_computePriceInstructionShapeIsRefused(void)
{
  g_spec.ma_instructions[1].m_programIndex = KEY_EXTRA;
  BUILD_REFUSED(X402_SOLANA_COMPUTE_REFUSED);
  static_resetValid();
  g_spec.ma_instructions[1].m_dataLen = 8;
  BUILD_REFUSED(X402_SOLANA_COMPUTE_REFUSED);
  g_spec.ma_instructions[1].m_dataLen = 10;
  BUILD_REFUSED(X402_SOLANA_COMPUTE_REFUSED);
  static_resetValid();
  g_spec.ma_instructions[1].ma_data[0] = 2;
  BUILD_REFUSED(X402_SOLANA_COMPUTE_REFUSED);
}

void test_transferProgramOtherThanTokenIsRefused(void)
{
  g_spec.ma_instructions[2].m_programIndex = KEY_COMPUTE_BUDGET;
  BUILD_REFUSED(X402_SOLANA_TRANSFER_REFUSED);
  static_resetValid();
  static_decode(TOKEN_2022_TEXT, g_spec.ma_keys[KEY_EXTRA]);
  g_spec.ma_instructions[2].m_programIndex = KEY_EXTRA;
  BUILD_REFUSED(X402_SOLANA_TRANSFER_REFUSED);
}

void test_transferDataLengthIsRefused(void)
{
  g_spec.ma_instructions[2].m_dataLen = 9;
  BUILD_REFUSED(X402_SOLANA_TRANSFER_REFUSED);
  g_spec.ma_instructions[2].m_dataLen = 11;
  BUILD_REFUSED(X402_SOLANA_TRANSFER_REFUSED);
}

void test_transferTagOtherThanTransferCheckedIsRefused(void)
{
  g_spec.ma_instructions[2].ma_data[0] = 3;
  BUILD_REFUSED(X402_SOLANA_TRANSFER_REFUSED);
}

void test_transferAccountCountIsRefused(void)
{
  g_spec.ma_instructions[2].m_accountCount = 3;
  BUILD_REFUSED(X402_SOLANA_TRANSFER_REFUSED);
  g_spec.ma_instructions[2].m_accountCount = 5;
  g_spec.ma_instructions[2].ma_accounts[4] = KEY_EXTRA;
  BUILD_REFUSED(X402_SOLANA_TRANSFER_REFUSED);
}

void test_transferMintMismatchIsRefused(void)
{
  g_policy.ma_mint[31] ^= 0x01;
  BUILD_REFUSED(X402_SOLANA_TRANSFER_REFUSED);
  static_resetValid();
  g_spec.ma_keys[KEY_MINT][0] ^= 0x01;
  BUILD_REFUSED(X402_SOLANA_TRANSFER_REFUSED);
}

void test_transferDestinationMismatchIsRefused(void)
{
  g_policy.ma_destination[31] ^= 0x01;
  BUILD_REFUSED(X402_SOLANA_TRANSFER_REFUSED);
}

void test_transferAccountsInAnotherOrderAreRefused(void)
{
  g_spec.ma_instructions[2].ma_accounts[1] = KEY_DESTINATION;
  g_spec.ma_instructions[2].ma_accounts[2] = KEY_MINT;
  BUILD_REFUSED(X402_SOLANA_TRANSFER_REFUSED);
}

void test_transferAmountMismatchIsRefused(void)
{
  g_spec.ma_instructions[2].ma_data[1] += 1;
  BUILD_REFUSED(X402_SOLANA_TRANSFER_REFUSED);
  static_resetValid();
  g_spec.ma_instructions[2].ma_data[1] -= 1;
  BUILD_REFUSED(X402_SOLANA_TRANSFER_REFUSED);
  static_resetValid();
  static_setTransferInstruction(&g_spec.ma_instructions[2], VALID_AMOUNT + ((uint64_t)1 << 56));
  BUILD_REFUSED(X402_SOLANA_TRANSFER_REFUSED);
}

void test_transferDecimalsOtherThanSixAreRefused(void)
{
  g_spec.ma_instructions[2].ma_data[9] = 5;
  BUILD_REFUSED(X402_SOLANA_TRANSFER_REFUSED);
  g_spec.ma_instructions[2].ma_data[9] = 7;
  BUILD_REFUSED(X402_SOLANA_TRANSFER_REFUSED);
}

void test_transferAuthorityOtherThanSignerOneIsRefused(void)
{
  g_spec.ma_instructions[2].ma_accounts[3] = KEY_EXTRA;
  BUILD_REFUSED(X402_SOLANA_TRANSFER_REFUSED);
  g_spec.ma_instructions[2].ma_accounts[3] = KEY_FEE_PAYER;
  BUILD_REFUSED(X402_SOLANA_TRANSFER_REFUSED);
}

void test_transferSourceEqualToDestinationIsRefused(void)
{
  g_spec.ma_instructions[2].ma_accounts[0] = KEY_DESTINATION;
  BUILD_REFUSED(X402_SOLANA_TRANSFER_REFUSED);
}

void test_feePayerAsTransferSourceIsRefused(void)
{
  g_spec.ma_instructions[2].ma_accounts[0] = KEY_FEE_PAYER;
  BUILD_REFUSED(X402_SOLANA_FEE_PAYER_IN_USE);
  static_build();
  g_tx[1 + 64] ^= 0x01;
  EXPECT_REFUSED(X402_SOLANA_FEE_PAYER_IN_USE);
}

void test_feePayerInAnyAccountListIsRefused(void)
{
  g_spec.ma_instructions[0].m_accountCount   = 1;
  g_spec.ma_instructions[0].ma_accounts[0]   = KEY_FEE_PAYER;
  BUILD_REFUSED(X402_SOLANA_FEE_PAYER_IN_USE);
  static_resetValid();
  TestInstruction_t* memo = static_addMemo(1);
  memo->m_accountCount   = 2;
  memo->ma_accounts[0]   = KEY_EXTRA;
  memo->ma_accounts[1]   = KEY_FEE_PAYER;
  BUILD_REFUSED(X402_SOLANA_FEE_PAYER_IN_USE);
}

void test_feePayerAsProgramIsRefused(void)
{
  static_decode(MEMO_TEXT, g_spec.ma_keys[KEY_FEE_PAYER]);
  static_decode(LIGHTHOUSE_TEXT, g_spec.ma_keys[KEY_EXTRA]);
  memcpy(g_policy.ma_feePayer, MEMO_BYTES, 32);
  static_addMemo(1);
  BUILD_ACCEPTED();
  g_spec.ma_instructions[3].m_programIndex = KEY_FEE_PAYER;
  BUILD_REFUSED(X402_SOLANA_FEE_PAYER_IN_USE);
}

void test_flippedSignatureByteIsInvalid(void)
{
  static_build();
  g_tx[1 + 64] ^= 0x01;
  EXPECT_REFUSED(X402_SOLANA_SIGNATURE_INVALID);
  g_tx[1 + 64] ^= 0x01;
  g_tx[1 + 127] ^= 0x80;
  EXPECT_REFUSED(X402_SOLANA_SIGNATURE_INVALID);
}

void test_messageChangedAfterSigningIsInvalid(void)
{
  static_addMemo(5);
  static_build();
  g_tx[g_txLen - 1] ^= 0x01;
  EXPECT_REFUSED(X402_SOLANA_SIGNATURE_INVALID);
  g_tx[g_txLen - 1] ^= 0x01;
  g_tx[g_messageOffset + 3 + 1 + 8 * 32] ^= 0x01;
  EXPECT_REFUSED(X402_SOLANA_SIGNATURE_INVALID);
}

void test_signatureByAnotherKeyIsInvalid(void)
{
  g_spec.mp_signingKey = g_otherKey;
  BUILD_REFUSED(X402_SOLANA_SIGNATURE_INVALID);
}

void test_v0SignatureWithoutVersionPrefixIsInvalid(void)
{
  g_spec.m_isV0        = true;
  g_spec.m_versionByte = 0x80;
  static_build();
  static_sign(g_authorityKey, g_tx + g_messageOffset + 1, g_txLen - g_messageOffset - 1, g_tx + 1 + 64);
  EXPECT_REFUSED(X402_SOLANA_SIGNATURE_INVALID);
}

void test_signatureInFeePayerSlotOnlyIsInvalid(void)
{
  static_build();
  memcpy(g_tx + 1, g_tx + 1 + 64, 64);
  memset(g_tx + 1 + 64, 0xab, 64);
  EXPECT_REFUSED(X402_SOLANA_SIGNATURE_INVALID);
}

static void static_expectDecoded(const char* text, const uint8_t expected[32])
{
  uint8_t out[32];
  TEST_ASSERT_TRUE_MESSAGE(x402_solana_tryDecodeAddress(text, out), text);
  TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(expected, out, 32, text);
}

static void static_expectNotDecoded(const char* text)
{
  uint8_t out[32];
  uint8_t sentinel[32];
  memset(out, CHECK_SENTINEL, sizeof(out));
  memset(sentinel, CHECK_SENTINEL, sizeof(sentinel));
  TEST_ASSERT_FALSE_MESSAGE(x402_solana_tryDecodeAddress(text, out), text);
  TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(sentinel, out, 32, text);
}

void test_decodeAddressProgramIds(void)
{
  static_expectDecoded(COMPUTE_BUDGET_TEXT, COMPUTE_BUDGET_BYTES);
  static_expectDecoded(TOKEN_TEXT, TOKEN_BYTES);
  static_expectDecoded(TOKEN_2022_TEXT, TOKEN_2022_BYTES);
  static_expectDecoded(MEMO_TEXT, MEMO_BYTES);
  static_expectDecoded(LIGHTHOUSE_TEXT, LIGHTHOUSE_BYTES);
  static_expectDecoded(ATA_TEXT, ATA_BYTES);
  static_expectDecoded(USDC_TEXT, USDC_BYTES);
}

void test_decodeAddressLeadingOnes(void)
{
  uint8_t expected[32] = { 0 };
  static_expectDecoded("11111111111111111111111111111111", expected);

  for (int i = 1; i < 32; i++)
    expected[i] = (uint8_t)i;
  static_expectDecoded("1thX6LZfHDZZKUs92febYZhYRcXddmzfzF2NvTkPNE", expected);

  expected[1] = 0;
  for (int i = 2; i < 32; i++)
    expected[i] = 0xfe;
  static_expectDecoded("11t6ULwBhBoicdvo8BhKh6bpe8ESmbZAt3wBBejuikV", expected);

  memset(expected, 0xff, sizeof(expected));
  static_expectDecoded("JEKNVnkbo3jma5nREBBJCDoXFVeKkD56V3xKrvRmWxFG", expected);
}

void test_decodeAddressOfOtherLengthIsRefused(void)
{
  static_expectNotDecoded("");
  static_expectNotDecoded("1111111111111111111111111111111");
  static_expectNotDecoded("111111111111111111111111111111111");
  static_expectNotDecoded("4uQeVj5tqViQh7yWWGStvkEG1Zmhx6uasJtWCJziofL");
  static_expectNotDecoded("JJEfe6DcPM2ziB2vfUWDV6aHVerXRGkv3TcyvJUNGHZz");
  static_expectNotDecoded("1" "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz");
  static_expectNotDecoded("11" "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz");
}

void test_decodeAddressCharOutsideAlphabetIsRefused(void)
{
  const char bad_chars[] = { '0', 'O', 'I', 'l', '+', '/', ' ', (char)0xc3 };
  for (size_t i = 0; i < sizeof(bad_chars); i++)
  {
    char text[] = TOKEN_TEXT;
    text[10] = bad_chars[i];
    static_expectNotDecoded(text);
    text[10] = TOKEN_TEXT[10];
    text[0]  = bad_chars[i];
    static_expectNotDecoded(text);
  }
}

void test_decodeAddressOf45CharsIsRefused(void)
{
  static_expectNotDecoded("1" "JEKNVnkbo3jma5nREBBJCDoXFVeKkD56V3xKrvRmWxFG");
  static_expectNotDecoded("111111111111111111111111111111111111111111111");
}

#define SIG_TEXT_FF_64    "67rpwLCuS5DGA8KGZXKsVQ7dnPb9goRLoKfgGbLfQg9WoLUgNY77E2jT11fem3coV9nAkguBACzrU1iyZM4B8roQ"
#define SIG_TEXT_00_FF_63 "12AFv15MNPuA84RmU66xw2uMzGipcVxNpzAffoacGVvjFue3CBmf633fAWuiP9cwL9C3z3CJiGgRSFjJfeEcA6QW"
#define SIG_TEXT_01_ZEROS "2AFv15MNPuA84RmU66xw2uMzGipcVxNpzAffoacGVvjFue3CBmf633fAWuiP9cwL9C3z3CJiGgRSFjJfeEcA6QX"

#define SIG_TEXT_FF_65    "PbGvaomYRfb7uHHdgYrHrM2HMLhjLftSPTPiKpZnXVnaXWyAn4HxUWeMm3wbfQZ2BFkN3q7HqdxMLECGdmX1jgorv"
#define SIG_TEXT_00_FF_64 "167rpwLCuS5DGA8KGZXKsVQ7dnPb9goRLoKfgGbLfQg9WoLUgNY77E2jT11fem3coV9nAkguBACzrU1iyZM4B8roQ"

#define ONES_16 "1111111111111111"
#define ONES_63 ONES_16 ONES_16 ONES_16 "111111111111111"
#define Z_16    "zzzzzzzzzzzzzzzz"

static void static_expectSignatureDecoded(const char* text, const uint8_t expected[64])
{
  uint8_t out[64];
  TEST_ASSERT_TRUE_MESSAGE(x402_solana_tryDecodeSignature(text, out), text);
  TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(expected, out, 64, text);
}

static void static_expectSignatureNotDecoded(const char* text)
{
  uint8_t out[64];
  uint8_t sentinel[64];
  memset(out, CHECK_SENTINEL, sizeof(out));
  memset(sentinel, CHECK_SENTINEL, sizeof(sentinel));
  TEST_ASSERT_FALSE_MESSAGE(x402_solana_tryDecodeSignature(text, out), text);
  TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(sentinel, out, 64, text);
}

void test_decodeSignatureOf88And87Chars(void)
{
  TEST_ASSERT_EQUAL_size_t(88, strlen(SIG_TEXT_FF_64));
  TEST_ASSERT_EQUAL_size_t(88, strlen(SIG_TEXT_00_FF_63));
  TEST_ASSERT_EQUAL_size_t(87, strlen(SIG_TEXT_01_ZEROS));
  TEST_ASSERT_EQUAL_INT(89, X402_SOLANA_SIGNATURE_TEXT_BUF_SIZE);

  uint8_t expected[64];
  memset(expected, 0xff, sizeof(expected));
  static_expectSignatureDecoded(SIG_TEXT_FF_64, expected);

  expected[0] = 0x00;
  static_expectSignatureDecoded(SIG_TEXT_00_FF_63, expected);

  memset(expected, 0, sizeof(expected));
  expected[0] = 0x01;
  static_expectSignatureDecoded(SIG_TEXT_01_ZEROS, expected);
}

void test_decodeSignatureLeadingOnes(void)
{
  uint8_t expected[64] = { 0 };
  static_expectSignatureDecoded(ONES_63 "1", expected);
  expected[63] = 0x01;
  static_expectSignatureDecoded(ONES_63 "2", expected);
}

void test_decodeSignatureOf89CharsIsRefused(void)
{
  TEST_ASSERT_EQUAL_size_t(89, strlen(SIG_TEXT_FF_65));
  TEST_ASSERT_EQUAL_size_t(89, strlen(SIG_TEXT_00_FF_64));
  static_expectSignatureNotDecoded(SIG_TEXT_FF_65);
  static_expectSignatureNotDecoded(SIG_TEXT_00_FF_64);
  static_expectSignatureNotDecoded("1" SIG_TEXT_01_ZEROS "1");
}

void test_decodeSignatureOfOtherByteCountIsRefused(void)
{
  static_expectSignatureNotDecoded("");
  static_expectSignatureNotDecoded(ONES_63);
  static_expectSignatureNotDecoded(ONES_63 "11");
  static_expectSignatureNotDecoded(ONES_63 "12");
  static_expectSignatureNotDecoded(TOKEN_TEXT);
  static_expectSignatureNotDecoded(Z_16 Z_16 Z_16 Z_16 Z_16 "zzzzzzzz");
  static_expectSignatureNotDecoded("1" Z_16 Z_16 Z_16 Z_16 Z_16 "zzzzzzz");
}

void test_decodeSignatureCharOutsideAlphabetIsRefused(void)
{
  const char bad_chars[] = { '0', 'O', 'I', 'l', '+', '/', ' ', (char)0xc3 };
  for (size_t i = 0; i < sizeof(bad_chars); i++)
  {
    char text[] = SIG_TEXT_FF_64;
    text[40] = bad_chars[i];
    static_expectSignatureNotDecoded(text);
    text[40] = SIG_TEXT_FF_64[40];
    text[87] = bad_chars[i];
    static_expectSignatureNotDecoded(text);
  }
}

static void static_buildAndSignAsFeePayer(EVP_PKEY* key, uint8_t signature_out[64])
{
  memcpy(g_spec.ma_keys[KEY_FEE_PAYER], g_feePayerPublicKey, 32);
  static_build();
  static_sign(key, g_tx + g_messageOffset, g_txLen - g_messageOffset, signature_out);
}

void test_feePayerSignatureVerifies(void)
{
  uint8_t signature[64];
  static_buildAndSignAsFeePayer(g_feePayerKey, signature);
  TEST_ASSERT_TRUE(x402_solana_isFeePayerSignatureValid(g_tx, g_txLen, g_feePayerPublicKey, signature));

  g_spec.m_isV0        = true;
  g_spec.m_versionByte = 0x80;
  static_buildAndSignAsFeePayer(g_feePayerKey, signature);
  TEST_ASSERT_TRUE(x402_solana_isFeePayerSignatureValid(g_tx, g_txLen, g_feePayerPublicKey, signature));
}

void test_feePayerSignatureByAnotherKeyIsRefused(void)
{
  uint8_t signature[64];
  static_buildAndSignAsFeePayer(g_authorityKey, signature);
  TEST_ASSERT_FALSE(x402_solana_isFeePayerSignatureValid(g_tx, g_txLen, g_feePayerPublicKey, signature));
  static_buildAndSignAsFeePayer(g_otherKey, signature);
  TEST_ASSERT_FALSE(x402_solana_isFeePayerSignatureValid(g_tx, g_txLen, g_feePayerPublicKey, signature));
}

void test_feePayerSignatureOfAnotherKeyZeroIsRefused(void)
{
  uint8_t other_public_key[32];
  size_t  other_public_key_len = sizeof(other_public_key);
  TEST_ASSERT_EQUAL_INT(1, EVP_PKEY_get_raw_public_key(g_otherKey, other_public_key, &other_public_key_len));
  TEST_ASSERT_EQUAL_size_t(32, other_public_key_len);

  uint8_t signature[64];
  memcpy(g_spec.ma_keys[KEY_FEE_PAYER], other_public_key, 32);
  static_build();
  static_sign(g_otherKey, g_tx + g_messageOffset, g_txLen - g_messageOffset, signature);
  TEST_ASSERT_FALSE(x402_solana_isFeePayerSignatureValid(g_tx, g_txLen, g_feePayerPublicKey, signature));
  TEST_ASSERT_TRUE(x402_solana_isFeePayerSignatureValid(g_tx, g_txLen, other_public_key, signature));
}

void test_feePayerSignatureWithOneFlippedBitIsRefused(void)
{
  uint8_t signature[64];
  static_buildAndSignAsFeePayer(g_feePayerKey, signature);
  for (int i = 0; i < 64; i += 21)
  {
    signature[i] ^= 0x01;
    TEST_ASSERT_FALSE(x402_solana_isFeePayerSignatureValid(g_tx, g_txLen, g_feePayerPublicKey, signature));
    signature[i] ^= 0x01;
  }
  signature[63] ^= 0x80;
  TEST_ASSERT_FALSE(x402_solana_isFeePayerSignatureValid(g_tx, g_txLen, g_feePayerPublicKey, signature));
  signature[63] ^= 0x80;

  g_tx[g_txLen - 1] ^= 0x01;
  TEST_ASSERT_FALSE(x402_solana_isFeePayerSignatureValid(g_tx, g_txLen, g_feePayerPublicKey, signature));
  g_tx[g_txLen - 1] ^= 0x01;
  TEST_ASSERT_TRUE(x402_solana_isFeePayerSignatureValid(g_tx, g_txLen, g_feePayerPublicKey, signature));
}

void test_feePayerSignatureOfUnparsedTransactionIsRefused(void)
{
  uint8_t signature[64];
  static_buildAndSignAsFeePayer(g_feePayerKey, signature);
  TEST_ASSERT_FALSE(x402_solana_isFeePayerSignatureValid(g_tx, g_txLen - 1, g_feePayerPublicKey, signature));
  TEST_ASSERT_FALSE(x402_solana_isFeePayerSignatureValid(g_tx, 0, g_feePayerPublicKey, signature));

  g_spec.m_trailingByteCount = 1;
  static_buildAndSignAsFeePayer(g_feePayerKey, signature);
  TEST_ASSERT_FALSE(x402_solana_isFeePayerSignatureValid(g_tx, g_txLen, g_feePayerPublicKey, signature));
}

void test_feePayerSignatureOf1232BytesVerifiesAnd1233IsRefused(void)
{
  uint8_t signature[64];
  memcpy(g_spec.ma_keys[KEY_FEE_PAYER], g_feePayerPublicKey, 32);
  static_padTo(1232);
  static_sign(g_feePayerKey, g_tx + g_messageOffset, g_txLen - g_messageOffset, signature);
  TEST_ASSERT_TRUE(x402_solana_isFeePayerSignatureValid(g_tx, g_txLen, g_feePayerPublicKey, signature));

  static_resetValid();
  memcpy(g_spec.ma_keys[KEY_FEE_PAYER], g_feePayerPublicKey, 32);
  static_padTo(1233);
  static_sign(g_feePayerKey, g_tx + g_messageOffset, g_txLen - g_messageOffset, signature);
  TEST_ASSERT_FALSE(x402_solana_isFeePayerSignatureValid(g_tx, g_txLen, g_feePayerPublicKey, signature));
}

static EVP_PKEY* static_newKey(void)
{
  EVP_PKEY*     key = NULL;
  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
  if (ctx != NULL && EVP_PKEY_keygen_init(ctx) == 1)
    (void)EVP_PKEY_keygen(ctx, &key);
  EVP_PKEY_CTX_free(ctx);
  return key;
}

void test_registrationGateTestCount(void)
{
  TEST_ASSERT_EQUAL_INT_MESSAGE(71, (int)Unity.NumberOfTests, "RUN_TEST list and test definitions have drifted apart - a test may be unregistered");
}

int main(void)
{
  g_authorityKey = static_newKey();
  g_otherKey     = static_newKey();
  g_feePayerKey  = static_newKey();
  size_t public_key_len           = sizeof(g_authorityPublicKey);
  size_t fee_payer_public_key_len = sizeof(g_feePayerPublicKey);
  if (g_authorityKey == NULL || g_otherKey == NULL || g_feePayerKey == NULL
      || EVP_PKEY_get_raw_public_key(g_authorityKey, g_authorityPublicKey, &public_key_len) != 1 || public_key_len != 32
      || EVP_PKEY_get_raw_public_key(g_feePayerKey, g_feePayerPublicKey, &fee_payer_public_key_len) != 1 || fee_payer_public_key_len != 32)
    return 1;

  UNITY_BEGIN();
  RUN_TEST(test_validLegacyTransactionIsAccepted);
  RUN_TEST(test_validV0TransactionIsAccepted);
  RUN_TEST(test_memoAndLighthouseInstructionsAreAccepted);
  RUN_TEST(test_feePayerSignatureSlotIsNotChecked);
  RUN_TEST(test_emptyTransactionIsMalformed);
  RUN_TEST(test_everyTruncatedPrefixIsMalformed);
  RUN_TEST(test_trailingByteIsMalformed);
  RUN_TEST(test_transactionOf1232BytesIsAccepted);
  RUN_TEST(test_transactionOf1233BytesIsMalformed);
  RUN_TEST(test_versionOtherThanV0IsMalformed);
  RUN_TEST(test_v0AddressTableLookupIsMalformed);
  RUN_TEST(test_readonlySignedAtRequiredIsMalformed);
  RUN_TEST(test_readonlyUnsignedPastKeyCountIsMalformed);
  RUN_TEST(test_duplicateKeyIsMalformed);
  RUN_TEST(test_programIndexAtKeyCountIsMalformed);
  RUN_TEST(test_accountIndexAtKeyCountIsMalformed);
  RUN_TEST(test_signatureCountPastTheBytesIsMalformed);
  RUN_TEST(test_compactU16Of127And128IsRead);
  RUN_TEST(test_compactU16Of16383And16384WithoutTheBytesIsMalformed);
  RUN_TEST(test_overlongCompactU16IsMalformed);
  RUN_TEST(test_compactU16ThirdByteAboveTwoBitsIsMalformed);
  RUN_TEST(test_compactU16ContinuationReadsThirdByte);
  RUN_TEST(test_signatureCountOneIsRefused);
  RUN_TEST(test_signatureCountThreeIsRefused);
  RUN_TEST(test_requiredSignaturesOtherThanTwoIsRefused);
  RUN_TEST(test_feePayerKeyMismatchIsRefused);
  RUN_TEST(test_instructionCountBoundaries);
  RUN_TEST(test_otherProgramAfterTransferIsRefused);
  RUN_TEST(test_ataProgramIsRefusedAnywhere);
  RUN_TEST(test_computeLimitBoundaries);
  RUN_TEST(test_computeLimitHighByteIsRead);
  RUN_TEST(test_computePriceBoundaries);
  RUN_TEST(test_computePriceHighBytesAreRead);
  RUN_TEST(test_computeLimitInstructionShapeIsRefused);
  RUN_TEST(test_computePriceInstructionShapeIsRefused);
  RUN_TEST(test_transferProgramOtherThanTokenIsRefused);
  RUN_TEST(test_transferDataLengthIsRefused);
  RUN_TEST(test_transferTagOtherThanTransferCheckedIsRefused);
  RUN_TEST(test_transferAccountCountIsRefused);
  RUN_TEST(test_transferMintMismatchIsRefused);
  RUN_TEST(test_transferDestinationMismatchIsRefused);
  RUN_TEST(test_transferAccountsInAnotherOrderAreRefused);
  RUN_TEST(test_transferAmountMismatchIsRefused);
  RUN_TEST(test_transferDecimalsOtherThanSixAreRefused);
  RUN_TEST(test_transferAuthorityOtherThanSignerOneIsRefused);
  RUN_TEST(test_transferSourceEqualToDestinationIsRefused);
  RUN_TEST(test_feePayerAsTransferSourceIsRefused);
  RUN_TEST(test_feePayerInAnyAccountListIsRefused);
  RUN_TEST(test_feePayerAsProgramIsRefused);
  RUN_TEST(test_flippedSignatureByteIsInvalid);
  RUN_TEST(test_messageChangedAfterSigningIsInvalid);
  RUN_TEST(test_signatureByAnotherKeyIsInvalid);
  RUN_TEST(test_v0SignatureWithoutVersionPrefixIsInvalid);
  RUN_TEST(test_signatureInFeePayerSlotOnlyIsInvalid);
  RUN_TEST(test_decodeAddressProgramIds);
  RUN_TEST(test_decodeAddressLeadingOnes);
  RUN_TEST(test_decodeAddressOfOtherLengthIsRefused);
  RUN_TEST(test_decodeAddressCharOutsideAlphabetIsRefused);
  RUN_TEST(test_decodeAddressOf45CharsIsRefused);
  RUN_TEST(test_decodeSignatureOf88And87Chars);
  RUN_TEST(test_decodeSignatureLeadingOnes);
  RUN_TEST(test_decodeSignatureOf89CharsIsRefused);
  RUN_TEST(test_decodeSignatureOfOtherByteCountIsRefused);
  RUN_TEST(test_decodeSignatureCharOutsideAlphabetIsRefused);
  RUN_TEST(test_feePayerSignatureVerifies);
  RUN_TEST(test_feePayerSignatureByAnotherKeyIsRefused);
  RUN_TEST(test_feePayerSignatureOfAnotherKeyZeroIsRefused);
  RUN_TEST(test_feePayerSignatureWithOneFlippedBitIsRefused);
  RUN_TEST(test_feePayerSignatureOfUnparsedTransactionIsRefused);
  RUN_TEST(test_feePayerSignatureOf1232BytesVerifiesAnd1233IsRefused);
  RUN_TEST(test_registrationGateTestCount);
  int failures = UNITY_END();

  EVP_PKEY_free(g_authorityKey);
  EVP_PKEY_free(g_otherKey);
  EVP_PKEY_free(g_feePayerKey);
  return failures;
}
