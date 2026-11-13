#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <openssl/evp.h>

#include "x402_solana.h"

#define X402_SOLANA_VERSION_PREFIX_BIT          0x80

#define X402_SOLANA_VERSION_0_PREFIX            0x80

#define X402_SOLANA_REQUIRED_SIGNATURE_COUNT    2

#define X402_SOLANA_FEE_PAYER_KEY_INDEX         0
#define X402_SOLANA_AUTHORITY_KEY_INDEX         1

#define X402_SOLANA_MIN_INSTRUCTION_COUNT       3

#define X402_SOLANA_LIMIT_INSTRUCTION_INDEX     0
#define X402_SOLANA_PRICE_INSTRUCTION_INDEX     1
#define X402_SOLANA_TRANSFER_INSTRUCTION_INDEX  2

#define X402_SOLANA_TAG_BYTE_COUNT              1
#define X402_SOLANA_U32_BYTE_COUNT              4
#define X402_SOLANA_U64_BYTE_COUNT              8

#define X402_SOLANA_SET_LIMIT_TAG               2
#define X402_SOLANA_SET_LIMIT_DATA_BYTE_COUNT   5
#define X402_SOLANA_SET_PRICE_TAG               3
#define X402_SOLANA_SET_PRICE_DATA_BYTE_COUNT   9

#define X402_SOLANA_TRANSFER_CHECKED_TAG        12
#define X402_SOLANA_TRANSFER_DATA_BYTE_COUNT    10
#define X402_SOLANA_TRANSFER_DECIMALS_OFFSET    9
#define X402_SOLANA_TRANSFER_ACCOUNT_COUNT      4
#define X402_SOLANA_TRANSFER_SOURCE_INDEX       0
#define X402_SOLANA_TRANSFER_MINT_INDEX         1
#define X402_SOLANA_TRANSFER_DESTINATION_INDEX  2
#define X402_SOLANA_TRANSFER_AUTHORITY_INDEX    3

#define X402_SOLANA_BASE58_MAX_TEXT_LEN         44

#define X402_SOLANA_SIGNATURE_BASE58_MAX_TEXT_LEN  (X402_SOLANA_SIGNATURE_TEXT_BUF_SIZE - 1)

static const uint8_t COMPUTE_BUDGET_PROGRAM_ID[X402_SOLANA_ADDRESS_BYTE_COUNT] = {
  0x03, 0x06, 0x46, 0x6f, 0xe5, 0x21, 0x17, 0x32, 0xff, 0xec, 0xad, 0xba, 0x72, 0xc3, 0x9b, 0xe7,
  0xbc, 0x8c, 0xe5, 0xbb, 0xc5, 0xf7, 0x12, 0x6b, 0x2c, 0x43, 0x9b, 0x3a, 0x40, 0x00, 0x00, 0x00
};

static const uint8_t TOKEN_PROGRAM_ID[X402_SOLANA_ADDRESS_BYTE_COUNT] = {
  0x06, 0xdd, 0xf6, 0xe1, 0xd7, 0x65, 0xa1, 0x93, 0xd9, 0xcb, 0xe1, 0x46, 0xce, 0xeb, 0x79, 0xac,
  0x1c, 0xb4, 0x85, 0xed, 0x5f, 0x5b, 0x37, 0x91, 0x3a, 0x8c, 0xf5, 0x85, 0x7e, 0xff, 0x00, 0xa9
};

static const uint8_t MEMO_PROGRAM_ID[X402_SOLANA_ADDRESS_BYTE_COUNT] = {
  0x05, 0x4a, 0x53, 0x5a, 0x99, 0x29, 0x21, 0x06, 0x4d, 0x24, 0xe8, 0x71, 0x60, 0xda, 0x38, 0x7c,
  0x7c, 0x35, 0xb5, 0xdd, 0xbc, 0x92, 0xbb, 0x81, 0xe4, 0x1f, 0xa8, 0x40, 0x41, 0x05, 0x44, 0x8d
};

static const uint8_t LIGHTHOUSE_PROGRAM_ID[X402_SOLANA_ADDRESS_BYTE_COUNT] = {
  0x04, 0xdf, 0xad, 0x79, 0x62, 0xff, 0xb1, 0xdd, 0x92, 0x5d, 0x0a, 0x9f, 0xb5, 0xe6, 0xd0, 0x0c,
  0xe6, 0x19, 0x5b, 0xa8, 0xbb, 0x3a, 0x91, 0xfd, 0x07, 0xef, 0x98, 0x60, 0xc5, 0xe9, 0x7b, 0xb8
};

static const uint8_t ATA_PROGRAM_ID[X402_SOLANA_ADDRESS_BYTE_COUNT] = {
  0x8c, 0x97, 0x25, 0x8f, 0x4e, 0x24, 0x89, 0xf1, 0xbb, 0x3d, 0x10, 0x29, 0x14, 0x8e, 0x0d, 0x83,
  0x0b, 0x5a, 0x13, 0x99, 0xda, 0xff, 0x10, 0x84, 0x04, 0x8e, 0x7b, 0xd8, 0xdb, 0xe9, 0xf8, 0x59
};

static const char BASE58_ALPHABET[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

typedef struct {
  const uint8_t*  mp_bytes;
  size_t          m_len;
  size_t          m_offset;
} X402SolanaReader_t;

typedef struct {
  uint8_t         m_programIndex;
  int             m_accountCount;
  const uint8_t*  mp_accounts;
  size_t          m_dataLen;
  const uint8_t*  mp_data;
} X402SolanaInstruction_t;

typedef struct {
  int                       m_signatureCount;
  const uint8_t*            mp_signatures;
  const uint8_t*            mp_message;
  size_t                    m_messageLen;
  int                       m_requiredSignatureCount;
  int                       m_keyCount;
  const uint8_t*            mp_keys;
  int                       m_instructionCount;
  X402SolanaInstruction_t   ma_instructions[X402_SOLANA_MAX_INSTRUCTION_COUNT];
} X402SolanaTransaction_t;

static bool               static_tryParseTransaction  (const uint8_t* tx, size_t tx_len, X402SolanaTransaction_t* parsed_out);
static bool               static_tryReadInstruction   (X402SolanaReader_t* reader, int key_count, X402SolanaInstruction_t* instruction_out);
static bool               static_tryReadByte          (X402SolanaReader_t* reader, uint8_t* value_out);
static bool               static_tryReadCompactU16    (X402SolanaReader_t* reader, uint16_t* value_out);
static bool               static_tryReadSpan          (X402SolanaReader_t* reader, size_t byte_count, const uint8_t** span_out);
static bool               static_hasDuplicateKey      (const uint8_t* keys, int key_count);
static const uint8_t*     static_accountKey           (const X402SolanaTransaction_t* parsed, int key_index);
static bool               static_isProgram            (const X402SolanaTransaction_t* parsed, int instruction_index, const uint8_t* program_id);
static X402SolanaStatus_t static_checkInstructionList (const X402SolanaTransaction_t* parsed);
static X402SolanaStatus_t static_checkComputeBudget   (const X402SolanaTransaction_t* parsed);
static X402SolanaStatus_t static_checkTransfer        (const X402SolanaTransaction_t* parsed, const X402SolanaPolicy_t* policy);
static bool               static_isFeePayerInUse      (const X402SolanaTransaction_t* parsed);
static bool               static_isSignatureValid     (const X402SolanaTransaction_t* parsed);
static bool               static_isEd25519Valid       (const uint8_t* public_key, const uint8_t* signature, const uint8_t* message, size_t message_len);
static bool               static_tryDecodeBase58      (const char* text, size_t max_text_len, uint8_t* out, size_t byte_count);
static uint64_t           static_readLittleEndian     (const uint8_t* bytes, int byte_count);
static int                static_base58DigitValue     (char digit);

X402SolanaStatus_t x402_solana_checkTransaction(const uint8_t* tx, size_t tx_len, const X402SolanaPolicy_t* policy, X402SolanaCheck_t* check_out)
{
  assert(tx != NULL || tx_len == 0);
  assert(policy != NULL);
  assert(check_out != NULL);

  if (tx_len == 0 || tx_len > X402_SOLANA_MAX_TRANSACTION_BYTE_COUNT)
    return X402_SOLANA_MALFORMED;

  X402SolanaTransaction_t parsed;
  if (!static_tryParseTransaction(tx, tx_len, &parsed))
    return X402_SOLANA_MALFORMED;

  if (parsed.m_signatureCount != parsed.m_requiredSignatureCount
      || parsed.m_requiredSignatureCount != X402_SOLANA_REQUIRED_SIGNATURE_COUNT
      || memcmp(static_accountKey(&parsed, X402_SOLANA_FEE_PAYER_KEY_INDEX), policy->ma_feePayer, X402_SOLANA_ADDRESS_BYTE_COUNT) != 0)
    return X402_SOLANA_SIGNERS_REFUSED;

  X402SolanaStatus_t status = static_checkInstructionList(&parsed);
  if (status != X402_SOLANA_OK)
    return status;
  status = static_checkComputeBudget(&parsed);
  if (status != X402_SOLANA_OK)
    return status;
  status = static_checkTransfer(&parsed, policy);
  if (status != X402_SOLANA_OK)
    return status;
  if (static_isFeePayerInUse(&parsed))
    return X402_SOLANA_FEE_PAYER_IN_USE;
  if (!static_isSignatureValid(&parsed))
    return X402_SOLANA_SIGNATURE_INVALID;

  uint8_t      message_hash[X402_SOLANA_MESSAGE_HASH_BYTE_COUNT];
  unsigned int message_hash_len = 0;
  if (EVP_Digest(parsed.mp_message, parsed.m_messageLen, message_hash, &message_hash_len, EVP_sha256(), NULL) != 1
      || message_hash_len != X402_SOLANA_MESSAGE_HASH_BYTE_COUNT)
  {
    return X402_SOLANA_SIGNATURE_INVALID;
  }

  const X402SolanaInstruction_t* transfer = &parsed.ma_instructions[X402_SOLANA_TRANSFER_INSTRUCTION_INDEX];
  memcpy(check_out->ma_messageHash, message_hash, X402_SOLANA_MESSAGE_HASH_BYTE_COUNT);
  memcpy(check_out->ma_source, static_accountKey(&parsed, transfer->mp_accounts[X402_SOLANA_TRANSFER_SOURCE_INDEX]), X402_SOLANA_ADDRESS_BYTE_COUNT);
  return X402_SOLANA_OK;
}

bool x402_solana_tryDecodeAddress(const char* text, uint8_t out[X402_SOLANA_ADDRESS_BYTE_COUNT])
{
  assert(text != NULL);
  assert(out != NULL);

  return static_tryDecodeBase58(text, X402_SOLANA_BASE58_MAX_TEXT_LEN, out, X402_SOLANA_ADDRESS_BYTE_COUNT);
}

bool x402_solana_tryDecodeSignature(const char* text, uint8_t out[X402_SOLANA_SIGNATURE_BYTE_COUNT])
{
  assert(text != NULL);
  assert(out != NULL);

  return static_tryDecodeBase58(text, X402_SOLANA_SIGNATURE_BASE58_MAX_TEXT_LEN, out, X402_SOLANA_SIGNATURE_BYTE_COUNT);
}

bool x402_solana_isFeePayerSignatureValid(const uint8_t* tx, size_t tx_len, const uint8_t fee_payer[X402_SOLANA_ADDRESS_BYTE_COUNT], const uint8_t signature[X402_SOLANA_SIGNATURE_BYTE_COUNT])
{
  assert(tx != NULL || tx_len == 0);
  assert(fee_payer != NULL);
  assert(signature != NULL);

  if (tx_len == 0 || tx_len > X402_SOLANA_MAX_TRANSACTION_BYTE_COUNT)
    return false;
  X402SolanaTransaction_t parsed;
  if (!static_tryParseTransaction(tx, tx_len, &parsed))
    return false;
  const uint8_t* key_zero = static_accountKey(&parsed, X402_SOLANA_FEE_PAYER_KEY_INDEX);
  if (memcmp(key_zero, fee_payer, X402_SOLANA_ADDRESS_BYTE_COUNT) != 0)
    return false;
  return static_isEd25519Valid(key_zero, signature, parsed.mp_message, parsed.m_messageLen);
}

static bool static_tryParseTransaction(const uint8_t* tx, size_t tx_len, X402SolanaTransaction_t* parsed_out)
{
  assert(tx != NULL);
  assert(parsed_out != NULL);

  X402SolanaReader_t reader = { .mp_bytes = tx, .m_len = tx_len, .m_offset = 0 };

  uint16_t signature_count = 0;
  if (!static_tryReadCompactU16(&reader, &signature_count)
      || !static_tryReadSpan(&reader, (size_t)signature_count * X402_SOLANA_SIGNATURE_BYTE_COUNT, &parsed_out->mp_signatures))
  {
    return false;
  }
  parsed_out->m_signatureCount = signature_count;
  parsed_out->mp_message       = tx + reader.m_offset;

  uint8_t first_byte = 0;
  if (!static_tryReadByte(&reader, &first_byte))
    return false;
  bool is_v0 = (first_byte & X402_SOLANA_VERSION_PREFIX_BIT) != 0;
  if (is_v0 && first_byte != X402_SOLANA_VERSION_0_PREFIX)
    return false;

  uint8_t required_count          = first_byte;
  uint8_t readonly_signed_count   = 0;
  uint8_t readonly_unsigned_count = 0;
  if (is_v0 && !static_tryReadByte(&reader, &required_count))
    return false;
  if (!static_tryReadByte(&reader, &readonly_signed_count) || !static_tryReadByte(&reader, &readonly_unsigned_count))
    return false;

  uint16_t key_count = 0;
  if (!static_tryReadCompactU16(&reader, &key_count)
      || !static_tryReadSpan(&reader, (size_t)key_count * X402_SOLANA_ADDRESS_BYTE_COUNT, &parsed_out->mp_keys))
  {
    return false;
  }
  if (readonly_signed_count >= required_count || required_count + readonly_unsigned_count > key_count)
    return false;
  if (static_hasDuplicateKey(parsed_out->mp_keys, key_count))
    return false;
  parsed_out->m_requiredSignatureCount = required_count;
  parsed_out->m_keyCount               = key_count;

  const uint8_t* blockhash = NULL;
  uint16_t instruction_count = 0;
  if (!static_tryReadSpan(&reader, X402_SOLANA_ADDRESS_BYTE_COUNT, &blockhash)
      || !static_tryReadCompactU16(&reader, &instruction_count))
  {
    return false;
  }
  parsed_out->m_instructionCount = instruction_count;

  for (int i = 0; i < instruction_count; i++)
  {
    X402SolanaInstruction_t instruction;
    if (!static_tryReadInstruction(&reader, key_count, &instruction))
      return false;
    if (i < X402_SOLANA_MAX_INSTRUCTION_COUNT)
      parsed_out->ma_instructions[i] = instruction;
  }

  if (is_v0)
  {
    uint16_t table_count = 0;
    if (!static_tryReadCompactU16(&reader, &table_count) || table_count != 0)
      return false;
  }

  parsed_out->m_messageLen = tx_len - (size_t)(parsed_out->mp_message - tx);
  return reader.m_offset == tx_len;
}

static bool static_tryReadInstruction(X402SolanaReader_t* reader, int key_count, X402SolanaInstruction_t* instruction_out)
{
  assert(reader != NULL);
  assert(instruction_out != NULL);

  uint16_t account_count = 0;
  uint16_t data_len      = 0;
  if (!static_tryReadByte(reader, &instruction_out->m_programIndex) || instruction_out->m_programIndex >= key_count)
    return false;
  if (!static_tryReadCompactU16(reader, &account_count) || !static_tryReadSpan(reader, account_count, &instruction_out->mp_accounts))
    return false;
  for (int i = 0; i < account_count; i++)
    if (instruction_out->mp_accounts[i] >= key_count)
      return false;
  if (!static_tryReadCompactU16(reader, &data_len) || !static_tryReadSpan(reader, data_len, &instruction_out->mp_data))
    return false;

  instruction_out->m_accountCount = account_count;
  instruction_out->m_dataLen      = data_len;
  return true;
}

static bool static_tryReadByte(X402SolanaReader_t* reader, uint8_t* value_out)
{
  assert(reader != NULL);
  assert(value_out != NULL);

  if (reader->m_offset >= reader->m_len)
    return false;
  *value_out = reader->mp_bytes[reader->m_offset++];
  return true;
}

static bool static_tryReadCompactU16(X402SolanaReader_t* reader, uint16_t* value_out)
{
  assert(reader != NULL);
  assert(value_out != NULL);

  uint8_t first = 0;
  if (!static_tryReadByte(reader, &first))
    return false;
  uint32_t value = first & 0x7f;
  if ((first & 0x80) != 0)
  {
    uint8_t second = 0;
    if (!static_tryReadByte(reader, &second))
      return false;
    value |= (uint32_t)(second & 0x7f) << 7;
    if ((second & 0x80) != 0)
    {
      uint8_t third = 0;
      if (!static_tryReadByte(reader, &third) || third == 0 || third > 0x03)
        return false;
      value |= (uint32_t)third << 14;
    }
    else if (second == 0)
      return false;
  }
  *value_out = (uint16_t)value;
  return true;
}

static bool static_tryReadSpan(X402SolanaReader_t* reader, size_t byte_count, const uint8_t** span_out)
{
  assert(reader != NULL);
  assert(span_out != NULL);

  if (byte_count > reader->m_len - reader->m_offset)
    return false;
  *span_out         = reader->mp_bytes + reader->m_offset;
  reader->m_offset += byte_count;
  return true;
}

static bool static_hasDuplicateKey(const uint8_t* keys, int key_count)
{
  assert(keys != NULL || key_count == 0);

  for (int i = 0; i < key_count; i++)
    for (int j = i + 1; j < key_count; j++)
      if (memcmp(keys + (size_t)i * X402_SOLANA_ADDRESS_BYTE_COUNT, keys + (size_t)j * X402_SOLANA_ADDRESS_BYTE_COUNT, X402_SOLANA_ADDRESS_BYTE_COUNT) == 0)
        return true;
  return false;
}

static const uint8_t* static_accountKey(const X402SolanaTransaction_t* parsed, int key_index)
{
  assert(parsed != NULL);
  assert(key_index >= 0 && key_index < parsed->m_keyCount);

  return parsed->mp_keys + (size_t)key_index * X402_SOLANA_ADDRESS_BYTE_COUNT;
}

static bool static_isProgram(const X402SolanaTransaction_t* parsed, int instruction_index, const uint8_t* program_id)
{
  assert(parsed != NULL);
  assert(instruction_index >= 0 && instruction_index < parsed->m_instructionCount && instruction_index < X402_SOLANA_MAX_INSTRUCTION_COUNT);

  const uint8_t* key = static_accountKey(parsed, parsed->ma_instructions[instruction_index].m_programIndex);
  return memcmp(key, program_id, X402_SOLANA_ADDRESS_BYTE_COUNT) == 0;
}

static X402SolanaStatus_t static_checkInstructionList(const X402SolanaTransaction_t* parsed)
{
  assert(parsed != NULL);

  if (parsed->m_instructionCount < X402_SOLANA_MIN_INSTRUCTION_COUNT || parsed->m_instructionCount > X402_SOLANA_MAX_INSTRUCTION_COUNT)
    return X402_SOLANA_INSTRUCTION_REFUSED;
  for (int i = 0; i < parsed->m_instructionCount; i++)
    if (static_isProgram(parsed, i, ATA_PROGRAM_ID))
      return X402_SOLANA_INSTRUCTION_REFUSED;
  for (int i = X402_SOLANA_MIN_INSTRUCTION_COUNT; i < parsed->m_instructionCount; i++)
    if (!static_isProgram(parsed, i, MEMO_PROGRAM_ID) && !static_isProgram(parsed, i, LIGHTHOUSE_PROGRAM_ID))
      return X402_SOLANA_INSTRUCTION_REFUSED;

  return X402_SOLANA_OK;
}

static X402SolanaStatus_t static_checkComputeBudget(const X402SolanaTransaction_t* parsed)
{
  assert(parsed != NULL);

  const X402SolanaInstruction_t* limit = &parsed->ma_instructions[X402_SOLANA_LIMIT_INSTRUCTION_INDEX];
  if (!static_isProgram(parsed, X402_SOLANA_LIMIT_INSTRUCTION_INDEX, COMPUTE_BUDGET_PROGRAM_ID)
      || limit->m_dataLen != X402_SOLANA_SET_LIMIT_DATA_BYTE_COUNT
      || limit->mp_data[0] != X402_SOLANA_SET_LIMIT_TAG
      || static_readLittleEndian(limit->mp_data + X402_SOLANA_TAG_BYTE_COUNT, X402_SOLANA_U32_BYTE_COUNT) > X402_SOLANA_MAX_COMPUTE_UNIT_LIMIT)
    return X402_SOLANA_COMPUTE_REFUSED;

  const X402SolanaInstruction_t* price = &parsed->ma_instructions[X402_SOLANA_PRICE_INSTRUCTION_INDEX];
  if (!static_isProgram(parsed, X402_SOLANA_PRICE_INSTRUCTION_INDEX, COMPUTE_BUDGET_PROGRAM_ID)
      || price->m_dataLen != X402_SOLANA_SET_PRICE_DATA_BYTE_COUNT
      || price->mp_data[0] != X402_SOLANA_SET_PRICE_TAG
      || static_readLittleEndian(price->mp_data + X402_SOLANA_TAG_BYTE_COUNT, X402_SOLANA_U64_BYTE_COUNT) > X402_SOLANA_MAX_COMPUTE_UNIT_PRICE)
    return X402_SOLANA_COMPUTE_REFUSED;

  return X402_SOLANA_OK;
}

static X402SolanaStatus_t static_checkTransfer(const X402SolanaTransaction_t* parsed, const X402SolanaPolicy_t* policy)
{
  assert(parsed != NULL);
  assert(policy != NULL);

  const X402SolanaInstruction_t* transfer = &parsed->ma_instructions[X402_SOLANA_TRANSFER_INSTRUCTION_INDEX];
  if (!static_isProgram(parsed, X402_SOLANA_TRANSFER_INSTRUCTION_INDEX, TOKEN_PROGRAM_ID)
      || transfer->m_dataLen != X402_SOLANA_TRANSFER_DATA_BYTE_COUNT
      || transfer->mp_data[0] != X402_SOLANA_TRANSFER_CHECKED_TAG
      || transfer->m_accountCount != X402_SOLANA_TRANSFER_ACCOUNT_COUNT)
    return X402_SOLANA_TRANSFER_REFUSED;

  const uint8_t* accounts = transfer->mp_accounts;
  if (memcmp(static_accountKey(parsed, accounts[X402_SOLANA_TRANSFER_MINT_INDEX]), policy->ma_mint, X402_SOLANA_ADDRESS_BYTE_COUNT) != 0
      || memcmp(static_accountKey(parsed, accounts[X402_SOLANA_TRANSFER_DESTINATION_INDEX]), policy->ma_destination, X402_SOLANA_ADDRESS_BYTE_COUNT) != 0
      || static_readLittleEndian(transfer->mp_data + X402_SOLANA_TAG_BYTE_COUNT, X402_SOLANA_U64_BYTE_COUNT) != policy->m_amount
      || transfer->mp_data[X402_SOLANA_TRANSFER_DECIMALS_OFFSET] != X402_SOLANA_USDC_DECIMALS
      || accounts[X402_SOLANA_TRANSFER_AUTHORITY_INDEX] != X402_SOLANA_AUTHORITY_KEY_INDEX
      || accounts[X402_SOLANA_TRANSFER_SOURCE_INDEX] == accounts[X402_SOLANA_TRANSFER_DESTINATION_INDEX])
    return X402_SOLANA_TRANSFER_REFUSED;
    
  return X402_SOLANA_OK;
}

static bool static_isFeePayerInUse(const X402SolanaTransaction_t* parsed)
{
  assert(parsed != NULL);
  assert(parsed->m_instructionCount <= X402_SOLANA_MAX_INSTRUCTION_COUNT);

  for (int i = 0; i < parsed->m_instructionCount; i++)
  {
    const X402SolanaInstruction_t* instruction = &parsed->ma_instructions[i];
    if (instruction->m_programIndex == X402_SOLANA_FEE_PAYER_KEY_INDEX)
      return true;
    for (int j = 0; j < instruction->m_accountCount; j++)
      if (instruction->mp_accounts[j] == X402_SOLANA_FEE_PAYER_KEY_INDEX)
        return true;
  }
  return false;
}

static bool static_isSignatureValid(const X402SolanaTransaction_t* parsed)
{
  assert(parsed != NULL);
  assert(parsed->m_signatureCount == X402_SOLANA_REQUIRED_SIGNATURE_COUNT);

  const uint8_t* signature = parsed->mp_signatures + (size_t)X402_SOLANA_AUTHORITY_KEY_INDEX * X402_SOLANA_SIGNATURE_BYTE_COUNT;
  return static_isEd25519Valid(static_accountKey(parsed, X402_SOLANA_AUTHORITY_KEY_INDEX), signature, parsed->mp_message, parsed->m_messageLen);
}

static bool static_isEd25519Valid(const uint8_t* public_key, const uint8_t* signature, const uint8_t* message, size_t message_len)
{
  assert(public_key != NULL);
  assert(signature != NULL);
  assert(message != NULL);

  EVP_PKEY* key = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, public_key, X402_SOLANA_ADDRESS_BYTE_COUNT);
  if (key == NULL)
    return false;
  EVP_MD_CTX* verify_ctx = EVP_MD_CTX_new();
  bool is_valid = verify_ctx != NULL
               && EVP_DigestVerifyInit(verify_ctx, NULL, NULL, NULL, key) == 1
               && EVP_DigestVerify(verify_ctx, signature, X402_SOLANA_SIGNATURE_BYTE_COUNT, message, message_len) == 1;
  EVP_MD_CTX_free(verify_ctx);
  EVP_PKEY_free(key);
  return is_valid;
}

static bool static_tryDecodeBase58(const char* text, size_t max_text_len, uint8_t* out, size_t byte_count)
{
  assert(text != NULL);
  assert(out != NULL);
  assert(byte_count > 0 && byte_count <= X402_SOLANA_SIGNATURE_BYTE_COUNT);

  size_t text_len = strnlen(text, max_text_len + 1);
  if (text_len == 0 || text_len > max_text_len)
    return false;

  size_t leading_one_count = 0;
  while (leading_one_count < text_len && text[leading_one_count] == '1')
    leading_one_count++;

  uint8_t number[X402_SOLANA_SIGNATURE_BYTE_COUNT] = { 0 };
  for (size_t i = 0; i < text_len; i++)
  {
    int digit = static_base58DigitValue(text[i]);
    if (digit < 0)
      return false;
    uint32_t carry = (uint32_t)digit;
    for (size_t j = byte_count; j-- > 0;)
    {
      carry    += (uint32_t)number[j] * 58;
      number[j] = (uint8_t)carry;
      carry   >>= 8;
    }
    if (carry != 0)
      return false;
  }

  size_t leading_zero_count = 0;
  while (leading_zero_count < byte_count && number[leading_zero_count] == 0)
    leading_zero_count++;
  if (leading_zero_count != leading_one_count)
    return false;

  memcpy(out, number, byte_count);
  return true;
}

static uint64_t static_readLittleEndian(const uint8_t* bytes, int byte_count)
{
  assert(bytes != NULL);
  assert(byte_count >= 1 && byte_count <= X402_SOLANA_U64_BYTE_COUNT);

  uint64_t value = 0;
  for (int i = byte_count - 1; i >= 0; i--)
    value = (value << 8) | bytes[i];
  return value;
}

static int static_base58DigitValue(char digit)
{
  for (int i = 0; i < (int)sizeof(BASE58_ALPHABET) - 1; i++)
    if (BASE58_ALPHABET[i] == digit)
      return i;
  return -1;
}
