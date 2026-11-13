#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>
#include <assert.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>


#include "auth.h"
#include "bytes.h"
#include "picohttpparser.h"
#include "validate.h"

#define API_KEY_PREFIX            "contrastapi_"
#define API_KEY_PREFIX_LEN        12
#define API_KEY_BODY_LEN          48
#define API_KEY_CHECKSUM_LEN      8
#define AUTH_API_KEY_RANDOM_BYTE_COUNT 24

#define AUTH_UUID_RANDOM_BYTE_COUNT 16
_Static_assert(2 * AUTH_UUID_RANDOM_BYTE_COUNT + 4 == VALIDATE_UUID_LEN, "a UUID is its bytes in hex plus four hyphens");
#define AUTH_CRC32_POLYNOMIAL     0xEDB88320u
#define AUTH_CRC32_INITIAL        0xFFFFFFFFu
#define AUTH_BEARER_PREFIX        "Bearer "
#define AUTH_BEARER_PREFIX_LEN    (sizeof(AUTH_BEARER_PREFIX) - 1)
#define AUTH_IPV6_PREFIX_BYTES    8
#define AUTH_IPV6_BUCKET_SUFFIX   "/64"
#define AUTH_IP_BUCKET_BUF_SIZE   (INET6_ADDRSTRLEN + sizeof(AUTH_IPV6_BUCKET_SUFFIX) - 1)

_Static_assert(API_KEY_PREFIX_LEN + API_KEY_BODY_LEN + API_KEY_CHECKSUM_LEN == API_KEY_TOTAL_LEN, "key length mismatch");
_Static_assert(sizeof(API_KEY_PREFIX) - 1 == API_KEY_PREFIX_LEN, "key prefix length mismatch");
_Static_assert(API_KEY_CHECKSUM_LEN == 2 * sizeof(uint32_t), "a checksum is one uint32_t in hex");
_Static_assert(SHA256_HEX_LEN == SHA256_DIGEST_LENGTH * 2, "hex hash length mismatch");
_Static_assert(2 * AUTH_API_KEY_RANDOM_BYTE_COUNT == API_KEY_BODY_LEN, "a key body is its random bytes in hex");

static const struct phr_header* static_findHeader                     (const struct phr_header* headers, size_t header_count, const char* header_name);
static AuthApiKeyStatus_t       static_classifyApiKeyFormat           (const char* raw_key, size_t raw_key_len);
static void                     static_classifyApiKeyAndWriteToResult (const char* raw_key, size_t raw_key_len, AuthApiKeyParseResult_t* result_out);
static bool                     static_isLowercaseHex                 (unsigned char ch);
static uint32_t                 static_computeCrc32                   (const char* bytes, size_t byte_count);
static const char*              static_normalizeIp                    (const char* ip, char* bucket_out, size_t bucket_out_size);


AuthApiKeyParseResult_t auth_parseApiKey(const struct phr_header* headers, size_t header_count)
{
  assert(headers != NULL || header_count == 0);

  AuthApiKeyParseResult_t no_usable_key_result = { AUTH_API_KEY_NONE, { 0 } };

  AuthApiKeyParseResult_t bearer_key_result = { AUTH_API_KEY_NONE, { 0 } };
  const struct phr_header* header = static_findHeader(headers, header_count, "authorization");
  if (header && bytes_hasPrefix(header->value, header->value_len, AUTH_BEARER_PREFIX, AUTH_BEARER_PREFIX_LEN, true))
  {
    static_classifyApiKeyAndWriteToResult(header->value + AUTH_BEARER_PREFIX_LEN,
                                          header->value_len - AUTH_BEARER_PREFIX_LEN, &bearer_key_result);
    if (bearer_key_result.m_apiKeyStatus == AUTH_API_KEY_VALID_FORMAT)
      return bearer_key_result;
  }

  AuthApiKeyParseResult_t x_api_key_result = { AUTH_API_KEY_NONE, { 0 } };
  header = static_findHeader(headers, header_count, "x-api-key");
  if (header)
  {
    static_classifyApiKeyAndWriteToResult(header->value, header->value_len, &x_api_key_result);
    if (x_api_key_result.m_apiKeyStatus == AUTH_API_KEY_VALID_FORMAT)
      return x_api_key_result;
  }

  if (bearer_key_result.m_apiKeyStatus == AUTH_API_KEY_MALFORMED || x_api_key_result.m_apiKeyStatus == AUTH_API_KEY_MALFORMED)
    no_usable_key_result.m_apiKeyStatus = AUTH_API_KEY_MALFORMED;
  return no_usable_key_result;
}

void auth_hashApiKey(const char* api_key, char* hex_out_buf)
{
  assert(api_key != NULL);
  assert(hex_out_buf != NULL);

  unsigned char sha256_digest[SHA256_DIGEST_LENGTH];
  unsigned int  digest_len = SHA256_DIGEST_LENGTH;
  EVP_Digest(api_key, strlen(api_key), sha256_digest, &digest_len, EVP_sha256(), NULL);
  bytes_writeHex(sha256_digest, SHA256_DIGEST_LENGTH, hex_out_buf);
}

void auth_hashIp(const char* ip, const char* secret, char* hex_out_buf)
{
  assert(ip != NULL);
  assert(hex_out_buf != NULL);

  char        bucket_buf[AUTH_IP_BUCKET_BUF_SIZE];
  const char* bucket = static_normalizeIp(ip, bucket_buf, sizeof(bucket_buf));

  if (!secret)
  {
    auth_hashApiKey(bucket, hex_out_buf);
    return;
  }
  unsigned char digest[SHA256_DIGEST_LENGTH];
  unsigned int  digest_len = SHA256_DIGEST_LENGTH;
  HMAC(EVP_sha256(), secret, (int)strlen(secret), (const unsigned char*)bucket, strlen(bucket), digest, &digest_len);
  bytes_writeHex(digest, SHA256_DIGEST_LENGTH, hex_out_buf);
}


bool auth_tryGenerateUuid(char* out, size_t out_size)
{
  assert(out != NULL);
  assert(out_size > 0);

  if (out_size < VALIDATE_UUID_LEN + 1)
  {
    out[0] = '\0';
    return false;
  }

  unsigned char random_bytes[AUTH_UUID_RANDOM_BYTE_COUNT];
  if (RAND_bytes(random_bytes, AUTH_UUID_RANDOM_BYTE_COUNT) != 1)
  {
    explicit_bzero(random_bytes, sizeof(random_bytes));
    out[0] = '\0';
    return false;
  }
  random_bytes[6] = (unsigned char)((random_bytes[6] & 0x0F) | 0x40);
  random_bytes[8] = (unsigned char)((random_bytes[8] & 0x3F) | 0x80);

  static const size_t group_byte_counts[] = { 4, 2, 2, 2, 6 };
  size_t group_count = sizeof(group_byte_counts) / sizeof(group_byte_counts[0]);
  size_t byte_offset = 0;
  size_t text_offset = 0;
  for (size_t group = 0; group < group_count; group++)
  {
    bytes_writeHex(random_bytes + byte_offset, group_byte_counts[group], out + text_offset);
    byte_offset += group_byte_counts[group];
    text_offset += 2 * group_byte_counts[group];
    if (group + 1 < group_count)
      out[text_offset++] = '-';
  }
  out[text_offset] = '\0';
  explicit_bzero(random_bytes, sizeof(random_bytes));
  return true;
}

bool auth_tryGenerateApiKey(char* key_out)
{
  assert(key_out != NULL);

  unsigned char random_bytes[AUTH_API_KEY_RANDOM_BYTE_COUNT];
  if (RAND_bytes(random_bytes, AUTH_API_KEY_RANDOM_BYTE_COUNT) != 1)
  {
    explicit_bzero(random_bytes, sizeof(random_bytes));
    key_out[0] = '\0';
    return false;
  }

  memcpy(key_out, API_KEY_PREFIX, API_KEY_PREFIX_LEN);
  char* body = key_out + API_KEY_PREFIX_LEN;
  bytes_writeHex(random_bytes, AUTH_API_KEY_RANDOM_BYTE_COUNT, body);
  explicit_bzero(random_bytes, sizeof(random_bytes));
  snprintf(body + API_KEY_BODY_LEN, API_KEY_CHECKSUM_LEN + 1, "%08" PRIx32, static_computeCrc32(body, API_KEY_BODY_LEN));
  return true;
}


static const struct phr_header* static_findHeader(const struct phr_header* headers, size_t header_count, const char* header_name)
{
  assert(headers != NULL);
  assert(header_name != NULL);
  assert(header_name[0] != '\0');

  for (size_t i = 0; i < header_count; i++)
  {
    if (headers[i].name == NULL)
      continue;
    if (bytes_isEqual(headers[i].name, headers[i].name_len, header_name, true))
      return &headers[i];
  }
  return NULL;
}

static bool static_isLowercaseHex(unsigned char ch)
{
  return ((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f'));
}

static uint32_t static_computeCrc32(const char* bytes, size_t byte_count)
{
  assert(bytes != NULL);

  uint32_t crc = AUTH_CRC32_INITIAL;
  for (size_t i = 0; i < byte_count; i++)
  {
    crc ^= (unsigned char)bytes[i];
    for (int bit = 0; bit < 8; bit++)
      crc = (crc >> 1) ^ (AUTH_CRC32_POLYNOMIAL & (0u - (crc & 1u)));
  }
  return ~crc;
}

static AuthApiKeyStatus_t static_classifyApiKeyFormat(const char* raw_key, size_t raw_key_len)
{
  assert(raw_key != NULL);

  if (!bytes_hasPrefix(raw_key, raw_key_len, API_KEY_PREFIX, API_KEY_PREFIX_LEN, false))
    return AUTH_API_KEY_NONE;

  if (raw_key_len != API_KEY_TOTAL_LEN)
    return AUTH_API_KEY_MALFORMED;

  const char* body = raw_key + API_KEY_PREFIX_LEN;
  for (size_t i = 0; i < API_KEY_BODY_LEN; i++)
    if (!static_isLowercaseHex((unsigned char)body[i]))
      return AUTH_API_KEY_MALFORMED;

  char checksum[API_KEY_CHECKSUM_LEN + 1];
  snprintf(checksum, sizeof(checksum), "%08" PRIx32, static_computeCrc32(body, API_KEY_BODY_LEN));
  if (memcmp(body + API_KEY_BODY_LEN, checksum, API_KEY_CHECKSUM_LEN) != 0)
    return AUTH_API_KEY_MALFORMED;

  return AUTH_API_KEY_VALID_FORMAT;
}

static void static_classifyApiKeyAndWriteToResult(const char* raw_key, size_t raw_key_len, AuthApiKeyParseResult_t* result_out)
{
  assert(raw_key != NULL);
  assert(result_out != NULL);

  result_out->m_apiKeyStatus = static_classifyApiKeyFormat(raw_key, raw_key_len);
  if (result_out->m_apiKeyStatus == AUTH_API_KEY_VALID_FORMAT)
  {
    memcpy(result_out->ma_apiKey, raw_key, API_KEY_TOTAL_LEN);
    result_out->ma_apiKey[API_KEY_TOTAL_LEN] = '\0';
  }
}

static const char* static_normalizeIp(const char* ip, char* bucket_out, size_t bucket_out_size)
{
  assert(ip != NULL);
  assert(bucket_out != NULL);
  assert(bucket_out_size >= AUTH_IP_BUCKET_BUF_SIZE);

  socklen_t address_room = (socklen_t)(bucket_out_size - (sizeof(AUTH_IPV6_BUCKET_SUFFIX) - 1));

  struct in_addr ipv4;
  if (inet_pton(AF_INET, ip, &ipv4) == 1)
    return inet_ntop(AF_INET, &ipv4, bucket_out, address_room) ? bucket_out : ip;

  struct in6_addr ipv6;
  if (inet_pton(AF_INET6, ip, &ipv6) != 1)
    return ip;

  if (IN6_IS_ADDR_V4MAPPED(&ipv6))
    return inet_ntop(AF_INET, &ipv6.s6_addr[12], bucket_out, address_room) ? bucket_out : ip;

  memset(&ipv6.s6_addr[AUTH_IPV6_PREFIX_BYTES], 0, sizeof(ipv6.s6_addr) - AUTH_IPV6_PREFIX_BYTES);
  if (!inet_ntop(AF_INET6, &ipv6, bucket_out, address_room))
    return ip;
  size_t address_len = strlen(bucket_out);
  memcpy(bucket_out + address_len, AUTH_IPV6_BUCKET_SUFFIX, sizeof(AUTH_IPV6_BUCKET_SUFFIX));
  return bucket_out;
}