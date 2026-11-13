#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include "keyvault.h"
#include "bytes.h"

#define KEYVAULT_SEAL_KEY_LABEL "contrastapi vendor key seal v1"

#define KEYVAULT_SEALED_FORMAT_VERSION 1

#define KEYVAULT_HMAC_BYTE_COUNT 32

#define KEYVAULT_AUTHENTICATED_DATA_HEAD_BYTE_COUNT 9

#define KEYVAULT_SEALED_MIN_BYTE_COUNT (1 + KEYVAULT_NONCE_BYTE_COUNT + 1 + KEYVAULT_TAG_BYTE_COUNT)

#define KEYVAULT_SEALED_MAX_BYTE_COUNT (KEYVAULT_SEALED_HEX_MAX_LEN / 2)

#define KEYVAULT_VENDOR_KEY_LINK_BYTE_COUNT (KEYVAULT_VENDOR_KEY_LINK_LEN / 2)

#define KEYVAULT_SHA256_BYTE_COUNT (KEYVAULT_VENDOR_KEY_LINK_HASH_HEX_LEN / 2)

static unsigned char g_sealKey[KEYVAULT_HMAC_BYTE_COUNT];
static bool          g_isMasterKeySet = false;

static void static_writeInt64                 (int64_t value, unsigned char* bytes_out);
static void static_writeAuthenticatedDataHead (int64_t api_key_id, unsigned char* head_out);
static bool static_tryDeriveKey               (const unsigned char* master_key_bytes, const char* label, unsigned char* key_out);
static bool static_isLowerCaseHex             (const char* text, size_t text_len);

bool keyvault_trySetMasterKey(const KeyVaultMasterKey_t* master_key)
{
  assert(master_key != NULL);

  unsigned char seal_key[KEYVAULT_HMAC_BYTE_COUNT];
  bool is_derived = static_tryDeriveKey(master_key->ma_key, KEYVAULT_SEAL_KEY_LABEL, seal_key);
  if (is_derived)
  {
    memcpy(g_sealKey, seal_key, sizeof(g_sealKey));
    g_isMasterKeySet = true;
  }

  OPENSSL_cleanse(seal_key, sizeof(seal_key));
  return is_derived;
}

bool keyvault_trySeal(int64_t api_key_id, const char* vendor_name, const char* vendor_key, size_t vendor_key_len, char* sealed_hex_out)
{
  assert(vendor_name != NULL && vendor_name[0] != '\0');
  assert(vendor_key != NULL);
  assert(sealed_hex_out != NULL);

  sealed_hex_out[0] = '\0';
  if (!g_isMasterKeySet || api_key_id < 1 || vendor_key_len < 1 || vendor_key_len > KEYVAULT_VENDOR_KEY_MAX_LEN)
    return false;

  unsigned char  sealed[KEYVAULT_SEALED_MAX_BYTE_COUNT];
  unsigned char* nonce      = sealed + 1;
  unsigned char* ciphertext = nonce + KEYVAULT_NONCE_BYTE_COUNT;
  unsigned char* tag        = ciphertext + vendor_key_len;
  sealed[0] = KEYVAULT_SEALED_FORMAT_VERSION;
  if (RAND_bytes(nonce, KEYVAULT_NONCE_BYTE_COUNT) != 1)
    return false;

  unsigned char authenticated_data_head[KEYVAULT_AUTHENTICATED_DATA_HEAD_BYTE_COUNT];
  static_writeAuthenticatedDataHead(api_key_id, authenticated_data_head);

  EVP_CIPHER_CTX* cipher_ctx = EVP_CIPHER_CTX_new();
  if (cipher_ctx == NULL)
    return false;

  int  written_len = 0;
  int  final_len   = 0;
  bool is_sealed   = EVP_EncryptInit_ex(cipher_ctx, EVP_aes_256_gcm(), NULL, g_sealKey, nonce) == 1
                  && EVP_EncryptUpdate(cipher_ctx, NULL, &written_len, authenticated_data_head, KEYVAULT_AUTHENTICATED_DATA_HEAD_BYTE_COUNT) == 1
                  && EVP_EncryptUpdate(cipher_ctx, NULL, &written_len, (const unsigned char*)vendor_name, (int)strlen(vendor_name)) == 1
                  && EVP_EncryptUpdate(cipher_ctx, ciphertext, &written_len, (const unsigned char*)vendor_key, (int)vendor_key_len) == 1
                  && EVP_EncryptFinal_ex(cipher_ctx, ciphertext + written_len, &final_len) == 1
                  && EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_GCM_GET_TAG, KEYVAULT_TAG_BYTE_COUNT, tag) == 1;
  EVP_CIPHER_CTX_free(cipher_ctx);
  if (!is_sealed)
    return false;

  bytes_writeHex(sealed, 1 + KEYVAULT_NONCE_BYTE_COUNT + vendor_key_len + KEYVAULT_TAG_BYTE_COUNT, sealed_hex_out);
  return true;
}

bool keyvault_tryOpen(int64_t api_key_id, const char* vendor_name, const char* sealed_hex, char* vendor_key_out, size_t* vendor_key_len_out)
{
  assert(vendor_name != NULL && vendor_name[0] != '\0');
  assert(sealed_hex != NULL);
  assert(vendor_key_out != NULL);
  assert(vendor_key_len_out != NULL);

  OPENSSL_cleanse(vendor_key_out, KEYVAULT_VENDOR_KEY_MAX_LEN + 1);
  *vendor_key_len_out = 0;

  size_t sealed_hex_len = strlen(sealed_hex);
  if (!g_isMasterKeySet || api_key_id < 1 || sealed_hex_len < 2 * KEYVAULT_SEALED_MIN_BYTE_COUNT || sealed_hex_len > KEYVAULT_SEALED_HEX_MAX_LEN)
    return false;

  unsigned char sealed[KEYVAULT_SEALED_MAX_BYTE_COUNT];
  if (!bytes_tryReadHex(sealed_hex, sealed_hex_len, sealed) || sealed[0] != KEYVAULT_SEALED_FORMAT_VERSION)
    return false;

  size_t         sealed_len     = sealed_hex_len / 2;
  size_t         ciphertext_len = sealed_len - 1 - KEYVAULT_NONCE_BYTE_COUNT - KEYVAULT_TAG_BYTE_COUNT;
  unsigned char* nonce          = sealed + 1;
  unsigned char* ciphertext     = nonce + KEYVAULT_NONCE_BYTE_COUNT;
  unsigned char* tag            = ciphertext + ciphertext_len;

  unsigned char authenticated_data_head[KEYVAULT_AUTHENTICATED_DATA_HEAD_BYTE_COUNT];
  static_writeAuthenticatedDataHead(api_key_id, authenticated_data_head);

  EVP_CIPHER_CTX* cipher_ctx = EVP_CIPHER_CTX_new();
  if (cipher_ctx == NULL)
    return false;

  int  written_len = 0;
  int  final_len   = 0;
  bool is_opened   = EVP_DecryptInit_ex(cipher_ctx, EVP_aes_256_gcm(), NULL, g_sealKey, nonce) == 1
                  && EVP_DecryptUpdate(cipher_ctx, NULL, &written_len, authenticated_data_head, KEYVAULT_AUTHENTICATED_DATA_HEAD_BYTE_COUNT) == 1
                  && EVP_DecryptUpdate(cipher_ctx, NULL, &written_len, (const unsigned char*)vendor_name, (int)strlen(vendor_name)) == 1
                  && EVP_DecryptUpdate(cipher_ctx, (unsigned char*)vendor_key_out, &written_len, ciphertext, (int)ciphertext_len) == 1
                  && EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_GCM_SET_TAG, KEYVAULT_TAG_BYTE_COUNT, tag) == 1
                  && EVP_DecryptFinal_ex(cipher_ctx, (unsigned char*)vendor_key_out + written_len, &final_len) > 0;
  EVP_CIPHER_CTX_free(cipher_ctx);
  if (!is_opened)
  {
    OPENSSL_cleanse(vendor_key_out, KEYVAULT_VENDOR_KEY_MAX_LEN + 1);
    return false;
  }

  vendor_key_out[ciphertext_len] = '\0';
  *vendor_key_len_out = ciphertext_len;
  return true;
}

bool keyvault_tryWriteVendorKeyLink(char* link_out)
{
  assert(link_out != NULL);

  link_out[0] = '\0';
  unsigned char link_bytes[KEYVAULT_VENDOR_KEY_LINK_BYTE_COUNT];
  if (RAND_bytes(link_bytes, KEYVAULT_VENDOR_KEY_LINK_BYTE_COUNT) != 1)
    return false;

  bytes_writeHex(link_bytes, sizeof(link_bytes), link_out);
  OPENSSL_cleanse(link_bytes, sizeof(link_bytes));
  return true;
}

bool keyvault_tryHashVendorKeyLink(const char* link, char* link_hash_hex_out)
{
  assert(link != NULL);
  assert(link_hash_hex_out != NULL);

  link_hash_hex_out[0] = '\0';
  size_t link_len = strlen(link);
  if (link_len != KEYVAULT_VENDOR_KEY_LINK_LEN || !static_isLowerCaseHex(link, link_len))
    return false;

  unsigned char link_hash[KEYVAULT_SHA256_BYTE_COUNT];
  unsigned int  link_hash_len = KEYVAULT_SHA256_BYTE_COUNT;
  if (EVP_Digest(link, link_len, link_hash, &link_hash_len, EVP_sha256(), NULL) != 1)
    return false;

  bytes_writeHex(link_hash, sizeof(link_hash), link_hash_hex_out);
  return true;
}

static void static_writeInt64(int64_t value, unsigned char* bytes_out)
{
  uint64_t unsigned_value = (uint64_t)value;
  for (int i = 7; i >= 0; i--)
  {
    bytes_out[i] = (unsigned char)(unsigned_value & 0xFF);
    unsigned_value >>= 8;
  }
}

static void static_writeAuthenticatedDataHead (int64_t api_key_id, unsigned char* head_out)
{
  static_writeInt64(api_key_id, head_out);
  head_out[8] = KEYVAULT_SEALED_FORMAT_VERSION;
}

static bool static_tryDeriveKey(const unsigned char* master_key_bytes, const char* label, unsigned char* key_out)
{
  unsigned int key_len = KEYVAULT_HMAC_BYTE_COUNT;
  return HMAC(EVP_sha256(), master_key_bytes, KEYVAULT_MASTER_KEY_BYTE_COUNT, (const unsigned char*)label, strlen(label), key_out, &key_len) != NULL;
}

static bool static_isLowerCaseHex(const char* text, size_t text_len)
{
  for (size_t i = 0; i < text_len; i++)
  {
    bool is_digit  = text[i] >= '0' && text[i] <= '9';
    bool is_letter = text[i] >= 'a' && text[i] <= 'f';
    if (!is_digit && !is_letter)
      return false;
  }
  return true;
}
