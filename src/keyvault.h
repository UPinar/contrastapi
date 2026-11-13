#ifndef KEYVAULT_H
#define KEYVAULT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define KEYVAULT_MASTER_KEY_BYTE_COUNT            32

#define KEYVAULT_VENDOR_KEY_MAX_LEN              128

#define KEYVAULT_NONCE_BYTE_COUNT                 12

#define KEYVAULT_TAG_BYTE_COUNT                   16

#define KEYVAULT_SEALED_HEX_MAX_LEN              (2 * (1 + KEYVAULT_NONCE_BYTE_COUNT + KEYVAULT_VENDOR_KEY_MAX_LEN + KEYVAULT_TAG_BYTE_COUNT))

#define KEYVAULT_VENDOR_KEY_LINK_LEN              64

#define KEYVAULT_VENDOR_KEY_LINK_HASH_HEX_LEN     64

typedef struct {
  unsigned char ma_key[KEYVAULT_MASTER_KEY_BYTE_COUNT];
} KeyVaultMasterKey_t;

bool keyvault_trySetMasterKey       (const KeyVaultMasterKey_t* master_key);
bool keyvault_trySeal               (int64_t api_key_id, const char* vendor_name, const char* vendor_key, size_t vendor_key_len, char* sealed_hex_out);
bool keyvault_tryOpen               (int64_t api_key_id, const char* vendor_name, const char* sealed_hex, char* vendor_key_out, size_t* vendor_key_len_out);
bool keyvault_tryWriteVendorKeyLink (char* link_out);
bool keyvault_tryHashVendorKeyLink  (const char* link, char* link_hash_hex_out);

#endif
