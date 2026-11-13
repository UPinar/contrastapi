#ifndef AUTH_H
#define AUTH_H

#include <stdbool.h>
#include <stddef.h>

#include "picohttpparser.h"

#define API_KEY_TOTAL_LEN  68

#define SHA256_HEX_LEN     64

typedef enum {
  AUTH_API_KEY_NONE,
  AUTH_API_KEY_MALFORMED,
  AUTH_API_KEY_VALID_FORMAT,
} AuthApiKeyStatus_t;

typedef struct {
  AuthApiKeyStatus_t m_apiKeyStatus;
  char               ma_apiKey[API_KEY_TOTAL_LEN + 1];
} AuthApiKeyParseResult_t;

AuthApiKeyParseResult_t auth_parseApiKey (const struct phr_header* headers, size_t header_count);
void                    auth_hashApiKey  (const char* api_key, char* hex_out_buf);
void                    auth_hashIp      (const char* ip, const char* secret, char* hex_out_buf);

bool auth_tryGenerateApiKey (char* key_out)               __attribute__((warn_unused_result));
bool auth_tryGenerateUuid   (char* out, size_t out_size)  __attribute__((warn_unused_result));

#endif
