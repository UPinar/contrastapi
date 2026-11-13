#ifndef DBAPIKEY_H
#define DBAPIKEY_H

#include <stdbool.h>
#include <stdint.h>

typedef struct {
  bool    m_hasExpiry;
  int64_t m_expiresAt;
} DbApiKeyExpiry_t;

#endif
