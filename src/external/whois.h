#ifndef WHOIS_H
#define WHOIS_H

#include <stddef.h>

#include "rdap.h"

#define WHOIS_PORT 43

#define WHOIS_DEADLINE_MS          5000
#define WHOIS_RESOLVE_DEADLINE_MS  2000
#define WHOIS_CONNECT_DEADLINE_MS  2000

#define WHOIS_MAX_ANSWER_BYTE_COUNT 65536

typedef enum {
  WHOIS_FIELD_DOMAIN_NAME,
  WHOIS_FIELD_REGISTRAR_NAME,
  WHOIS_FIELD_REGISTRAR_IANA_ID,
  WHOIS_FIELD_CREATED_AT,
  WHOIS_FIELD_UPDATED_AT,
  WHOIS_FIELD_EXPIRES_AT,
  WHOIS_FIELD_STATUS,
  WHOIS_FIELD_NAME_SERVER,
  WHOIS_FIELD_DNSSEC,
} WhoisField_t;

typedef struct {
  const char*   mp_key;
  WhoisField_t  m_field;
} WhoisKey_t;

typedef struct {
  const WhoisKey_t*  mp_keys;
  int                m_keyCount;
} WhoisKeyMap_t;

typedef struct {
  const char*            mp_tld;
  const char*            mp_host;
  const WhoisKeyMap_t*   mp_keyMap;
  const char*            mp_notFoundMarker;
} WhoisServer_t;

extern const WhoisServer_t whois_servers[];
extern const int           whois_serverCount;

typedef enum {
  WHOIS_OK = 0,
  WHOIS_NOT_REGISTERED,
  WHOIS_UPSTREAM_ERROR,
  WHOIS_INVALID_NAME,
} WhoisStatus_t;

const WhoisServer_t* whois_findServer   (const char* domain_name);
WhoisStatus_t        whois_readAnswer   (const char* answer, size_t answer_len, const char* domain_name, const WhoisServer_t* server, RdapRegistration_t* registration_out);
WhoisStatus_t        whois_lookupDomain (const char* domain_name, const WhoisServer_t* server, RdapRegistration_t* registration_out);

#endif
