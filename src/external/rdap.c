#include <assert.h>
#include <ctype.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "rdap.h"
#include "http.h"
#include "jsonread.h"
#include "retryafter.h"
#include "validate.h"

#define RDAP_TIMEOUT_MS           5000
#define RDAP_MAX_BODY_BYTE_COUNT  (256 * 1024)
#define RDAP_ACCEPT_HEADER        "Accept: application/rdap+json"
#define RDAP_DOMAIN_PATH          "domain/"

#define RDAP_URL_MAX_LEN 512

#define RDAP_IANA_REGISTRAR_ID_MAX_DIGITS 9

static int static_compareTld(const void* tld, const void* entry)
{
  return strcasecmp((const char*)tld, ((const RdapServer_t*)entry)->mp_tld);
}

const char* rdap_findServerBaseUrl(const char* domain_name)
{
  assert(domain_name != NULL);

  const char* last_dot = strrchr(domain_name, '.');
  const char* tld      = last_dot != NULL ? last_dot + 1 : domain_name;

  const RdapServer_t* server = bsearch(tld, rdap_servers, (size_t)rdap_serverCount, sizeof(rdap_servers[0]), static_compareTld);
  return server != NULL ? server->mp_baseUrl : NULL;
}

static void static_readEvents(JsonReadSpan_t root_span, RdapRegistration_t* registration)
{
  JsonReadSpan_t events_span = { 0 };
  if (jsonread_objectKey(root_span, "events", &events_span) != JSONREAD_OK)
    return;

  JsonReadSpan_t event_span   = { 0 };
  size_t         event_offset = 0;
  while (jsonread_arrayNextElement(events_span, &event_offset, &event_span) == JSONREAD_OK)
  {
    JsonReadSpan_t action_span = { 0 };
    JsonReadSpan_t date_span   = { 0 };
    if (jsonread_objectKey(event_span, "eventAction", &action_span) != JSONREAD_OK ||
        jsonread_objectKey(event_span, "eventDate", &date_span) != JSONREAD_OK)
      continue;

    char* date_out = NULL;
    if (jsonread_isSpanEqual(action_span, "\"registration\""))
      date_out = registration->ma_createdAt;
    else if (jsonread_isSpanEqual(action_span, "\"expiration\""))
      date_out = registration->ma_expiresAt;
    else if (jsonread_isSpanEqual(action_span, "\"last changed\""))
      date_out = registration->ma_updatedAt;

    if (date_out == NULL || date_out[0] != '\0')
      continue;
    if (jsonread_spanToStrStatus(date_span, date_out, RDAP_DATE_MAX_LEN + 1) != JSONREAD_OK)
      date_out[0] = '\0';
  }
}

static void static_readStatuses(JsonReadSpan_t root_span, RdapRegistration_t* registration)
{
  JsonReadSpan_t statuses_span = { 0 };
  if (jsonread_objectKey(root_span, "status", &statuses_span) != JSONREAD_OK)
    return;

  JsonReadSpan_t status_span   = { 0 };
  size_t         status_offset = 0;
  while (jsonread_arrayNextElement(statuses_span, &status_offset, &status_span) == JSONREAD_OK)
  {
    char status[RDAP_STATUS_MAX_LEN + 1];
    if (jsonread_spanToStrStatus(status_span, status, sizeof(status)) != JSONREAD_OK || status[0] == '\0')
      continue;

    if (registration->m_statusCount < RDAP_STATUS_MAX_COUNT)
      memcpy(registration->ma_statuses[registration->m_statusCount], status, sizeof(status));
    if (registration->m_statusCount < INT_MAX)
      registration->m_statusCount++;
  }
}

static void static_readNameServers(JsonReadSpan_t root_span, RdapRegistration_t* registration)
{
  JsonReadSpan_t name_servers_span = { 0 };
  if (jsonread_objectKey(root_span, "nameservers", &name_servers_span) != JSONREAD_OK)
    return;

  JsonReadSpan_t name_server_span   = { 0 };
  size_t         name_server_offset = 0;
  while (jsonread_arrayNextElement(name_servers_span, &name_server_offset, &name_server_span) == JSONREAD_OK)
  {
    JsonReadSpan_t ldh_name_span = { 0 };
    char name[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
    if (jsonread_objectKey(name_server_span, "ldhName", &ldh_name_span) != JSONREAD_OK  ||
        jsonread_spanToStrStatus(ldh_name_span, name, sizeof(name)) != JSONREAD_OK      ||
        !validate_domainName(name))
      continue;

    for (char* byte = name; *byte != '\0'; byte++)
      *byte = (char)tolower((unsigned char)*byte);
    if (registration->m_nameServerCount < RDAP_NAME_SERVER_MAX_COUNT)
      memcpy(registration->ma_nameServers[registration->m_nameServerCount], name, sizeof(name));
    if (registration->m_nameServerCount < INT_MAX)
      registration->m_nameServerCount++;
  }
}

static bool static_hasRole(JsonReadSpan_t entity_span, const char* quoted_role)
{
  JsonReadSpan_t roles_span = { 0 };
  if (jsonread_objectKey(entity_span, "roles", &roles_span) != JSONREAD_OK)
    return false;

  JsonReadSpan_t role_span   = { 0 };
  size_t         role_offset = 0;
  while (jsonread_arrayNextElement(roles_span, &role_offset, &role_span) == JSONREAD_OK)
    if (jsonread_isSpanEqual(role_span, quoted_role))
      return true;

  return false;
}

static void static_readFullName(JsonReadSpan_t entity_span, char name_out[RDAP_REGISTRAR_NAME_MAX_LEN + 1])
{
  JsonReadSpan_t vcard_array_span = { 0 };
  JsonReadSpan_t vcard_tag_span   = { 0 };
  JsonReadSpan_t properties_span  = { 0 };
  size_t         vcard_offset     = 0;
  if (jsonread_objectKey(entity_span, "vcardArray", &vcard_array_span) != JSONREAD_OK               ||
      jsonread_arrayNextElement(vcard_array_span, &vcard_offset, &vcard_tag_span) != JSONREAD_OK    ||
      !jsonread_isSpanEqual(vcard_tag_span, "\"vcard\"")                                            ||
      jsonread_arrayNextElement(vcard_array_span, &vcard_offset, &properties_span) != JSONREAD_OK)
    return;

  JsonReadSpan_t property_span   = { 0 };
  size_t         property_offset = 0;
  while (jsonread_arrayNextElement(properties_span, &property_offset, &property_span) == JSONREAD_OK)
  {
    JsonReadSpan_t part_span   = { 0 };
    size_t         part_offset = 0;
    if (jsonread_arrayNextElement(property_span, &part_offset, &part_span) != JSONREAD_OK ||
        !jsonread_isSpanEqual(part_span, "\"fn\""))
      continue;

    for (int part_index = 1; part_index <= 3; part_index++)
      if (jsonread_arrayNextElement(property_span, &part_offset, &part_span) != JSONREAD_OK)
        return;
    if (jsonread_spanToStrStatus(part_span, name_out, RDAP_REGISTRAR_NAME_MAX_LEN + 1) != JSONREAD_OK)
      name_out[0] = '\0';
    return;
  }
}

static long static_readIanaRegistrarId(JsonReadSpan_t entity_span)
{
  JsonReadSpan_t public_ids_span = { 0 };
  if (jsonread_objectKey(entity_span, "publicIds", &public_ids_span) != JSONREAD_OK)
    return -1;

  JsonReadSpan_t public_id_span   = { 0 };
  size_t         public_id_offset = 0;
  while (jsonread_arrayNextElement(public_ids_span, &public_id_offset, &public_id_span) == JSONREAD_OK)
  {
    JsonReadSpan_t type_span       = { 0 };
    JsonReadSpan_t identifier_span = { 0 };
    char           identifier[RDAP_IANA_REGISTRAR_ID_MAX_DIGITS + 1];
    if (jsonread_objectKey(public_id_span, "type", &type_span) != JSONREAD_OK                     ||
        !jsonread_isSpanEqual(type_span, "\"IANA Registrar ID\"")                                 ||
        jsonread_objectKey(public_id_span, "identifier", &identifier_span) != JSONREAD_OK         ||
        jsonread_spanToStrStatus(identifier_span, identifier, sizeof(identifier)) != JSONREAD_OK  ||
        identifier[0] == '\0')
      continue;

    bool is_all_digits = true;
    for (const char* byte = identifier; *byte != '\0'; byte++)
      if (!isdigit((unsigned char)*byte))
        is_all_digits = false;
    if (is_all_digits)
      return strtol(identifier, NULL, 10);
  }
  return -1;
}

static void static_readRegistrar(JsonReadSpan_t root_span, RdapRegistration_t* registration)
{
  JsonReadSpan_t entities_span = { 0 };
  if (jsonread_objectKey(root_span, "entities", &entities_span) != JSONREAD_OK)
    return;

  JsonReadSpan_t entity_span   = { 0 };
  size_t         entity_offset = 0;
  while (jsonread_arrayNextElement(entities_span, &entity_offset, &entity_span) == JSONREAD_OK)
  {
    if (!static_hasRole(entity_span, "\"registrar\""))
      continue;

    static_readFullName(entity_span, registration->ma_registrarName);
    registration->m_registrarIanaId = static_readIanaRegistrarId(entity_span);
    return;
  }
}

bool rdap_tryReadDomain(const char* body, size_t body_len, RdapRegistration_t* registration_out)
{
  assert(body             != NULL);
  assert(registration_out != NULL);

  memset(registration_out, 0, sizeof(*registration_out));
  registration_out->m_registrarIanaId = -1;

  JsonReadSpan_t root_span       = { 0 };
  JsonReadSpan_t class_name_span = { 0 };
  if (jsonread_root(body, body_len, &root_span) != JSONREAD_OK                          ||
      jsonread_objectKey(root_span, "objectClassName", &class_name_span) != JSONREAD_OK ||
      !jsonread_isSpanEqual(class_name_span, "\"domain\""))
    return false;

  static_readRegistrar(root_span, registration_out);
  static_readEvents(root_span, registration_out);
  static_readStatuses(root_span, registration_out);
  static_readNameServers(root_span, registration_out);

  JsonReadSpan_t secure_dns_span        = { 0 };
  JsonReadSpan_t delegation_signed_span = { 0 };
  bool           is_delegation_signed   = false;
  if (jsonread_objectKey(root_span, "secureDNS", &secure_dns_span) == JSONREAD_OK                     &&
      jsonread_objectKey(secure_dns_span, "delegationSigned", &delegation_signed_span) == JSONREAD_OK &&
      jsonread_spanToBoolStatus(delegation_signed_span, &is_delegation_signed) == JSONREAD_OK)
  {
    registration_out->m_delegationSigned = is_delegation_signed ? RDAP_DELEGATION_SIGNED_YES : RDAP_DELEGATION_SIGNED_NO;
  }

  return true;
}

RdapStatus_t rdap_lookupDomain(const char* domain_name, const char* base_url, RdapRegistration_t* registration_out, unsigned int* retry_after_seconds_out)
{
  assert(domain_name             != NULL);
  assert(base_url                != NULL);
  assert(registration_out        != NULL);
  assert(retry_after_seconds_out != NULL);

  memset(registration_out, 0, sizeof(*registration_out));
  registration_out->m_registrarIanaId = -1;
  *retry_after_seconds_out = 0;

  if (!validate_domainName(domain_name))
    return RDAP_INVALID_NAME;

  char url[RDAP_URL_MAX_LEN + 1];
  int  url_len = snprintf(url, sizeof(url), "%s" RDAP_DOMAIN_PATH "%s", base_url, domain_name);
  if (url_len < 0 || (size_t)url_len >= sizeof(url))
    return RDAP_INVALID_NAME;

  static const char* const extra_headers[] = { RDAP_ACCEPT_HEADER, NULL };
  static const char* const header_names[]  = { RETRYAFTER_HEADER_NAME, NULL };
  const HttpRequest_t request = {
    .mp_url                  = url,
    .m_timeoutMs             = RDAP_TIMEOUT_MS,
    .mp_extraHeaders         = extra_headers,
    .m_maxBodyByteCount      = RDAP_MAX_BODY_BYTE_COUNT,
    .mp_headerNamesToCapture = header_names,
    .m_isTargetTrusted       = true,
  };
  HttpResponse_t response = http_GETWithOptions(&request);

  RdapStatus_t status = RDAP_UPSTREAM_ERROR;
  if (response.m_status == 404)
    status = RDAP_NOT_REGISTERED;
  else if (response.m_status == 429)
  {
    *retry_after_seconds_out = retryafter_parseSeconds(response.m_capturedHeaderValueCount > 0 ? response.mp_capturedHeaderValues[0] : NULL);
    status = RDAP_RATE_LIMITED;
  }
  else if (response.m_status == 200 && response.mp_body != NULL &&
           rdap_tryReadDomain(response.mp_body, response.m_bodyLen, registration_out))
  {
    status = RDAP_OK;
  }

  http_free(&response);
  return status;
}
