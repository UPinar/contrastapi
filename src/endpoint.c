#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "endpoint.h"
#include "bulk.h"
#include "bytes.h"
#include "cve.h"
#include "watchlist/watchlist.h"
#include "jsonbuf.h"
#include "jsonread.h"
#include "package.h"
#include "query.h"
#include "request.h"
#include "utf8.h"
#include "validate.h"
#include "usagelog.h"

const Endpoint_t* endpoint_findByHttpPath(const char* path, const char** path_segment_out)
{
  assert(path != NULL);

  for (int i = 0; i < endpoint_count; i++)
  {
    const Endpoint_t* endpoint = &endpoints[i];
    bool path_matched          = false;
    const char* param          = NULL;

    if (!endpoint->m_hasPathSegment)
      path_matched = (strcmp(path, endpoint->mp_httpPath) == 0);
    else
    {
      size_t http_path_len = strlen(endpoint->mp_httpPath);
      assert(http_path_len > 1 && endpoint->mp_httpPath[http_path_len - 1] == '/');

      if (strncmp(path, endpoint->mp_httpPath, http_path_len) == 0)
      {
        path_matched = true;
        param = path + http_path_len;
      }
      else if (strncmp(path, endpoint->mp_httpPath, http_path_len - 1) == 0
               && path[http_path_len - 1] == '\0')
      {
        path_matched = true;
        param = path + http_path_len - 1;
      }
    }

    if (path_matched)
    {
      if (path_segment_out != NULL)
        *path_segment_out = param;
      return endpoint;
    }
  }

  return NULL;
}

const Endpoint_t* endpoint_findByMcpName(const char* tool_name)
{
  assert(tool_name != NULL);

  for (int i = 0; i < endpoint_count; i++)
  {
    if (endpoints[i].mp_mcpToolName != NULL && strcmp(endpoints[i].mp_mcpToolName, tool_name) == 0)
      return &endpoints[i];
  }

  return NULL;
}

int endpoint_mcpToolCount(void)
{
  int tool_count = 0;
  for (int i = 0; i < endpoint_count; i++)
  {
    if (endpoints[i].mp_mcpToolName != NULL)
      tool_count++;
  }
  return tool_count;
}

const char* endpoint_mcpToolCategoryName(EndpointMcpToolCategory_t category)
{
  switch (category)
  {
    case ENDPOINT_MCP_TOOL_CATEGORY_NONE:
      return NULL;
    case ENDPOINT_MCP_TOOL_CATEGORY_CVE:
      return "CVE Intelligence";
    case ENDPOINT_MCP_TOOL_CATEGORY_PACKAGE:
      return "Package Vulnerabilities (SBOM)";
    case ENDPOINT_MCP_TOOL_CATEGORY_CREDENTIAL:
      return "Credential Checks";
    case ENDPOINT_MCP_TOOL_CATEGORY_DOMAIN:
      return "Domain Intelligence";
    case ENDPOINT_MCP_TOOL_CATEGORY_IP:
      return "IP Intelligence";
    case ENDPOINT_MCP_TOOL_CATEGORY_THREAT_DEFENSE:
      return "Threat Defense";
    case ENDPOINT_MCP_TOOL_CATEGORY_MONITORING:
      return "Monitoring";
    case ENDPOINT_MCP_TOOL_CATEGORY_OPERATIONS:
      return "Operations";
  }

  return NULL;
}

bool endpoint_isHttpMethodAllowed(const Endpoint_t* endpoint, const char* http_method)
{
  assert(endpoint    != NULL);
  assert(http_method != NULL);

  for (int i = 0; endpoint->ma_allowedMethods[i] != NULL; i++)
  {
    if (strcmp(endpoint->ma_allowedMethods[i], http_method) == 0)
      return true;
  }
  return false;
}

static bool static_isParamTypeText(EndpointParamType_t type)
{
  return  type == ENDPOINT_PARAM_TYPE_STRING  || 
          type == ENDPOINT_PARAM_TYPE_ENUM    || 
          type == ENDPOINT_PARAM_TYPE_CVE_ID  || 
          type == ENDPOINT_PARAM_TYPE_CWE_ID;
}

static bool static_isValueInEnum(const EndpointParamSpec_t* spec, const char* value)
{
  for (size_t i = 0; spec->mp_enumValues[i] != NULL; i++)
  {
    if (strcmp(spec->mp_enumValues[i], value) == 0)
      return true;
  }
  return false;
}

static void static_writeToParamsField(const EndpointParam_t* param, char* params_field, const void* value, size_t value_size)
{
  assert(param->m_size == value_size);
  (void)param;
  memcpy(params_field, value, value_size);
}

static void static_writeDefaultToParamsField(const EndpointParam_t* param, char* params_field)
{
  const EndpointParamSpec_t* spec = param->mp_spec;

  if (spec->m_type == ENDPOINT_PARAM_TYPE_INT)
  {
    int value = (int)spec->m_default;
    static_writeToParamsField(param, params_field, &value, sizeof(value));
  }
  else if (spec->m_type == ENDPOINT_PARAM_TYPE_DOUBLE)
  {
    double value = spec->m_default;
    static_writeToParamsField(param, params_field, &value, sizeof(value));
  }
  else if (spec->m_type == ENDPOINT_PARAM_TYPE_BOOL)
  {
    bool value = false;
    assert(spec->m_default == 0.0);
    static_writeToParamsField(param, params_field, &value, sizeof(value));
  }
  else if (spec->m_type == ENDPOINT_PARAM_TYPE_KEV_FILTER)
  {
    CveKevFilter_t value = CVE_KEV_FILTER_ANY;
    assert(spec->m_default == 0.0);
    static_writeToParamsField(param, params_field, &value, sizeof(value));
  }
  else
    memset(params_field, 0, param->m_size);
}

static EndpointGateStatus_t static_checkIntBoundsAndWriteToParamsField(const EndpointParam_t* param, long param_value, char* params_field)
{
  const EndpointParamSpec_t* spec = param->mp_spec;

  if (param_value < spec->m_min || param_value > spec->m_max)
    return ENDPOINT_GATE_REJECT_VALUE;

  int int_value = (int)param_value;
  static_writeToParamsField(param, params_field, &int_value, sizeof(int_value));

  return ENDPOINT_GATE_OK;
}

static EndpointGateStatus_t static_checkDoubleBoundsAndWriteToParamsField(const EndpointParam_t* param, double param_value, char* params_field)
{
  const EndpointParamSpec_t* spec = param->mp_spec;

  if (!(param_value >= spec->m_min && param_value <= spec->m_max))
    return ENDPOINT_GATE_REJECT_VALUE;

  static_writeToParamsField(param, params_field, &param_value, sizeof(param_value));
  return ENDPOINT_GATE_OK;
}

static EndpointGateStatus_t static_checkBoolAndWriteToParamsField(const EndpointParam_t* param, bool param_value, char* params_field)
{
  if (param->mp_spec->m_type == ENDPOINT_PARAM_TYPE_KEV_FILTER)
  {
    CveKevFilter_t kev_filter = param_value ? CVE_KEV_FILTER_ONLY_IN_KEV : CVE_KEV_FILTER_NOT_IN_KEV;
    static_writeToParamsField(param, params_field, &kev_filter, sizeof(kev_filter));
    return ENDPOINT_GATE_OK;
  }

  assert(param->mp_spec->m_type == ENDPOINT_PARAM_TYPE_BOOL);
  if (!param_value && param->mp_spec->m_isOnlyTrueAccepted)
    return ENDPOINT_GATE_REJECT_VALUE;

  static_writeToParamsField(param, params_field, &param_value, sizeof(param_value));
  return ENDPOINT_GATE_OK;
}

static bool static_hasControlChar(const char* text)
{
  for (const unsigned char* byte = (const unsigned char*)text; *byte != '\0'; byte++)
  {
    if (*byte < 0x20 || *byte == 0x7F)
      return true;
  }
  return false;
}

static void static_applyLowerCase(const EndpointParamSpec_t* spec, char* field)
{
  if (!spec->m_isWrittenInLowerCase)
    return;
  for (char* byte = field; *byte != '\0'; byte++)
    *byte = (char)tolower((unsigned char)*byte);
}

static EndpointGateStatus_t static_checkParamValueAndWriteToParamsField(const EndpointParam_t* param, const char* param_value, char* params_field)
{
  const EndpointParamSpec_t* spec = param->mp_spec;

  switch (spec->m_type)
  {
    case ENDPOINT_PARAM_TYPE_STRING:
    case ENDPOINT_PARAM_TYPE_CVE_ID:
    case ENDPOINT_PARAM_TYPE_CWE_ID:
      assert(spec->m_type == ENDPOINT_PARAM_TYPE_STRING || spec->m_validatorFunction != NULL);
      if (spec->m_validatorFunction != NULL && !spec->m_validatorFunction(param_value))
        return ENDPOINT_GATE_REJECT_VALUE;
      if (static_hasControlChar(param_value))
        return ENDPOINT_GATE_REJECT_CONTROL_CHAR;
      if (!utf8_isTextValid(param_value, strlen(param_value)))
        return ENDPOINT_GATE_REJECT_INVALID_UTF8;
      if (params_field != NULL)
        static_applyLowerCase(spec, params_field);
      return ENDPOINT_GATE_OK;

    case ENDPOINT_PARAM_TYPE_ENUM:
      return static_isValueInEnum(spec, param_value) ? ENDPOINT_GATE_OK : ENDPOINT_GATE_REJECT_VALUE;

    case ENDPOINT_PARAM_TYPE_INT:
    {
      if (!jsonread_isNumberToken(param_value, param_value + strlen(param_value)))
        return ENDPOINT_GATE_REJECT_VALUE;
      char* parse_end;
      errno = 0;
      long parsed_value = strtol(param_value, &parse_end, 10);
      if (*parse_end != '\0' || errno != 0)
        return ENDPOINT_GATE_REJECT_VALUE;
      return static_checkIntBoundsAndWriteToParamsField(param, parsed_value, params_field);
    }

    case ENDPOINT_PARAM_TYPE_DOUBLE:
    {
      if (!jsonread_isNumberToken(param_value, param_value + strlen(param_value)))
        return ENDPOINT_GATE_REJECT_VALUE;
      char* parse_end;
      errno = 0;
      double parsed_value = strtod(param_value, &parse_end);
      if (*parse_end != '\0' || errno != 0)
        return ENDPOINT_GATE_REJECT_VALUE;
      return static_checkDoubleBoundsAndWriteToParamsField(param, parsed_value, params_field);
    }

    case ENDPOINT_PARAM_TYPE_BOOL:
    case ENDPOINT_PARAM_TYPE_KEV_FILTER:
      if (strcmp(param_value, "true") == 0)
        return static_checkBoolAndWriteToParamsField(param, true, params_field);
      else if (strcmp(param_value, "false") == 0)
        return static_checkBoolAndWriteToParamsField(param, false, params_field);
      return ENDPOINT_GATE_REJECT_VALUE;

    case ENDPOINT_PARAM_TYPE_CVE_ID_ARRAY:
    case ENDPOINT_PARAM_TYPE_FILE_HASH_ARRAY:
    case ENDPOINT_PARAM_TYPE_PACKAGE_ARRAY:
    case ENDPOINT_PARAM_TYPE_BYTES:
      break;
  }

  assert(false && "a bulk array is read from a JSON body and BYTES from a raw body, never from the REST query or the path");
  return ENDPOINT_GATE_REJECT_VALUE;
}

static EndpointGateStatus_t static_countArrayElements(const EndpointParamSpec_t* spec, JsonReadSpan_t array_span, size_t* element_count_out)
{
  size_t element_count;
  if (jsonread_arrayLen(array_span, &element_count) != JSONREAD_OK)
    return ENDPOINT_GATE_REJECT_TYPE;
  else if (element_count == 0)
    return ENDPOINT_GATE_REJECT_ITEMS_EMPTY;
  else if (element_count > (size_t)spec->m_max)
    return ENDPOINT_GATE_REJECT_ITEMS_TOO_MANY;

  *element_count_out = element_count;
  return ENDPOINT_GATE_OK;
}

static EndpointGateStatus_t static_readArrayMember(const EndpointParamSpec_t* spec, JsonReadSpan_t object_span, JsonReadSpan_t* array_span_out, size_t* element_count_out)
{
  size_t           member_offset = 0;
  JsonReadSpan_t   key_span;
  JsonReadSpan_t   array_span;
  JsonReadStatus_t walk_status = jsonread_objectNextMember(object_span, &member_offset, &key_span, &array_span);
  if (walk_status == JSONREAD_ERR_NOTFOUND)
    return ENDPOINT_GATE_REJECT_MISSING;
  else if (walk_status != JSONREAD_OK)
    return ENDPOINT_GATE_REJECT_BODY;
  else if (!jsonread_isSpanEqual(key_span, spec->mp_name))
    return ENDPOINT_GATE_REJECT_UNKNOWN_PARAM_NAME;

  JsonReadSpan_t extra_key_span;
  JsonReadSpan_t extra_value_span;
  walk_status = jsonread_objectNextMember(object_span, &member_offset, &extra_key_span, &extra_value_span);
  if (walk_status == JSONREAD_OK && jsonread_isSpanEqual(extra_key_span, spec->mp_name))
    return ENDPOINT_GATE_REJECT_DUPLICATE_PARAM_NAME;
  else if (walk_status == JSONREAD_OK)
    return ENDPOINT_GATE_REJECT_UNKNOWN_PARAM_NAME;
  else if (walk_status != JSONREAD_ERR_NOTFOUND)
    return ENDPOINT_GATE_REJECT_BODY;

  EndpointGateStatus_t count_status = static_countArrayElements(spec, array_span, element_count_out);
  if (count_status == ENDPOINT_GATE_OK)
    *array_span_out = array_span;
  return count_status;
}

static EndpointGateStatus_t static_readBulkIds(const EndpointParamSpec_t* spec, JsonReadSpan_t object_span, BulkIdsParams_t* ids_out, int* duplicate_item_index_out, int* original_item_index_out)
{
  assert((size_t)spec->m_max <= sizeof(ids_out->ma_ids) / sizeof(ids_out->ma_ids[0]));
  assert(spec->m_maxLen < sizeof(ids_out->ma_ids[0]));
  assert(spec->m_validatorFunction != NULL);

  JsonReadSpan_t       ids_span;
  size_t               element_count;
  EndpointGateStatus_t array_status = static_readArrayMember(spec, object_span, &ids_span, &element_count);
  if (array_status != ENDPOINT_GATE_OK)
    return array_status;

  int id_element_indexes[sizeof(ids_out->ma_ids) / sizeof(ids_out->ma_ids[0])];
  ids_out->m_idCount              = 0;
  ids_out->m_skippedIdCount       = 0;
  ids_out->m_notProcessedIdCount  = 0;
  size_t element_offset           = 0;
  for (size_t i = 0; i < element_count; i++)
  {
    char* id = ids_out->ma_ids[ids_out->m_idCount];
    JsonReadSpan_t element_span;
    if (jsonread_arrayNextElement(ids_span, &element_offset, &element_span) == JSONREAD_OK  &&
        jsonread_spanToStrStatus(element_span, id, spec->m_maxLen + 1) == JSONREAD_OK       &&
        spec->m_validatorFunction(id))
    {
      if (spec->m_type == ENDPOINT_PARAM_TYPE_FILE_HASH_ARRAY)
        for (char* byte = id; *byte != '\0'; byte++)
          *byte = (char)tolower((unsigned char)*byte);

      id_element_indexes[ids_out->m_idCount] = (int)i;
      ids_out->m_idCount++;
    }
    else
      ids_out->m_skippedIdCount++;
  }

  for (int later = 1; later < ids_out->m_idCount; later++)
  {
    for (int earlier = 0; earlier < later; earlier++)
    {
      if (strcmp(ids_out->ma_ids[later], ids_out->ma_ids[earlier]) == 0)
      {
        *duplicate_item_index_out = id_element_indexes[later];
        *original_item_index_out  = id_element_indexes[earlier];
        return ENDPOINT_GATE_REJECT_ITEMS_REPEATED;
      }
    }
  }
  return ENDPOINT_GATE_OK;
}

EndpointRefusalMessage_t endpoint_writeGateRefusalMessage(const Endpoint_t* endpoint, EndpointGateResult_t gate_result, char* message_out, size_t message_size)
{
  assert(endpoint    != NULL);
  assert(message_out != NULL);

  if (gate_result.m_refusedParamIndex < 0 || gate_result.m_refusedParamIndex >= endpoint->m_paramCount)
  {
    fprintf(stderr, "endpoint_writeGateRefusalMessage: refusal %d names no parameter\n", (int)gate_result.m_status);
    snprintf(message_out, message_size, "%s", ENDPOINT_GATE_FALLBACK_REFUSAL_MESSAGE);
    return ENDPOINT_REFUSAL_MESSAGE_FALLBACK;
  }

  const EndpointParam_t*     param = &endpoint->mp_params[gate_result.m_refusedParamIndex];
  const EndpointParamSpec_t* spec  = param->mp_spec;
  const char*                name  = spec->mp_name;
  int written = -1;
  switch (gate_result.m_status)
  {
    case ENDPOINT_GATE_REJECT_MISSING:
    {
      bool is_path_segment = (param->m_sources & ENDPOINT_PARAM_SRC_REST_PATH_SEGMENT) != 0;
      if (is_path_segment && spec->m_type == ENDPOINT_PARAM_TYPE_CWE_ID)
        written = snprintf(message_out, message_size, "missing CWE ID");
      else if (is_path_segment && spec->m_type == ENDPOINT_PARAM_TYPE_CVE_ID)
        written = snprintf(message_out, message_size, "missing CVE ID");
      else
        written = snprintf(message_out, message_size, "%s is required", name);
      break;
    }
    case ENDPOINT_GATE_REJECT_TOOLONG:
      written = snprintf(message_out, message_size, "%s is too long", name);
      break;
    case ENDPOINT_GATE_REJECT_VALUE:
      assert(spec->mp_message != NULL);
      written = snprintf(message_out, message_size, "%s", spec->mp_message);
      break;
    case ENDPOINT_GATE_REJECT_TYPE:
      if (endpoint_isBulkArrayType(spec->m_type))
        written = snprintf(message_out, message_size, "%s must be an array", name);
      else
        written = snprintf(message_out, message_size, "%s must be a string", name);
      break;
    case ENDPOINT_GATE_REJECT_ESCAPE:
      written = snprintf(message_out, message_size, "%s contains an escape this server cannot decode", name);
      break;
    case ENDPOINT_GATE_REJECT_ENCODING:
      written = snprintf(message_out, message_size, "%s is not valid percent-encoding", name);
      break;
    case ENDPOINT_GATE_REJECT_CONTROL_CHAR:
      written = snprintf(message_out, message_size, "%s must not contain control characters", name);
      break;
    case ENDPOINT_GATE_REJECT_INVALID_UTF8:
      written = snprintf(message_out, message_size, "%s must be valid UTF-8", name);
      break;
    case ENDPOINT_GATE_REJECT_DUPLICATE_PARAM_NAME:
      written = snprintf(message_out, message_size, "%s appears more than once", name);
      break;
    case ENDPOINT_GATE_REJECT_OBJECT_OR_ARRAY_VALUE:
      written = snprintf(message_out, message_size, "%s must not be an object or an array", name);
      break;
    case ENDPOINT_GATE_REJECT_ITEMS_EMPTY:
      written = snprintf(message_out, message_size, "%s array must not be empty", name);
      break;
    case ENDPOINT_GATE_REJECT_ITEMS_TOO_MANY:
      written = snprintf(message_out, message_size, "%s array exceeds maximum of %d", name, (int)spec->m_max);
      break;
    case ENDPOINT_GATE_REJECT_ITEMS_REPEATED:
      written = snprintf(message_out, message_size, "%s[%d] repeats %s[%d]", name, gate_result.m_duplicateItemIndex, name, gate_result.m_originalItemIndex);
      break;
    case ENDPOINT_GATE_OK:
    case ENDPOINT_GATE_REJECT_UNKNOWN_PARAM_NAME:
    case ENDPOINT_GATE_REJECT_MALFORMED_PARAM:
    case ENDPOINT_GATE_REJECT_BODY:
    case ENDPOINT_GATE_REJECT_BODY_TOO_LARGE:
      fprintf(stderr, "endpoint_writeGateRefusalMessage: refusal %d is written by the transport\n", (int)gate_result.m_status);
      snprintf(message_out, message_size, "%s", ENDPOINT_GATE_FALLBACK_REFUSAL_MESSAGE);
      return ENDPOINT_REFUSAL_MESSAGE_FALLBACK;
  }
  assert(written > 0 && (size_t)written < message_size);
  (void)written;
  return ENDPOINT_REFUSAL_MESSAGE_NAMES_PARAM;
}

EndpointParamNameListStatus_t endpoint_appendParamNameListToRefusalMessage(const Endpoint_t* endpoint, unsigned int param_source, char* refusal_message, size_t refusal_message_size)
{
  assert(endpoint        != NULL);
  assert(refusal_message != NULL);

  size_t list_start = strlen(refusal_message);
  assert(list_start < refusal_message_size);

  size_t list_end            = list_start;
  int    appended_name_count = 0;
  for (int i = 0; i < endpoint->m_paramCount; i++)
  {
    const EndpointParam_t* param = &endpoint->mp_params[i];
    if (!(param->m_sources & param_source))
      continue;

    const char* separator = appended_name_count > 0 ? ", " : " ";
    int written = snprintf(refusal_message + list_end, refusal_message_size - list_end, "%s%s", separator, param->mp_spec->mp_name);
    if (written < 0 || (size_t)written >= refusal_message_size - list_end)
    {
      refusal_message[list_start] = '\0';
      return ENDPOINT_PARAM_NAME_LIST_TOO_LONG;
    }

    list_end += (size_t)written;
    appended_name_count++;
  }

  return appended_name_count > 0 ? ENDPOINT_PARAM_NAME_LIST_WRITTEN : ENDPOINT_PARAM_NAME_LIST_EMPTY;
}

enum {
  ENDPOINT_PACKAGE_FIELD_ECOSYSTEM = 0,
  ENDPOINT_PACKAGE_FIELD_NAME,
  ENDPOINT_PACKAGE_FIELD_VERSION,
  ENDPOINT_PACKAGE_FIELD_COUNT,
};

typedef struct {
  const char*             mp_memberName;
  char*                   mp_value;
  size_t                  m_valueSize;
  PackageElementProblem_t m_unreadValueProblem;
  bool                    m_isSeen;
  bool                    m_isRead;
} EndpointPackageField_t;

static bool static_readPackageFields(JsonReadSpan_t element_span, EndpointPackageField_t* fields, PackageElementProblem_t* member_problem_out)
{
  assert(fields             != NULL);
  assert(member_problem_out != NULL);

  *member_problem_out = PACKAGE_ELEMENT_PROBLEM_NONE;
  size_t           member_offset = 0;
  JsonReadSpan_t   key_span;
  JsonReadSpan_t   value_span;
  JsonReadStatus_t walk_status;
  while ((walk_status = jsonread_objectNextMember(element_span, &member_offset, &key_span, &value_span)) == JSONREAD_OK)
  {
    size_t i = 0;
    while (i < ENDPOINT_PACKAGE_FIELD_COUNT && !jsonread_isSpanEqual(key_span, fields[i].mp_memberName))
      i++;

    if (i == ENDPOINT_PACKAGE_FIELD_COUNT)
    {
      if (*member_problem_out == PACKAGE_ELEMENT_PROBLEM_NONE)
        *member_problem_out = PACKAGE_ELEMENT_PROBLEM_MEMBER_UNKNOWN;
      continue;
    }
    if (fields[i].m_isSeen)
    {
      if (*member_problem_out == PACKAGE_ELEMENT_PROBLEM_NONE)
        *member_problem_out = PACKAGE_ELEMENT_PROBLEM_MEMBER_REPEATED;
      continue;
    }

    fields[i].m_isSeen = true;
    fields[i].m_isRead = jsonread_spanToStrStatus(value_span, fields[i].mp_value, fields[i].m_valueSize) == JSONREAD_OK;
    if (!fields[i].m_isRead)
      fields[i].mp_value[0] = '\0';
  }
  return walk_status == JSONREAD_ERR_NOTFOUND;
}

static PackageElementProblem_t static_findPackageValueProblem(const PACKAGECHECKBULKItem_t* item, bool is_version_optional)
{
  assert(item != NULL);

  if (!validate_packageEcosystem(item->ma_ecosystem))
    return PACKAGE_ELEMENT_PROBLEM_ECOSYSTEM_UNKNOWN;
  if (item->ma_packageName[0] == '\0')
    return PACKAGE_ELEMENT_PROBLEM_NAME_EMPTY;
  if (static_hasControlChar(item->ma_packageName))
    return PACKAGE_ELEMENT_PROBLEM_NAME_CONTROL_CHAR;
  if (!validate_packageName(item->ma_packageName))
    return PACKAGE_ELEMENT_PROBLEM_NAME_SPACE;
  bool is_version_valid = is_version_optional ? validate_packageVersion(item->ma_version)
                                              : validate_packageExactVersion(item->ma_version);
  if (!is_version_valid)
    return PACKAGE_ELEMENT_PROBLEM_VERSION_INVALID;
  return PACKAGE_ELEMENT_PROBLEM_NONE;
}

static PackageElementProblem_t static_readPackageElement(JsonReadSpan_t element_span, bool is_version_optional, PACKAGECHECKBULKItem_t* item_out, bool* is_field_read_out)
{
  assert(item_out != NULL);
  memset(item_out, 0, sizeof(*item_out));
  EndpointPackageField_t fields[ENDPOINT_PACKAGE_FIELD_COUNT] = {
    [ENDPOINT_PACKAGE_FIELD_ECOSYSTEM] = { "ecosystem", item_out->ma_ecosystem,   sizeof(item_out->ma_ecosystem),   PACKAGE_ELEMENT_PROBLEM_ECOSYSTEM_NOT_TEXT, false, false },
    [ENDPOINT_PACKAGE_FIELD_NAME]      = { "name",      item_out->ma_packageName, sizeof(item_out->ma_packageName), PACKAGE_ELEMENT_PROBLEM_NAME_NOT_TEXT,      false, false },
    [ENDPOINT_PACKAGE_FIELD_VERSION]   = { "version",   item_out->ma_version,     sizeof(item_out->ma_version),     PACKAGE_ELEMENT_PROBLEM_VERSION_NOT_TEXT,   false, false },
  };

  PackageElementProblem_t member_problem;
  bool is_object = static_readPackageFields(element_span, fields, &member_problem);
  for (size_t i = 0; is_field_read_out != NULL && i < ENDPOINT_PACKAGE_FIELD_COUNT; i++)
    is_field_read_out[i] = is_object && fields[i].m_isRead;

  if (!is_object)
  {
    memset(item_out, 0, sizeof(*item_out));
    return PACKAGE_ELEMENT_PROBLEM_NOT_AN_OBJECT;
  }
  if (member_problem != PACKAGE_ELEMENT_PROBLEM_NONE)
    return member_problem;
  for (size_t i = 0; i < ENDPOINT_PACKAGE_FIELD_COUNT; i++)
  {
    if (fields[i].m_isSeen && !fields[i].m_isRead)
      return fields[i].m_unreadValueProblem;
  }
  return static_findPackageValueProblem(item_out, is_version_optional);
}

bool endpoint_tryReadPackageItem(JsonReadSpan_t element_span, PACKAGECHECKBULKItem_t* item_out)
{
  assert(item_out != NULL);

  return static_readPackageElement(element_span, false, item_out, NULL) == PACKAGE_ELEMENT_PROBLEM_NONE;
}

bool endpoint_readKeptPackageItems(const PACKAGECHECKBULKParams_t* bulk_params, int read_count, PACKAGECHECKBULKItem_t** items_out)
{
  assert(bulk_params != NULL);
  assert(items_out   != NULL);
  assert(read_count  >= 0);

  *items_out = NULL;
  if (read_count == 0)
    return true;

  PACKAGECHECKBULKItem_t* items = calloc((size_t)read_count, sizeof(PACKAGECHECKBULKItem_t));
  if (!items)
    return false;

  int    kept_count     = 0;
  size_t element_offset = 0;
  JsonReadSpan_t element_span;
  while (kept_count < read_count && jsonread_arrayNextElement(bulk_params->m_itemArraySpan, &element_offset, &element_span) == JSONREAD_OK)
  {
    if (endpoint_tryReadPackageItem(element_span, &items[kept_count]))
      kept_count++;
  }
  assert(kept_count == read_count);

  *items_out = items;
  return true;
}

static uint64_t static_hashPackage(const PACKAGECHECKBULKItem_t* item)
{
  uint64_t hash = 14695981039346656037ULL;
  for (const char* byte = item->ma_ecosystem; *byte != '\0'; byte++)
    hash = (hash ^ (unsigned char)tolower((unsigned char)*byte)) * 1099511628211ULL;
  hash *= 1099511628211ULL;
  for (const char* byte = item->ma_packageName; *byte != '\0'; byte++)
    hash = (hash ^ (unsigned char)*byte) * 1099511628211ULL;
  hash *= 1099511628211ULL;
  for (const char* byte = item->ma_version; *byte != '\0'; byte++)
    hash = (hash ^ (unsigned char)*byte) * 1099511628211ULL;
  return hash;
}

static bool static_isPackageRepeat(const PACKAGECHECKBULKItem_t* item, const PACKAGECHECKBULKItem_t* earlier_item)
{
  assert(item != NULL && earlier_item != NULL);
  return strcasecmp(item->ma_ecosystem, earlier_item->ma_ecosystem) == 0 &&
         strcmp(item->ma_packageName, earlier_item->ma_packageName) == 0 &&
         strcmp(item->ma_version, earlier_item->ma_version) == 0;
}

bool endpoint_readWatchlistPackageElements(const PACKAGECHECKBULKParams_t* package_list, WATCHLISTEDITPackageElement_t** elements_out)
{
  assert(package_list != NULL);
  assert(elements_out != NULL);
  assert(package_list->m_itemCount >= 0 && package_list->m_itemCount <= WATCHLIST_PACKAGE_ITEM_MAX_COUNT_PER_API_KEY);

  *elements_out = NULL;
  if (package_list->m_itemCount == 0)
    return true;

  WATCHLISTEDITPackageElement_t* elements = calloc((size_t)package_list->m_itemCount, sizeof(WATCHLISTEDITPackageElement_t));
  if (!elements)
    return false;

  uint64_t element_hashes[WATCHLIST_PACKAGE_ITEM_MAX_COUNT_PER_API_KEY];
  size_t   element_offset = 0;
  for (int i = 0; i < package_list->m_itemCount; i++)
  {
    WATCHLISTEDITPackageElement_t* element = &elements[i];
    bool                           is_member_read[ENDPOINT_PACKAGE_FIELD_COUNT] = { false, false, false };
    JsonReadSpan_t                 element_span;
    if (jsonread_arrayNextElement(package_list->m_itemArraySpan, &element_offset, &element_span) != JSONREAD_OK)
      element->m_problem = PACKAGE_ELEMENT_PROBLEM_NOT_AN_OBJECT;
    else
      element->m_problem = static_readPackageElement(element_span, true, &element->m_package, is_member_read);

    element->m_hasEcosystem = is_member_read[ENDPOINT_PACKAGE_FIELD_ECOSYSTEM];
    element->m_hasName      = is_member_read[ENDPOINT_PACKAGE_FIELD_NAME];
    element->m_hasVersion   = is_member_read[ENDPOINT_PACKAGE_FIELD_VERSION];
    element->m_earlierIndex = -1;

    if (element->m_problem != PACKAGE_ELEMENT_PROBLEM_NONE)
      continue;

    element_hashes[i] = static_hashPackage(&element->m_package);
    for (int earlier = 0; earlier < i; earlier++)
    {
      if (elements[earlier].m_problem == PACKAGE_ELEMENT_PROBLEM_NONE &&
          element_hashes[earlier] == element_hashes[i]                &&
          static_isPackageRepeat(&element->m_package, &elements[earlier].m_package))
      {
        element->m_problem      = PACKAGE_ELEMENT_PROBLEM_REPEATED;
        element->m_earlierIndex = earlier;
        break;
      }
    }
  }

  *elements_out = elements;
  return true;
}

static EndpointGateStatus_t static_readPackageItems(const EndpointParamSpec_t* spec, JsonReadSpan_t object_span, PACKAGECHECKBULKParams_t* packages_out, int* duplicate_item_index_out, int* original_item_index_out)
{
  assert((size_t)spec->m_max <= PACKAGECHECKBULK_MAX_ITEMS);

  JsonReadSpan_t       item_array_span;
  size_t               element_count;
  EndpointGateStatus_t array_status = static_readArrayMember(spec, object_span, &item_array_span, &element_count);
  if (array_status != ENDPOINT_GATE_OK)
    return array_status;

  uint64_t       item_hashes[PACKAGECHECKBULK_MAX_ITEMS];
  JsonReadSpan_t item_element_spans[PACKAGECHECKBULK_MAX_ITEMS];
  int            item_element_indexes[PACKAGECHECKBULK_MAX_ITEMS];
  packages_out->m_itemArraySpan          = item_array_span;
  packages_out->m_itemCount              = 0;
  packages_out->m_skippedItemCount       = 0;
  packages_out->m_notProcessedItemCount  = 0;
  size_t element_offset                  = 0;
  for (size_t i = 0; i < element_count; i++)
  {
    JsonReadSpan_t element_span;
    PACKAGECHECKBULKItem_t item;
    if (jsonread_arrayNextElement(item_array_span, &element_offset, &element_span) != JSONREAD_OK ||
        !endpoint_tryReadPackageItem(element_span, &item))
    {
      packages_out->m_skippedItemCount++;
      continue;
    }

    uint64_t item_hash = static_hashPackage(&item);
    for (int kept_index = 0; kept_index < packages_out->m_itemCount; kept_index++)
    {
      if (item_hashes[kept_index] != item_hash)
        continue;

      PACKAGECHECKBULKItem_t kept_item;
      bool is_kept_item_read = endpoint_tryReadPackageItem(item_element_spans[kept_index], &kept_item);
      assert(is_kept_item_read);
      (void)is_kept_item_read;

      if (static_isPackageRepeat(&item, &kept_item))
      {
        *duplicate_item_index_out = (int)i;
        *original_item_index_out  = item_element_indexes[kept_index];
        return ENDPOINT_GATE_REJECT_ITEMS_REPEATED;
      }
    }

    item_hashes[packages_out->m_itemCount]          = item_hash;
    item_element_spans[packages_out->m_itemCount]   = element_span;
    item_element_indexes[packages_out->m_itemCount] = (int)i;
    packages_out->m_itemCount++;
  }
  return ENDPOINT_GATE_OK;
}

static EndpointGateStatus_t static_readBulkArray(const EndpointParam_t* param, JsonReadSpan_t object_span, void* params_out, int* duplicate_item_index_out, int* original_item_index_out)
{
  char* params_field = (char*)params_out + param->m_offset;

  if (param->mp_spec->m_type == ENDPOINT_PARAM_TYPE_PACKAGE_ARRAY)
  {
    assert(param->m_size == sizeof(PACKAGECHECKBULKParams_t));
    return static_readPackageItems(param->mp_spec, object_span, (PACKAGECHECKBULKParams_t*)params_field, duplicate_item_index_out, original_item_index_out);
  }
  assert(endpoint_isIdArrayType(param->mp_spec->m_type) && param->m_size == sizeof(BulkIdsParams_t));
  
  return static_readBulkIds(param->mp_spec, object_span, (BulkIdsParams_t*)params_field, duplicate_item_index_out, original_item_index_out);
}

static EndpointGateStatus_t static_locatePackageArray(const EndpointParam_t* param, JsonReadSpan_t object_span, PACKAGECHECKBULKParams_t* package_list_out)
{
  const EndpointParamSpec_t* spec = param->mp_spec;
  assert(spec->m_type == ENDPOINT_PARAM_TYPE_PACKAGE_ARRAY);

  JsonReadSpan_t   array_span;
  JsonReadStatus_t key_status = jsonread_objectKey(object_span, spec->mp_name, &array_span);
  if (key_status == JSONREAD_ERR_NOTFOUND)
    return param->m_isRequired ? ENDPOINT_GATE_REJECT_MISSING : ENDPOINT_GATE_OK;
  else if (key_status != JSONREAD_OK)
    return ENDPOINT_GATE_REJECT_BODY;

  size_t               element_count;
  EndpointGateStatus_t count_status = static_countArrayElements(spec, array_span, &element_count);
  if (count_status != ENDPOINT_GATE_OK)
    return count_status;

  package_list_out->m_itemArraySpan = array_span;
  package_list_out->m_itemCount     = (int)element_count;
  return ENDPOINT_GATE_OK;
}

static int static_findBulkArrayParamIndex(const Endpoint_t* endpoint, unsigned int param_source);

static EndpointGateStatus_t static_readRestQueryParam(const EndpointParam_t* param, const char* query, char* params_field)
{
  const EndpointParamSpec_t* spec = param->mp_spec;

  char   scalar_value_buf[ENDPOINT_SCALAR_VALUE_BUF_SIZE];
  char*  value;
  size_t value_size;
  if (static_isParamTypeText(spec->m_type))
  {
    assert(spec->m_maxLen < param->m_size);
    value      = params_field;
    value_size = spec->m_maxLen + 1;
  }
  else
  {
    value      = scalar_value_buf;
    value_size = sizeof(scalar_value_buf);
  }

  QueryStatus_t query_status = query_paramGetStatus(query, spec->mp_name, value, value_size);
  if (query_status == QUERY_TOOLONG)
    return ENDPOINT_GATE_REJECT_TOOLONG;
  else if (query_status == QUERY_BADENCODING)
    return ENDPOINT_GATE_REJECT_ENCODING;
  else if (query_status == QUERY_NUL)
    return ENDPOINT_GATE_REJECT_CONTROL_CHAR;
  else if (query_status == QUERY_NOTFOUND)
    return param->m_isRequired ? ENDPOINT_GATE_REJECT_MISSING : ENDPOINT_GATE_OK;
  else if (param->m_isRequired && *value == '\0')
    return ENDPOINT_GATE_REJECT_MISSING;

  return static_checkParamValueAndWriteToParamsField(param, value, params_field);
}

static int static_findRestQueryParamIndex(const Endpoint_t* endpoint, const QueryParamName_t* param_name)
{
  for (int i = 0; i < endpoint->m_paramCount; i++)
  {
    const EndpointParam_t* param = &endpoint->mp_params[i];
    if (!(param->m_sources & ENDPOINT_PARAM_SRC_REST_QUERY))
      continue;

    if (bytes_isEqual(param_name->mp_start, param_name->m_len, param->mp_spec->mp_name, false))
      return i;
  }
  return -1;
}

EndpointGateResult_t endpoint_checkHttpQueryParamNames(const Endpoint_t* endpoint, const char* query)
{
  assert(endpoint != NULL);
  assert(query    != NULL);
  assert(endpoint->m_paramCount <= ENDPOINT_MAX_PARAMS);

  EndpointGateResult_t result = { .m_status = ENDPOINT_GATE_OK, .m_refusedParamIndex = -1 };
  unsigned int seen_mask = 0;
  size_t offset = 0;
  QueryParamName_t param_name;
  while (query_nextParamName(query, &offset, &param_name))
  {
    if (!param_name.m_hasValue || param_name.m_len == 0)
    {
      result.m_status = ENDPOINT_GATE_REJECT_MALFORMED_PARAM;
      return result;
    }

    int index = static_findRestQueryParamIndex(endpoint, &param_name);
    if (index < 0)
    {
      result.m_status = ENDPOINT_GATE_REJECT_UNKNOWN_PARAM_NAME;
      return result;
    }

    unsigned int bit = 1u << index;
    if (seen_mask & bit)
    {
      result.m_status = ENDPOINT_GATE_REJECT_DUPLICATE_PARAM_NAME;
      result.m_refusedParamIndex = index;
      return result;
    }
    seen_mask |= bit;
  }

  return result;
}

EndpointGateResult_t endpoint_restQueryGate(const Endpoint_t* endpoint, const char* query, void* params_out, size_t params_size)
{
  assert(endpoint   != NULL);
  assert(query      != NULL);
  assert(params_out != NULL);
  assert(params_size == endpoint->m_paramsSize);
  (void)params_size;

  for (int i = 0; i < endpoint->m_paramCount; i++)
  {
    const EndpointParam_t* param = &endpoint->mp_params[i];
    if (!(param->m_sources & ENDPOINT_PARAM_SRC_REST_QUERY))
      continue;

    assert(param->m_size > 0 && param->m_offset + param->m_size <= params_size);
    static_writeDefaultToParamsField(param, (char*)params_out + param->m_offset);
  }

  EndpointGateResult_t result = endpoint_checkHttpQueryParamNames(endpoint, query);
  if (result.m_status != ENDPOINT_GATE_OK)
    return result;

  for (int i = 0; i < endpoint->m_paramCount; i++)
  {
    const EndpointParam_t* param = &endpoint->mp_params[i];
    if (!(param->m_sources & ENDPOINT_PARAM_SRC_REST_QUERY))
      continue;

    EndpointGateStatus_t status = static_readRestQueryParam(param, query, (char*)params_out + param->m_offset);
    if (status != ENDPOINT_GATE_OK)
    {
      result.m_status = status;
      result.m_refusedParamIndex = i;
      return result;
    }
  }

  return result;
}

static int static_findRestPathSegmentParamIndex(const Endpoint_t* endpoint)
{
  for (int i = 0; i < endpoint->m_paramCount; i++)
  {
    if (endpoint->mp_params[i].m_sources & ENDPOINT_PARAM_SRC_REST_PATH_SEGMENT)
      return i;
  }
  return -1;
}

static EndpointGateStatus_t static_decodePathSegment(const char* path_segment, size_t segment_len, size_t field_size, char* decoded_out, size_t decoded_out_size)
{
  assert(field_size <= decoded_out_size);
  (void)decoded_out_size;

  switch (query_percentDecode(path_segment, segment_len, false, decoded_out, field_size))
  {
    case QUERY_OK:          return ENDPOINT_GATE_OK;
    case QUERY_TOOLONG:     return ENDPOINT_GATE_REJECT_VALUE;
    case QUERY_BADENCODING: return ENDPOINT_GATE_REJECT_ENCODING;
    case QUERY_NUL:         return ENDPOINT_GATE_REJECT_CONTROL_CHAR;
    case QUERY_NOTFOUND:    break;
  }
  assert(false && "query_percentDecode never answers QUERY_NOTFOUND");
  return ENDPOINT_GATE_REJECT_VALUE;
}

EndpointGateResult_t endpoint_restPathSegmentGate(const Endpoint_t* endpoint, const char* path_segment, void* params_out, size_t params_size)
{
  assert(endpoint != NULL);
  assert(endpoint->m_hasPathSegment);
  assert(params_out != NULL);
  assert(params_size == endpoint->m_paramsSize);
  (void)params_size;

  int segment_param_index = static_findRestPathSegmentParamIndex(endpoint);
  assert(segment_param_index >= 0);

  const EndpointParam_t* param = &endpoint->mp_params[segment_param_index];
  assert(static_isParamTypeText(param->mp_spec->m_type));
  assert(param->m_size > 0 && param->m_offset + param->m_size <= params_size);

  EndpointGateResult_t result = { .m_status = ENDPOINT_GATE_OK, .m_refusedParamIndex = -1 };
  size_t      segment_len   = path_segment != NULL ? strlen(path_segment) : 0;
  const char* segment_value = path_segment;
  char decoded_segment[REQUEST_TARGET_MAX_LEN + 1];
  if (segment_len == 0)
    result.m_status = ENDPOINT_GATE_REJECT_MISSING;
  else if (param->mp_spec->m_isPathSegmentPercentDecoded)
  {
    result.m_status = static_decodePathSegment(path_segment, segment_len, param->m_size, decoded_segment, sizeof(decoded_segment));
    segment_value   = decoded_segment;
    segment_len     = strlen(decoded_segment);
  }
  else if (segment_len >= param->m_size)
    result.m_status = ENDPOINT_GATE_REJECT_VALUE;

  if (result.m_status == ENDPOINT_GATE_OK)
    result.m_status = static_checkParamValueAndWriteToParamsField(param, segment_value, NULL);

  if (result.m_status != ENDPOINT_GATE_OK)
  {
    result.m_refusedParamIndex = segment_param_index;
    return result;
  }

  memcpy((char*)params_out + param->m_offset, segment_value, segment_len + 1);
  static_applyLowerCase(param->mp_spec, (char*)params_out + param->m_offset);
  return result;
}

static EndpointGateResult_t static_gateRefusal(EndpointGateStatus_t status, int param_index)
{
  EndpointGateResult_t result = { .m_status = status, .m_refusedParamIndex = param_index };
  return result;
}

EndpointGateResult_t endpoint_restBulkBodyGate(const Endpoint_t* endpoint, const char* body, void* params_out, size_t params_size)
{
  assert(endpoint   != NULL);
  assert(params_out != NULL);
  assert(params_size == endpoint->m_paramsSize);
  (void)params_size;

  int array_param_index = static_findBulkArrayParamIndex(endpoint, ENDPOINT_PARAM_SRC_REST_BODY);
  assert(array_param_index >= 0);

  const EndpointParam_t* param = &endpoint->mp_params[array_param_index];
  assert(param->m_offset + param->m_size <= params_size);

  if (body == NULL || *body == '\0')
    return static_gateRefusal(ENDPOINT_GATE_REJECT_MISSING, array_param_index);

  size_t body_len = strlen(body);
  if (!utf8_isTextValid(body, body_len))
    return static_gateRefusal(ENDPOINT_GATE_REJECT_BODY, array_param_index);

  JsonReadSpan_t root_span;
  if (jsonread_root(body, body_len, &root_span) != JSONREAD_OK)
    return static_gateRefusal(ENDPOINT_GATE_REJECT_BODY, array_param_index);
  if (root_span.m_len >= endpoint_jsonObjectSizeLimit(endpoint))
    return static_gateRefusal(ENDPOINT_GATE_REJECT_BODY_TOO_LARGE, array_param_index);

  EndpointGateResult_t result = { .m_status = ENDPOINT_GATE_OK, .m_refusedParamIndex = -1 };
  result.m_status = static_readBulkArray(param, root_span, params_out, &result.m_duplicateItemIndex, &result.m_originalItemIndex);
  if (result.m_status != ENDPOINT_GATE_OK && result.m_status != ENDPOINT_GATE_REJECT_UNKNOWN_PARAM_NAME)
    result.m_refusedParamIndex = array_param_index;

  return result;
}

bool endpoint_isIdArrayType(EndpointParamType_t type)
{
  return type == ENDPOINT_PARAM_TYPE_CVE_ID_ARRAY || type == ENDPOINT_PARAM_TYPE_FILE_HASH_ARRAY;
}

const char* endpoint_jsonSchemaTypeName(EndpointParamType_t type)
{
  switch (type)
  {
    case ENDPOINT_PARAM_TYPE_STRING:
    case ENDPOINT_PARAM_TYPE_ENUM:
    case ENDPOINT_PARAM_TYPE_CVE_ID:
    case ENDPOINT_PARAM_TYPE_CWE_ID:
      return "string";
    case ENDPOINT_PARAM_TYPE_INT:
      return "integer";
    case ENDPOINT_PARAM_TYPE_DOUBLE:
      return "number";
    case ENDPOINT_PARAM_TYPE_BOOL:
    case ENDPOINT_PARAM_TYPE_KEV_FILTER:
      return "boolean";
    case ENDPOINT_PARAM_TYPE_CVE_ID_ARRAY:
    case ENDPOINT_PARAM_TYPE_FILE_HASH_ARRAY:
    case ENDPOINT_PARAM_TYPE_PACKAGE_ARRAY:
      return "array";
    case ENDPOINT_PARAM_TYPE_BYTES:
      break;
  }

  return "string";
}

bool endpoint_isBulkArrayType(EndpointParamType_t type)
{
  return endpoint_isIdArrayType(type) || type == ENDPOINT_PARAM_TYPE_PACKAGE_ARRAY;
}

void endpoint_appendSchemaBounds(const EndpointParamSpec_t* spec, JsonBuf_t* json_buf)
{
  if (spec->m_type == ENDPOINT_PARAM_TYPE_INT || spec->m_type == ENDPOINT_PARAM_TYPE_DOUBLE)
  {
    jsonbuf_appendFormat(json_buf, ",\"minimum\":%.17g", spec->m_min);
    if (spec->m_max != INT_MAX)
      jsonbuf_appendFormat(json_buf, ",\"maximum\":%.17g", spec->m_max);
    if (spec->m_default != -1.0)
      jsonbuf_appendFormat(json_buf, ",\"default\":%.17g", spec->m_default);
  }

  if (strcmp(endpoint_jsonSchemaTypeName(spec->m_type), "string") == 0)
    jsonbuf_appendFormat(json_buf, ",\"maxLength\":%zu", spec->m_maxLen);

  if (endpoint_isBulkArrayType(spec->m_type))
    jsonbuf_appendFormat(json_buf, ",\"minItems\":1,\"maxItems\":%lld", (long long)spec->m_max);
}

size_t endpoint_jsonObjectSizeLimit(const Endpoint_t* endpoint)
{
  assert(endpoint != NULL);

  int array_param_index = static_findBulkArrayParamIndex(endpoint, ENDPOINT_PARAM_SRC_REST_BODY | ENDPOINT_PARAM_SRC_MCP_ARG);
  if (array_param_index >= 0 && endpoint->mp_params[array_param_index].mp_spec->m_type == ENDPOINT_PARAM_TYPE_PACKAGE_ARRAY)
    return PACKAGECHECKBULK_JSON_OBJECT_BUF_SIZE;

  return ENDPOINT_JSON_OBJECT_BUF_SIZE;
}

bool endpoint_hasRestBodyParam(const Endpoint_t* endpoint)
{
  assert(endpoint != NULL);

  for (int i = 0; i < endpoint->m_paramCount; i++)
  {
    if (endpoint->mp_params[i].m_sources & ENDPOINT_PARAM_SRC_REST_BODY)
      return true;
  }
  return false;
}

bool endpoint_hasPackageArrayWithOtherMembers(const Endpoint_t* endpoint)
{
  assert(endpoint != NULL);

  int  body_param_count = 0;
  bool has_bulk_array   = false;
  for (int i = 0; i < endpoint->m_paramCount; i++)
  {
    const EndpointParam_t* param = &endpoint->mp_params[i];
    if (!(param->m_sources & ENDPOINT_PARAM_SRC_REST_BODY))
      continue;
    body_param_count++;
    if (endpoint_isBulkArrayType(param->mp_spec->m_type))
      has_bulk_array = true;
  }
  return has_bulk_array && body_param_count > 1;
}

static int static_findRawBodyParamIndex(const Endpoint_t* endpoint)
{
  for (int i = 0; i < endpoint->m_paramCount; i++)
  {
    if (endpoint->mp_params[i].m_sources & ENDPOINT_PARAM_SRC_REST_RAW_BODY)
      return i;
  }
  return -1;
}

size_t endpoint_rawBodyByteLimit(const Endpoint_t* endpoint)
{
  assert(endpoint != NULL);

  int raw_body_param_index = static_findRawBodyParamIndex(endpoint);
  assert(raw_body_param_index >= 0);

  return endpoint->mp_params[raw_body_param_index].mp_spec->m_maxLen;
}

static bool static_isHeaderNamed(const struct phr_header* header, const char* name)
{
  size_t name_len = strlen(name);
  return header->name != NULL && header->name_len == name_len && strncasecmp(header->name, name, name_len) == 0;
}

static EndpointGateStatus_t static_readRestHeaderParam(const EndpointParam_t* param, const struct phr_header* headers, size_t header_count, char* params_field)
{
  const EndpointParamSpec_t* spec = param->mp_spec;
  assert(spec->m_type == ENDPOINT_PARAM_TYPE_STRING);
  assert(spec->m_maxLen < param->m_size);

  const struct phr_header* found = NULL;
  bool is_after_found = false;
  for (size_t i = 0; i < header_count; i++)
  {
    bool is_continuation = headers[i].name == NULL;
    bool is_named        = static_isHeaderNamed(&headers[i], spec->mp_name);
    if ((is_named && found != NULL) || (is_continuation && is_after_found))
      return ENDPOINT_GATE_REJECT_DUPLICATE_PARAM_NAME;
    if (is_named)
      found = &headers[i];
    if (!is_continuation)
      is_after_found = is_named;
  }

  if (found == NULL)
    return param->m_isRequired ? ENDPOINT_GATE_REJECT_MISSING : ENDPOINT_GATE_OK;
  if (found->value_len > spec->m_maxLen)
    return ENDPOINT_GATE_REJECT_TOOLONG;

  memcpy(params_field, found->value, found->value_len);
  params_field[found->value_len] = '\0';
  if (param->m_isRequired && found->value_len == 0)
    return ENDPOINT_GATE_REJECT_MISSING;

  return static_checkParamValueAndWriteToParamsField(param, params_field, params_field);
}

static EndpointGateResult_t static_restHeaderGate(const Endpoint_t* endpoint, const EndpointRestInput_t* input, void* params_out, size_t params_size)
{
  assert(input->mp_headers != NULL || input->m_headerCount == 0);
  (void)params_size;

  EndpointGateResult_t result = { .m_status = ENDPOINT_GATE_OK, .m_refusedParamIndex = -1 };
  for (int i = 0; i < endpoint->m_paramCount; i++)
  {
    const EndpointParam_t* param = &endpoint->mp_params[i];
    if (!(param->m_sources & ENDPOINT_PARAM_SRC_REST_HEADER))
      continue;

    assert(param->m_size > 0 && param->m_offset + param->m_size <= params_size);
    char* params_field = (char*)params_out + param->m_offset;
    static_writeDefaultToParamsField(param, params_field);
    EndpointGateStatus_t status = static_readRestHeaderParam(param, input->mp_headers, input->m_headerCount, params_field);
    if (status != ENDPOINT_GATE_OK)
    {
      result.m_status = status;
      result.m_refusedParamIndex = i;
      return result;
    }
  }
  return result;
}

bool endpoint_hasRawBodyParam(const Endpoint_t* endpoint)
{
  assert(endpoint != NULL);

  return static_findRawBodyParamIndex(endpoint) >= 0;
}

EndpointGateResult_t endpoint_restRequestGate(const Endpoint_t* endpoint, const EndpointRestInput_t* input, void* params_out, size_t params_size)
{
  assert(endpoint != NULL);
  assert(input != NULL);
  assert(input->m_body.mp_bytes != NULL || input->m_body.m_byteCount == 0);

  EndpointGateResult_t header_result = static_restHeaderGate(endpoint, input, params_out, params_size);
  if (header_result.m_status != ENDPOINT_GATE_OK)
    return header_result;

  if (endpoint_hasRawBodyParam(endpoint))
  {
    int raw_body_param_index = static_findRawBodyParamIndex(endpoint);
    const EndpointParam_t* param = &endpoint->mp_params[raw_body_param_index];
    if (input->m_body.m_byteCount == 0 && param->m_isRequired)
    {
      EndpointGateResult_t result = { .m_status = ENDPOINT_GATE_REJECT_MISSING, .m_refusedParamIndex = raw_body_param_index };
      return result;
    }
    assert(param->m_size == sizeof(EndpointByteSpan_t) && param->m_offset + param->m_size <= params_size);
    (void)params_size;
    
    EndpointByteSpan_t* bytes = (EndpointByteSpan_t*)((char*)params_out + param->m_offset);
    *bytes = input->m_body;
    
    EndpointGateResult_t result = { .m_status = ENDPOINT_GATE_OK, .m_refusedParamIndex = -1 };
    return result;
  }

  if (endpoint->m_hasPathSegment)
  {
    EndpointGateResult_t result = endpoint_restPathSegmentGate(endpoint, input->mp_pathSegment, params_out, params_size);
    if (result.m_status != ENDPOINT_GATE_OK)
      return result;
  }

  if (!endpoint_hasRestBodyParam(endpoint))
    return endpoint_restQueryGate(endpoint, input->mp_query, params_out, params_size);

  const char* body = (const char*)input->m_body.mp_bytes;
  if (!endpoint_hasPackageArrayWithOtherMembers(endpoint) && static_findBulkArrayParamIndex(endpoint, ENDPOINT_PARAM_SRC_REST_BODY) >= 0)
    return endpoint_restBulkBodyGate(endpoint, body, params_out, params_size);

  return endpoint_restFieldsBodyGate(endpoint, body, params_out, params_size);
}

static int static_findBulkArrayParamIndex(const Endpoint_t* endpoint, unsigned int param_source)
{
  for (int i = 0; i < endpoint->m_paramCount; i++)
  {
    const EndpointParam_t* param = &endpoint->mp_params[i];
    if ((param->m_sources & param_source) && endpoint_isBulkArrayType(param->mp_spec->m_type))
      return i;
  }
  return -1;
}

static int static_findObjectMemberParamIndex(const Endpoint_t* endpoint, unsigned int param_source, JsonReadSpan_t key_span)
{
  for (int i = 0; i < endpoint->m_paramCount; i++)
  {
    const EndpointParam_t* param = &endpoint->mp_params[i];
    if (!(param->m_sources & param_source))
      continue;

    const char* spec_name = param->mp_spec->mp_name;
    if (jsonread_isSpanEqual(key_span, spec_name))
      return i;
  }
  return -1;
}

static EndpointGateResult_t static_checkObjectMemberNames(const Endpoint_t* endpoint, unsigned int param_source, JsonReadSpan_t object_span)
{
  EndpointGateResult_t result = { .m_status = ENDPOINT_GATE_OK, .m_refusedParamIndex = -1 };
  unsigned int seen_mask = 0;
  size_t member_offset = 0;
  for (;;)
  {
    JsonReadSpan_t key_span;
    JsonReadSpan_t value_span;
    JsonReadStatus_t walk_status = jsonread_objectNextMember(object_span, &member_offset, &key_span, &value_span);
    if (walk_status == JSONREAD_ERR_NOTFOUND)
      break;
    else if (walk_status != JSONREAD_OK)
    {
      result.m_status = ENDPOINT_GATE_REJECT_BODY;
      return result;
    }

    int param_index = static_findObjectMemberParamIndex(endpoint, param_source, key_span);
    if (param_index < 0)
    {
      result.m_status = ENDPOINT_GATE_REJECT_UNKNOWN_PARAM_NAME;
      return result;
    }

    unsigned int bit = 1u << param_index;
    if (seen_mask & bit)
    {
      result.m_status = ENDPOINT_GATE_REJECT_DUPLICATE_PARAM_NAME;
      result.m_refusedParamIndex = param_index;
      return result;
    }
    seen_mask |= bit;

    bool is_bulk_array = endpoint_isBulkArrayType(endpoint->mp_params[param_index].mp_spec->m_type);
    if (!is_bulk_array && value_span.m_len > 0 && (value_span.mp_start[0] == '{' || value_span.mp_start[0] == '['))
    {
      result.m_status = ENDPOINT_GATE_REJECT_OBJECT_OR_ARRAY_VALUE;
      result.m_refusedParamIndex = param_index;
      return result;
    }
  }

  return result;
}

static EndpointGateStatus_t static_readObjectTextMember(const EndpointParam_t* param, const char* object_buf, char* params_field)
{
  const EndpointParamSpec_t* spec = param->mp_spec;
  assert(spec->m_maxLen < param->m_size);

  JsonReadStatus_t read_status = jsonread_strStatus(object_buf, spec->mp_name, params_field, spec->m_maxLen + 1);
  if (read_status == JSONREAD_ERR_NOTFOUND)
    return param->m_isRequired ? ENDPOINT_GATE_REJECT_MISSING : ENDPOINT_GATE_OK;
  else if (read_status == JSONREAD_ERR_TOOLONG)
    return (param->m_sources & ENDPOINT_PARAM_SRC_REST_PATH_SEGMENT) ? ENDPOINT_GATE_REJECT_VALUE : ENDPOINT_GATE_REJECT_TOOLONG;
  else if (read_status == JSONREAD_ERR_SYNTAX)
    return ENDPOINT_GATE_REJECT_ESCAPE;
  else if (read_status == JSONREAD_ERR_NUL)
    return ENDPOINT_GATE_REJECT_CONTROL_CHAR;
  else if (read_status == JSONREAD_ERR_LONE_SURROGATE)
    return ENDPOINT_GATE_REJECT_INVALID_UTF8;
  else if (read_status != JSONREAD_OK)
    return ENDPOINT_GATE_REJECT_TYPE;
  else if (param->m_isRequired && *params_field == '\0')
    return ENDPOINT_GATE_REJECT_MISSING;

  return static_checkParamValueAndWriteToParamsField(param, params_field, params_field);
}

static EndpointGateStatus_t static_readObjectScalarMember(const EndpointParam_t* param, const char* object_buf, char* params_field)
{
  const EndpointParamSpec_t* spec = param->mp_spec;

  JsonReadSpan_t object_span = { .mp_start = object_buf, .m_len = strlen(object_buf) };
  JsonReadSpan_t value_span;
  if (jsonread_objectKey(object_span, spec->mp_name, &value_span) == JSONREAD_OK &&
      value_span.m_len >= ENDPOINT_SCALAR_VALUE_BUF_SIZE)
  {
    return ENDPOINT_GATE_REJECT_TOOLONG;
  }

  JsonReadStatus_t read_status;
  if (spec->m_type == ENDPOINT_PARAM_TYPE_INT)
  {
    long value = 0;
    read_status = jsonread_intStatus(object_buf, spec->mp_name, &value);
    if (read_status == JSONREAD_OK)
      return static_checkIntBoundsAndWriteToParamsField(param, value, params_field);
  }
  else if (spec->m_type == ENDPOINT_PARAM_TYPE_DOUBLE)
  {
    double value = 0.0;
    read_status = jsonread_doubleStatus(object_buf, spec->mp_name, &value);
    if (read_status == JSONREAD_OK)
      return static_checkDoubleBoundsAndWriteToParamsField(param, value, params_field);
  }
  else
  {
    assert(spec->m_type == ENDPOINT_PARAM_TYPE_BOOL || spec->m_type == ENDPOINT_PARAM_TYPE_KEV_FILTER);
    bool value = false;
    read_status = jsonread_boolStatus(object_buf, spec->mp_name, &value);
    if (read_status == JSONREAD_OK)
      return static_checkBoolAndWriteToParamsField(param, value, params_field);
  }

  if (read_status == JSONREAD_ERR_NOTFOUND)
    return param->m_isRequired ? ENDPOINT_GATE_REJECT_MISSING : ENDPOINT_GATE_OK;
  return ENDPOINT_GATE_REJECT_VALUE;
}

static JsonReadStatus_t static_fillFlatGetterBuffer(const Endpoint_t* endpoint, unsigned int param_source, JsonReadSpan_t object_span, char* object_buf, size_t object_buf_size)
{
  if (!endpoint_hasPackageArrayWithOtherMembers(endpoint))
    return jsonread_spanToRawStringStatus(object_span, object_buf, object_buf_size);

  int array_param_index = static_findBulkArrayParamIndex(endpoint, param_source);
  assert(array_param_index >= 0);
  const char* array_name = endpoint->mp_params[array_param_index].mp_spec->mp_name;
  assert(object_buf_size >= sizeof("{}"));

  size_t           used          = 0;
  size_t           member_offset = 0;
  JsonReadSpan_t   key_span;
  JsonReadSpan_t   value_span;
  JsonReadStatus_t walk_status;
  object_buf[used++] = '{';
  while ((walk_status = jsonread_objectNextMember(object_span, &member_offset, &key_span, &value_span)) == JSONREAD_OK)
  {
    if (jsonread_isSpanEqual(key_span, array_name))
      continue;

    size_t comma_len  = used > 1 ? 1 : 0;
    size_t member_len = comma_len + key_span.m_len + sizeof("\"\":") - 1 + value_span.m_len;
    if (member_len + 2 > object_buf_size - used)
      return JSONREAD_ERR_TOOLONG;

    if (comma_len > 0)
      object_buf[used++] = ',';
    object_buf[used++] = '"';
    memcpy(object_buf + used, key_span.mp_start, key_span.m_len);
    used += key_span.m_len;
    object_buf[used++] = '"';
    object_buf[used++] = ':';
    memcpy(object_buf + used, value_span.mp_start, value_span.m_len);
    used += value_span.m_len;
  }
  if (walk_status != JSONREAD_ERR_NOTFOUND)
    return walk_status;

  object_buf[used++] = '}';
  object_buf[used]   = '\0';
  return JSONREAD_OK;
}

static EndpointGateResult_t static_readObjectMembersIntoParams(const Endpoint_t* endpoint, unsigned int param_source, JsonReadSpan_t object_span, const char* object_buf, void* params_out)
{
  EndpointGateResult_t result = static_checkObjectMemberNames(endpoint, param_source, object_span);
  if (result.m_status != ENDPOINT_GATE_OK)
    return result;

  for (int i = 0; i < endpoint->m_paramCount; i++)
  {
    const EndpointParam_t* param = &endpoint->mp_params[i];
    if (!(param->m_sources & param_source))
      continue;

    char* params_field = (char*)params_out + param->m_offset;
    EndpointGateStatus_t status;
    if (static_isParamTypeText(param->mp_spec->m_type))
      status = static_readObjectTextMember(param, object_buf, params_field);
    else if (endpoint_isBulkArrayType(param->mp_spec->m_type))
    {
      assert(endpoint_hasPackageArrayWithOtherMembers(endpoint));
      assert(param->m_size == sizeof(PACKAGECHECKBULKParams_t));
      status = static_locatePackageArray(param, object_span, (PACKAGECHECKBULKParams_t*)params_field);
    }
    else
      status = static_readObjectScalarMember(param, object_buf, params_field);

    if (status != ENDPOINT_GATE_OK)
    {
      result.m_status            = status;
      result.m_refusedParamIndex = i;
      return result;
    }
  }

  return result;
}

EndpointGateResult_t endpoint_mcpArgsGate(const Endpoint_t* endpoint, JsonReadSpan_t args_span, void* params_out, size_t params_size)
{
  assert(endpoint != NULL);
  assert(args_span.m_len == 0 || args_span.mp_start != NULL);
  assert(params_out != NULL || params_size == 0);
  assert(params_size == endpoint->m_paramsSize);
  (void)params_size;
  assert(endpoint->m_paramCount <= ENDPOINT_MAX_PARAMS);

  for (int i = 0; i < endpoint->m_paramCount; i++)
  {
    const EndpointParam_t* param = &endpoint->mp_params[i];
    if (!(param->m_sources & ENDPOINT_PARAM_SRC_MCP_ARG))
      continue;

    assert(param->m_size > 0 && param->m_offset + param->m_size <= params_size);
    static_writeDefaultToParamsField(param, (char*)params_out + param->m_offset);
  }

  EndpointGateResult_t result = { .m_status = ENDPOINT_GATE_OK, .m_refusedParamIndex = -1 };
  if (args_span.m_len >= endpoint_jsonObjectSizeLimit(endpoint))
  {
    result.m_status = ENDPOINT_GATE_REJECT_BODY_TOO_LARGE;
    return result;
  }
  if (args_span.m_len == 0 || args_span.mp_start[0] != '{')
  {
    result.m_status = ENDPOINT_GATE_REJECT_BODY;
    return result;
  }

  int array_param_index = static_findBulkArrayParamIndex(endpoint, ENDPOINT_PARAM_SRC_MCP_ARG);
  if (!endpoint_hasPackageArrayWithOtherMembers(endpoint) && array_param_index >= 0)
  {
    const EndpointParam_t* param = &endpoint->mp_params[array_param_index];

    result.m_status = static_readBulkArray(param, args_span, params_out, &result.m_duplicateItemIndex, &result.m_originalItemIndex);
    if (result.m_status != ENDPOINT_GATE_OK && result.m_status != ENDPOINT_GATE_REJECT_UNKNOWN_PARAM_NAME)
      result.m_refusedParamIndex = array_param_index;

    return result;
  }

  assert(endpoint_hasPackageArrayWithOtherMembers(endpoint) || endpoint_jsonObjectSizeLimit(endpoint) == ENDPOINT_JSON_OBJECT_BUF_SIZE);
  char args_buf[ENDPOINT_JSON_OBJECT_BUF_SIZE];
  JsonReadStatus_t copy_status = static_fillFlatGetterBuffer(endpoint, ENDPOINT_PARAM_SRC_MCP_ARG, args_span, args_buf, sizeof(args_buf));
  if (copy_status == JSONREAD_ERR_TOOLONG)
    result.m_status = ENDPOINT_GATE_REJECT_BODY_TOO_LARGE;
  else if (copy_status != JSONREAD_OK)
    result.m_status = ENDPOINT_GATE_REJECT_BODY;
  if (result.m_status != ENDPOINT_GATE_OK)
    return result;

  return static_readObjectMembersIntoParams(endpoint, ENDPOINT_PARAM_SRC_MCP_ARG, args_span, args_buf, params_out);
}

EndpointGateResult_t endpoint_restFieldsBodyGate(const Endpoint_t* endpoint, const char* body, void* params_out, size_t params_size)
{
  assert(endpoint   != NULL);
  assert(params_out != NULL);
  assert(params_size == endpoint->m_paramsSize);
  (void)params_size;
  assert(endpoint->m_paramCount <= ENDPOINT_MAX_PARAMS);
  assert(endpoint_hasPackageArrayWithOtherMembers(endpoint) || static_findBulkArrayParamIndex(endpoint, ENDPOINT_PARAM_SRC_REST_BODY) < 0);

  for (int i = 0; i < endpoint->m_paramCount; i++)
  {
    const EndpointParam_t* param = &endpoint->mp_params[i];
    if (!(param->m_sources & ENDPOINT_PARAM_SRC_REST_BODY))
      continue;

    assert(param->m_size > 0 && param->m_offset + param->m_size <= params_size);
    static_writeDefaultToParamsField(param, (char*)params_out + param->m_offset);
  }

  if (body == NULL || *body == '\0')
    return static_gateRefusal(ENDPOINT_GATE_REJECT_BODY, -1);

  size_t body_len = strlen(body);
  if (!utf8_isTextValid(body, body_len))
    return static_gateRefusal(ENDPOINT_GATE_REJECT_BODY, -1);

  JsonReadSpan_t object_span;
  if (jsonread_root(body, body_len, &object_span) != JSONREAD_OK)
    return static_gateRefusal(ENDPOINT_GATE_REJECT_BODY, -1);
  if (object_span.m_len >= endpoint_jsonObjectSizeLimit(endpoint))
    return static_gateRefusal(ENDPOINT_GATE_REJECT_BODY_TOO_LARGE, -1);
  if (object_span.mp_start[0] != '{')
    return static_gateRefusal(ENDPOINT_GATE_REJECT_BODY, -1);

  char object_buf[ENDPOINT_JSON_OBJECT_BUF_SIZE];
  JsonReadStatus_t copy_status = static_fillFlatGetterBuffer(endpoint, ENDPOINT_PARAM_SRC_REST_BODY, object_span, object_buf, sizeof(object_buf));
  if (copy_status == JSONREAD_ERR_TOOLONG)
    return static_gateRefusal(ENDPOINT_GATE_REJECT_BODY_TOO_LARGE, -1);
  else if (copy_status != JSONREAD_OK)
    return static_gateRefusal(ENDPOINT_GATE_REJECT_BODY, -1);
  return static_readObjectMembersIntoParams(endpoint, ENDPOINT_PARAM_SRC_REST_BODY, object_span, object_buf, params_out);
}

static EndpointParamType_t static_bulkArrayType(const Endpoint_t* endpoint)
{
  int array_param_index = static_findBulkArrayParamIndex(endpoint, ENDPOINT_PARAM_SRC_REST_BODY | ENDPOINT_PARAM_SRC_MCP_ARG);
  assert(array_param_index >= 0 && endpoint->mp_params[array_param_index].m_offset == 0);
  
  return endpoint->mp_params[array_param_index].mp_spec->m_type;
}

static int static_bulkKeptCount(const Endpoint_t* endpoint, const EndpointAnyParams_t* params)
{
  switch (static_bulkArrayType(endpoint))
  {
    case ENDPOINT_PARAM_TYPE_CVE_ID_ARRAY:
    case ENDPOINT_PARAM_TYPE_FILE_HASH_ARRAY:
      return params->m_bulkIds.m_idCount;

    case ENDPOINT_PARAM_TYPE_PACKAGE_ARRAY:
      return params->m_packageCheckBulk.m_itemCount;

    case ENDPOINT_PARAM_TYPE_STRING:
    case ENDPOINT_PARAM_TYPE_ENUM:
    case ENDPOINT_PARAM_TYPE_INT:
    case ENDPOINT_PARAM_TYPE_DOUBLE:
    case ENDPOINT_PARAM_TYPE_BOOL:
    case ENDPOINT_PARAM_TYPE_KEV_FILTER:
    case ENDPOINT_PARAM_TYPE_CVE_ID:
    case ENDPOINT_PARAM_TYPE_CWE_ID:
    case ENDPOINT_PARAM_TYPE_BYTES:
      break;
  }
  assert(false && "a BULK_IDS row reads a bulk array");
  return 0;
}

unsigned int endpoint_price(const Endpoint_t* endpoint, EndpointGateStatus_t gate_status, const EndpointAnyParams_t* params, size_t params_size)
{
  assert(endpoint != NULL);
  assert(params   != NULL);
  assert(params_size == endpoint->m_paramsSize);
  assert(!endpoint->m_isMcpEndpoint && "mcp_creditCost prices the /mcp row from its JSON-RPC body");
  (void)params_size;

  if (gate_status != ENDPOINT_GATE_OK)
    return endpoint->m_creditCost;

  switch (endpoint->m_costRule)
  {
    case ENDPOINT_COST_FLAT:
      return endpoint->m_creditCost;

    case ENDPOINT_COST_BULK_IDS:
    {
      unsigned int charge_count = (unsigned int)static_bulkKeptCount(endpoint, params);
      return charge_count > endpoint->m_creditCost ? charge_count : endpoint->m_creditCost;
    }
  }

  assert(false && "every cost rule has a case above");
  return endpoint->m_creditCost;
}

bool endpoint_willCallUpstream(const Endpoint_t* endpoint, EndpointGateStatus_t gate_status, const EndpointAnyParams_t* params)
{
  assert(endpoint != NULL);
  assert(params   != NULL);

  if (gate_status != ENDPOINT_GATE_OK)
    return false;
  else if (endpoint->m_callsUpstreamFunction != NULL)
    return endpoint->m_callsUpstreamFunction(params);
  return endpoint->m_callsUpstream;
}

bool endpoint_isPartialChargeAllowed(const Endpoint_t* endpoint)
{
  assert(endpoint != NULL);

  return endpoint->m_costRule == ENDPOINT_COST_BULK_IDS;
}

void endpoint_limitWorkToCharge(const Endpoint_t* endpoint, EndpointAnyParams_t* params, unsigned int charged_credit_count)
{
  assert(endpoint != NULL);
  assert(params   != NULL);
  assert(endpoint->m_costRule == ENDPOINT_COST_BULK_IDS);

  int* kept_count          = NULL;
  int* not_processed_count = NULL;
  switch (static_bulkArrayType(endpoint))
  {
    case ENDPOINT_PARAM_TYPE_CVE_ID_ARRAY:
    case ENDPOINT_PARAM_TYPE_FILE_HASH_ARRAY:
      kept_count          = &params->m_bulkIds.m_idCount;
      not_processed_count = &params->m_bulkIds.m_notProcessedIdCount;
      break;

    case ENDPOINT_PARAM_TYPE_PACKAGE_ARRAY:
      kept_count          = &params->m_packageCheckBulk.m_itemCount;
      not_processed_count = &params->m_packageCheckBulk.m_notProcessedItemCount;
      break;

    case ENDPOINT_PARAM_TYPE_STRING:
    case ENDPOINT_PARAM_TYPE_ENUM:
    case ENDPOINT_PARAM_TYPE_INT:
    case ENDPOINT_PARAM_TYPE_DOUBLE:
    case ENDPOINT_PARAM_TYPE_BOOL:
    case ENDPOINT_PARAM_TYPE_KEV_FILTER:
    case ENDPOINT_PARAM_TYPE_CVE_ID:
    case ENDPOINT_PARAM_TYPE_CWE_ID:
    case ENDPOINT_PARAM_TYPE_BYTES:
      assert(false && "a BULK_IDS row reads a bulk array");
      return;
  }

  if ((unsigned int)*kept_count <= charged_credit_count)
    return;

  *not_processed_count  = *kept_count - (int)charged_credit_count;
  *kept_count           = (int)charged_credit_count;
}

EndpointRunStatus_t endpoint_limitWorkToWeight(const Endpoint_t* endpoint, PGconn* conn, EndpointAnyParams_t* params, unsigned int max_item_count)
{
  assert(endpoint != NULL);
  assert(params   != NULL);
  assert(endpoint->m_costRule == ENDPOINT_COST_BULK_IDS);
  assert(endpoint->m_weighFunction != NULL);

  int kept_count         = static_bulkKeptCount(endpoint, params);
  int weighed_item_count = (unsigned int)kept_count < max_item_count ? kept_count : (int)max_item_count;
  int served_item_count  = weighed_item_count;
  if (weighed_item_count >= 2)
  {
    EndpointRunStatus_t run_status = endpoint->m_weighFunction(conn, params, weighed_item_count, &served_item_count);
    if (run_status != ENDPOINT_RUN_OK)
      return run_status;
  }

  endpoint_limitWorkToCharge(endpoint, params, (unsigned int)served_item_count);
  return ENDPOINT_RUN_OK;
}

_Static_assert(offsetof(WATCHLISTEDITParams_t, mp_creditBudget) == 0,
               "endpoint_runRow writes the credit budget at offset 0 of the watchlist_edit params");
_Static_assert(offsetof(WATCHLISTEVENTSParams_t, mp_creditBudget) == 0,
               "endpoint_runRow writes the credit budget at offset 0 of the watchlist_events params");
_Static_assert(offsetof(PRIVACYMYDATAParams_t, mp_creditBudget) == 0,
               "endpoint_runRow writes the credit budget at offset 0 of the privacy_my_data params");

EndpointRunResult_t endpoint_runRow(const Endpoint_t* endpoint, EndpointAnyParams_t* params, PGconn* conn, const RequestCharge_t* charge)
{
  assert(endpoint != NULL);
  assert(endpoint->m_runFunction != NULL);
  assert(params != NULL);
  assert(charge != NULL);

  EndpointRunResult_t run_result = { .m_status = ENDPOINT_RUN_OK, .mp_body = NULL, .mp_message = NULL };

  if (endpoint->m_costRule == ENDPOINT_COST_BULK_IDS)
  {
    usagelog_setItemCount(static_bulkKeptCount(endpoint, params));
    endpoint_limitWorkToCharge(endpoint, params, charge->m_chargedCreditCount);
  }

  if (endpoint->m_readsCreditBudget)
  {
    if (charge->mp_creditBudget == NULL)
    {
      run_result.m_status = ENDPOINT_RUN_NO_CREDIT_BUDGET;
      return run_result;
    }
    params->mp_creditBudget = charge->mp_creditBudget;
  }

  if (endpoint->m_isDbRequired && !conn)
  {
    run_result.m_status = ENDPOINT_RUN_NO_CONNECTION;
    return run_result;
  }

  JsonBuf_t* json_buf = jsonbuf_create(JSONBUF_INITIAL_CAP, endpoint->m_jsonCeiling);
  if (!json_buf)
  {
    run_result.m_status = ENDPOINT_RUN_NO_MEMORY;
    return run_result;
  }

  run_result.m_status = endpoint->m_runFunction(conn, params, json_buf, &run_result.mp_message);
  assert(run_result.m_status != ENDPOINT_RUN_NOT_FOUND || endpoint->mp_notFoundMessage != NULL);
  assert(run_result.m_status != ENDPOINT_RUN_REFUSED   || run_result.mp_message != NULL);
  assert(run_result.m_status != ENDPOINT_RUN_TARGET_UNREACHABLE || run_result.mp_message != NULL);
  assert(run_result.m_status != ENDPOINT_RUN_UNAUTHORIZED || run_result.mp_message != NULL);
  assert(run_result.m_status != ENDPOINT_RUN_GONE || run_result.mp_message != NULL);
  assert(run_result.m_status != ENDPOINT_RUN_NO_CONNECTION);
  assert(run_result.m_status != ENDPOINT_RUN_NO_CREDIT_BUDGET);

  if (run_result.m_status == ENDPOINT_RUN_OK                ||
      run_result.m_status == ENDPOINT_RUN_REFUSED_WITH_BODY ||
      run_result.m_status == ENDPOINT_RUN_DEGRADED)
  {
    run_result.mp_body = jsonbuf_finish(json_buf);
    if (!run_result.mp_body && run_result.m_status != ENDPOINT_RUN_DEGRADED)
      run_result.m_status = ENDPOINT_RUN_NO_MEMORY;
  }
  jsonbuf_destroy(json_buf);
  return run_result;
}
