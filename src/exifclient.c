#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "exifclient.h"
#include "bytes.h"
#include "jsonread.h"
#include "macro.h"
#include "monotonic.h"

#define EXIFCLIENT_JPEG_QUALITY_MAX 100

#define EXIFCLIENT_MAX_LATITUDE  90.0
#define EXIFCLIENT_MAX_LONGITUDE 180.0

#define EXIFCLIENT_C2PA_LABEL_JSON "\"c2pa\""

typedef struct {
  const char* mp_key;
  size_t      m_fieldOffset;
  size_t      m_fieldSize;
} ExifClientTextField_t;

static const ExifClientTextField_t RESULT_TEXT_FIELDS[] = {
  { "IFD0:Make",                     offsetof(ExifClientResult_t, ma_cameraMake),         MACRO_FIELD_SIZE(ExifClientResult_t, ma_cameraMake) },
  { "IFD0:Model",                    offsetof(ExifClientResult_t, ma_cameraModel),        MACRO_FIELD_SIZE(ExifClientResult_t, ma_cameraModel) },
  { "IFD0:Software",                 offsetof(ExifClientResult_t, ma_software),           MACRO_FIELD_SIZE(ExifClientResult_t, ma_software) },
  { "XMP-xmp:CreatorTool",           offsetof(ExifClientResult_t, ma_creatorTool),        MACRO_FIELD_SIZE(ExifClientResult_t, ma_creatorTool) },
  { "XMP-iptcExt:DigitalSourceType", offsetof(ExifClientResult_t, ma_digitalSourceType),  MACRO_FIELD_SIZE(ExifClientResult_t, ma_digitalSourceType) },
  { "CBOR:Claim_generator",          offsetof(ExifClientResult_t, ma_c2paClaimGenerator), MACRO_FIELD_SIZE(ExifClientResult_t, ma_c2paClaimGenerator) },
  { "ExifIFD:DateTimeOriginal",      offsetof(ExifClientResult_t, ma_dateTimeOriginal),   MACRO_FIELD_SIZE(ExifClientResult_t, ma_dateTimeOriginal) },
  { "ExifIFD:OffsetTimeOriginal",    offsetof(ExifClientResult_t, ma_offsetTimeOriginal), MACRO_FIELD_SIZE(ExifClientResult_t, ma_offsetTimeOriginal) },
  { "IFD0:ModifyDate",               offsetof(ExifClientResult_t, ma_modifyDate),         MACRO_FIELD_SIZE(ExifClientResult_t, ma_modifyDate) },
  { "Composite:GPSDateTime",         offsetof(ExifClientResult_t, ma_gpsDateTime),        MACRO_FIELD_SIZE(ExifClientResult_t, ma_gpsDateTime) },
};

static const size_t RESULT_TEXT_FIELD_COUNT = sizeof(RESULT_TEXT_FIELDS) / sizeof(RESULT_TEXT_FIELDS[0]);

static const ExifClientTextField_t HISTORY_ENTRY_TEXT_FIELDS[] = {
  { "Action",        offsetof(ExifClientHistoryEntry_t, ma_action),        MACRO_FIELD_SIZE(ExifClientHistoryEntry_t, ma_action) },
  { "When",          offsetof(ExifClientHistoryEntry_t, ma_when),          MACRO_FIELD_SIZE(ExifClientHistoryEntry_t, ma_when) },
  { "SoftwareAgent", offsetof(ExifClientHistoryEntry_t, ma_softwareAgent), MACRO_FIELD_SIZE(ExifClientHistoryEntry_t, ma_softwareAgent) },
};

static const size_t HISTORY_ENTRY_TEXT_FIELD_COUNT = sizeof(HISTORY_ENTRY_TEXT_FIELDS) / sizeof(HISTORY_ENTRY_TEXT_FIELDS[0]);

typedef struct {
  const char*            mp_tagText;
  bool                   m_isWholeTagName;
  ExifClientIdentifier_t m_identifier;
} ExifClientIdentifierTagRule_t;

static const ExifClientIdentifierTagRule_t IDENTIFIER_TAG_RULES[] = {
  { "Serial",                      false, EXIFCLIENT_IDENTIFIER_SERIAL_NUMBER },
  { "OwnerName",                   false, EXIFCLIENT_IDENTIFIER_OWNER_NAME },
  { "Owner",                       true,  EXIFCLIENT_IDENTIFIER_OWNER_NAME },
  { "UserName",                    true,  EXIFCLIENT_IDENTIFIER_OWNER_NAME },
  { "CameraOwner",                 true,  EXIFCLIENT_IDENTIFIER_OWNER_NAME },
  { "OwnerID",                     true,  EXIFCLIENT_IDENTIFIER_OWNER_NAME },
  { "RightsOwner",                 true,  EXIFCLIENT_IDENTIFIER_OWNER_NAME },
  { "UniqueID",                    false, EXIFCLIENT_IDENTIFIER_UNIQUE_ID },
  { "DocumentID",                  false, EXIFCLIENT_IDENTIFIER_UNIQUE_ID },
  { "InstanceID",                  false, EXIFCLIENT_IDENTIFIER_UNIQUE_ID },
  { "UUID",                        false, EXIFCLIENT_IDENTIFIER_UNIQUE_ID },
  { "ContentIdentifier",           false, EXIFCLIENT_IDENTIFIER_UNIQUE_ID },
  { "DocumentAncestors",           false, EXIFCLIENT_IDENTIFIER_UNIQUE_ID },
  { "DerivedFrom",                 false, EXIFCLIENT_IDENTIFIER_UNIQUE_ID },
  { "ArtworkCopyrightOwnerID",     true,  EXIFCLIENT_IDENTIFIER_UNIQUE_ID },
  { "ArtworkCreatorID",            true,  EXIFCLIENT_IDENTIFIER_UNIQUE_ID },
  { "ArtworkLicensorID",           true,  EXIFCLIENT_IDENTIFIER_UNIQUE_ID },
  { "AuthorIdentifier",            true,  EXIFCLIENT_IDENTIFIER_UNIQUE_ID },
  { "CreatorIdentifier",           true,  EXIFCLIENT_IDENTIFIER_UNIQUE_ID },
  { "Identifier",                  true,  EXIFCLIENT_IDENTIFIER_UNIQUE_ID },
  { "Ingredients",                 false, EXIFCLIENT_IDENTIFIER_UNIQUE_ID },
  { "LicenseID",                   true,  EXIFCLIENT_IDENTIFIER_UNIQUE_ID },
  { "ManagedFrom",                 false, EXIFCLIENT_IDENTIFIER_UNIQUE_ID },
  { "Pantry",                      false, EXIFCLIENT_IDENTIFIER_UNIQUE_ID },
  { "ParentID",                    true,  EXIFCLIENT_IDENTIFIER_UNIQUE_ID },
  { "RegistryID",                  true,  EXIFCLIENT_IDENTIFIER_UNIQUE_ID },
  { "RegistryItemID",              true,  EXIFCLIENT_IDENTIFIER_UNIQUE_ID },
  { "RegistryOrganisationID",      true,  EXIFCLIENT_IDENTIFIER_UNIQUE_ID },
  { "ReleaseID",                   false, EXIFCLIENT_IDENTIFIER_UNIQUE_ID },
  { "UserID",                      true,  EXIFCLIENT_IDENTIFIER_UNIQUE_ID },
  { "Versions",                    true,  EXIFCLIENT_IDENTIFIER_UNIQUE_ID },
  { "HostComputer",                false, EXIFCLIENT_IDENTIFIER_HOST_COMPUTER },
  { "Artist",                      true,  EXIFCLIENT_IDENTIFIER_AUTHOR },
  { "Creator",                     true,  EXIFCLIENT_IDENTIFIER_AUTHOR },
  { "Author",                      true,  EXIFCLIENT_IDENTIFIER_AUTHOR },
  { "By-line",                     true,  EXIFCLIENT_IDENTIFIER_AUTHOR },
  { "XPAuthor",                    false, EXIFCLIENT_IDENTIFIER_AUTHOR },
  { "Photographer",                false, EXIFCLIENT_IDENTIFIER_AUTHOR },
  { "ImageEditor",                 false, EXIFCLIENT_IDENTIFIER_AUTHOR },
  { "CaptionWriter",               false, EXIFCLIENT_IDENTIFIER_AUTHOR },
  { "ImageCreator",                false, EXIFCLIENT_IDENTIFIER_AUTHOR },
  { "CreatorContactInfo",          false, EXIFCLIENT_IDENTIFIER_AUTHOR },
  { "AIPromptWriterName",          true,  EXIFCLIENT_IDENTIFIER_AUTHOR },
  { "AlbumArtist",                 false, EXIFCLIENT_IDENTIFIER_AUTHOR },
  { "Artist2",                     true,  EXIFCLIENT_IDENTIFIER_AUTHOR },
  { "ArtistURL",                   true,  EXIFCLIENT_IDENTIFIER_AUTHOR },
  { "ArtworkCreator",              false, EXIFCLIENT_IDENTIFIER_AUTHOR },
  { "ArtworkOrObject",             true,  EXIFCLIENT_IDENTIFIER_AUTHOR },
  { "AttributionName",             true,  EXIFCLIENT_IDENTIFIER_AUTHOR },
  { "AttributionURL",              true,  EXIFCLIENT_IDENTIFIER_AUTHOR },
  { "AuthorName",                  false, EXIFCLIENT_IDENTIFIER_AUTHOR },
  { "AuthorURL",                   true,  EXIFCLIENT_IDENTIFIER_AUTHOR },
  { "Authors",                     true,  EXIFCLIENT_IDENTIFIER_AUTHOR },
  { "CameraOperator",              true,  EXIFCLIENT_IDENTIFIER_AUTHOR },
  { "CommentBy",                   true,  EXIFCLIENT_IDENTIFIER_AUTHOR },
  { "Composer",                    true,  EXIFCLIENT_IDENTIFIER_AUTHOR },
  { "Contact",                     true,  EXIFCLIENT_IDENTIFIER_AUTHOR },
  { "Contributor",                 false, EXIFCLIENT_IDENTIFIER_AUTHOR },
  { "CreatedBy",                   true,  EXIFCLIENT_IDENTIFIER_AUTHOR },
  { "CreatorAddress",              true,  EXIFCLIENT_IDENTIFIER_AUTHOR },
  { "CreatorCity",                 true,  EXIFCLIENT_IDENTIFIER_AUTHOR },
  { "CreatorCountry",              true,  EXIFCLIENT_IDENTIFIER_AUTHOR },
  { "CreatorName",                 false, EXIFCLIENT_IDENTIFIER_AUTHOR },
  { "CreatorPostalCode",           true,  EXIFCLIENT_IDENTIFIER_AUTHOR },
  { "CreatorRegion",               true,  EXIFCLIENT_IDENTIFIER_AUTHOR },
  { "CreatorWork",                 false, EXIFCLIENT_IDENTIFIER_AUTHOR },
  { "Credit",                      true,  EXIFCLIENT_IDENTIFIER_AUTHOR },
  { "Editor",                      true,  EXIFCLIENT_IDENTIFIER_AUTHOR },
  { "Email",                       true,  EXIFCLIENT_IDENTIFIER_AUTHOR },
  { "FormattedName",               true,  EXIFCLIENT_IDENTIFIER_AUTHOR },
  { "LastAuthor",                  true,  EXIFCLIENT_IDENTIFIER_AUTHOR },
  { "LastModifiedBy",              true,  EXIFCLIENT_IDENTIFIER_AUTHOR },
  { "LastSavedBy",                 true,  EXIFCLIENT_IDENTIFIER_AUTHOR },
  { "MDItemAuthors",               true,  EXIFCLIENT_IDENTIFIER_AUTHOR },
  { "MetadataLastEditor",          false, EXIFCLIENT_IDENTIFIER_AUTHOR },
  { "OriginalArtist",              true,  EXIFCLIENT_IDENTIFIER_AUTHOR },
  { "Performer",                   true,  EXIFCLIENT_IDENTIFIER_AUTHOR },
  { "PhoneNumber",                 false, EXIFCLIENT_IDENTIFIER_AUTHOR },
  { "ThumbnailArtist",             true,  EXIFCLIENT_IDENTIFIER_AUTHOR },
  { "ExifArtist",                  true,  EXIFCLIENT_IDENTIFIER_AUTHOR },
  { "CredentialSubject",           true,  EXIFCLIENT_IDENTIFIER_AUTHOR },
  { "Publisher",                   true,  EXIFCLIENT_IDENTIFIER_AUTHOR },
  { "Writer",                      true,  EXIFCLIENT_IDENTIFIER_AUTHOR },
  { "Writer-Editor",               true,  EXIFCLIENT_IDENTIFIER_AUTHOR },
  { "Copyright",                   true,  EXIFCLIENT_IDENTIFIER_COPYRIGHT },
  { "CopyrightNotice",             true,  EXIFCLIENT_IDENTIFIER_COPYRIGHT },
  { "CopyrightOwner",              false, EXIFCLIENT_IDENTIFIER_COPYRIGHT },
  { "Rights",                      true,  EXIFCLIENT_IDENTIFIER_COPYRIGHT },
  { "Broker",                      false, EXIFCLIENT_IDENTIFIER_COPYRIGHT },
  { "CopyrightRegistrationNumber", true,  EXIFCLIENT_IDENTIFIER_COPYRIGHT },
  { "CopyrightURL",                true,  EXIFCLIENT_IDENTIFIER_COPYRIGHT },
  { "EndUser",                     false, EXIFCLIENT_IDENTIFIER_COPYRIGHT },
  { "ExifCopyright",               true,  EXIFCLIENT_IDENTIFIER_COPYRIGHT },
  { "ImageSupplier",               false, EXIFCLIENT_IDENTIFIER_COPYRIGHT },
  { "Licensee",                    false, EXIFCLIENT_IDENTIFIER_COPYRIGHT },
  { "Licensor",                    false, EXIFCLIENT_IDENTIFIER_COPYRIGHT },
  { "MDItemCopyright",             true,  EXIFCLIENT_IDENTIFIER_COPYRIGHT },
  { "Notice",                      false, EXIFCLIENT_IDENTIFIER_COPYRIGHT },
  { "Source",                      true,  EXIFCLIENT_IDENTIFIER_COPYRIGHT },
  { "PersonInImage",               false, EXIFCLIENT_IDENTIFIER_PERSON_IN_IMAGE },
  { "RegionInfo",                  false, EXIFCLIENT_IDENTIFIER_PERSON_IN_IMAGE },
  { "BabyName",                    true,  EXIFCLIENT_IDENTIFIER_PERSON_IN_IMAGE },
  { "Face1Name",                   true,  EXIFCLIENT_IDENTIFIER_PERSON_IN_IMAGE },
  { "Face2Name",                   true,  EXIFCLIENT_IDENTIFIER_PERSON_IN_IMAGE },
  { "Face3Name",                   true,  EXIFCLIENT_IDENTIFIER_PERSON_IN_IMAGE },
  { "Face4Name",                   true,  EXIFCLIENT_IDENTIFIER_PERSON_IN_IMAGE },
  { "Face5Name",                   true,  EXIFCLIENT_IDENTIFIER_PERSON_IN_IMAGE },
  { "Face6Name",                   true,  EXIFCLIENT_IDENTIFIER_PERSON_IN_IMAGE },
  { "Face7Name",                   true,  EXIFCLIENT_IDENTIFIER_PERSON_IN_IMAGE },
  { "Face8Name",                   true,  EXIFCLIENT_IDENTIFIER_PERSON_IN_IMAGE },
  { "FaceName",                    true,  EXIFCLIENT_IDENTIFIER_PERSON_IN_IMAGE },
  { "People",                      true,  EXIFCLIENT_IDENTIFIER_PERSON_IN_IMAGE },
  { "Person",                      true,  EXIFCLIENT_IDENTIFIER_PERSON_IN_IMAGE },
  { "PersonHeard",                 false, EXIFCLIENT_IDENTIFIER_PERSON_IN_IMAGE },
  { "Personality",                 true,  EXIFCLIENT_IDENTIFIER_PERSON_IN_IMAGE },
  { "RecognizedFace1Name",         true,  EXIFCLIENT_IDENTIFIER_PERSON_IN_IMAGE },
  { "RecognizedFace2Name",         true,  EXIFCLIENT_IDENTIFIER_PERSON_IN_IMAGE },
  { "RecognizedFace3Name",         true,  EXIFCLIENT_IDENTIFIER_PERSON_IN_IMAGE },
  { "PreservedFileName",           false, EXIFCLIENT_IDENTIFIER_ORIGINAL_FILE_NAME },
  { "FileNameAsDelivered",         true,  EXIFCLIENT_IDENTIFIER_ORIGINAL_FILE_NAME },
  { "ManageTo",                    false, EXIFCLIENT_IDENTIFIER_ORIGINAL_FILE_NAME },
  { "RawFileName",                 false, EXIFCLIENT_IDENTIFIER_ORIGINAL_FILE_NAME },
};

static const size_t IDENTIFIER_TAG_RULE_COUNT = sizeof(IDENTIFIER_TAG_RULES) / sizeof(IDENTIFIER_TAG_RULES[0]);

typedef struct {
  bool m_hasLatitude;
  bool m_hasLongitude;
  bool m_hasExifToolError;
} ExifClientReadState_t;

_Static_assert(sizeof(EXIFCLIENT_SOCKET_PATH) <= sizeof(((struct sockaddr_un*)0)->sun_path), "EXIFCLIENT_SOCKET_PATH must fit sun_path");

static int                static_connectToService (void);
static ExifClientStatus_t static_exchange         (int fd, const unsigned char* image_bytes, size_t image_byte_count, int64_t deadline_at, char* answer, size_t* answer_len);
static void               static_sendSome         (int fd, const unsigned char* image_bytes, size_t image_byte_count, size_t* sent_byte_count, bool* will_still_send);

static void                         static_readMember                 (JsonReadSpan_t key_span, JsonReadSpan_t value_span, ExifClientResult_t* result, ExifClientReadState_t* state);
static const ExifClientTextField_t* static_findTextField              (const ExifClientTextField_t* fields, size_t field_count, JsonReadSpan_t key_span);
static void                         static_copyTextValue              (JsonReadSpan_t value_span, char* buf, size_t buf_size);
static void                         static_markIdentifier             (JsonReadSpan_t key_span, ExifClientResult_t* result);
static bool                         static_tryReadCoordinate          (JsonReadSpan_t value_span, double max_degrees, double* degrees_out);
static int                          static_jpegQualityOrZero          (JsonReadSpan_t value_span);
static size_t                       static_byteCountOrZero            (JsonReadSpan_t value_span);
static void                         static_readHistory                (JsonReadSpan_t history_span, ExifClientResult_t* result);
static void                         static_readClaimGeneratorInfo     (JsonReadSpan_t info_span, ExifClientResult_t* result);
static bool                         static_isTextInSpan               (JsonReadSpan_t span, const char* text);
static bool                         static_isTagNameOrLanguageVariant (JsonReadSpan_t tag_span, const char* text);
static JsonReadSpan_t               static_findTagName                (JsonReadSpan_t key_span);

ExifClientStatus_t exifclient_inspect(const unsigned char* image_bytes, size_t image_byte_count, ExifClientResult_t* result_out)
{
  assert(image_bytes != NULL || image_byte_count == 0);
  assert(result_out != NULL);

  memset(result_out, 0, sizeof(*result_out));
  int64_t deadline_at = monotonic_nowMs() + EXIFCLIENT_DEADLINE_MS;

  char* answer = malloc(EXIFCLIENT_MAX_RESPONSE_BYTE_COUNT + 1);
  if (answer == NULL)
    return EXIFCLIENT_ERR_NO_MEMORY;

  int fd = static_connectToService();
  if (fd < 0)
  {
    free(answer);
    return EXIFCLIENT_ERR_CONNECT;
  }

  size_t answer_len = 0;
  ExifClientStatus_t status = static_exchange(fd, image_bytes, image_byte_count, deadline_at, answer, &answer_len);
  if (status == EXIFCLIENT_OK)
    status = exifclient_readResponse(answer, answer_len, result_out);

  explicit_bzero(answer, answer_len);
  free(answer);
  close(fd);
  return status;
}

ExifClientStatus_t exifclient_readResponse(const char* json, size_t json_len, ExifClientResult_t* result_out)
{
  assert(result_out != NULL);

  memset(result_out, 0, sizeof(*result_out));

  JsonReadSpan_t root_span      = { 0 };
  JsonReadSpan_t object_span    = { 0 };
  size_t         element_count  = 0;
  size_t         element_offset = 0;
  if (jsonread_root(json, json_len, &root_span) != JSONREAD_OK                             ||
      jsonread_arrayLen(root_span, &element_count) != JSONREAD_OK                          ||
      element_count != 1                                                                   ||
      jsonread_arrayNextElement(root_span, &element_offset, &object_span) != JSONREAD_OK)
  {
    return EXIFCLIENT_ERR_MALFORMED;
  }

  ExifClientReadState_t state         = { 0 };
  size_t                member_offset = 0;
  JsonReadSpan_t        key_span      = { 0 };
  JsonReadSpan_t        value_span    = { 0 };
  JsonReadStatus_t      walk_status;
  while ((walk_status = jsonread_objectNextMember(object_span, &member_offset, &key_span, &value_span)) == JSONREAD_OK)
    static_readMember(key_span, value_span, result_out, &state);

  if (walk_status != JSONREAD_ERR_NOTFOUND)
  {
    memset(result_out, 0, sizeof(*result_out));
    return EXIFCLIENT_ERR_MALFORMED;
  }
  if (state.m_hasExifToolError)
  {
    memset(result_out, 0, sizeof(*result_out));
    return EXIFCLIENT_ERR_REFUSED;
  }

  result_out->m_hasGpsPosition = state.m_hasLatitude && state.m_hasLongitude;
  if (!result_out->m_hasGpsPosition)
  {
    result_out->m_gpsLatitude  = 0.0;
    result_out->m_gpsLongitude = 0.0;
  }
  return EXIFCLIENT_OK;
}

static int static_connectToService(void)
{
  int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  if (fd < 0)
    return -1;

  struct sockaddr_un address = { 0 };
  address.sun_family = AF_UNIX;
  memcpy(address.sun_path, EXIFCLIENT_SOCKET_PATH, sizeof(EXIFCLIENT_SOCKET_PATH));
  if (connect(fd, (const struct sockaddr*)&address, sizeof(address)) != 0)
  {
    close(fd);
    return -1;
  }
  return fd;
}

static ExifClientStatus_t static_exchange(int fd, const unsigned char* image_bytes, size_t image_byte_count, int64_t deadline_at, char* answer, size_t* answer_len)
{
  assert(answer     != NULL);
  assert(answer_len != NULL);

  size_t sent_byte_count = 0;
  bool will_still_send = image_byte_count > 0;
  if (!will_still_send)
    shutdown(fd, SHUT_WR);

  for (;;)
  {
    int64_t wait_ms = deadline_at - monotonic_nowMs();
    if (wait_ms <= 0)
      return EXIFCLIENT_ERR_DEADLINE;

    struct pollfd poll_fd = { .fd = fd, .events = POLLIN | (will_still_send ? POLLOUT : 0) };
    int ready_count = poll(&poll_fd, 1, (int)wait_ms);
    if (ready_count < 0 && errno != EINTR)
      return EXIFCLIENT_ERR_TRANSFER;
    if (ready_count <= 0)
      continue;

    if (will_still_send)
    {
      if ((poll_fd.revents & (POLLERR | POLLHUP)) != 0)
        will_still_send = false;
      else if ((poll_fd.revents & POLLOUT) != 0)
        static_sendSome(fd, image_bytes, image_byte_count, &sent_byte_count, &will_still_send);
    }

    if ((poll_fd.revents & (POLLIN | POLLERR | POLLHUP)) == 0)
      continue;

    ssize_t read_count = recv(fd, answer + *answer_len, EXIFCLIENT_MAX_RESPONSE_BYTE_COUNT + 1 - *answer_len, MSG_DONTWAIT);
    if (read_count == 0 || (read_count < 0 && errno == ECONNRESET))
      return EXIFCLIENT_OK;
    else if (read_count < 0 && errno != EAGAIN && errno != EINTR)
      return EXIFCLIENT_ERR_TRANSFER;
    else if (read_count > 0)
      *answer_len += (size_t)read_count;
    
    if (*answer_len > EXIFCLIENT_MAX_RESPONSE_BYTE_COUNT)
      return EXIFCLIENT_ERR_TOO_LARGE;
  }
}

static void static_sendSome(int fd, const unsigned char* image_bytes, size_t image_byte_count, size_t* sent_byte_count, bool* will_still_send)
{
  assert(sent_byte_count != NULL);
  assert(will_still_send != NULL);
  assert(*sent_byte_count < image_byte_count);

  ssize_t written = send(fd, image_bytes + *sent_byte_count, image_byte_count - *sent_byte_count, MSG_NOSIGNAL | MSG_DONTWAIT);
  if (written < 0)
  {
    *will_still_send = errno == EAGAIN || errno == EINTR;
    return;
  }

  *sent_byte_count += (size_t)written;
  if (*sent_byte_count < image_byte_count)
    return;
  
  shutdown(fd, SHUT_WR);
  *will_still_send = false;
}

static void static_readMember(JsonReadSpan_t key_span, JsonReadSpan_t value_span, ExifClientResult_t* result, ExifClientReadState_t* state)
{
  assert(result != NULL);
  assert(state  != NULL);

  static_markIdentifier(key_span, result);

  const ExifClientTextField_t* text_field = static_findTextField(RESULT_TEXT_FIELDS, RESULT_TEXT_FIELD_COUNT, key_span);
  if (text_field != NULL)
  {
    static_copyTextValue(value_span, (char*)result + text_field->m_fieldOffset, text_field->m_fieldSize);
    return;
  }

  if (jsonread_isSpanEqual(key_span, "ExifTool:Error"))
    state->m_hasExifToolError = true;
  else if (jsonread_isSpanEqual(key_span, "Composite:GPSLatitude"))
    state->m_hasLatitude = static_tryReadCoordinate(value_span, EXIFCLIENT_MAX_LATITUDE, &result->m_gpsLatitude);
  else if (jsonread_isSpanEqual(key_span, "Composite:GPSLongitude"))
    state->m_hasLongitude = static_tryReadCoordinate(value_span, EXIFCLIENT_MAX_LONGITUDE, &result->m_gpsLongitude);
  else if (jsonread_isSpanEqual(key_span, "File:JPEGQualityEstimate"))
    result->m_jpegQualityEstimate = static_jpegQualityOrZero(value_span);
  else if (jsonread_isSpanEqual(key_span, "IFD1:ThumbnailLength"))
    result->m_thumbnailByteCount = static_byteCountOrZero(value_span);
  else if (jsonread_isSpanEqual(key_span, "JUMBF:JUMDLabel"))
    result->m_hasC2paManifest = jsonread_isSpanEqual(value_span, EXIFCLIENT_C2PA_LABEL_JSON);
  else if (jsonread_isSpanEqual(key_span, "PNG:Parameters") || jsonread_isSpanEqual(key_span, "PNG:Prompt") || jsonread_isSpanEqual(key_span, "PNG:Workflow"))
    result->m_hasGeneratorParameters = true;
  else if (jsonread_isSpanEqual(key_span, "XMP-xmpMM:History"))
    static_readHistory(value_span, result);
  else if (jsonread_isSpanEqual(key_span, "CBOR:Claim_generator_info"))
    static_readClaimGeneratorInfo(value_span, result);
}

static const ExifClientTextField_t* static_findTextField(const ExifClientTextField_t* fields, size_t field_count, JsonReadSpan_t key_span)
{
  assert(fields != NULL);

  for (size_t i = 0; i < field_count; i++)
  {
    if (jsonread_isSpanEqual(key_span, fields[i].mp_key))
      return &fields[i];
  }
  return NULL;
}

static void static_copyTextValue(JsonReadSpan_t value_span, char* buf, size_t buf_size)
{
  assert(buf != NULL);
  assert(buf_size > 0);

  memset(buf, 0, buf_size);
  JsonReadStatus_t status = jsonread_spanToStrStatus(value_span, buf, buf_size);
  if (status == JSONREAD_ERR_TYPE                                                           && 
      value_span.m_len > 0                                                                  && 
      jsonread_isNumberToken(value_span.mp_start, value_span.mp_start + value_span.m_len))
  {
    status = jsonread_spanToRawStringStatus(value_span, buf, buf_size);
  }
  if (status != JSONREAD_OK)
    memset(buf, 0, buf_size);
}

static void static_markIdentifier(JsonReadSpan_t key_span, ExifClientResult_t* result)
{
  assert(result != NULL);

  JsonReadSpan_t tag_span = static_findTagName(key_span);
  for (size_t i = 0; i < IDENTIFIER_TAG_RULE_COUNT; i++)
  {
    const ExifClientIdentifierTagRule_t* rule = &IDENTIFIER_TAG_RULES[i];
    bool is_match = rule->m_isWholeTagName  ? static_isTagNameOrLanguageVariant(tag_span, rule->mp_tagText)
                                            : static_isTextInSpan(tag_span, rule->mp_tagText);
    if (is_match)
      result->ma_isIdentifierPresent[rule->m_identifier] = true;
  }
}

static bool static_tryReadCoordinate(JsonReadSpan_t value_span, double max_degrees, double* degrees_out)
{
  assert(degrees_out != NULL);

  double degrees = 0.0;
  if (jsonread_spanToDoubleStatus(value_span, &degrees) != JSONREAD_OK)
    return false;

  if (!(degrees >= -max_degrees && degrees <= max_degrees))
    return false;

  *degrees_out = degrees;
  return true;
}

static int static_jpegQualityOrZero(JsonReadSpan_t value_span)
{
  long quality = 0;
  if (jsonread_spanToLongStatus(value_span, &quality) != JSONREAD_OK)
    return 0;

  if (quality < 1 || quality > EXIFCLIENT_JPEG_QUALITY_MAX)
    return 0;

  return (int)quality;
}

static size_t static_byteCountOrZero(JsonReadSpan_t value_span)
{
  long byte_count = 0;
  if (jsonread_spanToLongStatus(value_span, &byte_count) != JSONREAD_OK)
    return 0;

  if (byte_count < 0)
    return 0;

  return (size_t)byte_count;
}

static void static_readHistory(JsonReadSpan_t history_span, ExifClientResult_t* result)
{
  assert(result != NULL);

  memset(result->ma_editHistoryEntries, 0, sizeof(result->ma_editHistoryEntries));
  result->m_editHistoryEntryCount = 0;
  result->m_hasMoreEditHistoryEntries = false;

  JsonReadSpan_t entry_span   = { 0 };
  size_t         entry_offset = 0;
  while (jsonread_arrayNextElement(history_span, &entry_offset, &entry_span) == JSONREAD_OK)
  {
    if (result->m_editHistoryEntryCount == EXIFCLIENT_KEPT_HISTORY_ENTRY_COUNT)
    {
      result->m_hasMoreEditHistoryEntries = true;
      return;
    }

    ExifClientHistoryEntry_t* entry         = &result->ma_editHistoryEntries[result->m_editHistoryEntryCount++];
    size_t                    member_offset = 0;
    JsonReadSpan_t            key_span      = { 0 };
    JsonReadSpan_t            value_span    = { 0 };
    while (jsonread_objectNextMember(entry_span, &member_offset, &key_span, &value_span) == JSONREAD_OK)
    {
      const ExifClientTextField_t* text_field = static_findTextField(HISTORY_ENTRY_TEXT_FIELDS, HISTORY_ENTRY_TEXT_FIELD_COUNT, key_span);
      if (text_field != NULL)
        static_copyTextValue(value_span, (char*)entry + text_field->m_fieldOffset, text_field->m_fieldSize);
    }
  }
}

static void static_readClaimGeneratorInfo(JsonReadSpan_t info_span, ExifClientResult_t* result)
{
  assert(result != NULL);

  if (result->ma_c2paClaimGenerator[0] != '\0')
    return;

  JsonReadSpan_t entry_span       = info_span;
  JsonReadSpan_t first_entry_span = { 0 };
  size_t         entry_offset     = 0;
  if (jsonread_arrayNextElement(info_span, &entry_offset, &first_entry_span) == JSONREAD_OK)
    entry_span = first_entry_span;

  JsonReadSpan_t name_span = { 0 };
  if (jsonread_objectKey(entry_span, "name", &name_span) == JSONREAD_OK)
    static_copyTextValue(name_span, result->ma_c2paClaimGenerator, sizeof(result->ma_c2paClaimGenerator));
}

static bool static_isTextInSpan(JsonReadSpan_t span, const char* text)
{
  assert(text != NULL && text[0] != '\0');

  size_t text_len = strlen(text);
  for (size_t start = 0; start + text_len <= span.m_len; start++)
  {
    if (memcmp(span.mp_start + start, text, text_len) == 0)
      return true;
  }
  return false;
}

static bool static_isTagNameOrLanguageVariant(JsonReadSpan_t tag_span, const char* text)
{
  assert(text != NULL);

  size_t text_len = strlen(text);
  if (!bytes_hasPrefix(tag_span.mp_start, tag_span.m_len, text, text_len, false))
    return false;

  const char* rest     = tag_span.mp_start + text_len;
  size_t      rest_len = tag_span.m_len - text_len;
  if (rest_len == 0)
    return true;

  return rest_len >= 2 && rest[0] == '-' && rest[1] >= 'a' && rest[1] <= 'z';
}

static JsonReadSpan_t static_findTagName(JsonReadSpan_t key_span)
{
  for (size_t i = 0; i < key_span.m_len; i++)
  {
    if (key_span.mp_start[i] == ':')
    {
      JsonReadSpan_t tag_span = { key_span.mp_start + i + 1, key_span.m_len - i - 1 };
      return tag_span;
    }
  }
  return key_span;
}
