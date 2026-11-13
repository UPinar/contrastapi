#ifndef EXIFCLIENT_H
#define EXIFCLIENT_H

#include <stdbool.h>
#include <stddef.h>

#define EXIFCLIENT_SOCKET_PATH "/run/contrastapi-exif/exif.sock"

#define EXIFCLIENT_DEADLINE_MS 15000

#define EXIFCLIENT_MAX_RESPONSE_BYTE_COUNT (256 * 1024)

#define EXIFCLIENT_KEPT_HISTORY_ENTRY_COUNT 16

#define EXIFCLIENT_TEXT_BUF_SIZE       128
#define EXIFCLIENT_SHORT_TEXT_BUF_SIZE 32

typedef enum {
  EXIFCLIENT_IDENTIFIER_SERIAL_NUMBER = 0,
  EXIFCLIENT_IDENTIFIER_OWNER_NAME,
  EXIFCLIENT_IDENTIFIER_UNIQUE_ID,
  EXIFCLIENT_IDENTIFIER_HOST_COMPUTER,
  EXIFCLIENT_IDENTIFIER_AUTHOR,
  EXIFCLIENT_IDENTIFIER_COPYRIGHT,
  EXIFCLIENT_IDENTIFIER_PERSON_IN_IMAGE,
  EXIFCLIENT_IDENTIFIER_ORIGINAL_FILE_NAME,
  EXIFCLIENT_IDENTIFIER_COUNT
} ExifClientIdentifier_t;

typedef struct {
  char ma_action[EXIFCLIENT_SHORT_TEXT_BUF_SIZE];
  char ma_when[EXIFCLIENT_SHORT_TEXT_BUF_SIZE];
  char ma_softwareAgent[EXIFCLIENT_TEXT_BUF_SIZE];
} ExifClientHistoryEntry_t;

typedef struct {
  char                     ma_cameraMake[EXIFCLIENT_TEXT_BUF_SIZE];
  char                     ma_cameraModel[EXIFCLIENT_TEXT_BUF_SIZE];
  char                     ma_software[EXIFCLIENT_TEXT_BUF_SIZE];
  char                     ma_creatorTool[EXIFCLIENT_TEXT_BUF_SIZE];
  char                     ma_digitalSourceType[EXIFCLIENT_TEXT_BUF_SIZE];
  char                     ma_c2paClaimGenerator[EXIFCLIENT_TEXT_BUF_SIZE];
  char                     ma_dateTimeOriginal[EXIFCLIENT_SHORT_TEXT_BUF_SIZE];
  char                     ma_offsetTimeOriginal[EXIFCLIENT_SHORT_TEXT_BUF_SIZE];
  char                     ma_modifyDate[EXIFCLIENT_SHORT_TEXT_BUF_SIZE];
  char                     ma_gpsDateTime[EXIFCLIENT_SHORT_TEXT_BUF_SIZE];
  bool                     m_hasGpsPosition;
  double                   m_gpsLatitude;
  double                   m_gpsLongitude;
  int                      m_jpegQualityEstimate;
  size_t                   m_thumbnailByteCount;
  bool                     m_hasC2paManifest;
  bool                     m_hasGeneratorParameters;
  bool                     ma_isIdentifierPresent[EXIFCLIENT_IDENTIFIER_COUNT];
  ExifClientHistoryEntry_t ma_editHistoryEntries[EXIFCLIENT_KEPT_HISTORY_ENTRY_COUNT];
  int                      m_editHistoryEntryCount;
  bool                     m_hasMoreEditHistoryEntries;
} ExifClientResult_t;

#define EXIFCLIENT_REFUSAL_MESSAGE "the metadata of the image could not be read"

typedef enum {
  EXIFCLIENT_OK = 0,
  EXIFCLIENT_ERR_MALFORMED,
  EXIFCLIENT_ERR_REFUSED,
  EXIFCLIENT_ERR_CONNECT,
  EXIFCLIENT_ERR_TRANSFER,
  EXIFCLIENT_ERR_DEADLINE,
  EXIFCLIENT_ERR_TOO_LARGE,
  EXIFCLIENT_ERR_NO_MEMORY,
} ExifClientStatus_t;

ExifClientStatus_t exifclient_inspect     (const unsigned char* image_bytes, size_t image_byte_count, ExifClientResult_t* result_out);
ExifClientStatus_t exifclient_readResponse(const char* json, size_t json_len, ExifClientResult_t* result_out);

#endif
