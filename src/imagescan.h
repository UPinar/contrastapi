#ifndef IMAGESCAN_H
#define IMAGESCAN_H

#include <stdbool.h>
#include <stddef.h>

#define IMAGESCAN_SHA256_HEX_LEN 64

#define IMAGESCAN_UNKNOWN_FORMAT_REFUSAL_MESSAGE "the body is not a JPEG, PNG, WebP, TIFF, HEIC or AVIF image"

typedef enum {
  IMAGESCAN_FORMAT_UNKNOWN = 0,
  IMAGESCAN_FORMAT_JPEG,
  IMAGESCAN_FORMAT_PNG,
  IMAGESCAN_FORMAT_WEBP,
  IMAGESCAN_FORMAT_TIFF,
  IMAGESCAN_FORMAT_HEIC,
  IMAGESCAN_FORMAT_AVIF,
} ImageScanFormat_t;

typedef enum {
  IMAGESCAN_FILE_TYPE_ZIP = 0,
  IMAGESCAN_FILE_TYPE_RAR,
  IMAGESCAN_FILE_TYPE_7Z,
  IMAGESCAN_FILE_TYPE_PDF,
  IMAGESCAN_FILE_TYPE_ELF,
  IMAGESCAN_FILE_TYPE_PE,
  IMAGESCAN_FILE_TYPE_PHP,
  IMAGESCAN_FILE_TYPE_HTML_SCRIPT,
  IMAGESCAN_FILE_TYPE_SHELL_SCRIPT,
  IMAGESCAN_FILE_TYPE_COUNT
} ImageScanFileType_t;

#define IMAGESCAN_MAX_MATCH_OFFSETS 16

typedef struct {
  int    m_matchCount;
  size_t ma_matchOffsets[IMAGESCAN_MAX_MATCH_OFFSETS];
} ImageScanSignatureMatch_t;

typedef struct {
  ImageScanFormat_t         m_format;
  size_t                    m_byteCount;
  char                      ma_sha256Hex[IMAGESCAN_SHA256_HEX_LEN + 1];
  ImageScanSignatureMatch_t ma_signatureMatches[IMAGESCAN_FILE_TYPE_COUNT];
} ImageScanResult_t;

typedef enum {
  IMAGESCAN_OK = 0,
  IMAGESCAN_ERR_UNKNOWN_FORMAT,
  IMAGESCAN_ERR_HASH,
} ImageScanStatus_t;

ImageScanStatus_t imagescan_scan                       (const unsigned char* bytes, size_t byte_count, ImageScanResult_t* result_out);
ImageScanFormat_t imagescan_findFormat                 (const unsigned char* bytes, size_t byte_count);
const char*       imagescan_formatName                 (ImageScanFormat_t format);
bool              imagescan_writeSha256Hex             (const unsigned char* bytes, size_t byte_count, char* hex_out);
void              imagescan_findEmbeddedFileSignatures (const unsigned char* bytes, size_t byte_count, ImageScanSignatureMatch_t* matches_out);
const char*       imagescan_fileTypeName               (ImageScanFileType_t file_type);

#endif
