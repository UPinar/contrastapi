#define _GNU_SOURCE

#include <assert.h>
#include <ctype.h>
#include <limits.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include "imagescan.h"
#include "bytes.h"

_Static_assert(IMAGESCAN_SHA256_HEX_LEN == 2 * SHA256_DIGEST_LENGTH, "two hex digits write one byte of the hash");

#define IMAGESCAN_ISO_BRAND_LEN           4
#define IMAGESCAN_ISO_FTYP_OFFSET         4
#define IMAGESCAN_ISO_MAJOR_BRAND_OFFSET  8

#define IMAGESCAN_WEBP_FORM_OFFSET 8

#define IMAGESCAN_ZIP_MIN_VERSION 10
#define IMAGESCAN_ZIP_MAX_VERSION 63

typedef struct {
  const char*       mp_brand;
  ImageScanFormat_t m_format;
} ImageScanIsoBrand_t;

static const ImageScanIsoBrand_t ISO_BRANDS[] = {
  { "avif", IMAGESCAN_FORMAT_AVIF },
  { "avis", IMAGESCAN_FORMAT_AVIF },
  { "heic", IMAGESCAN_FORMAT_HEIC },
  { "heix", IMAGESCAN_FORMAT_HEIC },
  { "heim", IMAGESCAN_FORMAT_HEIC },
  { "heis", IMAGESCAN_FORMAT_HEIC },
  { "hevc", IMAGESCAN_FORMAT_HEIC },
  { "hevx", IMAGESCAN_FORMAT_HEIC },
  { "hevm", IMAGESCAN_FORMAT_HEIC },
  { "hevs", IMAGESCAN_FORMAT_HEIC },
  { "mif1", IMAGESCAN_FORMAT_HEIC },
  { "msf1", IMAGESCAN_FORMAT_HEIC },
};

static const char* const FORMAT_NAMES[] = {
  [IMAGESCAN_FORMAT_UNKNOWN] = "unknown",
  [IMAGESCAN_FORMAT_JPEG]    = "jpeg",
  [IMAGESCAN_FORMAT_PNG]     = "png",
  [IMAGESCAN_FORMAT_WEBP]    = "webp",
  [IMAGESCAN_FORMAT_TIFF]    = "tiff",
  [IMAGESCAN_FORMAT_HEIC]    = "heic",
  [IMAGESCAN_FORMAT_AVIF]    = "avif",
};

typedef struct {
  const char* mp_name;
  const char* mp_prefix;
  size_t      m_prefixLen;
  bool        m_isCaseInsensitive;
  size_t      m_tailLen;
  bool      (*m_isTailAcceptedFunction)(const unsigned char* signature_start);
} ImageScanSignature_t;

#define IMAGESCAN_PREFIX(text) text, sizeof(text) - 1

static bool                 static_isZipVersionAccepted      (const unsigned char* signature_start);
static bool                 static_isElfIdentAccepted        (const unsigned char* signature_start);
static bool                 static_isPeMachineAccepted       (const unsigned char* signature_start);
static bool                 static_isShellPathAccepted       (const unsigned char* signature_start);
static bool                 static_hasPrefix                 (const unsigned char* bytes, size_t byte_count, const char* prefix, size_t prefix_len);
static bool                 static_isWebp                    (const unsigned char* bytes, size_t byte_count);
static bool                 static_hasIsoFtypBox             (const unsigned char* bytes, size_t byte_count);
static ImageScanFormat_t    static_findIsoBrandFormat        (const unsigned char* major_brand);
static const unsigned char* static_findSignaturePrefix       (const unsigned char* bytes, size_t byte_count, const ImageScanSignature_t* signature);

static const unsigned int PE_MACHINES[] = { 0x014c, 0x01c0, 0x01c4, 0x0200, 0x8664, 0xaa64 };

static const ImageScanSignature_t SIGNATURES[IMAGESCAN_FILE_TYPE_COUNT] = {
  [IMAGESCAN_FILE_TYPE_ZIP]          = { "zip",          IMAGESCAN_PREFIX("PK\x03\x04"),         false, 2, static_isZipVersionAccepted },
  [IMAGESCAN_FILE_TYPE_RAR]          = { "rar",          IMAGESCAN_PREFIX("Rar!\x1a\x07"),       false, 0, NULL },
  [IMAGESCAN_FILE_TYPE_7Z]           = { "7z",           IMAGESCAN_PREFIX("7z\xbc\xaf\x27\x1c"), false, 0, NULL },
  [IMAGESCAN_FILE_TYPE_PDF]          = { "pdf",          IMAGESCAN_PREFIX("%PDF-"),              false, 0, NULL },
  [IMAGESCAN_FILE_TYPE_ELF]          = { "elf",          IMAGESCAN_PREFIX("\x7f" "ELF"),         false, 3, static_isElfIdentAccepted },
  [IMAGESCAN_FILE_TYPE_PE]           = { "pe",           IMAGESCAN_PREFIX("PE\0\0"),             false, 2, static_isPeMachineAccepted },
  [IMAGESCAN_FILE_TYPE_PHP]          = { "php",          IMAGESCAN_PREFIX("<?php"),              true,  0, NULL },
  [IMAGESCAN_FILE_TYPE_HTML_SCRIPT]  = { "html_script",  IMAGESCAN_PREFIX("<script"),            true,  0, NULL },
  [IMAGESCAN_FILE_TYPE_SHELL_SCRIPT] = { "shell_script", IMAGESCAN_PREFIX("#!/"),                false, 4, static_isShellPathAccepted },
};

ImageScanStatus_t imagescan_scan(const unsigned char* bytes, size_t byte_count, ImageScanResult_t* result_out)
{
  assert(bytes != NULL || byte_count == 0);
  assert(result_out != NULL);

  memset(result_out, 0, sizeof(*result_out));

  result_out->m_format    = imagescan_findFormat(bytes, byte_count);
  result_out->m_byteCount = byte_count;

  if (result_out->m_format == IMAGESCAN_FORMAT_UNKNOWN)
    return IMAGESCAN_ERR_UNKNOWN_FORMAT;
  if (!imagescan_writeSha256Hex(bytes, byte_count, result_out->ma_sha256Hex))
    return IMAGESCAN_ERR_HASH;

  imagescan_findEmbeddedFileSignatures(bytes, byte_count, result_out->ma_signatureMatches);
  return IMAGESCAN_OK;
}

ImageScanFormat_t imagescan_findFormat(const unsigned char* bytes, size_t byte_count)
{
  assert(bytes != NULL || byte_count == 0);

  if (static_hasPrefix(bytes, byte_count, IMAGESCAN_PREFIX("\xff\xd8\xff")))
    return IMAGESCAN_FORMAT_JPEG;
  else if (static_hasPrefix(bytes, byte_count, IMAGESCAN_PREFIX("\x89PNG\r\n\x1a\n")))
    return IMAGESCAN_FORMAT_PNG;
  else if (static_isWebp(bytes, byte_count))
    return IMAGESCAN_FORMAT_WEBP;
  else if (static_hasPrefix(bytes, byte_count, IMAGESCAN_PREFIX("II*\0")) || static_hasPrefix(bytes, byte_count, IMAGESCAN_PREFIX("MM\0*")))
    return IMAGESCAN_FORMAT_TIFF;
  else if (static_hasIsoFtypBox(bytes, byte_count))
    return static_findIsoBrandFormat(bytes + IMAGESCAN_ISO_MAJOR_BRAND_OFFSET);

  return IMAGESCAN_FORMAT_UNKNOWN;
}

const char* imagescan_formatName(ImageScanFormat_t format)
{
  assert((size_t)format < sizeof(FORMAT_NAMES) / sizeof(FORMAT_NAMES[0]));
  return FORMAT_NAMES[format];
}

bool imagescan_writeSha256Hex(const unsigned char* bytes, size_t byte_count, char* hex_out)
{
  assert(bytes != NULL || byte_count == 0);
  assert(hex_out != NULL);

  unsigned char digest[SHA256_DIGEST_LENGTH];
  unsigned int  digest_len = 0;
  if (EVP_Digest(bytes, byte_count, digest, &digest_len, EVP_sha256(), NULL) != 1 || digest_len != SHA256_DIGEST_LENGTH)
  {
    hex_out[0] = '\0';
    return false;
  }
  bytes_writeHex(digest, SHA256_DIGEST_LENGTH, hex_out);
  return true;
}

void imagescan_findEmbeddedFileSignatures(const unsigned char* bytes, size_t byte_count, ImageScanSignatureMatch_t* matches_out)
{
  assert(bytes != NULL || byte_count == 0);
  assert(matches_out != NULL);
  assert(byte_count <= (size_t)INT_MAX);

  memset(matches_out, 0, IMAGESCAN_FILE_TYPE_COUNT * sizeof(matches_out[0]));
  for (int file_type = 0; file_type < IMAGESCAN_FILE_TYPE_COUNT; file_type++)
  {
    const ImageScanSignature_t* signature = &SIGNATURES[file_type];
    ImageScanSignatureMatch_t*  match     = &matches_out[file_type];
    assert((signature->m_tailLen == 0) == (signature->m_isTailAcceptedFunction == NULL));
    size_t signature_len = signature->m_prefixLen + signature->m_tailLen;
    size_t offset = 0;
    while (byte_count - offset >= signature_len)
    {
      const unsigned char* candidate = static_findSignaturePrefix(bytes + offset, byte_count - offset, signature);
      if (candidate == NULL)
        break;
      size_t candidate_offset = (size_t)(candidate - bytes);
      if (byte_count - candidate_offset < signature_len)
        break;
      if (signature->m_isTailAcceptedFunction != NULL && !signature->m_isTailAcceptedFunction(candidate))
      {
        offset = candidate_offset + 1;
        continue;
      }
      if (match->m_matchCount < IMAGESCAN_MAX_MATCH_OFFSETS)
        match->ma_matchOffsets[match->m_matchCount] = candidate_offset;
      match->m_matchCount++;
      offset = candidate_offset + signature_len;
    }
  }
}

const char* imagescan_fileTypeName(ImageScanFileType_t file_type)
{
  assert(file_type < IMAGESCAN_FILE_TYPE_COUNT);
  return SIGNATURES[file_type].mp_name;
}

static bool static_isZipVersionAccepted(const unsigned char* signature_start)
{
  return  signature_start[4] >= IMAGESCAN_ZIP_MIN_VERSION && 
          signature_start[4] <= IMAGESCAN_ZIP_MAX_VERSION && 
          signature_start[5] == 0;
}

static bool static_isElfIdentAccepted(const unsigned char* signature_start)
{
  return  (signature_start[4] == 1 || signature_start[4] == 2) && 
          (signature_start[5] == 1 || signature_start[5] == 2) && 
          signature_start[6] == 1;
}

static bool static_isPeMachineAccepted(const unsigned char* signature_start)
{
  unsigned int machine = (unsigned int)signature_start[4] | (unsigned int)signature_start[5] << 8;
  for (size_t i = 0; i < sizeof(PE_MACHINES) / sizeof(PE_MACHINES[0]); i++)
  {
    if (machine == PE_MACHINES[i])
      return true;
  }
  return false;
}

static bool static_isShellPathAccepted(const unsigned char* signature_start)
{
  const unsigned char* path = signature_start + sizeof("#!/") - 1;
  return memcmp(path, IMAGESCAN_PREFIX("bin/")) == 0 || memcmp(path, IMAGESCAN_PREFIX("usr/")) == 0;
}

static bool static_hasPrefix(const unsigned char* bytes, size_t byte_count, const char* prefix, size_t prefix_len)
{
  return bytes_hasPrefix((const char*)bytes, byte_count, prefix, prefix_len, false);
}

static bool static_isWebp(const unsigned char* bytes, size_t byte_count)
{
  return  static_hasPrefix(bytes, byte_count, IMAGESCAN_PREFIX("RIFF")) && 
          byte_count >= IMAGESCAN_WEBP_FORM_OFFSET                      && 
          static_hasPrefix(bytes + IMAGESCAN_WEBP_FORM_OFFSET, byte_count - IMAGESCAN_WEBP_FORM_OFFSET, IMAGESCAN_PREFIX("WEBP"));
}

static bool static_hasIsoFtypBox(const unsigned char* bytes, size_t byte_count)
{
  return  byte_count >= IMAGESCAN_ISO_MAJOR_BRAND_OFFSET + IMAGESCAN_ISO_BRAND_LEN  && 
          memcmp(bytes + IMAGESCAN_ISO_FTYP_OFFSET, IMAGESCAN_PREFIX("ftyp")) == 0;
}

static ImageScanFormat_t static_findIsoBrandFormat(const unsigned char* major_brand)
{
  for (size_t i = 0; i < sizeof(ISO_BRANDS) / sizeof(ISO_BRANDS[0]); i++)
  {
    if (memcmp(major_brand, ISO_BRANDS[i].mp_brand, IMAGESCAN_ISO_BRAND_LEN) == 0)
      return ISO_BRANDS[i].m_format;
  }
  return IMAGESCAN_FORMAT_UNKNOWN;
}

static const unsigned char* static_findSignaturePrefix(const unsigned char* bytes, size_t byte_count, const ImageScanSignature_t* signature)
{
  if (!signature->m_isCaseInsensitive)
    return memmem(bytes, byte_count, signature->mp_prefix, signature->m_prefixLen);

  assert(!isalpha((unsigned char)signature->mp_prefix[0]));
  const unsigned char* cursor = bytes;
  const unsigned char* end    = bytes + byte_count;
  while ((size_t)(end - cursor) >= signature->m_prefixLen)
  {
    const unsigned char* candidate = memchr(cursor, signature->mp_prefix[0], (size_t)(end - cursor) - signature->m_prefixLen + 1);
    if (candidate == NULL)
      return NULL;
    if (bytes_hasPrefix((const char*)candidate, (size_t)(end - candidate), signature->mp_prefix, signature->m_prefixLen, true))
      return candidate;
    
    cursor = candidate + 1;
  }
  return NULL;
}
