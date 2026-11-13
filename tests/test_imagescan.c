#include <string.h>
#include <openssl/evp.h>

#include "unity/unity.h"
#include "imagescan.h"

typedef enum {
  TEST_DIGEST_PASS = 0,
  TEST_DIGEST_FAIL,
  TEST_DIGEST_SHORT_LENGTH,
} ImageScanTestDigestFault_t;

static ImageScanTestDigestFault_t g_digestFault = TEST_DIGEST_PASS;

static int g_digestCallCount = 0;

int __real_EVP_Digest(const void* data, size_t count, unsigned char* md, unsigned int* size, const EVP_MD* type, ENGINE* impl);

int __wrap_EVP_Digest(const void* data, size_t count, unsigned char* md, unsigned int* size, const EVP_MD* type, ENGINE* impl)
{
  ImageScanTestDigestFault_t fault = g_digestFault;
  g_digestFault = TEST_DIGEST_PASS;
  g_digestCallCount++;
  if (fault == TEST_DIGEST_FAIL)
    return 0;
  int digest_status = __real_EVP_Digest(data, count, md, size, type, impl);
  if (fault == TEST_DIGEST_SHORT_LENGTH)
    *size = 20;
  return digest_status;
}

void setUp(void)
{
  g_digestFault     = TEST_DIGEST_PASS;
  g_digestCallCount = 0;
}

void tearDown(void) {}

static ImageScanFormat_t static_format(const char* bytes, size_t byte_count)
{
  return imagescan_findFormat((const unsigned char*)bytes, byte_count);
}

void test_findFormat_names_each_format_from_its_whole_prefix_only(void)
{
  static const struct {
    const char*       mp_name;
    const char*       mp_bytes;
    size_t            m_byteCount;
    ImageScanFormat_t m_format;
  } cases[] = {
    { "jpeg",     "\xff\xd8\xff",                    3,  IMAGESCAN_FORMAT_JPEG },
    { "png",      "\x89PNG\r\n\x1a\n",               8,  IMAGESCAN_FORMAT_PNG },
    { "webp",     "RIFF\x24\x00\x00\x00WEBP",        12, IMAGESCAN_FORMAT_WEBP },
    { "tiff II",  "II*\0",                           4,  IMAGESCAN_FORMAT_TIFF },
    { "tiff MM",  "MM\0*",                           4,  IMAGESCAN_FORMAT_TIFF },
    { "heic",     "\x00\x00\x00\x18" "ftypheic",     12, IMAGESCAN_FORMAT_HEIC },
    { "avif",     "\x00\x00\x00\x1c" "ftypavif",     12, IMAGESCAN_FORMAT_AVIF },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_format, static_format(cases[i].mp_bytes, cases[i].m_byteCount), cases[i].mp_name);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IMAGESCAN_FORMAT_UNKNOWN, static_format(cases[i].mp_bytes, cases[i].m_byteCount - 1), cases[i].mp_name);
  }
}

void test_findFormat_refuses_a_prefix_with_one_byte_changed(void)
{
  static const struct {
    const char* mp_name;
    const char* mp_bytes;
    size_t      m_byteCount;
  } cases[] = {
    { "jpeg third byte", "\xff\xd8\xfe",                    3 },
    { "png last byte",   "\x89PNG\r\n\x1a\x0b",             8 },
    { "riff wave",       "RIFF\x24\x00\x00\x00WAVE",        12 },
    { "tiff II",         "II\0*",                           4 },
    { "tiff MM",         "MM*\0",                           4 },
    { "ftyq box",        "\x00\x00\x00\x18" "ftyqheic",     12 },
    { "png lower case",  "\x89png\r\n\x1a\n",               8 },
    { "riff lower case", "riff\x24\x00\x00\x00webp",        12 },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
    TEST_ASSERT_EQUAL_INT_MESSAGE(IMAGESCAN_FORMAT_UNKNOWN, static_format(cases[i].mp_bytes, cases[i].m_byteCount), cases[i].mp_name);
}

void test_findFormat_reads_each_major_brand(void)
{
  static const struct {
    const char*       mp_brand;
    ImageScanFormat_t m_format;
  } cases[] = {
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
    { "isom", IMAGESCAN_FORMAT_UNKNOWN },
    { "heia", IMAGESCAN_FORMAT_UNKNOWN },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    char box[12] = "\x00\x00\x00\x18" "ftyp";
    memcpy(box + 8, cases[i].mp_brand, 4);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_format, static_format(box, sizeof(box)), cases[i].mp_brand);
  }
}

void test_findFormat_reads_no_bytes_as_unknown(void)
{
  TEST_ASSERT_EQUAL_INT(IMAGESCAN_FORMAT_UNKNOWN, imagescan_findFormat(NULL, 0));
  TEST_ASSERT_EQUAL_INT(IMAGESCAN_FORMAT_UNKNOWN, static_format("", 0));
}

void test_formatName_names_each_format(void)
{
  TEST_ASSERT_EQUAL_STRING("unknown", imagescan_formatName(IMAGESCAN_FORMAT_UNKNOWN));
  TEST_ASSERT_EQUAL_STRING("jpeg",    imagescan_formatName(IMAGESCAN_FORMAT_JPEG));
  TEST_ASSERT_EQUAL_STRING("png",     imagescan_formatName(IMAGESCAN_FORMAT_PNG));
  TEST_ASSERT_EQUAL_STRING("webp",    imagescan_formatName(IMAGESCAN_FORMAT_WEBP));
  TEST_ASSERT_EQUAL_STRING("tiff",    imagescan_formatName(IMAGESCAN_FORMAT_TIFF));
  TEST_ASSERT_EQUAL_STRING("heic",    imagescan_formatName(IMAGESCAN_FORMAT_HEIC));
  TEST_ASSERT_EQUAL_STRING("avif",    imagescan_formatName(IMAGESCAN_FORMAT_AVIF));
}

void test_fileTypeName_names_each_file_type(void)
{
  TEST_ASSERT_EQUAL_INT(9, IMAGESCAN_FILE_TYPE_COUNT);
  TEST_ASSERT_EQUAL_STRING("zip",          imagescan_fileTypeName(IMAGESCAN_FILE_TYPE_ZIP));
  TEST_ASSERT_EQUAL_STRING("rar",          imagescan_fileTypeName(IMAGESCAN_FILE_TYPE_RAR));
  TEST_ASSERT_EQUAL_STRING("7z",           imagescan_fileTypeName(IMAGESCAN_FILE_TYPE_7Z));
  TEST_ASSERT_EQUAL_STRING("pdf",          imagescan_fileTypeName(IMAGESCAN_FILE_TYPE_PDF));
  TEST_ASSERT_EQUAL_STRING("elf",          imagescan_fileTypeName(IMAGESCAN_FILE_TYPE_ELF));
  TEST_ASSERT_EQUAL_STRING("pe",           imagescan_fileTypeName(IMAGESCAN_FILE_TYPE_PE));
  TEST_ASSERT_EQUAL_STRING("php",          imagescan_fileTypeName(IMAGESCAN_FILE_TYPE_PHP));
  TEST_ASSERT_EQUAL_STRING("html_script",  imagescan_fileTypeName(IMAGESCAN_FILE_TYPE_HTML_SCRIPT));
  TEST_ASSERT_EQUAL_STRING("shell_script", imagescan_fileTypeName(IMAGESCAN_FILE_TYPE_SHELL_SCRIPT));
}

void test_writeSha256Hex_hashes_every_byte_nul_bytes_included(void)
{
  static const struct {
    const char* mp_bytes;
    size_t      m_byteCount;
    const char* mp_hex;
  } cases[] = {
    { "",                 0, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
    { "abc",              3, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" },
    { "\x00\x01\x02\x00", 4, "856aaf43b61beefd07691ab6e60cd50522b8c08721f6570dba877c5222745b04" },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    char hex[IMAGESCAN_SHA256_HEX_LEN + 1];
    memset(hex, 'Z', sizeof(hex));
    TEST_ASSERT_TRUE(imagescan_writeSha256Hex((const unsigned char*)cases[i].mp_bytes, cases[i].m_byteCount, hex));
    TEST_ASSERT_EQUAL_STRING(cases[i].mp_hex, hex);
  }
}

void test_writeSha256Hex_answers_false_and_empty_when_openssl_fails(void)
{
  static const ImageScanTestDigestFault_t faults[] = { TEST_DIGEST_FAIL, TEST_DIGEST_SHORT_LENGTH };
  for (size_t i = 0; i < sizeof(faults) / sizeof(faults[0]); i++)
  {
    char hex[IMAGESCAN_SHA256_HEX_LEN + 1];
    memset(hex, 'Z', sizeof(hex));
    g_digestFault = faults[i];
    TEST_ASSERT_FALSE(imagescan_writeSha256Hex((const unsigned char*)"abc", 3, hex));
    TEST_ASSERT_EQUAL_STRING("", hex);
  }
}

static void static_findSignatures(const char* bytes, size_t byte_count, ImageScanSignatureMatch_t* matches)
{
  memset(matches, 0x5A, IMAGESCAN_FILE_TYPE_COUNT * sizeof(matches[0]));
  imagescan_findEmbeddedFileSignatures((const unsigned char*)bytes, byte_count, matches);
}

static void static_assertOnlyMatch(const ImageScanSignatureMatch_t* matches, ImageScanFileType_t file_type, int match_count, size_t first_offset, const char* message)
{
  for (int i = 0; i < IMAGESCAN_FILE_TYPE_COUNT; i++)
  {
    if (i == (int)file_type)
    {
      TEST_ASSERT_EQUAL_INT_MESSAGE(match_count, matches[i].m_matchCount, message);
      TEST_ASSERT_EQUAL_size_t_MESSAGE(first_offset, matches[i].ma_matchOffsets[0], message);
    }
    else
    {
      TEST_ASSERT_EQUAL_INT_MESSAGE(0, matches[i].m_matchCount, message);
      for (int k = 0; k < IMAGESCAN_MAX_MATCH_OFFSETS; k++)
        TEST_ASSERT_EQUAL_size_t_MESSAGE(0, matches[i].ma_matchOffsets[k], message);
    }
  }
}

void test_findEmbeddedFileSignatures_finds_each_signature_at_its_offset(void)
{
  static const struct {
    ImageScanFileType_t m_fileType;
    const char*         mp_signature;
    size_t              m_signatureLen;
  } cases[] = {
    { IMAGESCAN_FILE_TYPE_ZIP,          "PK\x03\x04\x14\x00",     6 },
    { IMAGESCAN_FILE_TYPE_RAR,          "Rar!\x1a\x07",           6 },
    { IMAGESCAN_FILE_TYPE_7Z,           "7z\xbc\xaf\x27\x1c",     6 },
    { IMAGESCAN_FILE_TYPE_PDF,          "%PDF-",                  5 },
    { IMAGESCAN_FILE_TYPE_ELF,          "\x7f" "ELF\x02\x01\x01", 7 },
    { IMAGESCAN_FILE_TYPE_PE,           "PE\0\0\x64\x86",         6 },
    { IMAGESCAN_FILE_TYPE_PHP,          "<?php",                  5 },
    { IMAGESCAN_FILE_TYPE_HTML_SCRIPT,  "<script",                7 },
    { IMAGESCAN_FILE_TYPE_SHELL_SCRIPT, "#!/bin/",                7 },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    char bytes[64];
    size_t offset = 3 + i;
    memset(bytes, 'x', sizeof(bytes));
    memcpy(bytes + offset, cases[i].mp_signature, cases[i].m_signatureLen);
    ImageScanSignatureMatch_t matches[IMAGESCAN_FILE_TYPE_COUNT];
    static_findSignatures(bytes, sizeof(bytes), matches);
    static_assertOnlyMatch(matches, cases[i].m_fileType, 1, offset, imagescan_fileTypeName(cases[i].m_fileType));
  }
}

void test_findEmbeddedFileSignatures_reads_a_zip_version_from_10_to_63(void)
{
  static const struct {
    unsigned char m_version;
    unsigned char m_versionHighByte;
    int           m_matchCount;
  } cases[] = {
    { 9,  0, 0 },
    { 10, 0, 1 },
    { 63, 0, 1 },
    { 64, 0, 0 },
    { 20, 1, 0 },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    char bytes[16] = "xxPK\x03\x04";
    memset(bytes + 6, 'x', sizeof(bytes) - 6);
    bytes[6] = (char)cases[i].m_version;
    bytes[7] = (char)cases[i].m_versionHighByte;
    ImageScanSignatureMatch_t matches[IMAGESCAN_FILE_TYPE_COUNT];
    static_findSignatures(bytes, sizeof(bytes), matches);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_matchCount, matches[IMAGESCAN_FILE_TYPE_ZIP].m_matchCount, "zip version");
  }
}

void test_findEmbeddedFileSignatures_reads_a_pe_machine_from_the_list(void)
{
  static const struct {
    unsigned int m_machine;
    int          m_matchCount;
  } cases[] = {
    { 0x014c, 1 },
    { 0x01c0, 1 },
    { 0x01c4, 1 },
    { 0x0200, 1 },
    { 0x8664, 1 },
    { 0xaa64, 1 },
    { 0x014d, 0 },
    { 0x8663, 0 },
    { 0xaa65, 0 },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    char bytes[16];
    memset(bytes, 'x', sizeof(bytes));
    memcpy(bytes + 2, "PE\0\0", 4);
    bytes[6] = (char)(cases[i].m_machine & 0xff);
    bytes[7] = (char)(cases[i].m_machine >> 8);
    ImageScanSignatureMatch_t matches[IMAGESCAN_FILE_TYPE_COUNT];
    static_findSignatures(bytes, sizeof(bytes), matches);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_matchCount, matches[IMAGESCAN_FILE_TYPE_PE].m_matchCount, "pe machine");
  }
}

void test_findEmbeddedFileSignatures_reads_the_elf_class_encoding_and_version(void)
{
  static const struct {
    unsigned char ma_ident[3];
    int           m_matchCount;
  } cases[] = {
    { { 1, 1, 1 }, 1 },
    { { 2, 2, 1 }, 1 },
    { { 0, 1, 1 }, 0 },
    { { 3, 1, 1 }, 0 },
    { { 1, 0, 1 }, 0 },
    { { 1, 3, 1 }, 0 },
    { { 1, 1, 0 }, 0 },
    { { 1, 1, 2 }, 0 },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    char bytes[16] = "xx\x7f" "ELF";
    memset(bytes + 6, 'x', sizeof(bytes) - 6);
    memcpy(bytes + 6, cases[i].ma_ident, 3);
    ImageScanSignatureMatch_t matches[IMAGESCAN_FILE_TYPE_COUNT];
    static_findSignatures(bytes, sizeof(bytes), matches);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_matchCount, matches[IMAGESCAN_FILE_TYPE_ELF].m_matchCount, "elf ident");
  }
}

void test_findEmbeddedFileSignatures_reads_a_shell_path_under_bin_or_usr(void)
{
  static const struct {
    const char* mp_bytes;
    int         m_matchCount;
  } cases[] = {
    { "xx#!/bin/shxx", 1 },
    { "xx#!/usr/bin/env", 1 },
    { "xx#!/opt/tool", 0 },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    ImageScanSignatureMatch_t matches[IMAGESCAN_FILE_TYPE_COUNT];
    static_findSignatures(cases[i].mp_bytes, strlen(cases[i].mp_bytes), matches);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_matchCount, matches[IMAGESCAN_FILE_TYPE_SHELL_SCRIPT].m_matchCount, cases[i].mp_bytes);
  }
}

void test_findEmbeddedFileSignatures_matches_the_tags_in_either_case(void)
{
  static const struct {
    const char*         mp_bytes;
    ImageScanFileType_t m_fileType;
    int                 m_matchCount;
  } cases[] = {
    { "x<SCRIPT>", IMAGESCAN_FILE_TYPE_HTML_SCRIPT, 1 },
    { "x<ScRiPt>", IMAGESCAN_FILE_TYPE_HTML_SCRIPT, 1 },
    { "x<?PHP x",  IMAGESCAN_FILE_TYPE_PHP,         1 },
    { "x<scripx>", IMAGESCAN_FILE_TYPE_HTML_SCRIPT, 0 },
    { "x<<script", IMAGESCAN_FILE_TYPE_HTML_SCRIPT, 1 },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    ImageScanSignatureMatch_t matches[IMAGESCAN_FILE_TYPE_COUNT];
    static_findSignatures(cases[i].mp_bytes, strlen(cases[i].mp_bytes), matches);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_matchCount, matches[cases[i].m_fileType].m_matchCount, cases[i].mp_bytes);
  }
}

void test_findEmbeddedFileSignatures_needs_the_whole_signature_before_the_end(void)
{
  static const struct {
    ImageScanFileType_t m_fileType;
    const char*         mp_bytes;
    size_t              m_byteCount;
  } cases[] = {
    { IMAGESCAN_FILE_TYPE_ZIP,          "xxxPK\x03\x04\x14",     9 },
    { IMAGESCAN_FILE_TYPE_PE,           "xxxPE\0\0\x64\x86",      9 },
    { IMAGESCAN_FILE_TYPE_PDF,          "xxx%PDF-",             8 },
    { IMAGESCAN_FILE_TYPE_HTML_SCRIPT,  "xxx<script",           10 },
    { IMAGESCAN_FILE_TYPE_SHELL_SCRIPT, "xxx#!/bin/",           10 },
    { IMAGESCAN_FILE_TYPE_ELF,          "xxx\x7f" "ELF\x01\x01\x01", 10 },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    size_t byte_count = cases[i].m_byteCount;
    ImageScanSignatureMatch_t matches[IMAGESCAN_FILE_TYPE_COUNT];
    static_findSignatures(cases[i].mp_bytes, byte_count, matches);
    static_assertOnlyMatch(matches, cases[i].m_fileType, 1, 3, cases[i].mp_bytes);

    static_findSignatures(cases[i].mp_bytes, byte_count - 1, matches);
    static_assertOnlyMatch(matches, cases[i].m_fileType, 0, 0, cases[i].mp_bytes);
  }
}

void test_findEmbeddedFileSignatures_refuses_each_prefix_with_one_byte_changed(void)
{
  static const struct {
    ImageScanFileType_t m_fileType;
    const char*         mp_signature;
    size_t              m_signatureLen;
    size_t              m_prefixLen;
  } cases[] = {
    { IMAGESCAN_FILE_TYPE_ZIP,          "PK\x03\x04\x14\x00",     6, 4 },
    { IMAGESCAN_FILE_TYPE_RAR,          "Rar!\x1a\x07",           6, 6 },
    { IMAGESCAN_FILE_TYPE_7Z,           "7z\xbc\xaf\x27\x1c",     6, 6 },
    { IMAGESCAN_FILE_TYPE_PDF,          "%PDF-",                  5, 5 },
    { IMAGESCAN_FILE_TYPE_ELF,          "\x7f" "ELF\x02\x01\x01", 7, 4 },
    { IMAGESCAN_FILE_TYPE_PE,           "PE\0\0\x64\x86",         6, 4 },
    { IMAGESCAN_FILE_TYPE_PHP,          "<?php",                  5, 5 },
    { IMAGESCAN_FILE_TYPE_HTML_SCRIPT,  "<script",                7, 7 },
    { IMAGESCAN_FILE_TYPE_SHELL_SCRIPT, "#!/bin/",                7, 3 },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    for (size_t j = 0; j < cases[i].m_prefixLen; j++)
    {
      char bytes[32];
      memset(bytes, 'x', sizeof(bytes));
      memcpy(bytes + 3, cases[i].mp_signature, cases[i].m_signatureLen);
      bytes[3 + j] = (char)(bytes[3 + j] ^ 0x01);
      ImageScanSignatureMatch_t matches[IMAGESCAN_FILE_TYPE_COUNT];
      static_findSignatures(bytes, sizeof(bytes), matches);
      TEST_ASSERT_EQUAL_INT_MESSAGE(0, matches[cases[i].m_fileType].m_matchCount, imagescan_fileTypeName(cases[i].m_fileType));
    }
  }
}

void test_findEmbeddedFileSignatures_counts_matches_side_by_side(void)
{
  ImageScanSignatureMatch_t matches[IMAGESCAN_FILE_TYPE_COUNT];
  static_findSignatures("%PDF-", 5, matches);
  static_assertOnlyMatch(matches, IMAGESCAN_FILE_TYPE_PDF, 1, 0, "pdf alone");

  static_findSignatures("xx%PDF-%PDF-xx", 14, matches);
  static_assertOnlyMatch(matches, IMAGESCAN_FILE_TYPE_PDF, 2, 2, "two pdf");
  TEST_ASSERT_EQUAL_size_t_MESSAGE(7, matches[IMAGESCAN_FILE_TYPE_PDF].ma_matchOffsets[1], "two pdf");
  TEST_ASSERT_EQUAL_size_t_MESSAGE(0, matches[IMAGESCAN_FILE_TYPE_PDF].ma_matchOffsets[2], "two pdf");

  static_findSignatures("xx#!/#!/bin/x", 13, matches);
  static_assertOnlyMatch(matches, IMAGESCAN_FILE_TYPE_SHELL_SCRIPT, 1, 5, "shell after a rejected candidate");
}

void test_findEmbeddedFileSignatures_reads_no_bytes_as_no_match(void)
{
  ImageScanSignatureMatch_t matches[IMAGESCAN_FILE_TYPE_COUNT];
  memset(matches, 0x5A, sizeof(matches));
  imagescan_findEmbeddedFileSignatures(NULL, 0, matches);
  for (int i = 0; i < IMAGESCAN_FILE_TYPE_COUNT; i++)
  {
    TEST_ASSERT_EQUAL_INT(0, matches[i].m_matchCount);
    for (int k = 0; k < IMAGESCAN_MAX_MATCH_OFFSETS; k++)
      TEST_ASSERT_EQUAL_size_t(0, matches[i].ma_matchOffsets[k]);
  }
}

void test_findEmbeddedFileSignatures_keeps_the_first_offsets_and_counts_every_match(void)
{
  for (int match_count = IMAGESCAN_MAX_MATCH_OFFSETS; match_count <= IMAGESCAN_MAX_MATCH_OFFSETS + 1; match_count++)
  {
    char bytes[1 + 5 * (IMAGESCAN_MAX_MATCH_OFFSETS + 1)];
    bytes[0] = 'x';
    for (int k = 0; k < match_count; k++)
      memcpy(bytes + 1 + 5 * k, "%PDF-", 5);
    size_t byte_count = 1 + 5 * (size_t)match_count;
    ImageScanSignatureMatch_t matches[IMAGESCAN_FILE_TYPE_COUNT];
    static_findSignatures(bytes, byte_count, matches);
    static_assertOnlyMatch(matches, IMAGESCAN_FILE_TYPE_PDF, match_count, 1, "pdf");
    for (int k = 0; k < IMAGESCAN_MAX_MATCH_OFFSETS; k++)
      TEST_ASSERT_EQUAL_size_t_MESSAGE(1 + 5 * (size_t)k, matches[IMAGESCAN_FILE_TYPE_PDF].ma_matchOffsets[k], "pdf offset");
  }
}

static const char POLYGLOT_JPEG[] = "\xff\xd8\xff\xe0xx\xff\xd9" "PK\x03\x04\x2d\x00xx" "%PDF-1.7";
#define POLYGLOT_JPEG_SHA256 "f14b811e80eb98f21325f3bb78aed636a7d37c7606f8bc62abcd869950e41482"

void test_a_jpeg_with_a_zip_and_a_pdf_appended(void)
{
  size_t byte_count = sizeof(POLYGLOT_JPEG) - 1;
  TEST_ASSERT_EQUAL_INT(IMAGESCAN_FORMAT_JPEG, static_format(POLYGLOT_JPEG, byte_count));

  ImageScanSignatureMatch_t matches[IMAGESCAN_FILE_TYPE_COUNT];
  static_findSignatures(POLYGLOT_JPEG, byte_count, matches);
  for (int i = 0; i < IMAGESCAN_FILE_TYPE_COUNT; i++)
  {
    int    expected_count  = i == IMAGESCAN_FILE_TYPE_ZIP || i == IMAGESCAN_FILE_TYPE_PDF ? 1 : 0;
    size_t expected_offset = i == IMAGESCAN_FILE_TYPE_ZIP ? 8 : i == IMAGESCAN_FILE_TYPE_PDF ? 16 : 0;
    TEST_ASSERT_EQUAL_INT_MESSAGE(expected_count, matches[i].m_matchCount, imagescan_fileTypeName((ImageScanFileType_t)i));
    TEST_ASSERT_EQUAL_size_t_MESSAGE(expected_offset, matches[i].ma_matchOffsets[0], imagescan_fileTypeName((ImageScanFileType_t)i));
  }
}

void test_scan_fills_the_format_the_count_the_hash_and_the_matches(void)
{
  ImageScanResult_t result;
  memset(&result, 0x5A, sizeof(result));
  TEST_ASSERT_EQUAL_INT(IMAGESCAN_OK, imagescan_scan((const unsigned char*)POLYGLOT_JPEG, sizeof(POLYGLOT_JPEG) - 1, &result));
  TEST_ASSERT_EQUAL_INT(IMAGESCAN_FORMAT_JPEG, result.m_format);
  TEST_ASSERT_EQUAL_size_t(24, result.m_byteCount);
  TEST_ASSERT_EQUAL_STRING(POLYGLOT_JPEG_SHA256, result.ma_sha256Hex);
  for (int i = 0; i < IMAGESCAN_FILE_TYPE_COUNT; i++)
  {
    int    expected_count  = i == IMAGESCAN_FILE_TYPE_ZIP || i == IMAGESCAN_FILE_TYPE_PDF ? 1 : 0;
    size_t expected_offset = i == IMAGESCAN_FILE_TYPE_ZIP ? 8 : i == IMAGESCAN_FILE_TYPE_PDF ? 16 : 0;
    TEST_ASSERT_EQUAL_INT_MESSAGE(expected_count, result.ma_signatureMatches[i].m_matchCount, imagescan_fileTypeName((ImageScanFileType_t)i));
    TEST_ASSERT_EQUAL_size_t_MESSAGE(expected_offset, result.ma_signatureMatches[i].ma_matchOffsets[0], imagescan_fileTypeName((ImageScanFileType_t)i));
  }
}

void test_scan_stops_at_an_unknown_format(void)
{
  ImageScanResult_t result;
  memset(&result, 0x5A, sizeof(result));
  TEST_ASSERT_EQUAL_INT(IMAGESCAN_ERR_UNKNOWN_FORMAT, imagescan_scan((const unsigned char*)"GIF89a\x01%PDF-", 13, &result));
  TEST_ASSERT_EQUAL_INT(0, g_digestCallCount);
  TEST_ASSERT_EQUAL_INT(IMAGESCAN_FORMAT_UNKNOWN, result.m_format);
  TEST_ASSERT_EQUAL_size_t(13, result.m_byteCount);
  TEST_ASSERT_EQUAL_STRING("", result.ma_sha256Hex);
  TEST_ASSERT_EQUAL_INT(0, result.ma_signatureMatches[IMAGESCAN_FILE_TYPE_PDF].m_matchCount);
}

void test_scan_stops_when_the_hash_fails(void)
{
  ImageScanResult_t result;
  memset(&result, 0x5A, sizeof(result));
  g_digestFault = TEST_DIGEST_FAIL;
  TEST_ASSERT_EQUAL_INT(IMAGESCAN_ERR_HASH, imagescan_scan((const unsigned char*)POLYGLOT_JPEG, sizeof(POLYGLOT_JPEG) - 1, &result));
  TEST_ASSERT_EQUAL_STRING("", result.ma_sha256Hex);
  TEST_ASSERT_EQUAL_INT(0, result.ma_signatureMatches[IMAGESCAN_FILE_TYPE_ZIP].m_matchCount);
  TEST_ASSERT_EQUAL_INT(0, result.ma_signatureMatches[IMAGESCAN_FILE_TYPE_PDF].m_matchCount);
}

void test_registration_gate_test_count(void)
{
  TEST_ASSERT_EQUAL_INT_MESSAGE(24, (int)Unity.NumberOfTests,
    "RUN_TEST list and test definitions have drifted apart - a test may be unregistered");
}

int main(void)
{
  UNITY_BEGIN();
  RUN_TEST(test_findFormat_names_each_format_from_its_whole_prefix_only);
  RUN_TEST(test_findFormat_refuses_a_prefix_with_one_byte_changed);
  RUN_TEST(test_findFormat_reads_each_major_brand);
  RUN_TEST(test_findFormat_reads_no_bytes_as_unknown);
  RUN_TEST(test_formatName_names_each_format);
  RUN_TEST(test_fileTypeName_names_each_file_type);
  RUN_TEST(test_writeSha256Hex_hashes_every_byte_nul_bytes_included);
  RUN_TEST(test_writeSha256Hex_answers_false_and_empty_when_openssl_fails);
  RUN_TEST(test_findEmbeddedFileSignatures_finds_each_signature_at_its_offset);
  RUN_TEST(test_findEmbeddedFileSignatures_reads_a_zip_version_from_10_to_63);
  RUN_TEST(test_findEmbeddedFileSignatures_reads_a_pe_machine_from_the_list);
  RUN_TEST(test_findEmbeddedFileSignatures_reads_the_elf_class_encoding_and_version);
  RUN_TEST(test_findEmbeddedFileSignatures_reads_a_shell_path_under_bin_or_usr);
  RUN_TEST(test_findEmbeddedFileSignatures_matches_the_tags_in_either_case);
  RUN_TEST(test_findEmbeddedFileSignatures_needs_the_whole_signature_before_the_end);
  RUN_TEST(test_findEmbeddedFileSignatures_refuses_each_prefix_with_one_byte_changed);
  RUN_TEST(test_findEmbeddedFileSignatures_counts_matches_side_by_side);
  RUN_TEST(test_findEmbeddedFileSignatures_reads_no_bytes_as_no_match);
  RUN_TEST(test_findEmbeddedFileSignatures_keeps_the_first_offsets_and_counts_every_match);
  RUN_TEST(test_a_jpeg_with_a_zip_and_a_pdf_appended);
  RUN_TEST(test_scan_fills_the_format_the_count_the_hash_and_the_matches);
  RUN_TEST(test_scan_stops_at_an_unknown_format);
  RUN_TEST(test_scan_stops_when_the_hash_fails);
  RUN_TEST(test_registration_gate_test_count);
  return UNITY_END();
}
