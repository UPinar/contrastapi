#include <assert.h>
#include <ctype.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include "watchlist_domain.h"

_Static_assert(WATCHLIST_DOMAIN_SHA256_HEX_LEN == SHA256_DIGEST_LENGTH * 2, "a SHA-256 in hex has two digits for each byte");

typedef struct {
  WatchlistDomainValue_t m_value;
  size_t                 m_textLen;
  bool                   m_isTextFull;
  EVP_MD_CTX*            mp_sha256Context;
  bool                   m_isSha256Ok;
} WatchlistDomainWriter_t;

static void          static_sortLines      (WatchlistDomainLine_t* lines, int line_count);
static int           static_compareLines   (const WatchlistDomainLine_t* left, const WatchlistDomainLine_t* right);
static unsigned char static_lineByte       (const WatchlistDomainLine_t* line, size_t index);
static void          static_writerOpen     (WatchlistDomainWriter_t* writer);
static void          static_writerAddLine  (WatchlistDomainWriter_t* writer, const WatchlistDomainLine_t* line);
static void          static_writerAppend   (WatchlistDomainWriter_t* writer, const char* bytes, size_t byte_count, bool is_kept);
static bool          static_writerTryClose (WatchlistDomainWriter_t* writer, WatchlistDomainValue_t* value_out);

#define WATCHLIST_DOMAIN_LOWER_CHUNK_SIZE 64

bool watchlist_domain_tryWriteState(const char* state, WatchlistDomainValue_t* value_out)
{
  WatchlistDomainLine_t line = { .mp_prefix = state, .m_prefixLen = strlen(state), .mp_domainName = "", .m_domainNameLen = 0 };
  return watchlist_domain_tryWriteLines(&line, 1, value_out);
}

const char* watchlist_domain_findExpiryBucket(const WatchlistDomainExpiryBucket_t* buckets, int bucket_count, int days_remaining)
{
  assert(buckets != NULL);
  assert(bucket_count > 0);

  for (int i = 0; i < bucket_count; i++)
  {
    if (days_remaining <= buckets[i].m_maxDays)
      return buckets[i].mp_text;
  }
  return "none";
}

bool watchlist_domain_tryWriteLines(WatchlistDomainLine_t* lines, int line_count, WatchlistDomainValue_t* value_out)
{
  static_sortLines(lines, line_count);

  WatchlistDomainWriter_t writer;
  static_writerOpen(&writer);

  for (int i = 0; i < line_count; i++)
  {
    if (i > 0 && static_compareLines(&lines[i - 1], &lines[i]) == 0)
      continue;
    static_writerAddLine(&writer, &lines[i]);
  }

  return static_writerTryClose(&writer, value_out);
}

bool watchlist_domain_tryWriteLinesAsGiven(const WatchlistDomainLine_t* lines, int line_count, WatchlistDomainValue_t* value_out)
{
  WatchlistDomainWriter_t writer;
  static_writerOpen(&writer);

  for (int i = 0; i < line_count; i++)
    static_writerAddLine(&writer, &lines[i]);

  return static_writerTryClose(&writer, value_out);
}

static void static_sortLines(WatchlistDomainLine_t* lines, int line_count)
{
  for (int i = 1; i < line_count; i++)
  {
    WatchlistDomainLine_t line = lines[i];
    int j = i;
    while (j > 0 && static_compareLines(&lines[j - 1], &line) > 0)
    {
      lines[j] = lines[j - 1];
      j--;
    }
    lines[j] = line;
  }
}

static int static_compareLines(const WatchlistDomainLine_t* left, const WatchlistDomainLine_t* right)
{
  size_t left_len   = left->m_prefixLen + left->m_domainNameLen;
  size_t right_len  = right->m_prefixLen + right->m_domainNameLen;
  size_t common_len = left_len < right_len ? left_len : right_len;
  for (size_t i = 0; i < common_len; i++)
  {
    unsigned char left_byte  = static_lineByte(left, i);
    unsigned char right_byte = static_lineByte(right, i);
    if (left_byte != right_byte)
      return left_byte < right_byte ? -1 : 1;
  }
  if (left_len == right_len)
    return 0;
  return left_len < right_len ? -1 : 1;
}

static unsigned char static_lineByte(const WatchlistDomainLine_t* line, size_t index)
{
  if (index < line->m_prefixLen)
    return (unsigned char)line->mp_prefix[index];
  return (unsigned char)tolower((unsigned char)line->mp_domainName[index - line->m_prefixLen]);
}

static void static_writerOpen(WatchlistDomainWriter_t* writer)
{
  memset(writer, 0, sizeof(*writer));
  writer->mp_sha256Context = EVP_MD_CTX_new();
  writer->m_isSha256Ok     = writer->mp_sha256Context != NULL && EVP_DigestInit_ex(writer->mp_sha256Context, EVP_sha256(), NULL) == 1;
}

static void static_writerAddLine(WatchlistDomainWriter_t* writer, const WatchlistDomainLine_t* line)
{
  size_t separator_len = writer->m_value.m_itemCount > 0 ? 1 : 0;
  size_t line_len      = line->m_prefixLen + line->m_domainNameLen;
  bool   is_kept       = !writer->m_isTextFull && writer->m_textLen + separator_len + line_len <= WATCHLIST_DOMAIN_VALUE_MAX_LEN;
  if (!is_kept)
    writer->m_isTextFull = true;

  static_writerAppend(writer, "\n", separator_len, is_kept);
  static_writerAppend(writer, line->mp_prefix, line->m_prefixLen, is_kept);
  for (size_t offset = 0; offset < line->m_domainNameLen; offset += WATCHLIST_DOMAIN_LOWER_CHUNK_SIZE)
  {
    char   lower_chunk[WATCHLIST_DOMAIN_LOWER_CHUNK_SIZE];
    size_t chunk_len = line->m_domainNameLen - offset < WATCHLIST_DOMAIN_LOWER_CHUNK_SIZE ? line->m_domainNameLen - offset : WATCHLIST_DOMAIN_LOWER_CHUNK_SIZE;
    for (size_t i = 0; i < chunk_len; i++)
      lower_chunk[i] = (char)tolower((unsigned char)line->mp_domainName[offset + i]);
    static_writerAppend(writer, lower_chunk, chunk_len, is_kept);
  }

  writer->m_value.m_itemCount++;
  if (is_kept)
    writer->m_value.m_keptItemCount++;
}

static void static_writerAppend(WatchlistDomainWriter_t* writer, const char* bytes, size_t byte_count, bool is_kept)
{
  writer->m_isSha256Ok = writer->m_isSha256Ok && EVP_DigestUpdate(writer->mp_sha256Context, bytes, byte_count) == 1;
  if (!is_kept)
    return;
  memcpy(writer->m_value.ma_text + writer->m_textLen, bytes, byte_count);
  writer->m_textLen += byte_count;
}

static bool static_writerTryClose(WatchlistDomainWriter_t* writer, WatchlistDomainValue_t* value_out)
{
  static const char HEX_DIGITS[] = "0123456789abcdef";
  unsigned char sha256[EVP_MAX_MD_SIZE];
  unsigned int  sha256_len = 0;
  bool is_sha256_ok = writer->m_isSha256Ok &&
                      EVP_DigestFinal_ex(writer->mp_sha256Context, sha256, &sha256_len) == 1 &&
                      sha256_len == SHA256_DIGEST_LENGTH;
  EVP_MD_CTX_free(writer->mp_sha256Context);
  if (!is_sha256_ok)
    return false;

  for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
  {
    writer->m_value.ma_sha256Hex[2 * i]     = HEX_DIGITS[sha256[i] >> 4];
    writer->m_value.ma_sha256Hex[2 * i + 1] = HEX_DIGITS[sha256[i] & 0x0f];
  }
  memcpy(value_out, &writer->m_value, sizeof(*value_out));
  return true;
}
