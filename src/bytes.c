#include <assert.h>
#include <ctype.h>
#include <string.h>
#include <strings.h>

#include "bytes.h"

static bool static_isSameBytes(const char* left, const char* right, size_t byte_count, bool is_case_ignored);

bool bytes_isEqual(const char* bytes, size_t byte_count, const char* text, bool is_case_ignored)
{
  assert(text != NULL);
  assert(bytes != NULL || byte_count == 0);

  if (strlen(text) != byte_count)
    return false;
  if (byte_count == 0)
    return true;

  if (is_case_ignored)
    return strncasecmp(bytes, text, byte_count) == 0;
  return memcmp(bytes, text, byte_count) == 0;
}

bool bytes_hasPrefix(const char* bytes, size_t byte_count, const char* prefix, size_t prefix_len, bool is_case_ignored)
{
  assert(bytes != NULL || byte_count == 0);
  assert(prefix != NULL || prefix_len == 0);

  if (byte_count < prefix_len)
    return false;
  return static_isSameBytes(bytes, prefix, prefix_len, is_case_ignored);
}

bool bytes_hasSuffix(const char* bytes, size_t byte_count, const char* suffix, size_t suffix_len, bool is_case_ignored)
{
  assert(bytes != NULL || byte_count == 0);
  assert(suffix != NULL || suffix_len == 0);

  if (byte_count < suffix_len)
    return false;
  return static_isSameBytes(bytes + byte_count - suffix_len, suffix, suffix_len, is_case_ignored);
}

bool bytes_isNameUnderSuffix(const char* name, size_t name_len, const char* suffix)
{
  assert(suffix != NULL);

  size_t suffix_len = strlen(suffix);
  if (!bytes_hasSuffix(name, name_len, suffix, suffix_len, true))
    return false;
  return name_len == suffix_len || name[name_len - suffix_len - 1] == '.';
}

int bytes_hexDigitValue(char digit)
{
  if (digit >= '0' && digit <= '9')
    return digit - '0';
  else if (digit >= 'a' && digit <= 'f')
    return digit - 'a' + 10;
  else if (digit >= 'A' && digit <= 'F')
    return digit - 'A' + 10;
  return -1;
}

void bytes_writeHex(const unsigned char* bytes, size_t byte_count, char* hex_out)
{
  assert(bytes != NULL || byte_count == 0);
  assert(hex_out != NULL);

  static const char HEX_DIGITS[] = "0123456789abcdef";
  for (size_t i = 0; i < byte_count; i++)
  {
    hex_out[2 * i]     = HEX_DIGITS[bytes[i] >> 4];
    hex_out[2 * i + 1] = HEX_DIGITS[bytes[i] & 0x0f];
  }
  hex_out[2 * byte_count] = '\0';
}

bool bytes_tryReadHex(const char* hex, size_t hex_len, unsigned char* bytes_out)
{
  assert(hex != NULL || hex_len == 0);
  assert(bytes_out != NULL);

  if (hex_len % 2 != 0)
    return false;

  for (size_t i = 0; i < hex_len / 2; i++)
  {
    int high_value = bytes_hexDigitValue(hex[2 * i]);
    int low_value  = bytes_hexDigitValue(hex[2 * i + 1]);
    if (high_value < 0 || low_value < 0)
      return false;
    bytes_out[i] = (unsigned char)(high_value * 16 + low_value);
  }
  return true;
}


static bool static_isSameBytes(const char* left, const char* right, size_t byte_count, bool is_case_ignored)
{
  if (byte_count == 0)
    return true;
  if (!is_case_ignored)
    return memcmp(left, right, byte_count) == 0;

  for (size_t i = 0; i < byte_count; i++)
  {
    if (tolower((unsigned char)left[i]) != tolower((unsigned char)right[i]))
      return false;
  }
  return true;
}
