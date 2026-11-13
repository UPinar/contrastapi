#ifndef BYTES_H
#define BYTES_H

#include <stdbool.h>
#include <stddef.h>

bool bytes_isEqual           (const char* bytes, size_t byte_count, const char* text, bool is_case_ignored);
bool bytes_hasPrefix         (const char* bytes, size_t byte_count, const char* prefix, size_t prefix_len, bool is_case_ignored);
bool bytes_hasSuffix         (const char* bytes, size_t byte_count, const char* suffix, size_t suffix_len, bool is_case_ignored);
bool bytes_isNameUnderSuffix (const char* name, size_t name_len, const char* suffix);
int  bytes_hexDigitValue     (char digit);
void bytes_writeHex          (const unsigned char* bytes, size_t byte_count, char* hex_out);
bool bytes_tryReadHex        (const char* hex, size_t hex_len, unsigned char* bytes_out);

#endif
