#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <stdarg.h>
#include <limits.h>
#include <stdint.h>
#include <math.h>
#include <time.h>
#include <assert.h>

#include "dbhelper.h"

_Static_assert(sizeof(long long) == sizeof(int64_t), "long long must be 64 bits");

_Static_assert(DBHELPER_INT_PARAM_BUF_SIZE >= sizeof("-2147483648"),
               "DBHELPER_INT_PARAM_BUF_SIZE must hold every int in decimal text");

static __thread time_t       g_logSecond           = (time_t)-1;
static __thread unsigned int g_suppressedLineCount = 0;

static void static_logLine(const char* format, ...) __attribute__((format(printf, 1, 2)));

static void static_logLine(const char* format, ...)
{
  time_t now = time(NULL);
  if (now == g_logSecond)
  {
    g_suppressedLineCount++;
    return;
  }
  g_logSecond = now;

  if (g_suppressedLineCount > 0)
  {
    fprintf(stderr, "static_logLine: %u lines suppressed since the last one\n", g_suppressedLineCount);
    g_suppressedLineCount = 0;
  }

  va_list args;
  va_start(args, format);
  vfprintf(stderr, format, args);
  va_end(args);
}

static const char* static_columnName(const PGresult* res, int col)
{
  const char* column_name = PQfname(res, col);
  return column_name ? column_name : "?";
}

static bool static_isColumnInResult(const PGresult* res, int col, const char* reader_name)
{
  int column_count = PQnfields(res);
  if (col >= 0 && col < column_count)
    return true;

  static_logLine("%s: no column at index %d (column count %d)\n", reader_name, col, column_count);
  return false;
}

bool dbhelper_fetchColStr(PGresult* res, int row, int col, char* dest, size_t max_len)
{
  assert(res  != NULL);
  assert(dest != NULL);

  if (!static_isColumnInResult(res, col, __func__))
  {
    dest[0] = '\0';
    return false;
  }

  const char* value  = PQgetvalue(res, row, col);
  size_t      length = strlen(value);
  if (length > max_len)
  {
    static_logLine("dbhelper_fetchColStr: column %s (index %d) holds %zu bytes, limit %zu\n",
                   static_columnName(res, col), col, length, max_len);
    dest[0] = '\0';
    return false;
  }

  memcpy(dest, value, length + 1);
  return true;
}

bool dbhelper_fetchColDouble(PGresult* res, int row, int col, double fallback, double* value_out)
{
  assert(res != NULL);
  assert(value_out != NULL);

  *value_out = fallback;
  if (!static_isColumnInResult(res, col, __func__))
    return false;

  const char* text = PQgetvalue(res, row, col);
  if (PQgetisnull(res, row, col) || text[0] == '\0')
    return true;

  char* parse_end;
  errno = 0;
  double parsed_value = strtod(text, &parse_end);
  if (*parse_end != '\0' || errno != 0)
  {
    static_logLine("dbhelper_fetchColDouble: column %s (index %d) holds no number\n",
                   static_columnName(res, col), col);
    return false;
  }
  if (!isfinite(parsed_value))
  {
    static_logLine("dbhelper_fetchColDouble: column %s (index %d) holds no finite number, read as the fallback\n",
                   static_columnName(res, col), col);
    return true;
  }

  *value_out = parsed_value;
  return true;
}

bool dbhelper_fetchColInt(PGresult* res, int row, int col, int fallback, int* value_out)
{
  assert(res != NULL);
  assert(value_out != NULL);

  *value_out = fallback;
  if (!static_isColumnInResult(res, col, __func__))
    return false;

  const char* text = PQgetvalue(res, row, col);
  if (PQgetisnull(res, row, col) || text[0] == '\0')
    return true;

  char* parse_end;
  errno = 0;
  long parsed_value = strtol(text, &parse_end, 10);
  if (*parse_end != '\0' || errno != 0 || parsed_value < (long)INT_MIN || parsed_value > (long)INT_MAX)
  {
    static_logLine("dbhelper_fetchColInt: column %s (index %d) holds no int\n",
                   static_columnName(res, col), col);
    return false;
  }

  *value_out = (int)parsed_value;
  return true;
}

bool dbhelper_fetchColInt64(PGresult* res, int row, int col, int64_t fallback, int64_t* value_out)
{
  assert(res != NULL);
  assert(value_out != NULL);

  *value_out = fallback;
  if (!static_isColumnInResult(res, col, __func__))
    return false;

  const char* text = PQgetvalue(res, row, col);
  if (PQgetisnull(res, row, col) || text[0] == '\0')
    return true;

  char* parse_end;
  errno = 0;
  long long parsed_value = strtoll(text, &parse_end, 10);
  if (*parse_end != '\0' || errno != 0)
  {
    static_logLine("dbhelper_fetchColInt64: column %s (index %d) holds no int64\n",
                   static_columnName(res, col), col);
    return false;
  }

  *value_out = (int64_t)parsed_value;
  return true;
}

bool dbhelper_fetchColBool(PGresult* res, int row, int col, bool* value_out)
{
  assert(res != NULL);
  assert(value_out != NULL);

  *value_out = false;
  if (!static_isColumnInResult(res, col, __func__))
    return false;

  if (!PQgetisnull(res, row, col))
  {
    const char* text = PQgetvalue(res, row, col);
    if (strcmp(text, "t") == 0)
    {
      *value_out = true;
      return true;
    }
    else if (strcmp(text, "f") == 0)
      return true;
  }

  static_logLine("dbhelper_fetchColBool: column %s (index %d) holds no boolean\n",
                 static_columnName(res, col), col);
  return false;
}

bool dbhelper_isColWithinLength(PGresult* res, int row, int col, size_t max_len)
{
  assert(res != NULL);

  if (!static_isColumnInResult(res, col, __func__))
    return false;

  if (PQgetisnull(res, row, col))
    return true;

  size_t length = strlen(PQgetvalue(res, row, col));
  if (length > max_len)
  {
    static_logLine("dbhelper_isColWithinLength: column %s (index %d) holds %zu bytes, limit %zu\n",
                   static_columnName(res, col), col, length, max_len);
    return false;
  }
  return true;
}

bool dbhelper_fetchColStrdup(PGresult* res, int row, int col, char** out_ptr)
{
  assert(res     != NULL);
  assert(out_ptr != NULL);

  *out_ptr = NULL;
  if (!static_isColumnInResult(res, col, __func__))
    return false;

  if (PQgetisnull(res, row, col))
    return true;
  *out_ptr = strdup(PQgetvalue(res, row, col));
  return (*out_ptr != NULL);
}

bool dbhelper_isColumnListEqual(const PGresult* res, const char* const* expected_names, int expected_count)
{
  assert(res != NULL);
  assert(expected_names != NULL);

  int column_count = PQnfields(res);
  if (column_count != expected_count)
  {
    static_logLine("dbhelper_isColumnListEqual: column count %d, expected %d\n",
                   column_count, expected_count);
    return false;
  }

  for (int col = 0; col < column_count; col++)
  {
    const char* column_name = static_columnName(res, col);
    if (strcmp(column_name, expected_names[col]) != 0)
    {
      static_logLine("dbhelper_isColumnListEqual: column %d is %s, expected %s\n",
                     col, column_name, expected_names[col]);
      return false;
    }
  }
  return true;
}

PGresult* dbhelper_executeQueryFrom(const char* caller_name, PGconn* conn, const char* query, int n_params, const char** param_values)
{
  assert(caller_name != NULL);
  assert(query != NULL);

  PGresult* res = PQexecParams(conn, query, n_params, NULL, param_values, NULL, NULL, 0);
  if (res && PQresultStatus(res) == PGRES_TUPLES_OK)
    return res;

  const char* sqlstate = res ? PQresultErrorField(res, PG_DIAG_SQLSTATE) : NULL;
  static_logLine("dbhelper_executeQueryFrom: %s: query failed (status %s, sqlstate %s, connection %s)\n",
                 caller_name,
                 res ? PQresStatus(PQresultStatus(res)) : "no result",
                 sqlstate ? sqlstate : "none",
                 PQstatus(conn) == CONNECTION_OK ? "ok" : "bad");
  if (res)
    PQclear(res);
  return NULL;
}

bool dbhelper_runPurgeLoopFrom(const char* caller_name, PGconn* conn, const char* query, const char* column_name, int batch_row_count)
{
  assert(caller_name     != NULL);
  assert(conn            != NULL);
  assert(query           != NULL);
  assert(column_name     != NULL);
  assert(batch_row_count >  0);

  char batch_row_count_text[DBHELPER_UINT_STR_BUF_SIZE];
  snprintf(batch_row_count_text, sizeof(batch_row_count_text), "%d", batch_row_count);
  const char* param_values[] = { batch_row_count_text };

  const char* const column_names[] = { column_name };
  int purged_row_count = batch_row_count;
  while (purged_row_count == batch_row_count)
  {
    PGresult* res = dbhelper_executeQueryFrom(caller_name, conn, query, DBHELPER_PARAM_COUNT(param_values), param_values);
    if (!res)
      return false;

    bool is_read =  PQntuples(res) == 1                                                                &&
                    dbhelper_isColumnListEqual(res, column_names, DBHELPER_COLUMN_COUNT(column_names)) &&
                    !PQgetisnull(res, 0, 0)                                                            &&
                    dbhelper_fetchColInt(res, 0, 0, 0, &purged_row_count);
    PQclear(res);

    if (!is_read)
      return false;
  }
  return true;
}

char* dbhelper_buildTextArrayLiteral(const char* const* values, int value_count)
{
  assert(values != NULL || value_count == 0);
  assert(value_count >= 0);

  const size_t braces_and_nul_byte_count   = 3;
  const size_t quotes_and_comma_byte_count = 3;
  const size_t escaped_byte_max_byte_count = 2;

  size_t literal_size = braces_and_nul_byte_count;
  for (int i = 0; i < value_count; i++)
    literal_size += quotes_and_comma_byte_count + escaped_byte_max_byte_count * strlen(values[i]);

  char* literal = malloc(literal_size);
  if (!literal)
    return NULL;

  size_t pos = 0;
  literal[pos++] = '{';
  for (int i = 0; i < value_count; i++)
  {
    if (i > 0)
      literal[pos++] = ',';
    literal[pos++] = '"';

    for (const char* byte = values[i]; *byte != '\0'; byte++)
    {
      if (*byte == '"' || *byte == '\\')
        literal[pos++] = '\\';
      literal[pos++] = *byte;
    }
    literal[pos++] = '"';
  }
  literal[pos++] = '}';
  literal[pos]   = '\0';
  
  assert(pos < literal_size);
  return literal;
}

const char* dbhelper_textOrNull(const char* text)
{
  assert(text != NULL);

  return (*text != '\0') ? text : NULL;
}

const char* dbhelper_numberOrNull(char* buf, size_t size, int decimals, double value)
{
  assert(buf  != NULL);
  assert(size > 0);

  if (value < 0.0)
    return NULL;
  snprintf(buf, size, "%.*f", decimals, value);
  return buf;
}

const char* dbhelper_kevFilterValue(CveKevFilter_t kev_filter)
{
  switch (kev_filter)
  {
    case CVE_KEV_FILTER_ANY:
      return NULL;
    case CVE_KEV_FILTER_ONLY_IN_KEV:
      return "true";
    case CVE_KEV_FILTER_NOT_IN_KEV:
      return "false";
  }
  return NULL;
}

const char* dbhelper_intParam(char* buf, size_t size, int value)
{
  assert(buf  != NULL);
  assert(size >= DBHELPER_INT_PARAM_BUF_SIZE);

  snprintf(buf, size, "%d", value);
  return buf;
}
