#ifndef DBHELPER_H
#define DBHELPER_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <libpq-fe.h>

#include "cve.h"

#define DBHELPER_COLUMN_COUNT(column_names) ((int)(sizeof(column_names) / sizeof((column_names)[0])))

#define DBHELPER_PARAM_COUNT(param_values) ((int)(sizeof(param_values) / sizeof((param_values)[0])))

#define DBHELPER_COLUMN_INDEX(index_name, column_name) index_name,
#define DBHELPER_COLUMN_NAME(index_name, column_name)  column_name,

#define DBHELPER_UINT_STR_BUF_SIZE 16

#define DBHELPER_NUMERIC_PARAM_BUF_SIZE 32
#define DBHELPER_INT_PARAM_BUF_SIZE     16

const char* dbhelper_textOrNull    (const char* text);
const char* dbhelper_numberOrNull  (char* buf, size_t size, int decimals, double value);
const char* dbhelper_kevFilterValue(CveKevFilter_t kev_filter);
const char* dbhelper_intParam      (char* buf, size_t size, int value);

bool dbhelper_fetchColStr   (PGresult* res, int row, int col, char* dest, size_t max_len) __attribute__((warn_unused_result));
bool dbhelper_fetchColDouble(PGresult* res, int row, int col, double fallback, double* value_out) __attribute__((warn_unused_result));
bool dbhelper_fetchColInt   (PGresult* res, int row, int col, int fallback, int* value_out) __attribute__((warn_unused_result));
bool dbhelper_fetchColInt64 (PGresult* res, int row, int col, int64_t fallback, int64_t* value_out) __attribute__((warn_unused_result));
bool dbhelper_fetchColBool  (PGresult* res, int row, int col, bool* value_out) __attribute__((warn_unused_result));

bool dbhelper_isColWithinLength(PGresult* res, int row, int col, size_t max_len);
bool dbhelper_fetchColStrdup   (PGresult* res, int row, int col, char** out_ptr);

bool dbhelper_isColumnListEqual(const PGresult* res, const char* const* expected_names, int expected_count);

char* dbhelper_buildTextArrayLiteral(const char* const* values, int value_count);

PGresult* dbhelper_executeQueryFrom(const char* caller_name, PGconn* conn, const char* query, int n_params, const char** param_values);
#define dbhelper_executeQuery(conn, query, n_params, param_values) dbhelper_executeQueryFrom(__func__, (conn), (query), (n_params), (param_values))

bool dbhelper_runPurgeLoopFrom(const char* caller_name, PGconn* conn, const char* query, const char* column_name, int batch_row_count);
#define dbhelper_runPurgeLoop(conn, query, column_name, batch_row_count) dbhelper_runPurgeLoopFrom(__func__, (conn), (query), (column_name), (batch_row_count))


#endif
