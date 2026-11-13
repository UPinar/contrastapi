#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <libpq-fe.h>

#include "unity/unity.h"
#include "db.h"
#include "dbhelper.h"
#include "watchlist/watchlist.h"
#include "request.h"
#include "validate.h"

#define CVELOOKUP_ROW_COLUMN_COUNT                        38
#define CVELOOKUP_ROW_CWES_COLUMN_INDEX                    9
#define CVELOOKUP_ROW_CVE_TAGS_COLUMN_INDEX               15
#define CVELOOKUP_ROW_AFFECTED_PRODUCTS_COLUMN_INDEX      17
#define CVELOOKUP_ROW_REFS_COLUMN_INDEX                   18
#define CVELOOKUP_ROW_EPSS_TREND_COLUMN_INDEX             19
#define CVELOOKUP_ROW_RANSOMWARE_COLUMN_INDEX             20
#define CVELOOKUP_ROW_CVSS_V4_VECTOR_COLUMN_INDEX         22
#define CVELOOKUP_ROW_SSVC_EXPLOITATION_COLUMN_INDEX      23
#define CVELOOKUP_ROW_SSVC_AUTOMATABLE_COLUMN_INDEX       24
#define CVELOOKUP_ROW_SSVC_TECHNICAL_IMPACT_COLUMN_INDEX  25
#define CVELOOKUP_ROW_SSVC_VERSION_COLUMN_INDEX           26
#define CVELOOKUP_ROW_SSVC_SCORED_AT_COLUMN_INDEX         27
#define CVELOOKUP_ROW_METASPLOIT_FEED_LOADED_COLUMN_INDEX 28
#define CVELOOKUP_ROW_NUCLEI_TEMPLATE_COUNT_COLUMN_INDEX       29
#define CVELOOKUP_ROW_NUCLEI_TEMPLATE_FEED_LOADED_COLUMN_INDEX 30
#define CVELOOKUP_ROW_NUCLEI_TEMPLATES_COLUMN_INDEX            31
#define CVELOOKUP_ROW_CVSS_V3_SOURCE_COLUMN_INDEX              32
#define CVELOOKUP_ROW_CVSS_V4_SOURCE_COLUMN_INDEX              33
#define CVELOOKUP_ROW_CWE_SOURCE_COLUMN_INDEX                  34
#define CVELOOKUP_ROW_AFFECTED_PRODUCT_COUNT_COLUMN_INDEX      35
#define CVELOOKUP_ROW_PRODUCT_COUNT_BY_VENDOR_COLUMN_INDEX     36
#define CVELOOKUP_ROW_REF_COUNT_COLUMN_INDEX                   37

#define WATCHLISTEVENTS_ROW_COLUMN_COUNT 65

#define FAKE_ANSWER_MAX_COLUMNS  WATCHLISTEVENTS_ROW_COLUMN_COUNT
#define FAKE_ANSWER_MAX_ROWS     (HEALTH_MAX_FEEDS + 1)
#define FAKE_ANSWER_QUEUE_LEN     8

static const char g_sqlNullMarker[] = "";
#define FAKE_SQL_NULL g_sqlNullMarker

typedef struct {
  ExecStatusType m_status;
  int            m_columnCount;
  int            m_rowCount;
  const char*    ma_columnNames[FAKE_ANSWER_MAX_COLUMNS];
  const char*    ma_cells[FAKE_ANSWER_MAX_ROWS][FAKE_ANSWER_MAX_COLUMNS];
} FakeAnswer_t;

static const char* const g_cvelookupRowValues[CVELOOKUP_ROW_COLUMN_COUNT] = {
  "CVE-2021-44228", "description", "CRITICAL", "10.0", "", "2021-12-10T00:00:00Z",
  "0.97566", "0.99970", "CWE-917", "", "t", "2021-12-10", "Analyzed", "0", "0", "[]", "0",
  "", "", "", "Known", "9.3", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
  "active", "yes", "total", "2.0.3", "2024-04-17T04:00:13Z", "t", "1", "t", "",
  "nvd", "cna", "other", "6", "", "4"
};

static const char* const g_cvelookupColumnNames[CVELOOKUP_ROW_COLUMN_COUNT] = {
  "cve_id", "cve_description", "severity", "cvss_v3", "cvss_v3_vector", "published_time",
  "epss_score", "epss_percentile", "cwe_id", "cwes", "in_kev", "kev_date_added",
  "vulnerability_status", "poc_count", "vendor_advisory_count", "cve_tags", "metasploit_module_count",
  "affected_products", "refs", "epss_trend", "ransomware_campaign", "cvss_v4", "cvss_v4_vector",
  "ssvc_exploitation", "ssvc_automatable", "ssvc_technical_impact", "ssvc_version", "ssvc_scored_at",
  "metasploit_feed_loaded", "nuclei_template_count", "nuclei_template_feed_loaded", "nuclei_templates",
  "cvss_v3_source", "cvss_v4_source", "cwe_source", "affected_product_count",
  "product_count_by_vendor", "ref_count"
};

static const char*    g_cwesDocument             = "[]";
static const char*    g_cveTagsDocument          = "[]";
static const char*    g_affectedProductsDocument = "[]";
static const char*    g_refsDocument             = "[]";
static const char*    g_epssTrendDocument        = "[]";
static const char*    g_nucleiTemplatesDocument = "[]";
static const char*    g_productCountByVendorDocument = "{}";
static int            g_rowCount                 = 1;
static ExecStatusType g_resultStatus             = PGRES_TUPLES_OK;

static FakeAnswer_t g_queuedAnswers[FAKE_ANSWER_QUEUE_LEN];
static int          g_queuedAnswerCount = 0;

#define FAKE_CALL_MAX_PARAMS   17
#define FAKE_CALL_PARAM_LEN    2048
#define FAKE_CALL_COMMAND_LEN  8192

typedef struct {
  char ma_command[FAKE_CALL_COMMAND_LEN];
  int  m_paramCount;
  int  m_resultFormat;
  bool ma_isParamNull[FAKE_CALL_MAX_PARAMS];
  char ma_params[FAKE_CALL_MAX_PARAMS][FAKE_CALL_PARAM_LEN];
} FakeCall_t;

static int        g_callCount = 0;
static FakeCall_t g_calls[FAKE_ANSWER_QUEUE_LEN];

static time_t         g_fakeNow              = 1000000;
static const char*    g_fakeSqlstate         = NULL;
static ConnStatusType g_fakeConnectionStatus = CONNECTION_BAD;

static int g_strdupFailsAtCall = 0;
static int g_strdupCallCount   = 0;

static int g_mallocFailsAtCall = 0;
static int g_mallocCallCount   = 0;

static volatile bool g_dirtyMalloc = false;

static void static_resetFake(void)
{
  g_cwesDocument             = "[]";
  g_cveTagsDocument          = "[]";
  g_affectedProductsDocument = "[]";
  g_refsDocument             = "[]";
  g_epssTrendDocument        = "[]";
  g_nucleiTemplatesDocument = "[]";
  g_productCountByVendorDocument = "{}";
  g_rowCount                 = 1;
  g_resultStatus             = PGRES_TUPLES_OK;
  memset(g_queuedAnswers, 0, sizeof(g_queuedAnswers));
  g_queuedAnswerCount        = 0;
  g_callCount                = 0;
  g_fakeSqlstate             = NULL;
  g_fakeConnectionStatus     = CONNECTION_BAD;
  g_strdupFailsAtCall        = 0;
  g_strdupCallCount          = 0;
  g_mallocFailsAtCall        = 0;
  g_mallocCallCount          = 0;
  g_dirtyMalloc              = false;
}

static void static_clearLogLimit(void);

void setUp(void)
{
  static_resetFake();
  static_clearLogLimit();
}

void tearDown(void) { static_resetFake(); }

time_t __wrap_time(time_t* now_out)
{
  if (now_out)
    *now_out = g_fakeNow;
  return g_fakeNow;
}

char* __wrap_PQresultErrorField(const PGresult* res, int fieldcode)
{
  (void)res;
  return (fieldcode == PG_DIAG_SQLSTATE) ? (char*)g_fakeSqlstate : NULL;
}

ConnStatusType __wrap_PQstatus(const PGconn* conn)
{
  (void)conn;
  return g_fakeConnectionStatus;
}

char* __real_strdup(const char* text);
char* __wrap_strdup(const char* text);
void* __real_malloc(size_t size);
void* __wrap_malloc(size_t size);

char* __wrap_strdup(const char* text)
{
  g_strdupCallCount++;
  if (g_strdupCallCount == g_strdupFailsAtCall)
    return NULL;
  return __real_strdup(text);
}

void* __wrap_malloc(size_t size)
{
  if (g_mallocFailsAtCall > 0 && ++g_mallocCallCount == g_mallocFailsAtCall)
    return NULL;
  void* block = __real_malloc(size);
  if (block && g_dirtyMalloc)
    memset(block, 0xA5, size);
  return block;
}

static FakeAnswer_t* static_queueAnswer(ExecStatusType status, int column_count, int row_count)
{
  assert(g_queuedAnswerCount < FAKE_ANSWER_QUEUE_LEN);
  assert(column_count >= 0 && column_count <= FAKE_ANSWER_MAX_COLUMNS);
  assert(row_count >= 0 && row_count <= FAKE_ANSWER_MAX_ROWS);

  FakeAnswer_t* answer = &g_queuedAnswers[g_queuedAnswerCount++];
  memset(answer, 0, sizeof(*answer));
  answer->m_status      = status;
  answer->m_columnCount = column_count;
  answer->m_rowCount    = row_count;
  return answer;
}

static PGresult* static_buildResult(const FakeAnswer_t* answer)
{
  PGresult* result = PQmakeEmptyPGresult(NULL, answer->m_status);
  if (!result)
    return NULL;

  if (answer->m_status != PGRES_TUPLES_OK)
    return result;

  PGresAttDesc columns[FAKE_ANSWER_MAX_COLUMNS];
  memset(columns, 0, sizeof(columns));
  for (int col = 0; col < answer->m_columnCount; col++)
    columns[col].name = (char*)(answer->ma_columnNames[col] ? answer->ma_columnNames[col] : "column");

  if (!PQsetResultAttrs(result, answer->m_columnCount, columns))
  {
    PQclear(result);
    return NULL;
  }

  for (int row = 0; row < answer->m_rowCount; row++)
  {
    for (int col = 0; col < answer->m_columnCount; col++)
    {
      const char* value = answer->ma_cells[row][col];
      assert(value != NULL);

      int length = (value == FAKE_SQL_NULL) ? -1 : (int)strlen(value);
      if (!PQsetvalue(result, row, col, (char*)value, length))
      {
        PQclear(result);
        return NULL;
      }
    }
  }

  return result;
}

static void static_fillCvelookupRow(FakeAnswer_t* answer, int row)
{
  for (int col = 0; col < CVELOOKUP_ROW_COLUMN_COUNT; col++)
  {
    answer->ma_columnNames[col] = g_cvelookupColumnNames[col];
    answer->ma_cells[row][col]  = g_cvelookupRowValues[col];
  }

  answer->ma_cells[row][CVELOOKUP_ROW_CWES_COLUMN_INDEX]              = g_cwesDocument;
  answer->ma_cells[row][CVELOOKUP_ROW_CVE_TAGS_COLUMN_INDEX]          = g_cveTagsDocument;
  answer->ma_cells[row][CVELOOKUP_ROW_AFFECTED_PRODUCTS_COLUMN_INDEX] = g_affectedProductsDocument;
  answer->ma_cells[row][CVELOOKUP_ROW_REFS_COLUMN_INDEX]              = g_refsDocument;
  answer->ma_cells[row][CVELOOKUP_ROW_EPSS_TREND_COLUMN_INDEX]        = g_epssTrendDocument;
  answer->ma_cells[row][CVELOOKUP_ROW_NUCLEI_TEMPLATES_COLUMN_INDEX] = g_nucleiTemplatesDocument;
  answer->ma_cells[row][CVELOOKUP_ROW_PRODUCT_COUNT_BY_VENDOR_COLUMN_INDEX] = g_productCountByVendorDocument;
}

static const FakeCall_t* static_call(int call_index)
{
  TEST_ASSERT_TRUE_MESSAGE(call_index >= 0 && call_index < g_callCount, "no such call");
  TEST_ASSERT_TRUE_MESSAGE(g_callCount - call_index <= FAKE_ANSWER_QUEUE_LEN, "call overwritten");
  return &g_calls[call_index % FAKE_ANSWER_QUEUE_LEN];
}

static const FakeCall_t* static_lastCall(void)
{
  return static_call(g_callCount - 1);
}

PGresult* __wrap_PQexecParams(PGconn* conn, const char* command, int n_params, const Oid* param_types,
                              const char* const* param_values, const int* param_lengths,
                              const int* param_formats, int result_format)
{
  (void)conn;
  (void)param_types;
  (void)param_lengths;
  (void)param_formats;

  int call_index = g_callCount++;
  FakeCall_t* call = &g_calls[call_index % FAKE_ANSWER_QUEUE_LEN];
  int written = snprintf(call->ma_command, sizeof(call->ma_command), "%s", command);
  TEST_ASSERT_TRUE(written >= 0 && (size_t)written < sizeof(call->ma_command));
  TEST_ASSERT_TRUE(n_params >= 0 && n_params <= FAKE_CALL_MAX_PARAMS);
  TEST_ASSERT_TRUE(n_params == 0 || param_values != NULL);
  call->m_paramCount   = n_params;
  call->m_resultFormat = result_format;
  for (int n = 0; n < n_params; n++)
  {
    call->ma_isParamNull[n] = (param_values[n] == NULL);
    written = snprintf(call->ma_params[n], sizeof(call->ma_params[n]), "%s",
                       call->ma_isParamNull[n] ? "" : param_values[n]);
    TEST_ASSERT_TRUE(written >= 0 && (size_t)written < sizeof(call->ma_params[n]));
  }

  if (g_queuedAnswerCount > 0)
  {
    if (call_index >= g_queuedAnswerCount)
      return NULL;
    return static_buildResult(&g_queuedAnswers[call_index]);
  }

  assert(g_rowCount <= FAKE_ANSWER_MAX_ROWS);
  FakeAnswer_t answer;
  memset(&answer, 0, sizeof(answer));
  answer.m_status      = g_resultStatus;
  answer.m_columnCount = CVELOOKUP_ROW_COLUMN_COUNT;
  answer.m_rowCount    = g_rowCount;
  for (int col = 0; col < CVELOOKUP_ROW_COLUMN_COUNT; col++)
    answer.ma_columnNames[col] = g_cvelookupColumnNames[col];
  for (int row = 0; row < g_rowCount; row++)
    static_fillCvelookupRow(&answer, row);

  return static_buildResult(&answer);
}

static char* static_makeJsonArrayDocument(size_t length)
{
  assert(length >= 4);

  char* document = malloc(length + 1);
  if (!document)
    return NULL;

  memset(document, 'a', length);
  document[0]          = '[';
  document[1]          = '"';
  document[length - 2] = '"';
  document[length - 1] = ']';
  document[length]     = '\0';
  return document;
}

void test_CVELOOKUP_long_refs_is_read_whole(void)
{
  static const size_t lengths[] = { 8193, 65537, 1048577 };

  for (size_t row = 0; row < sizeof(lengths) / sizeof(lengths[0]); row++)
  {
    char* document = static_makeJsonArrayDocument(lengths[row]);
    TEST_ASSERT_NOT_NULL(document);
    g_refsDocument = document;
    CVELOOKUPRecord_t record = { 0 };
    char message[64] = "";
    snprintf(message, sizeof(message), "refs length %zu", lengths[row]);

    DbStatus_t db_status = db_CVELOOKUP(NULL, "CVE-2021-44228", &record);

    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_OK, db_status, message);
    TEST_ASSERT_NOT_NULL_MESSAGE(record.mp_refs, message);
    TEST_ASSERT_EQUAL_size_t_MESSAGE(lengths[row], strlen(record.mp_refs), message);
    TEST_ASSERT_EQUAL_MEMORY_MESSAGE(document, record.mp_refs, lengths[row], message);

    db_CVELOOKUPRecordFree(&record);
    free(document);
  }
}

void test_CVELOOKUP_long_affected_products_is_read_whole(void)
{
  static const size_t lengths[] = { 8193, 65537, 1048577 };

  for (size_t row = 0; row < sizeof(lengths) / sizeof(lengths[0]); row++)
  {
    char* document = static_makeJsonArrayDocument(lengths[row]);
    TEST_ASSERT_NOT_NULL(document);
    g_affectedProductsDocument = document;
    CVELOOKUPRecord_t record = { 0 };
    char message[64] = "";
    snprintf(message, sizeof(message), "affected_products length %zu", lengths[row]);

    DbStatus_t db_status = db_CVELOOKUP(NULL, "CVE-2021-44228", &record);

    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_OK, db_status, message);
    TEST_ASSERT_NOT_NULL_MESSAGE(record.mp_affectedProducts, message);
    TEST_ASSERT_EQUAL_size_t_MESSAGE(lengths[row], strlen(record.mp_affectedProducts), message);
    TEST_ASSERT_EQUAL_MEMORY_MESSAGE(document, record.mp_affectedProducts, lengths[row], message);

    db_CVELOOKUPRecordFree(&record);
    free(document);
  }
}

void test_CVELOOKUP_long_cwes_is_read_whole(void)
{
  static const size_t lengths[] = { 8193, 65537, 1048577 };

  for (size_t row = 0; row < sizeof(lengths) / sizeof(lengths[0]); row++)
  {
    char* document = static_makeJsonArrayDocument(lengths[row]);
    TEST_ASSERT_NOT_NULL(document);
    g_cwesDocument = document;
    CVELOOKUPRecord_t record = { 0 };
    char message[64] = "";
    snprintf(message, sizeof(message), "cwes length %zu", lengths[row]);

    DbStatus_t db_status = db_CVELOOKUP(NULL, "CVE-2021-44228", &record);

    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_OK, db_status, message);
    TEST_ASSERT_NOT_NULL_MESSAGE(record.mp_cwes, message);
    TEST_ASSERT_EQUAL_size_t_MESSAGE(lengths[row], strlen(record.mp_cwes), message);
    TEST_ASSERT_EQUAL_MEMORY_MESSAGE(document, record.mp_cwes, lengths[row], message);

    db_CVELOOKUPRecordFree(&record);
    free(document);
  }
}

void test_CVELOOKUP_long_cve_tags_is_read_whole(void)
{
  static const size_t lengths[] = { 8193, 65537, 1048577 };

  for (size_t row = 0; row < sizeof(lengths) / sizeof(lengths[0]); row++)
  {
    char* document = static_makeJsonArrayDocument(lengths[row]);
    TEST_ASSERT_NOT_NULL(document);
    g_cveTagsDocument = document;
    CVELOOKUPRecord_t record = { 0 };
    char message[64] = "";
    snprintf(message, sizeof(message), "cve_tags length %zu", lengths[row]);

    DbStatus_t db_status = db_CVELOOKUP(NULL, "CVE-2021-44228", &record);

    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_OK, db_status, message);
    TEST_ASSERT_NOT_NULL_MESSAGE(record.mp_cveTags, message);
    TEST_ASSERT_EQUAL_size_t_MESSAGE(lengths[row], strlen(record.mp_cveTags), message);
    TEST_ASSERT_EQUAL_MEMORY_MESSAGE(document, record.mp_cveTags, lengths[row], message);

    db_CVELOOKUPRecordFree(&record);
    free(document);
  }
}

void test_CVELOOKUP_epss_trend_at_its_length_check_is_read_whole(void)
{
  char* document = static_makeJsonArrayDocument(CVELOOKUP_EPSS_TREND_MAX_LEN);
  TEST_ASSERT_NOT_NULL(document);
  g_epssTrendDocument = document;
  CVELOOKUPRecord_t record = { 0 };

  DbStatus_t db_status = db_CVELOOKUP(NULL, "CVE-2021-44228", &record);

  TEST_ASSERT_EQUAL_INT(DB_OK, db_status);
  TEST_ASSERT_NOT_NULL(record.mp_epssTrend);
  TEST_ASSERT_EQUAL_size_t(CVELOOKUP_EPSS_TREND_MAX_LEN, strlen(record.mp_epssTrend));
  TEST_ASSERT_EQUAL_MEMORY(document, record.mp_epssTrend, CVELOOKUP_EPSS_TREND_MAX_LEN);

  db_CVELOOKUPRecordFree(&record);
  free(document);
}

void test_CVELOOKUP_epss_trend_past_its_length_check_is_refused(void)
{
  char* document = static_makeJsonArrayDocument(CVELOOKUP_EPSS_TREND_MAX_LEN + 1);
  TEST_ASSERT_NOT_NULL(document);
  g_epssTrendDocument = document;
  CVELOOKUPRecord_t record = { 0 };

  DbStatus_t db_status = db_CVELOOKUP(NULL, "CVE-2021-44228", &record);

  TEST_ASSERT_EQUAL_INT(DB_ERROR, db_status);
  TEST_ASSERT_NULL(record.mp_cwes);
  TEST_ASSERT_NULL(record.mp_cveTags);
  TEST_ASSERT_NULL(record.mp_affectedProducts);
  TEST_ASSERT_NULL(record.mp_productCountByVendor);
  TEST_ASSERT_NULL(record.mp_refs);
  TEST_ASSERT_NULL(record.mp_epssTrend);
  TEST_ASSERT_NULL(record.mp_nucleiTemplates);

  free(document);
}

void test_CVELOOKUP_nuclei_templates_at_its_length_check_is_read_whole(void)
{
  char* document = static_makeJsonArrayDocument(CVELOOKUP_NUCLEI_TEMPLATES_MAX_LEN);
  TEST_ASSERT_NOT_NULL(document);
  g_nucleiTemplatesDocument = document;
  CVELOOKUPRecord_t record = { 0 };

  DbStatus_t db_status = db_CVELOOKUP(NULL, "CVE-2021-44228", &record);

  TEST_ASSERT_EQUAL_INT(DB_OK, db_status);
  TEST_ASSERT_NOT_NULL(record.mp_nucleiTemplates);
  TEST_ASSERT_EQUAL_size_t(CVELOOKUP_NUCLEI_TEMPLATES_MAX_LEN, strlen(record.mp_nucleiTemplates));
  TEST_ASSERT_EQUAL_MEMORY(document, record.mp_nucleiTemplates, CVELOOKUP_NUCLEI_TEMPLATES_MAX_LEN);

  db_CVELOOKUPRecordFree(&record);
  free(document);
}

void test_CVELOOKUP_nuclei_templates_past_its_length_check_is_refused(void)
{
  char* document = static_makeJsonArrayDocument(CVELOOKUP_NUCLEI_TEMPLATES_MAX_LEN + 1);
  TEST_ASSERT_NOT_NULL(document);
  g_nucleiTemplatesDocument = document;
  CVELOOKUPRecord_t record = { 0 };

  DbStatus_t db_status = db_CVELOOKUP(NULL, "CVE-2021-44228", &record);

  TEST_ASSERT_EQUAL_INT(DB_ERROR, db_status);
  TEST_ASSERT_NULL(record.mp_cwes);
  TEST_ASSERT_NULL(record.mp_cveTags);
  TEST_ASSERT_NULL(record.mp_affectedProducts);
  TEST_ASSERT_NULL(record.mp_productCountByVendor);
  TEST_ASSERT_NULL(record.mp_refs);
  TEST_ASSERT_NULL(record.mp_epssTrend);
  TEST_ASSERT_NULL(record.mp_nucleiTemplates);

  free(document);
}

void test_CVELOOKUP_no_row_is_not_found(void)
{
  g_rowCount = 0;
  CVELOOKUPRecord_t record = { 0 };

  DbStatus_t db_status = db_CVELOOKUP(NULL, "CVE-2021-44228", &record);

  TEST_ASSERT_EQUAL_INT(DB_NOT_FOUND, db_status);
}

void test_CVELOOKUP_failed_query_is_error(void)
{
  g_resultStatus = PGRES_FATAL_ERROR;
  CVELOOKUPRecord_t record = { 0 };

  DbStatus_t db_status = db_CVELOOKUP(NULL, "CVE-2021-44228", &record);

  TEST_ASSERT_EQUAL_INT(DB_ERROR, db_status);
}

void test_CVELOOKUP_sends_the_id_and_the_trend_row_limit_and_asks_for_text(void)
{
  CVELOOKUPRecord_t record = { 0 };
  char row_limit[16];
  snprintf(row_limit, sizeof(row_limit), "%d", CVELOOKUP_EPSS_TREND_MAX_ROWS);

  DbStatus_t db_status = db_CVELOOKUP(NULL, "CVE-2021-44228", &record);

  TEST_ASSERT_EQUAL_INT(DB_OK, db_status);
  TEST_ASSERT_EQUAL_INT(1, g_callCount);
  TEST_ASSERT_EQUAL_STRING("SELECT * FROM api.fn_cve_lookup(ARRAY[$1], $2, $3, $4, $5, $6)", static_lastCall()->ma_command);
  TEST_ASSERT_EQUAL_INT(6, static_lastCall()->m_paramCount);
  TEST_ASSERT_EQUAL_STRING("CVE-2021-44228", static_lastCall()->ma_params[0]);
  TEST_ASSERT_EQUAL_STRING(row_limit, static_lastCall()->ma_params[1]);
  TEST_ASSERT_EQUAL_STRING("5", static_lastCall()->ma_params[2]);
  TEST_ASSERT_EQUAL_STRING("20", static_lastCall()->ma_params[3]);
  TEST_ASSERT_EQUAL_STRING("10", static_lastCall()->ma_params[4]);
  TEST_ASSERT_EQUAL_STRING("20", static_lastCall()->ma_params[5]);
  TEST_ASSERT_EQUAL_INT(0, static_lastCall()->m_resultFormat);

  db_CVELOOKUPRecordFree(&record);
}

void test_CVELOOKUP_no_row_leaves_every_heap_field_null(void)
{
  g_rowCount = 0;
  CVELOOKUPRecord_t record;
  memset(&record, 0xA5, sizeof(record));

  DbStatus_t db_status = db_CVELOOKUP(NULL, "CVE-2021-44228", &record);

  TEST_ASSERT_EQUAL_INT(DB_NOT_FOUND, db_status);
  TEST_ASSERT_NULL(record.mp_cwes);
  TEST_ASSERT_NULL(record.mp_cveTags);
  TEST_ASSERT_NULL(record.mp_affectedProducts);
  TEST_ASSERT_NULL(record.mp_productCountByVendor);
  TEST_ASSERT_NULL(record.mp_refs);
  TEST_ASSERT_NULL(record.mp_epssTrend);
  TEST_ASSERT_NULL(record.mp_nucleiTemplates);
  TEST_ASSERT_NULL(record.mp_ghsa);
}

void test_CVELOOKUP_failed_query_leaves_every_heap_field_null(void)
{
  g_resultStatus = PGRES_FATAL_ERROR;
  CVELOOKUPRecord_t record;
  memset(&record, 0xA5, sizeof(record));

  DbStatus_t db_status = db_CVELOOKUP(NULL, "CVE-2021-44228", &record);

  TEST_ASSERT_EQUAL_INT(DB_ERROR, db_status);
  TEST_ASSERT_NULL(record.mp_cwes);
  TEST_ASSERT_NULL(record.mp_cveTags);
  TEST_ASSERT_NULL(record.mp_affectedProducts);
  TEST_ASSERT_NULL(record.mp_productCountByVendor);
  TEST_ASSERT_NULL(record.mp_refs);
  TEST_ASSERT_NULL(record.mp_epssTrend);
  TEST_ASSERT_NULL(record.mp_nucleiTemplates);
  TEST_ASSERT_NULL(record.mp_ghsa);
}

void test_CVELOOKUPRecordFree_leaves_every_heap_field_null(void)
{
  CVELOOKUPRecord_t record = { 0 };
  DbStatus_t db_status = db_CVELOOKUP(NULL, "CVE-2021-44228", &record);
  TEST_ASSERT_EQUAL_INT(DB_OK, db_status);
  record.mp_ghsa = strdup(R"({"ghsa_id":"GHSA-jfh8-c2jp-5v3q"})");
  TEST_ASSERT_NOT_NULL(record.mp_ghsa);
  TEST_ASSERT_NOT_NULL(record.mp_cwes);
  TEST_ASSERT_NOT_NULL(record.mp_cveTags);
  TEST_ASSERT_NOT_NULL(record.mp_affectedProducts);
  TEST_ASSERT_NOT_NULL(record.mp_productCountByVendor);
  TEST_ASSERT_NOT_NULL(record.mp_refs);
  TEST_ASSERT_NOT_NULL(record.mp_epssTrend);
  TEST_ASSERT_NOT_NULL(record.mp_nucleiTemplates);

  db_CVELOOKUPRecordFree(&record);

  TEST_ASSERT_NULL(record.mp_cwes);
  TEST_ASSERT_NULL(record.mp_cveTags);
  TEST_ASSERT_NULL(record.mp_affectedProducts);
  TEST_ASSERT_NULL(record.mp_productCountByVendor);
  TEST_ASSERT_NULL(record.mp_refs);
  TEST_ASSERT_NULL(record.mp_epssTrend);
  TEST_ASSERT_NULL(record.mp_nucleiTemplates);
  TEST_ASSERT_NULL(record.mp_ghsa);
}

void test_CVELOOKUPBULKResultFree_frees_the_array_once(void)
{
  CVELOOKUPRecord_t* items = calloc(2, sizeof(*items));
  TEST_ASSERT_NOT_NULL(items);
  TEST_ASSERT_EQUAL_INT(DB_OK, db_CVELOOKUP(NULL, "CVE-2021-44228", &items[0]));
  TEST_ASSERT_EQUAL_INT(DB_OK, db_CVELOOKUP(NULL, "CVE-2021-44228", &items[1]));
  CVELOOKUPBULKResult_t result = { 0 };
  result.m_successful = 2;
  result.mp_items     = items;

  db_CVELOOKUPBULKResultFree(&result);
  TEST_ASSERT_NULL(result.mp_items);

  db_CVELOOKUPBULKResultFree(&result);
  db_CVELOOKUPBULKResultFree(NULL);
}

void test_CVELOOKUP_null_cwes_column_reads_as_a_null_field(void)
{
  FakeAnswer_t* answer = static_queueAnswer(PGRES_TUPLES_OK, CVELOOKUP_ROW_COLUMN_COUNT, 1);
  static_fillCvelookupRow(answer, 0);
  answer->ma_cells[0][CVELOOKUP_ROW_CWES_COLUMN_INDEX] = FAKE_SQL_NULL;
  CVELOOKUPRecord_t record = { 0 };

  DbStatus_t db_status = db_CVELOOKUP(NULL, "CVE-2021-44228", &record);

  TEST_ASSERT_EQUAL_INT(DB_OK, db_status);
  TEST_ASSERT_NULL(record.mp_cwes);
  TEST_ASSERT_NOT_NULL(record.mp_cveTags);
  TEST_ASSERT_NOT_NULL(record.mp_affectedProducts);
  TEST_ASSERT_NOT_NULL(record.mp_productCountByVendor);
  TEST_ASSERT_NOT_NULL(record.mp_refs);
  TEST_ASSERT_NOT_NULL(record.mp_epssTrend);
  TEST_ASSERT_NOT_NULL(record.mp_nucleiTemplates);

  db_CVELOOKUPRecordFree(&record);
}

void test_CVELOOKUP_reads_ransomware_campaign_from_its_column(void)
{
  FakeAnswer_t* answer = static_queueAnswer(PGRES_TUPLES_OK, CVELOOKUP_ROW_COLUMN_COUNT, 1);
  static_fillCvelookupRow(answer, 0);
  answer->ma_cells[0][CVELOOKUP_ROW_RANSOMWARE_COLUMN_INDEX] = "Unknown";
  CVELOOKUPRecord_t record = { 0 };

  DbStatus_t db_status = db_CVELOOKUP(NULL, "CVE-2021-44228", &record);

  TEST_ASSERT_EQUAL_INT(DB_OK, db_status);
  TEST_ASSERT_EQUAL_STRING("Unknown", record.ma_ransomwareCampaign);

  db_CVELOOKUPRecordFree(&record);
}

void test_CVELOOKUP_null_ransomware_campaign_empties_a_reused_record(void)
{
  FakeAnswer_t* answer = static_queueAnswer(PGRES_TUPLES_OK, CVELOOKUP_ROW_COLUMN_COUNT, 1);
  static_fillCvelookupRow(answer, 0);
  answer->ma_cells[0][CVELOOKUP_ROW_RANSOMWARE_COLUMN_INDEX] = FAKE_SQL_NULL;
  CVELOOKUPRecord_t record = { 0 };
  memcpy(record.ma_ransomwareCampaign, "Known", sizeof("Known"));

  DbStatus_t db_status = db_CVELOOKUP(NULL, "CVE-2021-44228", &record);

  TEST_ASSERT_EQUAL_INT(DB_OK, db_status);
  TEST_ASSERT_EQUAL_STRING("", record.ma_ransomwareCampaign);

  db_CVELOOKUPRecordFree(&record);
}

void test_CVELOOKUP_empty_cvss_v4_vector_empties_a_reused_record(void)
{
  FakeAnswer_t* answer = static_queueAnswer(PGRES_TUPLES_OK, CVELOOKUP_ROW_COLUMN_COUNT, 1);
  static_fillCvelookupRow(answer, 0);
  answer->ma_cells[0][CVELOOKUP_ROW_CVSS_V4_VECTOR_COLUMN_INDEX] = "";
  CVELOOKUPRecord_t record = { 0 };
  memcpy(record.ma_cvssV4Vector, "CVSS:4.0/AV:N", sizeof("CVSS:4.0/AV:N"));

  DbStatus_t db_status = db_CVELOOKUP(NULL, "CVE-2021-44228", &record);

  TEST_ASSERT_EQUAL_INT(DB_OK, db_status);
  TEST_ASSERT_EQUAL_STRING("", record.ma_cvssV4Vector);

  db_CVELOOKUPRecordFree(&record);
}

void test_CVELOOKUP_reads_each_source_column(void)
{
  CVELOOKUPRecord_t record = { 0 };

  DbStatus_t db_status = db_CVELOOKUP(NULL, "CVE-2021-44228", &record);

  TEST_ASSERT_EQUAL_INT(DB_OK, db_status);
  TEST_ASSERT_EQUAL_STRING("nvd",   record.ma_cvssV3Source);
  TEST_ASSERT_EQUAL_STRING("cna",   record.ma_cvssV4Source);
  TEST_ASSERT_EQUAL_STRING("other", record.ma_cweSource);

  db_CVELOOKUPRecordFree(&record);
}

#define HEALTH_QUERY_COUNT      2
#define HEALTH_FEEDS_ANSWER     1
#define HEALTH_ROW_COLUMN_COUNT 9

static FakeAnswer_t* static_queueFeedsAnswer(int row_count)
{
  static char feed_names[FAKE_ANSWER_MAX_ROWS][16];
  static char counts[FAKE_ANSWER_MAX_ROWS][16];
  for (int row = 0; row < FAKE_ANSWER_MAX_ROWS; row++)
  {
    int written = snprintf(feed_names[row], sizeof(feed_names[row]), "feed_%d", row);
    TEST_ASSERT_TRUE(written > 0 && (size_t)written < sizeof(feed_names[row]));
    written = snprintf(counts[row], sizeof(counts[row]), "%d", row);
    TEST_ASSERT_TRUE(written > 0 && (size_t)written < sizeof(counts[row]));
  }

  FakeAnswer_t* answer = static_queueAnswer(PGRES_TUPLES_OK, 4, row_count);
  answer->ma_columnNames[0] = "feed_name";
  answer->ma_columnNames[1] = "last_synced";
  answer->ma_columnNames[2] = "last_status";
  answer->ma_columnNames[3] = "records_updated";
  for (int row = 0; row < row_count; row++)
  {
    answer->ma_cells[row][0] = feed_names[row];
    answer->ma_cells[row][1] = "2026-10-08T01:22:39Z";
    answer->ma_cells[row][2] = "ok";
    answer->ma_cells[row][3] = counts[row];
  }
  return answer;
}

static const char* const g_healthRowValues[HEALTH_ROW_COLUMN_COUNT] = {
  "391254", "CVE-2026-0001", "2026-09-24T10:00:00", "1710", "CVE-2026-0002", "2026-09-23",
  "944", "CWE-79", "2026-09-22"
};

static const char* const g_healthColumnNames[HEALTH_ROW_COLUMN_COUNT] = {
  "cve_count", "nvd_last_cve_id", "nvd_last_published_time", "kev_count", "kev_last_cve_id",
  "kev_last_date_added", "cwe_count", "cwe_last_id", "cwe_last_updated_at"
};

static FakeAnswer_t* static_queueHealthRow(int row_count)
{
  FakeAnswer_t* answer = static_queueAnswer(PGRES_TUPLES_OK, HEALTH_ROW_COLUMN_COUNT, row_count);
  for (int col = 0; col < HEALTH_ROW_COLUMN_COUNT; col++)
  {
    answer->ma_columnNames[col] = g_healthColumnNames[col];
    for (int row = 0; row < row_count; row++)
      answer->ma_cells[row][col] = g_healthRowValues[col];
  }
  return answer;
}

static void static_queueHealthAnswers(void)
{
  static_queueHealthRow(1);
  FakeAnswer_t* answer = static_queueFeedsAnswer(2);
  answer->ma_cells[0][0] = "nvd";
  answer->ma_cells[0][3] = "21874";
  answer->ma_cells[1][0] = "cwe";
  answer->ma_cells[1][1] = FAKE_SQL_NULL;
  answer->ma_cells[1][2] = "in_progress";
}

void test_HEALTH_reads_each_query_answer_in_order(void)
{
  static_queueHealthAnswers();
  HEALTHData_t data;

  DbStatus_t db_status = db_HEALTH(NULL, &data);

  TEST_ASSERT_EQUAL_INT(DB_OK, db_status);
  TEST_ASSERT_EQUAL_INT(HEALTH_QUERY_COUNT, g_callCount);
  TEST_ASSERT_EQUAL_INT(391254, data.m_cveCount);
  TEST_ASSERT_EQUAL_STRING("CVE-2026-0001", data.ma_nvdLastCveId);
  TEST_ASSERT_EQUAL_STRING("2026-09-24T10:00:00", data.ma_nvdLastPublishedTime);
  TEST_ASSERT_EQUAL_INT(1710, data.m_kevCount);
  TEST_ASSERT_EQUAL_STRING("CVE-2026-0002", data.ma_kevLastCveId);
  TEST_ASSERT_EQUAL_STRING("2026-09-23", data.ma_kevLastDateAdded);
  TEST_ASSERT_EQUAL_INT(944, data.m_cweCount);
  TEST_ASSERT_EQUAL_STRING("CWE-79", data.ma_cweLastId);
  TEST_ASSERT_EQUAL_STRING("2026-09-22", data.ma_cweLastUpdatedAt);
  TEST_ASSERT_EQUAL_INT(2, data.m_feedCount);
  TEST_ASSERT_EQUAL_STRING("nvd", data.ma_feeds[0].ma_name);
  TEST_ASSERT_EQUAL_STRING("2026-10-08T01:22:39Z", data.ma_feeds[0].ma_lastSynced);
  TEST_ASSERT_EQUAL_STRING("ok", data.ma_feeds[0].ma_lastStatus);
  TEST_ASSERT_EQUAL_INT(21874, data.ma_feeds[0].m_recordsUpdated);
  TEST_ASSERT_EQUAL_STRING("cwe", data.ma_feeds[1].ma_name);
  TEST_ASSERT_EQUAL_STRING("", data.ma_feeds[1].ma_lastSynced);
  TEST_ASSERT_EQUAL_STRING("in_progress", data.ma_feeds[1].ma_lastStatus);
  TEST_ASSERT_EQUAL_INT(1, data.ma_feeds[1].m_recordsUpdated);
}

void test_HEALTH_reads_at_most_HEALTH_MAX_FEEDS_feeds(void)
{
  static_queueHealthAnswers();
  g_queuedAnswerCount = HEALTH_FEEDS_ANSWER;
  static_queueFeedsAnswer(HEALTH_MAX_FEEDS + 1);
  HEALTHData_t data;

  DbStatus_t db_status = db_HEALTH(NULL, &data);

  TEST_ASSERT_EQUAL_INT(DB_OK, db_status);
  TEST_ASSERT_EQUAL_INT(HEALTH_MAX_FEEDS, data.m_feedCount);
  TEST_ASSERT_EQUAL_STRING("feed_31", data.ma_feeds[HEALTH_MAX_FEEDS - 1].ma_name);
  const FakeCall_t* feeds_call = static_call(HEALTH_FEEDS_ANSWER);
  TEST_ASSERT_EQUAL_STRING("SELECT * FROM api.fn_upstream_feed_status($1)", feeds_call->ma_command);
  TEST_ASSERT_EQUAL_INT(1, feeds_call->m_paramCount);
  TEST_ASSERT_EQUAL_STRING("32", feeds_call->ma_params[0]);
}

void test_HEALTH_feed_row_that_cannot_be_read_is_left_out(void)
{
  static char long_name[HEALTH_FEED_NAME_LEN + 2];
  static char long_time[HEALTH_FEED_LAST_SYNCED_LEN + 2];
  static char long_status[HEALTH_FEED_LAST_STATUS_LEN + 2];
  memset(long_name,   'n', HEALTH_FEED_NAME_LEN + 1);
  memset(long_time,   't', HEALTH_FEED_LAST_SYNCED_LEN + 1);
  memset(long_status, 's', HEALTH_FEED_LAST_STATUS_LEN + 1);
  const char* const bad_cells[4] = { long_name, long_time, long_status, "12abc" };

  for (int column = 0; column < 4; column++)
  {
    static_resetFake();
    static_queueHealthAnswers();
    g_queuedAnswerCount = HEALTH_FEEDS_ANSWER;
    static_queueFeedsAnswer(3)->ma_cells[1][column] = bad_cells[column];
    HEALTHData_t data;
    char message[16] = "";
    snprintf(message, sizeof(message), "column %d", column);

    DbStatus_t db_status = db_HEALTH(NULL, &data);

    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_OK, db_status, message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(391254, data.m_cveCount, message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(2, data.m_feedCount, message);
    TEST_ASSERT_EQUAL_STRING_MESSAGE("feed_0", data.ma_feeds[0].ma_name, message);
    TEST_ASSERT_EQUAL_STRING_MESSAGE("feed_2", data.ma_feeds[1].ma_name, message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(2, data.ma_feeds[1].m_recordsUpdated, message);
  }
}

void test_HEALTH_feeds_answer_with_other_columns_is_error(void)
{
  static_queueHealthAnswers();
  g_queuedAnswers[HEALTH_FEEDS_ANSWER].ma_columnNames[1] = "resume_cursor";
  HEALTHData_t data;

  DbStatus_t db_status = db_HEALTH(NULL, &data);

  TEST_ASSERT_EQUAL_INT(DB_ERROR, db_status);
}

void test_HEALTH_stops_at_the_first_failed_query(void)
{
  for (int failed = 0; failed < HEALTH_QUERY_COUNT; failed++)
  {
    static_resetFake();
    static_queueHealthAnswers();
    g_queuedAnswers[failed].m_status = PGRES_FATAL_ERROR;
    HEALTHData_t data;
    char message[32] = "";
    snprintf(message, sizeof(message), "failed query %d", failed);

    DbStatus_t db_status = db_HEALTH(NULL, &data);

    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_ERROR, db_status, message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(failed + 1, g_callCount, message);
  }
}

void test_fake_answers_a_call_past_the_queue_as_a_failed_query(void)
{
  static_queueHealthAnswers();
  g_queuedAnswerCount = HEALTH_QUERY_COUNT - 1;
  HEALTHData_t data;

  DbStatus_t db_status = db_HEALTH(NULL, &data);

  TEST_ASSERT_EQUAL_INT(DB_ERROR, db_status);
  TEST_ASSERT_EQUAL_INT(HEALTH_QUERY_COUNT, g_callCount);
}

void test_HEALTH_answer_that_is_not_one_row_is_error(void)
{
  for (int row_count = 0; row_count <= 2; row_count += 2)
  {
    static_resetFake();
    static_queueHealthRow(row_count);
    static_queueFeedsAnswer(1);
    HEALTHData_t data;
    char message[16] = "";
    snprintf(message, sizeof(message), "%d rows", row_count);

    DbStatus_t db_status = db_HEALTH(NULL, &data);

    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_ERROR, db_status, message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_callCount, message);
  }
}

void test_fake_records_each_call_in_order(void)
{
  static_queueHealthAnswers();
  HEALTHData_t data;
  TEST_ASSERT_EQUAL_INT(DB_OK, db_HEALTH(NULL, &data));

  TEST_ASSERT_EQUAL_STRING("SELECT * FROM api.fn_health()", static_call(0)->ma_command);
  TEST_ASSERT_EQUAL_INT(0, static_call(0)->m_paramCount);
  TEST_ASSERT_NOT_NULL(strstr(static_call(1)->ma_command, "FROM api.fn_upstream_feed_status($1)"));

  static_resetFake();
  const char* params[2] = { "CVE-2021-44228", NULL };
  PGresult* result = dbhelper_executeQuery(NULL, "SELECT $1, $2", 2, params);
  TEST_ASSERT_NOT_NULL(result);
  PQclear(result);

  TEST_ASSERT_EQUAL_STRING("SELECT $1, $2", static_lastCall()->ma_command);
  TEST_ASSERT_EQUAL_INT(2, static_lastCall()->m_paramCount);
  TEST_ASSERT_FALSE(static_lastCall()->ma_isParamNull[0]);
  TEST_ASSERT_EQUAL_STRING("CVE-2021-44228", static_lastCall()->ma_params[0]);
  TEST_ASSERT_TRUE(static_lastCall()->ma_isParamNull[1]);
  TEST_ASSERT_EQUAL_STRING("", static_lastCall()->ma_params[1]);
}

static char* static_makeText(size_t length)
{
  char* text = malloc(length + 1);
  if (!text)
    return NULL;

  memset(text, 'a', length);
  text[length] = '\0';
  return text;
}

static PGresult* static_buildOneCellResult(const char* value)
{
  FakeAnswer_t answer;
  memset(&answer, 0, sizeof(answer));
  answer.m_status       = PGRES_TUPLES_OK;
  answer.m_columnCount  = 1;
  answer.m_rowCount     = 1;
  answer.ma_cells[0][0] = value;
  return static_buildResult(&answer);
}

typedef struct {
  FILE* mp_file;
  int   m_savedStderr;
} StderrCapture_t;

static void static_beginStderrCapture(StderrCapture_t* capture)
{
  capture->mp_file = tmpfile();
  TEST_ASSERT_NOT_NULL(capture->mp_file);
  fflush(stderr);
  capture->m_savedStderr = dup(STDERR_FILENO);
  TEST_ASSERT_TRUE(capture->m_savedStderr >= 0);
  TEST_ASSERT_TRUE(dup2(fileno(capture->mp_file), STDERR_FILENO) >= 0);
}

static void static_endStderrCapture(StderrCapture_t* capture, char* text, size_t size)
{
  fflush(stderr);
  dup2(capture->m_savedStderr, STDERR_FILENO);
  close(capture->m_savedStderr);
  rewind(capture->mp_file);
  size_t length = fread(text, 1, size - 1, capture->mp_file);
  text[length] = '\0';
  fclose(capture->mp_file);
}

static void static_clearLogLimit(void)
{
  PGresult* result = static_buildOneCellResult("ab");
  TEST_ASSERT_NOT_NULL(result);
  char dest[2];
  char discarded[256];
  StderrCapture_t capture;

  g_fakeNow++;
  static_beginStderrCapture(&capture);
  bool is_copied = dbhelper_fetchColStr(result, 0, 0, dest, 1);
  static_endStderrCapture(&capture, discarded, sizeof(discarded));
  g_fakeNow++;
  PQclear(result);

  TEST_ASSERT_FALSE(is_copied);
}

void test_fetchColStr_copies_up_to_max_len_and_refuses_a_longer_value(void)
{
  static const struct {
    const char* mp_value;
    size_t      m_maxLen;
    bool        m_isCopied;
  } rows[] = {
    { "abcd",             4, true  },
    { "abcde",            4, false },
    { "",                 4, true  },
    { FAKE_SQL_NULL,      4, true  },
    { "ab\xC3\xA9",       4, true  },
    { "ab\xC3\xA9",       3, false },
    { "a\xE2\x82\xAC",    2, false },
    { "a\xE2\x82\xAC",    3, false },
    { "\xF0\x9F\x98\x80", 3, false },
  };

  for (size_t row = 0; row < sizeof(rows) / sizeof(rows[0]); row++)
  {
    PGresult* result = static_buildOneCellResult(rows[row].mp_value);
    TEST_ASSERT_NOT_NULL(result);
    char dest[8];
    memset(dest, 0xA5, sizeof(dest));
    char message[32] = "";
    snprintf(message, sizeof(message), "row %zu", row);

    bool is_copied = dbhelper_fetchColStr(result, 0, 0, dest, rows[row].m_maxLen);

    TEST_ASSERT_EQUAL_MESSAGE(rows[row].m_isCopied, is_copied, message);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(rows[row].m_isCopied ? rows[row].mp_value : "", dest, message);
    PQclear(result);
  }
}

void test_fetchColStr_refusal_writes_one_line_without_the_value(void)
{
  PGresult* result = static_buildOneCellResult("secret-value-xyz");
  TEST_ASSERT_NOT_NULL(result);
  StderrCapture_t capture;
  static_beginStderrCapture(&capture);
  char dest[8];

  bool is_copied = dbhelper_fetchColStr(result, 0, 0, dest, 4);

  char line[256];
  static_endStderrCapture(&capture, line, sizeof(line));
  PQclear(result);

  TEST_ASSERT_FALSE(is_copied);
  TEST_ASSERT_EQUAL_STRING("dbhelper_fetchColStr: column column (index 0) holds 16 bytes, limit 4\n", line);
  TEST_ASSERT_NULL(strstr(line, "secret"));
}

typedef struct {
  int         m_answer;
  int         m_row;
  int         m_column;
  size_t      m_limit;
  size_t      m_offset;
  const char* mp_name;
  size_t      m_size;
} FieldLimit_t;

#define FIELD_LIMIT(answer, row, column, limit, type, field) \
  { answer, row, column, limit, offsetof(type, field), #field, sizeof(((type*)0)->field) }

static void static_fieldMessage(char* message, size_t size, const FieldLimit_t* field, size_t length)
{
  snprintf(message, size, "%s with %zu bytes", field->mp_name, length);
}

static void static_assertFieldHoldsLimit(const void* out, const FieldLimit_t* field, const char* message)
{
  const char* value = (const char*)out + field->m_offset;
  TEST_ASSERT_EQUAL_size_t_MESSAGE(field->m_limit + 1, field->m_size, message);
  TEST_ASSERT_EQUAL_size_t_MESSAGE(field->m_limit, strlen(value), message);
}

void test_CVELOOKUP_fixed_size_field_past_its_limit_is_error(void)
{
  static const FieldLimit_t fields[] = {
    FIELD_LIMIT(0, 0,  0, CVELOOKUP_ID_MAX_LEN,    CVELOOKUPRecord_t, ma_cveId),
    FIELD_LIMIT(0, 0,  1, CVELOOKUP_DESC_MAX_LEN,  CVELOOKUPRecord_t, ma_description),
    FIELD_LIMIT(0, 0,  2, CVELOOKUP_SEVERITY_LEN,  CVELOOKUPRecord_t, ma_severity),
    FIELD_LIMIT(0, 0,  4, CVELOOKUP_V3_VECTOR_LEN, CVELOOKUPRecord_t, ma_cvssV3Vector),
    FIELD_LIMIT(0, 0,  5, CVELOOKUP_PUBLISHED_LEN, CVELOOKUPRecord_t, ma_publishedTime),
    FIELD_LIMIT(0, 0,  8, CVELOOKUP_CWE_ID_LEN,    CVELOOKUPRecord_t, ma_cweId),
    FIELD_LIMIT(0, 0, 11, CVELOOKUP_PUBLISHED_LEN, CVELOOKUPRecord_t, ma_kevDateAdded),
    FIELD_LIMIT(0, 0, 12, CVELOOKUP_STATUS_LEN,    CVELOOKUPRecord_t, ma_vulnerabilityStatus),
    FIELD_LIMIT(0, 0, 20, CVELOOKUP_RANSOMWARE_LEN, CVELOOKUPRecord_t, ma_ransomwareCampaign),
    FIELD_LIMIT(0, 0, 22, CVELOOKUP_V4_VECTOR_LEN,  CVELOOKUPRecord_t, ma_cvssV4Vector),
    FIELD_LIMIT(0, 0, 27, CVELOOKUP_PUBLISHED_LEN,  CVELOOKUPRecord_t, ma_ssvcScoredAt),
    FIELD_LIMIT(0, 0, 32, CVELOOKUP_SOURCE_LEN,     CVELOOKUPRecord_t, ma_cvssV3Source),
    FIELD_LIMIT(0, 0, 33, CVELOOKUP_SOURCE_LEN,     CVELOOKUPRecord_t, ma_cvssV4Source),
    FIELD_LIMIT(0, 0, 34, CVELOOKUP_SOURCE_LEN,     CVELOOKUPRecord_t, ma_cweSource),
  };

  for (size_t f = 0; f < sizeof(fields) / sizeof(fields[0]); f++)
  {
    for (size_t extra = 0; extra <= 1; extra++)
    {
      static_resetFake();
      size_t length = fields[f].m_limit + extra;
      char* text = static_makeText(length);
      TEST_ASSERT_NOT_NULL(text);
      FakeAnswer_t* answer = static_queueAnswer(PGRES_TUPLES_OK, CVELOOKUP_ROW_COLUMN_COUNT, 1);
      static_fillCvelookupRow(answer, 0);
      answer->ma_cells[fields[f].m_row][fields[f].m_column] = text;
      CVELOOKUPRecord_t record = { 0 };
      char message[64] = "";
      static_fieldMessage(message, sizeof(message), &fields[f], length);

      DbStatus_t db_status = db_CVELOOKUP(NULL, "CVE-2021-44228", &record);

      if (extra == 0)
      {
        TEST_ASSERT_EQUAL_INT_MESSAGE(DB_OK, db_status, message);
        static_assertFieldHoldsLimit(&record, &fields[f], message);
      }
      else
      {
        TEST_ASSERT_EQUAL_INT_MESSAGE(DB_ERROR, db_status, message);
        TEST_ASSERT_NULL_MESSAGE(record.mp_cwes, message);
        TEST_ASSERT_NULL_MESSAGE(record.mp_cveTags, message);
        TEST_ASSERT_NULL_MESSAGE(record.mp_affectedProducts, message);
        TEST_ASSERT_NULL_MESSAGE(record.mp_productCountByVendor, message);
        TEST_ASSERT_NULL_MESSAGE(record.mp_refs, message);
        TEST_ASSERT_NULL_MESSAGE(record.mp_epssTrend, message);
        TEST_ASSERT_NULL_MESSAGE(record.mp_nucleiTemplates, message);
      }
      db_CVELOOKUPRecordFree(&record);
      free(text);
    }
  }
}

static void static_assertSsvcEmpty(const CVELOOKUPRecord_t* record, const char* message)
{
  TEST_ASSERT_EQUAL_STRING_MESSAGE("", record->ma_ssvcExploitation, message);
  TEST_ASSERT_EQUAL_STRING_MESSAGE("", record->ma_ssvcAutomatable, message);
  TEST_ASSERT_EQUAL_STRING_MESSAGE("", record->ma_ssvcTechnicalImpact, message);
  TEST_ASSERT_EQUAL_STRING_MESSAGE("", record->ma_ssvcVersion, message);
  TEST_ASSERT_EQUAL_STRING_MESSAGE("", record->ma_ssvcScoredAt, message);
  const unsigned char* bytes = (const unsigned char*)&record->m_ssvcResult;
  for (size_t i = 0; i < sizeof(record->m_ssvcResult); i++)
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(0, bytes[i], message);
}

void test_CVELOOKUP_reads_each_ssvc_column_and_gives_its_decisions(void)
{
  FakeAnswer_t* answer = static_queueAnswer(PGRES_TUPLES_OK, CVELOOKUP_ROW_COLUMN_COUNT, 1);
  static_fillCvelookupRow(answer, 0);
  CVELOOKUPRecord_t record = { 0 };

  DbStatus_t db_status = db_CVELOOKUP(NULL, "CVE-2021-44228", &record);

  TEST_ASSERT_EQUAL_INT(DB_OK, db_status);
  TEST_ASSERT_EQUAL_STRING("active", record.ma_ssvcExploitation);
  TEST_ASSERT_EQUAL_STRING("yes", record.ma_ssvcAutomatable);
  TEST_ASSERT_EQUAL_STRING("total", record.ma_ssvcTechnicalImpact);
  TEST_ASSERT_EQUAL_STRING("2.0.3", record.ma_ssvcVersion);
  TEST_ASSERT_EQUAL_STRING("2024-04-17T04:00:13Z", record.ma_ssvcScoredAt);
  TEST_ASSERT_EQUAL_STRING("Attend", record.m_ssvcResult.ma_decisions[SSVC_MISSION_WELLBEING_LOW]);
  TEST_ASSERT_EQUAL_STRING("Act", record.m_ssvcResult.ma_decisions[SSVC_MISSION_WELLBEING_MEDIUM]);
  TEST_ASSERT_EQUAL_STRING("Act", record.m_ssvcResult.ma_decisions[SSVC_MISSION_WELLBEING_HIGH]);
  TEST_ASSERT_EQUAL_STRING("sooner than standard update timelines",
                           record.m_ssvcResult.ma_remediationAdvice[SSVC_MISSION_WELLBEING_LOW]);
  TEST_ASSERT_EQUAL_STRING("as soon as possible", record.m_ssvcResult.ma_remediationAdvice[SSVC_MISSION_WELLBEING_MEDIUM]);
  TEST_ASSERT_EQUAL_STRING("as soon as possible", record.m_ssvcResult.ma_remediationAdvice[SSVC_MISSION_WELLBEING_HIGH]);

  db_CVELOOKUPRecordFree(&record);
}

void test_CVELOOKUP_row_without_ssvc_empties_a_reused_record(void)
{
  FakeAnswer_t* answer = static_queueAnswer(PGRES_TUPLES_OK, CVELOOKUP_ROW_COLUMN_COUNT, 1);
  static_fillCvelookupRow(answer, 0);
  for (int col = CVELOOKUP_ROW_SSVC_EXPLOITATION_COLUMN_INDEX; col <= CVELOOKUP_ROW_SSVC_SCORED_AT_COLUMN_INDEX; col++)
    answer->ma_cells[0][col] = FAKE_SQL_NULL;
  CVELOOKUPRecord_t record = { 0 };
  memcpy(record.ma_ssvcExploitation, "poc", sizeof("poc"));
  memcpy(record.ma_ssvcAutomatable, "no", sizeof("no"));
  memcpy(record.ma_ssvcTechnicalImpact, "partial", sizeof("partial"));
  memcpy(record.ma_ssvcVersion, "2.0.3", sizeof("2.0.3"));
  memcpy(record.ma_ssvcScoredAt, "2023-01-02T03:04:05Z", sizeof("2023-01-02T03:04:05Z"));
  memset(&record.m_ssvcResult, 'X', sizeof(record.m_ssvcResult));

  DbStatus_t db_status = db_CVELOOKUP(NULL, "CVE-2021-44228", &record);

  TEST_ASSERT_EQUAL_INT(DB_OK, db_status);
  static_assertSsvcEmpty(&record, "no assessment");

  db_CVELOOKUPRecordFree(&record);
}

typedef struct {
  const char* ma_cells[5];
  const char* mp_line;
} SsvcRowCase_t;

void test_CVELOOKUP_ssvc_row_the_tree_cannot_read_is_error(void)
{
  static const char VERSION_LINE[] =
    "static_CVELOOKUPTryReadSsvc: CVE-2021-44228 holds an SSVC assessment that is not of version 2.0.3\n";
  static const char VALUE_LINE_FORMAT[] =
    "static_CVELOOKUPTryReadSsvc: CVE-2021-44228 holds an SSVC value that ssvc_evaluate refuses with status %d\n";
  char exploitation_line[160];
  char automatable_line[160];
  char technical_impact_line[160];
  snprintf(exploitation_line, sizeof(exploitation_line), VALUE_LINE_FORMAT, (int)SSVC_ERR_EXPLOITATION);
  snprintf(automatable_line, sizeof(automatable_line), VALUE_LINE_FORMAT, (int)SSVC_ERR_AUTOMATABLE);
  snprintf(technical_impact_line, sizeof(technical_impact_line), VALUE_LINE_FORMAT, (int)SSVC_ERR_TECHNICAL_IMPACT);
  const SsvcRowCase_t cases[] = {
    { { NULL,     NULL,  NULL,    NULL,    "2024-04-17T04:00:13Z" }, VERSION_LINE },
    { { "active", NULL,  NULL,    NULL,    NULL },                   VERSION_LINE },
    { { NULL,     "yes", NULL,    NULL,    NULL },                   VERSION_LINE },
    { { NULL,     NULL,  "total", NULL,    NULL },                   VERSION_LINE },
    { { "active", "yes", "total", NULL,    NULL },                   VERSION_LINE },
    { { "active", "yes", "total", "2.0.2", NULL },                   VERSION_LINE },
    { { "active", "yes", "total", "2.0.3 ", NULL },                  VERSION_LINE },
    { { NULL,     NULL,  NULL,    "2.0.3", NULL },                   exploitation_line },
    { { NULL,     "yes", "total", "2.0.3", NULL },                   exploitation_line },
    { { "Active", "yes", "total", "2.0.3", NULL },                   exploitation_line },
    { { "active", NULL,  "total", "2.0.3", NULL },                   automatable_line },
    { { "active", "yes", NULL,    "2.0.3", NULL },                   technical_impact_line },
    { { "active", "yes", "bogus", "2.0.3", NULL },                   technical_impact_line },
  };

  for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++)
  {
    static_resetFake();
    FakeAnswer_t* answer = static_queueAnswer(PGRES_TUPLES_OK, CVELOOKUP_ROW_COLUMN_COUNT, 1);
    static_fillCvelookupRow(answer, 0);
    for (int i = 0; i < 5; i++)
      answer->ma_cells[0][CVELOOKUP_ROW_SSVC_EXPLOITATION_COLUMN_INDEX + i] =
        cases[c].ma_cells[i] != NULL ? cases[c].ma_cells[i] : FAKE_SQL_NULL;
    CVELOOKUPRecord_t record = { 0 };
    char message[32];
    snprintf(message, sizeof(message), "case %zu", c);
    StderrCapture_t capture;
    static_beginStderrCapture(&capture);

    DbStatus_t db_status = db_CVELOOKUP(NULL, "CVE-2021-44228", &record);

    char line[256];
    static_endStderrCapture(&capture, line, sizeof(line));
    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_ERROR, db_status, message);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(cases[c].mp_line, line, message);
    TEST_ASSERT_NULL_MESSAGE(record.mp_cwes, message);
    TEST_ASSERT_NULL_MESSAGE(record.mp_cveTags, message);
    TEST_ASSERT_NULL_MESSAGE(record.mp_affectedProducts, message);
    TEST_ASSERT_NULL_MESSAGE(record.mp_productCountByVendor, message);
    TEST_ASSERT_NULL_MESSAGE(record.mp_refs, message);
    TEST_ASSERT_NULL_MESSAGE(record.mp_epssTrend, message);
    TEST_ASSERT_NULL_MESSAGE(record.mp_nucleiTemplates, message);
    db_CVELOOKUPRecordFree(&record);
  }
}

void test_CVELOOKUP_ssvc_value_past_its_limit_is_refused_by_its_reader(void)
{
  static const struct { int m_column; const char* mp_name; size_t m_size; } fields[] = {
    { CVELOOKUP_ROW_SSVC_EXPLOITATION_COLUMN_INDEX,     "ssvc_exploitation",     sizeof(((CVELOOKUPRecord_t*)0)->ma_ssvcExploitation) },
    { CVELOOKUP_ROW_SSVC_AUTOMATABLE_COLUMN_INDEX,      "ssvc_automatable",      sizeof(((CVELOOKUPRecord_t*)0)->ma_ssvcAutomatable) },
    { CVELOOKUP_ROW_SSVC_TECHNICAL_IMPACT_COLUMN_INDEX, "ssvc_technical_impact", sizeof(((CVELOOKUPRecord_t*)0)->ma_ssvcTechnicalImpact) },
    { CVELOOKUP_ROW_SSVC_VERSION_COLUMN_INDEX,          "ssvc_version",          sizeof(((CVELOOKUPRecord_t*)0)->ma_ssvcVersion) },
  };

  for (size_t f = 0; f < sizeof(fields) / sizeof(fields[0]); f++)
  {
    static_resetFake();
    static_clearLogLimit();
    char* text = static_makeText(CVELOOKUP_SSVC_VALUE_LEN + 1);
    TEST_ASSERT_NOT_NULL(text);
    FakeAnswer_t* answer = static_queueAnswer(PGRES_TUPLES_OK, CVELOOKUP_ROW_COLUMN_COUNT, 1);
    static_fillCvelookupRow(answer, 0);
    answer->ma_cells[0][fields[f].m_column] = text;
    CVELOOKUPRecord_t record = { 0 };
    char expected[160];
    snprintf(expected, sizeof(expected), "dbhelper_fetchColStr: column %s (index %d) holds %d bytes, limit %d\n",
             fields[f].mp_name, fields[f].m_column, CVELOOKUP_SSVC_VALUE_LEN + 1, CVELOOKUP_SSVC_VALUE_LEN);
    StderrCapture_t capture;
    static_beginStderrCapture(&capture);

    DbStatus_t db_status = db_CVELOOKUP(NULL, "CVE-2021-44228", &record);

    char line[256];
    static_endStderrCapture(&capture, line, sizeof(line));
    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_ERROR, db_status, fields[f].mp_name);
    TEST_ASSERT_EQUAL_size_t_MESSAGE(CVELOOKUP_SSVC_VALUE_LEN + 1, fields[f].m_size, fields[f].mp_name);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(expected, line, fields[f].mp_name);
    db_CVELOOKUPRecordFree(&record);
    free(text);
  }
}

static char g_fakeConnection;
#define FAKE_CONN ((PGconn*)&g_fakeConnection)

static void static_queueTotalAnswer(const char* total)
{
  FakeAnswer_t* answer = static_queueAnswer(PGRES_TUPLES_OK, 1, 1);
  answer->ma_columnNames[0] = "cve_count";
  answer->ma_cells[0][0]    = total;
}

#define LIST_ROW_COLUMN_COUNT 14

static const char* const g_listRowValues[LIST_ROW_COLUMN_COUNT] = {
  "CVE-2021-44228", "CRITICAL", "10.0", "0.97566", "0.99970", "t", "2021-12-10", "CWE-917",
  "9.3", "t", "t", "adp", "other", "nvd"
};

static const char* const g_listColumnNames[LIST_ROW_COLUMN_COUNT] = {
  "cve_id", "severity", "cvss_v3", "epss_score", "epss_percentile", "in_kev", "published_time",
  "cwe_id", "cvss_v4", "has_cvss_v4", "has_cvss_v3", "cvss_v3_source", "cvss_v4_source", "cwe_source"
};

static FakeAnswer_t* static_queueListAnswers(void)
{
  static_queueTotalAnswer("2");
  FakeAnswer_t* page = static_queueAnswer(PGRES_TUPLES_OK, LIST_ROW_COLUMN_COUNT, 2);
  for (int col = 0; col < LIST_ROW_COLUMN_COUNT; col++)
  {
    page->ma_columnNames[col] = g_listColumnNames[col];
    for (int row = 0; row < 2; row++)
      page->ma_cells[row][col] = g_listRowValues[col];
  }
  return page;
}

void test_CVESEARCH_fixed_size_field_past_its_limit_is_error(void)
{
  static const FieldLimit_t fields[] = {
    FIELD_LIMIT(1, 0, 0, CVELOOKUP_ID_MAX_LEN,    CveListItem_t, ma_cveId),
    FIELD_LIMIT(1, 1, 0, CVELOOKUP_ID_MAX_LEN,    CveListItem_t, ma_cveId),
    FIELD_LIMIT(1, 1, 1, CVELOOKUP_SEVERITY_LEN,  CveListItem_t, ma_severity),
    FIELD_LIMIT(1, 1, 6, CVELOOKUP_PUBLISHED_LEN, CveListItem_t, ma_publishedTime),
    FIELD_LIMIT(1, 1, 7, CVELOOKUP_CWE_ID_LEN,    CveListItem_t, ma_cweId),
    FIELD_LIMIT(1, 1, 11, CVELOOKUP_SOURCE_LEN,   CveListItem_t, ma_cvssV3Source),
    FIELD_LIMIT(1, 1, 12, CVELOOKUP_SOURCE_LEN,   CveListItem_t, ma_cvssV4Source),
    FIELD_LIMIT(1, 1, 13, CVELOOKUP_SOURCE_LEN,   CveListItem_t, ma_cweSource),
  };

  for (size_t f = 0; f < sizeof(fields) / sizeof(fields[0]); f++)
  {
    for (size_t extra = 0; extra <= 1; extra++)
    {
      static_resetFake();
      size_t length = fields[f].m_limit + extra;
      char* text = static_makeText(length);
      TEST_ASSERT_NOT_NULL(text);
      static_queueListAnswers();
      g_queuedAnswers[fields[f].m_answer].ma_cells[fields[f].m_row][fields[f].m_column] = text;
      CVESEARCHParams_t params;
      memset(&params, 0, sizeof(params));
      params.m_limit = 2;
      CveListResult_t results;
      memset(&results, 0xA5, sizeof(results));
      char message[64] = "";
      static_fieldMessage(message, sizeof(message), &fields[f], length);

      DbStatus_t db_status = db_CVESEARCH(FAKE_CONN, &params, &results);

      if (extra == 0)
      {
        TEST_ASSERT_EQUAL_INT_MESSAGE(DB_OK, db_status, message);
        TEST_ASSERT_EQUAL_INT_MESSAGE(2, results.m_count, message);
        static_assertFieldHoldsLimit(&results.mp_items[fields[f].m_row], &fields[f], message);
        db_CveListResultFree(&results);
      }
      else
      {
        TEST_ASSERT_EQUAL_INT_MESSAGE(DB_ERROR, db_status, message);
        TEST_ASSERT_NULL_MESSAGE(results.mp_items, message);
      }
      free(text);
    }
  }
}

void test_CVESEARCH_reads_each_source_column(void)
{
  static_resetFake();
  static_queueListAnswers();
  CVESEARCHParams_t params;
  memset(&params, 0, sizeof(params));
  params.m_limit = 2;
  CveListResult_t results;
  memset(&results, 0, sizeof(results));

  DbStatus_t db_status = db_CVESEARCH(FAKE_CONN, &params, &results);

  TEST_ASSERT_EQUAL_INT(DB_OK, db_status);
  TEST_ASSERT_EQUAL_INT(2, results.m_count);
  TEST_ASSERT_EQUAL_STRING("adp",   results.mp_items[0].ma_cvssV3Source);
  TEST_ASSERT_EQUAL_STRING("other", results.mp_items[0].ma_cvssV4Source);
  TEST_ASSERT_EQUAL_STRING("nvd",   results.mp_items[0].ma_cweSource);
  db_CveListResultFree(&results);
}

#define TRIAGE_ROW_COLUMN_COUNT        5
#define TRIAGE_ROW_LABEL_COLUMN_INDEX  4

static const char* const g_triageRowValues[TRIAGE_ROW_COLUMN_COUNT] = {
  "CVE-2021-44228", "0.97566", "10.0", "96.5", "CRITICAL"
};

static const char* const g_triageColumnNames[TRIAGE_ROW_COLUMN_COUNT] = {
  "cve_id", "epss_score", "cvss_v3", "risk_score", "risk_label"
};

static void static_fillTriageRows(FakeAnswer_t* answer)
{
  for (int col = 0; col < TRIAGE_ROW_COLUMN_COUNT; col++)
    answer->ma_columnNames[col] = g_triageColumnNames[col];
  for (int row = 0; row < 2; row++)
    for (int col = 0; col < TRIAGE_ROW_COLUMN_COUNT; col++)
      answer->ma_cells[row][col] = g_triageRowValues[col];
}

#define CPESEARCH_ROW_COLUMN_COUNT 4

static const char* const g_cpeSearchColumnNames[CPESEARCH_ROW_COLUMN_COUNT] = {
  "vendor", "product", "vulnerable_cve_count", "product_named_by"
};

static const char* const g_cpeSearchRowValues[2][CPESEARCH_ROW_COLUMN_COUNT] = {
  { "microsoft",         "windows_10",     "7", "[\"cna\", \"nvd\"]" },
  { "notepad-plus-plus", "notepad\\+\\+", "0", "[\"cna_cpe\"]"      },
};

static FakeAnswer_t* static_queueCpeSearchAnswers(void)
{
  FakeAnswer_t* total = static_queueAnswer(PGRES_TUPLES_OK, 1, 1);
  total->ma_columnNames[0] = "product_count";
  total->ma_cells[0][0]    = "2";
  FakeAnswer_t* page = static_queueAnswer(PGRES_TUPLES_OK, CPESEARCH_ROW_COLUMN_COUNT, 2);
  for (int col = 0; col < CPESEARCH_ROW_COLUMN_COUNT; col++)
  {
    page->ma_columnNames[col] = g_cpeSearchColumnNames[col];
    for (int row = 0; row < 2; row++)
      page->ma_cells[row][col] = g_cpeSearchRowValues[row][col];
  }
  return page;
}

#define D3FENDFORATTACK_ROW_COLUMN_COUNT 7
#define D3FENDFORATTACK_CALL "SELECT * FROM api.fn_d3fend_for_attack($1)"

static const char* const g_d3fendForAttackColumnNames[D3FENDFORATTACK_ROW_COLUMN_COUNT] = {
  "defense_id", "defense_label", "defense_tactic", "digital_artifact", "parent_defense_labels", "attack_technique_ids", "attack_techniques"
};

static const char* const g_d3fendForAttackRowValues[2][D3FENDFORATTACK_ROW_COLUMN_COUNT] = {
  { "Multi-factorAuthentication", "Multi-factor Authentication", "Harden", "", R"(["Agent Authentication"])", R"(["T1055"])",
    R"([{"attack_technique_id":"T1055","subtechnique_of":null,"attack_label":"Process Injection"}])" },
  { "SystemCallAnalysis", "System Call Analysis", "Detect", "System Call", R"(["Operating System Monitoring","Platform Monitoring"])",
    R"(["T1055.001","T1055.012"])", R"([{"attack_technique_id":"T1055.012","subtechnique_of":"T1055","attack_label":"Process Hollowing"}])" },
};

static FakeAnswer_t* static_queueD3fendForAttackAnswer(void)
{
  FakeAnswer_t* answer = static_queueAnswer(PGRES_TUPLES_OK, D3FENDFORATTACK_ROW_COLUMN_COUNT, 2);
  for (int col = 0; col < D3FENDFORATTACK_ROW_COLUMN_COUNT; col++)
  {
    answer->ma_columnNames[col] = g_d3fendForAttackColumnNames[col];
    for (int row = 0; row < 2; row++)
      answer->ma_cells[row][col] = g_d3fendForAttackRowValues[row][col];
  }
  return answer;
}

#define DRIVERLOOKUP_ROW_COLUMN_COUNT 4
#define DRIVERLOOKUP_CALL "SELECT * FROM api.fn_driver_lookup(ARRAY[$1], $2, $3)"
#define DRIVERLOOKUP_TEST_HASH "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"

static const char* const g_driverLookupColumnNames[DRIVERLOOKUP_ROW_COLUMN_COUNT] = {
  "file_hash", "match_count", "driver_feed_loaded", "matches"
};

static const char* const g_driverLookupRowValues[DRIVERLOOKUP_ROW_COLUMN_COUNT] = {
  DRIVERLOOKUP_TEST_HASH, "7", "t", R"([{"driver_id":"00000000-0000-0000-0000-00000000000a"}])"
};

#define IPLOOKUP_ROW_COLUMN_COUNT 15
#define IPLOOKUP_CALL "SELECT * FROM api.fn_ip_lookup($1)"
#define IPLOOKUP_TEST_IP "2001:4860:4860::8888"
#define IPLOOKUP_TEST_LISTED_ON \
  R"([{"prefix": "1.10.16.0/20", "source": "drop", "copyright": "(c) 2026 The Spamhaus Project SLU", "list_time": "2026-10-24T00:00:00Z", "listing_id": "SBL256894"}])"

enum {
  IPLOOKUP_COL_ASN = 0, IPLOOKUP_COL_ASN_NAME, IPLOOKUP_COL_ASN_COUNTRY, IPLOOKUP_COL_GEO_COUNTRY,
  IPLOOKUP_COL_CLOUD_PROVIDER, IPLOOKUP_COL_CLOUD_SERVICE, IPLOOKUP_COL_IS_CDN, IPLOOKUP_COL_IS_DATACENTER,
  IPLOOKUP_COL_IS_TOR_EXIT, IPLOOKUP_COL_LISTED_ON, IPLOOKUP_COL_ASN_FEED_LOADED, IPLOOKUP_COL_GEO_FEED_LOADED,
  IPLOOKUP_COL_CLOUD_FEED_LOADED, IPLOOKUP_COL_TOR_FEED_LOADED, IPLOOKUP_COL_DROP_LIST_FEED_LOADED
};

static const char* const g_ipLookupColumnNames[IPLOOKUP_ROW_COLUMN_COUNT] = {
  "asn", "asn_name", "asn_country", "geo_country", "cloud_provider", "cloud_service", "is_cdn",
  "is_datacenter", "is_tor_exit", "listed_on", "asn_feed_loaded", "geo_feed_loaded",
  "cloud_feed_loaded", "tor_feed_loaded", "drop_list_feed_loaded"
};

static const char* const g_ipLookupRowValues[IPLOOKUP_ROW_COLUMN_COUNT] = {
  "15169", "GOOGLE", "US", "AU", "google", "googlecloud", "t", "t", "f", IPLOOKUP_TEST_LISTED_ON,
  "t", "t", "t", "t", "t"
};

static FakeAnswer_t* static_queueIpLookupAnswer(void)
{
  FakeAnswer_t* answer = static_queueAnswer(PGRES_TUPLES_OK, IPLOOKUP_ROW_COLUMN_COUNT, 1);
  for (int col = 0; col < IPLOOKUP_ROW_COLUMN_COUNT; col++)
  {
    answer->ma_columnNames[col] = g_ipLookupColumnNames[col];
    answer->ma_cells[0][col]    = g_ipLookupRowValues[col];
  }
  return answer;
}

#define ASNPREFIX_ROW_COLUMN_COUNT 2
#define ASNLOOKUP_ROW_COLUMN_COUNT 7
#define ASNPREFIX_CALL "SELECT * FROM api.fn_ip_asn_prefix($1)"
#define ASNLOOKUP_CALL "SELECT * FROM api.fn_asn_lookup($1, $2, $3)"
#define ASNLOOKUP_TEST_IP           "2606:4700::1111"
#define ASNLOOKUP_TEST_PREFIX       "2606:4700::/32"
#define ASNLOOKUP_TEST_IPV4_PREFIXES R"(["1.0.0.0/24", "1.1.1.0/24"])"
#define ASNLOOKUP_TEST_IPV6_PREFIXES R"(["2606:4700::/32"])"

enum {
  ASNLOOKUP_COL_ASN = 0, ASNLOOKUP_COL_ASN_NAME, ASNLOOKUP_COL_ASN_COUNTRY, ASNLOOKUP_COL_IPV4_PREFIX_COUNT,
  ASNLOOKUP_COL_IPV6_PREFIX_COUNT, ASNLOOKUP_COL_IPV4_PREFIXES, ASNLOOKUP_COL_IPV6_PREFIXES
};

static const char* const g_asnPrefixColumnNames[ASNPREFIX_ROW_COLUMN_COUNT] = { "asn", "prefix" };
static const char* const g_asnPrefixRowValues[ASNPREFIX_ROW_COLUMN_COUNT]   = { "13335", ASNLOOKUP_TEST_PREFIX };

static const char* const g_asnLookupColumnNames[ASNLOOKUP_ROW_COLUMN_COUNT] = {
  "asn", "asn_name", "asn_country", "ipv4_prefix_count", "ipv6_prefix_count", "ipv4_prefixes", "ipv6_prefixes"
};

static const char* const g_asnLookupRowValues[ASNLOOKUP_ROW_COLUMN_COUNT] = {
  "13335", "CLOUDFLARENET", "US", "1789", "214", ASNLOOKUP_TEST_IPV4_PREFIXES, ASNLOOKUP_TEST_IPV6_PREFIXES
};

static FakeAnswer_t* static_queueAsnPrefixAnswer(void)
{
  FakeAnswer_t* answer = static_queueAnswer(PGRES_TUPLES_OK, ASNPREFIX_ROW_COLUMN_COUNT, 1);
  for (int col = 0; col < ASNPREFIX_ROW_COLUMN_COUNT; col++)
  {
    answer->ma_columnNames[col] = g_asnPrefixColumnNames[col];
    answer->ma_cells[0][col]    = g_asnPrefixRowValues[col];
  }
  return answer;
}

static FakeAnswer_t* static_queueAsnLookupAnswer(void)
{
  FakeAnswer_t* answer = static_queueAnswer(PGRES_TUPLES_OK, ASNLOOKUP_ROW_COLUMN_COUNT, 1);
  for (int col = 0; col < ASNLOOKUP_ROW_COLUMN_COUNT; col++)
  {
    answer->ma_columnNames[col] = g_asnLookupColumnNames[col];
    answer->ma_cells[0][col]    = g_asnLookupRowValues[col];
  }
  return answer;
}

static ASNLOOKUPParams_t static_asnLookupParams(const char* target)
{
  ASNLOOKUPParams_t params;
  memset(&params, 0, sizeof(params));
  snprintf(params.ma_target, sizeof(params.ma_target), "%s", target);
  params.m_limit  = ASNLOOKUP_MAX_LIMIT;
  params.m_offset = 0;
  return params;
}

#define EMAILADDRESSCHECK_ROW_COLUMN_COUNT 2
#define EMAILADDRESSCHECK_CALL "SELECT * FROM api.fn_email_disposable_domain($1)"
#define EMAILADDRESSCHECK_TEST_DOMAIN "a.b.mailinator.com"

static const char* const g_emailAddressCheckColumnNames[EMAILADDRESSCHECK_ROW_COLUMN_COUNT] = {
  "disposable_feed_loaded", "listed_domain"
};

static FakeAnswer_t* static_queueEmailAddressCheckAnswer(const char* feed_loaded, const char* listed_domain)
{
  FakeAnswer_t* answer = static_queueAnswer(PGRES_TUPLES_OK, EMAILADDRESSCHECK_ROW_COLUMN_COUNT, 1);
  for (int col = 0; col < EMAILADDRESSCHECK_ROW_COLUMN_COUNT; col++)
    answer->ma_columnNames[col] = g_emailAddressCheckColumnNames[col];
  answer->ma_cells[0][0] = feed_loaded;
  answer->ma_cells[0][1] = listed_domain;
  return answer;
}

#define SSLCHECK_ROW_COLUMN_COUNT 3
#define SSLCHECK_CALL "SELECT * FROM api.fn_ssl_blacklist_certificate($1)"
#define SSLCHECK_TEST_SHA1 "0a1b2c3d4e5f60718293a4b5c6d7e8f901234567"

static const char* const g_sslCheckColumnNames[SSLCHECK_ROW_COLUMN_COUNT] = {
  "ssl_blacklist_feed_loaded", "listing_reason", "listing_time"
};

static FakeAnswer_t* static_queueSslCheckAnswer(const char* feed_loaded, const char* listing_reason, const char* listing_time)
{
  FakeAnswer_t* answer = static_queueAnswer(PGRES_TUPLES_OK, SSLCHECK_ROW_COLUMN_COUNT, 1);
  for (int col = 0; col < SSLCHECK_ROW_COLUMN_COUNT; col++)
    answer->ma_columnNames[col] = g_sslCheckColumnNames[col];
  answer->ma_cells[0][0] = feed_loaded;
  answer->ma_cells[0][1] = listing_reason;
  answer->ma_cells[0][2] = listing_time;
  return answer;
}

#define PACKAGECHECK_ROW_COLUMN_COUNT 7
#define PACKAGECHECK_CALL "SELECT * FROM api.fn_package_check($1, $2, $3, $4, $5)"
#define PACKAGECHECK_EOL_CALL "SELECT * FROM api.fn_package_check_eol($1, $2, $3, $4)"

static FakeAnswer_t* static_queueProductExposureEol(int row_count);

static const char* const g_packageCheckColumnNames[PACKAGECHECK_ROW_COLUMN_COUNT] = {
  "advisory_feed_loaded", "has_advisory_data", "result_count", "fixed_version", "malicious", "results", "attribution"
};

static const char* const g_packageCheckRowValues[PACKAGECHECK_ROW_COLUMN_COUNT] = {
  "t", "f", "7", "4.17.21", R"({"id":"MAL-1"})", R"([{"id":"GHSA-a"}])", R"([{"source":"ghsa"}])"
};

static FakeAnswer_t* static_queuePackageCheckAnswer(void)
{
  FakeAnswer_t* answer = static_queueAnswer(PGRES_TUPLES_OK, PACKAGECHECK_ROW_COLUMN_COUNT, 1);
  for (int col = 0; col < PACKAGECHECK_ROW_COLUMN_COUNT; col++)
  {
    answer->ma_columnNames[col] = g_packageCheckColumnNames[col];
    answer->ma_cells[0][col]    = g_packageCheckRowValues[col];
  }
  static_queueProductExposureEol(0);
  return answer;
}

static PACKAGECHECKParams_t static_packageCheckParams(const char* version)
{
  PACKAGECHECKParams_t params = { .ma_ecosystem = "NPM", .ma_packageName = "lodash", .m_limit = 20, .m_offset = 3 };
  snprintf(params.ma_version, sizeof(params.ma_version), "%s", version);
  return params;
}

#define CVEPRODUCTS_ROW_COLUMN_COUNT 3
#define CVEPRODUCTS_CALL "SELECT * FROM api.fn_cve_products($1, $2, $3, $4, $5)"

static const char* const g_cveProductsColumnNames[CVEPRODUCTS_ROW_COLUMN_COUNT] = {
  "affected_product_count", "listed_product_count", "affected_products"
};

static const char* const g_cveProductsRowValues[CVEPRODUCTS_ROW_COLUMN_COUNT] = {
  "9", "2", R"([{"vendor":"acme","product":"alpha"},{"vendor":"acme","product":"beta"}])"
};

static FakeAnswer_t* static_queueCveProductsAnswer(void)
{
  FakeAnswer_t* answer = static_queueAnswer(PGRES_TUPLES_OK, CVEPRODUCTS_ROW_COLUMN_COUNT, 1);
  for (int col = 0; col < CVEPRODUCTS_ROW_COLUMN_COUNT; col++)
  {
    answer->ma_columnNames[col] = g_cveProductsColumnNames[col];
    answer->ma_cells[0][col]    = g_cveProductsRowValues[col];
  }
  return answer;
}

static CVEPRODUCTSParams_t static_cveProductsParams(const char* vendor, const char* product)
{
  CVEPRODUCTSParams_t params = { .ma_cveId = "CVE-2021-44228", .m_limit = 7, .m_offset = 3 };
  snprintf(params.ma_vendor, sizeof(params.ma_vendor), "%s", vendor);
  snprintf(params.ma_product, sizeof(params.ma_product), "%s", product);
  return params;
}

#define CVELOOKUPGHSA_ROW_COLUMN_COUNT 2
#define CVELOOKUPGHSA_CALL "SELECT * FROM api.fn_cve_ghsa_advisory($1, $2)"

static const char* const g_cveLookupGhsaColumnNames[CVELOOKUPGHSA_ROW_COLUMN_COUNT] = {
  "ghsa_feed_loaded", "advisory"
};

static const char* const g_cveLookupGhsaRowValues[CVELOOKUPGHSA_ROW_COLUMN_COUNT] = {
  "f", R"({"ghsa_id":"GHSA-jfh8-c2jp-5v3q","affected_total":10})"
};

static FakeAnswer_t* static_queueCveLookupGhsaAnswer(void)
{
  FakeAnswer_t* answer = static_queueAnswer(PGRES_TUPLES_OK, CVELOOKUPGHSA_ROW_COLUMN_COUNT, 1);
  for (int col = 0; col < CVELOOKUPGHSA_ROW_COLUMN_COUNT; col++)
  {
    answer->ma_columnNames[col] = g_cveLookupGhsaColumnNames[col];
    answer->ma_cells[0][col]    = g_cveLookupGhsaRowValues[col];
  }
  return answer;
}

#define PACKAGECHECKBULK_ROW_COLUMN_COUNT 4
#define PACKAGECHECKBULK_CALL "SELECT * FROM api.fn_package_check_bulk($1, $2, $3, $4)"

static const char* const g_packageCheckBulkColumnNames[PACKAGECHECKBULK_ROW_COLUMN_COUNT] = {
  "advisory_feed_loaded", "results", "attribution", "failed_item_count"
};

static const char* const g_packageCheckBulkRowValues[PACKAGECHECKBULK_ROW_COLUMN_COUNT] = {
  "t", R"([{"name":"lodash"},{"name":"django"}])", R"([{"source":"ghsa"}])", "0"
};

static FakeAnswer_t* static_queuePackageCheckBulkAnswer(void)
{
  FakeAnswer_t* answer = static_queueAnswer(PGRES_TUPLES_OK, PACKAGECHECKBULK_ROW_COLUMN_COUNT, 1);
  for (int col = 0; col < PACKAGECHECKBULK_ROW_COLUMN_COUNT; col++)
  {
    answer->ma_columnNames[col] = g_packageCheckBulkColumnNames[col];
    answer->ma_cells[0][col]    = g_packageCheckBulkRowValues[col];
  }
  return answer;
}

static const PACKAGECHECKBULKItem_t g_packageCheckBulkItems[2] = {
  { .ma_ecosystem = "npm",  .ma_packageName = "lodash",       .ma_version = "4.17.20" },
  { .ma_ecosystem = "PyPI", .ma_packageName = "a\"b\\c", .ma_version = "1.0" },
};

static FakeAnswer_t* static_queueDriverLookupAnswer(void)
{
  FakeAnswer_t* answer = static_queueAnswer(PGRES_TUPLES_OK, DRIVERLOOKUP_ROW_COLUMN_COUNT, 1);
  for (int col = 0; col < DRIVERLOOKUP_ROW_COLUMN_COUNT; col++)
  {
    answer->ma_columnNames[col] = g_driverLookupColumnNames[col];
    answer->ma_cells[0][col]    = g_driverLookupRowValues[col];
  }
  return answer;
}

void test_CVETRIAGE_cve_id_past_its_limit_is_error(void)
{
  static const FieldLimit_t field =
    FIELD_LIMIT(1, 1, 0, CVELOOKUP_ID_MAX_LEN, CVETRIAGEItem_t, ma_cveId);

  for (size_t extra = 0; extra <= 1; extra++)
  {
    static_resetFake();
    size_t length = field.m_limit + extra;
    char* text = static_makeText(length);
    TEST_ASSERT_NOT_NULL(text);
    static_queueTotalAnswer("2");
    FakeAnswer_t* page = static_queueAnswer(PGRES_TUPLES_OK, TRIAGE_ROW_COLUMN_COUNT, 2);
    static_fillTriageRows(page);
    page->ma_cells[field.m_row][field.m_column] = text;
    CVETRIAGEParams_t params;
    memset(&params, 0, sizeof(params));
    params.m_limit = 2;
    CVETRIAGEResult_t results;
    memset(&results, 0xA5, sizeof(results));
    char message[64] = "";
    static_fieldMessage(message, sizeof(message), &field, length);

    DbStatus_t db_status = db_CVETRIAGE(FAKE_CONN, &params, &results);

    if (extra == 0)
    {
      TEST_ASSERT_EQUAL_INT_MESSAGE(DB_OK, db_status, message);
      TEST_ASSERT_EQUAL_INT_MESSAGE(2, results.m_count, message);
      static_assertFieldHoldsLimit(&results.mp_items[1], &field, message);
      db_CVETRIAGEResultFree(&results);
    }
    else
    {
      TEST_ASSERT_EQUAL_INT_MESSAGE(DB_ERROR, db_status, message);
      TEST_ASSERT_NULL_MESSAGE(results.mp_items, message);
    }
    free(text);
  }
}

void test_CVETRIAGEBULK_cve_id_past_its_limit_fails_only_its_id(void)
{
  static const FieldLimit_t field =
    FIELD_LIMIT(0, 1, 0, CVELOOKUP_ID_MAX_LEN, CVETRIAGEItem_t, ma_cveId);
  static const BulkIdsParams_t params = {
    .ma_ids    = { "CVE-2021-44228", "CVE-2014-0160" },
    .m_idCount = 2,
  };

  for (size_t extra = 0; extra <= 1; extra++)
  {
    static_resetFake();
    size_t length = field.m_limit + extra;
    char* text = static_makeText(length);
    TEST_ASSERT_NOT_NULL(text);
    FakeAnswer_t* select = static_queueAnswer(PGRES_TUPLES_OK, TRIAGE_ROW_COLUMN_COUNT, 2);
    static_fillTriageRows(select);
    select->ma_cells[field.m_row][field.m_column] = text;
    CVETRIAGEBULKResult_t results;
    memset(&results, 0xA5, sizeof(results));
    char message[64] = "";
    static_fieldMessage(message, sizeof(message), &field, length);

    DbStatus_t db_status = db_CVETRIAGEBULK(NULL, &params, &results);

    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_OK, db_status, message);
    if (extra == 0)
    {
      TEST_ASSERT_EQUAL_INT_MESSAGE(2, results.m_successful, message);
      static_assertFieldHoldsLimit(&results.mp_items[1], &field, message);
    }
    else
    {
      TEST_ASSERT_EQUAL_INT_MESSAGE(1, results.m_successful, message);
      TEST_ASSERT_EQUAL_INT_MESSAGE(1, results.m_failed, message);
      TEST_ASSERT_EQUAL_STRING_MESSAGE("CVE-2021-44228", results.mp_items[0].ma_cveId, message);
    }
    db_CVETRIAGEBULKResultFree(&results);
    free(text);
  }
}

void test_CVETRIAGEBULK_sends_every_kept_id_and_fails_the_ones_without_a_row(void)
{
  static const BulkIdsParams_t params = {
    .ma_ids        = { "CVE-2021-44228", "CVE-2014-0160" },
    .m_idCount     = 2,
    .m_skippedIdCount = 3,
  };
  FakeAnswer_t* select = static_queueAnswer(PGRES_TUPLES_OK, TRIAGE_ROW_COLUMN_COUNT, 1);
  static_fillTriageRows(select);
  CVETRIAGEBULKResult_t results;
  memset(&results, 0xA5, sizeof(results));

  DbStatus_t db_status = db_CVETRIAGEBULK(NULL, &params, &results);

  TEST_ASSERT_EQUAL_INT(DB_OK, db_status);
  TEST_ASSERT_EQUAL_STRING("SELECT * FROM api.fn_cve_triage_bulk($1)", static_lastCall()->ma_command);
  TEST_ASSERT_EQUAL_INT(1, static_lastCall()->m_paramCount);
  TEST_ASSERT_EQUAL_STRING("{CVE-2021-44228,CVE-2014-0160}", static_lastCall()->ma_params[0]);
  TEST_ASSERT_EQUAL_INT(1, results.m_successful);
  TEST_ASSERT_EQUAL_INT(1, results.m_failed);
  TEST_ASSERT_NOT_NULL(results.mp_items);
  TEST_ASSERT_EQUAL_STRING("CVE-2021-44228", results.mp_items[0].ma_cveId);
  db_CVETRIAGEBULKResultFree(&results);
}

static const char* const g_bulkIds[3] = { "CVE-2021-44228", "CVE-2014-0160", "CVE-2017-0144" };

static FakeAnswer_t* static_queueTriageBulkRows(int row_count)
{
  assert(row_count >= 0 && row_count <= 3);

  FakeAnswer_t* answer = static_queueAnswer(PGRES_TUPLES_OK, TRIAGE_ROW_COLUMN_COUNT, row_count);
  for (int col = 0; col < TRIAGE_ROW_COLUMN_COUNT; col++)
    answer->ma_columnNames[col] = g_triageColumnNames[col];
  for (int row = 0; row < row_count; row++)
  {
    for (int col = 0; col < TRIAGE_ROW_COLUMN_COUNT; col++)
      answer->ma_cells[row][col] = g_triageRowValues[col];
    answer->ma_cells[row][0] = g_bulkIds[row];
  }
  return answer;
}

void test_CVETRIAGEBULK_unreadable_row_fails_only_its_id(void)
{
  static const BulkIdsParams_t params = {
    .ma_ids    = { "CVE-2021-44228", "CVE-2014-0160", "CVE-2017-0144" },
    .m_idCount = 3,
  };
  char* long_id    = static_makeText(CVELOOKUP_ID_MAX_LEN + 1);
  char* long_label = static_makeText(CVERISKSCORE_LABEL_LEN + 1);
  TEST_ASSERT_NOT_NULL(long_id);
  TEST_ASSERT_NOT_NULL(long_label);
  const struct {
    int         m_column;
    const char* mp_value;
    const char* mp_name;
  } rows[] = {
    { 0, NULL,       "nothing broken" },
    { 0, long_id,    "cve_id" },
    { 3, "12abc",    "risk_score" },
    { 4, long_label, "risk_label" },
  };

  for (size_t row = 0; row < sizeof(rows) / sizeof(rows[0]); row++)
  {
    static_resetFake();
    FakeAnswer_t* select = static_queueTriageBulkRows(3);
    if (rows[row].mp_value)
      select->ma_cells[1][rows[row].m_column] = rows[row].mp_value;
    CVETRIAGEBULKResult_t results;
    memset(&results, 0xA5, sizeof(results));
    int successful = rows[row].mp_value ? 2 : 3;

    DbStatus_t db_status = db_CVETRIAGEBULK(NULL, &params, &results);

    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_OK, db_status, rows[row].mp_name);
    TEST_ASSERT_EQUAL_INT_MESSAGE(successful, results.m_successful, rows[row].mp_name);
    TEST_ASSERT_EQUAL_INT_MESSAGE(3 - successful, results.m_failed, rows[row].mp_name);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(g_bulkIds[0], results.mp_items[0].ma_cveId, rows[row].mp_name);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(g_bulkIds[successful == 3 ? 1 : 2], results.mp_items[1].ma_cveId,
                                     rows[row].mp_name);
    db_CVETRIAGEBULKResultFree(&results);
  }
  free(long_id);
  free(long_label);
}

void test_CVETRIAGEBULK_more_rows_than_ids_is_error(void)
{
  static const BulkIdsParams_t params = {
    .ma_ids    = { "CVE-2021-44228", "CVE-2014-0160" },
    .m_idCount = 2,
  };

  for (int row_count = 2; row_count <= 3; row_count++)
  {
    static_resetFake();
    static_queueTriageBulkRows(row_count);
    CVETRIAGEBULKResult_t results;
    memset(&results, 0xA5, sizeof(results));

    DbStatus_t db_status = db_CVETRIAGEBULK(NULL, &params, &results);

    if (row_count == 2)
    {
      TEST_ASSERT_EQUAL_INT(DB_OK, db_status);
      TEST_ASSERT_EQUAL_INT(2, results.m_successful);
    }
    else
    {
      TEST_ASSERT_EQUAL_INT(DB_ERROR, db_status);
      TEST_ASSERT_NULL(results.mp_items);
    }
    db_CVETRIAGEBULKResultFree(&results);
  }
}

static FakeAnswer_t* static_queueCvelookupBulkRows(int row_count)
{
  assert(row_count >= 0 && row_count <= 3);

  FakeAnswer_t* answer = static_queueAnswer(PGRES_TUPLES_OK, CVELOOKUP_ROW_COLUMN_COUNT, row_count);
  for (int col = 0; col < CVELOOKUP_ROW_COLUMN_COUNT; col++)
    answer->ma_columnNames[col] = g_cvelookupColumnNames[col];
  for (int row = 0; row < row_count; row++)
  {
    static_fillCvelookupRow(answer, row);
    answer->ma_cells[row][0] = g_bulkIds[row];
  }
  return answer;
}

void test_CVELOOKUPBULK_sends_the_ids_and_the_trend_row_limit_in_one_call(void)
{
  static const BulkIdsParams_t params = {
    .ma_ids        = { "CVE-2021-44228", "CVE-2014-0160" },
    .m_idCount     = 2,
    .m_skippedIdCount = 3,
  };
  char row_limit[16];
  snprintf(row_limit, sizeof(row_limit), "%d", CVELOOKUP_EPSS_TREND_MAX_ROWS);
  static_queueCvelookupBulkRows(1);
  CVELOOKUPBULKResult_t results;
  memset(&results, 0xA5, sizeof(results));

  DbStatus_t db_status = db_CVELOOKUPBULK(NULL, &params, &results);

  TEST_ASSERT_EQUAL_INT(DB_OK, db_status);
  TEST_ASSERT_EQUAL_INT(1, g_callCount);
  TEST_ASSERT_EQUAL_STRING("SELECT * FROM api.fn_cve_lookup($1, $2, $3, $4, $5, $6)", static_lastCall()->ma_command);
  TEST_ASSERT_EQUAL_INT(6, static_lastCall()->m_paramCount);
  TEST_ASSERT_EQUAL_STRING("{CVE-2021-44228,CVE-2014-0160}", static_lastCall()->ma_params[0]);
  TEST_ASSERT_EQUAL_STRING(row_limit, static_lastCall()->ma_params[1]);
  TEST_ASSERT_EQUAL_STRING("5", static_lastCall()->ma_params[2]);
  TEST_ASSERT_EQUAL_STRING("20", static_lastCall()->ma_params[3]);
  TEST_ASSERT_EQUAL_STRING("10", static_lastCall()->ma_params[4]);
  TEST_ASSERT_EQUAL_STRING("20", static_lastCall()->ma_params[5]);
  TEST_ASSERT_EQUAL_INT(0, static_lastCall()->m_resultFormat);
  TEST_ASSERT_EQUAL_INT(1, results.m_successful);
  TEST_ASSERT_EQUAL_INT(1, results.m_failed);
  TEST_ASSERT_NOT_NULL(results.mp_items);
  TEST_ASSERT_EQUAL_STRING("CVE-2021-44228", results.mp_items[0].ma_cveId);
  db_CVELOOKUPBULKResultFree(&results);
}

void test_CVELOOKUPBULK_unreadable_row_fails_only_its_id(void)
{
  static const BulkIdsParams_t params = {
    .ma_ids    = { "CVE-2021-44228", "CVE-2014-0160", "CVE-2017-0144" },
    .m_idCount = 3,
  };
  char* long_id         = static_makeText(CVELOOKUP_ID_MAX_LEN + 1);
  char* long_epss_trend = static_makeJsonArrayDocument(CVELOOKUP_EPSS_TREND_MAX_LEN + 1);
  char* long_nuclei_templates = static_makeJsonArrayDocument(CVELOOKUP_NUCLEI_TEMPLATES_MAX_LEN + 1);
  TEST_ASSERT_NOT_NULL(long_id);
  TEST_ASSERT_NOT_NULL(long_epss_trend);
  TEST_ASSERT_NOT_NULL(long_nuclei_templates);
  const struct {
    int         m_column;
    const char* mp_value;
    int         m_strdupFailsAtCall;
    const char* mp_name;
  } rows[] = {
    { 0,                                     NULL,            0,  "nothing broken"  },
    { 3,                                     "12abc",         0,  "cvss_v3"         },
    { 0,                                     long_id,         0,  "cve_id"          },
    { CVELOOKUP_ROW_EPSS_TREND_COLUMN_INDEX, long_epss_trend, 0,  "epss_trend"      },
    { 0,                                     NULL,            13, "epss_trend copy" },
    { CVELOOKUP_ROW_NUCLEI_TEMPLATES_COLUMN_INDEX, long_nuclei_templates, 0, "nuclei_templates" },
    { 0,                                     NULL,            14, "nuclei_templates copy" },
  };

  for (size_t row = 0; row < sizeof(rows) / sizeof(rows[0]); row++)
  {
    static_resetFake();
    FakeAnswer_t* answer = static_queueCvelookupBulkRows(3);
    if (rows[row].mp_value)
      answer->ma_cells[1][rows[row].m_column] = rows[row].mp_value;
    g_strdupFailsAtCall = rows[row].m_strdupFailsAtCall;
    CVELOOKUPBULKResult_t results;
    memset(&results, 0xA5, sizeof(results));
    bool is_broken = rows[row].mp_value != NULL || rows[row].m_strdupFailsAtCall != 0;
    int successful = is_broken ? 2 : 3;

    DbStatus_t db_status = db_CVELOOKUPBULK(NULL, &params, &results);

    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_OK, db_status, rows[row].mp_name);
    TEST_ASSERT_EQUAL_INT_MESSAGE(successful, results.m_successful, rows[row].mp_name);
    TEST_ASSERT_EQUAL_INT_MESSAGE(3 - successful, results.m_failed, rows[row].mp_name);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(g_bulkIds[0], results.mp_items[0].ma_cveId, rows[row].mp_name);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(g_bulkIds[is_broken ? 2 : 1], results.mp_items[1].ma_cveId, rows[row].mp_name);
    TEST_ASSERT_NOT_NULL_MESSAGE(results.mp_items[1].mp_refs, rows[row].mp_name);
    db_CVELOOKUPBULKResultFree(&results);
  }
  free(long_id);
  free(long_epss_trend);
  free(long_nuclei_templates);
}

void test_CVELOOKUPBULK_no_row_fails_every_id(void)
{
  static const BulkIdsParams_t params = {
    .ma_ids    = { "CVE-2021-44228", "CVE-2014-0160" },
    .m_idCount = 2,
  };
  static_queueCvelookupBulkRows(0);
  CVELOOKUPBULKResult_t results;
  memset(&results, 0xA5, sizeof(results));

  DbStatus_t db_status = db_CVELOOKUPBULK(NULL, &params, &results);

  TEST_ASSERT_EQUAL_INT(DB_OK, db_status);
  TEST_ASSERT_EQUAL_INT(0, results.m_successful);
  TEST_ASSERT_EQUAL_INT(2, results.m_failed);
  TEST_ASSERT_NULL(results.mp_items);
}

void test_CVELOOKUPBULK_failed_query_is_error(void)
{
  static const BulkIdsParams_t params = {
    .ma_ids    = { "CVE-2021-44228", "CVE-2014-0160" },
    .m_idCount = 2,
  };
  g_resultStatus = PGRES_FATAL_ERROR;
  CVELOOKUPBULKResult_t results;
  memset(&results, 0xA5, sizeof(results));

  DbStatus_t db_status = db_CVELOOKUPBULK(NULL, &params, &results);

  TEST_ASSERT_EQUAL_INT(DB_ERROR, db_status);
  TEST_ASSERT_NULL(results.mp_items);
}

void test_CVELOOKUPBULK_more_rows_than_ids_is_error(void)
{
  static const BulkIdsParams_t params = {
    .ma_ids    = { "CVE-2021-44228", "CVE-2014-0160" },
    .m_idCount = 2,
  };

  for (int row_count = 2; row_count <= 3; row_count++)
  {
    static_resetFake();
    static_queueCvelookupBulkRows(row_count);
    CVELOOKUPBULKResult_t results;
    memset(&results, 0xA5, sizeof(results));

    DbStatus_t db_status = db_CVELOOKUPBULK(NULL, &params, &results);

    if (row_count == 2)
    {
      TEST_ASSERT_EQUAL_INT(DB_OK, db_status);
      TEST_ASSERT_EQUAL_INT(2, results.m_successful);
    }
    else
    {
      TEST_ASSERT_EQUAL_INT(DB_ERROR, db_status);
      TEST_ASSERT_NULL(results.mp_items);
    }
    db_CVELOOKUPBULKResultFree(&results);
  }
}

void test_CVELOOKUPBULK_reads_each_column_from_its_own_row(void)
{
  static const BulkIdsParams_t params = {
    .ma_ids    = { "CVE-2021-44228", "CVE-2014-0160" },
    .m_idCount = 2,
  };
  static const char* const row1[CVELOOKUP_ROW_COLUMN_COUNT] = {
    "CVE-2014-0160", "other description", "LOW", "3.1", "CVSS:3.1/AV:L", "2014-04-07T00:00:00Z",
    "0.12345", "0.54321", "CWE-119", "[\"CWE-119\"]", "f", "2022-01-01", "Modified", "7", "5",
    "[\"tag\"]", "2", "[\"prod\"]", "[\"ref\"]", "[\"trend\"]", "Unknown", "4.2", "",
    "poc", "no", "partial", "2.0.3", "2023-01-02T03:04:05Z", "f", "4", "f", "[\"template\"]",
    "adp", "other", "nvd", "11", "{\"vendor\":3}", "12"
  };
  FakeAnswer_t* answer = static_queueCvelookupBulkRows(2);
  for (int col = 0; col < CVELOOKUP_ROW_COLUMN_COUNT; col++)
    answer->ma_cells[1][col] = row1[col];
  CVELOOKUPBULKResult_t results;
  memset(&results, 0xA5, sizeof(results));

  DbStatus_t db_status = db_CVELOOKUPBULK(NULL, &params, &results);

  TEST_ASSERT_EQUAL_INT(DB_OK, db_status);
  TEST_ASSERT_EQUAL_INT(2, results.m_successful);
  const CVELOOKUPRecord_t* record = &results.mp_items[1];
  TEST_ASSERT_EQUAL_STRING("CVE-2014-0160", record->ma_cveId);
  TEST_ASSERT_EQUAL_STRING("other description", record->ma_description);
  TEST_ASSERT_EQUAL_STRING("LOW", record->ma_severity);
  TEST_ASSERT_EQUAL_INT(310, (int)(record->m_cvssV3 * 100.0 + 0.5));
  TEST_ASSERT_EQUAL_STRING("CVSS:3.1/AV:L", record->ma_cvssV3Vector);
  TEST_ASSERT_EQUAL_STRING("2014-04-07T00:00:00Z", record->ma_publishedTime);
  TEST_ASSERT_EQUAL_INT(12345, (int)(record->m_epssScore * 100000.0 + 0.5));
  TEST_ASSERT_EQUAL_INT(54321, (int)(record->m_epssPercentile * 100000.0 + 0.5));
  TEST_ASSERT_EQUAL_STRING("CWE-119", record->ma_cweId);
  TEST_ASSERT_EQUAL_STRING("[\"CWE-119\"]", record->mp_cwes);
  TEST_ASSERT_FALSE(record->m_inKev);
  TEST_ASSERT_EQUAL_STRING("2022-01-01", record->ma_kevDateAdded);
  TEST_ASSERT_EQUAL_STRING("Modified", record->ma_vulnerabilityStatus);
  TEST_ASSERT_EQUAL_INT(7, record->m_pocCount);
  TEST_ASSERT_EQUAL_INT(5, record->m_vendorAdvisoryCount);
  TEST_ASSERT_EQUAL_STRING("[\"tag\"]", record->mp_cveTags);
  TEST_ASSERT_EQUAL_INT(2, record->m_metasploitModuleCount);
  TEST_ASSERT_EQUAL_STRING("[\"prod\"]", record->mp_affectedProducts);
  TEST_ASSERT_EQUAL_INT(11, record->m_affectedProductCount);
  TEST_ASSERT_EQUAL_STRING("{\"vendor\":3}", record->mp_productCountByVendor);
  TEST_ASSERT_EQUAL_STRING("[\"ref\"]", record->mp_refs);
  TEST_ASSERT_EQUAL_INT(12, record->m_refCount);
  TEST_ASSERT_EQUAL_STRING("[\"trend\"]", record->mp_epssTrend);
  TEST_ASSERT_EQUAL_STRING("Unknown", record->ma_ransomwareCampaign);
  TEST_ASSERT_EQUAL_INT(420, (int)(record->m_cvssV4 * 100.0 + 0.5));
  TEST_ASSERT_EQUAL_STRING("", record->ma_cvssV4Vector);
  TEST_ASSERT_EQUAL_STRING("poc", record->ma_ssvcExploitation);
  TEST_ASSERT_EQUAL_STRING("no", record->ma_ssvcAutomatable);
  TEST_ASSERT_EQUAL_STRING("partial", record->ma_ssvcTechnicalImpact);
  TEST_ASSERT_EQUAL_STRING("2.0.3", record->ma_ssvcVersion);
  TEST_ASSERT_EQUAL_STRING("2023-01-02T03:04:05Z", record->ma_ssvcScoredAt);
  TEST_ASSERT_EQUAL_STRING("Track", record->m_ssvcResult.ma_decisions[SSVC_MISSION_WELLBEING_LOW]);
  TEST_ASSERT_EQUAL_STRING("Track", record->m_ssvcResult.ma_decisions[SSVC_MISSION_WELLBEING_MEDIUM]);
  TEST_ASSERT_EQUAL_STRING("Track*", record->m_ssvcResult.ma_decisions[SSVC_MISSION_WELLBEING_HIGH]);
  TEST_ASSERT_FALSE(record->m_isMetasploitFeedLoaded);
  TEST_ASSERT_TRUE(results.mp_items[0].m_isMetasploitFeedLoaded);
  TEST_ASSERT_EQUAL_INT(4, record->m_nucleiTemplateCount);
  TEST_ASSERT_FALSE(record->m_isNucleiTemplateFeedLoaded);
  TEST_ASSERT_TRUE(results.mp_items[0].m_isNucleiTemplateFeedLoaded);
  TEST_ASSERT_EQUAL_STRING("[\"template\"]", record->mp_nucleiTemplates);
  TEST_ASSERT_EQUAL_STRING("adp", record->ma_cvssV3Source);
  TEST_ASSERT_EQUAL_STRING("other", record->ma_cvssV4Source);
  TEST_ASSERT_EQUAL_STRING("nvd", record->ma_cweSource);
  db_CVELOOKUPBULKResultFree(&results);
}

void test_CVELOOKUPBULK_items_hold_no_ghsa_advisory(void)
{
  static const BulkIdsParams_t params = {
    .ma_ids    = { "CVE-2021-44228", "CVE-2014-0160" },
    .m_idCount = 2,
  };
  static_queueCvelookupBulkRows(2);
  CVELOOKUPBULKResult_t results;
  memset(&results, 0xA5, sizeof(results));

  g_dirtyMalloc = true;
  DbStatus_t db_status = db_CVELOOKUPBULK(NULL, &params, &results);
  g_dirtyMalloc = false;

  TEST_ASSERT_EQUAL_INT(DB_OK, db_status);
  TEST_ASSERT_EQUAL_INT(2, results.m_successful);
  for (int i = 0; i < 2; i++)
  {
    const CVELOOKUPRecord_t* record = &results.mp_items[i];
    TEST_ASSERT_FALSE(record->m_isGhsaAsked);
    TEST_ASSERT_FALSE(record->m_ghsaUnavailable);
    TEST_ASSERT_FALSE(record->m_isGhsaFeedLoaded);
    TEST_ASSERT_NULL(record->mp_ghsa);
  }
  db_CVELOOKUPBULKResultFree(&results);
}

static DbStatus_t static_runBulkCall(bool is_lookup, const BulkIdsParams_t* params, bool* is_items_null_out)
{
  static_resetFake();
  DbStatus_t db_status = DB_ERROR;
  if (is_lookup)
  {
    static_queueCvelookupBulkRows(0);
    CVELOOKUPBULKResult_t results;
    memset(&results, 0xA5, sizeof(results));
    db_status = db_CVELOOKUPBULK(NULL, params, &results);
    *is_items_null_out = (results.mp_items == NULL);
    db_CVELOOKUPBULKResultFree(&results);
  }
  else
  {
    static_queueTriageBulkRows(0);
    CVETRIAGEBULKResult_t results;
    memset(&results, 0xA5, sizeof(results));
    db_status = db_CVETRIAGEBULK(NULL, params, &results);
    *is_items_null_out = (results.mp_items == NULL);
    db_CVETRIAGEBULKResultFree(&results);
  }
  return db_status;
}

void test_bulk_calls_refuse_ids_their_literal_cannot_hold(void)
{
  static struct {
    BulkIdsParams_t m_params;
    char               ma_after[CVELOOKUP_ID_MAX_LEN + 1];
  } padded;
  static const int refused_counts[] = { -1, BULK_MAX_IDS + 1 };

  for (int call = 0; call < 2; call++)
  {
    bool is_lookup = (call == 0);
    const char* name = is_lookup ? "db_CVELOOKUPBULK" : "db_CVETRIAGEBULK";
    bool is_items_null = false;
    memset(&padded, 0, sizeof(padded));
    for (int i = 0; i < CVELOOKUPBULK_MAX_IDS; i++)
      snprintf(padded.m_params.ma_ids[i], sizeof(padded.m_params.ma_ids[i]), "CVE-2021-%015d", i);
    padded.m_params.m_idCount = CVELOOKUPBULK_MAX_IDS;

    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_OK, static_runBulkCall(is_lookup, &padded.m_params, &is_items_null), name);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_callCount, name);
    const char* literal = static_lastCall()->ma_params[0];
    TEST_ASSERT_EQUAL_size_t_MESSAGE((size_t)CVELOOKUPBULK_MAX_IDS * (CVELOOKUP_ID_MAX_LEN + 1) + 1, strlen(literal), name);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, strncmp(literal, "{CVE-2021-000000000000000,", 26), name);
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(literal, ",CVE-2021-000000000000049}"), name);

    for (size_t k = 0; k < sizeof(refused_counts) / sizeof(refused_counts[0]); k++)
    {
      padded.m_params.m_idCount = refused_counts[k];
      TEST_ASSERT_EQUAL_INT_MESSAGE(DB_ERROR, static_runBulkCall(is_lookup, &padded.m_params, &is_items_null), name);
      TEST_ASSERT_EQUAL_INT_MESSAGE(0, g_callCount, name);
      TEST_ASSERT_TRUE_MESSAGE(is_items_null, name);
    }

    padded.m_params.m_idCount = 2;
    memset(padded.m_params.ma_ids[0], 'A', sizeof(padded.m_params.ma_ids[0]));
    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_ERROR, static_runBulkCall(is_lookup, &padded.m_params, &is_items_null), name);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, g_callCount, name);
    TEST_ASSERT_TRUE_MESSAGE(is_items_null, name);
  }
}

#define PRODUCTEXPOSURE_ROW_COLUMN_COUNT            15
#define PRODUCTEXPOSURE_SUMMARY_COLUMN_COUNT        12
#define PRODUCTEXPOSURE_ROW_CVE_ID_COLUMN_INDEX     12
#define PRODUCTEXPOSURE_ROW_RISK_SCORE_COLUMN_INDEX 13
#define PRODUCTEXPOSURE_ROW_LABEL_COLUMN_INDEX      14

static const char* const g_productExposureSummaryValues[PRODUCTEXPOSURE_SUMMARY_COLUMN_COUNT] = {
  "2", "1", "1", "0", "0", "1", "10.0", "9.5", "0.97566", "1", "96.5", "2021-12-10"
};

static const char* const g_productExposureTopValues[2][3] = {
  { "CVE-2021-44228", "96.5",  "CRITICAL" },
  { "CVE-2014-0160",  "71.25", "HIGH"     },
};

static const char* const g_productExposureColumnNames[PRODUCTEXPOSURE_ROW_COLUMN_COUNT] = {
  "cve_count", "critical_count", "high_count", "medium_count", "low_count", "kev_count",
  "max_cvss", "avg_cvss", "max_epss", "poc_backed_count", "worst_risk_score",
  "most_recent_published", "cve_id", "risk_score", "risk_label"
};

static FakeAnswer_t* static_queueProductExposureAnswer(const char* const summary[PRODUCTEXPOSURE_SUMMARY_COLUMN_COUNT], int row_count)
{
  FakeAnswer_t* answer = static_queueAnswer(PGRES_TUPLES_OK, PRODUCTEXPOSURE_ROW_COLUMN_COUNT, row_count);
  for (int col = 0; col < PRODUCTEXPOSURE_ROW_COLUMN_COUNT; col++)
    answer->ma_columnNames[col] = g_productExposureColumnNames[col];
  for (int row = 0; row < row_count; row++)
  {
    for (int col = 0; col < PRODUCTEXPOSURE_SUMMARY_COLUMN_COUNT; col++)
      answer->ma_cells[row][col] = summary[col];
    for (int col = PRODUCTEXPOSURE_SUMMARY_COLUMN_COUNT; col < PRODUCTEXPOSURE_ROW_COLUMN_COUNT; col++)
      answer->ma_cells[row][col] = g_productExposureTopValues[row % 2][col - PRODUCTEXPOSURE_SUMMARY_COLUMN_COUNT];
  }
  return answer;
}

#define PRODUCTEXPOSURE_EOL_COLUMN_COUNT 9

static const char* const g_productExposureEolNames[PRODUCTEXPOSURE_EOL_COLUMN_COUNT] = {
  "row_kind", "name", "url", "eol_date", "is_eol", "is_maintained", "is_lts", "latest_version",
  "maintained_cycle_count"
};

static FakeAnswer_t* static_queueProductExposureEol(int row_count)
{
  FakeAnswer_t* answer = static_queueAnswer(PGRES_TUPLES_OK, PRODUCTEXPOSURE_EOL_COLUMN_COUNT, row_count);
  for (int col = 0; col < PRODUCTEXPOSURE_EOL_COLUMN_COUNT; col++)
  {
    answer->ma_columnNames[col] = g_productExposureEolNames[col];
    for (int row = 0; row < row_count; row++)
      answer->ma_cells[row][col] = FAKE_SQL_NULL;
  }
  return answer;
}

static void static_setEolProductRow(FakeAnswer_t* answer, int row, const char* name, const char* url, const char* maintained_cycle_count)
{
  answer->ma_cells[row][0] = "product";
  answer->ma_cells[row][1] = name;
  answer->ma_cells[row][2] = url;
  answer->ma_cells[row][8] = maintained_cycle_count;
}

static void static_setEolCycleRow(FakeAnswer_t* answer, int row, const char* kind, const char* name, const char* eol_date,
                                  const char* is_eol, const char* is_maintained, const char* is_lts, const char* latest_version)
{
  answer->ma_cells[row][0] = kind;
  answer->ma_cells[row][1] = name;
  answer->ma_cells[row][3] = eol_date;
  answer->ma_cells[row][4] = is_eol;
  answer->ma_cells[row][5] = is_maintained;
  answer->ma_cells[row][6] = is_lts;
  answer->ma_cells[row][7] = latest_version;
}

static DbStatus_t static_runProductExposure(const char* version, bool is_rejected_included, PRODUCTEXPOSURERecord_t* record)
{
  PRODUCTEXPOSUREParams_t params;
  memset(&params, 0, sizeof(params));
  snprintf(params.ma_vendor,  sizeof(params.ma_vendor),  "%s", "apache");
  snprintf(params.ma_product, sizeof(params.ma_product), "%s", "log4j");
  snprintf(params.ma_version, sizeof(params.ma_version), "%s", version);
  params.m_isRejectedIncluded = is_rejected_included;
  return db_PRODUCTEXPOSURE(NULL, &params, record);
}

static FakeAnswer_t* static_queueProductExposureAnswers(int eol_row_count)
{
  static_queueProductExposureAnswer(g_productExposureSummaryValues, 2);
  return static_queueProductExposureEol(eol_row_count);
}

void test_PRODUCTEXPOSURE_fixed_size_field_past_its_limit_is_error(void)
{
  static const FieldLimit_t fields[] = {
    FIELD_LIMIT(0, 0, 11, CVELOOKUP_PUBLISHED_LEN, PRODUCTEXPOSURERecord_t, ma_mostRecentPublished),
    FIELD_LIMIT(0, 1, 12, CVELOOKUP_ID_MAX_LEN,    PRODUCTEXPOSURERecord_t, ma_topCves[1].ma_cveId),
    FIELD_LIMIT(0, 1, 14, CVERISKSCORE_LABEL_LEN,  PRODUCTEXPOSURERecord_t, ma_topCves[1].ma_label),
  };
  for (size_t f = 0; f < sizeof(fields) / sizeof(fields[0]); f++)
  {
    for (size_t extra = 0; extra <= 1; extra++)
    {
      static_resetFake();
      size_t length = fields[f].m_limit + extra;
      char* text = static_makeText(length);
      TEST_ASSERT_NOT_NULL(text);
      static_queueProductExposureAnswers(0);
      g_queuedAnswers[fields[f].m_answer].ma_cells[fields[f].m_row][fields[f].m_column] = text;
      PRODUCTEXPOSURERecord_t record;
      char message[80] = "";
      static_fieldMessage(message, sizeof(message), &fields[f], length);

      DbStatus_t db_status = static_runProductExposure("", false, &record);

      if (extra == 0)
      {
        TEST_ASSERT_EQUAL_INT_MESSAGE(DB_OK, db_status, message);
        static_assertFieldHoldsLimit(&record, &fields[f], message);
      }
      else
      {
        TEST_ASSERT_EQUAL_INT_MESSAGE(DB_ERROR, db_status, message);
      }
      free(text);
    }
  }
}

#define KEVLOOKUP_ROW_COLUMN_COUNT 13

static const char* const g_kevlookupRowValues[KEVLOOKUP_ROW_COLUMN_COUNT] = {
  "CVE-2021-44228", "Apache", "Log4j2", "2021-12-24", "Apply updates", "t", "Log4Shell",
  "short description", "2021-12-10", "", "[]", "notes", "t"
};

static const char* const g_kevlookupColumnNames[KEVLOOKUP_ROW_COLUMN_COUNT] = {
  "cve_id", "vendor_project", "product", "patch_deadline", "required_action", "known_ransomware_use",
  "vulnerability_name", "short_description", "kev_date_added", "date_removed", "cwes", "notes",
  "in_kev"
};

static FakeAnswer_t* static_queueKevlookupRow(void)
{
  FakeAnswer_t* answer = static_queueAnswer(PGRES_TUPLES_OK, KEVLOOKUP_ROW_COLUMN_COUNT, 1);
  for (int col = 0; col < KEVLOOKUP_ROW_COLUMN_COUNT; col++)
  {
    answer->ma_columnNames[col] = g_kevlookupColumnNames[col];
    answer->ma_cells[0][col]    = g_kevlookupRowValues[col];
  }
  return answer;
}

void test_KEVLOOKUP_fixed_size_field_past_its_limit_is_error(void)
{
  static const FieldLimit_t fields[] = {
    FIELD_LIMIT(0, 0, 0, CVELOOKUP_ID_MAX_LEN,          KEVLOOKUPRecord_t, ma_cveId),
    FIELD_LIMIT(0, 0, 1, KEVLOOKUP_VENDOR_LEN,          KEVLOOKUPRecord_t, ma_vendorProject),
    FIELD_LIMIT(0, 0, 2, KEVLOOKUP_PRODUCT_LEN,         KEVLOOKUPRecord_t, ma_product),
    FIELD_LIMIT(0, 0, 3, CVELOOKUP_PUBLISHED_LEN,       KEVLOOKUPRecord_t, ma_patchDeadline),
    FIELD_LIMIT(0, 0, 4, KEVLOOKUP_REQUIRED_ACTION_LEN, KEVLOOKUPRecord_t, ma_requiredAction),
    FIELD_LIMIT(0, 0, 6, KEVLOOKUP_VULN_NAME_LEN,       KEVLOOKUPRecord_t, ma_vulnerabilityName),
    FIELD_LIMIT(0, 0, 7, KEVLOOKUP_SHORT_DESC_LEN,      KEVLOOKUPRecord_t, ma_shortDescription),
    FIELD_LIMIT(0, 0, 8, CVELOOKUP_PUBLISHED_LEN,       KEVLOOKUPRecord_t, ma_dateAdded),
    FIELD_LIMIT(0, 0, 9, KEVLOOKUP_DATE_REMOVED_LEN,    KEVLOOKUPRecord_t, ma_dateRemoved),
  };

  for (size_t f = 0; f < sizeof(fields) / sizeof(fields[0]); f++)
  {
    for (size_t extra = 0; extra <= 1; extra++)
    {
      static_resetFake();
      size_t length = fields[f].m_limit + extra;
      char* text = static_makeText(length);
      TEST_ASSERT_NOT_NULL(text);
      FakeAnswer_t* answer = static_queueKevlookupRow();
      answer->ma_cells[fields[f].m_row][fields[f].m_column] = text;
      KEVLOOKUPRecord_t record;
      memset(&record, 0xA5, sizeof(record));
      char message[64] = "";
      static_fieldMessage(message, sizeof(message), &fields[f], length);

      DbStatus_t db_status = db_KEVLOOKUP(NULL, "CVE-2021-44228", &record);

      if (extra == 0)
      {
        TEST_ASSERT_EQUAL_INT_MESSAGE(DB_OK, db_status, message);
        static_assertFieldHoldsLimit(&record, &fields[f], message);
      }
      else
      {
        TEST_ASSERT_EQUAL_INT_MESSAGE(DB_ERROR, db_status, message);
        TEST_ASSERT_NULL_MESSAGE(record.mp_cwes, message);
        TEST_ASSERT_NULL_MESSAGE(record.mp_notes, message);
      }
      db_KEVLOOKUPRecordFree(&record);
      free(text);
    }
  }
}

void test_KEVLOOKUP_reads_notes_and_in_kev_from_their_columns(void)
{
  FakeAnswer_t* answer = static_queueKevlookupRow();
  answer->ma_cells[0][11] = "https://example.com/a ; https://example.com/b";
  answer->ma_cells[0][12] = "f";
  KEVLOOKUPRecord_t record;
  memset(&record, 0xA5, sizeof(record));

  DbStatus_t db_status = db_KEVLOOKUP(NULL, "CVE-2021-44228", &record);

  TEST_ASSERT_EQUAL_INT(DB_OK, db_status);
  TEST_ASSERT_EQUAL_STRING("SELECT * FROM api.fn_kev_lookup($1)", static_lastCall()->ma_command);
  TEST_ASSERT_EQUAL_INT(1, static_lastCall()->m_paramCount);
  TEST_ASSERT_EQUAL_STRING("CVE-2021-44228", static_lastCall()->ma_params[0]);
  TEST_ASSERT_FALSE(record.m_inKev);
  TEST_ASSERT_EQUAL_STRING("https://example.com/a ; https://example.com/b", record.mp_notes);
  db_KEVLOOKUPRecordFree(&record);

  static_resetFake();
  answer = static_queueKevlookupRow();
  answer->ma_cells[0][11] = FAKE_SQL_NULL;
  memset(&record, 0xA5, sizeof(record));

  db_status = db_KEVLOOKUP(NULL, "CVE-2021-44228", &record);

  TEST_ASSERT_EQUAL_INT(DB_OK, db_status);
  TEST_ASSERT_TRUE(record.m_inKev);
  TEST_ASSERT_NULL(record.mp_notes);
  db_KEVLOOKUPRecordFree(&record);
}

void test_KEVLOOKUP_failed_notes_copy_frees_the_cwes_copy(void)
{
  static_queueKevlookupRow();
  g_strdupFailsAtCall = 2;
  KEVLOOKUPRecord_t record;
  memset(&record, 0xA5, sizeof(record));

  DbStatus_t db_status = db_KEVLOOKUP(NULL, "CVE-2021-44228", &record);

  TEST_ASSERT_EQUAL_INT(DB_ERROR, db_status);
  TEST_ASSERT_EQUAL_INT(2, g_strdupCallCount);
  TEST_ASSERT_NULL(record.mp_cwes);
  TEST_ASSERT_NULL(record.mp_notes);
}

#define CWELOOKUP_ROW_COLUMN_COUNT              15
#define CWELOOKUP_ROW_FIRST_NUMBER_COLUMN_INDEX 11
#define CWELOOKUP_ROW_NUMBER_COLUMN_COUNT        4

static const char* const g_cwelookupRowValues[CWELOOKUP_ROW_COLUMN_COUNT] = {
  "CWE-79", "Cross-site Scripting", "description", "High", "CWE-74", "2026-09-22", "[]",
  "extended description", "[]", "Base", "Stable", "2", "7.25", "0.1234", "3"
};

static const char* const g_cwelookupColumnNames[CWELOOKUP_ROW_COLUMN_COUNT] = {
  "cwe_id", "cwe_name", "cwe_description", "likelihood", "parent_cwe", "updated_at",
  "mitigations", "extended_description", "examples", "abstract_type", "cwe_status",
  "kev_cve_count", "avg_cvss", "avg_epss", "cve_count"
};

static FakeAnswer_t* static_queueCwelookupRow(void)
{
  FakeAnswer_t* answer = static_queueAnswer(PGRES_TUPLES_OK, CWELOOKUP_ROW_COLUMN_COUNT, 1);
  for (int col = 0; col < CWELOOKUP_ROW_COLUMN_COUNT; col++)
  {
    answer->ma_columnNames[col] = g_cwelookupColumnNames[col];
    answer->ma_cells[0][col]    = g_cwelookupRowValues[col];
  }
  return answer;
}

void test_CWELOOKUP_fixed_size_field_past_its_limit_is_error(void)
{
  static const FieldLimit_t fields[] = {
    FIELD_LIMIT(0, 0, 0, CWELOOKUP_ID_MAX_LEN,     CWELOOKUPRecord_t, ma_cweId),
    FIELD_LIMIT(0, 0, 1, CWELOOKUP_NAME_LEN,       CWELOOKUPRecord_t, ma_name),
    FIELD_LIMIT(0, 0, 2, CWELOOKUP_DESC_MAX_LEN,   CWELOOKUPRecord_t, ma_description),
    FIELD_LIMIT(0, 0, 3, CWELOOKUP_LIKELIHOOD_LEN, CWELOOKUPRecord_t, ma_likelihood),
    FIELD_LIMIT(0, 0, 4, CWELOOKUP_PARENT_CWE_LEN, CWELOOKUPRecord_t, ma_parentCwe),
    FIELD_LIMIT(0, 0, 5, CWELOOKUP_UPDATED_AT_LEN, CWELOOKUPRecord_t, ma_updatedAt),
    FIELD_LIMIT(0, 0, 9, CWELOOKUP_ABSTRACTION_LEN, CWELOOKUPRecord_t, ma_abstraction),
    FIELD_LIMIT(0, 0, 10, CWELOOKUP_STATUS_LEN,     CWELOOKUPRecord_t, ma_status),
  };

  for (size_t f = 0; f < sizeof(fields) / sizeof(fields[0]); f++)
  {
    for (size_t extra = 0; extra <= 1; extra++)
    {
      static_resetFake();
      size_t length = fields[f].m_limit + extra;
      char* text = static_makeText(length);
      TEST_ASSERT_NOT_NULL(text);
      FakeAnswer_t* answer = static_queueCwelookupRow();
      answer->ma_cells[fields[f].m_row][fields[f].m_column] = text;
      CWELOOKUPRecord_t record;
      memset(&record, 0xA5, sizeof(record));
      char message[64] = "";
      static_fieldMessage(message, sizeof(message), &fields[f], length);

      DbStatus_t db_status = db_CWELOOKUP(NULL, "CWE-79", &record);

      if (extra == 0)
      {
        TEST_ASSERT_EQUAL_INT_MESSAGE(DB_OK, db_status, message);
        static_assertFieldHoldsLimit(&record, &fields[f], message);
      }
      else
      {
        TEST_ASSERT_EQUAL_INT_MESSAGE(DB_ERROR, db_status, message);
        TEST_ASSERT_NULL_MESSAGE(record.mp_mitigations, message);
        TEST_ASSERT_NULL_MESSAGE(record.mp_extendedDescription, message);
        TEST_ASSERT_NULL_MESSAGE(record.mp_examples, message);
      }
      db_CWELOOKUPRecordFree(&record);
      free(text);
    }
  }
}

void test_HEALTH_fixed_size_field_past_its_limit_is_error(void)
{
  static const FieldLimit_t fields[] = {
    FIELD_LIMIT(0, 0, 1, CVELOOKUP_ID_MAX_LEN,     HEALTHData_t, ma_nvdLastCveId),
    FIELD_LIMIT(0, 0, 2, CVELOOKUP_PUBLISHED_LEN,  HEALTHData_t, ma_nvdLastPublishedTime),
    FIELD_LIMIT(0, 0, 4, CVELOOKUP_ID_MAX_LEN,     HEALTHData_t, ma_kevLastCveId),
    FIELD_LIMIT(0, 0, 5, CVELOOKUP_PUBLISHED_LEN,  HEALTHData_t, ma_kevLastDateAdded),
    FIELD_LIMIT(0, 0, 7, CWELOOKUP_ID_MAX_LEN,     HEALTHData_t, ma_cweLastId),
    FIELD_LIMIT(0, 0, 8, CWELOOKUP_UPDATED_AT_LEN, HEALTHData_t, ma_cweLastUpdatedAt),
  };

  for (size_t f = 0; f < sizeof(fields) / sizeof(fields[0]); f++)
  {
    for (size_t extra = 0; extra <= 1; extra++)
    {
      static_resetFake();
      size_t length = fields[f].m_limit + extra;
      char* text = static_makeText(length);
      TEST_ASSERT_NOT_NULL(text);
      static_queueHealthAnswers();
      g_queuedAnswers[fields[f].m_answer].ma_cells[fields[f].m_row][fields[f].m_column] = text;
      HEALTHData_t data;
      char message[64] = "";
      static_fieldMessage(message, sizeof(message), &fields[f], length);

      DbStatus_t db_status = db_HEALTH(NULL, &data);

      if (extra == 0)
      {
        TEST_ASSERT_EQUAL_INT_MESSAGE(DB_OK, db_status, message);
        static_assertFieldHoldsLimit(&data, &fields[f], message);
      }
      else
      {
        TEST_ASSERT_EQUAL_INT_MESSAGE(DB_ERROR, db_status, message);
        TEST_ASSERT_EQUAL_INT_MESSAGE(fields[f].m_answer + 1, g_callCount, message);
      }
      free(text);
    }
  }
}

void test_HEALTH_null_newest_row_leaves_fields_empty(void)
{
  static const int newest_row_columns[] = { 1, 2, 4, 5, 7, 8 };
  static_queueHealthAnswers();
  for (size_t i = 0; i < sizeof(newest_row_columns) / sizeof(newest_row_columns[0]); i++)
    g_queuedAnswers[0].ma_cells[0][newest_row_columns[i]] = FAKE_SQL_NULL;
  HEALTHData_t data;
  memset(&data, 0xA5, sizeof(data));

  DbStatus_t db_status = db_HEALTH(NULL, &data);

  TEST_ASSERT_EQUAL_INT(DB_OK, db_status);
  TEST_ASSERT_EQUAL_INT(HEALTH_QUERY_COUNT, g_callCount);
  TEST_ASSERT_EQUAL_INT(391254, data.m_cveCount);
  TEST_ASSERT_EQUAL_INT(1710, data.m_kevCount);
  TEST_ASSERT_EQUAL_INT(944, data.m_cweCount);
  TEST_ASSERT_EQUAL_STRING("", data.ma_nvdLastCveId);
  TEST_ASSERT_EQUAL_STRING("", data.ma_nvdLastPublishedTime);
  TEST_ASSERT_EQUAL_STRING("", data.ma_kevLastCveId);
  TEST_ASSERT_EQUAL_STRING("", data.ma_kevLastDateAdded);
  TEST_ASSERT_EQUAL_STRING("", data.ma_cweLastId);
  TEST_ASSERT_EQUAL_STRING("", data.ma_cweLastUpdatedAt);
}

#define RISKSCORE_ROW_COLUMN_COUNT 6

static const char* const g_riskscoreRowValues[RISKSCORE_ROW_COLUMN_COUNT] = {
  "72.4", "40.0", "29.4", "3.0", "t", "HIGH"
};

static const char* const g_riskscoreColumnNames[RISKSCORE_ROW_COLUMN_COUNT] = {
  "risk_score", "exploitability", "impact", "evidence", "has_public_poc", "risk_label"
};

static FakeAnswer_t* static_queueRiskscoreAnswer(int row_count)
{
  FakeAnswer_t* answer = static_queueAnswer(PGRES_TUPLES_OK, RISKSCORE_ROW_COLUMN_COUNT, row_count);
  for (int col = 0; col < RISKSCORE_ROW_COLUMN_COUNT; col++)
  {
    answer->ma_columnNames[col] = g_riskscoreColumnNames[col];
    for (int row = 0; row < row_count; row++)
      answer->ma_cells[row][col] = g_riskscoreRowValues[col];
  }
  return answer;
}

typedef enum {
  TRIAGE_CALL_CVETRIAGE,
  TRIAGE_CALL_CVETRIAGEBULK,
  TRIAGE_CALL_PRODUCTEXPOSURE
} TriageCall_t;

static const char* const g_triageCallNames[] = { "db_CVETRIAGE", "db_CVETRIAGEBULK", "db_PRODUCTEXPOSURE" };

static DbStatus_t static_runTriageCall(TriageCall_t call, const char* const labels[2], CVETRIAGEItem_t items_out[2])
{
  static_resetFake();
  memset(items_out, 0, 2 * sizeof(CVETRIAGEItem_t));
  if (call == TRIAGE_CALL_PRODUCTEXPOSURE)
  {
    FakeAnswer_t* exposure = static_queueProductExposureAnswer(g_productExposureSummaryValues, 2);
    for (int row = 0; row < 2; row++)
    {
      exposure->ma_cells[row][PRODUCTEXPOSURE_ROW_RISK_SCORE_COLUMN_INDEX] = "96.5";
      exposure->ma_cells[row][PRODUCTEXPOSURE_ROW_LABEL_COLUMN_INDEX]      = labels[row];
    }
    static_queueProductExposureEol(0);
  }
  else
  {
    if (call == TRIAGE_CALL_CVETRIAGE)
      static_queueTotalAnswer("2");
    FakeAnswer_t* page = static_queueAnswer(PGRES_TUPLES_OK, TRIAGE_ROW_COLUMN_COUNT, 2);
    static_fillTriageRows(page);
    for (int row = 0; row < 2; row++)
      page->ma_cells[row][TRIAGE_ROW_LABEL_COLUMN_INDEX] = labels[row];
  }

  DbStatus_t db_status = DB_ERROR;
  switch (call)
  {
    case TRIAGE_CALL_CVETRIAGE:
    {
      CVETRIAGEParams_t params;
      memset(&params, 0, sizeof(params));
      params.m_minRiskScore = -1.0;
      params.m_limit    = 2;
      CVETRIAGEResult_t results;
      memset(&results, 0, sizeof(results));
      db_status = db_CVETRIAGE(FAKE_CONN, &params, &results);
      if (db_status == DB_OK && results.m_count == 2)
        memcpy(items_out, results.mp_items, 2 * sizeof(CVETRIAGEItem_t));
      db_CVETRIAGEResultFree(&results);
      break;
    }
    case TRIAGE_CALL_CVETRIAGEBULK:
    {
      static const BulkIdsParams_t params = {
        .ma_ids    = { "CVE-2021-44228", "CVE-2014-0160" },
        .m_idCount = 2,
      };
      CVETRIAGEBULKResult_t results;
      memset(&results, 0, sizeof(results));
      db_status = db_CVETRIAGEBULK(NULL, &params, &results);
      if (db_status == DB_OK && results.m_successful == 2)
        memcpy(items_out, results.mp_items, 2 * sizeof(CVETRIAGEItem_t));
      db_CVETRIAGEBULKResultFree(&results);
      break;
    }
    case TRIAGE_CALL_PRODUCTEXPOSURE:
    {
      PRODUCTEXPOSURERecord_t record;
      db_status = static_runProductExposure("", false, &record);
      if (db_status == DB_OK && record.m_topCveCount == 2)
        memcpy(items_out, record.ma_topCves, 2 * sizeof(CVETRIAGEItem_t));
      break;
    }
  }
  return db_status;
}

void test_triage_items_read_the_label_from_its_column(void)
{
  static const char* const contrary_labels[2] = { "LOW", "MEDIUM" };

  for (int call = TRIAGE_CALL_CVETRIAGE; call <= TRIAGE_CALL_PRODUCTEXPOSURE; call++)
  {
    const char* name = g_triageCallNames[call];
    CVETRIAGEItem_t items[2];
    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_OK, static_runTriageCall((TriageCall_t)call, contrary_labels, items), name);
    TEST_ASSERT_EQUAL_STRING_MESSAGE("LOW", items[0].ma_label, name);
    TEST_ASSERT_EQUAL_STRING_MESSAGE("MEDIUM", items[1].ma_label, name);
    TEST_ASSERT_EQUAL_INT_MESSAGE(965, (int)(items[1].m_riskScore * 10.0 + 0.5), name);

    for (size_t extra = 0; extra <= 1; extra++)
    {
      char* text = static_makeText(CVERISKSCORE_LABEL_LEN + extra);
      TEST_ASSERT_NOT_NULL(text);
      const char* const long_labels[2] = { "CRITICAL", text };

      DbStatus_t db_status = static_runTriageCall((TriageCall_t)call, long_labels, items);

      if (extra == 0)
      {
        TEST_ASSERT_EQUAL_INT_MESSAGE(DB_OK, db_status, name);
        TEST_ASSERT_EQUAL_size_t_MESSAGE(CVERISKSCORE_LABEL_LEN, strlen(items[1].ma_label), name);
      }
      else if (call == TRIAGE_CALL_CVETRIAGEBULK)
      {
        TEST_ASSERT_EQUAL_INT_MESSAGE(DB_OK, db_status, name);
      }
      else
      {
        TEST_ASSERT_EQUAL_INT_MESSAGE(DB_ERROR, db_status, name);
      }
      free(text);
    }
  }
}

void test_CVERISKSCORE_columns_land_in_their_own_fields(void)
{
  FakeAnswer_t* risk = static_queueRiskscoreAnswer(1);
  CVERISKSCORERecord_t record;
  TEST_ASSERT_EQUAL_INT(DB_OK, db_CVERISKSCORE(NULL, "CVE-2021-44228", &record));
  TEST_ASSERT_EQUAL_STRING("SELECT * FROM api.fn_cve_risk_breakdown($1)", static_lastCall()->ma_command);
  TEST_ASSERT_EQUAL_INT(1, static_lastCall()->m_paramCount);
  TEST_ASSERT_EQUAL_STRING("CVE-2021-44228", static_lastCall()->ma_params[0]);
  TEST_ASSERT_EQUAL_INT(724, (int)(record.m_score * 10.0 + 0.5));
  TEST_ASSERT_EQUAL_INT(400, (int)(record.m_exploitabilityComponent * 10.0 + 0.5));
  TEST_ASSERT_EQUAL_INT(294, (int)(record.m_impactComponent * 10.0 + 0.5));
  TEST_ASSERT_EQUAL_INT(30, (int)(record.m_evidenceComponent * 10.0 + 0.5));
  TEST_ASSERT_TRUE(record.m_hasPublicPoc);
  TEST_ASSERT_EQUAL_STRING("HIGH", record.ma_label);

  static_resetFake();
  risk = static_queueRiskscoreAnswer(1);
  risk->ma_cells[0][4] = "f";
  risk->ma_cells[0][5] = "MEDIUM";
  TEST_ASSERT_EQUAL_INT(DB_OK, db_CVERISKSCORE(NULL, "CVE-2021-44228", &record));
  TEST_ASSERT_FALSE(record.m_hasPublicPoc);
  TEST_ASSERT_EQUAL_STRING("MEDIUM", record.ma_label);

  for (size_t extra = 0; extra <= 1; extra++)
  {
    static_resetFake();
    char* text = static_makeText(CVERISKSCORE_LABEL_LEN + extra);
    TEST_ASSERT_NOT_NULL(text);
    risk = static_queueRiskscoreAnswer(1);
    risk->ma_cells[0][5] = text;

    DbStatus_t db_status = db_CVERISKSCORE(NULL, "CVE-2021-44228", &record);

    if (extra == 0)
    {
      TEST_ASSERT_EQUAL_INT(DB_OK, db_status);
      TEST_ASSERT_EQUAL_size_t(CVERISKSCORE_LABEL_LEN, strlen(record.ma_label));
    }
    else
    {
      TEST_ASSERT_EQUAL_INT(DB_ERROR, db_status);
    }
    free(text);
  }
}

void test_CVE_lists_send_the_kev_filter_as_its_value(void)
{
  static const struct { CveKevFilter_t m_kevFilter; const char* mp_value; } cases[] = {
    { CVE_KEV_FILTER_ANY,         NULL },
    { CVE_KEV_FILTER_ONLY_IN_KEV, "true" },
    { CVE_KEV_FILTER_NOT_IN_KEV,  "false" },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    for (int is_leading = 0; is_leading <= 1; is_leading++)
    {
      static_resetFake();
      static_queueListAnswers();
      CveListResult_t results;
      memset(&results, 0, sizeof(results));
      int in_kev_index = 3;
      if (is_leading)
      {
        CVELEADINGParams_t params;
        memset(&params, 0, sizeof(params));
        params.m_minEpss   = -1.0;
        params.m_kevFilter = cases[i].m_kevFilter;
        params.m_limit     = 2;
        TEST_ASSERT_EQUAL_INT(DB_OK, db_CVELEADING(FAKE_CONN, &params, &results));
        in_kev_index = 1;
      }
      else
      {
        CVESEARCHParams_t params;
        memset(&params, 0, sizeof(params));
        params.m_minCvss   = -1.0;
        params.m_minEpss   = -1.0;
        params.m_kevFilter = cases[i].m_kevFilter;
        params.m_limit     = 2;
        TEST_ASSERT_EQUAL_INT(DB_OK, db_CVESEARCH(FAKE_CONN, &params, &results));
      }

      for (int call_index = 0; call_index < 2; call_index++)
      {
        const FakeCall_t* call = static_call(call_index);
        if (cases[i].mp_value == NULL)
          TEST_ASSERT_TRUE(call->ma_isParamNull[in_kev_index]);
        else
        {
          TEST_ASSERT_FALSE(call->ma_isParamNull[in_kev_index]);
          TEST_ASSERT_EQUAL_STRING(cases[i].mp_value, call->ma_params[in_kev_index]);
        }
      }
      db_CveListResultFree(&results);
    }
  }
}

void test_CVE_lists_send_known_ransomware_only_when_it_is_true(void)
{
  for (int is_known_ransomware = 0; is_known_ransomware <= 1; is_known_ransomware++)
  {
    for (int is_leading = 0; is_leading <= 1; is_leading++)
    {
      static_resetFake();
      static_queueListAnswers();
      CveListResult_t results;
      memset(&results, 0, sizeof(results));
      int ransomware_index = 4;
      if (is_leading)
      {
        CVELEADINGParams_t params;
        memset(&params, 0, sizeof(params));
        params.m_minEpss         = -1.0;
        params.m_knownRansomware = is_known_ransomware;
        params.m_limit           = 2;
        TEST_ASSERT_EQUAL_INT(DB_OK, db_CVELEADING(FAKE_CONN, &params, &results));
        ransomware_index = 2;
      }
      else
      {
        CVESEARCHParams_t params;
        memset(&params, 0, sizeof(params));
        params.m_minCvss         = -1.0;
        params.m_minEpss         = -1.0;
        params.m_knownRansomware = is_known_ransomware;
        params.m_limit           = 2;
        TEST_ASSERT_EQUAL_INT(DB_OK, db_CVESEARCH(FAKE_CONN, &params, &results));
      }

      for (int call_index = 0; call_index < 2; call_index++)
      {
        const FakeCall_t* call = static_call(call_index);
        if (is_known_ransomware)
        {
          TEST_ASSERT_FALSE(call->ma_isParamNull[ransomware_index]);
          TEST_ASSERT_EQUAL_STRING("true", call->ma_params[ransomware_index]);
        }
        else
          TEST_ASSERT_TRUE(call->ma_isParamNull[ransomware_index]);
      }
      db_CveListResultFree(&results);
    }
  }
}

void test_CVE_lists_send_has_nuclei_template_only_when_it_is_true(void)
{
  for (int has_nuclei_template = 0; has_nuclei_template <= 1; has_nuclei_template++)
  {
    for (int is_leading = 0; is_leading <= 1; is_leading++)
    {
      static_resetFake();
      static_queueListAnswers();
      CveListResult_t results;
      memset(&results, 0, sizeof(results));
      int template_index   = 10;
      int ransomware_index = 4;
      if (is_leading)
      {
        CVELEADINGParams_t params;
        memset(&params, 0, sizeof(params));
        params.m_minEpss           = -1.0;
        params.m_hasNucleiTemplate = has_nuclei_template;
        params.m_limit             = 2;
        TEST_ASSERT_EQUAL_INT(DB_OK, db_CVELEADING(FAKE_CONN, &params, &results));
        template_index   = 5;
        ransomware_index = 2;
      }
      else
      {
        CVESEARCHParams_t params;
        memset(&params, 0, sizeof(params));
        params.m_minCvss           = -1.0;
        params.m_minEpss           = -1.0;
        params.m_hasNucleiTemplate = has_nuclei_template;
        params.m_limit             = 2;
        TEST_ASSERT_EQUAL_INT(DB_OK, db_CVESEARCH(FAKE_CONN, &params, &results));
      }

      for (int call_index = 0; call_index < 2; call_index++)
      {
        const FakeCall_t* call = static_call(call_index);
        if (has_nuclei_template)
        {
          TEST_ASSERT_FALSE(call->ma_isParamNull[template_index]);
          TEST_ASSERT_EQUAL_STRING("true", call->ma_params[template_index]);
        }
        else
          TEST_ASSERT_TRUE(call->ma_isParamNull[template_index]);
        TEST_ASSERT_TRUE(call->ma_isParamNull[ransomware_index]);
      }
      db_CveListResultFree(&results);
    }
  }
}

void test_CVE_lists_send_include_rejected_as_true_or_false(void)
{
  for (int is_rejected_included = 0; is_rejected_included <= 1; is_rejected_included++)
  {
    for (int list_index = 0; list_index < 3; list_index++)
    {
      static_resetFake();
      CveListResult_t   results;
      CVETRIAGEResult_t triage_results;
      memset(&results, 0, sizeof(results));
      memset(&triage_results, 0, sizeof(triage_results));
      int rejected_index = 11;
      int template_index = 10;
      if (list_index == 0)
      {
        static_queueListAnswers();
        CVESEARCHParams_t params;
        memset(&params, 0, sizeof(params));
        params.m_minCvss            = -1.0;
        params.m_minEpss            = -1.0;
        params.m_isRejectedIncluded = is_rejected_included;
        params.m_limit              = 2;
        TEST_ASSERT_EQUAL_INT(DB_OK, db_CVESEARCH(FAKE_CONN, &params, &results));
      }
      else if (list_index == 1)
      {
        static_queueListAnswers();
        CVELEADINGParams_t params;
        memset(&params, 0, sizeof(params));
        params.m_minEpss            = -1.0;
        params.m_isRejectedIncluded = is_rejected_included;
        params.m_limit              = 2;
        TEST_ASSERT_EQUAL_INT(DB_OK, db_CVELEADING(FAKE_CONN, &params, &results));
        rejected_index = 6;
        template_index = 5;
      }
      else
      {
        static_queueTotalAnswer("2");
        static_fillTriageRows(static_queueAnswer(PGRES_TUPLES_OK, TRIAGE_ROW_COLUMN_COUNT, 2));
        CVETRIAGEParams_t params;
        memset(&params, 0, sizeof(params));
        params.m_minRiskScore       = -1.0;
        params.m_isRejectedIncluded = is_rejected_included;
        params.m_limit              = 2;
        TEST_ASSERT_EQUAL_INT(DB_OK, db_CVETRIAGE(FAKE_CONN, &params, &triage_results));
        rejected_index = 3;
        template_index = -1;
      }

      for (int call_index = 0; call_index < 2; call_index++)
      {
        const FakeCall_t* call = static_call(call_index);
        TEST_ASSERT_FALSE(call->ma_isParamNull[rejected_index]);
        TEST_ASSERT_EQUAL_STRING(is_rejected_included ? "true" : "false", call->ma_params[rejected_index]);
        if (template_index >= 0)
          TEST_ASSERT_TRUE(call->ma_isParamNull[template_index]);
      }
      db_CveListResultFree(&results);
      db_CVETRIAGEResultFree(&triage_results);
    }
  }
}

static void static_setText(char* field, size_t field_size, const char* text)
{
  int written = snprintf(field, field_size, "%s", text);
  TEST_ASSERT_TRUE(written >= 0 && (size_t)written < field_size);
}

static void static_assertCall(int call_index, const char* command, const char* const* values,
                              int value_count)
{
  const FakeCall_t* call = static_call(call_index);
  TEST_ASSERT_EQUAL_STRING(command, call->ma_command);
  TEST_ASSERT_EQUAL_INT(value_count, call->m_paramCount);
  for (int n = 0; n < value_count; n++)
  {
    char message[32] = "";
    snprintf(message, sizeof(message), "call %d, parameter %d", call_index, n + 1);
    if (values[n] == NULL)
      TEST_ASSERT_TRUE_MESSAGE(call->ma_isParamNull[n], message);
    else
    {
      TEST_ASSERT_FALSE_MESSAGE(call->ma_isParamNull[n], message);
      TEST_ASSERT_EQUAL_STRING_MESSAGE(values[n], call->ma_params[n], message);
    }
  }
}

#define CVESEARCH_TOTAL_CALL \
  "SELECT api.fn_cve_search_match_count($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) AS cve_count"
#define CVESEARCH_PAGE_CALL \
  "SELECT * FROM api.fn_cve_search($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)"
#define CVELEADING_TOTAL_CALL \
  "SELECT api.fn_cve_leading_match_count($1, $2, $3, $4, $5, $6, $7) AS cve_count"
#define CVELEADING_PAGE_CALL  "SELECT * FROM api.fn_cve_leading($1, $2, $3, $4, $5, $6, $7, $8)"
#define CVETRIAGE_TOTAL_CALL  "SELECT api.fn_cve_triage_match_count($1, $2, $3, $4) AS cve_count"
#define CVETRIAGE_PAGE_CALL   "SELECT * FROM api.fn_cve_triage($1, $2, $3, $4, $5, $6)"
#define CPESEARCH_TOTAL_CALL  "SELECT api.fn_cpe_search_match_count($1) AS product_count"
#define CPESEARCH_PAGE_CALL   "SELECT * FROM api.fn_cpe_search($1, $2, $3)"

void test_CVE_lists_send_each_filter_in_its_own_parameter(void)
{
  static const char* const search_values[] = {
    "HIGH", "7.50", "0.250000", "true", "true", "CWE-79", "2020-01-01", "2021-01-01", "v", "p",
    "true", "true", "cvss", "2", "40"
  };
  static const char* const leading_values[] = { "0.250000", "false", "true", "v", "p", "true", "true", "2" };
  static const char* const triage_values[]  = { "v", "p", "0.0000", "true", "2", "40" };
  CveListResult_t results;

  static_queueListAnswers();
  CVESEARCHParams_t search_params;
  memset(&search_params, 0, sizeof(search_params));
  static_setText(search_params.ma_severity,        sizeof(search_params.ma_severity),        "HIGH");
  static_setText(search_params.ma_cweId,           sizeof(search_params.ma_cweId),           "CWE-79");
  static_setText(search_params.ma_publishedAfter,  sizeof(search_params.ma_publishedAfter),  "2020-01-01");
  static_setText(search_params.ma_publishedBefore, sizeof(search_params.ma_publishedBefore), "2021-01-01");
  static_setText(search_params.ma_vendor,          sizeof(search_params.ma_vendor),          "v");
  static_setText(search_params.ma_product,         sizeof(search_params.ma_product),         "p");
  static_setText(search_params.ma_sort,            sizeof(search_params.ma_sort),            "cvss");
  search_params.m_minCvss           = 7.5;
  search_params.m_minEpss           = 0.25;
  search_params.m_kevFilter         = CVE_KEV_FILTER_ONLY_IN_KEV;
  search_params.m_knownRansomware   = true;
  search_params.m_hasNucleiTemplate = true;
  search_params.m_isRejectedIncluded = true;
  search_params.m_limit             = 2;
  search_params.m_offset            = 40;
  g_queuedAnswers[0].ma_cells[0][0] = "42";
  memset(&results, 0, sizeof(results));
  TEST_ASSERT_EQUAL_INT(DB_OK, db_CVESEARCH(FAKE_CONN, &search_params, &results));
  static_assertCall(0, CVESEARCH_TOTAL_CALL, search_values, 12);
  static_assertCall(1, CVESEARCH_PAGE_CALL,  search_values, 15);
  db_CveListResultFree(&results);

  static_resetFake();
  static_queueListAnswers();
  CVELEADINGParams_t leading_params;
  memset(&leading_params, 0, sizeof(leading_params));
  static_setText(leading_params.ma_vendor,  sizeof(leading_params.ma_vendor),  "v");
  static_setText(leading_params.ma_product, sizeof(leading_params.ma_product), "p");
  leading_params.m_minEpss           = 0.25;
  leading_params.m_kevFilter         = CVE_KEV_FILTER_NOT_IN_KEV;
  leading_params.m_knownRansomware   = true;
  leading_params.m_hasNucleiTemplate = true;
  leading_params.m_isRejectedIncluded = true;
  leading_params.m_limit             = 2;
  memset(&results, 0, sizeof(results));
  TEST_ASSERT_EQUAL_INT(DB_OK, db_CVELEADING(FAKE_CONN, &leading_params, &results));
  static_assertCall(0, CVELEADING_TOTAL_CALL, leading_values, 7);
  static_assertCall(1, CVELEADING_PAGE_CALL,  leading_values, 8);
  db_CveListResultFree(&results);

  static_resetFake();
  static_queueTotalAnswer("42");
  static_fillTriageRows(static_queueAnswer(PGRES_TUPLES_OK, TRIAGE_ROW_COLUMN_COUNT, 2));
  CVETRIAGEParams_t triage_params;
  memset(&triage_params, 0, sizeof(triage_params));
  static_setText(triage_params.ma_vendor,  sizeof(triage_params.ma_vendor),  "v");
  static_setText(triage_params.ma_product, sizeof(triage_params.ma_product), "p");
  triage_params.m_minRiskScore = 0.0;
  triage_params.m_isRejectedIncluded = true;
  triage_params.m_limit    = 2;
  triage_params.m_offset   = 40;
  CVETRIAGEResult_t triage_results;
  memset(&triage_results, 0, sizeof(triage_results));
  TEST_ASSERT_EQUAL_INT(DB_OK, db_CVETRIAGE(FAKE_CONN, &triage_params, &triage_results));
  static_assertCall(0, CVETRIAGE_TOTAL_CALL, triage_values, 4);
  static_assertCall(1, CVETRIAGE_PAGE_CALL,  triage_values, 6);
  db_CVETRIAGEResultFree(&triage_results);
}

void test_CVE_lists_send_an_unset_filter_as_null(void)
{
  static const char* const search_values[] = {
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, "false", NULL, "2", "0"
  };
  static const char* const leading_values[] = { NULL, NULL, NULL, NULL, NULL, NULL, "false", "2" };
  static const char* const triage_values[]  = { NULL, NULL, NULL, "false", "2", "0" };
  CveListResult_t results;

  static_queueListAnswers();
  CVESEARCHParams_t search_params;
  memset(&search_params, 0, sizeof(search_params));
  search_params.m_minCvss = -1.0;
  search_params.m_minEpss = -1.0;
  search_params.m_limit   = 2;
  memset(&results, 0, sizeof(results));
  TEST_ASSERT_EQUAL_INT(DB_OK, db_CVESEARCH(FAKE_CONN, &search_params, &results));
  static_assertCall(0, CVESEARCH_TOTAL_CALL, search_values, 12);
  static_assertCall(1, CVESEARCH_PAGE_CALL,  search_values, 15);
  db_CveListResultFree(&results);

  static_resetFake();
  static_queueListAnswers();
  CVELEADINGParams_t leading_params;
  memset(&leading_params, 0, sizeof(leading_params));
  leading_params.m_minEpss = -1.0;
  leading_params.m_limit   = 2;
  memset(&results, 0, sizeof(results));
  TEST_ASSERT_EQUAL_INT(DB_OK, db_CVELEADING(FAKE_CONN, &leading_params, &results));
  static_assertCall(0, CVELEADING_TOTAL_CALL, leading_values, 7);
  static_assertCall(1, CVELEADING_PAGE_CALL,  leading_values, 8);
  db_CveListResultFree(&results);

  static_resetFake();
  static_queueTotalAnswer("2");
  static_fillTriageRows(static_queueAnswer(PGRES_TUPLES_OK, TRIAGE_ROW_COLUMN_COUNT, 2));
  CVETRIAGEParams_t triage_params;
  memset(&triage_params, 0, sizeof(triage_params));
  triage_params.m_minRiskScore = -1.0;
  triage_params.m_limit    = 2;
  CVETRIAGEResult_t triage_results;
  memset(&triage_results, 0, sizeof(triage_results));
  TEST_ASSERT_EQUAL_INT(DB_OK, db_CVETRIAGE(FAKE_CONN, &triage_params, &triage_results));
  static_assertCall(0, CVETRIAGE_TOTAL_CALL, triage_values, 4);
  static_assertCall(1, CVETRIAGE_PAGE_CALL,  triage_values, 6);
  db_CVETRIAGEResultFree(&triage_results);
}

void test_CVE_lists_read_the_total_from_the_total_answer(void)
{
  CveListResult_t results;

  static_queueListAnswers();
  g_queuedAnswers[0].ma_cells[0][0] = "7";
  CVESEARCHParams_t search_params;
  memset(&search_params, 0, sizeof(search_params));
  search_params.m_minCvss = -1.0;
  search_params.m_minEpss = -1.0;
  search_params.m_limit   = 2;
  memset(&results, 0, sizeof(results));
  TEST_ASSERT_EQUAL_INT(DB_OK, db_CVESEARCH(FAKE_CONN, &search_params, &results));
  TEST_ASSERT_EQUAL_INT(7, results.m_total);
  TEST_ASSERT_EQUAL_INT(2, results.m_count);
  db_CveListResultFree(&results);

  static_resetFake();
  static_queueListAnswers();
  g_queuedAnswers[0].ma_cells[0][0] = "7";
  CVELEADINGParams_t leading_params;
  memset(&leading_params, 0, sizeof(leading_params));
  leading_params.m_minEpss = -1.0;
  leading_params.m_limit   = 2;
  memset(&results, 0, sizeof(results));
  TEST_ASSERT_EQUAL_INT(DB_OK, db_CVELEADING(FAKE_CONN, &leading_params, &results));
  TEST_ASSERT_EQUAL_INT(7, results.m_total);
  TEST_ASSERT_EQUAL_INT(2, results.m_count);
  db_CveListResultFree(&results);

  static_resetFake();
  static_queueTotalAnswer("7");
  static_fillTriageRows(static_queueAnswer(PGRES_TUPLES_OK, TRIAGE_ROW_COLUMN_COUNT, 2));
  CVETRIAGEParams_t triage_params;
  memset(&triage_params, 0, sizeof(triage_params));
  triage_params.m_minRiskScore = -1.0;
  triage_params.m_limit    = 2;
  CVETRIAGEResult_t triage_results;
  memset(&triage_results, 0, sizeof(triage_results));
  TEST_ASSERT_EQUAL_INT(DB_OK, db_CVETRIAGE(FAKE_CONN, &triage_params, &triage_results));
  TEST_ASSERT_EQUAL_INT(7, triage_results.m_total);
  TEST_ASSERT_EQUAL_INT(2, triage_results.m_count);
  db_CVETRIAGEResultFree(&triage_results);
}

void test_CVE_lists_empty_page_is_ok(void)
{
  static_queueTotalAnswer("1");
  FakeAnswer_t* page = static_queueAnswer(PGRES_TUPLES_OK, LIST_ROW_COLUMN_COUNT, 0);
  for (int col = 0; col < LIST_ROW_COLUMN_COUNT; col++)
    page->ma_columnNames[col] = g_listColumnNames[col];
  CVESEARCHParams_t search_params;
  memset(&search_params, 0, sizeof(search_params));
  search_params.m_minCvss = -1.0;
  search_params.m_minEpss = -1.0;
  search_params.m_limit   = 2;
  CveListResult_t results;
  memset(&results, 0xA5, sizeof(results));
  TEST_ASSERT_EQUAL_INT(DB_OK, db_CVESEARCH(FAKE_CONN, &search_params, &results));
  TEST_ASSERT_EQUAL_INT(2, g_callCount);
  TEST_ASSERT_EQUAL_INT(1, results.m_total);
  TEST_ASSERT_EQUAL_INT(0, results.m_count);
  TEST_ASSERT_NULL(results.mp_items);

  static_resetFake();
  static_queueTotalAnswer("1");
  FakeAnswer_t* triage_page = static_queueAnswer(PGRES_TUPLES_OK, TRIAGE_ROW_COLUMN_COUNT, 0);
  for (int col = 0; col < TRIAGE_ROW_COLUMN_COUNT; col++)
    triage_page->ma_columnNames[col] = g_triageColumnNames[col];
  CVETRIAGEParams_t triage_params;
  memset(&triage_params, 0, sizeof(triage_params));
  triage_params.m_minRiskScore = -1.0;
  triage_params.m_limit    = 2;
  CVETRIAGEResult_t triage_results;
  memset(&triage_results, 0xA5, sizeof(triage_results));
  TEST_ASSERT_EQUAL_INT(DB_OK, db_CVETRIAGE(FAKE_CONN, &triage_params, &triage_results));
  TEST_ASSERT_EQUAL_INT(2, g_callCount);
  TEST_ASSERT_EQUAL_INT(1, triage_results.m_total);
  TEST_ASSERT_EQUAL_INT(0, triage_results.m_count);
  TEST_ASSERT_NULL(triage_results.mp_items);
}

typedef enum {
  LIST_CALL_CVESEARCH,
  LIST_CALL_CVETRIAGE,
  LIST_CALL_CPESEARCH
} ListCall_t;

static const char* const g_listCallNames[] = { "db_CVESEARCH", "db_CVETRIAGE", "db_CPESEARCH" };

static DbStatus_t static_runListAtOffset(ListCall_t call, const char* total, int offset, int* total_out, int* count_out, bool* is_items_null)
{
  static_resetFake();
  DbStatus_t db_status = DB_ERROR;
  switch (call)
  {
    case LIST_CALL_CVESEARCH:
    {
      static_queueListAnswers();
      g_queuedAnswers[0].ma_cells[0][0] = total;
      CVESEARCHParams_t params;
      memset(&params, 0, sizeof(params));
      params.m_minCvss = -1.0;
      params.m_minEpss = -1.0;
      params.m_limit   = 2;
      params.m_offset  = offset;
      CveListResult_t results;
      memset(&results, 0xA5, sizeof(results));
      db_status = db_CVESEARCH(FAKE_CONN, &params, &results);
      *total_out     = results.m_total;
      *count_out     = results.m_count;
      *is_items_null = results.mp_items == NULL;
      db_CveListResultFree(&results);
      break;
    }
    case LIST_CALL_CVETRIAGE:
    {
      static_queueTotalAnswer(total);
      static_fillTriageRows(static_queueAnswer(PGRES_TUPLES_OK, TRIAGE_ROW_COLUMN_COUNT, 2));
      CVETRIAGEParams_t params;
      memset(&params, 0, sizeof(params));
      params.m_minRiskScore = -1.0;
      params.m_limit        = 2;
      params.m_offset       = offset;
      CVETRIAGEResult_t results;
      memset(&results, 0xA5, sizeof(results));
      db_status = db_CVETRIAGE(FAKE_CONN, &params, &results);
      *total_out     = results.m_total;
      *count_out     = results.m_count;
      *is_items_null = results.mp_items == NULL;
      db_CVETRIAGEResultFree(&results);
      break;
    }
    case LIST_CALL_CPESEARCH:
    {
      static_queueCpeSearchAnswers();
      g_queuedAnswers[0].ma_cells[0][0] = total;
      CPESEARCHParams_t params;
      memset(&params, 0, sizeof(params));
      static_setText(params.ma_search, sizeof(params.ma_search), "windows");
      params.m_limit  = 2;
      params.m_offset = offset;
      CPESEARCHResult_t results;
      memset(&results, 0xA5, sizeof(results));
      db_status = db_CPESEARCH(FAKE_CONN, &params, &results);
      *total_out     = results.m_total;
      *count_out     = results.m_count;
      *is_items_null = results.mp_items == NULL;
      db_CPESEARCHResultFree(&results);
      break;
    }
  }
  return db_status;
}

void test_lists_send_no_page_call_at_or_past_the_total(void)
{
  static const struct {
    const char* mp_total;
    int         m_totalCount;
    int         m_offset;
    int         m_callCount;
    int         m_itemCount;
  } cases[] = {
    { "5", 5, 5, 1, 0 },
    { "5", 5, 6, 1, 0 },
    { "0", 0, 0, 1, 0 },
    { "5", 5, 4, 2, 2 },
  };

  for (int call = LIST_CALL_CVESEARCH; call <= LIST_CALL_CPESEARCH; call++)
  {
    for (size_t k = 0; k < sizeof(cases) / sizeof(cases[0]); k++)
    {
      char message[64];
      snprintf(message, sizeof(message), "%s total %s offset %d", g_listCallNames[call], cases[k].mp_total, cases[k].m_offset);
      int  total         = -1;
      int  count         = -1;
      bool is_items_null = false;

      DbStatus_t db_status = static_runListAtOffset((ListCall_t)call, cases[k].mp_total, cases[k].m_offset, &total, &count, &is_items_null);

      TEST_ASSERT_EQUAL_INT_MESSAGE(DB_OK, db_status, message);
      TEST_ASSERT_EQUAL_INT_MESSAGE(cases[k].m_callCount, g_callCount, message);
      TEST_ASSERT_EQUAL_INT_MESSAGE(cases[k].m_totalCount, total, message);
      TEST_ASSERT_EQUAL_INT_MESSAGE(cases[k].m_itemCount, count, message);
      TEST_ASSERT_EQUAL_MESSAGE(cases[k].m_itemCount == 0, is_items_null, message);
    }
  }
}

void test_CVE_lists_total_that_is_not_one_row_is_error(void)
{
  for (int row_count = 0; row_count <= 2; row_count += 2)
  {
    char message[32] = "";
    snprintf(message, sizeof(message), "%d rows", row_count);

    static_resetFake();
    FakeAnswer_t* total = static_queueAnswer(PGRES_TUPLES_OK, 1, row_count);
    total->ma_columnNames[0] = "cve_count";
    for (int row = 0; row < row_count; row++)
      total->ma_cells[row][0] = "2";
    static_queueListAnswers();
    CVESEARCHParams_t search_params;
    memset(&search_params, 0, sizeof(search_params));
    search_params.m_limit = 2;
    CveListResult_t search_results;
    memset(&search_results, 0xA5, sizeof(search_results));
    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_ERROR, db_CVESEARCH(FAKE_CONN, &search_params, &search_results), message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_callCount, message);
    TEST_ASSERT_NULL_MESSAGE(search_results.mp_items, message);

    static_resetFake();
    total = static_queueAnswer(PGRES_TUPLES_OK, 1, row_count);
    total->ma_columnNames[0] = "cve_count";
    for (int row = 0; row < row_count; row++)
      total->ma_cells[row][0] = "2";
    static_fillTriageRows(static_queueAnswer(PGRES_TUPLES_OK, TRIAGE_ROW_COLUMN_COUNT, 2));
    CVETRIAGEParams_t triage_params;
    memset(&triage_params, 0, sizeof(triage_params));
    triage_params.m_limit = 2;
    CVETRIAGEResult_t triage_results;
    memset(&triage_results, 0xA5, sizeof(triage_results));
    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_ERROR, db_CVETRIAGE(FAKE_CONN, &triage_params, &triage_results), message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_callCount, message);
    TEST_ASSERT_NULL_MESSAGE(triage_results.mp_items, message);
  }
}

void test_failed_query_writes_one_line_naming_its_caller(void)
{
  static const struct {
    bool           m_isAnswered;
    ExecStatusType m_status;
    const char*    mp_sqlstate;
    ConnStatusType m_connectionStatus;
    const char*    mp_line;
  } rows[] = {
    { true,  PGRES_FATAL_ERROR, "42P01", CONNECTION_OK,
      "dbhelper_executeQueryFrom: db_HEALTH: query failed (status PGRES_FATAL_ERROR, sqlstate 42P01, connection ok)\n" },
    { true,  PGRES_COMMAND_OK,  NULL,    CONNECTION_OK,
      "dbhelper_executeQueryFrom: db_HEALTH: query failed (status PGRES_COMMAND_OK, sqlstate none, connection ok)\n" },
    { false, PGRES_FATAL_ERROR, "57P01", CONNECTION_BAD,
      "dbhelper_executeQueryFrom: db_HEALTH: query failed (status no result, sqlstate none, connection bad)\n" },
  };

  for (size_t row = 0; row < sizeof(rows) / sizeof(rows[0]); row++)
  {
    static_resetFake();
    static_clearLogLimit();
    static_queueHealthRow(1);
    if (rows[row].m_isAnswered)
      static_queueAnswer(rows[row].m_status, 0, 0);
    g_fakeSqlstate         = rows[row].mp_sqlstate;
    g_fakeConnectionStatus = rows[row].m_connectionStatus;
    HEALTHData_t data;
    StderrCapture_t capture;
    char message[16] = "";
    snprintf(message, sizeof(message), "row %zu", row);
    static_beginStderrCapture(&capture);

    DbStatus_t db_status = db_HEALTH(NULL, &data);

    char text[512];
    static_endStderrCapture(&capture, text, sizeof(text));
    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_ERROR, db_status, message);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(rows[row].mp_line, text, message);
  }
}

void test_succeeded_queries_write_no_line(void)
{
  static_queueHealthAnswers();
  HEALTHData_t data;
  StderrCapture_t capture;
  static_beginStderrCapture(&capture);

  DbStatus_t db_status = db_HEALTH(NULL, &data);

  char text[512];
  static_endStderrCapture(&capture, text, sizeof(text));
  TEST_ASSERT_EQUAL_INT(DB_OK, db_status);
  TEST_ASSERT_EQUAL_STRING("", text);
}

void test_failed_list_call_names_the_function_that_sent_it(void)
{
  static const struct {
    bool        m_isTotalAnswered;
    bool        m_isTriage;
    const char* mp_sender;
  } rows[] = {
    { false, false, "static_tryReadMatchCount" },
    { true,  false, "static_CVESEARCHReadPage" },
    { true,  true,  "static_CVETRIAGEReadPage" },
  };

  for (size_t row = 0; row < sizeof(rows) / sizeof(rows[0]); row++)
  {
    static_resetFake();
    static_clearLogLimit();
    if (rows[row].m_isTotalAnswered)
      static_queueTotalAnswer("2");
    static_queueAnswer(PGRES_FATAL_ERROR, 0, 0);
    StderrCapture_t capture;
    char text[512];
    static_beginStderrCapture(&capture);

    DbStatus_t db_status = DB_OK;
    if (rows[row].m_isTriage)
    {
      CVETRIAGEParams_t triage_params;
      memset(&triage_params, 0, sizeof(triage_params));
      triage_params.m_limit = 2;
      CVETRIAGEResult_t triage_results;
      memset(&triage_results, 0, sizeof(triage_results));
      db_status = db_CVETRIAGE(FAKE_CONN, &triage_params, &triage_results);
    }
    else
    {
      CVESEARCHParams_t search_params;
      memset(&search_params, 0, sizeof(search_params));
      search_params.m_limit = 2;
      CveListResult_t search_results;
      memset(&search_results, 0, sizeof(search_results));
      db_status = db_CVESEARCH(FAKE_CONN, &search_params, &search_results);
    }

    static_endStderrCapture(&capture, text, sizeof(text));
    char expected[256];
    snprintf(expected, sizeof(expected), "dbhelper_executeQueryFrom: %s: query failed "
             "(status PGRES_FATAL_ERROR, sqlstate none, connection bad)\n", rows[row].mp_sender);
    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_ERROR, db_status, rows[row].mp_sender);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(expected, text, rows[row].mp_sender);
  }
}

void test_failed_purge_call_names_the_purge_function(void)
{
  static const struct {
    bool        (*m_purge)(PGconn* conn);
    const char* mp_sender;
  } rows[] = {
    { db_purgeExpiredCveChangeEvents,       "db_purgeExpiredCveChangeEvents" },
    { db_purgeExpiredWatchlists,            "db_purgeExpiredWatchlists" },
    { db_purgeExpiredDomainChangeEvents,    "db_purgeExpiredDomainChangeEvents" },
    { db_purgeUnwatchedDomains,             "db_purgeUnwatchedDomains" },
    { db_purgeExpiredPackageAdvisoryChangeEvents, "db_purgeExpiredPackageAdvisoryChangeEvents" },
  };

  for (size_t row = 0; row < sizeof(rows) / sizeof(rows[0]); row++)
  {
    static_resetFake();
    static_clearLogLimit();
    static_queueAnswer(PGRES_FATAL_ERROR, 0, 0);
    StderrCapture_t capture;
    char text[512];
    static_beginStderrCapture(&capture);

    bool is_purged = rows[row].m_purge(FAKE_CONN);

    static_endStderrCapture(&capture, text, sizeof(text));
    char expected[256];
    snprintf(expected, sizeof(expected), "dbhelper_executeQueryFrom: %s: query failed "
             "(status PGRES_FATAL_ERROR, sqlstate none, connection bad)\n", rows[row].mp_sender);
    TEST_ASSERT_FALSE_MESSAGE(is_purged, rows[row].mp_sender);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(expected, text, rows[row].mp_sender);
  }
}

void test_lines_past_the_first_in_a_second_are_counted_not_written(void)
{
  PGresult* result = static_buildOneCellResult("abcde");
  TEST_ASSERT_NOT_NULL(result);
  char dest[8];
  bool is_copied[4];
  StderrCapture_t capture;
  static_beginStderrCapture(&capture);

  is_copied[0] = dbhelper_fetchColStr(result, 0, 0, dest, 4);
  is_copied[1] = dbhelper_fetchColStr(result, 0, 0, dest, 3);
  is_copied[2] = dbhelper_fetchColStr(result, 0, 0, dest, 2);
  g_fakeNow++;
  is_copied[3] = dbhelper_fetchColStr(result, 0, 0, dest, 1);

  char text[512];
  static_endStderrCapture(&capture, text, sizeof(text));
  PQclear(result);
  for (int call = 0; call < 4; call++)
    TEST_ASSERT_FALSE(is_copied[call]);
  TEST_ASSERT_EQUAL_STRING("dbhelper_fetchColStr: column column (index 0) holds 5 bytes, limit 4\n"
                           "static_logLine: 2 lines suppressed since the last one\n"
                           "dbhelper_fetchColStr: column column (index 0) holds 5 bytes, limit 1\n",
                           text);
}

typedef enum {
  LOG_SOURCE_QUERY,
  LOG_SOURCE_STR,
  LOG_SOURCE_WITHIN_LENGTH,
  LOG_SOURCE_DOUBLE_TEXT,
  LOG_SOURCE_DOUBLE_NONFINITE,
  LOG_SOURCE_INT,
  LOG_SOURCE_INT64,
  LOG_SOURCE_BOOL
} LogSource_t;

static void static_writeLogLine(LogSource_t source)
{
  if (source == LOG_SOURCE_QUERY)
  {
    static_resetFake();
    static_queueAnswer(PGRES_FATAL_ERROR, 0, 0);
    PGresult* query_result = dbhelper_executeQuery(NULL, "SELECT 1", 0, NULL);
    TEST_ASSERT_NULL(query_result);
    return;
  }

  const char* value = (source == LOG_SOURCE_STR || source == LOG_SOURCE_WITHIN_LENGTH) ? "abcde"
                    : (source == LOG_SOURCE_DOUBLE_NONFINITE)                          ? "NaN"
                    : "12abc";
  PGresult* result = static_buildOneCellResult(value);
  TEST_ASSERT_NOT_NULL(result);
  char   dest[8];
  double double_value = 0.0;
  int    int_value    = 0;
  int64_t int64_value = 0;
  bool   bool_value   = false;
  bool   is_as_chosen = false;

  switch (source)
  {
    case LOG_SOURCE_STR:              is_as_chosen = !dbhelper_fetchColStr(result, 0, 0, dest, 4);                break;
    case LOG_SOURCE_WITHIN_LENGTH:    is_as_chosen = !dbhelper_isColWithinLength(result, 0, 0, 4);                break;
    case LOG_SOURCE_DOUBLE_TEXT:      is_as_chosen = !dbhelper_fetchColDouble(result, 0, 0, 0.0, &double_value);  break;
    case LOG_SOURCE_DOUBLE_NONFINITE: is_as_chosen = dbhelper_fetchColDouble(result, 0, 0, 0.0, &double_value);   break;
    case LOG_SOURCE_INT:              is_as_chosen = !dbhelper_fetchColInt(result, 0, 0, 0, &int_value);          break;
    case LOG_SOURCE_INT64:            is_as_chosen = !dbhelper_fetchColInt64(result, 0, 0, 0, &int64_value);      break;
    case LOG_SOURCE_BOOL:             is_as_chosen = !dbhelper_fetchColBool(result, 0, 0, &bool_value);           break;
    case LOG_SOURCE_QUERY:                                                                                    break;
  }
  PQclear(result);
  TEST_ASSERT_TRUE(is_as_chosen);
}

void test_each_source_writes_one_line_and_its_repeat_is_dropped(void)
{
  static const struct {
    LogSource_t m_source;
    const char* mp_line;
  } rows[] = {
    { LOG_SOURCE_QUERY,
      "dbhelper_executeQueryFrom: static_writeLogLine: query failed (status PGRES_FATAL_ERROR, sqlstate none, connection bad)\n" },
    { LOG_SOURCE_STR,
      "dbhelper_fetchColStr: column column (index 0) holds 5 bytes, limit 4\n" },
    { LOG_SOURCE_WITHIN_LENGTH,
      "dbhelper_isColWithinLength: column column (index 0) holds 5 bytes, limit 4\n" },
    { LOG_SOURCE_DOUBLE_TEXT,
      "dbhelper_fetchColDouble: column column (index 0) holds no number\n" },
    { LOG_SOURCE_DOUBLE_NONFINITE,
      "dbhelper_fetchColDouble: column column (index 0) holds no finite number, read as the fallback\n" },
    { LOG_SOURCE_INT,
      "dbhelper_fetchColInt: column column (index 0) holds no int\n" },
    { LOG_SOURCE_INT64,
      "dbhelper_fetchColInt64: column column (index 0) holds no int64\n" },
    { LOG_SOURCE_BOOL,
      "dbhelper_fetchColBool: column column (index 0) holds no boolean\n" },
  };

  for (size_t row = 0; row < sizeof(rows) / sizeof(rows[0]); row++)
  {
    static_clearLogLimit();
    StderrCapture_t capture;
    char message[16] = "";
    snprintf(message, sizeof(message), "row %zu", row);
    static_beginStderrCapture(&capture);

    static_writeLogLine(rows[row].m_source);
    static_writeLogLine(rows[row].m_source);

    char text[512];
    static_endStderrCapture(&capture, text, sizeof(text));
    TEST_ASSERT_EQUAL_STRING_MESSAGE(rows[row].mp_line, text, message);
  }
}

void test_fetchColDouble_reads_a_finite_number_and_nothing_else(void)
{
  static const struct {
    const char* mp_text;
    bool        m_isRead;
    double      m_value;
  } rows[] = {
    { "9.8",       true,  9.8 },
    { "-0.5",      true,  -0.5 },
    { "NaN",       true,  7.5 },
    { "Infinity",  true,  7.5 },
    { "-Infinity", true,  7.5 },
    { "",          true,  7.5 },
    { FAKE_SQL_NULL, true, 7.5 },
    { "12abc",     false, 7.5 },
    { "x",         false, 7.5 },
    { "1e400",     false, 7.5 },
  };

  for (size_t row = 0; row < sizeof(rows) / sizeof(rows[0]); row++)
  {
    PGresult* result = static_buildOneCellResult(rows[row].mp_text);
    TEST_ASSERT_NOT_NULL(result);
    double value = -1.0;
    char message[16] = "";
    snprintf(message, sizeof(message), "row %zu", row);

    bool is_read = dbhelper_fetchColDouble(result, 0, 0, 7.5, &value);

    PQclear(result);
    TEST_ASSERT_EQUAL_MESSAGE(rows[row].m_isRead, is_read, message);
    TEST_ASSERT_TRUE_MESSAGE(value == rows[row].m_value, message);
  }
}

void test_fetchColInt_reads_an_int_and_nothing_else(void)
{
  static const struct {
    const char* mp_text;
    bool        m_isRead;
    int         m_value;
  } rows[] = {
    { "42",           true,  42 },
    { "-3",           true,  -3 },
    { "2147483647",   true,  INT_MAX },
    { "-2147483648",  true,  INT_MIN },
    { "",             true,  7 },
    { FAKE_SQL_NULL,  true,  7 },
    { "12abc",        false, 7 },
    { "4.5",          false, 7 },
    { "2147483648",   false, 7 },
    { "-2147483649",  false, 7 },
  };

  for (size_t row = 0; row < sizeof(rows) / sizeof(rows[0]); row++)
  {
    PGresult* result = static_buildOneCellResult(rows[row].mp_text);
    TEST_ASSERT_NOT_NULL(result);
    int value = -1;
    char message[16] = "";
    snprintf(message, sizeof(message), "row %zu", row);

    bool is_read = dbhelper_fetchColInt(result, 0, 0, 7, &value);

    PQclear(result);
    TEST_ASSERT_EQUAL_MESSAGE(rows[row].m_isRead, is_read, message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(rows[row].m_value, value, message);
  }
}

void test_fetchColInt64_reads_an_int64_and_nothing_else(void)
{
  static const struct {
    const char* mp_text;
    bool        m_isRead;
    int64_t     m_value;
  } rows[] = {
    { "42",                    true,  42 },
    { "-3",                    true,  -3 },
    { "4102444800",            true,  4102444800 },
    { "9223372036854775807",   true,  INT64_MAX },
    { "-9223372036854775808",  true,  INT64_MIN },
    { "",                      true,  7 },
    { FAKE_SQL_NULL,           true,  7 },
    { "12abc",                 false, 7 },
    { "4.5",                   false, 7 },
    { "9223372036854775808",   false, 7 },
    { "-9223372036854775809",  false, 7 },
  };

  for (size_t row = 0; row < sizeof(rows) / sizeof(rows[0]); row++)
  {
    PGresult* result = static_buildOneCellResult(rows[row].mp_text);
    TEST_ASSERT_NOT_NULL(result);
    int64_t value = -1;
    char message[16] = "";
    snprintf(message, sizeof(message), "row %zu", row);

    errno = ERANGE;
    bool is_read = dbhelper_fetchColInt64(result, 0, 0, 7, &value);

    PQclear(result);
    TEST_ASSERT_EQUAL_MESSAGE(rows[row].m_isRead, is_read, message);
    TEST_ASSERT_EQUAL_INT64_MESSAGE(rows[row].m_value, value, message);
  }
}

void test_fetchColBool_reads_t_and_f_and_nothing_else(void)
{
  static const struct {
    const char* mp_text;
    bool        m_isRead;
    bool        m_value;
  } rows[] = {
    { "t",           true,  true  },
    { "f",           true,  false },
    { FAKE_SQL_NULL, false, false },
    { "",            false, false },
    { "true",        false, false },
    { "12abc",       false, false },
  };

  for (size_t row = 0; row < sizeof(rows) / sizeof(rows[0]); row++)
  {
    PGresult* result = static_buildOneCellResult(rows[row].mp_text);
    TEST_ASSERT_NOT_NULL(result);
    bool value = true;
    char message[16] = "";
    snprintf(message, sizeof(message), "row %zu", row);

    bool is_read = dbhelper_fetchColBool(result, 0, 0, &value);

    PQclear(result);
    TEST_ASSERT_EQUAL_MESSAGE(rows[row].m_isRead, is_read, message);
    TEST_ASSERT_EQUAL_MESSAGE(rows[row].m_value, value, message);
  }
}

typedef enum {
  COLUMN_READER_STR,
  COLUMN_READER_DOUBLE,
  COLUMN_READER_INT,
  COLUMN_READER_INT64,
  COLUMN_READER_BOOL,
  COLUMN_READER_WITHIN_LENGTH,
  COLUMN_READER_STRDUP
} ColumnReader_t;

static bool static_readColumn(ColumnReader_t reader, PGresult* result, int col, bool* is_output_reset_out)
{
  char   dest[8]      = "x";
  double double_value = -1.0;
  int    int_value    = -1;
  int64_t int64_value = -1;
  bool   bool_value   = true;
  char*  copy         = dest;
  bool   is_accepted  = false;

  switch (reader)
  {
    case COLUMN_READER_STR:
      is_accepted          = dbhelper_fetchColStr(result, 0, col, dest, 4);
      *is_output_reset_out = (dest[0] == '\0');
      break;
    case COLUMN_READER_DOUBLE:
      is_accepted          = dbhelper_fetchColDouble(result, 0, col, 7.5, &double_value);
      *is_output_reset_out = (double_value == 7.5);
      break;
    case COLUMN_READER_INT:
      is_accepted          = dbhelper_fetchColInt(result, 0, col, 7, &int_value);
      *is_output_reset_out = (int_value == 7);
      break;
    case COLUMN_READER_INT64:
      is_accepted          = dbhelper_fetchColInt64(result, 0, col, 7, &int64_value);
      *is_output_reset_out = (int64_value == 7);
      break;
    case COLUMN_READER_BOOL:
      is_accepted          = dbhelper_fetchColBool(result, 0, col, &bool_value);
      *is_output_reset_out = !bool_value;
      break;
    case COLUMN_READER_WITHIN_LENGTH:
      is_accepted          = dbhelper_isColWithinLength(result, 0, col, 4);
      *is_output_reset_out = true;
      break;
    case COLUMN_READER_STRDUP:
      is_accepted          = dbhelper_fetchColStrdup(result, 0, col, &copy);
      *is_output_reset_out = (copy == NULL);
      break;
  }
  if (copy != dest)
    free(copy);
  return is_accepted;
}

void test_readers_refuse_a_column_outside_the_result(void)
{
  static const struct {
    ColumnReader_t m_reader;
    int            m_col;
    const char*    mp_line;
  } rows[] = {
    { COLUMN_READER_DOUBLE,        -1, "dbhelper_fetchColDouble: no column at index -1 (column count 1)\n" },
    { COLUMN_READER_DOUBLE,         1, "dbhelper_fetchColDouble: no column at index 1 (column count 1)\n" },
    { COLUMN_READER_INT,            1, "dbhelper_fetchColInt: no column at index 1 (column count 1)\n" },
    { COLUMN_READER_INT64,          1, "dbhelper_fetchColInt64: no column at index 1 (column count 1)\n" },
    { COLUMN_READER_BOOL,           1, "dbhelper_fetchColBool: no column at index 1 (column count 1)\n" },
    { COLUMN_READER_WITHIN_LENGTH,  1, "dbhelper_isColWithinLength: no column at index 1 (column count 1)\n" },
    { COLUMN_READER_STRDUP,         1, "dbhelper_fetchColStrdup: no column at index 1 (column count 1)\n" },
    { COLUMN_READER_STR,            1, "dbhelper_fetchColStr: no column at index 1 (column count 1)\n" },
  };

  for (size_t row = 0; row < sizeof(rows) / sizeof(rows[0]); row++)
  {
    PGresult* result = static_buildOneCellResult("1");
    TEST_ASSERT_NOT_NULL(result);
    char message[16] = "";
    snprintf(message, sizeof(message), "row %zu", row);
    static_clearLogLimit();
    StderrCapture_t capture;
    static_beginStderrCapture(&capture);

    bool is_output_reset = false;
    bool is_accepted     = static_readColumn(rows[row].m_reader, result, rows[row].m_col, &is_output_reset);

    char line[256];
    static_endStderrCapture(&capture, line, sizeof(line));
    PQclear(result);
    TEST_ASSERT_FALSE_MESSAGE(is_accepted, message);
    TEST_ASSERT_TRUE_MESSAGE(is_output_reset, message);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(rows[row].mp_line, line, message);
  }
}

void test_column_list_needs_every_name_in_order(void)
{
  static const char* const expected_names[] = { "a", "b" };
  static const struct {
    int         m_columnCount;
    const char* ma_names[3];
    bool        m_isEqual;
    const char* mp_line;
  } rows[] = {
    { 2, { "a", "b" },      true,  "" },
    { 2, { "b", "a" },      false, "dbhelper_isColumnListEqual: column 0 is b, expected a\n" },
    { 2, { "a", "c" },      false, "dbhelper_isColumnListEqual: column 1 is c, expected b\n" },
    { 1, { "a" },           false, "dbhelper_isColumnListEqual: column count 1, expected 2\n" },
    { 3, { "a", "b", "c" }, false, "dbhelper_isColumnListEqual: column count 3, expected 2\n" },
  };

  for (size_t row = 0; row < sizeof(rows) / sizeof(rows[0]); row++)
  {
    FakeAnswer_t answer;
    memset(&answer, 0, sizeof(answer));
    answer.m_status      = PGRES_TUPLES_OK;
    answer.m_columnCount = rows[row].m_columnCount;
    answer.m_rowCount    = 1;
    for (int col = 0; col < rows[row].m_columnCount; col++)
    {
      answer.ma_columnNames[col] = rows[row].ma_names[col];
      answer.ma_cells[0][col]    = "x";
    }
    PGresult* result = static_buildResult(&answer);
    TEST_ASSERT_NOT_NULL(result);
    char message[16] = "";
    snprintf(message, sizeof(message), "row %zu", row);
    static_clearLogLimit();
    StderrCapture_t capture;
    static_beginStderrCapture(&capture);

    bool is_equal = dbhelper_isColumnListEqual(result, expected_names, 2);

    char line[256];
    static_endStderrCapture(&capture, line, sizeof(line));
    PQclear(result);
    TEST_ASSERT_EQUAL_MESSAGE(rows[row].m_isEqual, is_equal, message);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(rows[row].mp_line, line, message);
  }
}

void test_CWELOOKUP_reads_its_counts_and_a_nonfinite_average_as_zero(void)
{
  static const struct {
    const char* ma_cells[CWELOOKUP_ROW_NUMBER_COLUMN_COUNT];
    int         m_kevCount;
    double      m_avgCvss;
    double      m_avgEpss;
    int         m_cveCount;
  } rows[] = {
    { { "2", "7.25", "0.1234",   "3" }, 2, 7.25, 0.1234, 3 },
    { { "4", "NaN",  "Infinity", "5" }, 4, 0.0,  0.0,    5 },
  };

  for (size_t row = 0; row < sizeof(rows) / sizeof(rows[0]); row++)
  {
    static_resetFake();
    FakeAnswer_t* answer = static_queueCwelookupRow();
    for (int col = 0; col < CWELOOKUP_ROW_NUMBER_COLUMN_COUNT; col++)
      answer->ma_cells[0][CWELOOKUP_ROW_FIRST_NUMBER_COLUMN_INDEX + col] = rows[row].ma_cells[col];
    CWELOOKUPRecord_t record;
    char message[16] = "";
    snprintf(message, sizeof(message), "row %zu", row);

    DbStatus_t db_status = db_CWELOOKUP(NULL, "CWE-79", &record);

    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_OK, db_status, message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(rows[row].m_kevCount, record.m_kevCount, message);
    TEST_ASSERT_EQUAL_STRING_MESSAGE("SELECT * FROM api.fn_cwe_lookup($1)", static_lastCall()->ma_command, message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, static_lastCall()->m_paramCount, message);
    TEST_ASSERT_EQUAL_STRING_MESSAGE("CWE-79", static_lastCall()->ma_params[0], message);
    TEST_ASSERT_EQUAL_STRING_MESSAGE("Base", record.ma_abstraction, message);
    TEST_ASSERT_EQUAL_STRING_MESSAGE("Stable", record.ma_status, message);
    TEST_ASSERT_TRUE_MESSAGE(record.m_avgCvss == rows[row].m_avgCvss, message);
    TEST_ASSERT_TRUE_MESSAGE(record.m_avgEpss == rows[row].m_avgEpss, message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(rows[row].m_cveCount, record.m_cveCount, message);
    db_CWELOOKUPRecordFree(&record);
  }
}

void test_CWELOOKUP_failed_query_or_unreadable_count_is_error(void)
{
  for (int fault = 0; fault < 2; fault++)
  {
    static_resetFake();
    FakeAnswer_t* answer = static_queueCwelookupRow();
    if (fault == 0)
      answer->m_status = PGRES_FATAL_ERROR;
    else
      answer->ma_cells[0][CWELOOKUP_ROW_FIRST_NUMBER_COLUMN_INDEX] = "12abc";
    CWELOOKUPRecord_t record;
    memset(&record, 0xA5, sizeof(record));
    char message[16] = "";
    snprintf(message, sizeof(message), "fault %d", fault);

    DbStatus_t db_status = db_CWELOOKUP(NULL, "CWE-79", &record);

    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_ERROR, db_status, message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_callCount, message);
    TEST_ASSERT_NULL_MESSAGE(record.mp_mitigations, message);
    TEST_ASSERT_NULL_MESSAGE(record.mp_extendedDescription, message);
    TEST_ASSERT_NULL_MESSAGE(record.mp_examples, message);
  }
}

typedef enum {
  DB_CALL_HEALTH,
  DB_CALL_CVELOOKUP,
  DB_CALL_CVESEARCH,
  DB_CALL_CVETRIAGE,
  DB_CALL_KEVLOOKUP,
  DB_CALL_CWELOOKUP,
  DB_CALL_CVERISKSCORE,
  DB_CALL_PRODUCTEXPOSURE,
  DB_CALL_CVETRIAGEBULK,
  DB_CALL_CVELOOKUPBULK,
  DB_CALL_CPESEARCH,
  DB_CALL_D3FENDFORATTACK,
  DB_CALL_DRIVERLOOKUP,
  DB_CALL_IPLOOKUP,
  DB_CALL_ASNLOOKUP,
  DB_CALL_EMAILADDRESSCHECK,
  DB_CALL_SSLCHECK,
  DB_CALL_PACKAGECHECK,
  DB_CALL_CVEPRODUCTS,
  DB_CALL_CVELOOKUPGHSA,
  DB_CALL_PACKAGECHECKBULK
} DbCall_t;

static DbStatus_t static_runDbCall(DbCall_t call, int answer, int row, int column, const char* value,
                                   const char* column_name)
{
  DbStatus_t db_status = DB_ERROR;

  static_resetFake();
  switch (call)
  {
    case DB_CALL_HEALTH:
      static_queueHealthAnswers();
      break;
    case DB_CALL_CVELOOKUP:
      static_fillCvelookupRow(static_queueAnswer(PGRES_TUPLES_OK, CVELOOKUP_ROW_COLUMN_COUNT, 1), 0);
      break;
    case DB_CALL_CVESEARCH:
      static_queueListAnswers();
      break;
    case DB_CALL_CVETRIAGE:
      static_queueTotalAnswer("2");
      static_fillTriageRows(static_queueAnswer(PGRES_TUPLES_OK, TRIAGE_ROW_COLUMN_COUNT, 2));
      break;
    case DB_CALL_KEVLOOKUP:
      static_queueKevlookupRow();
      break;
    case DB_CALL_CWELOOKUP:
      static_queueCwelookupRow();
      break;
    case DB_CALL_CVERISKSCORE:
      static_queueRiskscoreAnswer(1);
      break;
    case DB_CALL_PRODUCTEXPOSURE:
      static_queueProductExposureAnswers(0);
      break;
    case DB_CALL_CVETRIAGEBULK:
      static_fillTriageRows(static_queueAnswer(PGRES_TUPLES_OK, TRIAGE_ROW_COLUMN_COUNT, 2));
      break;
    case DB_CALL_CVELOOKUPBULK:
      static_queueCvelookupBulkRows(2);
      break;
    case DB_CALL_CPESEARCH:
      static_queueCpeSearchAnswers();
      break;
    case DB_CALL_D3FENDFORATTACK:
      static_queueD3fendForAttackAnswer();
      break;
    case DB_CALL_DRIVERLOOKUP:
      static_queueDriverLookupAnswer();
      break;
    case DB_CALL_IPLOOKUP:
      static_queueIpLookupAnswer();
      break;
    case DB_CALL_ASNLOOKUP:
      static_queueAsnPrefixAnswer();
      static_queueAsnLookupAnswer();
      break;
    case DB_CALL_EMAILADDRESSCHECK:
      static_queueEmailAddressCheckAnswer("t", "mailinator.com");
      break;
    case DB_CALL_SSLCHECK:
      static_queueSslCheckAnswer("t", "Dridex C&C", "2024-05-06T07:08:09Z");
      break;
    case DB_CALL_PACKAGECHECK:
      static_queuePackageCheckAnswer();
      break;
    case DB_CALL_CVEPRODUCTS:
      static_queueCveProductsAnswer();
      break;
    case DB_CALL_CVELOOKUPGHSA:
      static_queueCveLookupGhsaAnswer();
      break;
    case DB_CALL_PACKAGECHECKBULK:
      static_queuePackageCheckBulkAnswer();
      break;
  }
  if (value)
    g_queuedAnswers[answer].ma_cells[row][column] = value;
  if (column_name)
    g_queuedAnswers[answer].ma_columnNames[column] = column_name;

  switch (call)
  {
    case DB_CALL_HEALTH:
    {
      HEALTHData_t data;
      db_status = db_HEALTH(NULL, &data);
      break;
    }
    case DB_CALL_CVELOOKUP:
    {
      CVELOOKUPRecord_t record = { 0 };
      db_status = db_CVELOOKUP(NULL, "CVE-2021-44228", &record);
      if (db_status != DB_OK)
      {
        TEST_ASSERT_NULL(record.mp_cwes);
        TEST_ASSERT_NULL(record.mp_cveTags);
        TEST_ASSERT_NULL(record.mp_affectedProducts);
        TEST_ASSERT_NULL(record.mp_refs);
        TEST_ASSERT_NULL(record.mp_epssTrend);
        TEST_ASSERT_NULL(record.mp_nucleiTemplates);
      }
      db_CVELOOKUPRecordFree(&record);
      break;
    }
    case DB_CALL_CVESEARCH:
    {
      CVESEARCHParams_t params;
      memset(&params, 0, sizeof(params));
      params.m_limit = 2;
      CveListResult_t results;
      memset(&results, 0, sizeof(results));
      db_status = db_CVESEARCH(FAKE_CONN, &params, &results);
      db_CveListResultFree(&results);
      break;
    }
    case DB_CALL_CVETRIAGE:
    {
      CVETRIAGEParams_t params;
      memset(&params, 0, sizeof(params));
      params.m_limit = 2;
      CVETRIAGEResult_t results;
      memset(&results, 0, sizeof(results));
      db_status = db_CVETRIAGE(FAKE_CONN, &params, &results);
      db_CVETRIAGEResultFree(&results);
      break;
    }
    case DB_CALL_KEVLOOKUP:
    {
      KEVLOOKUPRecord_t record;
      memset(&record, 0, sizeof(record));
      db_status = db_KEVLOOKUP(NULL, "CVE-2021-44228", &record);
      if (db_status != DB_OK)
      {
        TEST_ASSERT_NULL(record.mp_cwes);
        TEST_ASSERT_NULL(record.mp_notes);
      }
      db_KEVLOOKUPRecordFree(&record);
      break;
    }
    case DB_CALL_CWELOOKUP:
    {
      CWELOOKUPRecord_t record;
      memset(&record, 0, sizeof(record));
      db_status = db_CWELOOKUP(NULL, "CWE-79", &record);
      if (db_status != DB_OK)
      {
        TEST_ASSERT_NULL(record.mp_mitigations);
        TEST_ASSERT_NULL(record.mp_extendedDescription);
        TEST_ASSERT_NULL(record.mp_examples);
      }
      db_CWELOOKUPRecordFree(&record);
      break;
    }
    case DB_CALL_CVERISKSCORE:
    {
      CVERISKSCORERecord_t record;
      db_status = db_CVERISKSCORE(NULL, "CVE-2021-44228", &record);
      break;
    }
    case DB_CALL_PRODUCTEXPOSURE:
    {
      PRODUCTEXPOSURERecord_t record;
      db_status = static_runProductExposure("", false, &record);
      break;
    }
    case DB_CALL_CVETRIAGEBULK:
    {
      static const BulkIdsParams_t params = {
        .ma_ids    = { "CVE-2021-44228", "CVE-2014-0160" },
        .m_idCount = 2,
      };
      CVETRIAGEBULKResult_t results;
      memset(&results, 0, sizeof(results));
      db_status = db_CVETRIAGEBULK(NULL, &params, &results);
      db_CVETRIAGEBULKResultFree(&results);
      break;
    }
    case DB_CALL_CVELOOKUPBULK:
    {
      static const BulkIdsParams_t params = {
        .ma_ids    = { "CVE-2021-44228", "CVE-2014-0160" },
        .m_idCount = 2,
      };
      CVELOOKUPBULKResult_t results;
      memset(&results, 0, sizeof(results));
      db_status = db_CVELOOKUPBULK(NULL, &params, &results);
      db_CVELOOKUPBULKResultFree(&results);
      break;
    }
    case DB_CALL_CPESEARCH:
    {
      CPESEARCHParams_t params;
      memset(&params, 0, sizeof(params));
      params.m_limit = 2;
      CPESEARCHResult_t results;
      memset(&results, 0, sizeof(results));
      db_status = db_CPESEARCH(FAKE_CONN, &params, &results);
      db_CPESEARCHResultFree(&results);
      break;
    }
    case DB_CALL_D3FENDFORATTACK:
    {
      D3FENDFORATTACKResult_t result;
      db_status = db_D3FENDFORATTACK(FAKE_CONN, "T1055", &result);
      db_D3FENDFORATTACKResultFree(&result);
      break;
    }
    case DB_CALL_DRIVERLOOKUP:
    {
      DRIVERLOOKUPRecord_t record;
      db_status = db_DRIVERLOOKUP(FAKE_CONN, DRIVERLOOKUP_TEST_HASH, false, &record);
      if (db_status != DB_OK)
        TEST_ASSERT_NULL(record.mp_matches);
      db_DRIVERLOOKUPRecordFree(&record);
      break;
    }
    case DB_CALL_IPLOOKUP:
    {
      IPLOOKUPRecord_t record;
      db_status = db_IPLOOKUP(FAKE_CONN, IPLOOKUP_TEST_IP, &record);
      if (db_status != DB_OK)
        TEST_ASSERT_NULL(record.mp_listedOn);
      db_IPLOOKUPRecordFree(&record);
      break;
    }
    case DB_CALL_ASNLOOKUP:
    {
      ASNLOOKUPParams_t params = static_asnLookupParams(ASNLOOKUP_TEST_IP);
      ASNLOOKUPRecord_t record;
      memset(&record, 0xA5, sizeof(record));
      db_status = db_ASNLOOKUP(FAKE_CONN, &params, &record);
      if (db_status != DB_OK)
      {
        TEST_ASSERT_NULL(record.mp_ipv4Prefixes);
        TEST_ASSERT_NULL(record.mp_ipv6Prefixes);
      }
      db_ASNLOOKUPRecordFree(&record);
      break;
    }
    case DB_CALL_EMAILADDRESSCHECK:
    {
      EMAILADDRESSCHECKRecord_t record;
      memset(&record, 0xA5, sizeof(record));
      db_status = db_EMAILADDRESSCHECK(FAKE_CONN, EMAILADDRESSCHECK_TEST_DOMAIN, &record);
      if (db_status != DB_OK)
      {
        TEST_ASSERT_FALSE(record.m_isDisposableFeedLoaded);
        TEST_ASSERT_EQUAL_STRING("", record.ma_disposableListedDomain);
      }
      break;
    }
    case DB_CALL_SSLCHECK:
    {
      static SSLCHECKRecord_t record;
      memset(&record, 0xA5, sizeof(record));
      db_status = db_SSLCHECK(FAKE_CONN, SSLCHECK_TEST_SHA1, &record);
      if (db_status != DB_OK)
      {
        TEST_ASSERT_FALSE(record.m_isBlacklistFeedLoaded);
        TEST_ASSERT_EQUAL_STRING("", record.ma_blacklistListingReason);
        TEST_ASSERT_EQUAL_STRING("", record.ma_blacklistListingTime);
      }
      break;
    }
    case DB_CALL_PACKAGECHECK:
    {
      PACKAGECHECKParams_t params = static_packageCheckParams("4.17.20");
      PACKAGECHECKResult_t result;
      db_status = db_PACKAGECHECK(FAKE_CONN, &params, &result);
      if (db_status != DB_OK)
      {
        TEST_ASSERT_NULL(result.mp_malicious);
        TEST_ASSERT_NULL(result.mp_results);
        TEST_ASSERT_NULL(result.mp_attribution);
      }
      db_PACKAGECHECKResultFree(&result);
      break;
    }
    case DB_CALL_CVEPRODUCTS:
    {
      CVEPRODUCTSParams_t params = static_cveProductsParams("acme", "");
      CVEPRODUCTSResult_t result;
      db_status = db_CVEPRODUCTS(FAKE_CONN, &params, &result);
      if (db_status != DB_OK)
        TEST_ASSERT_NULL(result.mp_affectedProducts);
      db_CVEPRODUCTSResultFree(&result);
      break;
    }
    case DB_CALL_CVELOOKUPGHSA:
    {
      CVELOOKUPRecord_t record = { 0 };
      db_status = db_CVELOOKUPGHSA(FAKE_CONN, "CVE-2021-44228", &record);
      if (db_status != DB_OK)
        TEST_ASSERT_NULL(record.mp_ghsa);
      db_CVELOOKUPRecordFree(&record);
      break;
    }
    case DB_CALL_PACKAGECHECKBULK:
    {
      PACKAGECHECKBULKResult_t result;
      db_status = db_PACKAGECHECKBULK(FAKE_CONN, g_packageCheckBulkItems, 2, &result);
      if (db_status != DB_OK)
      {
        TEST_ASSERT_NULL(result.mp_results);
        TEST_ASSERT_NULL(result.mp_attribution);
      }
      db_PACKAGECHECKBULKResultFree(&result);
      break;
    }
  }
  return db_status;
}

void test_unreadable_number_or_boolean_is_error(void)
{
  static const struct {
    DbCall_t    m_call;
    int         m_answer;
    int         m_row;
    int         m_column;
    const char* mp_name;
  } rows[] = {
    { DB_CALL_HEALTH,           0, 0,  0, "HEALTH cve count" },
    { DB_CALL_HEALTH,           0, 0,  3, "HEALTH kev count" },
    { DB_CALL_HEALTH,           0, 0,  6, "HEALTH cwe count" },
    { DB_CALL_CVELOOKUP,        0, 0,  3, "CVELOOKUP cvss_v3" },
    { DB_CALL_CVELOOKUP,        0, 0,  6, "CVELOOKUP epss_score" },
    { DB_CALL_CVELOOKUP,        0, 0,  7, "CVELOOKUP epss_percentile" },
    { DB_CALL_CVELOOKUP,        0, 0, 10, "CVELOOKUP in_kev" },
    { DB_CALL_CVELOOKUP,        0, 0, 13, "CVELOOKUP poc_count" },
    { DB_CALL_CVELOOKUP,        0, 0, 14, "CVELOOKUP vendor_advisory_count" },
    { DB_CALL_CVELOOKUP,        0, 0, 16, "CVELOOKUP metasploit_module_count" },
    { DB_CALL_CVELOOKUP,        0, 0, 21, "CVELOOKUP cvss_v4" },
    { DB_CALL_CVELOOKUP,        0, 0, 28, "CVELOOKUP metasploit_feed_loaded" },
    { DB_CALL_CVELOOKUP,        0, 0, 29, "CVELOOKUP nuclei_template_count" },
    { DB_CALL_CVELOOKUP,        0, 0, 30, "CVELOOKUP nuclei_template_feed_loaded" },
    { DB_CALL_CVELOOKUP,        0, 0, 35, "CVELOOKUP affected_product_count" },
    { DB_CALL_CVELOOKUP,        0, 0, 37, "CVELOOKUP ref_count" },
    { DB_CALL_CVESEARCH,        0, 0,  0, "CVESEARCH total" },
    { DB_CALL_CVESEARCH,        1, 1,  2, "CVESEARCH cvss_v3" },
    { DB_CALL_CVESEARCH,        1, 1,  3, "CVESEARCH epss_score" },
    { DB_CALL_CVESEARCH,        1, 1,  4, "CVESEARCH epss_percentile" },
    { DB_CALL_CVESEARCH,        1, 1,  5, "CVESEARCH in_kev" },
    { DB_CALL_CVESEARCH,        1, 1,  8, "CVESEARCH cvss_v4" },
    { DB_CALL_CVESEARCH,        1, 1,  9, "CVESEARCH has_cvss_v4" },
    { DB_CALL_CVESEARCH,        1, 1, 10, "CVESEARCH has_cvss_v3" },
    { DB_CALL_CVETRIAGE,        0, 0,  0, "CVETRIAGE total" },
    { DB_CALL_CVETRIAGE,        1, 1,  3, "CVETRIAGE risk_score" },
    { DB_CALL_KEVLOOKUP,        0, 0,  5, "KEVLOOKUP known_ransomware_use" },
    { DB_CALL_KEVLOOKUP,        0, 0, 12, "KEVLOOKUP in_kev" },
    { DB_CALL_CWELOOKUP,        0, 0, 11, "CWELOOKUP kev count" },
    { DB_CALL_CWELOOKUP,        0, 0, 12, "CWELOOKUP avg_cvss" },
    { DB_CALL_CWELOOKUP,        0, 0, 13, "CWELOOKUP avg_epss" },
    { DB_CALL_CWELOOKUP,        0, 0, 14, "CWELOOKUP cve count" },
    { DB_CALL_CVERISKSCORE,     0, 0,  0, "CVERISKSCORE risk_score" },
    { DB_CALL_CVERISKSCORE,     0, 0,  1, "CVERISKSCORE exploitability" },
    { DB_CALL_CVERISKSCORE,     0, 0,  2, "CVERISKSCORE impact" },
    { DB_CALL_CVERISKSCORE,     0, 0,  3, "CVERISKSCORE evidence" },
    { DB_CALL_CVERISKSCORE,     0, 0,  4, "CVERISKSCORE has_public_poc" },
    { DB_CALL_PRODUCTEXPOSURE,  0, 0,  0, "PRODUCTEXPOSURE total" },
    { DB_CALL_PRODUCTEXPOSURE,  0, 0,  1, "PRODUCTEXPOSURE critical" },
    { DB_CALL_PRODUCTEXPOSURE,  0, 0,  2, "PRODUCTEXPOSURE high" },
    { DB_CALL_PRODUCTEXPOSURE,  0, 0,  3, "PRODUCTEXPOSURE medium" },
    { DB_CALL_PRODUCTEXPOSURE,  0, 0,  4, "PRODUCTEXPOSURE low" },
    { DB_CALL_PRODUCTEXPOSURE,  0, 0,  5, "PRODUCTEXPOSURE kev" },
    { DB_CALL_PRODUCTEXPOSURE,  0, 0,  6, "PRODUCTEXPOSURE max_cvss" },
    { DB_CALL_PRODUCTEXPOSURE,  0, 0,  7, "PRODUCTEXPOSURE avg_cvss" },
    { DB_CALL_PRODUCTEXPOSURE,  0, 0,  8, "PRODUCTEXPOSURE max_epss" },
    { DB_CALL_PRODUCTEXPOSURE,  0, 0,  9, "PRODUCTEXPOSURE poc_backed" },
    { DB_CALL_PRODUCTEXPOSURE,  0, 0, 10, "PRODUCTEXPOSURE worst_risk" },
    { DB_CALL_PRODUCTEXPOSURE,  0, 1, 13, "PRODUCTEXPOSURE top risk_score" },
    { DB_CALL_CPESEARCH,        1, 1,  2, "CPESEARCH vulnerable_cve_count" },
    { DB_CALL_DRIVERLOOKUP,     0, 0,  1, "DRIVERLOOKUP match_count" },
    { DB_CALL_DRIVERLOOKUP,     0, 0,  2, "DRIVERLOOKUP driver_feed_loaded" },
    { DB_CALL_IPLOOKUP,         0, 0,  0, "IPLOOKUP asn" },
    { DB_CALL_IPLOOKUP,         0, 0,  6, "IPLOOKUP is_cdn" },
    { DB_CALL_IPLOOKUP,         0, 0,  7, "IPLOOKUP is_datacenter" },
    { DB_CALL_IPLOOKUP,         0, 0,  8, "IPLOOKUP is_tor_exit" },
    { DB_CALL_IPLOOKUP,         0, 0, 10, "IPLOOKUP asn_feed_loaded" },
    { DB_CALL_IPLOOKUP,         0, 0, 11, "IPLOOKUP geo_feed_loaded" },
    { DB_CALL_IPLOOKUP,         0, 0, 12, "IPLOOKUP cloud_feed_loaded" },
    { DB_CALL_IPLOOKUP,         0, 0, 13, "IPLOOKUP tor_feed_loaded" },
    { DB_CALL_IPLOOKUP,         0, 0, 14, "IPLOOKUP drop_list_feed_loaded" },
    { DB_CALL_ASNLOOKUP,        0, 0,  0, "ASNLOOKUPPREFIX asn" },
    { DB_CALL_ASNLOOKUP,        1, 0,  0, "ASNLOOKUP asn" },
    { DB_CALL_ASNLOOKUP,        1, 0,  3, "ASNLOOKUP ipv4_prefix_count" },
    { DB_CALL_ASNLOOKUP,        1, 0,  4, "ASNLOOKUP ipv6_prefix_count" },
    { DB_CALL_EMAILADDRESSCHECK, 0, 0, 0, "EMAILADDRESSCHECK disposable_feed_loaded" },
    { DB_CALL_SSLCHECK,         0, 0,  0, "SSLCHECK ssl_blacklist_feed_loaded" },
    { DB_CALL_PACKAGECHECK,     0, 0,  0, "PACKAGECHECK advisory_feed_loaded" },
    { DB_CALL_PACKAGECHECK,     0, 0,  1, "PACKAGECHECK has_advisory_data" },
    { DB_CALL_PACKAGECHECK,     0, 0,  2, "PACKAGECHECK result_count" },
    { DB_CALL_CVEPRODUCTS,      0, 0,  0, "CVEPRODUCTS affected_product_count" },
    { DB_CALL_CVEPRODUCTS,      0, 0,  1, "CVEPRODUCTS listed_product_count" },
    { DB_CALL_CVELOOKUPGHSA,    0, 0,  0, "CVELOOKUPGHSA ghsa_feed_loaded" },
    { DB_CALL_PACKAGECHECKBULK, 0, 0,  0, "PACKAGECHECKBULK advisory_feed_loaded" },
    { DB_CALL_PACKAGECHECKBULK, 0, 0,  3, "PACKAGECHECKBULK failed_item_count" },
  };

  for (size_t row = 0; row < sizeof(rows) / sizeof(rows[0]); row++)
  {
    DbStatus_t readable_status = static_runDbCall(rows[row].m_call, rows[row].m_answer,
                                                  rows[row].m_row, rows[row].m_column, NULL, NULL);
    DbStatus_t unreadable_status = static_runDbCall(rows[row].m_call, rows[row].m_answer,
                                                    rows[row].m_row, rows[row].m_column, "12abc", NULL);

    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_OK, readable_status, rows[row].mp_name);
    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_ERROR, unreadable_status, rows[row].mp_name);
  }
}

void test_answer_with_other_column_names_is_error(void)
{
  static const struct {
    DbCall_t    m_call;
    int         m_answer;
    int         m_column;
    const char* mp_name;
  } rows[] = {
    { DB_CALL_CVELOOKUP,       0, 0,  "CVELOOKUP cve_id" },
    { DB_CALL_CVELOOKUP,       0, 22, "CVELOOKUP cvss_v4_vector" },
    { DB_CALL_CVELOOKUPBULK,   0, 0,  "CVELOOKUPBULK cve_id" },
    { DB_CALL_CVELOOKUPBULK,   0, 22, "CVELOOKUPBULK cvss_v4_vector" },
    { DB_CALL_KEVLOOKUP,       0, 0,  "KEVLOOKUP cve_id" },
    { DB_CALL_KEVLOOKUP,       0, 12, "KEVLOOKUP in_kev" },
    { DB_CALL_CWELOOKUP,       0, 0,  "CWELOOKUP cwe_id" },
    { DB_CALL_CWELOOKUP,       0, 14, "CWELOOKUP cve_count" },
    { DB_CALL_CVERISKSCORE,    0, 0,  "CVERISKSCORE risk_score" },
    { DB_CALL_CVERISKSCORE,    0, 5,  "CVERISKSCORE risk_label" },
    { DB_CALL_HEALTH,          0, 0,  "HEALTH cve_count" },
    { DB_CALL_HEALTH,          0, 8,  "HEALTH cwe_last_updated_at" },
    { DB_CALL_CVETRIAGEBULK,   0, 0,  "CVETRIAGEBULK cve_id" },
    { DB_CALL_CVETRIAGEBULK,   0, 4,  "CVETRIAGEBULK risk_label" },
    { DB_CALL_PRODUCTEXPOSURE, 0, 0,  "PRODUCTEXPOSURE cve_count" },
    { DB_CALL_PRODUCTEXPOSURE, 0, 11, "PRODUCTEXPOSURE most_recent_published" },
    { DB_CALL_PRODUCTEXPOSURE, 0, 12, "PRODUCTEXPOSURE top cve_id" },
    { DB_CALL_PRODUCTEXPOSURE, 0, 14, "PRODUCTEXPOSURE top risk_label" },
    { DB_CALL_PRODUCTEXPOSURE, 1, 0,  "PRODUCTEXPOSURE eol row_kind" },
    { DB_CALL_PRODUCTEXPOSURE, 1, 8,  "PRODUCTEXPOSURE eol maintained_cycle_count" },
    { DB_CALL_CVESEARCH,       0, 0,  "CVESEARCH total cve_count" },
    { DB_CALL_CVESEARCH,       1, 0,  "CVESEARCH page cve_id" },
    { DB_CALL_CVESEARCH,       1, 10, "CVESEARCH page has_cvss_v3" },
    { DB_CALL_CVETRIAGE,       0, 0,  "CVETRIAGE total cve_count" },
    { DB_CALL_CVETRIAGE,       1, 0,  "CVETRIAGE page cve_id" },
    { DB_CALL_CVETRIAGE,       1, 4,  "CVETRIAGE page risk_label" },
    { DB_CALL_CPESEARCH,       0, 0,  "CPESEARCH total product_count" },
    { DB_CALL_CPESEARCH,       1, 0,  "CPESEARCH page vendor" },
    { DB_CALL_CPESEARCH,       1, 2,  "CPESEARCH page vulnerable_cve_count" },
    { DB_CALL_D3FENDFORATTACK, 0, 0,  "D3FENDFORATTACK defense_id" },
    { DB_CALL_D3FENDFORATTACK, 0, 6,  "D3FENDFORATTACK attack_techniques" },
    { DB_CALL_DRIVERLOOKUP,    0, 0,  "DRIVERLOOKUP hash" },
    { DB_CALL_DRIVERLOOKUP,    0, 3,  "DRIVERLOOKUP matches" },
    { DB_CALL_IPLOOKUP,        0, 0,  "IPLOOKUP asn" },
    { DB_CALL_IPLOOKUP,        0, 14, "IPLOOKUP drop_list_feed_loaded" },
    { DB_CALL_ASNLOOKUP,       0, 0,  "ASNLOOKUPPREFIX asn" },
    { DB_CALL_ASNLOOKUP,       0, 1,  "ASNLOOKUPPREFIX prefix" },
    { DB_CALL_ASNLOOKUP,       1, 0,  "ASNLOOKUP asn" },
    { DB_CALL_ASNLOOKUP,       1, 6,  "ASNLOOKUP ipv6_prefixes" },
    { DB_CALL_EMAILADDRESSCHECK, 0, 0, "EMAILADDRESSCHECK disposable_feed_loaded" },
    { DB_CALL_EMAILADDRESSCHECK, 0, 1, "EMAILADDRESSCHECK listed_domain" },
    { DB_CALL_SSLCHECK,        0, 0,  "SSLCHECK ssl_blacklist_feed_loaded" },
    { DB_CALL_SSLCHECK,        0, 2,  "SSLCHECK listing_time" },
    { DB_CALL_PACKAGECHECK,    0, 0,  "PACKAGECHECK advisory_feed_loaded" },
    { DB_CALL_PACKAGECHECK,    0, 6,  "PACKAGECHECK attribution" },
    { DB_CALL_PACKAGECHECK,    1, 0,  "PACKAGECHECK eol row_kind" },
    { DB_CALL_PACKAGECHECK,    1, 8,  "PACKAGECHECK eol maintained_cycle_count" },
    { DB_CALL_CVEPRODUCTS,     0, 0,  "CVEPRODUCTS affected_product_count" },
    { DB_CALL_CVEPRODUCTS,     0, 2,  "CVEPRODUCTS affected_products" },
    { DB_CALL_CVELOOKUPGHSA,   0, 0,  "CVELOOKUPGHSA ghsa_feed_loaded" },
    { DB_CALL_CVELOOKUPGHSA,   0, 1,  "CVELOOKUPGHSA advisory" },
    { DB_CALL_PACKAGECHECKBULK, 0, 0, "PACKAGECHECKBULK advisory_feed_loaded" },
    { DB_CALL_PACKAGECHECKBULK, 0, 3, "PACKAGECHECKBULK failed_item_count" },
  };

  for (size_t row = 0; row < sizeof(rows) / sizeof(rows[0]); row++)
  {
    DbStatus_t named_status   = static_runDbCall(rows[row].m_call, rows[row].m_answer, 0,
                                                 rows[row].m_column, NULL, NULL);
    DbStatus_t renamed_status = static_runDbCall(rows[row].m_call, rows[row].m_answer, 0,
                                                 rows[row].m_column, NULL, "moved");

    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_OK, named_status, rows[row].mp_name);
    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_ERROR, renamed_status, rows[row].mp_name);
  }
}

void test_scalar_columns_land_in_their_own_fields(void)
{
  FakeAnswer_t* lookup = static_queueAnswer(PGRES_TUPLES_OK, CVELOOKUP_ROW_COLUMN_COUNT, 1);
  static_fillCvelookupRow(lookup, 0);
  lookup->ma_cells[0][3]  = "7.5";
  lookup->ma_cells[0][6]  = "0.25";
  lookup->ma_cells[0][7]  = "0.125";
  lookup->ma_cells[0][13] = "13";
  lookup->ma_cells[0][14] = "14";
  lookup->ma_cells[0][16] = "16";
  lookup->ma_cells[0][21] = "6.25";
  lookup->ma_cells[0][CVELOOKUP_ROW_METASPLOIT_FEED_LOADED_COLUMN_INDEX] = "f";
  lookup->ma_cells[0][CVELOOKUP_ROW_NUCLEI_TEMPLATE_COUNT_COLUMN_INDEX] = "29";
  lookup->ma_cells[0][CVELOOKUP_ROW_AFFECTED_PRODUCT_COUNT_COLUMN_INDEX] = "35";
  lookup->ma_cells[0][CVELOOKUP_ROW_REF_COUNT_COLUMN_INDEX] = "37";
  CVELOOKUPRecord_t record = { 0 };

  TEST_ASSERT_EQUAL_INT(DB_OK, db_CVELOOKUP(NULL, "CVE-2021-44228", &record));

  TEST_ASSERT_TRUE(record.m_cvssV3 == 7.5);
  TEST_ASSERT_TRUE(record.m_epssScore == 0.25);
  TEST_ASSERT_TRUE(record.m_epssPercentile == 0.125);
  TEST_ASSERT_TRUE(record.m_inKev);
  TEST_ASSERT_EQUAL_INT(13, record.m_pocCount);
  TEST_ASSERT_EQUAL_INT(14, record.m_vendorAdvisoryCount);
  TEST_ASSERT_EQUAL_INT(16, record.m_metasploitModuleCount);
  TEST_ASSERT_FALSE(record.m_isMetasploitFeedLoaded);
  TEST_ASSERT_EQUAL_INT(29, record.m_nucleiTemplateCount);
  TEST_ASSERT_TRUE(record.m_isNucleiTemplateFeedLoaded);
  TEST_ASSERT_TRUE(record.m_cvssV4 == 6.25);
  TEST_ASSERT_EQUAL_INT(35, record.m_affectedProductCount);
  TEST_ASSERT_EQUAL_INT(37, record.m_refCount);
  db_CVELOOKUPRecordFree(&record);

  static_resetFake();
  FakeAnswer_t* select = static_queueListAnswers();
  select->ma_cells[0][2] = "7.5";
  select->ma_cells[0][3] = "0.25";
  select->ma_cells[0][4] = "0.125";
  select->ma_cells[0][8] = "4.5";
  select->ma_cells[0][9] = "f";
  select->ma_cells[1][10] = "f";
  CVESEARCHParams_t params;
  memset(&params, 0, sizeof(params));
  params.m_limit = 2;
  CveListResult_t results;
  memset(&results, 0, sizeof(results));

  TEST_ASSERT_EQUAL_INT(DB_OK, db_CVESEARCH(FAKE_CONN, &params, &results));

  TEST_ASSERT_TRUE(results.mp_items[0].m_cvssV3 == 7.5);
  TEST_ASSERT_TRUE(results.mp_items[0].m_epssScore == 0.25);
  TEST_ASSERT_TRUE(results.mp_items[0].m_epssPercentile == 0.125);
  TEST_ASSERT_TRUE(results.mp_items[0].m_cvssV4 == 4.5);
  TEST_ASSERT_TRUE(results.mp_items[0].m_inKev);
  TEST_ASSERT_FALSE(results.mp_items[0].m_hasCvssV4);
  TEST_ASSERT_TRUE(results.mp_items[0].m_hasCvssV3);
  TEST_ASSERT_TRUE(results.mp_items[1].m_hasCvssV4);
  TEST_ASSERT_FALSE(results.mp_items[1].m_hasCvssV3);
  db_CveListResultFree(&results);

  static_resetFake();
  static const char* const summary_values[PRODUCTEXPOSURE_SUMMARY_COLUMN_COUNT] = {
    "10", "11", "12", "13", "14", "15", "9.5", "8.5", "0.75", "19", "97.25", "2021-12-11"
  };
  static_queueProductExposureAnswer(summary_values, 2);
  static_queueProductExposureEol(0);
  PRODUCTEXPOSURERecord_t exposure;

  TEST_ASSERT_EQUAL_INT(DB_OK, static_runProductExposure("", false, &exposure));

  TEST_ASSERT_EQUAL_INT(10, exposure.m_totalCveCount);
  TEST_ASSERT_EQUAL_INT(11, exposure.m_criticalCount);
  TEST_ASSERT_EQUAL_INT(12, exposure.m_highCount);
  TEST_ASSERT_EQUAL_INT(13, exposure.m_mediumCount);
  TEST_ASSERT_EQUAL_INT(14, exposure.m_lowCount);
  TEST_ASSERT_EQUAL_INT(15, exposure.m_kevCount);
  TEST_ASSERT_TRUE(exposure.m_maxCvss == 9.5);
  TEST_ASSERT_TRUE(exposure.m_avgCvss == 8.5);
  TEST_ASSERT_TRUE(exposure.m_maxEpss == 0.75);
  TEST_ASSERT_EQUAL_INT(19, exposure.m_pocBackedCount);
  TEST_ASSERT_TRUE(exposure.m_worstRiskScore == 97.25);
  TEST_ASSERT_EQUAL_STRING("2021-12-11", exposure.ma_mostRecentPublished);
}

static void* static_refuseOnceOnThread(void* unused)
{
  (void)unused;
  PGresult* result = static_buildOneCellResult("abcde");
  char dest[8];
  if (result)
  {
    bool is_copied = dbhelper_fetchColStr(result, 0, 0, dest, 4);
    (void)is_copied;
    PQclear(result);
  }
  return NULL;
}

void test_each_thread_has_its_own_log_limit(void)
{
  StderrCapture_t capture;
  static_beginStderrCapture(&capture);

  static_refuseOnceOnThread(NULL);
  pthread_t thread;
  int create_status = pthread_create(&thread, NULL, static_refuseOnceOnThread, NULL);
  int join_status   = (create_status == 0) ? pthread_join(thread, NULL) : -1;

  char text[512];
  static_endStderrCapture(&capture, text, sizeof(text));
  TEST_ASSERT_EQUAL_INT(0, create_status);
  TEST_ASSERT_EQUAL_INT(0, join_status);
  TEST_ASSERT_EQUAL_STRING("dbhelper_fetchColStr: column column (index 0) holds 5 bytes, limit 4\n"
                           "dbhelper_fetchColStr: column column (index 0) holds 5 bytes, limit 4\n", text);
}

void test_clock_step_back_is_a_new_second(void)
{
  PGresult* result = static_buildOneCellResult("abcde");
  TEST_ASSERT_NOT_NULL(result);
  char dest[8];
  StderrCapture_t capture;
  static_beginStderrCapture(&capture);

  bool is_first_copied = dbhelper_fetchColStr(result, 0, 0, dest, 4);
  g_fakeNow -= 1;
  bool is_second_copied = dbhelper_fetchColStr(result, 0, 0, dest, 3);
  g_fakeNow += 2;

  char text[512];
  static_endStderrCapture(&capture, text, sizeof(text));
  PQclear(result);
  TEST_ASSERT_FALSE(is_first_copied);
  TEST_ASSERT_FALSE(is_second_copied);
  TEST_ASSERT_EQUAL_STRING("dbhelper_fetchColStr: column column (index 0) holds 5 bytes, limit 4\n"
                           "dbhelper_fetchColStr: column column (index 0) holds 5 bytes, limit 3\n", text);
}

void test_CVELOOKUP_reads_the_longest_cvss_v4_vector(void)
{
  static const char* const longest =
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A/CR:H/IR:H/AR:H"
    "/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:H/MVI:H/MVA:H/MSC:H/MSI:S/MSA:S/S:N/AU:N/R:A/V:D/RE:L/U:Amber";
  FakeAnswer_t* answer = static_queueAnswer(PGRES_TUPLES_OK, CVELOOKUP_ROW_COLUMN_COUNT, 1);
  static_fillCvelookupRow(answer, 0);
  answer->ma_cells[0][CVELOOKUP_ROW_CVSS_V4_VECTOR_COLUMN_INDEX] = longest;
  CVELOOKUPRecord_t record = { 0 };

  TEST_ASSERT_EQUAL_INT(DB_OK, db_CVELOOKUP(NULL, "CVE-2021-44228", &record));
  TEST_ASSERT_EQUAL_STRING(longest, record.ma_cvssV4Vector);
  db_CVELOOKUPRecordFree(&record);
}

static void static_queueOneCell(const char* column_name, const char* cell)
{
  FakeAnswer_t* answer = static_queueAnswer(PGRES_TUPLES_OK, 1, 1);
  answer->ma_columnNames[0] = column_name;
  answer->ma_cells[0][0]    = cell;
}

typedef enum {
  WRONG_SHAPE_FAILED_QUERY,
  WRONG_SHAPE_DEFAULT_ROW,
  WRONG_SHAPE_NO_ROW,
  WRONG_SHAPE_TWO_ROWS,
  WRONG_SHAPE_TWO_COLUMNS,
  WRONG_SHAPE_OTHER_NAME
} WrongShape_t;

static const WrongShape_t g_wrongShapes[] = {
  WRONG_SHAPE_FAILED_QUERY,
  WRONG_SHAPE_DEFAULT_ROW,
  WRONG_SHAPE_NO_ROW,
  WRONG_SHAPE_TWO_ROWS,
  WRONG_SHAPE_TWO_COLUMNS,
  WRONG_SHAPE_OTHER_NAME,
};

static void static_queueWrongShape(WrongShape_t shape, const char* column_name, const char* cell)
{
  FakeAnswer_t* answer = NULL;
  switch (shape)
  {
    case WRONG_SHAPE_FAILED_QUERY:
      static_queueAnswer(PGRES_FATAL_ERROR, 0, 0);
      break;
    case WRONG_SHAPE_DEFAULT_ROW:
      break;
    case WRONG_SHAPE_NO_ROW:
      answer = static_queueAnswer(PGRES_TUPLES_OK, 1, 0);
      answer->ma_columnNames[0] = column_name;
      break;
    case WRONG_SHAPE_TWO_ROWS:
      answer = static_queueAnswer(PGRES_TUPLES_OK, 1, 2);
      answer->ma_columnNames[0] = column_name;
      answer->ma_cells[0][0]    = cell;
      answer->ma_cells[1][0]    = cell;
      break;
    case WRONG_SHAPE_TWO_COLUMNS:
      answer = static_queueAnswer(PGRES_TUPLES_OK, 2, 1);
      answer->ma_columnNames[0] = column_name;
      answer->ma_cells[0][0]    = cell;
      answer->ma_cells[0][1]    = cell;
      break;
    case WRONG_SHAPE_OTHER_NAME:
      static_queueOneCell("version", cell);
      break;
  }
}

void test_readSchemaVersion_reads_one_int(void)
{
  static const struct {
    const char* mp_cell;
    DbStatus_t  m_status;
    int         m_version;
  } rows[] = {
    { "1",           DB_OK,    1  },
    { "42",          DB_OK,    42 },
    { FAKE_SQL_NULL, DB_ERROR, 0  },
    { "x",           DB_ERROR, 0  },
  };

  for (size_t row = 0; row < sizeof(rows) / sizeof(rows[0]); row++)
  {
    static_resetFake();
    static_queueOneCell("schema_version", rows[row].mp_cell);
    char message[16] = "";
    snprintf(message, sizeof(message), "row %zu", row);
    int version = -1;

    DbStatus_t db_status = db_readSchemaVersion(NULL, &version);

    TEST_ASSERT_EQUAL_INT_MESSAGE(rows[row].m_status, db_status, message);
    if (db_status == DB_OK)
      TEST_ASSERT_EQUAL_INT_MESSAGE(rows[row].m_version, version, message);
  }
}

void test_readSchemaVersion_refuses_any_other_answer(void)
{
  for (size_t row = 0; row < sizeof(g_wrongShapes) / sizeof(g_wrongShapes[0]); row++)
  {
    static_resetFake();
    static_queueWrongShape(g_wrongShapes[row], "schema_version", "1");
    char message[16] = "";
    snprintf(message, sizeof(message), "row %zu", row);
    int version = -1;

    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_ERROR, db_readSchemaVersion(NULL, &version), message);
  }
}

void test_readSchemaVersion_calls_the_api_function(void)
{
  static_queueOneCell("schema_version", "1");
  int version = -1;

  TEST_ASSERT_EQUAL_INT(DB_OK, db_readSchemaVersion(NULL, &version));

  TEST_ASSERT_EQUAL_INT(1, g_callCount);
  TEST_ASSERT_EQUAL_STRING("SELECT api.fn_schema_version() AS schema_version", static_lastCall()->ma_command);
  TEST_ASSERT_EQUAL_INT(0, static_lastCall()->m_paramCount);
  TEST_ASSERT_EQUAL_INT(0, static_lastCall()->m_resultFormat);
}

static void static_queueRoleStateRow(const char* superuser_cell, const char* owner_cell)
{
  FakeAnswer_t* answer = static_queueAnswer(PGRES_TUPLES_OK, 2, 1);
  answer->ma_columnNames[0] = "is_superuser";
  answer->ma_columnNames[1] = "is_owner_member";
  answer->ma_cells[0][0]    = superuser_cell;
  answer->ma_cells[0][1]    = owner_cell;
}

void test_readConnectionRoleState_reads_both_flags(void)
{
  static const struct {
    const char* mp_superuserCell;
    const char* mp_ownerCell;
    DbStatus_t  m_status;
    bool        m_isSuperuser;
    bool        m_isOwnerMember;
  } rows[] = {
    { "f",           "f",           DB_OK,    false, false },
    { "t",           "f",           DB_OK,    true,  false },
    { "f",           "t",           DB_OK,    false, true  },
    { FAKE_SQL_NULL, "f",           DB_ERROR, false, false },
    { "f",           FAKE_SQL_NULL, DB_ERROR, false, false },
    { "x",           "f",           DB_ERROR, false, false },
  };

  for (size_t row = 0; row < sizeof(rows) / sizeof(rows[0]); row++)
  {
    static_resetFake();
    static_queueRoleStateRow(rows[row].mp_superuserCell, rows[row].mp_ownerCell);
    char message[16] = "";
    snprintf(message, sizeof(message), "row %zu", row);
    DbConnectionRoleState_t state = { .m_isSuperuser   = !rows[row].m_isSuperuser,
                                      .m_isOwnerMember = !rows[row].m_isOwnerMember };

    DbStatus_t db_status = db_readConnectionRoleState(NULL, &state);

    TEST_ASSERT_EQUAL_INT_MESSAGE(rows[row].m_status, db_status, message);
    if (db_status == DB_OK)
    {
      TEST_ASSERT_EQUAL_MESSAGE(rows[row].m_isSuperuser,   state.m_isSuperuser,   message);
      TEST_ASSERT_EQUAL_MESSAGE(rows[row].m_isOwnerMember, state.m_isOwnerMember, message);
    }
  }
}

void test_readConnectionRoleState_refuses_any_other_answer(void)
{
  static const struct {
    ExecStatusType m_status;
    int            m_rowCount;
    int            m_columnCount;
    const char*    ma_names[3];
  } shapes[] = {
    { PGRES_FATAL_ERROR, 0, 0, { NULL,              NULL,              NULL              } },
    { PGRES_TUPLES_OK,   0, 2, { "is_superuser",    "is_owner_member", NULL              } },
    { PGRES_TUPLES_OK,   2, 2, { "is_superuser",    "is_owner_member", NULL              } },
    { PGRES_TUPLES_OK,   1, 2, { "superuser",       "is_owner_member", NULL              } },
    { PGRES_TUPLES_OK,   1, 2, { "is_superuser",    "is_owner",        NULL              } },
    { PGRES_TUPLES_OK,   1, 3, { "is_superuser",    "is_owner_member", "is_owner_member" } },
    { PGRES_TUPLES_OK,   1, 2, { "is_owner_member", "is_superuser",    NULL              } },
    { PGRES_TUPLES_OK,   1, 1, { "is_superuser",    NULL,              NULL              } },
  };

  for (size_t row = 0; row < sizeof(shapes) / sizeof(shapes[0]); row++)
  {
    static_resetFake();
    FakeAnswer_t* answer = static_queueAnswer(shapes[row].m_status, shapes[row].m_columnCount, shapes[row].m_rowCount);
    for (int column = 0; column < shapes[row].m_columnCount; column++)
    {
      answer->ma_columnNames[column] = shapes[row].ma_names[column];
      for (int tuple = 0; tuple < shapes[row].m_rowCount; tuple++)
        answer->ma_cells[tuple][column] = "f";
    }
    char message[16] = "";
    snprintf(message, sizeof(message), "row %zu", row);
    DbConnectionRoleState_t state = { 0 };

    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_ERROR, db_readConnectionRoleState(NULL, &state), message);
  }
}

void test_readConnectionRoleState_calls_the_api_function(void)
{
  static_queueRoleStateRow("f", "f");
  DbConnectionRoleState_t state = { 0 };

  TEST_ASSERT_EQUAL_INT(DB_OK, db_readConnectionRoleState(NULL, &state));

  TEST_ASSERT_EQUAL_INT(1, g_callCount);
  TEST_ASSERT_EQUAL_STRING("SELECT * FROM api.fn_connection_role_state()", static_lastCall()->ma_command);
  TEST_ASSERT_EQUAL_INT(0, static_lastCall()->m_paramCount);
  TEST_ASSERT_EQUAL_INT(0, static_lastCall()->m_resultFormat);
}

static const char g_apiKeyHash[] = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

static const DbApiKeyExpiry_t g_apiKeyExpiryUntouched = { true, 99 };

static void static_queueApiKeyStateAnswer(const char* state_cell, const char* expires_cell)
{
  FakeAnswer_t* answer = static_queueAnswer(PGRES_TUPLES_OK, 2, 1);
  answer->ma_columnNames[0] = "api_key_state";
  answer->ma_columnNames[1] = "key_expires_at";
  answer->ma_cells[0][0]    = state_cell;
  answer->ma_cells[0][1]    = expires_cell;
}

void test_readApiKeyState_reads_the_three_states(void)
{
  static const struct {
    const char*     mp_cell;
    DbStatus_t      m_status;
    DbApiKeyState_t m_state;
  } rows[] = {
    { "active",      DB_OK,    DB_API_KEY_ACTIVE   },
    { "inactive",    DB_OK,    DB_API_KEY_INACTIVE },
    { "unknown",     DB_OK,    DB_API_KEY_UNKNOWN  },
    { "Active",      DB_ERROR, DB_API_KEY_UNKNOWN  },
    { "activ",       DB_ERROR, DB_API_KEY_UNKNOWN  },
    { "inactivex",   DB_ERROR, DB_API_KEY_UNKNOWN  },
    { "activex",     DB_ERROR, DB_API_KEY_UNKNOWN  },
    { "unknownx",    DB_ERROR, DB_API_KEY_UNKNOWN  },
    { "",            DB_ERROR, DB_API_KEY_UNKNOWN  },
    { FAKE_SQL_NULL, DB_ERROR, DB_API_KEY_UNKNOWN  },
  };

  for (size_t row = 0; row < sizeof(rows) / sizeof(rows[0]); row++)
  {
    static_resetFake();
    static_queueApiKeyStateAnswer(rows[row].mp_cell, FAKE_SQL_NULL);
    char message[16] = "";
    snprintf(message, sizeof(message), "row %zu", row);
    DbApiKeyState_t  state  = (rows[row].m_state == DB_API_KEY_ACTIVE) ? DB_API_KEY_UNKNOWN : DB_API_KEY_ACTIVE;
    DbApiKeyExpiry_t expiry = g_apiKeyExpiryUntouched;

    DbStatus_t db_status = db_readApiKeyState(NULL, g_apiKeyHash, &state, &expiry);

    TEST_ASSERT_EQUAL_INT_MESSAGE(rows[row].m_status, db_status, message);
    if (db_status == DB_OK)
    {
      TEST_ASSERT_EQUAL_INT_MESSAGE(rows[row].m_state, state, message);
      TEST_ASSERT_FALSE_MESSAGE(expiry.m_hasExpiry, message);
      TEST_ASSERT_EQUAL_INT64_MESSAGE(0, expiry.m_expiresAt, message);
    }
    else
    {
      TEST_ASSERT_TRUE_MESSAGE(expiry.m_hasExpiry, message);
      TEST_ASSERT_EQUAL_INT64_MESSAGE(99, expiry.m_expiresAt, message);
    }
  }
}

void test_readApiKeyState_reads_the_expiry(void)
{
  static const struct {
    const char*     mp_state;
    const char*     mp_expires;
    DbStatus_t      m_status;
    DbApiKeyState_t m_state;
    bool            m_hasExpiry;
    int64_t         m_expiresAt;
  } rows[] = {
    { "active",   FAKE_SQL_NULL,          DB_OK,    DB_API_KEY_ACTIVE,   false, 0 },
    { "active",   "1798761600",           DB_OK,    DB_API_KEY_ACTIVE,   true,  1798761600 },
    { "active",   "4102444800",           DB_OK,    DB_API_KEY_ACTIVE,   true,  4102444800 },
    { "active",   "9223372036854775807",  DB_OK,    DB_API_KEY_ACTIVE,   true,  INT64_MAX },
    { "inactive", "0",                    DB_OK,    DB_API_KEY_INACTIVE, true,  0 },
    { "inactive", "-1",                   DB_OK,    DB_API_KEY_INACTIVE, true,  -1 },
    { "unknown",  FAKE_SQL_NULL,          DB_OK,    DB_API_KEY_UNKNOWN,  false, 0 },
    { "active",   "",                     DB_ERROR, DB_API_KEY_UNKNOWN,  false, 0 },
    { "active",   "12abc",                DB_ERROR, DB_API_KEY_UNKNOWN,  false, 0 },
    { "active",   "4.5",                  DB_ERROR, DB_API_KEY_UNKNOWN,  false, 0 },
    { "active",   "9223372036854775808",  DB_ERROR, DB_API_KEY_UNKNOWN,  false, 0 },
  };

  for (size_t row = 0; row < sizeof(rows) / sizeof(rows[0]); row++)
  {
    static_resetFake();
    static_queueApiKeyStateAnswer(rows[row].mp_state, rows[row].mp_expires);
    char message[16] = "";
    snprintf(message, sizeof(message), "row %zu", row);
    DbApiKeyState_t  state  = DB_API_KEY_UNKNOWN;
    DbApiKeyExpiry_t expiry = g_apiKeyExpiryUntouched;

    DbStatus_t db_status = db_readApiKeyState(NULL, g_apiKeyHash, &state, &expiry);

    TEST_ASSERT_EQUAL_INT_MESSAGE(rows[row].m_status, db_status, message);
    if (db_status == DB_OK)
    {
      TEST_ASSERT_EQUAL_INT_MESSAGE(rows[row].m_state, state, message);
      TEST_ASSERT_EQUAL_MESSAGE(rows[row].m_hasExpiry, expiry.m_hasExpiry, message);
      TEST_ASSERT_EQUAL_INT64_MESSAGE(rows[row].m_expiresAt, expiry.m_expiresAt, message);
    }
    else
    {
      TEST_ASSERT_EQUAL_INT_MESSAGE(DB_API_KEY_UNKNOWN, state, message);
      TEST_ASSERT_TRUE_MESSAGE(expiry.m_hasExpiry, message);
      TEST_ASSERT_EQUAL_INT64_MESSAGE(99, expiry.m_expiresAt, message);
    }
  }
}

typedef enum {
  API_KEY_STATE_SHAPE_FAILED_QUERY,
  API_KEY_STATE_SHAPE_DEFAULT_ROW,
  API_KEY_STATE_SHAPE_NO_ROW,
  API_KEY_STATE_SHAPE_TWO_ROWS,
  API_KEY_STATE_SHAPE_STATE_ONLY,
  API_KEY_STATE_SHAPE_THREE_COLUMNS,
  API_KEY_STATE_SHAPE_SWAPPED_NAMES,
  API_KEY_STATE_SHAPE_OTHER_FIRST_NAME,
  API_KEY_STATE_SHAPE_OTHER_SECOND_NAME
} ApiKeyStateShape_t;

static void static_queueApiKeyStateShape(ApiKeyStateShape_t shape)
{
  FakeAnswer_t* answer = NULL;
  switch (shape)
  {
    case API_KEY_STATE_SHAPE_FAILED_QUERY:
      static_queueAnswer(PGRES_FATAL_ERROR, 0, 0);
      break;
    case API_KEY_STATE_SHAPE_DEFAULT_ROW:
      break;
    case API_KEY_STATE_SHAPE_NO_ROW:
      answer = static_queueAnswer(PGRES_TUPLES_OK, 2, 0);
      answer->ma_columnNames[0] = "api_key_state";
      answer->ma_columnNames[1] = "key_expires_at";
      break;
    case API_KEY_STATE_SHAPE_TWO_ROWS:
      answer = static_queueAnswer(PGRES_TUPLES_OK, 2, 2);
      answer->ma_columnNames[0] = "api_key_state";
      answer->ma_columnNames[1] = "key_expires_at";
      answer->ma_cells[0][0]    = "active";
      answer->ma_cells[0][1]    = "1798761600";
      answer->ma_cells[1][0]    = "active";
      answer->ma_cells[1][1]    = "1798761600";
      break;
    case API_KEY_STATE_SHAPE_STATE_ONLY:
      static_queueOneCell("api_key_state", "active");
      break;
    case API_KEY_STATE_SHAPE_THREE_COLUMNS:
      answer = static_queueAnswer(PGRES_TUPLES_OK, 3, 1);
      answer->ma_columnNames[0] = "api_key_state";
      answer->ma_columnNames[1] = "key_expires_at";
      answer->ma_columnNames[2] = "key_expires_at";
      answer->ma_cells[0][0]    = "active";
      answer->ma_cells[0][1]    = "1798761600";
      answer->ma_cells[0][2]    = "1798761600";
      break;
    case API_KEY_STATE_SHAPE_SWAPPED_NAMES:
      answer = static_queueAnswer(PGRES_TUPLES_OK, 2, 1);
      answer->ma_columnNames[0] = "key_expires_at";
      answer->ma_columnNames[1] = "api_key_state";
      answer->ma_cells[0][0]    = "1798761600";
      answer->ma_cells[0][1]    = "active";
      break;
    case API_KEY_STATE_SHAPE_OTHER_FIRST_NAME:
      answer = static_queueAnswer(PGRES_TUPLES_OK, 2, 1);
      answer->ma_columnNames[0] = "state";
      answer->ma_columnNames[1] = "key_expires_at";
      answer->ma_cells[0][0]    = "active";
      answer->ma_cells[0][1]    = "1798761600";
      break;
    case API_KEY_STATE_SHAPE_OTHER_SECOND_NAME:
      answer = static_queueAnswer(PGRES_TUPLES_OK, 2, 1);
      answer->ma_columnNames[0] = "api_key_state";
      answer->ma_columnNames[1] = "expires_at";
      answer->ma_cells[0][0]    = "active";
      answer->ma_cells[0][1]    = "1798761600";
      break;
  }
}

void test_readApiKeyState_refuses_any_other_answer(void)
{
  static const ApiKeyStateShape_t shapes[] = {
    API_KEY_STATE_SHAPE_FAILED_QUERY,
    API_KEY_STATE_SHAPE_DEFAULT_ROW,
    API_KEY_STATE_SHAPE_NO_ROW,
    API_KEY_STATE_SHAPE_TWO_ROWS,
    API_KEY_STATE_SHAPE_STATE_ONLY,
    API_KEY_STATE_SHAPE_THREE_COLUMNS,
    API_KEY_STATE_SHAPE_SWAPPED_NAMES,
    API_KEY_STATE_SHAPE_OTHER_FIRST_NAME,
    API_KEY_STATE_SHAPE_OTHER_SECOND_NAME,
  };

  for (size_t row = 0; row < sizeof(shapes) / sizeof(shapes[0]); row++)
  {
    static_resetFake();
    static_queueApiKeyStateShape(shapes[row]);
    char message[16] = "";
    snprintf(message, sizeof(message), "row %zu", row);
    DbApiKeyState_t  state  = DB_API_KEY_UNKNOWN;
    DbApiKeyExpiry_t expiry = g_apiKeyExpiryUntouched;

    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_ERROR, db_readApiKeyState(NULL, g_apiKeyHash, &state, &expiry), message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_API_KEY_UNKNOWN, state, message);
    TEST_ASSERT_TRUE_MESSAGE(expiry.m_hasExpiry, message);
    TEST_ASSERT_EQUAL_INT64_MESSAGE(99, expiry.m_expiresAt, message);
  }
}

void test_readApiKeyState_sends_the_hash_to_the_api_function(void)
{
  static_queueApiKeyStateAnswer("active", FAKE_SQL_NULL);
  DbApiKeyState_t  state  = DB_API_KEY_UNKNOWN;
  DbApiKeyExpiry_t expiry = g_apiKeyExpiryUntouched;

  TEST_ASSERT_EQUAL_INT(DB_OK, db_readApiKeyState(NULL, g_apiKeyHash, &state, &expiry));

  TEST_ASSERT_EQUAL_INT(1, g_callCount);
  TEST_ASSERT_EQUAL_STRING("SELECT * FROM api.fn_api_key_state($1)", static_lastCall()->ma_command);
  TEST_ASSERT_EQUAL_INT(1, static_lastCall()->m_paramCount);
  TEST_ASSERT_FALSE(static_lastCall()->ma_isParamNull[0]);
  TEST_ASSERT_EQUAL_STRING(g_apiKeyHash, static_lastCall()->ma_params[0]);
  TEST_ASSERT_EQUAL_INT(0, static_lastCall()->m_resultFormat);
}

static const char g_billingEventRef[] = "e0000000-0000-4000-8000-000000000001";
static const char g_billingOrderId[]  = "a0000000-0000-4000-8000-000000000001";

static BillingLemonSqueezyEvent_t static_billingEvent(int64_t updated_at, int64_t ends_at)
{
  BillingLemonSqueezyEvent_t event = {
    .m_action            = BILLING_ACTION_IGNORE,
    .mp_eventName        = "subscription_expired",
    .m_providerUpdatedAt = updated_at,
    .m_endsAt            = ends_at,
  };
  snprintf(event.ma_webhookId,               sizeof(event.ma_webhookId),               "%s", g_billingEventRef);
  snprintf(event.ma_orderId,                 sizeof(event.ma_orderId),                 "%s", g_billingOrderId);
  snprintf(event.ma_providerOrderRef,        sizeof(event.ma_providerOrderRef),        "%s", "9915543");
  snprintf(event.ma_providerSubscriptionRef, sizeof(event.ma_providerSubscriptionRef), "%s", "1712834");
  return event;
}

static const DbBillingEventStatus_t g_billingEventStatusUntouched = (DbBillingEventStatus_t)-1;
static const DbBillingClaimStatus_t g_billingClaimStatusUntouched = (DbBillingClaimStatus_t)-1;

typedef enum {
  BILLING_EVENT_CALL_ORDER_PAID,
  BILLING_EVENT_CALL_SET_EXPIRY,
  BILLING_EVENT_CALL_CLEAR_EXPIRY,
  BILLING_EVENT_CALL_REVOKE,
  BILLING_EVENT_CALL_RECORD,
} BillingEventCall_t;

static const BillingEventCall_t g_billingEventCalls[] = {
  BILLING_EVENT_CALL_ORDER_PAID,
  BILLING_EVENT_CALL_SET_EXPIRY,
  BILLING_EVENT_CALL_CLEAR_EXPIRY,
  BILLING_EVENT_CALL_REVOKE,
  BILLING_EVENT_CALL_RECORD,
};

static DbStatus_t static_runBillingEventCall(BillingEventCall_t call, DbBillingEventStatus_t* status_out)
{
  const BillingLemonSqueezyEvent_t event = static_billingEvent(1793506844, 1796185244);
  switch (call)
  {
    case BILLING_EVENT_CALL_ORDER_PAID:
      return db_billingLemonSqueezyOrderPaid(NULL, &event, status_out);
    case BILLING_EVENT_CALL_SET_EXPIRY:
      return db_billingLemonSqueezySetExpiry(NULL, &event, status_out);
    case BILLING_EVENT_CALL_CLEAR_EXPIRY:
      return db_billingLemonSqueezyClearExpiry(NULL, &event, status_out);
    case BILLING_EVENT_CALL_REVOKE:
      return db_billingLemonSqueezyRevoke(NULL, &event, status_out);
    case BILLING_EVENT_CALL_RECORD:
      return db_billingLemonSqueezyEventRecord(NULL, &event, status_out);
  }
  return DB_ERROR;
}

void test_billing_event_calls_send_their_text_and_params(void)
{
  static const struct {
    BillingEventCall_t m_call;
    const char*        mp_command;
    int                m_paramCount;
    const char*        ma_params[5];
  } rows[] = {
    { BILLING_EVENT_CALL_ORDER_PAID,   "SELECT api.fn_billing_lemonsqueezy_order_paid($1, $2, $3) AS billing_event_status", 3,
      { g_billingEventRef, g_billingOrderId, "9915543" } },
    { BILLING_EVENT_CALL_SET_EXPIRY,   "SELECT api.fn_billing_lemonsqueezy_set_expiry($1, $2, $3, $4, $5) AS billing_event_status", 5,
      { g_billingEventRef, "9915543", "1712834", "1793506844", "1796185244" } },
    { BILLING_EVENT_CALL_CLEAR_EXPIRY, "SELECT api.fn_billing_lemonsqueezy_clear_expiry($1, $2, $3, $4) AS billing_event_status", 4,
      { g_billingEventRef, "9915543", "1712834", "1793506844" } },
    { BILLING_EVENT_CALL_REVOKE,       "SELECT api.fn_billing_lemonsqueezy_revoke($1, $2, $3) AS billing_event_status", 3,
      { g_billingEventRef, "subscription_expired", "9915543" } },
    { BILLING_EVENT_CALL_RECORD,       "SELECT api.fn_billing_event_record($1, $2, $3, $4, $5) AS billing_event_status", 5,
      { "lemonsqueezy", g_billingEventRef, "subscription_expired", "9915543", "1712834" } },
  };

  for (size_t row = 0; row < sizeof(rows) / sizeof(rows[0]); row++)
  {
    static_resetFake();
    static_queueOneCell("billing_event_status", "applied");
    char message[16] = "";
    snprintf(message, sizeof(message), "row %zu", row);
    DbBillingEventStatus_t status = g_billingEventStatusUntouched;

    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_OK, static_runBillingEventCall(rows[row].m_call, &status), message);

    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_BILLING_EVENT_APPLIED, status, message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_callCount, message);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(rows[row].mp_command, static_lastCall()->ma_command, message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(rows[row].m_paramCount, static_lastCall()->m_paramCount, message);
    for (int n = 0; n < rows[row].m_paramCount; n++)
    {
      TEST_ASSERT_FALSE_MESSAGE(static_lastCall()->ma_isParamNull[n], message);
      TEST_ASSERT_EQUAL_STRING_MESSAGE(rows[row].ma_params[n], static_lastCall()->ma_params[n], message);
    }
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, static_lastCall()->m_resultFormat, message);
  }
}

void test_billing_nowpayments_order_paid_sends_its_text_and_params(void)
{
  static_resetFake();
  static_queueOneCell("billing_event_status", "exists");
  DbBillingEventStatus_t status = g_billingEventStatusUntouched;

  TEST_ASSERT_EQUAL_INT(DB_OK, db_billingNowPaymentsOrderPaid(NULL, "paid:77", "finished", g_billingOrderId, "77", &status));

  TEST_ASSERT_EQUAL_INT(DB_BILLING_EVENT_EXISTS, status);
  TEST_ASSERT_EQUAL_INT(1, g_callCount);
  TEST_ASSERT_EQUAL_STRING("SELECT api.fn_billing_nowpayments_order_paid($1, $2, $3, $4) AS billing_event_status", static_lastCall()->ma_command);
  TEST_ASSERT_EQUAL_INT(4, static_lastCall()->m_paramCount);
  TEST_ASSERT_EQUAL_STRING("paid:77", static_lastCall()->ma_params[0]);
  TEST_ASSERT_EQUAL_STRING("finished", static_lastCall()->ma_params[1]);
  TEST_ASSERT_EQUAL_STRING(g_billingOrderId, static_lastCall()->ma_params[2]);
  TEST_ASSERT_EQUAL_STRING("77", static_lastCall()->ma_params[3]);
  for (int n = 0; n < 4; n++)
    TEST_ASSERT_FALSE(static_lastCall()->ma_isParamNull[n]);
}

void test_billing_nowpayments_order_paid_refuses_a_wrong_answer(void)
{
  DbBillingEventStatus_t status = g_billingEventStatusUntouched;

  static_resetFake();
  static_queueOneCell("other_column", "applied");
  TEST_ASSERT_EQUAL_INT(DB_ERROR, db_billingNowPaymentsOrderPaid(NULL, "paid:77", "finished", g_billingOrderId, "77", &status));
  TEST_ASSERT_EQUAL_INT(g_billingEventStatusUntouched, status);

  static_resetFake();
  static_queueOneCell("billing_event_status", "created");
  TEST_ASSERT_EQUAL_INT(DB_ERROR, db_billingNowPaymentsOrderPaid(NULL, "paid:77", "finished", g_billingOrderId, "77", &status));
  TEST_ASSERT_EQUAL_INT(g_billingEventStatusUntouched, status);
}

void test_billing_expiry_calls_send_each_time_as_decimal_text(void)
{
  static const struct {
    int64_t     m_updatedAt;
    int64_t     m_expiresAt;
    const char* mp_updatedAt;
    const char* mp_expiresAt;
  } rows[] = {
    { 0,          1,          "0",                    "1" },
    { 4102444800, -1,         "4102444800",           "-1" },
    { INT64_MAX,  INT64_MIN,  "9223372036854775807",  "-9223372036854775808" },
    { INT64_MIN,  INT64_MAX,  "-9223372036854775808", "9223372036854775807" },
  };

  for (size_t row = 0; row < sizeof(rows) / sizeof(rows[0]); row++)
  {
    static_resetFake();
    static_queueOneCell("billing_event_status", "applied");
    static_queueOneCell("billing_event_status", "applied");
    char message[16] = "";
    snprintf(message, sizeof(message), "row %zu", row);
    DbBillingEventStatus_t status = g_billingEventStatusUntouched;
    const BillingLemonSqueezyEvent_t event = static_billingEvent(rows[row].m_updatedAt, rows[row].m_expiresAt);

    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_OK, db_billingLemonSqueezySetExpiry(NULL, &event, &status), message);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(rows[row].mp_updatedAt, static_call(0)->ma_params[3], message);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(rows[row].mp_expiresAt, static_call(0)->ma_params[4], message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_OK, db_billingLemonSqueezyClearExpiry(NULL, &event, &status), message);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(rows[row].mp_updatedAt, static_call(1)->ma_params[3], message);
  }
}

void test_billingEventRecord_sends_an_empty_ref_as_null(void)
{
  static const struct {
    const char* mp_orderRef;
    const char* mp_subscriptionRef;
  } rows[] = {
    { "",        "" },
    { "9915543", "" },
    { "",        "1712834" },
    { "9915543", "1712834" },
  };

  for (size_t row = 0; row < sizeof(rows) / sizeof(rows[0]); row++)
  {
    static_resetFake();
    static_queueOneCell("billing_event_status", "duplicate");
    char message[16] = "";
    snprintf(message, sizeof(message), "row %zu", row);
    DbBillingEventStatus_t status = g_billingEventStatusUntouched;
    BillingLemonSqueezyEvent_t event = static_billingEvent(0, 0);
    snprintf(event.ma_providerOrderRef,        sizeof(event.ma_providerOrderRef),        "%s", rows[row].mp_orderRef);
    snprintf(event.ma_providerSubscriptionRef, sizeof(event.ma_providerSubscriptionRef), "%s", rows[row].mp_subscriptionRef);

    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_OK, db_billingLemonSqueezyEventRecord(NULL, &event, &status), message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_BILLING_EVENT_DUPLICATE, status, message);
    TEST_ASSERT_EQUAL_STRING_MESSAGE("lemonsqueezy", static_lastCall()->ma_params[0], message);
    TEST_ASSERT_EQUAL_MESSAGE(rows[row].mp_orderRef[0] == '\0', static_lastCall()->ma_isParamNull[3], message);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(rows[row].mp_orderRef, static_lastCall()->ma_params[3], message);
    TEST_ASSERT_EQUAL_MESSAGE(rows[row].mp_subscriptionRef[0] == '\0', static_lastCall()->ma_isParamNull[4], message);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(rows[row].mp_subscriptionRef, static_lastCall()->ma_params[4], message);
  }
}

void test_billing_event_calls_read_each_status(void)
{
  static const struct {
    const char*            mp_cell;
    DbStatus_t             m_status;
    DbBillingEventStatus_t m_eventStatus;
  } rows[] = {
    { "applied",       DB_OK,    DB_BILLING_EVENT_APPLIED },
    { "duplicate",     DB_OK,    DB_BILLING_EVENT_DUPLICATE },
    { "exists",        DB_OK,    DB_BILLING_EVENT_EXISTS },
    { "stale",         DB_OK,    DB_BILLING_EVENT_STALE },
    { "revoked",       DB_OK,    DB_BILLING_EVENT_ORDER_REVOKED },
    { "unknown",       DB_OK,    DB_BILLING_EVENT_UNKNOWN_ORDER },
    { "applie",        DB_ERROR, DB_BILLING_EVENT_APPLIED },
    { "duplicatex",    DB_ERROR, DB_BILLING_EVENT_APPLIED },
    { "Applied",       DB_ERROR, DB_BILLING_EVENT_APPLIED },
    { "applied ",      DB_ERROR, DB_BILLING_EVENT_APPLIED },
    { "claimed",       DB_ERROR, DB_BILLING_EVENT_APPLIED },
    { "unknown_key",   DB_ERROR, DB_BILLING_EVENT_APPLIED },
    { "",              DB_ERROR, DB_BILLING_EVENT_APPLIED },
    { FAKE_SQL_NULL,   DB_ERROR, DB_BILLING_EVENT_APPLIED },
  };

  for (size_t c = 0; c < sizeof(g_billingEventCalls) / sizeof(g_billingEventCalls[0]); c++)
  {
    for (size_t row = 0; row < sizeof(rows) / sizeof(rows[0]); row++)
    {
      static_resetFake();
      static_queueOneCell("billing_event_status", rows[row].mp_cell);
      char message[32] = "";
      snprintf(message, sizeof(message), "call %zu row %zu", c, row);
      DbBillingEventStatus_t status = g_billingEventStatusUntouched;

      DbStatus_t db_status = static_runBillingEventCall(g_billingEventCalls[c], &status);

      TEST_ASSERT_EQUAL_INT_MESSAGE(rows[row].m_status, db_status, message);
      TEST_ASSERT_EQUAL_INT_MESSAGE(db_status == DB_OK ? (int)rows[row].m_eventStatus : (int)g_billingEventStatusUntouched, (int)status, message);
    }
  }
}

void test_billingEventStatusText_gives_each_answer_text(void)
{
  static const struct {
    DbBillingEventStatus_t m_status;
    const char*            mp_text;
  } rows[] = {
    { DB_BILLING_EVENT_APPLIED,       "applied" },
    { DB_BILLING_EVENT_DUPLICATE,     "duplicate" },
    { DB_BILLING_EVENT_EXISTS,        "exists" },
    { DB_BILLING_EVENT_STALE,         "stale" },
    { DB_BILLING_EVENT_ORDER_REVOKED, "revoked" },
    { DB_BILLING_EVENT_UNKNOWN_ORDER, "unknown" },
  };

  for (size_t row = 0; row < sizeof(rows) / sizeof(rows[0]); row++)
    TEST_ASSERT_EQUAL_STRING(rows[row].mp_text, db_billingEventStatusText(rows[row].m_status));
  TEST_ASSERT_EQUAL_STRING("", db_billingEventStatusText((DbBillingEventStatus_t)(DB_BILLING_EVENT_UNKNOWN_ORDER + 1)));
}

void test_billing_event_calls_refuse_any_other_answer(void)
{
  for (size_t c = 0; c < sizeof(g_billingEventCalls) / sizeof(g_billingEventCalls[0]); c++)
  {
    for (size_t shape = 0; shape <= sizeof(g_wrongShapes) / sizeof(g_wrongShapes[0]); shape++)
    {
      static_resetFake();
      if (shape < sizeof(g_wrongShapes) / sizeof(g_wrongShapes[0]))
        static_queueWrongShape(g_wrongShapes[shape], "billing_event_status", "applied");
      else
        static_queueOneCell("billing_claim_status", "applied");
      char message[32] = "";
      snprintf(message, sizeof(message), "call %zu shape %zu", c, shape);
      DbBillingEventStatus_t status = g_billingEventStatusUntouched;

      TEST_ASSERT_EQUAL_INT_MESSAGE(DB_ERROR, static_runBillingEventCall(g_billingEventCalls[c], &status), message);
      TEST_ASSERT_EQUAL_INT_MESSAGE((int)g_billingEventStatusUntouched, (int)status, message);
    }
  }
}

void test_billingClaim_sends_its_text_and_params(void)
{
  static_queueOneCell("billing_claim_status", "claimed");
  DbBillingClaimStatus_t status = g_billingClaimStatusUntouched;

  TEST_ASSERT_EQUAL_INT(DB_OK, db_billingClaim(NULL, g_billingOrderId, g_apiKeyHash, &status));

  TEST_ASSERT_EQUAL_INT(DB_BILLING_CLAIM_CLAIMED, status);
  TEST_ASSERT_EQUAL_INT(1, g_callCount);
  TEST_ASSERT_EQUAL_STRING("SELECT api.fn_billing_claim($1, $2) AS billing_claim_status", static_lastCall()->ma_command);
  TEST_ASSERT_EQUAL_INT(2, static_lastCall()->m_paramCount);
  TEST_ASSERT_FALSE(static_lastCall()->ma_isParamNull[0]);
  TEST_ASSERT_FALSE(static_lastCall()->ma_isParamNull[1]);
  TEST_ASSERT_EQUAL_STRING(g_billingOrderId, static_lastCall()->ma_params[0]);
  TEST_ASSERT_EQUAL_STRING(g_apiKeyHash, static_lastCall()->ma_params[1]);
  TEST_ASSERT_EQUAL_INT(0, static_lastCall()->m_resultFormat);
}

void test_billingClaim_reads_each_status(void)
{
  static const struct {
    const char*            mp_cell;
    DbStatus_t             m_status;
    DbBillingClaimStatus_t m_claimStatus;
  } rows[] = {
    { "claimed",          DB_OK,    DB_BILLING_CLAIM_CLAIMED },
    { "already_claimed",  DB_OK,    DB_BILLING_CLAIM_ALREADY_CLAIMED },
    { "lapsed",           DB_OK,    DB_BILLING_CLAIM_LAPSED },
    { "revoked",          DB_OK,    DB_BILLING_CLAIM_REVOKED },
    { "unknown",          DB_OK,    DB_BILLING_CLAIM_UNKNOWN },
    { "already_claimedx", DB_ERROR, DB_BILLING_CLAIM_CLAIMED },
    { "claime",           DB_ERROR, DB_BILLING_CLAIM_CLAIMED },
    { "Claimed",          DB_ERROR, DB_BILLING_CLAIM_CLAIMED },
    { "applied",          DB_ERROR, DB_BILLING_CLAIM_CLAIMED },
    { "unknown_key",      DB_ERROR, DB_BILLING_CLAIM_CLAIMED },
    { "",                 DB_ERROR, DB_BILLING_CLAIM_CLAIMED },
    { FAKE_SQL_NULL,      DB_ERROR, DB_BILLING_CLAIM_CLAIMED },
  };

  for (size_t row = 0; row < sizeof(rows) / sizeof(rows[0]); row++)
  {
    static_resetFake();
    static_queueOneCell("billing_claim_status", rows[row].mp_cell);
    char message[16] = "";
    snprintf(message, sizeof(message), "row %zu", row);
    DbBillingClaimStatus_t status = g_billingClaimStatusUntouched;

    DbStatus_t db_status = db_billingClaim(NULL, g_billingOrderId, g_apiKeyHash, &status);

    TEST_ASSERT_EQUAL_INT_MESSAGE(rows[row].m_status, db_status, message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(db_status == DB_OK ? (int)rows[row].m_claimStatus : (int)g_billingClaimStatusUntouched, (int)status, message);
  }
}

void test_billingClaim_refuses_any_other_answer(void)
{
  for (size_t shape = 0; shape <= sizeof(g_wrongShapes) / sizeof(g_wrongShapes[0]); shape++)
  {
    static_resetFake();
    if (shape < sizeof(g_wrongShapes) / sizeof(g_wrongShapes[0]))
      static_queueWrongShape(g_wrongShapes[shape], "billing_claim_status", "claimed");
    else
      static_queueOneCell("billing_event_status", "claimed");
    char message[16] = "";
    snprintf(message, sizeof(message), "shape %zu", shape);
    DbBillingClaimStatus_t status = g_billingClaimStatusUntouched;

    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_ERROR, db_billingClaim(NULL, g_billingOrderId, g_apiKeyHash, &status), message);
    TEST_ASSERT_EQUAL_INT_MESSAGE((int)g_billingClaimStatusUntouched, (int)status, message);
  }
}

void test_billing_status_one_byte_past_its_limit_logs_the_limit(void)
{
  for (size_t c = 0; c < sizeof(g_billingEventCalls) / sizeof(g_billingEventCalls[0]); c++)
  {
    static_resetFake();
    static_clearLogLimit();
    static_queueOneCell("billing_event_status", "duplicatex");
    char message[16] = "";
    snprintf(message, sizeof(message), "call %zu", c);
    DbBillingEventStatus_t status = g_billingEventStatusUntouched;
    StderrCapture_t capture;
    static_beginStderrCapture(&capture);

    DbStatus_t db_status = static_runBillingEventCall(g_billingEventCalls[c], &status);

    char line[256];
    static_endStderrCapture(&capture, line, sizeof(line));
    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_ERROR, db_status, message);
    TEST_ASSERT_EQUAL_INT_MESSAGE((int)g_billingEventStatusUntouched, (int)status, message);
    TEST_ASSERT_EQUAL_STRING_MESSAGE("dbhelper_fetchColStr: column billing_event_status (index 0) holds 10 bytes, limit 9\n", line, message);
  }

  static_resetFake();
  static_clearLogLimit();
  static_queueOneCell("billing_claim_status", "already_claimedx");
  DbBillingClaimStatus_t claim_status = g_billingClaimStatusUntouched;
  StderrCapture_t capture;
  static_beginStderrCapture(&capture);

  DbStatus_t db_status = db_billingClaim(NULL, g_billingOrderId, g_apiKeyHash, &claim_status);

  char line[256];
  static_endStderrCapture(&capture, line, sizeof(line));
  TEST_ASSERT_EQUAL_INT(DB_ERROR, db_status);
  TEST_ASSERT_EQUAL_INT((int)g_billingClaimStatusUntouched, (int)claim_status);
  TEST_ASSERT_EQUAL_STRING("dbhelper_fetchColStr: column billing_claim_status (index 0) holds 16 bytes, limit 15\n", line);
}

static const char g_vendorKeyFingerprint[] = "00112233445566778899aabbccddeeff";
static const char g_vendorKeyLinkHash[]   = "6c86c6aac5fb24bcf5d9939cb7d7d5645ce39418f449e03b262dd4fa14b4b92b";

#define VENDOR_KEY_LINK_STATE_UNTOUCHED ((DbVendorKeyLinkState_t)99)
#define VENDOR_KEY_APPLY_STATUS_UNTOUCHED     ((DbVendorKeyApplyStatus_t)99)

static void static_vendorKeysUntouched(DbVendorKeys_t* vendor_keys)
{
  vendor_keys->m_apiKeyId = 77;
  snprintf(vendor_keys->ma_keyFingerprint, sizeof(vendor_keys->ma_keyFingerprint), "%s", "untouched");
  snprintf(vendor_keys->ma_shodanSealedHex, sizeof(vendor_keys->ma_shodanSealedHex), "%s", "untouched");
  snprintf(vendor_keys->ma_abuseIpDbSealedHex, sizeof(vendor_keys->ma_abuseIpDbSealedHex), "%s", "untouched");
}

static void static_assertVendorKeysUntouched(const DbVendorKeys_t* vendor_keys, const char* message)
{
  TEST_ASSERT_EQUAL_INT64_MESSAGE(77, vendor_keys->m_apiKeyId, message);
  TEST_ASSERT_EQUAL_STRING_MESSAGE("untouched", vendor_keys->ma_keyFingerprint, message);
  TEST_ASSERT_EQUAL_STRING_MESSAGE("untouched", vendor_keys->ma_shodanSealedHex, message);
  TEST_ASSERT_EQUAL_STRING_MESSAGE("untouched", vendor_keys->ma_abuseIpDbSealedHex, message);
}

static void static_queueVendorKeyReadAnswer(const char* api_key_id_cell, const char* key_fingerprint_cell,
                                            const char* shodan_cell, const char* abuseipdb_cell)
{
  FakeAnswer_t* answer = static_queueAnswer(PGRES_TUPLES_OK, 4, 1);
  answer->ma_columnNames[0] = "api_key_id";
  answer->ma_columnNames[1] = "key_fingerprint";
  answer->ma_columnNames[2] = "shodan_sealed_hex";
  answer->ma_columnNames[3] = "abuseipdb_sealed_hex";
  answer->ma_cells[0][0]    = api_key_id_cell;
  answer->ma_cells[0][1]    = key_fingerprint_cell;
  answer->ma_cells[0][2]    = shodan_cell;
  answer->ma_cells[0][3]    = abuseipdb_cell;
}

static void static_queueVendorKeyLinkReadAnswer(const char* state_cell, const char* api_key_id_cell, const char* link_expires_at_cell,
                                                const char* shodan_cell, const char* abuseipdb_cell)
{
  FakeAnswer_t* answer = static_queueAnswer(PGRES_TUPLES_OK, 5, 1);
  answer->ma_columnNames[0] = "link_state";
  answer->ma_columnNames[1] = "api_key_id";
  answer->ma_columnNames[2] = "link_expires_at";
  answer->ma_columnNames[3] = "shodan_sealed_hex";
  answer->ma_columnNames[4] = "abuseipdb_sealed_hex";
  answer->ma_cells[0][0]    = state_cell;
  answer->ma_cells[0][1]    = api_key_id_cell;
  answer->ma_cells[0][2]    = link_expires_at_cell;
  answer->ma_cells[0][3]    = shodan_cell;
  answer->ma_cells[0][4]    = abuseipdb_cell;
}

static void static_sealedHexOfLength(char* buf, size_t length)
{
  memset(buf, 'a', length);
  buf[length] = '\0';
}

void test_readVendorKeys_sends_the_hash_and_reads_each_column(void)
{
  static_queueVendorKeyReadAnswer("4242", g_vendorKeyFingerprint, "01aa", "01bb");
  DbVendorKeys_t vendor_keys;
  static_vendorKeysUntouched(&vendor_keys);

  TEST_ASSERT_EQUAL_INT(DB_OK, db_readVendorKeys(NULL, g_apiKeyHash, &vendor_keys));

  TEST_ASSERT_EQUAL_INT(1, g_callCount);
  TEST_ASSERT_EQUAL_STRING("SELECT * FROM api.fn_vendor_key_read($1)", static_lastCall()->ma_command);
  TEST_ASSERT_EQUAL_INT(1, static_lastCall()->m_paramCount);
  TEST_ASSERT_FALSE(static_lastCall()->ma_isParamNull[0]);
  TEST_ASSERT_EQUAL_STRING(g_apiKeyHash, static_lastCall()->ma_params[0]);
  TEST_ASSERT_EQUAL_INT(0, static_lastCall()->m_resultFormat);
  TEST_ASSERT_EQUAL_INT64(4242, vendor_keys.m_apiKeyId);
  TEST_ASSERT_EQUAL_STRING(g_vendorKeyFingerprint, vendor_keys.ma_keyFingerprint);
  TEST_ASSERT_EQUAL_STRING("01aa", vendor_keys.ma_shodanSealedHex);
  TEST_ASSERT_EQUAL_STRING("01bb", vendor_keys.ma_abuseIpDbSealedHex);
}

void test_readVendorKeys_reads_an_unknown_key_and_a_missing_vendor_key_as_empty(void)
{
  static char longest_sealed[KEYVAULT_SEALED_HEX_MAX_LEN + 1];
  static_sealedHexOfLength(longest_sealed, KEYVAULT_SEALED_HEX_MAX_LEN);

  static const char* const no_fingerprint = "";
  const struct {
    const char* mp_idCell;
    const char* mp_fingerprintCell;
    const char* mp_shodanCell;
    const char* mp_abuseIpDbCell;
    int64_t     m_apiKeyId;
    const char* mp_fingerprint;
    const char* mp_shodan;
    const char* mp_abuseIpDb;
  } rows[] = {
    { FAKE_SQL_NULL, FAKE_SQL_NULL,          FAKE_SQL_NULL,  FAKE_SQL_NULL,  0,          no_fingerprint,         "",             ""             },
    { "1",           g_vendorKeyFingerprint, FAKE_SQL_NULL,  FAKE_SQL_NULL,  1,          g_vendorKeyFingerprint, "",             ""             },
    { "2147483647",  g_vendorKeyFingerprint, longest_sealed, FAKE_SQL_NULL,  2147483647, g_vendorKeyFingerprint, longest_sealed, ""             },
    { "5",           g_vendorKeyFingerprint, FAKE_SQL_NULL,  longest_sealed, 5,          g_vendorKeyFingerprint, "",             longest_sealed },
  };

  for (size_t row = 0; row < sizeof(rows) / sizeof(rows[0]); row++)
  {
    static_resetFake();
    static_queueVendorKeyReadAnswer(rows[row].mp_idCell, rows[row].mp_fingerprintCell, rows[row].mp_shodanCell, rows[row].mp_abuseIpDbCell);
    char message[16] = "";
    snprintf(message, sizeof(message), "row %zu", row);
    DbVendorKeys_t vendor_keys;
    static_vendorKeysUntouched(&vendor_keys);

    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_OK, db_readVendorKeys(NULL, g_apiKeyHash, &vendor_keys), message);
    TEST_ASSERT_EQUAL_INT64_MESSAGE(rows[row].m_apiKeyId, vendor_keys.m_apiKeyId, message);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(rows[row].mp_fingerprint, vendor_keys.ma_keyFingerprint, message);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(rows[row].mp_shodan, vendor_keys.ma_shodanSealedHex, message);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(rows[row].mp_abuseIpDb, vendor_keys.ma_abuseIpDbSealedHex, message);
  }
}

void test_readVendorKeys_refuses_a_broken_row(void)
{
  static char too_long_sealed[KEYVAULT_SEALED_HEX_MAX_LEN + 2];
  static_sealedHexOfLength(too_long_sealed, KEYVAULT_SEALED_HEX_MAX_LEN + 1);

  const struct {
    const char* mp_idCell;
    const char* mp_fingerprintCell;
    const char* mp_shodanCell;
    const char* mp_abuseIpDbCell;
  } rows[] = {
    { "0",          g_vendorKeyFingerprint,              FAKE_SQL_NULL,   FAKE_SQL_NULL   },
    { "-1",         g_vendorKeyFingerprint,              FAKE_SQL_NULL,   FAKE_SQL_NULL   },
    { "",           g_vendorKeyFingerprint,              FAKE_SQL_NULL,   FAKE_SQL_NULL   },
    { "x",          g_vendorKeyFingerprint,              FAKE_SQL_NULL,   FAKE_SQL_NULL   },
    { "2147483648", g_vendorKeyFingerprint,              FAKE_SQL_NULL,   FAKE_SQL_NULL   },
    { "4242",       FAKE_SQL_NULL,                       FAKE_SQL_NULL,   FAKE_SQL_NULL   },
    { "4242",       "0112233445566778899aabbccddeeff",   FAKE_SQL_NULL,   FAKE_SQL_NULL   },
    { "4242",       "00112233445566778899aabbccddeeff0", FAKE_SQL_NULL,   FAKE_SQL_NULL   },
    { "4242",       g_vendorKeyFingerprint,              too_long_sealed, FAKE_SQL_NULL   },
    { "4242",       g_vendorKeyFingerprint,              FAKE_SQL_NULL,   too_long_sealed },
  };

  for (size_t row = 0; row < sizeof(rows) / sizeof(rows[0]); row++)
  {
    static_resetFake();
    static_queueVendorKeyReadAnswer(rows[row].mp_idCell, rows[row].mp_fingerprintCell, rows[row].mp_shodanCell, rows[row].mp_abuseIpDbCell);
    char message[16] = "";
    snprintf(message, sizeof(message), "row %zu", row);
    DbVendorKeys_t vendor_keys;
    static_vendorKeysUntouched(&vendor_keys);

    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_ERROR, db_readVendorKeys(NULL, g_apiKeyHash, &vendor_keys), message);
    static_assertVendorKeysUntouched(&vendor_keys, message);
  }
}

void test_readVendorKeys_reads_the_fingerprint_with_its_limit(void)
{
  static_clearLogLimit();
  static_queueVendorKeyReadAnswer("4242", "00112233445566778899aabbccddeeff0", FAKE_SQL_NULL, FAKE_SQL_NULL);
  DbVendorKeys_t vendor_keys;
  static_vendorKeysUntouched(&vendor_keys);
  StderrCapture_t capture;
  static_beginStderrCapture(&capture);

  DbStatus_t db_status = db_readVendorKeys(NULL, g_apiKeyHash, &vendor_keys);

  char line[256];
  static_endStderrCapture(&capture, line, sizeof(line));
  TEST_ASSERT_EQUAL_INT(DB_ERROR, db_status);
  TEST_ASSERT_EQUAL_STRING("dbhelper_fetchColStr: column key_fingerprint (index 1) holds 33 bytes, limit 32\n", line);
}

typedef enum {
  VENDOR_KEY_SHAPE_FAILED_QUERY,
  VENDOR_KEY_SHAPE_DEFAULT_ROW,
  VENDOR_KEY_SHAPE_NO_ROW,
  VENDOR_KEY_SHAPE_TWO_ROWS,
  VENDOR_KEY_SHAPE_ONE_COLUMN_LESS,
  VENDOR_KEY_SHAPE_ONE_COLUMN_MORE,
  VENDOR_KEY_SHAPE_SWAPPED_SEALED_NAMES,
  VENDOR_KEY_SHAPE_OTHER_FIRST_NAME,
} VendorKeyShape_t;

static const VendorKeyShape_t g_vendorKeyShapes[] = {
  VENDOR_KEY_SHAPE_FAILED_QUERY,
  VENDOR_KEY_SHAPE_DEFAULT_ROW,
  VENDOR_KEY_SHAPE_NO_ROW,
  VENDOR_KEY_SHAPE_TWO_ROWS,
  VENDOR_KEY_SHAPE_ONE_COLUMN_LESS,
  VENDOR_KEY_SHAPE_ONE_COLUMN_MORE,
  VENDOR_KEY_SHAPE_SWAPPED_SEALED_NAMES,
  VENDOR_KEY_SHAPE_OTHER_FIRST_NAME,
};

static void static_queueVendorKeyShape(VendorKeyShape_t shape, const char* const* names, const char* const* cells, int column_count)
{
  if (shape == VENDOR_KEY_SHAPE_FAILED_QUERY)
  {
    static_queueAnswer(PGRES_FATAL_ERROR, 0, 0);
    return;
  }
  if (shape == VENDOR_KEY_SHAPE_DEFAULT_ROW)
    return;

  int answer_columns = column_count;
  if (shape == VENDOR_KEY_SHAPE_ONE_COLUMN_LESS)
    answer_columns = column_count - 1;
  else if (shape == VENDOR_KEY_SHAPE_ONE_COLUMN_MORE)
    answer_columns = column_count + 1;
  int answer_rows = (shape == VENDOR_KEY_SHAPE_NO_ROW) ? 0 : (shape == VENDOR_KEY_SHAPE_TWO_ROWS) ? 2 : 1;

  FakeAnswer_t* answer = static_queueAnswer(PGRES_TUPLES_OK, answer_columns, answer_rows);
  for (int col = 0; col < answer_columns; col++)
  {
    int source = col < column_count ? col : column_count - 1;
    answer->ma_columnNames[col] = names[source];
    for (int row = 0; row < answer_rows; row++)
      answer->ma_cells[row][col] = cells[source];
  }
  if (shape == VENDOR_KEY_SHAPE_SWAPPED_SEALED_NAMES)
  {
    answer->ma_columnNames[column_count - 2] = names[column_count - 1];
    answer->ma_columnNames[column_count - 1] = names[column_count - 2];
  }
  else if (shape == VENDOR_KEY_SHAPE_OTHER_FIRST_NAME)
  {
    answer->ma_columnNames[0] = "column";
  }
}

void test_readVendorKeys_refuses_any_other_answer(void)
{
  static const char* const names[] = { "api_key_id", "key_fingerprint", "shodan_sealed_hex", "abuseipdb_sealed_hex" };
  const char* const        cells[] = { "4242", g_vendorKeyFingerprint, "01aa", "01bb" };

  for (size_t shape = 0; shape < sizeof(g_vendorKeyShapes) / sizeof(g_vendorKeyShapes[0]); shape++)
  {
    static_resetFake();
    static_queueVendorKeyShape(g_vendorKeyShapes[shape], names, cells, 4);
    char message[16] = "";
    snprintf(message, sizeof(message), "shape %zu", shape);
    DbVendorKeys_t vendor_keys;
    static_vendorKeysUntouched(&vendor_keys);

    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_ERROR, db_readVendorKeys(NULL, g_apiKeyHash, &vendor_keys), message);
    static_assertVendorKeysUntouched(&vendor_keys, message);
  }
}

void test_openVendorKeyLink_sends_the_id_the_hash_and_the_lifetime(void)
{
  TEST_ASSERT_EQUAL_INT(900, DB_VENDOR_KEY_LINK_LIFETIME_SECONDS);
  static_queueOneCell("link_expires_at", "1800001800");
  int64_t link_expires_at = -1;

  TEST_ASSERT_EQUAL_INT(DB_OK, db_openVendorKeyLink(NULL, 4242, g_vendorKeyLinkHash, &link_expires_at));

  TEST_ASSERT_EQUAL_INT64(1800001800, link_expires_at);
  TEST_ASSERT_EQUAL_INT(1, g_callCount);
  TEST_ASSERT_EQUAL_STRING("SELECT api.fn_vendor_key_link_open($1, $2, $3) AS link_expires_at", static_lastCall()->ma_command);
  TEST_ASSERT_EQUAL_INT(3, static_lastCall()->m_paramCount);
  TEST_ASSERT_FALSE(static_lastCall()->ma_isParamNull[0]);
  TEST_ASSERT_FALSE(static_lastCall()->ma_isParamNull[1]);
  TEST_ASSERT_FALSE(static_lastCall()->ma_isParamNull[2]);
  TEST_ASSERT_EQUAL_STRING("4242", static_lastCall()->ma_params[0]);
  TEST_ASSERT_EQUAL_STRING(g_vendorKeyLinkHash, static_lastCall()->ma_params[1]);
  TEST_ASSERT_EQUAL_STRING("900", static_lastCall()->ma_params[2]);
  TEST_ASSERT_EQUAL_INT(0, static_lastCall()->m_resultFormat);
}

void test_openVendorKeyLink_reads_each_answer(void)
{
  static const struct {
    const char* mp_cell;
    DbStatus_t  m_status;
    int64_t     m_linkExpiresAt;
  } rows[] = {
    { "1",                   DB_OK,        1         },
    { "9223372036854775807", DB_OK,        INT64_MAX },
    { FAKE_SQL_NULL,         DB_NOT_FOUND, -1        },
    { "0",                   DB_ERROR,     -1        },
    { "-5",                  DB_ERROR,     -1        },
    { "",                    DB_ERROR,     -1        },
    { "x",                   DB_ERROR,     -1        },
  };

  for (size_t row = 0; row < sizeof(rows) / sizeof(rows[0]); row++)
  {
    static_resetFake();
    static_queueOneCell("link_expires_at", rows[row].mp_cell);
    char message[16] = "";
    snprintf(message, sizeof(message), "row %zu", row);
    int64_t link_expires_at = -1;

    TEST_ASSERT_EQUAL_INT_MESSAGE(rows[row].m_status, db_openVendorKeyLink(NULL, 4242, g_vendorKeyLinkHash, &link_expires_at), message);
    TEST_ASSERT_EQUAL_INT64_MESSAGE(rows[row].m_linkExpiresAt, link_expires_at, message);
  }

  for (size_t shape = 0; shape < sizeof(g_wrongShapes) / sizeof(g_wrongShapes[0]); shape++)
  {
    static_resetFake();
    static_queueWrongShape(g_wrongShapes[shape], "link_expires_at", "1800001800");
    char message[16] = "";
    snprintf(message, sizeof(message), "shape %zu", shape);
    int64_t link_expires_at = -1;

    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_ERROR, db_openVendorKeyLink(NULL, 4242, g_vendorKeyLinkHash, &link_expires_at), message);
    TEST_ASSERT_EQUAL_INT64_MESSAGE(-1, link_expires_at, message);
  }
}

static void static_vendorKeyLinkUntouched(DbVendorKeyLink_t* vendor_key_link)
{
  vendor_key_link->m_linkState     = VENDOR_KEY_LINK_STATE_UNTOUCHED;
  vendor_key_link->m_apiKeyId      = 77;
  vendor_key_link->m_linkExpiresAt = 77;
  snprintf(vendor_key_link->ma_shodanSealedHex, sizeof(vendor_key_link->ma_shodanSealedHex), "%s", "untouched");
  snprintf(vendor_key_link->ma_abuseIpDbSealedHex, sizeof(vendor_key_link->ma_abuseIpDbSealedHex), "%s", "untouched");
}

void test_readVendorKeyLink_sends_the_hash_and_reads_each_column(void)
{
  static_queueVendorKeyLinkReadAnswer("open", "4242", "1800001800", "01aa", "01bb");
  DbVendorKeyLink_t vendor_key_link;
  static_vendorKeyLinkUntouched(&vendor_key_link);

  TEST_ASSERT_EQUAL_INT(DB_OK, db_readVendorKeyLink(NULL, g_vendorKeyLinkHash, &vendor_key_link));

  TEST_ASSERT_EQUAL_INT(1, g_callCount);
  TEST_ASSERT_EQUAL_STRING("SELECT * FROM api.fn_vendor_key_link_read($1)", static_lastCall()->ma_command);
  TEST_ASSERT_EQUAL_INT(1, static_lastCall()->m_paramCount);
  TEST_ASSERT_FALSE(static_lastCall()->ma_isParamNull[0]);
  TEST_ASSERT_EQUAL_STRING(g_vendorKeyLinkHash, static_lastCall()->ma_params[0]);
  TEST_ASSERT_EQUAL_INT(0, static_lastCall()->m_resultFormat);
  TEST_ASSERT_EQUAL_INT(DB_VENDOR_KEY_LINK_OPEN, vendor_key_link.m_linkState);
  TEST_ASSERT_EQUAL_INT64(4242, vendor_key_link.m_apiKeyId);
  TEST_ASSERT_EQUAL_INT64(1800001800, vendor_key_link.m_linkExpiresAt);
  TEST_ASSERT_EQUAL_STRING("01aa", vendor_key_link.ma_shodanSealedHex);
  TEST_ASSERT_EQUAL_STRING("01bb", vendor_key_link.ma_abuseIpDbSealedHex);
}

void test_readVendorKeyLink_reads_each_state(void)
{
  static char longest_sealed[KEYVAULT_SEALED_HEX_MAX_LEN + 1];
  static char too_long_sealed[KEYVAULT_SEALED_HEX_MAX_LEN + 2];
  static_sealedHexOfLength(longest_sealed, KEYVAULT_SEALED_HEX_MAX_LEN);
  static_sealedHexOfLength(too_long_sealed, KEYVAULT_SEALED_HEX_MAX_LEN + 1);

  const struct {
    const char*            mp_stateCell;
    const char*            mp_idCell;
    const char*            mp_endCell;
    const char*            mp_shodanCell;
    const char*            mp_abuseIpDbCell;
    DbStatus_t             m_status;
    DbVendorKeyLinkState_t m_state;
    int64_t                m_apiKeyId;
    int64_t                m_linkExpiresAt;
    const char*            mp_shodan;
    const char*            mp_abuseIpDb;
  } rows[] = {
    { "open",        "1",             "1",                   longest_sealed,  FAKE_SQL_NULL,   DB_OK,    DB_VENDOR_KEY_LINK_OPEN,    1,          1,         longest_sealed, ""             },
    { "open",        "2147483647",    "9223372036854775807", FAKE_SQL_NULL,   longest_sealed,  DB_OK,    DB_VENDOR_KEY_LINK_OPEN,    2147483647, INT64_MAX, "",             longest_sealed },
    { "expired",     FAKE_SQL_NULL,   FAKE_SQL_NULL,         FAKE_SQL_NULL,   FAKE_SQL_NULL,   DB_OK,    DB_VENDOR_KEY_LINK_EXPIRED, 0,          0,         "",             ""             },
    { "invalid",     FAKE_SQL_NULL,   FAKE_SQL_NULL,         FAKE_SQL_NULL,   FAKE_SQL_NULL,   DB_OK,    DB_VENDOR_KEY_LINK_INVALID, 0,          0,         "",             ""             },
    { "expired",     "4242",          "1800001800",          "01aa",          "01bb",          DB_OK,    DB_VENDOR_KEY_LINK_EXPIRED, 0,          0,         "",             ""             },
    { "invalid",     "4242",          "1800001800",          "01aa",          "01bb",          DB_OK,    DB_VENDOR_KEY_LINK_INVALID, 0,          0,         "",             ""             },
    { "open",        "0",             "1800001800",          FAKE_SQL_NULL,   FAKE_SQL_NULL,   DB_ERROR, DB_VENDOR_KEY_LINK_OPEN,    0,          0,         "",             ""             },
    { "open",        FAKE_SQL_NULL,   "1800001800",          FAKE_SQL_NULL,   FAKE_SQL_NULL,   DB_ERROR, DB_VENDOR_KEY_LINK_OPEN,    0,          0,         "",             ""             },
    { "open",        "2147483648",    "1800001800",          FAKE_SQL_NULL,   FAKE_SQL_NULL,   DB_ERROR, DB_VENDOR_KEY_LINK_OPEN,    0,          0,         "",             ""             },
    { "open",        "4242",          "0",                   FAKE_SQL_NULL,   FAKE_SQL_NULL,   DB_ERROR, DB_VENDOR_KEY_LINK_OPEN,    0,          0,         "",             ""             },
    { "open",        "4242",          FAKE_SQL_NULL,         FAKE_SQL_NULL,   FAKE_SQL_NULL,   DB_ERROR, DB_VENDOR_KEY_LINK_OPEN,    0,          0,         "",             ""             },
    { "open",        "4242",          "x",                   FAKE_SQL_NULL,   FAKE_SQL_NULL,   DB_ERROR, DB_VENDOR_KEY_LINK_OPEN,    0,          0,         "",             ""             },
    { "Open",        "4242",          "1800001800",          FAKE_SQL_NULL,   FAKE_SQL_NULL,   DB_ERROR, DB_VENDOR_KEY_LINK_OPEN,    0,          0,         "",             ""             },
    { "opened",      "4242",          "1800001800",          FAKE_SQL_NULL,   FAKE_SQL_NULL,   DB_ERROR, DB_VENDOR_KEY_LINK_OPEN,    0,          0,         "",             ""             },
    { "expire",      FAKE_SQL_NULL,   FAKE_SQL_NULL,         FAKE_SQL_NULL,   FAKE_SQL_NULL,   DB_ERROR, DB_VENDOR_KEY_LINK_OPEN,    0,          0,         "",             ""             },
    { "invalidx",    FAKE_SQL_NULL,   FAKE_SQL_NULL,         FAKE_SQL_NULL,   FAKE_SQL_NULL,   DB_ERROR, DB_VENDOR_KEY_LINK_OPEN,    0,          0,         "",             ""             },
    { "spent",       FAKE_SQL_NULL,   FAKE_SQL_NULL,         FAKE_SQL_NULL,   FAKE_SQL_NULL,   DB_ERROR, DB_VENDOR_KEY_LINK_OPEN,    0,          0,         "",             ""             },
    { "inactive",    FAKE_SQL_NULL,   FAKE_SQL_NULL,         FAKE_SQL_NULL,   FAKE_SQL_NULL,   DB_ERROR, DB_VENDOR_KEY_LINK_OPEN,    0,          0,         "",             ""             },
    { "applied",     FAKE_SQL_NULL,   FAKE_SQL_NULL,         FAKE_SQL_NULL,   FAKE_SQL_NULL,   DB_ERROR, DB_VENDOR_KEY_LINK_OPEN,    0,          0,         "",             ""             },
    { "",            FAKE_SQL_NULL,   FAKE_SQL_NULL,         FAKE_SQL_NULL,   FAKE_SQL_NULL,   DB_ERROR, DB_VENDOR_KEY_LINK_OPEN,    0,          0,         "",             ""             },
    { FAKE_SQL_NULL, FAKE_SQL_NULL,   FAKE_SQL_NULL,         FAKE_SQL_NULL,   FAKE_SQL_NULL,   DB_ERROR, DB_VENDOR_KEY_LINK_OPEN,    0,          0,         "",             ""             },
    { "open",        "4242",          "1800001800",          too_long_sealed, FAKE_SQL_NULL,   DB_ERROR, DB_VENDOR_KEY_LINK_OPEN,    0,          0,         "",             ""             },
    { "open",        "4242",          "1800001800",          FAKE_SQL_NULL,   too_long_sealed, DB_ERROR, DB_VENDOR_KEY_LINK_OPEN,    0,          0,         "",             ""             },
  };

  for (size_t row = 0; row < sizeof(rows) / sizeof(rows[0]); row++)
  {
    static_resetFake();
    static_queueVendorKeyLinkReadAnswer(rows[row].mp_stateCell, rows[row].mp_idCell, rows[row].mp_endCell, rows[row].mp_shodanCell, rows[row].mp_abuseIpDbCell);
    char message[16] = "";
    snprintf(message, sizeof(message), "row %zu", row);
    DbVendorKeyLink_t vendor_key_link;
    static_vendorKeyLinkUntouched(&vendor_key_link);

    DbStatus_t db_status = db_readVendorKeyLink(NULL, g_vendorKeyLinkHash, &vendor_key_link);

    TEST_ASSERT_EQUAL_INT_MESSAGE(rows[row].m_status, db_status, message);
    if (db_status == DB_OK)
    {
      TEST_ASSERT_EQUAL_INT_MESSAGE(rows[row].m_state, vendor_key_link.m_linkState, message);
      TEST_ASSERT_EQUAL_INT64_MESSAGE(rows[row].m_apiKeyId, vendor_key_link.m_apiKeyId, message);
      TEST_ASSERT_EQUAL_INT64_MESSAGE(rows[row].m_linkExpiresAt, vendor_key_link.m_linkExpiresAt, message);
      TEST_ASSERT_EQUAL_STRING_MESSAGE(rows[row].mp_shodan, vendor_key_link.ma_shodanSealedHex, message);
      TEST_ASSERT_EQUAL_STRING_MESSAGE(rows[row].mp_abuseIpDb, vendor_key_link.ma_abuseIpDbSealedHex, message);
    }
    else
    {
      TEST_ASSERT_EQUAL_INT_MESSAGE(VENDOR_KEY_LINK_STATE_UNTOUCHED, vendor_key_link.m_linkState, message);
      TEST_ASSERT_EQUAL_INT64_MESSAGE(77, vendor_key_link.m_apiKeyId, message);
      TEST_ASSERT_EQUAL_INT64_MESSAGE(77, vendor_key_link.m_linkExpiresAt, message);
      TEST_ASSERT_EQUAL_STRING_MESSAGE("untouched", vendor_key_link.ma_shodanSealedHex, message);
      TEST_ASSERT_EQUAL_STRING_MESSAGE("untouched", vendor_key_link.ma_abuseIpDbSealedHex, message);
    }
  }
}

void test_readVendorKeyLink_refuses_any_other_answer(void)
{
  static const char* const names[] = { "link_state", "api_key_id", "link_expires_at", "shodan_sealed_hex", "abuseipdb_sealed_hex" };
  static const char* const cells[] = { "open", "4242", "1800001800", "01aa", "01bb" };

  for (size_t shape = 0; shape < sizeof(g_vendorKeyShapes) / sizeof(g_vendorKeyShapes[0]); shape++)
  {
    static_resetFake();
    static_queueVendorKeyShape(g_vendorKeyShapes[shape], names, cells, 5);
    char message[16] = "";
    snprintf(message, sizeof(message), "shape %zu", shape);
    DbVendorKeyLink_t vendor_key_link;
    static_vendorKeyLinkUntouched(&vendor_key_link);

    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_ERROR, db_readVendorKeyLink(NULL, g_vendorKeyLinkHash, &vendor_key_link), message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(VENDOR_KEY_LINK_STATE_UNTOUCHED, vendor_key_link.m_linkState, message);
    TEST_ASSERT_EQUAL_STRING_MESSAGE("untouched", vendor_key_link.ma_shodanSealedHex, message);
  }
}

void test_vendor_key_state_one_byte_past_its_limit_logs_the_limit(void)
{
  static_clearLogLimit();
  static_queueVendorKeyLinkReadAnswer("inactivex", FAKE_SQL_NULL, FAKE_SQL_NULL, FAKE_SQL_NULL, FAKE_SQL_NULL);
  DbVendorKeyLink_t vendor_key_link;
  static_vendorKeyLinkUntouched(&vendor_key_link);
  StderrCapture_t capture;
  static_beginStderrCapture(&capture);

  DbStatus_t db_status = db_readVendorKeyLink(NULL, g_vendorKeyLinkHash, &vendor_key_link);

  char line[256];
  static_endStderrCapture(&capture, line, sizeof(line));
  TEST_ASSERT_EQUAL_INT(DB_ERROR, db_status);
  TEST_ASSERT_EQUAL_STRING("dbhelper_fetchColStr: column link_state (index 0) holds 9 bytes, limit 8\n", line);

  static_resetFake();
  static_clearLogLimit();
  static_queueOneCell("vendor_key_apply_status", "inactivex");
  const DbVendorKeyChange_t change = { 4242, NULL, NULL, false, NULL, true, NULL, false };
  DbVendorKeyApplyStatus_t  apply_status = VENDOR_KEY_APPLY_STATUS_UNTOUCHED;
  static_beginStderrCapture(&capture);

  db_status = db_applyVendorKeys(NULL, &change, &apply_status);

  static_endStderrCapture(&capture, line, sizeof(line));
  TEST_ASSERT_EQUAL_INT(DB_ERROR, db_status);
  TEST_ASSERT_EQUAL_STRING("dbhelper_fetchColStr: column vendor_key_apply_status (index 0) holds 9 bytes, limit 8\n", line);
}

void test_applyVendorKeys_sends_each_field_in_its_own_param(void)
{
  static const struct {
    DbVendorKeyChange_t m_change;
    const char*         ma_params[8];
  } rows[] = {
    { { 4242, "6c86c6aac5fb24bcf5d9939cb7d7d5645ce39418f449e03b262dd4fa14b4b92b", NULL, true,  "01aa", false, NULL,   true  },
      { "4242", "6c86c6aac5fb24bcf5d9939cb7d7d5645ce39418f449e03b262dd4fa14b4b92b", NULL, "true", "01aa", "false", NULL, "true" } },
    { { 7,    NULL, "ffeeddccbbaa99887766554433221100", false, NULL,   true,  "01bb", false },
      { "7", NULL, "ffeeddccbbaa99887766554433221100", "false", NULL, "true", "01bb", "false" } },
  };

  for (size_t row = 0; row < sizeof(rows) / sizeof(rows[0]); row++)
  {
    static_resetFake();
    static_queueOneCell("vendor_key_apply_status", "applied");
    char message[32] = "";
    DbVendorKeyApplyStatus_t apply_status = VENDOR_KEY_APPLY_STATUS_UNTOUCHED;

    snprintf(message, sizeof(message), "row %zu", row);
    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_OK, db_applyVendorKeys(NULL, &rows[row].m_change, &apply_status), message);

    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_VENDOR_KEY_APPLY_APPLIED, apply_status, message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_callCount, message);
    TEST_ASSERT_EQUAL_STRING_MESSAGE("SELECT api.fn_vendor_key_apply($1, $2, $3, $4, $5, $6, $7, $8) AS vendor_key_apply_status",
                                     static_lastCall()->ma_command, message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(8, static_lastCall()->m_paramCount, message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, static_lastCall()->m_resultFormat, message);
    for (int param = 0; param < 8; param++)
    {
      snprintf(message, sizeof(message), "row %zu param %d", row, param + 1);
      const char* expected = rows[row].ma_params[param];
      TEST_ASSERT_EQUAL_MESSAGE(expected == NULL, static_lastCall()->ma_isParamNull[param], message);
      if (expected != NULL)
        TEST_ASSERT_EQUAL_STRING_MESSAGE(expected, static_lastCall()->ma_params[param], message);
    }
  }
}

void test_applyVendorKeys_reads_each_status(void)
{
  static const struct {
    const char*              mp_cell;
    DbStatus_t               m_status;
    DbVendorKeyApplyStatus_t m_applyStatus;
  } rows[] = {
    { "applied",     DB_OK,    DB_VENDOR_KEY_APPLY_APPLIED  },
    { "expired",     DB_OK,    DB_VENDOR_KEY_APPLY_EXPIRED  },
    { "invalid",     DB_OK,    DB_VENDOR_KEY_APPLY_INVALID  },
    { "inactive",    DB_OK,    DB_VENDOR_KEY_APPLY_INACTIVE },
    { "Applied",     DB_ERROR, DB_VENDOR_KEY_APPLY_APPLIED  },
    { "applie",      DB_ERROR, DB_VENDOR_KEY_APPLY_APPLIED  },
    { "expiredx",    DB_ERROR, DB_VENDOR_KEY_APPLY_APPLIED  },
    { "invali",      DB_ERROR, DB_VENDOR_KEY_APPLY_APPLIED  },
    { "spent",       DB_ERROR, DB_VENDOR_KEY_APPLY_APPLIED  },
    { "inactiv",     DB_ERROR, DB_VENDOR_KEY_APPLY_APPLIED  },
    { "open",        DB_ERROR, DB_VENDOR_KEY_APPLY_APPLIED  },
    { "",            DB_ERROR, DB_VENDOR_KEY_APPLY_APPLIED  },
    { FAKE_SQL_NULL, DB_ERROR, DB_VENDOR_KEY_APPLY_APPLIED  },
  };
  const DbVendorKeyChange_t change = { 4242, g_vendorKeyLinkHash, NULL, true, "01aa", false, NULL, false };

  for (size_t row = 0; row < sizeof(rows) / sizeof(rows[0]); row++)
  {
    static_resetFake();
    static_queueOneCell("vendor_key_apply_status", rows[row].mp_cell);
    char message[16] = "";
    snprintf(message, sizeof(message), "row %zu", row);
    DbVendorKeyApplyStatus_t apply_status = VENDOR_KEY_APPLY_STATUS_UNTOUCHED;

    DbStatus_t db_status = db_applyVendorKeys(NULL, &change, &apply_status);

    TEST_ASSERT_EQUAL_INT_MESSAGE(rows[row].m_status, db_status, message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(db_status == DB_OK ? (int)rows[row].m_applyStatus : (int)VENDOR_KEY_APPLY_STATUS_UNTOUCHED, (int)apply_status, message);
  }

  for (size_t shape = 0; shape < sizeof(g_wrongShapes) / sizeof(g_wrongShapes[0]); shape++)
  {
    static_resetFake();
    static_queueWrongShape(g_wrongShapes[shape], "vendor_key_apply_status", "applied");
    char message[16] = "";
    snprintf(message, sizeof(message), "shape %zu", shape);
    DbVendorKeyApplyStatus_t apply_status = VENDOR_KEY_APPLY_STATUS_UNTOUCHED;

    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_ERROR, db_applyVendorKeys(NULL, &change, &apply_status), message);
    TEST_ASSERT_EQUAL_INT_MESSAGE((int)VENDOR_KEY_APPLY_STATUS_UNTOUCHED, (int)apply_status, message);
  }
}

void test_CVERISKSCORE_no_row_is_not_found(void)
{
  static_queueRiskscoreAnswer(0);
  CVERISKSCORERecord_t record;

  TEST_ASSERT_EQUAL_INT(DB_NOT_FOUND, db_CVERISKSCORE(NULL, "CVE-2021-44228", &record));
}

void test_PRODUCTEXPOSURE_failed_exposure_query_is_error(void)
{
  PRODUCTEXPOSURERecord_t record;

  TEST_ASSERT_EQUAL_INT(DB_ERROR, static_runProductExposure("", false, &record));
  TEST_ASSERT_EQUAL_INT(1, g_callCount);
}

void test_PRODUCTEXPOSURE_sends_the_vendor_the_product_and_the_row_limit(void)
{
  static_queueProductExposureAnswers(0);
  char row_limit[16];
  snprintf(row_limit, sizeof(row_limit), "%d", PRODUCTEXPOSURE_TOP_N);
  char maintained_limit[16];
  snprintf(maintained_limit, sizeof(maintained_limit), "%d", PRODUCTEXPOSURE_EOL_MAINTAINED_CYCLE_MAX);
  PRODUCTEXPOSURERecord_t record;

  TEST_ASSERT_EQUAL_INT(DB_OK, static_runProductExposure("v22.1", false, &record));

  TEST_ASSERT_EQUAL_INT(2, g_callCount);
  TEST_ASSERT_EQUAL_STRING("SELECT * FROM api.fn_product_exposure($1, $2, $3, $4)", static_call(0)->ma_command);
  TEST_ASSERT_EQUAL_INT(4, static_call(0)->m_paramCount);
  TEST_ASSERT_EQUAL_STRING("apache", static_call(0)->ma_params[0]);
  TEST_ASSERT_EQUAL_STRING("log4j", static_call(0)->ma_params[1]);
  TEST_ASSERT_EQUAL_STRING("false", static_call(0)->ma_params[2]);
  TEST_ASSERT_EQUAL_STRING(row_limit, static_call(0)->ma_params[3]);
  TEST_ASSERT_EQUAL_STRING("SELECT * FROM api.fn_product_exposure_eol($1, $2, $3, $4)", static_call(1)->ma_command);
  TEST_ASSERT_EQUAL_INT(4, static_call(1)->m_paramCount);
  TEST_ASSERT_EQUAL_STRING("apache", static_call(1)->ma_params[0]);
  TEST_ASSERT_EQUAL_STRING("log4j", static_call(1)->ma_params[1]);
  TEST_ASSERT_FALSE(static_call(1)->ma_isParamNull[2]);
  TEST_ASSERT_EQUAL_STRING("v22.1", static_call(1)->ma_params[2]);
  TEST_ASSERT_EQUAL_STRING(maintained_limit, static_call(1)->ma_params[3]);
  TEST_ASSERT_EQUAL_STRING_MESSAGE("apache", record.ma_vendor, "the record echoes the vendor it was asked for");
  TEST_ASSERT_EQUAL_STRING_MESSAGE("log4j", record.ma_product, "the record echoes the product it was asked for");
}

void test_PRODUCTEXPOSURE_sends_include_rejected_as_true_or_false(void)
{
  for (int is_rejected_included = 1; is_rejected_included >= 0; is_rejected_included--)
  {
    static_resetFake();
    static_queueProductExposureAnswers(0);
    PRODUCTEXPOSURERecord_t record;

    TEST_ASSERT_EQUAL_INT(DB_OK, static_runProductExposure("", is_rejected_included, &record));

    TEST_ASSERT_FALSE(static_call(0)->ma_isParamNull[2]);
    TEST_ASSERT_EQUAL_STRING(is_rejected_included ? "true" : "false", static_call(0)->ma_params[2]);
    TEST_ASSERT_EQUAL_INT(4, static_call(1)->m_paramCount);
  }
}

void test_PRODUCTEXPOSURE_reads_each_top_item_from_its_own_row(void)
{
  static_queueProductExposureAnswers(0);
  PRODUCTEXPOSURERecord_t record;

  TEST_ASSERT_EQUAL_INT(DB_OK, static_runProductExposure("", false, &record));

  TEST_ASSERT_EQUAL_INT(2, record.m_topCveCount);
  TEST_ASSERT_EQUAL_STRING("CVE-2021-44228", record.ma_topCves[0].ma_cveId);
  TEST_ASSERT_TRUE(record.ma_topCves[0].m_riskScore == 96.5);
  TEST_ASSERT_EQUAL_STRING("CRITICAL", record.ma_topCves[0].ma_label);
  TEST_ASSERT_EQUAL_STRING("CVE-2014-0160", record.ma_topCves[1].ma_cveId);
  TEST_ASSERT_TRUE(record.ma_topCves[1].m_riskScore == 71.25);
  TEST_ASSERT_EQUAL_STRING("HIGH", record.ma_topCves[1].ma_label);
}

void test_PRODUCTEXPOSURE_one_row_with_a_null_cve_id_has_no_top_cve(void)
{
  FakeAnswer_t* exposure = static_queueProductExposureAnswer(g_productExposureSummaryValues, 1);
  for (int col = PRODUCTEXPOSURE_ROW_CVE_ID_COLUMN_INDEX; col <= PRODUCTEXPOSURE_ROW_LABEL_COLUMN_INDEX; col++)
    exposure->ma_cells[0][col] = FAKE_SQL_NULL;
  FakeAnswer_t* eol = static_queueProductExposureEol(1);
  static_setEolProductRow(eol, 0, "log4j", "https://endoflife.date/log4j", "1");
  PRODUCTEXPOSURERecord_t record;

  TEST_ASSERT_EQUAL_INT(DB_OK, static_runProductExposure("", false, &record));

  TEST_ASSERT_EQUAL_INT(2, g_callCount);
  TEST_ASSERT_EQUAL_INT(2, record.m_totalCveCount);
  TEST_ASSERT_EQUAL_STRING("2021-12-10", record.ma_mostRecentPublished);
  TEST_ASSERT_EQUAL_INT(0, record.m_topCveCount);
  TEST_ASSERT_EQUAL_STRING("", record.ma_topCves[0].ma_cveId);
  TEST_ASSERT_TRUE(record.m_eol.m_hasEol);
  TEST_ASSERT_EQUAL_STRING("log4j", record.m_eol.ma_eolProduct);
}

void test_PRODUCTEXPOSURE_null_cve_id_beside_another_row_is_error(void)
{
  for (int null_row = 1; null_row >= 0; null_row--)
  {
    static_resetFake();
    FakeAnswer_t* exposure = static_queueProductExposureAnswer(g_productExposureSummaryValues, 2);
    exposure->ma_cells[null_row][PRODUCTEXPOSURE_ROW_CVE_ID_COLUMN_INDEX] = FAKE_SQL_NULL;
    static_queueProductExposureEol(0);
    PRODUCTEXPOSURERecord_t record;
    char message[32];
    snprintf(message, sizeof(message), "NULL cve_id in row %d", null_row);

    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_ERROR, static_runProductExposure("", false, &record), message);
  }
}

void test_PRODUCTEXPOSURE_answer_with_no_row_is_a_zeroed_record(void)
{
  static_queueProductExposureAnswer(g_productExposureSummaryValues, 0);
  FakeAnswer_t* eol = static_queueProductExposureEol(1);
  static_setEolProductRow(eol, 0, "log4j", "https://endoflife.date/log4j", "1");
  PRODUCTEXPOSURERecord_t record;
  memset(&record, 0xA5, sizeof(record));

  TEST_ASSERT_EQUAL_INT(DB_OK, static_runProductExposure("", false, &record));

  TEST_ASSERT_EQUAL_INT(2, g_callCount);
  TEST_ASSERT_EQUAL_INT(0, record.m_totalCveCount);
  TEST_ASSERT_EQUAL_INT(0, record.m_criticalCount);
  TEST_ASSERT_EQUAL_INT(0, record.m_kevCount);
  TEST_ASSERT_EQUAL_INT(0, record.m_pocBackedCount);
  TEST_ASSERT_TRUE(record.m_maxCvss == 0.0);
  TEST_ASSERT_TRUE(record.m_worstRiskScore == 0.0);
  TEST_ASSERT_EQUAL_STRING("", record.ma_mostRecentPublished);
  TEST_ASSERT_EQUAL_INT(0, record.m_topCveCount);
  TEST_ASSERT_EQUAL_STRING("apache", record.ma_vendor);
  TEST_ASSERT_TRUE(record.m_eol.m_hasEol);
}

void test_PRODUCTEXPOSURE_empty_version_is_sent_as_null_and_no_eol_row_is_no_eol(void)
{
  static_queueProductExposureAnswers(0);
  PRODUCTEXPOSURERecord_t record;

  TEST_ASSERT_EQUAL_INT(DB_OK, static_runProductExposure("", false, &record));

  TEST_ASSERT_TRUE(static_call(1)->ma_isParamNull[2]);
  TEST_ASSERT_FALSE(record.m_eol.m_hasEol);
  TEST_ASSERT_EQUAL_INT(0, record.m_eol.m_eolSeriesCycleCount);
  TEST_ASSERT_EQUAL_INT(0, record.m_eol.m_eolMaintainedCycleCount);
}

void test_PRODUCTEXPOSURE_failed_eol_query_is_error(void)
{
  static_queueProductExposureAnswer(g_productExposureSummaryValues, 2);
  PRODUCTEXPOSURERecord_t record;

  TEST_ASSERT_EQUAL_INT(DB_ERROR, static_runProductExposure("", false, &record));
}

void test_PRODUCTEXPOSURE_reads_each_eol_field_from_its_own_column(void)
{
  FakeAnswer_t* eol = static_queueProductExposureAnswers(5);
  static_setEolCycleRow(eol, 0, "series", "11-24h2-w", "2026-10-13", "t", "f", "f", "26100.1");
  static_setEolProductRow(eol, 1, "windows", "https://endoflife.date/windows", "2");
  static_setEolCycleRow(eol, 2, "maintained", "26", "2029-04-30", "f", "t", "f", "26.0.1");
  static_setEolCycleRow(eol, 3, "series", "11-24h2-e", FAKE_SQL_NULL, "f", "f", "t", FAKE_SQL_NULL);
  static_setEolCycleRow(eol, 4, "maintained", "24", "2028-04-30", "t", "t", "f", "24.1.0");
  PRODUCTEXPOSURERecord_t record;

  TEST_ASSERT_EQUAL_INT(DB_OK, static_runProductExposure("", false, &record));

  TEST_ASSERT_TRUE(record.m_eol.m_hasEol);
  TEST_ASSERT_EQUAL_STRING("windows", record.m_eol.ma_eolProduct);
  TEST_ASSERT_EQUAL_STRING("https://endoflife.date/windows", record.m_eol.ma_eolUrl);
  TEST_ASSERT_EQUAL_INT(2, record.m_eol.m_eolSeriesCycleCount);
  const PRODUCTEXPOSUREEolCycle_t* first = &record.m_eol.ma_eolSeriesCycles[0];
  TEST_ASSERT_EQUAL_STRING("11-24h2-w", first->ma_name);
  TEST_ASSERT_EQUAL_STRING("2026-10-13", first->ma_eolDate);
  TEST_ASSERT_TRUE(first->m_isEol);
  TEST_ASSERT_FALSE(first->m_isMaintained);
  TEST_ASSERT_FALSE(first->m_isLts);
  TEST_ASSERT_EQUAL_STRING("26100.1", first->ma_latestVersion);
  const PRODUCTEXPOSUREEolCycle_t* second = &record.m_eol.ma_eolSeriesCycles[1];
  TEST_ASSERT_EQUAL_STRING("11-24h2-e", second->ma_name);
  TEST_ASSERT_EQUAL_STRING("", second->ma_eolDate);
  TEST_ASSERT_FALSE(second->m_isEol);
  TEST_ASSERT_FALSE(second->m_isMaintained);
  TEST_ASSERT_TRUE(second->m_isLts);
  TEST_ASSERT_EQUAL_STRING("", second->ma_latestVersion);
  TEST_ASSERT_EQUAL_INT(2, record.m_eol.m_eolMaintainedCycleCount);
  TEST_ASSERT_FALSE(record.m_eol.m_hasMoreEolMaintainedCycles);
  const PRODUCTEXPOSUREEolCycle_t* newest = &record.m_eol.ma_eolMaintainedCycles[0];
  TEST_ASSERT_EQUAL_STRING("26", newest->ma_name);
  TEST_ASSERT_EQUAL_STRING("2029-04-30", newest->ma_eolDate);
  TEST_ASSERT_FALSE(newest->m_isEol);
  TEST_ASSERT_TRUE(newest->m_isMaintained);
  TEST_ASSERT_FALSE(newest->m_isLts);
  const PRODUCTEXPOSUREEolCycle_t* older = &record.m_eol.ma_eolMaintainedCycles[1];
  TEST_ASSERT_EQUAL_STRING("24", older->ma_name);
  TEST_ASSERT_EQUAL_STRING("2028-04-30", older->ma_eolDate);
  TEST_ASSERT_TRUE(older->m_isEol);
  TEST_ASSERT_TRUE(older->m_isMaintained);
  TEST_ASSERT_FALSE(older->m_isLts);
}

void test_PRODUCTEXPOSURE_maintained_cycle_count_past_the_limit_sets_has_more(void)
{
  TEST_ASSERT_EQUAL_INT(10, PRODUCTEXPOSURE_EOL_MAINTAINED_CYCLE_MAX);
  for (int total = PRODUCTEXPOSURE_EOL_MAINTAINED_CYCLE_MAX - 1; total <= PRODUCTEXPOSURE_EOL_MAINTAINED_CYCLE_MAX + 1; total++)
  {
    static_resetFake();
    int row_count = total < PRODUCTEXPOSURE_EOL_MAINTAINED_CYCLE_MAX ? total : PRODUCTEXPOSURE_EOL_MAINTAINED_CYCLE_MAX;
    FakeAnswer_t* eol = static_queueProductExposureAnswers(row_count + 1);
    char total_text[16];
    snprintf(total_text, sizeof(total_text), "%d", total);
    static_setEolProductRow(eol, 0, "nodejs", "https://endoflife.date/nodejs", total_text);
    for (int row = 1; row <= row_count; row++)
      static_setEolCycleRow(eol, row, "maintained", "26", "2029-04-30", "f", "t", "f", "26.0.1");
    PRODUCTEXPOSURERecord_t record;

    TEST_ASSERT_EQUAL_INT(DB_OK, static_runProductExposure("", false, &record));

    TEST_ASSERT_EQUAL_INT_MESSAGE(row_count, record.m_eol.m_eolMaintainedCycleCount, total_text);
    TEST_ASSERT_EQUAL_MESSAGE(total > PRODUCTEXPOSURE_EOL_MAINTAINED_CYCLE_MAX, record.m_eol.m_hasMoreEolMaintainedCycles, total_text);
  }
}

void test_PRODUCTEXPOSURE_reads_at_most_the_maintained_cycle_limit(void)
{
  FakeAnswer_t* eol = static_queueProductExposureAnswers(PRODUCTEXPOSURE_EOL_MAINTAINED_CYCLE_MAX + 2);
  static_setEolProductRow(eol, 0, "nodejs", "https://endoflife.date/nodejs", "11");
  for (int row = 1; row <= PRODUCTEXPOSURE_EOL_MAINTAINED_CYCLE_MAX + 1; row++)
    static_setEolCycleRow(eol, row, "maintained", "26", "2029-04-30", "f", "t", "f", "26.0.1");
  PRODUCTEXPOSURERecord_t record;

  TEST_ASSERT_EQUAL_INT(DB_OK, static_runProductExposure("", false, &record));
  TEST_ASSERT_EQUAL_INT(PRODUCTEXPOSURE_EOL_MAINTAINED_CYCLE_MAX, record.m_eol.m_eolMaintainedCycleCount);
  TEST_ASSERT_TRUE(record.m_eol.m_hasMoreEolMaintainedCycles);
}

void test_PRODUCTEXPOSURE_series_past_its_limit_is_error(void)
{
  TEST_ASSERT_EQUAL_INT(8, PRODUCTEXPOSURE_EOL_SERIES_CYCLE_MAX);
  for (int extra = 0; extra <= 1; extra++)
  {
    static_resetFake();
    int series_count = PRODUCTEXPOSURE_EOL_SERIES_CYCLE_MAX + extra;
    FakeAnswer_t* eol = static_queueProductExposureAnswers(series_count + 1);
    static_setEolProductRow(eol, 0, "windows", "https://endoflife.date/windows", "0");
    for (int row = 1; row <= series_count; row++)
      static_setEolCycleRow(eol, row, "series", "11-24h2-w", "2026-10-13", "t", "f", "f", "26100.1");
    PRODUCTEXPOSURERecord_t record;

    DbStatus_t db_status = static_runProductExposure("", false, &record);

    if (extra == 0)
    {
      TEST_ASSERT_EQUAL_INT(DB_OK, db_status);
      TEST_ASSERT_EQUAL_INT(PRODUCTEXPOSURE_EOL_SERIES_CYCLE_MAX, record.m_eol.m_eolSeriesCycleCount);
    }
    else
    {
      TEST_ASSERT_EQUAL_INT(DB_ERROR, db_status);
    }
  }
}

void test_PRODUCTEXPOSURE_eol_answer_with_broken_rows_is_error(void)
{
  for (int broken = 0; broken < 5; broken++)
  {
    static_resetFake();
    FakeAnswer_t* eol = static_queueProductExposureAnswers(2);
    static_setEolProductRow(eol, 0, "windows", "https://endoflife.date/windows", "0");
    static_setEolCycleRow(eol, 1, "series", "11-24h2-w", "2026-10-13", "t", "f", "f", "26100.1");
    if (broken == 0)
      eol->ma_cells[1][0] = "cycle";
    else if (broken == 1)
      static_setEolProductRow(eol, 1, "windows", "https://endoflife.date/windows", "0");
    else if (broken == 2)
      static_setEolCycleRow(eol, 0, "series", "11-24h2-e", "2027-10-12", "f", "t", "f", "26100.2");
    else if (broken == 3)
      eol->ma_cells[0][8] = FAKE_SQL_NULL;
    else
      eol->ma_cells[1][5] = FAKE_SQL_NULL;
    PRODUCTEXPOSURERecord_t record;
    char message[32];
    snprintf(message, sizeof(message), "broken answer %d", broken);

    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_ERROR, static_runProductExposure("", false, &record), message);
  }
}

void test_PRODUCTEXPOSURE_eol_field_past_its_limit_is_error(void)
{
  TEST_ASSERT_EQUAL_INT(256, PRODUCTEXPOSURE_EOL_URL_MAX_LEN);
  TEST_ASSERT_EQUAL_INT(100, PRODUCTEXPOSURE_EOL_LATEST_VERSION_MAX_LEN);
  static const FieldLimit_t fields[] = {
    FIELD_LIMIT(1, 0, 1, PRODUCTEXPOSURE_EOL_PRODUCT_MAX_LEN,        PRODUCTEXPOSURERecord_t, m_eol.ma_eolProduct),
    FIELD_LIMIT(1, 0, 2, PRODUCTEXPOSURE_EOL_URL_MAX_LEN,            PRODUCTEXPOSURERecord_t, m_eol.ma_eolUrl),
    FIELD_LIMIT(1, 1, 1, PRODUCTEXPOSURE_EOL_CYCLE_NAME_MAX_LEN,     PRODUCTEXPOSURERecord_t, m_eol.ma_eolSeriesCycles[0].ma_name),
    FIELD_LIMIT(1, 1, 3, PRODUCTEXPOSURE_EOL_DATE_LEN,               PRODUCTEXPOSURERecord_t, m_eol.ma_eolSeriesCycles[0].ma_eolDate),
    FIELD_LIMIT(1, 1, 7, PRODUCTEXPOSURE_EOL_LATEST_VERSION_MAX_LEN, PRODUCTEXPOSURERecord_t, m_eol.ma_eolSeriesCycles[0].ma_latestVersion),
    FIELD_LIMIT(1, 2, 1, PRODUCTEXPOSURE_EOL_CYCLE_NAME_MAX_LEN,     PRODUCTEXPOSURERecord_t, m_eol.ma_eolMaintainedCycles[0].ma_name),
    FIELD_LIMIT(1, 2, 3, PRODUCTEXPOSURE_EOL_DATE_LEN,               PRODUCTEXPOSURERecord_t, m_eol.ma_eolMaintainedCycles[0].ma_eolDate),
  };
  for (size_t f = 0; f < sizeof(fields) / sizeof(fields[0]); f++)
  {
    for (size_t extra = 0; extra <= 1; extra++)
    {
      static_resetFake();
      size_t length = fields[f].m_limit + extra;
      char* text = static_makeText(length);
      TEST_ASSERT_NOT_NULL(text);
      FakeAnswer_t* eol = static_queueProductExposureAnswers(3);
      static_setEolProductRow(eol, 0, "windows", "https://endoflife.date/windows", "1");
      static_setEolCycleRow(eol, 1, "series", "11-24h2-w", "2026-10-13", "t", "f", "f", "26100.1");
      static_setEolCycleRow(eol, 2, "maintained", "26", "2029-04-30", "f", "t", "f", "26.0.1");
      g_queuedAnswers[fields[f].m_answer].ma_cells[fields[f].m_row][fields[f].m_column] = text;
      PRODUCTEXPOSURERecord_t record;
      char message[96] = "";
      static_fieldMessage(message, sizeof(message), &fields[f], length);

      DbStatus_t db_status = static_runProductExposure("", false, &record);

      if (extra == 0)
      {
        TEST_ASSERT_EQUAL_INT_MESSAGE(DB_OK, db_status, message);
        static_assertFieldHoldsLimit(&record, &fields[f], message);
      }
      else
      {
        TEST_ASSERT_EQUAL_INT_MESSAGE(DB_ERROR, db_status, message);
      }
      free(text);
    }
  }
}

void test_PRODUCTEXPOSURE_reads_at_most_PRODUCTEXPOSURE_TOP_N_top_rows(void)
{
  FakeAnswer_t* exposure = static_queueProductExposureAnswer(g_productExposureSummaryValues, PRODUCTEXPOSURE_TOP_N + 1);
  char* text = static_makeText(CVELOOKUP_ID_MAX_LEN + 1);
  TEST_ASSERT_NOT_NULL(text);
  exposure->ma_cells[PRODUCTEXPOSURE_TOP_N][PRODUCTEXPOSURE_ROW_CVE_ID_COLUMN_INDEX] = text;
  static_queueProductExposureEol(0);
  PRODUCTEXPOSURERecord_t record;

  DbStatus_t db_status = static_runProductExposure("", false, &record);
  free(text);

  TEST_ASSERT_EQUAL_INT(DB_OK, db_status);
  TEST_ASSERT_EQUAL_INT(PRODUCTEXPOSURE_TOP_N, record.m_topCveCount);
  TEST_ASSERT_EQUAL_STRING(g_productExposureTopValues[(PRODUCTEXPOSURE_TOP_N - 1) % 2][0], record.ma_topCves[PRODUCTEXPOSURE_TOP_N - 1].ma_cveId);
}

void test_CPESEARCH_sends_the_query_and_the_page_and_reads_each_row(void)
{
  static const char* const values[] = { "windows 10", "2", "40" };
  static_queueCpeSearchAnswers();
  g_queuedAnswers[0].ma_cells[0][0] = "49";
  CPESEARCHParams_t params;
  memset(&params, 0, sizeof(params));
  static_setText(params.ma_search, sizeof(params.ma_search), "windows 10");
  params.m_limit  = 2;
  params.m_offset = 40;
  CPESEARCHResult_t results;
  memset(&results, 0xA5, sizeof(results));

  TEST_ASSERT_EQUAL_INT(DB_OK, db_CPESEARCH(FAKE_CONN, &params, &results));

  static_assertCall(0, CPESEARCH_TOTAL_CALL, values, 1);
  static_assertCall(1, CPESEARCH_PAGE_CALL,  values, 3);
  TEST_ASSERT_EQUAL_INT(49, results.m_total);
  TEST_ASSERT_EQUAL_INT(2, results.m_count);
  TEST_ASSERT_EQUAL_STRING("microsoft", results.mp_items[0].ma_vendor);
  TEST_ASSERT_EQUAL_STRING("windows_10", results.mp_items[0].ma_product);
  TEST_ASSERT_EQUAL_INT(7, results.mp_items[0].m_vulnerableCveCount);
  TEST_ASSERT_EQUAL_STRING("[\"cna\", \"nvd\"]", results.mp_items[0].mp_productNamedBy);
  TEST_ASSERT_EQUAL_STRING("notepad-plus-plus", results.mp_items[1].ma_vendor);
  TEST_ASSERT_EQUAL_STRING("notepad\\+\\+", results.mp_items[1].ma_product);
  TEST_ASSERT_EQUAL_INT(0, results.mp_items[1].m_vulnerableCveCount);
  TEST_ASSERT_EQUAL_STRING("[\"cna_cpe\"]", results.mp_items[1].mp_productNamedBy);
  db_CPESEARCHResultFree(&results);
  TEST_ASSERT_NULL(results.mp_items);
  TEST_ASSERT_EQUAL_INT(0, results.m_count);
}

void test_CPESEARCH_name_past_its_limit_is_error(void)
{
  static const FieldLimit_t fields[] = {
    FIELD_LIMIT(1, 0, 0, CVESEARCH_VENDOR_LEN,  CPESEARCHItem_t, ma_vendor),
    FIELD_LIMIT(1, 1, 1, CVESEARCH_PRODUCT_LEN, CPESEARCHItem_t, ma_product),
  };

  for (size_t f = 0; f < sizeof(fields) / sizeof(fields[0]); f++)
  {
    for (size_t extra = 0; extra <= 1; extra++)
    {
      static_resetFake();
      size_t length = fields[f].m_limit + extra;
      char* text = static_makeText(length);
      TEST_ASSERT_NOT_NULL(text);
      static_queueCpeSearchAnswers();
      g_queuedAnswers[fields[f].m_answer].ma_cells[fields[f].m_row][fields[f].m_column] = text;
      CPESEARCHParams_t params;
      memset(&params, 0, sizeof(params));
      params.m_limit = 2;
      CPESEARCHResult_t results;
      memset(&results, 0xA5, sizeof(results));
      char message[64] = "";
      static_fieldMessage(message, sizeof(message), &fields[f], length);

      DbStatus_t db_status = db_CPESEARCH(FAKE_CONN, &params, &results);

      if (extra == 0)
      {
        TEST_ASSERT_EQUAL_INT_MESSAGE(DB_OK, db_status, message);
        TEST_ASSERT_EQUAL_INT_MESSAGE(2, results.m_count, message);
        static_assertFieldHoldsLimit(&results.mp_items[fields[f].m_row], &fields[f], message);
        db_CPESEARCHResultFree(&results);
      }
      else
      {
        TEST_ASSERT_EQUAL_INT_MESSAGE(DB_ERROR, db_status, message);
        TEST_ASSERT_NULL_MESSAGE(results.mp_items, message);
      }
      free(text);
    }
  }
}

void test_CPESEARCH_empty_page_is_ok(void)
{
  FakeAnswer_t* total = static_queueAnswer(PGRES_TUPLES_OK, 1, 1);
  total->ma_columnNames[0] = "product_count";
  total->ma_cells[0][0]    = "0";
  FakeAnswer_t* page = static_queueAnswer(PGRES_TUPLES_OK, CPESEARCH_ROW_COLUMN_COUNT, 0);
  for (int col = 0; col < CPESEARCH_ROW_COLUMN_COUNT; col++)
    page->ma_columnNames[col] = g_cpeSearchColumnNames[col];
  CPESEARCHParams_t params;
  memset(&params, 0, sizeof(params));
  params.m_limit = 2;
  CPESEARCHResult_t results;
  memset(&results, 0xA5, sizeof(results));

  TEST_ASSERT_EQUAL_INT(DB_OK, db_CPESEARCH(FAKE_CONN, &params, &results));
  TEST_ASSERT_EQUAL_INT(0, results.m_total);
  TEST_ASSERT_EQUAL_INT(0, results.m_count);
  TEST_ASSERT_NULL(results.mp_items);
}

void test_D3FENDFORATTACK_sends_the_id_and_reads_each_row(void)
{
  static const char* const values[] = { "T1055" };
  static_queueD3fendForAttackAnswer();
  D3FENDFORATTACKResult_t result;
  memset(&result, 0xA5, sizeof(result));

  TEST_ASSERT_EQUAL_INT(DB_OK, db_D3FENDFORATTACK(FAKE_CONN, "T1055", &result));

  static_assertCall(0, D3FENDFORATTACK_CALL, values, 1);
  TEST_ASSERT_EQUAL_INT(2, result.m_defenseCount);
  TEST_ASSERT_EQUAL_STRING(g_d3fendForAttackRowValues[0][6], result.mp_attackTechniques);
  for (int row = 0; row < 2; row++)
  {
    const D3FENDFORATTACKItem_t* item = &result.mp_defenses[row];
    TEST_ASSERT_EQUAL_STRING(g_d3fendForAttackRowValues[row][0], item->ma_defenseId);
    TEST_ASSERT_EQUAL_STRING(g_d3fendForAttackRowValues[row][1], item->ma_defenseLabel);
    TEST_ASSERT_EQUAL_STRING(g_d3fendForAttackRowValues[row][2], item->ma_defenseTactic);
    TEST_ASSERT_EQUAL_STRING(g_d3fendForAttackRowValues[row][3], item->ma_digitalArtifact);
    TEST_ASSERT_EQUAL_STRING(g_d3fendForAttackRowValues[row][4], item->mp_parentDefenseLabels);
    TEST_ASSERT_EQUAL_STRING(g_d3fendForAttackRowValues[row][5], item->mp_attackTechniqueIds);
  }
  for (int pass = 0; pass < 2; pass++)
  {
    db_D3FENDFORATTACKResultFree(&result);
    TEST_ASSERT_NULL(result.mp_attackTechniques);
    TEST_ASSERT_NULL(result.mp_defenses);
    TEST_ASSERT_EQUAL_INT(0, result.m_defenseCount);
  }
}

void test_D3FENDFORATTACK_text_past_its_limit_is_error(void)
{
  static const FieldLimit_t fields[] = {
    FIELD_LIMIT(0, 1, 0, D3FEND_DEFENSE_ID_MAX_LEN,       D3FENDFORATTACKItem_t, ma_defenseId),
    FIELD_LIMIT(0, 1, 1, D3FEND_DEFENSE_LABEL_MAX_LEN,    D3FENDFORATTACKItem_t, ma_defenseLabel),
    FIELD_LIMIT(0, 1, 2, D3FEND_DEFENSE_TACTIC_MAX_LEN,   D3FENDFORATTACKItem_t, ma_defenseTactic),
    FIELD_LIMIT(0, 1, 3, D3FEND_DIGITAL_ARTIFACT_MAX_LEN, D3FENDFORATTACKItem_t, ma_digitalArtifact),
  };

  for (size_t f = 0; f < sizeof(fields) / sizeof(fields[0]); f++)
  {
    for (size_t extra = 0; extra <= 1; extra++)
    {
      static_resetFake();
      size_t length = fields[f].m_limit + extra;
      char* text = static_makeText(length);
      TEST_ASSERT_NOT_NULL(text);
      static_queueD3fendForAttackAnswer();
      g_queuedAnswers[fields[f].m_answer].ma_cells[fields[f].m_row][fields[f].m_column] = text;
      D3FENDFORATTACKResult_t result;
      memset(&result, 0xA5, sizeof(result));
      char message[64] = "";
      static_fieldMessage(message, sizeof(message), &fields[f], length);

      DbStatus_t db_status = db_D3FENDFORATTACK(FAKE_CONN, "T1055", &result);

      if (extra == 0)
      {
        TEST_ASSERT_EQUAL_INT_MESSAGE(DB_OK, db_status, message);
        TEST_ASSERT_EQUAL_INT_MESSAGE(2, result.m_defenseCount, message);
        static_assertFieldHoldsLimit(&result.mp_defenses[fields[f].m_row], &fields[f], message);
        db_D3FENDFORATTACKResultFree(&result);
      }
      else
      {
        TEST_ASSERT_EQUAL_INT_MESSAGE(DB_ERROR, db_status, message);
        TEST_ASSERT_NULL_MESSAGE(result.mp_attackTechniques, message);
        TEST_ASSERT_NULL_MESSAGE(result.mp_defenses, message);
        TEST_ASSERT_EQUAL_INT_MESSAGE(0, result.m_defenseCount, message);
      }
      free(text);
    }
  }
}

void test_D3FENDFORATTACK_failed_copy_frees_every_copy(void)
{
  for (int failing_call = 1; failing_call <= 5; failing_call++)
  {
    static_resetFake();
    static_queueD3fendForAttackAnswer();
    g_strdupFailsAtCall = failing_call;
    D3FENDFORATTACKResult_t result;
    memset(&result, 0xA5, sizeof(result));

    DbStatus_t db_status = db_D3FENDFORATTACK(FAKE_CONN, "T1055", &result);

    TEST_ASSERT_EQUAL_INT(DB_ERROR, db_status);
    TEST_ASSERT_EQUAL_INT(failing_call, g_strdupCallCount);
    TEST_ASSERT_NULL(result.mp_attackTechniques);
    TEST_ASSERT_NULL(result.mp_defenses);
    TEST_ASSERT_EQUAL_INT(0, result.m_defenseCount);
  }
}

void test_D3FENDFORATTACK_no_row_is_ok_and_failed_query_is_error(void)
{
  FakeAnswer_t* empty = static_queueAnswer(PGRES_TUPLES_OK, D3FENDFORATTACK_ROW_COLUMN_COUNT, 0);
  for (int col = 0; col < D3FENDFORATTACK_ROW_COLUMN_COUNT; col++)
    empty->ma_columnNames[col] = g_d3fendForAttackColumnNames[col];
  static_queueAnswer(PGRES_FATAL_ERROR, 0, 0);

  for (int call = 0; call < 2; call++)
  {
    D3FENDFORATTACKResult_t result;
    memset(&result, 0xA5, sizeof(result));
    TEST_ASSERT_EQUAL_INT(call == 0 ? DB_OK : DB_ERROR, db_D3FENDFORATTACK(FAKE_CONN, "T9999", &result));
    TEST_ASSERT_NULL(result.mp_attackTechniques);
    TEST_ASSERT_NULL(result.mp_defenses);
    TEST_ASSERT_EQUAL_INT(0, result.m_defenseCount);
  }
}

void test_DRIVERLOOKUP_sends_the_hash_and_reads_each_column(void)
{
  static const char* const values_without_command[] = { DRIVERLOOKUP_TEST_HASH, "16", "false" };
  static const char* const values_with_command[]    = { DRIVERLOOKUP_TEST_HASH, "16", "true" };
  static_queueDriverLookupAnswer();
  static_queueDriverLookupAnswer()->ma_cells[0][2] = "f";
  DRIVERLOOKUPRecord_t record;
  memset(&record, 0xA5, sizeof(record));

  TEST_ASSERT_EQUAL_INT(DB_OK, db_DRIVERLOOKUP(FAKE_CONN, DRIVERLOOKUP_TEST_HASH, false, &record));

  static_assertCall(0, DRIVERLOOKUP_CALL, values_without_command, 3);
  TEST_ASSERT_EQUAL_STRING(DRIVERLOOKUP_TEST_HASH, record.ma_fileHash);
  TEST_ASSERT_EQUAL_INT(7, record.m_matchCount);
  TEST_ASSERT_TRUE(record.m_isDriverFeedLoaded);
  TEST_ASSERT_EQUAL_STRING(g_driverLookupRowValues[3], record.mp_matches);
  for (int pass = 0; pass < 2; pass++)
  {
    db_DRIVERLOOKUPRecordFree(&record);
    TEST_ASSERT_NULL(record.mp_matches);
  }

  TEST_ASSERT_EQUAL_INT(DB_OK, db_DRIVERLOOKUP(FAKE_CONN, DRIVERLOOKUP_TEST_HASH, true, &record));
  static_assertCall(1, DRIVERLOOKUP_CALL, values_with_command, 3);
  TEST_ASSERT_FALSE(record.m_isDriverFeedLoaded);
  db_DRIVERLOOKUPRecordFree(&record);
  db_DRIVERLOOKUPRecordFree(NULL);
}

void test_DRIVERLOOKUP_hash_and_matches_at_their_limits_and_past_them(void)
{
  for (size_t extra = 0; extra <= 1; extra++)
  {
    static_resetFake();
    char* hash = static_makeText(VALIDATE_SHA256_HEX_LEN + extra);
    TEST_ASSERT_NOT_NULL(hash);
    static_queueDriverLookupAnswer()->ma_cells[0][0] = hash;
    DRIVERLOOKUPRecord_t record;
    memset(&record, 0xA5, sizeof(record));

    DbStatus_t db_status = db_DRIVERLOOKUP(FAKE_CONN, DRIVERLOOKUP_TEST_HASH, false, &record);

    if (extra == 0)
    {
      TEST_ASSERT_EQUAL_INT(DB_OK, db_status);
      TEST_ASSERT_EQUAL_STRING(hash, record.ma_fileHash);
    }
    else
    {
      TEST_ASSERT_EQUAL_INT(DB_ERROR, db_status);
      TEST_ASSERT_NULL(record.mp_matches);
    }
    db_DRIVERLOOKUPRecordFree(&record);
    free(hash);
  }

  for (size_t extra = 0; extra <= 1; extra++)
  {
    static_resetFake();
    char* document = static_makeJsonArrayDocument(DRIVERLOOKUP_MATCHES_MAX_LEN + extra);
    TEST_ASSERT_NOT_NULL(document);
    static_queueDriverLookupAnswer()->ma_cells[0][3] = document;
    DRIVERLOOKUPRecord_t record;
    memset(&record, 0xA5, sizeof(record));

    DbStatus_t db_status = db_DRIVERLOOKUP(FAKE_CONN, DRIVERLOOKUP_TEST_HASH, false, &record);

    if (extra == 0)
    {
      TEST_ASSERT_EQUAL_INT(DB_OK, db_status);
      TEST_ASSERT_NOT_NULL(record.mp_matches);
      TEST_ASSERT_EQUAL_size_t(DRIVERLOOKUP_MATCHES_MAX_LEN, strlen(record.mp_matches));
      TEST_ASSERT_EQUAL_MEMORY(document, record.mp_matches, DRIVERLOOKUP_MATCHES_MAX_LEN);
    }
    else
    {
      TEST_ASSERT_EQUAL_INT(DB_ERROR, db_status);
      TEST_ASSERT_NULL(record.mp_matches);
    }
    db_DRIVERLOOKUPRecordFree(&record);
    free(document);
  }
}

void test_DRIVERLOOKUP_other_than_one_row_or_a_failed_copy_is_error(void)
{
  for (int row_count = 0; row_count <= 2; row_count += 2)
  {
    static_resetFake();
    FakeAnswer_t* answer = static_queueAnswer(PGRES_TUPLES_OK, DRIVERLOOKUP_ROW_COLUMN_COUNT, row_count);
    for (int col = 0; col < DRIVERLOOKUP_ROW_COLUMN_COUNT; col++)
    {
      answer->ma_columnNames[col] = g_driverLookupColumnNames[col];
      for (int row = 0; row < row_count; row++)
        answer->ma_cells[row][col] = g_driverLookupRowValues[col];
    }
    DRIVERLOOKUPRecord_t record;
    memset(&record, 0xA5, sizeof(record));
    TEST_ASSERT_EQUAL_INT(DB_ERROR, db_DRIVERLOOKUP(FAKE_CONN, DRIVERLOOKUP_TEST_HASH, false, &record));
    TEST_ASSERT_NULL(record.mp_matches);
  }

  static_resetFake();
  static_queueAnswer(PGRES_FATAL_ERROR, 0, 0);
  DRIVERLOOKUPRecord_t record;
  memset(&record, 0xA5, sizeof(record));
  TEST_ASSERT_EQUAL_INT(DB_ERROR, db_DRIVERLOOKUP(FAKE_CONN, DRIVERLOOKUP_TEST_HASH, false, &record));
  TEST_ASSERT_NULL(record.mp_matches);

  static_resetFake();
  static_queueDriverLookupAnswer();
  g_strdupFailsAtCall = 1;
  memset(&record, 0xA5, sizeof(record));
  TEST_ASSERT_EQUAL_INT(DB_ERROR, db_DRIVERLOOKUP(FAKE_CONN, DRIVERLOOKUP_TEST_HASH, false, &record));
  TEST_ASSERT_EQUAL_INT(1, g_strdupCallCount);
  TEST_ASSERT_NULL(record.mp_matches);
}

#define DRIVERLOOKUPBULK_TEST_MD5 "5f4dcc3b5aa765d61d8327deb882cf99"

static FakeAnswer_t* static_queueDriverLookupBulkAnswer(int row_count, const char* flag_text)
{
  static const char* const hashes[] = { DRIVERLOOKUP_TEST_HASH, DRIVERLOOKUPBULK_TEST_MD5 };
  static const char* const counts[] = { "7", "3" };
  FakeAnswer_t* answer = static_queueAnswer(PGRES_TUPLES_OK, DRIVERLOOKUP_ROW_COLUMN_COUNT, row_count);
  for (int col = 0; col < DRIVERLOOKUP_ROW_COLUMN_COUNT; col++)
    answer->ma_columnNames[col] = g_driverLookupColumnNames[col];
  for (int row = 0; row < row_count; row++)
  {
    answer->ma_cells[row][0] = hashes[row % 2];
    answer->ma_cells[row][1] = counts[row % 2];
    answer->ma_cells[row][2] = flag_text;
    answer->ma_cells[row][3] = g_driverLookupRowValues[3];
  }
  return answer;
}

void test_DRIVERLOOKUPBULK_sends_the_hashes_and_reads_each_row(void)
{
  static const BulkIdsParams_t params = {
    .ma_ids    = { DRIVERLOOKUP_TEST_HASH, DRIVERLOOKUPBULK_TEST_MD5 },
    .m_idCount = 2,
  };
  static const char* const values[] = { "{" DRIVERLOOKUP_TEST_HASH "," DRIVERLOOKUPBULK_TEST_MD5 "}", "16", "false" };
  static_queueDriverLookupBulkAnswer(2, "f")->ma_cells[1][2] = "t";
  DRIVERLOOKUPBULKResult_t results;
  memset(&results, 0xA5, sizeof(results));

  TEST_ASSERT_EQUAL_INT(DB_OK, db_DRIVERLOOKUPBULK(FAKE_CONN, &params, &results));

  static_assertCall(0, "SELECT * FROM api.fn_driver_lookup($1, $2, $3)", values, 3);
  TEST_ASSERT_EQUAL_INT(2, results.m_successful);
  TEST_ASSERT_EQUAL_INT(0, results.m_failed);
  TEST_ASSERT_EQUAL_STRING(DRIVERLOOKUP_TEST_HASH, results.mp_items[0].ma_fileHash);
  TEST_ASSERT_EQUAL_INT(7, results.mp_items[0].m_matchCount);
  TEST_ASSERT_EQUAL_STRING(DRIVERLOOKUPBULK_TEST_MD5, results.mp_items[1].ma_fileHash);
  TEST_ASSERT_EQUAL_INT(3, results.mp_items[1].m_matchCount);
  TEST_ASSERT_EQUAL_STRING(g_driverLookupRowValues[3], results.mp_items[1].mp_matches);
  TEST_ASSERT_FALSE(results.mp_items[0].m_isDriverFeedLoaded);
  TEST_ASSERT_TRUE(results.mp_items[1].m_isDriverFeedLoaded);
  for (int pass = 0; pass < 2; pass++)
  {
    db_DRIVERLOOKUPBULKResultFree(&results);
    TEST_ASSERT_NULL(results.mp_items);
    TEST_ASSERT_EQUAL_INT(0, results.m_successful);
  }
  db_DRIVERLOOKUPBULKResultFree(NULL);
}

void test_DRIVERLOOKUPBULK_unreadable_row_fails_only_its_hash(void)
{
  static const BulkIdsParams_t params = {
    .ma_ids    = { DRIVERLOOKUP_TEST_HASH, DRIVERLOOKUPBULK_TEST_MD5 },
    .m_idCount = 2,
  };
  static_queueDriverLookupBulkAnswer(2, "t")->ma_cells[0][1] = "12abc";
  DRIVERLOOKUPBULKResult_t results;
  memset(&results, 0xA5, sizeof(results));
  TEST_ASSERT_EQUAL_INT(DB_OK, db_DRIVERLOOKUPBULK(FAKE_CONN, &params, &results));
  TEST_ASSERT_EQUAL_INT(1, results.m_successful);
  TEST_ASSERT_EQUAL_INT(1, results.m_failed);
  TEST_ASSERT_EQUAL_STRING(DRIVERLOOKUPBULK_TEST_MD5, results.mp_items[0].ma_fileHash);
  TEST_ASSERT_TRUE(results.mp_items[0].m_isDriverFeedLoaded);
  db_DRIVERLOOKUPBULKResultFree(&results);

  static_resetFake();
  FakeAnswer_t* answer = static_queueDriverLookupBulkAnswer(2, "t");
  answer->ma_cells[0][1] = "12abc";
  answer->ma_cells[1][1] = "12abc";
  memset(&results, 0xA5, sizeof(results));
  TEST_ASSERT_EQUAL_INT(DB_OK, db_DRIVERLOOKUPBULK(FAKE_CONN, &params, &results));
  TEST_ASSERT_EQUAL_INT(0, results.m_successful);
  TEST_ASSERT_EQUAL_INT(2, results.m_failed);
  db_DRIVERLOOKUPBULKResultFree(&results);
}

void test_DRIVERLOOKUPBULK_other_row_count_is_error(void)
{
  static const BulkIdsParams_t params = {
    .ma_ids    = { DRIVERLOOKUP_TEST_HASH, DRIVERLOOKUPBULK_TEST_MD5 },
    .m_idCount = 2,
  };
  for (int row_count = 1; row_count <= 3; row_count += 2)
  {
    static_resetFake();
    static_queueDriverLookupBulkAnswer(row_count, "t");
    DRIVERLOOKUPBULKResult_t results;
    memset(&results, 0xA5, sizeof(results));
    TEST_ASSERT_EQUAL_INT(DB_ERROR, db_DRIVERLOOKUPBULK(FAKE_CONN, &params, &results));
    TEST_ASSERT_NULL(results.mp_items);
  }

  static_resetFake();
  static_queueAnswer(PGRES_FATAL_ERROR, 0, 0);
  DRIVERLOOKUPBULKResult_t results;
  memset(&results, 0xA5, sizeof(results));
  TEST_ASSERT_EQUAL_INT(DB_ERROR, db_DRIVERLOOKUPBULK(FAKE_CONN, &params, &results));
  TEST_ASSERT_NULL(results.mp_items);
}

static void static_IPLOOKUPFeedFlags(const IPLOOKUPRecord_t* record, bool flags_out[5])
{
  flags_out[0] = record->m_isAsnFeedLoaded;
  flags_out[1] = record->m_isGeoFeedLoaded;
  flags_out[2] = record->m_isCloudFeedLoaded;
  flags_out[3] = record->m_isTorFeedLoaded;
  flags_out[4] = record->m_isDropListFeedLoaded;
}

void test_IPLOOKUP_sends_the_address_and_reads_each_column(void)
{
  static const char* const values[] = { IPLOOKUP_TEST_IP };
  static const int value_columns[3] = { IPLOOKUP_COL_IS_CDN, IPLOOKUP_COL_IS_DATACENTER, IPLOOKUP_COL_IS_TOR_EXIT };
  for (int pass = 0; pass < 2; pass++)
  {
    static_resetFake();
    FakeAnswer_t* answer = static_queueIpLookupAnswer();
    for (int n = 0; n < 3; n++)
      answer->ma_cells[0][value_columns[n]] = (((n + 1) >> pass) & 1) ? "t" : "f";
    IPLOOKUPRecord_t record;
    memset(&record, 0xA5, sizeof(record));

    TEST_ASSERT_EQUAL_INT(DB_OK, db_IPLOOKUP(FAKE_CONN, IPLOOKUP_TEST_IP, &record));

    static_assertCall(0, IPLOOKUP_CALL, values, 1);
    TEST_ASSERT_EQUAL_STRING(IPLOOKUP_TEST_IP, record.ma_ipAddress);
    TEST_ASSERT_EQUAL_UINT32(15169, record.m_asn);
    TEST_ASSERT_EQUAL_STRING("GOOGLE", record.ma_asnName);
    TEST_ASSERT_EQUAL_STRING("US", record.ma_asnCountry);
    TEST_ASSERT_EQUAL_STRING("AU", record.ma_geoCountry);
    TEST_ASSERT_EQUAL_STRING("google", record.ma_cloudProvider);
    TEST_ASSERT_EQUAL_STRING("googlecloud", record.ma_cloudService);
    TEST_ASSERT_EQUAL_STRING(IPLOOKUP_TEST_LISTED_ON, record.mp_listedOn);
    const bool booleans[3] = { record.m_isCdn, record.m_isDatacenter, record.m_isTorExit };
    for (int n = 0; n < 3; n++)
    {
      char message[32];
      snprintf(message, sizeof(message), "pass %d, boolean %d", pass, n);
      TEST_ASSERT_TRUE_MESSAGE(booleans[n] == ((((n + 1) >> pass) & 1) != 0), message);
    }
    bool flags[5];
    static_IPLOOKUPFeedFlags(&record, flags);
    for (int n = 0; n < 5; n++)
      TEST_ASSERT_TRUE_MESSAGE(flags[n], g_ipLookupColumnNames[IPLOOKUP_COL_ASN_FEED_LOADED + n]);
    unsigned char untouched[sizeof(record.m_ptrAnswer)];
    memset(untouched, 0xA5, sizeof(untouched));
    TEST_ASSERT_EQUAL_MEMORY(untouched, &record.m_ptrAnswer, sizeof(untouched));

    db_IPLOOKUPRecordFree(&record);
    TEST_ASSERT_NULL(record.mp_listedOn);
    db_IPLOOKUPRecordFree(&record);
    TEST_ASSERT_NULL(record.mp_listedOn);
  }
  db_IPLOOKUPRecordFree(NULL);
}

void test_IPLOOKUP_null_texts_and_asn_read_as_empty(void)
{
  FakeAnswer_t* answer = static_queueIpLookupAnswer();
  for (int col = IPLOOKUP_COL_ASN; col <= IPLOOKUP_COL_CLOUD_SERVICE; col++)
    answer->ma_cells[0][col] = FAKE_SQL_NULL;
  IPLOOKUPRecord_t record;
  memset(&record, 0xA5, sizeof(record));

  TEST_ASSERT_EQUAL_INT(DB_OK, db_IPLOOKUP(FAKE_CONN, IPLOOKUP_TEST_IP, &record));

  TEST_ASSERT_EQUAL_UINT32(0, record.m_asn);
  TEST_ASSERT_EQUAL_STRING("", record.ma_asnName);
  TEST_ASSERT_EQUAL_STRING("", record.ma_asnCountry);
  TEST_ASSERT_EQUAL_STRING("", record.ma_geoCountry);
  TEST_ASSERT_EQUAL_STRING("", record.ma_cloudProvider);
  TEST_ASSERT_EQUAL_STRING("", record.ma_cloudService);
  db_IPLOOKUPRecordFree(&record);
}

void test_IPLOOKUP_unloaded_feed_leaves_its_column_unread(void)
{
  static const struct { int m_flagColumn; int m_dependentColumn; const char* mp_filled; } feeds[] = {
    { IPLOOKUP_COL_ASN_FEED_LOADED,       -1,                      NULL },
    { IPLOOKUP_COL_GEO_FEED_LOADED,       -1,                      NULL },
    { IPLOOKUP_COL_CLOUD_FEED_LOADED,     IPLOOKUP_COL_IS_CDN,      "t" },
    { IPLOOKUP_COL_TOR_FEED_LOADED,       IPLOOKUP_COL_IS_TOR_EXIT, "t" },
    { IPLOOKUP_COL_DROP_LIST_FEED_LOADED, IPLOOKUP_COL_LISTED_ON,   "[]" },
  };
  for (size_t i = 0; i < sizeof(feeds) / sizeof(feeds[0]); i++)
  {
    for (int is_filled = 0; is_filled <= 1; is_filled++)
    {
      const char* name = g_ipLookupColumnNames[feeds[i].m_flagColumn];
      static_resetFake();
      FakeAnswer_t* answer = static_queueIpLookupAnswer();
      answer->ma_cells[0][feeds[i].m_flagColumn] = "f";
      if (feeds[i].m_dependentColumn >= 0)
        answer->ma_cells[0][feeds[i].m_dependentColumn] = is_filled ? feeds[i].mp_filled : FAKE_SQL_NULL;
      IPLOOKUPRecord_t record;
      memset(&record, 0xA5, sizeof(record));

      TEST_ASSERT_EQUAL_INT_MESSAGE(DB_OK, db_IPLOOKUP(FAKE_CONN, IPLOOKUP_TEST_IP, &record), name);

      bool flags[5];
      static_IPLOOKUPFeedFlags(&record, flags);
      for (int n = 0; n < 5; n++)
        TEST_ASSERT_TRUE_MESSAGE(flags[n] == (IPLOOKUP_COL_ASN_FEED_LOADED + n != feeds[i].m_flagColumn), name);
      TEST_ASSERT_TRUE_MESSAGE(record.m_isDatacenter, name);
      TEST_ASSERT_TRUE_MESSAGE(record.m_isCdn == (feeds[i].m_dependentColumn != IPLOOKUP_COL_IS_CDN), name);
      TEST_ASSERT_FALSE_MESSAGE(record.m_isTorExit, name);
      if (feeds[i].m_dependentColumn == IPLOOKUP_COL_LISTED_ON)
        TEST_ASSERT_NULL_MESSAGE(record.mp_listedOn, name);
      else
        TEST_ASSERT_EQUAL_STRING_MESSAGE(IPLOOKUP_TEST_LISTED_ON, record.mp_listedOn, name);
      db_IPLOOKUPRecordFree(&record);
    }
  }
}

void test_IPLOOKUP_null_in_a_loaded_feed_or_a_feed_flag_is_error(void)
{
  static const int null_columns[] = {
    IPLOOKUP_COL_IS_CDN, IPLOOKUP_COL_IS_TOR_EXIT, IPLOOKUP_COL_LISTED_ON,
    IPLOOKUP_COL_ASN_FEED_LOADED, IPLOOKUP_COL_GEO_FEED_LOADED, IPLOOKUP_COL_CLOUD_FEED_LOADED,
    IPLOOKUP_COL_TOR_FEED_LOADED, IPLOOKUP_COL_DROP_LIST_FEED_LOADED,
  };
  for (size_t i = 0; i < sizeof(null_columns) / sizeof(null_columns[0]); i++)
  {
    static_resetFake();
    static_queueIpLookupAnswer()->ma_cells[0][null_columns[i]] = FAKE_SQL_NULL;
    IPLOOKUPRecord_t record;
    memset(&record, 0xA5, sizeof(record));

    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_ERROR, db_IPLOOKUP(FAKE_CONN, IPLOOKUP_TEST_IP, &record), g_ipLookupColumnNames[null_columns[i]]);

    TEST_ASSERT_NULL_MESSAGE(record.mp_listedOn, g_ipLookupColumnNames[null_columns[i]]);
  }
}

void test_IPLOOKUP_no_cloud_range_leaves_is_cdn_unread(void)
{
  for (int is_filled = 0; is_filled <= 1; is_filled++)
  {
    const char* name = is_filled ? "is_cdn t" : "is_cdn NULL";
    static_resetFake();
    FakeAnswer_t* answer = static_queueIpLookupAnswer();
    answer->ma_cells[0][IPLOOKUP_COL_CLOUD_PROVIDER] = FAKE_SQL_NULL;
    answer->ma_cells[0][IPLOOKUP_COL_CLOUD_SERVICE]  = FAKE_SQL_NULL;
    answer->ma_cells[0][IPLOOKUP_COL_IS_CDN]         = is_filled ? "t" : FAKE_SQL_NULL;
    IPLOOKUPRecord_t record;
    memset(&record, 0xA5, sizeof(record));

    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_OK, db_IPLOOKUP(FAKE_CONN, IPLOOKUP_TEST_IP, &record), name);

    TEST_ASSERT_EQUAL_STRING_MESSAGE("", record.ma_cloudProvider, name);
    TEST_ASSERT_EQUAL_STRING_MESSAGE("", record.ma_cloudService, name);
    TEST_ASSERT_TRUE_MESSAGE(record.m_isCloudFeedLoaded, name);
    TEST_ASSERT_FALSE_MESSAGE(record.m_isCdn, name);
    db_IPLOOKUPRecordFree(&record);
  }
}

void test_IPLOOKUP_null_datacenter_is_false_only_while_a_feed_is_off(void)
{
  static const struct { bool m_isAsnLoaded; bool m_isCloudLoaded; const char* mp_name; } cases[] = {
    { false, true,  "asn feed off" },
    { true,  false, "cloud feed off" },
    { false, false, "both feeds off" },
    { true,  true,  "both feeds on" },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    for (int is_true = 0; is_true <= 1; is_true++)
    {
      static_resetFake();
      FakeAnswer_t* answer = static_queueIpLookupAnswer();
      answer->ma_cells[0][IPLOOKUP_COL_ASN_FEED_LOADED]   = cases[i].m_isAsnLoaded ? "t" : "f";
      answer->ma_cells[0][IPLOOKUP_COL_CLOUD_FEED_LOADED] = cases[i].m_isCloudLoaded ? "t" : "f";
      answer->ma_cells[0][IPLOOKUP_COL_IS_DATACENTER]     = is_true ? "t" : FAKE_SQL_NULL;
      IPLOOKUPRecord_t record;
      memset(&record, 0xA5, sizeof(record));
      bool is_refused = !is_true && cases[i].m_isAsnLoaded && cases[i].m_isCloudLoaded;

      DbStatus_t db_status = db_IPLOOKUP(FAKE_CONN, IPLOOKUP_TEST_IP, &record);

      TEST_ASSERT_EQUAL_INT_MESSAGE(is_refused ? DB_ERROR : DB_OK, db_status, cases[i].mp_name);
      if (is_refused)
        TEST_ASSERT_NULL_MESSAGE(record.mp_listedOn, cases[i].mp_name);
      else
        TEST_ASSERT_TRUE_MESSAGE(record.m_isDatacenter == (is_true != 0), cases[i].mp_name);
      db_IPLOOKUPRecordFree(&record);
    }
  }
}

void test_IPLOOKUP_asn_from_1_to_4294967295_and_nothing_else(void)
{
  static const struct { const char* mp_text; DbStatus_t m_status; uint32_t m_asn; } cases[] = {
    { "1",                     DB_OK,    1u },
    { "4294967295",            DB_OK,    4294967295u },
    { "0",                     DB_ERROR, 0 },
    { "4294967296",            DB_ERROR, 0 },
    { "184467440737095516160", DB_ERROR, 0 },
    { "+5",                    DB_ERROR, 0 },
    { " 5",                    DB_ERROR, 0 },
    { "-1",                    DB_ERROR, 0 },
    { "12abc",                 DB_ERROR, 0 },
    { "",                      DB_ERROR, 0 },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    static_resetFake();
    static_queueIpLookupAnswer()->ma_cells[0][IPLOOKUP_COL_ASN] = cases[i].mp_text;
    IPLOOKUPRecord_t record;
    memset(&record, 0xA5, sizeof(record));

    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_status, db_IPLOOKUP(FAKE_CONN, IPLOOKUP_TEST_IP, &record), cases[i].mp_text);

    TEST_ASSERT_EQUAL_UINT32_MESSAGE(cases[i].m_asn, record.m_asn, cases[i].mp_text);
    if (cases[i].m_status != DB_OK)
      TEST_ASSERT_NULL_MESSAGE(record.mp_listedOn, cases[i].mp_text);
    db_IPLOOKUPRecordFree(&record);
  }
}

void test_IPLOOKUP_texts_and_listed_on_at_their_limits_and_past_them(void)
{
  static const struct { int m_column; size_t m_limit; } limits[] = {
    { IPLOOKUP_COL_ASN_NAME,       256 },
    { IPLOOKUP_COL_ASN_COUNTRY,    2 },
    { IPLOOKUP_COL_GEO_COUNTRY,    2 },
    { IPLOOKUP_COL_CLOUD_PROVIDER, 10 },
    { IPLOOKUP_COL_CLOUD_SERVICE,  32 },
    { IPLOOKUP_COL_LISTED_ON,      IPLOOKUP_LISTED_ON_MAX_LEN },
  };
  for (size_t i = 0; i < sizeof(limits) / sizeof(limits[0]); i++)
  {
    for (size_t extra = 0; extra <= 1; extra++)
    {
      static_resetFake();
      size_t length = limits[i].m_limit + extra;
      char* text = limits[i].m_column == IPLOOKUP_COL_LISTED_ON ? static_makeJsonArrayDocument(length) : static_makeText(length);
      TEST_ASSERT_NOT_NULL(text);
      static_queueIpLookupAnswer()->ma_cells[0][limits[i].m_column] = text;
      IPLOOKUPRecord_t record;
      memset(&record, 0xA5, sizeof(record));
      const char* name = g_ipLookupColumnNames[limits[i].m_column];

      DbStatus_t db_status = db_IPLOOKUP(FAKE_CONN, IPLOOKUP_TEST_IP, &record);

      if (extra == 0)
      {
        TEST_ASSERT_EQUAL_INT_MESSAGE(DB_OK, db_status, name);
        const char* fields[IPLOOKUP_ROW_COLUMN_COUNT] = { NULL };
        fields[IPLOOKUP_COL_ASN_NAME]       = record.ma_asnName;
        fields[IPLOOKUP_COL_ASN_COUNTRY]    = record.ma_asnCountry;
        fields[IPLOOKUP_COL_GEO_COUNTRY]    = record.ma_geoCountry;
        fields[IPLOOKUP_COL_CLOUD_PROVIDER] = record.ma_cloudProvider;
        fields[IPLOOKUP_COL_CLOUD_SERVICE]  = record.ma_cloudService;
        fields[IPLOOKUP_COL_LISTED_ON]      = record.mp_listedOn;
        TEST_ASSERT_EQUAL_STRING_MESSAGE(text, fields[limits[i].m_column], name);
      }
      else
      {
        TEST_ASSERT_EQUAL_INT_MESSAGE(DB_ERROR, db_status, name);
        TEST_ASSERT_NULL_MESSAGE(record.mp_listedOn, name);
      }
      db_IPLOOKUPRecordFree(&record);
      free(text);
    }
  }
}

void test_IPLOOKUP_other_than_one_row_a_failed_copy_or_a_long_address_is_error(void)
{
  for (int row_count = 0; row_count <= 2; row_count += 2)
  {
    static_resetFake();
    FakeAnswer_t* answer = static_queueAnswer(PGRES_TUPLES_OK, IPLOOKUP_ROW_COLUMN_COUNT, row_count);
    for (int col = 0; col < IPLOOKUP_ROW_COLUMN_COUNT; col++)
    {
      answer->ma_columnNames[col] = g_ipLookupColumnNames[col];
      for (int row = 0; row < row_count; row++)
        answer->ma_cells[row][col] = g_ipLookupRowValues[col];
    }
    IPLOOKUPRecord_t record;
    memset(&record, 0xA5, sizeof(record));
    TEST_ASSERT_EQUAL_INT(DB_ERROR, db_IPLOOKUP(FAKE_CONN, IPLOOKUP_TEST_IP, &record));
    TEST_ASSERT_NULL(record.mp_listedOn);
  }

  static_resetFake();
  static_queueAnswer(PGRES_FATAL_ERROR, 0, 0);
  IPLOOKUPRecord_t record;
  memset(&record, 0xA5, sizeof(record));
  TEST_ASSERT_EQUAL_INT(DB_ERROR, db_IPLOOKUP(FAKE_CONN, IPLOOKUP_TEST_IP, &record));
  TEST_ASSERT_NULL(record.mp_listedOn);

  static_resetFake();
  static_queueIpLookupAnswer();
  g_strdupFailsAtCall = 1;
  memset(&record, 0xA5, sizeof(record));
  TEST_ASSERT_EQUAL_INT(DB_ERROR, db_IPLOOKUP(FAKE_CONN, IPLOOKUP_TEST_IP, &record));
  TEST_ASSERT_EQUAL_INT(1, g_strdupCallCount);
  TEST_ASSERT_NULL(record.mp_listedOn);

  static_resetFake();
  static_queueIpLookupAnswer();
  char* long_address = static_makeText(INET6_ADDRSTRLEN);
  TEST_ASSERT_NOT_NULL(long_address);
  memset(&record, 0xA5, sizeof(record));
  TEST_ASSERT_EQUAL_INT(DB_ERROR, db_IPLOOKUP(FAKE_CONN, long_address, &record));
  TEST_ASSERT_NULL(record.mp_listedOn);
  TEST_ASSERT_EQUAL_INT(0, g_callCount);
  free(long_address);

  static_resetFake();
  static_queueIpLookupAnswer();
  char* longest_address = static_makeText(INET6_ADDRSTRLEN - 1);
  TEST_ASSERT_NOT_NULL(longest_address);
  TEST_ASSERT_EQUAL_INT(DB_OK, db_IPLOOKUP(FAKE_CONN, longest_address, &record));
  TEST_ASSERT_EQUAL_STRING(longest_address, record.ma_ipAddress);
  db_IPLOOKUPRecordFree(&record);
  free(longest_address);
}

static void static_assertAsnLookupRecord(const ASNLOOKUPRecord_t* record, uint32_t asn, const char* label)
{
  TEST_ASSERT_EQUAL_UINT32_MESSAGE(asn, record->m_asn, label);
  TEST_ASSERT_EQUAL_STRING_MESSAGE("CLOUDFLARENET", record->ma_asnName, label);
  TEST_ASSERT_EQUAL_STRING_MESSAGE("US", record->ma_asnCountry, label);
  TEST_ASSERT_EQUAL_INT_MESSAGE(1789, record->m_ipv4PrefixCount, label);
  TEST_ASSERT_EQUAL_INT_MESSAGE(214, record->m_ipv6PrefixCount, label);
  TEST_ASSERT_EQUAL_STRING_MESSAGE(ASNLOOKUP_TEST_IPV4_PREFIXES, record->mp_ipv4Prefixes, label);
  TEST_ASSERT_EQUAL_STRING_MESSAGE(ASNLOOKUP_TEST_IPV6_PREFIXES, record->mp_ipv6Prefixes, label);
}

void test_ASNLOOKUP_ip_target_reads_its_prefix_then_its_as(void)
{
  static const struct { const char* mp_asnText; uint32_t m_asn; } passes[] = {
    { "13335",      13335u },
    { "4294967295", 4294967295u },
  };
  for (size_t i = 0; i < sizeof(passes) / sizeof(passes[0]); i++)
  {
    static_resetFake();
    static_queueAsnPrefixAnswer()->ma_cells[0][0] = passes[i].mp_asnText;
    static_queueAsnLookupAnswer()->ma_cells[0][ASNLOOKUP_COL_ASN] = passes[i].mp_asnText;
    ASNLOOKUPParams_t params = static_asnLookupParams(ASNLOOKUP_TEST_IP);
    params.m_limit  = 12;
    params.m_offset = 34;
    ASNLOOKUPRecord_t record;
    memset(&record, 0xA5, sizeof(record));

    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_OK, db_ASNLOOKUP(FAKE_CONN, &params, &record), passes[i].mp_asnText);

    TEST_ASSERT_EQUAL_INT(2, g_callCount);
    const char* const prefix_values[] = { ASNLOOKUP_TEST_IP };
    static_assertCall(0, ASNPREFIX_CALL, prefix_values, 1);
    const char* const lookup_values[] = { passes[i].mp_asnText, "12", "34" };
    static_assertCall(1, ASNLOOKUP_CALL, lookup_values, 3);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(ASNLOOKUP_TEST_PREFIX, record.ma_prefix, passes[i].mp_asnText);
    static_assertAsnLookupRecord(&record, passes[i].m_asn, passes[i].mp_asnText);

    db_ASNLOOKUPRecordFree(&record);
    TEST_ASSERT_NULL(record.mp_ipv4Prefixes);
    TEST_ASSERT_NULL(record.mp_ipv6Prefixes);
    db_ASNLOOKUPRecordFree(&record);
    TEST_ASSERT_NULL(record.mp_ipv4Prefixes);
    TEST_ASSERT_NULL(record.mp_ipv6Prefixes);
  }
  db_ASNLOOKUPRecordFree(NULL);
}

void test_ASNLOOKUP_as_target_reads_its_as_alone(void)
{
  static const struct { const char* mp_target; int m_limit; int m_offset; const char* mp_asnText; const char* mp_limitText; const char* mp_offsetText; uint32_t m_asn; } cases[] = {
    { "AS1",          50, 0,       "1",          "50", "0",          1u },
    { "AS4294967295", 1,  INT_MAX, "4294967295", "1",  "2147483647", 4294967295u },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    static_resetFake();
    static_queueAsnLookupAnswer()->ma_cells[0][ASNLOOKUP_COL_ASN] = cases[i].mp_asnText;
    ASNLOOKUPParams_t params = static_asnLookupParams(cases[i].mp_target);
    params.m_limit  = cases[i].m_limit;
    params.m_offset = cases[i].m_offset;
    ASNLOOKUPRecord_t record;
    memset(&record, 0xA5, sizeof(record));

    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_OK, db_ASNLOOKUP(FAKE_CONN, &params, &record), cases[i].mp_target);

    TEST_ASSERT_EQUAL_INT(1, g_callCount);
    const char* const values[] = { cases[i].mp_asnText, cases[i].mp_limitText, cases[i].mp_offsetText };
    static_assertCall(0, ASNLOOKUP_CALL, values, 3);
    TEST_ASSERT_EQUAL_STRING_MESSAGE("", record.ma_prefix, cases[i].mp_target);
    static_assertAsnLookupRecord(&record, cases[i].m_asn, cases[i].mp_target);
    db_ASNLOOKUPRecordFree(&record);
  }
}

void test_ASNLOOKUP_no_row_at_either_step_is_not_found(void)
{
  enum { NO_PREFIX_STEP = -1 };
  static const struct { const char* mp_target; int m_prefixRowCount; int m_callCount; } cases[] = {
    { ASNLOOKUP_TEST_IP, 0,              1 },
    { ASNLOOKUP_TEST_IP, 1,              2 },
    { "AS64496",         NO_PREFIX_STEP, 1 },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    static_resetFake();
    if (cases[i].m_prefixRowCount != NO_PREFIX_STEP)
    {
      FakeAnswer_t* prefix = static_queueAnswer(PGRES_TUPLES_OK, ASNPREFIX_ROW_COLUMN_COUNT, cases[i].m_prefixRowCount);
      for (int col = 0; col < ASNPREFIX_ROW_COLUMN_COUNT; col++)
      {
        prefix->ma_columnNames[col] = g_asnPrefixColumnNames[col];
        if (cases[i].m_prefixRowCount == 1)
          prefix->ma_cells[0][col] = g_asnPrefixRowValues[col];
      }
    }
    FakeAnswer_t* lookup = static_queueAnswer(PGRES_TUPLES_OK, ASNLOOKUP_ROW_COLUMN_COUNT, 0);
    for (int col = 0; col < ASNLOOKUP_ROW_COLUMN_COUNT; col++)
      lookup->ma_columnNames[col] = g_asnLookupColumnNames[col];
    ASNLOOKUPParams_t params = static_asnLookupParams(cases[i].mp_target);
    ASNLOOKUPRecord_t record;
    memset(&record, 0xA5, sizeof(record));
    char label[32];
    snprintf(label, sizeof(label), "case %zu", i);

    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_NOT_FOUND, db_ASNLOOKUP(FAKE_CONN, &params, &record), label);

    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_callCount, g_callCount, label);
    TEST_ASSERT_NULL_MESSAGE(record.mp_ipv4Prefixes, label);
    TEST_ASSERT_NULL_MESSAGE(record.mp_ipv6Prefixes, label);
  }
}

void test_ASNLOOKUP_two_rows_or_a_failed_query_at_either_step_is_error(void)
{
  for (int step = 0; step < 2; step++)
  {
    for (int is_failed = 0; is_failed <= 1; is_failed++)
    {
      static_resetFake();
      if (step == 1)
        static_queueAsnPrefixAnswer();
      int column_count = step == 0 ? ASNPREFIX_ROW_COLUMN_COUNT : ASNLOOKUP_ROW_COLUMN_COUNT;
      FakeAnswer_t* answer = static_queueAnswer(is_failed ? PGRES_FATAL_ERROR : PGRES_TUPLES_OK, is_failed ? 0 : column_count, is_failed ? 0 : 2);
      for (int col = 0; !is_failed && col < column_count; col++)
      {
        answer->ma_columnNames[col] = step == 0 ? g_asnPrefixColumnNames[col] : g_asnLookupColumnNames[col];
        for (int row = 0; row < 2; row++)
          answer->ma_cells[row][col] = step == 0 ? g_asnPrefixRowValues[col] : g_asnLookupRowValues[col];
      }
      ASNLOOKUPParams_t params = static_asnLookupParams(ASNLOOKUP_TEST_IP);
      ASNLOOKUPRecord_t record;
      memset(&record, 0xA5, sizeof(record));
      char label[32];
      snprintf(label, sizeof(label), "step %d failed %d", step, is_failed);

      TEST_ASSERT_EQUAL_INT_MESSAGE(DB_ERROR, db_ASNLOOKUP(FAKE_CONN, &params, &record), label);

      TEST_ASSERT_EQUAL_INT_MESSAGE(step + 1, g_callCount, label);
      TEST_ASSERT_NULL_MESSAGE(record.mp_ipv4Prefixes, label);
      TEST_ASSERT_NULL_MESSAGE(record.mp_ipv6Prefixes, label);
    }
  }
}

void test_ASNLOOKUP_null_country_reads_as_empty(void)
{
  static_queueAsnLookupAnswer()->ma_cells[0][ASNLOOKUP_COL_ASN_COUNTRY] = FAKE_SQL_NULL;
  ASNLOOKUPParams_t params = static_asnLookupParams("AS13335");
  ASNLOOKUPRecord_t record;
  memset(&record, 0xA5, sizeof(record));

  TEST_ASSERT_EQUAL_INT(DB_OK, db_ASNLOOKUP(FAKE_CONN, &params, &record));

  TEST_ASSERT_EQUAL_STRING("", record.ma_asnCountry);
  TEST_ASSERT_EQUAL_UINT32(13335, record.m_asn);
  TEST_ASSERT_EQUAL_STRING("CLOUDFLARENET", record.ma_asnName);
  TEST_ASSERT_EQUAL_INT(214, record.m_ipv6PrefixCount);
  db_ASNLOOKUPRecordFree(&record);
}

void test_ASNLOOKUP_asn_from_1_to_4294967295_at_both_steps_and_nothing_else(void)
{
  const char* const sql_null = FAKE_SQL_NULL;
  const struct { const char* mp_text; DbStatus_t m_status; } cases[] = {
    { "1",                     DB_OK },
    { "4294967295",            DB_OK },
    { "0",                     DB_ERROR },
    { "4294967296",            DB_ERROR },
    { "99999999999",           DB_ERROR },
    { "184467440737095516160", DB_ERROR },
    { "+5",                    DB_ERROR },
    { " 5",                    DB_ERROR },
    { "-1",                    DB_ERROR },
    { "12abc",                 DB_ERROR },
    { "",                      DB_ERROR },
    { sql_null,                DB_ERROR },
  };
  for (int step = 0; step < 2; step++)
  {
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
    {
      static_resetFake();
      if (step == 1)
        static_queueAsnPrefixAnswer()->ma_cells[0][0] = cases[i].mp_text;
      FakeAnswer_t* lookup = static_queueAsnLookupAnswer();
      if (step == 0)
        lookup->ma_cells[0][ASNLOOKUP_COL_ASN] = cases[i].mp_text;
      else if (cases[i].m_status == DB_OK)
        lookup->ma_cells[0][ASNLOOKUP_COL_ASN] = cases[i].mp_text;
      ASNLOOKUPParams_t params = static_asnLookupParams(step == 0 ? "AS13335" : ASNLOOKUP_TEST_IP);
      ASNLOOKUPRecord_t record;
      memset(&record, 0xA5, sizeof(record));
      char label[48];
      snprintf(label, sizeof(label), "step %d asn '%s'", step, cases[i].mp_text == sql_null ? "NULL" : cases[i].mp_text);

      TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_status, db_ASNLOOKUP(FAKE_CONN, &params, &record), label);

      if (cases[i].m_status == DB_OK)
        TEST_ASSERT_EQUAL_UINT32_MESSAGE((uint32_t)strtoul(cases[i].mp_text, NULL, 10), record.m_asn, label);
      else
      {
        TEST_ASSERT_NULL_MESSAGE(record.mp_ipv4Prefixes, label);
        TEST_ASSERT_NULL_MESSAGE(record.mp_ipv6Prefixes, label);
        TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_callCount, label);
      }
      db_ASNLOOKUPRecordFree(&record);
    }
  }
}

void test_ASNLOOKUP_counts_are_never_null_or_negative(void)
{
  static const int count_columns[] = { ASNLOOKUP_COL_IPV4_PREFIX_COUNT, ASNLOOKUP_COL_IPV6_PREFIX_COUNT };
  const char* const texts[] = { "0", "-1", "abc", FAKE_SQL_NULL };
  for (size_t c = 0; c < sizeof(count_columns) / sizeof(count_columns[0]); c++)
  {
    for (size_t i = 0; i < sizeof(texts) / sizeof(texts[0]); i++)
    {
      static_resetFake();
      static_queueAsnLookupAnswer()->ma_cells[0][count_columns[c]] = texts[i];
      ASNLOOKUPParams_t params = static_asnLookupParams("AS13335");
      ASNLOOKUPRecord_t record;
      memset(&record, 0xA5, sizeof(record));
      char label[48];
      snprintf(label, sizeof(label), "%s '%s'", g_asnLookupColumnNames[count_columns[c]], texts[i]);

      DbStatus_t db_status = db_ASNLOOKUP(FAKE_CONN, &params, &record);

      if (i == 0)
      {
        TEST_ASSERT_EQUAL_INT_MESSAGE(DB_OK, db_status, label);
        TEST_ASSERT_EQUAL_INT_MESSAGE(c == 0 ? 0 : 1789, record.m_ipv4PrefixCount, label);
        TEST_ASSERT_EQUAL_INT_MESSAGE(c == 1 ? 0 : 214, record.m_ipv6PrefixCount, label);
      }
      else
      {
        TEST_ASSERT_EQUAL_INT_MESSAGE(DB_ERROR, db_status, label);
        TEST_ASSERT_NULL_MESSAGE(record.mp_ipv4Prefixes, label);
        TEST_ASSERT_NULL_MESSAGE(record.mp_ipv6Prefixes, label);
      }
      db_ASNLOOKUPRecordFree(&record);
    }
  }
}

void test_ASNLOOKUP_prefix_lists_are_never_null(void)
{
  static const int list_columns[] = { ASNLOOKUP_COL_IPV4_PREFIXES, ASNLOOKUP_COL_IPV6_PREFIXES };
  for (size_t c = 0; c < sizeof(list_columns) / sizeof(list_columns[0]); c++)
  {
    static_resetFake();
    static_queueAsnLookupAnswer()->ma_cells[0][list_columns[c]] = FAKE_SQL_NULL;
    ASNLOOKUPParams_t params = static_asnLookupParams("AS13335");
    ASNLOOKUPRecord_t record;
    memset(&record, 0xA5, sizeof(record));

    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_ERROR, db_ASNLOOKUP(FAKE_CONN, &params, &record), g_asnLookupColumnNames[list_columns[c]]);

    TEST_ASSERT_NULL_MESSAGE(record.mp_ipv4Prefixes, g_asnLookupColumnNames[list_columns[c]]);
    TEST_ASSERT_NULL_MESSAGE(record.mp_ipv6Prefixes, g_asnLookupColumnNames[list_columns[c]]);
  }

  static_resetFake();
  FakeAnswer_t* answer = static_queueAsnLookupAnswer();
  answer->ma_cells[0][ASNLOOKUP_COL_IPV4_PREFIXES] = "[]";
  answer->ma_cells[0][ASNLOOKUP_COL_IPV6_PREFIXES] = "[]";
  ASNLOOKUPParams_t params = static_asnLookupParams("AS13335");
  ASNLOOKUPRecord_t record;
  TEST_ASSERT_EQUAL_INT(DB_OK, db_ASNLOOKUP(FAKE_CONN, &params, &record));
  TEST_ASSERT_EQUAL_STRING("[]", record.mp_ipv4Prefixes);
  TEST_ASSERT_EQUAL_STRING("[]", record.mp_ipv6Prefixes);
  db_ASNLOOKUPRecordFree(&record);
}

void test_ASNLOOKUP_texts_and_lists_at_their_limits_and_past_them(void)
{
  enum { LIMIT_PREFIX = -1 };
  static const struct { int m_column; size_t m_limit; } limits[] = {
    { ASNLOOKUP_COL_ASN_NAME,      256 },
    { ASNLOOKUP_COL_ASN_COUNTRY,   2 },
    { LIMIT_PREFIX,                49 },
    { ASNLOOKUP_COL_IPV4_PREFIXES, ASNLOOKUP_PREFIX_ARRAY_MAX_LEN },
    { ASNLOOKUP_COL_IPV6_PREFIXES, ASNLOOKUP_PREFIX_ARRAY_MAX_LEN },
  };
  for (size_t i = 0; i < sizeof(limits) / sizeof(limits[0]); i++)
  {
    for (size_t extra = 0; extra <= 1; extra++)
    {
      static_resetFake();
      size_t length = limits[i].m_limit + extra;
      bool is_list  = limits[i].m_column == ASNLOOKUP_COL_IPV4_PREFIXES || limits[i].m_column == ASNLOOKUP_COL_IPV6_PREFIXES;
      char* text = is_list ? static_makeJsonArrayDocument(length) : static_makeText(length);
      TEST_ASSERT_NOT_NULL(text);
      bool is_prefix = limits[i].m_column == LIMIT_PREFIX;
      if (is_prefix)
        static_queueAsnPrefixAnswer()->ma_cells[0][1] = text;
      FakeAnswer_t* lookup = static_queueAsnLookupAnswer();
      if (!is_prefix)
        lookup->ma_cells[0][limits[i].m_column] = text;
      ASNLOOKUPParams_t params = static_asnLookupParams(is_prefix ? ASNLOOKUP_TEST_IP : "AS13335");
      ASNLOOKUPRecord_t record;
      memset(&record, 0xA5, sizeof(record));
      const char* name = is_prefix ? "prefix" : g_asnLookupColumnNames[limits[i].m_column];

      DbStatus_t db_status = db_ASNLOOKUP(FAKE_CONN, &params, &record);

      if (extra == 0)
      {
        TEST_ASSERT_EQUAL_INT_MESSAGE(DB_OK, db_status, name);
        const char* field = is_prefix                                               ? record.ma_prefix
                          : limits[i].m_column == ASNLOOKUP_COL_ASN_NAME            ? record.ma_asnName
                          : limits[i].m_column == ASNLOOKUP_COL_ASN_COUNTRY         ? record.ma_asnCountry
                          : limits[i].m_column == ASNLOOKUP_COL_IPV4_PREFIXES       ? record.mp_ipv4Prefixes
                          : record.mp_ipv6Prefixes;
        TEST_ASSERT_EQUAL_STRING_MESSAGE(text, field, name);
      }
      else
      {
        TEST_ASSERT_EQUAL_INT_MESSAGE(DB_ERROR, db_status, name);
        TEST_ASSERT_NULL_MESSAGE(record.mp_ipv4Prefixes, name);
        TEST_ASSERT_NULL_MESSAGE(record.mp_ipv6Prefixes, name);
      }
      db_ASNLOOKUPRecordFree(&record);
      free(text);
    }
  }
}

void test_ASNLOOKUP_failed_copy_of_either_list_is_error(void)
{
  for (int failing_call = 1; failing_call <= 2; failing_call++)
  {
    static_resetFake();
    static_queueAsnLookupAnswer();
    g_strdupFailsAtCall = failing_call;
    ASNLOOKUPParams_t params = static_asnLookupParams("AS13335");
    ASNLOOKUPRecord_t record;
    memset(&record, 0, sizeof(record));

    TEST_ASSERT_EQUAL_INT(DB_ERROR, db_ASNLOOKUP(FAKE_CONN, &params, &record));

    TEST_ASSERT_EQUAL_INT(failing_call, g_strdupCallCount);
    TEST_ASSERT_NULL(record.mp_ipv4Prefixes);
    TEST_ASSERT_NULL(record.mp_ipv6Prefixes);
  }
}

void test_ASNLOOKUP_asn_too_long_for_its_parameter_is_error(void)
{
  static_resetFake();
  static_queueAsnLookupAnswer();
  ASNLOOKUPParams_t params = static_asnLookupParams("AS111111111111111");
  ASNLOOKUPRecord_t record;
  db_ASNLOOKUP(FAKE_CONN, &params, &record);
  TEST_ASSERT_EQUAL_INT(1, g_callCount);
  const char* const values[] = { "111111111111111", "50", "0" };
  static_assertCall(0, ASNLOOKUP_CALL, values, 3);
  db_ASNLOOKUPRecordFree(&record);

  static_resetFake();
  static_queueAsnLookupAnswer();
  params = static_asnLookupParams("AS1111111111111111");
  memset(&record, 0xA5, sizeof(record));
  TEST_ASSERT_EQUAL_INT(DB_ERROR, db_ASNLOOKUP(FAKE_CONN, &params, &record));
  TEST_ASSERT_EQUAL_INT(0, g_callCount);
  TEST_ASSERT_NULL(record.mp_ipv4Prefixes);
  TEST_ASSERT_NULL(record.mp_ipv6Prefixes);
}

void test_PACKAGECHECK_sends_its_params_and_reads_each_column(void)
{
  static const char* const values_with_version[]    = { "NPM", "lodash", "4.17.20", "20", "3" };
  static const char* const values_without_version[] = { "NPM", "lodash", NULL, "20", "3" };
  static const char* const eol_values_with_version[]    = { "NPM", "lodash", "4.17.20", "10" };
  static const char* const eol_values_without_version[] = { "NPM", "lodash", NULL, "10" };
  TEST_ASSERT_EQUAL_INT(10, PRODUCTEXPOSURE_EOL_MAINTAINED_CYCLE_MAX);
  static_queuePackageCheckAnswer();
  FakeAnswer_t* second = static_queuePackageCheckAnswer();
  second->ma_cells[0][0] = "f";
  second->ma_cells[0][1] = "t";
  second->ma_cells[0][3] = FAKE_SQL_NULL;
  second->ma_cells[0][4] = FAKE_SQL_NULL;
  PACKAGECHECKParams_t params = static_packageCheckParams("4.17.20");
  PACKAGECHECKResult_t result;
  memset(&result, 0xA5, sizeof(result));

  TEST_ASSERT_EQUAL_INT(DB_OK, db_PACKAGECHECK(FAKE_CONN, &params, &result));

  static_assertCall(0, PACKAGECHECK_CALL, values_with_version, 5);
  static_assertCall(1, PACKAGECHECK_EOL_CALL, eol_values_with_version, 4);
  TEST_ASSERT_FALSE(result.m_eol.m_hasEol);
  TEST_ASSERT_TRUE(result.m_isAdvisoryFeedLoaded);
  TEST_ASSERT_FALSE(result.m_hasAdvisoryData);
  TEST_ASSERT_EQUAL_INT(7, result.m_resultCount);
  TEST_ASSERT_EQUAL_STRING("4.17.21", result.ma_fixedVersion);
  TEST_ASSERT_EQUAL_STRING(g_packageCheckRowValues[4], result.mp_malicious);
  TEST_ASSERT_EQUAL_STRING(g_packageCheckRowValues[5], result.mp_results);
  TEST_ASSERT_EQUAL_STRING(g_packageCheckRowValues[6], result.mp_attribution);
  for (int pass = 0; pass < 2; pass++)
  {
    db_PACKAGECHECKResultFree(&result);
    TEST_ASSERT_NULL(result.mp_malicious);
    TEST_ASSERT_NULL(result.mp_results);
    TEST_ASSERT_NULL(result.mp_attribution);
  }

  params = static_packageCheckParams("");
  TEST_ASSERT_EQUAL_INT(DB_OK, db_PACKAGECHECK(FAKE_CONN, &params, &result));
  static_assertCall(2, PACKAGECHECK_CALL, values_without_version, 5);
  static_assertCall(3, PACKAGECHECK_EOL_CALL, eol_values_without_version, 4);
  TEST_ASSERT_FALSE(result.m_isAdvisoryFeedLoaded);
  TEST_ASSERT_TRUE(result.m_hasAdvisoryData);
  TEST_ASSERT_EQUAL_STRING("", result.ma_fixedVersion);
  TEST_ASSERT_NULL(result.mp_malicious);
  TEST_ASSERT_NOT_NULL(result.mp_results);
  db_PACKAGECHECKResultFree(&result);
  db_PACKAGECHECKResultFree(NULL);
}

void test_CVEPRODUCTS_sends_its_params_and_reads_each_column(void)
{
  static const char* const values_with_vendor[]  = { "CVE-2021-44228", "acme", NULL, "7", "3" };
  static const char* const values_with_product[] = { "CVE-2021-44228", NULL, "beta", "7", "3" };
  static_queueCveProductsAnswer();
  static_queueCveProductsAnswer();
  CVEPRODUCTSParams_t params = static_cveProductsParams("acme", "");
  CVEPRODUCTSResult_t result;
  memset(&result, 0xA5, sizeof(result));

  TEST_ASSERT_EQUAL_INT(DB_OK, db_CVEPRODUCTS(FAKE_CONN, &params, &result));

  static_assertCall(0, CVEPRODUCTS_CALL, values_with_vendor, 5);
  TEST_ASSERT_EQUAL_INT(9, result.m_affectedProductCount);
  TEST_ASSERT_EQUAL_INT(2, result.m_listedProductCount);
  TEST_ASSERT_EQUAL_STRING(g_cveProductsRowValues[2], result.mp_affectedProducts);
  for (int pass = 0; pass < 2; pass++)
  {
    db_CVEPRODUCTSResultFree(&result);
    TEST_ASSERT_NULL(result.mp_affectedProducts);
  }

  params = static_cveProductsParams("", "beta");
  TEST_ASSERT_EQUAL_INT(DB_OK, db_CVEPRODUCTS(FAKE_CONN, &params, &result));
  static_assertCall(1, CVEPRODUCTS_CALL, values_with_product, 5);
  db_CVEPRODUCTSResultFree(&result);
  db_CVEPRODUCTSResultFree(NULL);
}

void test_CVEPRODUCTS_no_row_is_not_found_and_other_answers_are_errors(void)
{
  CVEPRODUCTSParams_t params = static_cveProductsParams("", "");
  for (int row_count = 0; row_count <= 2; row_count += 2)
  {
    static_resetFake();
    FakeAnswer_t* answer = static_queueAnswer(PGRES_TUPLES_OK, CVEPRODUCTS_ROW_COLUMN_COUNT, row_count);
    for (int col = 0; col < CVEPRODUCTS_ROW_COLUMN_COUNT; col++)
    {
      answer->ma_columnNames[col] = g_cveProductsColumnNames[col];
      for (int row = 0; row < row_count; row++)
        answer->ma_cells[row][col] = g_cveProductsRowValues[col];
    }
    CVEPRODUCTSResult_t result;
    memset(&result, 0xA5, sizeof(result));
    TEST_ASSERT_EQUAL_INT(row_count == 0 ? DB_NOT_FOUND : DB_ERROR, db_CVEPRODUCTS(FAKE_CONN, &params, &result));
    TEST_ASSERT_NULL(result.mp_affectedProducts);
    TEST_ASSERT_EQUAL_INT(0, result.m_affectedProductCount);
    TEST_ASSERT_EQUAL_INT(0, result.m_listedProductCount);
  }

  static_resetFake();
  static_queueAnswer(PGRES_FATAL_ERROR, 0, 0);
  CVEPRODUCTSResult_t result;
  memset(&result, 0xA5, sizeof(result));
  TEST_ASSERT_EQUAL_INT(DB_ERROR, db_CVEPRODUCTS(FAKE_CONN, &params, &result));
  TEST_ASSERT_NULL(result.mp_affectedProducts);

  static_resetFake();
  static_queueCveProductsAnswer();
  g_strdupFailsAtCall = 1;
  memset(&result, 0xA5, sizeof(result));
  TEST_ASSERT_EQUAL_INT(DB_ERROR, db_CVEPRODUCTS(FAKE_CONN, &params, &result));
  TEST_ASSERT_NULL(result.mp_affectedProducts);
}

void test_CVELOOKUPGHSA_sends_its_params_and_reads_each_column(void)
{
  static const char* const values[] = { "CVE-2021-44228", "32" };
  static_queueCveLookupGhsaAnswer();
  static_queueCveLookupGhsaAnswer();
  g_queuedAnswers[1].ma_cells[0][0] = "t";
  g_queuedAnswers[1].ma_cells[0][1] = FAKE_SQL_NULL;
  CVELOOKUPRecord_t record = { 0 };
  record.m_isGhsaFeedLoaded = true;

  TEST_ASSERT_EQUAL_INT(DB_OK, db_CVELOOKUPGHSA(FAKE_CONN, "CVE-2021-44228", &record));

  static_assertCall(0, CVELOOKUPGHSA_CALL, values, 2);
  TEST_ASSERT_FALSE(record.m_isGhsaFeedLoaded);
  TEST_ASSERT_EQUAL_STRING(g_cveLookupGhsaRowValues[1], record.mp_ghsa);
  db_CVELOOKUPRecordFree(&record);
  TEST_ASSERT_NULL(record.mp_ghsa);

  TEST_ASSERT_EQUAL_INT(DB_OK, db_CVELOOKUPGHSA(FAKE_CONN, "CVE-2021-44228", &record));
  static_assertCall(1, CVELOOKUPGHSA_CALL, values, 2);
  TEST_ASSERT_TRUE(record.m_isGhsaFeedLoaded);
  TEST_ASSERT_NULL(record.mp_ghsa);
}

void test_CVELOOKUPGHSA_other_than_one_row_a_failed_copy_or_a_long_advisory_is_error(void)
{
  for (int row_count = 0; row_count <= 2; row_count += 2)
  {
    static_resetFake();
    FakeAnswer_t* answer = static_queueAnswer(PGRES_TUPLES_OK, CVELOOKUPGHSA_ROW_COLUMN_COUNT, row_count);
    for (int col = 0; col < CVELOOKUPGHSA_ROW_COLUMN_COUNT; col++)
    {
      answer->ma_columnNames[col] = g_cveLookupGhsaColumnNames[col];
      for (int row = 0; row < row_count; row++)
        answer->ma_cells[row][col] = g_cveLookupGhsaRowValues[col];
    }
    CVELOOKUPRecord_t record = { 0 };
    TEST_ASSERT_EQUAL_INT(DB_ERROR, db_CVELOOKUPGHSA(FAKE_CONN, "CVE-2021-44228", &record));
    TEST_ASSERT_NULL(record.mp_ghsa);
  }

  static_resetFake();
  static_queueAnswer(PGRES_FATAL_ERROR, 0, 0);
  CVELOOKUPRecord_t record = { 0 };
  TEST_ASSERT_EQUAL_INT(DB_ERROR, db_CVELOOKUPGHSA(FAKE_CONN, "CVE-2021-44228", &record));
  TEST_ASSERT_NULL(record.mp_ghsa);

  static_resetFake();
  static_queueCveLookupGhsaAnswer();
  g_strdupFailsAtCall = 1;
  TEST_ASSERT_EQUAL_INT(DB_ERROR, db_CVELOOKUPGHSA(FAKE_CONN, "CVE-2021-44228", &record));
  TEST_ASSERT_NULL(record.mp_ghsa);

  for (size_t extra = 0; extra <= 1; extra++)
  {
    static_resetFake();
    char* document = static_makeJsonArrayDocument(CVELOOKUP_GHSA_MAX_LEN + extra);
    TEST_ASSERT_NOT_NULL(document);
    static_queueCveLookupGhsaAnswer()->ma_cells[0][1] = document;

    DbStatus_t db_status = db_CVELOOKUPGHSA(FAKE_CONN, "CVE-2021-44228", &record);

    TEST_ASSERT_EQUAL_INT(extra == 0 ? DB_OK : DB_ERROR, db_status);
    if (extra == 0)
      TEST_ASSERT_EQUAL_size_t(CVELOOKUP_GHSA_MAX_LEN, strlen(record.mp_ghsa));
    else
      TEST_ASSERT_NULL(record.mp_ghsa);
    db_CVELOOKUPRecordFree(&record);
    free(document);
  }
}

static FakeAnswer_t* static_queuePackageCheckRow(void)
{
  FakeAnswer_t* answer = static_queueAnswer(PGRES_TUPLES_OK, PACKAGECHECK_ROW_COLUMN_COUNT, 1);
  for (int col = 0; col < PACKAGECHECK_ROW_COLUMN_COUNT; col++)
  {
    answer->ma_columnNames[col] = g_packageCheckColumnNames[col];
    answer->ma_cells[0][col]    = g_packageCheckRowValues[col];
  }
  return answer;
}

void test_PACKAGECHECK_reads_the_eol_answer(void)
{
  static_queuePackageCheckRow();
  FakeAnswer_t* eol = static_queueProductExposureEol(3);
  static_setEolProductRow(eol, 0, "django", "https://endoflife.date/django", "11");
  static_setEolCycleRow(eol, 1, "series", "4.2", "2026-04-30", "t", "f", "f", "4.2.7");
  static_setEolCycleRow(eol, 2, "maintained", "5.2", FAKE_SQL_NULL, "f", "t", "f", FAKE_SQL_NULL);
  PACKAGECHECKParams_t params = static_packageCheckParams("4.2.7");
  PACKAGECHECKResult_t result;
  memset(&result, 0xA5, sizeof(result));

  TEST_ASSERT_EQUAL_INT(DB_OK, db_PACKAGECHECK(FAKE_CONN, &params, &result));

  TEST_ASSERT_TRUE(result.m_eol.m_hasEol);
  TEST_ASSERT_EQUAL_STRING("django", result.m_eol.ma_eolProduct);
  TEST_ASSERT_EQUAL_STRING("https://endoflife.date/django", result.m_eol.ma_eolUrl);
  TEST_ASSERT_EQUAL_INT(1, result.m_eol.m_eolSeriesCycleCount);
  TEST_ASSERT_EQUAL_STRING("4.2", result.m_eol.ma_eolSeriesCycles[0].ma_name);
  TEST_ASSERT_EQUAL_STRING("2026-04-30", result.m_eol.ma_eolSeriesCycles[0].ma_eolDate);
  TEST_ASSERT_TRUE(result.m_eol.ma_eolSeriesCycles[0].m_isEol);
  TEST_ASSERT_FALSE(result.m_eol.ma_eolSeriesCycles[0].m_isMaintained);
  TEST_ASSERT_FALSE(result.m_eol.ma_eolSeriesCycles[0].m_isLts);
  TEST_ASSERT_EQUAL_STRING("4.2.7", result.m_eol.ma_eolSeriesCycles[0].ma_latestVersion);
  TEST_ASSERT_EQUAL_INT(1, result.m_eol.m_eolMaintainedCycleCount);
  TEST_ASSERT_EQUAL_STRING("5.2", result.m_eol.ma_eolMaintainedCycles[0].ma_name);
  TEST_ASSERT_EQUAL_STRING("", result.m_eol.ma_eolMaintainedCycles[0].ma_eolDate);
  TEST_ASSERT_TRUE(result.m_eol.ma_eolMaintainedCycles[0].m_isMaintained);
  TEST_ASSERT_TRUE(result.m_eol.m_hasMoreEolMaintainedCycles);
  TEST_ASSERT_EQUAL_STRING(g_packageCheckRowValues[6], result.mp_attribution);
  db_PACKAGECHECKResultFree(&result);
}

void test_PACKAGECHECK_failed_or_refused_eol_answer_is_error(void)
{
  PACKAGECHECKParams_t params = static_packageCheckParams("4.17.20");
  for (int broken = 0; broken < 4; broken++)
  {
    static_resetFake();
    static_queuePackageCheckRow();
    if (broken == 0)
      static_queueAnswer(PGRES_FATAL_ERROR, 0, 0);
    else if (broken == 1)
      static_queueProductExposureEol(0)->ma_columnNames[0] = "kind";
    else if (broken == 2)
    {
      FakeAnswer_t* eol = static_queueProductExposureEol(1);
      static_setEolProductRow(eol, 0, "django", "https://endoflife.date/django", "0");
      eol->ma_cells[0][0] = "cycle";
    }
    else
    {
      FakeAnswer_t* eol = static_queueProductExposureEol(PRODUCTEXPOSURE_EOL_SERIES_CYCLE_MAX + 2);
      static_setEolProductRow(eol, 0, "django", "https://endoflife.date/django", "0");
      for (int row = 1; row <= PRODUCTEXPOSURE_EOL_SERIES_CYCLE_MAX + 1; row++)
        static_setEolCycleRow(eol, row, "series", "4.2", "2026-04-30", "t", "f", "t", "4.2.7");
    }
    PACKAGECHECKResult_t result;
    memset(&result, 0xA5, sizeof(result));
    char message[32];
    snprintf(message, sizeof(message), "broken eol answer %d", broken);

    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_ERROR, db_PACKAGECHECK(FAKE_CONN, &params, &result), message);
    TEST_ASSERT_NULL_MESSAGE(result.mp_malicious, message);
    TEST_ASSERT_NULL_MESSAGE(result.mp_results, message);
    TEST_ASSERT_NULL_MESSAGE(result.mp_attribution, message);
    db_PACKAGECHECKResultFree(&result);
  }
}

void test_PACKAGECHECK_fixed_version_and_texts_at_their_limits_and_past_them(void)
{
  PACKAGECHECKParams_t params = static_packageCheckParams("4.17.20");
  for (size_t extra = 0; extra <= 1; extra++)
  {
    static_resetFake();
    char* version = static_makeText(PACKAGECHECK_VERSION_MAX_LEN + extra);
    TEST_ASSERT_NOT_NULL(version);
    static_queuePackageCheckAnswer()->ma_cells[0][3] = version;
    PACKAGECHECKResult_t result;
    memset(&result, 0xA5, sizeof(result));

    DbStatus_t db_status = db_PACKAGECHECK(FAKE_CONN, &params, &result);

    if (extra == 0)
    {
      TEST_ASSERT_EQUAL_INT(DB_OK, db_status);
      TEST_ASSERT_EQUAL_STRING(version, result.ma_fixedVersion);
    }
    else
    {
      TEST_ASSERT_EQUAL_INT(DB_ERROR, db_status);
      TEST_ASSERT_NULL(result.mp_results);
    }
    db_PACKAGECHECKResultFree(&result);
    free(version);
  }

  for (int column = 4; column <= 6; column++)
  {
    for (size_t extra = 0; extra <= 1; extra++)
    {
      static_resetFake();
      char* document = static_makeJsonArrayDocument(PACKAGECHECK_JSON_MAX_LEN + extra);
      TEST_ASSERT_NOT_NULL(document);
      static_queuePackageCheckAnswer()->ma_cells[0][column] = document;
      PACKAGECHECKResult_t result;
      memset(&result, 0xA5, sizeof(result));

      DbStatus_t db_status = db_PACKAGECHECK(FAKE_CONN, &params, &result);

      char* texts[] = { result.mp_malicious, result.mp_results, result.mp_attribution };
      if (extra == 0)
      {
        TEST_ASSERT_EQUAL_INT_MESSAGE(DB_OK, db_status, g_packageCheckColumnNames[column]);
        TEST_ASSERT_NOT_NULL(texts[column - 4]);
        TEST_ASSERT_EQUAL_size_t(PACKAGECHECK_JSON_MAX_LEN, strlen(texts[column - 4]));
      }
      else
      {
        TEST_ASSERT_EQUAL_INT_MESSAGE(DB_ERROR, db_status, g_packageCheckColumnNames[column]);
        TEST_ASSERT_NULL(result.mp_malicious);
        TEST_ASSERT_NULL(result.mp_results);
        TEST_ASSERT_NULL(result.mp_attribution);
      }
      db_PACKAGECHECKResultFree(&result);
      free(document);
    }
  }
}

void test_PACKAGECHECK_other_than_one_row_or_a_failed_copy_is_error(void)
{
  PACKAGECHECKParams_t params = static_packageCheckParams("4.17.20");
  for (int row_count = 0; row_count <= 2; row_count += 2)
  {
    static_resetFake();
    FakeAnswer_t* answer = static_queueAnswer(PGRES_TUPLES_OK, PACKAGECHECK_ROW_COLUMN_COUNT, row_count);
    for (int col = 0; col < PACKAGECHECK_ROW_COLUMN_COUNT; col++)
    {
      answer->ma_columnNames[col] = g_packageCheckColumnNames[col];
      for (int row = 0; row < row_count; row++)
        answer->ma_cells[row][col] = g_packageCheckRowValues[col];
    }
    PACKAGECHECKResult_t result;
    memset(&result, 0xA5, sizeof(result));
    TEST_ASSERT_EQUAL_INT(DB_ERROR, db_PACKAGECHECK(FAKE_CONN, &params, &result));
    TEST_ASSERT_NULL(result.mp_results);
  }

  static_resetFake();
  static_queueAnswer(PGRES_FATAL_ERROR, 0, 0);
  PACKAGECHECKResult_t result;
  memset(&result, 0xA5, sizeof(result));
  TEST_ASSERT_EQUAL_INT(DB_ERROR, db_PACKAGECHECK(FAKE_CONN, &params, &result));
  TEST_ASSERT_NULL(result.mp_malicious);

  for (int failing_copy = 1; failing_copy <= 3; failing_copy++)
  {
    static_resetFake();
    static_queuePackageCheckAnswer();
    g_strdupFailsAtCall = failing_copy;
    memset(&result, 0xA5, sizeof(result));
    TEST_ASSERT_EQUAL_INT(DB_ERROR, db_PACKAGECHECK(FAKE_CONN, &params, &result));
    TEST_ASSERT_EQUAL_INT(failing_copy, g_strdupCallCount);
    TEST_ASSERT_NULL(result.mp_malicious);
    TEST_ASSERT_NULL(result.mp_results);
    TEST_ASSERT_NULL(result.mp_attribution);
  }
}

void test_buildTextArrayLiteral_quotes_each_value_and_escapes_its_quotes_and_backslashes(void)
{
  static const char* const values[] = { "lodash", "a,b", "{x}", " ", "NULL", "", "q\"r", "s\\t", "\"\\\"\\" };
  char* literal = dbhelper_buildTextArrayLiteral(values, (int)(sizeof(values) / sizeof(values[0])));
  TEST_ASSERT_NOT_NULL(literal);
  TEST_ASSERT_EQUAL_STRING(R"({"lodash","a,b","{x}"," ","NULL","","q\"r","s\\t","\"\\\"\\"})", literal);
  free(literal);

  static const char* const empty_values[] = { "", "", "" };
  literal = dbhelper_buildTextArrayLiteral(empty_values, 3);
  TEST_ASSERT_EQUAL_STRING(R"({"","",""})", literal);
  free(literal);

  literal = dbhelper_buildTextArrayLiteral(NULL, 0);
  TEST_ASSERT_EQUAL_STRING("{}", literal);
  free(literal);

  g_mallocFailsAtCall = 1;
  TEST_ASSERT_NULL(dbhelper_buildTextArrayLiteral(values, 1));
}

void test_buildTextArrayLiteral_fits_a_value_whose_every_byte_is_escaped(void)
{
  static const char* const values[] = { "\"\\\"\\\"\\\"\\" };
  char* literal = dbhelper_buildTextArrayLiteral(values, 1);
  TEST_ASSERT_EQUAL_STRING(R"({"\"\\\"\\\"\\\"\\"})", literal);
  free(literal);
}

void test_PACKAGECHECKBULK_sends_three_literals_and_reads_each_column(void)
{
  static const char* const values[] = {
    R"({"npm","PyPI"})", R"({"lodash","a\"b\\c"})", R"({"4.17.20","1.0"})", "10"
  };
  static_queuePackageCheckBulkAnswer();
  static_queuePackageCheckBulkAnswer()->ma_cells[0][0] = "f";
  PACKAGECHECKBULKResult_t result;
  memset(&result, 0xA5, sizeof(result));

  TEST_ASSERT_EQUAL_INT(DB_OK, db_PACKAGECHECKBULK(FAKE_CONN, g_packageCheckBulkItems, 2, &result));

  static_assertCall(0, PACKAGECHECKBULK_CALL, values, 4);
  TEST_ASSERT_EQUAL_INT(2, result.m_successful);
  TEST_ASSERT_EQUAL_INT(0, result.m_failed);
  TEST_ASSERT_TRUE(result.m_isAdvisoryFeedLoaded);
  TEST_ASSERT_EQUAL_STRING(g_packageCheckBulkRowValues[1], result.mp_results);
  TEST_ASSERT_EQUAL_STRING(g_packageCheckBulkRowValues[2], result.mp_attribution);
  for (int pass = 0; pass < 2; pass++)
  {
    db_PACKAGECHECKBULKResultFree(&result);
    TEST_ASSERT_NULL(result.mp_results);
    TEST_ASSERT_NULL(result.mp_attribution);
  }
  db_PACKAGECHECKBULKResultFree(NULL);

  TEST_ASSERT_EQUAL_INT(DB_OK, db_PACKAGECHECKBULK(FAKE_CONN, g_packageCheckBulkItems, 2, &result));
  TEST_ASSERT_FALSE(result.m_isAdvisoryFeedLoaded);
  db_PACKAGECHECKBULKResultFree(&result);
}

void test_PACKAGECHECKBULK_counts_failed_packages_and_refuses_a_count_out_of_range(void)
{
  static const struct {
    const char* mp_cell;
    DbStatus_t  m_status;
    int         m_successful;
    int         m_failed;
  } rows[] = {
    { "1",  DB_OK,    1, 1 },
    { "2",  DB_OK,    0, 2 },
    { "0",  DB_OK,    2, 0 },
    { "3",  DB_ERROR, 0, 0 },
    { "-1", DB_ERROR, 0, 0 },
    { FAKE_SQL_NULL, DB_ERROR, 0, 0 },
  };
  for (size_t row = 0; row < sizeof(rows) / sizeof(rows[0]); row++)
  {
    static_resetFake();
    static_queuePackageCheckBulkAnswer()->ma_cells[0][3] = rows[row].mp_cell;
    PACKAGECHECKBULKResult_t result;
    memset(&result, 0xA5, sizeof(result));

    DbStatus_t db_status = db_PACKAGECHECKBULK(FAKE_CONN, g_packageCheckBulkItems, 2, &result);

    const char* label = rows[row].mp_cell == FAKE_SQL_NULL ? "SQL NULL" : rows[row].mp_cell;
    TEST_ASSERT_EQUAL_INT_MESSAGE(rows[row].m_status, db_status, label);
    TEST_ASSERT_EQUAL_INT_MESSAGE(rows[row].m_successful, result.m_successful, label);
    TEST_ASSERT_EQUAL_INT_MESSAGE(rows[row].m_failed, result.m_failed, label);
    if (rows[row].m_status == DB_OK)
    {
      TEST_ASSERT_EQUAL_STRING_MESSAGE(g_packageCheckBulkRowValues[1], result.mp_results, label);
    }
    else
    {
      TEST_ASSERT_NULL_MESSAGE(result.mp_results, label);
      TEST_ASSERT_NULL_MESSAGE(result.mp_attribution, label);
    }
    db_PACKAGECHECKBULKResultFree(&result);
  }
}

void test_PACKAGECHECKBULK_texts_at_their_limit_and_past_it(void)
{
  for (int column = 1; column <= 2; column++)
  {
    for (size_t extra = 0; extra <= 1; extra++)
    {
      static_resetFake();
      char* document = static_makeJsonArrayDocument(PACKAGECHECKBULK_JSON_MAX_LEN + extra);
      TEST_ASSERT_NOT_NULL(document);
      static_queuePackageCheckBulkAnswer()->ma_cells[0][column] = document;
      PACKAGECHECKBULKResult_t result;
      memset(&result, 0xA5, sizeof(result));

      DbStatus_t db_status = db_PACKAGECHECKBULK(FAKE_CONN, g_packageCheckBulkItems, 2, &result);

      char* texts[] = { result.mp_results, result.mp_attribution };
      if (extra == 0)
      {
        TEST_ASSERT_EQUAL_INT_MESSAGE(DB_OK, db_status, g_packageCheckBulkColumnNames[column]);
        TEST_ASSERT_NOT_NULL(texts[column - 1]);
        TEST_ASSERT_EQUAL_size_t(PACKAGECHECKBULK_JSON_MAX_LEN, strlen(texts[column - 1]));
      }
      else
      {
        TEST_ASSERT_EQUAL_INT_MESSAGE(DB_ERROR, db_status, g_packageCheckBulkColumnNames[column]);
        TEST_ASSERT_NULL(result.mp_results);
        TEST_ASSERT_NULL(result.mp_attribution);
        TEST_ASSERT_EQUAL_INT(0, result.m_successful);
      }
      db_PACKAGECHECKBULKResultFree(&result);
      free(document);
    }
  }
}

void test_PACKAGECHECKBULK_other_than_one_row_or_a_failed_copy_is_error(void)
{
  PACKAGECHECKBULKResult_t result;
  for (int row_count = 0; row_count <= 2; row_count += 2)
  {
    static_resetFake();
    FakeAnswer_t* answer = static_queueAnswer(PGRES_TUPLES_OK, PACKAGECHECKBULK_ROW_COLUMN_COUNT, row_count);
    for (int col = 0; col < PACKAGECHECKBULK_ROW_COLUMN_COUNT; col++)
    {
      answer->ma_columnNames[col] = g_packageCheckBulkColumnNames[col];
      for (int row = 0; row < row_count; row++)
        answer->ma_cells[row][col] = g_packageCheckBulkRowValues[col];
    }
    memset(&result, 0xA5, sizeof(result));
    TEST_ASSERT_EQUAL_INT(DB_ERROR, db_PACKAGECHECKBULK(FAKE_CONN, g_packageCheckBulkItems, 2, &result));
    TEST_ASSERT_NULL(result.mp_results);
    TEST_ASSERT_EQUAL_INT(0, result.m_successful);
  }

  static_resetFake();
  static_queueAnswer(PGRES_FATAL_ERROR, 0, 0);
  memset(&result, 0xA5, sizeof(result));
  TEST_ASSERT_EQUAL_INT(DB_ERROR, db_PACKAGECHECKBULK(FAKE_CONN, g_packageCheckBulkItems, 2, &result));
  TEST_ASSERT_NULL(result.mp_attribution);

  for (int failing_copy = 1; failing_copy <= 2; failing_copy++)
  {
    static_resetFake();
    static_queuePackageCheckBulkAnswer();
    g_strdupFailsAtCall = failing_copy;
    memset(&result, 0xA5, sizeof(result));
    TEST_ASSERT_EQUAL_INT(DB_ERROR, db_PACKAGECHECKBULK(FAKE_CONN, g_packageCheckBulkItems, 2, &result));
    TEST_ASSERT_EQUAL_INT(failing_copy, g_strdupCallCount);
    TEST_ASSERT_NULL(result.mp_results);
    TEST_ASSERT_NULL(result.mp_attribution);
    TEST_ASSERT_EQUAL_INT(0, result.m_successful);
  }

  for (int failing_literal = 1; failing_literal <= 3; failing_literal++)
  {
    static_resetFake();
    static_queuePackageCheckBulkAnswer();
    g_mallocFailsAtCall = failing_literal;
    memset(&result, 0xA5, sizeof(result));
    TEST_ASSERT_EQUAL_INT(DB_ERROR, db_PACKAGECHECKBULK(FAKE_CONN, g_packageCheckBulkItems, 2, &result));
    TEST_ASSERT_EQUAL_INT(0, g_callCount);
    TEST_ASSERT_NULL(result.mp_results);
    TEST_ASSERT_NULL(result.mp_attribution);
    TEST_ASSERT_EQUAL_INT(0, result.m_successful);
  }
}

#define PACKAGECHECKBULKWEIGH_CALL "SELECT api.fn_package_check_bulk_weigh($1, $2, $3, $4, $5) AS served_item_count"

void test_PACKAGECHECKBULKWeigh_sends_two_literals_and_the_three_weight_values(void)
{
  static const char* const values[] = { R"({"npm","PyPI"})", R"({"lodash","a\"b\\c"})", "100", "100000", "20" };
  static const struct { const char* mp_cell; int m_served; } rows[] = { { "1", 1 }, { "2", 2 } };
  for (size_t row = 0; row < sizeof(rows) / sizeof(rows[0]); row++)
  {
    static_resetFake();
    static_queueOneCell("served_item_count", rows[row].mp_cell);
    int served = -7;
    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_OK, db_PACKAGECHECKBULKWeigh(FAKE_CONN, g_packageCheckBulkItems, 2, &served), rows[row].mp_cell);
    TEST_ASSERT_EQUAL_INT_MESSAGE(rows[row].m_served, served, rows[row].mp_cell);
    TEST_ASSERT_EQUAL_INT(1, g_callCount);
    static_assertCall(0, PACKAGECHECKBULKWEIGH_CALL, values, 5);
  }
}

void test_PACKAGECHECKBULKWeigh_refuses_any_other_answer(void)
{
  for (size_t row = 0; row < sizeof(g_wrongShapes) / sizeof(g_wrongShapes[0]); row++)
  {
    static_resetFake();
    static_queueWrongShape(g_wrongShapes[row], "served_item_count", "1");
    char message[16] = "";
    snprintf(message, sizeof(message), "row %zu", row);
    int served = -7;
    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_ERROR, db_PACKAGECHECKBULKWeigh(FAKE_CONN, g_packageCheckBulkItems, 2, &served), message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(-7, served, message);
  }

  static const char* const cells[] = { FAKE_SQL_NULL, "many", "0", "3", "-1" };
  for (size_t c = 0; c < sizeof(cells) / sizeof(cells[0]); c++)
  {
    static_resetFake();
    static_queueOneCell("served_item_count", cells[c]);
    int served = -7;
    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_ERROR, db_PACKAGECHECKBULKWeigh(FAKE_CONN, g_packageCheckBulkItems, 2, &served), cells[c] == FAKE_SQL_NULL ? "NULL" : cells[c]);
    TEST_ASSERT_EQUAL_INT(-7, served);
  }

  for (int failing_literal = 1; failing_literal <= 2; failing_literal++)
  {
    static_resetFake();
    static_queueOneCell("served_item_count", "1");
    g_mallocFailsAtCall = failing_literal;
    int served = -7;
    TEST_ASSERT_EQUAL_INT(DB_ERROR, db_PACKAGECHECKBULKWeigh(FAKE_CONN, g_packageCheckBulkItems, 2, &served));
    TEST_ASSERT_EQUAL_INT(0, g_callCount);
    TEST_ASSERT_EQUAL_INT(-7, served);
  }
}

void test_list_queries_refuse_a_null_connection(void)
{
  CVESEARCHParams_t search_params;
  memset(&search_params, 0, sizeof(search_params));
  search_params.m_limit = 2;
  CveListResult_t search_results;
  memset(&search_results, 0xA5, sizeof(search_results));
  TEST_ASSERT_EQUAL_INT(DB_ERROR, db_CVESEARCH(NULL, &search_params, &search_results));
  TEST_ASSERT_NULL(search_results.mp_items);

  CVELEADINGParams_t leading_params;
  memset(&leading_params, 0, sizeof(leading_params));
  leading_params.m_minEpss = -1.0;
  leading_params.m_limit   = 2;
  CveListResult_t leading_results;
  memset(&leading_results, 0xA5, sizeof(leading_results));
  TEST_ASSERT_EQUAL_INT(DB_ERROR, db_CVELEADING(NULL, &leading_params, &leading_results));
  TEST_ASSERT_NULL(leading_results.mp_items);

  CVETRIAGEParams_t triage_params;
  memset(&triage_params, 0, sizeof(triage_params));
  triage_params.m_limit = 2;
  CVETRIAGEResult_t triage_results;
  memset(&triage_results, 0xA5, sizeof(triage_results));
  TEST_ASSERT_EQUAL_INT(DB_ERROR, db_CVETRIAGE(NULL, &triage_params, &triage_results));
  TEST_ASSERT_NULL(triage_results.mp_items);

  CPESEARCHParams_t cpe_search_params;
  memset(&cpe_search_params, 0, sizeof(cpe_search_params));
  cpe_search_params.m_limit = 2;
  CPESEARCHResult_t cpe_search_results;
  memset(&cpe_search_results, 0xA5, sizeof(cpe_search_results));
  TEST_ASSERT_EQUAL_INT(DB_ERROR, db_CPESEARCH(NULL, &cpe_search_params, &cpe_search_results));
  TEST_ASSERT_NULL(cpe_search_results.mp_items);

  TEST_ASSERT_EQUAL_INT(0, g_callCount);
}

static void static_formatEventCount(char* text_out, size_t text_size, int count)
{
  int written = snprintf(text_out, text_size, "%d", count);
  TEST_ASSERT_TRUE(written > 0 && (size_t)written < text_size);
}

void test_purgeExpiredCveChangeEvents_runs_again_after_a_full_batch(void)
{
  char batch[16];
  char batch_less_one[16];
  char batch_plus_one[16];
  static_formatEventCount(batch,          sizeof(batch),          DB_CVE_CHANGE_PURGE_BATCH_EVENT_COUNT);
  static_formatEventCount(batch_less_one, sizeof(batch_less_one), DB_CVE_CHANGE_PURGE_BATCH_EVENT_COUNT - 1);
  static_formatEventCount(batch_plus_one, sizeof(batch_plus_one), DB_CVE_CHANGE_PURGE_BATCH_EVENT_COUNT + 1);
  const struct {
    const char* ma_counts[3];
    int         m_callCount;
  } rows[] = {
    { { "42" },                1 },
    { { "0" },                 1 },
    { { batch_less_one },      1 },
    { { batch_plus_one },      1 },
    { { batch, "0" },          2 },
    { { batch, batch, "7" },   3 },
  };

  for (size_t row = 0; row < sizeof(rows) / sizeof(rows[0]); row++)
  {
    static_resetFake();
    for (int call = 0; call < rows[row].m_callCount; call++)
      static_queueOneCell("purged_event_count", rows[row].ma_counts[call]);
    char message[16] = "";
    snprintf(message, sizeof(message), "row %zu", row);

    TEST_ASSERT_TRUE_MESSAGE(db_purgeExpiredCveChangeEvents(FAKE_CONN), message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(rows[row].m_callCount, g_callCount, message);
    for (int call = 0; call < g_callCount; call++)
    {
      const FakeCall_t* sent = &g_calls[call];
      TEST_ASSERT_EQUAL_STRING_MESSAGE("SELECT api.fn_cve_change_event_purge($1) AS purged_event_count", sent->ma_command, message);
      TEST_ASSERT_EQUAL_INT_MESSAGE(1, sent->m_paramCount, message);
      TEST_ASSERT_FALSE_MESSAGE(sent->ma_isParamNull[0], message);
      TEST_ASSERT_EQUAL_STRING_MESSAGE(batch, sent->ma_params[0], message);
      TEST_ASSERT_EQUAL_INT_MESSAGE(0, sent->m_resultFormat, message);
    }
  }
}

void test_purgeExpiredCveChangeEvents_refuses_any_other_answer(void)
{
  for (size_t row = 0; row < sizeof(g_wrongShapes) / sizeof(g_wrongShapes[0]); row++)
  {
    static_resetFake();
    static_queueWrongShape(g_wrongShapes[row], "purged_event_count", "1");
    char message[16] = "";
    snprintf(message, sizeof(message), "row %zu", row);

    TEST_ASSERT_FALSE_MESSAGE(db_purgeExpiredCveChangeEvents(FAKE_CONN), message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_callCount, message);
  }

  static_resetFake();
  static_queueOneCell("purged_event_count", FAKE_SQL_NULL);
  TEST_ASSERT_FALSE(db_purgeExpiredCveChangeEvents(FAKE_CONN));
  TEST_ASSERT_EQUAL_INT(1, g_callCount);

  static_resetFake();
  static_queueOneCell("purged_event_count", "many");
  TEST_ASSERT_FALSE(db_purgeExpiredCveChangeEvents(FAKE_CONN));
  TEST_ASSERT_EQUAL_INT(1, g_callCount);

  char batch[16];
  static_formatEventCount(batch, sizeof(batch), DB_CVE_CHANGE_PURGE_BATCH_EVENT_COUNT);
  static_resetFake();
  static_queueOneCell("purged_event_count", batch);
  static_queueAnswer(PGRES_FATAL_ERROR, 0, 0);
  TEST_ASSERT_FALSE(db_purgeExpiredCveChangeEvents(FAKE_CONN));
  TEST_ASSERT_EQUAL_INT(2, g_callCount);
}


#define WATCHLIST_TEST_KEY_HASH "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"

#define WATCHLISTEDIT_ROW_COLUMN_COUNT                  20
#define WATCHLISTEDIT_CVE_ID_ROW_COLUMN_COUNT           5
#define WATCHLISTEDIT_PRODUCT_EXPOSURE_ROW_COLUMN_COUNT 8
#define WATCHLISTEDIT_CVE_SEARCH_ROW_COLUMN_COUNT       13
#define WATCHLISTEDIT_DOMAIN_ROW_COLUMN_COUNT           5
#define WATCHLISTEDIT_PACKAGE_ROW_COLUMN_COUNT          7
#define WATCHLISTEDIT_IP_ROW_COLUMN_COUNT               5

static const char* const g_watchlistEditColumnNames[WATCHLISTEDIT_ROW_COLUMN_COUNT] = {
  "edit_status", "endpoint_name", "cve_id", "vendor", "product", "severity", "cwe_id", "min_cvss", "min_epss",
  "in_kev", "known_ransomware", "has_nuclei_template", "product_has_cves", "domain_name", "ecosystem", "package_name", "version",
  "ip_address", "item_count", "package_item_count"
};
static const char* const g_watchlistEditCveIdColumnNames[WATCHLISTEDIT_CVE_ID_ROW_COLUMN_COUNT] = {
  "edit_status", "endpoint_name", "cve_id", "item_count", "package_item_count"
};
static const char* const g_watchlistEditProductExposureColumnNames[WATCHLISTEDIT_PRODUCT_EXPOSURE_ROW_COLUMN_COUNT] = {
  "edit_status", "endpoint_name", "vendor", "product", "product_has_cves", "version", "item_count", "package_item_count"
};
static const char* const g_watchlistEditCveSearchColumnNames[WATCHLISTEDIT_CVE_SEARCH_ROW_COLUMN_COUNT] = {
  "edit_status", "endpoint_name", "vendor", "product", "severity", "cwe_id", "min_cvss", "min_epss", "in_kev",
  "known_ransomware", "has_nuclei_template", "item_count", "package_item_count"
};
static const char* const g_watchlistEditDomainColumnNames[WATCHLISTEDIT_DOMAIN_ROW_COLUMN_COUNT] = {
  "edit_status", "endpoint_name", "domain_name", "item_count", "package_item_count"
};
static const char* const g_watchlistEditPackageColumnNames[WATCHLISTEDIT_PACKAGE_ROW_COLUMN_COUNT] = {
  "edit_status", "endpoint_name", "ecosystem", "package_name", "version", "item_count", "package_item_count"
};
static const char* const g_watchlistEditIpColumnNames[WATCHLISTEDIT_IP_ROW_COLUMN_COUNT] = {
  "edit_status", "endpoint_name", "ip_address", "item_count", "package_item_count"
};
static const char* const g_watchlistEventsColumnNames[WATCHLISTEVENTS_ROW_COLUMN_COUNT] = {
  "events_status", "next_cursor", "has_more",
  "item_id", "item_endpoint_name", "item_cve_id", "item_vendor", "item_product", "item_severity", "item_cwe_id", "item_min_cvss",
  "item_min_epss", "item_in_kev", "item_known_ransomware", "item_has_nuclei_template", "item_product_has_cves",
  "item_domain_name", "item_ecosystem", "item_package_name", "item_version", "item_ip_address",
  "event_rank", "is_first_row_of_event", "event_type", "changed_at",
  "cve_id", "previous_value", "current_value", "vendor", "product",
  "degraded_email_check_id", "previous_domain_value", "current_domain_value",
  "is_first_event_of_cve", "risk_score", "risk_label", "in_kev", "kev_patch_deadline", "kev_known_ransomware", "has_metasploit", "poc_count",
  "is_first_event_of_domain", "registered_domain", "dns_presence_value", "ns_value", "mx_value", "ip_address_reachability_value",
  "cname_takeover_value", "email_auth_value",
  "advisory_id", "fixed_version", "previous_ip_value", "current_ip_value", "drop_list_time", "drop_copyright",
  "eol_product", "eol_cycle", "eol_date", "previous_eol_date",
  "affects_version", "is_first_event_of_advisory", "advisory_source", "advisory_aliases",
  "advisory_cve_facts", "attribution"
};

#define WATCHLISTEDIT_LIST_CALL             "SELECT * FROM api.fn_watchlist_list($1)"
#define WATCHLISTEDIT_CLEAR_CALL            "SELECT * FROM api.fn_watchlist_clear($1)"
#define WATCHLISTEDIT_CVE_LOOKUP_CALL       "SELECT * FROM api.fn_watchlist_edit_cve_lookup($1, $2, $3, $4)"
#define WATCHLISTEDIT_KEV_LOOKUP_CALL       "SELECT * FROM api.fn_watchlist_edit_kev_lookup($1, $2, $3, $4)"
#define WATCHLISTEDIT_CVE_EXPLOIT_CALL      "SELECT * FROM api.fn_watchlist_edit_cve_exploit($1, $2, $3, $4)"
#define WATCHLISTEDIT_PRODUCT_EXPOSURE_CALL "SELECT * FROM api.fn_watchlist_edit_product_exposure($1, $2, $3, $4, $5, $6)"
#define WATCHLISTEDIT_CVE_SEARCH_CALL       "SELECT * FROM api.fn_watchlist_edit_cve_search($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)"
#define WATCHLISTEDIT_DNS_LOOKUP_CALL       "SELECT * FROM api.fn_watchlist_edit_dns_lookup($1, $2, $3, $4, $5, $6)"
#define WATCHLISTEDIT_SSL_CHECK_CALL        "SELECT * FROM api.fn_watchlist_edit_ssl_check($1, $2, $3, $4, $5, $6)"
#define WATCHLISTEDIT_WHOIS_LOOKUP_CALL     "SELECT * FROM api.fn_watchlist_edit_whois_lookup($1, $2, $3, $4, $5, $6)"
#define WATCHLISTEDIT_HEADERS_CHECK_CALL    "SELECT * FROM api.fn_watchlist_edit_headers_check($1, $2, $3, $4, $5, $6)"
#define WATCHLISTEDIT_CERT_SEARCH_CALL      "SELECT * FROM api.fn_watchlist_edit_cert_search($1, $2, $3, $4, $5, $6)"
#define WATCHLISTEDIT_PACKAGE_CHECK_CALL    "SELECT * FROM api.fn_watchlist_edit_package_check($1, $2, $3, $4, $5, $6, $7, $8, $9)"
#define WATCHLISTEDIT_IP_LOOKUP_CALL        "SELECT * FROM api.fn_watchlist_edit_ip_lookup($1, $2, $3, $4)"
#define WATCHLISTEVENTS_CALL "SELECT * FROM api.fn_watchlist_events($1, $2, $3, $4, $5, $6)"
#define WATCHLISTPURGE_CALL  "SELECT api.fn_watchlist_purge($1) AS cleared_key_count"

static FakeAnswer_t* static_queueNamedAnswer(const char* const* column_names, int column_count, int row_count)
{
  FakeAnswer_t* answer = static_queueAnswer(PGRES_TUPLES_OK, column_count, row_count);
  for (int col = 0; col < column_count; col++)
  {
    answer->ma_columnNames[col] = column_names[col];
    for (int row = 0; row < row_count; row++)
      answer->ma_cells[row][col] = FAKE_SQL_NULL;
  }
  return answer;
}

static void static_setRow(FakeAnswer_t* answer, int row, const char* const* cells, int column_count)
{
  for (int col = 0; col < column_count; col++)
    answer->ma_cells[row][col] = cells[col] != NULL ? cells[col] : FAKE_SQL_NULL;
}

static void static_setEditCounts(FakeAnswer_t* answer, int column_count, const char* item_count, const char* package_item_count)
{
  answer->ma_cells[0][column_count - 2] = item_count;
  answer->ma_cells[0][column_count - 1] = package_item_count;
}

typedef struct {
  const char*        mp_call;
  const char* const* mp_columnNames;
  int                m_columnCount;
} WatchlistEditShape_t;

static WatchlistEditShape_t static_editShape(WatchlistItemKind_t kind)
{
  switch (kind)
  {
    case WATCHLIST_ITEM_CVE_LOOKUP:       return (WatchlistEditShape_t){ WATCHLISTEDIT_CVE_LOOKUP_CALL,       g_watchlistEditCveIdColumnNames,           WATCHLISTEDIT_CVE_ID_ROW_COLUMN_COUNT };
    case WATCHLIST_ITEM_KEV_LOOKUP:       return (WatchlistEditShape_t){ WATCHLISTEDIT_KEV_LOOKUP_CALL,       g_watchlistEditCveIdColumnNames,           WATCHLISTEDIT_CVE_ID_ROW_COLUMN_COUNT };
    case WATCHLIST_ITEM_CVE_EXPLOIT:      return (WatchlistEditShape_t){ WATCHLISTEDIT_CVE_EXPLOIT_CALL,      g_watchlistEditCveIdColumnNames,           WATCHLISTEDIT_CVE_ID_ROW_COLUMN_COUNT };
    case WATCHLIST_ITEM_PRODUCT_EXPOSURE: return (WatchlistEditShape_t){ WATCHLISTEDIT_PRODUCT_EXPOSURE_CALL, g_watchlistEditProductExposureColumnNames, WATCHLISTEDIT_PRODUCT_EXPOSURE_ROW_COLUMN_COUNT };
    case WATCHLIST_ITEM_CVE_SEARCH:       return (WatchlistEditShape_t){ WATCHLISTEDIT_CVE_SEARCH_CALL,       g_watchlistEditCveSearchColumnNames,       WATCHLISTEDIT_CVE_SEARCH_ROW_COLUMN_COUNT };
    case WATCHLIST_ITEM_DNS_LOOKUP:       return (WatchlistEditShape_t){ WATCHLISTEDIT_DNS_LOOKUP_CALL,       g_watchlistEditDomainColumnNames,          WATCHLISTEDIT_DOMAIN_ROW_COLUMN_COUNT };
    case WATCHLIST_ITEM_SSL_CHECK:        return (WatchlistEditShape_t){ WATCHLISTEDIT_SSL_CHECK_CALL,        g_watchlistEditDomainColumnNames,          WATCHLISTEDIT_DOMAIN_ROW_COLUMN_COUNT };
    case WATCHLIST_ITEM_WHOIS_LOOKUP:     return (WatchlistEditShape_t){ WATCHLISTEDIT_WHOIS_LOOKUP_CALL,     g_watchlistEditDomainColumnNames,          WATCHLISTEDIT_DOMAIN_ROW_COLUMN_COUNT };
    case WATCHLIST_ITEM_HEADERS_CHECK:    return (WatchlistEditShape_t){ WATCHLISTEDIT_HEADERS_CHECK_CALL,    g_watchlistEditDomainColumnNames,          WATCHLISTEDIT_DOMAIN_ROW_COLUMN_COUNT };
    case WATCHLIST_ITEM_CERT_SEARCH:      return (WatchlistEditShape_t){ WATCHLISTEDIT_CERT_SEARCH_CALL,      g_watchlistEditDomainColumnNames,          WATCHLISTEDIT_DOMAIN_ROW_COLUMN_COUNT };
    case WATCHLIST_ITEM_PACKAGE_CHECK:    return (WatchlistEditShape_t){ WATCHLISTEDIT_PACKAGE_CHECK_CALL,    g_watchlistEditPackageColumnNames,         WATCHLISTEDIT_PACKAGE_ROW_COLUMN_COUNT };
    case WATCHLIST_ITEM_IP_LOOKUP:        return (WatchlistEditShape_t){ WATCHLISTEDIT_IP_LOOKUP_CALL,        g_watchlistEditIpColumnNames,              WATCHLISTEDIT_IP_ROW_COLUMN_COUNT };
  }
  TEST_FAIL_MESSAGE("no edit shape for the kind");
  return (WatchlistEditShape_t){ NULL, NULL, 0 };
}

static FakeAnswer_t* static_queueEditAnswer(WatchlistEditShape_t shape, const char* status, const char* item_count, const char* package_item_count)
{
  FakeAnswer_t* answer = static_queueNamedAnswer(shape.mp_columnNames, shape.m_columnCount, 1);
  answer->ma_cells[0][0] = status;
  static_setEditCounts(answer, shape.m_columnCount, item_count, package_item_count);
  return answer;
}

static void static_watchlistBudget(RequestCreditBudget_t* budget)
{
  memset(budget, 0, sizeof(*budget));
  memcpy(budget->ma_budgetHash, WATCHLIST_TEST_KEY_HASH, sizeof(WATCHLIST_TEST_KEY_HASH));
  budget->m_tier = REQUEST_TIER_PRO;
}

static void static_unsetEditParams(WATCHLISTEDITItemsDbParams_t* params, const RequestCreditBudget_t* budget)
{
  memset(params, 0, sizeof(*params));
  params->mp_creditBudget = budget;
}

static void static_itemEditParams(WATCHLISTEDITItemsDbParams_t* params, const RequestCreditBudget_t* budget, WATCHLISTEDITAction_t action, WatchlistItemKind_t kind)
{
  static_unsetEditParams(params, budget);
  params->m_action          = action;
  params->m_item.m_itemKind = kind;
  if (kind == WATCHLIST_ITEM_CVE_SEARCH)
  {
    params->m_item.m_cveSearch.m_minCvss   = -1.0;
    params->m_item.m_cveSearch.m_minEpss   = -1.0;
    params->m_item.m_cveSearch.m_kevFilter = CVE_KEV_FILTER_ANY;
  }
}

void test_WATCHLISTEDIT_sends_each_value_in_its_own_parameter(void)
{
  RequestCreditBudget_t budget;
  static_watchlistBudget(&budget);

  WATCHLISTEDITItemsDbParams_t every_filter;
  static_itemEditParams(&every_filter, &budget, WATCHLISTEDIT_ACTION_REMOVE, WATCHLIST_ITEM_CVE_SEARCH);
  WATCHLISTCVESEARCHItem_t* filter = &every_filter.m_item.m_cveSearch;
  static_setText(filter->ma_vendor,   sizeof(filter->ma_vendor),   "apache");
  static_setText(filter->ma_product,  sizeof(filter->ma_product),  "log4j");
  static_setText(filter->ma_severity, sizeof(filter->ma_severity), "HIGH");
  static_setText(filter->ma_cweId,    sizeof(filter->ma_cweId),    "CWE-917");
  filter->m_minCvss           = 7.5;
  filter->m_minEpss           = 0.25;
  filter->m_kevFilter         = CVE_KEV_FILTER_ONLY_IN_KEV;
  filter->m_knownRansomware   = true;
  filter->m_hasNucleiTemplate = true;

  WATCHLISTEDITItemsDbParams_t clear;
  static_unsetEditParams(&clear, &budget);
  clear.m_action = WATCHLISTEDIT_ACTION_CLEAR;

  WATCHLISTEDITItemsDbParams_t list;
  static_unsetEditParams(&list, &budget);

  WATCHLISTEDITItemsDbParams_t not_in_kev;
  static_itemEditParams(&not_in_kev, &budget, WATCHLISTEDIT_ACTION_ADD, WATCHLIST_ITEM_CVE_SEARCH);
  not_in_kev.m_item.m_cveSearch.m_kevFilter = CVE_KEV_FILTER_NOT_IN_KEV;

  WATCHLISTEDITItemsDbParams_t nuclei_only;
  static_itemEditParams(&nuclei_only, &budget, WATCHLISTEDIT_ACTION_ADD, WATCHLIST_ITEM_CVE_SEARCH);
  nuclei_only.m_item.m_cveSearch.m_hasNucleiTemplate = true;

  WATCHLISTEDITItemsDbParams_t domain_add;
  static_itemEditParams(&domain_add, &budget, WATCHLISTEDIT_ACTION_ADD, WATCHLIST_ITEM_DNS_LOOKUP);
  static_setText(domain_add.m_item.m_dnsLookup.ma_domainName, sizeof(domain_add.m_item.m_dnsLookup.ma_domainName), "www.example.co.uk");

  WATCHLISTEDITItemsDbParams_t cve_add;
  static_itemEditParams(&cve_add, &budget, WATCHLISTEDIT_ACTION_ADD, WATCHLIST_ITEM_CVE_LOOKUP);
  static_setText(cve_add.m_item.m_cveLookup.ma_cveId, sizeof(cve_add.m_item.m_cveLookup.ma_cveId), "CVE-2021-44228");

  WATCHLISTEDITItemsDbParams_t package_add;
  static_itemEditParams(&package_add, &budget, WATCHLISTEDIT_ACTION_ADD, WATCHLIST_ITEM_PACKAGE_CHECK);
  WATCHLISTPACKAGECHECKItem_t* package = &package_add.m_item.m_packageCheck;
  static_setText(package->ma_ecosystem, sizeof(package->ma_ecosystem), "PyPI");
  static_setText(package->ma_name,      sizeof(package->ma_name),      "Django");

  WATCHLISTEDITItemsDbParams_t package_remove;
  static_itemEditParams(&package_remove, &budget, WATCHLISTEDIT_ACTION_REMOVE, WATCHLIST_ITEM_PACKAGE_CHECK);
  package = &package_remove.m_item.m_packageCheck;
  static_setText(package->ma_ecosystem, sizeof(package->ma_ecosystem), "npm");
  static_setText(package->ma_name,      sizeof(package->ma_name),      "lodash");
  static_setText(package->ma_version,   sizeof(package->ma_version),   "4.17.20");

  WATCHLISTEDITItemsDbParams_t ip_remove;
  static_itemEditParams(&ip_remove, &budget, WATCHLISTEDIT_ACTION_REMOVE, WATCHLIST_ITEM_IP_LOOKUP);
  static_setText(ip_remove.m_item.m_ipLookup.ma_ipAddress, sizeof(ip_remove.m_item.m_ipLookup.ma_ipAddress), "2606:4700::1111");

  static const char* const every_filter_values[]   = { WATCHLIST_TEST_KEY_HASH, "remove", "apache", "log4j", "HIGH", "CWE-917", "7.50", "0.250000", "true", "true", "true", "100" };
  static const char* const clear_values[]          = { WATCHLIST_TEST_KEY_HASH };
  static const char* const list_values[]           = { WATCHLIST_TEST_KEY_HASH };
  static const char* const not_in_kev_values[]     = { WATCHLIST_TEST_KEY_HASH, "add", NULL, NULL, NULL, NULL, NULL, NULL, "false", NULL, NULL, "100" };
  static const char* const nuclei_only_values[]    = { WATCHLIST_TEST_KEY_HASH, "add", NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, "true", "100" };
  static const char* const domain_add_values[]     = { WATCHLIST_TEST_KEY_HASH, "add", "www.example.co.uk", "example.co.uk", "100", "20" };
  static const char* const cve_add_values[]        = { WATCHLIST_TEST_KEY_HASH, "add", "CVE-2021-44228", "100" };
  static const char* const package_add_values[]    = { WATCHLIST_TEST_KEY_HASH, "add", "PyPI", "Django", NULL, "500", "100", "100000", "20" };
  static const char* const package_remove_values[] = { WATCHLIST_TEST_KEY_HASH, "remove", "npm", "lodash", "4.17.20", "500", "100", "100000", "20" };
  static const char* const ip_remove_values[]      = { WATCHLIST_TEST_KEY_HASH, "remove", "2606:4700::1111", "100" };
  const WatchlistEditShape_t wide = { NULL, g_watchlistEditColumnNames, WATCHLISTEDIT_ROW_COLUMN_COUNT };
  const struct {
    const WATCHLISTEDITItemsDbParams_t* mp_params;
    const char*                  mp_registeredDomain;
    const char*                  mp_call;
    WatchlistEditShape_t         m_answer;
    const char* const*           mp_values;
    int                          m_valueCount;
  } cases[] = {
    { &every_filter,   NULL,            WATCHLISTEDIT_CVE_SEARCH_CALL,    static_editShape(WATCHLIST_ITEM_CVE_SEARCH),    every_filter_values,   12 },
    { &clear,          NULL,            WATCHLISTEDIT_CLEAR_CALL,         wide,                                           clear_values,          1 },
    { &list,           NULL,            WATCHLISTEDIT_LIST_CALL,          wide,                                           list_values,           1 },
    { &not_in_kev,     NULL,            WATCHLISTEDIT_CVE_SEARCH_CALL,    static_editShape(WATCHLIST_ITEM_CVE_SEARCH),    not_in_kev_values,     12 },
    { &nuclei_only,    NULL,            WATCHLISTEDIT_CVE_SEARCH_CALL,    static_editShape(WATCHLIST_ITEM_CVE_SEARCH),    nuclei_only_values,    12 },
    { &domain_add,     "example.co.uk", WATCHLISTEDIT_DNS_LOOKUP_CALL,    static_editShape(WATCHLIST_ITEM_DNS_LOOKUP),    domain_add_values,     6 },
    { &cve_add,        NULL,            WATCHLISTEDIT_CVE_LOOKUP_CALL,    static_editShape(WATCHLIST_ITEM_CVE_LOOKUP),    cve_add_values,        4 },
    { &package_add,    NULL,            WATCHLISTEDIT_PACKAGE_CHECK_CALL, static_editShape(WATCHLIST_ITEM_PACKAGE_CHECK), package_add_values,    9 },
    { &package_remove, NULL,            WATCHLISTEDIT_PACKAGE_CHECK_CALL, static_editShape(WATCHLIST_ITEM_PACKAGE_CHECK), package_remove_values, 9 },
    { &ip_remove,      NULL,            WATCHLISTEDIT_IP_LOOKUP_CALL,     static_editShape(WATCHLIST_ITEM_IP_LOOKUP),     ip_remove_values,      4 },
  };
  TEST_ASSERT_EQUAL_INT(100, WATCHLIST_ITEM_MAX_COUNT_PER_API_KEY);
  TEST_ASSERT_EQUAL_INT(20, WATCHLIST_DOMAIN_NAME_MAX_COUNT_PER_REGISTERED_DOMAIN);
  TEST_ASSERT_EQUAL_INT(500, WATCHLIST_PACKAGE_ITEM_MAX_COUNT_PER_API_KEY);
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    static_resetFake();
    static_queueEditAnswer(cases[i].m_answer, "ok", "0", "0");
    WATCHLISTEDITItemsResult_t result;
    memset(&result, 0xA5, sizeof(result));

    TEST_ASSERT_EQUAL_INT(DB_OK, db_WATCHLISTEDITItems(FAKE_CONN, cases[i].mp_params, cases[i].mp_registeredDomain, &result));
    TEST_ASSERT_EQUAL_INT(1, g_callCount);
    static_assertCall(0, cases[i].mp_call, cases[i].mp_values, cases[i].m_valueCount);
    TEST_ASSERT_EQUAL_INT(0, static_call(0)->m_resultFormat);
    TEST_ASSERT_EQUAL_INT(WATCHLISTEDIT_OK, result.m_status);
    TEST_ASSERT_EQUAL_INT(0, result.m_itemCount);
    db_WATCHLISTEDITItemsResultFree(&result);
    TEST_ASSERT_NULL(result.mp_items);
  }
}

#define WATCHLISTEDIT_PACKAGE_LIST_ROW_COLUMN_COUNT 7
#define WATCHLISTEDIT_PACKAGE_LIST_CALL "SELECT * FROM api.fn_watchlist_package_list_edit($1, $2, $3, $4, $5, $6, $7, $8, $9)"

static const char* const g_watchlistEditPackageListColumnNames[WATCHLISTEDIT_PACKAGE_LIST_ROW_COLUMN_COUNT] = {
  "edit_status", "package_index", "earlier_package_index", "added_count", "removed_count", "unchanged_count", "package_item_count"
};

static void static_packageListParams(WATCHLISTEDITPackageListDbParams_t* params, const RequestCreditBudget_t* budget, WATCHLISTEDITAction_t action,
                                     const WATCHLISTEDITPackageElement_t* elements, int element_count)
{
  memset(params, 0, sizeof(*params));
  params->mp_creditBudget = budget;
  params->m_action        = action;
  params->mp_elements     = elements;
  params->m_elementCount  = element_count;
}

static void static_setPackageElement(WATCHLISTEDITPackageElement_t* element, const char* ecosystem, const char* name, const char* version,
                                     PackageElementProblem_t problem)
{
  memset(element, 0, sizeof(*element));
  static_setText(element->m_package.ma_ecosystem,   sizeof(element->m_package.ma_ecosystem),   ecosystem);
  static_setText(element->m_package.ma_packageName, sizeof(element->m_package.ma_packageName), name);
  static_setText(element->m_package.ma_version,     sizeof(element->m_package.ma_version),     version);
  element->m_problem      = problem;
  element->m_earlierIndex = -1;
}

static FakeAnswer_t* static_queuePackageListAnswer(int row_count, const char* status, const char* const counts[4])
{
  FakeAnswer_t* answer = static_queueNamedAnswer(g_watchlistEditPackageListColumnNames, WATCHLISTEDIT_PACKAGE_LIST_ROW_COLUMN_COUNT, row_count);
  for (int row = 0; row < row_count; row++)
  {
    answer->ma_cells[row][0] = status;
    for (int k = 0; k < 4; k++)
      answer->ma_cells[row][3 + k] = counts[k] != NULL ? counts[k] : FAKE_SQL_NULL;
  }
  return answer;
}

void test_WATCHLISTEDIT_package_list_sends_its_elements_as_three_arrays(void)
{
  RequestCreditBudget_t budget;
  static_watchlistBudget(&budget);
  WATCHLISTEDITPackageElement_t elements[3];
  static_setPackageElement(&elements[0], "npm",  "lodash", "4.17.20", PACKAGE_ELEMENT_PROBLEM_NONE);
  static_setPackageElement(&elements[1], "PyPI", "a\"b",   "",        PACKAGE_ELEMENT_PROBLEM_NONE);
  static_setPackageElement(&elements[2], "x",    "y",      "1",       PACKAGE_ELEMENT_PROBLEM_ECOSYSTEM_UNKNOWN);

  WATCHLISTEDITPackageListDbParams_t add;
  static_packageListParams(&add, &budget, WATCHLISTEDIT_ACTION_ADD, elements, 3);
  WATCHLISTEDITPackageListDbParams_t remove;
  static_packageListParams(&remove, &budget, WATCHLISTEDIT_ACTION_REMOVE, elements, 1);
  WATCHLISTEDITItemsDbParams_t single;
  static_itemEditParams(&single, &budget, WATCHLISTEDIT_ACTION_ADD, WATCHLIST_ITEM_PACKAGE_CHECK);
  static_setText(single.m_item.m_packageCheck.ma_ecosystem, sizeof(single.m_item.m_packageCheck.ma_ecosystem), "npm");
  static_setText(single.m_item.m_packageCheck.ma_name,      sizeof(single.m_item.m_packageCheck.ma_name),      "lodash");

  static const char* const add_values[]    = { WATCHLIST_TEST_KEY_HASH, "add", "{\"npm\",\"PyPI\",\"\"}", "{\"lodash\",\"a\\\"b\",\"\"}", "{\"4.17.20\",\"\",\"\"}", "500", "100", "100000", "20" };
  static const char* const remove_values[] = { WATCHLIST_TEST_KEY_HASH, "remove", "{\"npm\"}", "{\"lodash\"}", "{\"4.17.20\"}", "500", "100", "100000", "20" };
  static const char* const single_values[] = { WATCHLIST_TEST_KEY_HASH, "add", "npm", "lodash", NULL, "500", "100", "100000", "20" };
  static const char* const zero_counts[4]  = { "0", "0", "0", "0" };
  const struct { const WATCHLISTEDITPackageListDbParams_t* mp_params; const char* const* mp_values; } package_lists[] = {
    { &add,    add_values },
    { &remove, remove_values },
  };
  for (size_t i = 0; i < sizeof(package_lists) / sizeof(package_lists[0]); i++)
  {
    static_resetFake();
    static_queuePackageListAnswer(1, "ok", zero_counts);
    WATCHLISTEDITPackageListResult_t result;
    memset(&result, 0xA5, sizeof(result));
    TEST_ASSERT_EQUAL_INT(DB_OK, db_WATCHLISTEDITPackageList(FAKE_CONN, package_lists[i].mp_params, &result));
    TEST_ASSERT_EQUAL_INT(1, g_callCount);
    static_assertCall(0, WATCHLISTEDIT_PACKAGE_LIST_CALL, package_lists[i].mp_values, 9);
    TEST_ASSERT_NULL(result.mp_repeatedPackages);
    TEST_ASSERT_EQUAL_INT(package_lists[i].mp_params->m_action, result.m_action);
    db_WATCHLISTEDITPackageListResultFree(&result);
  }

  static_resetFake();
  static_queueEditAnswer(static_editShape(WATCHLIST_ITEM_PACKAGE_CHECK), "ok", "0", "0");
  WATCHLISTEDITItemsResult_t result;
  memset(&result, 0xA5, sizeof(result));
  TEST_ASSERT_EQUAL_INT(DB_OK, db_WATCHLISTEDITItems(FAKE_CONN, &single, NULL, &result));
  TEST_ASSERT_EQUAL_INT(1, g_callCount);
  static_assertCall(0, WATCHLISTEDIT_PACKAGE_CHECK_CALL, single_values, 9);
  TEST_ASSERT_EQUAL_INT(0, result.m_itemCount);
  TEST_ASSERT_NULL(result.mp_items);
  db_WATCHLISTEDITItemsResultFree(&result);
}

void test_WATCHLISTEDIT_package_list_reads_no_element_past_the_last(void)
{
  RequestCreditBudget_t budget;
  static_watchlistBudget(&budget);
  int count = WATCHLIST_PACKAGE_ITEM_MAX_COUNT_PER_API_KEY;
  WATCHLISTEDITPackageElement_t* elements = calloc((size_t)count, sizeof(*elements));
  TEST_ASSERT_NOT_NULL(elements);
  for (int i = 0; i < count; i++)
    static_setPackageElement(&elements[i], "a", "a", "", PACKAGE_ELEMENT_PROBLEM_NONE);
  WATCHLISTEDITPackageListDbParams_t add;
  static_packageListParams(&add, &budget, WATCHLISTEDIT_ACTION_ADD, elements, count);
  static const char* const zero_counts[4] = { "0", "0", "0", "0" };
  static_resetFake();
  static_queuePackageListAnswer(1, "ok", zero_counts);
  WATCHLISTEDITPackageListResult_t result;
  TEST_ASSERT_EQUAL_INT(DB_OK, db_WATCHLISTEDITPackageList(FAKE_CONN, &add, &result));
  TEST_ASSERT_EQUAL_INT(1, g_callCount);
  db_WATCHLISTEDITPackageListResultFree(&result);
  free(elements);
}

void test_WATCHLISTEDIT_package_list_reads_its_counts_and_repeats(void)
{
  RequestCreditBudget_t budget;
  static_watchlistBudget(&budget);
  WATCHLISTEDITPackageElement_t elements[5];
  for (int i = 0; i < 5; i++)
    static_setPackageElement(&elements[i], "npm", "a", "", PACKAGE_ELEMENT_PROBLEM_NONE);
  WATCHLISTEDITPackageListDbParams_t add;
  static_packageListParams(&add, &budget, WATCHLISTEDIT_ACTION_ADD, elements, 5);
  WATCHLISTEDITPackageListDbParams_t remove;
  static_packageListParams(&remove, &budget, WATCHLISTEDIT_ACTION_REMOVE, elements, 5);

  static const char* const add_counts[4] = { "1", "0", "7", "9" };
  static_resetFake();
  static_queuePackageListAnswer(1, "ok", add_counts);
  WATCHLISTEDITPackageListResult_t result;
  memset(&result, 0xA5, sizeof(result));
  TEST_ASSERT_EQUAL_INT(DB_OK, db_WATCHLISTEDITPackageList(FAKE_CONN, &add, &result));
  TEST_ASSERT_EQUAL_INT(WATCHLISTEDIT_OK, result.m_status);
  TEST_ASSERT_EQUAL_INT(WATCHLISTEDIT_ACTION_ADD, result.m_action);
  TEST_ASSERT_EQUAL_INT(1, result.m_addedCount);
  TEST_ASSERT_EQUAL_INT(0, result.m_removedCount);
  TEST_ASSERT_EQUAL_INT(7, result.m_unchangedCount);
  TEST_ASSERT_EQUAL_INT(9, result.m_packageItemCountForCurrentApiKey);
  TEST_ASSERT_NULL(result.mp_repeatedPackages);
  TEST_ASSERT_EQUAL_INT(0, result.m_repeatedCount);
  db_WATCHLISTEDITPackageListResultFree(&result);

  static const char* const remove_counts[4] = { "0", "2", "1", "6" };
  static_resetFake();
  static_queuePackageListAnswer(1, "ok", remove_counts);
  memset(&result, 0xA5, sizeof(result));
  TEST_ASSERT_EQUAL_INT(DB_OK, db_WATCHLISTEDITPackageList(FAKE_CONN, &remove, &result));
  TEST_ASSERT_EQUAL_INT(WATCHLISTEDIT_ACTION_REMOVE, result.m_action);
  TEST_ASSERT_EQUAL_INT(0, result.m_addedCount);
  TEST_ASSERT_EQUAL_INT(2, result.m_removedCount);
  TEST_ASSERT_EQUAL_INT(1, result.m_unchangedCount);
  TEST_ASSERT_EQUAL_INT(6, result.m_packageItemCountForCurrentApiKey);
  db_WATCHLISTEDITPackageListResultFree(&result);

  static const char* const refused_counts[4] = { "0", "0", "0", "500" };
  static_resetFake();
  static_queuePackageListAnswer(1, "over_package_limit", refused_counts);
  memset(&result, 0xA5, sizeof(result));
  TEST_ASSERT_EQUAL_INT(DB_OK, db_WATCHLISTEDITPackageList(FAKE_CONN, &add, &result));
  TEST_ASSERT_EQUAL_INT(WATCHLISTEDIT_OVER_PACKAGE_LIMIT, result.m_status);
  TEST_ASSERT_EQUAL_INT(500, result.m_packageItemCountForCurrentApiKey);
  db_WATCHLISTEDITPackageListResultFree(&result);

  static const char* const null_counts[4] = { NULL, NULL, NULL, NULL };
  static_resetFake();
  FakeAnswer_t* answer = static_queuePackageListAnswer(2, "package_problem", null_counts);
  answer->ma_cells[0][1] = "2";
  answer->ma_cells[0][2] = "0";
  answer->ma_cells[1][1] = "4";
  answer->ma_cells[1][2] = "1";
  memset(&result, 0xA5, sizeof(result));
  TEST_ASSERT_EQUAL_INT(DB_OK, db_WATCHLISTEDITPackageList(FAKE_CONN, &add, &result));
  TEST_ASSERT_EQUAL_INT(WATCHLISTEDIT_PACKAGE_PROBLEM, result.m_status);
  TEST_ASSERT_EQUAL_INT(2, result.m_repeatedCount);
  TEST_ASSERT_NOT_NULL(result.mp_repeatedPackages);
  TEST_ASSERT_EQUAL_INT(2, result.mp_repeatedPackages[0].m_currentIndex);
  TEST_ASSERT_EQUAL_INT(0, result.mp_repeatedPackages[0].m_earlierIndex);
  TEST_ASSERT_EQUAL_INT(4, result.mp_repeatedPackages[1].m_currentIndex);
  TEST_ASSERT_EQUAL_INT(1, result.mp_repeatedPackages[1].m_earlierIndex);
  db_WATCHLISTEDITPackageListResultFree(&result);
  TEST_ASSERT_NULL(result.mp_repeatedPackages);
  TEST_ASSERT_EQUAL_INT(0, result.m_repeatedCount);

  static_resetFake();
  answer = static_queuePackageListAnswer(1, "package_problem", null_counts);
  answer->ma_cells[0][1] = "3";
  answer->ma_cells[0][2] = "2";
  memset(&result, 0xA5, sizeof(result));
  TEST_ASSERT_EQUAL_INT(DB_OK, db_WATCHLISTEDITPackageList(FAKE_CONN, &add, &result));
  TEST_ASSERT_EQUAL_INT(1, result.m_repeatedCount);
  TEST_ASSERT_NOT_NULL(result.mp_repeatedPackages);
  TEST_ASSERT_EQUAL_INT(3, result.mp_repeatedPackages[0].m_currentIndex);
  TEST_ASSERT_EQUAL_INT(2, result.mp_repeatedPackages[0].m_earlierIndex);
  db_WATCHLISTEDITPackageListResultFree(&result);

  static_resetFake();
  static_queuePackageListAnswer(1, "package_problem", null_counts);
  memset(&result, 0xA5, sizeof(result));
  TEST_ASSERT_EQUAL_INT(DB_OK, db_WATCHLISTEDITPackageList(FAKE_CONN, &remove, &result));
  TEST_ASSERT_EQUAL_INT(WATCHLISTEDIT_PACKAGE_PROBLEM, result.m_status);
  TEST_ASSERT_EQUAL_INT(0, result.m_repeatedCount);
  TEST_ASSERT_NULL(result.mp_repeatedPackages);
  db_WATCHLISTEDITPackageListResultFree(&result);

  static_resetFake();
  static_queuePackageListAnswer(1, "unknown_key", null_counts);
  memset(&result, 0xA5, sizeof(result));
  TEST_ASSERT_EQUAL_INT(DB_OK, db_WATCHLISTEDITPackageList(FAKE_CONN, &add, &result));
  TEST_ASSERT_EQUAL_INT(WATCHLISTEDIT_UNKNOWN_KEY, result.m_status);
  TEST_ASSERT_EQUAL_INT(0, result.m_packageItemCountForCurrentApiKey);
  TEST_ASSERT_EQUAL_INT(0, result.m_addedCount);
  TEST_ASSERT_NULL(result.mp_repeatedPackages);
  db_WATCHLISTEDITPackageListResultFree(&result);
}

void test_WATCHLISTEDIT_package_list_refuses_an_answer_it_cannot_trust(void)
{
  RequestCreditBudget_t budget;
  static_watchlistBudget(&budget);
  WATCHLISTEDITPackageElement_t elements[2];
  static_setPackageElement(&elements[0], "npm", "a", "", PACKAGE_ELEMENT_PROBLEM_NONE);
  static_setPackageElement(&elements[1], "npm", "b", "", PACKAGE_ELEMENT_PROBLEM_NONE);
  WATCHLISTEDITPackageListDbParams_t add;
  static_packageListParams(&add, &budget, WATCHLISTEDIT_ACTION_ADD, elements, 2);

  static const char* const ok_counts[4]   = { "1", "0", "1", "2" };
  static const char* const null_counts[4] = { NULL, NULL, NULL, NULL };
  enum { NULL_ADDED, NULL_REMOVED, NULL_UNCHANGED, NULL_PACKAGE_ITEM_COUNT, BAD_COUNT, SECOND_OK_ROW, NULL_EARLIER,
         NULL_SECOND_INDEX, BAD_INDEX, ROW_AFTER_NO_REPEAT, NULL_INDEX_ONLY, MORE_ROWS_THAN_ELEMENTS, WRONG_COLUMNS, CASE_COUNT };
  for (int c = 0; c < CASE_COUNT; c++)
  {
    static_resetFake();
    bool is_problem = c >= NULL_EARLIER && c <= NULL_INDEX_ONLY;
    int row_count = (c == SECOND_OK_ROW || (is_problem && c != NULL_INDEX_ONLY)) ? 2 : (c == MORE_ROWS_THAN_ELEMENTS ? 3 : 1);
    FakeAnswer_t* answer = static_queuePackageListAnswer(row_count, is_problem || c == MORE_ROWS_THAN_ELEMENTS ? "package_problem" : "ok",
                                                         is_problem || c == MORE_ROWS_THAN_ELEMENTS ? null_counts : ok_counts);
    for (int row = 0; is_problem && row < row_count; row++)
    {
      answer->ma_cells[row][1] = "1";
      answer->ma_cells[row][2] = "0";
    }
    for (int row = 0; c == MORE_ROWS_THAN_ELEMENTS && row < row_count; row++)
    {
      answer->ma_cells[row][1] = "1";
      answer->ma_cells[row][2] = "0";
    }
    if (c <= NULL_PACKAGE_ITEM_COUNT)
      answer->ma_cells[0][3 + c] = FAKE_SQL_NULL;
    switch (c)
    {
      case BAD_COUNT:           answer->ma_cells[0][5] = "x"; break;
      case NULL_EARLIER:        answer->ma_cells[0][2] = FAKE_SQL_NULL; break;
      case NULL_SECOND_INDEX:   answer->ma_cells[1][1] = FAKE_SQL_NULL; break;
      case BAD_INDEX:           answer->ma_cells[1][1] = "x"; break;
      case ROW_AFTER_NO_REPEAT: answer->ma_cells[0][1] = FAKE_SQL_NULL; answer->ma_cells[0][2] = FAKE_SQL_NULL; break;
      case NULL_INDEX_ONLY:     answer->ma_cells[0][1] = FAKE_SQL_NULL; break;
      case WRONG_COLUMNS:       answer->ma_columnNames[1] = "repeat_index"; break;
      default:                  break;
    }
    WATCHLISTEDITPackageListResult_t result;
    memset(&result, 0xA5, sizeof(result));
    char label[32];
    snprintf(label, sizeof(label), "case %d", c);
    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_ERROR, db_WATCHLISTEDITPackageList(FAKE_CONN, &add, &result), label);
    TEST_ASSERT_NULL_MESSAGE(result.mp_repeatedPackages, label);
  }
}

void test_WATCHLISTEDIT_binds_each_kind_from_its_own_member(void)
{
  RequestCreditBudget_t budget;
  static_watchlistBudget(&budget);

  WATCHLISTEDITItemsDbParams_t params[WATCHLIST_ITEM_KIND_COUNT];
  static_itemEditParams(&params[0], &budget, WATCHLISTEDIT_ACTION_ADD, WATCHLIST_ITEM_CVE_LOOKUP);
  static_setText(params[0].m_item.m_cveLookup.ma_cveId, sizeof(params[0].m_item.m_cveLookup.ma_cveId), "CVE-2021-44228");
  static_itemEditParams(&params[1], &budget, WATCHLISTEDIT_ACTION_REMOVE, WATCHLIST_ITEM_KEV_LOOKUP);
  static_setText(params[1].m_item.m_kevLookup.ma_cveId, sizeof(params[1].m_item.m_kevLookup.ma_cveId), "CVE-2022-0001");
  static_itemEditParams(&params[2], &budget, WATCHLISTEDIT_ACTION_ADD, WATCHLIST_ITEM_CVE_EXPLOIT);
  static_setText(params[2].m_item.m_cveExploit.ma_cveId, sizeof(params[2].m_item.m_cveExploit.ma_cveId), "CVE-2023-0002");
  static_itemEditParams(&params[3], &budget, WATCHLISTEDIT_ACTION_ADD, WATCHLIST_ITEM_PRODUCT_EXPOSURE);
  static_setText(params[3].m_item.m_productExposure.ma_vendor,  sizeof(params[3].m_item.m_productExposure.ma_vendor),  "cisco");
  static_setText(params[3].m_item.m_productExposure.ma_product, sizeof(params[3].m_item.m_productExposure.ma_product), "ios");
  static_setText(params[3].m_item.m_productExposure.ma_version, sizeof(params[3].m_item.m_productExposure.ma_version), "15.2");
  params[3].m_item.m_productExposure.m_hasCves = true;
  static_itemEditParams(&params[4], &budget, WATCHLISTEDIT_ACTION_ADD, WATCHLIST_ITEM_CVE_SEARCH);
  WATCHLISTCVESEARCHItem_t* filter = &params[4].m_item.m_cveSearch;
  static_setText(filter->ma_vendor,   sizeof(filter->ma_vendor),   "oracle");
  static_setText(filter->ma_product,  sizeof(filter->ma_product),  "mysql");
  static_setText(filter->ma_severity, sizeof(filter->ma_severity), "CRITICAL");
  static_setText(filter->ma_cweId,    sizeof(filter->ma_cweId),    "CWE-79");
  filter->m_minCvss         = 9.1;
  filter->m_minEpss         = 0.5;
  filter->m_kevFilter       = CVE_KEV_FILTER_NOT_IN_KEV;
  filter->m_knownRansomware = true;
  static_itemEditParams(&params[5], &budget, WATCHLISTEDIT_ACTION_ADD, WATCHLIST_ITEM_DNS_LOOKUP);
  static_setText(params[5].m_item.m_dnsLookup.ma_domainName, sizeof(params[5].m_item.m_dnsLookup.ma_domainName), "a.example.com");
  static_itemEditParams(&params[6], &budget, WATCHLISTEDIT_ACTION_ADD, WATCHLIST_ITEM_SSL_CHECK);
  static_setText(params[6].m_item.m_sslCheck.ma_domainName, sizeof(params[6].m_item.m_sslCheck.ma_domainName), "b.example.org");
  static_itemEditParams(&params[7], &budget, WATCHLISTEDIT_ACTION_REMOVE, WATCHLIST_ITEM_WHOIS_LOOKUP);
  static_setText(params[7].m_item.m_whoisLookup.ma_domainName, sizeof(params[7].m_item.m_whoisLookup.ma_domainName), "example.net");
  static_itemEditParams(&params[8], &budget, WATCHLISTEDIT_ACTION_ADD, WATCHLIST_ITEM_HEADERS_CHECK);
  static_setText(params[8].m_item.m_headersCheck.ma_domainName, sizeof(params[8].m_item.m_headersCheck.ma_domainName), "c.example.io");
  static_itemEditParams(&params[9], &budget, WATCHLISTEDIT_ACTION_ADD, WATCHLIST_ITEM_CERT_SEARCH);
  static_setText(params[9].m_item.m_certSearch.ma_domainName, sizeof(params[9].m_item.m_certSearch.ma_domainName), "d.example.dev");
  static_itemEditParams(&params[10], &budget, WATCHLISTEDIT_ACTION_ADD, WATCHLIST_ITEM_PACKAGE_CHECK);
  WATCHLISTPACKAGECHECKItem_t* package = &params[10].m_item.m_packageCheck;
  static_setText(package->ma_ecosystem, sizeof(package->ma_ecosystem), "Go");
  static_setText(package->ma_name,      sizeof(package->ma_name),      "github.com/gin-gonic/gin");
  static_setText(package->ma_version,   sizeof(package->ma_version),   "v1.9.1");
  static_itemEditParams(&params[11], &budget, WATCHLISTEDIT_ACTION_ADD, WATCHLIST_ITEM_IP_LOOKUP);
  static_setText(params[11].m_item.m_ipLookup.ma_ipAddress, sizeof(params[11].m_item.m_ipLookup.ma_ipAddress), "8.8.4.4");

  static const char* const registered_domains[WATCHLIST_ITEM_KIND_COUNT] = { NULL, NULL, NULL, NULL, NULL, "example.com", "example.org", "example.net", "example.io", "example.dev", NULL, NULL };
  static const struct { const char* mp_call; int m_valueCount; const char* ma_values[12]; } expected[WATCHLIST_ITEM_KIND_COUNT] = {
    { WATCHLISTEDIT_CVE_LOOKUP_CALL,       4,  { WATCHLIST_TEST_KEY_HASH, "add",    "CVE-2021-44228", "100" } },
    { WATCHLISTEDIT_KEV_LOOKUP_CALL,       4,  { WATCHLIST_TEST_KEY_HASH, "remove", "CVE-2022-0001",  "100" } },
    { WATCHLISTEDIT_CVE_EXPLOIT_CALL,      4,  { WATCHLIST_TEST_KEY_HASH, "add",    "CVE-2023-0002",  "100" } },
    { WATCHLISTEDIT_PRODUCT_EXPOSURE_CALL, 6,  { WATCHLIST_TEST_KEY_HASH, "add",    "cisco", "ios", "15.2", "100" } },
    { WATCHLISTEDIT_CVE_SEARCH_CALL,       12, { WATCHLIST_TEST_KEY_HASH, "add",    "oracle", "mysql", "CRITICAL", "CWE-79", "9.10", "0.500000", "false", "true", NULL, "100" } },
    { WATCHLISTEDIT_DNS_LOOKUP_CALL,       6,  { WATCHLIST_TEST_KEY_HASH, "add",    "a.example.com", "example.com", "100", "20" } },
    { WATCHLISTEDIT_SSL_CHECK_CALL,        6,  { WATCHLIST_TEST_KEY_HASH, "add",    "b.example.org", "example.org", "100", "20" } },
    { WATCHLISTEDIT_WHOIS_LOOKUP_CALL,     6,  { WATCHLIST_TEST_KEY_HASH, "remove", "example.net",   "example.net", "100", "20" } },
    { WATCHLISTEDIT_HEADERS_CHECK_CALL,    6,  { WATCHLIST_TEST_KEY_HASH, "add",    "c.example.io",  "example.io",  "100", "20" } },
    { WATCHLISTEDIT_CERT_SEARCH_CALL,      6,  { WATCHLIST_TEST_KEY_HASH, "add",    "d.example.dev", "example.dev", "100", "20" } },
    { WATCHLISTEDIT_PACKAGE_CHECK_CALL,    9,  { WATCHLIST_TEST_KEY_HASH, "add",    "Go", "github.com/gin-gonic/gin", "v1.9.1", "500", "100", "100000", "20" } },
    { WATCHLISTEDIT_IP_LOOKUP_CALL,        4,  { WATCHLIST_TEST_KEY_HASH, "add",    "8.8.4.4", "100" } },
  };
  for (size_t i = 0; i < WATCHLIST_ITEM_KIND_COUNT; i++)
  {
    TEST_ASSERT_EQUAL_INT((int)i, (int)params[i].m_item.m_itemKind);
    static_resetFake();
    static_queueEditAnswer(static_editShape(params[i].m_item.m_itemKind), "ok", "0", "0");
    WATCHLISTEDITItemsResult_t result;
    memset(&result, 0xA5, sizeof(result));

    TEST_ASSERT_EQUAL_INT(DB_OK, db_WATCHLISTEDITItems(FAKE_CONN, &params[i], registered_domains[i], &result));
    TEST_ASSERT_EQUAL_INT(1, g_callCount);
    static_assertCall(0, expected[i].mp_call, expected[i].ma_values, expected[i].m_valueCount);
    db_WATCHLISTEDITItemsResultFree(&result);
  }
}

void test_lookups_answer_not_found_for_no_row_and_error_for_a_failed_query(void)
{
  KEVLOOKUPRecord_t     kev;
  CWELOOKUPRecord_t     cwe;
  CVERISKSCORERecord_t  risk;
  CVETRIAGEBULKResult_t triage;
  static const BulkIdsParams_t ids = {
    .ma_ids    = { "CVE-2021-44228" },
    .m_idCount = 1,
  };

  static_resetFake();
  static_queueNamedAnswer(g_kevlookupColumnNames, KEVLOOKUP_ROW_COLUMN_COUNT, 0);
  TEST_ASSERT_EQUAL_INT(DB_NOT_FOUND, db_KEVLOOKUP(NULL, "CVE-2021-44228", &kev));
  db_KEVLOOKUPRecordFree(&kev);

  static_resetFake();
  static_queueNamedAnswer(g_cwelookupColumnNames, CWELOOKUP_ROW_COLUMN_COUNT, 0);
  TEST_ASSERT_EQUAL_INT(DB_NOT_FOUND, db_CWELOOKUP(NULL, "CWE-79", &cwe));
  db_CWELOOKUPRecordFree(&cwe);

  static_resetFake();
  g_resultStatus = PGRES_FATAL_ERROR;
  TEST_ASSERT_EQUAL_INT(DB_ERROR, db_KEVLOOKUP(NULL, "CVE-2021-44228", &kev));
  db_KEVLOOKUPRecordFree(&kev);
  TEST_ASSERT_EQUAL_INT(DB_ERROR, db_CWELOOKUP(NULL, "CWE-79", &cwe));
  db_CWELOOKUPRecordFree(&cwe);
  TEST_ASSERT_EQUAL_INT(DB_ERROR, db_CVERISKSCORE(NULL, "CVE-2021-44228", &risk));
  TEST_ASSERT_EQUAL_INT(DB_ERROR, db_CVETRIAGEBULK(NULL, &ids, &triage));
  TEST_ASSERT_NULL(triage.mp_items);
}

void test_WATCHLISTEDIT_binds_an_unset_product_exposure_version_as_null(void)
{
  RequestCreditBudget_t budget;
  static_watchlistBudget(&budget);
  WATCHLISTEDITItemsDbParams_t params;
  static_itemEditParams(&params, &budget, WATCHLISTEDIT_ACTION_ADD, WATCHLIST_ITEM_PRODUCT_EXPOSURE);
  static_setText(params.m_item.m_productExposure.ma_vendor,  sizeof(params.m_item.m_productExposure.ma_vendor),  "cisco");
  static_setText(params.m_item.m_productExposure.ma_product, sizeof(params.m_item.m_productExposure.ma_product), "ios");
  static const char* const expected[] = { WATCHLIST_TEST_KEY_HASH, "add", "cisco", "ios", NULL, "100" };
  static_resetFake();
  static_queueEditAnswer(static_editShape(WATCHLIST_ITEM_PRODUCT_EXPOSURE), "ok", "0", "0");
  WATCHLISTEDITItemsResult_t result;
  memset(&result, 0xA5, sizeof(result));

  TEST_ASSERT_EQUAL_INT(DB_OK, db_WATCHLISTEDITItems(FAKE_CONN, &params, NULL, &result));
  TEST_ASSERT_EQUAL_INT(1, g_callCount);
  static_assertCall(0, WATCHLISTEDIT_PRODUCT_EXPOSURE_CALL, expected, 6);
  db_WATCHLISTEDITItemsResultFree(&result);
}

void test_WATCHLISTEDIT_reads_the_narrow_answer_of_each_shape(void)
{
  RequestCreditBudget_t budget;
  static_watchlistBudget(&budget);
  WATCHLISTEDITItemsResult_t result;

  WATCHLISTEDITItemsDbParams_t kev;
  static_itemEditParams(&kev, &budget, WATCHLISTEDIT_ACTION_REMOVE, WATCHLIST_ITEM_KEV_LOOKUP);
  static const char* const kev_row[WATCHLISTEDIT_CVE_ID_ROW_COLUMN_COUNT] = { "ok", "kev_lookup", "CVE-2022-0001", "7", "3" };
  static_resetFake();
  FakeAnswer_t* answer = static_queueNamedAnswer(g_watchlistEditCveIdColumnNames, WATCHLISTEDIT_CVE_ID_ROW_COLUMN_COUNT, 1);
  static_setRow(answer, 0, kev_row, WATCHLISTEDIT_CVE_ID_ROW_COLUMN_COUNT);
  memset(&result, 0xA5, sizeof(result));
  g_dirtyMalloc = true;
  TEST_ASSERT_EQUAL_INT(DB_OK, db_WATCHLISTEDITItems(FAKE_CONN, &kev, NULL, &result));
  g_dirtyMalloc = false;
  TEST_ASSERT_EQUAL_INT(WATCHLISTEDIT_OK, result.m_status);
  TEST_ASSERT_EQUAL_INT(1, result.m_itemCount);
  TEST_ASSERT_EQUAL_INT(7, result.m_itemCountForCurrentApiKey);
  TEST_ASSERT_EQUAL_INT(3, result.m_packageItemCountForCurrentApiKey);
  TEST_ASSERT_EQUAL_INT(WATCHLIST_ITEM_KEV_LOOKUP, result.mp_items[0].m_itemKind);
  TEST_ASSERT_EQUAL_STRING("CVE-2022-0001", result.mp_items[0].m_kevLookup.ma_cveId);
  db_WATCHLISTEDITItemsResultFree(&result);

  WATCHLISTEDITItemsDbParams_t exposure;
  static_itemEditParams(&exposure, &budget, WATCHLISTEDIT_ACTION_ADD, WATCHLIST_ITEM_PRODUCT_EXPOSURE);
  static const char* const exposure_row[WATCHLISTEDIT_PRODUCT_EXPOSURE_ROW_COLUMN_COUNT] = { "ok", "product_exposure", "cisco", "ios", "t", NULL, "8", "5" };
  static_resetFake();
  answer = static_queueNamedAnswer(g_watchlistEditProductExposureColumnNames, WATCHLISTEDIT_PRODUCT_EXPOSURE_ROW_COLUMN_COUNT, 1);
  static_setRow(answer, 0, exposure_row, WATCHLISTEDIT_PRODUCT_EXPOSURE_ROW_COLUMN_COUNT);
  memset(&result, 0xA5, sizeof(result));
  TEST_ASSERT_EQUAL_INT(DB_OK, db_WATCHLISTEDITItems(FAKE_CONN, &exposure, NULL, &result));
  TEST_ASSERT_EQUAL_INT(1, result.m_itemCount);
  TEST_ASSERT_EQUAL_INT(8, result.m_itemCountForCurrentApiKey);
  TEST_ASSERT_EQUAL_INT(5, result.m_packageItemCountForCurrentApiKey);
  TEST_ASSERT_EQUAL_INT(WATCHLIST_ITEM_PRODUCT_EXPOSURE, result.mp_items[0].m_itemKind);
  TEST_ASSERT_EQUAL_STRING("cisco", result.mp_items[0].m_productExposure.ma_vendor);
  TEST_ASSERT_EQUAL_STRING("ios", result.mp_items[0].m_productExposure.ma_product);
  TEST_ASSERT_EQUAL_STRING("", result.mp_items[0].m_productExposure.ma_version);
  TEST_ASSERT_TRUE(result.mp_items[0].m_productExposure.m_hasCves);
  db_WATCHLISTEDITItemsResultFree(&result);

  static const char* const exposure_version_row[WATCHLISTEDIT_PRODUCT_EXPOSURE_ROW_COLUMN_COUNT] = { "ok", "product_exposure", "cisco", "ios", "f", "15.2", "8", "5" };
  static_resetFake();
  answer = static_queueNamedAnswer(g_watchlistEditProductExposureColumnNames, WATCHLISTEDIT_PRODUCT_EXPOSURE_ROW_COLUMN_COUNT, 1);
  static_setRow(answer, 0, exposure_version_row, WATCHLISTEDIT_PRODUCT_EXPOSURE_ROW_COLUMN_COUNT);
  memset(&result, 0xA5, sizeof(result));
  TEST_ASSERT_EQUAL_INT(DB_OK, db_WATCHLISTEDITItems(FAKE_CONN, &exposure, NULL, &result));
  TEST_ASSERT_EQUAL_INT(1, result.m_itemCount);
  TEST_ASSERT_EQUAL_STRING("cisco", result.mp_items[0].m_productExposure.ma_vendor);
  TEST_ASSERT_EQUAL_STRING("ios", result.mp_items[0].m_productExposure.ma_product);
  TEST_ASSERT_EQUAL_STRING("15.2", result.mp_items[0].m_productExposure.ma_version);
  TEST_ASSERT_FALSE(result.mp_items[0].m_productExposure.m_hasCves);
  db_WATCHLISTEDITItemsResultFree(&result);

  WATCHLISTEDITItemsDbParams_t search;
  static_itemEditParams(&search, &budget, WATCHLISTEDIT_ACTION_ADD, WATCHLIST_ITEM_CVE_SEARCH);
  static const char* const search_row[WATCHLISTEDIT_CVE_SEARCH_ROW_COLUMN_COUNT] = { "ok", "cve_search", "oracle", "mysql", "CRITICAL", "CWE-79", "9.1", "0.5", "f", "t", NULL, "9", "1" };
  static_resetFake();
  answer = static_queueNamedAnswer(g_watchlistEditCveSearchColumnNames, WATCHLISTEDIT_CVE_SEARCH_ROW_COLUMN_COUNT, 1);
  static_setRow(answer, 0, search_row, WATCHLISTEDIT_CVE_SEARCH_ROW_COLUMN_COUNT);
  memset(&result, 0xA5, sizeof(result));
  TEST_ASSERT_EQUAL_INT(DB_OK, db_WATCHLISTEDITItems(FAKE_CONN, &search, NULL, &result));
  TEST_ASSERT_EQUAL_INT(1, result.m_itemCount);
  TEST_ASSERT_EQUAL_INT(9, result.m_itemCountForCurrentApiKey);
  TEST_ASSERT_EQUAL_INT(1, result.m_packageItemCountForCurrentApiKey);
  const WATCHLISTCVESEARCHItem_t* read_filter = &result.mp_items[0].m_cveSearch;
  TEST_ASSERT_EQUAL_INT(WATCHLIST_ITEM_CVE_SEARCH, result.mp_items[0].m_itemKind);
  TEST_ASSERT_EQUAL_STRING("oracle", read_filter->ma_vendor);
  TEST_ASSERT_EQUAL_STRING("mysql", read_filter->ma_product);
  TEST_ASSERT_EQUAL_STRING("CRITICAL", read_filter->ma_severity);
  TEST_ASSERT_EQUAL_STRING("CWE-79", read_filter->ma_cweId);
  TEST_ASSERT_EQUAL_FLOAT(9.1, read_filter->m_minCvss);
  TEST_ASSERT_EQUAL_FLOAT(0.5, read_filter->m_minEpss);
  TEST_ASSERT_EQUAL_INT(CVE_KEV_FILTER_NOT_IN_KEV, read_filter->m_kevFilter);
  TEST_ASSERT_TRUE(read_filter->m_knownRansomware);
  TEST_ASSERT_FALSE(read_filter->m_hasNucleiTemplate);
  db_WATCHLISTEDITItemsResultFree(&result);

  static const char* const unset_search_row[WATCHLISTEDIT_CVE_SEARCH_ROW_COLUMN_COUNT] = { "ok", "cve_search", NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, "t", "9", "1" };
  static_resetFake();
  answer = static_queueNamedAnswer(g_watchlistEditCveSearchColumnNames, WATCHLISTEDIT_CVE_SEARCH_ROW_COLUMN_COUNT, 1);
  static_setRow(answer, 0, unset_search_row, WATCHLISTEDIT_CVE_SEARCH_ROW_COLUMN_COUNT);
  memset(&result, 0xA5, sizeof(result));
  TEST_ASSERT_EQUAL_INT(DB_OK, db_WATCHLISTEDITItems(FAKE_CONN, &search, NULL, &result));
  read_filter = &result.mp_items[0].m_cveSearch;
  TEST_ASSERT_EQUAL_STRING("", read_filter->ma_vendor);
  TEST_ASSERT_EQUAL_STRING("", read_filter->ma_severity);
  TEST_ASSERT_EQUAL_FLOAT(-1.0, read_filter->m_minCvss);
  TEST_ASSERT_EQUAL_FLOAT(-1.0, read_filter->m_minEpss);
  TEST_ASSERT_EQUAL_INT(CVE_KEV_FILTER_ANY, read_filter->m_kevFilter);
  TEST_ASSERT_FALSE(read_filter->m_knownRansomware);
  TEST_ASSERT_TRUE(read_filter->m_hasNucleiTemplate);
  db_WATCHLISTEDITItemsResultFree(&result);

  WATCHLISTEDITItemsDbParams_t domain;
  static_itemEditParams(&domain, &budget, WATCHLISTEDIT_ACTION_ADD, WATCHLIST_ITEM_SSL_CHECK);
  static const char* const domain_row[WATCHLISTEDIT_DOMAIN_ROW_COLUMN_COUNT] = { "ok", "ssl_check", "b.example.org", "10", "2" };
  static_resetFake();
  answer = static_queueNamedAnswer(g_watchlistEditDomainColumnNames, WATCHLISTEDIT_DOMAIN_ROW_COLUMN_COUNT, 1);
  static_setRow(answer, 0, domain_row, WATCHLISTEDIT_DOMAIN_ROW_COLUMN_COUNT);
  memset(&result, 0xA5, sizeof(result));
  TEST_ASSERT_EQUAL_INT(DB_OK, db_WATCHLISTEDITItems(FAKE_CONN, &domain, "example.org", &result));
  TEST_ASSERT_EQUAL_INT(1, result.m_itemCount);
  TEST_ASSERT_EQUAL_INT(10, result.m_itemCountForCurrentApiKey);
  TEST_ASSERT_EQUAL_INT(2, result.m_packageItemCountForCurrentApiKey);
  TEST_ASSERT_EQUAL_INT(WATCHLIST_ITEM_SSL_CHECK, result.mp_items[0].m_itemKind);
  TEST_ASSERT_EQUAL_STRING("b.example.org", result.mp_items[0].m_sslCheck.ma_domainName);
  db_WATCHLISTEDITItemsResultFree(&result);

  WATCHLISTEDITItemsDbParams_t package;
  static_itemEditParams(&package, &budget, WATCHLISTEDIT_ACTION_ADD, WATCHLIST_ITEM_PACKAGE_CHECK);
  static const char* const package_row[WATCHLISTEDIT_PACKAGE_ROW_COLUMN_COUNT] = { "ok", "package_check", "Go", "github.com/gin-gonic/gin", NULL, "0", "4" };
  static_resetFake();
  answer = static_queueNamedAnswer(g_watchlistEditPackageColumnNames, WATCHLISTEDIT_PACKAGE_ROW_COLUMN_COUNT, 1);
  static_setRow(answer, 0, package_row, WATCHLISTEDIT_PACKAGE_ROW_COLUMN_COUNT);
  memset(&result, 0xA5, sizeof(result));
  TEST_ASSERT_EQUAL_INT(DB_OK, db_WATCHLISTEDITItems(FAKE_CONN, &package, NULL, &result));
  TEST_ASSERT_EQUAL_INT(1, result.m_itemCount);
  TEST_ASSERT_EQUAL_INT(0, result.m_itemCountForCurrentApiKey);
  TEST_ASSERT_EQUAL_INT(4, result.m_packageItemCountForCurrentApiKey);
  TEST_ASSERT_EQUAL_INT(WATCHLIST_ITEM_PACKAGE_CHECK, result.mp_items[0].m_itemKind);
  TEST_ASSERT_EQUAL_STRING("Go", result.mp_items[0].m_packageCheck.ma_ecosystem);
  TEST_ASSERT_EQUAL_STRING("github.com/gin-gonic/gin", result.mp_items[0].m_packageCheck.ma_name);
  TEST_ASSERT_EQUAL_STRING("", result.mp_items[0].m_packageCheck.ma_version);
  db_WATCHLISTEDITItemsResultFree(&result);

  static const char* const versioned_package_row[WATCHLISTEDIT_PACKAGE_ROW_COLUMN_COUNT] = { "ok", "package_check", "npm", "lodash", "4.17.20", "3", "6" };
  static_resetFake();
  answer = static_queueNamedAnswer(g_watchlistEditPackageColumnNames, WATCHLISTEDIT_PACKAGE_ROW_COLUMN_COUNT, 1);
  static_setRow(answer, 0, versioned_package_row, WATCHLISTEDIT_PACKAGE_ROW_COLUMN_COUNT);
  memset(&result, 0xA5, sizeof(result));
  TEST_ASSERT_EQUAL_INT(DB_OK, db_WATCHLISTEDITItems(FAKE_CONN, &package, NULL, &result));
  TEST_ASSERT_EQUAL_INT(3, result.m_itemCountForCurrentApiKey);
  TEST_ASSERT_EQUAL_INT(6, result.m_packageItemCountForCurrentApiKey);
  TEST_ASSERT_EQUAL_STRING("npm", result.mp_items[0].m_packageCheck.ma_ecosystem);
  TEST_ASSERT_EQUAL_STRING("lodash", result.mp_items[0].m_packageCheck.ma_name);
  TEST_ASSERT_EQUAL_STRING("4.17.20", result.mp_items[0].m_packageCheck.ma_version);
  db_WATCHLISTEDITItemsResultFree(&result);

  WATCHLISTEDITItemsDbParams_t ip;
  static_itemEditParams(&ip, &budget, WATCHLISTEDIT_ACTION_ADD, WATCHLIST_ITEM_IP_LOOKUP);
  static const char* const ip_row[WATCHLISTEDIT_IP_ROW_COLUMN_COUNT] = { "ok", "ip_lookup", "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255", "11", "2" };
  static_resetFake();
  answer = static_queueNamedAnswer(g_watchlistEditIpColumnNames, WATCHLISTEDIT_IP_ROW_COLUMN_COUNT, 1);
  static_setRow(answer, 0, ip_row, WATCHLISTEDIT_IP_ROW_COLUMN_COUNT);
  memset(&result, 0xA5, sizeof(result));
  TEST_ASSERT_EQUAL_INT(DB_OK, db_WATCHLISTEDITItems(FAKE_CONN, &ip, NULL, &result));
  TEST_ASSERT_EQUAL_INT(1, result.m_itemCount);
  TEST_ASSERT_EQUAL_INT(11, result.m_itemCountForCurrentApiKey);
  TEST_ASSERT_EQUAL_INT(2, result.m_packageItemCountForCurrentApiKey);
  TEST_ASSERT_EQUAL_INT(WATCHLIST_ITEM_IP_LOOKUP, result.mp_items[0].m_itemKind);
  TEST_ASSERT_EQUAL_STRING("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255", result.mp_items[0].m_ipLookup.ma_ipAddress);
  db_WATCHLISTEDITItemsResultFree(&result);

  WATCHLISTEDITItemsDbParams_t cve_add;
  static_itemEditParams(&cve_add, &budget, WATCHLISTEDIT_ACTION_ADD, WATCHLIST_ITEM_CVE_LOOKUP);
  const struct { const WATCHLISTEDITItemsDbParams_t* mp_params; const char* mp_status; WATCHLISTEDITStatus_t m_status; int m_itemCountForCurrentApiKey; int m_packageItemCountForCurrentApiKey; } no_item[] = {
    { &cve_add,  "over_limit",          WATCHLISTEDIT_OVER_LIMIT,          100, 0 },
    { &package,  "over_package_weight", WATCHLISTEDIT_OVER_PACKAGE_WEIGHT, 0,   2 },
    { &package,  "over_package_limit",  WATCHLISTEDIT_OVER_PACKAGE_LIMIT,  6,   500 },
    { &domain,   "over_domain_limit",   WATCHLISTEDIT_OVER_DOMAIN_LIMIT,   21,  0 },
    { &ip,       "over_limit",          WATCHLISTEDIT_OVER_LIMIT,          100, 1 },
    { &domain,   "unknown_key",         WATCHLISTEDIT_UNKNOWN_KEY,         0,   0 },
    { &cve_add,  "unknown_key",         WATCHLISTEDIT_UNKNOWN_KEY,         0,   0 },
    { &exposure, "unknown_key",         WATCHLISTEDIT_UNKNOWN_KEY,         0,   0 },
    { &search,   "unknown_key",         WATCHLISTEDIT_UNKNOWN_KEY,         0,   0 },
    { &package,  "unknown_key",         WATCHLISTEDIT_UNKNOWN_KEY,         0,   0 },
    { &ip,       "unknown_key",         WATCHLISTEDIT_UNKNOWN_KEY,         0,   0 },
  };
  for (size_t i = 0; i < sizeof(no_item) / sizeof(no_item[0]); i++)
  {
    char item_count[16];
    char package_item_count[16];
    snprintf(item_count, sizeof(item_count), "%d", no_item[i].m_itemCountForCurrentApiKey);
    snprintf(package_item_count, sizeof(package_item_count), "%d", no_item[i].m_packageItemCountForCurrentApiKey);
    static_resetFake();
    answer = static_queueEditAnswer(static_editShape(no_item[i].mp_params->m_item.m_itemKind), no_item[i].mp_status, item_count, package_item_count);
    if (no_item[i].m_status == WATCHLISTEDIT_UNKNOWN_KEY)
      static_setEditCounts(answer, static_editShape(no_item[i].mp_params->m_item.m_itemKind).m_columnCount, "77", "77");
    memset(&result, 0xA5, sizeof(result));
    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_OK, db_WATCHLISTEDITItems(FAKE_CONN, no_item[i].mp_params, "example.org", &result), no_item[i].mp_status);
    TEST_ASSERT_EQUAL_INT_MESSAGE(no_item[i].m_status, result.m_status, no_item[i].mp_status);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, result.m_itemCount, no_item[i].mp_status);
    TEST_ASSERT_NULL_MESSAGE(result.mp_items, no_item[i].mp_status);
    TEST_ASSERT_EQUAL_INT_MESSAGE(no_item[i].m_itemCountForCurrentApiKey, result.m_itemCountForCurrentApiKey, no_item[i].mp_status);
    TEST_ASSERT_EQUAL_INT_MESSAGE(no_item[i].m_packageItemCountForCurrentApiKey, result.m_packageItemCountForCurrentApiKey, no_item[i].mp_status);
  }

  static const char* const two_rows[WATCHLISTEDIT_CVE_ID_ROW_COLUMN_COUNT]       = { "ok", "kev_lookup", "CVE-2022-0001", "7", "3" };
  static const char* const other_endpoint[WATCHLISTEDIT_CVE_ID_ROW_COLUMN_COUNT] = { "ok", "cve_lookup", "CVE-2022-0001", "7", "3" };
  static const char* const null_cve_id[WATCHLISTEDIT_CVE_ID_ROW_COLUMN_COUNT]    = { "ok", "kev_lookup", NULL, "7", "3" };
  static const char* const null_count[WATCHLISTEDIT_CVE_ID_ROW_COLUMN_COUNT]     = { "ok", "kev_lookup", "CVE-2022-0001", "7", NULL };
  static const char* const null_has_cves[WATCHLISTEDIT_PRODUCT_EXPOSURE_ROW_COLUMN_COUNT] = { "ok", "product_exposure", "cisco", "ios", NULL, NULL, "8", "0" };
  static const char* const null_vendor[WATCHLISTEDIT_PRODUCT_EXPOSURE_ROW_COLUMN_COUNT]   = { "ok", "product_exposure", NULL, "ios", "t", NULL, "8", "0" };
  static const char* const bad_kev[WATCHLISTEDIT_CVE_SEARCH_ROW_COLUMN_COUNT]       = { "ok", "cve_search", "oracle", NULL, NULL, NULL, NULL, NULL, "yes", NULL, NULL, "9", "1" };
  static const char* const null_domain[WATCHLISTEDIT_DOMAIN_ROW_COLUMN_COUNT]       = { "ok", "ssl_check", NULL, "10", "2" };
  static const char* const other_domain[WATCHLISTEDIT_DOMAIN_ROW_COLUMN_COUNT]      = { "ok", "dns_lookup", "b.example.org", "10", "2" };
  static const char* const null_ecosystem[WATCHLISTEDIT_PACKAGE_ROW_COLUMN_COUNT]   = { "ok", "package_check", NULL, "gin", NULL, "0", "4" };
  static const char* const null_name[WATCHLISTEDIT_PACKAGE_ROW_COLUMN_COUNT]        = { "ok", "package_check", "Go", NULL, NULL, "0", "4" };
  static const char* const null_ip_address[WATCHLISTEDIT_IP_ROW_COLUMN_COUNT]      = { "ok", "ip_lookup", NULL, "11", "2" };
  static const char* const other_ip_endpoint[WATCHLISTEDIT_IP_ROW_COLUMN_COUNT]    = { "ok", "dns_lookup", "2606:4700::1111", "11", "2" };
  static const char* const long_ip_address[WATCHLISTEDIT_IP_ROW_COLUMN_COUNT]      = { "ok", "ip_lookup", "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.2550", "11", "2" };
  static char pe_long_version[PACKAGECHECK_VERSION_MAX_LEN + 2];
  memset(pe_long_version, '1', sizeof(pe_long_version) - 1);
  pe_long_version[sizeof(pe_long_version) - 1] = '\0';
  const char* const long_pe_version[WATCHLISTEDIT_PRODUCT_EXPOSURE_ROW_COLUMN_COUNT] = { "ok", "product_exposure", "cisco", "ios", "t", pe_long_version, "8", "0" };
  const struct {
    const char*                  mp_label;
    const WATCHLISTEDITItemsDbParams_t* mp_params;
    const char* const*           mp_columnNames;
    int                          m_columnCount;
    int                          m_rowCount;
    const char* const*           mp_row;
  } refused[] = {
    { "two rows",             &kev,      g_watchlistEditCveIdColumnNames,           WATCHLISTEDIT_CVE_ID_ROW_COLUMN_COUNT,           2, two_rows },
    { "other endpoint",       &kev,      g_watchlistEditCveIdColumnNames,           WATCHLISTEDIT_CVE_ID_ROW_COLUMN_COUNT,           1, other_endpoint },
    { "null cve_id",          &kev,      g_watchlistEditCveIdColumnNames,           WATCHLISTEDIT_CVE_ID_ROW_COLUMN_COUNT,           1, null_cve_id },
    { "null count",           &kev,      g_watchlistEditCveIdColumnNames,           WATCHLISTEDIT_CVE_ID_ROW_COLUMN_COUNT,           1, null_count },
    { "domain columns",       &kev,      g_watchlistEditDomainColumnNames,          WATCHLISTEDIT_DOMAIN_ROW_COLUMN_COUNT,           1, two_rows },
    { "null product_has_cves", &exposure, g_watchlistEditProductExposureColumnNames, WATCHLISTEDIT_PRODUCT_EXPOSURE_ROW_COLUMN_COUNT, 1, null_has_cves },
    { "null vendor",          &exposure, g_watchlistEditProductExposureColumnNames, WATCHLISTEDIT_PRODUCT_EXPOSURE_ROW_COLUMN_COUNT, 1, null_vendor },
    { "long pe version",      &exposure, g_watchlistEditProductExposureColumnNames, WATCHLISTEDIT_PRODUCT_EXPOSURE_ROW_COLUMN_COUNT, 1, long_pe_version },
    { "unreadable in_kev",    &search,   g_watchlistEditCveSearchColumnNames,       WATCHLISTEDIT_CVE_SEARCH_ROW_COLUMN_COUNT,       1, bad_kev },
    { "null domain_name",     &domain,   g_watchlistEditDomainColumnNames,          WATCHLISTEDIT_DOMAIN_ROW_COLUMN_COUNT,           1, null_domain },
    { "other domain endpoint", &domain,  g_watchlistEditDomainColumnNames,          WATCHLISTEDIT_DOMAIN_ROW_COLUMN_COUNT,           1, other_domain },
    { "wide columns",         &domain,   g_watchlistEditColumnNames,                WATCHLISTEDIT_ROW_COLUMN_COUNT,                  1, NULL },
    { "null ecosystem",       &package,  g_watchlistEditPackageColumnNames,         WATCHLISTEDIT_PACKAGE_ROW_COLUMN_COUNT,          1, null_ecosystem },
    { "null package_name",    &package,  g_watchlistEditPackageColumnNames,         WATCHLISTEDIT_PACKAGE_ROW_COLUMN_COUNT,          1, null_name },
    { "null ip_address",      &ip,       g_watchlistEditIpColumnNames,              WATCHLISTEDIT_IP_ROW_COLUMN_COUNT,               1, null_ip_address },
    { "other ip endpoint",    &ip,       g_watchlistEditIpColumnNames,              WATCHLISTEDIT_IP_ROW_COLUMN_COUNT,               1, other_ip_endpoint },
    { "long ip_address",      &ip,       g_watchlistEditIpColumnNames,              WATCHLISTEDIT_IP_ROW_COLUMN_COUNT,               1, long_ip_address },
    { "ip with domain columns", &ip,     g_watchlistEditDomainColumnNames,          WATCHLISTEDIT_DOMAIN_ROW_COLUMN_COUNT,           1, other_ip_endpoint },
  };
  for (size_t i = 0; i < sizeof(refused) / sizeof(refused[0]); i++)
  {
    static_resetFake();
    answer = static_queueNamedAnswer(refused[i].mp_columnNames, refused[i].m_columnCount, refused[i].m_rowCount);
    for (int row = 0; row < refused[i].m_rowCount && refused[i].mp_row != NULL; row++)
      static_setRow(answer, row, refused[i].mp_row, refused[i].m_columnCount);
    answer->ma_cells[0][0] = "ok";
    memset(&result, 0xA5, sizeof(result));
    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_ERROR, db_WATCHLISTEDITItems(FAKE_CONN, refused[i].mp_params, "example.org", &result), refused[i].mp_label);
    TEST_ASSERT_NULL_MESSAGE(result.mp_items, refused[i].mp_label);
  }
}

void test_WATCHLISTEDIT_reads_the_wide_answer_of_a_list_and_a_clear(void)
{
  RequestCreditBudget_t budget;
  static_watchlistBudget(&budget);
  WATCHLISTEDITItemsDbParams_t clear;
  static_unsetEditParams(&clear, &budget);
  clear.m_action = WATCHLISTEDIT_ACTION_CLEAR;
  WATCHLISTEDITItemsDbParams_t list;
  static_unsetEditParams(&list, &budget);
  static const char* const hash_only[] = { WATCHLIST_TEST_KEY_HASH };
  const WatchlistEditShape_t wide = { NULL, g_watchlistEditColumnNames, WATCHLISTEDIT_ROW_COLUMN_COUNT };
  WATCHLISTEDITItemsResult_t result;

  static_resetFake();
  static_queueEditAnswer(wide, "ok", "0", "0");
  memset(&result, 0xA5, sizeof(result));
  TEST_ASSERT_EQUAL_INT(DB_OK, db_WATCHLISTEDITItems(FAKE_CONN, &clear, NULL, &result));
  static_assertCall(0, WATCHLISTEDIT_CLEAR_CALL, hash_only, 1);
  TEST_ASSERT_EQUAL_INT(WATCHLISTEDIT_OK, result.m_status);
  TEST_ASSERT_EQUAL_INT(0, result.m_itemCount);
  TEST_ASSERT_NULL(result.mp_items);
  TEST_ASSERT_EQUAL_INT(0, result.m_itemCountForCurrentApiKey);
  TEST_ASSERT_EQUAL_INT(0, result.m_packageItemCountForCurrentApiKey);

  static_resetFake();
  static_queueEditAnswer(wide, "unknown_key", "6", "6");
  memset(&result, 0xA5, sizeof(result));
  TEST_ASSERT_EQUAL_INT(DB_OK, db_WATCHLISTEDITItems(FAKE_CONN, &clear, NULL, &result));
  TEST_ASSERT_EQUAL_INT(WATCHLISTEDIT_UNKNOWN_KEY, result.m_status);
  TEST_ASSERT_NULL(result.mp_items);
  TEST_ASSERT_EQUAL_INT(0, result.m_itemCountForCurrentApiKey);
  TEST_ASSERT_EQUAL_INT(0, result.m_packageItemCountForCurrentApiKey);

  static_resetFake();
  static_queueEditAnswer(wide, "ok", "4", "5");
  memset(&result, 0xA5, sizeof(result));
  TEST_ASSERT_EQUAL_INT(DB_OK, db_WATCHLISTEDITItems(FAKE_CONN, &list, NULL, &result));
  static_assertCall(0, WATCHLISTEDIT_LIST_CALL, hash_only, 1);
  TEST_ASSERT_EQUAL_INT(0, result.m_itemCount);
  TEST_ASSERT_EQUAL_INT(4, result.m_itemCountForCurrentApiKey);
  TEST_ASSERT_EQUAL_INT(5, result.m_packageItemCountForCurrentApiKey);

  static_resetFake();
  static_queueEditAnswer(static_editShape(WATCHLIST_ITEM_DNS_LOOKUP), "ok", "0", "0");
  memset(&result, 0xA5, sizeof(result));
  TEST_ASSERT_EQUAL_INT(DB_ERROR, db_WATCHLISTEDITItems(FAKE_CONN, &clear, NULL, &result));
  TEST_ASSERT_NULL(result.mp_items);
}

void test_WATCHLISTEDIT_reads_each_cve_id_kind(void)
{
  RequestCreditBudget_t budget;
  static_watchlistBudget(&budget);
  WATCHLISTEDITItemsDbParams_t params;
  static_unsetEditParams(&params, &budget);

  static const char* const row_kev[WATCHLISTEDIT_ROW_COLUMN_COUNT]     = { "ok", "kev_lookup",  "CVE-2022-0001", "dv", NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, "decoy.example", NULL, NULL, NULL, NULL, "2", "0" };
  static const char* const row_exploit[WATCHLISTEDIT_ROW_COLUMN_COUNT] = { "ok", "cve_exploit", "CVE-2023-0002", "dv", NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, "decoy.example", NULL, NULL, NULL, NULL, "2", "0" };
  static_resetFake();
  FakeAnswer_t* answer = static_queueNamedAnswer(g_watchlistEditColumnNames, WATCHLISTEDIT_ROW_COLUMN_COUNT, 2);
  static_setRow(answer, 0, row_kev,     WATCHLISTEDIT_ROW_COLUMN_COUNT);
  static_setRow(answer, 1, row_exploit, WATCHLISTEDIT_ROW_COLUMN_COUNT);
  WATCHLISTEDITItemsResult_t result;
  TEST_ASSERT_EQUAL_INT(DB_OK, db_WATCHLISTEDITItems(FAKE_CONN, &params, NULL, &result));
  TEST_ASSERT_EQUAL_INT(2, result.m_itemCount);
  TEST_ASSERT_EQUAL_INT(WATCHLIST_ITEM_KEV_LOOKUP, result.mp_items[0].m_itemKind);
  TEST_ASSERT_EQUAL_STRING("CVE-2022-0001", result.mp_items[0].m_kevLookup.ma_cveId);
  TEST_ASSERT_EQUAL_INT(WATCHLIST_ITEM_CVE_EXPLOIT, result.mp_items[1].m_itemKind);
  TEST_ASSERT_EQUAL_STRING("CVE-2023-0002", result.mp_items[1].m_cveExploit.ma_cveId);
  db_WATCHLISTEDITItemsResultFree(&result);
}

void test_WATCHLISTEDIT_reads_each_item_column(void)
{
  RequestCreditBudget_t budget;
  static_watchlistBudget(&budget);
  WATCHLISTEDITItemsDbParams_t params;
  static_unsetEditParams(&params, &budget);

  static const char* const row_cve[WATCHLISTEDIT_ROW_COLUMN_COUNT]     = { "ok", "cve_lookup",       "CVE-2021-44228", NULL,     NULL,    NULL,   NULL,     NULL,  NULL,   NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, "3", "0" };
  static const char* const row_exposed[WATCHLISTEDIT_ROW_COLUMN_COUNT] = { "ok", "product_exposure", NULL,             "apache", "log4j", NULL,   NULL,     NULL,  NULL,   NULL, NULL, NULL, "t", NULL, NULL, NULL, "2.14.1", NULL, "3", "0" };
  static const char* const row_search[WATCHLISTEDIT_ROW_COLUMN_COUNT]  = { "ok", "cve_search",       NULL,             "cisco",  "ios",   "HIGH", "CWE-79", "7.5", "0.25", "f",  "t",  NULL,  NULL, NULL, NULL, NULL, NULL, NULL, "3", "0" };
  static const char* const row_product[WATCHLISTEDIT_ROW_COLUMN_COUNT] = { "ok", "product_exposure", NULL,             "x",      "y",     NULL,   NULL,     NULL,  NULL,   "t",  NULL, NULL, "f", NULL, NULL, NULL, NULL, NULL, "3", "0" };
  static const char* const row_no_filter[WATCHLISTEDIT_ROW_COLUMN_COUNT] = { "ok", "cve_search",     NULL,             NULL,     NULL,    NULL,   NULL,     NULL,  NULL,   NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, "3", "0" };
  static const char* const row_domain[WATCHLISTEDIT_ROW_COLUMN_COUNT]    = { "ok", "dns_lookup", "CVE-2021-44228", "apache", NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, "example.co.uk", NULL, NULL, NULL, NULL, "3", "0" };
  static const char* const row_subdomain[WATCHLISTEDIT_ROW_COLUMN_COUNT] = { "ok", "dns_lookup", NULL,             NULL,     NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, "shop.example.com", NULL, NULL, NULL, NULL, "3", "0" };
  static const char* const row_nuclei[WATCHLISTEDIT_ROW_COLUMN_COUNT]    = { "ok", "cve_search", NULL,             NULL,     NULL, NULL, NULL, NULL, NULL, NULL, NULL, "t",  NULL, NULL, NULL, NULL, NULL, NULL, "3", "0" };

  static const char* const row_package[WATCHLISTEDIT_ROW_COLUMN_COUNT]    = { "ok", "package_check", NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, "npm", "@babel/core", "7.24.0", NULL, "3", "0" };
  static const char* const row_no_version[WATCHLISTEDIT_ROW_COLUMN_COUNT] = { "ok", "package_check", NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, "PyPI", "Django_X", NULL, NULL, "3", "0" };
  static const char* const row_ip[WATCHLISTEDIT_ROW_COLUMN_COUNT]         = { "ok", "ip_lookup", "CVE-2021-44228", NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, "decoy.example", "npm", NULL, NULL, "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255", "3", "0" };

  static_resetFake();
  FakeAnswer_t* answer = static_queueNamedAnswer(g_watchlistEditColumnNames, WATCHLISTEDIT_ROW_COLUMN_COUNT, 11);
  static_setRow(answer, 0, row_cve,       WATCHLISTEDIT_ROW_COLUMN_COUNT);
  static_setRow(answer, 1, row_exposed,   WATCHLISTEDIT_ROW_COLUMN_COUNT);
  static_setRow(answer, 2, row_search,    WATCHLISTEDIT_ROW_COLUMN_COUNT);
  static_setRow(answer, 3, row_product,   WATCHLISTEDIT_ROW_COLUMN_COUNT);
  static_setRow(answer, 4, row_no_filter, WATCHLISTEDIT_ROW_COLUMN_COUNT);
  static_setRow(answer, 5, row_domain,    WATCHLISTEDIT_ROW_COLUMN_COUNT);
  static_setRow(answer, 6, row_subdomain, WATCHLISTEDIT_ROW_COLUMN_COUNT);
  static_setRow(answer, 7, row_nuclei,    WATCHLISTEDIT_ROW_COLUMN_COUNT);
  static_setRow(answer, 8, row_package,    WATCHLISTEDIT_ROW_COLUMN_COUNT);
  static_setRow(answer, 9, row_no_version, WATCHLISTEDIT_ROW_COLUMN_COUNT);
  static_setRow(answer, 10, row_ip,        WATCHLISTEDIT_ROW_COLUMN_COUNT);
  static_setEditCounts(answer, WATCHLISTEDIT_ROW_COLUMN_COUNT, "97", "998");
  WATCHLISTEDITItemsResult_t result;
  memset(&result, 0xA5, sizeof(result));
  g_dirtyMalloc = true;
  TEST_ASSERT_EQUAL_INT(DB_OK, db_WATCHLISTEDITItems(FAKE_CONN, &params, NULL, &result));
  g_dirtyMalloc = false;
  TEST_ASSERT_EQUAL_INT(WATCHLISTEDIT_OK, result.m_status);
  TEST_ASSERT_EQUAL_INT(11, result.m_itemCount);
  TEST_ASSERT_EQUAL_INT(97, result.m_itemCountForCurrentApiKey);
  TEST_ASSERT_EQUAL_INT(998, result.m_packageItemCountForCurrentApiKey);
  TEST_ASSERT_NOT_NULL(result.mp_items);
  const WatchlistItem_t* cve = &result.mp_items[0];
  TEST_ASSERT_EQUAL_STRING("cve_lookup", watchlist_findEndpointName(cve->m_itemKind));
  TEST_ASSERT_EQUAL_INT(WATCHLIST_ITEM_CVE_LOOKUP, cve->m_itemKind);
  TEST_ASSERT_EQUAL_STRING("CVE-2021-44228", cve->m_cveLookup.ma_cveId);
  const WatchlistItem_t* exposed = &result.mp_items[1];
  TEST_ASSERT_EQUAL_STRING("product_exposure", watchlist_findEndpointName(exposed->m_itemKind));
  TEST_ASSERT_EQUAL_INT(WATCHLIST_ITEM_PRODUCT_EXPOSURE, exposed->m_itemKind);
  TEST_ASSERT_EQUAL_STRING("apache", exposed->m_productExposure.ma_vendor);
  TEST_ASSERT_EQUAL_STRING("log4j", exposed->m_productExposure.ma_product);
  TEST_ASSERT_EQUAL_STRING("2.14.1", exposed->m_productExposure.ma_version);
  TEST_ASSERT_TRUE(exposed->m_productExposure.m_hasCves);
  const WatchlistItem_t* search = &result.mp_items[2];
  TEST_ASSERT_EQUAL_STRING("cve_search", watchlist_findEndpointName(search->m_itemKind));
  TEST_ASSERT_EQUAL_INT(WATCHLIST_ITEM_CVE_SEARCH, search->m_itemKind);
  TEST_ASSERT_EQUAL_STRING("cisco", search->m_cveSearch.ma_vendor);
  TEST_ASSERT_EQUAL_STRING("ios", search->m_cveSearch.ma_product);
  TEST_ASSERT_EQUAL_STRING("HIGH", search->m_cveSearch.ma_severity);
  TEST_ASSERT_EQUAL_STRING("CWE-79", search->m_cveSearch.ma_cweId);
  TEST_ASSERT_EQUAL_FLOAT(7.5, search->m_cveSearch.m_minCvss);
  TEST_ASSERT_EQUAL_FLOAT(0.25, search->m_cveSearch.m_minEpss);
  TEST_ASSERT_EQUAL_INT(CVE_KEV_FILTER_NOT_IN_KEV, search->m_cveSearch.m_kevFilter);
  TEST_ASSERT_TRUE(search->m_cveSearch.m_knownRansomware);
  TEST_ASSERT_FALSE(search->m_cveSearch.m_hasNucleiTemplate);
  const WatchlistItem_t* product = &result.mp_items[3];
  TEST_ASSERT_EQUAL_STRING("product_exposure", watchlist_findEndpointName(product->m_itemKind));
  TEST_ASSERT_EQUAL_INT(WATCHLIST_ITEM_PRODUCT_EXPOSURE, product->m_itemKind);
  TEST_ASSERT_EQUAL_STRING("x", product->m_productExposure.ma_vendor);
  TEST_ASSERT_EQUAL_STRING("y", product->m_productExposure.ma_product);
  TEST_ASSERT_EQUAL_STRING("", product->m_productExposure.ma_version);
  TEST_ASSERT_FALSE(product->m_productExposure.m_hasCves);
  const WatchlistItem_t* no_filter = &result.mp_items[4];
  TEST_ASSERT_EQUAL_INT(WATCHLIST_ITEM_CVE_SEARCH, no_filter->m_itemKind);
  TEST_ASSERT_EQUAL_STRING("", no_filter->m_cveSearch.ma_vendor);
  TEST_ASSERT_EQUAL_STRING("", no_filter->m_cveSearch.ma_product);
  TEST_ASSERT_EQUAL_STRING("", no_filter->m_cveSearch.ma_severity);
  TEST_ASSERT_EQUAL_STRING("", no_filter->m_cveSearch.ma_cweId);
  TEST_ASSERT_TRUE(no_filter->m_cveSearch.m_minCvss < 0.0);
  TEST_ASSERT_TRUE(no_filter->m_cveSearch.m_minEpss < 0.0);
  TEST_ASSERT_EQUAL_INT(CVE_KEV_FILTER_ANY, no_filter->m_cveSearch.m_kevFilter);
  TEST_ASSERT_FALSE(no_filter->m_cveSearch.m_knownRansomware);
  TEST_ASSERT_FALSE(no_filter->m_cveSearch.m_hasNucleiTemplate);
  const WatchlistItem_t* domain = &result.mp_items[5];
  TEST_ASSERT_EQUAL_STRING("dns_lookup", watchlist_findEndpointName(domain->m_itemKind));
  TEST_ASSERT_EQUAL_INT(WATCHLIST_ITEM_DNS_LOOKUP, domain->m_itemKind);
  TEST_ASSERT_EQUAL_STRING("example.co.uk", domain->m_dnsLookup.ma_domainName);
  const WatchlistItem_t* subdomain = &result.mp_items[6];
  TEST_ASSERT_EQUAL_STRING("dns_lookup", watchlist_findEndpointName(subdomain->m_itemKind));
  TEST_ASSERT_EQUAL_INT(WATCHLIST_ITEM_DNS_LOOKUP, subdomain->m_itemKind);
  TEST_ASSERT_EQUAL_STRING("shop.example.com", subdomain->m_dnsLookup.ma_domainName);
  const WatchlistItem_t* nuclei = &result.mp_items[7];
  TEST_ASSERT_EQUAL_INT(WATCHLIST_ITEM_CVE_SEARCH, nuclei->m_itemKind);
  TEST_ASSERT_TRUE(nuclei->m_cveSearch.m_hasNucleiTemplate);
  TEST_ASSERT_FALSE(nuclei->m_cveSearch.m_knownRansomware);
  const WatchlistItem_t* package = &result.mp_items[8];
  TEST_ASSERT_EQUAL_STRING("package_check", watchlist_findEndpointName(package->m_itemKind));
  TEST_ASSERT_EQUAL_INT(WATCHLIST_ITEM_PACKAGE_CHECK, package->m_itemKind);
  TEST_ASSERT_EQUAL_STRING("npm", package->m_packageCheck.ma_ecosystem);
  TEST_ASSERT_EQUAL_STRING("@babel/core", package->m_packageCheck.ma_name);
  TEST_ASSERT_EQUAL_STRING("7.24.0", package->m_packageCheck.ma_version);
  const WatchlistItem_t* no_version = &result.mp_items[9];
  TEST_ASSERT_EQUAL_INT(WATCHLIST_ITEM_PACKAGE_CHECK, no_version->m_itemKind);
  TEST_ASSERT_EQUAL_STRING("PyPI", no_version->m_packageCheck.ma_ecosystem);
  TEST_ASSERT_EQUAL_STRING("Django_X", no_version->m_packageCheck.ma_name);
  TEST_ASSERT_EQUAL_STRING("", no_version->m_packageCheck.ma_version);
  const WatchlistItem_t* ip = &result.mp_items[10];
  TEST_ASSERT_EQUAL_STRING("ip_lookup", watchlist_findEndpointName(ip->m_itemKind));
  TEST_ASSERT_EQUAL_INT(WATCHLIST_ITEM_IP_LOOKUP, ip->m_itemKind);
  TEST_ASSERT_EQUAL_STRING("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255", ip->m_ipLookup.ma_ipAddress);
  db_WATCHLISTEDITItemsResultFree(&result);
  TEST_ASSERT_NULL(result.mp_items);
  db_WATCHLISTEDITItemsResultFree(&result);
  db_WATCHLISTEDITItemsResultFree(NULL);

  static const struct { const char* mp_status; WATCHLISTEDITStatus_t m_status; int m_itemCount; int m_itemCountForCurrentApiKey; } statuses[] = {
    { "ok",                  WATCHLISTEDIT_OK,                  1, 3 },
    { "over_limit",          WATCHLISTEDIT_OVER_LIMIT,          1, 3 },
    { "over_domain_limit",   WATCHLISTEDIT_OVER_DOMAIN_LIMIT,   1, 3 },
    { "over_package_limit",  WATCHLISTEDIT_OVER_PACKAGE_LIMIT,  1, 3 },
    { "over_package_weight", WATCHLISTEDIT_OVER_PACKAGE_WEIGHT, 1, 3 },
    { "unknown_key",         WATCHLISTEDIT_UNKNOWN_KEY,         0, 0 },
  };
  TEST_ASSERT_EQUAL_size_t(strlen("over_package_weight"), (size_t)19);
  for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); i++)
  {
    static_resetFake();
    answer = static_queueNamedAnswer(g_watchlistEditColumnNames, WATCHLISTEDIT_ROW_COLUMN_COUNT, 1);
    static_setRow(answer, 0, row_cve, WATCHLISTEDIT_ROW_COLUMN_COUNT);
    answer->ma_cells[0][0] = statuses[i].mp_status;
    memset(&result, 0xA5, sizeof(result));
    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_OK, db_WATCHLISTEDITItems(FAKE_CONN, &params, NULL, &result), statuses[i].mp_status);
    TEST_ASSERT_EQUAL_INT_MESSAGE(statuses[i].m_status, result.m_status, statuses[i].mp_status);
    TEST_ASSERT_EQUAL_INT_MESSAGE(statuses[i].m_itemCount, result.m_itemCount, statuses[i].mp_status);
    TEST_ASSERT_EQUAL_INT_MESSAGE(statuses[i].m_itemCountForCurrentApiKey, result.m_itemCountForCurrentApiKey, statuses[i].mp_status);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, result.m_packageItemCountForCurrentApiKey, statuses[i].mp_status);
    db_WATCHLISTEDITItemsResultFree(&result);
  }

  static_resetFake();
  answer = static_queueNamedAnswer(g_watchlistEditColumnNames, WATCHLISTEDIT_ROW_COLUMN_COUNT, 1);
  answer->ma_cells[0][0] = "ok";
  static_setEditCounts(answer, WATCHLISTEDIT_ROW_COLUMN_COUNT, "100", "500");
  memset(&result, 0xA5, sizeof(result));
  TEST_ASSERT_EQUAL_INT(DB_OK, db_WATCHLISTEDITItems(FAKE_CONN, &params, NULL, &result));
  TEST_ASSERT_EQUAL_INT(0, result.m_itemCount);
  TEST_ASSERT_NULL(result.mp_items);
  TEST_ASSERT_EQUAL_INT(100, result.m_itemCountForCurrentApiKey);
  TEST_ASSERT_EQUAL_INT(500, result.m_packageItemCountForCurrentApiKey);

  {
    static_resetFake();
    answer = static_queueNamedAnswer(g_watchlistEditColumnNames, WATCHLISTEDIT_ROW_COLUMN_COUNT, 1);
    static_setRow(answer, 0, row_cve, WATCHLISTEDIT_ROW_COLUMN_COUNT);
    answer->ma_cells[0][0] = "over_package_weightx";
    static_clearLogLimit();
    StderrCapture_t capture;
    static_beginStderrCapture(&capture);
    memset(&result, 0xA5, sizeof(result));
    DbStatus_t status = db_WATCHLISTEDITItems(FAKE_CONN, &params, NULL, &result);
    char log_line[512];
    static_endStderrCapture(&capture, log_line, sizeof(log_line));
    TEST_ASSERT_EQUAL_INT(DB_ERROR, status);
    TEST_ASSERT_NULL(result.mp_items);
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(log_line, "holds 20 bytes, limit 19"), log_line);
  }

  static_resetFake();
  answer = static_queueNamedAnswer(g_watchlistEditColumnNames, WATCHLISTEDIT_ROW_COLUMN_COUNT, 2);
  static_setRow(answer, 0, row_cve, WATCHLISTEDIT_ROW_COLUMN_COUNT);
  answer->ma_cells[1][0] = "ok";
  memset(&result, 0xA5, sizeof(result));
  TEST_ASSERT_EQUAL_INT(DB_ERROR, db_WATCHLISTEDITItems(FAKE_CONN, &params, NULL, &result));
  TEST_ASSERT_NULL(result.mp_items);
  TEST_ASSERT_EQUAL_INT(0, result.m_itemCount);

  static char long_endpoint[WATCHLIST_ENDPOINT_MAX_LEN + 2];
  memset(long_endpoint, 'e', sizeof(long_endpoint) - 1);
  long_endpoint[sizeof(long_endpoint) - 1] = '\0';
  static char long_vendor[CVESEARCH_VENDOR_LEN + 2];
  memset(long_vendor, 'v', sizeof(long_vendor) - 1);
  long_vendor[sizeof(long_vendor) - 1] = '\0';
  static const char* const long_endpoint_row[WATCHLISTEDIT_ROW_COLUMN_COUNT] = { "ok", NULL, "CVE-2021-44228", NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, "3", "0" };
  static const char* const long_vendor_row[WATCHLISTEDIT_ROW_COLUMN_COUNT]   = { "ok", "cve_search", NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, "3", "0" };
  static const char* const bad_number_row[WATCHLISTEDIT_ROW_COLUMN_COUNT]    = { "ok", "cve_search", NULL, NULL, NULL, NULL, NULL, "high", NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, "3", "0" };
  static const char* const bad_bool_row[WATCHLISTEDIT_ROW_COLUMN_COUNT]      = { "ok", "cve_search", NULL, NULL, NULL, NULL, NULL, NULL, NULL, "yes", NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, "3", "0" };
  static const char* const bad_nuclei_row[WATCHLISTEDIT_ROW_COLUMN_COUNT]    = { "ok", "cve_search", NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, "yes", NULL, NULL, NULL, NULL, NULL, NULL, "3", "0" };
  static const char* const null_status_row[WATCHLISTEDIT_ROW_COLUMN_COUNT]   = { NULL, "cve_lookup", "CVE-2021-44228", NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, "3", "0" };
  static const char* const bogus_status_row[WATCHLISTEDIT_ROW_COLUMN_COUNT]  = { "bogus", "cve_lookup", "CVE-2021-44228", NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, "3", "0" };
  static const char* const no_kind_row[WATCHLISTEDIT_ROW_COLUMN_COUNT]       = { "ok", "cve_leading", "CVE-2021-44228", NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, "3", "0" };
  static const char* const null_cve_id_row[WATCHLISTEDIT_ROW_COLUMN_COUNT]   = { "ok", "kev_lookup", NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, "3", "0" };
  static const char* const null_vendor_row[WATCHLISTEDIT_ROW_COLUMN_COUNT]   = { "ok", "product_exposure", NULL, NULL, "log4j", NULL, NULL, NULL, NULL, NULL, NULL, NULL, "t", NULL, NULL, NULL, NULL, NULL, "3", "0" };
  static const char* const null_product_row[WATCHLISTEDIT_ROW_COLUMN_COUNT]  = { "ok", "product_exposure", NULL, "apache", NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, "t", NULL, NULL, NULL, NULL, NULL, "3", "0" };
  static const char* const null_has_cves_row[WATCHLISTEDIT_ROW_COLUMN_COUNT] = { "ok", "product_exposure", NULL, "apache", "log4j", NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, "3", "0" };
  static const char* const bad_has_cves_row[WATCHLISTEDIT_ROW_COLUMN_COUNT]  = { "ok", "product_exposure", NULL, "apache", "log4j", NULL, NULL, NULL, NULL, NULL, NULL, NULL, "yes", NULL, NULL, NULL, NULL, NULL, "3", "0" };
  static const char* const null_domain_row[WATCHLISTEDIT_ROW_COLUMN_COUNT]   = { "ok", "dns_lookup", NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, "3", "0" };
  static const char* const takeover_row[WATCHLISTEDIT_ROW_COLUMN_COUNT]      = { "ok", "dns_takeover_check", NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, "shop.example.com", NULL, NULL, NULL, NULL, "3", "0" };
  static char long_ecosystem[PACKAGECHECK_ECOSYSTEM_MAX_LEN + 2];
  memset(long_ecosystem, 'e', sizeof(long_ecosystem) - 1);
  long_ecosystem[sizeof(long_ecosystem) - 1] = '\0';
  static char long_package_name[PACKAGECHECK_NAME_MAX_LEN + 2];
  memset(long_package_name, 'n', sizeof(long_package_name) - 1);
  long_package_name[sizeof(long_package_name) - 1] = '\0';
  static char long_version[PACKAGECHECK_VERSION_MAX_LEN + 2];
  memset(long_version, '1', sizeof(long_version) - 1);
  long_version[sizeof(long_version) - 1] = '\0';
  const char* const null_ecosystem_row[WATCHLISTEDIT_ROW_COLUMN_COUNT]    = { "ok", "package_check", NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, "lodash", NULL, NULL, "3", "0" };
  const char* const null_package_name_row[WATCHLISTEDIT_ROW_COLUMN_COUNT] = { "ok", "package_check", NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, "npm", NULL, NULL, NULL, "3", "0" };
  const char* const long_ecosystem_row[WATCHLISTEDIT_ROW_COLUMN_COUNT]    = { "ok", "package_check", NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, long_ecosystem, "lodash", NULL, NULL, "3", "0" };
  const char* const long_package_name_row[WATCHLISTEDIT_ROW_COLUMN_COUNT] = { "ok", "package_check", NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, "npm", long_package_name, NULL, NULL, "3", "0" };
  const char* const long_version_row[WATCHLISTEDIT_ROW_COLUMN_COUNT]      = { "ok", "package_check", NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, "npm", "lodash", long_version, NULL, "3", "0" };
  const char* const long_pe_version_row[WATCHLISTEDIT_ROW_COLUMN_COUNT]   = { "ok", "product_exposure", NULL, "apache", "log4j", NULL, NULL, NULL, NULL, NULL, NULL, NULL, "t", NULL, NULL, NULL, long_version, NULL, "3", "0" };
  static const char* const null_ip_row[WATCHLISTEDIT_ROW_COLUMN_COUNT]    = { "ok", "ip_lookup", NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, "decoy.example", NULL, NULL, NULL, NULL, "3", "0" };
  static const char* const long_ip_row[WATCHLISTEDIT_ROW_COLUMN_COUNT]    = { "ok", "ip_lookup", NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.2550", "3", "0" };
  static const char* const null_item_count_row[WATCHLISTEDIT_ROW_COLUMN_COUNT]    = { "ok", "cve_lookup", "CVE-2021-44228", NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, "0" };
  static const char* const null_package_count_row[WATCHLISTEDIT_ROW_COLUMN_COUNT] = { "ok", "cve_lookup", "CVE-2021-44228", NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, "3", NULL };
  static const char* const bad_item_count_row[WATCHLISTEDIT_ROW_COLUMN_COUNT]     = { "ok", "cve_lookup", "CVE-2021-44228", NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, "x", "0" };
  static const char* const bad_package_count_row[WATCHLISTEDIT_ROW_COLUMN_COUNT]  = { "ok", "cve_lookup", "CVE-2021-44228", NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, "3", "x" };
  static const char* const null_counts_empty_row[WATCHLISTEDIT_ROW_COLUMN_COUNT]  = { "ok", NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL };
  const struct { const char* mp_label; const char* const* mp_row; const char* mp_cell_1; const char* mp_cell_3; } refused[] = {
    { "an endpoint one byte past its field",       long_endpoint_row, long_endpoint, NULL },
    { "a vendor one byte past its field",          long_vendor_row,   NULL,          long_vendor },
    { "a product item vendor past its field",      null_vendor_row,   NULL,          long_vendor },
    { "a min_cvss that is no number",              bad_number_row,    NULL,          NULL },
    { "an in_kev that is no boolean",              bad_bool_row,      NULL,          NULL },
    { "a has_nuclei_template that is no boolean",  bad_nuclei_row,    NULL,          NULL },
    { "a NULL status",                             null_status_row,   NULL,          NULL },
    { "an unknown status",                         bogus_status_row,  NULL,          NULL },
    { "an endpoint with no kind",                  no_kind_row,       NULL,          NULL },
    { "a CVE id item with a NULL cve_id",          null_cve_id_row,   NULL,          NULL },
    { "a product item with a NULL vendor",         null_vendor_row,   NULL,          NULL },
    { "a product item with a NULL product",        null_product_row,  NULL,          NULL },
    { "a product item with a NULL has_cves",       null_has_cves_row, NULL,          NULL },
    { "a product_has_cves that is no boolean",     bad_has_cves_row,  NULL,          NULL },
    { "a dns_lookup item with a NULL domain_name", null_domain_row,   NULL,          NULL },
    { "a dns_takeover_check item: too long",       takeover_row,      NULL,          NULL },
    { "a package item with a NULL ecosystem",      null_ecosystem_row,    NULL,      NULL },
    { "a package item with a NULL package_name",   null_package_name_row, NULL,      NULL },
    { "an ecosystem one byte past its field",      long_ecosystem_row,    NULL,      NULL },
    { "a package_name one byte past its field",    long_package_name_row, NULL,      NULL },
    { "a version one byte past its field",         long_version_row,      NULL,      NULL },
    { "an ip_lookup item with a NULL ip_address",  null_ip_row,           NULL,      NULL },
    { "an ip_address one byte past its field",     long_ip_row,           NULL,      NULL },
    { "a product item version past its field",     long_pe_version_row,   NULL,      NULL },
    { "a NULL item_count",                         null_item_count_row,   NULL,      NULL },
    { "a NULL package_item_count",                 null_package_count_row, NULL,     NULL },
    { "an item_count that is no number",           bad_item_count_row,    NULL,      NULL },
    { "a package_item_count that is no number",    bad_package_count_row, NULL,      NULL },
    { "a list with no item and NULL counts",       null_counts_empty_row, NULL,      NULL },
  };
  for (size_t i = 0; i < sizeof(refused) / sizeof(refused[0]); i++)
  {
    static_resetFake();
    answer = static_queueNamedAnswer(g_watchlistEditColumnNames, WATCHLISTEDIT_ROW_COLUMN_COUNT, 1);
    static_setRow(answer, 0, refused[i].mp_row, WATCHLISTEDIT_ROW_COLUMN_COUNT);
    if (refused[i].mp_cell_1 != NULL)
      answer->ma_cells[0][1] = refused[i].mp_cell_1;
    if (refused[i].mp_cell_3 != NULL)
      answer->ma_cells[0][3] = refused[i].mp_cell_3;
    memset(&result, 0xA5, sizeof(result));
    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_ERROR, db_WATCHLISTEDITItems(FAKE_CONN, &params, NULL, &result), refused[i].mp_label);
    TEST_ASSERT_NULL_MESSAGE(result.mp_items, refused[i].mp_label);
  }

  {
    static_resetFake();
    answer = static_queueNamedAnswer(g_watchlistEditColumnNames, WATCHLISTEDIT_ROW_COLUMN_COUNT, 1);
    static_setRow(answer, 0, long_endpoint_row, WATCHLISTEDIT_ROW_COLUMN_COUNT);
    answer->ma_cells[0][1] = long_endpoint;
    static_clearLogLimit();
    StderrCapture_t capture;
    static_beginStderrCapture(&capture);
    memset(&result, 0xA5, sizeof(result));
    DbStatus_t status = db_WATCHLISTEDITItems(FAKE_CONN, &params, NULL, &result);
    char log_line[512];
    static_endStderrCapture(&capture, log_line, sizeof(log_line));
    char expected[64];
    snprintf(expected, sizeof(expected), "holds %d bytes, limit %d", WATCHLIST_ENDPOINT_MAX_LEN + 1, WATCHLIST_ENDPOINT_MAX_LEN);
    TEST_ASSERT_EQUAL_INT(DB_ERROR, status);
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(log_line, expected), log_line);
  }

  static char longest_name[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
  memset(longest_name, 'd', sizeof(longest_name) - 1);
  longest_name[sizeof(longest_name) - 1] = '\0';
  static char long_name[VALIDATE_DOMAIN_NAME_MAX_LEN + 2];
  memset(long_name, 'd', sizeof(long_name) - 1);
  long_name[sizeof(long_name) - 1] = '\0';
  static_resetFake();
  answer = static_queueNamedAnswer(g_watchlistEditColumnNames, WATCHLISTEDIT_ROW_COLUMN_COUNT, 1);
  answer->ma_cells[0][0]  = "ok";
  answer->ma_cells[0][1]  = "dns_lookup";
  answer->ma_cells[0][13] = longest_name;
  static_setEditCounts(answer, WATCHLISTEDIT_ROW_COLUMN_COUNT, "1", "0");
  memset(&result, 0xA5, sizeof(result));
  TEST_ASSERT_EQUAL_INT(DB_OK, db_WATCHLISTEDITItems(FAKE_CONN, &params, NULL, &result));
  TEST_ASSERT_EQUAL_INT(1, result.m_itemCount);
  TEST_ASSERT_EQUAL_STRING(longest_name, result.mp_items[0].m_dnsLookup.ma_domainName);
  db_WATCHLISTEDITItemsResultFree(&result);

  static_resetFake();
  answer = static_queueNamedAnswer(g_watchlistEditColumnNames, WATCHLISTEDIT_ROW_COLUMN_COUNT, 1);
  answer->ma_cells[0][0]  = "ok";
  answer->ma_cells[0][1]  = "dns_lookup";
  answer->ma_cells[0][13] = long_name;
  static_setEditCounts(answer, WATCHLISTEDIT_ROW_COLUMN_COUNT, "1", "0");
  memset(&result, 0xA5, sizeof(result));
  TEST_ASSERT_EQUAL_INT(DB_ERROR, db_WATCHLISTEDITItems(FAKE_CONN, &params, NULL, &result));
  TEST_ASSERT_NULL(result.mp_items);

  static char longest_ecosystem[PACKAGECHECK_ECOSYSTEM_MAX_LEN + 1];
  memset(longest_ecosystem, 'e', sizeof(longest_ecosystem) - 1);
  longest_ecosystem[sizeof(longest_ecosystem) - 1] = '\0';
  static char longest_package_name[PACKAGECHECK_NAME_MAX_LEN + 1];
  memset(longest_package_name, 'n', sizeof(longest_package_name) - 1);
  longest_package_name[sizeof(longest_package_name) - 1] = '\0';
  static char longest_version[PACKAGECHECK_VERSION_MAX_LEN + 1];
  memset(longest_version, '1', sizeof(longest_version) - 1);
  longest_version[sizeof(longest_version) - 1] = '\0';
  static_resetFake();
  answer = static_queueNamedAnswer(g_watchlistEditColumnNames, WATCHLISTEDIT_ROW_COLUMN_COUNT, 1);
  answer->ma_cells[0][0]  = "ok";
  answer->ma_cells[0][1]  = "package_check";
  answer->ma_cells[0][14] = longest_ecosystem;
  answer->ma_cells[0][15] = longest_package_name;
  answer->ma_cells[0][16] = longest_version;
  static_setEditCounts(answer, WATCHLISTEDIT_ROW_COLUMN_COUNT, "0", "1");
  memset(&result, 0xA5, sizeof(result));
  TEST_ASSERT_EQUAL_INT(DB_OK, db_WATCHLISTEDITItems(FAKE_CONN, &params, NULL, &result));
  TEST_ASSERT_EQUAL_INT(1, result.m_itemCount);
  TEST_ASSERT_EQUAL_STRING(longest_ecosystem, result.mp_items[0].m_packageCheck.ma_ecosystem);
  TEST_ASSERT_EQUAL_STRING(longest_package_name, result.mp_items[0].m_packageCheck.ma_name);
  TEST_ASSERT_EQUAL_STRING(longest_version, result.mp_items[0].m_packageCheck.ma_version);
  TEST_ASSERT_EQUAL_INT(1, result.m_packageItemCountForCurrentApiKey);
  db_WATCHLISTEDITItemsResultFree(&result);

  for (size_t i = 0; i < sizeof(g_wrongShapes) / sizeof(g_wrongShapes[0]); i++)
  {
    static_resetFake();
    static_queueWrongShape(g_wrongShapes[i], "edit_status", "ok");
    memset(&result, 0xA5, sizeof(result));
    char message[16] = "";
    snprintf(message, sizeof(message), "shape %zu", i);
    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_ERROR, db_WATCHLISTEDITItems(FAKE_CONN, &params, NULL, &result), message);
    TEST_ASSERT_NULL_MESSAGE(result.mp_items, message);
  }
  static_resetFake();
  answer = static_queueNamedAnswer(g_watchlistEditColumnNames, WATCHLISTEDIT_ROW_COLUMN_COUNT - 1, 1);
  answer->ma_cells[0][0] = "ok";
  memset(&result, 0xA5, sizeof(result));
  TEST_ASSERT_EQUAL_INT(DB_ERROR, db_WATCHLISTEDITItems(FAKE_CONN, &params, NULL, &result));
  TEST_ASSERT_NULL(result.mp_items);
}

void test_WATCHLISTEVENTS_sends_its_six_parameters(void)
{
  RequestCreditBudget_t budget;
  static_watchlistBudget(&budget);
  TEST_ASSERT_EQUAL_INT(10000, WATCHLIST_SCAN_EVENT_MAX_COUNT);
  TEST_ASSERT_EQUAL_INT(600, WATCHLIST_ANSWER_PAIR_MAX_COUNT);

  WATCHLISTEVENTSParams_t with_cursor;
  memset(&with_cursor, 0, sizeof(with_cursor));
  with_cursor.mp_creditBudget = &budget;
  static_setText(with_cursor.ma_cursor, sizeof(with_cursor.ma_cursor), "41");
  with_cursor.m_limit = 7;

  WATCHLISTEVENTSParams_t repeat;
  memset(&repeat, 0, sizeof(repeat));
  repeat.mp_creditBudget = &budget;
  repeat.m_limit         = 7;
  repeat.m_isRepeat      = true;

  const char* const with_cursor_values[] = { WATCHLIST_TEST_KEY_HASH, "41", "false", "7", "10000", "600" };
  const char* const repeat_values[]      = { WATCHLIST_TEST_KEY_HASH, NULL, "true", "100", "10000", "600" };
  const struct { const WATCHLISTEVENTSParams_t* mp_params; int m_rowCount; const char* const* mp_values; } cases[] = {
    { &with_cursor, 7,   with_cursor_values },
    { &repeat,      100, repeat_values },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    static_resetFake();
    FakeAnswer_t* answer = static_queueNamedAnswer(g_watchlistEventsColumnNames, WATCHLISTEVENTS_ROW_COLUMN_COUNT, 1);
    answer->ma_cells[0][0] = "ok";
    answer->ma_cells[0][1] = "41";
    answer->ma_cells[0][2] = "f";
    WATCHLISTEVENTSResult_t result;
    memset(&result, 0xA5, sizeof(result));

    TEST_ASSERT_EQUAL_INT(DB_OK, db_WATCHLISTEVENTS(FAKE_CONN, cases[i].mp_params, cases[i].m_rowCount, &result));
    TEST_ASSERT_EQUAL_INT(1, g_callCount);
    static_assertCall(0, WATCHLISTEVENTS_CALL, cases[i].mp_values, 6);
    TEST_ASSERT_EQUAL_INT(0, static_call(0)->m_resultFormat);
    TEST_ASSERT_EQUAL_INT(WATCHLISTEVENTS_OK, result.m_status);
    TEST_ASSERT_EQUAL_STRING("41", result.ma_nextCursor);
    TEST_ASSERT_FALSE(result.m_hasMore);
    TEST_ASSERT_EQUAL_INT(0, result.m_eventCount);
    db_WATCHLISTEVENTSResultFree(&result);
    TEST_ASSERT_NULL(result.mp_events);
  }
}

static int static_eventsColumn(const char* name)
{
  for (int col = 0; col < WATCHLISTEVENTS_ROW_COLUMN_COUNT; col++)
  {
    if (strcmp(g_watchlistEventsColumnNames[col], name) == 0)
      return col;
  }
  TEST_FAIL_MESSAGE(name);
  return -1;
}

static void static_setEventsRow(FakeAnswer_t* answer, int row, const char* const* pairs)
{
  answer->ma_cells[row][static_eventsColumn("events_status")] = "ok";
  answer->ma_cells[row][static_eventsColumn("next_cursor")]   = "58";
  answer->ma_cells[row][static_eventsColumn("has_more")]      = "t";
  answer->ma_cells[row][static_eventsColumn("is_first_event_of_advisory")] = "f";
  answer->ma_cells[row][static_eventsColumn("attribution")]                = "[]";
  for (int i = 0; pairs[i] != NULL; i += 2)
    answer->ma_cells[row][static_eventsColumn(pairs[i])] = pairs[i + 1] != NULL ? pairs[i + 1] : FAKE_SQL_NULL;
}

static FakeAnswer_t* static_queueEventsAnswer(const char* const* const* rows, int row_count)
{
  FakeAnswer_t* answer = static_queueNamedAnswer(g_watchlistEventsColumnNames, WATCHLISTEVENTS_ROW_COLUMN_COUNT, row_count);
  for (int row = 0; row < row_count; row++)
    static_setEventsRow(answer, row, rows[row]);
  return answer;
}

static void static_watchlistEventsParams(WATCHLISTEVENTSParams_t* params, const RequestCreditBudget_t* budget)
{
  memset(params, 0, sizeof(*params));
  params->mp_creditBudget = budget;
  params->m_limit         = 20;
}

#define FLAGS_FIRST_CVE(rank)    "event_rank", rank, "is_first_row_of_event", "t", "is_first_event_of_cve", "t", "is_first_event_of_domain", "f"
#define FLAGS_FIRST_EVENT(rank)  "event_rank", rank, "is_first_row_of_event", "t", "is_first_event_of_cve", "f", "is_first_event_of_domain", "f"
#define FLAGS_LATER(rank)        "event_rank", rank, "is_first_row_of_event", "f", "is_first_event_of_cve", "f", "is_first_event_of_domain", "f"
#define FLAGS_FIRST_DOMAIN(rank) "event_rank", rank, "is_first_row_of_event", "t", "is_first_event_of_cve", "f", "is_first_event_of_domain", "t"

#define FACTS_LOG4J  "risk_score", "96.5", "risk_label", "CRITICAL", "in_kev", "t", "kev_patch_deadline", "2021-12-24", "kev_known_ransomware", "t", "has_metasploit", "f", "poc_count", "3"
#define FACTS_OTHER  "risk_score", "40", "risk_label", "MEDIUM", "in_kev", "f", "kev_patch_deadline", NULL, "kev_known_ransomware", "f", "has_metasploit", "t", "poc_count", "12"

#define EMAIL_VECTOR_BEFORE "ppppppppppppppppppppp"
#define EMAIL_VECTOR_AFTER  "pppwpppppfppppppppppp"

static const char* const g_cveRowLookup[] = {
  "item_id", "5", "item_endpoint_name", "cve_lookup", "item_cve_id", "CVE-2021-44228",
  FLAGS_FIRST_CVE("1"), "event_type", "kev_added", "changed_at", "2026-10-15T08:09:10Z", "cve_id", "CVE-2021-44228", FACTS_LOG4J, NULL
};
static const char* const g_cveRowSearchSame[] = {
  "item_id", "7", "item_endpoint_name", "cve_search", "item_severity", "CRITICAL", "item_cwe_id", "CWE-79", "item_min_cvss", "9", "item_in_kev", "t",
  "item_known_ransomware", "t",
  FLAGS_LATER("1"), "event_type", "kev_removed", "changed_at", "2026-10-15T08:09:19Z", "cve_id", "CVE-2099-0001", FACTS_OTHER, NULL
};
static const char* const g_cveRowSearchEpss[] = {
  "item_id", "7", "item_endpoint_name", "nobody_reads_it",
  FLAGS_FIRST_CVE("2"), "event_type", "epss_changed", "changed_at", "2026-10-15T08:09:11Z", "cve_id", "CVE-2022-12345",
  "previous_value", "0.4", "current_value", "0.52345", FACTS_OTHER, NULL
};
static const char* const g_cveRowProduct[] = {
  "item_id", "10", "item_endpoint_name", "product_exposure", "item_vendor", "apache", "item_product", "log4j", "item_product_has_cves", "t",
  "item_version", "2.14.1",
  FLAGS_FIRST_EVENT("3"), "event_type", "product_added", "changed_at", "2026-10-15T08:09:12Z", "cve_id", "CVE-2021-44228",
  "vendor", "apache", "product", "log4j-core", NULL
};
static const char* const* const g_cveRows[] = { g_cveRowLookup, g_cveRowSearchSame, g_cveRowSearchEpss, g_cveRowProduct };
#define CVE_ROW_COUNT 4

static const char* const g_domainRowNs[] = {
  "item_id", "11", "item_endpoint_name", "dns_lookup", "item_domain_name", "example.com",
  FLAGS_FIRST_DOMAIN("1"), "event_type", "ns_changed", "changed_at", "2026-10-16T01:02:03Z",
  "previous_domain_value", "ns1.example.net\nns2.example.net", "current_domain_value", "ns1.example.org",
  "registered_domain", "example.com", "dns_presence_value", "found", "ns_value", "ns1.example.org",
  "mx_value", "10 mx.example.com\nnull", "ip_address_reachability_value", "public", "cname_takeover_value", "none",
  "email_auth_value", EMAIL_VECTOR_AFTER, NULL
};
static const char* const g_domainRowEmail[] = {
  "item_id", "11", "item_endpoint_name", "dns_lookup", "item_domain_name", "example.com",
  FLAGS_FIRST_EVENT("2"), "event_type", "email_auth_degraded", "changed_at", "2026-10-16T01:02:04Z",
  "degraded_email_check_id", "dmarc_policy", "previous_domain_value", EMAIL_VECTOR_BEFORE, "current_domain_value", EMAIL_VECTOR_AFTER,
  "registered_domain", "other.org", "dns_presence_value", "not_found", "ns_value", "x", "mx_value", "y",
  "ip_address_reachability_value", "empty", "cname_takeover_value", "vulnerable", "email_auth_value", "w", NULL
};
static const char* const g_domainRowTakeover[] = {
  "item_id", "12", "item_endpoint_name", "dns_lookup", "item_domain_name", "www.example.com",
  FLAGS_FIRST_DOMAIN("3"), "event_type", "cname_takeover_detected", "changed_at", "2026-10-16T01:02:05Z",
  "previous_domain_value", "none", "current_domain_value", "vulnerable github",
  "registered_domain", "example.com", "cname_takeover_value", "vulnerable github", NULL
};
static const char* const* const g_domainRows[] = { g_domainRowNs, g_domainRowEmail, g_domainRowTakeover };
#define DOMAIN_ROW_COUNT 3

void test_WATCHLISTEVENTS_reads_items_pairs_and_shared_events(void)
{
  RequestCreditBudget_t budget;
  static_watchlistBudget(&budget);
  WATCHLISTEVENTSParams_t params;
  static_watchlistEventsParams(&params, &budget);

  static_resetFake();
  static_queueEventsAnswer(g_cveRows, CVE_ROW_COUNT);
  WATCHLISTEVENTSResult_t result;
  memset(&result, 0xA5, sizeof(result));
  g_dirtyMalloc = true;
  TEST_ASSERT_EQUAL_INT(DB_OK, db_WATCHLISTEVENTS(FAKE_CONN, &params, 20, &result));
  g_dirtyMalloc = false;
  TEST_ASSERT_EQUAL_INT(WATCHLISTEVENTS_OK, result.m_status);
  TEST_ASSERT_EQUAL_STRING("58", result.ma_nextCursor);
  TEST_ASSERT_TRUE(result.m_hasMore);

  TEST_ASSERT_EQUAL_INT(3, result.m_eventCount);
  const WATCHLISTEVENTSEvent_t* kev = &result.mp_events[0];
  TEST_ASSERT_EQUAL_INT(WATCHLIST_EVENT_CVE, kev->m_eventKind);
  TEST_ASSERT_EQUAL_STRING("kev_added", kev->ma_eventType);
  TEST_ASSERT_EQUAL_STRING("2026-10-15T08:09:10Z", kev->ma_changedAt);
  TEST_ASSERT_EQUAL_STRING("CVE-2021-44228", kev->m_cveChange.ma_cveId);
  TEST_ASSERT_FALSE(kev->m_cveChange.m_hasPreviousValue);
  TEST_ASSERT_FALSE(kev->m_cveChange.m_hasCurrentValue);
  TEST_ASSERT_FALSE(kev->m_cveChange.m_hasProductPair);
  const WATCHLISTEVENTSEvent_t* epss = &result.mp_events[1];
  TEST_ASSERT_EQUAL_INT(WATCHLIST_EVENT_CVE, epss->m_eventKind);
  TEST_ASSERT_EQUAL_STRING("epss_changed", epss->ma_eventType);
  TEST_ASSERT_EQUAL_STRING("CVE-2022-12345", epss->m_cveChange.ma_cveId);
  TEST_ASSERT_TRUE(epss->m_cveChange.m_hasPreviousValue);
  TEST_ASSERT_EQUAL_FLOAT(0.4, epss->m_cveChange.m_previousValue);
  TEST_ASSERT_TRUE(epss->m_cveChange.m_hasCurrentValue);
  TEST_ASSERT_EQUAL_FLOAT(0.52345, epss->m_cveChange.m_currentValue);
  const WATCHLISTEVENTSEvent_t* product = &result.mp_events[2];
  TEST_ASSERT_EQUAL_STRING("product_added", product->ma_eventType);
  TEST_ASSERT_TRUE(product->m_cveChange.m_hasProductPair);
  TEST_ASSERT_EQUAL_STRING("apache", product->m_cveChange.ma_vendor);
  TEST_ASSERT_EQUAL_STRING("log4j-core", product->m_cveChange.ma_product);

  TEST_ASSERT_EQUAL_INT(3, result.m_answerItemCount);
  const WATCHLISTEVENTSAnswerItem_t* lookup = &result.mp_answerItems[0];
  TEST_ASSERT_EQUAL_STRING("cve_lookup", watchlist_findEndpointName(lookup->m_item.m_itemKind));
  TEST_ASSERT_EQUAL_INT(WATCHLIST_ITEM_CVE_LOOKUP, lookup->m_item.m_itemKind);
  TEST_ASSERT_EQUAL_STRING("CVE-2021-44228", lookup->m_item.m_cveLookup.ma_cveId);
  TEST_ASSERT_EQUAL_INT(0, lookup->m_firstPairIndex);
  TEST_ASSERT_EQUAL_INT(1, lookup->m_pairCount);
  const WATCHLISTEVENTSAnswerItem_t* search = &result.mp_answerItems[1];
  TEST_ASSERT_EQUAL_STRING("cve_search", watchlist_findEndpointName(search->m_item.m_itemKind));
  TEST_ASSERT_EQUAL_INT(WATCHLIST_ITEM_CVE_SEARCH, search->m_item.m_itemKind);
  TEST_ASSERT_EQUAL_STRING("CRITICAL", search->m_item.m_cveSearch.ma_severity);
  TEST_ASSERT_EQUAL_STRING("", search->m_item.m_cveSearch.ma_vendor);
  TEST_ASSERT_EQUAL_STRING("CWE-79", search->m_item.m_cveSearch.ma_cweId);
  TEST_ASSERT_TRUE(search->m_item.m_cveSearch.m_knownRansomware);
  TEST_ASSERT_FALSE(search->m_item.m_cveSearch.m_hasNucleiTemplate);
  TEST_ASSERT_EQUAL_FLOAT(9.0, search->m_item.m_cveSearch.m_minCvss);
  TEST_ASSERT_EQUAL_FLOAT(-1.0, search->m_item.m_cveSearch.m_minEpss);
  TEST_ASSERT_EQUAL_INT(CVE_KEV_FILTER_ONLY_IN_KEV, search->m_item.m_cveSearch.m_kevFilter);
  TEST_ASSERT_EQUAL_INT(1, search->m_firstPairIndex);
  TEST_ASSERT_EQUAL_INT(2, search->m_pairCount);
  const WATCHLISTEVENTSAnswerItem_t* exposure = &result.mp_answerItems[2];
  TEST_ASSERT_EQUAL_INT(WATCHLIST_ITEM_PRODUCT_EXPOSURE, exposure->m_item.m_itemKind);
  TEST_ASSERT_EQUAL_STRING("apache", exposure->m_item.m_productExposure.ma_vendor);
  TEST_ASSERT_EQUAL_STRING("log4j", exposure->m_item.m_productExposure.ma_product);
  TEST_ASSERT_EQUAL_STRING("2.14.1", exposure->m_item.m_productExposure.ma_version);
  TEST_ASSERT_TRUE(exposure->m_item.m_productExposure.m_hasCves);
  TEST_ASSERT_EQUAL_INT(3, exposure->m_firstPairIndex);
  TEST_ASSERT_EQUAL_INT(1, exposure->m_pairCount);

  TEST_ASSERT_EQUAL_INT(4, result.m_pairCount);
  const int pairs[] = { 0, 0, 1, 2 };
  TEST_ASSERT_EQUAL_INT_ARRAY(pairs, result.mp_pairEventIndexes, 4);

  TEST_ASSERT_EQUAL_INT(2, result.m_cveFactCount);
  const WATCHLISTEVENTSCveFacts_t* log4j = &result.mp_cveFacts[0];
  TEST_ASSERT_EQUAL_STRING("CVE-2021-44228", log4j->ma_cveId);
  TEST_ASSERT_EQUAL_FLOAT(96.5, log4j->m_riskScore);
  TEST_ASSERT_EQUAL_STRING("CRITICAL", log4j->ma_riskLabel);
  TEST_ASSERT_TRUE(log4j->m_isInKev);
  TEST_ASSERT_TRUE(log4j->m_hasKev);
  TEST_ASSERT_EQUAL_STRING("2021-12-24", log4j->ma_kevPatchDeadline);
  TEST_ASSERT_TRUE(log4j->m_kevKnownRansomware);
  TEST_ASSERT_FALSE(log4j->m_hasMetasploit);
  TEST_ASSERT_EQUAL_INT(3, log4j->m_pocCount);
  TEST_ASSERT_EQUAL_STRING("CVE-2022-12345", result.mp_cveFacts[1].ma_cveId);
  TEST_ASSERT_EQUAL_INT(12, result.mp_cveFacts[1].m_pocCount);
  TEST_ASSERT_FALSE(result.mp_cveFacts[1].m_hasKev);
  TEST_ASSERT_EQUAL_INT(0, result.m_domainFactCount);
  TEST_ASSERT_NULL(result.mp_domainFacts);

  db_WATCHLISTEVENTSResultFree(&result);
  TEST_ASSERT_NULL(result.mp_events);
  TEST_ASSERT_NULL(result.mp_answerItems);
  TEST_ASSERT_NULL(result.mp_pairEventIndexes);
  TEST_ASSERT_NULL(result.mp_cveFacts);
  TEST_ASSERT_EQUAL_INT(0, result.m_eventCount);
  TEST_ASSERT_EQUAL_INT(0, result.m_answerItemCount);
  TEST_ASSERT_EQUAL_INT(0, result.m_pairCount);
  TEST_ASSERT_EQUAL_INT(0, result.m_cveFactCount);
  db_WATCHLISTEVENTSResultFree(&result);
  db_WATCHLISTEVENTSResultFree(NULL);

  static const char* const newer_first[] = {
    "item_id", "5", "item_endpoint_name", "cve_lookup", "item_cve_id", "CVE-2021-44228",
    FLAGS_FIRST_CVE("2"), "event_type", "kev_added", "changed_at", "2026-10-15T08:09:10Z", "cve_id", "CVE-2021-44228", FACTS_LOG4J, NULL
  };
  static const char* const older_last[] = {
    "item_id", "100000000000000007", "item_endpoint_name", "cve_search", "item_cwe_id", "CWE-89", "item_min_cvss", "7",
    "item_has_nuclei_template", "t",
    FLAGS_FIRST_CVE("1"), "event_type", "epss_changed", "changed_at", "2026-10-15T08:09:09Z", "cve_id", "CVE-2022-12345", FACTS_OTHER, NULL
  };
  static const char* const* const newer_then_older[] = { newer_first, older_last };
  static_resetFake();
  static_queueEventsAnswer(newer_then_older, 2);
  TEST_ASSERT_EQUAL_INT(DB_OK, db_WATCHLISTEVENTS(FAKE_CONN, &params, 20, &result));
  TEST_ASSERT_EQUAL_INT(2, result.m_eventCount);
  TEST_ASSERT_EQUAL_STRING("epss_changed", result.mp_events[0].ma_eventType);
  TEST_ASSERT_EQUAL_STRING("kev_added", result.mp_events[1].ma_eventType);
  const int newer_then_older_pairs[] = { 1, 0 };
  TEST_ASSERT_EQUAL_INT_ARRAY(newer_then_older_pairs, result.mp_pairEventIndexes, 2);
  TEST_ASSERT_EQUAL_INT(2, result.m_answerItemCount);
  const WATCHLISTCVESEARCHItem_t* older_filter = &result.mp_answerItems[1].m_item.m_cveSearch;
  TEST_ASSERT_EQUAL_STRING("cve_search", watchlist_findEndpointName(result.mp_answerItems[1].m_item.m_itemKind));
  TEST_ASSERT_EQUAL_STRING("CWE-89", older_filter->ma_cweId);
  TEST_ASSERT_EQUAL_FLOAT(7.0, older_filter->m_minCvss);
  TEST_ASSERT_EQUAL_INT(CVE_KEV_FILTER_ANY, older_filter->m_kevFilter);
  TEST_ASSERT_FALSE(older_filter->m_knownRansomware);
  TEST_ASSERT_TRUE(older_filter->m_hasNucleiTemplate);
  db_WATCHLISTEVENTSResultFree(&result);
}

void test_WATCHLISTEVENTS_reads_domain_events_and_facts(void)
{
  RequestCreditBudget_t budget;
  static_watchlistBudget(&budget);
  WATCHLISTEVENTSParams_t params;
  static_watchlistEventsParams(&params, &budget);

  static_resetFake();
  static_queueEventsAnswer(g_domainRows, DOMAIN_ROW_COUNT);
  WATCHLISTEVENTSResult_t result;
  memset(&result, 0xA5, sizeof(result));
  g_dirtyMalloc = true;
  TEST_ASSERT_EQUAL_INT(DB_OK, db_WATCHLISTEVENTS(FAKE_CONN, &params, 20, &result));
  g_dirtyMalloc = false;

  TEST_ASSERT_EQUAL_INT(3, result.m_eventCount);
  const WATCHLISTEVENTSEvent_t* ns = &result.mp_events[0];
  TEST_ASSERT_EQUAL_INT(WATCHLIST_EVENT_DNS_LOOKUP, ns->m_eventKind);
  TEST_ASSERT_EQUAL_STRING("ns_changed", ns->ma_eventType);
  TEST_ASSERT_EQUAL_STRING("2026-10-16T01:02:03Z", ns->ma_changedAt);
  TEST_ASSERT_EQUAL_STRING("", ns->m_dnsLookupChange.ma_degradedEmailCheckId);
  TEST_ASSERT_EQUAL_STRING("ns1.example.net\nns2.example.net", ns->m_dnsLookupChange.mp_previousValue);
  TEST_ASSERT_EQUAL_STRING("ns1.example.org", ns->m_dnsLookupChange.mp_currentValue);
  const WATCHLISTEVENTSEvent_t* email = &result.mp_events[1];
  TEST_ASSERT_EQUAL_INT(WATCHLIST_EVENT_DNS_LOOKUP, email->m_eventKind);
  TEST_ASSERT_EQUAL_STRING("email_auth_degraded", email->ma_eventType);
  TEST_ASSERT_EQUAL_STRING("dmarc_policy", email->m_dnsLookupChange.ma_degradedEmailCheckId);
  TEST_ASSERT_EQUAL_STRING(EMAIL_VECTOR_BEFORE, email->m_dnsLookupChange.mp_previousValue);
  TEST_ASSERT_EQUAL_STRING(EMAIL_VECTOR_AFTER, email->m_dnsLookupChange.mp_currentValue);
  const WATCHLISTEVENTSEvent_t* takeover = &result.mp_events[2];
  TEST_ASSERT_EQUAL_INT(WATCHLIST_EVENT_DNS_LOOKUP, takeover->m_eventKind);
  TEST_ASSERT_EQUAL_STRING("cname_takeover_detected", takeover->ma_eventType);
  TEST_ASSERT_EQUAL_STRING("none", takeover->m_dnsLookupChange.mp_previousValue);
  TEST_ASSERT_EQUAL_STRING("vulnerable github", takeover->m_dnsLookupChange.mp_currentValue);

  TEST_ASSERT_EQUAL_INT(2, result.m_answerItemCount);
  TEST_ASSERT_EQUAL_INT(WATCHLIST_ITEM_DNS_LOOKUP, result.mp_answerItems[0].m_item.m_itemKind);
  TEST_ASSERT_EQUAL_STRING("example.com", result.mp_answerItems[0].m_item.m_dnsLookup.ma_domainName);
  TEST_ASSERT_EQUAL_INT(2, result.mp_answerItems[0].m_pairCount);
  TEST_ASSERT_EQUAL_INT(WATCHLIST_ITEM_DNS_LOOKUP, result.mp_answerItems[1].m_item.m_itemKind);
  TEST_ASSERT_EQUAL_STRING("www.example.com", result.mp_answerItems[1].m_item.m_dnsLookup.ma_domainName);
  TEST_ASSERT_EQUAL_INT(2, result.mp_answerItems[1].m_firstPairIndex);
  TEST_ASSERT_EQUAL_INT(1, result.mp_answerItems[1].m_pairCount);
  const int pairs[] = { 0, 1, 2 };
  TEST_ASSERT_EQUAL_INT_ARRAY(pairs, result.mp_pairEventIndexes, 3);
  TEST_ASSERT_EQUAL_INT(0, result.m_cveFactCount);
  TEST_ASSERT_NULL(result.mp_cveFacts);

  TEST_ASSERT_EQUAL_INT(2, result.m_domainFactCount);
  const WATCHLISTEVENTSDomainFacts_t* apex = &result.mp_domainFacts[0];
  TEST_ASSERT_EQUAL_STRING("example.com", apex->ma_domainName);
  TEST_ASSERT_EQUAL_STRING("example.com", apex->ma_registeredDomain);
  TEST_ASSERT_EQUAL_STRING("found", apex->m_dnsFacts.mp_dnsPresenceValue);
  TEST_ASSERT_EQUAL_STRING("ns1.example.org", apex->m_dnsFacts.mp_nsValue);
  TEST_ASSERT_EQUAL_STRING("10 mx.example.com\nnull", apex->m_dnsFacts.mp_mxValue);
  TEST_ASSERT_EQUAL_STRING("public", apex->m_dnsFacts.mp_ipAddressReachabilityValue);
  TEST_ASSERT_EQUAL_STRING("none", apex->m_dnsFacts.mp_cnameTakeoverValue);
  TEST_ASSERT_EQUAL_STRING(EMAIL_VECTOR_AFTER, apex->m_dnsFacts.mp_emailAuthValue);
  const WATCHLISTEVENTSDomainFacts_t* host = &result.mp_domainFacts[1];
  TEST_ASSERT_EQUAL_STRING("www.example.com", host->ma_domainName);
  TEST_ASSERT_EQUAL_STRING("example.com", host->ma_registeredDomain);
  TEST_ASSERT_NULL(host->m_dnsFacts.mp_dnsPresenceValue);
  TEST_ASSERT_NULL(host->m_dnsFacts.mp_nsValue);
  TEST_ASSERT_NULL(host->m_dnsFacts.mp_mxValue);
  TEST_ASSERT_NULL(host->m_dnsFacts.mp_ipAddressReachabilityValue);
  TEST_ASSERT_EQUAL_STRING("vulnerable github", host->m_dnsFacts.mp_cnameTakeoverValue);
  TEST_ASSERT_NULL(host->m_dnsFacts.mp_emailAuthValue);
  db_WATCHLISTEVENTSResultFree(&result);
  TEST_ASSERT_NULL(result.mp_events);
  TEST_ASSERT_NULL(result.mp_domainFacts);
  TEST_ASSERT_EQUAL_INT(0, result.m_domainFactCount);

  static char text_at_limit[WATCHLIST_DOMAIN_VALUE_MAX_LEN + 1];
  memset(text_at_limit, 'n', sizeof(text_at_limit) - 1);
  text_at_limit[sizeof(text_at_limit) - 1] = '\0';
  static_resetFake();
  FakeAnswer_t* answer = static_queueEventsAnswer(g_domainRows, 1);
  answer->ma_cells[0][static_eventsColumn("previous_domain_value")] = text_at_limit;
  answer->ma_cells[0][static_eventsColumn("ns_value")]      = text_at_limit;
  memset(&result, 0xA5, sizeof(result));
  TEST_ASSERT_EQUAL_INT(DB_OK, db_WATCHLISTEVENTS(FAKE_CONN, &params, 20, &result));
  TEST_ASSERT_EQUAL_size_t(WATCHLIST_DOMAIN_VALUE_MAX_LEN, strlen(result.mp_events[0].m_dnsLookupChange.mp_previousValue));
  TEST_ASSERT_EQUAL_size_t(WATCHLIST_DOMAIN_VALUE_MAX_LEN, strlen(result.mp_domainFacts[0].m_dnsFacts.mp_nsValue));
  db_WATCHLISTEVENTSResultFree(&result);
}

static void static_assertEventsRefused(const WATCHLISTEVENTSParams_t* params, const char* label)
{
  WATCHLISTEVENTSResult_t result;
  memset(&result, 0xA5, sizeof(result));
  TEST_ASSERT_EQUAL_INT_MESSAGE(DB_ERROR, db_WATCHLISTEVENTS(FAKE_CONN, params, 20, &result), label);
  TEST_ASSERT_NULL_MESSAGE(result.mp_events, label);
  TEST_ASSERT_NULL_MESSAGE(result.mp_answerItems, label);
  TEST_ASSERT_NULL_MESSAGE(result.mp_pairEventIndexes, label);
  TEST_ASSERT_NULL_MESSAGE(result.mp_cveFacts, label);
  TEST_ASSERT_NULL_MESSAGE(result.mp_domainFacts, label);
  TEST_ASSERT_NULL_MESSAGE(result.mp_pairIsVersionAffected, label);
  TEST_ASSERT_NULL_MESSAGE(result.mp_advisories, label);
  TEST_ASSERT_NULL_MESSAGE(result.mp_attribution, label);
  TEST_ASSERT_EQUAL_INT_MESSAGE(0, result.m_advisoryCount, label);
  TEST_ASSERT_EQUAL_INT_MESSAGE(0, result.m_eventCount, label);
  TEST_ASSERT_EQUAL_INT_MESSAGE(0, result.m_answerItemCount, label);
  TEST_ASSERT_EQUAL_INT_MESSAGE(0, result.m_pairCount, label);
  TEST_ASSERT_EQUAL_INT_MESSAGE(0, result.m_cveFactCount, label);
  TEST_ASSERT_EQUAL_INT_MESSAGE(0, result.m_domainFactCount, label);
  TEST_ASSERT_EQUAL_STRING_MESSAGE("", result.ma_nextCursor, label);
  db_WATCHLISTEVENTSResultFree(&result);
}

void test_WATCHLISTEVENTS_refuses_each_broken_row_rule(void)
{
  RequestCreditBudget_t budget;
  static_watchlistBudget(&budget);
  WATCHLISTEVENTSParams_t params;
  static_watchlistEventsParams(&params, &budget);

  static char long_text[WATCHLIST_DOMAIN_VALUE_MAX_LEN + 2];
  memset(long_text, 'n', sizeof(long_text) - 1);
  long_text[sizeof(long_text) - 1] = '\0';
  static char long_domain[VALIDATE_DOMAIN_NAME_MAX_LEN + 2];
  memset(long_domain, 'd', sizeof(long_domain) - 1);
  long_domain[sizeof(long_domain) - 1] = '\0';
  static char long_check_id[EMAILCHECK_KIND_ID_MAX_LEN + 2];
  memset(long_check_id, 'c', sizeof(long_check_id) - 1);
  long_check_id[sizeof(long_check_id) - 1] = '\0';

  const struct { const char* mp_label; bool m_isDomainAnswer; int m_row; const char* mp_column; const char* mp_cell; } refused[] = {
    { "event_rank 0",                                    false, 0, "event_rank",                    "0" },
    { "event_rank 5 in a four-row answer",               false, 1, "event_rank",                    "5" },
    { "event_rank 5 on the first row of an event",       false, 3, "event_rank",                    "5" },
    { "a NULL event_rank",                               false, 1, "event_rank",                    NULL },
    { "an event_rank that is no number",                 false, 1, "event_rank",                    "one" },
    { "a second first row of an event",                  false, 1, "is_first_row_of_event",         "t" },
    { "an event no row fills",                           false, 0, "is_first_row_of_event",         "f" },
    { "a NULL is_first_row_of_event",                    false, 1, "is_first_row_of_event",         NULL },
    { "a NULL is_first_event_of_cve",                    false, 1, "is_first_event_of_cve",         NULL },
    { "a NULL is_first_event_of_domain",                 false, 1, "is_first_event_of_domain",      NULL },
    { "a first row of a domain on a CVE item",           false, 0, "is_first_event_of_domain",      "t" },
    { "an item_id that goes back",                       false, 3, "item_id",                       "6" },
    { "an item_id that comes back after another",        false, 3, "item_id",                       "5" },
    { "an item_id of fewer digits that goes back",       true,  2, "item_id",                       "9" },
    { "a NULL item_id on a later row",                   false, 1, "item_id",                       NULL },
    { "an item_id with a leading 0",                     false, 3, "item_id",                       "010" },
    { "an item_id past WATCHLIST_CURSOR_MAX_LEN digits", false, 3, "item_id",                       "1000000000000000010" },
    { "a NULL item endpoint on a new item",              false, 1, "item_endpoint_name",            NULL },
    { "an item endpoint with no kind",                   false, 1, "item_endpoint_name",            "cve_triage" },
    { "a NULL item_cve_id on a cve_lookup item",         false, 0, "item_cve_id",                   NULL },
    { "a NULL item_product_has_cves",                    false, 3, "item_product_has_cves",         NULL },
    { "a NULL event_type on a first row",                false, 2, "event_type",                    NULL },
    { "a NULL changed_at on a first row",                false, 2, "changed_at",                    NULL },
    { "a NULL cve_id on a CVE event",                    false, 3, "cve_id",                        NULL },
    { "a NULL cve_id on a first row of a CVE",           false, 0, "cve_id",                        NULL },
    { "a NULL poc_count on a first row of a CVE",        false, 2, "poc_count",                     NULL },
    { "a vendor with a NULL product",                    false, 3, "product",                       NULL },
    { "a NULL item_domain_name on a dns_lookup item",    true,  0, "item_domain_name",              NULL },
    { "a NULL event_type on a domain event",             true,  1, "event_type",                    NULL },
    { "a NULL changed_at on a domain event",             true,  2, "changed_at",                    NULL },
    { "a NULL registered_domain",                        true,  0, "registered_domain",             NULL },
    { "a registered_domain past its field",              true,  2, "registered_domain",             long_domain },
    { "a degraded_email_check_id past its field",        true,  1, "degraded_email_check_id",       long_check_id },
    { "a previous_domain_value past the limit",          true,  0, "previous_domain_value",         long_text },
    { "a current_domain_value past the limit",           true,  2, "current_domain_value",          long_text },
    { "a dns_presence_value past the limit",             true,  0, "dns_presence_value",            long_text },
    { "an ns_value past the limit",                      true,  0, "ns_value",                      long_text },
    { "an mx_value past the limit",                      true,  0, "mx_value",                      long_text },
    { "an ip_address_reachability_value past the limit", true,  0, "ip_address_reachability_value", long_text },
    { "a cname_takeover_value past the limit",           true,  2, "cname_takeover_value",          long_text },
    { "an email_auth_value past the limit",              true,  0, "email_auth_value",              long_text },
    { "a first row of a CVE on a domain item",           true,  1, "is_first_event_of_cve",         "t" },
    { "a second first row of a domain",                  true,  1, "is_first_event_of_domain",      "t" },
  };
  for (size_t i = 0; i < sizeof(refused) / sizeof(refused[0]); i++)
  {
    static_resetFake();
    FakeAnswer_t* answer = refused[i].m_isDomainAnswer ? static_queueEventsAnswer(g_domainRows, DOMAIN_ROW_COUNT)
                                                       : static_queueEventsAnswer(g_cveRows, CVE_ROW_COUNT);
    answer->ma_cells[refused[i].m_row][static_eventsColumn(refused[i].mp_column)] = refused[i].mp_cell != NULL ? refused[i].mp_cell : FAKE_SQL_NULL;
    static_assertEventsRefused(&params, refused[i].mp_label);
  }

  const struct { int m_row; const char* mp_label; } cve_item_rows[] = {
    { 0, "a first row of a domain with its facts on a cve_lookup item" },
    { 2, "a first row of a domain with its facts on a cve_search item" },
    { 3, "a first row of a domain with its facts on a product_exposure item" },
  };
  FakeAnswer_t* answer = NULL;
  for (size_t i = 0; i < sizeof(cve_item_rows) / sizeof(cve_item_rows[0]); i++)
  {
    static_resetFake();
    answer = static_queueEventsAnswer(g_cveRows, CVE_ROW_COUNT);
    answer->ma_cells[cve_item_rows[i].m_row][static_eventsColumn("is_first_event_of_domain")] = "t";
    answer->ma_cells[cve_item_rows[i].m_row][static_eventsColumn("registered_domain")]        = "example.com";
    static_assertEventsRefused(&params, cve_item_rows[i].mp_label);
  }

  static const char* const no_event_row[] = { NULL };
  static const char* const* const no_event_then_event[] = { no_event_row, g_cveRowLookup };
  static_resetFake();
  static_queueEventsAnswer(no_event_then_event, 2);
  static_assertEventsRefused(&params, "a row after the row of no event");

  static const char* const* const lookup_alone[] = { g_cveRowLookup };
  static_resetFake();
  answer = static_queueEventsAnswer(lookup_alone, 1);
  answer->ma_cells[0][static_eventsColumn("event_type")] = FAKE_SQL_NULL;
  static_assertEventsRefused(&params, "a lone pair row with a NULL event_type");
}

void test_WATCHLISTEVENTS_frees_every_text_after_a_failed_copy(void)
{
  RequestCreditBudget_t budget;
  static_watchlistBudget(&budget);
  WATCHLISTEVENTSParams_t params;
  static_watchlistEventsParams(&params, &budget);

  int failed_count = 0;
  for (int n = 1; n <= 20; n++)
  {
    static_resetFake();
    static_queueEventsAnswer(g_domainRows, DOMAIN_ROW_COUNT);
    g_strdupFailsAtCall = n;
    WATCHLISTEVENTSResult_t result;
    memset(&result, 0xA5, sizeof(result));
    DbStatus_t status = db_WATCHLISTEVENTS(FAKE_CONN, &params, 20, &result);
    if (status == DB_OK)
    {
      db_WATCHLISTEVENTSResultFree(&result);
      break;
    }
    char label[32];
    snprintf(label, sizeof(label), "strdup call %d", n);
    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_ERROR, status, label);
    TEST_ASSERT_NULL_MESSAGE(result.mp_events, label);
    TEST_ASSERT_NULL_MESSAGE(result.mp_domainFacts, label);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, result.m_domainFactCount, label);
    failed_count++;
  }
  TEST_ASSERT_EQUAL_INT(14, failed_count);
}

#define FLAGS_FIRST_ADVISORY(rank) "event_rank", rank, "is_first_row_of_event", "t", "is_first_event_of_cve", "f", \
                                   "is_first_event_of_domain", "f", "is_first_event_of_advisory", "t"

#define PACKAGE_ATTRIBUTION "[{\"url\": \"https://github.com/github/advisory-database\", \"notice\": \"Retrieved through OSV.dev.\", " \
                            "\"source\": \"ghsa\", \"license\": \"CC-BY-4.0\"}]"

#define PACKAGE_ALIASES_LODASH "[\"CVE-2020-8203\", \"CVE-2020-28500\", \"SNYK-JS-LODASH-590103\"]"

#define PACKAGE_ALIAS_FACTS_LODASH                                                                                    \
  "[{\"cve_id\": \"CVE-2020-8203\", \"in_kev\": true, \"poc_count\": 4, \"risk_label\": \"HIGH\", \"risk_score\": 72.5, " \
  "\"has_metasploit\": true, \"kev_patch_deadline\": \"2022-01-10\", \"kev_known_ransomware\": false}, "                \
  "{\"cve_id\": \"CVE-2020-28500\", \"in_kev\": false, \"poc_count\": 0, \"risk_label\": \"MEDIUM\", \"risk_score\": 5.3, " \
  "\"has_metasploit\": true, \"kev_patch_deadline\": null, \"kev_known_ransomware\": true}]"

static const char* const g_packageRowFix[] = {
  "item_id", "20", "item_endpoint_name", "package_check", "item_ecosystem", "npm", "item_package_name", "lodash", "item_version", "4.17.20",
  FLAGS_FIRST_ADVISORY("1"), "event_type", "fix_available", "changed_at", "2026-10-20T01:02:03Z",
  "advisory_id", "GHSA-p6mc-m468-83gw", "fixed_version", "4.17.21", "affects_version", "t", "advisory_source", "ghsa",
  "advisory_aliases", PACKAGE_ALIASES_LODASH, "advisory_cve_facts", PACKAGE_ALIAS_FACTS_LODASH, "attribution", PACKAGE_ATTRIBUTION, NULL
};
static const char* const g_packageRowKev[] = {
  "item_id", "20", "item_endpoint_name", "package_check", "item_ecosystem", "npm", "item_package_name", "lodash", "item_version", "4.17.20",
  FLAGS_FIRST_CVE("2"), "event_type", "kev_added", "changed_at", "2026-10-20T01:02:04Z", "cve_id", "CVE-2021-23337", FACTS_OTHER,
  "affects_version", "t", NULL
};
static const char* const g_packageRowNoVersion[] = {
  "item_id", "21", "item_endpoint_name", "package_check", "item_ecosystem", "npm", "item_package_name", "Lodash",
  FLAGS_LATER("1"), "event_type", "malware_added", "changed_at", "2026-10-20T09:09:09Z", "advisory_id", "MAL-2099-0001",
  "fixed_version", "9.9.9", NULL
};
static const char* const g_packageRowMalware[] = {
  "item_id", "22", "item_endpoint_name", "package_check", "item_ecosystem", "PyPI", "item_package_name", "requests-x", "item_version", "0.0.1",
  FLAGS_FIRST_ADVISORY("3"), "event_type", "malware_added", "changed_at", "2026-10-20T01:02:05Z", "advisory_id", "MAL-2026-0001",
  "advisory_source", "mal", "advisory_aliases", "[]", "advisory_cve_facts", "[]", NULL
};
static const char* const* const g_packageRows[] = { g_packageRowFix, g_packageRowKev, g_packageRowNoVersion, g_packageRowMalware };
#define PACKAGE_ROW_COUNT 4

static const char* const g_kindRowCve[] = {
  "item_id", "1", "item_endpoint_name", "cve_lookup", "item_cve_id", "CVE-2021-44228",
  FLAGS_FIRST_CVE("1"), "event_type", "kev_added", "changed_at", "2026-10-21T01:00:01Z", "cve_id", "CVE-2021-44228", FACTS_LOG4J, NULL
};
static const char* const g_kindRowDns[] = {
  "item_id", "2", "item_endpoint_name", "dns_lookup", "item_domain_name", "dns.example.com",
  FLAGS_FIRST_EVENT("2"), "event_type", "ns_changed", "changed_at", "2026-10-21T01:00:02Z",
  "previous_domain_value", "ns1.dns.example", "current_domain_value", "ns2.dns.example", NULL
};
static const char* const g_kindRowSsl[] = {
  "item_id", "3", "item_endpoint_name", "ssl_check", "item_domain_name", "tls.example.com",
  FLAGS_FIRST_DOMAIN("3"), "event_type", "tls_downgraded", "changed_at", "2026-10-21T01:00:03Z",
  "previous_domain_value", "TLSv1.3", "current_domain_value", "TLSv1.1", "registered_domain", "example.com", NULL
};
static const char* const g_kindRowWhois[] = {
  "item_id", "4", "item_endpoint_name", "whois_lookup", "item_domain_name", "example.org",
  FLAGS_FIRST_EVENT("4"), "event_type", "dnssec_disabled", "changed_at", "2026-10-21T01:00:04Z",
  "previous_domain_value", "signed", "current_domain_value", "unsigned", NULL
};
static const char* const g_kindRowHeaders[] = {
  "item_id", "5", "item_endpoint_name", "headers_check", "item_domain_name", "www.example.net",
  FLAGS_FIRST_EVENT("5"), "event_type", "security_header_removed", "changed_at", "2026-10-21T01:00:05Z",
  "previous_domain_value", "https://www.example.net/\nx-frame-options", "current_domain_value", "https://www.example.net/", NULL
};
static const char* const g_kindRowCert[] = {
  "item_id", "6", "item_endpoint_name", "cert_search", "item_domain_name", "ct.example.com",
  FLAGS_FIRST_EVENT("6"), "event_type", "cert_unexpected", "changed_at", "2026-10-21T01:00:06Z",
  "previous_domain_value", "issuer-a", "current_domain_value", "known issuer-a\nnew_issuer issuer-b", NULL
};
static const char* const g_kindRowPackage[] = {
  "item_id", "7", "item_endpoint_name", "package_check", "item_ecosystem", "PyPI", "item_package_name", "requests-x",
  FLAGS_FIRST_ADVISORY("7"), "event_type", "malware_added", "changed_at", "2026-10-21T01:00:07Z", "advisory_id", "MAL-2026-0007",
  "advisory_source", "mal", "advisory_aliases", "[]", "advisory_cve_facts", "[]", NULL
};
static const char* const g_kindRowIp[] = {
  "item_id", "8", "item_endpoint_name", "ip_lookup", "item_ip_address", "192.0.2.8",
  FLAGS_FIRST_EVENT("8"), "event_type", "drop_unlisted", "changed_at", "2026-10-21T01:00:08Z",
  "previous_ip_value", "192.0.2.0/24 SBL123", "current_ip_value", "", "drop_list_time", "2026-10-20T23:00:00Z",
  "drop_copyright", "(c) 2026 The Spamhaus Project SLM", NULL
};
static const char* const g_kindRowEol[] = {
  "item_id", "9", "item_endpoint_name", "product_exposure", "item_vendor", "f5", "item_product", "nginx", "item_product_has_cves", "t",
  FLAGS_FIRST_EVENT("9"), "event_type", "eol_approaching", "changed_at", "2026-10-21T01:00:09Z", "eol_product", "nginx",
  "eol_cycle", "1.24", "eol_date", "2026-11-30", NULL
};
static const char* const* const g_kindRows[] = {
  g_kindRowCve, g_kindRowDns, g_kindRowSsl, g_kindRowWhois, g_kindRowHeaders, g_kindRowCert, g_kindRowPackage, g_kindRowIp,
  g_kindRowEol
};
#define KIND_ROW_COUNT 9

#define KIND_FAILED_COPY_COUNT 14

void test_WATCHLISTEVENTS_fills_and_frees_an_event_of_each_kind(void)
{
  RequestCreditBudget_t budget;
  static_watchlistBudget(&budget);
  WATCHLISTEVENTSParams_t params;
  static_watchlistEventsParams(&params, &budget);

  static_resetFake();
  static_queueEventsAnswer(g_kindRows, KIND_ROW_COUNT);
  WATCHLISTEVENTSResult_t result;
  memset(&result, 0xA5, sizeof(result));
  g_dirtyMalloc = true;
  TEST_ASSERT_EQUAL_INT(DB_OK, db_WATCHLISTEVENTS(FAKE_CONN, &params, 20, &result));
  g_dirtyMalloc = false;
  TEST_ASSERT_EQUAL_INT(KIND_ROW_COUNT, result.m_eventCount);
  TEST_ASSERT_EQUAL_INT(KIND_ROW_COUNT, result.m_answerItemCount);

  const WATCHLISTEVENTSEvent_t* events = result.mp_events;
  TEST_ASSERT_EQUAL_INT(WATCHLIST_EVENT_CVE, events[0].m_eventKind);
  TEST_ASSERT_EQUAL_STRING("CVE-2021-44228", events[0].m_cveChange.ma_cveId);
  TEST_ASSERT_EQUAL_INT(WATCHLIST_EVENT_DNS_LOOKUP, events[1].m_eventKind);
  TEST_ASSERT_EQUAL_STRING("", events[1].m_dnsLookupChange.ma_degradedEmailCheckId);
  TEST_ASSERT_EQUAL_STRING("ns1.dns.example", events[1].m_dnsLookupChange.mp_previousValue);
  TEST_ASSERT_EQUAL_STRING("ns2.dns.example", events[1].m_dnsLookupChange.mp_currentValue);
  TEST_ASSERT_EQUAL_INT(WATCHLIST_EVENT_SSL_CHECK, events[2].m_eventKind);
  TEST_ASSERT_EQUAL_STRING("TLSv1.3", events[2].m_sslCheckChange.mp_previousValue);
  TEST_ASSERT_EQUAL_STRING("TLSv1.1", events[2].m_sslCheckChange.mp_currentValue);
  TEST_ASSERT_EQUAL_INT(WATCHLIST_EVENT_WHOIS_LOOKUP, events[3].m_eventKind);
  TEST_ASSERT_EQUAL_STRING("signed", events[3].m_whoisLookupChange.mp_previousValue);
  TEST_ASSERT_EQUAL_STRING("unsigned", events[3].m_whoisLookupChange.mp_currentValue);
  TEST_ASSERT_EQUAL_INT(WATCHLIST_EVENT_HEADERS_CHECK, events[4].m_eventKind);
  TEST_ASSERT_EQUAL_STRING("https://www.example.net/\nx-frame-options", events[4].m_headersCheckChange.mp_previousValue);
  TEST_ASSERT_EQUAL_STRING("https://www.example.net/", events[4].m_headersCheckChange.mp_currentValue);
  TEST_ASSERT_EQUAL_INT(WATCHLIST_EVENT_CERT_SEARCH, events[5].m_eventKind);
  TEST_ASSERT_EQUAL_STRING("issuer-a", events[5].m_certSearchChange.mp_previousValue);
  TEST_ASSERT_EQUAL_STRING("known issuer-a\nnew_issuer issuer-b", events[5].m_certSearchChange.mp_currentValue);
  TEST_ASSERT_EQUAL_INT(WATCHLIST_EVENT_PACKAGE_CHECK, events[6].m_eventKind);
  TEST_ASSERT_EQUAL_STRING("MAL-2026-0007", events[6].m_packageCheckChange.ma_advisoryId);
  TEST_ASSERT_EQUAL_STRING("", events[6].m_packageCheckChange.ma_fixedVersion);
  TEST_ASSERT_EQUAL_INT(WATCHLIST_EVENT_IP_LOOKUP, events[7].m_eventKind);
  TEST_ASSERT_EQUAL_STRING("drop_unlisted", events[7].ma_eventType);
  TEST_ASSERT_EQUAL_STRING("192.0.2.0/24 SBL123", events[7].m_ipLookupChange.mp_previousValue);
  TEST_ASSERT_EQUAL_STRING("", events[7].m_ipLookupChange.mp_currentValue);
  TEST_ASSERT_EQUAL_STRING("2026-10-20T23:00:00Z", events[7].m_ipLookupChange.ma_dropListTime);
  TEST_ASSERT_EQUAL_STRING("(c) 2026 The Spamhaus Project SLM", events[7].m_ipLookupChange.ma_dropCopyright);
  TEST_ASSERT_EQUAL_INT(WATCHLIST_EVENT_PRODUCT_EXPOSURE, events[8].m_eventKind);
  TEST_ASSERT_EQUAL_STRING("nginx", events[8].m_productExposureChange.ma_eolProduct);
  TEST_ASSERT_EQUAL_STRING("1.24", events[8].m_productExposureChange.ma_cycle);

  static const WatchlistItemKind_t item_kinds[KIND_ROW_COUNT] = {
    WATCHLIST_ITEM_CVE_LOOKUP, WATCHLIST_ITEM_DNS_LOOKUP, WATCHLIST_ITEM_SSL_CHECK, WATCHLIST_ITEM_WHOIS_LOOKUP,
    WATCHLIST_ITEM_HEADERS_CHECK, WATCHLIST_ITEM_CERT_SEARCH, WATCHLIST_ITEM_PACKAGE_CHECK, WATCHLIST_ITEM_IP_LOOKUP,
    WATCHLIST_ITEM_PRODUCT_EXPOSURE,
  };
  for (int i = 0; i < KIND_ROW_COUNT; i++)
    TEST_ASSERT_EQUAL_INT(item_kinds[i], result.mp_answerItems[i].m_item.m_itemKind);
  TEST_ASSERT_EQUAL_STRING("dns.example.com", result.mp_answerItems[1].m_item.m_dnsLookup.ma_domainName);
  TEST_ASSERT_EQUAL_STRING("tls.example.com", result.mp_answerItems[2].m_item.m_sslCheck.ma_domainName);
  TEST_ASSERT_EQUAL_STRING("example.org", result.mp_answerItems[3].m_item.m_whoisLookup.ma_domainName);
  TEST_ASSERT_EQUAL_STRING("www.example.net", result.mp_answerItems[4].m_item.m_headersCheck.ma_domainName);
  TEST_ASSERT_EQUAL_STRING("ct.example.com", result.mp_answerItems[5].m_item.m_certSearch.ma_domainName);
  TEST_ASSERT_EQUAL_STRING("192.0.2.8", result.mp_answerItems[7].m_item.m_ipLookup.ma_ipAddress);
  TEST_ASSERT_EQUAL_INT(1, result.m_domainFactCount);
  TEST_ASSERT_EQUAL_STRING("tls.example.com", result.mp_domainFacts[0].ma_domainName);
  TEST_ASSERT_EQUAL_STRING("example.com", result.mp_domainFacts[0].ma_registeredDomain);

  db_WATCHLISTEVENTSResultFree(&result);
  TEST_ASSERT_NULL(result.mp_events);
  TEST_ASSERT_EQUAL_INT(0, result.m_eventCount);
  TEST_ASSERT_NULL(result.mp_answerItems);
  TEST_ASSERT_NULL(result.mp_domainFacts);
}

void test_WATCHLISTEVENTS_frees_a_half_filled_answer_of_each_kind(void)
{
  RequestCreditBudget_t budget;
  static_watchlistBudget(&budget);
  WATCHLISTEVENTSParams_t params;
  static_watchlistEventsParams(&params, &budget);

  int failed_count = 0;
  bool is_read = false;
  for (int n = 1; n <= 40 && !is_read; n++)
  {
    static_resetFake();
    static_queueEventsAnswer(g_kindRows, KIND_ROW_COUNT);
    g_strdupFailsAtCall = n;
    WATCHLISTEVENTSResult_t result;
    memset(&result, 0xA5, sizeof(result));
    DbStatus_t status = db_WATCHLISTEVENTS(FAKE_CONN, &params, 20, &result);
    if (status == DB_OK)
    {
      db_WATCHLISTEVENTSResultFree(&result);
      is_read = true;
      break;
    }
    char label[32];
    snprintf(label, sizeof(label), "strdup call %d", n);
    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_ERROR, status, label);
    TEST_ASSERT_NULL_MESSAGE(result.mp_events, label);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, result.m_eventCount, label);
    TEST_ASSERT_NULL_MESSAGE(result.mp_domainFacts, label);
    failed_count++;
  }
  TEST_ASSERT_TRUE(is_read);
  TEST_ASSERT_EQUAL_INT(KIND_FAILED_COPY_COUNT, failed_count);
}

void test_WATCHLISTEVENTS_reads_package_events_and_advisories(void)
{
  RequestCreditBudget_t budget;
  static_watchlistBudget(&budget);
  WATCHLISTEVENTSParams_t params;
  static_watchlistEventsParams(&params, &budget);

  static_resetFake();
  static_queueEventsAnswer(g_packageRows, PACKAGE_ROW_COUNT);
  WATCHLISTEVENTSResult_t result;
  memset(&result, 0xA5, sizeof(result));
  g_dirtyMalloc = true;
  TEST_ASSERT_EQUAL_INT(DB_OK, db_WATCHLISTEVENTS(FAKE_CONN, &params, 20, &result));
  g_dirtyMalloc = false;

  TEST_ASSERT_EQUAL_INT(3, result.m_eventCount);
  const WATCHLISTEVENTSEvent_t* fix = &result.mp_events[0];
  TEST_ASSERT_EQUAL_INT(WATCHLIST_EVENT_PACKAGE_CHECK, fix->m_eventKind);
  TEST_ASSERT_EQUAL_STRING("fix_available", fix->ma_eventType);
  TEST_ASSERT_EQUAL_STRING("2026-10-20T01:02:03Z", fix->ma_changedAt);
  TEST_ASSERT_EQUAL_STRING("GHSA-p6mc-m468-83gw", fix->m_packageCheckChange.ma_advisoryId);
  TEST_ASSERT_EQUAL_STRING("4.17.21", fix->m_packageCheckChange.ma_fixedVersion);
  const WATCHLISTEVENTSEvent_t* kev = &result.mp_events[1];
  TEST_ASSERT_EQUAL_INT(WATCHLIST_EVENT_CVE, kev->m_eventKind);
  TEST_ASSERT_EQUAL_STRING("kev_added", kev->ma_eventType);
  TEST_ASSERT_EQUAL_STRING("CVE-2021-23337", kev->m_cveChange.ma_cveId);
  const WATCHLISTEVENTSEvent_t* malware = &result.mp_events[2];
  TEST_ASSERT_EQUAL_INT(WATCHLIST_EVENT_PACKAGE_CHECK, malware->m_eventKind);
  TEST_ASSERT_EQUAL_STRING("malware_added", malware->ma_eventType);
  TEST_ASSERT_EQUAL_STRING("MAL-2026-0001", malware->m_packageCheckChange.ma_advisoryId);
  TEST_ASSERT_EQUAL_STRING("", malware->m_packageCheckChange.ma_fixedVersion);

  TEST_ASSERT_EQUAL_INT(3, result.m_answerItemCount);
  const struct { const char* mp_ecosystem; const char* mp_name; const char* mp_version; int m_firstPairIndex; int m_pairCount; } items[] = {
    { "npm",  "lodash",     "4.17.20", 0, 2 },
    { "npm",  "Lodash",     "",        2, 1 },
    { "PyPI", "requests-x", "0.0.1",   3, 1 },
  };
  for (int i = 0; i < 3; i++)
  {
    const WATCHLISTEVENTSAnswerItem_t* answer_item = &result.mp_answerItems[i];
    TEST_ASSERT_EQUAL_STRING("package_check", watchlist_findEndpointName(answer_item->m_item.m_itemKind));
    TEST_ASSERT_EQUAL_INT(WATCHLIST_ITEM_PACKAGE_CHECK, answer_item->m_item.m_itemKind);
    TEST_ASSERT_EQUAL_STRING(items[i].mp_ecosystem, answer_item->m_item.m_packageCheck.ma_ecosystem);
    TEST_ASSERT_EQUAL_STRING(items[i].mp_name, answer_item->m_item.m_packageCheck.ma_name);
    TEST_ASSERT_EQUAL_STRING(items[i].mp_version, answer_item->m_item.m_packageCheck.ma_version);
    TEST_ASSERT_EQUAL_INT(items[i].m_firstPairIndex, answer_item->m_firstPairIndex);
    TEST_ASSERT_EQUAL_INT(items[i].m_pairCount, answer_item->m_pairCount);
  }

  TEST_ASSERT_EQUAL_INT(4, result.m_pairCount);
  const int pairs[] = { 0, 1, 0, 2 };
  TEST_ASSERT_EQUAL_INT_ARRAY(pairs, result.mp_pairEventIndexes, 4);
  TEST_ASSERT_NOT_NULL(result.mp_pairIsVersionAffected);
  TEST_ASSERT_TRUE(result.mp_pairIsVersionAffected[0]);
  TEST_ASSERT_TRUE(result.mp_pairIsVersionAffected[1]);
  TEST_ASSERT_FALSE(result.mp_pairIsVersionAffected[2]);
  TEST_ASSERT_FALSE(result.mp_pairIsVersionAffected[3]);

  TEST_ASSERT_EQUAL_INT(3, result.m_cveFactCount);
  const WATCHLISTEVENTSCveFacts_t* alias_first = &result.mp_cveFacts[0];
  TEST_ASSERT_EQUAL_STRING("CVE-2020-8203", alias_first->ma_cveId);
  TEST_ASSERT_EQUAL_FLOAT(72.5, alias_first->m_riskScore);
  TEST_ASSERT_EQUAL_STRING("HIGH", alias_first->ma_riskLabel);
  TEST_ASSERT_TRUE(alias_first->m_isInKev);
  TEST_ASSERT_TRUE(alias_first->m_hasKev);
  TEST_ASSERT_EQUAL_STRING("2022-01-10", alias_first->ma_kevPatchDeadline);
  TEST_ASSERT_FALSE(alias_first->m_kevKnownRansomware);
  TEST_ASSERT_TRUE(alias_first->m_hasMetasploit);
  TEST_ASSERT_EQUAL_INT(4, alias_first->m_pocCount);
  const WATCHLISTEVENTSCveFacts_t* alias_second = &result.mp_cveFacts[1];
  TEST_ASSERT_EQUAL_STRING("CVE-2020-28500", alias_second->ma_cveId);
  TEST_ASSERT_EQUAL_FLOAT(5.3, alias_second->m_riskScore);
  TEST_ASSERT_EQUAL_STRING("MEDIUM", alias_second->ma_riskLabel);
  TEST_ASSERT_FALSE(alias_second->m_isInKev);
  TEST_ASSERT_FALSE(alias_second->m_hasKev);
  TEST_ASSERT_EQUAL_STRING("", alias_second->ma_kevPatchDeadline);
  TEST_ASSERT_TRUE(alias_second->m_kevKnownRansomware);
  TEST_ASSERT_TRUE(alias_second->m_hasMetasploit);
  TEST_ASSERT_EQUAL_INT(0, alias_second->m_pocCount);
  TEST_ASSERT_EQUAL_STRING("CVE-2021-23337", result.mp_cveFacts[2].ma_cveId);
  TEST_ASSERT_EQUAL_INT(12, result.mp_cveFacts[2].m_pocCount);
  TEST_ASSERT_EQUAL_INT(0, result.m_domainFactCount);

  TEST_ASSERT_EQUAL_INT(2, result.m_advisoryCount);
  TEST_ASSERT_EQUAL_STRING("GHSA-p6mc-m468-83gw", result.mp_advisories[0].ma_advisoryId);
  TEST_ASSERT_EQUAL_STRING("ghsa", result.mp_advisories[0].ma_source);
  TEST_ASSERT_EQUAL_STRING(PACKAGE_ALIASES_LODASH, result.mp_advisories[0].mp_aliases);
  TEST_ASSERT_EQUAL_STRING("MAL-2026-0001", result.mp_advisories[1].ma_advisoryId);
  TEST_ASSERT_EQUAL_STRING("mal", result.mp_advisories[1].ma_source);
  TEST_ASSERT_EQUAL_STRING("[]", result.mp_advisories[1].mp_aliases);
  TEST_ASSERT_EQUAL_STRING(PACKAGE_ATTRIBUTION, result.mp_attribution);

  db_WATCHLISTEVENTSResultFree(&result);
  TEST_ASSERT_NULL(result.mp_events);
  TEST_ASSERT_NULL(result.mp_pairEventIndexes);
  TEST_ASSERT_NULL(result.mp_pairIsVersionAffected);
  TEST_ASSERT_NULL(result.mp_cveFacts);
  TEST_ASSERT_NULL(result.mp_advisories);
  TEST_ASSERT_NULL(result.mp_attribution);
  TEST_ASSERT_EQUAL_INT(0, result.m_advisoryCount);
  TEST_ASSERT_EQUAL_INT(0, result.m_pairCount);
  db_WATCHLISTEVENTSResultFree(&result);

  static_resetFake();
  static const char* const* const malware_alone[] = { g_packageRowMalware };
  FakeAnswer_t* answer = static_queueEventsAnswer(malware_alone, 1);
  answer->ma_cells[0][static_eventsColumn("event_rank")]      = "1";
  answer->ma_cells[0][static_eventsColumn("advisory_source")] = FAKE_SQL_NULL;
  TEST_ASSERT_EQUAL_INT(DB_OK, db_WATCHLISTEVENTS(FAKE_CONN, &params, 20, &result));
  TEST_ASSERT_EQUAL_INT(1, result.m_advisoryCount);
  TEST_ASSERT_EQUAL_STRING("", result.mp_advisories[0].ma_source);
  TEST_ASSERT_EQUAL_STRING("[]", result.mp_attribution);
  db_WATCHLISTEVENTSResultFree(&result);
}

void test_WATCHLISTEVENTS_takes_the_event_kind_from_the_row(void)
{
  RequestCreditBudget_t budget;
  static_watchlistBudget(&budget);
  WATCHLISTEVENTSParams_t params;
  static_watchlistEventsParams(&params, &budget);

  static const char* const cve_item_advisory[] = {
    "item_id", "1", "item_endpoint_name", "cve_lookup", "item_cve_id", "CVE-2021-44228",
    FLAGS_FIRST_ADVISORY("1"), "event_type", "advisory_added", "changed_at", "2026-10-20T01:02:03Z", "advisory_id", "GHSA-aaaa-bbbb-cccc",
    "advisory_aliases", "[]", "advisory_cve_facts", "[]", NULL
  };
  static const char* const domain_item_advisory[] = {
    "item_id", "1", "item_endpoint_name", "dns_lookup", "item_domain_name", "example.com",
    FLAGS_FIRST_ADVISORY("1"), "event_type", "advisory_added", "changed_at", "2026-10-20T01:02:03Z", "advisory_id", "GHSA-aaaa-bbbb-cccc",
    "advisory_aliases", "[]", "advisory_cve_facts", "[]", NULL
  };
  static const char* const domain_item_domain[] = {
    "item_id", "1", "item_endpoint_name", "dns_lookup", "item_domain_name", "example.com",
    FLAGS_FIRST_EVENT("1"), "event_type", "ns_changed", "changed_at", "2026-10-20T01:02:03Z", NULL
  };
  static const char* const package_item_cve[] = {
    "item_id", "1", "item_endpoint_name", "package_check", "item_ecosystem", "npm", "item_package_name", "lodash",
    FLAGS_FIRST_EVENT("1"), "event_type", "ransomware_linked", "changed_at", "2026-10-20T01:02:03Z", "cve_id", "CVE-2021-23337", NULL
  };
  static const char* const ip_item_hosting[] = {
    "item_id", "1", "item_endpoint_name", "ip_lookup", "item_ip_address", "2001:db8::1",
    FLAGS_FIRST_EVENT("1"), "event_type", "hosting_changed", "changed_at", "2026-10-20T01:02:03Z",
    "previous_ip_value", "AS64510", "current_ip_value", "aws/ec2", NULL
  };
  static const char* const product_item_cve[] = {
    "item_id", "1", "item_endpoint_name", "product_exposure", "item_vendor", "f5", "item_product", "nginx", "item_product_has_cves", "t",
    FLAGS_FIRST_EVENT("1"), "event_type", "product_added", "changed_at", "2026-10-20T01:02:03Z", "cve_id", "CVE-2021-23017", NULL
  };
  static const char* const cve_item_eol[] = {
    "item_id", "1", "item_endpoint_name", "cve_lookup", "item_cve_id", "CVE-2021-44228",
    FLAGS_FIRST_EVENT("1"), "event_type", "eol_reached", "changed_at", "2026-10-20T01:02:03Z", "eol_product", "nginx", "eol_cycle", "1.24", NULL
  };
  const struct { const char* const* mp_row; WatchlistEventKind_t m_kind; } cases[] = {
    { cve_item_advisory,    WATCHLIST_EVENT_PACKAGE_CHECK },
    { domain_item_advisory, WATCHLIST_EVENT_PACKAGE_CHECK },
    { domain_item_domain,   WATCHLIST_EVENT_DNS_LOOKUP },
    { package_item_cve,     WATCHLIST_EVENT_CVE },
    { ip_item_hosting,      WATCHLIST_EVENT_IP_LOOKUP },
    { product_item_cve,     WATCHLIST_EVENT_CVE },
    { cve_item_eol,         WATCHLIST_EVENT_PRODUCT_EXPOSURE },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    static_resetFake();
    const char* const* const rows[] = { cases[i].mp_row };
    static_queueEventsAnswer(rows, 1);
    WATCHLISTEVENTSResult_t result;
    char label[16];
    snprintf(label, sizeof(label), "case %zu", i);
    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_OK, db_WATCHLISTEVENTS(FAKE_CONN, &params, 20, &result), label);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_kind, result.mp_events[0].m_eventKind, label);
    db_WATCHLISTEVENTSResultFree(&result);
  }
}

static const char* static_fillText(char* buf, size_t buf_size, const char* prefix, char letter, size_t byte_count)
{
  TEST_ASSERT_TRUE(byte_count < buf_size);
  memset(buf, letter, byte_count);
  buf[byte_count] = '\0';
  size_t prefix_length = strlen(prefix);
  TEST_ASSERT_TRUE(prefix_length <= byte_count);
  memcpy(buf, prefix, prefix_length);
  return buf;
}

#define EOL_ATTRIBUTION "[{\"url\": \"https://endoflife.date\", \"notice\": \"Retrieved from endoflife.date.\", " \
                        "\"source\": \"endoflife.date\", \"license\": \"MIT\"}]"

static const char* const g_eolRowApproaching[] = {
  "item_id", "30", "item_endpoint_name", "product_exposure", "item_vendor", "f5", "item_product", "nginx", "item_product_has_cves", "t",
  "item_version", "1.24.0",
  FLAGS_FIRST_EVENT("1"), "event_type", "eol_approaching", "changed_at", "2026-11-01T01:02:03Z",
  "eol_product", "nginx", "eol_cycle", "1.24", "eol_date", "2026-11-30", "attribution", EOL_ATTRIBUTION, NULL
};
static const char* const g_eolRowDateChanged[] = {
  "item_id", "30", "item_endpoint_name", "product_exposure", "item_vendor", "f5", "item_product", "nginx", "item_product_has_cves", "t",
  "item_version", "1.24.0",
  FLAGS_FIRST_EVENT("2"), "event_type", "eol_date_changed", "changed_at", "2026-11-02T01:02:03Z",
  "eol_product", "nginx", "eol_cycle", "1.24", "eol_date", "2027-05-31", "previous_eol_date", "2026-11-30", NULL
};
static const char* const g_eolRowReached[] = {
  "item_id", "31", "item_endpoint_name", "product_exposure", "item_vendor", "f5", "item_product", "nginx", "item_product_has_cves", "f",
  FLAGS_FIRST_EVENT("3"), "event_type", "eol_reached", "changed_at", "2026-11-03T01:02:03Z",
  "eol_product", "nginx-plus", "eol_cycle", "r30", NULL
};
static const char* const* const g_eolRows[] = { g_eolRowApproaching, g_eolRowDateChanged, g_eolRowReached };
#define EOL_ROW_COUNT 3

void test_WATCHLISTEVENTS_reads_eol_events(void)
{
  RequestCreditBudget_t budget;
  static_watchlistBudget(&budget);
  WATCHLISTEVENTSParams_t params;
  static_watchlistEventsParams(&params, &budget);

  static_resetFake();
  static_queueEventsAnswer(g_eolRows, EOL_ROW_COUNT);
  WATCHLISTEVENTSResult_t result;
  memset(&result, 0xA5, sizeof(result));
  g_dirtyMalloc = true;
  TEST_ASSERT_EQUAL_INT(DB_OK, db_WATCHLISTEVENTS(FAKE_CONN, &params, 20, &result));
  g_dirtyMalloc = false;

  TEST_ASSERT_EQUAL_INT(EOL_ROW_COUNT, result.m_eventCount);
  const struct { const char* mp_type; const char* mp_changedAt; const char* mp_product; const char* mp_cycle; const char* mp_date; const char* mp_previousDate; } events[] = {
    { "eol_approaching",  "2026-11-01T01:02:03Z", "nginx",      "1.24", "2026-11-30", ""           },
    { "eol_date_changed", "2026-11-02T01:02:03Z", "nginx",      "1.24", "2027-05-31", "2026-11-30" },
    { "eol_reached",      "2026-11-03T01:02:03Z", "nginx-plus", "r30",  "",           ""           },
  };
  for (int e = 0; e < EOL_ROW_COUNT; e++)
  {
    const WATCHLISTEVENTSEvent_t* event = &result.mp_events[e];
    TEST_ASSERT_EQUAL_INT_MESSAGE(WATCHLIST_EVENT_PRODUCT_EXPOSURE, event->m_eventKind, events[e].mp_type);
    TEST_ASSERT_EQUAL_STRING(events[e].mp_type, event->ma_eventType);
    TEST_ASSERT_EQUAL_STRING(events[e].mp_changedAt, event->ma_changedAt);
    TEST_ASSERT_EQUAL_STRING(events[e].mp_product, event->m_productExposureChange.ma_eolProduct);
    TEST_ASSERT_EQUAL_STRING(events[e].mp_cycle, event->m_productExposureChange.ma_cycle);
    TEST_ASSERT_EQUAL_STRING(events[e].mp_date, event->m_productExposureChange.ma_eolDate);
    TEST_ASSERT_EQUAL_STRING(events[e].mp_previousDate, event->m_productExposureChange.ma_previousEolDate);
  }

  TEST_ASSERT_EQUAL_INT(2, result.m_answerItemCount);
  TEST_ASSERT_EQUAL_INT(WATCHLIST_ITEM_PRODUCT_EXPOSURE, result.mp_answerItems[0].m_item.m_itemKind);
  TEST_ASSERT_EQUAL_STRING("1.24.0", result.mp_answerItems[0].m_item.m_productExposure.ma_version);
  TEST_ASSERT_EQUAL_INT(2, result.mp_answerItems[0].m_pairCount);
  TEST_ASSERT_EQUAL_INT(WATCHLIST_ITEM_PRODUCT_EXPOSURE, result.mp_answerItems[1].m_item.m_itemKind);
  TEST_ASSERT_EQUAL_STRING("", result.mp_answerItems[1].m_item.m_productExposure.ma_version);
  TEST_ASSERT_EQUAL_INT(1, result.mp_answerItems[1].m_pairCount);
  TEST_ASSERT_EQUAL_INT(3, result.m_pairCount);
  const int pairs[] = { 0, 1, 2 };
  TEST_ASSERT_EQUAL_INT_ARRAY(pairs, result.mp_pairEventIndexes, 3);
  TEST_ASSERT_EQUAL_INT(0, result.m_cveFactCount);
  TEST_ASSERT_EQUAL_INT(0, result.m_domainFactCount);
  TEST_ASSERT_EQUAL_INT(0, result.m_advisoryCount);
  TEST_ASSERT_EQUAL_STRING(EOL_ATTRIBUTION, result.mp_attribution);
  db_WATCHLISTEVENTSResultFree(&result);
  TEST_ASSERT_NULL(result.mp_events);
  TEST_ASSERT_NULL(result.mp_attribution);
}

void test_WATCHLISTEVENTS_reads_eol_texts_at_their_limits(void)
{
  RequestCreditBudget_t budget;
  static_watchlistBudget(&budget);
  WATCHLISTEVENTSParams_t params;
  static_watchlistEventsParams(&params, &budget);

  TEST_ASSERT_EQUAL_INT(64, PRODUCTEXPOSURE_EOL_PRODUCT_MAX_LEN);
  TEST_ASSERT_EQUAL_INT(100, PRODUCTEXPOSURE_EOL_CYCLE_NAME_MAX_LEN);
  TEST_ASSERT_EQUAL_INT(10, PRODUCTEXPOSURE_EOL_DATE_LEN);
  char product[PRODUCTEXPOSURE_EOL_PRODUCT_MAX_LEN + 1];
  char cycle[PRODUCTEXPOSURE_EOL_CYCLE_NAME_MAX_LEN + 1];
  static_fillText(product, sizeof(product), "p", 'p', PRODUCTEXPOSURE_EOL_PRODUCT_MAX_LEN);
  static_fillText(cycle, sizeof(cycle), "c", 'c', PRODUCTEXPOSURE_EOL_CYCLE_NAME_MAX_LEN);
  static const char* const* const date_changed_alone[] = { g_eolRowDateChanged };
  static_resetFake();
  FakeAnswer_t* answer = static_queueEventsAnswer(date_changed_alone, 1);
  answer->ma_cells[0][static_eventsColumn("event_rank")]  = "1";
  answer->ma_cells[0][static_eventsColumn("eol_product")] = product;
  answer->ma_cells[0][static_eventsColumn("eol_cycle")]   = cycle;
  WATCHLISTEVENTSResult_t result;
  TEST_ASSERT_EQUAL_INT(DB_OK, db_WATCHLISTEVENTS(FAKE_CONN, &params, 20, &result));
  TEST_ASSERT_EQUAL_STRING(product, result.mp_events[0].m_productExposureChange.ma_eolProduct);
  TEST_ASSERT_EQUAL_STRING(cycle, result.mp_events[0].m_productExposureChange.ma_cycle);
  TEST_ASSERT_EQUAL_STRING("2027-05-31", result.mp_events[0].m_productExposureChange.ma_eolDate);
  TEST_ASSERT_EQUAL_STRING("2026-11-30", result.mp_events[0].m_productExposureChange.ma_previousEolDate);
  db_WATCHLISTEVENTSResultFree(&result);
}

void test_WATCHLISTEVENTS_refuses_each_broken_eol_row(void)
{
  RequestCreditBudget_t budget;
  static_watchlistBudget(&budget);
  WATCHLISTEVENTSParams_t params;
  static_watchlistEventsParams(&params, &budget);

  char long_product[PRODUCTEXPOSURE_EOL_PRODUCT_MAX_LEN + 2];
  char long_cycle[PRODUCTEXPOSURE_EOL_CYCLE_NAME_MAX_LEN + 2];
  static_fillText(long_product, sizeof(long_product), "p", 'p', PRODUCTEXPOSURE_EOL_PRODUCT_MAX_LEN + 1);
  static_fillText(long_cycle, sizeof(long_cycle), "c", 'c', PRODUCTEXPOSURE_EOL_CYCLE_NAME_MAX_LEN + 1);

  const struct { const char* mp_label; int m_row; const char* mp_column; const char* mp_cell; } refused[] = {
    { "an EOL event type it does not know",           0, "event_type",        "eol_moved" },
    { "a CVE event type on an EOL row",               2, "event_type",        "product_added" },
    { "a NULL eol_cycle",                             0, "eol_cycle",         NULL },
    { "a NULL eol_date on eol_approaching",           0, "eol_date",          NULL },
    { "a NULL eol_date on eol_date_changed",          1, "eol_date",          NULL },
    { "a previous_eol_date on eol_approaching",       0, "previous_eol_date", "2026-01-31" },
    { "a previous_eol_date on eol_reached",           2, "previous_eol_date", "2026-01-31" },
    { "a NULL previous_eol_date on eol_date_changed", 1, "previous_eol_date", NULL },
    { "an eol_product past its field",                0, "eol_product",       long_product },
    { "an eol_cycle past its field",                  2, "eol_cycle",         long_cycle },
    { "an eol_date past its field",                   0, "eol_date",          "2026-11-30T" },
    { "a previous_eol_date past its field",           1, "previous_eol_date", "2026-11-30T" },
  };
  for (size_t i = 0; i < sizeof(refused) / sizeof(refused[0]); i++)
  {
    static_resetFake();
    FakeAnswer_t* answer = static_queueEventsAnswer(g_eolRows, EOL_ROW_COUNT);
    answer->ma_cells[refused[i].m_row][static_eventsColumn(refused[i].mp_column)] = refused[i].mp_cell != NULL ? refused[i].mp_cell : FAKE_SQL_NULL;
    static_assertEventsRefused(&params, refused[i].mp_label);
  }
}

static const char* static_aliasFactsText(char* buf, size_t buf_size, int fact_count)
{
  size_t length = 0;
  buf[length++] = '[';
  for (int f = 0; f < fact_count; f++)
  {
    int written = snprintf(buf + length, buf_size - length,
                           "%s{\"cve_id\": \"CVE-2030-%07d\", \"in_kev\": false, \"poc_count\": 1, \"risk_label\": \"LOW\", \"risk_score\": 1.5, "
                           "\"has_metasploit\": false, \"kev_patch_deadline\": null, \"kev_known_ransomware\": false}",
                           f > 0 ? ", " : "", f);
    TEST_ASSERT_TRUE(written > 0 && (size_t)written < buf_size - length);
    length += (size_t)written;
  }
  TEST_ASSERT_TRUE(length + 2 <= buf_size);
  buf[length++] = ']';
  buf[length]   = '\0';
  return buf;
}

static const char* static_paddedFactsText(char* buf, size_t buf_size, size_t byte_count)
{
  TEST_ASSERT_TRUE(byte_count < buf_size);
  static_aliasFactsText(buf, buf_size, 1);
  size_t length = strlen(buf);
  TEST_ASSERT_TRUE(length <= byte_count);
  memset(buf + length - 1, ' ', byte_count - length + 1);
  buf[byte_count - 1] = ']';
  buf[byte_count]     = '\0';
  return buf;
}

void test_WATCHLISTEVENTS_ip_limits_match_the_schema(void)
{
  TEST_ASSERT_EQUAL_INT(4096, WATCHLIST_IP_VALUE_MAX_LEN);
  TEST_ASSERT_EQUAL_INT(256, WATCHLIST_IP_DROP_COPYRIGHT_MAX_LEN);
}

static void static_queueIpEventRow(const char* name, const char* value)
{
  static const char* const ip_row[] = {
    "item_id", "1", "item_endpoint_name", "ip_lookup", "item_ip_address", "192.0.2.9",
    FLAGS_FIRST_EVENT("1"), "event_type", "drop_listed", "changed_at", "2026-10-22T01:00:00Z",
    "previous_ip_value", "", "current_ip_value", "192.0.2.0/24 SBL9", "drop_list_time", "2026-10-21T23:00:00Z",
    "drop_copyright", "(c) 2026 drop", NULL
  };
  const char* const* const rows[] = { ip_row };
  FakeAnswer_t* answer = static_queueEventsAnswer(rows, 1);
  answer->ma_cells[0][static_eventsColumn(name)] = value != NULL ? value : FAKE_SQL_NULL;
}

void test_WATCHLISTEVENTS_reads_ip_cells_at_their_limits(void)
{
  RequestCreditBudget_t budget;
  static_watchlistBudget(&budget);
  WATCHLISTEVENTSParams_t params;
  static_watchlistEventsParams(&params, &budget);

  static char longest_value[WATCHLIST_IP_VALUE_MAX_LEN + 1];
  static char long_value[WATCHLIST_IP_VALUE_MAX_LEN + 2];
  static char longest_copyright[WATCHLIST_IP_DROP_COPYRIGHT_MAX_LEN + 1];
  static char long_copyright[WATCHLIST_IP_DROP_COPYRIGHT_MAX_LEN + 2];
  static char long_list_time[CVELOOKUP_PUBLISHED_LEN + 2];
  static_fillText(longest_value,     sizeof(longest_value),     "192.0.2.0/24 SBL", 'v', WATCHLIST_IP_VALUE_MAX_LEN);
  static_fillText(long_value,        sizeof(long_value),        "192.0.2.0/24 SBL", 'v', WATCHLIST_IP_VALUE_MAX_LEN + 1);
  static_fillText(longest_copyright, sizeof(longest_copyright), "(c) ", 'c', WATCHLIST_IP_DROP_COPYRIGHT_MAX_LEN);
  static_fillText(long_copyright,    sizeof(long_copyright),    "(c) ", 'c', WATCHLIST_IP_DROP_COPYRIGHT_MAX_LEN + 1);
  static_fillText(long_list_time,    sizeof(long_list_time),    "2026-", '1', CVELOOKUP_PUBLISHED_LEN + 1);

  const char* const read_names[] = { "previous_ip_value", "current_ip_value" };
  for (size_t n = 0; n < sizeof(read_names) / sizeof(read_names[0]); n++)
  {
    static_resetFake();
    static_queueIpEventRow(read_names[n], longest_value);
    WATCHLISTEVENTSResult_t result;
    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_OK, db_WATCHLISTEVENTS(FAKE_CONN, &params, 20, &result), read_names[n]);
    TEST_ASSERT_EQUAL_INT_MESSAGE(WATCHLIST_EVENT_IP_LOOKUP, result.mp_events[0].m_eventKind, read_names[n]);
    const WATCHLISTIPLOOKUPChange_t* change = &result.mp_events[0].m_ipLookupChange;
    TEST_ASSERT_EQUAL_STRING_MESSAGE(longest_value, n == 0 ? change->mp_previousValue : change->mp_currentValue, read_names[n]);
    db_WATCHLISTEVENTSResultFree(&result);

    static_resetFake();
    static_queueIpEventRow(read_names[n], NULL);
    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_OK, db_WATCHLISTEVENTS(FAKE_CONN, &params, 20, &result), read_names[n]);
    change = &result.mp_events[0].m_ipLookupChange;
    TEST_ASSERT_NULL_MESSAGE(n == 0 ? change->mp_previousValue : change->mp_currentValue, read_names[n]);
    TEST_ASSERT_NOT_NULL_MESSAGE(n == 0 ? change->mp_currentValue : change->mp_previousValue, read_names[n]);
    db_WATCHLISTEVENTSResultFree(&result);
  }

  static_resetFake();
  static_queueIpEventRow("drop_copyright", longest_copyright);
  WATCHLISTEVENTSResult_t result;
  TEST_ASSERT_EQUAL_INT(DB_OK, db_WATCHLISTEVENTS(FAKE_CONN, &params, 20, &result));
  TEST_ASSERT_EQUAL_STRING(longest_copyright, result.mp_events[0].m_ipLookupChange.ma_dropCopyright);
  TEST_ASSERT_EQUAL_STRING("2026-10-21T23:00:00Z", result.mp_events[0].m_ipLookupChange.ma_dropListTime);
  db_WATCHLISTEVENTSResultFree(&result);

  const char* const empty_names[] = { "drop_list_time", "drop_copyright" };
  for (size_t n = 0; n < sizeof(empty_names) / sizeof(empty_names[0]); n++)
  {
    static_resetFake();
    static_queueIpEventRow(empty_names[n], NULL);
    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_OK, db_WATCHLISTEVENTS(FAKE_CONN, &params, 20, &result), empty_names[n]);
    const WATCHLISTIPLOOKUPChange_t* change = &result.mp_events[0].m_ipLookupChange;
    TEST_ASSERT_EQUAL_STRING_MESSAGE("", n == 0 ? change->ma_dropListTime : change->ma_dropCopyright, empty_names[n]);
    db_WATCHLISTEVENTSResultFree(&result);
  }

  const struct { const char* mp_name; const char* mp_value; } refused[] = {
    { "previous_ip_value", long_value },
    { "current_ip_value",  long_value },
    { "drop_copyright",    long_copyright },
    { "drop_list_time",    long_list_time },
  };
  for (size_t n = 0; n < sizeof(refused) / sizeof(refused[0]); n++)
  {
    static_resetFake();
    static_queueIpEventRow(refused[n].mp_name, refused[n].mp_value);
    memset(&result, 0xA5, sizeof(result));
    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_ERROR, db_WATCHLISTEVENTS(FAKE_CONN, &params, 20, &result), refused[n].mp_name);
    TEST_ASSERT_NULL_MESSAGE(result.mp_events, refused[n].mp_name);
  }
}

void test_WATCHLISTEVENTS_reads_package_cells_at_their_limits(void)
{
  RequestCreditBudget_t budget;
  static_watchlistBudget(&budget);
  WATCHLISTEVENTSParams_t params;
  static_watchlistEventsParams(&params, &budget);
  static const char* const* const fix_alone[] = { g_packageRowFix };

  static char advisory_id[WATCHLIST_PACKAGE_CHECK_ADVISORY_ID_MAX_LEN + 1];
  static char fixed_version[PACKAGECHECK_VERSION_MAX_LEN + 1];
  static char source[WATCHLIST_PACKAGE_CHECK_ADVISORY_SOURCE_MAX_LEN + 1];
  static char aliases[WATCHLIST_PACKAGE_CHECK_ADVISORY_ALIASES_JSON_MAX_LEN + 1];
  static char attribution[WATCHLIST_PACKAGE_CHECK_ATTRIBUTION_JSON_MAX_LEN + 1];
  static_fillText(advisory_id, sizeof(advisory_id), "RUSTSEC-", '9', WATCHLIST_PACKAGE_CHECK_ADVISORY_ID_MAX_LEN);
  static_fillText(fixed_version, sizeof(fixed_version), "", 'f', PACKAGECHECK_VERSION_MAX_LEN);
  static_fillText(source, sizeof(source), "", 's', WATCHLIST_PACKAGE_CHECK_ADVISORY_SOURCE_MAX_LEN);
  static_fillText(aliases, sizeof(aliases), "[\"", 'a', WATCHLIST_PACKAGE_CHECK_ADVISORY_ALIASES_JSON_MAX_LEN);
  aliases[WATCHLIST_PACKAGE_CHECK_ADVISORY_ALIASES_JSON_MAX_LEN - 2] = '"';
  aliases[WATCHLIST_PACKAGE_CHECK_ADVISORY_ALIASES_JSON_MAX_LEN - 1] = ']';
  static_fillText(attribution, sizeof(attribution), "[\"", 't', WATCHLIST_PACKAGE_CHECK_ATTRIBUTION_JSON_MAX_LEN);
  attribution[WATCHLIST_PACKAGE_CHECK_ATTRIBUTION_JSON_MAX_LEN - 2] = '"';
  attribution[WATCHLIST_PACKAGE_CHECK_ATTRIBUTION_JSON_MAX_LEN - 1] = ']';
  const struct { const char* mp_column; const char* mp_cell; } cases[] = {
    { "advisory_id",      advisory_id },
    { "fixed_version",    fixed_version },
    { "advisory_source",  source },
    { "advisory_aliases", aliases },
    { "attribution",      attribution },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    static_resetFake();
    FakeAnswer_t* answer = static_queueEventsAnswer(fix_alone, 1);
    answer->ma_cells[0][static_eventsColumn(cases[i].mp_column)] = cases[i].mp_cell;
    WATCHLISTEVENTSResult_t result;
    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_OK, db_WATCHLISTEVENTS(FAKE_CONN, &params, 20, &result), cases[i].mp_column);
    TEST_ASSERT_EQUAL_STRING(i == 0 ? advisory_id : "GHSA-p6mc-m468-83gw", result.mp_events[0].m_packageCheckChange.ma_advisoryId);
    TEST_ASSERT_EQUAL_STRING(i == 0 ? advisory_id : "GHSA-p6mc-m468-83gw", result.mp_advisories[0].ma_advisoryId);
    TEST_ASSERT_EQUAL_STRING(i == 1 ? fixed_version : "4.17.21", result.mp_events[0].m_packageCheckChange.ma_fixedVersion);
    TEST_ASSERT_EQUAL_STRING(i == 2 ? source : "ghsa", result.mp_advisories[0].ma_source);
    TEST_ASSERT_EQUAL_STRING(i == 3 ? aliases : PACKAGE_ALIASES_LODASH, result.mp_advisories[0].mp_aliases);
    TEST_ASSERT_EQUAL_STRING(i == 4 ? attribution : PACKAGE_ATTRIBUTION, result.mp_attribution);
    db_WATCHLISTEVENTSResultFree(&result);
  }

  static char facts[WATCHLIST_PACKAGE_CHECK_ADVISORY_CVE_FACTS_JSON_MAX_LEN + 1];
  static_resetFake();
  FakeAnswer_t* answer = static_queueEventsAnswer(fix_alone, 1);
  answer->ma_cells[0][static_eventsColumn("advisory_cve_facts")] =
    static_paddedFactsText(facts, sizeof(facts), WATCHLIST_PACKAGE_CHECK_ADVISORY_CVE_FACTS_JSON_MAX_LEN);
  WATCHLISTEVENTSResult_t padded;
  TEST_ASSERT_EQUAL_INT(DB_OK, db_WATCHLISTEVENTS(FAKE_CONN, &params, 20, &padded));
  TEST_ASSERT_EQUAL_INT(1, padded.m_cveFactCount);
  TEST_ASSERT_EQUAL_STRING("CVE-2030-0000000", padded.mp_cveFacts[0].ma_cveId);
  db_WATCHLISTEVENTSResultFree(&padded);

  static_resetFake();
  answer = static_queueEventsAnswer(fix_alone, 1);
  answer->ma_cells[0][static_eventsColumn("advisory_cve_facts")] =
    static_aliasFactsText(facts, sizeof(facts), WATCHLIST_PACKAGE_CHECK_ADVISORY_ALIAS_MAX_COUNT);
  WATCHLISTEVENTSResult_t result;
  TEST_ASSERT_EQUAL_INT(DB_OK, db_WATCHLISTEVENTS(FAKE_CONN, &params, 20, &result));
  TEST_ASSERT_EQUAL_INT(WATCHLIST_PACKAGE_CHECK_ADVISORY_ALIAS_MAX_COUNT, result.m_cveFactCount);
  TEST_ASSERT_EQUAL_STRING("CVE-2030-0000000", result.mp_cveFacts[0].ma_cveId);
  TEST_ASSERT_EQUAL_STRING("CVE-2030-0000063", result.mp_cveFacts[WATCHLIST_PACKAGE_CHECK_ADVISORY_ALIAS_MAX_COUNT - 1].ma_cveId);
  TEST_ASSERT_EQUAL_FLOAT(1.5, result.mp_cveFacts[63].m_riskScore);
  TEST_ASSERT_EQUAL_INT(1, result.mp_cveFacts[63].m_pocCount);
  TEST_ASSERT_EQUAL_STRING("LOW", result.mp_cveFacts[63].ma_riskLabel);
  db_WATCHLISTEVENTSResultFree(&result);
}

void test_WATCHLISTEVENTS_refuses_each_broken_package_row(void)
{
  RequestCreditBudget_t budget;
  static_watchlistBudget(&budget);
  WATCHLISTEVENTSParams_t params;
  static_watchlistEventsParams(&params, &budget);

  static char long_advisory_id[WATCHLIST_PACKAGE_CHECK_ADVISORY_ID_MAX_LEN + 2];
  static char long_fixed_version[PACKAGECHECK_VERSION_MAX_LEN + 2];
  static char long_source[WATCHLIST_PACKAGE_CHECK_ADVISORY_SOURCE_MAX_LEN + 2];
  static char long_aliases[WATCHLIST_PACKAGE_CHECK_ADVISORY_ALIASES_JSON_MAX_LEN + 2];
  static char long_attribution[WATCHLIST_PACKAGE_CHECK_ATTRIBUTION_JSON_MAX_LEN + 2];
  static char long_facts[WATCHLIST_PACKAGE_CHECK_ADVISORY_CVE_FACTS_JSON_MAX_LEN + 2];
  static char too_many_facts[WATCHLIST_PACKAGE_CHECK_ADVISORY_CVE_FACTS_JSON_MAX_LEN + 1];
  static char long_ecosystem[PACKAGECHECK_ECOSYSTEM_MAX_LEN + 2];
  static_fillText(long_advisory_id, sizeof(long_advisory_id), "RUSTSEC-", '9', WATCHLIST_PACKAGE_CHECK_ADVISORY_ID_MAX_LEN + 1);
  static_fillText(long_fixed_version, sizeof(long_fixed_version), "", 'f', PACKAGECHECK_VERSION_MAX_LEN + 1);
  static_fillText(long_source, sizeof(long_source), "", 's', WATCHLIST_PACKAGE_CHECK_ADVISORY_SOURCE_MAX_LEN + 1);
  static_fillText(long_aliases, sizeof(long_aliases), "[\"", 'a', WATCHLIST_PACKAGE_CHECK_ADVISORY_ALIASES_JSON_MAX_LEN + 1);
  long_aliases[WATCHLIST_PACKAGE_CHECK_ADVISORY_ALIASES_JSON_MAX_LEN - 1] = '"';
  long_aliases[WATCHLIST_PACKAGE_CHECK_ADVISORY_ALIASES_JSON_MAX_LEN]     = ']';
  static_fillText(long_attribution, sizeof(long_attribution), "[\"", 't', WATCHLIST_PACKAGE_CHECK_ATTRIBUTION_JSON_MAX_LEN + 1);
  long_attribution[WATCHLIST_PACKAGE_CHECK_ATTRIBUTION_JSON_MAX_LEN - 1] = '"';
  long_attribution[WATCHLIST_PACKAGE_CHECK_ATTRIBUTION_JSON_MAX_LEN]     = ']';
  static_paddedFactsText(long_facts, sizeof(long_facts), WATCHLIST_PACKAGE_CHECK_ADVISORY_CVE_FACTS_JSON_MAX_LEN + 1);
  static_aliasFactsText(too_many_facts, sizeof(too_many_facts), WATCHLIST_PACKAGE_CHECK_ADVISORY_ALIAS_MAX_COUNT + 1);
  static_fillText(long_ecosystem, sizeof(long_ecosystem), "", 'e', PACKAGECHECK_ECOSYSTEM_MAX_LEN + 1);

  const struct { const char* mp_label; int m_row; const char* mp_column; const char* mp_cell; } refused[] = {
    { "advisory_id past its limit",                       0, "advisory_id",                long_advisory_id },
    { "fixed_version past its limit",                     0, "fixed_version",              long_fixed_version },
    { "advisory_source past its limit",                   0, "advisory_source",            long_source },
    { "advisory_aliases past its limit",                  0, "advisory_aliases",           long_aliases },
    { "attribution past its limit",                       0, "attribution",                long_attribution },
    { "advisory_cve_facts past its limit",                0, "advisory_cve_facts",         long_facts },
    { "advisory_cve_facts past the alias count",          0, "advisory_cve_facts",         too_many_facts },
    { "item_ecosystem past its limit",                    0, "item_ecosystem",             long_ecosystem },
    { "a NULL item_ecosystem",                            0, "item_ecosystem",             NULL },
    { "a NULL item_package_name",                         3, "item_package_name",          NULL },
    { "a NULL attribution on the first row",              0, "attribution",                NULL },
    { "a NULL advisory_aliases on an advisory's row",     0, "advisory_aliases",           NULL },
    { "a NULL advisory_cve_facts on an advisory's row",   3, "advisory_cve_facts",         NULL },
    { "a NULL event_type on a package event",             3, "event_type",                 NULL },
    { "affects_version false",                            0, "affects_version",            "f" },
    { "affects_version not a boolean",                    1, "affects_version",            "yes" },
    { "a NULL is_first_event_of_advisory",                1, "is_first_event_of_advisory", NULL },
    { "is_first_event_of_advisory not a boolean",         1, "is_first_event_of_advisory", "x" },
    { "the first of an advisory on a later row",          2, "is_first_event_of_advisory", "t" },
    { "the first of an advisory on a CVE event",          1, "is_first_event_of_advisory", "t" },
    { "an advisory that no row names",                    0, "is_first_event_of_advisory", "f" },
    { "an advisory named twice",                          3, "advisory_id",                "GHSA-p6mc-m468-83gw" },
    { "alias facts not JSON",                             0, "advisory_cve_facts",         "[{\"cve_id\": \"CVE-2030-0000001\"" },
    { "alias facts not an array",                         0, "advisory_cve_facts",         "{}" },
    { "alias facts element not an object",                0, "advisory_cve_facts",         "[\"CVE-2030-0000001\"]" },
    { "alias facts element with no cve_id",
      0, "advisory_cve_facts", "[{\"in_kev\": false, \"poc_count\": 1, \"risk_label\": \"LOW\", \"risk_score\": 1.5, \"has_metasploit\": false, \"kev_patch_deadline\": null, \"kev_known_ransomware\": false}]" },
    { "alias facts cve_id past its limit",
      0, "advisory_cve_facts", "[{\"cve_id\": \"CVE-2030-00000000000000001\", \"in_kev\": false, \"poc_count\": 1, \"risk_label\": \"LOW\", \"risk_score\": 1.5, \"has_metasploit\": false, \"kev_patch_deadline\": null, \"kev_known_ransomware\": false}]" },
    { "alias facts risk_label past its limit",
      0, "advisory_cve_facts", "[{\"cve_id\": \"CVE-2030-0000001\", \"in_kev\": false, \"poc_count\": 1, \"risk_label\": \"LLLLLLLLLLLLLLLLL\", \"risk_score\": 1.5, \"has_metasploit\": false, \"kev_patch_deadline\": null, \"kev_known_ransomware\": false}]" },
    { "alias facts kev_patch_deadline past its limit",
      0, "advisory_cve_facts", "[{\"cve_id\": \"CVE-2030-0000001\", \"in_kev\": true, \"poc_count\": 1, \"risk_label\": \"LOW\", \"risk_score\": 1.5, \"has_metasploit\": false, \"kev_patch_deadline\": \"2022-01-10T00:00:00.000000000000Z\", \"kev_known_ransomware\": false}]" },
    { "alias facts risk_score not a number",
      0, "advisory_cve_facts", "[{\"cve_id\": \"CVE-2030-0000001\", \"in_kev\": false, \"poc_count\": 1, \"risk_label\": \"LOW\", \"risk_score\": \"x\", \"has_metasploit\": false, \"kev_patch_deadline\": null, \"kev_known_ransomware\": false}]" },
    { "alias facts poc_count not a number",
      0, "advisory_cve_facts", "[{\"cve_id\": \"CVE-2030-0000001\", \"in_kev\": false, \"poc_count\": true, \"risk_label\": \"LOW\", \"risk_score\": 1.5, \"has_metasploit\": false, \"kev_patch_deadline\": null, \"kev_known_ransomware\": false}]" },
    { "alias facts poc_count below 0",
      0, "advisory_cve_facts", "[{\"cve_id\": \"CVE-2030-0000001\", \"in_kev\": false, \"poc_count\": -1, \"risk_label\": \"LOW\", \"risk_score\": 1.5, \"has_metasploit\": false, \"kev_patch_deadline\": null, \"kev_known_ransomware\": false}]" },
    { "alias facts in_kev null",
      0, "advisory_cve_facts", "[{\"cve_id\": \"CVE-2030-0000001\", \"in_kev\": null, \"poc_count\": 1, \"risk_label\": \"LOW\", \"risk_score\": 1.5, \"has_metasploit\": false, \"kev_patch_deadline\": null, \"kev_known_ransomware\": false}]" },
    { "alias facts with no has_metasploit",
      0, "advisory_cve_facts", "[{\"cve_id\": \"CVE-2030-0000001\", \"in_kev\": false, \"poc_count\": 1, \"risk_label\": \"LOW\", \"risk_score\": 1.5, \"kev_patch_deadline\": null, \"kev_known_ransomware\": false}]" },
    { "alias facts with no kev_known_ransomware",
      0, "advisory_cve_facts", "[{\"cve_id\": \"CVE-2030-0000001\", \"in_kev\": false, \"poc_count\": 1, \"risk_label\": \"LOW\", \"risk_score\": 1.5, \"has_metasploit\": false, \"kev_patch_deadline\": null}]" },
    { "alias facts naming a CVE of a later CVE event",
      0, "advisory_cve_facts", "[{\"cve_id\": \"CVE-2021-23337\", \"in_kev\": false, \"poc_count\": 1, \"risk_label\": \"LOW\", \"risk_score\": 1.5, \"has_metasploit\": false, \"kev_patch_deadline\": null, \"kev_known_ransomware\": false}]" },
    { "alias facts naming one CVE twice",
      0, "advisory_cve_facts", "[{\"cve_id\": \"CVE-2030-0000001\", \"in_kev\": false, \"poc_count\": 1, \"risk_label\": \"LOW\", \"risk_score\": 1.5, \"has_metasploit\": false, \"kev_patch_deadline\": null, \"kev_known_ransomware\": false}, "
         "{\"cve_id\": \"CVE-2030-0000001\", \"in_kev\": false, \"poc_count\": 1, \"risk_label\": \"LOW\", \"risk_score\": 1.5, \"has_metasploit\": false, \"kev_patch_deadline\": null, \"kev_known_ransomware\": false}]" },
  };
  for (size_t i = 0; i < sizeof(refused) / sizeof(refused[0]); i++)
  {
    static_resetFake();
    FakeAnswer_t* answer = static_queueEventsAnswer(g_packageRows, PACKAGE_ROW_COUNT);
    answer->ma_cells[refused[i].m_row][static_eventsColumn(refused[i].mp_column)] = refused[i].mp_cell != NULL ? refused[i].mp_cell : FAKE_SQL_NULL;
    static_assertEventsRefused(&params, refused[i].mp_label);
  }

  static_resetFake();
  FakeAnswer_t* answer = static_queueEventsAnswer(g_packageRows, PACKAGE_ROW_COUNT);
  answer->ma_cells[0][static_eventsColumn("is_first_event_of_advisory")] = "f";
  answer->ma_cells[2][static_eventsColumn("is_first_event_of_advisory")] = "t";
  answer->ma_cells[2][static_eventsColumn("advisory_aliases")]           = "[]";
  answer->ma_cells[2][static_eventsColumn("advisory_cve_facts")]         = "[]";
  static_assertEventsRefused(&params, "the only first of an advisory on a later row");
}

void test_WATCHLISTEVENTS_package_limits_match_the_schema(void)
{
  TEST_ASSERT_EQUAL_INT(48, WATCHLIST_PACKAGE_CHECK_ADVISORY_ID_MAX_LEN);
  TEST_ASSERT_EQUAL_INT((int)strlen("RUSTSEC-") + 40, WATCHLIST_PACKAGE_CHECK_ADVISORY_ID_MAX_LEN);
  TEST_ASSERT_EQUAL_INT((int)strlen("rustsec"), WATCHLIST_PACKAGE_CHECK_ADVISORY_SOURCE_MAX_LEN);
  TEST_ASSERT_EQUAL_INT(64, WATCHLIST_PACKAGE_CHECK_ADVISORY_ALIAS_MAX_COUNT);
  TEST_ASSERT_EQUAL_INT(64, WATCHLIST_PACKAGE_CHECK_ADVISORY_ALIAS_MAX_LEN);
  TEST_ASSERT_EQUAL_INT(4096, WATCHLIST_PACKAGE_CHECK_ATTRIBUTION_JSON_MAX_LEN);
  TEST_ASSERT_EQUAL_INT(64 * 512, WATCHLIST_PACKAGE_CHECK_ADVISORY_CVE_FACTS_JSON_MAX_LEN);
}

void test_WATCHLISTEVENTS_frees_package_texts_after_a_failed_copy(void)
{
  RequestCreditBudget_t budget;
  static_watchlistBudget(&budget);
  WATCHLISTEVENTSParams_t params;
  static_watchlistEventsParams(&params, &budget);

  int failed_count = 0;
  for (int n = 1; n <= 10; n++)
  {
    static_resetFake();
    static_queueEventsAnswer(g_packageRows, PACKAGE_ROW_COUNT);
    g_strdupFailsAtCall = n;
    WATCHLISTEVENTSResult_t result;
    memset(&result, 0xA5, sizeof(result));
    DbStatus_t status = db_WATCHLISTEVENTS(FAKE_CONN, &params, 20, &result);
    if (status == DB_OK)
    {
      db_WATCHLISTEVENTSResultFree(&result);
      break;
    }
    char label[32];
    snprintf(label, sizeof(label), "strdup call %d", n);
    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_ERROR, status, label);
    TEST_ASSERT_NULL_MESSAGE(result.mp_events, label);
    TEST_ASSERT_NULL_MESSAGE(result.mp_advisories, label);
    TEST_ASSERT_NULL_MESSAGE(result.mp_attribution, label);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, result.m_advisoryCount, label);
    failed_count++;
  }
  TEST_ASSERT_EQUAL_INT(3, failed_count);
}

static const char* const g_cveEventColumnNames[] = {
  "events_status", "next_cursor", "has_more", "event_type", "changed_at", "cve_id", "previous_value", "current_value", "vendor",
  "product", "is_first_event_of_cve", "risk_score", "risk_label", "in_kev", "kev_patch_deadline", "kev_known_ransomware",
  "has_metasploit", "poc_count"
};
#define CVE_EVENT_CELL_COUNT 18

static void static_setCveEventRow(FakeAnswer_t* answer, int row, const char* const* cells, const char* rank)
{
  for (int i = 0; i < CVE_EVENT_CELL_COUNT; i++)
    answer->ma_cells[row][static_eventsColumn(g_cveEventColumnNames[i])] = cells[i] != NULL ? cells[i] : FAKE_SQL_NULL;
  answer->ma_cells[row][static_eventsColumn("item_id")]                  = "1";
  answer->ma_cells[row][static_eventsColumn("item_endpoint_name")]       = "cve_search";
  answer->ma_cells[row][static_eventsColumn("event_rank")]               = rank;
  answer->ma_cells[row][static_eventsColumn("is_first_row_of_event")]    = "t";
  answer->ma_cells[row][static_eventsColumn("is_first_event_of_domain")] = "f";
  answer->ma_cells[row][static_eventsColumn("is_first_event_of_advisory")] = "f";
  answer->ma_cells[row][static_eventsColumn("attribution")]                = "[]";
}

void test_WATCHLISTEVENTS_reads_each_event_column(void)
{
  RequestCreditBudget_t budget;
  static_watchlistBudget(&budget);
  WATCHLISTEVENTSParams_t params;
  static_watchlistEventsParams(&params, &budget);

  static const char* const row_kev[]  = { "ok", "58", "t", "kev_added", "2026-10-15T08:09:10Z", "CVE-2021-44228", NULL, NULL, NULL, NULL, "t", "96.5", "CRITICAL", "t", "2021-12-24", "t", "f", "3" };
  static const char* const row_epss[] = { "ok", "58", "t", "epss_changed", "2026-10-15T08:09:11Z", "CVE-2022-12345", "0.4", "0.52345", NULL, NULL, "t", "40", "MEDIUM", "f", NULL, "f", "t", "12" };
  static const char* const row_cvss[] = { "ok", "58", "t", "cvss_added", "2026-10-15T08:09:12Z", "CVE-2023-99999", NULL, "7.5", NULL, NULL, "t", "71", "HIGH", "f", "2026-01-15", "t", "t", "0" };

  static const char* const row_kev_again[] = { "ok", "58", "t", "kev_removed", "2026-10-15T08:09:13Z", "CVE-2021-44228", NULL, NULL, NULL, NULL, "f", "1.5", "LOW", "f", NULL, "f", "t", "9" };
  static const char* const row_exploit[]   = { "ok", "58", "t", "exploit_published", "2026-10-15T08:09:14Z", "CVE-2022-12345", NULL, NULL, NULL, NULL, "f", NULL, NULL, NULL, NULL, NULL, NULL, NULL };
  static const char* const row_product[]   = { "ok", "58", "t", "product_removed", "2026-10-15T08:09:15Z", "CVE-2021-44228", NULL, NULL, "apache", "log4j", "f", NULL, NULL, NULL, NULL, NULL, NULL, NULL };
  static const char* const row_advisory[]  = { "ok", "58", "t", "vendor_advisory_published", "2026-10-15T08:09:16Z", "CVE-2023-99999", NULL, NULL, NULL, NULL, "f", NULL, NULL, NULL, NULL, NULL, NULL, NULL };

  static_resetFake();
  FakeAnswer_t* answer = static_queueNamedAnswer(g_watchlistEventsColumnNames, WATCHLISTEVENTS_ROW_COLUMN_COUNT, 7);
  static_setCveEventRow(answer, 0, row_kev,       "1");
  static_setCveEventRow(answer, 1, row_epss,      "2");
  static_setCveEventRow(answer, 2, row_cvss,      "3");
  static_setCveEventRow(answer, 3, row_kev_again, "4");
  static_setCveEventRow(answer, 4, row_exploit,   "5");
  static_setCveEventRow(answer, 5, row_product,   "6");
  static_setCveEventRow(answer, 6, row_advisory,  "7");
  WATCHLISTEVENTSResult_t result;
  memset(&result, 0xA5, sizeof(result));
  g_dirtyMalloc = true;
  TEST_ASSERT_EQUAL_INT(DB_OK, db_WATCHLISTEVENTS(FAKE_CONN, &params, 20, &result));
  g_dirtyMalloc = false;
  TEST_ASSERT_EQUAL_INT(WATCHLISTEVENTS_OK, result.m_status);
  TEST_ASSERT_EQUAL_STRING("58", result.ma_nextCursor);
  TEST_ASSERT_TRUE(result.m_hasMore);
  TEST_ASSERT_EQUAL_INT(7, result.m_eventCount);
  TEST_ASSERT_NOT_NULL(result.mp_events);
  TEST_ASSERT_EQUAL_INT(1, result.m_answerItemCount);
  TEST_ASSERT_EQUAL_INT(7, result.mp_answerItems[0].m_pairCount);
  const WATCHLISTEVENTSEvent_t* kev = &result.mp_events[0];
  TEST_ASSERT_EQUAL_STRING("kev_added", kev->ma_eventType);
  TEST_ASSERT_EQUAL_STRING("2026-10-15T08:09:10Z", kev->ma_changedAt);
  TEST_ASSERT_EQUAL_STRING("CVE-2021-44228", kev->m_cveChange.ma_cveId);
  TEST_ASSERT_FALSE(kev->m_cveChange.m_hasPreviousValue);
  TEST_ASSERT_FALSE(kev->m_cveChange.m_hasCurrentValue);
  TEST_ASSERT_FALSE(kev->m_cveChange.m_hasProductPair);
  const WATCHLISTEVENTSEvent_t* epss = &result.mp_events[1];
  TEST_ASSERT_EQUAL_STRING("epss_changed", epss->ma_eventType);
  TEST_ASSERT_EQUAL_STRING("2026-10-15T08:09:11Z", epss->ma_changedAt);
  TEST_ASSERT_EQUAL_STRING("CVE-2022-12345", epss->m_cveChange.ma_cveId);
  TEST_ASSERT_TRUE(epss->m_cveChange.m_hasPreviousValue);
  TEST_ASSERT_EQUAL_FLOAT(0.4, epss->m_cveChange.m_previousValue);
  TEST_ASSERT_TRUE(epss->m_cveChange.m_hasCurrentValue);
  TEST_ASSERT_EQUAL_FLOAT(0.52345, epss->m_cveChange.m_currentValue);
  const WATCHLISTEVENTSEvent_t* cvss = &result.mp_events[2];
  TEST_ASSERT_EQUAL_STRING("cvss_added", cvss->ma_eventType);
  TEST_ASSERT_EQUAL_STRING("CVE-2023-99999", cvss->m_cveChange.ma_cveId);
  TEST_ASSERT_FALSE(cvss->m_cveChange.m_hasPreviousValue);
  TEST_ASSERT_TRUE(cvss->m_cveChange.m_hasCurrentValue);
  TEST_ASSERT_EQUAL_FLOAT(7.5, cvss->m_cveChange.m_currentValue);
  TEST_ASSERT_EQUAL_STRING("kev_removed", result.mp_events[3].ma_eventType);
  TEST_ASSERT_EQUAL_STRING("CVE-2021-44228", result.mp_events[3].m_cveChange.ma_cveId);
  TEST_ASSERT_EQUAL_STRING("exploit_published", result.mp_events[4].ma_eventType);
  TEST_ASSERT_EQUAL_STRING("CVE-2022-12345", result.mp_events[4].m_cveChange.ma_cveId);
  const WATCHLISTEVENTSEvent_t* product = &result.mp_events[5];
  TEST_ASSERT_EQUAL_STRING("product_removed", product->ma_eventType);
  TEST_ASSERT_EQUAL_STRING("CVE-2021-44228", product->m_cveChange.ma_cveId);
  TEST_ASSERT_TRUE(product->m_cveChange.m_hasProductPair);
  TEST_ASSERT_EQUAL_STRING("apache", product->m_cveChange.ma_vendor);
  TEST_ASSERT_EQUAL_STRING("log4j", product->m_cveChange.ma_product);
  TEST_ASSERT_EQUAL_STRING("vendor_advisory_published", result.mp_events[6].ma_eventType);
  TEST_ASSERT_FALSE(result.mp_events[6].m_cveChange.m_hasProductPair);

  TEST_ASSERT_EQUAL_INT(3, result.m_cveFactCount);
  TEST_ASSERT_NOT_NULL(result.mp_cveFacts);
  const WATCHLISTEVENTSCveFacts_t* kev_facts = &result.mp_cveFacts[0];
  TEST_ASSERT_EQUAL_STRING("CVE-2021-44228", kev_facts->ma_cveId);
  TEST_ASSERT_EQUAL_FLOAT(96.5, kev_facts->m_riskScore);
  TEST_ASSERT_EQUAL_STRING("CRITICAL", kev_facts->ma_riskLabel);
  TEST_ASSERT_TRUE(kev_facts->m_isInKev);
  TEST_ASSERT_TRUE(kev_facts->m_hasKev);
  TEST_ASSERT_EQUAL_STRING("2021-12-24", kev_facts->ma_kevPatchDeadline);
  TEST_ASSERT_TRUE(kev_facts->m_kevKnownRansomware);
  TEST_ASSERT_FALSE(kev_facts->m_hasMetasploit);
  TEST_ASSERT_EQUAL_INT(3, kev_facts->m_pocCount);
  const WATCHLISTEVENTSCveFacts_t* epss_facts = &result.mp_cveFacts[1];
  TEST_ASSERT_EQUAL_STRING("CVE-2022-12345", epss_facts->ma_cveId);
  TEST_ASSERT_EQUAL_FLOAT(40.0, epss_facts->m_riskScore);
  TEST_ASSERT_EQUAL_STRING("MEDIUM", epss_facts->ma_riskLabel);
  TEST_ASSERT_FALSE(epss_facts->m_isInKev);
  TEST_ASSERT_FALSE(epss_facts->m_hasKev);
  TEST_ASSERT_EQUAL_STRING("", epss_facts->ma_kevPatchDeadline);
  TEST_ASSERT_FALSE(epss_facts->m_kevKnownRansomware);
  TEST_ASSERT_TRUE(epss_facts->m_hasMetasploit);
  TEST_ASSERT_EQUAL_INT(12, epss_facts->m_pocCount);
  const WATCHLISTEVENTSCveFacts_t* cvss_facts = &result.mp_cveFacts[2];
  TEST_ASSERT_EQUAL_STRING("CVE-2023-99999", cvss_facts->ma_cveId);
  TEST_ASSERT_EQUAL_FLOAT(71.0, cvss_facts->m_riskScore);
  TEST_ASSERT_EQUAL_STRING("HIGH", cvss_facts->ma_riskLabel);
  TEST_ASSERT_FALSE(cvss_facts->m_isInKev);
  TEST_ASSERT_TRUE(cvss_facts->m_hasKev);
  TEST_ASSERT_EQUAL_STRING("2026-01-15", cvss_facts->ma_kevPatchDeadline);
  TEST_ASSERT_TRUE(cvss_facts->m_kevKnownRansomware);
  TEST_ASSERT_TRUE(cvss_facts->m_hasMetasploit);
  TEST_ASSERT_EQUAL_INT(0, cvss_facts->m_pocCount);
  db_WATCHLISTEVENTSResultFree(&result);
  TEST_ASSERT_NULL(result.mp_events);
  TEST_ASSERT_NULL(result.mp_cveFacts);
  TEST_ASSERT_EQUAL_INT(0, result.m_cveFactCount);
  db_WATCHLISTEVENTSResultFree(&result);
  db_WATCHLISTEVENTSResultFree(NULL);

  static const struct { const char* mp_status; WATCHLISTEVENTSStatus_t m_status; } statuses[] = {
    { "no_position",    WATCHLISTEVENTS_NO_POSITION },
    { "cursor_invalid", WATCHLISTEVENTS_CURSOR_INVALID },
    { "unknown_key",    WATCHLISTEVENTS_UNKNOWN_KEY },
  };
  for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); i++)
  {
    static_resetFake();
    answer = static_queueNamedAnswer(g_watchlistEventsColumnNames, WATCHLISTEVENTS_ROW_COLUMN_COUNT, 1);
    answer->ma_cells[0][0] = statuses[i].mp_status;
    answer->ma_cells[0][2] = "f";
    memset(&result, 0xA5, sizeof(result));
    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_OK, db_WATCHLISTEVENTS(FAKE_CONN, &params, 20, &result), statuses[i].mp_status);
    TEST_ASSERT_EQUAL_INT_MESSAGE(statuses[i].m_status, result.m_status, statuses[i].mp_status);
    TEST_ASSERT_EQUAL_STRING_MESSAGE("", result.ma_nextCursor, statuses[i].mp_status);
    TEST_ASSERT_FALSE_MESSAGE(result.m_hasMore, statuses[i].mp_status);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, result.m_eventCount, statuses[i].mp_status);
    TEST_ASSERT_NULL_MESSAGE(result.mp_events, statuses[i].mp_status);
    TEST_ASSERT_NULL_MESSAGE(result.mp_answerItems, statuses[i].mp_status);
    TEST_ASSERT_NULL_MESSAGE(result.mp_pairEventIndexes, statuses[i].mp_status);
    TEST_ASSERT_NULL_MESSAGE(result.mp_domainFacts, statuses[i].mp_status);
  }

  static char vendor_at_limit[CVESEARCH_VENDOR_LEN + 1];
  static char product_at_limit[CVESEARCH_PRODUCT_LEN + 1];
  memset(vendor_at_limit, 'v', sizeof(vendor_at_limit) - 1);
  memset(product_at_limit, 'p', sizeof(product_at_limit) - 1);
  static const char* const limit_pair_row[] = { "ok", "58", "t", "product_added", "2026-10-15T08:09:10Z", "CVE-2021-44228", NULL, NULL, vendor_at_limit, product_at_limit, "t", "96.5", "CRITICAL", "t", NULL, "f", "t", "3" };
  static_resetFake();
  answer = static_queueNamedAnswer(g_watchlistEventsColumnNames, WATCHLISTEVENTS_ROW_COLUMN_COUNT, 1);
  static_setCveEventRow(answer, 0, limit_pair_row, "1");
  memset(&result, 0xA5, sizeof(result));
  TEST_ASSERT_EQUAL_INT(DB_OK, db_WATCHLISTEVENTS(FAKE_CONN, &params, 20, &result));
  TEST_ASSERT_EQUAL_size_t(CVESEARCH_VENDOR_LEN, strlen(result.mp_events[0].m_cveChange.ma_vendor));
  TEST_ASSERT_EQUAL_size_t(CVESEARCH_PRODUCT_LEN, strlen(result.mp_events[0].m_cveChange.ma_product));
  db_WATCHLISTEVENTSResultFree(&result);

  static char long_pair_name[CVESEARCH_VENDOR_LEN + 2];
  memset(long_pair_name, 'n', sizeof(long_pair_name) - 1);
  long_pair_name[sizeof(long_pair_name) - 1] = '\0';
  static char long_type[WATCHLIST_EVENT_TYPE_MAX_LEN + 2];
  memset(long_type, 't', sizeof(long_type) - 1);
  long_type[sizeof(long_type) - 1] = '\0';
  static char long_changed_at[CVELOOKUP_PUBLISHED_LEN + 2];
  memset(long_changed_at, '1', sizeof(long_changed_at) - 1);
  long_changed_at[sizeof(long_changed_at) - 1] = '\0';
  static const char* const null_cursor_row[]   = { "ok", NULL, "t", "kev_added", "2026-10-15T08:09:10Z", "CVE-2021-44228", NULL, NULL, NULL, NULL, "t", "96.5", "CRITICAL", "t", NULL, "f", "t", "3" };
  static const char* const null_more_row[]     = { "ok", "58", NULL, "kev_added", "2026-10-15T08:09:10Z", "CVE-2021-44228", NULL, NULL, NULL, NULL, "t", "96.5", "CRITICAL", "t", NULL, "f", "t", "3" };
  static const char* const long_cursor_row[]   = { "ok", "1234567890123456789", "t", "kev_added", "2026-10-15T08:09:10Z", "CVE-2021-44228", NULL, NULL, NULL, NULL, "t", "96.5", "CRITICAL", "t", NULL, "f", "t", "3" };
  static const char* const signed_cursor_row[] = { "ok", "-1", "t", "kev_added", "2026-10-15T08:09:10Z", "CVE-2021-44228", NULL, NULL, NULL, NULL, "t", "96.5", "CRITICAL", "t", NULL, "f", "t", "3" };
  static const char* const bogus_status_row[]  = { "bogus", "58", "t", "kev_added", "2026-10-15T08:09:10Z", "CVE-2021-44228", NULL, NULL, NULL, NULL, "t", "96.5", "CRITICAL", "t", NULL, "f", "t", "3" };
  static const char* const null_risk_row[]     = { "ok", "58", "t", "kev_added", "2026-10-15T08:09:10Z", "CVE-2021-44228", NULL, NULL, NULL, NULL, "t", NULL, "CRITICAL", "t", NULL, "f", "t", "3" };
  static const char* const null_label_row[]    = { "ok", "58", "t", "kev_added", "2026-10-15T08:09:10Z", "CVE-2021-44228", NULL, NULL, NULL, NULL, "t", "96.5", NULL, "t", NULL, "f", "t", "3" };
  static const char* const null_in_kev_row[]   = { "ok", "58", "t", "kev_added", "2026-10-15T08:09:10Z", "CVE-2021-44228", NULL, NULL, NULL, NULL, "t", "96.5", "CRITICAL", NULL, "2021-12-24", "f", "t", "3" };
  static const char* const null_ransom_row[]   = { "ok", "58", "t", "kev_added", "2026-10-15T08:09:10Z", "CVE-2021-44228", NULL, NULL, NULL, NULL, "t", "96.5", "CRITICAL", "t", NULL, NULL, "t", "3" };
  static const char* const null_msf_row[]      = { "ok", "58", "t", "kev_added", "2026-10-15T08:09:10Z", "CVE-2021-44228", NULL, NULL, NULL, NULL, "t", "96.5", "CRITICAL", "t", NULL, "f", NULL, "3" };
  static const char* const null_poc_row[]      = { "ok", "58", "t", "kev_added", "2026-10-15T08:09:10Z", "CVE-2021-44228", NULL, NULL, NULL, NULL, "t", "96.5", "CRITICAL", "t", NULL, "f", "t", NULL };
  static const char* const bad_in_kev_row[]    = { "ok", "58", "t", "kev_added", "2026-10-15T08:09:10Z", "CVE-2021-44228", NULL, NULL, NULL, NULL, "t", "96.5", "CRITICAL", "yes", NULL, "f", "t", "3" };
  static const char* const long_type_row[]     = { "ok", "58", "t", NULL, "2026-10-15T08:09:10Z", "CVE-2021-44228", NULL, NULL, NULL, NULL, "t", "96.5", "CRITICAL", "t", NULL, "f", "t", "3" };
  static const char* const long_time_row[]     = { "ok", "58", "t", "kev_added", NULL, "CVE-2021-44228", NULL, NULL, NULL, NULL, "t", "96.5", "CRITICAL", "t", NULL, "f", "t", "3" };
  static const char* const pair_row[]          = { "ok", "58", "t", "product_added", "2026-10-15T08:09:10Z", "CVE-2021-44228", NULL, NULL, "apache", "log4j", "t", "96.5", "CRITICAL", "t", NULL, "f", "t", "3" };
  static const char* const long_due_row[]      = { "ok", "58", "t", "kev_added", "2026-10-15T08:09:10Z", "CVE-2021-44228", NULL, NULL, NULL, NULL, "t", "96.5", "CRITICAL", "t", NULL, "f", "t", "3" };
  const struct { const char* mp_label; const char* const* mp_row; const char* mp_column; const char* mp_cell; } refused[] = {
    { "ok with a NULL next cursor",            null_cursor_row,   NULL,           NULL },
    { "ok with a NULL has_more",               null_more_row,     NULL,           NULL },
    { "a next cursor of 19 digits",            long_cursor_row,   NULL,           NULL },
    { "a signed next cursor",                  signed_cursor_row, NULL,           NULL },
    { "a next cursor with a leading 0",        signed_cursor_row, "next_cursor",  "01" },
    { "an unknown status",                     bogus_status_row,  NULL,           NULL },
    { "a NULL risk_score",                     null_risk_row,     NULL,           NULL },
    { "a NULL risk_label",                     null_label_row,    NULL,           NULL },
    { "a NULL in_kev",                         null_in_kev_row,   NULL,           NULL },
    { "a NULL kev_known_ransomware",           null_ransom_row,   NULL,           NULL },
    { "a NULL has_metasploit",                 null_msf_row,      NULL,           NULL },
    { "a NULL poc_count",                      null_poc_row,      NULL,           NULL },
    { "an in_kev that is no boolean",          bad_in_kev_row,    NULL,           NULL },
    { "an event_type one byte past its field", long_type_row,     "event_type",   long_type },
    { "a changed_at one byte past its field",  long_time_row,     "changed_at",   long_changed_at },
    { "a kev_patch_deadline one byte past its field", long_due_row, "kev_patch_deadline", long_changed_at },
    { "a NULL is_first_event_of_cve",          long_due_row,      "is_first_event_of_cve", NULL },
    { "an is_first_event_of_cve that is no boolean", long_due_row, "is_first_event_of_cve", "yes" },
    { "an is_first_row_of_event that is no boolean", long_due_row, "is_first_row_of_event", "yes" },
    { "an is_first_event_of_domain that is no boolean", long_due_row, "is_first_event_of_domain", "yes" },
    { "a vendor with a NULL product",           long_due_row,      "vendor",       "apache" },
    { "a product with a NULL vendor",           long_due_row,      "product",      "log4j" },
    { "a vendor one byte past its field",       pair_row,          "vendor",       long_pair_name },
    { "a product one byte past its field",      pair_row,          "product",      long_pair_name },
  };
  for (size_t i = 0; i < sizeof(refused) / sizeof(refused[0]); i++)
  {
    static_resetFake();
    answer = static_queueNamedAnswer(g_watchlistEventsColumnNames, WATCHLISTEVENTS_ROW_COLUMN_COUNT, 1);
    static_setCveEventRow(answer, 0, refused[i].mp_row, "1");
    if (refused[i].mp_column != NULL)
      answer->ma_cells[0][static_eventsColumn(refused[i].mp_column)] = refused[i].mp_cell != NULL ? refused[i].mp_cell : FAKE_SQL_NULL;
    static_assertEventsRefused(&params, refused[i].mp_label);
  }

  static_resetFake();
  answer = static_queueNamedAnswer(g_watchlistEventsColumnNames, WATCHLISTEVENTS_ROW_COLUMN_COUNT, 2);
  static_setCveEventRow(answer, 0, row_kev,      "1");
  static_setCveEventRow(answer, 1, null_poc_row, "2");
  answer->ma_cells[1][static_eventsColumn("cve_id")] = "CVE-2022-12345";
  static_assertEventsRefused(&params, "a NULL poc_count on the second row");

  static const char* const null_text_columns[] = { "event_type", "changed_at", "cve_id" };
  for (size_t i = 0; i < sizeof(null_text_columns) / sizeof(null_text_columns[0]); i++)
  {
    static_resetFake();
    answer = static_queueNamedAnswer(g_watchlistEventsColumnNames, WATCHLISTEVENTS_ROW_COLUMN_COUNT, 2);
    static_setCveEventRow(answer, 0, row_kev, "1");
    static_setCveEventRow(answer, 1, row_kev_again, "2");
    answer->ma_cells[1][static_eventsColumn(null_text_columns[i])] = FAKE_SQL_NULL;
    static_assertEventsRefused(&params, null_text_columns[i]);
  }

  static_resetFake();
  answer = static_queueNamedAnswer(g_watchlistEventsColumnNames, WATCHLISTEVENTS_ROW_COLUMN_COUNT, 2);
  static_setCveEventRow(answer, 0, row_kev, "1");
  static_setCveEventRow(answer, 1, row_kev, "2");
  static_assertEventsRefused(&params, "a second first row of a CVE");

  for (size_t i = 0; i < sizeof(g_wrongShapes) / sizeof(g_wrongShapes[0]); i++)
  {
    static_resetFake();
    static_queueWrongShape(g_wrongShapes[i], "events_status", "ok");
    memset(&result, 0xA5, sizeof(result));
    char message[16] = "";
    snprintf(message, sizeof(message), "shape %zu", i);
    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_ERROR, db_WATCHLISTEVENTS(FAKE_CONN, &params, 20, &result), message);
    TEST_ASSERT_NULL_MESSAGE(result.mp_events, message);
  }
  static_resetFake();
  answer = static_queueNamedAnswer(g_watchlistEventsColumnNames, WATCHLISTEVENTS_ROW_COLUMN_COUNT - 1, 1);
  answer->ma_cells[0][0] = "ok";
  answer->ma_cells[0][2] = "f";
  memset(&result, 0xA5, sizeof(result));
  TEST_ASSERT_EQUAL_INT(DB_ERROR, db_WATCHLISTEVENTS(FAKE_CONN, &params, 20, &result));
  TEST_ASSERT_NULL(result.mp_events);
}

void test_purgeExpiredWatchlists_runs_again_after_a_full_batch(void)
{
  char batch[16];
  char batch_less_one[16];
  char batch_plus_one[16];
  static_formatEventCount(batch,          sizeof(batch),          DB_WATCHLIST_PURGE_BATCH_KEY_COUNT);
  static_formatEventCount(batch_less_one, sizeof(batch_less_one), DB_WATCHLIST_PURGE_BATCH_KEY_COUNT - 1);
  static_formatEventCount(batch_plus_one, sizeof(batch_plus_one), DB_WATCHLIST_PURGE_BATCH_KEY_COUNT + 1);
  TEST_ASSERT_EQUAL_STRING("1000", batch);
  const struct {
    const char* ma_counts[3];
    int         m_callCount;
  } rows[] = {
    { { "42" },                1 },
    { { "0" },                 1 },
    { { batch_less_one },      1 },
    { { batch_plus_one },      1 },
    { { batch, "0" },          2 },
    { { batch, batch, "7" },   3 },
  };

  for (size_t row = 0; row < sizeof(rows) / sizeof(rows[0]); row++)
  {
    static_resetFake();
    for (int call = 0; call < rows[row].m_callCount; call++)
      static_queueOneCell("cleared_key_count", rows[row].ma_counts[call]);
    char message[16] = "";
    snprintf(message, sizeof(message), "row %zu", row);

    TEST_ASSERT_TRUE_MESSAGE(db_purgeExpiredWatchlists(FAKE_CONN), message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(rows[row].m_callCount, g_callCount, message);
    for (int call = 0; call < g_callCount; call++)
    {
      const FakeCall_t* sent = &g_calls[call];
      TEST_ASSERT_EQUAL_STRING_MESSAGE(WATCHLISTPURGE_CALL, sent->ma_command, message);
      TEST_ASSERT_EQUAL_INT_MESSAGE(1, sent->m_paramCount, message);
      TEST_ASSERT_FALSE_MESSAGE(sent->ma_isParamNull[0], message);
      TEST_ASSERT_EQUAL_STRING_MESSAGE(batch, sent->ma_params[0], message);
      TEST_ASSERT_EQUAL_INT_MESSAGE(0, sent->m_resultFormat, message);
    }
  }
}

void test_purgeExpiredWatchlists_refuses_any_other_answer(void)
{
  for (size_t row = 0; row < sizeof(g_wrongShapes) / sizeof(g_wrongShapes[0]); row++)
  {
    static_resetFake();
    static_queueWrongShape(g_wrongShapes[row], "cleared_key_count", "1");
    char message[16] = "";
    snprintf(message, sizeof(message), "row %zu", row);

    TEST_ASSERT_FALSE_MESSAGE(db_purgeExpiredWatchlists(FAKE_CONN), message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_callCount, message);
  }

  static_resetFake();
  static_queueOneCell("cleared_key_count", FAKE_SQL_NULL);
  TEST_ASSERT_FALSE(db_purgeExpiredWatchlists(FAKE_CONN));
  TEST_ASSERT_EQUAL_INT(1, g_callCount);

  static_resetFake();
  static_queueOneCell("cleared_key_count", "many");
  TEST_ASSERT_FALSE(db_purgeExpiredWatchlists(FAKE_CONN));
  TEST_ASSERT_EQUAL_INT(1, g_callCount);

  char batch[16];
  static_formatEventCount(batch, sizeof(batch), DB_WATCHLIST_PURGE_BATCH_KEY_COUNT);
  static_resetFake();
  static_queueOneCell("cleared_key_count", batch);
  static_queueAnswer(PGRES_FATAL_ERROR, 0, 0);
  TEST_ASSERT_FALSE(db_purgeExpiredWatchlists(FAKE_CONN));
  TEST_ASSERT_EQUAL_INT(2, g_callCount);
}

void test_EMAILADDRESSCHECK_sends_the_domain_and_reads_each_column(void)
{
  static const char* const values[] = { EMAILADDRESSCHECK_TEST_DOMAIN };
  static_queueEmailAddressCheckAnswer("t", "mailinator.com");
  EMAILADDRESSCHECKRecord_t record;
  memset(&record, 0xA5, sizeof(record));

  TEST_ASSERT_EQUAL_INT(DB_OK, db_EMAILADDRESSCHECK(FAKE_CONN, EMAILADDRESSCHECK_TEST_DOMAIN, &record));

  static_assertCall(0, EMAILADDRESSCHECK_CALL, values, 1);
  TEST_ASSERT_TRUE(record.m_isDisposableFeedLoaded);
  TEST_ASSERT_EQUAL_STRING("mailinator.com", record.ma_disposableListedDomain);
  EMAILADDRESSCHECKRecord_t untouched;
  memset(&untouched, 0xA5, sizeof(untouched));
  TEST_ASSERT_EQUAL_MEMORY(untouched.ma_email, record.ma_email, sizeof(record.ma_email));
  TEST_ASSERT_EQUAL_MEMORY(untouched.ma_domain, record.ma_domain, sizeof(record.ma_domain));
  TEST_ASSERT_EQUAL_MEMORY(&untouched.m_isDomainFound, &record.m_isDomainFound, sizeof(record.m_isDomainFound));
  TEST_ASSERT_EQUAL_MEMORY(&untouched.m_mxAnswer, &record.m_mxAnswer, sizeof(record.m_mxAnswer));
}

void test_EMAILADDRESSCHECK_null_listed_domain_reads_as_empty(void)
{
  static const char* const feed_flags[] = { "t", "f" };
  for (size_t i = 0; i < sizeof(feed_flags) / sizeof(feed_flags[0]); i++)
  {
    static_resetFake();
    static_queueEmailAddressCheckAnswer(feed_flags[i], FAKE_SQL_NULL);
    EMAILADDRESSCHECKRecord_t record;
    memset(&record, 0xA5, sizeof(record));

    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_OK, db_EMAILADDRESSCHECK(FAKE_CONN, EMAILADDRESSCHECK_TEST_DOMAIN, &record), feed_flags[i]);

    TEST_ASSERT_TRUE_MESSAGE(record.m_isDisposableFeedLoaded == (i == 0), feed_flags[i]);
    TEST_ASSERT_EQUAL_STRING_MESSAGE("", record.ma_disposableListedDomain, feed_flags[i]);
  }
}

void test_EMAILADDRESSCHECK_listed_domain_must_be_the_domain_or_a_parent(void)
{
  static const struct { const char* mp_feedLoaded; const char* mp_listedDomain; DbStatus_t m_status; } cases[] = {
    { "t", "mailinator.com",       DB_OK    },
    { "t", "b.mailinator.com",     DB_OK    },
    { "t", "a.b.mailinator.com",   DB_OK    },
    { "t", "inator.com",           DB_ERROR },
    { "t", "x.a.b.mailinator.com", DB_ERROR },
    { "t", "",                     DB_ERROR },
    { "t", "example.com",          DB_ERROR },
    { "t", "MAILINATOR.COM",       DB_ERROR },
    { "f", "mailinator.com",       DB_ERROR },
    { "t", "nailinator.com",       DB_ERROR },
    { "t", "mailinator.con",       DB_ERROR },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    static_resetFake();
    static_queueEmailAddressCheckAnswer(cases[i].mp_feedLoaded, cases[i].mp_listedDomain);
    EMAILADDRESSCHECKRecord_t record;
    memset(&record, 0xA5, sizeof(record));

    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_status, db_EMAILADDRESSCHECK(FAKE_CONN, EMAILADDRESSCHECK_TEST_DOMAIN, &record), cases[i].mp_listedDomain);

    if (cases[i].m_status == DB_OK)
    {
      TEST_ASSERT_TRUE_MESSAGE(record.m_isDisposableFeedLoaded, cases[i].mp_listedDomain);
      TEST_ASSERT_EQUAL_STRING_MESSAGE(cases[i].mp_listedDomain, record.ma_disposableListedDomain, cases[i].mp_listedDomain);
      continue;
    }
    TEST_ASSERT_FALSE_MESSAGE(record.m_isDisposableFeedLoaded, cases[i].mp_listedDomain);
    TEST_ASSERT_EQUAL_STRING_MESSAGE("", record.ma_disposableListedDomain, cases[i].mp_listedDomain);
  }
}

void test_EMAILADDRESSCHECK_listed_public_suffix_counts_as_not_listed(void)
{
  static const struct { const char* mp_domain; const char* mp_listedDomain; const char* mp_readDomain; } cases[] = {
    { "foo.co.uk",          "co.uk",          ""               },
    { "foo.co.uk",          "uk",             ""               },
    { "a.b.kobe.jp",        "b.kobe.jp",      ""               },
    { "a.mailinator.com",   "mailinator.com", "mailinator.com" },
    { "a.city.kobe.jp",     "city.kobe.jp",   "city.kobe.jp"   },
    { "x.foo.co.uk",        "foo.co.uk",      "foo.co.uk"      },
    { "a.github.io",        "github.io",      "github.io"      },
    { "co.uk",              "co.uk",          ""               },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    static_resetFake();
    static_queueEmailAddressCheckAnswer("t", cases[i].mp_listedDomain);
    EMAILADDRESSCHECKRecord_t record;
    memset(&record, 0xA5, sizeof(record));

    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_OK, db_EMAILADDRESSCHECK(FAKE_CONN, cases[i].mp_domain, &record), cases[i].mp_listedDomain);

    TEST_ASSERT_TRUE_MESSAGE(record.m_isDisposableFeedLoaded, cases[i].mp_listedDomain);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(cases[i].mp_readDomain, record.ma_disposableListedDomain, cases[i].mp_listedDomain);
  }
}

static void static_writeDomainOfLength(size_t domain_len, char* domain_out)
{
  for (size_t i = 0; i < domain_len; i++)
    domain_out[i] = (i % 64 == 63) ? '.' : 'c';
  domain_out[domain_len - 2] = '.';
  domain_out[domain_len]     = '\0';
}

void test_EMAILADDRESSCHECK_listed_domain_at_its_limit_and_past_it(void)
{
  static char longest_domain[300];
  static char long_domain[300];
  static_writeDomainOfLength(VALIDATE_DOMAIN_NAME_MAX_LEN, longest_domain);
  static_writeDomainOfLength(VALIDATE_DOMAIN_NAME_MAX_LEN + 1, long_domain);

  static_queueEmailAddressCheckAnswer("t", longest_domain);
  EMAILADDRESSCHECKRecord_t record;
  memset(&record, 0xA5, sizeof(record));
  TEST_ASSERT_EQUAL_INT(DB_OK, db_EMAILADDRESSCHECK(FAKE_CONN, longest_domain, &record));
  TEST_ASSERT_EQUAL_STRING(longest_domain, record.ma_disposableListedDomain);

  static_resetFake();
  static_queueEmailAddressCheckAnswer("t", long_domain);
  memset(&record, 0xA5, sizeof(record));
  TEST_ASSERT_EQUAL_INT(DB_ERROR, db_EMAILADDRESSCHECK(FAKE_CONN, long_domain, &record));
  TEST_ASSERT_EQUAL_STRING("", record.ma_disposableListedDomain);
}

void test_EMAILADDRESSCHECK_other_than_one_row_a_null_flag_or_a_failed_query_is_error(void)
{
  for (int row_count = 0; row_count <= 2; row_count += 2)
  {
    static_resetFake();
    FakeAnswer_t* answer = static_queueAnswer(PGRES_TUPLES_OK, EMAILADDRESSCHECK_ROW_COLUMN_COUNT, row_count);
    for (int col = 0; col < EMAILADDRESSCHECK_ROW_COLUMN_COUNT; col++)
    {
      answer->ma_columnNames[col] = g_emailAddressCheckColumnNames[col];
      for (int row = 0; row < row_count; row++)
        answer->ma_cells[row][col] = col == 0 ? "t" : "mailinator.com";
    }
    EMAILADDRESSCHECKRecord_t record;
    memset(&record, 0xA5, sizeof(record));
    TEST_ASSERT_EQUAL_INT(DB_ERROR, db_EMAILADDRESSCHECK(FAKE_CONN, EMAILADDRESSCHECK_TEST_DOMAIN, &record));
    TEST_ASSERT_FALSE(record.m_isDisposableFeedLoaded);
    TEST_ASSERT_EQUAL_STRING("", record.ma_disposableListedDomain);
  }

  static_resetFake();
  static_queueEmailAddressCheckAnswer(FAKE_SQL_NULL, FAKE_SQL_NULL);
  EMAILADDRESSCHECKRecord_t record;
  memset(&record, 0xA5, sizeof(record));
  TEST_ASSERT_EQUAL_INT(DB_ERROR, db_EMAILADDRESSCHECK(FAKE_CONN, EMAILADDRESSCHECK_TEST_DOMAIN, &record));
  TEST_ASSERT_FALSE(record.m_isDisposableFeedLoaded);
  TEST_ASSERT_EQUAL_STRING("", record.ma_disposableListedDomain);

  static_resetFake();
  static_queueAnswer(PGRES_FATAL_ERROR, 0, 0);
  memset(&record, 0xA5, sizeof(record));
  TEST_ASSERT_EQUAL_INT(DB_ERROR, db_EMAILADDRESSCHECK(FAKE_CONN, EMAILADDRESSCHECK_TEST_DOMAIN, &record));
  TEST_ASSERT_FALSE(record.m_isDisposableFeedLoaded);
  TEST_ASSERT_EQUAL_STRING("", record.ma_disposableListedDomain);
}

void test_SSLCHECK_sends_the_fingerprint_and_reads_each_column(void)
{
  static const char* const values[] = { SSLCHECK_TEST_SHA1 };
  static_queueSslCheckAnswer("t", "Dridex C&C", "2024-05-06T07:08:09Z");
  static SSLCHECKRecord_t record;
  memset(&record, 0xA5, sizeof(record));

  TEST_ASSERT_EQUAL_INT(DB_OK, db_SSLCHECK(FAKE_CONN, SSLCHECK_TEST_SHA1, &record));

  static_assertCall(0, SSLCHECK_CALL, values, 1);
  TEST_ASSERT_TRUE(record.m_isBlacklistFeedLoaded);
  TEST_ASSERT_EQUAL_STRING("Dridex C&C", record.ma_blacklistListingReason);
  TEST_ASSERT_EQUAL_STRING("2024-05-06T07:08:09Z", record.ma_blacklistListingTime);
  static SSLCHECKRecord_t untouched;
  memset(&untouched, 0xA5, sizeof(untouched));
  TEST_ASSERT_EQUAL_MEMORY(&untouched.m_result, &record.m_result, sizeof(record.m_result));
  TEST_ASSERT_EQUAL_MEMORY(untouched.ma_checkedAt, record.ma_checkedAt, sizeof(record.ma_checkedAt));
  TEST_ASSERT_EQUAL_MEMORY(&untouched.m_isBlacklistUnavailable, &record.m_isBlacklistUnavailable, sizeof(record.m_isBlacklistUnavailable));
}

void test_SSLCHECK_listing_must_be_whole_and_fit(void)
{
  static char reason_at_limit[128 + 1];
  static char reason_past_limit[128 + 2];
  memset(reason_at_limit, 'R', sizeof(reason_at_limit) - 1);
  memset(reason_past_limit, 'R', sizeof(reason_past_limit) - 1);
  static const struct {
    const char* mp_feedLoaded;
    const char* mp_reason;
    const char* mp_time;
    DbStatus_t  m_status;
    const char* mp_name;
  } cases[] = {
    { "t", NULL,          NULL,                    DB_OK,    "loaded, not listed" },
    { "f", NULL,          NULL,                    DB_OK,    "not loaded" },
    { "t", "QuasarRAT C&C", "2025-01-02T03:04:05Z", DB_OK,   "listed" },
    { "f", "QuasarRAT C&C", "2025-01-02T03:04:05Z", DB_ERROR, "listed while not loaded" },
    { "t", "QuasarRAT C&C", NULL,                  DB_ERROR, "a reason alone" },
    { "t", NULL,          "2025-01-02T03:04:05Z",  DB_ERROR, "a time alone" },
    { "t", "",            "2025-01-02T03:04:05Z",  DB_ERROR, "an empty reason" },
    { "t", "QuasarRAT C&C", "",                    DB_ERROR, "an empty time" },
    { "t", reason_at_limit, "2025-01-02T03:04:05Z", DB_OK,   "a reason at its limit" },
    { "t", reason_past_limit, "2025-01-02T03:04:05Z", DB_ERROR, "a reason past its limit" },
    { "t", "QuasarRAT C&C", "2025-01-02T03:04:05Zx", DB_ERROR, "a time past its limit" },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    static_resetFake();
    static_queueSslCheckAnswer(cases[i].mp_feedLoaded,
                               cases[i].mp_reason == NULL ? FAKE_SQL_NULL : cases[i].mp_reason,
                               cases[i].mp_time == NULL ? FAKE_SQL_NULL : cases[i].mp_time);
    static SSLCHECKRecord_t record;
    memset(&record, 0xA5, sizeof(record));

    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_status, db_SSLCHECK(FAKE_CONN, SSLCHECK_TEST_SHA1, &record), cases[i].mp_name);

    if (cases[i].m_status == DB_OK)
    {
      TEST_ASSERT_TRUE_MESSAGE(record.m_isBlacklistFeedLoaded == (cases[i].mp_feedLoaded[0] == 't'), cases[i].mp_name);
      TEST_ASSERT_EQUAL_STRING_MESSAGE(cases[i].mp_reason == NULL ? "" : cases[i].mp_reason, record.ma_blacklistListingReason, cases[i].mp_name);
      TEST_ASSERT_EQUAL_STRING_MESSAGE(cases[i].mp_time == NULL ? "" : cases[i].mp_time, record.ma_blacklistListingTime, cases[i].mp_name);
      continue;
    }
    TEST_ASSERT_FALSE_MESSAGE(record.m_isBlacklistFeedLoaded, cases[i].mp_name);
    TEST_ASSERT_EQUAL_STRING_MESSAGE("", record.ma_blacklistListingReason, cases[i].mp_name);
    TEST_ASSERT_EQUAL_STRING_MESSAGE("", record.ma_blacklistListingTime, cases[i].mp_name);
  }
}

void test_SSLCHECK_other_than_one_row_a_null_flag_or_a_failed_query_is_error(void)
{
  static SSLCHECKRecord_t record;
  for (int row_count = 0; row_count <= 2; row_count += 2)
  {
    static_resetFake();
    FakeAnswer_t* answer = static_queueAnswer(PGRES_TUPLES_OK, SSLCHECK_ROW_COLUMN_COUNT, row_count);
    for (int col = 0; col < SSLCHECK_ROW_COLUMN_COUNT; col++)
      answer->ma_columnNames[col] = g_sslCheckColumnNames[col];
    for (int row = 0; row < row_count; row++)
    {
      answer->ma_cells[row][0] = "t";
      answer->ma_cells[row][1] = "Dridex C&C";
      answer->ma_cells[row][2] = "2024-05-06T07:08:09Z";
    }
    memset(&record, 0xA5, sizeof(record));
    TEST_ASSERT_EQUAL_INT(DB_ERROR, db_SSLCHECK(FAKE_CONN, SSLCHECK_TEST_SHA1, &record));
    TEST_ASSERT_FALSE(record.m_isBlacklistFeedLoaded);
    TEST_ASSERT_EQUAL_STRING("", record.ma_blacklistListingReason);
    TEST_ASSERT_EQUAL_STRING("", record.ma_blacklistListingTime);
  }

  static_resetFake();
  static_queueSslCheckAnswer(FAKE_SQL_NULL, FAKE_SQL_NULL, FAKE_SQL_NULL);
  memset(&record, 0xA5, sizeof(record));
  TEST_ASSERT_EQUAL_INT(DB_ERROR, db_SSLCHECK(FAKE_CONN, SSLCHECK_TEST_SHA1, &record));
  TEST_ASSERT_FALSE(record.m_isBlacklistFeedLoaded);
  TEST_ASSERT_EQUAL_STRING("", record.ma_blacklistListingReason);
  TEST_ASSERT_EQUAL_STRING("", record.ma_blacklistListingTime);

  static_resetFake();
  static_queueAnswer(PGRES_FATAL_ERROR, 0, 0);
  memset(&record, 0xA5, sizeof(record));
  TEST_ASSERT_EQUAL_INT(DB_ERROR, db_SSLCHECK(FAKE_CONN, SSLCHECK_TEST_SHA1, &record));
  TEST_ASSERT_FALSE(record.m_isBlacklistFeedLoaded);
  TEST_ASSERT_EQUAL_STRING("", record.ma_blacklistListingReason);
  TEST_ASSERT_EQUAL_STRING("", record.ma_blacklistListingTime);
}

typedef struct {
  bool        (*m_purge)(PGconn* conn);
  const char* mp_call;
  const char* mp_columnName;
  int         m_batchRowCount;
} TablePurgeCase_t;

static const TablePurgeCase_t g_tablePurges[] = {
  { db_purgeExpiredDomainChangeEvents, "SELECT api.fn_domain_change_event_purge($1) AS purged_event_count",
    "purged_event_count", DB_DOMAIN_CHANGE_PURGE_BATCH_EVENT_COUNT },
  { db_purgeUnwatchedDomains, "SELECT api.fn_domain_watch_purge_unwatched($1) AS purged_domain_count",
    "purged_domain_count", DB_DOMAIN_WATCH_PURGE_BATCH_DOMAIN_COUNT },
  { db_purgeExpiredEolChangeEvents, "SELECT api.fn_eol_change_event_purge($1) AS purged_event_count",
    "purged_event_count", DB_EOL_CHANGE_PURGE_BATCH_EVENT_COUNT },
};

static const TablePurgeCase_t g_ipWatchJobs[] = {
  { db_writeWatchedIpValues, "SELECT api.fn_ip_watch_write_values($1) AS evaluated_item_count",
    "evaluated_item_count", DB_IP_WATCH_WRITE_BATCH_ITEM_COUNT },
  { db_purgeExpiredIpChangeEvents, "SELECT api.fn_ip_change_event_purge($1) AS purged_event_count",
    "purged_event_count", DB_IP_CHANGE_PURGE_BATCH_EVENT_COUNT },
};

static const TablePurgeCase_t g_vendorKeyPurges[] = {
  { db_purgeExpiredVendorKeys, "SELECT api.fn_vendor_key_purge($1) AS purged_key_count",
    "purged_key_count", DB_VENDOR_KEY_PURGE_BATCH_KEY_COUNT },
  { db_purgeExpiredVendorKeyLinks, "SELECT api.fn_vendor_key_link_purge($1) AS purged_link_count",
    "purged_link_count", DB_VENDOR_KEY_LINK_PURGE_BATCH_ROW_COUNT },
};

static const TablePurgeCase_t g_billingEventPurges[] = {
  { db_purgeExpiredBillingEvents, "SELECT api.fn_billing_event_purge($1) AS purged_event_count",
    "purged_event_count", DB_BILLING_EVENT_PURGE_BATCH_EVENT_COUNT },
};

static void static_checkPurgesRunAgain(const TablePurgeCase_t* purges, size_t purge_count)
{
  for (size_t purge = 0; purge < purge_count; purge++)
  {
    const TablePurgeCase_t* tested = &purges[purge];
    char batch[16];
    char batch_less_one[16];
    char batch_plus_one[16];
    static_formatEventCount(batch,          sizeof(batch),          tested->m_batchRowCount);
    static_formatEventCount(batch_less_one, sizeof(batch_less_one), tested->m_batchRowCount - 1);
    static_formatEventCount(batch_plus_one, sizeof(batch_plus_one), tested->m_batchRowCount + 1);
    const struct {
      const char* ma_counts[3];
      int         m_callCount;
    } rows[] = {
      { { "42" },                1 },
      { { "0" },                 1 },
      { { batch_less_one },      1 },
      { { batch_plus_one },      1 },
      { { batch, "0" },          2 },
      { { batch, batch, "7" },   3 },
    };

    for (size_t row = 0; row < sizeof(rows) / sizeof(rows[0]); row++)
    {
      static_resetFake();
      for (int call = 0; call < rows[row].m_callCount; call++)
        static_queueOneCell(tested->mp_columnName, rows[row].ma_counts[call]);
      char message[64] = "";
      snprintf(message, sizeof(message), "%s row %zu", tested->mp_columnName, row);

      TEST_ASSERT_TRUE_MESSAGE(tested->m_purge(FAKE_CONN), message);
      TEST_ASSERT_EQUAL_INT_MESSAGE(rows[row].m_callCount, g_callCount, message);
      for (int call = 0; call < g_callCount; call++)
      {
        const FakeCall_t* sent = &g_calls[call];
        TEST_ASSERT_EQUAL_STRING_MESSAGE(tested->mp_call, sent->ma_command, message);
        TEST_ASSERT_EQUAL_INT_MESSAGE(1, sent->m_paramCount, message);
        TEST_ASSERT_FALSE_MESSAGE(sent->ma_isParamNull[0], message);
        TEST_ASSERT_EQUAL_STRING_MESSAGE(batch, sent->ma_params[0], message);
        TEST_ASSERT_EQUAL_INT_MESSAGE(0, sent->m_resultFormat, message);
      }
    }
  }
}

void test_table_purges_run_again_after_a_full_batch(void)
{
  TEST_ASSERT_EQUAL_INT(10000, DB_DOMAIN_CHANGE_PURGE_BATCH_EVENT_COUNT);
  TEST_ASSERT_EQUAL_INT(1000, DB_DOMAIN_WATCH_PURGE_BATCH_DOMAIN_COUNT);
  TEST_ASSERT_EQUAL_INT(10000, DB_EOL_CHANGE_PURGE_BATCH_EVENT_COUNT);
  static_checkPurgesRunAgain(g_tablePurges, sizeof(g_tablePurges) / sizeof(g_tablePurges[0]));
}

void test_ip_watch_jobs_run_again_after_a_full_batch(void)
{
  TEST_ASSERT_EQUAL_INT(500, DB_IP_WATCH_WRITE_BATCH_ITEM_COUNT);
  TEST_ASSERT_EQUAL_INT(10000, DB_IP_CHANGE_PURGE_BATCH_EVENT_COUNT);
  static_checkPurgesRunAgain(g_ipWatchJobs, sizeof(g_ipWatchJobs) / sizeof(g_ipWatchJobs[0]));
}

void test_vendor_key_purges_run_again_after_a_full_batch(void)
{
  TEST_ASSERT_EQUAL_INT(1000, DB_VENDOR_KEY_PURGE_BATCH_KEY_COUNT);
  TEST_ASSERT_EQUAL_INT(10000, DB_VENDOR_KEY_LINK_PURGE_BATCH_ROW_COUNT);
  static_checkPurgesRunAgain(g_vendorKeyPurges, sizeof(g_vendorKeyPurges) / sizeof(g_vendorKeyPurges[0]));
}

static void static_checkPurgesRefuse(const TablePurgeCase_t* purges, size_t purge_count)
{
  for (size_t purge = 0; purge < purge_count; purge++)
  {
    const TablePurgeCase_t* tested = &purges[purge];
    for (size_t row = 0; row < sizeof(g_wrongShapes) / sizeof(g_wrongShapes[0]); row++)
    {
      static_resetFake();
      static_queueWrongShape(g_wrongShapes[row], tested->mp_columnName, "1");
      char message[64] = "";
      snprintf(message, sizeof(message), "%s row %zu", tested->mp_columnName, row);

      TEST_ASSERT_FALSE_MESSAGE(tested->m_purge(FAKE_CONN), message);
      TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_callCount, message);
    }

    static_resetFake();
    static_queueOneCell(tested->mp_columnName, FAKE_SQL_NULL);
    TEST_ASSERT_FALSE(tested->m_purge(FAKE_CONN));
    TEST_ASSERT_EQUAL_INT(1, g_callCount);

    static_resetFake();
    static_queueOneCell(tested->mp_columnName, "many");
    TEST_ASSERT_FALSE(tested->m_purge(FAKE_CONN));
    TEST_ASSERT_EQUAL_INT(1, g_callCount);

    char batch[16];
    static_formatEventCount(batch, sizeof(batch), tested->m_batchRowCount);
    static_resetFake();
    static_queueOneCell(tested->mp_columnName, batch);
    static_queueAnswer(PGRES_FATAL_ERROR, 0, 0);
    TEST_ASSERT_FALSE(tested->m_purge(FAKE_CONN));
    TEST_ASSERT_EQUAL_INT(2, g_callCount);
  }
}

void test_table_purges_refuse_any_other_answer(void)
{
  static_checkPurgesRefuse(g_tablePurges, sizeof(g_tablePurges) / sizeof(g_tablePurges[0]));
}

void test_ip_watch_jobs_refuse_any_other_answer(void)
{
  static_checkPurgesRefuse(g_ipWatchJobs, sizeof(g_ipWatchJobs) / sizeof(g_ipWatchJobs[0]));
}

void test_vendor_key_purges_refuse_any_other_answer(void)
{
  static_checkPurgesRefuse(g_vendorKeyPurges, sizeof(g_vendorKeyPurges) / sizeof(g_vendorKeyPurges[0]));
}

void test_billing_event_purge_runs_again_after_a_full_batch(void)
{
  TEST_ASSERT_EQUAL_INT(10000, DB_BILLING_EVENT_PURGE_BATCH_EVENT_COUNT);
  static_checkPurgesRunAgain(g_billingEventPurges, sizeof(g_billingEventPurges) / sizeof(g_billingEventPurges[0]));
}

void test_billing_event_purge_refuses_any_other_answer(void)
{
  static_checkPurgesRefuse(g_billingEventPurges, sizeof(g_billingEventPurges) / sizeof(g_billingEventPurges[0]));
}

void test_purgeExpiredPackageAdvisoryChangeEvents_runs_again_after_a_full_batch(void)
{
  TEST_ASSERT_EQUAL_INT(10000, DB_PACKAGE_ADVISORY_CHANGE_PURGE_BATCH_EVENT_COUNT);
  char batch[16];
  char batch_less_one[16];
  char batch_plus_one[16];
  static_formatEventCount(batch,          sizeof(batch),          DB_PACKAGE_ADVISORY_CHANGE_PURGE_BATCH_EVENT_COUNT);
  static_formatEventCount(batch_less_one, sizeof(batch_less_one), DB_PACKAGE_ADVISORY_CHANGE_PURGE_BATCH_EVENT_COUNT - 1);
  static_formatEventCount(batch_plus_one, sizeof(batch_plus_one), DB_PACKAGE_ADVISORY_CHANGE_PURGE_BATCH_EVENT_COUNT + 1);
  const struct {
    const char* ma_counts[3];
    int         m_callCount;
  } rows[] = {
    { { "42" },                1 },
    { { "0" },                 1 },
    { { batch_less_one },      1 },
    { { batch_plus_one },      1 },
    { { batch, "0" },          2 },
    { { batch, batch, "7" },   3 },
  };

  for (size_t row = 0; row < sizeof(rows) / sizeof(rows[0]); row++)
  {
    static_resetFake();
    for (int call = 0; call < rows[row].m_callCount; call++)
      static_queueOneCell("purged_event_count", rows[row].ma_counts[call]);
    char message[16] = "";
    snprintf(message, sizeof(message), "row %zu", row);

    TEST_ASSERT_TRUE_MESSAGE(db_purgeExpiredPackageAdvisoryChangeEvents(FAKE_CONN), message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(rows[row].m_callCount, g_callCount, message);
    for (int call = 0; call < g_callCount; call++)
    {
      const FakeCall_t* sent = &g_calls[call];
      TEST_ASSERT_EQUAL_STRING_MESSAGE("SELECT api.fn_package_advisory_change_event_purge($1) AS purged_event_count", sent->ma_command, message);
      TEST_ASSERT_EQUAL_INT_MESSAGE(1, sent->m_paramCount, message);
      TEST_ASSERT_FALSE_MESSAGE(sent->ma_isParamNull[0], message);
      TEST_ASSERT_EQUAL_STRING_MESSAGE(batch, sent->ma_params[0], message);
      TEST_ASSERT_EQUAL_INT_MESSAGE(0, sent->m_resultFormat, message);
    }
  }
}

void test_purgeExpiredPackageAdvisoryChangeEvents_refuses_any_other_answer(void)
{
  for (size_t row = 0; row < sizeof(g_wrongShapes) / sizeof(g_wrongShapes[0]); row++)
  {
    static_resetFake();
    static_queueWrongShape(g_wrongShapes[row], "purged_event_count", "1");
    char message[16] = "";
    snprintf(message, sizeof(message), "row %zu", row);

    TEST_ASSERT_FALSE_MESSAGE(db_purgeExpiredPackageAdvisoryChangeEvents(FAKE_CONN), message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_callCount, message);
  }

  static_resetFake();
  static_queueOneCell("purged_event_count", FAKE_SQL_NULL);
  TEST_ASSERT_FALSE(db_purgeExpiredPackageAdvisoryChangeEvents(FAKE_CONN));
  TEST_ASSERT_EQUAL_INT(1, g_callCount);

  static_resetFake();
  static_queueOneCell("purged_event_count", "many");
  TEST_ASSERT_FALSE(db_purgeExpiredPackageAdvisoryChangeEvents(FAKE_CONN));
  TEST_ASSERT_EQUAL_INT(1, g_callCount);

  char batch[16];
  static_formatEventCount(batch, sizeof(batch), DB_PACKAGE_ADVISORY_CHANGE_PURGE_BATCH_EVENT_COUNT);
  static_resetFake();
  static_queueOneCell("purged_event_count", batch);
  static_queueAnswer(PGRES_FATAL_ERROR, 0, 0);
  TEST_ASSERT_FALSE(db_purgeExpiredPackageAdvisoryChangeEvents(FAKE_CONN));
  TEST_ASSERT_EQUAL_INT(2, g_callCount);
}

#define DB_DOMAIN_WATCH_CLAIM_ROW_COLUMN_COUNT 2
#define DB_DOMAIN_WATCH_CLAIM_CALL "SELECT * FROM api.fn_domain_watch_claim($1, $2, $3)"
#define DB_DOMAIN_WATCH_RECORD_DNS_CALL "SELECT api.fn_domain_watch_record_dns($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17) AS written_event_count"

static const char* const g_domainWatchClaimColumnNames[DB_DOMAIN_WATCH_CLAIM_ROW_COLUMN_COUNT] = {
  "domain_name", "claimed_until"
};

typedef struct {
  const char* mp_laneName;
  const char* mp_sentName;
} ClaimLaneCase_t;
static const ClaimLaneCase_t g_claimLanes[] = {
  { DB_DOMAIN_WATCH_LANE_DNS,        "dns" },
  { DB_DOMAIN_WATCH_LANE_TLS,        "tls" },
  { DB_DOMAIN_WATCH_LANE_RDAP_WHOIS, "rdap_whois" },
  { DB_DOMAIN_WATCH_LANE_HEADERS,    "headers" },
  { DB_DOMAIN_WATCH_LANE_CT,         "ct" },
};
#define CLAIM_LANE_COUNT ((int) (sizeof(g_claimLanes) / sizeof(g_claimLanes[0])))

#define WATCHLIST_DNS_LOOKUP_TEST_CHECK_RESULTS "pppppppppppppppppppfw"

static FakeAnswer_t* static_queueClaimAnswer(int row_count)
{
  FakeAnswer_t* answer = static_queueAnswer(PGRES_TUPLES_OK, DB_DOMAIN_WATCH_CLAIM_ROW_COLUMN_COUNT, row_count);
  for (int col = 0; col < DB_DOMAIN_WATCH_CLAIM_ROW_COLUMN_COUNT; col++)
    answer->ma_columnNames[col] = g_domainWatchClaimColumnNames[col];
  for (int row = 0; row < row_count; row++)
  {
    answer->ma_cells[row][0] = "example.com";
    answer->ma_cells[row][1] = "2026-10-26 12:00:00.123456+00";
  }
  return answer;
}

void test_claimDomainLaneScans_sends_its_params_and_reads_each_column(void)
{
  TEST_ASSERT_EQUAL_INT(4, DB_DOMAIN_SCAN_CLAIM_DOMAIN_COUNT);
  TEST_ASSERT_EQUAL_INT(240, DB_DOMAIN_SCAN_LEASE_SECONDS);
  for (int l = 0; l < CLAIM_LANE_COUNT; l++)
  {
    static_resetFake();
    FakeAnswer_t* answer = static_queueClaimAnswer(2);
    answer->ma_cells[0][0] = "shop.example.com";
    answer->ma_cells[0][1] = "2026-10-26 12:01:02.5+00";
    answer->ma_cells[1][0] = "example.org";
    answer->ma_cells[1][1] = "2026-10-26 12:01:03+00";
    WatchlistDomainScanClaim_t claims[DB_DOMAIN_SCAN_CLAIM_DOMAIN_COUNT];
    memset(claims, 0xA5, sizeof(claims));
    int claim_count = -1;
    const char* message = g_claimLanes[l].mp_sentName;

    TEST_ASSERT_EQUAL_STRING_MESSAGE(g_claimLanes[l].mp_sentName, g_claimLanes[l].mp_laneName, message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_OK, db_claimDomainLaneScans(FAKE_CONN, g_claimLanes[l].mp_laneName, claims, &claim_count), message);

    TEST_ASSERT_EQUAL_INT_MESSAGE(2, claim_count, message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_callCount, message);
    const FakeCall_t* sent = static_lastCall();
    TEST_ASSERT_EQUAL_STRING_MESSAGE(DB_DOMAIN_WATCH_CLAIM_CALL, sent->ma_command, message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(3, sent->m_paramCount, message);
    TEST_ASSERT_FALSE_MESSAGE(sent->ma_isParamNull[0], message);
    TEST_ASSERT_FALSE_MESSAGE(sent->ma_isParamNull[1], message);
    TEST_ASSERT_FALSE_MESSAGE(sent->ma_isParamNull[2], message);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(g_claimLanes[l].mp_sentName, sent->ma_params[0], message);
    TEST_ASSERT_EQUAL_STRING_MESSAGE("4", sent->ma_params[1], message);
    TEST_ASSERT_EQUAL_STRING_MESSAGE("240", sent->ma_params[2], message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, sent->m_resultFormat, message);

    TEST_ASSERT_EQUAL_STRING_MESSAGE("shop.example.com", claims[0].ma_domain, message);
    TEST_ASSERT_EQUAL_STRING_MESSAGE("2026-10-26 12:01:02.5+00", claims[0].ma_claimedUntil, message);
    TEST_ASSERT_EQUAL_STRING_MESSAGE("example.org", claims[1].ma_domain, message);
    TEST_ASSERT_EQUAL_STRING_MESSAGE("2026-10-26 12:01:03+00", claims[1].ma_claimedUntil, message);
  }
}

void test_claimDomainLaneScans_no_row_is_ok(void)
{
  for (int l = 0; l < CLAIM_LANE_COUNT; l++)
  {
    static_resetFake();
    static_queueClaimAnswer(0);
    WatchlistDomainScanClaim_t claims[DB_DOMAIN_SCAN_CLAIM_DOMAIN_COUNT];
    int claim_count = -1;

    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_OK, db_claimDomainLaneScans(FAKE_CONN, g_claimLanes[l].mp_laneName, claims, &claim_count),
                                  g_claimLanes[l].mp_sentName);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, claim_count, g_claimLanes[l].mp_sentName);
  }
}

void test_claimDomainLaneScans_refuses_a_wrong_answer(void)
{
  enum { FAILED, TOO_MANY_ROWS, MISSING_COLUMN, EXTRA_COLUMN, OTHER_NAME, OLDER_SERVER_COLUMNS, NULL_DOMAIN_NAME, NULL_CLAIMED_UNTIL, CASE_COUNT };
  for (int l = 0; l < CLAIM_LANE_COUNT; l++)
  {
    for (int c = 0; c < CASE_COUNT; c++)
    {
      static_resetFake();
      FakeAnswer_t* answer = NULL;
      switch (c)
      {
        case FAILED:
          static_queueAnswer(PGRES_FATAL_ERROR, 0, 0);
          break;
        case TOO_MANY_ROWS:
          static_queueClaimAnswer(DB_DOMAIN_SCAN_CLAIM_DOMAIN_COUNT + 1);
          break;
        case MISSING_COLUMN:
          answer = static_queueClaimAnswer(1);
          answer->m_columnCount = DB_DOMAIN_WATCH_CLAIM_ROW_COLUMN_COUNT - 1;
          break;
        case EXTRA_COLUMN:
          answer = static_queueClaimAnswer(1);
          answer->m_columnCount     = DB_DOMAIN_WATCH_CLAIM_ROW_COLUMN_COUNT + 1;
          answer->ma_columnNames[2] = "lane_name";
          answer->ma_cells[0][2]    = g_claimLanes[l].mp_sentName;
          break;
        case OTHER_NAME:
          answer = static_queueClaimAnswer(1);
          answer->ma_columnNames[1] = "leased_until";
          break;
        case OLDER_SERVER_COLUMNS:
          answer = static_queueClaimAnswer(1);
          answer->m_columnCount     = 4;
          answer->ma_columnNames[2] = "last_dkim_selector";
          answer->ma_columnNames[3] = "email_auth_value";
          answer->ma_cells[0][2]    = "s1";
          answer->ma_cells[0][3]    = WATCHLIST_DNS_LOOKUP_TEST_CHECK_RESULTS;
          break;
        case NULL_DOMAIN_NAME:
          answer = static_queueClaimAnswer(1);
          answer->ma_cells[0][0] = FAKE_SQL_NULL;
          break;
        case NULL_CLAIMED_UNTIL:
          answer = static_queueClaimAnswer(1);
          answer->ma_cells[0][1] = FAKE_SQL_NULL;
          break;
      }
      WatchlistDomainScanClaim_t claims[DB_DOMAIN_SCAN_CLAIM_DOMAIN_COUNT + 1];
      int claim_count = -1;
      char message[32] = "";
      snprintf(message, sizeof(message), "%s case %d", g_claimLanes[l].mp_sentName, c);

      TEST_ASSERT_EQUAL_INT_MESSAGE(DB_ERROR, db_claimDomainLaneScans(FAKE_CONN, g_claimLanes[l].mp_laneName, claims, &claim_count), message);
      TEST_ASSERT_EQUAL_INT_MESSAGE(0, claim_count, message);
    }

    static_resetFake();
    static_queueClaimAnswer(DB_DOMAIN_SCAN_CLAIM_DOMAIN_COUNT);
    WatchlistDomainScanClaim_t claims[DB_DOMAIN_SCAN_CLAIM_DOMAIN_COUNT];
    int claim_count = -1;
    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_OK, db_claimDomainLaneScans(FAKE_CONN, g_claimLanes[l].mp_laneName, claims, &claim_count),
                                  g_claimLanes[l].mp_sentName);
    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_DOMAIN_SCAN_CLAIM_DOMAIN_COUNT, claim_count, g_claimLanes[l].mp_sentName);
  }
}

void test_claimDomainLaneScans_texts_at_their_limits_and_past_them(void)
{
  static const struct {
    int    m_column;
    size_t m_maxLen;
  } columns[] = {
    { 0, VALIDATE_DOMAIN_NAME_MAX_LEN },
    { 1, WATCHLIST_DOMAIN_SCAN_CLAIMED_UNTIL_MAX_LEN },
  };
  TEST_ASSERT_EQUAL_INT(128, WATCHLIST_DOMAIN_SCAN_CLAIMED_UNTIL_MAX_LEN);
  for (int l = 0; l < CLAIM_LANE_COUNT; l++)
  {
    for (size_t c = 0; c < sizeof(columns) / sizeof(columns[0]); c++)
    {
      for (size_t extra = 0; extra <= 1; extra++)
      {
        static_resetFake();
        size_t length = columns[c].m_maxLen + extra;
        char* text = static_makeText(length);
        TEST_ASSERT_NOT_NULL(text);
        FakeAnswer_t* answer = static_queueClaimAnswer(1);
        answer->ma_cells[0][columns[c].m_column] = text;
        WatchlistDomainScanClaim_t claims[DB_DOMAIN_SCAN_CLAIM_DOMAIN_COUNT];
        int claim_count = -1;
        char message[48] = "";
        snprintf(message, sizeof(message), "%s column %d length %zu", g_claimLanes[l].mp_sentName, columns[c].m_column, length);

        DbStatus_t db_status = db_claimDomainLaneScans(FAKE_CONN, g_claimLanes[l].mp_laneName, claims, &claim_count);

        if (extra == 0)
        {
          const char* fields[] = { claims[0].ma_domain, claims[0].ma_claimedUntil };
          TEST_ASSERT_EQUAL_INT_MESSAGE(DB_OK, db_status, message);
          TEST_ASSERT_EQUAL_INT_MESSAGE(1, claim_count, message);
          TEST_ASSERT_EQUAL_STRING_MESSAGE(text, fields[columns[c].m_column], message);
        }
        else
        {
          TEST_ASSERT_EQUAL_INT_MESSAGE(DB_ERROR, db_status, message);
          TEST_ASSERT_EQUAL_INT_MESSAGE(0, claim_count, message);
        }
        free(text);
      }
    }
  }
}

static void static_setWatchValue(WatchlistDomainValue_t* value, const char* text, const char* sha256)
{
  memset(value, 0, sizeof(*value));
  snprintf(value->ma_text, sizeof(value->ma_text), "%s", text);
  snprintf(value->ma_sha256Hex, sizeof(value->ma_sha256Hex), "%s", sha256);
}

void test_recordDnsScan_sends_each_field_in_its_own_parameter(void)
{
  WatchlistDomainValue_t values[6];
  static_setWatchValue(&values[0], "found",                        "sha256-dns-presence");
  static_setWatchValue(&values[1], "ns1.example.net",              "sha256-ns");
  static_setWatchValue(&values[2], "10 mx.example.net",            "sha256-mx");
  static_setWatchValue(&values[3], "public",                       "sha256-address-reachability");
  static_setWatchValue(&values[4], "none",                         "sha256-cname-takeover");
  static_setWatchValue(&values[5], WATCHLIST_DNS_LOOKUP_TEST_CHECK_RESULTS, "sha256-email-auth");
  const DbDnsScanRecord_t scan = {
    .mp_domain                     = "shop.example.com",
    .mp_claimedUntil               = "2026-10-26 12:01:02.5+00",
    .mp_dnsPresenceValue           = &values[0],
    .mp_nsValue                    = &values[1],
    .mp_mxValue                    = &values[2],
    .mp_ipAddressReachabilityValue = &values[3],
    .mp_cnameTakeoverValue         = &values[4],
    .mp_emailAuthValue             = &values[5],
    .mp_emailCheckIds              = "spf_record,mx",
    .mp_hostingIpAddresses         = "93.184.216.34,2606:2800:220:1:248:1893:25c8:1946",
    .m_questionCount               = 37,
  };
  static_queueOneCell("written_event_count", "3");

  TEST_ASSERT_EQUAL_INT(DB_OK, db_recordDnsScan(FAKE_CONN, &scan));

  TEST_ASSERT_EQUAL_INT(1, g_callCount);
  const FakeCall_t* sent = static_lastCall();
  TEST_ASSERT_EQUAL_STRING(DB_DOMAIN_WATCH_RECORD_DNS_CALL, sent->ma_command);
  TEST_ASSERT_EQUAL_INT(0, sent->m_resultFormat);
  static const char* const expected[17] = {
    "shop.example.com", "2026-10-26 12:01:02.5+00",
    "found", "sha256-dns-presence", "ns1.example.net", "sha256-ns", "10 mx.example.net", "sha256-mx",
    "public", "sha256-address-reachability", "none", "sha256-cname-takeover", WATCHLIST_DNS_LOOKUP_TEST_CHECK_RESULTS, "sha256-email-auth",
    "spf_record,mx", "93.184.216.34,2606:2800:220:1:248:1893:25c8:1946", "37",
  };
  TEST_ASSERT_EQUAL_INT(17, sent->m_paramCount);
  for (int n = 0; n < 17; n++)
  {
    char message[16] = "";
    snprintf(message, sizeof(message), "param %d", n + 1);
    TEST_ASSERT_FALSE_MESSAGE(sent->ma_isParamNull[n], message);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(expected[n], sent->ma_params[n], message);
  }
}

void test_recordDnsScan_sends_an_unset_value_as_null(void)
{
  WatchlistDomainValue_t value;
  static_setWatchValue(&value, "text", "sha256");
  for (int set_kind = -1; set_kind < 6; set_kind++)
  {
    static_resetFake();
    DbDnsScanRecord_t scan;
    memset(&scan, 0, sizeof(scan));
    scan.mp_domain       = "example.com";
    scan.mp_claimedUntil = "2026-10-26 12:00:00+00";
    const WatchlistDomainValue_t** slots[6] = {
      &scan.mp_dnsPresenceValue, &scan.mp_nsValue, &scan.mp_mxValue,
      &scan.mp_ipAddressReachabilityValue, &scan.mp_cnameTakeoverValue, &scan.mp_emailAuthValue,
    };
    if (set_kind >= 0)
      *slots[set_kind] = &value;
    static_queueOneCell("written_event_count", "0");
    char message[32] = "";
    snprintf(message, sizeof(message), "set kind %d", set_kind);

    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_OK, db_recordDnsScan(FAKE_CONN, &scan), message);

    const FakeCall_t* sent = static_lastCall();
    TEST_ASSERT_EQUAL_INT_MESSAGE(17, sent->m_paramCount, message);
    TEST_ASSERT_EQUAL_STRING_MESSAGE("example.com", sent->ma_params[0], message);
    TEST_ASSERT_EQUAL_STRING_MESSAGE("2026-10-26 12:00:00+00", sent->ma_params[1], message);
    TEST_ASSERT_FALSE_MESSAGE(sent->ma_isParamNull[0], message);
    TEST_ASSERT_FALSE_MESSAGE(sent->ma_isParamNull[1], message);
    TEST_ASSERT_TRUE_MESSAGE(sent->ma_isParamNull[14], message);
    TEST_ASSERT_TRUE_MESSAGE(sent->ma_isParamNull[15], message);
    TEST_ASSERT_FALSE_MESSAGE(sent->ma_isParamNull[16], message);
    TEST_ASSERT_EQUAL_STRING_MESSAGE("0", sent->ma_params[16], message);
    for (int kind = 0; kind < 6; kind++)
    {
      int text_param = 2 + 2 * kind;
      bool is_set = kind == set_kind;
      TEST_ASSERT_EQUAL_MESSAGE(!is_set, sent->ma_isParamNull[text_param], message);
      TEST_ASSERT_EQUAL_MESSAGE(!is_set, sent->ma_isParamNull[text_param + 1], message);
      if (is_set)
      {
        TEST_ASSERT_EQUAL_STRING_MESSAGE("text", sent->ma_params[text_param], message);
        TEST_ASSERT_EQUAL_STRING_MESSAGE("sha256", sent->ma_params[text_param + 1], message);
      }
    }
  }
}

void test_recordDnsScan_refuses_any_other_answer(void)
{
  DbDnsScanRecord_t scan;
  memset(&scan, 0, sizeof(scan));
  scan.mp_domain       = "example.com";
  scan.mp_claimedUntil = "2026-10-26 12:00:00+00";

  for (size_t row = 0; row < sizeof(g_wrongShapes) / sizeof(g_wrongShapes[0]); row++)
  {
    static_resetFake();
    static_queueWrongShape(g_wrongShapes[row], "written_event_count", "1");
    char message[16] = "";
    snprintf(message, sizeof(message), "row %zu", row);

    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_ERROR, db_recordDnsScan(FAKE_CONN, &scan), message);
  }

  static const char* const cells[] = { FAKE_SQL_NULL, "many", "-1" };
  for (size_t c = 0; c < sizeof(cells) / sizeof(cells[0]); c++)
  {
    static_resetFake();
    static_queueOneCell("written_event_count", cells[c]);
    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_ERROR, db_recordDnsScan(FAKE_CONN, &scan), cells[c]);
  }
}

#define DB_DOMAIN_WATCH_RECORD_TLS_CALL  "SELECT api.fn_domain_watch_record_tls($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) AS written_event_count"

void test_recordTlsScan_sends_each_field_in_its_own_parameter(void)
{
  WatchlistDomainValue_t values[4];
  static_setWatchValue(&values[0], "7\n2026-11-06T12:00:00Z", "sha256-certificate-expiry");
  static_setWatchValue(&values[1], "expired\nself_signed",    "sha256-certificate-validity");
  static_setWatchValue(&values[2], "listed\nDridex C&C",      "sha256-certificate-listing");
  static_setWatchValue(&values[3], "TLSv1.1",                 "sha256-tls-protocol");
  const DbTlsScanRecord_t scan = {
    .mp_domain                   = "shop.example.com",
    .mp_claimedUntil             = "2026-10-30 09:01:02.5+00",
    .mp_certificateExpiryValue   = &values[0],
    .mp_certificateValidityValue = &values[1],
    .mp_certificateListingValue  = &values[2],
    .mp_tlsProtocolValue         = &values[3],
  };
  static_queueOneCell("written_event_count", "2");

  TEST_ASSERT_EQUAL_INT(DB_OK, db_recordTlsScan(FAKE_CONN, &scan));

  TEST_ASSERT_EQUAL_INT(1, g_callCount);
  const FakeCall_t* sent = static_lastCall();
  TEST_ASSERT_EQUAL_STRING(DB_DOMAIN_WATCH_RECORD_TLS_CALL, sent->ma_command);
  TEST_ASSERT_EQUAL_INT(0, sent->m_resultFormat);
  static const char* const expected[10] = {
    "shop.example.com", "2026-10-30 09:01:02.5+00",
    "7\n2026-11-06T12:00:00Z", "sha256-certificate-expiry",
    "expired\nself_signed",    "sha256-certificate-validity",
    "listed\nDridex C&C",      "sha256-certificate-listing",
    "TLSv1.1",                 "sha256-tls-protocol",
  };
  TEST_ASSERT_EQUAL_INT(10, sent->m_paramCount);
  for (int n = 0; n < 10; n++)
  {
    char message[16] = "";
    snprintf(message, sizeof(message), "param %d", n + 1);
    TEST_ASSERT_FALSE_MESSAGE(sent->ma_isParamNull[n], message);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(expected[n], sent->ma_params[n], message);
  }
}

void test_recordTlsScan_sends_an_unset_value_as_null(void)
{
  WatchlistDomainValue_t value;
  static_setWatchValue(&value, "text", "sha256");
  for (int set_kind = -1; set_kind < 4; set_kind++)
  {
    static_resetFake();
    DbTlsScanRecord_t scan;
    memset(&scan, 0, sizeof(scan));
    scan.mp_domain       = "example.com";
    scan.mp_claimedUntil = "2026-10-30 09:00:00+00";
    const WatchlistDomainValue_t** slots[4] = {
      &scan.mp_certificateExpiryValue, &scan.mp_certificateValidityValue,
      &scan.mp_certificateListingValue, &scan.mp_tlsProtocolValue,
    };
    if (set_kind >= 0)
      *slots[set_kind] = &value;
    static_queueOneCell("written_event_count", "0");
    char message[32] = "";
    snprintf(message, sizeof(message), "set kind %d", set_kind);

    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_OK, db_recordTlsScan(FAKE_CONN, &scan), message);

    const FakeCall_t* sent = static_lastCall();
    TEST_ASSERT_EQUAL_INT_MESSAGE(10, sent->m_paramCount, message);
    TEST_ASSERT_EQUAL_STRING_MESSAGE("example.com", sent->ma_params[0], message);
    TEST_ASSERT_EQUAL_STRING_MESSAGE("2026-10-30 09:00:00+00", sent->ma_params[1], message);
    TEST_ASSERT_FALSE_MESSAGE(sent->ma_isParamNull[0], message);
    TEST_ASSERT_FALSE_MESSAGE(sent->ma_isParamNull[1], message);
    for (int kind = 0; kind < 4; kind++)
    {
      int text_param = 2 + 2 * kind;
      bool is_set = kind == set_kind;
      TEST_ASSERT_EQUAL_MESSAGE(!is_set, sent->ma_isParamNull[text_param], message);
      TEST_ASSERT_EQUAL_MESSAGE(!is_set, sent->ma_isParamNull[text_param + 1], message);
      if (is_set)
      {
        TEST_ASSERT_EQUAL_STRING_MESSAGE("text", sent->ma_params[text_param], message);
        TEST_ASSERT_EQUAL_STRING_MESSAGE("sha256", sent->ma_params[text_param + 1], message);
      }
    }
  }
}

void test_recordTlsScan_refuses_any_other_answer(void)
{
  DbTlsScanRecord_t scan;
  memset(&scan, 0, sizeof(scan));
  scan.mp_domain       = "example.com";
  scan.mp_claimedUntil = "2026-10-30 09:00:00+00";

  for (size_t row = 0; row < sizeof(g_wrongShapes) / sizeof(g_wrongShapes[0]); row++)
  {
    static_resetFake();
    static_queueWrongShape(g_wrongShapes[row], "written_event_count", "1");
    char message[16] = "";
    snprintf(message, sizeof(message), "row %zu", row);

    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_ERROR, db_recordTlsScan(FAKE_CONN, &scan), message);
  }

  static const char* const cells[] = { FAKE_SQL_NULL, "many", "-1" };
  for (size_t c = 0; c < sizeof(cells) / sizeof(cells[0]); c++)
  {
    static_resetFake();
    static_queueOneCell("written_event_count", cells[c]);
    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_ERROR, db_recordTlsScan(FAKE_CONN, &scan), cells[c]);
  }

  static_resetFake();
  static_queueOneCell("written_event_count", "0");
  TEST_ASSERT_EQUAL_INT(DB_OK, db_recordTlsScan(FAKE_CONN, &scan));
}

#define DB_DOMAIN_WATCH_RECORD_RDAP_WHOIS_CALL "SELECT api.fn_domain_watch_record_rdap_whois($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) AS written_event_count"

void test_recordRdapWhoisScan_sends_each_field_in_its_own_parameter(void)
{
  WatchlistDomainValue_t values[4];
  static_setWatchValue(&values[0], "30\n2026-11-20T04:00:00Z",   "sha256-registration-expiry");
  static_setWatchValue(&values[1], "292\nMarkMonitor Inc.",      "sha256-registrar");
  static_setWatchValue(&values[2], "client transfer prohibited", "sha256-transfer-lock");
  static_setWatchValue(&values[3], "signed",                     "sha256-dnssec-delegation");
  const DbRdapWhoisScanRecord_t scan = {
    .mp_domain                  = "example.com",
    .mp_claimedUntil            = "2026-10-31 09:01:02.5+00",
    .mp_registrationExpiryValue = &values[0],
    .mp_registrarValue          = &values[1],
    .mp_transferLockValue       = &values[2],
    .mp_dnssecDelegationValue   = &values[3],
    .m_retryAfterSeconds        = 0,
  };
  static_queueOneCell("written_event_count", "3");

  TEST_ASSERT_EQUAL_INT(DB_OK, db_recordRdapWhoisScan(FAKE_CONN, &scan));

  TEST_ASSERT_EQUAL_INT(1, g_callCount);
  const FakeCall_t* sent = static_lastCall();
  TEST_ASSERT_EQUAL_STRING(DB_DOMAIN_WATCH_RECORD_RDAP_WHOIS_CALL, sent->ma_command);
  TEST_ASSERT_EQUAL_INT(0, sent->m_resultFormat);
  static const char* const expected[10] = {
    "example.com", "2026-10-31 09:01:02.5+00",
    "30\n2026-11-20T04:00:00Z",   "sha256-registration-expiry",
    "292\nMarkMonitor Inc.",      "sha256-registrar",
    "client transfer prohibited", "sha256-transfer-lock",
    "signed",                     "sha256-dnssec-delegation",
  };
  TEST_ASSERT_EQUAL_INT(11, sent->m_paramCount);
  for (int n = 0; n < 10; n++)
  {
    char message[16] = "";
    snprintf(message, sizeof(message), "param %d", n + 1);
    TEST_ASSERT_FALSE_MESSAGE(sent->ma_isParamNull[n], message);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(expected[n], sent->ma_params[n], message);
  }
  TEST_ASSERT_TRUE(sent->ma_isParamNull[10]);
}

void test_recordRdapWhoisScan_sends_an_unset_value_as_null(void)
{
  WatchlistDomainValue_t value;
  static_setWatchValue(&value, "text", "sha256");
  for (int set_kind = -1; set_kind < 4; set_kind++)
  {
    static_resetFake();
    DbRdapWhoisScanRecord_t scan;
    memset(&scan, 0, sizeof(scan));
    scan.mp_domain       = "example.com";
    scan.mp_claimedUntil = "2026-10-31 09:00:00+00";
    const WatchlistDomainValue_t** slots[4] = {
      &scan.mp_registrationExpiryValue, &scan.mp_registrarValue,
      &scan.mp_transferLockValue,       &scan.mp_dnssecDelegationValue,
    };
    if (set_kind >= 0)
      *slots[set_kind] = &value;
    static_queueOneCell("written_event_count", "0");
    char message[32] = "";
    snprintf(message, sizeof(message), "set kind %d", set_kind);

    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_OK, db_recordRdapWhoisScan(FAKE_CONN, &scan), message);

    const FakeCall_t* sent = static_lastCall();
    TEST_ASSERT_EQUAL_INT_MESSAGE(11, sent->m_paramCount, message);
    TEST_ASSERT_EQUAL_STRING_MESSAGE("example.com", sent->ma_params[0], message);
    TEST_ASSERT_EQUAL_STRING_MESSAGE("2026-10-31 09:00:00+00", sent->ma_params[1], message);
    TEST_ASSERT_FALSE_MESSAGE(sent->ma_isParamNull[0], message);
    TEST_ASSERT_FALSE_MESSAGE(sent->ma_isParamNull[1], message);
    for (int kind = 0; kind < 4; kind++)
    {
      int text_param = 2 + 2 * kind;
      bool is_set = kind == set_kind;
      TEST_ASSERT_EQUAL_MESSAGE(!is_set, sent->ma_isParamNull[text_param], message);
      TEST_ASSERT_EQUAL_MESSAGE(!is_set, sent->ma_isParamNull[text_param + 1], message);
      if (is_set)
      {
        TEST_ASSERT_EQUAL_STRING_MESSAGE("text", sent->ma_params[text_param], message);
        TEST_ASSERT_EQUAL_STRING_MESSAGE("sha256", sent->ma_params[text_param + 1], message);
      }
    }
    TEST_ASSERT_TRUE_MESSAGE(sent->ma_isParamNull[10], message);
  }
}

void test_recordRdapWhoisScan_sends_the_retry_of_a_deferred_scan(void)
{
  static const struct {
    unsigned int m_retryAfterSeconds;
    const char*  mp_text;
  } cases[] = { { 1, "1" }, { 3600, "3600" } };
  for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++)
  {
    static_resetFake();
    DbRdapWhoisScanRecord_t scan;
    memset(&scan, 0, sizeof(scan));
    scan.mp_domain           = "example.com";
    scan.mp_claimedUntil     = "2026-10-31 09:00:00+00";
    scan.m_retryAfterSeconds = cases[c].m_retryAfterSeconds;
    static_queueOneCell("written_event_count", "0");

    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_OK, db_recordRdapWhoisScan(FAKE_CONN, &scan), cases[c].mp_text);

    const FakeCall_t* sent = static_lastCall();
    TEST_ASSERT_EQUAL_INT(11, sent->m_paramCount);
    for (int n = 2; n < 10; n++)
      TEST_ASSERT_TRUE_MESSAGE(sent->ma_isParamNull[n], cases[c].mp_text);
    TEST_ASSERT_FALSE_MESSAGE(sent->ma_isParamNull[10], cases[c].mp_text);
    TEST_ASSERT_EQUAL_STRING(cases[c].mp_text, sent->ma_params[10]);
  }
}

void test_recordRdapWhoisScan_refuses_any_other_answer(void)
{
  DbRdapWhoisScanRecord_t scan;
  memset(&scan, 0, sizeof(scan));
  scan.mp_domain       = "example.com";
  scan.mp_claimedUntil = "2026-10-31 09:00:00+00";

  for (size_t row = 0; row < sizeof(g_wrongShapes) / sizeof(g_wrongShapes[0]); row++)
  {
    static_resetFake();
    static_queueWrongShape(g_wrongShapes[row], "written_event_count", "1");
    char message[16] = "";
    snprintf(message, sizeof(message), "row %zu", row);

    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_ERROR, db_recordRdapWhoisScan(FAKE_CONN, &scan), message);
  }

  static const char* const cells[] = { FAKE_SQL_NULL, "many", "-1" };
  for (size_t c = 0; c < sizeof(cells) / sizeof(cells[0]); c++)
  {
    static_resetFake();
    static_queueOneCell("written_event_count", cells[c]);
    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_ERROR, db_recordRdapWhoisScan(FAKE_CONN, &scan), cells[c]);
  }

  static_resetFake();
  static_queueOneCell("written_event_count", "0");
  TEST_ASSERT_EQUAL_INT(DB_OK, db_recordRdapWhoisScan(FAKE_CONN, &scan));
}

#define DB_DOMAIN_WATCH_RECORD_HEADERS_CALL "SELECT api.fn_domain_watch_record_headers($1, $2, $3, $4, $5) AS written_event_count"

void test_recordHeadersScan_sends_each_field_in_its_own_parameter(void)
{
  WatchlistDomainValue_t value;
  static_setWatchValue(&value, "https://example.com/\ncontent-security-policy", "sha256-security-headers");
  const DbHeadersScanRecord_t scan = {
    .mp_domain               = "example.com",
    .mp_claimedUntil         = "2026-11-01 09:01:02.5+00",
    .mp_securityHeadersValue = &value,
    .m_retryAfterSeconds     = 0,
  };
  static_queueOneCell("written_event_count", "1");

  TEST_ASSERT_EQUAL_INT(DB_OK, db_recordHeadersScan(FAKE_CONN, &scan));

  TEST_ASSERT_EQUAL_INT(1, g_callCount);
  const FakeCall_t* sent = static_lastCall();
  TEST_ASSERT_EQUAL_STRING(DB_DOMAIN_WATCH_RECORD_HEADERS_CALL, sent->ma_command);
  TEST_ASSERT_EQUAL_INT(0, sent->m_resultFormat);
  static const char* const expected[4] = {
    "example.com", "2026-11-01 09:01:02.5+00", "https://example.com/\ncontent-security-policy", "sha256-security-headers",
  };
  TEST_ASSERT_EQUAL_INT(5, sent->m_paramCount);
  for (int n = 0; n < 4; n++)
  {
    char message[16] = "";
    snprintf(message, sizeof(message), "param %d", n + 1);
    TEST_ASSERT_FALSE_MESSAGE(sent->ma_isParamNull[n], message);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(expected[n], sent->ma_params[n], message);
  }
  TEST_ASSERT_TRUE(sent->ma_isParamNull[4]);
}

void test_recordHeadersScan_sends_an_unset_value_as_null(void)
{
  DbHeadersScanRecord_t scan;
  memset(&scan, 0, sizeof(scan));
  scan.mp_domain       = "example.com";
  scan.mp_claimedUntil = "2026-11-01 09:00:00+00";
  static_queueOneCell("written_event_count", "0");

  TEST_ASSERT_EQUAL_INT(DB_OK, db_recordHeadersScan(FAKE_CONN, &scan));

  const FakeCall_t* sent = static_lastCall();
  TEST_ASSERT_EQUAL_INT(5, sent->m_paramCount);
  TEST_ASSERT_EQUAL_STRING("example.com", sent->ma_params[0]);
  TEST_ASSERT_EQUAL_STRING("2026-11-01 09:00:00+00", sent->ma_params[1]);
  TEST_ASSERT_FALSE(sent->ma_isParamNull[0]);
  TEST_ASSERT_FALSE(sent->ma_isParamNull[1]);
  for (int n = 2; n < 5; n++)
    TEST_ASSERT_TRUE(sent->ma_isParamNull[n]);
}

void test_recordHeadersScan_sends_the_retry_of_a_deferred_scan(void)
{
  static const struct {
    unsigned int m_retryAfterSeconds;
    const char*  mp_text;
  } cases[] = { { 1, "1" }, { 3600, "3600" } };
  for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++)
  {
    static_resetFake();
    DbHeadersScanRecord_t scan;
    memset(&scan, 0, sizeof(scan));
    scan.mp_domain           = "example.com";
    scan.mp_claimedUntil     = "2026-11-01 09:00:00+00";
    scan.m_retryAfterSeconds = cases[c].m_retryAfterSeconds;
    static_queueOneCell("written_event_count", "0");

    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_OK, db_recordHeadersScan(FAKE_CONN, &scan), cases[c].mp_text);

    const FakeCall_t* sent = static_lastCall();
    TEST_ASSERT_EQUAL_INT(5, sent->m_paramCount);
    TEST_ASSERT_TRUE_MESSAGE(sent->ma_isParamNull[2], cases[c].mp_text);
    TEST_ASSERT_TRUE_MESSAGE(sent->ma_isParamNull[3], cases[c].mp_text);
    TEST_ASSERT_FALSE_MESSAGE(sent->ma_isParamNull[4], cases[c].mp_text);
    TEST_ASSERT_EQUAL_STRING(cases[c].mp_text, sent->ma_params[4]);
  }
}

void test_recordHeadersScan_refuses_any_other_answer(void)
{
  DbHeadersScanRecord_t scan;
  memset(&scan, 0, sizeof(scan));
  scan.mp_domain       = "example.com";
  scan.mp_claimedUntil = "2026-11-01 09:00:00+00";

  for (size_t row = 0; row < sizeof(g_wrongShapes) / sizeof(g_wrongShapes[0]); row++)
  {
    static_resetFake();
    static_queueWrongShape(g_wrongShapes[row], "written_event_count", "1");
    char message[16] = "";
    snprintf(message, sizeof(message), "row %zu", row);

    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_ERROR, db_recordHeadersScan(FAKE_CONN, &scan), message);
  }

  static const char* const cells[] = { FAKE_SQL_NULL, "many", "-1" };
  for (size_t c = 0; c < sizeof(cells) / sizeof(cells[0]); c++)
  {
    static_resetFake();
    static_queueOneCell("written_event_count", cells[c]);
    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_ERROR, db_recordHeadersScan(FAKE_CONN, &scan), cells[c]);
  }

  static_resetFake();
  static_queueOneCell("written_event_count", "0");
  TEST_ASSERT_EQUAL_INT(DB_OK, db_recordHeadersScan(FAKE_CONN, &scan));
}

#define DB_DOMAIN_WATCH_RECORD_CT_CALL "SELECT api.fn_domain_watch_record_ct($1, $2, $3, $4, $5) AS written_event_count"

void test_recordCtScan_sends_each_field_in_its_own_parameter(void)
{
  WatchlistDomainValue_t value;
  static_setWatchValue(&value, "caa_mismatch pki.goog\nnew_issuer letsencrypt.org", "sha256-cert-issuers");
  const DbCtScanRecord_t scan = {
    .mp_domain               = "example.com",
    .mp_claimedUntil         = "2026-11-01 09:01:02.5+00",
    .mp_certIssuersValue     = &value,
    .m_retryAfterSeconds     = 0,
  };
  static_queueOneCell("written_event_count", "1");

  TEST_ASSERT_EQUAL_INT(DB_OK, db_recordCtScan(FAKE_CONN, &scan));

  TEST_ASSERT_EQUAL_INT(1, g_callCount);
  const FakeCall_t* sent = static_lastCall();
  TEST_ASSERT_EQUAL_STRING(DB_DOMAIN_WATCH_RECORD_CT_CALL, sent->ma_command);
  TEST_ASSERT_EQUAL_INT(0, sent->m_resultFormat);
  static const char* const expected[4] = {
    "example.com", "2026-11-01 09:01:02.5+00", "caa_mismatch pki.goog\nnew_issuer letsencrypt.org", "sha256-cert-issuers",
  };
  TEST_ASSERT_EQUAL_INT(5, sent->m_paramCount);
  for (int n = 0; n < 4; n++)
  {
    char message[16] = "";
    snprintf(message, sizeof(message), "param %d", n + 1);
    TEST_ASSERT_FALSE_MESSAGE(sent->ma_isParamNull[n], message);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(expected[n], sent->ma_params[n], message);
  }
  TEST_ASSERT_TRUE(sent->ma_isParamNull[4]);
}

void test_recordCtScan_sends_an_unset_value_as_null(void)
{
  DbCtScanRecord_t scan;
  memset(&scan, 0, sizeof(scan));
  scan.mp_domain       = "example.com";
  scan.mp_claimedUntil = "2026-11-01 09:00:00+00";
  static_queueOneCell("written_event_count", "0");

  TEST_ASSERT_EQUAL_INT(DB_OK, db_recordCtScan(FAKE_CONN, &scan));

  const FakeCall_t* sent = static_lastCall();
  TEST_ASSERT_EQUAL_INT(5, sent->m_paramCount);
  TEST_ASSERT_EQUAL_STRING("example.com", sent->ma_params[0]);
  TEST_ASSERT_EQUAL_STRING("2026-11-01 09:00:00+00", sent->ma_params[1]);
  TEST_ASSERT_FALSE(sent->ma_isParamNull[0]);
  TEST_ASSERT_FALSE(sent->ma_isParamNull[1]);
  for (int n = 2; n < 5; n++)
    TEST_ASSERT_TRUE(sent->ma_isParamNull[n]);
}

void test_recordCtScan_sends_the_retry_of_a_deferred_scan(void)
{
  static const struct {
    unsigned int m_retryAfterSeconds;
    const char*  mp_text;
  } cases[] = { { 1, "1" }, { 3600, "3600" } };
  for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++)
  {
    static_resetFake();
    DbCtScanRecord_t scan;
    memset(&scan, 0, sizeof(scan));
    scan.mp_domain           = "example.com";
    scan.mp_claimedUntil     = "2026-11-01 09:00:00+00";
    scan.m_retryAfterSeconds = cases[c].m_retryAfterSeconds;
    static_queueOneCell("written_event_count", "0");

    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_OK, db_recordCtScan(FAKE_CONN, &scan), cases[c].mp_text);

    const FakeCall_t* sent = static_lastCall();
    TEST_ASSERT_EQUAL_INT(5, sent->m_paramCount);
    TEST_ASSERT_TRUE_MESSAGE(sent->ma_isParamNull[2], cases[c].mp_text);
    TEST_ASSERT_TRUE_MESSAGE(sent->ma_isParamNull[3], cases[c].mp_text);
    TEST_ASSERT_FALSE_MESSAGE(sent->ma_isParamNull[4], cases[c].mp_text);
    TEST_ASSERT_EQUAL_STRING(cases[c].mp_text, sent->ma_params[4]);
  }
}

void test_recordCtScan_refuses_any_other_answer(void)
{
  DbCtScanRecord_t scan;
  memset(&scan, 0, sizeof(scan));
  scan.mp_domain       = "example.com";
  scan.mp_claimedUntil = "2026-11-01 09:00:00+00";

  for (size_t row = 0; row < sizeof(g_wrongShapes) / sizeof(g_wrongShapes[0]); row++)
  {
    static_resetFake();
    static_queueWrongShape(g_wrongShapes[row], "written_event_count", "1");
    char message[16] = "";
    snprintf(message, sizeof(message), "row %zu", row);

    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_ERROR, db_recordCtScan(FAKE_CONN, &scan), message);
  }

  static const char* const cells[] = { FAKE_SQL_NULL, "many", "-1" };
  for (size_t c = 0; c < sizeof(cells) / sizeof(cells[0]); c++)
  {
    static_resetFake();
    static_queueOneCell("written_event_count", cells[c]);
    TEST_ASSERT_EQUAL_INT_MESSAGE(DB_ERROR, db_recordCtScan(FAKE_CONN, &scan), cells[c]);
  }

  static_resetFake();
  static_queueOneCell("written_event_count", "0");
  TEST_ASSERT_EQUAL_INT(DB_OK, db_recordCtScan(FAKE_CONN, &scan));
}

void test_registration_gate_test_count(void)
{
  TEST_ASSERT_EQUAL_INT_MESSAGE(267, (int)Unity.NumberOfTests,
    "RUN_TEST list and test definitions have drifted apart - a test may be unregistered");
}

int main(void)
{
  UNITY_BEGIN();
  RUN_TEST(test_CVELOOKUP_long_refs_is_read_whole);
  RUN_TEST(test_CVELOOKUP_long_affected_products_is_read_whole);
  RUN_TEST(test_CVELOOKUP_long_cwes_is_read_whole);
  RUN_TEST(test_CVELOOKUP_long_cve_tags_is_read_whole);
  RUN_TEST(test_CVELOOKUP_epss_trend_at_its_length_check_is_read_whole);
  RUN_TEST(test_CVELOOKUP_epss_trend_past_its_length_check_is_refused);
  RUN_TEST(test_CVELOOKUP_nuclei_templates_at_its_length_check_is_read_whole);
  RUN_TEST(test_CVELOOKUP_nuclei_templates_past_its_length_check_is_refused);
  RUN_TEST(test_CVELOOKUP_no_row_is_not_found);
  RUN_TEST(test_CVELOOKUP_failed_query_is_error);
  RUN_TEST(test_CVELOOKUP_sends_the_id_and_the_trend_row_limit_and_asks_for_text);
  RUN_TEST(test_CVELOOKUP_no_row_leaves_every_heap_field_null);
  RUN_TEST(test_CVELOOKUP_failed_query_leaves_every_heap_field_null);
  RUN_TEST(test_CVELOOKUPRecordFree_leaves_every_heap_field_null);
  RUN_TEST(test_CVELOOKUPBULKResultFree_frees_the_array_once);
  RUN_TEST(test_CVELOOKUP_null_cwes_column_reads_as_a_null_field);
  RUN_TEST(test_CVELOOKUP_reads_ransomware_campaign_from_its_column);
  RUN_TEST(test_CVELOOKUP_null_ransomware_campaign_empties_a_reused_record);
  RUN_TEST(test_CVELOOKUP_empty_cvss_v4_vector_empties_a_reused_record);
  RUN_TEST(test_CVELOOKUP_reads_each_source_column);
  RUN_TEST(test_HEALTH_reads_each_query_answer_in_order);
  RUN_TEST(test_HEALTH_reads_at_most_HEALTH_MAX_FEEDS_feeds);
  RUN_TEST(test_HEALTH_feed_row_that_cannot_be_read_is_left_out);
  RUN_TEST(test_HEALTH_feeds_answer_with_other_columns_is_error);
  RUN_TEST(test_HEALTH_stops_at_the_first_failed_query);
  RUN_TEST(test_fake_answers_a_call_past_the_queue_as_a_failed_query);
  RUN_TEST(test_HEALTH_answer_that_is_not_one_row_is_error);
  RUN_TEST(test_fake_records_each_call_in_order);
  RUN_TEST(test_fetchColStr_copies_up_to_max_len_and_refuses_a_longer_value);
  RUN_TEST(test_fetchColStr_refusal_writes_one_line_without_the_value);
  RUN_TEST(test_CVELOOKUP_fixed_size_field_past_its_limit_is_error);
  RUN_TEST(test_CVELOOKUP_reads_each_ssvc_column_and_gives_its_decisions);
  RUN_TEST(test_CVELOOKUP_row_without_ssvc_empties_a_reused_record);
  RUN_TEST(test_CVELOOKUP_ssvc_row_the_tree_cannot_read_is_error);
  RUN_TEST(test_CVELOOKUP_ssvc_value_past_its_limit_is_refused_by_its_reader);
  RUN_TEST(test_CVESEARCH_fixed_size_field_past_its_limit_is_error);
  RUN_TEST(test_CVESEARCH_reads_each_source_column);
  RUN_TEST(test_list_queries_refuse_a_null_connection);
  RUN_TEST(test_triage_items_read_the_label_from_its_column);
  RUN_TEST(test_CVERISKSCORE_columns_land_in_their_own_fields);
  RUN_TEST(test_CVE_lists_send_the_kev_filter_as_its_value);
  RUN_TEST(test_CVE_lists_send_known_ransomware_only_when_it_is_true);
  RUN_TEST(test_CVE_lists_send_has_nuclei_template_only_when_it_is_true);
  RUN_TEST(test_CVE_lists_send_include_rejected_as_true_or_false);
  RUN_TEST(test_PRODUCTEXPOSURE_sends_include_rejected_as_true_or_false);
  RUN_TEST(test_CVE_lists_send_each_filter_in_its_own_parameter);
  RUN_TEST(test_CVE_lists_send_an_unset_filter_as_null);
  RUN_TEST(test_CVE_lists_total_that_is_not_one_row_is_error);
  RUN_TEST(test_CVE_lists_read_the_total_from_the_total_answer);
  RUN_TEST(test_CVE_lists_empty_page_is_ok);
  RUN_TEST(test_lists_send_no_page_call_at_or_past_the_total);
  RUN_TEST(test_CVETRIAGE_cve_id_past_its_limit_is_error);
  RUN_TEST(test_CVETRIAGEBULK_cve_id_past_its_limit_fails_only_its_id);
  RUN_TEST(test_CVETRIAGEBULK_sends_every_kept_id_and_fails_the_ones_without_a_row);
  RUN_TEST(test_CVETRIAGEBULK_unreadable_row_fails_only_its_id);
  RUN_TEST(test_CVETRIAGEBULK_more_rows_than_ids_is_error);
  RUN_TEST(test_CVELOOKUPBULK_sends_the_ids_and_the_trend_row_limit_in_one_call);
  RUN_TEST(test_CVELOOKUPBULK_unreadable_row_fails_only_its_id);
  RUN_TEST(test_CVELOOKUPBULK_no_row_fails_every_id);
  RUN_TEST(test_CVELOOKUPBULK_failed_query_is_error);
  RUN_TEST(test_CVELOOKUPBULK_more_rows_than_ids_is_error);
  RUN_TEST(test_CVELOOKUPBULK_reads_each_column_from_its_own_row);
  RUN_TEST(test_CVELOOKUPBULK_items_hold_no_ghsa_advisory);
  RUN_TEST(test_bulk_calls_refuse_ids_their_literal_cannot_hold);
  RUN_TEST(test_PRODUCTEXPOSURE_fixed_size_field_past_its_limit_is_error);
  RUN_TEST(test_KEVLOOKUP_fixed_size_field_past_its_limit_is_error);
  RUN_TEST(test_KEVLOOKUP_reads_notes_and_in_kev_from_their_columns);
  RUN_TEST(test_KEVLOOKUP_failed_notes_copy_frees_the_cwes_copy);
  RUN_TEST(test_CWELOOKUP_fixed_size_field_past_its_limit_is_error);
  RUN_TEST(test_HEALTH_fixed_size_field_past_its_limit_is_error);
  RUN_TEST(test_HEALTH_null_newest_row_leaves_fields_empty);
  RUN_TEST(test_failed_query_writes_one_line_naming_its_caller);
  RUN_TEST(test_succeeded_queries_write_no_line);
  RUN_TEST(test_failed_list_call_names_the_function_that_sent_it);
  RUN_TEST(test_failed_purge_call_names_the_purge_function);
  RUN_TEST(test_lines_past_the_first_in_a_second_are_counted_not_written);
  RUN_TEST(test_each_source_writes_one_line_and_its_repeat_is_dropped);
  RUN_TEST(test_fetchColDouble_reads_a_finite_number_and_nothing_else);
  RUN_TEST(test_fetchColInt_reads_an_int_and_nothing_else);
  RUN_TEST(test_fetchColInt64_reads_an_int64_and_nothing_else);
  RUN_TEST(test_fetchColBool_reads_t_and_f_and_nothing_else);
  RUN_TEST(test_readers_refuse_a_column_outside_the_result);
  RUN_TEST(test_column_list_needs_every_name_in_order);
  RUN_TEST(test_CWELOOKUP_reads_its_counts_and_a_nonfinite_average_as_zero);
  RUN_TEST(test_CWELOOKUP_failed_query_or_unreadable_count_is_error);
  RUN_TEST(test_unreadable_number_or_boolean_is_error);
  RUN_TEST(test_answer_with_other_column_names_is_error);
  RUN_TEST(test_scalar_columns_land_in_their_own_fields);
  RUN_TEST(test_each_thread_has_its_own_log_limit);
  RUN_TEST(test_clock_step_back_is_a_new_second);
  RUN_TEST(test_CVELOOKUP_reads_the_longest_cvss_v4_vector);
  RUN_TEST(test_readSchemaVersion_reads_one_int);
  RUN_TEST(test_readSchemaVersion_refuses_any_other_answer);
  RUN_TEST(test_readSchemaVersion_calls_the_api_function);
  RUN_TEST(test_readConnectionRoleState_reads_both_flags);
  RUN_TEST(test_readConnectionRoleState_refuses_any_other_answer);
  RUN_TEST(test_readConnectionRoleState_calls_the_api_function);
  RUN_TEST(test_readApiKeyState_reads_the_three_states);
  RUN_TEST(test_readApiKeyState_reads_the_expiry);
  RUN_TEST(test_readApiKeyState_refuses_any_other_answer);
  RUN_TEST(test_readApiKeyState_sends_the_hash_to_the_api_function);
  RUN_TEST(test_billing_event_calls_send_their_text_and_params);
  RUN_TEST(test_billing_expiry_calls_send_each_time_as_decimal_text);
  RUN_TEST(test_billingEventRecord_sends_an_empty_ref_as_null);
  RUN_TEST(test_billing_event_calls_read_each_status);
  RUN_TEST(test_billingEventStatusText_gives_each_answer_text);
  RUN_TEST(test_billing_event_calls_refuse_any_other_answer);
  RUN_TEST(test_billingClaim_sends_its_text_and_params);
  RUN_TEST(test_billingClaim_reads_each_status);
  RUN_TEST(test_billingClaim_refuses_any_other_answer);
  RUN_TEST(test_billing_status_one_byte_past_its_limit_logs_the_limit);
  RUN_TEST(test_readVendorKeys_sends_the_hash_and_reads_each_column);
  RUN_TEST(test_readVendorKeys_reads_an_unknown_key_and_a_missing_vendor_key_as_empty);
  RUN_TEST(test_readVendorKeys_refuses_a_broken_row);
  RUN_TEST(test_readVendorKeys_reads_the_fingerprint_with_its_limit);
  RUN_TEST(test_readVendorKeys_refuses_any_other_answer);
  RUN_TEST(test_openVendorKeyLink_sends_the_id_the_hash_and_the_lifetime);
  RUN_TEST(test_openVendorKeyLink_reads_each_answer);
  RUN_TEST(test_readVendorKeyLink_sends_the_hash_and_reads_each_column);
  RUN_TEST(test_readVendorKeyLink_reads_each_state);
  RUN_TEST(test_readVendorKeyLink_refuses_any_other_answer);
  RUN_TEST(test_vendor_key_state_one_byte_past_its_limit_logs_the_limit);
  RUN_TEST(test_applyVendorKeys_sends_each_field_in_its_own_param);
  RUN_TEST(test_applyVendorKeys_reads_each_status);
  RUN_TEST(test_CVERISKSCORE_no_row_is_not_found);
  RUN_TEST(test_PRODUCTEXPOSURE_failed_exposure_query_is_error);
  RUN_TEST(test_PRODUCTEXPOSURE_sends_the_vendor_the_product_and_the_row_limit);
  RUN_TEST(test_PRODUCTEXPOSURE_empty_version_is_sent_as_null_and_no_eol_row_is_no_eol);
  RUN_TEST(test_PRODUCTEXPOSURE_failed_eol_query_is_error);
  RUN_TEST(test_PRODUCTEXPOSURE_reads_each_eol_field_from_its_own_column);
  RUN_TEST(test_PRODUCTEXPOSURE_maintained_cycle_count_past_the_limit_sets_has_more);
  RUN_TEST(test_PRODUCTEXPOSURE_reads_at_most_the_maintained_cycle_limit);
  RUN_TEST(test_PRODUCTEXPOSURE_series_past_its_limit_is_error);
  RUN_TEST(test_PRODUCTEXPOSURE_eol_answer_with_broken_rows_is_error);
  RUN_TEST(test_PRODUCTEXPOSURE_eol_field_past_its_limit_is_error);
  RUN_TEST(test_PRODUCTEXPOSURE_reads_at_most_PRODUCTEXPOSURE_TOP_N_top_rows);
  RUN_TEST(test_PRODUCTEXPOSURE_reads_each_top_item_from_its_own_row);
  RUN_TEST(test_PRODUCTEXPOSURE_one_row_with_a_null_cve_id_has_no_top_cve);
  RUN_TEST(test_PRODUCTEXPOSURE_null_cve_id_beside_another_row_is_error);
  RUN_TEST(test_PRODUCTEXPOSURE_answer_with_no_row_is_a_zeroed_record);
  RUN_TEST(test_CPESEARCH_sends_the_query_and_the_page_and_reads_each_row);
  RUN_TEST(test_CPESEARCH_name_past_its_limit_is_error);
  RUN_TEST(test_CPESEARCH_empty_page_is_ok);
  RUN_TEST(test_D3FENDFORATTACK_sends_the_id_and_reads_each_row);
  RUN_TEST(test_D3FENDFORATTACK_text_past_its_limit_is_error);
  RUN_TEST(test_D3FENDFORATTACK_failed_copy_frees_every_copy);
  RUN_TEST(test_D3FENDFORATTACK_no_row_is_ok_and_failed_query_is_error);
  RUN_TEST(test_DRIVERLOOKUP_sends_the_hash_and_reads_each_column);
  RUN_TEST(test_DRIVERLOOKUP_hash_and_matches_at_their_limits_and_past_them);
  RUN_TEST(test_DRIVERLOOKUP_other_than_one_row_or_a_failed_copy_is_error);
  RUN_TEST(test_DRIVERLOOKUPBULK_sends_the_hashes_and_reads_each_row);
  RUN_TEST(test_DRIVERLOOKUPBULK_unreadable_row_fails_only_its_hash);
  RUN_TEST(test_DRIVERLOOKUPBULK_other_row_count_is_error);
  RUN_TEST(test_IPLOOKUP_sends_the_address_and_reads_each_column);
  RUN_TEST(test_IPLOOKUP_null_texts_and_asn_read_as_empty);
  RUN_TEST(test_IPLOOKUP_unloaded_feed_leaves_its_column_unread);
  RUN_TEST(test_IPLOOKUP_null_in_a_loaded_feed_or_a_feed_flag_is_error);
  RUN_TEST(test_IPLOOKUP_no_cloud_range_leaves_is_cdn_unread);
  RUN_TEST(test_IPLOOKUP_null_datacenter_is_false_only_while_a_feed_is_off);
  RUN_TEST(test_IPLOOKUP_asn_from_1_to_4294967295_and_nothing_else);
  RUN_TEST(test_IPLOOKUP_texts_and_listed_on_at_their_limits_and_past_them);
  RUN_TEST(test_IPLOOKUP_other_than_one_row_a_failed_copy_or_a_long_address_is_error);
  RUN_TEST(test_EMAILADDRESSCHECK_sends_the_domain_and_reads_each_column);
  RUN_TEST(test_EMAILADDRESSCHECK_null_listed_domain_reads_as_empty);
  RUN_TEST(test_EMAILADDRESSCHECK_listed_domain_must_be_the_domain_or_a_parent);
  RUN_TEST(test_EMAILADDRESSCHECK_listed_public_suffix_counts_as_not_listed);
  RUN_TEST(test_EMAILADDRESSCHECK_listed_domain_at_its_limit_and_past_it);
  RUN_TEST(test_EMAILADDRESSCHECK_other_than_one_row_a_null_flag_or_a_failed_query_is_error);
  RUN_TEST(test_SSLCHECK_sends_the_fingerprint_and_reads_each_column);
  RUN_TEST(test_SSLCHECK_listing_must_be_whole_and_fit);
  RUN_TEST(test_SSLCHECK_other_than_one_row_a_null_flag_or_a_failed_query_is_error);
  RUN_TEST(test_ASNLOOKUP_ip_target_reads_its_prefix_then_its_as);
  RUN_TEST(test_ASNLOOKUP_as_target_reads_its_as_alone);
  RUN_TEST(test_ASNLOOKUP_no_row_at_either_step_is_not_found);
  RUN_TEST(test_ASNLOOKUP_two_rows_or_a_failed_query_at_either_step_is_error);
  RUN_TEST(test_ASNLOOKUP_null_country_reads_as_empty);
  RUN_TEST(test_ASNLOOKUP_asn_from_1_to_4294967295_at_both_steps_and_nothing_else);
  RUN_TEST(test_ASNLOOKUP_counts_are_never_null_or_negative);
  RUN_TEST(test_ASNLOOKUP_prefix_lists_are_never_null);
  RUN_TEST(test_ASNLOOKUP_texts_and_lists_at_their_limits_and_past_them);
  RUN_TEST(test_ASNLOOKUP_failed_copy_of_either_list_is_error);
  RUN_TEST(test_ASNLOOKUP_asn_too_long_for_its_parameter_is_error);
  RUN_TEST(test_PACKAGECHECK_sends_its_params_and_reads_each_column);
  RUN_TEST(test_PACKAGECHECK_reads_the_eol_answer);
  RUN_TEST(test_PACKAGECHECK_failed_or_refused_eol_answer_is_error);
  RUN_TEST(test_PACKAGECHECK_fixed_version_and_texts_at_their_limits_and_past_them);
  RUN_TEST(test_PACKAGECHECK_other_than_one_row_or_a_failed_copy_is_error);
  RUN_TEST(test_buildTextArrayLiteral_quotes_each_value_and_escapes_its_quotes_and_backslashes);
  RUN_TEST(test_buildTextArrayLiteral_fits_a_value_whose_every_byte_is_escaped);
  RUN_TEST(test_PACKAGECHECKBULK_sends_three_literals_and_reads_each_column);
  RUN_TEST(test_PACKAGECHECKBULK_counts_failed_packages_and_refuses_a_count_out_of_range);
  RUN_TEST(test_PACKAGECHECKBULK_texts_at_their_limit_and_past_it);
  RUN_TEST(test_PACKAGECHECKBULK_other_than_one_row_or_a_failed_copy_is_error);
  RUN_TEST(test_PACKAGECHECKBULKWeigh_sends_two_literals_and_the_three_weight_values);
  RUN_TEST(test_PACKAGECHECKBULKWeigh_refuses_any_other_answer);
  RUN_TEST(test_CVEPRODUCTS_sends_its_params_and_reads_each_column);
  RUN_TEST(test_CVEPRODUCTS_no_row_is_not_found_and_other_answers_are_errors);
  RUN_TEST(test_CVELOOKUPGHSA_sends_its_params_and_reads_each_column);
  RUN_TEST(test_CVELOOKUPGHSA_other_than_one_row_a_failed_copy_or_a_long_advisory_is_error);
  RUN_TEST(test_purgeExpiredCveChangeEvents_runs_again_after_a_full_batch);
  RUN_TEST(test_purgeExpiredCveChangeEvents_refuses_any_other_answer);
  RUN_TEST(test_WATCHLISTEDIT_sends_each_value_in_its_own_parameter);
  RUN_TEST(test_WATCHLISTEDIT_package_list_sends_its_elements_as_three_arrays);
  RUN_TEST(test_WATCHLISTEDIT_package_list_reads_no_element_past_the_last);
  RUN_TEST(test_WATCHLISTEDIT_package_list_reads_its_counts_and_repeats);
  RUN_TEST(test_WATCHLISTEDIT_package_list_refuses_an_answer_it_cannot_trust);
  RUN_TEST(test_WATCHLISTEDIT_binds_each_kind_from_its_own_member);
  RUN_TEST(test_WATCHLISTEDIT_binds_an_unset_product_exposure_version_as_null);
  RUN_TEST(test_WATCHLISTEDIT_reads_each_item_column);
  RUN_TEST(test_WATCHLISTEDIT_reads_each_cve_id_kind);
  RUN_TEST(test_lookups_answer_not_found_for_no_row_and_error_for_a_failed_query);
  RUN_TEST(test_WATCHLISTEDIT_reads_the_narrow_answer_of_each_shape);
  RUN_TEST(test_WATCHLISTEDIT_reads_the_wide_answer_of_a_list_and_a_clear);
  RUN_TEST(test_WATCHLISTEVENTS_sends_its_six_parameters);
  RUN_TEST(test_WATCHLISTEVENTS_reads_each_event_column);
  RUN_TEST(test_WATCHLISTEVENTS_reads_items_pairs_and_shared_events);
  RUN_TEST(test_WATCHLISTEVENTS_reads_domain_events_and_facts);
  RUN_TEST(test_WATCHLISTEVENTS_refuses_each_broken_row_rule);
  RUN_TEST(test_WATCHLISTEVENTS_frees_every_text_after_a_failed_copy);
  RUN_TEST(test_WATCHLISTEVENTS_fills_and_frees_an_event_of_each_kind);
  RUN_TEST(test_WATCHLISTEVENTS_frees_a_half_filled_answer_of_each_kind);
  RUN_TEST(test_WATCHLISTEVENTS_reads_package_events_and_advisories);
  RUN_TEST(test_WATCHLISTEVENTS_takes_the_event_kind_from_the_row);
  RUN_TEST(test_WATCHLISTEVENTS_ip_limits_match_the_schema);
  RUN_TEST(test_WATCHLISTEVENTS_reads_ip_cells_at_their_limits);
  RUN_TEST(test_WATCHLISTEVENTS_reads_eol_events);
  RUN_TEST(test_WATCHLISTEVENTS_reads_eol_texts_at_their_limits);
  RUN_TEST(test_WATCHLISTEVENTS_refuses_each_broken_eol_row);
  RUN_TEST(test_WATCHLISTEVENTS_reads_package_cells_at_their_limits);
  RUN_TEST(test_WATCHLISTEVENTS_refuses_each_broken_package_row);
  RUN_TEST(test_WATCHLISTEVENTS_frees_package_texts_after_a_failed_copy);
  RUN_TEST(test_WATCHLISTEVENTS_package_limits_match_the_schema);
  RUN_TEST(test_purgeExpiredWatchlists_runs_again_after_a_full_batch);
  RUN_TEST(test_purgeExpiredWatchlists_refuses_any_other_answer);
  RUN_TEST(test_table_purges_run_again_after_a_full_batch);
  RUN_TEST(test_table_purges_refuse_any_other_answer);
  RUN_TEST(test_ip_watch_jobs_run_again_after_a_full_batch);
  RUN_TEST(test_ip_watch_jobs_refuse_any_other_answer);
  RUN_TEST(test_vendor_key_purges_run_again_after_a_full_batch);
  RUN_TEST(test_vendor_key_purges_refuse_any_other_answer);
  RUN_TEST(test_billing_event_purge_runs_again_after_a_full_batch);
  RUN_TEST(test_billing_event_purge_refuses_any_other_answer);
  RUN_TEST(test_purgeExpiredPackageAdvisoryChangeEvents_runs_again_after_a_full_batch);
  RUN_TEST(test_purgeExpiredPackageAdvisoryChangeEvents_refuses_any_other_answer);
  RUN_TEST(test_claimDomainLaneScans_sends_its_params_and_reads_each_column);
  RUN_TEST(test_claimDomainLaneScans_no_row_is_ok);
  RUN_TEST(test_claimDomainLaneScans_refuses_a_wrong_answer);
  RUN_TEST(test_claimDomainLaneScans_texts_at_their_limits_and_past_them);
  RUN_TEST(test_recordDnsScan_sends_each_field_in_its_own_parameter);
  RUN_TEST(test_recordDnsScan_sends_an_unset_value_as_null);
  RUN_TEST(test_recordDnsScan_refuses_any_other_answer);
  RUN_TEST(test_recordTlsScan_sends_each_field_in_its_own_parameter);
  RUN_TEST(test_recordTlsScan_sends_an_unset_value_as_null);
  RUN_TEST(test_recordTlsScan_refuses_any_other_answer);
  RUN_TEST(test_recordRdapWhoisScan_sends_each_field_in_its_own_parameter);
  RUN_TEST(test_recordRdapWhoisScan_sends_an_unset_value_as_null);
  RUN_TEST(test_recordRdapWhoisScan_sends_the_retry_of_a_deferred_scan);
  RUN_TEST(test_recordRdapWhoisScan_refuses_any_other_answer);
  RUN_TEST(test_recordHeadersScan_sends_each_field_in_its_own_parameter);
  RUN_TEST(test_recordHeadersScan_sends_an_unset_value_as_null);
  RUN_TEST(test_recordHeadersScan_sends_the_retry_of_a_deferred_scan);
  RUN_TEST(test_recordHeadersScan_refuses_any_other_answer);
  RUN_TEST(test_recordCtScan_sends_each_field_in_its_own_parameter);
  RUN_TEST(test_recordCtScan_sends_an_unset_value_as_null);
  RUN_TEST(test_recordCtScan_sends_the_retry_of_a_deferred_scan);
  RUN_TEST(test_recordCtScan_refuses_any_other_answer);
  RUN_TEST(test_registration_gate_test_count);
  RUN_TEST(test_billing_nowpayments_order_paid_sends_its_text_and_params);
  RUN_TEST(test_billing_nowpayments_order_paid_refuses_a_wrong_answer);
  return UNITY_END();
}
