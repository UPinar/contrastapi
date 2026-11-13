#include <assert.h>
#include <math.h>
#include <stdbool.h>
#include <string.h>

#include "cvss.h"
#include "bytes.h"

#define CVSS_PREFIX_LEN (sizeof("CVSS:3.1/") - 1)

typedef enum {
  CVSS_METRIC_AV = 0,
  CVSS_METRIC_AC,
  CVSS_METRIC_PR,
  CVSS_METRIC_UI,
  CVSS_METRIC_S,
  CVSS_METRIC_C,
  CVSS_METRIC_I,
  CVSS_METRIC_A,

  CVSS_METRIC_E,
  CVSS_METRIC_RL,
  CVSS_METRIC_RC,

  CVSS_METRIC_CR,
  CVSS_METRIC_IR,
  CVSS_METRIC_AR,
  CVSS_METRIC_MAV,
  CVSS_METRIC_MAC,
  CVSS_METRIC_MPR,
  CVSS_METRIC_MUI,
  CVSS_METRIC_MS,
  CVSS_METRIC_MC,
  CVSS_METRIC_MI,
  CVSS_METRIC_MA,

  CVSS_METRIC_COUNT
} CvssMetricIndex_t;

#define CVSS_BASE_METRIC_COUNT (CVSS_METRIC_A + 1)

static const char* const METRIC_ABBREVIATIONS[CVSS_METRIC_COUNT] = {
  "AV", "AC", "PR", "UI", "S", "C", "I", "A",
  "E", "RL", "RC",
  "CR", "IR", "AR",
  "MAV", "MAC", "MPR", "MUI", "MS", "MC", "MI", "MA"
};

typedef struct {
  int         m_metricIndex;
  char        m_letter;
  double      m_weight;
  double      m_weightScopeChanged;
  const char* mp_label;
} CvssMetricValue_t;

static const CvssMetricValue_t METRIC_VALUES[] = {
  { CVSS_METRIC_AV, 'N', 0.85, 0.85, "NETWORK"          },
  { CVSS_METRIC_AV, 'A', 0.62, 0.62, "ADJACENT_NETWORK" },
  { CVSS_METRIC_AV, 'L', 0.55, 0.55, "LOCAL"            },
  { CVSS_METRIC_AV, 'P', 0.20, 0.20, "PHYSICAL"         },

  { CVSS_METRIC_AC, 'L', 0.77, 0.77, "LOW"  },
  { CVSS_METRIC_AC, 'H', 0.44, 0.44, "HIGH" },

  { CVSS_METRIC_PR, 'N', 0.85, 0.85, "NONE" },
  { CVSS_METRIC_PR, 'L', 0.62, 0.68, "LOW"  },
  { CVSS_METRIC_PR, 'H', 0.27, 0.50, "HIGH" },

  { CVSS_METRIC_UI, 'N', 0.85, 0.85, "NONE"     },
  { CVSS_METRIC_UI, 'R', 0.62, 0.62, "REQUIRED" },

  { CVSS_METRIC_S,  'U', 0.0, 0.0, "UNCHANGED" },
  { CVSS_METRIC_S,  'C', 0.0, 0.0, "CHANGED"   },

  { CVSS_METRIC_C,  'H', 0.56, 0.56, "HIGH" },
  { CVSS_METRIC_C,  'L', 0.22, 0.22, "LOW"  },
  { CVSS_METRIC_C,  'N', 0.00, 0.00, "NONE" },
  { CVSS_METRIC_I,  'H', 0.56, 0.56, "HIGH" },
  { CVSS_METRIC_I,  'L', 0.22, 0.22, "LOW"  },
  { CVSS_METRIC_I,  'N', 0.00, 0.00, "NONE" },
  { CVSS_METRIC_A,  'H', 0.56, 0.56, "HIGH" },
  { CVSS_METRIC_A,  'L', 0.22, 0.22, "LOW"  },
  { CVSS_METRIC_A,  'N', 0.00, 0.00, "NONE" },

  { CVSS_METRIC_E,  'X', 1.00, 1.00, NULL }, { CVSS_METRIC_E,  'H', 1.00, 1.00, NULL },
  { CVSS_METRIC_E,  'F', 0.97, 0.97, NULL }, { CVSS_METRIC_E,  'P', 0.94, 0.94, NULL },
  { CVSS_METRIC_E,  'U', 0.91, 0.91, NULL },

  { CVSS_METRIC_RL, 'X', 1.00, 1.00, NULL }, { CVSS_METRIC_RL, 'U', 1.00, 1.00, NULL },
  { CVSS_METRIC_RL, 'W', 0.97, 0.97, NULL }, { CVSS_METRIC_RL, 'T', 0.96, 0.96, NULL },
  { CVSS_METRIC_RL, 'O', 0.95, 0.95, NULL },

  { CVSS_METRIC_RC, 'X', 1.00, 1.00, NULL }, { CVSS_METRIC_RC, 'C', 1.00, 1.00, NULL },
  { CVSS_METRIC_RC, 'R', 0.96, 0.96, NULL }, { CVSS_METRIC_RC, 'U', 0.92, 0.92, NULL },

  { CVSS_METRIC_CR, 'X', 1.0, 1.0, NULL }, { CVSS_METRIC_CR, 'H', 1.5, 1.5, NULL },
  { CVSS_METRIC_CR, 'M', 1.0, 1.0, NULL }, { CVSS_METRIC_CR, 'L', 0.5, 0.5, NULL },
  { CVSS_METRIC_IR, 'X', 1.0, 1.0, NULL }, { CVSS_METRIC_IR, 'H', 1.5, 1.5, NULL },
  { CVSS_METRIC_IR, 'M', 1.0, 1.0, NULL }, { CVSS_METRIC_IR, 'L', 0.5, 0.5, NULL },
  { CVSS_METRIC_AR, 'X', 1.0, 1.0, NULL }, { CVSS_METRIC_AR, 'H', 1.5, 1.5, NULL },
  { CVSS_METRIC_AR, 'M', 1.0, 1.0, NULL }, { CVSS_METRIC_AR, 'L', 0.5, 0.5, NULL },

  { CVSS_METRIC_MAV, 'X', 0.00, 0.00, NULL }, { CVSS_METRIC_MAV, 'N', 0.85, 0.85, NULL },
  { CVSS_METRIC_MAV, 'A', 0.62, 0.62, NULL }, { CVSS_METRIC_MAV, 'L', 0.55, 0.55, NULL },
  { CVSS_METRIC_MAV, 'P', 0.20, 0.20, NULL },

  { CVSS_METRIC_MAC, 'X', 0.00, 0.00, NULL }, { CVSS_METRIC_MAC, 'L', 0.77, 0.77, NULL },
  { CVSS_METRIC_MAC, 'H', 0.44, 0.44, NULL },

  { CVSS_METRIC_MPR, 'X', 0.00, 0.00, NULL }, { CVSS_METRIC_MPR, 'N', 0.85, 0.85, NULL },
  { CVSS_METRIC_MPR, 'L', 0.62, 0.68, NULL }, { CVSS_METRIC_MPR, 'H', 0.27, 0.50, NULL },

  { CVSS_METRIC_MUI, 'X', 0.00, 0.00, NULL }, { CVSS_METRIC_MUI, 'N', 0.85, 0.85, NULL },
  { CVSS_METRIC_MUI, 'R', 0.62, 0.62, NULL },

  { CVSS_METRIC_MS,  'X', 0.0, 0.0, NULL }, { CVSS_METRIC_MS,  'U', 0.0, 0.0, NULL },
  { CVSS_METRIC_MS,  'C', 0.0, 0.0, NULL },

  { CVSS_METRIC_MC, 'X', 0.00, 0.00, NULL }, { CVSS_METRIC_MC, 'H', 0.56, 0.56, NULL },
  { CVSS_METRIC_MC, 'L', 0.22, 0.22, NULL }, { CVSS_METRIC_MC, 'N', 0.00, 0.00, NULL },
  { CVSS_METRIC_MI, 'X', 0.00, 0.00, NULL }, { CVSS_METRIC_MI, 'H', 0.56, 0.56, NULL },
  { CVSS_METRIC_MI, 'L', 0.22, 0.22, NULL }, { CVSS_METRIC_MI, 'N', 0.00, 0.00, NULL },
  { CVSS_METRIC_MA, 'X', 0.00, 0.00, NULL }, { CVSS_METRIC_MA, 'H', 0.56, 0.56, NULL },
  { CVSS_METRIC_MA, 'L', 0.22, 0.22, NULL }, { CVSS_METRIC_MA, 'N', 0.00, 0.00, NULL },
};

static const size_t metric_value_count = sizeof(METRIC_VALUES) / sizeof(METRIC_VALUES[0]);

static double static_roundup(double score)
{
  assert(score >= 0.0);
  long long scaled_score = llround(score * 100000.0);
  if (scaled_score % 10000 == 0)
    return (double)scaled_score / 100000.0;
  long long whole_tenths = scaled_score / 10000;
  return (double)(whole_tenths + 1) / 10.0;
}

static const CvssMetricValue_t* static_findMetricValue(int metric_index, char letter)
{
  for (size_t i = 0; i < metric_value_count; i++)
    if (METRIC_VALUES[i].m_metricIndex == metric_index && METRIC_VALUES[i].m_letter == letter)
      return &METRIC_VALUES[i];
  return NULL;
}

static int static_findMetricIndex(const char* abbreviation, size_t abbreviation_len)
{
  for (int i = 0; i < CVSS_METRIC_COUNT; i++)
    if (bytes_isEqual(abbreviation, abbreviation_len, METRIC_ABBREVIATIONS[i], false))
      return i;
  return -1;
}

static double static_metricWeight(const char* metric_letters, int metric_index, bool scope_changed)
{
  const CvssMetricValue_t* row = static_findMetricValue(metric_index, metric_letters[metric_index]);
  assert(row != NULL);
  return scope_changed ? row->m_weightScopeChanged : row->m_weight;
}

static double static_modifiedMetricWeight(const char* metric_letters, int modified_index, int base_index, bool scope_changed)
{
  if (metric_letters[modified_index] == 'X')
    return static_metricWeight(metric_letters, base_index, scope_changed);
  return static_metricWeight(metric_letters, modified_index, scope_changed);
}

static const char* static_severityForScore(double score)
{
  if (score <= 0.0)
    return "NONE";
  else if (score < 4.0)
    return "LOW";
  else if (score < 7.0)
    return "MEDIUM";
  else if (score < 9.0)
    return "HIGH";
  else
    return "CRITICAL";
}

static void static_copyMetricLabel(char* label_out, int metric_index, const char* metric_letters)
{
  const CvssMetricValue_t* row = static_findMetricValue(metric_index, metric_letters[metric_index]);
  assert(row != NULL && row->mp_label != NULL);
  size_t label_len = strlen(row->mp_label);
  assert(label_len < CVSS_LABEL_LEN);
  memcpy(label_out, row->mp_label, label_len + 1);
}

static void static_computeScores(const char* metric_letters, bool is_v31, CvssResult_t* result_out)
{
  bool scope_changed = (metric_letters[CVSS_METRIC_S] == 'C');

  double confidentiality = static_metricWeight(metric_letters, CVSS_METRIC_C, scope_changed);
  double integrity       = static_metricWeight(metric_letters, CVSS_METRIC_I, scope_changed);
  double availability    = static_metricWeight(metric_letters, CVSS_METRIC_A, scope_changed);
  double impact_subscore = 1.0 - ((1.0 - confidentiality) * (1.0 - integrity) * (1.0 - availability));
  double impact          = scope_changed ? 7.52 * (impact_subscore - 0.029) - 3.25 * pow(impact_subscore - 0.02, 15.0) : 6.42 * impact_subscore;
  double exploitability  = 8.22 * static_metricWeight(metric_letters, CVSS_METRIC_AV, scope_changed) * static_metricWeight(metric_letters, CVSS_METRIC_AC, scope_changed) * static_metricWeight(metric_letters, CVSS_METRIC_PR, scope_changed) * static_metricWeight(metric_letters, CVSS_METRIC_UI, scope_changed);

  if (impact <= 0.0)
  {
    result_out->m_baseScore = 0.0;
  }
  else
  {
    double raw_base_score = scope_changed ? 1.08 * (impact + exploitability) : impact + exploitability;
    result_out->m_baseScore = static_roundup(raw_base_score < 10.0 ? raw_base_score : 10.0);
  }

  double temporal_factor = static_metricWeight(metric_letters, CVSS_METRIC_E, scope_changed) * static_metricWeight(metric_letters, CVSS_METRIC_RL, scope_changed) * static_metricWeight(metric_letters, CVSS_METRIC_RC, scope_changed);
  result_out->m_temporalScore = static_roundup(result_out->m_baseScore * temporal_factor);

  bool modified_scope_changed = (metric_letters[CVSS_METRIC_MS] == 'X') ? scope_changed : (metric_letters[CVSS_METRIC_MS] == 'C');

  double modified_confidentiality = static_modifiedMetricWeight(metric_letters, CVSS_METRIC_MC, CVSS_METRIC_C, modified_scope_changed) * static_metricWeight(metric_letters, CVSS_METRIC_CR, modified_scope_changed);
  double modified_integrity       = static_modifiedMetricWeight(metric_letters, CVSS_METRIC_MI, CVSS_METRIC_I, modified_scope_changed) * static_metricWeight(metric_letters, CVSS_METRIC_IR, modified_scope_changed);
  double modified_availability    = static_modifiedMetricWeight(metric_letters, CVSS_METRIC_MA, CVSS_METRIC_A, modified_scope_changed) * static_metricWeight(metric_letters, CVSS_METRIC_AR, modified_scope_changed);
  double raw_modified_subscore    = 1.0 - ((1.0 - modified_confidentiality) * (1.0 - modified_integrity) * (1.0 - modified_availability));
  double modified_subscore        = raw_modified_subscore < 0.915 ? raw_modified_subscore : 0.915;

  double modified_impact;
  if (!modified_scope_changed)
    modified_impact = 6.42 * modified_subscore;
  else if (is_v31)
    modified_impact = 7.52 * (modified_subscore - 0.029) - 3.25 * pow(modified_subscore * 0.9731 - 0.02, 13.0);
  else
    modified_impact = 7.52 * (modified_subscore - 0.029) - 3.25 * pow(modified_subscore - 0.02, 15.0);

  double modified_exploitability = 8.22 * static_modifiedMetricWeight(metric_letters, CVSS_METRIC_MAV, CVSS_METRIC_AV, modified_scope_changed) * static_modifiedMetricWeight(metric_letters, CVSS_METRIC_MAC, CVSS_METRIC_AC, modified_scope_changed) * static_modifiedMetricWeight(metric_letters, CVSS_METRIC_MPR, CVSS_METRIC_PR, modified_scope_changed) * static_modifiedMetricWeight(metric_letters, CVSS_METRIC_MUI, CVSS_METRIC_UI, modified_scope_changed);

  if (modified_impact <= 0.0)
  {
    result_out->m_environmentalScore = 0.0;
  }
  else
  {
    double raw_modified_score     = modified_scope_changed ? 1.08 * (modified_impact + modified_exploitability) : modified_impact + modified_exploitability;
    double rounded_modified_score = static_roundup(raw_modified_score < 10.0 ? raw_modified_score : 10.0);
    result_out->m_environmentalScore = static_roundup(rounded_modified_score * temporal_factor);
  }
}

CvssParseStatus_t cvss_parse(const char* vector, CvssResult_t* result_out)
{
  assert(result_out != NULL);

  memset(result_out, 0, sizeof(*result_out));

  if (vector == NULL || vector[0] == '\0')
    return CVSS_ERR_EMPTY;

  size_t vector_len = strlen(vector);
  if (vector_len >= CVSS_VECTOR_MAX_LEN)
    return CVSS_ERR_TOO_LONG;

  bool is_v31;
  if (strncmp(vector, "CVSS:3.1/", CVSS_PREFIX_LEN) == 0)
    is_v31 = true;
  else if (strncmp(vector, "CVSS:3.0/", CVSS_PREFIX_LEN) == 0)
    is_v31 = false;
  else
    return CVSS_ERR_NOT_V3;

  char metric_letters[CVSS_METRIC_COUNT] = { 0 };

  const char* cursor = vector + CVSS_PREFIX_LEN;
  while (*cursor != '\0')
  {
    const char* slash = strchr(cursor, '/');
    size_t component_len = (slash != NULL) ? (size_t)(slash - cursor) : strlen(cursor);
    if (component_len == 0)
      return CVSS_ERR_EMPTY_COMPONENT;

    const char* colon = memchr(cursor, ':', component_len);
    if (colon == NULL)
      return CVSS_ERR_UNKNOWN_METRIC;

    size_t abbreviation_len = (size_t)(colon - cursor);
    int metric_index = static_findMetricIndex(cursor, abbreviation_len);
    if (metric_index < 0)
      return CVSS_ERR_UNKNOWN_METRIC;

    size_t value_len = component_len - abbreviation_len - 1;
    if (value_len != 1 || static_findMetricValue(metric_index, colon[1]) == NULL)
      return CVSS_ERR_UNKNOWN_VALUE;
    if (metric_letters[metric_index] != '\0')
      return CVSS_ERR_DUPLICATE_METRIC;
    metric_letters[metric_index] = colon[1];

    if (slash == NULL)
      break;
    cursor = slash + 1;
    if (*cursor == '\0')
      return CVSS_ERR_EMPTY_COMPONENT;
  }

  for (int i = 0; i < CVSS_BASE_METRIC_COUNT; i++)
    if (metric_letters[i] == '\0')
      return CVSS_ERR_MISSING_BASE_METRIC;

  for (int i = CVSS_BASE_METRIC_COUNT; i < CVSS_METRIC_COUNT; i++)
    if (metric_letters[i] == '\0')
      metric_letters[i] = 'X';

  for (int i = 0; i < CVSS_METRIC_COUNT; i++)
    if (static_findMetricValue(i, metric_letters[i]) == NULL)
      return CVSS_ERR_UNKNOWN_VALUE;

  memcpy(result_out->ma_vector, vector, vector_len + 1);
  memcpy(result_out->ma_version, is_v31 ? "3.1" : "3.0", CVSS_VERSION_LEN);

  static_computeScores(metric_letters, is_v31, result_out);

  static_copyMetricLabel(result_out->ma_attackVector,          CVSS_METRIC_AV, metric_letters);
  static_copyMetricLabel(result_out->ma_attackComplexity,      CVSS_METRIC_AC, metric_letters);
  static_copyMetricLabel(result_out->ma_privilegesRequired,    CVSS_METRIC_PR, metric_letters);
  static_copyMetricLabel(result_out->ma_userInteraction,       CVSS_METRIC_UI, metric_letters);
  static_copyMetricLabel(result_out->ma_scope,                 CVSS_METRIC_S,  metric_letters);
  static_copyMetricLabel(result_out->ma_confidentialityImpact, CVSS_METRIC_C,  metric_letters);
  static_copyMetricLabel(result_out->ma_integrityImpact,       CVSS_METRIC_I,  metric_letters);
  static_copyMetricLabel(result_out->ma_availabilityImpact,    CVSS_METRIC_A,  metric_letters);

  const char* base_severity = static_severityForScore(result_out->m_baseScore);
  memcpy(result_out->ma_baseSeverity, base_severity, strlen(base_severity) + 1);

  return CVSS_OK;
}

const char* cvss_parseStatusMessage(CvssParseStatus_t status)
{
  switch (status)
  {
    case CVSS_OK:                      return NULL;
    case CVSS_ERR_EMPTY:               return "vector is required";
    case CVSS_ERR_TOO_LONG:            return "vector is too long";
    case CVSS_ERR_NOT_V3:              return "vector must start with CVSS:3.0/ or CVSS:3.1/";
    case CVSS_ERR_UNKNOWN_METRIC:      return "vector has a component that is not a CVSS v3 metric";
    case CVSS_ERR_UNKNOWN_VALUE:       return "vector has a metric value CVSS v3 does not define";
    case CVSS_ERR_DUPLICATE_METRIC:    return "vector repeats a metric";
    case CVSS_ERR_MISSING_BASE_METRIC: return "vector is missing a base metric: AV, AC, PR, UI, S, C, I and A are required";
    case CVSS_ERR_EMPTY_COMPONENT:     return "vector has an empty component: a trailing or doubled slash";
  }
  return NULL;
}
