#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include "ssvc.h"

typedef enum {
  SSVC_EXPLOITATION_NONE = 0,
  SSVC_EXPLOITATION_POC,
  SSVC_EXPLOITATION_ACTIVE,
  SSVC_EXPLOITATION_VALUE_COUNT
} SsvcExploitation_t;

typedef enum {
  SSVC_AUTOMATABLE_NO = 0,
  SSVC_AUTOMATABLE_YES,
  SSVC_AUTOMATABLE_VALUE_COUNT
} SsvcAutomatable_t;

typedef enum {
  SSVC_TECHNICAL_IMPACT_PARTIAL = 0,
  SSVC_TECHNICAL_IMPACT_TOTAL,
  SSVC_TECHNICAL_IMPACT_VALUE_COUNT
} SsvcTechnicalImpact_t;

static const char* const EXPLOITATION_NAMES[SSVC_EXPLOITATION_VALUE_COUNT] = { "none", "poc", "active" };
static const char* const AUTOMATABLE_NAMES[SSVC_AUTOMATABLE_VALUE_COUNT] = { "no", "yes" };
static const char* const TECHNICAL_IMPACT_NAMES[SSVC_TECHNICAL_IMPACT_VALUE_COUNT] = { "partial", "total" };

typedef struct {
  SsvcExploitation_t     m_exploitation;
  SsvcAutomatable_t      m_automatable;
  SsvcTechnicalImpact_t  m_technicalImpact;
  SsvcMissionWellbeing_t m_missionWellbeing;
  const char*            mp_decision;
} SsvcDecisionRow_t;

static const SsvcDecisionRow_t DECISION_ROWS[] = {
  { SSVC_EXPLOITATION_NONE,   SSVC_AUTOMATABLE_NO,  SSVC_TECHNICAL_IMPACT_PARTIAL, SSVC_MISSION_WELLBEING_LOW,    "Track" },
  { SSVC_EXPLOITATION_NONE,   SSVC_AUTOMATABLE_NO,  SSVC_TECHNICAL_IMPACT_PARTIAL, SSVC_MISSION_WELLBEING_MEDIUM, "Track" },
  { SSVC_EXPLOITATION_NONE,   SSVC_AUTOMATABLE_NO,  SSVC_TECHNICAL_IMPACT_PARTIAL, SSVC_MISSION_WELLBEING_HIGH,   "Track" },
  { SSVC_EXPLOITATION_NONE,   SSVC_AUTOMATABLE_NO,  SSVC_TECHNICAL_IMPACT_TOTAL,   SSVC_MISSION_WELLBEING_LOW,    "Track" },
  { SSVC_EXPLOITATION_NONE,   SSVC_AUTOMATABLE_NO,  SSVC_TECHNICAL_IMPACT_TOTAL,   SSVC_MISSION_WELLBEING_MEDIUM, "Track" },
  { SSVC_EXPLOITATION_NONE,   SSVC_AUTOMATABLE_NO,  SSVC_TECHNICAL_IMPACT_TOTAL,   SSVC_MISSION_WELLBEING_HIGH,   "Track*" },
  { SSVC_EXPLOITATION_NONE,   SSVC_AUTOMATABLE_YES, SSVC_TECHNICAL_IMPACT_PARTIAL, SSVC_MISSION_WELLBEING_LOW,    "Track" },
  { SSVC_EXPLOITATION_NONE,   SSVC_AUTOMATABLE_YES, SSVC_TECHNICAL_IMPACT_PARTIAL, SSVC_MISSION_WELLBEING_MEDIUM, "Track" },
  { SSVC_EXPLOITATION_NONE,   SSVC_AUTOMATABLE_YES, SSVC_TECHNICAL_IMPACT_PARTIAL, SSVC_MISSION_WELLBEING_HIGH,   "Attend" },
  { SSVC_EXPLOITATION_NONE,   SSVC_AUTOMATABLE_YES, SSVC_TECHNICAL_IMPACT_TOTAL,   SSVC_MISSION_WELLBEING_LOW,    "Track" },
  { SSVC_EXPLOITATION_NONE,   SSVC_AUTOMATABLE_YES, SSVC_TECHNICAL_IMPACT_TOTAL,   SSVC_MISSION_WELLBEING_MEDIUM, "Track" },
  { SSVC_EXPLOITATION_NONE,   SSVC_AUTOMATABLE_YES, SSVC_TECHNICAL_IMPACT_TOTAL,   SSVC_MISSION_WELLBEING_HIGH,   "Attend" },
  { SSVC_EXPLOITATION_POC,    SSVC_AUTOMATABLE_NO,  SSVC_TECHNICAL_IMPACT_PARTIAL, SSVC_MISSION_WELLBEING_LOW,    "Track" },
  { SSVC_EXPLOITATION_POC,    SSVC_AUTOMATABLE_NO,  SSVC_TECHNICAL_IMPACT_PARTIAL, SSVC_MISSION_WELLBEING_MEDIUM, "Track" },
  { SSVC_EXPLOITATION_POC,    SSVC_AUTOMATABLE_NO,  SSVC_TECHNICAL_IMPACT_PARTIAL, SSVC_MISSION_WELLBEING_HIGH,   "Track*" },
  { SSVC_EXPLOITATION_POC,    SSVC_AUTOMATABLE_NO,  SSVC_TECHNICAL_IMPACT_TOTAL,   SSVC_MISSION_WELLBEING_LOW,    "Track" },
  { SSVC_EXPLOITATION_POC,    SSVC_AUTOMATABLE_NO,  SSVC_TECHNICAL_IMPACT_TOTAL,   SSVC_MISSION_WELLBEING_MEDIUM, "Track*" },
  { SSVC_EXPLOITATION_POC,    SSVC_AUTOMATABLE_NO,  SSVC_TECHNICAL_IMPACT_TOTAL,   SSVC_MISSION_WELLBEING_HIGH,   "Attend" },
  { SSVC_EXPLOITATION_POC,    SSVC_AUTOMATABLE_YES, SSVC_TECHNICAL_IMPACT_PARTIAL, SSVC_MISSION_WELLBEING_LOW,    "Track" },
  { SSVC_EXPLOITATION_POC,    SSVC_AUTOMATABLE_YES, SSVC_TECHNICAL_IMPACT_PARTIAL, SSVC_MISSION_WELLBEING_MEDIUM, "Track" },
  { SSVC_EXPLOITATION_POC,    SSVC_AUTOMATABLE_YES, SSVC_TECHNICAL_IMPACT_PARTIAL, SSVC_MISSION_WELLBEING_HIGH,   "Attend" },
  { SSVC_EXPLOITATION_POC,    SSVC_AUTOMATABLE_YES, SSVC_TECHNICAL_IMPACT_TOTAL,   SSVC_MISSION_WELLBEING_LOW,    "Track" },
  { SSVC_EXPLOITATION_POC,    SSVC_AUTOMATABLE_YES, SSVC_TECHNICAL_IMPACT_TOTAL,   SSVC_MISSION_WELLBEING_MEDIUM, "Track*" },
  { SSVC_EXPLOITATION_POC,    SSVC_AUTOMATABLE_YES, SSVC_TECHNICAL_IMPACT_TOTAL,   SSVC_MISSION_WELLBEING_HIGH,   "Attend" },
  { SSVC_EXPLOITATION_ACTIVE, SSVC_AUTOMATABLE_NO,  SSVC_TECHNICAL_IMPACT_PARTIAL, SSVC_MISSION_WELLBEING_LOW,    "Track" },
  { SSVC_EXPLOITATION_ACTIVE, SSVC_AUTOMATABLE_NO,  SSVC_TECHNICAL_IMPACT_PARTIAL, SSVC_MISSION_WELLBEING_MEDIUM, "Track" },
  { SSVC_EXPLOITATION_ACTIVE, SSVC_AUTOMATABLE_NO,  SSVC_TECHNICAL_IMPACT_PARTIAL, SSVC_MISSION_WELLBEING_HIGH,   "Attend" },
  { SSVC_EXPLOITATION_ACTIVE, SSVC_AUTOMATABLE_NO,  SSVC_TECHNICAL_IMPACT_TOTAL,   SSVC_MISSION_WELLBEING_LOW,    "Track" },
  { SSVC_EXPLOITATION_ACTIVE, SSVC_AUTOMATABLE_NO,  SSVC_TECHNICAL_IMPACT_TOTAL,   SSVC_MISSION_WELLBEING_MEDIUM, "Attend" },
  { SSVC_EXPLOITATION_ACTIVE, SSVC_AUTOMATABLE_NO,  SSVC_TECHNICAL_IMPACT_TOTAL,   SSVC_MISSION_WELLBEING_HIGH,   "Act" },
  { SSVC_EXPLOITATION_ACTIVE, SSVC_AUTOMATABLE_YES, SSVC_TECHNICAL_IMPACT_PARTIAL, SSVC_MISSION_WELLBEING_LOW,    "Attend" },
  { SSVC_EXPLOITATION_ACTIVE, SSVC_AUTOMATABLE_YES, SSVC_TECHNICAL_IMPACT_PARTIAL, SSVC_MISSION_WELLBEING_MEDIUM, "Attend" },
  { SSVC_EXPLOITATION_ACTIVE, SSVC_AUTOMATABLE_YES, SSVC_TECHNICAL_IMPACT_PARTIAL, SSVC_MISSION_WELLBEING_HIGH,   "Act" },
  { SSVC_EXPLOITATION_ACTIVE, SSVC_AUTOMATABLE_YES, SSVC_TECHNICAL_IMPACT_TOTAL,   SSVC_MISSION_WELLBEING_LOW,    "Attend" },
  { SSVC_EXPLOITATION_ACTIVE, SSVC_AUTOMATABLE_YES, SSVC_TECHNICAL_IMPACT_TOTAL,   SSVC_MISSION_WELLBEING_MEDIUM, "Act" },
  { SSVC_EXPLOITATION_ACTIVE, SSVC_AUTOMATABLE_YES, SSVC_TECHNICAL_IMPACT_TOTAL,   SSVC_MISSION_WELLBEING_HIGH,   "Act" },
};

static const size_t DECISION_ROW_COUNT = sizeof(DECISION_ROWS) / sizeof(DECISION_ROWS[0]);

_Static_assert(sizeof(DECISION_ROWS) / sizeof(DECISION_ROWS[0])
                 == SSVC_EXPLOITATION_VALUE_COUNT * SSVC_AUTOMATABLE_VALUE_COUNT
                    * SSVC_TECHNICAL_IMPACT_VALUE_COUNT * SSVC_MISSION_WELLBEING_LEVEL_COUNT,
               "DECISION_ROWS holds as many rows as there are combinations of the four decision points");

typedef struct {
  const char* mp_decision;
  const char* mp_remediationAdvice;
} SsvcRemediationAdviceRow_t;

static const SsvcRemediationAdviceRow_t REMEDIATION_ADVICE_ROWS[] = {
  { "Track",  "within standard update timelines" },
  { "Track*", "within standard update timelines" },
  { "Attend", "sooner than standard update timelines" },
  { "Act",    "as soon as possible" },
};

static const size_t REMEDIATION_ADVICE_ROW_COUNT = sizeof(REMEDIATION_ADVICE_ROWS) / sizeof(REMEDIATION_ADVICE_ROWS[0]);

static bool static_findValueIndex(const char* const* names, size_t name_count, const char* value, size_t* index_out)
{
  if (value == NULL)
    return false;

  for (size_t i = 0; i < name_count; i++)
  {
    if (strcmp(value, names[i]) == 0)
    {
      *index_out = i;
      return true;
    }
  }
  return false;
}

static const char* static_findRemediationAdvice(const char* decision)
{
  for (size_t i = 0; i < REMEDIATION_ADVICE_ROW_COUNT; i++)
  {
    if (strcmp(decision, REMEDIATION_ADVICE_ROWS[i].mp_decision) == 0)
      return REMEDIATION_ADVICE_ROWS[i].mp_remediationAdvice;
  }
  return NULL;
}

SsvcStatus_t ssvc_evaluate(const char* exploitation, const char* automatable, const char* technical_impact, SsvcResult_t* result_out)
{
  assert(result_out != NULL);
  memset(result_out, 0, sizeof(*result_out));

  size_t exploitation_index;
  size_t automatable_index;
  size_t technical_impact_index;
  if (!static_findValueIndex(EXPLOITATION_NAMES, SSVC_EXPLOITATION_VALUE_COUNT, exploitation, &exploitation_index))
    return SSVC_ERR_EXPLOITATION;
  if (!static_findValueIndex(AUTOMATABLE_NAMES, SSVC_AUTOMATABLE_VALUE_COUNT, automatable, &automatable_index))
    return SSVC_ERR_AUTOMATABLE;
  if (!static_findValueIndex(TECHNICAL_IMPACT_NAMES, SSVC_TECHNICAL_IMPACT_VALUE_COUNT, technical_impact, &technical_impact_index))
    return SSVC_ERR_TECHNICAL_IMPACT;

  for (size_t i = 0; i < DECISION_ROW_COUNT; i++)
  {
    const SsvcDecisionRow_t* row = &DECISION_ROWS[i];
    if (row->m_exploitation == (SsvcExploitation_t)exploitation_index             &&
        row->m_automatable == (SsvcAutomatable_t)automatable_index                &&
        row->m_technicalImpact == (SsvcTechnicalImpact_t)technical_impact_index)
    {
      size_t decision_len = strlen(row->mp_decision);
      assert(decision_len <= SSVC_DECISION_NAME_LEN);
      memcpy(result_out->ma_decisions[row->m_missionWellbeing], row->mp_decision, decision_len + 1);

      const char* remediation_advice = static_findRemediationAdvice(row->mp_decision);
      assert(remediation_advice != NULL);
      size_t remediation_advice_len = strlen(remediation_advice);
      assert(remediation_advice_len <= SSVC_REMEDIATION_ADVICE_LEN);
      memcpy(result_out->ma_remediationAdvice[row->m_missionWellbeing], remediation_advice, remediation_advice_len + 1);
    }
  }
  return SSVC_OK;
}
