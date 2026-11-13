#include <stdio.h>
#include <string.h>

#include "unity/unity.h"
#include "ssvc.h"

void setUp(void)    {}
void tearDown(void) {}

typedef struct {
  const char*            mp_exploitation;
  const char*            mp_automatable;
  const char*            mp_technicalImpact;
  SsvcMissionWellbeing_t m_missionWellbeing;
  const char*            mp_decision;
} ReferenceRow_t;

static const ReferenceRow_t REFERENCE_ROWS[] = {
  { "none",   "no",  "partial", SSVC_MISSION_WELLBEING_LOW,    "Track" },
  { "none",   "no",  "partial", SSVC_MISSION_WELLBEING_MEDIUM, "Track" },
  { "none",   "no",  "partial", SSVC_MISSION_WELLBEING_HIGH,   "Track" },
  { "none",   "no",  "total",   SSVC_MISSION_WELLBEING_LOW,    "Track" },
  { "none",   "no",  "total",   SSVC_MISSION_WELLBEING_MEDIUM, "Track" },
  { "none",   "no",  "total",   SSVC_MISSION_WELLBEING_HIGH,   "Track*" },
  { "none",   "yes", "partial", SSVC_MISSION_WELLBEING_LOW,    "Track" },
  { "none",   "yes", "partial", SSVC_MISSION_WELLBEING_MEDIUM, "Track" },
  { "none",   "yes", "partial", SSVC_MISSION_WELLBEING_HIGH,   "Attend" },
  { "none",   "yes", "total",   SSVC_MISSION_WELLBEING_LOW,    "Track" },
  { "none",   "yes", "total",   SSVC_MISSION_WELLBEING_MEDIUM, "Track" },
  { "none",   "yes", "total",   SSVC_MISSION_WELLBEING_HIGH,   "Attend" },
  { "poc",    "no",  "partial", SSVC_MISSION_WELLBEING_LOW,    "Track" },
  { "poc",    "no",  "partial", SSVC_MISSION_WELLBEING_MEDIUM, "Track" },
  { "poc",    "no",  "partial", SSVC_MISSION_WELLBEING_HIGH,   "Track*" },
  { "poc",    "no",  "total",   SSVC_MISSION_WELLBEING_LOW,    "Track" },
  { "poc",    "no",  "total",   SSVC_MISSION_WELLBEING_MEDIUM, "Track*" },
  { "poc",    "no",  "total",   SSVC_MISSION_WELLBEING_HIGH,   "Attend" },
  { "poc",    "yes", "partial", SSVC_MISSION_WELLBEING_LOW,    "Track" },
  { "poc",    "yes", "partial", SSVC_MISSION_WELLBEING_MEDIUM, "Track" },
  { "poc",    "yes", "partial", SSVC_MISSION_WELLBEING_HIGH,   "Attend" },
  { "poc",    "yes", "total",   SSVC_MISSION_WELLBEING_LOW,    "Track" },
  { "poc",    "yes", "total",   SSVC_MISSION_WELLBEING_MEDIUM, "Track*" },
  { "poc",    "yes", "total",   SSVC_MISSION_WELLBEING_HIGH,   "Attend" },
  { "active", "no",  "partial", SSVC_MISSION_WELLBEING_LOW,    "Track" },
  { "active", "no",  "partial", SSVC_MISSION_WELLBEING_MEDIUM, "Track" },
  { "active", "no",  "partial", SSVC_MISSION_WELLBEING_HIGH,   "Attend" },
  { "active", "no",  "total",   SSVC_MISSION_WELLBEING_LOW,    "Track" },
  { "active", "no",  "total",   SSVC_MISSION_WELLBEING_MEDIUM, "Attend" },
  { "active", "no",  "total",   SSVC_MISSION_WELLBEING_HIGH,   "Act" },
  { "active", "yes", "partial", SSVC_MISSION_WELLBEING_LOW,    "Attend" },
  { "active", "yes", "partial", SSVC_MISSION_WELLBEING_MEDIUM, "Attend" },
  { "active", "yes", "partial", SSVC_MISSION_WELLBEING_HIGH,   "Act" },
  { "active", "yes", "total",   SSVC_MISSION_WELLBEING_LOW,    "Attend" },
  { "active", "yes", "total",   SSVC_MISSION_WELLBEING_MEDIUM, "Act" },
  { "active", "yes", "total",   SSVC_MISSION_WELLBEING_HIGH,   "Act" },
};

#define REFERENCE_ROW_COUNT (sizeof(REFERENCE_ROWS) / sizeof(REFERENCE_ROWS[0]))

typedef struct {
  const char* mp_decision;
  const char* mp_remediationAdvice;
} ReferenceRemediationAdvice_t;

static const ReferenceRemediationAdvice_t REFERENCE_REMEDIATION_ADVICE[] = {
  { "Track",  "within standard update timelines" },
  { "Track*", "within standard update timelines" },
  { "Attend", "sooner than standard update timelines" },
  { "Act",    "as soon as possible" },
};

#define REFERENCE_REMEDIATION_ADVICE_COUNT (sizeof(REFERENCE_REMEDIATION_ADVICE) / sizeof(REFERENCE_REMEDIATION_ADVICE[0]))

static const char* static_referenceRemediationAdviceOf(const char* decision)
{
  for (size_t i = 0; i < REFERENCE_REMEDIATION_ADVICE_COUNT; i++)
    if (strcmp(decision, REFERENCE_REMEDIATION_ADVICE[i].mp_decision) == 0)
      return REFERENCE_REMEDIATION_ADVICE[i].mp_remediationAdvice;
  return NULL;
}

static const char* const EXPLOITATION_VALUES[]     = { "none", "poc", "active" };
static const char* const AUTOMATABLE_VALUES[]      = { "no", "yes" };
static const char* const TECHNICAL_IMPACT_VALUES[] = { "partial", "total" };

#define VALUE_COUNT(values) (sizeof(values) / sizeof((values)[0]))

static int static_decisionRank(const char* decision)
{
  static const char* const ORDER[] = { "Track", "Track*", "Attend", "Act" };
  if (decision == NULL)
    return -1;
  for (int i = 0; i < (int)(sizeof(ORDER) / sizeof(ORDER[0])); i++)
    if (strcmp(decision, ORDER[i]) == 0)
      return i;
  return -1;
}

static const char* static_decisionOf(const char* exploitation, const char* automatable, const char* technical_impact,
                                     SsvcMissionWellbeing_t level)
{
  static SsvcResult_t result;
  if (ssvc_evaluate(exploitation, automatable, technical_impact, &result) != SSVC_OK)
    return NULL;
  return result.ma_decisions[level];
}

void test_each_combination_of_the_cisa_tree_gives_its_decision(void)
{
  TEST_ASSERT_EQUAL_INT(36, REFERENCE_ROW_COUNT);
  for (size_t i = 0; i < REFERENCE_ROW_COUNT; i++)
  {
    const ReferenceRow_t* row = &REFERENCE_ROWS[i];
    SsvcResult_t result;
    char message[96];
    snprintf(message, sizeof(message), "%s,%s,%s level %d", row->mp_exploitation, row->mp_automatable,
             row->mp_technicalImpact, (int)row->m_missionWellbeing);

    SsvcStatus_t status = ssvc_evaluate(row->mp_exploitation, row->mp_automatable, row->mp_technicalImpact, &result);

    TEST_ASSERT_EQUAL_INT_MESSAGE(SSVC_OK, status, message);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(row->mp_decision, result.ma_decisions[row->m_missionWellbeing], message);
  }
}

void test_the_tree_gives_each_decision_as_often_as_the_cisa_tree(void)
{
  int counts[4] = { 0, 0, 0, 0 };
  for (size_t e = 0; e < VALUE_COUNT(EXPLOITATION_VALUES); e++)
    for (size_t a = 0; a < VALUE_COUNT(AUTOMATABLE_VALUES); a++)
      for (size_t t = 0; t < VALUE_COUNT(TECHNICAL_IMPACT_VALUES); t++)
        for (int level = 0; level < SSVC_MISSION_WELLBEING_LEVEL_COUNT; level++)
        {
          const char* decision = static_decisionOf(EXPLOITATION_VALUES[e], AUTOMATABLE_VALUES[a],
                                                   TECHNICAL_IMPACT_VALUES[t], (SsvcMissionWellbeing_t)level);
          TEST_ASSERT_NOT_NULL(decision);
          int rank = static_decisionRank(decision);
          TEST_ASSERT_TRUE_MESSAGE(rank >= 0, decision);
          counts[rank]++;
        }

  TEST_ASSERT_EQUAL_INT_MESSAGE(18, counts[0], "Track");
  TEST_ASSERT_EQUAL_INT_MESSAGE(4,  counts[1], "Track*");
  TEST_ASSERT_EQUAL_INT_MESSAGE(10, counts[2], "Attend");
  TEST_ASSERT_EQUAL_INT_MESSAGE(4,  counts[3], "Act");
}

void test_a_higher_decision_point_never_lowers_the_decision(void)
{
  for (size_t e = 0; e < VALUE_COUNT(EXPLOITATION_VALUES); e++)
    for (size_t a = 0; a < VALUE_COUNT(AUTOMATABLE_VALUES); a++)
      for (size_t t = 0; t < VALUE_COUNT(TECHNICAL_IMPACT_VALUES); t++)
        for (int level = 0; level < SSVC_MISSION_WELLBEING_LEVEL_COUNT; level++)
        {
          SsvcMissionWellbeing_t m = (SsvcMissionWellbeing_t)level;
          int rank = static_decisionRank(static_decisionOf(EXPLOITATION_VALUES[e], AUTOMATABLE_VALUES[a],
                                                           TECHNICAL_IMPACT_VALUES[t], m));
          char message[96];
          snprintf(message, sizeof(message), "%s,%s,%s level %d", EXPLOITATION_VALUES[e], AUTOMATABLE_VALUES[a],
                   TECHNICAL_IMPACT_VALUES[t], level);
          TEST_ASSERT_TRUE_MESSAGE(rank >= 0, message);
          if (e + 1 < VALUE_COUNT(EXPLOITATION_VALUES))
            TEST_ASSERT_TRUE_MESSAGE(static_decisionRank(static_decisionOf(EXPLOITATION_VALUES[e + 1], AUTOMATABLE_VALUES[a],
                                                                           TECHNICAL_IMPACT_VALUES[t], m)) >= rank, message);
          if (a + 1 < VALUE_COUNT(AUTOMATABLE_VALUES))
            TEST_ASSERT_TRUE_MESSAGE(static_decisionRank(static_decisionOf(EXPLOITATION_VALUES[e], AUTOMATABLE_VALUES[a + 1],
                                                                           TECHNICAL_IMPACT_VALUES[t], m)) >= rank, message);
          if (t + 1 < VALUE_COUNT(TECHNICAL_IMPACT_VALUES))
            TEST_ASSERT_TRUE_MESSAGE(static_decisionRank(static_decisionOf(EXPLOITATION_VALUES[e], AUTOMATABLE_VALUES[a],
                                                                           TECHNICAL_IMPACT_VALUES[t + 1], m)) >= rank, message);
          if (level + 1 < SSVC_MISSION_WELLBEING_LEVEL_COUNT)
            TEST_ASSERT_TRUE_MESSAGE(static_decisionRank(static_decisionOf(EXPLOITATION_VALUES[e], AUTOMATABLE_VALUES[a],
                                                                           TECHNICAL_IMPACT_VALUES[t],
                                                                           (SsvcMissionWellbeing_t)(level + 1))) >= rank, message);
        }
}

void test_the_longest_decision_name_is_the_name_length(void)
{
  size_t longest = 0;
  for (size_t i = 0; i < REFERENCE_ROW_COUNT; i++)
    if (strlen(REFERENCE_ROWS[i].mp_decision) > longest)
      longest = strlen(REFERENCE_ROWS[i].mp_decision);

  TEST_ASSERT_EQUAL_INT(SSVC_DECISION_NAME_LEN, longest);
  TEST_ASSERT_EQUAL_STRING("Attend", static_decisionOf("active", "yes", "partial", SSVC_MISSION_WELLBEING_LOW));
}

void test_each_decision_gives_the_remediation_advice_of_cisa_table_1(void)
{
  for (size_t i = 0; i < REFERENCE_ROW_COUNT; i++)
  {
    const ReferenceRow_t* row = &REFERENCE_ROWS[i];
    SsvcResult_t result;
    char message[96];
    snprintf(message, sizeof(message), "%s,%s,%s level %d", row->mp_exploitation, row->mp_automatable,
             row->mp_technicalImpact, (int)row->m_missionWellbeing);
    const char* remediation = static_referenceRemediationAdviceOf(row->mp_decision);
    TEST_ASSERT_NOT_NULL_MESSAGE(remediation, message);

    SsvcStatus_t status = ssvc_evaluate(row->mp_exploitation, row->mp_automatable, row->mp_technicalImpact, &result);

    TEST_ASSERT_EQUAL_INT_MESSAGE(SSVC_OK, status, message);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(remediation, result.ma_remediationAdvice[row->m_missionWellbeing], message);
  }
}

void test_the_longest_remediation_advice_is_the_remediation_advice_length(void)
{
  size_t longest = 0;
  for (size_t i = 0; i < REFERENCE_REMEDIATION_ADVICE_COUNT; i++)
    if (strlen(REFERENCE_REMEDIATION_ADVICE[i].mp_remediationAdvice) > longest)
      longest = strlen(REFERENCE_REMEDIATION_ADVICE[i].mp_remediationAdvice);

  SsvcResult_t result;
  TEST_ASSERT_EQUAL_INT(SSVC_REMEDIATION_ADVICE_LEN, longest);
  TEST_ASSERT_EQUAL_INT(SSVC_OK, ssvc_evaluate("active", "yes", "partial", &result));
  TEST_ASSERT_EQUAL_STRING("sooner than standard update timelines", result.ma_remediationAdvice[SSVC_MISSION_WELLBEING_LOW]);
}

static void static_assertRefused(const char* exploitation, const char* automatable, const char* technical_impact,
                                 SsvcStatus_t status, const char* message)
{
  SsvcResult_t result;
  TEST_ASSERT_EQUAL_INT_MESSAGE(status, ssvc_evaluate(exploitation, automatable, technical_impact, &result), message);
}

void test_each_near_miss_of_an_exploitation_value_is_refused(void)
{
  const char* near_misses[] = { "None", "POC", "PoC", "Active", "ACTIVE", "none ", " poc", "", "unknown", "yes", "total" };
  for (size_t i = 0; i < sizeof(near_misses) / sizeof(near_misses[0]); i++)
    static_assertRefused(near_misses[i], "no", "partial", SSVC_ERR_EXPLOITATION, near_misses[i]);
  static_assertRefused(NULL, "no", "partial", SSVC_ERR_EXPLOITATION, "NULL");
}

void test_each_near_miss_of_an_automatable_value_is_refused(void)
{
  const char* near_misses[] = { "No", "Yes", "YES", "yes ", " no", "", "maybe", "none", "poc", "total" };
  for (size_t i = 0; i < sizeof(near_misses) / sizeof(near_misses[0]); i++)
    static_assertRefused("none", near_misses[i], "partial", SSVC_ERR_AUTOMATABLE, near_misses[i]);
  static_assertRefused("none", NULL, "partial", SSVC_ERR_AUTOMATABLE, "NULL");
}

void test_each_near_miss_of_a_technical_impact_value_is_refused(void)
{
  const char* near_misses[] = { "Partial", "Total", "TOTAL", " total", "partial ", "", "full", "active", "no" };
  for (size_t i = 0; i < sizeof(near_misses) / sizeof(near_misses[0]); i++)
    static_assertRefused("none", "no", near_misses[i], SSVC_ERR_TECHNICAL_IMPACT, near_misses[i]);
  static_assertRefused("none", "no", NULL, SSVC_ERR_TECHNICAL_IMPACT, "NULL");
}

void test_the_first_refused_value_names_the_status(void)
{
  static_assertRefused("bad", "bad", "bad", SSVC_ERR_EXPLOITATION, "all three refused");
  static_assertRefused("none", "bad", "bad", SSVC_ERR_AUTOMATABLE, "automatable and technical impact refused");
}

void test_a_refused_value_clears_a_stale_result(void)
{
  const char* cases[3][3] = { { "bad", "no", "partial" }, { "none", "bad", "partial" }, { "none", "no", "bad" } };
  const char* messages[3] = { "exploitation refused", "automatable refused", "technical impact refused" };
  for (size_t c = 0; c < 3; c++)
  {
    SsvcResult_t result;
    memset(&result, 'X', sizeof(result));

    TEST_ASSERT_NOT_EQUAL(SSVC_OK, ssvc_evaluate(cases[c][0], cases[c][1], cases[c][2], &result));

    const unsigned char* bytes = (const unsigned char*)&result;
    for (size_t i = 0; i < sizeof(result); i++)
      TEST_ASSERT_EQUAL_UINT8_MESSAGE(0, bytes[i], messages[c]);
  }
}

void test_an_accepted_value_clears_a_stale_result(void)
{
  SsvcResult_t result;
  memset(&result, 'X', sizeof(result));

  TEST_ASSERT_EQUAL_INT(SSVC_OK, ssvc_evaluate("none", "no", "partial", &result));

  for (int level = 0; level < SSVC_MISSION_WELLBEING_LEVEL_COUNT; level++)
  {
    for (size_t i = strlen(result.ma_decisions[level]); i <= SSVC_DECISION_NAME_LEN; i++)
      TEST_ASSERT_EQUAL_UINT8(0, (unsigned char)result.ma_decisions[level][i]);
    for (size_t i = strlen(result.ma_remediationAdvice[level]); i <= SSVC_REMEDIATION_ADVICE_LEN; i++)
      TEST_ASSERT_EQUAL_UINT8(0, (unsigned char)result.ma_remediationAdvice[level][i]);
  }
}

int main(void)
{
  UNITY_BEGIN();
  RUN_TEST(test_each_combination_of_the_cisa_tree_gives_its_decision);
  RUN_TEST(test_the_tree_gives_each_decision_as_often_as_the_cisa_tree);
  RUN_TEST(test_a_higher_decision_point_never_lowers_the_decision);
  RUN_TEST(test_the_longest_decision_name_is_the_name_length);
  RUN_TEST(test_each_decision_gives_the_remediation_advice_of_cisa_table_1);
  RUN_TEST(test_the_longest_remediation_advice_is_the_remediation_advice_length);
  RUN_TEST(test_each_near_miss_of_an_exploitation_value_is_refused);
  RUN_TEST(test_each_near_miss_of_an_automatable_value_is_refused);
  RUN_TEST(test_each_near_miss_of_a_technical_impact_value_is_refused);
  RUN_TEST(test_the_first_refused_value_names_the_status);
  RUN_TEST(test_a_refused_value_clears_a_stale_result);
  RUN_TEST(test_an_accepted_value_clears_a_stale_result);
  return UNITY_END();
}
