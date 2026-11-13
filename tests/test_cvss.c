#include <math.h>
#include <string.h>

#include "unity/unity.h"
#include "cvss.h"

void setUp(void)    {}
void tearDown(void) {}

static int static_tenths(double score)
{
  return (int)llround(score * 10.0);
}

void test_roundup_base_ten_with_unknown_confidence_is_nine_point_two(void)
{
  CvssResult_t result;

  CvssParseStatus_t status = cvss_parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/RC:U", &result);

  TEST_ASSERT_EQUAL_INT(CVSS_OK, status);
  TEST_ASSERT_EQUAL_INT(100, static_tenths(result.m_baseScore));
  TEST_ASSERT_EQUAL_INT_MESSAGE(92, static_tenths(result.m_temporalScore), "ceil(x*10)/10 gives 9.3 here");
  TEST_ASSERT_EQUAL_INT_MESSAGE(92, static_tenths(result.m_environmentalScore), "ceil(x*10)/10 gives 9.3 here");
}

void test_roundup_base_five_with_unknown_confidence_is_four_point_six(void)
{
  CvssResult_t result;

  CvssParseStatus_t status = cvss_parse("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:N/A:N/RC:U", &result);

  TEST_ASSERT_EQUAL_INT(CVSS_OK, status);
  TEST_ASSERT_EQUAL_INT(50, static_tenths(result.m_baseScore));
  TEST_ASSERT_EQUAL_INT_MESSAGE(46, static_tenths(result.m_temporalScore), "ceil(x*10)/10 gives 4.7 here");
  TEST_ASSERT_EQUAL_INT_MESSAGE(46, static_tenths(result.m_environmentalScore), "ceil(x*10)/10 gives 4.7 here");
}

void test_roundup_base_two_point_five_with_unknown_confidence_is_two_point_three(void)
{
  CvssResult_t result;

  CvssParseStatus_t status = cvss_parse("CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N/RC:U", &result);

  TEST_ASSERT_EQUAL_INT(CVSS_OK, status);
  TEST_ASSERT_EQUAL_INT(25, static_tenths(result.m_baseScore));
  TEST_ASSERT_EQUAL_INT_MESSAGE(23, static_tenths(result.m_temporalScore), "ceil(x*10)/10 gives 2.4 here");
  TEST_ASSERT_EQUAL_INT_MESSAGE(23, static_tenths(result.m_environmentalScore), "ceil(x*10)/10 gives 2.4 here");
}

void test_roundup_is_the_integer_form_for_v30_too(void)
{
  CvssResult_t result;

  CvssParseStatus_t status = cvss_parse("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/RC:U", &result);

  TEST_ASSERT_EQUAL_INT(CVSS_OK, status);
  TEST_ASSERT_EQUAL_INT_MESSAGE(92, static_tenths(result.m_temporalScore), "ceil(x*10)/10 gives 9.3 here");
  TEST_ASSERT_EQUAL_INT_MESSAGE(92, static_tenths(result.m_environmentalScore), "ceil(x*10)/10 gives 9.3 here");
}

void test_classic_critical_vector_scores_nine_point_eight(void)
{
  CvssResult_t result;

  CvssParseStatus_t status = cvss_parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", &result);

  TEST_ASSERT_EQUAL_INT(CVSS_OK, status);
  TEST_ASSERT_EQUAL_INT(98, static_tenths(result.m_baseScore));
  TEST_ASSERT_EQUAL_STRING("CRITICAL", result.ma_baseSeverity);
  TEST_ASSERT_EQUAL_STRING("3.1", result.ma_version);
}

void test_no_impact_scores_zero_with_severity_none(void)
{
  CvssResult_t result;

  CvssParseStatus_t status = cvss_parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", &result);

  TEST_ASSERT_EQUAL_INT(CVSS_OK, status);
  TEST_ASSERT_EQUAL_INT(0, static_tenths(result.m_baseScore));
  TEST_ASSERT_EQUAL_INT(0, static_tenths(result.m_temporalScore));
  TEST_ASSERT_EQUAL_INT(0, static_tenths(result.m_environmentalScore));
  TEST_ASSERT_EQUAL_STRING("NONE", result.ma_baseSeverity);
}

void test_severity_bands_are_pinned_on_both_sides_of_each_edge(void)
{
  const struct { const char* mp_vector; int m_tenths; const char* mp_severity; } rows[] = {
    { "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",  0, "NONE"     },
    { "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L", 39, "LOW"      },
    { "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:N/A:N", 40, "MEDIUM"   },
    { "CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:H/I:L/A:N", 69, "MEDIUM"   },
    { "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:L", 70, "HIGH"     },
    { "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:L", 89, "HIGH"     },
    { "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H", 90, "CRITICAL" },
  };

  for (size_t i = 0; i < sizeof(rows) / sizeof(rows[0]); i++)
  {
    CvssResult_t result;
    CvssParseStatus_t status = cvss_parse(rows[i].mp_vector, &result);
    TEST_ASSERT_EQUAL_INT_MESSAGE(CVSS_OK, status, rows[i].mp_vector);
    TEST_ASSERT_EQUAL_INT_MESSAGE(rows[i].m_tenths, static_tenths(result.m_baseScore), rows[i].mp_vector);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(rows[i].mp_severity, result.ma_baseSeverity, rows[i].mp_vector);
  }
}

void test_severity_follows_the_base_score_not_the_derived_scores(void)
{
  CvssResult_t result;

  CvssParseStatus_t status = cvss_parse("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:N/A:N/E:U", &result);

  TEST_ASSERT_EQUAL_INT(CVSS_OK, status);
  TEST_ASSERT_EQUAL_INT(40, static_tenths(result.m_baseScore));
  TEST_ASSERT_EQUAL_INT(37, static_tenths(result.m_temporalScore));
  TEST_ASSERT_EQUAL_INT(37, static_tenths(result.m_environmentalScore));
  TEST_ASSERT_EQUAL_STRING("MEDIUM", result.ma_baseSeverity);
}

void test_environmental_differs_from_base_on_a_scope_changed_vector(void)
{
  CvssResult_t result;

  CvssParseStatus_t status = cvss_parse("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", &result);

  TEST_ASSERT_EQUAL_INT(CVSS_OK, status);
  TEST_ASSERT_EQUAL_INT(99, static_tenths(result.m_baseScore));
  TEST_ASSERT_EQUAL_INT(100, static_tenths(result.m_environmentalScore));
}

void test_v30_scores_the_modified_impact_with_the_base_formula(void)
{
  CvssResult_t result;

  CvssParseStatus_t status = cvss_parse("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", &result);

  TEST_ASSERT_EQUAL_INT(CVSS_OK, status);
  TEST_ASSERT_EQUAL_INT(99, static_tenths(result.m_baseScore));
  TEST_ASSERT_EQUAL_INT(99, static_tenths(result.m_temporalScore));
  TEST_ASSERT_EQUAL_INT(99, static_tenths(result.m_environmentalScore));
}

void test_absent_temporal_metrics_leave_derived_scores_at_the_base(void)
{
  CvssResult_t result;

  CvssParseStatus_t status = cvss_parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", &result);

  TEST_ASSERT_EQUAL_INT(CVSS_OK, status);
  TEST_ASSERT_EQUAL_INT(98, static_tenths(result.m_baseScore));
  TEST_ASSERT_EQUAL_INT(98, static_tenths(result.m_temporalScore));
  TEST_ASSERT_EQUAL_INT(98, static_tenths(result.m_environmentalScore));
}

void test_modified_impact_subscore_is_capped(void)
{
  CvssResult_t result;

  CvssParseStatus_t status = cvss_parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/CR:H/IR:H/AR:H", &result);

  TEST_ASSERT_EQUAL_INT(CVSS_OK, status);
  TEST_ASSERT_EQUAL_INT(98, static_tenths(result.m_environmentalScore));
}

void test_base_metrics_decode_to_their_long_labels(void)
{
  CvssResult_t result;

  CvssParseStatus_t status = cvss_parse("CVSS:3.1/AV:A/AC:H/PR:L/UI:R/S:C/C:L/I:N/A:H", &result);

  TEST_ASSERT_EQUAL_INT(CVSS_OK, status);
  TEST_ASSERT_EQUAL_STRING("ADJACENT_NETWORK", result.ma_attackVector);
  TEST_ASSERT_EQUAL_STRING("HIGH",             result.ma_attackComplexity);
  TEST_ASSERT_EQUAL_STRING("LOW",              result.ma_privilegesRequired);
  TEST_ASSERT_EQUAL_STRING("REQUIRED",         result.ma_userInteraction);
  TEST_ASSERT_EQUAL_STRING("CHANGED",          result.ma_scope);
  TEST_ASSERT_EQUAL_STRING("LOW",              result.ma_confidentialityImpact);
  TEST_ASSERT_EQUAL_STRING("NONE",             result.ma_integrityImpact);
  TEST_ASSERT_EQUAL_STRING("HIGH",             result.ma_availabilityImpact);
}

void test_v30_vector_is_accepted_and_reports_its_version(void)
{
  CvssResult_t result;

  CvssParseStatus_t status = cvss_parse("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", &result);

  TEST_ASSERT_EQUAL_INT(CVSS_OK, status);
  TEST_ASSERT_EQUAL_STRING("3.0", result.ma_version);
  TEST_ASSERT_EQUAL_INT(98, static_tenths(result.m_baseScore));
}

void test_metrics_are_accepted_in_any_order(void)
{
  const struct { const char* mp_vector; int m_baseTenths; int m_temporalTenths; int m_environmentalTenths; } rows[] = {
    { "CVSS:3.1/A:H/I:H/C:H/S:U/UI:N/PR:N/AC:L/AV:N",     98, 98, 98 },
    { "CVSS:3.1/E:U/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 98, 90, 90 },
  };

  for (size_t i = 0; i < sizeof(rows) / sizeof(rows[0]); i++)
  {
    CvssResult_t result;
    CvssParseStatus_t status = cvss_parse(rows[i].mp_vector, &result);
    TEST_ASSERT_EQUAL_INT_MESSAGE(CVSS_OK, status, rows[i].mp_vector);
    TEST_ASSERT_EQUAL_INT_MESSAGE(rows[i].m_baseTenths, static_tenths(result.m_baseScore), rows[i].mp_vector);
    TEST_ASSERT_EQUAL_INT_MESSAGE(rows[i].m_temporalTenths, static_tenths(result.m_temporalScore), rows[i].mp_vector);
    TEST_ASSERT_EQUAL_INT_MESSAGE(rows[i].m_environmentalTenths, static_tenths(result.m_environmentalScore), rows[i].mp_vector);
  }
}

void test_reference_vectors_score_and_decode_like_the_python_library(void)
{
  const struct { const char* mp_vector; int m_baseTenths; int m_temporalTenths; int m_environmentalTenths; const char* mp_severity; const char* ma_labels[8]; } rows[] = {
    { "CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:L/RL:O/RC:C/CR:M/IR:L/AR:L/MAV:A/MAC:H/MPR:L/MUI:R/MS:C/MC:H/MA:L",          65,  62, 64, "MEDIUM",   { "LOCAL", "HIGH", "LOW", "NONE", "UNCHANGED", "HIGH", "HIGH", "LOW" } },
    { "CVSS:3.1/AV:P/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:L/E:U/RL:T/RC:R/CR:L/IR:M/AR:L/MAC:L/MPR:N/MUI:N/MS:U/MC:N/MI:H/MA:H",       65,  55, 46, "MEDIUM",   { "PHYSICAL", "LOW", "NONE", "REQUIRED", "CHANGED", "HIGH", "LOW", "LOW" } },
    { "CVSS:3.0/AV:A/AC:L/PR:H/UI:R/S:U/C:H/I:H/A:L/E:F/RL:T/RC:R/IR:L/AR:M/MAV:P/MAC:L/MPR:H/MUI:N/MC:L/MI:H/MA:L",           62,  56, 35, "MEDIUM",   { "ADJACENT_NETWORK", "LOW", "HIGH", "REQUIRED", "UNCHANGED", "HIGH", "HIGH", "LOW" } },
    { "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N/E:H/RL:W/RC:R/CR:H/IR:L/AR:H/MAV:L/MAC:H/MPR:N/MUI:R/MS:C/MI:L/MA:N",      40,  38, 17, "MEDIUM",   { "LOCAL", "LOW", "NONE", "NONE", "UNCHANGED", "NONE", "LOW", "NONE" } },
    { "CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:P/RL:U/RC:C/CR:M/IR:M/AR:M/MAV:A/MAC:L/MPR:L/MUI:N/MC:L",                96,  91, 84, "CRITICAL", { "ADJACENT_NETWORK", "LOW", "NONE", "NONE", "CHANGED", "HIGH", "HIGH", "HIGH" } },
    { "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:N/I:L/A:H/E:H/RL:U/RC:U/CR:H/IR:M/MAV:N/MAC:H/MPR:H/MUI:R/MC:H/MI:N/MA:N",           63,  58, 56, "MEDIUM",   { "NETWORK", "LOW", "LOW", "REQUIRED", "UNCHANGED", "NONE", "LOW", "HIGH" } },
    { "CVSS:3.1/AV:A/AC:H/PR:H/UI:R/S:C/C:L/I:N/A:H/E:F/RL:O/RC:C/CR:H/IR:H/AR:H/MAV:N/MAC:L/MS:C/MC:L/MI:H/MA:N",             59,  55, 79, "MEDIUM",   { "ADJACENT_NETWORK", "HIGH", "HIGH", "REQUIRED", "CHANGED", "LOW", "NONE", "HIGH" } },
    { "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N/E:H/RL:W/RC:R/CR:M/IR:L/AR:H/MAV:A/MPR:L/MUI:N/MS:U/MC:H/MI:L/MA:L",       79,  74, 65, "HIGH",     { "LOCAL", "LOW", "NONE", "NONE", "CHANGED", "HIGH", "LOW", "NONE" } },
    { "CVSS:3.0/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:H/E:U/RL:O/AR:H/MAC:H/MPR:N/MUI:R/MS:U/MC:N/MI:L/MA:H",                      44,  39, 52, "MEDIUM",   { "PHYSICAL", "HIGH", "HIGH", "REQUIRED", "UNCHANGED", "LOW", "NONE", "HIGH" } },
    { "CVSS:3.1/AV:A/AC:L/PR:N/UI:R/S:U/C:L/I:H/A:N/E:P/RL:W/RC:C/CR:L/AR:H/MAV:L/MAC:L/MPR:H/MS:C/MC:N/MI:L/MA:L",            63,  58, 45, "MEDIUM",   { "ADJACENT_NETWORK", "LOW", "NONE", "REQUIRED", "UNCHANGED", "LOW", "HIGH", "NONE" } },
    { "CVSS:3.1/AV:P/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:L/MC:H",                                                                     70,  70, 69, "HIGH",     { "PHYSICAL", "HIGH", "LOW", "NONE", "CHANGED", "HIGH", "HIGH", "LOW" } },
    { "CVSS:3.1/AV:A/AC:L/PR:L/UI:R/S:U/C:H/I:N/A:N/RL:W/CR:L/IR:M/MAV:A/MPR:H/MUI:N/MS:C/MI:N/MA:H",                          52,  51, 70, "MEDIUM",   { "ADJACENT_NETWORK", "LOW", "LOW", "REQUIRED", "UNCHANGED", "HIGH", "NONE", "NONE" } },
    { "CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:C/C:N/I:H/A:N/E:F/RL:O/RC:C/CR:L/IR:M/AR:L/MAV:P/MAC:L/MPR:H/MS:C/MC:H/MI:N/MA:H",       59,  55, 38, "MEDIUM",   { "LOCAL", "LOW", "LOW", "REQUIRED", "CHANGED", "NONE", "HIGH", "NONE" } },
    { "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:L/A:N/E:U/RC:C/CR:L/IR:H/AR:M/MAV:P/MPR:L/MC:L/MA:L",                            55,  51, 39, "MEDIUM",   { "NETWORK", "LOW", "HIGH", "NONE", "UNCHANGED", "HIGH", "LOW", "NONE" } },
    { "CVSS:3.0/AV:A/AC:L/PR:H/UI:N/S:C/C:N/I:H/A:N/RL:U/CR:H/IR:H/MAV:N/MAC:L/MPR:L/MUI:R/MS:U/MC:L/MI:H/MA:N",               62,  62, 78, "MEDIUM",   { "ADJACENT_NETWORK", "LOW", "HIGH", "NONE", "CHANGED", "NONE", "HIGH", "NONE" } },
    { "CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:H/E:U/RL:T/IR:M/AR:M/MAV:P/MAC:L/MPR:N/MUI:R/MS:C/MC:H/MA:L",                59,  52, 57, "MEDIUM",   { "ADJACENT_NETWORK", "HIGH", "LOW", "NONE", "UNCHANGED", "LOW", "LOW", "HIGH" } },
    { "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:L/MAV:N",                                                                    47,  47, 47, "MEDIUM",   { "NETWORK", "LOW", "HIGH", "NONE", "UNCHANGED", "LOW", "LOW", "LOW" } },
    { "CVSS:3.0/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:H/A:N/RC:R/CR:M/IR:M/MAV:A/MPR:N/MC:H/MI:N/MA:L",                                44,  43, 52, "MEDIUM",   { "PHYSICAL", "HIGH", "HIGH", "REQUIRED", "UNCHANGED", "LOW", "HIGH", "NONE" } },
    { "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N/E:H/RL:O/RC:R/CR:H/IR:M/AR:H/MAV:N/MAC:H/MPR:L/MUI:N/MS:C/MC:N/MI:H/MA:L", 82,  75, 68, "HIGH",     { "LOCAL", "LOW", "NONE", "REQUIRED", "CHANGED", "HIGH", "HIGH", "NONE" } },
    { "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N/E:F/RC:U/CR:L/IR:M/AR:L/MAV:L/MAC:L/MPR:L/MS:U/MI:H/MA:H",                 52,  47, 61, "MEDIUM",   { "PHYSICAL", "LOW", "NONE", "NONE", "UNCHANGED", "HIGH", "LOW", "NONE" } },
    { "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/RC:U",                                                                     100, 92, 92, "CRITICAL", { "NETWORK", "LOW", "NONE", "NONE", "CHANGED", "HIGH", "HIGH", "HIGH" } },
    { "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N/E:H/RL:U/RC:C/CR:H/IR:H/AR:H/MAV:N/MAC:L/MPR:L/MS:C/MC:L/MI:L",            49,  49, 76, "MEDIUM",   { "NETWORK", "LOW", "HIGH", "NONE", "UNCHANGED", "HIGH", "NONE", "NONE" } },
    { "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",                                                                          0,   0,  0,  "NONE",     { "NETWORK", "LOW", "NONE", "NONE", "UNCHANGED", "NONE", "NONE", "NONE" } },
    { "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L/MAV:L",                                                                    86,  86, 73, "HIGH",     { "NETWORK", "LOW", "NONE", "NONE", "UNCHANGED", "HIGH", "LOW", "LOW" } },
  };

  for (size_t i = 0; i < sizeof(rows) / sizeof(rows[0]); i++)
  {
    CvssResult_t result;
    CvssParseStatus_t status = cvss_parse(rows[i].mp_vector, &result);
    TEST_ASSERT_EQUAL_INT_MESSAGE(CVSS_OK, status, rows[i].mp_vector);
    TEST_ASSERT_EQUAL_INT_MESSAGE(rows[i].m_baseTenths, static_tenths(result.m_baseScore), rows[i].mp_vector);
    TEST_ASSERT_EQUAL_INT_MESSAGE(rows[i].m_temporalTenths, static_tenths(result.m_temporalScore), rows[i].mp_vector);
    TEST_ASSERT_EQUAL_INT_MESSAGE(rows[i].m_environmentalTenths, static_tenths(result.m_environmentalScore), rows[i].mp_vector);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(rows[i].mp_severity, result.ma_baseSeverity, rows[i].mp_vector);

    const char* decoded_labels[] = { result.ma_attackVector, result.ma_attackComplexity, result.ma_privilegesRequired, result.ma_userInteraction, result.ma_scope, result.ma_confidentialityImpact, result.ma_integrityImpact, result.ma_availabilityImpact };
    for (size_t label_index = 0; label_index < sizeof(decoded_labels) / sizeof(decoded_labels[0]); label_index++)
      TEST_ASSERT_EQUAL_STRING_MESSAGE(rows[i].ma_labels[label_index], decoded_labels[label_index], rows[i].mp_vector);
  }
}

void test_each_refusal_reason_is_reported_for_its_own_input(void)
{
  const struct { const char* mp_vector; CvssParseStatus_t m_status; const char* mp_reason; } rows[] = {
    { NULL,                                                       CVSS_ERR_EMPTY,            "NULL input" },
    { "",                                                         CVSS_ERR_EMPTY,            "empty input" },
    { "CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P",                      CVSS_ERR_NOT_V3,           "v2 prefix" },
    { "CVSS:4.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",             CVSS_ERR_NOT_V3,           "v4 prefix" },
    { "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",                      CVSS_ERR_NOT_V3,           "no prefix" },
    { "CVSS:3.1XAV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",             CVSS_ERR_NOT_V3,           "v3.1 prefix without its slash" },
    { "CVSS:3.0XAV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",             CVSS_ERR_NOT_V3,           "v3.0 prefix without its slash" },
    { "cvss:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",             CVSS_ERR_NOT_V3,           "lower-case prefix" },
    { "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/ZZ:H",            CVSS_ERR_UNKNOWN_METRIC,   "unknown metric" },
    { "CVSS:3.1/av:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",             CVSS_ERR_UNKNOWN_METRIC,   "lower-case metric" },
    { "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/ZZ:HH",           CVSS_ERR_UNKNOWN_METRIC,   "unknown metric, long value" },
    { "CVSS:3.1/AV:N/ACL/PR:N/UI:N/S:U/C:H/I:H/A:H",              CVSS_ERR_UNKNOWN_METRIC,   "component without a colon" },
    { "CVSS:3.1/AV:Q/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",             CVSS_ERR_UNKNOWN_VALUE,    "unknown value" },
    { "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:HH",            CVSS_ERR_UNKNOWN_VALUE,    "value too long" },
    { "CVSS:3.1/AV:N/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",        CVSS_ERR_DUPLICATE_METRIC, "repeated base metric" },
    { "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:U/E:U",     CVSS_ERR_DUPLICATE_METRIC, "repeated temporal metric" },
    { "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/MAV:N/MAV:L", CVSS_ERR_DUPLICATE_METRIC, "repeated modified metric" },
    { "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/",            CVSS_ERR_EMPTY_COMPONENT,  "trailing slash" },
    { "CVSS:3.1/AV:N//AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",            CVSS_ERR_EMPTY_COMPONENT,  "doubled slash" },
  };

  for (size_t i = 0; i < sizeof(rows) / sizeof(rows[0]); i++)
  {
    CvssResult_t result;
    CvssParseStatus_t status = cvss_parse(rows[i].mp_vector, &result);
    TEST_ASSERT_EQUAL_INT_MESSAGE(rows[i].m_status, status, rows[i].mp_reason);
  }
}

void test_refused_vector_clears_a_stale_result(void)
{
  CvssResult_t result;
  memcpy(result.ma_vector, "stale", sizeof("stale"));
  memcpy(result.ma_baseSeverity, "CRITICAL", sizeof("CRITICAL"));
  result.m_baseScore          = 9.8;
  result.m_temporalScore      = 9.8;
  result.m_environmentalScore = 9.8;

  CvssParseStatus_t status = cvss_parse("CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P", &result);

  TEST_ASSERT_EQUAL_INT(CVSS_ERR_NOT_V3, status);
  TEST_ASSERT_EQUAL_INT(0, static_tenths(result.m_baseScore));
  TEST_ASSERT_EQUAL_INT(0, static_tenths(result.m_temporalScore));
  TEST_ASSERT_EQUAL_INT(0, static_tenths(result.m_environmentalScore));
  TEST_ASSERT_EQUAL_STRING("", result.ma_vector);
  TEST_ASSERT_EQUAL_STRING("", result.ma_baseSeverity);
}

void test_vector_one_byte_shorter_than_the_buffer_reaches_the_parser(void)
{
  char vector[CVSS_VECTOR_MAX_LEN];
  memset(vector, 'x', sizeof(vector) - 1);
  memcpy(vector, "CVSS:3.1/", sizeof("CVSS:3.1/") - 1);
  vector[sizeof(vector) - 1] = '\0';
  CvssResult_t result;

  CvssParseStatus_t status = cvss_parse(vector, &result);

  TEST_ASSERT_EQUAL_INT(CVSS_ERR_UNKNOWN_METRIC, status);
}

void test_vector_as_long_as_the_buffer_is_too_long(void)
{
  char vector[CVSS_VECTOR_MAX_LEN + 1];
  memset(vector, 'x', sizeof(vector) - 1);
  memcpy(vector, "CVSS:3.1/", sizeof("CVSS:3.1/") - 1);
  vector[sizeof(vector) - 1] = '\0';
  CvssResult_t result;

  CvssParseStatus_t status = cvss_parse(vector, &result);

  TEST_ASSERT_EQUAL_INT(CVSS_ERR_TOO_LONG, status);
}

void test_vector_carrying_every_metric_is_accepted(void)
{
  const char* every_metric_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:X/RL:X/RC:X/CR:X/IR:X/AR:X/MAV:X/MAC:X/MPR:X/MUI:X/MS:X/MC:X/MI:X/MA:X";
  CvssResult_t result;

  CvssParseStatus_t status = cvss_parse(every_metric_vector, &result);

  TEST_ASSERT_EQUAL_INT(CVSS_OK, status);
  TEST_ASSERT_EQUAL_STRING(every_metric_vector, result.ma_vector);
  TEST_ASSERT_EQUAL_INT(98, static_tenths(result.m_baseScore));
}

void test_each_status_has_its_own_message(void)
{
  const struct { CvssParseStatus_t m_status; const char* mp_message; } rows[] = {
    { CVSS_ERR_EMPTY,               "vector is required"                                                        },
    { CVSS_ERR_TOO_LONG,            "vector is too long"                                                        },
    { CVSS_ERR_NOT_V3,              "vector must start with CVSS:3.0/ or CVSS:3.1/"                             },
    { CVSS_ERR_UNKNOWN_METRIC,      "vector has a component that is not a CVSS v3 metric"                       },
    { CVSS_ERR_UNKNOWN_VALUE,       "vector has a metric value CVSS v3 does not define"                         },
    { CVSS_ERR_DUPLICATE_METRIC,    "vector repeats a metric"                                                   },
    { CVSS_ERR_MISSING_BASE_METRIC, "vector is missing a base metric: AV, AC, PR, UI, S, C, I and A are required" },
    { CVSS_ERR_EMPTY_COMPONENT,     "vector has an empty component: a trailing or doubled slash"                },
  };

  for (size_t i = 0; i < sizeof(rows) / sizeof(rows[0]); i++)
    TEST_ASSERT_EQUAL_STRING_MESSAGE(rows[i].mp_message, cvss_parseStatusMessage(rows[i].m_status), rows[i].mp_message);
  TEST_ASSERT_NULL(cvss_parseStatusMessage(CVSS_OK));
}

void test_every_base_metric_is_mandatory(void)
{
  const struct { const char* mp_vector; const char* mp_reason; } rows[] = {
    { "CVSS:3.1/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  "AV absent" },
    { "CVSS:3.1/AV:N/PR:N/UI:N/S:U/C:H/I:H/A:H",  "AC absent" },
    { "CVSS:3.1/AV:N/AC:L/UI:N/S:U/C:H/I:H/A:H",  "PR absent" },
    { "CVSS:3.1/AV:N/AC:L/PR:N/S:U/C:H/I:H/A:H",  "UI absent" },
    { "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/C:H/I:H/A:H", "S absent" },
    { "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/I:H/A:H", "C absent" },
    { "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/A:H", "I absent" },
    { "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H", "A absent" },
  };

  for (size_t i = 0; i < sizeof(rows) / sizeof(rows[0]); i++)
  {
    CvssResult_t result;
    CvssParseStatus_t status = cvss_parse(rows[i].mp_vector, &result);
    TEST_ASSERT_EQUAL_INT_MESSAGE(CVSS_ERR_MISSING_BASE_METRIC, status, rows[i].mp_reason);
  }
}

int main(void)
{
  UNITY_BEGIN();
  RUN_TEST(test_roundup_base_ten_with_unknown_confidence_is_nine_point_two);
  RUN_TEST(test_roundup_base_five_with_unknown_confidence_is_four_point_six);
  RUN_TEST(test_roundup_base_two_point_five_with_unknown_confidence_is_two_point_three);
  RUN_TEST(test_roundup_is_the_integer_form_for_v30_too);
  RUN_TEST(test_classic_critical_vector_scores_nine_point_eight);
  RUN_TEST(test_no_impact_scores_zero_with_severity_none);
  RUN_TEST(test_severity_bands_are_pinned_on_both_sides_of_each_edge);
  RUN_TEST(test_severity_follows_the_base_score_not_the_derived_scores);
  RUN_TEST(test_environmental_differs_from_base_on_a_scope_changed_vector);
  RUN_TEST(test_v30_scores_the_modified_impact_with_the_base_formula);
  RUN_TEST(test_absent_temporal_metrics_leave_derived_scores_at_the_base);
  RUN_TEST(test_modified_impact_subscore_is_capped);
  RUN_TEST(test_base_metrics_decode_to_their_long_labels);
  RUN_TEST(test_v30_vector_is_accepted_and_reports_its_version);
  RUN_TEST(test_metrics_are_accepted_in_any_order);
  RUN_TEST(test_reference_vectors_score_and_decode_like_the_python_library);
  RUN_TEST(test_each_refusal_reason_is_reported_for_its_own_input);
  RUN_TEST(test_refused_vector_clears_a_stale_result);
  RUN_TEST(test_vector_one_byte_shorter_than_the_buffer_reaches_the_parser);
  RUN_TEST(test_vector_as_long_as_the_buffer_is_too_long);
  RUN_TEST(test_vector_carrying_every_metric_is_accepted);
  RUN_TEST(test_each_status_has_its_own_message);
  RUN_TEST(test_every_base_metric_is_mandatory);
  return UNITY_END();
}
