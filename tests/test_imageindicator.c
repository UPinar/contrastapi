#include <string.h>
#include <time.h>

#include "unity/unity.h"
#include "imageindicator.h"

#define FAKE_NOW 1700000000

time_t __wrap_time(time_t* now_out)
{
  if (now_out != NULL)
    *now_out = FAKE_NOW;
  return FAKE_NOW;
}

void setUp(void)    {}
void tearDown(void) {}

static int static_find(const ExifClientResult_t* exif, ImageIndicatorResult_t* result_out)
{
  imageindicator_find(exif, result_out);
  int present_count = 0;
  for (int i = 0; i < IMAGEINDICATOR_KIND_COUNT; i++)
    present_count += result_out->ma_isIndicatorPresent[i] ? 1 : 0;
  return present_count;
}

static bool static_isPresent(const ExifClientResult_t* exif, ImageIndicatorKind_t kind)
{
  ImageIndicatorResult_t result;
  imageindicator_find(exif, &result);
  return result.ma_isIndicatorPresent[kind];
}

void test_a_zero_result_has_no_capture_metadata_and_nothing_else(void)
{
  ExifClientResult_t exif;
  memset(&exif, 0, sizeof(exif));
  ImageIndicatorResult_t result;
  TEST_ASSERT_EQUAL_INT(1, static_find(&exif, &result));
  TEST_ASSERT_TRUE(result.ma_isIndicatorPresent[IMAGEINDICATOR_KIND_NO_CAPTURE_METADATA]);
}

void test_the_flag_indicators_follow_their_flags(void)
{
  ExifClientResult_t exif;
  memset(&exif, 0, sizeof(exif));
  strcpy(exif.ma_cameraMake, "Canon");
  ImageIndicatorResult_t result;
  TEST_ASSERT_EQUAL_INT(0, static_find(&exif, &result));

  exif.m_hasC2paManifest = true;
  TEST_ASSERT_EQUAL_INT(1, static_find(&exif, &result));
  TEST_ASSERT_TRUE(result.ma_isIndicatorPresent[IMAGEINDICATOR_KIND_C2PA_MANIFEST]);
  exif.m_hasC2paManifest = false;

  exif.m_hasGeneratorParameters = true;
  TEST_ASSERT_EQUAL_INT(1, static_find(&exif, &result));
  TEST_ASSERT_TRUE(result.ma_isIndicatorPresent[IMAGEINDICATOR_KIND_AI_GENERATOR_PARAMETERS]);
}

void test_ai_source_type_needs_trained_algorithmic_media_in_any_case(void)
{
  static const struct { const char* mp_text; bool m_isPresent; } cases[] = {
    { "http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia",              true  },
    { "http://cv.iptc.org/newscodes/digitalsourcetype/compositeWithTrainedAlgorithmicMedia", true  },
    { "TRAINEDALGORITHMICMEDIA",                                                             true  },
    { "http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedi",               false },
    { "http://cv.iptc.org/newscodes/digitalsourcetype/digitalCapture",                       false },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    ExifClientResult_t exif;
    memset(&exif, 0, sizeof(exif));
    strcpy(exif.ma_digitalSourceType, cases[i].mp_text);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_isPresent, static_isPresent(&exif, IMAGEINDICATOR_KIND_AI_SOURCE_TYPE), cases[i].mp_text);
  }
}

void test_ai_generator_software_names_a_known_generator_in_any_case(void)
{
  static const char* const NAMES[] = { "Stable Diffusion", "Midjourney", "DALL-E", "Firefly", "ComfyUI", "InvokeAI", "NovelAI", "Fooocus" };
  for (size_t i = 0; i < sizeof(NAMES) / sizeof(NAMES[0]); i++)
  {
    ExifClientResult_t exif;
    memset(&exif, 0, sizeof(exif));
    strcpy(exif.ma_software, NAMES[i]);
    strcat(exif.ma_software, " 1.0");
    TEST_ASSERT_TRUE_MESSAGE(static_isPresent(&exif, IMAGEINDICATOR_KIND_AI_GENERATOR_SOFTWARE), NAMES[i]);
    for (char* c = exif.ma_software; *c != '\0'; c++)
      *c = (char)((*c >= 'A' && *c <= 'Z') ? *c - 'A' + 'a' : *c);
    TEST_ASSERT_TRUE_MESSAGE(static_isPresent(&exif, IMAGEINDICATOR_KIND_AI_GENERATOR_SOFTWARE), exif.ma_software);
  }

  ExifClientResult_t exif;
  memset(&exif, 0, sizeof(exif));
  strcpy(exif.ma_creatorTool, "Midjourney");
  TEST_ASSERT_TRUE(static_isPresent(&exif, IMAGEINDICATOR_KIND_AI_GENERATOR_SOFTWARE));
  memset(&exif, 0, sizeof(exif));
  strcpy(exif.ma_software, "Stable Diffusio");
  TEST_ASSERT_FALSE(static_isPresent(&exif, IMAGEINDICATOR_KIND_AI_GENERATOR_SOFTWARE));
  strcpy(exif.ma_software, "GIMP 2.10");
  TEST_ASSERT_FALSE(static_isPresent(&exif, IMAGEINDICATOR_KIND_AI_GENERATOR_SOFTWARE));
}

void test_gps_position_and_null_island(void)
{
  static const struct { bool m_hasPosition; double m_latitude; double m_longitude; bool m_isNullIsland; } cases[] = {
    { false, 0.0,     0.0,     false },
    { true,  41.0082, 28.9784, false },
    { true,  0.0,     28.9784, false },
    { true,  41.0082, 0.0,     false },
    { true,  0.0,     0.0,     true  },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    ExifClientResult_t exif;
    memset(&exif, 0, sizeof(exif));
    exif.m_hasGpsPosition = cases[i].m_hasPosition;
    exif.m_gpsLatitude    = cases[i].m_latitude;
    exif.m_gpsLongitude   = cases[i].m_longitude;
    TEST_ASSERT_EQUAL_INT(cases[i].m_hasPosition, static_isPresent(&exif, IMAGEINDICATOR_KIND_GPS_POSITION));
    TEST_ASSERT_EQUAL_INT(cases[i].m_isNullIsland, static_isPresent(&exif, IMAGEINDICATOR_KIND_GPS_NULL_ISLAND));
  }
}

void test_identifier_present_for_each_kind(void)
{
  for (int kind = 0; kind < EXIFCLIENT_IDENTIFIER_COUNT; kind++)
  {
    ExifClientResult_t exif;
    memset(&exif, 0, sizeof(exif));
    exif.ma_isIdentifierPresent[kind] = true;
    TEST_ASSERT_TRUE_MESSAGE(static_isPresent(&exif, IMAGEINDICATOR_KIND_IDENTIFIER), "an identifier kind");
  }
  ExifClientResult_t exif;
  memset(&exif, 0, sizeof(exif));
  TEST_ASSERT_FALSE(static_isPresent(&exif, IMAGEINDICATOR_KIND_IDENTIFIER));
}

static void static_setTimes(ExifClientResult_t* exif, const char* original, const char* offset, const char* modify)
{
  memset(exif, 0, sizeof(*exif));
  if (original) strcpy(exif->ma_dateTimeOriginal,   original);
  if (offset)   strcpy(exif->ma_offsetTimeOriginal, offset);
  if (modify)   strcpy(exif->ma_modifyDate,         modify);
}

void test_original_time_in_future_from_one_second_past_a_day(void)
{
  static const struct { const char* mp_original; const char* mp_offset; bool m_isFuture; } cases[] = {
    { "2023:11:15 22:13:20", NULL,     false },
    { "2023:11:15 22:13:21", NULL,     true  },
    { "2023:11:16 01:13:20", "+03:00", false },
    { "2023:11:16 01:13:21", "+03:00", true  },
    { "2023:11:15 17:13:20", "-05:00", false },
    { "2023:11:15 17:13:21", "-05:00", true  },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    ExifClientResult_t exif;
    static_setTimes(&exif, cases[i].mp_original, cases[i].mp_offset, NULL);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_isFuture, static_isPresent(&exif, IMAGEINDICATOR_KIND_ORIGINAL_TIME_IN_FUTURE), cases[i].mp_original);
  }
}

void test_modified_before_original_from_one_second_before(void)
{
  static const struct { const char* mp_modify; bool m_isBefore; } cases[] = {
    { "2024:05:01 09:59:59", true  },
    { "2024:05:01 10:00:00", false },
    { "2024:05:01 10:00:01", false },
    { "",                    false },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    ExifClientResult_t exif;
    static_setTimes(&exif, "2024:05:01 10:00:00", NULL, cases[i].mp_modify);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_isBefore, static_isPresent(&exif, IMAGEINDICATOR_KIND_MODIFIED_BEFORE_ORIGINAL), cases[i].mp_modify);
  }
}

void test_a_time_in_another_form_takes_part_in_no_rule(void)
{
  static const struct { const char* mp_original; bool m_isRead; } cases[] = {
    { "2024-05-01 10:00:00",     false },
    { "2024:05:01T10:00:00",     false },
    { "2024:13:01 10:00:00",     false },
    { "2024:05:01 10:00",        false },
    { "",                        false },
    { "2024:00:01 10:00:00",     false },
    { "2024:05:00 10:00:00",     false },
    { "2024:05:32 10:00:00",     false },
    { "2024:05:01 24:00:00",     false },
    { "2024:05:01 10:60:00",     false },
    { "2024:05:01 10:00:61",     false },
    { "2024:05:01 10:00:60",     true  },
    { "2024:05:01 10:00:00Z",    true  },
    { "2024:05:01 10:00:00.250", true  },
    { "2024:05:01 1 :00:00",     false },
    { "2024:05-01 10:00:00",     false },
    { "2024:05:01 10-00:00",     false },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    ExifClientResult_t exif;
    static_setTimes(&exif, cases[i].mp_original, NULL, "1970:01:01 00:00:00");
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_isRead, static_isPresent(&exif, IMAGEINDICATOR_KIND_MODIFIED_BEFORE_ORIGINAL), cases[i].mp_original);
  }
}

void test_a_time_before_1970_is_not_read(void)
{
  ExifClientResult_t exif;
  static_setTimes(&exif, "1969:12:31 23:59:59", "+03:00", NULL);
  strcpy(exif.ma_gpsDateTime, "2024:05:01 10:00:01Z");
  TEST_ASSERT_FALSE(static_isPresent(&exif, IMAGEINDICATOR_KIND_GPS_TIME_DIFFERS));
  static_setTimes(&exif, "1970:01:01 00:00:00", "+03:00", NULL);
  strcpy(exif.ma_gpsDateTime, "2024:05:01 10:00:01Z");
  TEST_ASSERT_TRUE(static_isPresent(&exif, IMAGEINDICATOR_KIND_GPS_TIME_DIFFERS));
}

void test_gps_time_differs_from_one_second_past_an_hour_with_an_offset(void)
{
  static const struct { const char* mp_gpsTime; const char* mp_offset; bool m_isDifferent; } cases[] = {
    { "2024:05:01 10:00:00Z", "+03:00", false },
    { "2024:05:01 10:00:01Z", "+03:00", true  },
    { "2024:05:01 08:00:00Z", "+03:00", false },
    { "2024:05:01 07:59:59Z", "+03:00", true  },
    { "2024:05:01 10:00:01Z", NULL,     false },
    { "",                     "+03:00", false },
    { "2024:05:01 10:00:01Z", "+14:00", true  },
    { "2024:05:01 10:00:01Z", "+15:00", false },
    { "2024:05:01 10:00:01Z", "+03:60", false },
    { "2024:05:01 10:00:01Z", "03:00",  false },
    { "2024:05:01 10:00:01Z", "003:00", false },
    { "2024:05:01 10:00:01Z", "+03:00:00", false },
    { "2024:05:01 07:30:00Z", "+05:30", false },
    { "2024:05:01 07:30:01Z", "+05:30", true  },
    { "2024:05:01 10:00:01Z", "+03-00", false },
    { "2024:05:01 10:00:01Z", "+ 3:00", false },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    ExifClientResult_t exif;
    static_setTimes(&exif, "2024:05:01 12:00:00", cases[i].mp_offset, NULL);
    strcpy(exif.ma_gpsDateTime, cases[i].mp_gpsTime);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_isDifferent, static_isPresent(&exif, IMAGEINDICATOR_KIND_GPS_TIME_DIFFERS), cases[i].mp_gpsTime);
  }
}

void test_edit_history_and_thumbnail_follow_their_counts(void)
{
  ExifClientResult_t exif;
  memset(&exif, 0, sizeof(exif));
  TEST_ASSERT_FALSE(static_isPresent(&exif, IMAGEINDICATOR_KIND_EDIT_HISTORY));
  TEST_ASSERT_FALSE(static_isPresent(&exif, IMAGEINDICATOR_KIND_THUMBNAIL));
  exif.m_editHistoryEntryCount = 1;
  exif.m_thumbnailByteCount = 1;
  TEST_ASSERT_TRUE(static_isPresent(&exif, IMAGEINDICATOR_KIND_EDIT_HISTORY));
  TEST_ASSERT_TRUE(static_isPresent(&exif, IMAGEINDICATOR_KIND_THUMBNAIL));
}

void test_no_capture_metadata_needs_all_three_absent(void)
{
  ExifClientResult_t exif;
  memset(&exif, 0, sizeof(exif));
  strcpy(exif.ma_cameraMake, "Canon");
  TEST_ASSERT_FALSE(static_isPresent(&exif, IMAGEINDICATOR_KIND_NO_CAPTURE_METADATA));
  memset(&exif, 0, sizeof(exif));
  strcpy(exif.ma_cameraModel, "EOS R5");
  TEST_ASSERT_FALSE(static_isPresent(&exif, IMAGEINDICATOR_KIND_NO_CAPTURE_METADATA));
  memset(&exif, 0, sizeof(exif));
  strcpy(exif.ma_dateTimeOriginal, "2024:05:01 10:00:00");
  TEST_ASSERT_FALSE(static_isPresent(&exif, IMAGEINDICATOR_KIND_NO_CAPTURE_METADATA));
  memset(&exif, 0, sizeof(exif));
  strcpy(exif.ma_dateTimeOriginal, "2024-05-01 10:00:00");
  TEST_ASSERT_FALSE(static_isPresent(&exif, IMAGEINDICATOR_KIND_NO_CAPTURE_METADATA));
  memset(&exif, 0, sizeof(exif));
  TEST_ASSERT_TRUE(static_isPresent(&exif, IMAGEINDICATOR_KIND_NO_CAPTURE_METADATA));
}

void test_each_kind_has_its_name_severity_and_note(void)
{
  static const char* const NOTE_PARTS[IMAGEINDICATOR_KIND_COUNT] = {
    "C2PA manifest", "digital source type", "PNG text chunk", "creator tool", "GPS position:",
    "Gulf of Guinea", "person or a device", "a day ahead", "modify date is before", "more than an hour",
    "XMP history", "embedded thumbnail", "no camera make",
  };
  static const struct { const char* mp_name; ImageIndicatorSeverity_t m_severity; } expected[IMAGEINDICATOR_KIND_COUNT] = {
    { "c2pa_manifest",            IMAGEINDICATOR_SEVERITY_INFO     },
    { "ai_source_type",           IMAGEINDICATOR_SEVERITY_MODERATE },
    { "ai_generator_parameters",  IMAGEINDICATOR_SEVERITY_MODERATE },
    { "ai_generator_software",    IMAGEINDICATOR_SEVERITY_WEAK     },
    { "gps_position",             IMAGEINDICATOR_SEVERITY_INFO     },
    { "gps_null_island",          IMAGEINDICATOR_SEVERITY_WEAK     },
    { "identifier_present",       IMAGEINDICATOR_SEVERITY_INFO     },
    { "original_time_in_future",  IMAGEINDICATOR_SEVERITY_WEAK     },
    { "modified_before_original", IMAGEINDICATOR_SEVERITY_WEAK     },
    { "gps_time_differs",         IMAGEINDICATOR_SEVERITY_WEAK     },
    { "edit_history",             IMAGEINDICATOR_SEVERITY_INFO     },
    { "thumbnail",                IMAGEINDICATOR_SEVERITY_INFO     },
    { "no_capture_metadata",      IMAGEINDICATOR_SEVERITY_INFO     },
  };
  for (int i = 0; i < IMAGEINDICATOR_KIND_COUNT; i++)
  {
    ImageIndicatorKind_t kind = (ImageIndicatorKind_t)i;
    TEST_ASSERT_EQUAL_STRING(expected[i].mp_name, imageindicator_kindName(kind));
    TEST_ASSERT_EQUAL_INT_MESSAGE(expected[i].m_severity, imageindicator_kindSeverity(kind), expected[i].mp_name);
    const char* note = imageindicator_kindNote(kind);
    TEST_ASSERT_TRUE_MESSAGE(strlen(note) > 0, expected[i].mp_name);
    TEST_ASSERT_NULL_MESSAGE(strchr(note, '"'), expected[i].mp_name);
    TEST_ASSERT_NULL_MESSAGE(strchr(note, '\\'), expected[i].mp_name);
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(note, NOTE_PARTS[i]), expected[i].mp_name);
  }
}

void test_each_severity_has_its_name(void)
{
  TEST_ASSERT_EQUAL_STRING("info",     imageindicator_severityName(IMAGEINDICATOR_SEVERITY_INFO));
  TEST_ASSERT_EQUAL_STRING("weak",     imageindicator_severityName(IMAGEINDICATOR_SEVERITY_WEAK));
  TEST_ASSERT_EQUAL_STRING("moderate", imageindicator_severityName(IMAGEINDICATOR_SEVERITY_MODERATE));
}

void test_registration_gate_test_count(void)
{
  TEST_ASSERT_EQUAL_INT_MESSAGE(16, (int)Unity.NumberOfTests,
    "RUN_TEST list and test definitions have drifted apart - a test may be unregistered");
}

int main(void)
{
  UNITY_BEGIN();
  RUN_TEST(test_a_zero_result_has_no_capture_metadata_and_nothing_else);
  RUN_TEST(test_the_flag_indicators_follow_their_flags);
  RUN_TEST(test_ai_source_type_needs_trained_algorithmic_media_in_any_case);
  RUN_TEST(test_ai_generator_software_names_a_known_generator_in_any_case);
  RUN_TEST(test_gps_position_and_null_island);
  RUN_TEST(test_identifier_present_for_each_kind);
  RUN_TEST(test_original_time_in_future_from_one_second_past_a_day);
  RUN_TEST(test_modified_before_original_from_one_second_before);
  RUN_TEST(test_a_time_in_another_form_takes_part_in_no_rule);
  RUN_TEST(test_a_time_before_1970_is_not_read);
  RUN_TEST(test_gps_time_differs_from_one_second_past_an_hour_with_an_offset);
  RUN_TEST(test_edit_history_and_thumbnail_follow_their_counts);
  RUN_TEST(test_no_capture_metadata_needs_all_three_absent);
  RUN_TEST(test_each_kind_has_its_name_severity_and_note);
  RUN_TEST(test_each_severity_has_its_name);
  RUN_TEST(test_registration_gate_test_count);
  return UNITY_END();
}
