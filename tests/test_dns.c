#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <resolv.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>

#include "unity/unity.h"
#include "dns.h"

static int g_failAllocationNumber = 0;
static int g_allocationCount      = 0;

void* __real_malloc(size_t size);
void* __real_calloc(size_t count, size_t size);
char* __real_strdup(const char* text);

static bool static_isFailingAllocation(void)
{
  g_allocationCount++;
  return g_allocationCount == g_failAllocationNumber;
}

void* __wrap_malloc(size_t size)
{
  return static_isFailingAllocation() ? NULL : __real_malloc(size);
}

void* __wrap_calloc(size_t count, size_t size)
{
  return static_isFailingAllocation() ? NULL : __real_calloc(count, size);
}

char* __wrap_strdup(const char* text)
{
  return static_isFailingAllocation() ? NULL : __real_strdup(text);
}

void setUp(void)
{
  g_failAllocationNumber = 0;
  g_allocationCount      = 0;
}

void tearDown(void) {}

#define DNS_TEST_HEADER_SIZE 12

#define QUERY_ID 0x1234

#define WIRE_TYPE_A     1
#define WIRE_TYPE_NS    2
#define WIRE_TYPE_CNAME 5
#define WIRE_TYPE_SOA   6
#define WIRE_TYPE_PTR   12
#define WIRE_TYPE_MX    15
#define WIRE_TYPE_TXT   16
#define WIRE_TYPE_AAAA  28
#define WIRE_TYPE_CAA   257
#define WIRE_CLASS_IN   1
#define WIRE_CLASS_CH   3

#define FLAGS_ANSWER  0x81
#define FLAGS_QUERY   0x01
#define FLAG_TC       0x02
#define FLAGS_RA      0x80

#define RCODE_NOERROR  0
#define RCODE_FORMERR  1
#define RCODE_SERVFAIL 2
#define RCODE_NXDOMAIN 3
#define RCODE_REFUSED  5

#define NAME_POINTER_TO_QUESTION 0xC00C

static unsigned char g_message[DNS_MESSAGE_MAX_SIZE + 1];
static size_t        g_messageLen = 0;

static void static_put8(uint8_t value)
{
  g_message[g_messageLen++] = value;
}

static void static_put16(uint16_t value)
{
  static_put8((uint8_t)(value >> 8));
  static_put8((uint8_t)value);
}

static void static_put32(uint32_t value)
{
  static_put16((uint16_t)(value >> 16));
  static_put16((uint16_t)value);
}

static void static_putBytes(const void* bytes, size_t byte_count)
{
  memcpy(g_message + g_messageLen, bytes, byte_count);
  g_messageLen += byte_count;
}

static void static_putName(const char* dotted_name)
{
  const char* label = dotted_name;
  while (*label != '\0')
  {
    const char* dot = strchr(label, '.');
    size_t label_len = dot != NULL ? (size_t)(dot - label) : strlen(label);
    static_put8((uint8_t)label_len);
    static_putBytes(label, label_len);
    label += label_len + (dot != NULL ? 1 : 0);
  }
  static_put8(0);
}

static void static_startMessageAbout(const char* question_name, uint16_t id, uint8_t flags, uint8_t rcode, uint16_t question_type, uint16_t answer_count)
{
  g_messageLen = 0;
  static_put16(id);
  static_put8(flags);
  static_put8((uint8_t)(FLAGS_RA | rcode));
  static_put16(1);
  static_put16(answer_count);
  static_put16(0);
  static_put16(0);
  static_putName(question_name);
  static_put16(question_type);
  static_put16(WIRE_CLASS_IN);
}

static void static_startMessage(uint16_t id, uint8_t flags, uint8_t rcode, uint16_t question_type, uint16_t answer_count)
{
  static_startMessageAbout("example.com", id, flags, rcode, question_type, answer_count);
}

static void static_startAnswer(uint16_t question_type, uint16_t answer_count)
{
  static_startMessage(QUERY_ID, FLAGS_ANSWER, RCODE_NOERROR, question_type, answer_count);
}

static void static_putRecordHead(uint16_t type, uint16_t class_, uint16_t data_len)
{
  static_put16(NAME_POINTER_TO_QUESTION);
  static_put16(type);
  static_put16(class_);
  static_put32(300);
  static_put16(data_len);
}

static const DnsQuestion_t EXAMPLE_COM_A     = { "example.com", DNS_RECORD_TYPE_A };
static const DnsQuestion_t EXAMPLE_COM_AAAA  = { "example.com", DNS_RECORD_TYPE_AAAA };
static const DnsQuestion_t EXAMPLE_COM_MX    = { "example.com", DNS_RECORD_TYPE_MX };
static const DnsQuestion_t EXAMPLE_COM_NS    = { "example.com", DNS_RECORD_TYPE_NS };
static const DnsQuestion_t EXAMPLE_COM_TXT   = { "example.com", DNS_RECORD_TYPE_TXT };
static const DnsQuestion_t EXAMPLE_COM_CNAME = { "example.com", DNS_RECORD_TYPE_CNAME };
static const DnsQuestion_t EXAMPLE_COM_SOA   = { "example.com", DNS_RECORD_TYPE_SOA };
static const DnsQuestion_t EXAMPLE_COM_CAA   = { "example.com", DNS_RECORD_TYPE_CAA };

static DnsAnswer_t static_readBuiltAnswer(const DnsQuestion_t* question)
{
  DnsAnswer_t answer;
  TEST_ASSERT_TRUE(dns_tryReadResponse(g_message, g_messageLen, question, QUERY_ID, &answer));
  return answer;
}

static DnsAnswer_t static_readFixedAnswer(const unsigned char* message, size_t message_len, const DnsQuestion_t* question)
{
  DnsAnswer_t answer;
  TEST_ASSERT_TRUE(dns_tryReadResponse(message, message_len, question, QUERY_ID, &answer));
  return answer;
}

static void static_assertText(const char* expected, size_t expected_count, const DnsRecordText_t* text)
{
  TEST_ASSERT_EQUAL_size_t(expected_count, text->m_byteCount);
  if (expected_count > 0)
    TEST_ASSERT_EQUAL_MEMORY(expected, text->mp_bytes, expected_count);
  TEST_ASSERT_EQUAL_CHAR('\0', text->mp_bytes[expected_count]);
}

static void static_assertFailedAnswer(DnsAnswerStatus_t expected_status, const DnsAnswer_t* answer)
{
  TEST_ASSERT_EQUAL_INT(expected_status, answer->m_status);
  TEST_ASSERT_EQUAL_INT(0, answer->m_recordCount);
  TEST_ASSERT_NULL(answer->mp_texts);
  TEST_ASSERT_NULL(answer->mp_mxRecords);
  TEST_ASSERT_NULL(answer->mp_soaRecord);
  TEST_ASSERT_NULL(answer->mp_caaRecords);
}

static const unsigned char ORACLE_MX[] = {
  0x12, 0x34, 0x81, 0x00, 0x00, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x07, 0x65, 0x78, 0x61,
  0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x0f, 0x00, 0x01, 0xc0, 0x0c, 0x00,
  0x0f, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x03, 0x00, 0x00, 0x00, 0xc0, 0x0c, 0x00, 0x0f,
  0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x09, 0x00, 0x0a, 0x04, 0x6d, 0x61, 0x69, 0x6c, 0xc0,
  0x0c, 0xc0, 0x0c, 0x00, 0x0f, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x1b, 0x00, 0x14, 0x06,
  0x62, 0x61, 0x63, 0x6b, 0x75, 0x70, 0x04, 0x6d, 0x61, 0x69, 0x6c, 0x07, 0x65, 0x78, 0x61, 0x6d,
  0x70, 0x6c, 0x65, 0x03, 0x6e, 0x65, 0x74, 0x00,
};

static const unsigned char ORACLE_TXT[] = {
  0x12, 0x34, 0x81, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x07, 0x65, 0x78, 0x61,
  0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x10, 0x00, 0x01, 0xc0, 0x0c, 0x00,
  0x10, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x06, 0x05, 0x61, 0x00, 0x62, 0x07, 0x63, 0xc0,
  0x0c, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x26, 0x20, 0x76, 0x3d, 0x73, 0x70,
  0x66, 0x31, 0x20, 0x69, 0x6e, 0x63, 0x6c, 0x75, 0x64, 0x65, 0x3a, 0x5f, 0x73, 0x70, 0x66, 0x2e,
  0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x6e, 0x65, 0x74, 0x20, 0x04, 0x2d, 0x61, 0x6c,
  0x6c,
};

static const unsigned char ORACLE_SOA[] = {
  0x12, 0x34, 0x81, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x07, 0x65, 0x78, 0x61,
  0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x06, 0x00, 0x01, 0xc0, 0x0c, 0x00,
  0x06, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x27, 0x03, 0x6e, 0x73, 0x31, 0xc0, 0x0c, 0x0a,
  0x68, 0x6f, 0x73, 0x74, 0x6d, 0x61, 0x73, 0x74, 0x65, 0x72, 0xc0, 0x0c, 0x78, 0xa5, 0x55, 0xb5,
  0x00, 0x00, 0x1c, 0x20, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x12, 0x75, 0x00, 0x00, 0x00, 0x01, 0x2c,
};

static const unsigned char ORACLE_A_AFTER_CNAME[] = {
  0x12, 0x34, 0x81, 0x00, 0x00, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x07, 0x65, 0x78, 0x61,
  0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00,
  0x05, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x12, 0x04, 0x65, 0x64, 0x67, 0x65, 0x07, 0x65,
  0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x6e, 0x65, 0x74, 0x00, 0xc0, 0x29, 0x00, 0x01, 0x00,
  0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x04, 0xc6, 0x33, 0x64, 0x07, 0xc0, 0x29, 0x00, 0x01, 0x00,
  0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x04, 0xc0, 0x00, 0x02, 0x0a,
};

static const unsigned char ORACLE_CAA[] = {
  0x12, 0x34, 0x81, 0x00, 0x00, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x07, 0x65, 0x78, 0x61,
  0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x01, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x01,
  0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x16, 0x00, 0x05, 0x69, 0x73, 0x73, 0x75, 0x65,
  0x6c, 0x65, 0x74, 0x73, 0x65, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x2e, 0x6f, 0x72, 0x67, 0xc0,
  0x0c, 0x01, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x0c, 0x00, 0x09, 0x69, 0x73, 0x73,
  0x75, 0x65, 0x77, 0x69, 0x6c, 0x64, 0x3b, 0xc0, 0x0c, 0x01, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01,
  0x2c, 0x00, 0x22, 0x80, 0x05, 0x69, 0x6f, 0x64, 0x65, 0x66, 0x6d, 0x61, 0x69, 0x6c, 0x74, 0x6f,
  0x3a, 0x73, 0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x40, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c,
  0x65, 0x2e, 0x63, 0x6f, 0x6d,
};

static const unsigned char ORACLE_AAAA[] = {
  0x12, 0x34, 0x81, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x07, 0x65, 0x78, 0x61,
  0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x1c, 0x00, 0x01, 0xc0, 0x0c, 0x00,
  0x1c, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x10, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x1c, 0x00, 0x01, 0x00,
  0x00, 0x01, 0x2c, 0x00, 0x10, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x01,
};

void test_tryReadResponse_oracle_mx_skips_the_null_mx(void)
{
  DnsAnswer_t answer = static_readFixedAnswer(ORACLE_MX, sizeof(ORACLE_MX), &EXAMPLE_COM_MX);
  TEST_ASSERT_EQUAL_INT(DNS_ANSWER_OK, answer.m_status);
  TEST_ASSERT_EQUAL_INT(2, answer.m_recordCount);
  TEST_ASSERT_EQUAL_UINT16(10, answer.mp_mxRecords[0].m_priority);
  TEST_ASSERT_EQUAL_STRING("mail.example.com", answer.mp_mxRecords[0].mp_hostname);
  TEST_ASSERT_EQUAL_UINT16(20, answer.mp_mxRecords[1].m_priority);
  TEST_ASSERT_EQUAL_STRING("backup.mail.example.net", answer.mp_mxRecords[1].mp_hostname);
  dns_answerFree(&answer);
}

void test_tryReadResponse_oracle_txt_joins_strings_and_keeps_nul(void)
{
  DnsAnswer_t answer = static_readFixedAnswer(ORACLE_TXT, sizeof(ORACLE_TXT), &EXAMPLE_COM_TXT);
  TEST_ASSERT_EQUAL_INT(DNS_ANSWER_OK, answer.m_status);
  TEST_ASSERT_EQUAL_INT(2, answer.m_recordCount);
  static_assertText("a\0b\7c", 5, &answer.mp_texts[0]);
  static_assertText("v=spf1 include:_spf.example.net -all", 36, &answer.mp_texts[1]);
  dns_answerFree(&answer);
}

void test_tryReadResponse_oracle_soa_reads_both_names_and_the_serial(void)
{
  DnsAnswer_t answer = static_readFixedAnswer(ORACLE_SOA, sizeof(ORACLE_SOA), &EXAMPLE_COM_SOA);
  TEST_ASSERT_EQUAL_INT(DNS_ANSWER_OK, answer.m_status);
  TEST_ASSERT_EQUAL_INT(1, answer.m_recordCount);
  TEST_ASSERT_EQUAL_STRING("ns1.example.com", answer.mp_soaRecord->mp_primaryNameServer);
  TEST_ASSERT_EQUAL_STRING("hostmaster.example.com", answer.mp_soaRecord->mp_adminEmail);
  TEST_ASSERT_EQUAL_UINT32(2024101301u, answer.mp_soaRecord->m_serial);
  dns_answerFree(&answer);
}

void test_tryReadResponse_oracle_a_after_cname_keeps_only_the_a_records(void)
{
  DnsAnswer_t answer = static_readFixedAnswer(ORACLE_A_AFTER_CNAME, sizeof(ORACLE_A_AFTER_CNAME), &EXAMPLE_COM_A);
  TEST_ASSERT_EQUAL_INT(DNS_ANSWER_OK, answer.m_status);
  TEST_ASSERT_EQUAL_INT(2, answer.m_recordCount);
  static_assertText("198.51.100.7", 12, &answer.mp_texts[0]);
  static_assertText("192.0.2.10", 10, &answer.mp_texts[1]);
  dns_answerFree(&answer);
}

void test_tryReadResponse_oracle_aaaa_writes_the_short_form(void)
{
  DnsAnswer_t answer = static_readFixedAnswer(ORACLE_AAAA, sizeof(ORACLE_AAAA), &EXAMPLE_COM_AAAA);
  TEST_ASSERT_EQUAL_INT(DNS_ANSWER_OK, answer.m_status);
  TEST_ASSERT_EQUAL_INT(2, answer.m_recordCount);
  static_assertText("2001:db8::1", 11, &answer.mp_texts[0]);
  static_assertText("2001:db8::1:0:0:1", 17, &answer.mp_texts[1]);
  dns_answerFree(&answer);
}

void test_tryReadResponse_oracle_caa_reads_flags_tag_and_value(void)
{
  DnsAnswer_t answer = static_readFixedAnswer(ORACLE_CAA, sizeof(ORACLE_CAA), &EXAMPLE_COM_CAA);
  TEST_ASSERT_EQUAL_INT(DNS_ANSWER_OK, answer.m_status);
  TEST_ASSERT_EQUAL_INT(3, answer.m_recordCount);
  TEST_ASSERT_EQUAL_UINT8(0, answer.mp_caaRecords[0].m_flags);
  static_assertText("issue", 5, &answer.mp_caaRecords[0].m_tag);
  static_assertText("letsencrypt.org", 15, &answer.mp_caaRecords[0].m_value);
  TEST_ASSERT_EQUAL_UINT8(0, answer.mp_caaRecords[1].m_flags);
  static_assertText("issuewild", 9, &answer.mp_caaRecords[1].m_tag);
  static_assertText(";", 1, &answer.mp_caaRecords[1].m_value);
  TEST_ASSERT_EQUAL_UINT8(128, answer.mp_caaRecords[2].m_flags);
  static_assertText("iodef", 5, &answer.mp_caaRecords[2].m_tag);
  static_assertText("mailto:security@example.com", 27, &answer.mp_caaRecords[2].m_value);
  dns_answerFree(&answer);
}

static void static_buildCaaAnswer(uint8_t tag_len, const char* bytes, uint16_t byte_count)
{
  static_startAnswer(WIRE_TYPE_CAA, 1);
  static_putRecordHead(WIRE_TYPE_CAA, WIRE_CLASS_IN, (uint16_t)(2 + byte_count));
  static_put8(0);
  static_put8(tag_len);
  static_putBytes(bytes, byte_count);
}

void test_tryReadResponse_caa_tag_length(void)
{
  static_buildCaaAnswer(5, "issue", 5);
  DnsAnswer_t answer = static_readBuiltAnswer(&EXAMPLE_COM_CAA);
  TEST_ASSERT_EQUAL_INT(DNS_ANSWER_OK, answer.m_status);
  TEST_ASSERT_EQUAL_INT(1, answer.m_recordCount);
  static_assertText("issue", 5, &answer.mp_caaRecords[0].m_tag);
  static_assertText("", 0, &answer.mp_caaRecords[0].m_value);
  dns_answerFree(&answer);

  char long_tag_and_value[129];
  memset(long_tag_and_value, 'a', 128);
  long_tag_and_value[128] = 'x';
  static_buildCaaAnswer(128, long_tag_and_value, 129);
  answer = static_readBuiltAnswer(&EXAMPLE_COM_CAA);
  TEST_ASSERT_EQUAL_INT(DNS_ANSWER_OK, answer.m_status);
  static_assertText(long_tag_and_value, 128, &answer.mp_caaRecords[0].m_tag);
  static_assertText("x", 1, &answer.mp_caaRecords[0].m_value);
  dns_answerFree(&answer);

  static_buildCaaAnswer(6, "issue", 5);
  answer = static_readBuiltAnswer(&EXAMPLE_COM_CAA);
  static_assertFailedAnswer(DNS_ANSWER_MALFORMED, &answer);

  static_buildCaaAnswer(0, "x", 1);
  answer = static_readBuiltAnswer(&EXAMPLE_COM_CAA);
  static_assertFailedAnswer(DNS_ANSWER_MALFORMED, &answer);
}

void test_tryReadResponse_caa_shorter_than_two_bytes_is_malformed(void)
{
  static_startAnswer(WIRE_TYPE_CAA, 1);
  static_putRecordHead(WIRE_TYPE_CAA, WIRE_CLASS_IN, 1);
  static_put8(0);
  DnsAnswer_t answer = static_readBuiltAnswer(&EXAMPLE_COM_CAA);
  static_assertFailedAnswer(DNS_ANSWER_MALFORMED, &answer);

  static_startAnswer(WIRE_TYPE_CAA, 2);
  static_putRecordHead(WIRE_TYPE_CAA, WIRE_CLASS_IN, 1);
  static_put8(0);
  static_putRecordHead(WIRE_TYPE_CAA, WIRE_CLASS_IN, 8);
  static_put8(0);
  static_put8(5);
  static_putBytes("issuex", 6);
  answer = static_readBuiltAnswer(&EXAMPLE_COM_CAA);
  static_assertFailedAnswer(DNS_ANSWER_MALFORMED, &answer);
}

void test_tryReadResponse_ns_and_cname_names(void)
{
  static_startAnswer(WIRE_TYPE_NS, 2);
  static_putRecordHead(WIRE_TYPE_NS, WIRE_CLASS_IN, 22);
  static_putName("ns1.provider.example");
  size_t first_name_offset = g_messageLen - 22;
  static_putRecordHead(WIRE_TYPE_NS, WIRE_CLASS_IN, 6);
  static_put8(3);
  static_putBytes("ns2", 3);
  static_put16((uint16_t)(0xC000 | (first_name_offset + 4)));
  DnsAnswer_t answer = static_readBuiltAnswer(&EXAMPLE_COM_NS);
  TEST_ASSERT_EQUAL_INT(DNS_ANSWER_OK, answer.m_status);
  TEST_ASSERT_EQUAL_INT(2, answer.m_recordCount);
  static_assertText("ns1.provider.example", 20, &answer.mp_texts[0]);
  static_assertText("ns2.provider.example", 20, &answer.mp_texts[1]);
  dns_answerFree(&answer);

  static_startAnswer(WIRE_TYPE_CNAME, 1);
  static_putRecordHead(WIRE_TYPE_CNAME, WIRE_CLASS_IN, 18);
  static_putName("edge.cdn.example");
  answer = static_readBuiltAnswer(&EXAMPLE_COM_CNAME);
  TEST_ASSERT_EQUAL_INT(DNS_ANSWER_OK, answer.m_status);
  TEST_ASSERT_EQUAL_INT(1, answer.m_recordCount);
  static_assertText("edge.cdn.example", 16, &answer.mp_texts[0]);
  dns_answerFree(&answer);
}

void test_tryReadResponse_empty_txt_is_one_empty_record(void)
{
  static_startAnswer(WIRE_TYPE_TXT, 1);
  static_putRecordHead(WIRE_TYPE_TXT, WIRE_CLASS_IN, 0);
  DnsAnswer_t answer = static_readBuiltAnswer(&EXAMPLE_COM_TXT);
  TEST_ASSERT_EQUAL_INT(DNS_ANSWER_OK, answer.m_status);
  TEST_ASSERT_EQUAL_INT(1, answer.m_recordCount);
  static_assertText("", 0, &answer.mp_texts[0]);
  dns_answerFree(&answer);
}

void test_tryReadResponse_txt_string_length_against_the_data_end(void)
{
  static_startAnswer(WIRE_TYPE_TXT, 1);
  static_putRecordHead(WIRE_TYPE_TXT, WIRE_CLASS_IN, 4);
  static_put8(3);
  static_putBytes("abc", 3);
  DnsAnswer_t answer = static_readBuiltAnswer(&EXAMPLE_COM_TXT);
  TEST_ASSERT_EQUAL_INT(DNS_ANSWER_OK, answer.m_status);
  static_assertText("abc", 3, &answer.mp_texts[0]);
  dns_answerFree(&answer);

  static_startAnswer(WIRE_TYPE_TXT, 1);
  static_putRecordHead(WIRE_TYPE_TXT, WIRE_CLASS_IN, 4);
  static_put8(4);
  static_putBytes("abc", 3);
  answer = static_readBuiltAnswer(&EXAMPLE_COM_TXT);
  static_assertFailedAnswer(DNS_ANSWER_MALFORMED, &answer);
}

void test_tryReadResponse_skips_records_of_another_class_or_type(void)
{
  static_startAnswer(WIRE_TYPE_A, 3);
  static_putRecordHead(WIRE_TYPE_A, WIRE_CLASS_CH, 4);
  static_putBytes("\x0a\x00\x00\x01", 4);
  static_putRecordHead(WIRE_TYPE_AAAA, WIRE_CLASS_IN, 16);
  static_putBytes("\x20\x01\x0d\xb8\0\0\0\0\0\0\0\0\0\0\0\x02", 16);
  static_putRecordHead(WIRE_TYPE_A, WIRE_CLASS_IN, 4);
  static_putBytes("\xcb\x00\x71\x05", 4);
  DnsAnswer_t answer = static_readBuiltAnswer(&EXAMPLE_COM_A);
  TEST_ASSERT_EQUAL_INT(DNS_ANSWER_OK, answer.m_status);
  TEST_ASSERT_EQUAL_INT(1, answer.m_recordCount);
  static_assertText("203.0.113.5", 11, &answer.mp_texts[0]);
  dns_answerFree(&answer);
}

void test_tryReadResponse_address_length_must_be_exact(void)
{
  static const struct {
    uint16_t               m_wireType;
    const DnsQuestion_t*   mp_question;
    uint16_t               m_dataLen;
  } cases[] = {
    { WIRE_TYPE_A,    &EXAMPLE_COM_A,    3 },
    { WIRE_TYPE_A,    &EXAMPLE_COM_A,    5 },
    { WIRE_TYPE_AAAA, &EXAMPLE_COM_AAAA, 15 },
    { WIRE_TYPE_AAAA, &EXAMPLE_COM_AAAA, 17 },
  };
  static const unsigned char zeros[17] = { 0 };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    static_startAnswer(cases[i].m_wireType, 1);
    static_putRecordHead(cases[i].m_wireType, WIRE_CLASS_IN, cases[i].m_dataLen);
    static_putBytes(zeros, cases[i].m_dataLen);
    DnsAnswer_t answer = static_readBuiltAnswer(cases[i].mp_question);
    static_assertFailedAnswer(DNS_ANSWER_MALFORMED, &answer);
  }
}

void test_tryReadResponse_name_must_fill_the_data(void)
{
  static_startAnswer(WIRE_TYPE_NS, 1);
  static_putRecordHead(WIRE_TYPE_NS, WIRE_CLASS_IN, 6);
  static_putName("ns1");
  static_put8(0);
  DnsAnswer_t answer = static_readBuiltAnswer(&EXAMPLE_COM_NS);
  static_assertFailedAnswer(DNS_ANSWER_MALFORMED, &answer);

  static_startAnswer(WIRE_TYPE_NS, 2);
  static_putRecordHead(WIRE_TYPE_NS, WIRE_CLASS_IN, 4);
  static_put8(3);
  static_putBytes("ns1", 3);
  static_putRecordHead(WIRE_TYPE_A, WIRE_CLASS_IN, 4);
  static_putBytes("\xc6\x33\x64\x07", 4);
  answer = static_readBuiltAnswer(&EXAMPLE_COM_NS);
  static_assertFailedAnswer(DNS_ANSWER_MALFORMED, &answer);
}

void test_tryReadResponse_compression_loop_is_malformed(void)
{
  static_startAnswer(WIRE_TYPE_CNAME, 1);
  static_putRecordHead(WIRE_TYPE_CNAME, WIRE_CLASS_IN, 2);
  static_put16((uint16_t)(0xC000 | g_messageLen));
  DnsAnswer_t answer = static_readBuiltAnswer(&EXAMPLE_COM_CNAME);
  static_assertFailedAnswer(DNS_ANSWER_MALFORMED, &answer);

  static_startAnswer(WIRE_TYPE_A, 1);
  static_put16((uint16_t)(0xC000 | g_messageLen));
  static_put16(WIRE_TYPE_A);
  static_put16(WIRE_CLASS_IN);
  static_put32(300);
  static_put16(4);
  static_putBytes("\xc0\x00\x02\x01", 4);
  answer = static_readBuiltAnswer(&EXAMPLE_COM_A);
  static_assertFailedAnswer(DNS_ANSWER_MALFORMED, &answer);
}

void test_tryReadResponse_mx_data_length(void)
{
  static_startAnswer(WIRE_TYPE_MX, 1);
  static_putRecordHead(WIRE_TYPE_MX, WIRE_CLASS_IN, 3);
  static_put16(0);
  static_put8(0);
  DnsAnswer_t answer = static_readBuiltAnswer(&EXAMPLE_COM_MX);
  TEST_ASSERT_EQUAL_INT(DNS_ANSWER_OK, answer.m_status);
  TEST_ASSERT_EQUAL_INT(0, answer.m_recordCount);
  dns_answerFree(&answer);

  static_startAnswer(WIRE_TYPE_MX, 1);
  static_putRecordHead(WIRE_TYPE_MX, WIRE_CLASS_IN, 2);
  static_put16(0);
  answer = static_readBuiltAnswer(&EXAMPLE_COM_MX);
  static_assertFailedAnswer(DNS_ANSWER_MALFORMED, &answer);

  static_startAnswer(WIRE_TYPE_MX, 1);
  static_putRecordHead(WIRE_TYPE_MX, WIRE_CLASS_IN, 1);
  static_put8(0);
  answer = static_readBuiltAnswer(&EXAMPLE_COM_MX);
  static_assertFailedAnswer(DNS_ANSWER_MALFORMED, &answer);

  static_startAnswer(WIRE_TYPE_MX, 2);
  static_putRecordHead(WIRE_TYPE_MX, WIRE_CLASS_IN, 4);
  static_put16(5);
  static_put8(3);
  static_putBytes("m", 1);
  static_putRecordHead(WIRE_TYPE_MX, WIRE_CLASS_IN, 3);
  static_put16(0);
  static_put8(0);
  answer = static_readBuiltAnswer(&EXAMPLE_COM_MX);
  static_assertFailedAnswer(DNS_ANSWER_MALFORMED, &answer);

  static_startAnswer(WIRE_TYPE_MX, 1);
  static_putRecordHead(WIRE_TYPE_MX, WIRE_CLASS_IN, 9);
  static_put16(5);
  static_putName("mx1");
  static_putBytes("\0\0", 2);
  answer = static_readBuiltAnswer(&EXAMPLE_COM_MX);
  static_assertFailedAnswer(DNS_ANSWER_MALFORMED, &answer);
}

void test_tryReadResponse_soa_numbers_and_second_record(void)
{
  static const uint16_t number_sizes[] = { 19, 21 };
  static const unsigned char numbers[21] = { 0 };
  for (size_t i = 0; i < sizeof(number_sizes) / sizeof(number_sizes[0]); i++)
  {
    static_startAnswer(WIRE_TYPE_SOA, 1);
    static_putRecordHead(WIRE_TYPE_SOA, WIRE_CLASS_IN, (uint16_t)(4 + number_sizes[i]));
    static_put16(NAME_POINTER_TO_QUESTION);
    static_put16(NAME_POINTER_TO_QUESTION);
    static_putBytes(numbers, number_sizes[i]);
    DnsAnswer_t answer = static_readBuiltAnswer(&EXAMPLE_COM_SOA);
    static_assertFailedAnswer(DNS_ANSWER_MALFORMED, &answer);
  }

  static_startAnswer(WIRE_TYPE_SOA, 1);
  static_putRecordHead(WIRE_TYPE_SOA, WIRE_CLASS_IN, 21);
  static_put16(NAME_POINTER_TO_QUESTION);
  static_put16((uint16_t)(0xC000 | g_messageLen));
  static_putBytes(numbers, 17);
  DnsAnswer_t looped = static_readBuiltAnswer(&EXAMPLE_COM_SOA);
  static_assertFailedAnswer(DNS_ANSWER_MALFORMED, &looped);

  static_startAnswer(WIRE_TYPE_SOA, 2);
  static_putRecordHead(WIRE_TYPE_SOA, WIRE_CLASS_IN, 24);
  static_put16(NAME_POINTER_TO_QUESTION);
  static_put16(NAME_POINTER_TO_QUESTION);
  static_put32(7);
  static_putBytes(numbers, 16);
  static_putRecordHead(WIRE_TYPE_SOA, WIRE_CLASS_IN, 24);
  static_put16(NAME_POINTER_TO_QUESTION);
  static_put16(NAME_POINTER_TO_QUESTION);
  static_put32(8);
  static_putBytes(numbers, 16);
  DnsAnswer_t answer = static_readBuiltAnswer(&EXAMPLE_COM_SOA);
  TEST_ASSERT_EQUAL_INT(DNS_ANSWER_OK, answer.m_status);
  TEST_ASSERT_EQUAL_INT(1, answer.m_recordCount);
  TEST_ASSERT_EQUAL_UINT32(7, answer.mp_soaRecord->m_serial);
  TEST_ASSERT_EQUAL_STRING("example.com", answer.mp_soaRecord->mp_primaryNameServer);
  dns_answerFree(&answer);
}

void test_tryReadResponse_bad_record_after_a_good_one_fails_the_answer(void)
{
  static_startAnswer(WIRE_TYPE_A, 2);
  static_putRecordHead(WIRE_TYPE_A, WIRE_CLASS_IN, 4);
  static_putBytes("\xc6\x33\x64\x07", 4);
  static_putRecordHead(WIRE_TYPE_A, WIRE_CLASS_IN, 5);
  static_putBytes("\xc6\x33\x64\x07\x00", 5);
  DnsAnswer_t answer = static_readBuiltAnswer(&EXAMPLE_COM_A);
  static_assertFailedAnswer(DNS_ANSWER_MALFORMED, &answer);
}

void test_tryReadResponse_nodata_is_ok_with_no_record(void)
{
  static_startAnswer(WIRE_TYPE_MX, 0);
  DnsAnswer_t answer = static_readBuiltAnswer(&EXAMPLE_COM_MX);
  static_assertFailedAnswer(DNS_ANSWER_OK, &answer);
}

void test_tryReadResponse_error_codes(void)
{
  static const struct {
    uint8_t           m_rcode;
    DnsAnswerStatus_t m_status;
  } cases[] = {
    { RCODE_NXDOMAIN, DNS_ANSWER_NXDOMAIN },
    { RCODE_SERVFAIL, DNS_ANSWER_SERVER_ERROR },
    { RCODE_REFUSED,  DNS_ANSWER_SERVER_ERROR },
    { RCODE_FORMERR,  DNS_ANSWER_SERVER_ERROR },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    static_startMessage(QUERY_ID, FLAGS_ANSWER, cases[i].m_rcode, WIRE_TYPE_A, 1);
    static_putRecordHead(WIRE_TYPE_A, WIRE_CLASS_IN, 4);
    static_putBytes("\xc6\x33\x64\x07", 4);
    DnsAnswer_t answer = static_readBuiltAnswer(&EXAMPLE_COM_A);
    static_assertFailedAnswer(cases[i].m_status, &answer);
  }
}

void test_tryReadResponse_truncated_answer(void)
{
  static_startMessage(QUERY_ID, FLAGS_ANSWER | FLAG_TC, RCODE_NOERROR, WIRE_TYPE_TXT, 1);
  static_putRecordHead(WIRE_TYPE_TXT, WIRE_CLASS_IN, 4);
  static_put8(3);
  static_putBytes("abc", 3);
  DnsAnswer_t answer = static_readBuiltAnswer(&EXAMPLE_COM_TXT);
  static_assertFailedAnswer(DNS_ANSWER_TRUNCATED, &answer);
}

static void static_assertNotTheAnswer(const DnsQuestion_t* question)
{
  DnsAnswer_t answer;
  memset(&answer, 0x5A, sizeof(answer));
  TEST_ASSERT_FALSE(dns_tryReadResponse(g_message, g_messageLen, question, QUERY_ID, &answer));
  DnsAnswer_t untouched;
  memset(&untouched, 0x5A, sizeof(untouched));
  TEST_ASSERT_EQUAL_MEMORY(&untouched, &answer, sizeof(answer));
}

void test_tryReadResponse_other_id_is_not_the_answer(void)
{
  static_startMessage(QUERY_ID + 1, FLAGS_ANSWER, RCODE_NOERROR, WIRE_TYPE_A, 0);
  static_assertNotTheAnswer(&EXAMPLE_COM_A);
}

void test_tryReadResponse_query_without_the_answer_bit_is_not_the_answer(void)
{
  static_startMessage(QUERY_ID, FLAGS_QUERY, RCODE_NOERROR, WIRE_TYPE_A, 0);
  static_assertNotTheAnswer(&EXAMPLE_COM_A);
}

void test_tryReadResponse_other_question_is_not_the_answer(void)
{
  static const DnsQuestion_t other_name = { "example.org", DNS_RECORD_TYPE_A };
  static_startAnswer(WIRE_TYPE_A, 0);
  static_assertNotTheAnswer(&other_name);

  static_startAnswer(WIRE_TYPE_AAAA, 0);
  static_assertNotTheAnswer(&EXAMPLE_COM_A);

  static_startAnswer(WIRE_TYPE_A, 0);
  g_message[g_messageLen - 1] = WIRE_CLASS_CH;
  static_assertNotTheAnswer(&EXAMPLE_COM_A);

  static_startAnswer(WIRE_TYPE_A, 0);
  g_messageLen = 12;
  static_put16(0xC000 | 12);
  static_put16(WIRE_TYPE_A);
  static_put16(WIRE_CLASS_IN);
  static_assertNotTheAnswer(&EXAMPLE_COM_A);
}

void test_tryReadResponse_question_name_case_is_ignored(void)
{
  static const DnsQuestion_t upper_name = { "EXAMPLE.Com", DNS_RECORD_TYPE_A };
  static_startAnswer(WIRE_TYPE_A, 0);
  DnsAnswer_t answer = static_readBuiltAnswer(&upper_name);
  TEST_ASSERT_EQUAL_INT(DNS_ANSWER_OK, answer.m_status);
  dns_answerFree(&answer);
}

void test_tryReadResponse_question_count_must_be_one(void)
{
  static_startAnswer(WIRE_TYPE_A, 0);
  g_message[5] = 0;
  g_messageLen = 12;
  static_assertNotTheAnswer(&EXAMPLE_COM_A);

  static_startAnswer(WIRE_TYPE_A, 0);
  g_message[5] = 2;
  static_putName("example.com");
  static_put16(WIRE_TYPE_A);
  static_put16(WIRE_CLASS_IN);
  static_assertNotTheAnswer(&EXAMPLE_COM_A);
}

void test_tryReadResponse_message_shorter_than_a_header_is_not_the_answer(void)
{
  static_startAnswer(WIRE_TYPE_A, 0);
  g_messageLen = 11;
  static_assertNotTheAnswer(&EXAMPLE_COM_A);

  static_startAnswer(WIRE_TYPE_A, 0);
  g_messageLen = 12;
  DnsAnswer_t answer = static_readBuiltAnswer(&EXAMPLE_COM_A);
  static_assertFailedAnswer(DNS_ANSWER_MALFORMED, &answer);
}

void test_tryReadResponse_sections_that_do_not_fit_are_malformed(void)
{
  static_startAnswer(WIRE_TYPE_A, 1);
  DnsAnswer_t answer = static_readBuiltAnswer(&EXAMPLE_COM_A);
  static_assertFailedAnswer(DNS_ANSWER_MALFORMED, &answer);
}

void test_tryReadResponse_message_size_limit(void)
{
  static_startAnswer(WIRE_TYPE_A, 0);
  memset(g_message + g_messageLen, 0, sizeof(g_message) - g_messageLen);
  g_messageLen = DNS_MESSAGE_MAX_SIZE;
  DnsAnswer_t answer = static_readBuiltAnswer(&EXAMPLE_COM_A);
  static_assertFailedAnswer(DNS_ANSWER_MALFORMED, &answer);

  g_messageLen = DNS_MESSAGE_MAX_SIZE + 1;
  static_assertNotTheAnswer(&EXAMPLE_COM_A);
}

void test_tryReadResponse_record_count_limit(void)
{
  TEST_ASSERT_EQUAL_INT(256, DNS_ANSWER_MAX_RECORD_COUNT);
  for (int record_count = DNS_ANSWER_MAX_RECORD_COUNT; record_count <= DNS_ANSWER_MAX_RECORD_COUNT + 1; record_count++)
  {
    static_startAnswer(WIRE_TYPE_A, (uint16_t)record_count);
    for (int i = 0; i < record_count; i++)
    {
      static_putRecordHead(WIRE_TYPE_A, WIRE_CLASS_IN, 4);
      static_putBytes((const unsigned char[]){ 192, 0, 2, (unsigned char)i }, 4);
    }
    DnsAnswer_t answer = static_readBuiltAnswer(&EXAMPLE_COM_A);
    if (record_count == DNS_ANSWER_MAX_RECORD_COUNT)
    {
      TEST_ASSERT_EQUAL_INT(DNS_ANSWER_OK, answer.m_status);
      TEST_ASSERT_EQUAL_INT(DNS_ANSWER_MAX_RECORD_COUNT, answer.m_recordCount);
      static_assertText("192.0.2.255", 11, &answer.mp_texts[DNS_ANSWER_MAX_RECORD_COUNT - 1]);
      dns_answerFree(&answer);
    }
    else
      static_assertFailedAnswer(DNS_ANSWER_MALFORMED, &answer);
  }
}

static void static_buildAnswerThroughCname(const char* target)
{
  static_startAnswer(WIRE_TYPE_A, 2);
  static_putRecordHead(WIRE_TYPE_CNAME, WIRE_CLASS_IN, (uint16_t)(strlen(target) + 2));
  static_putName(target);
  static_putName(target);
  static_put16(WIRE_TYPE_A);
  static_put16(WIRE_CLASS_IN);
  static_put32(300);
  static_put16(4);
  static_putBytes((const unsigned char[]){ 10, 0, 0, 5 }, 4);
}

void test_tryReadResponse_record_of_a_name_that_is_not_public(void)
{
  static_buildAnswerThroughCname("db.internal");
  DnsAnswer_t answer = static_readBuiltAnswer(&EXAMPLE_COM_A);
  static_assertFailedAnswer(DNS_ANSWER_NOT_PUBLIC_NAME, &answer);

  static_buildAnswerThroughCname("db.example.net");
  answer = static_readBuiltAnswer(&EXAMPLE_COM_A);
  TEST_ASSERT_EQUAL_INT(DNS_ANSWER_OK, answer.m_status);
  TEST_ASSERT_EQUAL_INT(1, answer.m_recordCount);
  static_assertText("10.0.0.5", 8, &answer.mp_texts[0]);
  dns_answerFree(&answer);
}

static void static_buildCnameOnlyAnswer(uint16_t question_type, uint8_t rcode, const char* target)
{
  static_startMessage(QUERY_ID, FLAGS_ANSWER, rcode, question_type, 1);
  static_putRecordHead(WIRE_TYPE_CNAME, WIRE_CLASS_IN, (uint16_t)(strlen(target) + 2));
  static_putName(target);
}

void test_tryReadResponse_cname_to_a_name_that_is_not_public_hides_whether_it_exists(void)
{
  static const uint8_t rcodes[2] = { RCODE_NOERROR, RCODE_NXDOMAIN };
  for (int r = 0; r < 2; r++)
  {
    static_buildCnameOnlyAnswer(WIRE_TYPE_A, rcodes[r], "db.internal");
    DnsAnswer_t answer = static_readBuiltAnswer(&EXAMPLE_COM_A);
    static_assertFailedAnswer(DNS_ANSWER_NOT_PUBLIC_NAME, &answer);

    static_buildCnameOnlyAnswer(WIRE_TYPE_A, rcodes[r], "db.example.net");
    answer = static_readBuiltAnswer(&EXAMPLE_COM_A);
    TEST_ASSERT_EQUAL_INT(r == 0 ? DNS_ANSWER_OK : DNS_ANSWER_NXDOMAIN, answer.m_status);
    TEST_ASSERT_EQUAL_INT(0, answer.m_recordCount);
    dns_answerFree(&answer);
  }

  static_buildCnameOnlyAnswer(WIRE_TYPE_A, RCODE_NOERROR, "db.internal");
  g_message[2] |= FLAG_TC;
  DnsAnswer_t answer = static_readBuiltAnswer(&EXAMPLE_COM_A);
  static_assertFailedAnswer(DNS_ANSWER_TRUNCATED, &answer);

  static_buildCnameOnlyAnswer(WIRE_TYPE_CNAME, RCODE_NOERROR, "db.internal");
  answer = static_readBuiltAnswer(&EXAMPLE_COM_CNAME);
  TEST_ASSERT_EQUAL_INT(DNS_ANSWER_OK, answer.m_status);
  TEST_ASSERT_EQUAL_INT(1, answer.m_recordCount);
  static_assertText("db.internal", 11, &answer.mp_texts[0]);
  dns_answerFree(&answer);
}

static const uint16_t WIRE_TYPES[DNS_RECORD_TYPE_COUNT] = {
  WIRE_TYPE_A, WIRE_TYPE_AAAA, WIRE_TYPE_MX, WIRE_TYPE_NS, WIRE_TYPE_TXT, WIRE_TYPE_CNAME, WIRE_TYPE_SOA, WIRE_TYPE_CAA, WIRE_TYPE_PTR,
};

static void static_putRecordOwnedBy(const char* owner, uint16_t wire_type)
{
  static_putName(owner);
  static_put16(wire_type);
  static_put16(WIRE_CLASS_IN);
  static_put32(300);
  switch (wire_type)
  {
    case WIRE_TYPE_A:     static_put16(4);  static_putBytes("\xc0\x00\x02\x01", 4); break;
    case WIRE_TYPE_AAAA:  static_put16(16); static_putBytes("\x20\x01\x0d\xb8\0\0\0\0\0\0\0\0\0\0\0\x01", 16); break;
    case WIRE_TYPE_MX:    static_put16(6);  static_put16(10); static_putBytes("\x02mx\x00", 4); break;
    case WIRE_TYPE_SOA:   static_put16(28); static_putBytes("\x02ns\x00\x02hm\x00", 8); static_putBytes("\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 20); break;
    case WIRE_TYPE_CAA:   static_put16(8);  static_putBytes("\x00\x05issuex", 8); break;
    case WIRE_TYPE_TXT:   static_put16(2);  static_putBytes("\x01x", 2); break;
    default:              static_put16(4);  static_putBytes("\x02ns\x00", 4); break;
  }
}

void test_tryReadResponse_every_type_refuses_a_record_of_a_name_that_is_not_public(void)
{
  static const char* const owners[2] = { "db.internal", "db.example.net" };
  for (int type = 0; type < DNS_RECORD_TYPE_COUNT; type++)
  {
    const DnsQuestion_t question = { "example.com", (DnsRecordType_t)type };
    for (int o = 0; o < 2; o++)
    {
      static_startAnswer(WIRE_TYPES[type], 1);
      static_putRecordOwnedBy(owners[o], WIRE_TYPES[type]);
      DnsAnswer_t answer = static_readBuiltAnswer(&question);
      if (o == 0)
        static_assertFailedAnswer(DNS_ANSWER_NOT_PUBLIC_NAME, &answer);
      else
      {
        TEST_ASSERT_EQUAL_INT_MESSAGE(DNS_ANSWER_OK, answer.m_status, owners[o]);
        TEST_ASSERT_EQUAL_INT(1, answer.m_recordCount);
        dns_answerFree(&answer);
      }
    }
  }
}

void test_tryReadResponse_record_of_the_question_name_is_read(void)
{
  static const DnsQuestion_t ptr_question = { "14.215.184.93.in-addr.arpa", DNS_RECORD_TYPE_PTR };
  static const char* const owners[2] = { "14.215.184.93.in-addr.arpa", "14.215.184.93.IN-ADDR.ARPA" };
  for (int o = 0; o < 2; o++)
  {
    static_startMessageAbout(ptr_question.mp_domainName, QUERY_ID, FLAGS_ANSWER, RCODE_NOERROR, WIRE_TYPE_PTR, 1);
    static_putName(owners[o]);
    static_put16(WIRE_TYPE_PTR);
    static_put16(WIRE_CLASS_IN);
    static_put32(300);
    static_put16(18);
    static_putName("host.example.net");
    DnsAnswer_t answer = static_readBuiltAnswer(&ptr_question);
    TEST_ASSERT_EQUAL_INT_MESSAGE(DNS_ANSWER_OK, answer.m_status, owners[o]);
    TEST_ASSERT_EQUAL_INT(1, answer.m_recordCount);
    static_assertText("host.example.net", 16, &answer.mp_texts[0]);
    dns_answerFree(&answer);
  }

  static_startMessageAbout(ptr_question.mp_domainName, QUERY_ID, FLAGS_ANSWER, RCODE_NOERROR, WIRE_TYPE_PTR, 1);
  static_putRecordOwnedBy("15.215.184.93.in-addr.arpa", WIRE_TYPE_PTR);
  DnsAnswer_t answer = static_readBuiltAnswer(&ptr_question);
  static_assertFailedAnswer(DNS_ANSWER_NOT_PUBLIC_NAME, &answer);

  static const DnsQuestion_t dmarc_question = { "_dmarc.example.com", DNS_RECORD_TYPE_TXT };
  static_startMessageAbout(dmarc_question.mp_domainName, QUERY_ID, FLAGS_ANSWER, RCODE_NOERROR, WIRE_TYPE_TXT, 1);
  static_putRecordHead(WIRE_TYPE_TXT, WIRE_CLASS_IN, 19);
  static_put8(18);
  static_putBytes("v=DMARC1; p=reject", 18);
  answer = static_readBuiltAnswer(&dmarc_question);
  TEST_ASSERT_EQUAL_INT(DNS_ANSWER_OK, answer.m_status);
  TEST_ASSERT_EQUAL_INT(1, answer.m_recordCount);
  static_assertText("v=DMARC1; p=reject", 18, &answer.mp_texts[0]);
  dns_answerFree(&answer);
}

void test_tryReadResponse_owner_that_only_contains_the_question_name_is_judged(void)
{
  static const DnsQuestion_t ptr_question = { "14.215.184.93.in-addr.arpa", DNS_RECORD_TYPE_PTR };
  static const char* const owners[2] = { "14.215.184.93.in-addr.arpa.internal", "x.14.215.184.93.in-addr.arpa" };
  for (int o = 0; o < 2; o++)
  {
    static_startMessageAbout(ptr_question.mp_domainName, QUERY_ID, FLAGS_ANSWER, RCODE_NOERROR, WIRE_TYPE_PTR, 1);
    static_putRecordOwnedBy(owners[o], WIRE_TYPE_PTR);
    DnsAnswer_t answer = static_readBuiltAnswer(&ptr_question);
    TEST_ASSERT_EQUAL_INT_MESSAGE(DNS_ANSWER_NOT_PUBLIC_NAME, answer.m_status, owners[o]);
    static_assertFailedAnswer(DNS_ANSWER_NOT_PUBLIC_NAME, &answer);
  }
}

static void static_buildTxtAnswerThroughCname(const char* question_name, const char* target)
{
  static_startMessageAbout(question_name, QUERY_ID, FLAGS_ANSWER, RCODE_NOERROR, WIRE_TYPE_TXT, 2);
  static_putRecordHead(WIRE_TYPE_CNAME, WIRE_CLASS_IN, (uint16_t)(strlen(target) + 2));
  static_putName(target);
  static_putName(target);
  static_put16(WIRE_TYPE_TXT);
  static_put16(WIRE_CLASS_IN);
  static_put32(300);
  static_put16(8);
  static_put8(7);
  static_putBytes("v=DKIM1", 7);
}

void test_tryReadResponse_cname_to_an_underscore_name_is_followed(void)
{
  static const DnsQuestion_t dkim_question = { "selector1._domainkey.example.com", DNS_RECORD_TYPE_TXT };
  static_buildTxtAnswerThroughCname(dkim_question.mp_domainName, "selector1-example-com._domainkey.example.onmicrosoft.com");
  DnsAnswer_t answer = static_readBuiltAnswer(&dkim_question);
  TEST_ASSERT_EQUAL_INT(DNS_ANSWER_OK, answer.m_status);
  TEST_ASSERT_EQUAL_INT(1, answer.m_recordCount);
  static_assertText("v=DKIM1", 7, &answer.mp_texts[0]);
  dns_answerFree(&answer);

  static const DnsQuestion_t ptr_question = { "14.215.184.93.in-addr.arpa", DNS_RECORD_TYPE_PTR };
  static_startMessageAbout(ptr_question.mp_domainName, QUERY_ID, FLAGS_ANSWER, RCODE_NOERROR, WIRE_TYPE_PTR, 1);
  static_putRecordHead(WIRE_TYPE_CNAME, WIRE_CLASS_IN, 33);
  static_putName("14.0-25.215.184.93.in-addr.arpa");
  answer = static_readBuiltAnswer(&ptr_question);
  static_assertFailedAnswer(DNS_ANSWER_NOT_PUBLIC_NAME, &answer);
}

void test_tryReadResponse_null_mx_sets_its_flag(void)
{
  DnsAnswer_t answer = static_readFixedAnswer(ORACLE_MX, sizeof(ORACLE_MX), &EXAMPLE_COM_MX);
  TEST_ASSERT_EQUAL_INT(DNS_ANSWER_OK, answer.m_status);
  TEST_ASSERT_EQUAL_INT(2, answer.m_recordCount);
  TEST_ASSERT_TRUE(answer.m_hasNullMx);
  dns_answerFree(&answer);

  static_startAnswer(WIRE_TYPE_MX, 1);
  static_putRecordHead(WIRE_TYPE_MX, WIRE_CLASS_IN, 3);
  static_put16(0);
  static_put8(0);
  answer = static_readBuiltAnswer(&EXAMPLE_COM_MX);
  TEST_ASSERT_EQUAL_INT(DNS_ANSWER_OK, answer.m_status);
  TEST_ASSERT_EQUAL_INT(0, answer.m_recordCount);
  TEST_ASSERT_TRUE(answer.m_hasNullMx);
  dns_answerFree(&answer);

  static_startAnswer(WIRE_TYPE_MX, 1);
  static_putRecordHead(WIRE_TYPE_MX, WIRE_CLASS_IN, 6);
  static_put16(10);
  static_putBytes("\x02mx\x00", 4);
  answer = static_readBuiltAnswer(&EXAMPLE_COM_MX);
  TEST_ASSERT_EQUAL_INT(DNS_ANSWER_OK, answer.m_status);
  TEST_ASSERT_EQUAL_INT(1, answer.m_recordCount);
  TEST_ASSERT_FALSE(answer.m_hasNullMx);
  dns_answerFree(&answer);
}

void test_tryReadResponse_failed_answer_clears_the_null_mx_flag(void)
{
  static_startAnswer(WIRE_TYPE_MX, 2);
  static_putRecordHead(WIRE_TYPE_MX, WIRE_CLASS_IN, 3);
  static_put16(0);
  static_put8(0);
  static_putRecordOwnedBy("db.internal", WIRE_TYPE_MX);
  DnsAnswer_t answer = static_readBuiltAnswer(&EXAMPLE_COM_MX);
  static_assertFailedAnswer(DNS_ANSWER_NOT_PUBLIC_NAME, &answer);
  TEST_ASSERT_FALSE(answer.m_hasNullMx);
}

void test_tryReadResponse_mx_priority_is_16_bits(void)
{
  static_startAnswer(WIRE_TYPE_MX, 1);
  static_putRecordHead(WIRE_TYPE_MX, WIRE_CLASS_IN, 6);
  static_put16(0xFF01);
  static_putBytes("\x02mx\x00", 4);
  DnsAnswer_t answer = static_readBuiltAnswer(&EXAMPLE_COM_MX);
  TEST_ASSERT_EQUAL_INT(DNS_ANSWER_OK, answer.m_status);
  TEST_ASSERT_EQUAL_INT(1, answer.m_recordCount);
  TEST_ASSERT_EQUAL_UINT16(65281, answer.mp_mxRecords[0].m_priority);
  dns_answerFree(&answer);
}

static int static_failEachAllocation(const unsigned char* message, size_t message_len, const DnsQuestion_t* question)
{
  g_failAllocationNumber = 0;
  g_allocationCount      = 0;
  DnsAnswer_t answer = static_readFixedAnswer(message, message_len, question);
  TEST_ASSERT_EQUAL_INT(DNS_ANSWER_OK, answer.m_status);
  dns_answerFree(&answer);
  int allocation_count = g_allocationCount;

  for (int n = 1; n <= allocation_count; n++)
  {
    g_failAllocationNumber = n;
    g_allocationCount      = 0;
    answer = static_readFixedAnswer(message, message_len, question);
    static_assertFailedAnswer(DNS_ANSWER_NO_MEMORY, &answer);
  }
  g_failAllocationNumber = 0;
  return allocation_count;
}

void test_tryReadResponse_each_failed_allocation_is_no_memory(void)
{
  TEST_ASSERT_EQUAL_INT(3, static_failEachAllocation(ORACLE_MX, sizeof(ORACLE_MX), &EXAMPLE_COM_MX));
  TEST_ASSERT_EQUAL_INT(3, static_failEachAllocation(ORACLE_TXT, sizeof(ORACLE_TXT), &EXAMPLE_COM_TXT));
  TEST_ASSERT_EQUAL_INT(3, static_failEachAllocation(ORACLE_SOA, sizeof(ORACLE_SOA), &EXAMPLE_COM_SOA));
  TEST_ASSERT_EQUAL_INT(3, static_failEachAllocation(ORACLE_A_AFTER_CNAME, sizeof(ORACLE_A_AFTER_CNAME), &EXAMPLE_COM_A));
  TEST_ASSERT_EQUAL_INT(7, static_failEachAllocation(ORACLE_CAA, sizeof(ORACLE_CAA), &EXAMPLE_COM_CAA));
}

#define FAKE_FD_BASE         1000
#define FAKE_SOCKET_MAX      64
#define FAKE_DELIVERY_MAX    64
#define FAKE_SENT_MAX        128
#define FAKE_QUERY_MAX_SIZE  600
#define FAKE_NAMESERVER_MAX  3

#define FAKE_START_MS 5000000

#define FAKE_POLL_LIMIT 1000

typedef struct {
  bool           m_isOpen;
  int            m_domain;
  int            m_type;
  int            m_nameserverIndex;
  bool           m_isRefused;
  unsigned char  ma_received[FAKE_QUERY_MAX_SIZE];
  size_t         m_receivedLen;
  unsigned char* mp_stream;
  size_t         m_streamLen;
  size_t         m_streamReadLen;
  bool           m_isStreamClosed;
} FakeSocket_t;

typedef struct {
  int            m_fd;
  int64_t        m_atMs;
  unsigned char* mp_bytes;
  size_t         m_len;
  bool           m_isTaken;
  bool           m_closesStream;
} FakeDelivery_t;

typedef struct {
  int           m_nameserverIndex;
  bool          m_isTcp;
  int64_t       m_atMs;
  unsigned char ma_query[FAKE_QUERY_MAX_SIZE];
  size_t        m_queryLen;
  int           m_fd;
} FakeSentQuery_t;

typedef void (*FakeAnswerer_t)(const FakeSentQuery_t* sent);

static FakeSocket_t     g_sockets[FAKE_SOCKET_MAX];
static int              g_socketCount = 0;
static FakeDelivery_t   g_deliveries[FAKE_DELIVERY_MAX];
static int              g_deliveryCount = 0;
static FakeSentQuery_t  g_sentQueries[FAKE_SENT_MAX];
static int              g_sentCount = 0;
static FakeAnswerer_t   g_answerer = NULL;
static int64_t          g_nowMs = FAKE_START_MS;
static int              g_pollCount = 0;
static int              g_pollTimeouts[FAKE_POLL_LIMIT];

static struct sockaddr_in  g_nameserverIpv4[FAKE_NAMESERVER_MAX];
static struct sockaddr_in6 g_nameserverIpv6[FAKE_NAMESERVER_MAX];
static bool                g_isNameserverIpv6[FAKE_NAMESERVER_MAX];
static int                 g_nameserverCount = 0;
static bool                g_isResolverInitFailing = false;
static int                 g_resolverCloseCount = 0;

static bool g_isUdpSocketFailing  = false;
static int  g_udpConnectFailingNs = -1;
static bool g_isTcpSocketFailing  = false;
static int  g_tcpRefusingNs       = -1;
static int  g_tcpTransferChunk    = 0;
static int  g_tcpConnectFailingNs = -1;

static int  g_tcpSendWouldBlockCount = 0;
static int  g_tcpRecvWouldBlockCount = 0;
static int  g_pollFailErrno          = 0;

int  __real_clock_gettime(clockid_t clock_id, struct timespec* time_out);
int  __real___res_ninit(res_state state);
void __real___res_nclose(res_state state);

static FakeSocket_t* static_fakeSocket(int fd)
{
  if (fd < FAKE_FD_BASE || fd >= FAKE_FD_BASE + g_socketCount)
    return NULL;
  return &g_sockets[fd - FAKE_FD_BASE];
}

int __wrap_clock_gettime(clockid_t clock_id, struct timespec* time_out)
{
  if (clock_id != CLOCK_MONOTONIC)
    return __real_clock_gettime(clock_id, time_out);
  time_out->tv_sec  = g_nowMs / 1000;
  time_out->tv_nsec = (long)(g_nowMs % 1000) * 1000000;
  return 0;
}

int __wrap___res_ninit(res_state state)
{
  if (g_isResolverInitFailing)
    return -1;
  int result = __real___res_ninit(state);
  if (result != 0)
    return result;

  state->options |= RES_TRUSTAD;

  for (int i = 0; i < MAXNS; i++)
  {
    free(state->_u._ext.nsaddrs[i]);
    state->_u._ext.nsaddrs[i] = NULL;
  }
  state->nscount = g_nameserverCount;
  for (int i = 0; i < g_nameserverCount; i++)
  {
    if (g_isNameserverIpv6[i])
    {
      state->nsaddr_list[i].sin_family = 0;
      state->_u._ext.nsaddrs[i]        = &g_nameserverIpv6[i];
    }
    else
      state->nsaddr_list[i] = g_nameserverIpv4[i];
  }
  return 0;
}

void __wrap___res_nclose(res_state state)
{
  g_resolverCloseCount++;
  for (int i = 0; i < MAXNS; i++)
    if (state->_u._ext.nsaddrs[i] == &g_nameserverIpv6[i])
      state->_u._ext.nsaddrs[i] = NULL;
  __real___res_nclose(state);
}

int __wrap_socket(int domain, int type, int protocol)
{
  (void)protocol;
  int base_type = type & ~(SOCK_NONBLOCK | SOCK_CLOEXEC);
  TEST_ASSERT_TRUE_MESSAGE((type & SOCK_NONBLOCK) != 0, "socket must be non-blocking");
  if ((base_type == SOCK_DGRAM && g_isUdpSocketFailing) || (base_type == SOCK_STREAM && g_isTcpSocketFailing))
  {
    errno = EMFILE;
    return -1;
  }
  TEST_ASSERT_TRUE(g_socketCount < FAKE_SOCKET_MAX);
  FakeSocket_t* fake = &g_sockets[g_socketCount];
  memset(fake, 0, sizeof(*fake));
  fake->m_isOpen          = true;
  fake->m_type            = base_type;
  fake->m_nameserverIndex = -1;
  fake->m_domain          = domain;
  return FAKE_FD_BASE + g_socketCount++;
}

static int static_nameserverIndexOf(const struct sockaddr* address, socklen_t address_len)
{
  for (int i = 0; i < g_nameserverCount; i++)
  {
    if (g_isNameserverIpv6[i] && address->sa_family == AF_INET6 && address_len == sizeof(struct sockaddr_in6)
        && memcmp(&((const struct sockaddr_in6*)address)->sin6_addr, &g_nameserverIpv6[i].sin6_addr, 16) == 0
        && ((const struct sockaddr_in6*)address)->sin6_port == g_nameserverIpv6[i].sin6_port)
      return i;
    if (!g_isNameserverIpv6[i] && address->sa_family == AF_INET && address_len == sizeof(struct sockaddr_in)
        && ((const struct sockaddr_in*)address)->sin_addr.s_addr == g_nameserverIpv4[i].sin_addr.s_addr
        && ((const struct sockaddr_in*)address)->sin_port == g_nameserverIpv4[i].sin_port)
      return i;
  }
  return -1;
}

int __wrap_connect(int fd, const struct sockaddr* address, socklen_t address_len)
{
  FakeSocket_t* fake = static_fakeSocket(fd);
  TEST_ASSERT_NOT_NULL(fake);
  TEST_ASSERT_EQUAL_INT_MESSAGE(fake->m_domain, address->sa_family, "connect to an address of another family");
  fake->m_nameserverIndex = static_nameserverIndexOf(address, address_len);
  TEST_ASSERT_TRUE_MESSAGE(fake->m_nameserverIndex >= 0, "connect to an address that is no name server");
  if (fake->m_type == SOCK_DGRAM)
  {
    if (fake->m_nameserverIndex == g_udpConnectFailingNs)
    {
      errno = ENETUNREACH;
      return -1;
    }
    return 0;
  }
  if (fake->m_nameserverIndex == g_tcpConnectFailingNs)
  {
    errno = ECONNREFUSED;
    return -1;
  }
  fake->m_isRefused = fake->m_nameserverIndex == g_tcpRefusingNs;
  errno = EINPROGRESS;
  return -1;
}

static void static_takeQuery(int fd, const FakeSocket_t* fake, const unsigned char* query, size_t query_len)
{
  TEST_ASSERT_TRUE(g_sentCount < FAKE_SENT_MAX);
  TEST_ASSERT_TRUE(query_len <= FAKE_QUERY_MAX_SIZE);
  FakeSentQuery_t* sent = &g_sentQueries[g_sentCount++];
  sent->m_nameserverIndex = fake->m_nameserverIndex;
  sent->m_isTcp           = fake->m_type == SOCK_STREAM;
  sent->m_atMs            = g_nowMs;
  sent->m_fd              = fd;
  memcpy(sent->ma_query, query, query_len);
  sent->m_queryLen        = query_len;
  if (g_answerer != NULL)
    g_answerer(sent);
}

ssize_t __wrap_send(int fd, const void* bytes, size_t byte_count, int flags)
{
  FakeSocket_t* fake = static_fakeSocket(fd);
  TEST_ASSERT_NOT_NULL(fake);
  TEST_ASSERT_TRUE_MESSAGE((flags & MSG_NOSIGNAL) != 0, "send must not raise SIGPIPE");
  if (fake->m_type == SOCK_DGRAM)
  {
    static_takeQuery(fd, fake, bytes, byte_count);
    return (ssize_t)byte_count;
  }
  if (fake->m_isRefused)
  {
    errno = ECONNREFUSED;
    return -1;
  }
  if (g_tcpSendWouldBlockCount > 0)
  {
    g_tcpSendWouldBlockCount--;
    errno = EAGAIN;
    return -1;
  }
  size_t taken = byte_count;
  if (g_tcpTransferChunk > 0 && taken > (size_t)g_tcpTransferChunk)
    taken = (size_t)g_tcpTransferChunk;
  TEST_ASSERT_TRUE(fake->m_receivedLen + taken <= FAKE_QUERY_MAX_SIZE);
  memcpy(fake->ma_received + fake->m_receivedLen, bytes, taken);
  fake->m_receivedLen += taken;
  if (fake->m_receivedLen >= 2 && fake->m_receivedLen == 2 + (size_t)((fake->ma_received[0] << 8) | fake->ma_received[1]))
    static_takeQuery(fd, fake, fake->ma_received + 2, fake->m_receivedLen - 2);
  return (ssize_t)taken;
}

static void static_deliverDueStreams(void)
{
  for (int d = 0; d < g_deliveryCount; d++)
  {
    FakeDelivery_t* delivery = &g_deliveries[d];
    FakeSocket_t*   fake     = static_fakeSocket(delivery->m_fd);
    if (delivery->m_isTaken || delivery->m_atMs > g_nowMs || fake->m_type != SOCK_STREAM)
      continue;
    fake->mp_stream = realloc(fake->mp_stream, fake->m_streamLen + delivery->m_len + 1);
    memcpy(fake->mp_stream + fake->m_streamLen, delivery->mp_bytes, delivery->m_len);
    fake->m_streamLen     += delivery->m_len;
    fake->m_isStreamClosed = fake->m_isStreamClosed || delivery->m_closesStream;
    delivery->m_isTaken    = true;
  }
}

ssize_t __wrap_recv(int fd, void* buffer, size_t buffer_size, int flags)
{
  FakeSocket_t* fake = static_fakeSocket(fd);
  TEST_ASSERT_NOT_NULL(fake);
  TEST_ASSERT_TRUE_MESSAGE((flags & MSG_DONTWAIT) != 0, "recv must not block");
  if (fake->m_type == SOCK_DGRAM)
  {
    for (int d = 0; d < g_deliveryCount; d++)
    {
      FakeDelivery_t* delivery = &g_deliveries[d];
      if (delivery->m_fd != fd || delivery->m_isTaken || delivery->m_atMs > g_nowMs)
        continue;
      delivery->m_isTaken = true;
      size_t copied = delivery->m_len < buffer_size ? delivery->m_len : buffer_size;
      memcpy(buffer, delivery->mp_bytes, copied);
      return (ssize_t)((flags & MSG_TRUNC) != 0 ? delivery->m_len : copied);
    }
    errno = EAGAIN;
    return -1;
  }

  static_deliverDueStreams();
  if (g_tcpRecvWouldBlockCount > 0)
  {
    g_tcpRecvWouldBlockCount--;
    errno = EAGAIN;
    return -1;
  }
  size_t available = fake->m_streamLen - fake->m_streamReadLen;
  if (available == 0)
  {
    if (fake->m_isStreamClosed)
      return 0;
    errno = EAGAIN;
    return -1;
  }
  size_t taken = available < buffer_size ? available : buffer_size;
  if (g_tcpTransferChunk > 0 && taken > (size_t)g_tcpTransferChunk)
    taken = (size_t)g_tcpTransferChunk;
  memcpy(buffer, fake->mp_stream + fake->m_streamReadLen, taken);
  fake->m_streamReadLen += taken;
  return (ssize_t)taken;
}

static int64_t static_readyAtMs(const struct pollfd* poll_fd)
{
  FakeSocket_t* fake = static_fakeSocket(poll_fd->fd);
  TEST_ASSERT_NOT_NULL(fake);
  if ((poll_fd->events & POLLOUT) != 0)
    return g_nowMs;

  int64_t ready_at = INT64_MAX;
  if (fake->m_type == SOCK_STREAM && (fake->m_streamReadLen < fake->m_streamLen || fake->m_isStreamClosed))
    ready_at = g_nowMs;
  for (int d = 0; d < g_deliveryCount; d++)
    if (g_deliveries[d].m_fd == poll_fd->fd && !g_deliveries[d].m_isTaken && g_deliveries[d].m_atMs < ready_at)
      ready_at = g_deliveries[d].m_atMs < g_nowMs ? g_nowMs : g_deliveries[d].m_atMs;
  return ready_at;
}

int __wrap_poll(struct pollfd* poll_fds, nfds_t poll_fd_count, int timeout_ms)
{
  TEST_ASSERT_TRUE_MESSAGE(g_pollCount < FAKE_POLL_LIMIT, "the poll loop does not end");
  TEST_ASSERT_TRUE(timeout_ms >= 0);
  g_pollTimeouts[g_pollCount++] = timeout_ms;
  if (g_pollFailErrno != 0)
  {
    errno           = g_pollFailErrno;
    g_pollFailErrno = 0;
    return -1;
  }

  int64_t first_ready_at = INT64_MAX;
  for (nfds_t f = 0; f < poll_fd_count; f++)
  {
    int64_t ready_at = static_readyAtMs(&poll_fds[f]);
    if (ready_at < first_ready_at)
      first_ready_at = ready_at;
  }
  if (first_ready_at > g_nowMs + timeout_ms)
  {
    g_nowMs += timeout_ms;
    for (nfds_t f = 0; f < poll_fd_count; f++)
      poll_fds[f].revents = 0;
    return 0;
  }

  g_nowMs = first_ready_at;
  int ready_count = 0;
  for (nfds_t f = 0; f < poll_fd_count; f++)
  {
    bool is_ready = static_readyAtMs(&poll_fds[f]) <= g_nowMs;
    poll_fds[f].revents = is_ready ? poll_fds[f].events : 0;
    ready_count += is_ready ? 1 : 0;
  }
  return ready_count;
}

int __wrap___poll_chk(struct pollfd* poll_fds, nfds_t poll_fd_count, int timeout_ms, size_t poll_fds_size)
{
  TEST_ASSERT_TRUE(poll_fd_count * sizeof(struct pollfd) <= poll_fds_size);
  return __wrap_poll(poll_fds, poll_fd_count, timeout_ms);
}

ssize_t __wrap___recv_chk(int fd, void* buffer, size_t buffer_size, size_t buffer_object_size, int flags)
{
  TEST_ASSERT_TRUE(buffer_size <= buffer_object_size);
  return __wrap_recv(fd, buffer, buffer_size, flags);
}

int __wrap_close(int fd)
{
  FakeSocket_t* fake = static_fakeSocket(fd);
  TEST_ASSERT_NOT_NULL_MESSAGE(fake, "close of a descriptor that is no fake socket");
  TEST_ASSERT_TRUE_MESSAGE(fake->m_isOpen, "a fake socket is closed twice");
  fake->m_isOpen = false;
  return 0;
}

static void static_resetFakeNetwork(void)
{
  for (int i = 0; i < g_socketCount; i++)
    free(g_sockets[i].mp_stream);
  for (int d = 0; d < g_deliveryCount; d++)
    free(g_deliveries[d].mp_bytes);
  g_socketCount = g_deliveryCount = g_sentCount = g_pollCount = 0;
  g_answerer = NULL;
  g_nowMs    = FAKE_START_MS;
  g_isResolverInitFailing = g_isUdpSocketFailing = g_isTcpSocketFailing = false;
  g_udpConnectFailingNs = g_tcpRefusingNs = g_tcpConnectFailingNs = -1;
  g_tcpTransferChunk   = 0;
  g_tcpSendWouldBlockCount = g_tcpRecvWouldBlockCount = 0;
  g_pollFailErrno      = 0;
  g_resolverCloseCount = 0;

  g_nameserverCount = 2;
  for (int i = 0; i < FAKE_NAMESERVER_MAX; i++)
  {
    g_isNameserverIpv6[i] = false;
    memset(&g_nameserverIpv4[i], 0, sizeof(g_nameserverIpv4[i]));
    g_nameserverIpv4[i].sin_family      = AF_INET;
    g_nameserverIpv4[i].sin_port        = htons(53);
    g_nameserverIpv4[i].sin_addr.s_addr = htonl(0xC0000235u + (uint32_t)i);
    memset(&g_nameserverIpv6[i], 0, sizeof(g_nameserverIpv6[i]));
    g_nameserverIpv6[i].sin6_family = AF_INET6;
    g_nameserverIpv6[i].sin6_port   = htons(53);
    inet_pton(AF_INET6, "2001:db8::53", &g_nameserverIpv6[i].sin6_addr);
    g_nameserverIpv6[i].sin6_addr.s6_addr[15] = (uint8_t)(0x53 + i);
  }
}

static void static_assertEverySocketClosed(void)
{
  for (int i = 0; i < g_socketCount; i++)
    TEST_ASSERT_FALSE_MESSAGE(g_sockets[i].m_isOpen, "a socket was left open");
}

static size_t static_questionLen(const unsigned char* query)
{
  size_t pos = DNS_TEST_HEADER_SIZE;
  while (query[pos] != 0)
    pos += 1 + query[pos];
  return pos + 1 + 4 - DNS_TEST_HEADER_SIZE;
}

static void static_startReplyTo(const unsigned char* query, uint8_t flags, uint8_t rcode, uint16_t answer_count)
{
  g_messageLen = 0;
  static_putBytes(query, 2);
  static_put8(flags);
  static_put8((uint8_t)(FLAGS_RA | rcode));
  static_put16(1);
  static_put16(answer_count);
  static_put16(0);
  static_put16(0);
  static_putBytes(query + DNS_TEST_HEADER_SIZE, static_questionLen(query));
}

static uint16_t static_queryType(const unsigned char* query)
{
  size_t type_at = DNS_TEST_HEADER_SIZE + static_questionLen(query) - 4;
  return (uint16_t)((query[type_at] << 8) | query[type_at + 1]);
}

static void static_queueReply(int fd, int64_t delay_ms, bool closes_stream)
{
  TEST_ASSERT_TRUE(g_deliveryCount < FAKE_DELIVERY_MAX);
  FakeSocket_t*   fake     = static_fakeSocket(fd);
  FakeDelivery_t* delivery = &g_deliveries[g_deliveryCount++];
  bool   is_tcp = fake->m_type == SOCK_STREAM;
  size_t len    = g_messageLen + (is_tcp ? 2 : 0);
  delivery->mp_bytes = __real_malloc(len);
  if (is_tcp)
  {
    delivery->mp_bytes[0] = (unsigned char)(g_messageLen >> 8);
    delivery->mp_bytes[1] = (unsigned char)g_messageLen;
  }
  memcpy(delivery->mp_bytes + (is_tcp ? 2 : 0), g_message, g_messageLen);
  delivery->m_fd          = fd;
  delivery->m_atMs        = g_nowMs + delay_ms;
  delivery->m_len         = len;
  delivery->m_isTaken     = false;
  delivery->m_closesStream = closes_stream;
}

static void static_queueStreamInTwoPieces(int fd, size_t first_len, size_t extra_len)
{
  static_queueReply(fd, 0, false);
  FakeDelivery_t* first     = &g_deliveries[g_deliveryCount - 1];
  size_t          whole_len = first->m_len;
  TEST_ASSERT_TRUE(first_len < whole_len && g_deliveryCount < FAKE_DELIVERY_MAX);
  FakeDelivery_t* second  = &g_deliveries[g_deliveryCount++];
  size_t          rest_len = whole_len - first_len;
  second->mp_bytes = __real_malloc(rest_len + extra_len);
  memcpy(second->mp_bytes, first->mp_bytes + first_len, rest_len);
  memset(second->mp_bytes + rest_len, 0xEE, extra_len);
  second->m_fd           = fd;
  second->m_atMs         = g_nowMs + 10;
  second->m_len          = rest_len + extra_len;
  second->m_isTaken      = false;
  second->m_closesStream = true;
  first->m_len           = first_len;
}

static void static_putOneRecordOf(uint16_t type)
{
  switch (type)
  {
    case WIRE_TYPE_A:
      static_putRecordHead(type, WIRE_CLASS_IN, 4);
      static_putBytes("\xc0\x00\x02\x01", 4);
      break;
    case WIRE_TYPE_AAAA:
      static_putRecordHead(type, WIRE_CLASS_IN, 16);
      static_putBytes("\x20\x01\x0d\xb8\0\0\0\0\0\0\0\0\0\0\0\x01", 16);
      break;
    case WIRE_TYPE_MX:
      static_putRecordHead(type, WIRE_CLASS_IN, 7);
      static_put16(10);
      static_put8(2);
      static_putBytes("mx", 2);
      static_put16(NAME_POINTER_TO_QUESTION);
      break;
    case WIRE_TYPE_PTR:
      static_putRecordHead(type, WIRE_CLASS_IN, 18);
      static_putName("host.example.net");
      break;
    default:
      static_putRecordHead(type, WIRE_CLASS_IN, 12);
      static_put8(11);
      static_putBytes("v=spf1 -all", 11);
      break;
  }
}

static void static_answerEachAtOnce(const FakeSentQuery_t* sent)
{
  static_startReplyTo(sent->ma_query, FLAGS_ANSWER, RCODE_NOERROR, 1);
  static_putOneRecordOf(static_queryType(sent->ma_query));
  static_queueReply(sent->m_fd, 0, sent->m_isTcp);
}

static const DnsQuestion_t LOOKUP_QUESTIONS[3] = {
  { "example.com", DNS_RECORD_TYPE_A },
  { "example.com", DNS_RECORD_TYPE_MX },
  { "example.com", DNS_RECORD_TYPE_TXT },
};

static const unsigned char OPT_RECORD[11] = { 0x00, 0x00, 0x29, 0x04, 0xD0, 0, 0, 0, 0, 0, 0 };

static void static_freeAnswers(DnsAnswer_t* answers, int answer_count)
{
  for (int i = 0; i < answer_count; i++)
    dns_answerFree(&answers[i]);
}

void test_askQuestions_sends_each_question_once_with_an_opt_record(void)
{
  static_resetFakeNetwork();
  g_answerer = static_answerEachAtOnce;
  DnsAnswer_t answers[3];
  dns_askQuestions(LOOKUP_QUESTIONS, 3, 5000, answers);

  TEST_ASSERT_EQUAL_INT(3, g_sentCount);
  static const uint16_t wire_types[3] = { WIRE_TYPE_A, WIRE_TYPE_MX, WIRE_TYPE_TXT };
  for (int i = 0; i < 3; i++)
  {
    const FakeSentQuery_t* sent = &g_sentQueries[i];
    TEST_ASSERT_EQUAL_INT(0, sent->m_nameserverIndex);
    TEST_ASSERT_FALSE(sent->m_isTcp);
    TEST_ASSERT_EQUAL_INT64(FAKE_START_MS, sent->m_atMs);
    TEST_ASSERT_EQUAL_HEX8(0x01, sent->ma_query[2]);
    TEST_ASSERT_EQUAL_HEX8(0x00, sent->ma_query[3]);
    TEST_ASSERT_EQUAL_HEX8_ARRAY("\x00\x01\x00\x00\x00\x00\x00\x01", sent->ma_query + 4, 8);
    TEST_ASSERT_EQUAL_UINT16(wire_types[i], static_queryType(sent->ma_query));
    TEST_ASSERT_EQUAL_MEMORY("\x07" "example" "\x03" "com" "\x00", sent->ma_query + DNS_TEST_HEADER_SIZE, 13);
    TEST_ASSERT_EQUAL_size_t(DNS_TEST_HEADER_SIZE + static_questionLen(sent->ma_query) + sizeof(OPT_RECORD), sent->m_queryLen);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(OPT_RECORD, sent->ma_query + sent->m_queryLen - sizeof(OPT_RECORD), sizeof(OPT_RECORD));
  }
  TEST_ASSERT_EQUAL_INT(1, g_resolverCloseCount);
  static_assertEverySocketClosed();
  static_freeAnswers(answers, 3);
}

void test_askQuestions_answers_each_question(void)
{
  static_resetFakeNetwork();
  g_answerer = static_answerEachAtOnce;
  DnsAnswer_t answers[3];
  dns_askQuestions(LOOKUP_QUESTIONS, 3, 5000, answers);

  TEST_ASSERT_EQUAL_INT(DNS_ANSWER_OK, answers[0].m_status);
  TEST_ASSERT_EQUAL_INT(1, answers[0].m_recordCount);
  static_assertText("192.0.2.1", 9, &answers[0].mp_texts[0]);
  TEST_ASSERT_EQUAL_INT(DNS_ANSWER_OK, answers[1].m_status);
  TEST_ASSERT_EQUAL_INT(1, answers[1].m_recordCount);
  TEST_ASSERT_EQUAL_UINT16(10, answers[1].mp_mxRecords[0].m_priority);
  TEST_ASSERT_EQUAL_STRING("mx.example.com", answers[1].mp_mxRecords[0].mp_hostname);
  TEST_ASSERT_EQUAL_INT(DNS_ANSWER_OK, answers[2].m_status);
  static_assertText("v=spf1 -all", 11, &answers[2].mp_texts[0]);
  TEST_ASSERT_EQUAL_INT64(FAKE_START_MS, g_nowMs);
  static_freeAnswers(answers, 3);
}

static void static_answerInReverse(const FakeSentQuery_t* sent)
{
  int index = (int)(sent - g_sentQueries);
  static_startReplyTo(sent->ma_query, FLAGS_ANSWER, RCODE_NOERROR, 1);
  static_putOneRecordOf(static_queryType(sent->ma_query));
  static_queueReply(sent->m_fd, (int64_t)(3 - index) * 10, false);
}

void test_askQuestions_answers_in_another_order(void)
{
  static_resetFakeNetwork();
  g_answerer = static_answerInReverse;
  DnsAnswer_t answers[3];
  dns_askQuestions(LOOKUP_QUESTIONS, 3, 5000, answers);
  for (int i = 0; i < 3; i++)
    TEST_ASSERT_EQUAL_INT(DNS_ANSWER_OK, answers[i].m_status);
  TEST_ASSERT_EQUAL_INT(3, g_sentCount);
  TEST_ASSERT_EQUAL_INT64(FAKE_START_MS + 30, g_nowMs);
  static_freeAnswers(answers, 3);
}

#define RCODE_NOTIMP 4

static uint8_t g_nameserverRcodes[FAKE_NAMESERVER_MAX];

static void static_answerByNameserver(const FakeSentQuery_t* sent)
{
  uint8_t rcode = g_nameserverRcodes[sent->m_nameserverIndex];
  static_startReplyTo(sent->ma_query, FLAGS_ANSWER, rcode, rcode == RCODE_NOERROR ? 1 : 0);
  if (rcode == RCODE_NOERROR)
    static_putOneRecordOf(static_queryType(sent->ma_query));
  static_queueReply(sent->m_fd, 0, false);
}

void test_askQuestions_server_failure_goes_to_the_next_nameserver(void)
{
  static const uint8_t moving_codes[] = { RCODE_SERVFAIL, RCODE_NOTIMP, RCODE_REFUSED };
  DnsAnswer_t answers[1];
  for (size_t i = 0; i < sizeof(moving_codes) / sizeof(moving_codes[0]); i++)
  {
    static_resetFakeNetwork();
    g_nameserverRcodes[0] = moving_codes[i];
    g_nameserverRcodes[1] = RCODE_NOERROR;
    g_answerer            = static_answerByNameserver;
    dns_askQuestions(LOOKUP_QUESTIONS, 1, 5000, answers);
    TEST_ASSERT_EQUAL_INT(DNS_ANSWER_OK, answers[0].m_status);
    TEST_ASSERT_EQUAL_INT(2, g_sentCount);
    TEST_ASSERT_EQUAL_INT(0, g_sentQueries[0].m_nameserverIndex);
    TEST_ASSERT_EQUAL_INT(1, g_sentQueries[1].m_nameserverIndex);
    TEST_ASSERT_EQUAL_INT64(FAKE_START_MS, g_nowMs);
    static_assertEverySocketClosed();
    static_freeAnswers(answers, 1);
  }

  static_resetFakeNetwork();
  g_nameserverRcodes[0] = RCODE_SERVFAIL;
  g_nameserverRcodes[1] = RCODE_SERVFAIL;
  g_answerer            = static_answerByNameserver;
  dns_askQuestions(LOOKUP_QUESTIONS, 1, 5000, answers);
  static_assertFailedAnswer(DNS_ANSWER_SERVER_ERROR, &answers[0]);
  TEST_ASSERT_EQUAL_INT(2, g_sentCount);

  static_resetFakeNetwork();
  g_nameserverRcodes[0] = RCODE_FORMERR;
  g_nameserverRcodes[1] = RCODE_NOERROR;
  g_answerer            = static_answerByNameserver;
  dns_askQuestions(LOOKUP_QUESTIONS, 1, 5000, answers);
  static_assertFailedAnswer(DNS_ANSWER_SERVER_ERROR, &answers[0]);
  TEST_ASSERT_EQUAL_INT(1, g_sentCount);
}

static int     g_answeringNs   = 0;
static int64_t g_answerDelayMs = 0;

static void static_answerFromOneNs(const FakeSentQuery_t* sent)
{
  if (sent->m_nameserverIndex != g_answeringNs)
    return;
  static_startReplyTo(sent->ma_query, FLAGS_ANSWER, RCODE_NOERROR, 1);
  static_putOneRecordOf(static_queryType(sent->ma_query));
  static_queueReply(sent->m_fd, g_answerDelayMs, sent->m_isTcp);
}

void test_askQuestions_resends_to_the_next_nameserver(void)
{
  static_resetFakeNetwork();
  g_answeringNs   = 1;
  g_answerDelayMs = 0;
  g_answerer      = static_answerFromOneNs;
  DnsAnswer_t answers[1];
  dns_askQuestions(LOOKUP_QUESTIONS, 1, 5000, answers);

  TEST_ASSERT_EQUAL_INT(2, g_sentCount);
  TEST_ASSERT_EQUAL_INT(0, g_sentQueries[0].m_nameserverIndex);
  TEST_ASSERT_EQUAL_INT64(FAKE_START_MS, g_sentQueries[0].m_atMs);
  TEST_ASSERT_EQUAL_INT(1, g_sentQueries[1].m_nameserverIndex);
  TEST_ASSERT_EQUAL_INT64(FAKE_START_MS + DNS_RETRANSMIT_MS, g_sentQueries[1].m_atMs);
  TEST_ASSERT_EQUAL_MEMORY(g_sentQueries[0].ma_query, g_sentQueries[1].ma_query, g_sentQueries[0].m_queryLen);
  TEST_ASSERT_EQUAL_INT(DNS_RETRANSMIT_MS, g_pollTimeouts[0]);
  TEST_ASSERT_EQUAL_INT(2, g_pollCount);
  TEST_ASSERT_EQUAL_INT(DNS_ANSWER_OK, answers[0].m_status);
  static_assertText("192.0.2.1", 9, &answers[0].mp_texts[0]);
  static_assertEverySocketClosed();
  static_freeAnswers(answers, 1);
}

void test_askQuestions_circles_the_nameservers_until_the_deadline(void)
{
  static_resetFakeNetwork();
  g_nameserverCount = 3;
  DnsAnswer_t answers[1];
  dns_askQuestions(LOOKUP_QUESTIONS, 1, 3500, answers);

  static const int expected_ns[4] = { 0, 1, 2, 0 };
  TEST_ASSERT_EQUAL_INT(4, g_sentCount);
  for (int i = 0; i < 4; i++)
  {
    TEST_ASSERT_EQUAL_INT(expected_ns[i], g_sentQueries[i].m_nameserverIndex);
    TEST_ASSERT_EQUAL_INT64(FAKE_START_MS + i * DNS_RETRANSMIT_MS, g_sentQueries[i].m_atMs);
  }
  static_assertFailedAnswer(DNS_ANSWER_TIMEOUT, &answers[0]);
  TEST_ASSERT_EQUAL_INT64(FAKE_START_MS + 3500, g_nowMs);
  static_assertEverySocketClosed();
}

void test_askQuestions_deadline_edge(void)
{
  static_resetFakeNetwork();
  g_answeringNs   = 0;
  g_answerDelayMs = 900;
  g_answerer      = static_answerFromOneNs;
  DnsAnswer_t answers[1];
  dns_askQuestions(LOOKUP_QUESTIONS, 1, 900, answers);
  TEST_ASSERT_EQUAL_INT(DNS_ANSWER_OK, answers[0].m_status);
  static_freeAnswers(answers, 1);

  static_resetFakeNetwork();
  g_answeringNs   = 0;
  g_answerDelayMs = 901;
  g_answerer      = static_answerFromOneNs;
  dns_askQuestions(LOOKUP_QUESTIONS, 1, 900, answers);
  static_assertFailedAnswer(DNS_ANSWER_TIMEOUT, &answers[0]);
  TEST_ASSERT_EQUAL_INT64(FAKE_START_MS + 900, g_nowMs);
  static_assertEverySocketClosed();
}

static void static_answerAfterTwoStrays(const FakeSentQuery_t* sent)
{
  unsigned char other_id_query[FAKE_QUERY_MAX_SIZE];
  memcpy(other_id_query, sent->ma_query, sent->m_queryLen);
  other_id_query[1] ^= 0x01;
  static_startReplyTo(other_id_query, FLAGS_ANSWER, RCODE_NXDOMAIN, 0);
  static_queueReply(sent->m_fd, 10, false);

  static_startReplyTo(sent->ma_query, FLAGS_ANSWER, RCODE_NXDOMAIN, 0);
  g_message[g_messageLen - 3] = WIRE_TYPE_AAAA;
  static_queueReply(sent->m_fd, 20, false);

  static_startReplyTo(sent->ma_query, FLAGS_ANSWER, RCODE_NOERROR, 1);
  static_putOneRecordOf(WIRE_TYPE_A);
  static_queueReply(sent->m_fd, 30, false);
}

void test_askQuestions_drops_replies_that_answer_something_else(void)
{
  static_resetFakeNetwork();
  g_answerer = static_answerAfterTwoStrays;
  DnsAnswer_t answers[1];
  dns_askQuestions(LOOKUP_QUESTIONS, 1, 5000, answers);
  TEST_ASSERT_EQUAL_INT(DNS_ANSWER_OK, answers[0].m_status);
  static_assertText("192.0.2.1", 9, &answers[0].mp_texts[0]);
  TEST_ASSERT_EQUAL_INT64(FAKE_START_MS + 30, g_nowMs);
  static_freeAnswers(answers, 1);
}

static size_t g_txtDataLen = 0;

static void static_putTxtReplyOfSize(const unsigned char* query, uint8_t flags)
{
  static_startReplyTo(query, flags, RCODE_NOERROR, 1);
  static_putRecordHead(WIRE_TYPE_TXT, WIRE_CLASS_IN, (uint16_t)g_txtDataLen);
  size_t left = g_txtDataLen;
  while (left > 0)
  {
    size_t string_len = left - 1 > 255 ? 255 : left - 1;
    static_put8((uint8_t)string_len);
    for (size_t i = 0; i < string_len; i++)
      static_put8('a');
    left -= 1 + string_len;
  }
}

static void static_answerSizedThenShort(const FakeSentQuery_t* sent)
{
  static_putTxtReplyOfSize(sent->ma_query, FLAGS_ANSWER);
  static_queueReply(sent->m_fd, 0, false);
  static_startReplyTo(sent->ma_query, FLAGS_ANSWER, RCODE_NOERROR, 1);
  static_putOneRecordOf(WIRE_TYPE_TXT);
  static_queueReply(sent->m_fd, 10, false);
}

void test_askQuestions_udp_payload_size_edge(void)
{
  static const DnsQuestion_t txt_question[1] = { { "example.com", DNS_RECORD_TYPE_TXT } };
  size_t fixed_len = DNS_TEST_HEADER_SIZE + 17 + 12;

  static_resetFakeNetwork();
  g_txtDataLen = DNS_UDP_PAYLOAD_SIZE - fixed_len;
  g_answerer   = static_answerSizedThenShort;
  DnsAnswer_t answers[1];
  dns_askQuestions(txt_question, 1, 5000, answers);
  TEST_ASSERT_EQUAL_INT(DNS_ANSWER_OK, answers[0].m_status);
  TEST_ASSERT_EQUAL_size_t(g_txtDataLen - 5, answers[0].mp_texts[0].m_byteCount);
  static_freeAnswers(answers, 1);

  static_resetFakeNetwork();
  g_txtDataLen = DNS_UDP_PAYLOAD_SIZE + 1 - fixed_len;
  g_answerer   = static_answerSizedThenShort;
  dns_askQuestions(txt_question, 1, 5000, answers);
  TEST_ASSERT_EQUAL_INT(DNS_ANSWER_OK, answers[0].m_status);
  static_assertText("v=spf1 -all", 11, &answers[0].mp_texts[0]);
  static_freeAnswers(answers, 1);
}

static void static_answerTruncatedThenTcp(const FakeSentQuery_t* sent)
{
  if (!sent->m_isTcp)
  {
    if (sent->m_nameserverIndex != g_answeringNs)
      return;
    static_startReplyTo(sent->ma_query, FLAGS_ANSWER | FLAG_TC, RCODE_NOERROR, 0);
    static_queueReply(sent->m_fd, 0, false);
    return;
  }
  static_putTxtReplyOfSize(sent->ma_query, FLAGS_ANSWER);
  static_queueReply(sent->m_fd, g_answerDelayMs, true);
}

void test_askQuestions_truncated_answer_is_asked_again_over_tcp(void)
{
  static const DnsQuestion_t txt_question[1] = { { "example.com", DNS_RECORD_TYPE_TXT } };
  static_resetFakeNetwork();
  g_answeringNs   = 1;
  g_answerDelayMs = 0;
  g_txtDataLen    = 3000;
  g_answerer      = static_answerTruncatedThenTcp;
  DnsAnswer_t answers[1];
  dns_askQuestions(txt_question, 1, 5000, answers);

  TEST_ASSERT_EQUAL_INT(DNS_ANSWER_OK, answers[0].m_status);
  TEST_ASSERT_EQUAL_size_t(3000 - 12, answers[0].mp_texts[0].m_byteCount);
  TEST_ASSERT_EQUAL_INT(3, g_sentCount);
  TEST_ASSERT_TRUE(g_sentQueries[2].m_isTcp);
  TEST_ASSERT_EQUAL_INT(1, g_sentQueries[2].m_nameserverIndex);
  TEST_ASSERT_EQUAL_size_t(g_sentQueries[1].m_queryLen, g_sentQueries[2].m_queryLen);
  TEST_ASSERT_EQUAL_MEMORY(g_sentQueries[1].ma_query, g_sentQueries[2].ma_query, g_sentQueries[1].m_queryLen);
  static_assertEverySocketClosed();
  static_freeAnswers(answers, 1);
}

void test_askQuestions_tcp_moves_in_small_pieces(void)
{
  static const DnsQuestion_t txt_question[1] = { { "example.com", DNS_RECORD_TYPE_TXT } };
  static const int chunks[] = { 1, 5 };
  for (size_t i = 0; i < sizeof(chunks) / sizeof(chunks[0]); i++)
  {
    static_resetFakeNetwork();
    g_answeringNs      = 0;
    g_answerDelayMs    = 0;
    g_txtDataLen       = 300;
    g_tcpTransferChunk = chunks[i];
    g_answerer         = static_answerTruncatedThenTcp;
    DnsAnswer_t answers[1];
    dns_askQuestions(txt_question, 1, 5000, answers);
    TEST_ASSERT_EQUAL_INT(DNS_ANSWER_OK, answers[0].m_status);
    TEST_ASSERT_EQUAL_size_t(300 - 2, answers[0].mp_texts[0].m_byteCount);
    TEST_ASSERT_EQUAL_size_t(42, g_sockets[g_socketCount - 1].m_receivedLen);
    static_assertEverySocketClosed();
    static_freeAnswers(answers, 1);
  }
}

void test_askQuestions_tcp_send_and_read_that_would_block_are_tried_again(void)
{
  static const DnsQuestion_t txt_question[1] = { { "example.com", DNS_RECORD_TYPE_TXT } };
  static_resetFakeNetwork();
  g_answeringNs            = 0;
  g_answerDelayMs          = 0;
  g_txtDataLen             = 300;
  g_tcpSendWouldBlockCount = 2;
  g_tcpRecvWouldBlockCount = 2;
  g_answerer               = static_answerTruncatedThenTcp;
  DnsAnswer_t answers[1];
  dns_askQuestions(txt_question, 1, 5000, answers);
  TEST_ASSERT_EQUAL_INT(DNS_ANSWER_OK, answers[0].m_status);
  TEST_ASSERT_EQUAL_INT(0, g_tcpSendWouldBlockCount);
  TEST_ASSERT_EQUAL_INT(0, g_tcpRecvWouldBlockCount);
  static_assertEverySocketClosed();
  static_freeAnswers(answers, 1);
}

static size_t g_firstPieceLen = 1;
static size_t g_extraLen      = 0;

static void static_answerTcpInPieces(const FakeSentQuery_t* sent)
{
  if (!sent->m_isTcp)
  {
    static_startReplyTo(sent->ma_query, FLAGS_ANSWER | FLAG_TC, RCODE_NOERROR, 0);
    static_queueReply(sent->m_fd, 0, false);
    return;
  }
  static_startReplyTo(sent->ma_query, FLAGS_ANSWER, RCODE_NOERROR, 1);
  static_putOneRecordOf(WIRE_TYPE_TXT);
  static_queueStreamInTwoPieces(sent->m_fd, g_firstPieceLen, g_extraLen);
}

void test_askQuestions_tcp_answer_in_two_pieces(void)
{
  static const DnsQuestion_t txt_question[1] = { { "example.com", DNS_RECORD_TYPE_TXT } };
  static const struct { size_t m_firstLen; size_t m_extraLen; } cases[] = { { 1, 0 }, { 12, 7 } };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    static_resetFakeNetwork();
    g_firstPieceLen = cases[i].m_firstLen;
    g_extraLen      = cases[i].m_extraLen;
    g_answerer      = static_answerTcpInPieces;
    DnsAnswer_t answers[1];
    dns_askQuestions(txt_question, 1, 5000, answers);
    TEST_ASSERT_EQUAL_INT(DNS_ANSWER_OK, answers[0].m_status);
    static_assertText("v=spf1 -all", 11, &answers[0].mp_texts[0]);
    const FakeSocket_t* tcp = &g_sockets[g_socketCount - 1];
    TEST_ASSERT_EQUAL_size_t(tcp->m_streamLen - cases[i].m_extraLen, tcp->m_streamReadLen);
    static_assertEverySocketClosed();
    static_freeAnswers(answers, 1);
  }
}

static void static_answerTruncatedTwiceThenTcp(const FakeSentQuery_t* sent)
{
  if (!sent->m_isTcp)
  {
    static_startReplyTo(sent->ma_query, FLAGS_ANSWER | FLAG_TC, RCODE_NOERROR, 0);
    static_queueReply(sent->m_fd, 0, false);
    static_queueReply(sent->m_fd, 0, false);
    return;
  }
  static_startReplyTo(sent->ma_query, FLAGS_ANSWER, RCODE_NOERROR, 1);
  static_putOneRecordOf(WIRE_TYPE_TXT);
  static_queueReply(sent->m_fd, 0, true);
}

void test_askQuestions_second_truncated_answer_is_dropped(void)
{
  static const DnsQuestion_t txt_question[1] = { { "example.com", DNS_RECORD_TYPE_TXT } };
  static_resetFakeNetwork();
  g_answerer = static_answerTruncatedTwiceThenTcp;
  DnsAnswer_t answers[1];
  dns_askQuestions(txt_question, 1, 5000, answers);
  TEST_ASSERT_EQUAL_INT(DNS_ANSWER_OK, answers[0].m_status);
  TEST_ASSERT_EQUAL_INT(g_nameserverCount + 1, g_socketCount);
  TEST_ASSERT_EQUAL_INT(2, g_sentCount);
  static_assertEverySocketClosed();
  static_freeAnswers(answers, 1);
}

static void static_answerAOverUdpTxtOverTcp(const FakeSentQuery_t* sent)
{
  if (static_queryType(sent->ma_query) == WIRE_TYPE_A)
  {
    static_startReplyTo(sent->ma_query, FLAGS_ANSWER, RCODE_NOERROR, 1);
    static_putOneRecordOf(WIRE_TYPE_A);
    static_queueReply(sent->m_fd, 10, false);
    return;
  }
  if (!sent->m_isTcp)
  {
    static_startReplyTo(sent->ma_query, FLAGS_ANSWER | FLAG_TC, RCODE_NOERROR, 0);
    static_queueReply(sent->m_fd, 0, false);
    return;
  }
  static_putTxtReplyOfSize(sent->ma_query, FLAGS_ANSWER);
  static_queueReply(sent->m_fd, 20, true);
}

void test_askQuestions_tcp_question_beside_a_udp_question(void)
{
  static const DnsQuestion_t questions[2] = { { "example.com", DNS_RECORD_TYPE_A }, { "example.com", DNS_RECORD_TYPE_TXT } };
  static_resetFakeNetwork();
  g_txtDataLen = 300;
  g_answerer   = static_answerAOverUdpTxtOverTcp;
  DnsAnswer_t answers[2];
  dns_askQuestions(questions, 2, 5000, answers);
  TEST_ASSERT_EQUAL_INT(DNS_ANSWER_OK, answers[0].m_status);
  static_assertText("192.0.2.1", 9, &answers[0].mp_texts[0]);
  TEST_ASSERT_EQUAL_INT(DNS_ANSWER_OK, answers[1].m_status);
  TEST_ASSERT_EQUAL_size_t(300 - 2, answers[1].mp_texts[0].m_byteCount);
  TEST_ASSERT_EQUAL_INT(3, g_sentCount);
  TEST_ASSERT_EQUAL_INT64(FAKE_START_MS + 20, g_nowMs);
  static_assertEverySocketClosed();
  static_freeAnswers(answers, 2);
}

void test_askQuestions_tcp_answer_after_the_deadline_times_out(void)
{
  static const DnsQuestion_t txt_question[1] = { { "example.com", DNS_RECORD_TYPE_TXT } };
  static_resetFakeNetwork();
  g_answeringNs   = 0;
  g_answerDelayMs = 2000;
  g_txtDataLen    = 300;
  g_answerer      = static_answerTruncatedThenTcp;
  DnsAnswer_t answers[1];
  dns_askQuestions(txt_question, 1, 1500, answers);
  static_assertFailedAnswer(DNS_ANSWER_TIMEOUT, &answers[0]);
  TEST_ASSERT_EQUAL_INT(2, g_sentCount);
  TEST_ASSERT_TRUE(g_sentQueries[1].m_isTcp);
  TEST_ASSERT_EQUAL_INT64(FAKE_START_MS + 1500, g_nowMs);
  static_assertEverySocketClosed();
}

typedef enum {
  TCP_REPLY_HALF_THEN_CLOSE,
  TCP_REPLY_EMPTY_LENGTH,
  TCP_REPLY_OTHER_ID,
  TCP_REPLY_TRUNCATED_AGAIN,
} TcpReplyKind_t;
static TcpReplyKind_t g_tcpReplyKind = TCP_REPLY_HALF_THEN_CLOSE;

static void static_answerTcpBadly(const FakeSentQuery_t* sent)
{
  if (!sent->m_isTcp)
  {
    static_startReplyTo(sent->ma_query, FLAGS_ANSWER | FLAG_TC, RCODE_NOERROR, 0);
    static_queueReply(sent->m_fd, 0, false);
    return;
  }
  switch (g_tcpReplyKind)
  {
    case TCP_REPLY_HALF_THEN_CLOSE:
      static_startReplyTo(sent->ma_query, FLAGS_ANSWER, RCODE_NOERROR, 1);
      static_putOneRecordOf(WIRE_TYPE_TXT);
      static_queueReply(sent->m_fd, 0, true);
      g_deliveries[g_deliveryCount - 1].m_len -= 5;
      break;
    case TCP_REPLY_EMPTY_LENGTH:
      g_messageLen = 0;
      static_queueReply(sent->m_fd, 0, true);
      break;
    case TCP_REPLY_OTHER_ID:
    {
      unsigned char other_id_query[FAKE_QUERY_MAX_SIZE];
      memcpy(other_id_query, sent->ma_query, sent->m_queryLen);
      other_id_query[0] ^= 0x80;
      static_startReplyTo(other_id_query, FLAGS_ANSWER, RCODE_NOERROR, 1);
      static_putOneRecordOf(WIRE_TYPE_TXT);
      static_queueReply(sent->m_fd, 0, true);
      break;
    }
    case TCP_REPLY_TRUNCATED_AGAIN:
      static_startReplyTo(sent->ma_query, FLAGS_ANSWER | FLAG_TC, RCODE_NOERROR, 0);
      static_queueReply(sent->m_fd, 0, true);
      break;
  }
}

void test_askQuestions_bad_tcp_answers(void)
{
  static const DnsQuestion_t txt_question[1] = { { "example.com", DNS_RECORD_TYPE_TXT } };
  static const struct {
    TcpReplyKind_t    m_kind;
    DnsAnswerStatus_t m_status;
  } cases[] = {
    { TCP_REPLY_HALF_THEN_CLOSE, DNS_ANSWER_TRUNCATED },
    { TCP_REPLY_EMPTY_LENGTH,    DNS_ANSWER_MALFORMED },
    { TCP_REPLY_OTHER_ID,        DNS_ANSWER_MALFORMED },
    { TCP_REPLY_TRUNCATED_AGAIN, DNS_ANSWER_TRUNCATED },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    static_resetFakeNetwork();
    g_tcpReplyKind = cases[i].m_kind;
    g_answerer     = static_answerTcpBadly;
    DnsAnswer_t answers[1];
    dns_askQuestions(txt_question, 1, 5000, answers);
    static_assertFailedAnswer(cases[i].m_status, &answers[0]);
    TEST_ASSERT_EQUAL_INT64(FAKE_START_MS, g_nowMs);
    static_assertEverySocketClosed();
  }
}

void test_askQuestions_tcp_that_cannot_connect_is_truncated(void)
{
  static const DnsQuestion_t txt_question[1] = { { "example.com", DNS_RECORD_TYPE_TXT } };
  DnsAnswer_t answers[1];

  static_resetFakeNetwork();
  g_tcpReplyKind = TCP_REPLY_TRUNCATED_AGAIN;
  g_tcpRefusingNs = 0;
  g_answerer     = static_answerTcpBadly;
  dns_askQuestions(txt_question, 1, 5000, answers);
  static_assertFailedAnswer(DNS_ANSWER_TRUNCATED, &answers[0]);
  TEST_ASSERT_EQUAL_INT(1, g_sentCount);
  static_assertEverySocketClosed();

  static_resetFakeNetwork();
  g_answeringNs         = 0;
  g_answerDelayMs       = 0;
  g_txtDataLen          = 300;
  g_tcpConnectFailingNs = 0;
  g_answerer            = static_answerTruncatedThenTcp;
  dns_askQuestions(txt_question, 1, 5000, answers);
  static_assertFailedAnswer(DNS_ANSWER_TRUNCATED, &answers[0]);
  TEST_ASSERT_EQUAL_INT(1, g_sentCount);
  static_assertEverySocketClosed();

  static_resetFakeNetwork();
  g_isTcpSocketFailing = true;
  g_answerer           = static_answerTcpBadly;
  dns_askQuestions(txt_question, 1, 5000, answers);
  static_assertFailedAnswer(DNS_ANSWER_TRUNCATED, &answers[0]);
  static_assertEverySocketClosed();
}

void test_askQuestions_tcp_buffer_allocation_failure(void)
{
  static const DnsQuestion_t txt_question[1] = { { "example.com", DNS_RECORD_TYPE_TXT } };
  static_resetFakeNetwork();
  g_answeringNs          = 0;
  g_answerDelayMs        = 0;
  g_txtDataLen           = 300;
  g_answerer             = static_answerTruncatedThenTcp;
  g_failAllocationNumber = 1;
  g_allocationCount      = 0;
  DnsAnswer_t answers[1];
  dns_askQuestions(txt_question, 1, 5000, answers);
  g_failAllocationNumber = 0;
  static_assertFailedAnswer(DNS_ANSWER_NO_MEMORY, &answers[0]);
  static_assertEverySocketClosed();
}

void test_askQuestions_without_a_nameserver_has_no_resolver(void)
{
  static_resetFakeNetwork();
  g_nameserverCount = 0;
  DnsAnswer_t answers[3];
  dns_askQuestions(LOOKUP_QUESTIONS, 3, 5000, answers);
  for (int i = 0; i < 3; i++)
    static_assertFailedAnswer(DNS_ANSWER_NO_RESOLVER, &answers[i]);
  TEST_ASSERT_EQUAL_INT(0, g_sentCount);
  TEST_ASSERT_EQUAL_INT(0, g_socketCount);
  TEST_ASSERT_EQUAL_INT(1, g_resolverCloseCount);
  TEST_ASSERT_EQUAL_INT64(FAKE_START_MS, g_nowMs);
}

void test_askQuestions_failed_resolver_init_has_no_resolver(void)
{
  static_resetFakeNetwork();
  g_isResolverInitFailing = true;
  DnsAnswer_t answers[3];
  dns_askQuestions(LOOKUP_QUESTIONS, 3, 5000, answers);
  for (int i = 0; i < 3; i++)
    static_assertFailedAnswer(DNS_ANSWER_NO_RESOLVER, &answers[i]);
  TEST_ASSERT_EQUAL_INT(0, g_resolverCloseCount);
  TEST_ASSERT_EQUAL_INT(0, g_socketCount);
}

void test_askQuestions_without_a_udp_socket_has_no_resolver(void)
{
  static_resetFakeNetwork();
  g_isUdpSocketFailing = true;
  DnsAnswer_t answers[1];
  dns_askQuestions(LOOKUP_QUESTIONS, 1, 5000, answers);
  static_assertFailedAnswer(DNS_ANSWER_NO_RESOLVER, &answers[0]);
  TEST_ASSERT_EQUAL_INT(0, g_sentCount);
}

void test_askQuestions_skips_a_nameserver_that_cannot_connect(void)
{
  static_resetFakeNetwork();
  g_udpConnectFailingNs = 0;
  g_answeringNs         = 1;
  g_answerDelayMs       = 0;
  g_answerer            = static_answerFromOneNs;
  DnsAnswer_t answers[1];
  dns_askQuestions(LOOKUP_QUESTIONS, 1, 5000, answers);
  TEST_ASSERT_EQUAL_INT(DNS_ANSWER_OK, answers[0].m_status);
  TEST_ASSERT_EQUAL_INT(1, g_sentCount);
  TEST_ASSERT_EQUAL_INT(1, g_sentQueries[0].m_nameserverIndex);
  static_assertEverySocketClosed();
  static_freeAnswers(answers, 1);
}

void test_askQuestions_poll_failure(void)
{
  DnsAnswer_t answers[3];
  static_resetFakeNetwork();
  g_pollFailErrno = EINTR;
  g_answerer      = static_answerEachAtOnce;
  dns_askQuestions(LOOKUP_QUESTIONS, 3, 5000, answers);
  for (int i = 0; i < 3; i++)
    TEST_ASSERT_EQUAL_INT(DNS_ANSWER_OK, answers[i].m_status);
  static_assertEverySocketClosed();
  static_freeAnswers(answers, 3);

  static_resetFakeNetwork();
  g_pollFailErrno = ENOMEM;
  g_answerer      = static_answerEachAtOnce;
  dns_askQuestions(LOOKUP_QUESTIONS, 3, 5000, answers);
  for (int i = 0; i < 3; i++)
    static_assertFailedAnswer(DNS_ANSWER_TIMEOUT, &answers[i]);
  TEST_ASSERT_EQUAL_INT(1, g_pollCount);
  TEST_ASSERT_EQUAL_INT64(FAKE_START_MS, g_nowMs);
  static_assertEverySocketClosed();
}

void test_askQuestions_asks_an_ipv6_nameserver(void)
{
  static_resetFakeNetwork();
  g_nameserverCount     = 1;
  g_isNameserverIpv6[0] = true;
  g_answerer            = static_answerEachAtOnce;
  DnsAnswer_t answers[1];
  dns_askQuestions(LOOKUP_QUESTIONS, 1, 5000, answers);
  TEST_ASSERT_EQUAL_INT(DNS_ANSWER_OK, answers[0].m_status);
  TEST_ASSERT_EQUAL_INT(0, g_sentQueries[0].m_nameserverIndex);
  static_assertEverySocketClosed();
  static_freeAnswers(answers, 1);
}

void test_askQuestions_bad_question_is_not_sent(void)
{
  static const DnsQuestion_t questions[2] = {
    { "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com", DNS_RECORD_TYPE_A },
    { "example.com", DNS_RECORD_TYPE_A },
  };
  static_resetFakeNetwork();
  g_answerer = static_answerEachAtOnce;
  DnsAnswer_t answers[2];
  dns_askQuestions(questions, 2, 5000, answers);
  static_assertFailedAnswer(DNS_ANSWER_BAD_QUESTION, &answers[0]);
  TEST_ASSERT_EQUAL_INT(DNS_ANSWER_OK, answers[1].m_status);
  TEST_ASSERT_EQUAL_INT(1, g_sentCount);
  static_freeAnswers(answers, 2);
}

void test_askQuestions_counts_each_question_once(void)
{
  static const DnsQuestion_t txt_question[1] = { { "example.com", DNS_RECORD_TYPE_TXT } };
  DnsAnswer_t answers[3];
  static_resetFakeNetwork();
  dns_resetQuestionCount();
  TEST_ASSERT_EQUAL_INT(0, dns_readQuestionCount());

  g_answerer = static_answerEachAtOnce;
  dns_askQuestions(LOOKUP_QUESTIONS, 3, 5000, answers);
  static_freeAnswers(answers, 3);
  TEST_ASSERT_EQUAL_INT(3, dns_readQuestionCount());

  static_resetFakeNetwork();
  g_answeringNs   = 1;
  g_answerDelayMs = 0;
  g_answerer      = static_answerFromOneNs;
  dns_askQuestions(LOOKUP_QUESTIONS, 1, 5000, answers);
  static_freeAnswers(answers, 1);
  TEST_ASSERT_EQUAL_INT(2, g_sentCount);
  TEST_ASSERT_EQUAL_INT(4, dns_readQuestionCount());

  static_resetFakeNetwork();
  g_answeringNs   = 1;
  g_answerDelayMs = 0;
  g_txtDataLen    = 3000;
  g_answerer      = static_answerTruncatedThenTcp;
  dns_askQuestions(txt_question, 1, 5000, answers);
  static_freeAnswers(answers, 1);
  TEST_ASSERT_EQUAL_INT(3, g_sentCount);
  TEST_ASSERT_EQUAL_INT(5, dns_readQuestionCount());

  static_resetFakeNetwork();
  g_isResolverInitFailing = true;
  dns_askQuestions(LOOKUP_QUESTIONS, 3, 5000, answers);
  static_freeAnswers(answers, 3);
  TEST_ASSERT_EQUAL_INT(8, dns_readQuestionCount());

  dns_resetQuestionCount();
  TEST_ASSERT_EQUAL_INT(0, dns_readQuestionCount());
}

typedef struct {
  int m_countAtStart;
  int m_countAfterAsking;
} ThreadQuestionCounts_t;

static void* static_askInAnotherThread(void* counts_out)
{
  ThreadQuestionCounts_t* counts = counts_out;
  DnsAnswer_t answers[3];
  counts->m_countAtStart = dns_readQuestionCount();
  dns_askQuestions(LOOKUP_QUESTIONS, 3, 5000, answers);
  static_freeAnswers(answers, 3);
  counts->m_countAfterAsking = dns_readQuestionCount();
  return NULL;
}

void test_askQuestions_question_count_is_kept_per_thread(void)
{
  DnsAnswer_t answers[1];
  static_resetFakeNetwork();
  g_isResolverInitFailing = true;
  dns_resetQuestionCount();
  dns_askQuestions(LOOKUP_QUESTIONS, 1, 5000, answers);
  static_freeAnswers(answers, 1);

  ThreadQuestionCounts_t counts = { -1, -1 };
  pthread_t thread;
  TEST_ASSERT_EQUAL_INT(0, pthread_create(&thread, NULL, static_askInAnotherThread, &counts));
  TEST_ASSERT_EQUAL_INT(0, pthread_join(thread, NULL));

  TEST_ASSERT_EQUAL_INT(0, counts.m_countAtStart);
  TEST_ASSERT_EQUAL_INT(3, counts.m_countAfterAsking);
  TEST_ASSERT_EQUAL_INT(1, dns_readQuestionCount());
}

static uint8_t g_lookupRcodes[DNS_LOOKUP_DOMAIN_RECORD_TYPE_COUNT];

static const char* g_lookupTxt[4];
static size_t      g_lookupTxtLen[4];
static int         g_lookupTxtCount = 0;

static void static_putTxtString(const char* text, size_t text_len)
{
  static_putRecordHead(WIRE_TYPE_TXT, WIRE_CLASS_IN, (uint16_t)(1 + text_len));
  static_put8((uint8_t)text_len);
  static_putBytes(text, text_len);
}

static void static_answerLookup(const FakeSentQuery_t* sent)
{
  uint16_t type  = static_queryType(sent->ma_query);
  int      index = -1;
  static const uint16_t wire_types[DNS_LOOKUP_DOMAIN_RECORD_TYPE_COUNT] = {
    WIRE_TYPE_A, WIRE_TYPE_AAAA, WIRE_TYPE_MX, WIRE_TYPE_NS, WIRE_TYPE_TXT, WIRE_TYPE_CNAME, WIRE_TYPE_SOA, WIRE_TYPE_CAA,
  };
  for (int t = 0; t < DNS_LOOKUP_DOMAIN_RECORD_TYPE_COUNT; t++)
    if (wire_types[t] == type)
      index = t;
  TEST_ASSERT_TRUE(index >= 0);

  uint8_t rcode = g_lookupRcodes[index];
  if (rcode != RCODE_NOERROR)
  {
    static_startReplyTo(sent->ma_query, FLAGS_ANSWER, rcode, 0);
    static_queueReply(sent->m_fd, 0, false);
    return;
  }
  if (type == WIRE_TYPE_A)
  {
    static_startReplyTo(sent->ma_query, FLAGS_ANSWER, RCODE_NOERROR, 2);
    static_putRecordHead(type, WIRE_CLASS_IN, 4);
    static_putBytes("\x0a\x00\x00\x01", 4);
    static_putRecordHead(type, WIRE_CLASS_IN, 4);
    static_putBytes("\x5d\xb8\xd7\x0e", 4);
  }
  else if (type == WIRE_TYPE_AAAA)
  {
    static_startReplyTo(sent->ma_query, FLAGS_ANSWER, RCODE_NOERROR, 2);
    static_putRecordHead(type, WIRE_CLASS_IN, 16);
    static_putBytes("\xfd\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01", 16);
    static_putRecordHead(type, WIRE_CLASS_IN, 16);
    static_putBytes("\x26\x06\x28\x00\x02\x1f\xcb\x07\0\0\0\0\0\0\0\x01", 16);
  }
  else if (type == WIRE_TYPE_TXT)
  {
    static_startReplyTo(sent->ma_query, FLAGS_ANSWER, RCODE_NOERROR, (uint16_t)g_lookupTxtCount);
    for (int i = 0; i < g_lookupTxtCount; i++)
      static_putTxtString(g_lookupTxt[i], g_lookupTxtLen[i]);
  }
  else if (type == WIRE_TYPE_SOA || type == WIRE_TYPE_CAA || type == WIRE_TYPE_CNAME || type == WIRE_TYPE_NS)
  {
    static_startReplyTo(sent->ma_query, FLAGS_ANSWER, RCODE_NOERROR, 0);
  }
  else
  {
    static_startReplyTo(sent->ma_query, FLAGS_ANSWER, RCODE_NOERROR, 1);
    static_putOneRecordOf(type);
  }
  static_queueReply(sent->m_fd, 0, false);
}

static void static_resetLookup(void)
{
  static_resetFakeNetwork();
  memset(g_lookupRcodes, 0, sizeof(g_lookupRcodes));
  g_lookupTxt[0]    = "v=spf1 -all";
  g_lookupTxtLen[0] = 11;
  g_lookupTxtCount  = 1;
  g_answerer        = static_answerLookup;
}

void test_lookupDomain_asks_each_type_of_the_lower_case_name(void)
{
  static_resetLookup();
  DNSLOOKUPRecord_t record;
  TEST_ASSERT_EQUAL_INT(DNS_LOOKUP_OK, dns_lookupDomain("Example.COM", &record));
  TEST_ASSERT_EQUAL_STRING("example.com", record.ma_domain);

  static const uint16_t wire_types[DNS_LOOKUP_DOMAIN_RECORD_TYPE_COUNT] = {
    WIRE_TYPE_A, WIRE_TYPE_AAAA, WIRE_TYPE_MX, WIRE_TYPE_NS, WIRE_TYPE_TXT, WIRE_TYPE_CNAME, WIRE_TYPE_SOA, WIRE_TYPE_CAA,
  };
  TEST_ASSERT_EQUAL_INT(DNS_LOOKUP_DOMAIN_RECORD_TYPE_COUNT, g_sentCount);
  for (int t = 0; t < DNS_LOOKUP_DOMAIN_RECORD_TYPE_COUNT; t++)
  {
    TEST_ASSERT_EQUAL_UINT16(wire_types[t], static_queryType(g_sentQueries[t].ma_query));
    TEST_ASSERT_EQUAL_MEMORY("\x07" "example" "\x03" "com" "\x00", g_sentQueries[t].ma_query + DNS_TEST_HEADER_SIZE, 13);
    TEST_ASSERT_EQUAL_INT64(FAKE_START_MS, g_sentQueries[t].m_atMs);
    TEST_ASSERT_EQUAL_INT(DNS_ANSWER_OK, record.ma_answers[t].m_status);
  }
  TEST_ASSERT_EQUAL_INT(2, record.ma_answers[DNS_RECORD_TYPE_A].m_recordCount);
  TEST_ASSERT_EQUAL_INT(1, record.ma_answers[DNS_RECORD_TYPE_MX].m_recordCount);
  dns_DNSLOOKUPRecordFree(&record);
  static_assertEverySocketClosed();
}

void test_lookupDomain_waits_until_one_deadline(void)
{
  static_resetLookup();
  g_answerer = NULL;
  DNSLOOKUPRecord_t record;
  TEST_ASSERT_EQUAL_INT(DNS_LOOKUP_NO_ANSWER, dns_lookupDomain("example.com", &record));
  TEST_ASSERT_EQUAL_INT64(FAKE_START_MS + DNS_LOOKUP_DEADLINE_MS, g_nowMs);
  dns_DNSLOOKUPRecordFree(&record);
  static_assertEverySocketClosed();
}

void test_lookupDomain_status_from_the_answers(void)
{
  static const struct {
    const char*       mp_name;
    uint8_t           ma_rcodes[DNS_LOOKUP_DOMAIN_RECORD_TYPE_COUNT];
    DnsLookupStatus_t m_status;
  } cases[] = {
    { "only CAA answered",           { 3, 3, 3, 3, 3, 3, 3, 0 }, DNS_LOOKUP_OK },
    { "every type NXDOMAIN",         { 3, 3, 3, 3, 3, 3, 3, 3 }, DNS_LOOKUP_NOT_FOUND },
    { "one NXDOMAIN, the rest fail", { 2, 2, 2, 2, 2, 2, 2, 3 }, DNS_LOOKUP_NOT_FOUND },
    { "every type SERVFAIL",         { 2, 2, 2, 2, 2, 2, 2, 2 }, DNS_LOOKUP_NO_ANSWER },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    static_resetLookup();
    memcpy(g_lookupRcodes, cases[i].ma_rcodes, sizeof(g_lookupRcodes));
    DNSLOOKUPRecord_t record;
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_status, dns_lookupDomain("example.com", &record), cases[i].mp_name);
    dns_DNSLOOKUPRecordFree(&record);
  }
}

static void static_answerFromInternal(const FakeSentQuery_t* sent)
{
  static_startReplyTo(sent->ma_query, FLAGS_ANSWER, RCODE_NOERROR, 1);
  static_putRecordOwnedBy("db.internal", static_queryType(sent->ma_query));
  static_queueReply(sent->m_fd, 0, false);
}

void test_lookupDomain_every_type_from_a_name_that_is_not_public_is_no_answer(void)
{
  static_resetLookup();
  g_answerer = static_answerFromInternal;
  DNSLOOKUPRecord_t record;
  TEST_ASSERT_EQUAL_INT(DNS_LOOKUP_NO_ANSWER, dns_lookupDomain("example.com", &record));
  for (int type = 0; type < DNS_LOOKUP_DOMAIN_RECORD_TYPE_COUNT; type++)
    TEST_ASSERT_EQUAL_INT(DNS_ANSWER_NOT_PUBLIC_NAME, record.ma_answers[type].m_status);
  dns_DNSLOOKUPRecordFree(&record);
}

void test_lookupDomain_refuses_a_name_that_is_not_public(void)
{
  static const char* const names[] = { "printer.local", "example.com." };
  for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++)
  {
    static_resetLookup();
    DNSLOOKUPRecord_t record;
    TEST_ASSERT_EQUAL_INT_MESSAGE(DNS_LOOKUP_INVALID_NAME, dns_lookupDomain(names[i], &record), names[i]);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, g_socketCount, names[i]);
    dns_DNSLOOKUPRecordFree(&record);
  }
}

static void static_answerLookupPublicAFirst(const FakeSentQuery_t* sent)
{
  if (static_queryType(sent->ma_query) != WIRE_TYPE_A)
  {
    static_answerLookup(sent);
    return;
  }
  static_startReplyTo(sent->ma_query, FLAGS_ANSWER, RCODE_NOERROR, 2);
  static_putRecordHead(WIRE_TYPE_A, WIRE_CLASS_IN, 4);
  static_putBytes("\x5d\xb8\xd7\x0e", 4);
  static_putRecordHead(WIRE_TYPE_A, WIRE_CLASS_IN, 4);
  static_putBytes("\x0a\x00\x00\x01", 4);
  static_queueReply(sent->m_fd, 0, false);
}

void test_lookupDomain_lists_the_non_public_addresses(void)
{
  static_resetLookup();
  DNSLOOKUPRecord_t record;
  TEST_ASSERT_EQUAL_INT(DNS_LOOKUP_OK, dns_lookupDomain("example.com", &record));
  TEST_ASSERT_EQUAL_INT(2, record.m_nonPublicAddressCount);
  TEST_ASSERT_EQUAL_PTR(&record.ma_answers[DNS_RECORD_TYPE_A].mp_texts[0], record.mp_nonPublicAddresses[0]);
  TEST_ASSERT_EQUAL_PTR(&record.ma_answers[DNS_RECORD_TYPE_AAAA].mp_texts[0], record.mp_nonPublicAddresses[1]);
  static_assertText("10.0.0.1", 8, record.mp_nonPublicAddresses[0]);
  static_assertText("fd00::1", 7, record.mp_nonPublicAddresses[1]);
  dns_DNSLOOKUPRecordFree(&record);
  TEST_ASSERT_NULL(record.mp_nonPublicAddresses);
  TEST_ASSERT_EQUAL_INT(0, record.m_nonPublicAddressCount);

  static_resetLookup();
  g_answerer = static_answerLookupPublicAFirst;
  TEST_ASSERT_EQUAL_INT(DNS_LOOKUP_OK, dns_lookupDomain("example.com", &record));
  TEST_ASSERT_EQUAL_INT(2, record.m_nonPublicAddressCount);
  TEST_ASSERT_EQUAL_PTR(&record.ma_answers[DNS_RECORD_TYPE_A].mp_texts[1], record.mp_nonPublicAddresses[0]);
  TEST_ASSERT_EQUAL_PTR(&record.ma_answers[DNS_RECORD_TYPE_AAAA].mp_texts[0], record.mp_nonPublicAddresses[1]);
  static_assertText("10.0.0.1", 8, record.mp_nonPublicAddresses[0]);
  dns_DNSLOOKUPRecordFree(&record);

  static_resetLookup();
  g_lookupRcodes[DNS_RECORD_TYPE_A] = RCODE_SERVFAIL;
  TEST_ASSERT_EQUAL_INT(DNS_LOOKUP_OK, dns_lookupDomain("example.com", &record));
  TEST_ASSERT_EQUAL_INT(1, record.m_nonPublicAddressCount);
  TEST_ASSERT_EQUAL_PTR(&record.ma_answers[DNS_RECORD_TYPE_AAAA].mp_texts[0], record.mp_nonPublicAddresses[0]);
  dns_DNSLOOKUPRecordFree(&record);

  static_resetLookup();
  g_lookupRcodes[DNS_RECORD_TYPE_A]    = RCODE_SERVFAIL;
  g_lookupRcodes[DNS_RECORD_TYPE_AAAA] = RCODE_SERVFAIL;
  TEST_ASSERT_EQUAL_INT(DNS_LOOKUP_OK, dns_lookupDomain("example.com", &record));
  TEST_ASSERT_EQUAL_INT(0, record.m_nonPublicAddressCount);
  TEST_ASSERT_NULL(record.mp_nonPublicAddresses);
  dns_DNSLOOKUPRecordFree(&record);
}

void test_lookupDomain_allocation_failure_is_no_memory(void)
{
  static_resetLookup();
  g_allocationCount = 0;
  DNSLOOKUPRecord_t record;
  TEST_ASSERT_EQUAL_INT(DNS_LOOKUP_OK, dns_lookupDomain("example.com", &record));
  dns_DNSLOOKUPRecordFree(&record);
  int allocation_count = g_allocationCount;

  int failing[] = { allocation_count, 1 };
  for (size_t i = 0; i < sizeof(failing) / sizeof(failing[0]); i++)
  {
    static_resetLookup();
    g_failAllocationNumber = failing[i];
    g_allocationCount      = 0;
    TEST_ASSERT_EQUAL_INT(DNS_LOOKUP_NO_MEMORY, dns_lookupDomain("example.com", &record));
    g_failAllocationNumber = 0;
    dns_DNSLOOKUPRecordFree(&record);
  }
}

static const DnsTxtService_t* static_txtService(const char* name)
{
  for (int i = 0; i < DNS_TXT_SERVICE_COUNT; i++)
    if (strcmp(dns_txtServices[i].mp_serviceName, name) == 0)
      return &dns_txtServices[i];
  TEST_FAIL_MESSAGE(name);
  return NULL;
}

void test_lookupDomain_lists_the_services_txt_records_name(void)
{
  static_resetLookup();
  g_lookupTxt[0] = "google-site-verification=abc";      g_lookupTxtLen[0] = 28;
  g_lookupTxt[1] = "x\0apple-domain-verification=def";  g_lookupTxtLen[1] = 31;
  g_lookupTxt[2] = "google-site-verification=ghi";      g_lookupTxtLen[2] = 28;
  g_lookupTxt[3] = "Keybase-Site-Verification=jkl";     g_lookupTxtLen[3] = 29;
  g_lookupTxtCount = 4;
  DNSLOOKUPRecord_t record;
  TEST_ASSERT_EQUAL_INT(DNS_LOOKUP_OK, dns_lookupDomain("example.com", &record));
  TEST_ASSERT_EQUAL_INT(2, record.m_serviceCount);
  TEST_ASSERT_EQUAL_PTR(static_txtService("apple"), record.ma_services[0]);
  TEST_ASSERT_EQUAL_PTR(static_txtService("google-workspace"), record.ma_services[1]);
  dns_DNSLOOKUPRecordFree(&record);
}

void test_txtServices_entries_are_safe_to_write_raw(void)
{
  for (int i = 0; i < DNS_TXT_SERVICE_COUNT; i++)
  {
    const char* fields[2] = { dns_txtServices[i].mp_serviceName, dns_txtServices[i].mp_evidence };
    for (int f = 0; f < 2; f++)
    {
      TEST_ASSERT_NOT_NULL(fields[f]);
      size_t len = strlen(fields[f]);
      TEST_ASSERT_TRUE_MESSAGE(len >= 1 && len <= 63, fields[f]);
      for (size_t k = 0; k < len; k++)
        TEST_ASSERT_TRUE_MESSAGE(fields[f][k] > 0x20 && fields[f][k] < 0x7F && fields[f][k] != '"' && fields[f][k] != '\\', fields[f]);
    }
    for (int j = 0; j < i; j++)
      TEST_ASSERT_TRUE_MESSAGE(strcmp(dns_txtServices[i].mp_serviceName, dns_txtServices[j].mp_serviceName) != 0, dns_txtServices[i].mp_serviceName);
  }
  TEST_ASSERT_EQUAL_STRING("keybase", dns_txtServices[0].mp_serviceName);
  TEST_ASSERT_EQUAL_STRING("keybase-site-verification", dns_txtServices[0].mp_evidence);
  TEST_ASSERT_EQUAL_STRING("atlassian-sending", dns_txtServices[DNS_TXT_SERVICE_COUNT - 1].mp_serviceName);
  TEST_ASSERT_EQUAL_STRING("atlassian-sending-domain-verification", dns_txtServices[DNS_TXT_SERVICE_COUNT - 1].mp_evidence);
}

void test_lookupDomain_finds_every_txt_service_by_its_whole_evidence(void)
{
  for (int s = 0; s < DNS_TXT_SERVICE_COUNT; s++)
  {
    const char* evidence = dns_txtServices[s].mp_evidence;
    for (int cut = 0; cut <= 2; cut++)
    {
      static_resetLookup();
      g_lookupTxt[0]    = cut == 2 ? evidence + 1 : evidence;
      g_lookupTxtLen[0] = strlen(evidence) - (cut == 0 ? 0 : 1);
      g_lookupTxtCount  = 1;
      DNSLOOKUPRecord_t record;
      TEST_ASSERT_EQUAL_INT_MESSAGE(DNS_LOOKUP_OK, dns_lookupDomain("example.com", &record), evidence);
      bool is_listed = false;
      for (int i = 0; i < record.m_serviceCount; i++)
        is_listed = is_listed || record.ma_services[i] == &dns_txtServices[s];
      TEST_ASSERT_TRUE_MESSAGE(is_listed == (cut == 0), evidence);
      dns_DNSLOOKUPRecordFree(&record);
    }
  }
}

#define TXT_SERVICES_HASH 0xa13e62b2e62a3a36ULL

void test_txtServices_table_is_pinned(void)
{
  uint64_t hash = 0xcbf29ce484222325ULL;
  for (int s = 0; s < DNS_TXT_SERVICE_COUNT; s++)
  {
    const char* fields[2] = { dns_txtServices[s].mp_serviceName, dns_txtServices[s].mp_evidence };
    for (int f = 0; f < 2; f++)
      for (size_t k = 0; k <= strlen(fields[f]); k++)
      {
        hash ^= (unsigned char)fields[f][k];
        hash *= 0x100000001b3ULL;
      }
  }
  TEST_ASSERT_TRUE_MESSAGE(hash == TXT_SERVICES_HASH, "dns_txtServices changed");
}

#define FAKE_NO_REPLY 0xFF

typedef struct {
  const char* mp_name;
  uint8_t     m_rcode;
  const char* mp_target;
  int64_t     m_delayMs;
} FakeCname_t;

static FakeCname_t g_cnames[12];
static int         g_cnameCount = 0;

static void static_addCname(const char* name, uint8_t rcode, const char* target)
{
  TEST_ASSERT_TRUE(g_cnameCount < (int)(sizeof(g_cnames) / sizeof(g_cnames[0])));
  g_cnames[g_cnameCount++] = (FakeCname_t){ name, rcode, target, 0 };
}

static void static_queryName(const unsigned char* query, char* name_out)
{
  size_t pos      = DNS_TEST_HEADER_SIZE;
  size_t name_len = 0;
  while (query[pos] != 0)
  {
    if (name_len > 0)
      name_out[name_len++] = '.';
    memcpy(name_out + name_len, query + pos + 1, query[pos]);
    name_len += query[pos];
    pos      += 1 + query[pos];
  }
  name_out[name_len] = '\0';
}

static void static_answerCnames(const FakeSentQuery_t* sent)
{
  TEST_ASSERT_EQUAL_UINT16(WIRE_TYPE_CNAME, static_queryType(sent->ma_query));
  char name[DNS_NAME_TEXT_SIZE];
  static_queryName(sent->ma_query, name);
  const FakeCname_t* entry = NULL;
  for (int i = 0; i < g_cnameCount; i++)
    if (strcasecmp(g_cnames[i].mp_name, name) == 0)
      entry = &g_cnames[i];

  uint8_t rcode = entry != NULL ? entry->m_rcode : RCODE_NXDOMAIN;
  if (rcode == FAKE_NO_REPLY)
    return;
  bool has_record = rcode == RCODE_NOERROR && entry->mp_target != NULL;
  static_startReplyTo(sent->ma_query, FLAGS_ANSWER, rcode, has_record ? 1 : 0);
  if (has_record)
  {
    static_putRecordHead(WIRE_TYPE_CNAME, WIRE_CLASS_IN, (uint16_t)(strlen(entry->mp_target) + 2));
    static_putName(entry->mp_target);
  }
  static_queueReply(sent->m_fd, entry != NULL ? entry->m_delayMs : 0, false);
}

static void static_resetTakeover(void)
{
  static_resetFakeNetwork();
  g_cnameCount = 0;
  static_addCname("shop.example.com", RCODE_NOERROR, "shop-example.cloudapp.net");
  g_answerer = static_answerCnames;
}

static const DnsTakeoverSuffix_t* static_takeoverSuffix(const char* suffix)
{
  for (int i = 0; i < DNS_TAKEOVER_SUFFIX_COUNT; i++)
    if (strcmp(dns_takeoverSuffixes[i].mp_suffix, suffix) == 0)
      return &dns_takeoverSuffixes[i];
  TEST_FAIL_MESSAGE(suffix);
  return NULL;
}

void test_checkTakeover_asks_each_name_of_the_chain(void)
{
  static_resetTakeover();
  DNSTAKEOVERCHECKRecord_t record;
  TEST_ASSERT_EQUAL_INT(DNS_LOOKUP_OK, dns_checkTakeover("Shop.Example.COM", &record));
  TEST_ASSERT_EQUAL_STRING("shop.example.com", record.ma_hostname);

  TEST_ASSERT_EQUAL_INT(2, g_sentCount);
  char name[DNS_NAME_TEXT_SIZE];
  static_queryName(g_sentQueries[0].ma_query, name);
  TEST_ASSERT_EQUAL_STRING("shop.example.com", name);
  static_queryName(g_sentQueries[1].ma_query, name);
  TEST_ASSERT_EQUAL_STRING("shop-example.cloudapp.net", name);
  for (int i = 0; i < 2; i++)
  {
    TEST_ASSERT_EQUAL_UINT16(WIRE_TYPE_CNAME, static_queryType(g_sentQueries[i].ma_query));
    TEST_ASSERT_EQUAL_INT64(FAKE_START_MS, g_sentQueries[i].m_atMs);
  }
  TEST_ASSERT_EQUAL_INT(1, record.m_hostnameChainLength);
  TEST_ASSERT_EQUAL_STRING("shop-example.cloudapp.net", record.ma_hostnameChain[0]);
  TEST_ASSERT_FALSE(record.m_isTargetFound);
  TEST_ASSERT_EQUAL_PTR(static_takeoverSuffix("cloudapp.net"), record.mp_matchedSuffix);
  static_assertEverySocketClosed();
}

void test_checkTakeover_suffix_must_end_at_a_dot(void)
{
  static const struct {
    const char* mp_target;
    const char* mp_suffix;
  } cases[] = {
    { "notcloudapp.net",          NULL },
    { "cloudapp.net",             "cloudapp.net" },
    { "loudapp.net",              NULL },
    { "a.CloudApp.NET",           "cloudapp.net" },
    { "cloudapp.net.example.org", NULL },
    { "x.blob.core.windows.net",  "blob.core.windows.net" },
    { "x.core.windows.net",       NULL },
    { "x.visualstudio.com",       "visualstudio.com" },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    static_resetTakeover();
    g_cnames[0].mp_target = cases[i].mp_target;
    DNSTAKEOVERCHECKRecord_t record;
    TEST_ASSERT_EQUAL_INT_MESSAGE(DNS_LOOKUP_OK, dns_checkTakeover("shop.example.com", &record), cases[i].mp_target);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(cases[i].mp_target, record.ma_hostnameChain[0], cases[i].mp_target);
    const DnsTakeoverSuffix_t* expected = cases[i].mp_suffix != NULL ? static_takeoverSuffix(cases[i].mp_suffix) : NULL;
    TEST_ASSERT_EQUAL_PTR_MESSAGE(expected, record.mp_matchedSuffix, cases[i].mp_target);
  }
}

void test_checkTakeover_judges_the_last_name_of_the_chain(void)
{
  static const struct {
    const char* mp_first;
    const char* mp_last;
    bool        m_isLastFound;
    const char* mp_suffix;
  } cases[] = {
    { "a.cloudapp.net", "b.example.org",  false, NULL },
    { "a.example.org",  "b.cloudapp.net", false, "cloudapp.net" },
    { "a.cloudapp.net", "b.example.org",  true,  NULL },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    static_resetTakeover();
    g_cnames[0].mp_target = cases[i].mp_first;
    static_addCname(cases[i].mp_first, RCODE_NOERROR, cases[i].mp_last);
    if (cases[i].m_isLastFound)
      static_addCname(cases[i].mp_last, RCODE_NOERROR, NULL);
    DNSTAKEOVERCHECKRecord_t record;
    TEST_ASSERT_EQUAL_INT(DNS_LOOKUP_OK, dns_checkTakeover("shop.example.com", &record));
    TEST_ASSERT_EQUAL_INT(2, record.m_hostnameChainLength);
    TEST_ASSERT_EQUAL_STRING(cases[i].mp_first, record.ma_hostnameChain[0]);
    TEST_ASSERT_EQUAL_STRING(cases[i].mp_last, record.ma_hostnameChain[1]);
    TEST_ASSERT_EQUAL(cases[i].m_isLastFound, record.m_isTargetFound);
    const DnsTakeoverSuffix_t* expected = cases[i].mp_suffix != NULL ? static_takeoverSuffix(cases[i].mp_suffix) : NULL;
    TEST_ASSERT_EQUAL_PTR(expected, record.mp_matchedSuffix);
    static_assertEverySocketClosed();
  }
}

void test_checkTakeover_status_from_the_answers(void)
{
  static const struct {
    const char*       mp_name;
    uint8_t           m_hostRcode;
    bool              m_hasCnameRecord;
    uint8_t           m_targetRcode;
    DnsLookupStatus_t m_status;
    int               m_hostnameChainLength;
    bool              m_isTargetFound;
  } cases[] = {
    { "target found",           RCODE_NOERROR,  true,  RCODE_NOERROR,  DNS_LOOKUP_OK,        1, true  },
    { "target not found",       RCODE_NOERROR,  true,  RCODE_NXDOMAIN, DNS_LOOKUP_OK,        1, false },
    { "target unknown",         RCODE_NOERROR,  true,  RCODE_SERVFAIL, DNS_LOOKUP_NO_ANSWER, 1, false },
    { "no CNAME",               RCODE_NOERROR,  false, RCODE_SERVFAIL, DNS_LOOKUP_OK,        0, false },
    { "host name not found",    RCODE_NXDOMAIN, false, RCODE_NOERROR,  DNS_LOOKUP_NOT_FOUND, 0, false },
    { "CNAME question fails",   RCODE_SERVFAIL, false, RCODE_NOERROR,  DNS_LOOKUP_NO_ANSWER, 0, false },
    { "CNAME question refused", RCODE_REFUSED,  false, RCODE_NOERROR,  DNS_LOOKUP_NO_ANSWER, 0, false },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    static_resetTakeover();
    g_cnames[0].m_rcode   = cases[i].m_hostRcode;
    g_cnames[0].mp_target = cases[i].m_hasCnameRecord ? "shop-example.cloudapp.net" : NULL;
    static_addCname("shop-example.cloudapp.net", cases[i].m_targetRcode, NULL);
    DNSTAKEOVERCHECKRecord_t record;
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_status, dns_checkTakeover("shop.example.com", &record), cases[i].mp_name);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_hostnameChainLength, record.m_hostnameChainLength, cases[i].mp_name);
    TEST_ASSERT_EQUAL_MESSAGE(cases[i].m_isTargetFound, record.m_isTargetFound, cases[i].mp_name);
    static_assertEverySocketClosed();
  }
}

void test_checkTakeover_chain_length_limit(void)
{
  static const char* const names[] = {
    "n1.example.com", "n2.example.com", "n3.example.com", "n4.example.com", "n5.example.com",
    "n6.example.com", "n7.example.com", "n8.example.com", "n9.example.com",
  };
  static const int lengths[] = { DNS_TAKEOVER_HOSTNAME_CHAIN_MAX, DNS_TAKEOVER_HOSTNAME_CHAIN_MAX + 1 };
  for (size_t c = 0; c < sizeof(lengths) / sizeof(lengths[0]); c++)
  {
    static_resetTakeover();
    g_cnames[0].mp_target = names[0];
    for (int k = 0; k < lengths[c]; k++)
      static_addCname(names[k], RCODE_NOERROR, k + 1 < lengths[c] ? names[k + 1] : NULL);
    DNSTAKEOVERCHECKRecord_t record;
    DnsLookupStatus_t expected = lengths[c] <= DNS_TAKEOVER_HOSTNAME_CHAIN_MAX ? DNS_LOOKUP_OK : DNS_LOOKUP_NO_ANSWER;
    TEST_ASSERT_EQUAL_INT(expected, dns_checkTakeover("shop.example.com", &record));
    if (expected == DNS_LOOKUP_OK)
    {
      TEST_ASSERT_EQUAL_INT(DNS_TAKEOVER_HOSTNAME_CHAIN_MAX, record.m_hostnameChainLength);
      TEST_ASSERT_EQUAL_STRING("n8.example.com", record.ma_hostnameChain[DNS_TAKEOVER_HOSTNAME_CHAIN_MAX - 1]);
      TEST_ASSERT_TRUE(record.m_isTargetFound);
    }
    else
      TEST_ASSERT_EQUAL_INT(DNS_TAKEOVER_HOSTNAME_CHAIN_MAX, record.m_hostnameChainLength);
    static_assertEverySocketClosed();
  }

  static_resetTakeover();
  g_cnames[0].mp_target = "a.example.net";
  static_addCname("a.example.net", RCODE_NOERROR, "b.example.net");
  static_addCname("b.example.net", RCODE_NOERROR, "a.example.net");
  DNSTAKEOVERCHECKRecord_t record;
  TEST_ASSERT_EQUAL_INT(DNS_LOOKUP_NO_ANSWER, dns_checkTakeover("shop.example.com", &record));
  static_assertEverySocketClosed();
}

void test_checkTakeover_does_not_ask_a_target_that_is_not_public(void)
{
  static_resetTakeover();
  g_cnames[0].mp_target = "printer.local";
  DNSTAKEOVERCHECKRecord_t record;
  TEST_ASSERT_EQUAL_INT(DNS_LOOKUP_NO_ANSWER, dns_checkTakeover("shop.example.com", &record));
  TEST_ASSERT_EQUAL_INT(1, g_sentCount);
  static_assertEverySocketClosed();
}

void test_checkTakeover_questions_share_one_deadline(void)
{
  static const int64_t host_delays[] = { 2000, DNS_LOOKUP_DEADLINE_MS };
  for (size_t i = 0; i < sizeof(host_delays) / sizeof(host_delays[0]); i++)
  {
    static_resetTakeover();
    g_cnames[0].m_delayMs = host_delays[i];
    static_addCname("shop-example.cloudapp.net", FAKE_NO_REPLY, NULL);
    DNSTAKEOVERCHECKRecord_t record;
    TEST_ASSERT_EQUAL_INT(DNS_LOOKUP_NO_ANSWER, dns_checkTakeover("shop.example.com", &record));
    TEST_ASSERT_EQUAL_INT64(FAKE_START_MS + DNS_LOOKUP_DEADLINE_MS, g_nowMs);
    static_assertEverySocketClosed();
  }
  TEST_ASSERT_EQUAL_INT(DNS_LOOKUP_DEADLINE_MS / DNS_RETRANSMIT_MS, g_sentCount);
}

void test_checkTakeover_answer_from_a_name_that_is_not_public_is_no_answer(void)
{
  static_resetTakeover();
  g_answerer = static_answerFromInternal;
  DNSTAKEOVERCHECKRecord_t record;
  TEST_ASSERT_EQUAL_INT(DNS_LOOKUP_NO_ANSWER, dns_checkTakeover("shop.example.com", &record));
}

void test_checkTakeover_refuses_a_name_that_is_not_public(void)
{
  static const char* const names[] = { "printer.local", "shop.example.com." };
  for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++)
  {
    static_resetTakeover();
    DNSTAKEOVERCHECKRecord_t record;
    TEST_ASSERT_EQUAL_INT_MESSAGE(DNS_LOOKUP_INVALID_NAME, dns_checkTakeover(names[i], &record), names[i]);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, g_socketCount, names[i]);
  }
}

void test_checkTakeover_allocation_failure_is_no_memory(void)
{
  static_resetTakeover();
  static_addCname("shop-example.cloudapp.net", RCODE_NOERROR, NULL);
  g_allocationCount = 0;
  DNSTAKEOVERCHECKRecord_t record;
  TEST_ASSERT_EQUAL_INT(DNS_LOOKUP_OK, dns_checkTakeover("shop.example.com", &record));
  int allocation_count = g_allocationCount;
  TEST_ASSERT_EQUAL_INT(2, allocation_count);

  for (int n = 1; n <= allocation_count; n++)
  {
    static_resetTakeover();
    static_addCname("shop-example.cloudapp.net", RCODE_NOERROR, NULL);
    g_failAllocationNumber = n;
    g_allocationCount      = 0;
    TEST_ASSERT_EQUAL_INT(DNS_LOOKUP_NO_MEMORY, dns_checkTakeover("shop.example.com", &record));
    g_failAllocationNumber = 0;
    static_assertEverySocketClosed();
  }
}

void test_takeoverSuffixes_entries_are_safe_to_write_raw(void)
{
  for (int i = 0; i < DNS_TAKEOVER_SUFFIX_COUNT; i++)
  {
    const char* provider = dns_takeoverSuffixes[i].mp_serviceName;
    const char* suffix   = dns_takeoverSuffixes[i].mp_suffix;
    TEST_ASSERT_NOT_NULL(provider);
    TEST_ASSERT_NOT_NULL(suffix);
    size_t provider_len = strlen(provider);
    TEST_ASSERT_TRUE_MESSAGE(provider_len >= 1 && provider_len <= 63, provider);
    for (size_t k = 0; k < provider_len; k++)
      TEST_ASSERT_TRUE_MESSAGE(provider[k] >= 0x20 && provider[k] < 0x7F && provider[k] != '"' && provider[k] != '\\', provider);

    size_t suffix_len = strlen(suffix);
    TEST_ASSERT_TRUE_MESSAGE(suffix_len >= 1 && suffix_len <= 63, suffix);
    TEST_ASSERT_NOT_NULL_MESSAGE(strchr(suffix, '.'), suffix);
    TEST_ASSERT_TRUE_MESSAGE(suffix[0] != '.' && suffix[suffix_len - 1] != '.', suffix);
    for (size_t k = 0; k < suffix_len; k++)
      TEST_ASSERT_TRUE_MESSAGE((suffix[k] >= 'a' && suffix[k] <= 'z') || (suffix[k] >= '0' && suffix[k] <= '9') || suffix[k] == '-' || suffix[k] == '.', suffix);
    for (int j = 0; j < i; j++)
      TEST_ASSERT_TRUE_MESSAGE(strcmp(suffix, dns_takeoverSuffixes[j].mp_suffix) != 0, suffix);
  }
  TEST_ASSERT_EQUAL_STRING("elasticbeanstalk.com", dns_takeoverSuffixes[0].mp_suffix);
  TEST_ASSERT_EQUAL_STRING("visualstudio.com", dns_takeoverSuffixes[DNS_TAKEOVER_SUFFIX_COUNT - 1].mp_suffix);
}

void test_takeoverSuffixes_table_is_pinned(void)
{
  static const char* const expected[DNS_TAKEOVER_SUFFIX_COUNT][2] = {
    { "AWS/Elastic Beanstalk", "elasticbeanstalk.com" },
    { "Discourse",             "trydiscourse.com" },
    { "Microsoft Azure",       "cloudapp.net" },
    { "Microsoft Azure",       "cloudapp.azure.com" },
    { "Microsoft Azure",       "azurewebsites.net" },
    { "Microsoft Azure",       "blob.core.windows.net" },
    { "Microsoft Azure",       "azure-api.net" },
    { "Microsoft Azure",       "azurehdinsight.net" },
    { "Microsoft Azure",       "azureedge.net" },
    { "Microsoft Azure",       "azurecontainer.io" },
    { "Microsoft Azure",       "database.windows.net" },
    { "Microsoft Azure",       "azuredatalakestore.net" },
    { "Microsoft Azure",       "search.windows.net" },
    { "Microsoft Azure",       "azurecr.io" },
    { "Microsoft Azure",       "redis.cache.windows.net" },
    { "Microsoft Azure",       "servicebus.windows.net" },
    { "Microsoft Azure",       "visualstudio.com" },
  };
  for (int i = 0; i < DNS_TAKEOVER_SUFFIX_COUNT; i++)
  {
    TEST_ASSERT_EQUAL_STRING(expected[i][0], dns_takeoverSuffixes[i].mp_serviceName);
    TEST_ASSERT_EQUAL_STRING(expected[i][1], dns_takeoverSuffixes[i].mp_suffix);
  }
}

void test_lookupPtr_asks_about_the_reverse_name(void)
{
  static const char* const cases[2][2] = {
    { "93.184.215.14",         "14.215.184.93.in-addr.arpa" },
    { "2606:2800:21F:CB07::1", "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.7.0.b.c.f.1.2.0.0.0.8.2.6.0.6.2.ip6.arpa" },
  };
  for (int i = 0; i < 2; i++)
  {
    static_resetFakeNetwork();
    g_answerer = static_answerEachAtOnce;
    DnsAnswer_t answer;
    dns_lookupPtr(cases[i][0], &answer);

    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_sentCount, cases[i][0]);
    TEST_ASSERT_EQUAL_UINT16(WIRE_TYPE_PTR, static_queryType(g_sentQueries[0].ma_query));
    char name[DNS_NAME_TEXT_SIZE];
    static_queryName(g_sentQueries[0].ma_query, name);
    TEST_ASSERT_EQUAL_STRING(cases[i][1], name);

    TEST_ASSERT_EQUAL_INT_MESSAGE(DNS_ANSWER_OK, answer.m_status, cases[i][0]);
    TEST_ASSERT_EQUAL_INT(1, answer.m_recordCount);
    static_assertText("host.example.net", 16, &answer.mp_texts[0]);
    dns_answerFree(&answer);
    static_assertEverySocketClosed();
  }
}

void test_lookupPtr_waits_until_its_deadline(void)
{
  static_resetFakeNetwork();
  g_answerer = NULL;
  DnsAnswer_t answer;
  dns_lookupPtr("93.184.215.14", &answer);
  static_assertFailedAnswer(DNS_ANSWER_TIMEOUT, &answer);
  TEST_ASSERT_EQUAL_INT64(FAKE_START_MS + DNS_PTR_DEADLINE_MS, g_nowMs);
  static_assertEverySocketClosed();
}

void test_lookupPtr_refuses_an_address_that_is_not_globally_reachable(void)
{
  static const char* const texts[] = {
    "10.0.0.1", "127.0.0.1", "192.0.2.1", "::1", "fe80::1", "::ffff:10.0.0.1",
    "example.com", "93.184.215.14 ", "93.184.215", "fe80::1%eth0", "",
  };
  for (size_t i = 0; i < sizeof(texts) / sizeof(texts[0]); i++)
  {
    static_resetFakeNetwork();
    g_answerer = static_answerEachAtOnce;
    DnsAnswer_t answer;
    memset(&answer, 0xA5, sizeof(answer));
    dns_lookupPtr(texts[i], &answer);
    TEST_ASSERT_EQUAL_INT_MESSAGE(DNS_ANSWER_BAD_QUESTION, answer.m_status, texts[i]);
    static_assertFailedAnswer(DNS_ANSWER_BAD_QUESTION, &answer);
    TEST_ASSERT_FALSE(answer.m_hasNullMx);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, g_socketCount, texts[i]);
  }
}

int main(void)
{
  UNITY_BEGIN();
  RUN_TEST(test_tryReadResponse_oracle_mx_skips_the_null_mx);
  RUN_TEST(test_tryReadResponse_oracle_txt_joins_strings_and_keeps_nul);
  RUN_TEST(test_tryReadResponse_oracle_soa_reads_both_names_and_the_serial);
  RUN_TEST(test_tryReadResponse_oracle_a_after_cname_keeps_only_the_a_records);
  RUN_TEST(test_tryReadResponse_oracle_aaaa_writes_the_short_form);
  RUN_TEST(test_tryReadResponse_oracle_caa_reads_flags_tag_and_value);
  RUN_TEST(test_tryReadResponse_caa_tag_length);
  RUN_TEST(test_tryReadResponse_caa_shorter_than_two_bytes_is_malformed);
  RUN_TEST(test_tryReadResponse_ns_and_cname_names);
  RUN_TEST(test_tryReadResponse_empty_txt_is_one_empty_record);
  RUN_TEST(test_tryReadResponse_txt_string_length_against_the_data_end);
  RUN_TEST(test_tryReadResponse_skips_records_of_another_class_or_type);
  RUN_TEST(test_tryReadResponse_address_length_must_be_exact);
  RUN_TEST(test_tryReadResponse_name_must_fill_the_data);
  RUN_TEST(test_tryReadResponse_compression_loop_is_malformed);
  RUN_TEST(test_tryReadResponse_mx_data_length);
  RUN_TEST(test_tryReadResponse_soa_numbers_and_second_record);
  RUN_TEST(test_tryReadResponse_bad_record_after_a_good_one_fails_the_answer);
  RUN_TEST(test_tryReadResponse_nodata_is_ok_with_no_record);
  RUN_TEST(test_tryReadResponse_error_codes);
  RUN_TEST(test_tryReadResponse_truncated_answer);
  RUN_TEST(test_tryReadResponse_other_id_is_not_the_answer);
  RUN_TEST(test_tryReadResponse_query_without_the_answer_bit_is_not_the_answer);
  RUN_TEST(test_tryReadResponse_other_question_is_not_the_answer);
  RUN_TEST(test_tryReadResponse_question_name_case_is_ignored);
  RUN_TEST(test_tryReadResponse_question_count_must_be_one);
  RUN_TEST(test_tryReadResponse_message_shorter_than_a_header_is_not_the_answer);
  RUN_TEST(test_tryReadResponse_sections_that_do_not_fit_are_malformed);
  RUN_TEST(test_tryReadResponse_message_size_limit);
  RUN_TEST(test_tryReadResponse_record_count_limit);
  RUN_TEST(test_tryReadResponse_record_of_a_name_that_is_not_public);
  RUN_TEST(test_tryReadResponse_every_type_refuses_a_record_of_a_name_that_is_not_public);
  RUN_TEST(test_tryReadResponse_record_of_the_question_name_is_read);
  RUN_TEST(test_tryReadResponse_owner_that_only_contains_the_question_name_is_judged);
  RUN_TEST(test_tryReadResponse_cname_to_an_underscore_name_is_followed);
  RUN_TEST(test_tryReadResponse_null_mx_sets_its_flag);
  RUN_TEST(test_tryReadResponse_failed_answer_clears_the_null_mx_flag);
  RUN_TEST(test_tryReadResponse_cname_to_a_name_that_is_not_public_hides_whether_it_exists);
  RUN_TEST(test_tryReadResponse_mx_priority_is_16_bits);
  RUN_TEST(test_tryReadResponse_each_failed_allocation_is_no_memory);
  RUN_TEST(test_askQuestions_sends_each_question_once_with_an_opt_record);
  RUN_TEST(test_askQuestions_answers_each_question);
  RUN_TEST(test_askQuestions_answers_in_another_order);
  RUN_TEST(test_askQuestions_resends_to_the_next_nameserver);
  RUN_TEST(test_askQuestions_server_failure_goes_to_the_next_nameserver);
  RUN_TEST(test_askQuestions_circles_the_nameservers_until_the_deadline);
  RUN_TEST(test_askQuestions_deadline_edge);
  RUN_TEST(test_askQuestions_drops_replies_that_answer_something_else);
  RUN_TEST(test_askQuestions_udp_payload_size_edge);
  RUN_TEST(test_askQuestions_truncated_answer_is_asked_again_over_tcp);
  RUN_TEST(test_askQuestions_tcp_moves_in_small_pieces);
  RUN_TEST(test_askQuestions_tcp_send_and_read_that_would_block_are_tried_again);
  RUN_TEST(test_askQuestions_tcp_answer_in_two_pieces);
  RUN_TEST(test_askQuestions_second_truncated_answer_is_dropped);
  RUN_TEST(test_askQuestions_tcp_question_beside_a_udp_question);
  RUN_TEST(test_askQuestions_tcp_answer_after_the_deadline_times_out);
  RUN_TEST(test_askQuestions_bad_tcp_answers);
  RUN_TEST(test_askQuestions_tcp_that_cannot_connect_is_truncated);
  RUN_TEST(test_askQuestions_tcp_buffer_allocation_failure);
  RUN_TEST(test_askQuestions_poll_failure);
  RUN_TEST(test_askQuestions_without_a_nameserver_has_no_resolver);
  RUN_TEST(test_askQuestions_failed_resolver_init_has_no_resolver);
  RUN_TEST(test_askQuestions_without_a_udp_socket_has_no_resolver);
  RUN_TEST(test_askQuestions_skips_a_nameserver_that_cannot_connect);
  RUN_TEST(test_askQuestions_asks_an_ipv6_nameserver);
  RUN_TEST(test_askQuestions_bad_question_is_not_sent);
  RUN_TEST(test_askQuestions_counts_each_question_once);
  RUN_TEST(test_askQuestions_question_count_is_kept_per_thread);
  RUN_TEST(test_lookupDomain_asks_each_type_of_the_lower_case_name);
  RUN_TEST(test_lookupDomain_waits_until_one_deadline);
  RUN_TEST(test_lookupDomain_status_from_the_answers);
  RUN_TEST(test_lookupDomain_every_type_from_a_name_that_is_not_public_is_no_answer);
  RUN_TEST(test_lookupDomain_refuses_a_name_that_is_not_public);
  RUN_TEST(test_lookupDomain_lists_the_non_public_addresses);
  RUN_TEST(test_lookupDomain_allocation_failure_is_no_memory);
  RUN_TEST(test_lookupDomain_lists_the_services_txt_records_name);
  RUN_TEST(test_txtServices_entries_are_safe_to_write_raw);
  RUN_TEST(test_lookupDomain_finds_every_txt_service_by_its_whole_evidence);
  RUN_TEST(test_txtServices_table_is_pinned);
  RUN_TEST(test_checkTakeover_asks_each_name_of_the_chain);
  RUN_TEST(test_checkTakeover_suffix_must_end_at_a_dot);
  RUN_TEST(test_checkTakeover_judges_the_last_name_of_the_chain);
  RUN_TEST(test_checkTakeover_status_from_the_answers);
  RUN_TEST(test_checkTakeover_chain_length_limit);
  RUN_TEST(test_checkTakeover_does_not_ask_a_target_that_is_not_public);
  RUN_TEST(test_checkTakeover_questions_share_one_deadline);
  RUN_TEST(test_checkTakeover_answer_from_a_name_that_is_not_public_is_no_answer);
  RUN_TEST(test_checkTakeover_refuses_a_name_that_is_not_public);
  RUN_TEST(test_checkTakeover_allocation_failure_is_no_memory);
  RUN_TEST(test_takeoverSuffixes_entries_are_safe_to_write_raw);
  RUN_TEST(test_takeoverSuffixes_table_is_pinned);
  RUN_TEST(test_lookupPtr_asks_about_the_reverse_name);
  RUN_TEST(test_lookupPtr_waits_until_its_deadline);
  RUN_TEST(test_lookupPtr_refuses_an_address_that_is_not_globally_reachable);
  return UNITY_END();
}
