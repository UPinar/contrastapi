#include <errno.h>
#include <poll.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>

#include "unity/unity.h"
#include "exifclient.h"

static ExifClientStatus_t static_read(const char* json, ExifClientResult_t* result_out)
{
  return exifclient_readResponse(json, strlen(json), result_out);
}

static bool static_isTextInResult(const ExifClientResult_t* result, const char* text)
{
  const unsigned char* bytes    = (const unsigned char*)result;
  size_t               text_len = strlen(text);
  for (size_t start = 0; start + text_len <= sizeof(*result); start++)
  {
    if (memcmp(bytes + start, text, text_len) == 0)
      return true;
  }
  return false;
}

static bool static_isResultZero(const ExifClientResult_t* result)
{
  ExifClientResult_t zero;
  memset(&zero, 0, sizeof(zero));
  return memcmp(&zero, result, sizeof(zero)) == 0;
}

#define FAKE_FD          900
#define FAKE_START_MS    1000000
#define FAKE_POLL_LIMIT  4096
#define FAKE_IMAGE_MAX   65536

void*   __real_malloc(size_t size);
void    __real_explicit_bzero(void* bytes, size_t byte_count);
int     __real_clock_gettime(clockid_t clock_id, struct timespec* time_out);

static int64_t        g_nowMs;
static int            g_socketCallCount;
static int            g_socketErrno;
static int            g_socketDomain;
static int            g_socketType;
static int            g_connectErrno;
static int64_t        g_connectCostMs;
static char           g_connectPath[sizeof(((struct sockaddr_un*)0)->sun_path)];
static bool           g_isOpen;
static int            g_closeCount;
static unsigned char  g_sentBytes[FAKE_IMAGE_MAX];
static size_t         g_sentLen;
static int            g_sendCallCount;
static size_t         g_sendRequestEnd;
static size_t         g_sendChunk;
static int            g_sendWouldBlockCount;
static int            g_sendInterruptCount;
static int            g_sendFailErrno;
static size_t         g_sendFailAfter;
static int            g_shutdownCount;
static int            g_shutdownHow;
static size_t         g_shutdownAtSentLen;
static const char*    g_answer;
static size_t         g_answerLen;
static size_t         g_answerOffset;
static size_t         g_recvChunk;
static int            g_recvWouldBlockCount;
static int            g_recvInterruptCount;
static int            g_recvFailErrno;
static size_t         g_recvFailAfter;
static bool           g_isAnswerEarly;
static bool           g_isResetAfterAnswer;
static size_t         g_answerStopAt;
static int64_t        g_recvCostMs;
static bool           g_isServiceSilent;
static short          g_closeEvents;
static bool           g_isSendBufferFull;
static int            g_pollCount;
static int            g_pollTimeouts[FAKE_POLL_LIMIT];
static int            g_pollFailErrno;
static bool           g_isAnswerBufferFailing;
static size_t         g_clearedByteCount;
static int            g_clearCount;

void setUp(void)
{
  g_nowMs               = FAKE_START_MS;
  g_socketCallCount     = 0;
  g_socketErrno         = 0;
  g_socketDomain        = -1;
  g_socketType          = -1;
  g_connectErrno        = 0;
  g_connectCostMs       = 0;
  g_connectPath[0]      = '\0';
  g_isOpen              = false;
  g_closeCount          = 0;
  g_sentLen             = 0;
  g_sendCallCount       = 0;
  g_sendRequestEnd      = 0;
  g_sendChunk           = 0;
  g_sendWouldBlockCount = 0;
  g_sendInterruptCount  = 0;
  g_sendFailErrno       = 0;
  g_sendFailAfter       = 0;
  g_shutdownCount       = 0;
  g_shutdownHow         = -1;
  g_shutdownAtSentLen   = 0;
  g_answer              = "";
  g_answerLen           = 0;
  g_answerOffset        = 0;
  g_recvChunk           = 0;
  g_recvWouldBlockCount = 0;
  g_recvInterruptCount  = 0;
  g_recvFailErrno       = 0;
  g_recvFailAfter       = 0;
  g_isAnswerEarly       = false;
  g_isResetAfterAnswer  = false;
  g_answerStopAt        = 0;
  g_recvCostMs          = 0;
  g_isServiceSilent     = false;
  g_closeEvents         = 0;
  g_isSendBufferFull    = false;
  g_pollCount           = 0;
  g_pollFailErrno       = 0;
  g_isAnswerBufferFailing = false;
  g_clearedByteCount    = 0;
  g_clearCount          = 0;
}

void tearDown(void) {}

static void static_answerWith(const char* answer, size_t answer_len)
{
  g_answer    = answer;
  g_answerLen = answer_len;
}

static bool static_isAnswerReadable(void)
{
  if (g_isServiceSilent || (g_answerStopAt > 0 && g_answerOffset >= g_answerStopAt))
    return false;
  return g_shutdownCount > 0 || g_isAnswerEarly;
}

void* __wrap_malloc(size_t size)
{
  if (g_isAnswerBufferFailing && size == EXIFCLIENT_MAX_RESPONSE_BYTE_COUNT + 1)
    return NULL;
  return __real_malloc(size);
}

void __wrap_explicit_bzero(void* bytes, size_t byte_count)
{
  g_clearCount++;
  g_clearedByteCount = byte_count;
  __real_explicit_bzero(bytes, byte_count);
}

void __wrap___explicit_bzero_chk(void* bytes, size_t byte_count, size_t buffer_size)
{
  TEST_ASSERT_TRUE(byte_count <= buffer_size);
  __wrap_explicit_bzero(bytes, byte_count);
}

int __wrap_clock_gettime(clockid_t clock_id, struct timespec* time_out)
{
  if (clock_id != CLOCK_MONOTONIC)
    return __real_clock_gettime(clock_id, time_out);
  time_out->tv_sec  = g_nowMs / 1000;
  time_out->tv_nsec = (long)(g_nowMs % 1000) * 1000000;
  return 0;
}

int __wrap_socket(int domain, int type, int protocol)
{
  (void)protocol;
  g_socketCallCount++;
  g_socketDomain = domain;
  g_socketType   = type;
  if (g_socketErrno != 0)
  {
    errno = g_socketErrno;
    return -1;
  }
  TEST_ASSERT_FALSE_MESSAGE(g_isOpen, "a second socket while the first is open");
  g_isOpen = true;
  return FAKE_FD;
}

int __wrap_connect(int fd, const struct sockaddr* address, socklen_t address_len)
{
  TEST_ASSERT_EQUAL_INT(FAKE_FD, fd);
  TEST_ASSERT_EQUAL_INT(AF_UNIX, address->sa_family);
  TEST_ASSERT_TRUE(address_len <= sizeof(struct sockaddr_un));
  TEST_ASSERT_TRUE(address_len >= offsetof(struct sockaddr_un, sun_path) + sizeof(EXIFCLIENT_SOCKET_PATH));
  const struct sockaddr_un* unix_address = (const struct sockaddr_un*)address;
  memcpy(g_connectPath, unix_address->sun_path, sizeof(g_connectPath));
  g_nowMs += g_connectCostMs;
  if (g_connectErrno != 0)
  {
    errno = g_connectErrno;
    return -1;
  }
  return 0;
}

ssize_t __wrap_send(int fd, const void* bytes, size_t byte_count, int flags)
{
  TEST_ASSERT_EQUAL_INT(FAKE_FD, fd);
  TEST_ASSERT_TRUE_MESSAGE((flags & MSG_NOSIGNAL) != 0, "send must not raise SIGPIPE");
  TEST_ASSERT_TRUE_MESSAGE(g_shutdownCount == 0, "send after shutdown");
  g_sendCallCount++;
  if (g_sentLen + byte_count > g_sendRequestEnd)
    g_sendRequestEnd = g_sentLen + byte_count;
  if (g_sendWouldBlockCount > 0)
  {
    g_sendWouldBlockCount--;
    errno = EAGAIN;
    return -1;
  }
  if (g_sendInterruptCount > 0)
  {
    g_sendInterruptCount--;
    errno = EINTR;
    return -1;
  }
  if (g_sendFailErrno != 0 && g_sentLen >= g_sendFailAfter)
  {
    errno = g_sendFailErrno;
    return -1;
  }
  size_t taken = byte_count;
  if (g_sendChunk > 0 && taken > g_sendChunk)
    taken = g_sendChunk;
  if (g_sendFailErrno != 0 && taken > g_sendFailAfter - g_sentLen)
    taken = g_sendFailAfter - g_sentLen;
  TEST_ASSERT_TRUE(g_sentLen + taken <= FAKE_IMAGE_MAX);
  memcpy(g_sentBytes + g_sentLen, bytes, taken);
  g_sentLen += taken;
  return (ssize_t)taken;
}

int __wrap_shutdown(int fd, int how)
{
  TEST_ASSERT_EQUAL_INT(FAKE_FD, fd);
  g_shutdownCount++;
  g_shutdownHow       = how;
  g_shutdownAtSentLen = g_sentLen;
  return 0;
}

ssize_t __wrap_recv(int fd, void* buffer, size_t buffer_size, int flags)
{
  TEST_ASSERT_EQUAL_INT(FAKE_FD, fd);
  TEST_ASSERT_TRUE_MESSAGE((flags & MSG_DONTWAIT) != 0, "recv must not block");
  TEST_ASSERT_TRUE_MESSAGE(g_answerOffset + buffer_size <= EXIFCLIENT_MAX_RESPONSE_BYTE_COUNT + 1, "recv asks past the answer's buffer");
  if (g_recvWouldBlockCount > 0)
  {
    g_recvWouldBlockCount--;
    errno = EAGAIN;
    return -1;
  }
  if (g_recvInterruptCount > 0)
  {
    g_recvInterruptCount--;
    errno = EINTR;
    return -1;
  }
  if (g_recvFailErrno != 0 && g_answerOffset >= g_recvFailAfter)
  {
    errno = g_recvFailErrno;
    return -1;
  }
  if (!static_isAnswerReadable())
  {
    errno = EAGAIN;
    return -1;
  }
  if (g_isResetAfterAnswer && g_answerOffset == g_answerLen)
  {
    errno = ECONNRESET;
    return -1;
  }
  size_t taken = g_answerLen - g_answerOffset;
  if (taken > buffer_size)
    taken = buffer_size;
  if (g_recvChunk > 0 && taken > g_recvChunk)
    taken = g_recvChunk;
  memcpy(buffer, g_answer + g_answerOffset, taken);
  g_answerOffset += taken;
  g_nowMs        += g_recvCostMs;
  return (ssize_t)taken;
}

ssize_t __wrap___recv_chk(int fd, void* buffer, size_t buffer_size, size_t buffer_object_size, int flags)
{
  TEST_ASSERT_TRUE(buffer_size <= buffer_object_size);
  return __wrap_recv(fd, buffer, buffer_size, flags);
}

int __wrap_poll(struct pollfd* poll_fds, nfds_t poll_fd_count, int timeout_ms)
{
  TEST_ASSERT_EQUAL_INT(1, (int)poll_fd_count);
  TEST_ASSERT_TRUE_MESSAGE(g_pollCount < FAKE_POLL_LIMIT, "the poll loop does not end");
  TEST_ASSERT_TRUE(timeout_ms >= 0);
  g_pollTimeouts[g_pollCount++] = timeout_ms;
  if (g_pollFailErrno != 0)
  {
    errno           = g_pollFailErrno;
    g_pollFailErrno = 0;
    return -1;
  }

  poll_fds[0].revents = 0;
  if (!g_isServiceSilent && !g_isSendBufferFull && (poll_fds[0].events & POLLOUT) != 0)
    poll_fds[0].revents |= POLLOUT;
  if (static_isAnswerReadable())
    poll_fds[0].revents |= POLLIN;
  if (static_isAnswerReadable() && g_answerOffset == g_answerLen)
    poll_fds[0].revents |= POLLHUP;
  poll_fds[0].revents |= g_closeEvents;
  if (poll_fds[0].revents == 0)
  {
    g_nowMs += timeout_ms;
    return 0;
  }
  return 1;
}

int __wrap___poll_chk(struct pollfd* poll_fds, nfds_t poll_fd_count, int timeout_ms, size_t poll_fds_size)
{
  TEST_ASSERT_TRUE(poll_fd_count * sizeof(struct pollfd) <= poll_fds_size);
  return __wrap_poll(poll_fds, poll_fd_count, timeout_ms);
}

int __wrap_close(int fd)
{
  TEST_ASSERT_EQUAL_INT(FAKE_FD, fd);
  TEST_ASSERT_TRUE_MESSAGE(g_isOpen, "the socket is closed twice");
  g_isOpen = false;
  g_closeCount++;
  return 0;
}

static void static_fillImage(unsigned char* image, size_t byte_count)
{
  for (size_t i = 0; i < byte_count; i++)
    image[i] = (unsigned char)(i * 7 + 3);
}

void test_readResponse_keeps_each_text_tag_in_its_own_field(void)
{
  ExifClientResult_t result;
  const char* json = R"([{"SourceFile":"-","IFD0:Make":"Canon","IFD0:Model":"EOS R5","IFD0:Software":"Adobe Photoshop 25.0","XMP-xmp:CreatorTool":"GIMP 2.10","XMP-iptcExt:DigitalSourceType":"http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia","CBOR:Claim_generator":"Adobe_Firefly adobe_c2pa/0.12.4","ExifIFD:DateTimeOriginal":"2024:05:06 07:08:09","ExifIFD:OffsetTimeOriginal":"+03:00","IFD0:ModifyDate":"2024:05:07 10:00:00","Composite:GPSDateTime":"2024:05:06 04:08:09Z"}])";
  TEST_ASSERT_EQUAL_INT(EXIFCLIENT_OK, static_read(json, &result));
  TEST_ASSERT_EQUAL_STRING("Canon",                result.ma_cameraMake);
  TEST_ASSERT_EQUAL_STRING("EOS R5",               result.ma_cameraModel);
  TEST_ASSERT_EQUAL_STRING("Adobe Photoshop 25.0", result.ma_software);
  TEST_ASSERT_EQUAL_STRING("GIMP 2.10",            result.ma_creatorTool);
  TEST_ASSERT_EQUAL_STRING("http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia", result.ma_digitalSourceType);
  TEST_ASSERT_EQUAL_STRING("Adobe_Firefly adobe_c2pa/0.12.4", result.ma_c2paClaimGenerator);
  TEST_ASSERT_EQUAL_STRING("2024:05:06 07:08:09",  result.ma_dateTimeOriginal);
  TEST_ASSERT_EQUAL_STRING("+03:00",               result.ma_offsetTimeOriginal);
  TEST_ASSERT_EQUAL_STRING("2024:05:07 10:00:00",  result.ma_modifyDate);
  TEST_ASSERT_EQUAL_STRING("2024:05:06 04:08:09Z", result.ma_gpsDateTime);
  TEST_ASSERT_FALSE(result.m_hasGpsPosition);
  TEST_ASSERT_EQUAL_INT(0, result.m_editHistoryEntryCount);
}

void test_readResponse_reads_a_number_as_text(void)
{
  ExifClientResult_t result;
  TEST_ASSERT_EQUAL_INT(EXIFCLIENT_OK, static_read(R"([{"IFD0:Model":5,"IFD0:Make":-1.5e3}])", &result));
  TEST_ASSERT_EQUAL_STRING("5",      result.ma_cameraModel);
  TEST_ASSERT_EQUAL_STRING("-1.5e3", result.ma_cameraMake);
}

void test_readResponse_drops_a_value_of_another_type_and_keeps_the_others(void)
{
  const char* values[] = { "true", "null", "[\"Canon\"]", "{\"a\":\"Canon\"}" };
  for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++)
  {
    char json[128];
    strcpy(json, "[{\"IFD0:Model\":\"EOS R5\",\"IFD0:Make\":");
    strcat(json, values[i]);
    strcat(json, "}]");
    ExifClientResult_t result;
    TEST_ASSERT_EQUAL_INT_MESSAGE(EXIFCLIENT_OK, static_read(json, &result), values[i]);
    TEST_ASSERT_EQUAL_STRING_MESSAGE("", result.ma_cameraMake, values[i]);
    TEST_ASSERT_EQUAL_STRING_MESSAGE("EOS R5", result.ma_cameraModel, values[i]);
  }
}

void test_readResponse_keeps_a_control_character_exiftool_escaped(void)
{
  ExifClientResult_t result;
  TEST_ASSERT_EQUAL_INT(EXIFCLIENT_OK, static_read(R"([{"IFD0:Software":"ab\u0001c","IFD0:Make":"Can\"on"}])", &result));
  TEST_ASSERT_EQUAL_STRING("ab\x01" "c", result.ma_software);
  TEST_ASSERT_EQUAL_STRING("Can\"on",   result.ma_cameraMake);
}

static void static_answerWithText(char* json, const char* key, size_t text_len)
{
  strcpy(json, "[{\"");
  strcat(json, key);
  strcat(json, "\":\"");
  size_t len = strlen(json);
  memset(json + len, 'x', text_len);
  strcpy(json + len + text_len, "\"}]");
}

typedef struct {
  const char* mp_key;
  size_t      m_fieldOffset;
  size_t      m_fieldSize;
} ExifClientTestTextField_t;

#define TEST_FIELD(type, field) offsetof(type, field), sizeof(((type*)0)->field)

void test_readResponse_keeps_a_text_that_fills_its_field_and_drops_one_byte_more(void)
{
  const ExifClientTestTextField_t result_fields[] = {
    { "IFD0:Make",                     TEST_FIELD(ExifClientResult_t, ma_cameraMake) },
    { "IFD0:Model",                    TEST_FIELD(ExifClientResult_t, ma_cameraModel) },
    { "IFD0:Software",                 TEST_FIELD(ExifClientResult_t, ma_software) },
    { "XMP-xmp:CreatorTool",           TEST_FIELD(ExifClientResult_t, ma_creatorTool) },
    { "XMP-iptcExt:DigitalSourceType", TEST_FIELD(ExifClientResult_t, ma_digitalSourceType) },
    { "CBOR:Claim_generator",          TEST_FIELD(ExifClientResult_t, ma_c2paClaimGenerator) },
    { "ExifIFD:DateTimeOriginal",      TEST_FIELD(ExifClientResult_t, ma_dateTimeOriginal) },
    { "ExifIFD:OffsetTimeOriginal",    TEST_FIELD(ExifClientResult_t, ma_offsetTimeOriginal) },
    { "IFD0:ModifyDate",               TEST_FIELD(ExifClientResult_t, ma_modifyDate) },
    { "Composite:GPSDateTime",         TEST_FIELD(ExifClientResult_t, ma_gpsDateTime) },
  };
  for (size_t i = 0; i < sizeof(result_fields) / sizeof(result_fields[0]); i++)
  {
    char               json[256];
    ExifClientResult_t result;
    const char*        field = (const char*)&result + result_fields[i].m_fieldOffset;
    for (size_t extra = 0; extra < 2; extra++)
    {
      static_answerWithText(json, result_fields[i].mp_key, result_fields[i].m_fieldSize - 1 + extra);
      TEST_ASSERT_EQUAL_INT_MESSAGE(EXIFCLIENT_OK, static_read(json, &result), result_fields[i].mp_key);
      TEST_ASSERT_EQUAL_size_t_MESSAGE(extra == 0 ? result_fields[i].m_fieldSize - 1 : 0, strlen(field), result_fields[i].mp_key);
      for (int kind = 0; kind < EXIFCLIENT_IDENTIFIER_COUNT; kind++)
        TEST_ASSERT_FALSE_MESSAGE(result.ma_isIdentifierPresent[kind], result_fields[i].mp_key);
    }
  }

  const ExifClientTestTextField_t history_fields[] = {
    { "Action",        TEST_FIELD(ExifClientHistoryEntry_t, ma_action) },
    { "When",          TEST_FIELD(ExifClientHistoryEntry_t, ma_when) },
    { "SoftwareAgent", TEST_FIELD(ExifClientHistoryEntry_t, ma_softwareAgent) },
  };
  for (size_t i = 0; i < sizeof(history_fields) / sizeof(history_fields[0]); i++)
  {
    char               json[256];
    ExifClientResult_t result;
    const char*        field = (const char*)&result.ma_editHistoryEntries[0] + history_fields[i].m_fieldOffset;
    for (size_t extra = 0; extra < 2; extra++)
    {
      strcpy(json, "[{\"XMP-xmpMM:History\":");
      static_answerWithText(json + strlen(json), history_fields[i].mp_key, history_fields[i].m_fieldSize - 1 + extra);
      strcat(json, "}]");
      TEST_ASSERT_EQUAL_INT_MESSAGE(EXIFCLIENT_OK, static_read(json, &result), history_fields[i].mp_key);
      TEST_ASSERT_EQUAL_INT(1, result.m_editHistoryEntryCount);
      TEST_ASSERT_EQUAL_size_t_MESSAGE(extra == 0 ? history_fields[i].m_fieldSize - 1 : 0, strlen(field), history_fields[i].mp_key);
    }
  }
}

void test_readResponse_leaves_no_byte_of_a_dropped_or_replaced_value(void)
{
  char               json[256];
  ExifClientResult_t result;

  static_answerWithText(json, "IFD0:Model", EXIFCLIENT_TEXT_BUF_SIZE);
  TEST_ASSERT_EQUAL_INT(EXIFCLIENT_OK, static_read(json, &result));
  TEST_ASSERT_TRUE(static_isResultZero(&result));

  TEST_ASSERT_EQUAL_INT(EXIFCLIENT_OK, static_read("[{\"IFD0:Software\":\"SECRET\\ud800\"}]", &result));
  TEST_ASSERT_TRUE(static_isResultZero(&result));
  TEST_ASSERT_EQUAL_INT(EXIFCLIENT_OK, static_read("[{\"IFD0:Software\":\"SECRET\\x\"}]", &result));
  TEST_ASSERT_TRUE(static_isResultZero(&result));

  TEST_ASSERT_EQUAL_INT(EXIFCLIENT_OK, static_read(R"([{"IFD0:Make":"LONGFIRSTVALUE","IFD0:Make":"B"}])", &result));
  TEST_ASSERT_EQUAL_STRING("B", result.ma_cameraMake);
  TEST_ASSERT_FALSE(static_isTextInResult(&result, "FIRST"));

  static_answerWithText(json, "IFD0:Make", EXIFCLIENT_TEXT_BUF_SIZE - 1);
  json[strlen(json) - 2] = '\0';
  strcat(json, R"(,"IFD0:Make":"B"}])");
  TEST_ASSERT_EQUAL_INT(EXIFCLIENT_OK, static_read(json, &result));
  TEST_ASSERT_EQUAL_STRING("B", result.ma_cameraMake);
  TEST_ASSERT_FALSE(static_isTextInResult(&result, "x"));
}

void test_readResponse_keeps_the_last_value_of_a_key_that_appears_twice(void)
{
  ExifClientResult_t result;
  TEST_ASSERT_EQUAL_INT(EXIFCLIENT_OK, static_read(R"([{"IFD0:Make":"Canon","IFD0:Make":"Nikon"}])", &result));
  TEST_ASSERT_EQUAL_STRING("Nikon", result.ma_cameraMake);

  TEST_ASSERT_EQUAL_INT(EXIFCLIENT_OK, static_read(R"([{"JUMBF:JUMDLabel":"c2pa","JUMBF:JUMDLabel":"c2pa.assertions"}])", &result));
  TEST_ASSERT_FALSE(result.m_hasC2paManifest);

  TEST_ASSERT_EQUAL_INT(EXIFCLIENT_OK, static_read(R"([{"Composite:GPSLatitude":10,"Composite:GPSLatitude":95,"Composite:GPSLongitude":20}])", &result));
  TEST_ASSERT_FALSE(result.m_hasGpsPosition);
}

void test_readResponse_skips_a_tag_it_does_not_know(void)
{
  ExifClientResult_t result;
  TEST_ASSERT_EQUAL_INT(EXIFCLIENT_OK, static_read(R"([{"SourceFile":"/home/jane/a.jpg","XMP-tiff:Make":"Leica","ExifIFD:UserComment":"meet at noon"}])", &result));
  TEST_ASSERT_TRUE(static_isResultZero(&result));
}

void test_readResponse_reads_the_gps_position_in_signed_degrees(void)
{
  ExifClientResult_t result;
  TEST_ASSERT_EQUAL_INT(EXIFCLIENT_OK, static_read(R"([{"Composite:GPSLatitude":-33.5,"Composite:GPSLongitude":28.9784,"GPS:GPSLatitude":33.5}])", &result));
  TEST_ASSERT_TRUE(result.m_hasGpsPosition);
  TEST_ASSERT_TRUE(result.m_gpsLatitude == -33.5);
  TEST_ASSERT_TRUE(result.m_gpsLongitude == 28.9784);
}

void test_readResponse_needs_both_coordinates_for_a_position(void)
{
  ExifClientResult_t result;
  TEST_ASSERT_EQUAL_INT(EXIFCLIENT_OK, static_read(R"([{"Composite:GPSLatitude":41.0082}])", &result));
  TEST_ASSERT_FALSE(result.m_hasGpsPosition);
  TEST_ASSERT_TRUE(result.m_gpsLatitude == 0.0);

  TEST_ASSERT_EQUAL_INT(EXIFCLIENT_OK, static_read(R"([{"Composite:GPSLongitude":28.9784}])", &result));
  TEST_ASSERT_FALSE(result.m_hasGpsPosition);
  TEST_ASSERT_TRUE(result.m_gpsLongitude == 0.0);

  TEST_ASSERT_EQUAL_INT(EXIFCLIENT_OK, static_read(R"([{"Composite:GPSLatitude":"41.0082","Composite:GPSLongitude":28.9784}])", &result));
  TEST_ASSERT_FALSE(result.m_hasGpsPosition);
  TEST_ASSERT_TRUE(result.m_gpsLongitude == 0.0);
}

void test_readResponse_keeps_a_coordinate_at_its_bound_and_drops_one_past_it(void)
{
  ExifClientResult_t result;
  TEST_ASSERT_EQUAL_INT(EXIFCLIENT_OK, static_read(R"([{"Composite:GPSLatitude":90,"Composite:GPSLongitude":-180}])", &result));
  TEST_ASSERT_TRUE(result.m_hasGpsPosition);
  TEST_ASSERT_TRUE(result.m_gpsLatitude == 90.0);
  TEST_ASSERT_TRUE(result.m_gpsLongitude == -180.0);

  TEST_ASSERT_EQUAL_INT(EXIFCLIENT_OK, static_read(R"([{"Composite:GPSLatitude":-90,"Composite:GPSLongitude":180}])", &result));
  TEST_ASSERT_TRUE(result.m_hasGpsPosition);
  TEST_ASSERT_TRUE(result.m_gpsLatitude == -90.0);
  TEST_ASSERT_TRUE(result.m_gpsLongitude == 180.0);

  const char* past[] = {
    R"([{"Composite:GPSLatitude":90.000001,"Composite:GPSLongitude":0.5}])",
    R"([{"Composite:GPSLatitude":-90.000001,"Composite:GPSLongitude":0.5}])",
    R"([{"Composite:GPSLatitude":0.5,"Composite:GPSLongitude":180.000001}])",
    R"([{"Composite:GPSLatitude":0.5,"Composite:GPSLongitude":-180.000001}])",
  };
  for (size_t i = 0; i < sizeof(past) / sizeof(past[0]); i++)
  {
    TEST_ASSERT_EQUAL_INT_MESSAGE(EXIFCLIENT_OK, static_read(past[i], &result), past[i]);
    TEST_ASSERT_FALSE_MESSAGE(result.m_hasGpsPosition, past[i]);
    TEST_ASSERT_TRUE_MESSAGE(result.m_gpsLatitude == 0.0 && result.m_gpsLongitude == 0.0, past[i]);
  }
}

void test_readResponse_keeps_a_jpeg_quality_from_1_to_100(void)
{
  const char* answers[]  = {
    R"([{"File:JPEGQualityEstimate":1}])",
    R"([{"File:JPEGQualityEstimate":100}])",
    R"([{"File:JPEGQualityEstimate":0}])",
    R"([{"File:JPEGQualityEstimate":101}])",
    R"([{"File:JPEGQualityEstimate":"61"}])",
    R"([{"File:JPEGQualityEstimate":61.5}])",
  };
  const int   expected[] = { 1, 100, 0, 0, 0, 0 };
  for (size_t i = 0; i < sizeof(answers) / sizeof(answers[0]); i++)
  {
    ExifClientResult_t result;
    TEST_ASSERT_EQUAL_INT_MESSAGE(EXIFCLIENT_OK, static_read(answers[i], &result), answers[i]);
    TEST_ASSERT_EQUAL_INT_MESSAGE(expected[i], result.m_jpegQualityEstimate, answers[i]);
  }
}

void test_readResponse_keeps_a_thumbnail_length_of_0_or_more(void)
{
  const char*  answers[]  = {
    R"([{"IFD1:ThumbnailLength":5120}])",
    R"([{"IFD1:ThumbnailLength":0}])",
    R"([{"IFD1:ThumbnailLength":-1}])",
    R"([{"IFD1:ThumbnailLength":"5120"}])",
  };
  const size_t expected[] = { 5120, 0, 0, 0 };
  for (size_t i = 0; i < sizeof(answers) / sizeof(answers[0]); i++)
  {
    ExifClientResult_t result;
    TEST_ASSERT_EQUAL_INT_MESSAGE(EXIFCLIENT_OK, static_read(answers[i], &result), answers[i]);
    TEST_ASSERT_EQUAL_size_t_MESSAGE(expected[i], result.m_thumbnailByteCount, answers[i]);
  }
}

void test_readResponse_reads_only_the_label_c2pa_as_a_manifest_store(void)
{
  const char* answers[]  = {
    R"([{"JUMBF:JUMDLabel":"c2pa"}])",
    R"([{"JUMBF:JUMDLabel":"c2pa.assertions"}])",
    R"([{"JUMBF:JUMDLabel":"C2PA"}])",
    R"([{"JUMBF:JUMDLabel":"c2p"}])",
    R"([{"XMP-x:JUMDLabel":"c2pa"}])",
  };
  const bool  expected[] = { true, false, false, false, false };
  for (size_t i = 0; i < sizeof(answers) / sizeof(answers[0]); i++)
  {
    ExifClientResult_t result;
    TEST_ASSERT_EQUAL_INT_MESSAGE(EXIFCLIENT_OK, static_read(answers[i], &result), answers[i]);
    TEST_ASSERT_EQUAL_INT_MESSAGE(expected[i], result.m_hasC2paManifest, answers[i]);
  }
}

void test_readResponse_marks_each_png_generator_chunk(void)
{
  const char* answers[]  = {
    R"([{"PNG:Parameters":"a cat, Steps: 20"}])",
    R"([{"PNG:Prompt":"{\"3\":{}}"}])",
    R"([{"PNG:Workflow":"{}"}])",
    R"([{"PNG:Comment":"a cat"}])",
  };
  const bool  expected[] = { true, true, true, false };
  for (size_t i = 0; i < sizeof(answers) / sizeof(answers[0]); i++)
  {
    ExifClientResult_t result;
    TEST_ASSERT_EQUAL_INT_MESSAGE(EXIFCLIENT_OK, static_read(answers[i], &result), answers[i]);
    TEST_ASSERT_EQUAL_INT_MESSAGE(expected[i], result.m_hasGeneratorParameters, answers[i]);
    TEST_ASSERT_FALSE_MESSAGE(static_isTextInResult(&result, "cat"), answers[i]);
  }
}

typedef struct {
  const char*            mp_answer;
  ExifClientIdentifier_t m_identifier;
} ExifClientTestIdentifierCase_t;

void test_readResponse_marks_each_identifier_kind_and_keeps_no_value(void)
{
  const ExifClientTestIdentifierCase_t cases[] = {
    { R"([{"ExifIFD:SerialNumber":"Jane"}])",         EXIFCLIENT_IDENTIFIER_SERIAL_NUMBER },
    { R"([{"Canon:InternalSerialNumber":"Jane"}])",   EXIFCLIENT_IDENTIFIER_SERIAL_NUMBER },
    { R"([{"ExifIFD:OwnerName":"Jane"}])",            EXIFCLIENT_IDENTIFIER_OWNER_NAME },
    { R"([{"XMP-exifEX:CameraOwnerName":"Jane"}])",   EXIFCLIENT_IDENTIFIER_OWNER_NAME },
    { R"([{"XMP-plus:CopyrightOwnerID":"Jane"}])",    EXIFCLIENT_IDENTIFIER_COPYRIGHT },
    { R"([{"XMP-xmpRights:Owner":["Jane"]}])",        EXIFCLIENT_IDENTIFIER_OWNER_NAME },
    { R"([{"ExifIFD:ImageUniqueID":"Jane"}])",        EXIFCLIENT_IDENTIFIER_UNIQUE_ID },
    { R"([{"XMP-xmpMM:OriginalDocumentID":"Jane"}])", EXIFCLIENT_IDENTIFIER_UNIQUE_ID },
    { R"([{"XMP-xmpMM:InstanceID":"Jane"}])",         EXIFCLIENT_IDENTIFIER_UNIQUE_ID },
    { R"([{"XMP-xmpMM:DerivedFromInstanceID":"Jane"}])", EXIFCLIENT_IDENTIFIER_UNIQUE_ID },
    { R"([{"XMP-xmpMM:ManagedFromInstanceID":"Jane"}])", EXIFCLIENT_IDENTIFIER_UNIQUE_ID },
    { R"([{"Leaf:BackSerial":"Jane"}])",              EXIFCLIENT_IDENTIFIER_SERIAL_NUMBER },
    { R"([{"IFD0:RawDataUniqueID":"Jane"}])",         EXIFCLIENT_IDENTIFIER_UNIQUE_ID },
    { R"([{"XMP-xmpMM:DocumentID":"Jane"}])",         EXIFCLIENT_IDENTIFIER_UNIQUE_ID },
    { R"([{"XISF:UUID":"Jane"}])",                    EXIFCLIENT_IDENTIFIER_UNIQUE_ID },
    { R"([{"Apple:BurstUUID":"Jane"}])",              EXIFCLIENT_IDENTIFIER_UNIQUE_ID },
    { R"([{"Apple:ContentIdentifier":"Jane"}])",      EXIFCLIENT_IDENTIFIER_UNIQUE_ID },
    { R"([{"XMP-photoshop:DocumentAncestors":["Jane"]}])", EXIFCLIENT_IDENTIFIER_UNIQUE_ID },
    { R"([{"XMP-xmpMM:DerivedFrom":{"DocumentID":"Jane"}}])", EXIFCLIENT_IDENTIFIER_UNIQUE_ID },
    { R"([{"XMP-xmpMM:Ingredients":[{"DocumentID":"Jane"}]}])", EXIFCLIENT_IDENTIFIER_UNIQUE_ID },
    { R"([{"XMP-xmpMM:ManagedFrom":{"DocumentID":"Jane"}}])", EXIFCLIENT_IDENTIFIER_UNIQUE_ID },
    { R"([{"XMP-xmpMM:Pantry":[{"InstanceID":"Jane"}]}])", EXIFCLIENT_IDENTIFIER_UNIQUE_ID },
    { R"([{"XMP-xmpMM:Versions":[{"Modifier":"Jane"}]}])", EXIFCLIENT_IDENTIFIER_UNIQUE_ID },
    { R"([{"XMP-dc:Identifier":"Jane"}])",            EXIFCLIENT_IDENTIFIER_UNIQUE_ID },
    { R"([{"XMP-xmpMM:IngredientsFilePath":"Jane"}])", EXIFCLIENT_IDENTIFIER_UNIQUE_ID },
    { R"([{"XMP-xmpMM:ManagedFromFilePath":"Jane"}])", EXIFCLIENT_IDENTIFIER_UNIQUE_ID },
    { R"([{"IFD0:HostComputer":"Jane"}])",            EXIFCLIENT_IDENTIFIER_HOST_COMPUTER },
    { R"([{"IFD0:Artist":"Jane"}])",                  EXIFCLIENT_IDENTIFIER_AUTHOR },
    { R"([{"XMP-dc:Creator":["Jane"]}])",             EXIFCLIENT_IDENTIFIER_AUTHOR },
    { R"([{"PNG:Author":"Jane"}])",                   EXIFCLIENT_IDENTIFIER_AUTHOR },
    { R"([{"IPTC:By-line":"Jane"}])",                 EXIFCLIENT_IDENTIFIER_AUTHOR },
    { R"([{"IFD0:XPAuthor":"Jane"}])",                EXIFCLIENT_IDENTIFIER_AUTHOR },
    { R"([{"ExifIFD:Photographer":"Jane"}])",         EXIFCLIENT_IDENTIFIER_AUTHOR },
    { R"([{"ExifIFD:ImageEditor":"Jane"}])",          EXIFCLIENT_IDENTIFIER_AUTHOR },
    { R"([{"XMP-photoshop:CaptionWriter":"Jane"}])",  EXIFCLIENT_IDENTIFIER_AUTHOR },
    { R"([{"XMP-plus:ImageCreator":[{"ImageCreatorName":"Jane"}]}])", EXIFCLIENT_IDENTIFIER_AUTHOR },
    { R"([{"XMP-plus:ImageCreatorID":"Jane"}])",      EXIFCLIENT_IDENTIFIER_AUTHOR },
    { R"([{"XMP-iptcCore:CreatorContactInfo":{"CiEmailWork":"Jane"}}])", EXIFCLIENT_IDENTIFIER_AUTHOR },
    { R"([{"XMP-iptcCore:CreatorContactInfoCiEmailWork":"Jane"}])", EXIFCLIENT_IDENTIFIER_AUTHOR },
    { R"([{"IFD0:Copyright":"Jane"}])",               EXIFCLIENT_IDENTIFIER_COPYRIGHT },
    { R"([{"IPTC:CopyrightNotice":"Jane"}])",         EXIFCLIENT_IDENTIFIER_COPYRIGHT },
    { R"([{"XMP-dc:Rights":"Jane"}])",                EXIFCLIENT_IDENTIFIER_COPYRIGHT },
    { R"([{"XMP-plus:CopyrightOwner":[{"CopyrightOwnerName":"Jane"}]}])", EXIFCLIENT_IDENTIFIER_COPYRIGHT },
    { R"([{"XMP-iptcExt:PersonInImage":["Jane"]}])",  EXIFCLIENT_IDENTIFIER_PERSON_IN_IMAGE },
    { R"([{"XMP-iptcExt:PersonInImageWDetails":[{"PersonName":"Jane"}]}])", EXIFCLIENT_IDENTIFIER_PERSON_IN_IMAGE },
    { R"([{"XMP-xmpMM:PreservedFileName":"Jane"}])",  EXIFCLIENT_IDENTIFIER_ORIGINAL_FILE_NAME },
    { R"([{"XMP-crs:RawFileName":"Jane"}])",          EXIFCLIENT_IDENTIFIER_ORIGINAL_FILE_NAME },
    { R"([{"ExifIFD:OriginalRawFileName":"Jane"}])",  EXIFCLIENT_IDENTIFIER_ORIGINAL_FILE_NAME },
    { R"([{"XMP-mwg-rs:RegionInfo":{"RegionList":[{"Name":"Jane"}]}}])", EXIFCLIENT_IDENTIFIER_PERSON_IN_IMAGE },
    { R"([{"XMP-MP:RegionInfoMP":{"Regions":[{"PersonDisplayName":"Jane"}]}}])", EXIFCLIENT_IDENTIFIER_PERSON_IN_IMAGE },
    { R"([{"XMP-xmpMM:RenditionOfManageTo":"Jane"}])", EXIFCLIENT_IDENTIFIER_ORIGINAL_FILE_NAME },
    { R"([{"QuickTime:AlbumArtistSortOrder":"Jane"}])", EXIFCLIENT_IDENTIFIER_AUTHOR },
    { R"([{"XMP-x:CaptionsAuthorNames":"Jane"}])",    EXIFCLIENT_IDENTIFIER_AUTHOR },
    { R"([{"XMP-x:ContentCreatorName":"Jane"}])",     EXIFCLIENT_IDENTIFIER_AUTHOR },
    { R"([{"DICOM:OrderCallbackPhoneNumber":"Jane"}])", EXIFCLIENT_IDENTIFIER_AUTHOR },
    { R"([{"ID3v2_4:ProducedNotice":"Jane"}])",       EXIFCLIENT_IDENTIFIER_COPYRIGHT },
    { R"([{"Panasonic:RecognizedFace1Name":"Jane"}])", EXIFCLIENT_IDENTIFIER_PERSON_IN_IMAGE },
    { R"([{"Panasonic:RecognizedFace2Name":"Jane"}])", EXIFCLIENT_IDENTIFIER_PERSON_IN_IMAGE },
    { R"([{"Panasonic:RecognizedFace3Name":"Jane"}])", EXIFCLIENT_IDENTIFIER_PERSON_IN_IMAGE },
    { R"([{"Panasonic:BabyName":"Jane"}])",            EXIFCLIENT_IDENTIFIER_PERSON_IN_IMAGE },
    { R"([{"FujiFilm:Face1Name":"Jane"}])",            EXIFCLIENT_IDENTIFIER_PERSON_IN_IMAGE },
    { R"([{"FujiFilm:Face2Name":"Jane"}])",            EXIFCLIENT_IDENTIFIER_PERSON_IN_IMAGE },
    { R"([{"FujiFilm:Face3Name":"Jane"}])",            EXIFCLIENT_IDENTIFIER_PERSON_IN_IMAGE },
    { R"([{"FujiFilm:Face4Name":"Jane"}])",            EXIFCLIENT_IDENTIFIER_PERSON_IN_IMAGE },
    { R"([{"FujiFilm:Face5Name":"Jane"}])",            EXIFCLIENT_IDENTIFIER_PERSON_IN_IMAGE },
    { R"([{"FujiFilm:Face6Name":"Jane"}])",            EXIFCLIENT_IDENTIFIER_PERSON_IN_IMAGE },
    { R"([{"FujiFilm:Face7Name":"Jane"}])",            EXIFCLIENT_IDENTIFIER_PERSON_IN_IMAGE },
    { R"([{"FujiFilm:Face8Name":"Jane"}])",            EXIFCLIENT_IDENTIFIER_PERSON_IN_IMAGE },
    { R"([{"Samsung:FaceName":"Jane"}])",              EXIFCLIENT_IDENTIFIER_PERSON_IN_IMAGE },
    { R"([{"XMP-MediaPro:People":"Jane"}])",           EXIFCLIENT_IDENTIFIER_PERSON_IN_IMAGE },
    { R"([{"XMP-prism:Person":"Jane"}])",              EXIFCLIENT_IDENTIFIER_PERSON_IN_IMAGE },
    { R"([{"XMP-GettyImages:Personality":"Jane"}])",   EXIFCLIENT_IDENTIFIER_PERSON_IN_IMAGE },
    { R"([{"XMP-iptcExt:PersonHeardName":"Jane"}])",   EXIFCLIENT_IDENTIFIER_PERSON_IN_IMAGE },
    { R"([{"Kodak:CameraOwner":"Jane"}])",             EXIFCLIENT_IDENTIFIER_OWNER_NAME },
    { R"([{"IPTC:OwnerID":"Jane"}])",                  EXIFCLIENT_IDENTIFIER_OWNER_NAME },
    { R"([{"XMP-pur:RightsOwner":"Jane"}])",           EXIFCLIENT_IDENTIFIER_OWNER_NAME },
    { R"([{"IFD1:ThumbnailArtist":"Jane"}])",          EXIFCLIENT_IDENTIFIER_AUTHOR },
    { R"([{"PNG:ExifArtist":"Jane"}])",                EXIFCLIENT_IDENTIFIER_AUTHOR },
    { R"([{"JSON:CredentialSubject":"Jane"}])",        EXIFCLIENT_IDENTIFIER_AUTHOR },
    { R"([{"PNG:ExifCopyright":"Jane"}])",             EXIFCLIENT_IDENTIFIER_COPYRIGHT },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    ExifClientResult_t result;
    TEST_ASSERT_EQUAL_INT_MESSAGE(EXIFCLIENT_OK, static_read(cases[i].mp_answer, &result), cases[i].mp_answer);
    for (int kind = 0; kind < EXIFCLIENT_IDENTIFIER_COUNT; kind++)
      TEST_ASSERT_EQUAL_INT_MESSAGE(kind == (int)cases[i].m_identifier, result.ma_isIdentifierPresent[kind], cases[i].mp_answer);
    TEST_ASSERT_FALSE_MESSAGE(static_isTextInResult(&result, "Jane"), cases[i].mp_answer);
  }
}

void test_readResponse_matches_an_identifier_by_the_tag_name_after_the_colon(void)
{
  const char* unmarked[] = {
    R"([{"XMP-xmp:CreatorTool":"GIMP"}])",
    R"([{"Serial:Make":"x"}])",
    R"([{"PhotoCD:CopyrightStatus":"x"}])",
    R"([{"IPTC:By-lineTitle":"x"}])",
    R"([{"XMP-pdfx:DocRights":"x"}])",
    R"([{"Sony:CPUVersions":"x"}])",
    R"([{"Kodak:BatteryIdentifier":"x"}])",
    R"([{"XMP-iptcExt:RegistryEntryRole":"x"}])",
    R"([{"QuickTime:ComposerKeywords":"x"}])",
    R"([{"QuickTime:PerformerKeywords":"x"}])",
    R"([{"QuickTime:SongWriterKeywords":"x"}])",
    R"([{"DICOM:CompressionContactArea":"x"}])",
    R"([{"IPTC:EditorialUpdate":"x"}])",
    R"([{"Palm:PublisherLimit":"x"}])",
    R"([{"DICOM:PersonalTitle":"x"}])",
    R"([{"XMP-x:NatureOfPersonality":"x"}])",
    R"([{"Nikon:LimitAF-AreaModeSelAutoPeople":"x"}])",
  };
  for (size_t i = 0; i < sizeof(unmarked) / sizeof(unmarked[0]); i++)
  {
    ExifClientResult_t result;
    TEST_ASSERT_EQUAL_INT_MESSAGE(EXIFCLIENT_OK, static_read(unmarked[i], &result), unmarked[i]);
    for (int kind = 0; kind < EXIFCLIENT_IDENTIFIER_COUNT; kind++)
      TEST_ASSERT_FALSE_MESSAGE(result.ma_isIdentifierPresent[kind], unmarked[i]);
  }

  ExifClientResult_t result;
  TEST_ASSERT_EQUAL_INT(EXIFCLIENT_OK, static_read(R"([{"SerialNumber":"x"}])", &result));
  TEST_ASSERT_TRUE(result.ma_isIdentifierPresent[EXIFCLIENT_IDENTIFIER_SERIAL_NUMBER]);
}

typedef struct {
  const char* mp_tagName;
  unsigned    m_kindMask;
} ExifClientTestAuthorTag_t;

#define KIND(name) (1u << EXIFCLIENT_IDENTIFIER_##name)

static const ExifClientTestAuthorTag_t AUTHOR_GROUP_TAGS[] = {
  { "AIPromptInformation",             0 },
  { "AIPromptWriterName",              KIND(AUTHOR) },
  { "AISystemUsed",                    0 },
  { "AISystemVersionUsed",             0 },
  { "AboutCvTerm",                     0 },
  { "AboutCvTermCvId",                 0 },
  { "AboutCvTermId",                   0 },
  { "AboutCvTermName",                 0 },
  { "AboutCvTermRefinedAbout",         0 },
  { "AdditionalModelInformation",      0 },
  { "AdultContentWarning",             0 },
  { "AlbumArtist",                     KIND(AUTHOR) },
  { "Artist",                          KIND(AUTHOR) },
  { "Artist2",                         KIND(AUTHOR) },
  { "ArtistURL",                       KIND(AUTHOR) },
  { "ArtworkContentDescription",       0 },
  { "ArtworkContributionDescription",  0 },
  { "ArtworkCopyrightNotice",          KIND(COPYRIGHT) },
  { "ArtworkCopyrightOwnerID",         KIND(UNIQUE_ID) | KIND(COPYRIGHT) },
  { "ArtworkCopyrightOwnerName",       KIND(OWNER_NAME) | KIND(COPYRIGHT) },
  { "ArtworkCreator",                  KIND(AUTHOR) },
  { "ArtworkCreatorID",                KIND(UNIQUE_ID) | KIND(AUTHOR) },
  { "ArtworkLicensorID",               KIND(UNIQUE_ID) | KIND(COPYRIGHT) },
  { "ArtworkLicensorName",             KIND(COPYRIGHT) },
  { "ArtworkOrObject",                 KIND(AUTHOR) },
  { "ArtworkPhysicalDescription",      0 },
  { "ArtworkSource",                   0 },
  { "ArtworkSourceInvURL",             0 },
  { "ArtworkSourceInventoryNo",        0 },
  { "ArtworkStylePeriod",              0 },
  { "ArtworkTitle",                    0 },
  { "AttributionName",                 KIND(AUTHOR) },
  { "AttributionURL",                  KIND(AUTHOR) },
  { "Author",                          KIND(AUTHOR) },
  { "AuthorIdentifier",                KIND(UNIQUE_ID) },
  { "AuthorName",                      KIND(AUTHOR) },
  { "AuthorURL",                       KIND(AUTHOR) },
  { "Authors",                         KIND(AUTHOR) },
  { "AuthorsPosition",                 0 },
  { "Authorship",                      0 },
  { "BannerImageType",                 0 },
  { "BannerImageURL",                  0 },
  { "By-line",                         KIND(AUTHOR) },
  { "By-lineTitle",                    0 },
  { "CameraOperator",                  KIND(AUTHOR) },
  { "CaptionWriter",                   KIND(AUTHOR) },
  { "Certificate",                     0 },
  { "CommentBy",                       KIND(AUTHOR) },
  { "Composer",                        KIND(AUTHOR) },
  { "Contact",                         KIND(AUTHOR) },
  { "Contributor",                     KIND(AUTHOR) },
  { "ContributorIdentifier",           KIND(AUTHOR) },
  { "ContributorName",                 KIND(AUTHOR) },
  { "ContributorRole",                 KIND(AUTHOR) },
  { "Contributors",                    KIND(AUTHOR) },
  { "ControlledVocabularyTerm",        0 },
  { "Copyright",                       KIND(COPYRIGHT) },
  { "CopyrightFlag",                   0 },
  { "CopyrightNotice",                 KIND(COPYRIGHT) },
  { "CopyrightOwner",                  KIND(COPYRIGHT) },
  { "CopyrightOwnerID",                KIND(COPYRIGHT) },
  { "CopyrightOwnerImageID",           KIND(COPYRIGHT) },
  { "CopyrightOwnerName",              KIND(OWNER_NAME) | KIND(COPYRIGHT) },
  { "CopyrightRegistrationNumber",     KIND(COPYRIGHT) },
  { "CopyrightStatus",                 0 },
  { "CopyrightURL",                    KIND(COPYRIGHT) },
  { "CreatedBy",                       KIND(AUTHOR) },
  { "Creator",                         KIND(AUTHOR) },
  { "CreatorAddress",                  KIND(AUTHOR) },
  { "CreatorCity",                     KIND(AUTHOR) },
  { "CreatorContactInfo",              KIND(AUTHOR) },
  { "CreatorCountry",                  KIND(AUTHOR) },
  { "CreatorIdentifier",               KIND(UNIQUE_ID) },
  { "CreatorName",                     KIND(AUTHOR) },
  { "CreatorPostalCode",               KIND(AUTHOR) },
  { "CreatorRegion",                   KIND(AUTHOR) },
  { "CreatorRole",                     0 },
  { "CreatorWorkEmail",                KIND(AUTHOR) },
  { "CreatorWorkTelephone",            KIND(AUTHOR) },
  { "CreatorWorkURL",                  KIND(AUTHOR) },
  { "Credit",                          KIND(AUTHOR) },
  { "CreditLineReq",                   0 },
  { "CreditLineRequired",              0 },
  { "Custom1",                         0 },
  { "Custom10",                        0 },
  { "Custom2",                         0 },
  { "Custom3",                         0 },
  { "Custom4",                         0 },
  { "Custom5",                         0 },
  { "Custom6",                         0 },
  { "Custom7",                         0 },
  { "Custom8",                         0 },
  { "Custom9",                         0 },
  { "DataMining",                      0 },
  { "DigitalImageBroker",              KIND(COPYRIGHT) },
  { "Editor",                          KIND(AUTHOR) },
  { "Email",                           KIND(AUTHOR) },
  { "EmbdEncRightsExpr",               0 },
  { "EmbeddedEncodedRightsExpr",       0 },
  { "EmbeddedEncodedRightsExprLangID", 0 },
  { "EmbeddedEncodedRightsExprType",   0 },
  { "EndUser",                         KIND(COPYRIGHT) },
  { "EndUserID",                       KIND(COPYRIGHT) },
  { "EndUserName",                     KIND(COPYRIGHT) },
  { "Event",                           0 },
  { "EventID",                         0 },
  { "FileNameAsDelivered",             KIND(ORIGINAL_FILE_NAME) },
  { "FormattedName",                   KIND(AUTHOR) },
  { "ImageAlterationConstraints",      0 },
  { "ImageCreator",                    KIND(AUTHOR) },
  { "ImageCreatorID",                  KIND(AUTHOR) },
  { "ImageCreatorImageID",             KIND(AUTHOR) },
  { "ImageCreatorName",                KIND(AUTHOR) },
  { "ImageDuplicationConstraints",     0 },
  { "ImageFileConstraints",            0 },
  { "ImageFileFormatAsDelivered",      0 },
  { "ImageFileSizeAsDelivered",        0 },
  { "ImageSupplier",                   KIND(COPYRIGHT) },
  { "ImageSupplierID",                 KIND(COPYRIGHT) },
  { "ImageSupplierImageID",            KIND(COPYRIGHT) },
  { "ImageSupplierName",               KIND(COPYRIGHT) },
  { "ImageType",                       0 },
  { "IntellectualPropertyNotes",       0 },
  { "Jurisdiction",                    0 },
  { "LastAuthor",                      KIND(AUTHOR) },
  { "LastModifiedBy",                  KIND(AUTHOR) },
  { "LastSavedBy",                     KIND(AUTHOR) },
  { "LegalCode",                       0 },
  { "License",                         0 },
  { "LicenseID",                       KIND(UNIQUE_ID) },
  { "Licensee",                        KIND(COPYRIGHT) },
  { "LicenseeID",                      KIND(COPYRIGHT) },
  { "LicenseeImageID",                 KIND(COPYRIGHT) },
  { "LicenseeImageNotes",              KIND(COPYRIGHT) },
  { "LicenseeName",                    KIND(COPYRIGHT) },
  { "LicenseeProjectReference",        KIND(COPYRIGHT) },
  { "LicenseeTransactionID",           KIND(COPYRIGHT) },
  { "Licensor",                        KIND(COPYRIGHT) },
  { "LicensorCity",                    KIND(COPYRIGHT) },
  { "LicensorCountry",                 KIND(COPYRIGHT) },
  { "LicensorEmail",                   KIND(COPYRIGHT) },
  { "LicensorExtendedAddress",         KIND(COPYRIGHT) },
  { "LicensorID",                      KIND(COPYRIGHT) },
  { "LicensorImageID",                 KIND(COPYRIGHT) },
  { "LicensorName",                    KIND(COPYRIGHT) },
  { "LicensorNotes",                   KIND(COPYRIGHT) },
  { "LicensorPostalCode",              KIND(COPYRIGHT) },
  { "LicensorRegion",                  KIND(COPYRIGHT) },
  { "LicensorStreetAddress",           KIND(COPYRIGHT) },
  { "LicensorTelephone1",              KIND(COPYRIGHT) },
  { "LicensorTelephone2",              KIND(COPYRIGHT) },
  { "LicensorTelephoneType1",          KIND(COPYRIGHT) },
  { "LicensorTelephoneType2",          KIND(COPYRIGHT) },
  { "LicensorTransactionID",           KIND(COPYRIGHT) },
  { "LicensorURL",                     KIND(COPYRIGHT) },
  { "LinkedEncRightsExpr",             0 },
  { "LinkedEncodedRightsExpr",         0 },
  { "LinkedEncodedRightsExprLangID",   0 },
  { "LinkedEncodedRightsExprType",     0 },
  { "MDItemAuthors",                   KIND(AUTHOR) },
  { "MDItemCopyright",                 KIND(COPYRIGHT) },
  { "MDItemFSCreatorCode",             0 },
  { "ManageTo",                        KIND(ORIGINAL_FILE_NAME) },
  { "Manager",                         0 },
  { "Marked",                          0 },
  { "MediaConstraints",                0 },
  { "MediaSummaryCode",                0 },
  { "MetadataAuthority",               0 },
  { "MetadataAuthorityIdentifier",     0 },
  { "MetadataAuthorityName",           0 },
  { "MetadataLastEditor",              KIND(AUTHOR) },
  { "MetadataLastEditorIdentifier",    KIND(AUTHOR) },
  { "MetadataLastEditorName",          KIND(AUTHOR) },
  { "MinorModelAgeDisclosure",         0 },
  { "ModelAge",                        0 },
  { "ModelReleaseID",                  KIND(UNIQUE_ID) },
  { "ModelReleaseStatus",              0 },
  { "MorePermissions",                 0 },
  { "Name",                            0 },
  { "Notice",                          KIND(COPYRIGHT) },
  { "OrganisationInImageCode",         0 },
  { "OrganisationInImageName",         0 },
  { "Organization",                    0 },
  { "OriginalArtist",                  KIND(AUTHOR) },
  { "OriginalAuthorName",              KIND(AUTHOR) },
  { "OriginalImageBroker",             KIND(COPYRIGHT) },
  { "OtherConditions",                 0 },
  { "OtherConstraints",                0 },
  { "OtherImageInfo",                  0 },
  { "OtherLicenseDocuments",           0 },
  { "OtherLicenseInfo",                0 },
  { "OtherLicenseRequirements",        0 },
  { "Owner",                           KIND(OWNER_NAME) },
  { "PLUSVersion",                     0 },
  { "ParentID",                        KIND(UNIQUE_ID) },
  { "Performer",                       KIND(AUTHOR) },
  { "Permits",                         0 },
  { "PersonInImage",                   KIND(PERSON_IN_IMAGE) },
  { "PersonInImageCharacteristic",     KIND(PERSON_IN_IMAGE) },
  { "PersonInImageCvTermCvId",         KIND(PERSON_IN_IMAGE) },
  { "PersonInImageCvTermId",           KIND(PERSON_IN_IMAGE) },
  { "PersonInImageCvTermName",         KIND(PERSON_IN_IMAGE) },
  { "PersonInImageCvTermRefinedAbout", KIND(PERSON_IN_IMAGE) },
  { "PersonInImageDescription",        KIND(PERSON_IN_IMAGE) },
  { "PersonInImageId",                 KIND(PERSON_IN_IMAGE) },
  { "PersonInImageName",               KIND(PERSON_IN_IMAGE) },
  { "PersonInImageWDetails",           KIND(PERSON_IN_IMAGE) },
  { "PhoneNumber",                     KIND(AUTHOR) },
  { "Photographer",                    KIND(AUTHOR) },
  { "PlanningRef",                     0 },
  { "PlanningRefIdentifier",           0 },
  { "PlanningRefName",                 0 },
  { "PlanningRefRole",                 0 },
  { "Producer",                        0 },
  { "ProductInImage",                  0 },
  { "ProductInImageDescription",       0 },
  { "ProductInImageGTIN",              0 },
  { "ProductInImageName",              0 },
  { "ProductInImageProductId",         0 },
  { "ProductOrServiceConstraints",     0 },
  { "Prohibits",                       0 },
  { "PropertyReleaseID",               KIND(UNIQUE_ID) },
  { "PropertyReleaseStatus",           0 },
  { "Publisher",                       KIND(AUTHOR) },
  { "RegionConstraints",               0 },
  { "RegistryEntryRole",               0 },
  { "RegistryID",                      KIND(UNIQUE_ID) },
  { "RegistryItemID",                  KIND(UNIQUE_ID) },
  { "RegistryOrganisationID",          KIND(UNIQUE_ID) },
  { "Requires",                        0 },
  { "Reuse",                           0 },
  { "ReuseAllowed",                    0 },
  { "Rights",                          KIND(COPYRIGHT) },
  { "Source",                          KIND(COPYRIGHT) },
  { "TermsAndConditionsText",          0 },
  { "TermsAndConditionsURL",           0 },
  { "URL",                             0 },
  { "UsageTerms",                      0 },
  { "UseGuidelines",                   0 },
  { "UserID",                          KIND(UNIQUE_ID) },
  { "UserName",                        KIND(OWNER_NAME) },
  { "WebStatement",                    0 },
  { "Writer",                          KIND(AUTHOR) },
  { "Writer-Editor",                   KIND(AUTHOR) },
  { "XPAuthor",                        KIND(AUTHOR) },
};

void test_readResponse_marks_each_author_group_tag_by_its_kind(void)
{
  TEST_ASSERT_EQUAL_size_t(245, sizeof(AUTHOR_GROUP_TAGS) / sizeof(AUTHOR_GROUP_TAGS[0]));
  for (size_t i = 0; i < sizeof(AUTHOR_GROUP_TAGS) / sizeof(AUTHOR_GROUP_TAGS[0]); i++)
  {
    char               json[128];
    ExifClientResult_t result;
    snprintf(json, sizeof(json), "[{\"XMP-x:%s\":\"Jane\"}]", AUTHOR_GROUP_TAGS[i].mp_tagName);
    TEST_ASSERT_EQUAL_INT_MESSAGE(EXIFCLIENT_OK, static_read(json, &result), json);
    for (int kind = 0; kind < EXIFCLIENT_IDENTIFIER_COUNT; kind++)
      TEST_ASSERT_EQUAL_INT_MESSAGE((AUTHOR_GROUP_TAGS[i].m_kindMask >> kind) & 1u, result.ma_isIdentifierPresent[kind], json);
    TEST_ASSERT_FALSE_MESSAGE(static_isTextInResult(&result, "Jane"), json);
  }
}

void test_readResponse_matches_a_whole_tag_name_with_a_language_code(void)
{
  const ExifClientTestIdentifierCase_t marked[] = {
    { R"([{"XMP-dc:Rights-fr":"Jane"}])",          EXIFCLIENT_IDENTIFIER_COPYRIGHT },
    { R"([{"Font:Copyright-en-US":"Jane"}])",      EXIFCLIENT_IDENTIFIER_COPYRIGHT },
    { R"([{"MIE-Doc:Copyright-en_US":"Jane"}])",   EXIFCLIENT_IDENTIFIER_COPYRIGHT },
    { R"([{"XMP-dc:Rights-a":"Jane"}])",           EXIFCLIENT_IDENTIFIER_COPYRIGHT },
    { R"([{"XMP-dc:Rights-z":"Jane"}])",           EXIFCLIENT_IDENTIFIER_COPYRIGHT },
    { R"([{"XMP-x:By-line-de":"Jane"}])",          EXIFCLIENT_IDENTIFIER_AUTHOR },
  };
  for (size_t i = 0; i < sizeof(marked) / sizeof(marked[0]); i++)
  {
    ExifClientResult_t result;
    TEST_ASSERT_EQUAL_INT_MESSAGE(EXIFCLIENT_OK, static_read(marked[i].mp_answer, &result), marked[i].mp_answer);
    for (int kind = 0; kind < EXIFCLIENT_IDENTIFIER_COUNT; kind++)
      TEST_ASSERT_EQUAL_INT_MESSAGE(kind == (int)marked[i].m_identifier, result.ma_isIdentifierPresent[kind], marked[i].mp_answer);
  }

  const char* unmarked[] = {
    R"([{"XMP-dc:Rights-`":"x"}])",
    R"([{"XMP-dc:Rights-{":"x"}])",
    R"([{"XMP-dc:Rights-FR":"x"}])",
    R"([{"XMP-dc:Rights-":"x"}])",
    R"([{"XMP-dc:Rights_fr":"x"}])",
    R"([{"XMP-dc:Right":"x"}])",
    R"([{"XMP-dc:Rightz":"x"}])",
    R"([{"XMP-dc:rights":"x"}])",
  };
  for (size_t i = 0; i < sizeof(unmarked) / sizeof(unmarked[0]); i++)
  {
    ExifClientResult_t result;
    TEST_ASSERT_EQUAL_INT_MESSAGE(EXIFCLIENT_OK, static_read(unmarked[i], &result), unmarked[i]);
    for (int kind = 0; kind < EXIFCLIENT_IDENTIFIER_COUNT; kind++)
      TEST_ASSERT_FALSE_MESSAGE(result.ma_isIdentifierPresent[kind], unmarked[i]);
  }
}

void test_readResponse_keeps_the_c2pa_claim_generator(void)
{
  const char* answers[] = {
    R"([{"CBOR:Claim_generator":"Adobe_Firefly adobe_c2pa/0.12.4","CBOR:Claim_generator_info":"null"}])",
    R"([{"CBOR:Claim_generator_info":{"name":"make_test_images","version":"0.67.1"}}])",
    R"([{"CBOR:Claim_generator_info":[{"name":"GIMP","version":"3.0"},{"name":"c2pa-rs"}]}])",
    R"([{"CBOR:Claim_generator_info":{"name":"GIMP"},"CBOR:Claim_generator":"Photoshop"}])",
    R"([{"CBOR:Claim_generator":"Photoshop","CBOR:Claim_generator_info":{"name":"GIMP"}}])",
    R"([{"CBOR:Claim_generator_info":{"name":"GIMP"},"CBOR:Claim_generator_info":{"name":"Krita"}}])",
    R"([{"CBOR:Claim_generator_info":[]}])",
    R"([{"CBOR:Claim_generator_info":{"version":"1.0"}}])",
    R"([{"CBOR:Claim_generator_info":{"name":{"text":"GIMP"}}}])",
    R"([{"CBOR:Claim_generator_info":[{"version":"1.0"},{"name":"GIMP"}]}])",
    R"([{"XMP-x:Claim_generator_info":{"name":"GIMP"}}])",
  };
  const char* expected[] = {
    "Adobe_Firefly adobe_c2pa/0.12.4",
    "make_test_images",
    "GIMP",
    "Photoshop",
    "Photoshop",
    "GIMP",
    "",
    "",
    "",
    "",
    "",
  };
  for (size_t i = 0; i < sizeof(answers) / sizeof(answers[0]); i++)
  {
    ExifClientResult_t result;
    TEST_ASSERT_EQUAL_INT_MESSAGE(EXIFCLIENT_OK, static_read(answers[i], &result), answers[i]);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(expected[i], result.ma_c2paClaimGenerator, answers[i]);
  }
}

void test_readResponse_keeps_a_claim_generator_name_that_fills_its_field_and_drops_one_byte_more(void)
{
  char               json[512];
  ExifClientResult_t result;
  for (size_t extra = 0; extra < 2; extra++)
  {
    size_t name_len = sizeof(result.ma_c2paClaimGenerator) - 1 + extra;
    strcpy(json, "[{\"CBOR:Claim_generator_info\":{\"name\":\"");
    size_t len = strlen(json);
    memset(json + len, 'x', name_len);
    strcpy(json + len + name_len, "\"}}]");
    TEST_ASSERT_EQUAL_INT(EXIFCLIENT_OK, static_read(json, &result));
    TEST_ASSERT_EQUAL_size_t(extra == 0 ? name_len : 0, strlen(result.ma_c2paClaimGenerator));
  }
}

void test_readResponse_keeps_a_claim_generator_name_written_as_a_number(void)
{
  ExifClientResult_t result;
  TEST_ASSERT_EQUAL_INT(EXIFCLIENT_OK, static_read(R"([{"CBOR:Claim_generator_info":{"name":5}}])", &result));
  TEST_ASSERT_EQUAL_STRING("5", result.ma_c2paClaimGenerator);
}

void test_readResponse_keeps_a_one_byte_claim_generator_name_before_a_second_info(void)
{
  ExifClientResult_t result;
  TEST_ASSERT_EQUAL_INT(EXIFCLIENT_OK, static_read(R"([{"CBOR:Claim_generator_info":{"name":"G"},"CBOR:Claim_generator_info":{"name":"Krita"}}])", &result));
  TEST_ASSERT_EQUAL_STRING("G", result.ma_c2paClaimGenerator);
}

void test_readResponse_keeps_the_action_time_and_software_of_a_history_entry(void)
{
  ExifClientResult_t result;
  const char* json = R"([{"XMP-xmpMM:History":[{"Action":"saved","Changed":"/metadata","InstanceID":"xmp.iid:1","Parameters":"C:\\Users\\jane\\x.psd","SoftwareAgent":"Adobe Photoshop 25.0","When":"2024:05:06 08:00:00+03:00"},{"Action":"converted","When":7,"SoftwareAgent":"GIMP"}]}])";
  TEST_ASSERT_EQUAL_INT(EXIFCLIENT_OK, static_read(json, &result));
  TEST_ASSERT_EQUAL_INT(2, result.m_editHistoryEntryCount);
  TEST_ASSERT_FALSE(result.m_hasMoreEditHistoryEntries);
  TEST_ASSERT_EQUAL_STRING("saved",                     result.ma_editHistoryEntries[0].ma_action);
  TEST_ASSERT_EQUAL_STRING("2024:05:06 08:00:00+03:00", result.ma_editHistoryEntries[0].ma_when);
  TEST_ASSERT_EQUAL_STRING("Adobe Photoshop 25.0",      result.ma_editHistoryEntries[0].ma_softwareAgent);
  TEST_ASSERT_EQUAL_STRING("converted",                 result.ma_editHistoryEntries[1].ma_action);
  TEST_ASSERT_EQUAL_STRING("7",                         result.ma_editHistoryEntries[1].ma_when);
  TEST_ASSERT_EQUAL_STRING("GIMP",                      result.ma_editHistoryEntries[1].ma_softwareAgent);
  TEST_ASSERT_FALSE(static_isTextInResult(&result, "jane"));
  TEST_ASSERT_FALSE(static_isTextInResult(&result, "xmp.iid"));
  TEST_ASSERT_FALSE(static_isTextInResult(&result, "/metadata"));
  TEST_ASSERT_FALSE(result.ma_isIdentifierPresent[EXIFCLIENT_IDENTIFIER_UNIQUE_ID]);
}

static void static_answerWithHistory(char* json, int entry_count)
{
  strcpy(json, "[{\"XMP-xmpMM:History\":[");
  for (int i = 0; i < entry_count; i++)
  {
    char entry[32];
    snprintf(entry, sizeof(entry), "%s{\"Action\":\"a%d\"}", i == 0 ? "" : ",", i);
    strcat(json, entry);
  }
  strcat(json, "]}]");
}

void test_readResponse_keeps_16_history_entries_and_reports_more_after_them(void)
{
  char               json[1024];
  ExifClientResult_t result;

  static_answerWithHistory(json, EXIFCLIENT_KEPT_HISTORY_ENTRY_COUNT - 1);
  TEST_ASSERT_EQUAL_INT(EXIFCLIENT_OK, static_read(json, &result));
  TEST_ASSERT_EQUAL_INT(EXIFCLIENT_KEPT_HISTORY_ENTRY_COUNT - 1, result.m_editHistoryEntryCount);
  TEST_ASSERT_FALSE(result.m_hasMoreEditHistoryEntries);

  static_answerWithHistory(json, EXIFCLIENT_KEPT_HISTORY_ENTRY_COUNT);
  TEST_ASSERT_EQUAL_INT(EXIFCLIENT_OK, static_read(json, &result));
  TEST_ASSERT_EQUAL_INT(EXIFCLIENT_KEPT_HISTORY_ENTRY_COUNT, result.m_editHistoryEntryCount);
  TEST_ASSERT_FALSE(result.m_hasMoreEditHistoryEntries);
  TEST_ASSERT_EQUAL_STRING("a15", result.ma_editHistoryEntries[EXIFCLIENT_KEPT_HISTORY_ENTRY_COUNT - 1].ma_action);

  static_answerWithHistory(json, EXIFCLIENT_KEPT_HISTORY_ENTRY_COUNT + 1);
  TEST_ASSERT_EQUAL_INT(EXIFCLIENT_OK, static_read(json, &result));
  TEST_ASSERT_EQUAL_INT(EXIFCLIENT_KEPT_HISTORY_ENTRY_COUNT, result.m_editHistoryEntryCount);
  TEST_ASSERT_TRUE(result.m_hasMoreEditHistoryEntries);
  TEST_ASSERT_EQUAL_STRING("a15", result.ma_editHistoryEntries[EXIFCLIENT_KEPT_HISTORY_ENTRY_COUNT - 1].ma_action);
}

void test_readResponse_lets_a_second_history_replace_the_first(void)
{
  char               json[1024];
  ExifClientResult_t result;
  static_answerWithHistory(json, EXIFCLIENT_KEPT_HISTORY_ENTRY_COUNT + 1);
  json[strlen(json) - 2] = '\0';
  strcat(json, R"(,"XMP-xmpMM:History":[{"Action":"edited"}]}])");

  TEST_ASSERT_EQUAL_INT(EXIFCLIENT_OK, static_read(json, &result));
  TEST_ASSERT_EQUAL_INT(1, result.m_editHistoryEntryCount);
  TEST_ASSERT_FALSE(result.m_hasMoreEditHistoryEntries);
  TEST_ASSERT_EQUAL_STRING("edited", result.ma_editHistoryEntries[0].ma_action);
  TEST_ASSERT_EQUAL_STRING("",       result.ma_editHistoryEntries[1].ma_action);
}

void test_readResponse_reads_a_history_that_is_not_an_array_as_no_entries(void)
{
  ExifClientResult_t result;
  TEST_ASSERT_EQUAL_INT(EXIFCLIENT_OK, static_read(R"([{"XMP-xmpMM:History":{"Action":"saved"}}])", &result));
  TEST_ASSERT_EQUAL_INT(0, result.m_editHistoryEntryCount);

  TEST_ASSERT_EQUAL_INT(EXIFCLIENT_OK, static_read(R"([{"XMP-xmpMM:History":["saved",{"Action":"edited"}]}])", &result));
  TEST_ASSERT_EQUAL_INT(2, result.m_editHistoryEntryCount);
  TEST_ASSERT_EQUAL_STRING("",       result.ma_editHistoryEntries[0].ma_action);
  TEST_ASSERT_EQUAL_STRING("edited", result.ma_editHistoryEntries[1].ma_action);
}

void test_readResponse_refuses_an_exiftool_error_and_leaves_the_result_zero(void)
{
  ExifClientResult_t result;
  TEST_ASSERT_EQUAL_INT(EXIFCLIENT_ERR_REFUSED, static_read(R"([{"IFD0:Make":"Canon","ExifTool:Error":"File is empty","IFD0:Artist":"Jane"}])", &result));
  TEST_ASSERT_TRUE(static_isResultZero(&result));

  TEST_ASSERT_EQUAL_INT(EXIFCLIENT_OK, static_read(R"([{"IFD0:Make":"Canon","ExifTool:Warning":"JPEG format error"}])", &result));
  TEST_ASSERT_EQUAL_STRING("Canon", result.ma_cameraMake);
}

void test_readResponse_refuses_a_malformed_answer_and_leaves_the_result_zero(void)
{
  const char* answers[] = {
    "",
    "{\"IFD0:Make\":\"Canon\"}",
    "[]",
    "[{\"IFD0:Make\":\"Canon\"},{}]",
    "[\"IFD0:Make\"]",
    "[{\"IFD0:Make\":\"Canon\"}",
    "[{\"IFD0:Make\":\"Canon\"}] x",
    "[{\"IFD0:Make\":\"Canon\",}]",
  };
  for (size_t i = 0; i < sizeof(answers) / sizeof(answers[0]); i++)
  {
    ExifClientResult_t result;
    memset(&result, 0x5a, sizeof(result));
    TEST_ASSERT_EQUAL_INT_MESSAGE(EXIFCLIENT_ERR_MALFORMED, static_read(answers[i], &result), answers[i]);
    TEST_ASSERT_TRUE_MESSAGE(static_isResultZero(&result), answers[i]);
  }

  ExifClientResult_t result;
  TEST_ASSERT_EQUAL_INT(EXIFCLIENT_ERR_MALFORMED, exifclient_readResponse(NULL, 0, &result));
  TEST_ASSERT_TRUE(static_isResultZero(&result));
}

void test_inspect_sends_the_image_shuts_down_and_reads_the_answer(void)
{
  static unsigned char image[3000];
  static_fillImage(image, sizeof(image));
  const char* answer = R"([{"SourceFile":"-","IFD0:Make":"Canon"}])";
  static_answerWith(answer, strlen(answer));
  g_sendChunk = 1000;
  g_recvChunk = 7;

  ExifClientResult_t result;
  TEST_ASSERT_EQUAL_INT(EXIFCLIENT_OK, exifclient_inspect(image, sizeof(image), &result));
  TEST_ASSERT_EQUAL_STRING("Canon", result.ma_cameraMake);
  TEST_ASSERT_EQUAL_INT(AF_UNIX, g_socketDomain);
  TEST_ASSERT_EQUAL_INT(SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, g_socketType);
  TEST_ASSERT_EQUAL_STRING(EXIFCLIENT_SOCKET_PATH, g_connectPath);
  TEST_ASSERT_EQUAL_size_t(sizeof(image), g_sentLen);
  TEST_ASSERT_EQUAL_MEMORY(image, g_sentBytes, sizeof(image));
  TEST_ASSERT_EQUAL_INT(3, g_sendCallCount);
  TEST_ASSERT_EQUAL_size_t(sizeof(image), g_sendRequestEnd);
  TEST_ASSERT_EQUAL_INT(1, g_shutdownCount);
  TEST_ASSERT_EQUAL_INT(SHUT_WR, g_shutdownHow);
  TEST_ASSERT_EQUAL_size_t(sizeof(image), g_shutdownAtSentLen);
  TEST_ASSERT_EQUAL_size_t(strlen(answer), g_answerOffset);
  TEST_ASSERT_EQUAL_INT(1, g_closeCount);
  TEST_ASSERT_EQUAL_INT(1, g_clearCount);
  TEST_ASSERT_EQUAL_size_t(strlen(answer), g_clearedByteCount);
}

void test_inspect_retries_a_send_and_a_read_that_would_block_or_are_interrupted(void)
{
  unsigned char image[64];
  static_fillImage(image, sizeof(image));
  const char* answer = R"([{"IFD0:Model":"EOS R5"}])";
  static_answerWith(answer, strlen(answer));
  g_sendWouldBlockCount = 2;
  g_recvWouldBlockCount = 2;
  g_sendInterruptCount  = 1;
  g_recvInterruptCount  = 1;

  ExifClientResult_t result;
  TEST_ASSERT_EQUAL_INT(EXIFCLIENT_OK, exifclient_inspect(image, sizeof(image), &result));
  TEST_ASSERT_EQUAL_STRING("EOS R5", result.ma_cameraModel);
  TEST_ASSERT_EQUAL_size_t(sizeof(image), g_sentLen);
  TEST_ASSERT_EQUAL_INT(1, g_shutdownCount);
}

void test_inspect_reads_the_answer_after_the_service_stops_reading(void)
{
  unsigned char image[4000];
  static_fillImage(image, sizeof(image));
  const char* answer = R"([{"ExifTool:Error":"File format error"}])";
  static_answerWith(answer, strlen(answer));
  g_isAnswerEarly = true;
  g_sendFailErrno = EPIPE;
  g_sendFailAfter = 100;
  g_recvChunk     = 5;
  g_isResetAfterAnswer = true;

  ExifClientResult_t result;
  TEST_ASSERT_EQUAL_INT(EXIFCLIENT_ERR_REFUSED, exifclient_inspect(image, sizeof(image), &result));
  TEST_ASSERT_EQUAL_size_t(100, g_sentLen);
  TEST_ASSERT_EQUAL_INT(2, g_sendCallCount);
  TEST_ASSERT_EQUAL_size_t(strlen(answer), g_answerOffset);
  TEST_ASSERT_EQUAL_INT(0, g_shutdownCount);
  TEST_ASSERT_EQUAL_INT(1, g_closeCount);
  TEST_ASSERT_EQUAL_size_t(strlen(answer), g_clearedByteCount);
}

void test_inspect_stops_sending_when_the_service_has_closed(void)
{
  const short close_events[] = { POLLHUP, POLLERR };
  for (size_t i = 0; i < sizeof(close_events) / sizeof(close_events[0]); i++)
  {
    setUp();
    unsigned char image[4000];
    static_fillImage(image, sizeof(image));
    const char* answer = R"([{"ExifTool:Error":"File format error"}])";
    static_answerWith(answer, strlen(answer));
    g_isAnswerEarly = true;
    g_closeEvents   = close_events[i];

    ExifClientResult_t result;
    TEST_ASSERT_EQUAL_INT(EXIFCLIENT_ERR_REFUSED, exifclient_inspect(image, sizeof(image), &result));
    TEST_ASSERT_EQUAL_INT(0, g_sendCallCount);
    TEST_ASSERT_EQUAL_INT(0, g_shutdownCount);
    TEST_ASSERT_EQUAL_size_t(strlen(answer), g_answerOffset);
  }
}

void test_inspect_reads_the_answer_while_the_socket_takes_no_bytes(void)
{
  unsigned char image[4000];
  static_fillImage(image, sizeof(image));
  const char* answer = R"([{"ExifTool:Error":"File format error"}])";
  static_answerWith(answer, strlen(answer));
  g_isAnswerEarly    = true;
  g_isSendBufferFull = true;

  ExifClientResult_t result;
  TEST_ASSERT_EQUAL_INT(EXIFCLIENT_ERR_REFUSED, exifclient_inspect(image, sizeof(image), &result));
  TEST_ASSERT_EQUAL_INT(0, g_sendCallCount);
  TEST_ASSERT_EQUAL_size_t(strlen(answer), g_answerOffset);
}

void test_inspect_shuts_down_at_once_for_an_empty_image(void)
{
  const char* answer = R"([{"ExifTool:Error":"File is empty"}])";
  static_answerWith(answer, strlen(answer));

  ExifClientResult_t result;
  TEST_ASSERT_EQUAL_INT(EXIFCLIENT_ERR_REFUSED, exifclient_inspect(NULL, 0, &result));
  TEST_ASSERT_EQUAL_size_t(strlen(answer), g_clearedByteCount);
  TEST_ASSERT_EQUAL_INT(0, g_sendCallCount);
  TEST_ASSERT_EQUAL_INT(1, g_shutdownCount);
  TEST_ASSERT_EQUAL_INT(SHUT_WR, g_shutdownHow);
}

void test_inspect_answers_connect_error_when_the_socket_or_the_connection_fails(void)
{
  unsigned char image[16];
  static_fillImage(image, sizeof(image));
  ExifClientResult_t result;

  g_socketErrno = EMFILE;
  TEST_ASSERT_EQUAL_INT(EXIFCLIENT_ERR_CONNECT, exifclient_inspect(image, sizeof(image), &result));
  TEST_ASSERT_EQUAL_INT(0, g_closeCount);
  TEST_ASSERT_EQUAL_INT(0, g_pollCount);

  const int connect_errnos[] = { ENOENT, ECONNREFUSED, EAGAIN };
  for (size_t i = 0; i < sizeof(connect_errnos) / sizeof(connect_errnos[0]); i++)
  {
    setUp();
    g_connectErrno = connect_errnos[i];
    memset(&result, 0x5a, sizeof(result));
    TEST_ASSERT_EQUAL_INT(EXIFCLIENT_ERR_CONNECT, exifclient_inspect(image, sizeof(image), &result));
    TEST_ASSERT_EQUAL_INT(1, g_closeCount);
    TEST_ASSERT_EQUAL_INT(0, g_pollCount);
    TEST_ASSERT_EQUAL_INT(0, g_sendCallCount);
    TEST_ASSERT_EQUAL_INT(0, result.m_editHistoryEntryCount);
  }
}

void test_inspect_answers_no_memory_before_it_connects(void)
{
  unsigned char image[16];
  static_fillImage(image, sizeof(image));
  g_isAnswerBufferFailing = true;

  ExifClientResult_t result;
  memset(&result, 0x5a, sizeof(result));
  TEST_ASSERT_EQUAL_INT(EXIFCLIENT_ERR_NO_MEMORY, exifclient_inspect(image, sizeof(image), &result));
  TEST_ASSERT_EQUAL_INT(0, g_socketCallCount);
  TEST_ASSERT_TRUE(static_isResultZero(&result));
}

void test_inspect_waits_until_the_deadline_counted_from_its_start(void)
{
  unsigned char image[16];
  static_fillImage(image, sizeof(image));
  g_isServiceSilent = true;
  g_connectCostMs   = 1000;

  ExifClientResult_t result;
  TEST_ASSERT_EQUAL_INT(EXIFCLIENT_ERR_DEADLINE, exifclient_inspect(image, sizeof(image), &result));
  TEST_ASSERT_EQUAL_INT(1, g_pollCount);
  TEST_ASSERT_EQUAL_INT(EXIFCLIENT_DEADLINE_MS - 1000, g_pollTimeouts[0]);
  TEST_ASSERT_EQUAL_INT(1, g_closeCount);
  TEST_ASSERT_EQUAL_INT(1, g_clearCount);
}

void test_inspect_waits_for_the_rest_of_the_deadline_after_a_partial_answer(void)
{
  unsigned char image[16];
  static_fillImage(image, sizeof(image));
  const char* answer = R"([{"IFD0:Make":"Canon","IFD0:Model":"EOS R5"}])";
  static_answerWith(answer, strlen(answer));
  g_recvChunk    = 10;
  g_answerStopAt = 20;
  g_recvCostMs   = 100;

  ExifClientResult_t result;
  TEST_ASSERT_EQUAL_INT(EXIFCLIENT_ERR_DEADLINE, exifclient_inspect(image, sizeof(image), &result));
  TEST_ASSERT_EQUAL_INT(4, g_pollCount);
  TEST_ASSERT_EQUAL_INT(EXIFCLIENT_DEADLINE_MS - 200, g_pollTimeouts[3]);
  TEST_ASSERT_EQUAL_size_t(20, g_clearedByteCount);
  TEST_ASSERT_EQUAL_STRING("", result.ma_cameraMake);
}

void test_inspect_ends_at_the_deadline_while_the_service_trickles(void)
{
  unsigned char image[16];
  static_fillImage(image, sizeof(image));
  const char* answer = R"([{"IFD0:Make":"Canon"}])";
  static_answerWith(answer, strlen(answer));
  g_recvChunk  = 1;
  g_recvCostMs = 6000;

  ExifClientResult_t result;
  TEST_ASSERT_EQUAL_INT(EXIFCLIENT_ERR_DEADLINE, exifclient_inspect(image, sizeof(image), &result));
  TEST_ASSERT_EQUAL_size_t(3, g_answerOffset);
  TEST_ASSERT_EQUAL_size_t(3, g_clearedByteCount);
  TEST_ASSERT_EQUAL_INT(1, g_closeCount);
}

void test_inspect_counts_the_deadline_after_24_days_of_uptime(void)
{
  unsigned char image[16];
  static_fillImage(image, sizeof(image));
  g_nowMs           = 2147483000;
  g_isServiceSilent = true;
  g_connectCostMs   = 1000;

  ExifClientResult_t result;
  TEST_ASSERT_EQUAL_INT(EXIFCLIENT_ERR_DEADLINE, exifclient_inspect(image, sizeof(image), &result));
  TEST_ASSERT_EQUAL_INT(1, g_pollCount);
  TEST_ASSERT_EQUAL_INT(EXIFCLIENT_DEADLINE_MS - 1000, g_pollTimeouts[0]);
}

void test_inspect_answers_transfer_error_when_poll_or_recv_fails(void)
{
  unsigned char image[16];
  static_fillImage(image, sizeof(image));
  const char* answer = R"([{"IFD0:Make":"Canon"}])";
  ExifClientResult_t result;

  static_answerWith(answer, strlen(answer));
  g_pollFailErrno = EBADF;
  TEST_ASSERT_EQUAL_INT(EXIFCLIENT_ERR_TRANSFER, exifclient_inspect(image, sizeof(image), &result));
  TEST_ASSERT_EQUAL_INT(1, g_closeCount);
  TEST_ASSERT_EQUAL_INT(1, g_clearCount);

  setUp();
  static_answerWith(answer, strlen(answer));
  g_recvFailErrno = ENOTCONN;
  TEST_ASSERT_EQUAL_INT(EXIFCLIENT_ERR_TRANSFER, exifclient_inspect(image, sizeof(image), &result));
  TEST_ASSERT_EQUAL_INT(1, g_closeCount);
  TEST_ASSERT_EQUAL_INT(1, g_clearCount);

  setUp();
  const char* long_answer = R"([{"IFD0:Make":"Canon","IFD0:Model":"EOS R5"}])";
  static_answerWith(long_answer, strlen(long_answer));
  g_recvChunk     = 10;
  g_recvFailErrno = ENOTCONN;
  g_recvFailAfter = 20;
  memset(&result, 0x5a, sizeof(result));
  TEST_ASSERT_EQUAL_INT(EXIFCLIENT_ERR_TRANSFER, exifclient_inspect(image, sizeof(image), &result));
  TEST_ASSERT_EQUAL_size_t(20, g_clearedByteCount);
  TEST_ASSERT_TRUE(static_isResultZero(&result));

  setUp();
  static_answerWith(answer, strlen(answer));
  g_pollFailErrno = EINTR;
  TEST_ASSERT_EQUAL_INT(EXIFCLIENT_OK, exifclient_inspect(image, sizeof(image), &result));
  TEST_ASSERT_EQUAL_STRING("Canon", result.ma_cameraMake);
}

static char* static_answerOfLength(size_t byte_count)
{
  const char* head = R"([{"IFD0:Make":"Canon"})";
  char*       text = malloc(byte_count + 1);
  TEST_ASSERT_NOT_NULL(text);
  size_t head_len = strlen(head);
  memcpy(text, head, head_len);
  memset(text + head_len, ' ', byte_count - head_len - 1);
  text[byte_count - 1] = ']';
  text[byte_count]     = '\0';
  return text;
}

void test_inspect_reads_an_answer_of_256_KiB_and_refuses_one_byte_more(void)
{
  unsigned char image[16];
  static_fillImage(image, sizeof(image));
  ExifClientResult_t result;

  char* answer = static_answerOfLength(EXIFCLIENT_MAX_RESPONSE_BYTE_COUNT);
  static_answerWith(answer, EXIFCLIENT_MAX_RESPONSE_BYTE_COUNT);
  TEST_ASSERT_EQUAL_INT(EXIFCLIENT_OK, exifclient_inspect(image, sizeof(image), &result));
  TEST_ASSERT_EQUAL_STRING("Canon", result.ma_cameraMake);
  TEST_ASSERT_EQUAL_size_t(EXIFCLIENT_MAX_RESPONSE_BYTE_COUNT, g_clearedByteCount);
  free(answer);

  setUp();
  answer = static_answerOfLength(EXIFCLIENT_MAX_RESPONSE_BYTE_COUNT + 1);
  static_answerWith(answer, EXIFCLIENT_MAX_RESPONSE_BYTE_COUNT + 1);
  TEST_ASSERT_EQUAL_INT(EXIFCLIENT_ERR_TOO_LARGE, exifclient_inspect(image, sizeof(image), &result));
  TEST_ASSERT_EQUAL_STRING("", result.ma_cameraMake);
  TEST_ASSERT_EQUAL_size_t(EXIFCLIENT_MAX_RESPONSE_BYTE_COUNT + 1, g_clearedByteCount);
  TEST_ASSERT_EQUAL_INT(1, g_closeCount);
  free(answer);

  setUp();
  answer = static_answerOfLength(EXIFCLIENT_MAX_RESPONSE_BYTE_COUNT + 50000);
  static_answerWith(answer, EXIFCLIENT_MAX_RESPONSE_BYTE_COUNT + 50000);
  g_recvChunk = 100000;
  TEST_ASSERT_EQUAL_INT(EXIFCLIENT_ERR_TOO_LARGE, exifclient_inspect(image, sizeof(image), &result));
  TEST_ASSERT_EQUAL_size_t(EXIFCLIENT_MAX_RESPONSE_BYTE_COUNT + 1, g_answerOffset);
  TEST_ASSERT_EQUAL_size_t(EXIFCLIENT_MAX_RESPONSE_BYTE_COUNT + 1, g_clearedByteCount);
  free(answer);
}

void test_inspect_passes_a_malformed_answer_on(void)
{
  unsigned char image[16];
  static_fillImage(image, sizeof(image));
  static_answerWith("[{", 2);

  ExifClientResult_t result;
  TEST_ASSERT_EQUAL_INT(EXIFCLIENT_ERR_MALFORMED, exifclient_inspect(image, sizeof(image), &result));
  TEST_ASSERT_EQUAL_INT(1, g_closeCount);
  TEST_ASSERT_EQUAL_size_t(2, g_clearedByteCount);

  setUp();
  g_recvFailErrno = ECONNRESET;
  TEST_ASSERT_EQUAL_INT(EXIFCLIENT_ERR_MALFORMED, exifclient_inspect(image, sizeof(image), &result));
  TEST_ASSERT_EQUAL_INT(1, g_closeCount);
}

void test_registration_gate_test_count(void)
{
  TEST_ASSERT_EQUAL_INT_MESSAGE(45, (int)Unity.NumberOfTests,
    "RUN_TEST list and test definitions have drifted apart - a test may be unregistered");
}

int main(void)
{
  UNITY_BEGIN();
  RUN_TEST(test_readResponse_keeps_each_text_tag_in_its_own_field);
  RUN_TEST(test_readResponse_reads_a_number_as_text);
  RUN_TEST(test_readResponse_drops_a_value_of_another_type_and_keeps_the_others);
  RUN_TEST(test_readResponse_keeps_a_control_character_exiftool_escaped);
  RUN_TEST(test_readResponse_keeps_a_text_that_fills_its_field_and_drops_one_byte_more);
  RUN_TEST(test_readResponse_leaves_no_byte_of_a_dropped_or_replaced_value);
  RUN_TEST(test_readResponse_keeps_the_last_value_of_a_key_that_appears_twice);
  RUN_TEST(test_readResponse_skips_a_tag_it_does_not_know);
  RUN_TEST(test_readResponse_reads_the_gps_position_in_signed_degrees);
  RUN_TEST(test_readResponse_needs_both_coordinates_for_a_position);
  RUN_TEST(test_readResponse_keeps_a_coordinate_at_its_bound_and_drops_one_past_it);
  RUN_TEST(test_readResponse_keeps_a_jpeg_quality_from_1_to_100);
  RUN_TEST(test_readResponse_keeps_a_thumbnail_length_of_0_or_more);
  RUN_TEST(test_readResponse_reads_only_the_label_c2pa_as_a_manifest_store);
  RUN_TEST(test_readResponse_marks_each_png_generator_chunk);
  RUN_TEST(test_readResponse_marks_each_identifier_kind_and_keeps_no_value);
  RUN_TEST(test_readResponse_matches_an_identifier_by_the_tag_name_after_the_colon);
  RUN_TEST(test_readResponse_marks_each_author_group_tag_by_its_kind);
  RUN_TEST(test_readResponse_matches_a_whole_tag_name_with_a_language_code);
  RUN_TEST(test_readResponse_keeps_the_c2pa_claim_generator);
  RUN_TEST(test_readResponse_keeps_a_claim_generator_name_that_fills_its_field_and_drops_one_byte_more);
  RUN_TEST(test_readResponse_keeps_a_claim_generator_name_written_as_a_number);
  RUN_TEST(test_readResponse_keeps_a_one_byte_claim_generator_name_before_a_second_info);
  RUN_TEST(test_readResponse_keeps_the_action_time_and_software_of_a_history_entry);
  RUN_TEST(test_readResponse_keeps_16_history_entries_and_reports_more_after_them);
  RUN_TEST(test_readResponse_lets_a_second_history_replace_the_first);
  RUN_TEST(test_readResponse_reads_a_history_that_is_not_an_array_as_no_entries);
  RUN_TEST(test_readResponse_refuses_an_exiftool_error_and_leaves_the_result_zero);
  RUN_TEST(test_readResponse_refuses_a_malformed_answer_and_leaves_the_result_zero);
  RUN_TEST(test_inspect_sends_the_image_shuts_down_and_reads_the_answer);
  RUN_TEST(test_inspect_retries_a_send_and_a_read_that_would_block_or_are_interrupted);
  RUN_TEST(test_inspect_reads_the_answer_after_the_service_stops_reading);
  RUN_TEST(test_inspect_stops_sending_when_the_service_has_closed);
  RUN_TEST(test_inspect_reads_the_answer_while_the_socket_takes_no_bytes);
  RUN_TEST(test_inspect_shuts_down_at_once_for_an_empty_image);
  RUN_TEST(test_inspect_answers_connect_error_when_the_socket_or_the_connection_fails);
  RUN_TEST(test_inspect_answers_no_memory_before_it_connects);
  RUN_TEST(test_inspect_waits_until_the_deadline_counted_from_its_start);
  RUN_TEST(test_inspect_waits_for_the_rest_of_the_deadline_after_a_partial_answer);
  RUN_TEST(test_inspect_ends_at_the_deadline_while_the_service_trickles);
  RUN_TEST(test_inspect_counts_the_deadline_after_24_days_of_uptime);
  RUN_TEST(test_inspect_answers_transfer_error_when_poll_or_recv_fails);
  RUN_TEST(test_inspect_reads_an_answer_of_256_KiB_and_refuses_one_byte_more);
  RUN_TEST(test_inspect_passes_a_malformed_answer_on);
  RUN_TEST(test_registration_gate_test_count);
  return UNITY_END();
}
