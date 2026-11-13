#include <string.h>

#include "exifclient.h"

ExifClientStatus_t g_stub_IMAGEINSPECT_exif_status = EXIFCLIENT_OK;
ExifClientResult_t g_stub_IMAGEINSPECT_exif_result;

int    g_stub_IMAGEINSPECT_exif_call_count      = 0;
size_t g_stub_IMAGEINSPECT_exif_last_byte_count = 0;
unsigned char g_stub_IMAGEINSPECT_exif_last_bytes[64];

ExifClientStatus_t exifclient_inspect(const unsigned char* image_bytes, size_t image_byte_count, ExifClientResult_t* result_out)
{
  size_t kept = image_byte_count < sizeof(g_stub_IMAGEINSPECT_exif_last_bytes) ? image_byte_count : sizeof(g_stub_IMAGEINSPECT_exif_last_bytes);
  memcpy(g_stub_IMAGEINSPECT_exif_last_bytes, image_bytes, kept);
  g_stub_IMAGEINSPECT_exif_call_count++;
  g_stub_IMAGEINSPECT_exif_last_byte_count = image_byte_count;

  memset(result_out, 0, sizeof(*result_out));
  if (g_stub_IMAGEINSPECT_exif_status != EXIFCLIENT_OK)
    return g_stub_IMAGEINSPECT_exif_status;

  memcpy(result_out, &g_stub_IMAGEINSPECT_exif_result, sizeof(*result_out));
  return EXIFCLIENT_OK;
}
