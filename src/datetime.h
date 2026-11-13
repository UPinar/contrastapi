#ifndef DATETIME_H
#define DATETIME_H

#include <stdbool.h>
#include <stdint.h>

#define DATETIME_DATE_TIME_LEN   19
#define DATETIME_FULL_DATE_LEN   10
#define DATETIME_SECONDS_PER_DAY 86400

bool datetime_tryReadDateTime (const char* text_start, const char* text_end, int64_t* epoch_out);
bool datetime_tryReadFullDate (const char* text_start, const char* text_end, int64_t* epoch_out);
int  datetime_daysUntil       (int64_t end_epoch, int64_t now_epoch);
bool datetime_tryReadDigits   (const char* digits, int digit_count, int* value_out);

#endif
