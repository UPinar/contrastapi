#ifndef REQUEST_TEXT_H
#define REQUEST_TEXT_H

#include <stdbool.h>

#include "receive.h"

bool requestText_parse(const char* text, ReceiveResult_t* result_out);

#endif
