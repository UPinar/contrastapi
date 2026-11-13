#ifndef MACRO_H
#define MACRO_H

#define MACRO_STR_(x) #x
#define MACRO_STR(x)  MACRO_STR_(x)

#define MACRO_FIELD_SIZE(type, field) sizeof(((type*)0)->field)

#endif
