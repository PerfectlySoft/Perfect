#ifndef UCONFIG_WRAPPER_H
#define UCONFIG_WRAPPER_H

#if defined(__has_include_next) && __has_include_next("unicode/uconfig.h")
#include_next "unicode/uconfig.h"
#else
#include "unicode/uconfig_orig.h"
#endif

#endif
