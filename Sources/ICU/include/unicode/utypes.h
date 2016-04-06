#ifndef UTYPES_WRAPPER_H
#define UTYPES_WRAPPER_H

#include "unicode/utypes_orig.h"

static inline const char*
u_errorName_wrapper(UErrorCode code) {
	return u_errorName(code);
}

#endif