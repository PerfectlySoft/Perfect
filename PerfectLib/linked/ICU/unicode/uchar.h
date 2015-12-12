#ifndef UCHAR_WRAPPER_H
#define UCHAR_WRAPPER_H

#include "unicode/uchar_orig.h"

static inline UBool
u_isWhitespace_wrapper(UChar32 c) {
	return u_isWhitespace(c);
}

static inline UBool
u_isdigit_wrapper(UChar32 c) {
	return u_isdigit(c);
}

static inline UBool
u_isalnum_wrapper(UChar32 c) {
	return u_isalnum(c);
}


#endif
