#ifndef UCAL_WRAPPER_H
#define UCAL_WRAPPER_H

#include "unicode/ucal_orig.h"

static inline UDate
ucal_getNow_wrapper(void) {
	return ucal_getNow();
}

#endif
