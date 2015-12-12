#ifndef UDAT_WRAPPER_H
#define UDAT_WRAPPER_H

#include "unicode/udat_orig.h"

static inline UDateFormat*
udat_open_wrapper(UDateFormatStyle  timeStyle,
                  UDateFormatStyle  dateStyle,
                  const char        *locale,
                  const UChar       *tzID,
                  int32_t           tzIDLength,
                  const UChar       *pattern,
                  int32_t           patternLength,
                  UErrorCode        *status) {
	return udat_open(timeStyle, dateStyle, locale, tzID,
		tzIDLength, pattern, patternLength, status);
}

static inline void
udat_close_wrapper(UDateFormat* format) {
	return udat_close(format);
}

static inline UDate
udat_parse_wrapper(const  UDateFormat*    format,
                   const  UChar*          text,
                          int32_t         textLength,
                          int32_t         *parsePos,
                          UErrorCode      *status) {
	return udat_parse(format, text, textLength, parsePos, status);
}

static inline int32_t
udat_format_wrapper(const UDateFormat*    format,
                          UDate           dateToFormat,
                          UChar*          result,
                          int32_t         resultLength,
                          UFieldPosition* position,
                          UErrorCode*     status) {
	return udat_format(format, dateToFormat, result,
		resultLength, position, status);
}

#endif
