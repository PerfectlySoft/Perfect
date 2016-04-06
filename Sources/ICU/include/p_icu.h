
#ifndef _p_icu_h_
#define _p_icu_h_

#include <sys/types.h>

// This file contains several imports from the ICU libraries.

typedef int8_t UBool;
typedef void* UDateFormat;
typedef double UDate;
typedef uint16_t UChar;
typedef enum UErrorCode {
		U_ZERO_ERROR = 0
} UErrorCode;

extern UBool u_isWhitespace(uint32_t);
extern UBool u_isdigit(uint32_t);
extern UBool u_isalnum(uint32_t);

extern double ucal_getNow();

extern const char * u_errorName(enum UErrorCode code);

typedef enum UDateFormatStyle {
	UDAT_FULL,
	UDAT_LONG,
	UDAT_MEDIUM,
	UDAT_SHORT,
	UDAT_DEFAULT = UDAT_MEDIUM,
	UDAT_RELATIVE = (1 << 7),
	UDAT_FULL_RELATIVE = UDAT_FULL | UDAT_RELATIVE,
	UDAT_LONG_RELATIVE = UDAT_LONG | UDAT_RELATIVE,
	UDAT_MEDIUM_RELATIVE = UDAT_MEDIUM | UDAT_RELATIVE,
	UDAT_SHORT_RELATIVE = UDAT_SHORT | UDAT_RELATIVE,
	UDAT_NONE = -1,
	UDAT_PATTERN = -2
} UDateFormatStyle;

extern UDateFormat * udat_open(UDateFormatStyle  timeStyle,
							   UDateFormatStyle  dateStyle,
							   const char        *locale,
							   const UChar       *tzID,
							   int32_t           tzIDLength,
							   const UChar       *pattern,
							   int32_t           patternLength,
							   enum UErrorCode        *status);

extern void udat_close(UDateFormat* format);

extern UDate udat_parse(const  UDateFormat*    format,
						   const  UChar*          text,
						   int32_t         textLength,
						   int32_t         *parsePos,
						   enum UErrorCode      *status);

extern int32_t udat_format(const UDateFormat*    format,
							UDate           dateToFormat,
							UChar*          result,
							int32_t         resultLength,
							void * position,
							enum UErrorCode*     status);

#endif
