
#ifndef _p_icu_h_
#define _p_icu_h_

#include <sys/types.h>

// This file contains several imports from the ICU libraries.

typedef char UBool;
typedef void* UDateFormat;
typedef double UDate;
typedef unsigned short UChar;

typedef enum UErrorCode {
	U_USING_FALLBACK_WARNING  = -128,
	U_ZERO_ERROR = 0
} UErrorCode;

extern UBool u_isWhitespace(unsigned int);
extern UBool u_isdigit(unsigned int);
extern UBool u_isalnum(unsigned int);

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
							   int           tzIDLength,
							   const UChar       *pattern,
							   int           patternLength,
							   enum UErrorCode        *status);

extern void udat_close(UDateFormat* format);

extern UDate udat_parse(const  UDateFormat*    format,
						   const  UChar*          text,
						   int         textLength,
						   int         *parsePos,
						   enum UErrorCode      *status);

extern int udat_format(const UDateFormat*    format,
							UDate           dateToFormat,
							UChar*          result,
							int         resultLength,
							void * position,
							enum UErrorCode*     status);

#endif
