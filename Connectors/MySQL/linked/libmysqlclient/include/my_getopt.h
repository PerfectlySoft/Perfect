/*
   Copyright (c) 2002, 2014, Oracle and/or its affiliates. All rights reserved.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 of the License.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301  USA */

#ifndef _my_getopt_h
#define _my_getopt_h

#include "my_sys.h"                             /* loglevel */

C_MODE_START

#define GET_NO_ARG     1
#define GET_BOOL       2
#define GET_INT        3
#define GET_UINT       4
#define GET_LONG       5
#define GET_ULONG      6
#define GET_LL         7
#define GET_ULL        8
#define GET_STR        9
#define GET_STR_ALLOC 10
#define GET_DISABLED  11
#define GET_ENUM      12
#define GET_SET       13
#define GET_DOUBLE    14
#define GET_FLAGSET   15
#define GET_PASSWORD  16

#define GET_ASK_ADDR	 128
#define GET_TYPE_MASK	 127

/**
  Enumeration of the my_option::arg_type attributes.
  It should be noted that for historical reasons variables with the combination
  arg_type=NO_ARG, my_option::var_type=GET_BOOL still accepts
  arguments. This is someone counter intuitive and care should be taken
  if the code is refactored.
*/
enum get_opt_arg_type { NO_ARG, OPT_ARG, REQUIRED_ARG };

struct st_typelib;

struct my_option
{
  const char *name;                     /**< Name of the option. name=NULL
                                           marks the end of the my_option[]
                                           array.
                                         */
  int        id;                        /**< For 0<id<255 it's means one
                                           character for a short option
                                           (like -A), if >255 no short option
                                           is created, but a long option still
                                           can be identified uniquely in the
                                           my_get_one_option() callback.
                                           If an opton needs neither special
                                           treatment in the my_get_one_option()
                                           nor one-letter short equivalent
                                           use id=0.
                                           id=-1 is a special case and is used
                                           to generate deprecation warnings for
                                           plugin options. It should not be
                                           used for anything else.
                                         */
  const char *comment;                  /**< option comment, for autom. --help.
                                           if it's NULL the option is not
                                           visible in --help.
                                         */
  void       *value;                    /**< A pointer to the variable value */
  void       *u_max_value;              /**< The user def. max variable value */
  struct st_typelib *typelib;           /**< Pointer to possible values */
  ulong     var_type;                   /**< GET_BOOL, GET_ULL, etc */
  enum get_opt_arg_type arg_type;       /**< e.g. REQUIRED_ARG or OPT_ARG */
  longlong   def_value;                 /**< Default value */
  longlong   min_value;                 /**< Min allowed value (for numbers) */
  ulonglong  max_value;                 /**< Max allowed value (for numbers) */
  longlong   sub_size;                  /**< Unused                          */
  long       block_size;                /**< Value should be a mult. of this (for numbers) */
  void       *app_type;                 /**< To be used by an application */
};


typedef my_bool (*my_get_one_option)(int, const struct my_option *, char *);
/**
  Used to retrieve a reference to the object (variable) that holds the value
  for the given option. For example, if var_type is GET_UINT, the function
  must return a pointer to a variable of type uint. A argument is stored in
  the location pointed to by the returned pointer.
*/
typedef void *(*my_getopt_value)(const char *, uint, const struct my_option *,
                                 int *);


extern char *disabled_my_option;
extern my_bool my_getopt_print_errors;
extern my_bool my_getopt_skip_unknown;
extern my_error_reporter my_getopt_error_reporter;

extern int handle_options (int *argc, char ***argv, 
			   const struct my_option *longopts, my_get_one_option);
extern int my_handle_options (int *argc, char ***argv,
                              const struct my_option *longopts,
                              my_get_one_option,
                              const char **command_list);
extern void print_cmdline_password_warning();
extern void my_cleanup_options(const struct my_option *options);
extern void my_cleanup_options(const struct my_option *options);
extern void my_print_help(const struct my_option *options);
extern void my_print_variables(const struct my_option *options);
extern void my_getopt_register_get_addr(my_getopt_value);

ulonglong getopt_ull_limit_value(ulonglong num, const struct my_option *optp,
                                 my_bool *fix);
longlong getopt_ll_limit_value(longlong, const struct my_option *,
                               my_bool *fix);
double getopt_double_limit_value(double num, const struct my_option *optp,
                                 my_bool *fix);
my_bool getopt_compare_strings(const char *s, const char *t, uint length);
ulonglong max_of_int_range(int var_type);

ulonglong getopt_double2ulonglong(double);
double getopt_ulonglong2double(ulonglong);

C_MODE_END

#endif /* _my_getopt_h */

