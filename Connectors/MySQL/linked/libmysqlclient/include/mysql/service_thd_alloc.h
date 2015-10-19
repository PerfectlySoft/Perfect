#ifndef MYSQL_SERVICE_THD_ALLOC_INCLUDED
/* Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.

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

/**
  @file
  This service provdes functions to allocate memory in a connection local
  memory pool. The memory allocated there will be automatically freed at the
  end of the statement, don't use it for allocations that should live longer
  than that. For short living allocations this is more efficient than
  using my_malloc and friends, and automatic "garbage collection" allows not
  to think about memory leaks.

  The pool is best for small to medium objects, don't use it for large
  allocations - they are better served with my_malloc.
*/

#ifndef MYSQL_ABI_CHECK
#include <stdlib.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

struct st_mysql_lex_string
{
  char *str;
  size_t length;
};
typedef struct st_mysql_lex_string MYSQL_LEX_STRING;

extern struct thd_alloc_service_st {
  void *(*thd_alloc_func)(MYSQL_THD, unsigned int);
  void *(*thd_calloc_func)(MYSQL_THD, unsigned int);
  char *(*thd_strdup_func)(MYSQL_THD, const char *);
  char *(*thd_strmake_func)(MYSQL_THD, const char *, unsigned int);
  void *(*thd_memdup_func)(MYSQL_THD, const void*, unsigned int);
  MYSQL_LEX_STRING *(*thd_make_lex_string_func)(MYSQL_THD, MYSQL_LEX_STRING *,
                                        const char *, unsigned int, int);
} *thd_alloc_service;

#ifdef MYSQL_DYNAMIC_PLUGIN

#define thd_alloc(thd,size) (thd_alloc_service->thd_alloc_func((thd), (size)))

#define thd_calloc(thd,size) (thd_alloc_service->thd_calloc_func((thd), (size)))

#define thd_strdup(thd,str) (thd_alloc_service->thd_strdup_func((thd), (str)))

#define thd_strmake(thd,str,size) \
  (thd_alloc_service->thd_strmake_func((thd), (str), (size)))

#define thd_memdup(thd,str,size) \
  (thd_alloc_service->thd_memdup_func((thd), (str), (size)))

#define thd_make_lex_string(thd, lex_str, str, size, allocate_lex_string) \
  (thd_alloc_service->thd_make_lex_string_func((thd), (lex_str), (str), \
                                               (size), (allocate_lex_string)))

#else

/**
  Allocate memory in the connection's local memory pool

  @details
  When properly used in place of @c my_malloc(), this can significantly
  improve concurrency. Don't use this or related functions to allocate
  large chunks of memory. Use for temporary storage only. The memory
  will be freed automatically at the end of the statement; no explicit
  code is required to prevent memory leaks.

  @see alloc_root()
*/
void *thd_alloc(MYSQL_THD thd, unsigned int size);
/**
  @see thd_alloc()
*/
void *thd_calloc(MYSQL_THD thd, unsigned int size);
/**
  @see thd_alloc()
*/
char *thd_strdup(MYSQL_THD thd, const char *str);
/**
  @see thd_alloc()
*/
char *thd_strmake(MYSQL_THD thd, const char *str, unsigned int size);
/**
  @see thd_alloc()
*/
void *thd_memdup(MYSQL_THD thd, const void* str, unsigned int size);

/**
  Create a LEX_STRING in this connection's local memory pool

  @param thd      user thread connection handle
  @param lex_str  pointer to LEX_STRING object to be initialized
  @param str      initializer to be copied into lex_str
  @param size     length of str, in bytes
  @param allocate_lex_string  flag: if TRUE, allocate new LEX_STRING object,
                              instead of using lex_str value
  @return  NULL on failure, or pointer to the LEX_STRING object

  @see thd_alloc()
*/
MYSQL_LEX_STRING *thd_make_lex_string(MYSQL_THD thd, MYSQL_LEX_STRING *lex_str,
                                      const char *str, unsigned int size,
                                      int allocate_lex_string);

#endif

#ifdef __cplusplus
}
#endif

#define MYSQL_SERVICE_THD_ALLOC_INCLUDED
#endif

