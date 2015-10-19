/* Copyright (c) 2000, 2011, Oracle and/or its affiliates. All rights reserved.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 of the License.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA */


#ifndef _typelib_h
#define _typelib_h

#include "my_alloc.h"

typedef struct st_typelib {	/* Different types saved here */
  unsigned int count;		/* How many types */
  const char *name;		/* Name of typelib */
  const char **type_names;
  unsigned int *type_lengths;
} TYPELIB;

extern my_ulonglong find_typeset(char *x, TYPELIB *typelib,int *error_position);
extern int find_type_or_exit(const char *x, TYPELIB *typelib,
                             const char *option);
#define FIND_TYPE_BASIC           0
/** makes @c find_type() require the whole name, no prefix */
#define FIND_TYPE_NO_PREFIX      (1 << 0)
/** always implicitely on, so unused, but old code may pass it */
#define FIND_TYPE_NO_OVERWRITE   (1 << 1)
/** makes @c find_type() accept a number */
#define FIND_TYPE_ALLOW_NUMBER   (1 << 2)
/** makes @c find_type() treat ',' as terminator */
#define FIND_TYPE_COMMA_TERM     (1 << 3)

extern int find_type(const char *x, const TYPELIB *typelib, unsigned int flags);
extern void make_type(char *to,unsigned int nr,TYPELIB *typelib);
extern const char *get_type(TYPELIB *typelib,unsigned int nr);
extern TYPELIB *copy_typelib(MEM_ROOT *root, TYPELIB *from);

extern TYPELIB sql_protocol_typelib;

my_ulonglong find_set_from_flags(const TYPELIB *lib, unsigned int default_name,
                              my_ulonglong cur_set, my_ulonglong default_set,
                              const char *str, unsigned int length,
                              char **err_pos, unsigned int *err_len);

#endif /* _typelib_h */
