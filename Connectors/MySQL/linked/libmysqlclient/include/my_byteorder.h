#ifndef MY_BYTEORDER_INCLUDED
#define MY_BYTEORDER_INCLUDED

/* Copyright (c) 2001, 2012, Oracle and/or its affiliates. All rights reserved.

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


/*
  Macro for reading 32-bit integer from network byte order (big-endian)
  from a unaligned memory location.
*/
#define int4net(A)        (int32) (((uint32) ((uchar) (A)[3]))        | \
                                  (((uint32) ((uchar) (A)[2])) << 8)  | \
                                  (((uint32) ((uchar) (A)[1])) << 16) | \
                                  (((uint32) ((uchar) (A)[0])) << 24))

/*
  Function-like macros for reading and storing in machine independent
  format (low byte first). There are 'korr' (assume 'corrector') variants
  for integer types, but 'get' (assume 'getter') for floating point types.
*/
#if defined(__i386__) || defined(_WIN32)
#define MY_BYTE_ORDER_ARCH_OPTIMIZED
#include "byte_order_generic_x86.h"
#elif defined(__x86_64__)
#include "byte_order_generic_x86_64.h"
#else
#include "byte_order_generic.h"
#endif

/*
  Function-like macros for reading and storing in machine format from/to
  short/long to/from some place in memory V should be a variable (not on
  a register) and M a pointer to byte.
*/
#ifdef WORDS_BIGENDIAN
#include "big_endian.h"
#else
#include "little_endian.h"
#endif

#endif /* MY_BYTEORDER_INCLUDED */
