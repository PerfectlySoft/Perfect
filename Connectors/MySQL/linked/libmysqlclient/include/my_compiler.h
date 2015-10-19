#ifndef MY_COMPILER_INCLUDED
#define MY_COMPILER_INCLUDED

/* Copyright (c) 2010, 2011, Oracle and/or its affiliates. All rights reserved.

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
  Header for compiler-dependent features.

  Intended to contain a set of reusable wrappers for preprocessor
  macros, attributes, pragmas, and any other features that are
  specific to a target compiler.
*/

#include <my_global.h>                          /* stddef.h offsetof */

/**
  Compiler-dependent internal convenience macros.
*/

/* GNU C/C++ */
#if defined __GNUC__
/* Convenience macro to test the minimum required GCC version. */
# define MY_GNUC_PREREQ(maj, min) \
    ((__GNUC__ << 16) + __GNUC_MINOR__ >= ((maj) << 16) + (min))
/* Any after 2.95... */
# define MY_ALIGN_EXT
/* Comunicate to the compiler the unreachability of the code. */
# if MY_GNUC_PREREQ(4,5)
#   define MY_ASSERT_UNREACHABLE()   __builtin_unreachable()
# endif

/* Microsoft Visual C++ */
#elif defined _MSC_VER
# define MY_ALIGNOF(type)   __alignof(type)
# define MY_ALIGNED(n)      __declspec(align(n))

/* Oracle Solaris Studio */
#elif defined(__SUNPRO_C) || defined(__SUNPRO_CC)
# if __SUNPRO_C >= 0x590
#   define MY_ALIGN_EXT
# endif

/* IBM XL C/C++ */
#elif defined __xlC__
# if __xlC__ >= 0x0600
#   define MY_ALIGN_EXT
# endif

/* HP aCC */
#elif defined(__HP_aCC) || defined(__HP_cc)
# if (__HP_aCC >= 60000) || (__HP_cc >= 60000)
#   define MY_ALIGN_EXT
# endif
#endif

#ifdef MY_ALIGN_EXT
/** Specifies the minimum alignment of a type. */
# define MY_ALIGNOF(type)   __alignof__(type)
/** Determine the alignment requirement of a type. */
# define MY_ALIGNED(n)      __attribute__((__aligned__((n))))
#endif

/**
  Generic (compiler-independent) features.
*/

#ifndef MY_GNUC_PREREQ
# define MY_GNUC_PREREQ(maj, min) (0)
#endif

#ifndef MY_ALIGNOF
# ifdef __cplusplus
    template<typename type> struct my_alignof_helper { char m1; type m2; };
    /* Invalid for non-POD types, but most compilers give the right answer. */
#   define MY_ALIGNOF(type)   offsetof(my_alignof_helper<type>, m2)
# else
#   define MY_ALIGNOF(type)   offsetof(struct { char m1; type m2; }, m2)
# endif
#endif

#ifndef MY_ASSERT_UNREACHABLE
# define MY_ASSERT_UNREACHABLE()  do { assert(0); } while (0)
#endif

/**
  C++ Type Traits
*/

#ifdef __cplusplus

/**
  Opaque storage with a particular alignment.
*/
# if defined(MY_ALIGNED)
/* Partial specialization used due to MSVC++. */
template<size_t alignment> struct my_alignment_imp;
template<> struct MY_ALIGNED(1) my_alignment_imp<1> {};
template<> struct MY_ALIGNED(2) my_alignment_imp<2> {};
template<> struct MY_ALIGNED(4) my_alignment_imp<4> {};
template<> struct MY_ALIGNED(8) my_alignment_imp<8> {};
template<> struct MY_ALIGNED(16) my_alignment_imp<16> {};
/* ... expand as necessary. */
# else
template<size_t alignment>
struct my_alignment_imp { double m1; };
# endif

/**
  A POD type with a given size and alignment.

  @remark If the compiler does not support a alignment attribute
          (MY_ALIGN macro), the default alignment of a double is
          used instead.

  @tparam size        The minimum size.
  @tparam alignment   The desired alignment: 1, 2, 4, 8 or 16.
*/
template <size_t size, size_t alignment>
struct my_aligned_storage
{
  union
  {
    char data[size];
    my_alignment_imp<alignment> align;
  };
};

#endif /* __cplusplus */

# ifndef MY_ALIGNED
/*
  Make sure MY_ALIGNED can be used also on platforms where we don't
  have a way of aligning data structures.
*/
#define MY_ALIGNED(size)
#endif

#include <my_attribute.h>

#endif /* MY_COMPILER_INCLUDED */
