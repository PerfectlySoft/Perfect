/* Copyright (c) 2010, 2015, Oracle and/or its affiliates. All rights reserved.   

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

#ifndef MYSQL_STATEMENT_H
#define MYSQL_STATEMENT_H

/**
  @file mysql/psi/mysql_statement.h
  Instrumentation helpers for statements.
*/

#include "mysql/psi/psi.h"

/**
  @defgroup Statement_instrumentation Statement Instrumentation
  @ingroup Instrumentation_interface
  @{
*/

/**
  @def mysql_statement_register(P1, P2, P3)
  Statement registration.
*/
#ifdef HAVE_PSI_STATEMENT_INTERFACE
#define mysql_statement_register(P1, P2, P3) \
  inline_mysql_statement_register(P1, P2, P3)
#else
#define mysql_statement_register(P1, P2, P3) \
  do {} while (0)
#endif

#ifdef HAVE_PSI_STATEMENT_DIGEST_INTERFACE
  #define MYSQL_DIGEST_START(LOCKER) \
    inline_mysql_digest_start(LOCKER)
#else
  #define MYSQL_DIGEST_START(LOCKER) \
    NULL
#endif

#ifdef HAVE_PSI_STATEMENT_DIGEST_INTERFACE
  #define MYSQL_DIGEST_END(LOCKER, DIGEST) \
    inline_mysql_digest_end(LOCKER, DIGEST)
#else
  #define MYSQL_DIGEST_END(LOCKER, DIGEST) \
    do {} while (0)
#endif

#ifdef HAVE_PSI_STATEMENT_INTERFACE
  #define MYSQL_START_STATEMENT(STATE, K, DB, DB_LEN, CS) \
    inline_mysql_start_statement(STATE, K, DB, DB_LEN, CS, __FILE__, __LINE__)
#else
  #define MYSQL_START_STATEMENT(STATE, K, DB, DB_LEN, CS) \
    NULL
#endif

#ifdef HAVE_PSI_STATEMENT_INTERFACE
  #define MYSQL_REFINE_STATEMENT(LOCKER, K) \
    inline_mysql_refine_statement(LOCKER, K)
#else
  #define MYSQL_REFINE_STATEMENT(LOCKER, K) \
    NULL
#endif

#ifdef HAVE_PSI_STATEMENT_INTERFACE
  #define MYSQL_SET_STATEMENT_TEXT(LOCKER, P1, P2) \
    inline_mysql_set_statement_text(LOCKER, P1, P2)
#else
  #define MYSQL_SET_STATEMENT_TEXT(LOCKER, P1, P2) \
    do {} while (0)
#endif

#ifdef HAVE_PSI_STATEMENT_INTERFACE
  #define MYSQL_SET_STATEMENT_LOCK_TIME(LOCKER, P1) \
    inline_mysql_set_statement_lock_time(LOCKER, P1)
#else
  #define MYSQL_SET_STATEMENT_LOCK_TIME(LOCKER, P1) \
    do {} while (0)
#endif

#ifdef HAVE_PSI_STATEMENT_INTERFACE
  #define MYSQL_SET_STATEMENT_ROWS_SENT(LOCKER, P1) \
    inline_mysql_set_statement_rows_sent(LOCKER, P1)
#else
  #define MYSQL_SET_STATEMENT_ROWS_SENT(LOCKER, P1) \
    do {} while (0)
#endif

#ifdef HAVE_PSI_STATEMENT_INTERFACE
  #define MYSQL_SET_STATEMENT_ROWS_EXAMINED(LOCKER, P1) \
    inline_mysql_set_statement_rows_examined(LOCKER, P1)
#else
  #define MYSQL_SET_STATEMENT_ROWS_EXAMINED(LOCKER, P1) \
    do {} while (0)
#endif

#ifdef HAVE_PSI_STATEMENT_INTERFACE
  #define MYSQL_END_STATEMENT(LOCKER, DA) \
    inline_mysql_end_statement(LOCKER, DA)
#else
  #define MYSQL_END_STATEMENT(LOCKER, DA) \
    do {} while (0)
#endif

#ifdef HAVE_PSI_STATEMENT_INTERFACE
static inline void inline_mysql_statement_register(
  const char *category, PSI_statement_info *info, int count)
{
  PSI_STATEMENT_CALL(register_statement)(category, info, count);
}

#ifdef HAVE_PSI_STATEMENT_DIGEST_INTERFACE
static inline struct PSI_digest_locker *
inline_mysql_digest_start(PSI_statement_locker *locker)
{
  PSI_digest_locker* digest_locker= NULL;

  if (likely(locker != NULL))
    digest_locker= PSI_DIGEST_CALL(digest_start)(locker);
  return digest_locker;
}
#endif

#ifdef HAVE_PSI_STATEMENT_DIGEST_INTERFACE
static inline void
inline_mysql_digest_end(PSI_digest_locker *locker, const sql_digest_storage *digest)
{
  if (likely(locker != NULL))
    PSI_DIGEST_CALL(digest_end)(locker, digest);
}
#endif

static inline struct PSI_statement_locker *
inline_mysql_start_statement(PSI_statement_locker_state *state,
                             PSI_statement_key key,
                             const char *db, uint db_len,
                             const CHARSET_INFO *charset,
                             const char *src_file, int src_line)
{
  PSI_statement_locker *locker;
  locker= PSI_STATEMENT_CALL(get_thread_statement_locker)(state, key, charset);
  if (likely(locker != NULL))
    PSI_STATEMENT_CALL(start_statement)(locker, db, db_len, src_file, src_line);
  return locker;
}

static inline struct PSI_statement_locker *
inline_mysql_refine_statement(PSI_statement_locker *locker,
                              PSI_statement_key key)
{
  if (likely(locker != NULL))
  {
    locker= PSI_STATEMENT_CALL(refine_statement)(locker, key);
  }
  return locker;
}

static inline void
inline_mysql_set_statement_text(PSI_statement_locker *locker,
                                const char *text, uint text_len)
{
  if (likely(locker != NULL))
  {
    PSI_STATEMENT_CALL(set_statement_text)(locker, text, text_len);
  }
}

static inline void
inline_mysql_set_statement_lock_time(PSI_statement_locker *locker,
                                     ulonglong count)
{
  if (likely(locker != NULL))
  {
    PSI_STATEMENT_CALL(set_statement_lock_time)(locker, count);
  }
}

static inline void
inline_mysql_set_statement_rows_sent(PSI_statement_locker *locker,
                                     ulonglong count)
{
  if (likely(locker != NULL))
  {
    PSI_STATEMENT_CALL(set_statement_rows_sent)(locker, count);
  }
}

static inline void
inline_mysql_set_statement_rows_examined(PSI_statement_locker *locker,
                                         ulonglong count)
{
  if (likely(locker != NULL))
  {
    PSI_STATEMENT_CALL(set_statement_rows_examined)(locker, count);
  }
}

static inline void
inline_mysql_end_statement(struct PSI_statement_locker *locker,
                           Diagnostics_area *stmt_da)
{
  PSI_STAGE_CALL(end_stage)();
  if (likely(locker != NULL))
    PSI_STATEMENT_CALL(end_statement)(locker, stmt_da);
}
#endif

/** @} (end of group Statement_instrumentation) */

#endif

