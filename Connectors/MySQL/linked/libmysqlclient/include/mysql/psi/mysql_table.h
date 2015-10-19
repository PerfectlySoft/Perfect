/* Copyright (c) 2010, 2012, Oracle and/or its affiliates. All rights reserved.

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software Foundation,
  51 Franklin Street, Suite 500, Boston, MA 02110-1335 USA */

#ifndef MYSQL_TABLE_H
#define MYSQL_TABLE_H

/**
  @file mysql/psi/mysql_table.h
  Instrumentation helpers for table io.
*/

#include "mysql/psi/psi.h"

/**
  @defgroup Table_instrumentation Table Instrumentation
  @ingroup Instrumentation_interface
  @{
*/

/**
  @def MYSQL_TABLE_WAIT_VARIABLES
  Instrumentation helper for table waits.
  This instrumentation declares local variables.
  Do not use a ';' after this macro
  @param LOCKER the locker
  @param STATE the locker state
  @sa MYSQL_START_TABLE_IO_WAIT.
  @sa MYSQL_END_TABLE_IO_WAIT.
  @sa MYSQL_START_TABLE_LOCK_WAIT.
  @sa MYSQL_END_TABLE_LOCK_WAIT.
*/
#ifdef HAVE_PSI_TABLE_INTERFACE
  #define MYSQL_TABLE_WAIT_VARIABLES(LOCKER, STATE) \
    struct PSI_table_locker* LOCKER; \
    PSI_table_locker_state STATE;
#else
  #define MYSQL_TABLE_WAIT_VARIABLES(LOCKER, STATE)
#endif

/**
  @def MYSQL_TABLE_IO_WAIT
  Instrumentation helper for table io_waits.
  This instrumentation marks the start of a wait event.
  @param PSI the instrumented table
  @param OP the table operation to be performed
  @param INDEX the table index used if any, or MAY_KEY.
  @param FLAGS per table operation flags.
  @sa MYSQL_END_TABLE_WAIT.
*/
#ifdef HAVE_PSI_TABLE_INTERFACE
  #define MYSQL_TABLE_IO_WAIT(PSI, OP, INDEX, FLAGS, PAYLOAD) \
    {                                                         \
      if (PSI != NULL)                                        \
      {                                                       \
        PSI_table_locker *locker;                             \
        PSI_table_locker_state state;                         \
        locker= PSI_TABLE_CALL(start_table_io_wait)           \
          (& state, PSI, OP, INDEX, __FILE__, __LINE__);      \
        PAYLOAD                                               \
        if (locker != NULL)                                   \
          PSI_TABLE_CALL(end_table_io_wait)(locker);          \
      }                                                       \
      else                                                    \
      {                                                       \
        PAYLOAD                                               \
      }                                                       \
    }
#else
  #define MYSQL_TABLE_IO_WAIT(PSI, OP, INDEX, FLAGS, PAYLOAD) \
    PAYLOAD
#endif

/**
  @def MYSQL_TABLE_LOCK_WAIT
  Instrumentation helper for table io_waits.
  This instrumentation marks the start of a wait event.
  @param PSI the instrumented table
  @param OP the table operation to be performed
  @param INDEX the table index used if any, or MAY_KEY.
  @param FLAGS per table operation flags.
  @sa MYSQL_END_TABLE_WAIT.
*/
#ifdef HAVE_PSI_TABLE_INTERFACE
  #define MYSQL_TABLE_LOCK_WAIT(PSI, OP, FLAGS, PAYLOAD) \
    {                                                    \
      if (PSI != NULL)                                   \
      {                                                  \
        PSI_table_locker *locker;                        \
        PSI_table_locker_state state;                    \
        locker= PSI_TABLE_CALL(start_table_lock_wait)    \
          (& state, PSI, OP, FLAGS, __FILE__, __LINE__); \
        PAYLOAD                                          \
        if (locker != NULL)                              \
          PSI_TABLE_CALL(end_table_lock_wait)(locker);   \
      }                                                  \
      else                                               \
      {                                                  \
        PAYLOAD                                          \
      }                                                  \
    }
#else
  #define MYSQL_TABLE_LOCK_WAIT(PSI, OP, FLAGS, PAYLOAD) \
    PAYLOAD
#endif

/**
  @def MYSQL_START_TABLE_LOCK_WAIT
  Instrumentation helper for table lock waits.
  This instrumentation marks the start of a wait event.
  @param LOCKER the locker
  @param STATE the locker state
  @param PSI the instrumented table
  @param OP the table operation to be performed
  @param FLAGS per table operation flags.
  @sa MYSQL_END_TABLE_LOCK_WAIT.
*/
#ifdef HAVE_PSI_TABLE_INTERFACE
  #define MYSQL_START_TABLE_LOCK_WAIT(LOCKER, STATE, PSI, OP, FLAGS) \
    LOCKER= inline_mysql_start_table_lock_wait(STATE, PSI, \
                                               OP, FLAGS, __FILE__, __LINE__)
#else
  #define MYSQL_START_TABLE_LOCK_WAIT(LOCKER, STATE, PSI, OP, FLAGS) \
    do {} while (0)
#endif

/**
  @def MYSQL_END_TABLE_LOCK_WAIT
  Instrumentation helper for table lock waits.
  This instrumentation marks the end of a wait event.
  @param LOCKER the locker
  @sa MYSQL_START_TABLE_LOCK_WAIT.
*/
#ifdef HAVE_PSI_TABLE_INTERFACE
  #define MYSQL_END_TABLE_LOCK_WAIT(LOCKER) \
    inline_mysql_end_table_lock_wait(LOCKER)
#else
  #define MYSQL_END_TABLE_LOCK_WAIT(LOCKER) \
    do {} while (0)
#endif

#ifdef HAVE_PSI_TABLE_INTERFACE
/**
  Instrumentation calls for MYSQL_START_TABLE_LOCK_WAIT.
  @sa MYSQL_END_TABLE_LOCK_WAIT.
*/
static inline struct PSI_table_locker *
inline_mysql_start_table_lock_wait(PSI_table_locker_state *state,
                                   struct PSI_table *psi,
                                   enum PSI_table_lock_operation op,
                                   ulong flags, const char *src_file, int src_line)
{
  if (psi != NULL)
  {
    struct PSI_table_locker *locker;
    locker= PSI_TABLE_CALL(start_table_lock_wait)
      (state, psi, op, flags, src_file, src_line);
    return locker;
  }
  return NULL;
}

/**
  Instrumentation calls for MYSQL_END_TABLE_LOCK_WAIT.
  @sa MYSQL_START_TABLE_LOCK_WAIT.
*/
static inline void
inline_mysql_end_table_lock_wait(struct PSI_table_locker *locker)
{
  if (locker != NULL)
    PSI_TABLE_CALL(end_table_lock_wait)(locker);
}
#endif

/** @} (end of group Table_instrumentation) */

#endif

