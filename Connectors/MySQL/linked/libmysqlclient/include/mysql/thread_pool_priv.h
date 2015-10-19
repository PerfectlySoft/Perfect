/*
  Copyright (c) 2010, 2015, Oracle and/or its affiliates. All rights reserved.

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301  USA
*/

#ifndef THREAD_POOL_PRIV_INCLUDED
#define THREAD_POOL_PRIV_INCLUDED

/*
  The thread pool requires access to some MySQL server error codes, this is
  accessed from mysqld_error.h.
  We need access to the struct that defines the thread pool plugin interface
  which is accessed through scheduler.h.
  All accesses to THD variables and functions are defined in this header file.
  A thread pool can also use DEBUG_SYNC and must thus include
  debug_sync.h
  To handle definitions of Information Schema plugins it is also required
  to include sql_profile.h and table.h.
*/
#include <mysqld_error.h> /* To get ER_ERROR_ON_READ */
#define MYSQL_SERVER 1
#include <scheduler.h>
#include <debug_sync.h>
#include <sql_profile.h>
#include <table.h>
#include "field.h"
#include <set>

typedef std::set<THD*>::iterator Thread_iterator;
/* Needed to get access to scheduler variables */
void* thd_get_scheduler_data(THD *thd);
void thd_set_scheduler_data(THD *thd, void *data);
PSI_thread* thd_get_psi(THD *thd);
void thd_set_psi(THD *thd, PSI_thread *psi);

/* Interface to THD variables and functions */
void thd_set_killed(THD *thd);
void thd_clear_errors(THD *thd);
void thd_set_thread_stack(THD *thd, char *stack_start);
void thd_lock_thread_count(THD *thd);
void thd_unlock_thread_count(THD *thd);
void thd_close_connection(THD *thd);
THD *thd_get_current_thd();
void thd_new_connection_setup(THD *thd, char *stack_start);
void thd_lock_data(THD *thd);
void thd_unlock_data(THD *thd);
bool thd_is_transaction_active(THD *thd);
int thd_connection_has_data(THD *thd);
void thd_set_net_read_write(THD *thd, uint val);
uint thd_get_net_read_write(THD *thd);
void thd_set_mysys_var(THD *thd, st_my_thread_var *mysys_var);
ulong  thd_get_net_wait_timeout(THD *thd);
my_socket thd_get_fd(THD *thd);
int thd_store_globals(THD* thd);

/* Interface to global thread list iterator functions */
Thread_iterator thd_get_global_thread_list_begin();
Thread_iterator thd_get_global_thread_list_end();

/* Print to the MySQL error log */
void sql_print_error(const char *format, ...);

/* Store a table record */
bool schema_table_store_record(THD *thd, TABLE *table);

/*
  The thread pool must be able to execute statements using the connection
  state in THD object. This is the main objective of the thread pool to
  schedule the start of these commands.
*/
bool do_command(THD *thd);

/*
  The thread pool requires an interface to the connection logic in the
  MySQL Server since the thread pool will maintain the event logic on
  the TCP connection of the MySQL Server. Thus new connections, dropped
  connections will be discovered by the thread pool and it needs to
  ensure that the proper MySQL Server logic attached to these events is
  executed.
*/
/* Initialise a new connection handler thread */
bool init_new_connection_handler_thread();
/* Set up connection thread before use as execution thread */
bool setup_connection_thread_globals(THD *thd);
/* Prepare connection as part of connection set-up */
bool thd_prepare_connection(THD *thd);
/* Release auditing before executing statement */
void mysql_audit_release(THD *thd);
/* Check if connection is still alive */
bool thd_is_connection_alive(THD *thd);
/* Close connection with possible error code */
void close_connection(THD *thd, uint errcode);
/* End the connection before closing it */
void end_connection(THD *thd);
/* Release resources of the THD object */
void thd_release_resources(THD *thd);
/* Decrement connection counter */
void dec_connection_count();
/* Destroy THD object */
void destroy_thd(THD *thd);
/* Remove the THD from the set of global threads. */
void remove_global_thread(THD *thd);

/*
  thread_created is maintained by thread pool when activated since
  user threads are created by the thread pool (and also special
  threads to maintain the thread pool). This is done through
  inc_thread_created.

  max_connections is needed to calculate the maximum number of threads
  that is allowed to be started by the thread pool. The method
  get_max_connections() gets reference to this variable.

  connection_attrib is the thread attributes for connection threads,
  the method get_connection_attrib provides a reference to these
  attributes.
*/
void inc_thread_created(void);
ulong get_max_connections(void);
pthread_attr_t *get_connection_attrib(void);
#endif
