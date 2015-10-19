/*
  Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.

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

#ifndef SERVICE_THREAD_SCHEDULER_INCLUDED
#define SERVICE_THREAD_SCHEDULER_INCLUDED

#ifdef __cplusplus
extern "C" {
#endif

struct scheduler_functions;

extern struct my_thread_scheduler_service {
  int (*set)(struct scheduler_functions *scheduler);
  int (*reset)();
} *my_thread_scheduler_service;

#ifdef MYSQL_DYNAMIC_PLUGIN

#define my_thread_scheduler_set(F) my_thread_scheduler_service->set((F))
#define my_thread_scheduler_reset() my_thread_scheduler_service->reset()

#else

/**
  Set the thread scheduler to use for the server.

  @param scheduler Pointer to scheduler callbacks to use.
  @retval 0 Scheduler installed correctly.
  @retval 1 Invalid value (NULL) used for scheduler.
*/
int my_thread_scheduler_set(struct scheduler_functions *scheduler);

/**
  Restore the previous thread scheduler.

  @note If no thread scheduler was installed previously with
  thd_set_thread_scheduler, this function will report an error.

  @retval 0 Scheduler installed correctly.
  @retval 1 No scheduler installed.
*/
int my_thread_scheduler_reset();

#endif

#ifdef __cplusplus
}
#endif

#endif /* SERVICE_THREAD_SCHEDULER_INCLUDED */
