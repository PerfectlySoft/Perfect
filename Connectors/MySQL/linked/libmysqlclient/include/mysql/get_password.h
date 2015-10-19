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
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301  USA */

/*
** Ask for a password from tty
** This is an own file to avoid conflicts with curses
*/

#ifndef MYSQL_GET_PASSWORD_H_INCLUDED
#define MYSQL_GET_PASSWORD_H_INCLUDED

#ifdef __cplusplus
extern "C" {
#endif

typedef char *(* strdup_handler_t)(const char *, int);
char *get_tty_password_ext(const char *opt_message,
                           strdup_handler_t strdup_function);

#ifdef __cplusplus
}
#endif

#endif /* ! MYSQL_GET_PASSWORD_H_INCLUDED */
