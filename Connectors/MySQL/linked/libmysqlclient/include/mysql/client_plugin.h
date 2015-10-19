#ifndef MYSQL_CLIENT_PLUGIN_INCLUDED
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
  @file

  MySQL Client Plugin API

  This file defines the API for plugins that work on the client side
*/
#define MYSQL_CLIENT_PLUGIN_INCLUDED

#ifndef MYSQL_ABI_CHECK
#include <stdarg.h>
#include <stdlib.h>
#endif

/* known plugin types */
#define MYSQL_CLIENT_reserved1               0
#define MYSQL_CLIENT_reserved2               1
#define MYSQL_CLIENT_AUTHENTICATION_PLUGIN   2

#define MYSQL_CLIENT_AUTHENTICATION_PLUGIN_INTERFACE_VERSION  0x0100

#define MYSQL_CLIENT_MAX_PLUGINS             3

#define mysql_declare_client_plugin(X)          \
     MYSQL_PLUGIN_EXPORT struct st_mysql_client_plugin_ ## X        \
        _mysql_client_plugin_declaration_ = {   \
          MYSQL_CLIENT_ ## X ## _PLUGIN,        \
          MYSQL_CLIENT_ ## X ## _PLUGIN_INTERFACE_VERSION,
#define mysql_end_client_plugin             }

/* generic plugin header structure */
#define MYSQL_CLIENT_PLUGIN_HEADER                      \
  int type;                                             \
  unsigned int interface_version;                       \
  const char *name;                                     \
  const char *author;                                   \
  const char *desc;                                     \
  unsigned int version[3];                              \
  const char *license;                                  \
  void *mysql_api;                                      \
  int (*init)(char *, size_t, int, va_list);            \
  int (*deinit)();                                      \
  int (*options)(const char *option, const void *);

struct st_mysql_client_plugin
{
  MYSQL_CLIENT_PLUGIN_HEADER
};

struct st_mysql;

/******** authentication plugin specific declarations *********/
#include <mysql/plugin_auth_common.h>

struct st_mysql_client_plugin_AUTHENTICATION
{
  MYSQL_CLIENT_PLUGIN_HEADER
  int (*authenticate_user)(MYSQL_PLUGIN_VIO *vio, struct st_mysql *mysql);
};

/******** using plugins ************/

/**
  loads a plugin and initializes it

  @param mysql  MYSQL structure.
  @param name   a name of the plugin to load
  @param type   type of plugin that should be loaded, -1 to disable type check
  @param argc   number of arguments to pass to the plugin initialization
                function
  @param ...    arguments for the plugin initialization function

  @retval
  a pointer to the loaded plugin, or NULL in case of a failure
*/
struct st_mysql_client_plugin *
mysql_load_plugin(struct st_mysql *mysql, const char *name, int type,
                  int argc, ...);

/**
  loads a plugin and initializes it, taking va_list as an argument

  This is the same as mysql_load_plugin, but take va_list instead of
  a list of arguments.

  @param mysql  MYSQL structure.
  @param name   a name of the plugin to load
  @param type   type of plugin that should be loaded, -1 to disable type check
  @param argc   number of arguments to pass to the plugin initialization
                function
  @param args   arguments for the plugin initialization function

  @retval
  a pointer to the loaded plugin, or NULL in case of a failure
*/
struct st_mysql_client_plugin *
mysql_load_plugin_v(struct st_mysql *mysql, const char *name, int type,
                    int argc, va_list args);

/**
  finds an already loaded plugin by name, or loads it, if necessary

  @param mysql  MYSQL structure.
  @param name   a name of the plugin to load
  @param type   type of plugin that should be loaded

  @retval
  a pointer to the plugin, or NULL in case of a failure
*/
struct st_mysql_client_plugin *
mysql_client_find_plugin(struct st_mysql *mysql, const char *name, int type);

/**
  adds a plugin structure to the list of loaded plugins

  This is useful if an application has the necessary functionality
  (for example, a special load data handler) statically linked into
  the application binary. It can use this function to register the plugin
  directly, avoiding the need to factor it out into a shared object.

  @param mysql  MYSQL structure. It is only used for error reporting
  @param plugin an st_mysql_client_plugin structure to register

  @retval
  a pointer to the plugin, or NULL in case of a failure
*/
struct st_mysql_client_plugin *
mysql_client_register_plugin(struct st_mysql *mysql,
                             struct st_mysql_client_plugin *plugin);

/**
  set plugin options

  Can be used to set extra options and affect behavior for a plugin.
  This function may be called multiple times to set several options

  @param plugin an st_mysql_client_plugin structure
  @param option a string which specifies the option to set
  @param value  value for the option.

  @retval 0 on success, 1 in case of failure
**/
int mysql_plugin_options(struct st_mysql_client_plugin *plugin,
                         const char *option, const void *value);
#endif

