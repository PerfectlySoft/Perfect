#ifndef MYSQL_PLUGIN_AUTH_COMMON_INCLUDED
/* Copyright (c) 2010, 2012, Oracle and/or its affiliates. All rights reserved.

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

  This file defines constants and data structures that are the same for
  both client- and server-side authentication plugins.
*/
#define MYSQL_PLUGIN_AUTH_COMMON_INCLUDED

/** the max allowed length for a user name */
#define MYSQL_USERNAME_LENGTH 48

/**
  return values of the plugin authenticate_user() method.
*/

/**
  Authentication failed, plugin internal error.
  An error occurred in the authentication plugin itself.
  These errors are reported in table performance_schema.host_cache,
  column COUNT_AUTH_PLUGIN_ERRORS.
*/
#define CR_AUTH_PLUGIN_ERROR 3
/**
  Authentication failed, client server handshake.
  An error occurred during the client server handshake.
  These errors are reported in table performance_schema.host_cache,
  column COUNT_HANDSHAKE_ERRORS.
*/
#define CR_AUTH_HANDSHAKE 2
/**
  Authentication failed, user credentials.
  For example, wrong passwords.
  These errors are reported in table performance_schema.host_cache,
  column COUNT_AUTHENTICATION_ERRORS.
*/
#define CR_AUTH_USER_CREDENTIALS 1
/**
  Authentication failed. Additionally, all other CR_xxx values
  (libmysql error code) can be used too.

  The client plugin may set the error code and the error message directly
  in the MYSQL structure and return CR_ERROR. If a CR_xxx specific error
  code was returned, an error message in the MYSQL structure will be
  overwritten. If CR_ERROR is returned without setting the error in MYSQL,
  CR_UNKNOWN_ERROR will be user.
*/
#define CR_ERROR 0
/**
  Authentication (client part) was successful. It does not mean that the
  authentication as a whole was successful, usually it only means
  that the client was able to send the user name and the password to the
  server. If CR_OK is returned, the libmysql reads the next packet expecting
  it to be one of OK, ERROR, or CHANGE_PLUGIN packets.
*/
#define CR_OK -1
/**
  Authentication was successful.
  It means that the client has done its part successfully and also that
  a plugin has read the last packet (one of OK, ERROR, CHANGE_PLUGIN).
  In this case, libmysql will not read a packet from the server,
  but it will use the data at mysql->net.read_pos.

  A plugin may return this value if the number of roundtrips in the
  authentication protocol is not known in advance, and the client plugin
  needs to read one packet more to determine if the authentication is finished
  or not.
*/
#define CR_OK_HANDSHAKE_COMPLETE -2

typedef struct st_plugin_vio_info
{
  enum { MYSQL_VIO_INVALID, MYSQL_VIO_TCP, MYSQL_VIO_SOCKET,
         MYSQL_VIO_PIPE, MYSQL_VIO_MEMORY } protocol;
  int socket;     /**< it's set, if the protocol is SOCKET or TCP */
#ifdef _WIN32
  HANDLE handle;  /**< it's set, if the protocol is PIPE or MEMORY */
#endif
} MYSQL_PLUGIN_VIO_INFO;

/**
  Provides plugin access to communication channel
*/
typedef struct st_plugin_vio
{
  /**
    Plugin provides a pointer reference and this function sets it to the
    contents of any incoming packet. Returns the packet length, or -1 if
    the plugin should terminate.
  */
  int (*read_packet)(struct st_plugin_vio *vio, 
                     unsigned char **buf);
  
  /**
    Plugin provides a buffer with data and the length and this
    function sends it as a packet. Returns 0 on success, 1 on failure.
  */
  int (*write_packet)(struct st_plugin_vio *vio, 
                      const unsigned char *packet, 
                      int packet_len);

  /**
    Fills in a st_plugin_vio_info structure, providing the information
    about the connection.
  */
  void (*info)(struct st_plugin_vio *vio, struct st_plugin_vio_info *info);

} MYSQL_PLUGIN_VIO;

#endif

