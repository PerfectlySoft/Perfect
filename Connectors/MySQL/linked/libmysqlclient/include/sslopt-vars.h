#ifndef SSLOPT_VARS_INCLUDED
#define SSLOPT_VARS_INCLUDED

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

#if defined(HAVE_OPENSSL) && !defined(EMBEDDED_LIBRARY)
#ifdef SSL_VARS_NOT_STATIC
#define SSL_STATIC
#else
#define SSL_STATIC static
#endif
SSL_STATIC my_bool opt_use_ssl   = 0;
SSL_STATIC char *opt_ssl_ca      = 0;
SSL_STATIC char *opt_ssl_capath  = 0;
SSL_STATIC char *opt_ssl_cert    = 0;
SSL_STATIC char *opt_ssl_cipher  = 0;
SSL_STATIC char *opt_ssl_key     = 0;
SSL_STATIC char *opt_ssl_crl     = 0;
SSL_STATIC char *opt_ssl_crlpath = 0;
#ifdef MYSQL_CLIENT
SSL_STATIC my_bool opt_ssl_verify_server_cert= 0;
#endif
#endif
#endif /* SSLOPT_VARS_INCLUDED */
