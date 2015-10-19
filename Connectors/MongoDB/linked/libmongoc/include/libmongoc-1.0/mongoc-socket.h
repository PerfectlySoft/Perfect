/*
 * Copyright 2014 MongoDB, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef MONGOC_SOCKET_H
#define MONGOC_SOCKET_H

#if !defined (MONGOC_INSIDE) && !defined (MONGOC_COMPILATION)
# error "Only <mongoc.h> can be included directly."
#endif

#include <bson.h>

#ifdef _WIN32
# include <winsock2.h>
# include <ws2tcpip.h>
#else
# include <arpa/inet.h>
# include <poll.h>
# include <netdb.h>
# include <netinet/in.h>
# include <netinet/tcp.h>
# include <sys/types.h>
# include <sys/socket.h>
# include <sys/uio.h>
# include <sys/un.h>
#endif

#include "mongoc-iovec.h"


BSON_BEGIN_DECLS


typedef struct _mongoc_socket_t mongoc_socket_t;


mongoc_socket_t *mongoc_socket_accept     (mongoc_socket_t       *sock,
                                           int64_t                expire_at);
int              mongoc_socket_bind       (mongoc_socket_t       *sock,
                                           const struct sockaddr *addr,
                                           socklen_t              addrlen);
int              mongoc_socket_close      (mongoc_socket_t       *socket);
int              mongoc_socket_connect    (mongoc_socket_t       *sock,
                                           const struct sockaddr *addr,
                                           socklen_t              addrlen,
                                           int64_t                expire_at);
char            *mongoc_socket_getnameinfo(mongoc_socket_t       *sock);
void             mongoc_socket_destroy    (mongoc_socket_t       *sock);
int              mongoc_socket_errno      (mongoc_socket_t       *sock);
int              mongoc_socket_getsockname(mongoc_socket_t       *sock,
                                           struct sockaddr       *addr,
                                           socklen_t             *addrlen);
int              mongoc_socket_listen     (mongoc_socket_t       *sock,
                                           unsigned int           backlog);
mongoc_socket_t *mongoc_socket_new        (int                    domain,
                                           int                    type,
                                           int                    protocol);
ssize_t          mongoc_socket_recv       (mongoc_socket_t       *sock,
                                           void                  *buf,
                                           size_t                 buflen,
                                           int                    flags,
                                           int64_t                expire_at);
int              mongoc_socket_setsockopt (mongoc_socket_t       *sock,
                                           int                    level,
                                           int                    optname,
                                           const void            *optval,
                                           socklen_t              optlen);
ssize_t          mongoc_socket_send       (mongoc_socket_t       *sock,
                                           const void            *buf,
                                           size_t                 buflen,
                                           int64_t                expire_at);
ssize_t          mongoc_socket_sendv      (mongoc_socket_t       *sock,
                                           mongoc_iovec_t        *iov,
                                           size_t                 iovcnt,
                                           int64_t                expire_at);
bool             mongoc_socket_check_closed (mongoc_socket_t       *sock);
void             mongoc_socket_inet_ntop  (struct addrinfo         *rp,
                                           char                    *buf,
                                           size_t                   buflen);


BSON_END_DECLS


#endif /* MONGOC_SOCKET_H */
