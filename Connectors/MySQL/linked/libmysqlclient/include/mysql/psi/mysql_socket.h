/* Copyright (c) 2010, 2012, Oracle and/or its affiliates. All rights reserved.

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License as
published by the Free Software Foundation; version 2 of the
License.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
02110-1301  USA
*/

#ifndef MYSQL_SOCKET_H
#define MYSQL_SOCKET_H

/* For strlen() */
#include <string.h>
/* For MY_STAT */
#include <my_dir.h>
/* For my_chsize */
#include <my_sys.h>
/* For socket api */
#ifdef __WIN__
  #include <ws2def.h>
  #include <winsock2.h>
  #include <MSWSock.h>
  #define SOCKBUF_T char
#else
  #include <netinet/in.h>
  #define SOCKBUF_T void
#endif
/**
  @file mysql/psi/mysql_socket.h
[...]
*/

#include "mysql/psi/psi.h"

/**
  @defgroup Socket_instrumentation Socket Instrumentation
  @ingroup Instrumentation_interface
  @{
*/

/**
  @def mysql_socket_register(P1, P2, P3)
  Socket registration.
*/
#ifdef HAVE_PSI_SOCKET_INTERFACE
  #define mysql_socket_register(P1, P2, P3) \
    inline_mysql_socket_register(P1, P2, P3)
#else
  #define mysql_socket_register(P1, P2, P3) \
    do {} while (0)
#endif

struct st_mysql_socket
{
  /** The real socket descriptor. */
  my_socket fd;

  /**
    The instrumentation hook.
    Note that this hook is not conditionally defined,
    for binary compatibility of the @c MYSQL_SOCKET interface.
  */
  struct PSI_socket *m_psi;
};

/**
  An instrumented socket.
  @c MYSQL_SOCKET is a replacement for @c my_socket.
*/
typedef struct st_mysql_socket MYSQL_SOCKET;


/**
  @def MYSQL_INVALID_SOCKET
  MYSQL_SOCKET initial value.
*/
//MYSQL_SOCKET MYSQL_INVALID_SOCKET= {INVALID_SOCKET, NULL};
#define MYSQL_INVALID_SOCKET mysql_socket_invalid()

/**
  MYSQL_SOCKET helper. Initialize instrumented socket.
  @sa mysql_socket_getfd
  @sa mysql_socket_setfd
*/
static inline MYSQL_SOCKET
mysql_socket_invalid()
{
  MYSQL_SOCKET mysql_socket= {INVALID_SOCKET, NULL};
  return mysql_socket;
}

/**
  Set socket descriptor and address.
  @param socket nstrumented socket
  @param fd socket descriptor
  @param addr unformatted socket address
  @param adr_len length of socket addres
*/

static inline void
mysql_socket_set_address(
#ifdef HAVE_PSI_SOCKET_INTERFACE
  MYSQL_SOCKET socket,
  const struct sockaddr *addr,
  socklen_t addr_len
#else
  MYSQL_SOCKET socket __attribute__ ((unused)),
  const struct sockaddr *addr __attribute__ ((unused)),
  socklen_t addr_len __attribute__ ((unused))
#endif
)
{
#ifdef HAVE_PSI_SOCKET_INTERFACE
  if (socket.m_psi != NULL)
    PSI_SOCKET_CALL(set_socket_info)(socket.m_psi, NULL, addr, addr_len);
#endif
}

/**
  Set socket descriptor and address.
  @param socket instrumented socket
  @param thread instrumented owning thread
*/
static inline void
mysql_socket_set_thread_owner(
#ifdef HAVE_PSI_SOCKET_INTERFACE
MYSQL_SOCKET socket
#else
MYSQL_SOCKET socket __attribute__ ((unused))
#endif
)
{
#ifdef HAVE_PSI_SOCKET_INTERFACE
  if (socket.m_psi != NULL)
    PSI_SOCKET_CALL(set_socket_thread_owner)(socket.m_psi);
#endif
}

/**
  MYSQL_SOCKET helper. Get socket descriptor.
  @param mysql_socket Instrumented socket
  @sa mysql_socket_setfd
*/
static inline my_socket
mysql_socket_getfd(MYSQL_SOCKET mysql_socket)
{
  return mysql_socket.fd;
}

/**
  MYSQL_SOCKET helper. Set socket descriptor.
  @param mysql_socket Instrumented socket
  @param fd Socket descriptor
  @sa mysql_socket_getfd
*/
static inline void
mysql_socket_setfd(MYSQL_SOCKET *mysql_socket, my_socket fd)
{
  if (likely(mysql_socket != NULL))
    mysql_socket->fd= fd;
}

/**
  @def MYSQL_SOCKET_WAIT_VARIABLES
  Instrumentation helper for socket waits.
  This instrumentation declares local variables.
  Do not use a ';' after this macro
  @param LOCKER locker
  @param STATE locker state
  @sa MYSQL_START_SOCKET_WAIT.
  @sa MYSQL_END_SOCKET_WAIT.
*/
#ifdef HAVE_PSI_SOCKET_INTERFACE
  #define MYSQL_SOCKET_WAIT_VARIABLES(LOCKER, STATE) \
    struct PSI_socket_locker* LOCKER; \
    PSI_socket_locker_state STATE;
#else
  #define MYSQL_SOCKET_WAIT_VARIABLES(LOCKER, STATE)
#endif

/**
  @def MYSQL_START_SOCKET_WAIT
  Instrumentation helper for socket waits.
  This instrumentation marks the start of a wait event.
  @param LOCKER locker
  @param STATE locker state
  @param SOCKET instrumented socket
  @param OP The socket operation to be performed
  @param FLAGS per-socket operation flags.
  @param COUNT bytes to be written/read
  @sa MYSQL_END_SOCKET_WAIT.
*/
#ifdef HAVE_PSI_SOCKET_INTERFACE
  #define MYSQL_START_SOCKET_WAIT(LOCKER, STATE, SOCKET, OP, COUNT) \
    LOCKER= inline_mysql_start_socket_wait(STATE, SOCKET, OP, COUNT,\
                                           __FILE__, __LINE__)
#else
  #define MYSQL_START_SOCKET_WAIT(LOCKER, STATE, SOCKET, OP, COUNT) \
    do {} while (0)
#endif

/**
  @def MYSQL_END_SOCKET_WAIT
  Instrumentation helper for socket waits.
  This instrumentation marks the end of a wait event.
  @param LOCKER locker
  @param COUNT actual bytes written/read, or -1
  @sa MYSQL_START_SOCKET_WAIT.
*/
#ifdef HAVE_PSI_SOCKET_INTERFACE
  #define MYSQL_END_SOCKET_WAIT(LOCKER, COUNT) \
    inline_mysql_end_socket_wait(LOCKER, COUNT)
#else
  #define MYSQL_END_SOCKET_WAIT(LOCKER, COUNT) \
    do {} while (0)
#endif

#ifdef HAVE_PSI_SOCKET_INTERFACE
  #define MYSQL_SOCKET_SET_STATE(SOCKET, STATE) \
    inline_mysql_socket_set_state(SOCKET, STATE)
#else
  #define MYSQL_SOCKET_SET_STATE(SOCKET, STATE) \
    do {} while (0)
#endif

#ifdef HAVE_PSI_SOCKET_INTERFACE
/**
  Instrumentation calls for MYSQL_START_SOCKET_WAIT.
  @sa MYSQL_START_SOCKET_WAIT.
*/
static inline struct PSI_socket_locker*
inline_mysql_start_socket_wait(PSI_socket_locker_state *state,
                               MYSQL_SOCKET mysql_socket,
                               enum PSI_socket_operation op,
                               size_t byte_count,
                               const char *src_file, int src_line)
{
  struct PSI_socket_locker *locker;
  if (mysql_socket.m_psi != NULL)
  {
    locker= PSI_SOCKET_CALL(start_socket_wait)
      (state, mysql_socket.m_psi, op, byte_count, src_file, src_line);
  }
  else
    locker= NULL;
  return locker;
}

/**
  Instrumentation calls for MYSQL_END_SOCKET_WAIT.
  @sa MYSQL_END_SOCKET_WAIT.
*/
static inline void
inline_mysql_end_socket_wait(struct PSI_socket_locker *locker, size_t byte_count)
{
  if (locker != NULL)
    PSI_SOCKET_CALL(end_socket_wait)(locker, byte_count);
}

/**
  Set the state (IDLE, ACTIVE) of an instrumented socket.
  @param socket the instrumented socket
  @param state the new state
  @sa PSI_socket_state
*/
static inline void
inline_mysql_socket_set_state(MYSQL_SOCKET socket, enum PSI_socket_state state)
{
  if (socket.m_psi != NULL)
    PSI_SOCKET_CALL(set_socket_state)(socket.m_psi, state);
}
#endif /* HAVE_PSI_SOCKET_INTERFACE */

/**
  @def mysql_socket_socket(K, D, T, P)
  Create a socket.
  @c mysql_socket_socket is a replacement for @c socket.
  @param K PSI_socket_key for this instrumented socket
  @param D Socket domain
  @param T Protocol type
  @param P Transport protocol
*/

#ifdef HAVE_PSI_SOCKET_INTERFACE
  #define mysql_socket_socket(K, D, T, P) \
    inline_mysql_socket_socket(K, D, T, P)
#else
  #define mysql_socket_socket(K, D, T, P) \
    inline_mysql_socket_socket(D, T, P)
#endif

/**
  @def mysql_socket_bind(FD, AP, L)
  Bind a socket to a local port number and IP address
  @c mysql_socket_bind is a replacement for @c bind.
  @param FD Instrumented socket descriptor returned by socket()
  @param AP Pointer to local port number and IP address in sockaddr structure
  @param L  Length of sockaddr structure
*/
#ifdef HAVE_PSI_SOCKET_INTERFACE
  #define mysql_socket_bind(FD, AP, L) \
    inline_mysql_socket_bind(__FILE__, __LINE__, FD, AP, L)
#else
  #define mysql_socket_bind(FD, AP, L) \
    inline_mysql_socket_bind(FD, AP, L)
#endif

/**
  @def mysql_socket_getsockname(FD, AP, LP)
  Return port number and IP address of the local host
  @c mysql_socket_getsockname is a replacement for @c getsockname.
  @param FD Instrumented socket descriptor returned by socket()
  @param A  Pointer to returned address of local host in sockaddr structure
  @param L  Pointer to length of sockaddr structure
*/
#ifdef HAVE_PSI_SOCKET_INTERFACE
  #define mysql_socket_getsockname(FD, AP, LP) \
    inline_mysql_socket_getsockname(__FILE__, __LINE__, FD, AP, LP)
#else
  #define mysql_socket_getsockname(FD, AP, LP) \
    inline_mysql_socket_getsockname(FD, AP, LP)
#endif

/**
  @def mysql_socket_connect(FD, AP, L)
  Establish a connection to a remote host.
  @c mysql_socket_connect is a replacement for @c connect.
  @param FD Instrumented socket descriptor returned by socket()
  @param AP Pointer to target address in sockaddr structure
  @param L  Length of sockaddr structure
*/
#ifdef HAVE_PSI_SOCKET_INTERFACE
  #define mysql_socket_connect(FD, AP, L) \
    inline_mysql_socket_connect(__FILE__, __LINE__, FD, AP, L)
#else
  #define mysql_socket_connect(FD, AP, L) \
    inline_mysql_socket_connect(FD, AP, L)
#endif

/**
  @def mysql_socket_getpeername(FD, AP, LP)
  Get port number and IP address of remote host that a socket is connected to.
  @c mysql_socket_getpeername is a replacement for @c getpeername.
  @param FD Instrumented socket descriptor returned by socket() or accept()
  @param AP Pointer to returned address of remote host in sockaddr structure
  @param LP Pointer to length of sockaddr structure
*/
#ifdef HAVE_PSI_SOCKET_INTERFACE
  #define mysql_socket_getpeername(FD, AP, LP) \
    inline_mysql_socket_getpeername(__FILE__, __LINE__, FD, AP, LP)
#else
  #define mysql_socket_getpeername(FD, AP, LP) \
    inline_mysql_socket_getpeername(FD, AP, LP)
#endif

/**
  @def mysql_socket_send(FD, B, N, FL)
  Send data from the buffer, B, to a connected socket.
  @c mysql_socket_send is a replacement for @c send.
  @param FD Instrumented socket descriptor returned by socket() or accept()
  @param B  Buffer to send
  @param N  Number of bytes to send
  @param FL Control flags
*/
#ifdef HAVE_PSI_SOCKET_INTERFACE
  #define mysql_socket_send(FD, B, N, FL) \
    inline_mysql_socket_send(__FILE__, __LINE__, FD, B, N, FL)
#else
  #define mysql_socket_send(FD, B, N, FL) \
    inline_mysql_socket_send(FD, B, N, FL)
#endif

/**
  @def mysql_socket_recv(FD, B, N, FL)
  Receive data from a connected socket.
  @c mysql_socket_recv is a replacement for @c recv.
  @param FD Instrumented socket descriptor returned by socket() or accept()
  @param B  Buffer to receive to
  @param N  Maximum bytes to receive
  @param FL Control flags
*/
#ifdef HAVE_PSI_SOCKET_INTERFACE
  #define mysql_socket_recv(FD, B, N, FL) \
    inline_mysql_socket_recv(__FILE__, __LINE__, FD, B, N, FL)
#else
  #define mysql_socket_recv(FD, B, N, FL) \
    inline_mysql_socket_recv(FD, B, N, FL)
#endif

/**
  @def mysql_socket_sendto(FD, B, N, FL, AP, L)
  Send data to a socket at the specified address.
  @c mysql_socket_sendto is a replacement for @c sendto.
  @param FD Instrumented socket descriptor returned by socket()
  @param B  Buffer to send
  @param N  Number of bytes to send
  @param FL Control flags
  @param AP Pointer to destination sockaddr structure
  @param L  Size of sockaddr structure
*/
#ifdef HAVE_PSI_SOCKET_INTERFACE
  #define mysql_socket_sendto(FD, B, N, FL, AP, L) \
    inline_mysql_socket_sendto(__FILE__, __LINE__, FD, B, N, FL, AP, L)
#else
  #define mysql_socket_sendto(FD, B, N, FL, AP, L) \
    inline_mysql_socket_sendto(FD, B, N, FL, AP, L)
#endif

/**
  @def mysql_socket_recvfrom(FD, B, N, FL, AP, L)
  Receive data from a socket and return source address information
  @c mysql_socket_recvfrom is a replacement for @c recvfrom.
  @param FD Instrumented socket descriptor returned by socket()
  @param B  Buffer to receive to
  @param N  Maximum bytes to receive
  @param FL Control flags
  @param AP Pointer to source address in sockaddr_storage structure
  @param L  Size of sockaddr_storage structure
*/
#ifdef HAVE_PSI_SOCKET_INTERFACE
  #define mysql_socket_recvfrom(FD, B, N, FL, AP, LP) \
    inline_mysql_socket_recvfrom(__FILE__, __LINE__, FD, B, N, FL, AP, LP)
#else
  #define mysql_socket_recvfrom(FD, B, N, FL, AP, LP) \
    inline_mysql_socket_recvfrom(FD, B, N, FL, AP, LP)
#endif

/**
  @def mysql_socket_getsockopt(FD, LV, ON, OP, OL)
  Get a socket option for the specified socket.
  @c mysql_socket_getsockopt is a replacement for @c getsockopt.
  @param FD Instrumented socket descriptor returned by socket()
  @param LV Protocol level
  @param ON Option to query
  @param OP Buffer which will contain the value for the requested option
  @param OL Pointer to length of OP
*/
#ifdef HAVE_PSI_SOCKET_INTERFACE
  #define mysql_socket_getsockopt(FD, LV, ON, OP, OL) \
    inline_mysql_socket_getsockopt(__FILE__, __LINE__, FD, LV, ON, OP, OL)
#else
  #define mysql_socket_getsockopt(FD, LV, ON, OP, OL) \
    inline_mysql_socket_getsockopt(FD, LV, ON, OP, OL)
#endif

/**
  @def mysql_socket_setsockopt(FD, LV, ON, OP, OL)
  Set a socket option for the specified socket.
  @c mysql_socket_setsockopt is a replacement for @c setsockopt.
  @param FD Instrumented socket descriptor returned by socket()
  @param LV Protocol level
  @param ON Option to modify
  @param OP Buffer containing the value for the specified option
  @param OL Pointer to length of OP
*/
#ifdef HAVE_PSI_SOCKET_INTERFACE
  #define mysql_socket_setsockopt(FD, LV, ON, OP, OL) \
    inline_mysql_socket_setsockopt(__FILE__, __LINE__, FD, LV, ON, OP, OL)
#else
  #define mysql_socket_setsockopt(FD, LV, ON, OP, OL) \
    inline_mysql_socket_setsockopt(FD, LV, ON, OP, OL)
#endif

/**
  @def mysql_socket_listen(FD, N)
  Set socket state to listen for an incoming connection.
  @c mysql_socket_listen is a replacement for @c listen.
  @param FD Instrumented socket descriptor, bound and connected
  @param N  Maximum number of pending connections allowed.
*/
#ifdef HAVE_PSI_SOCKET_INTERFACE
  #define mysql_socket_listen(FD, N) \
    inline_mysql_socket_listen(__FILE__, __LINE__, FD, N)
#else
  #define mysql_socket_listen(FD, N) \
    inline_mysql_socket_listen(FD, N)
#endif

/**
  @def mysql_socket_accept(K, FD, AP, LP)
  Accept a connection from any remote host; TCP only.
  @c mysql_socket_accept is a replacement for @c accept.
  @param K PSI_socket_key for this instrumented socket
  @param FD Instrumented socket descriptor, bound and placed in a listen state
  @param AP Pointer to sockaddr structure with returned IP address and port of connected host
  @param LP Pointer to length of valid information in AP
*/
#ifdef HAVE_PSI_SOCKET_INTERFACE
  #define mysql_socket_accept(K, FD, AP, LP) \
    inline_mysql_socket_accept(__FILE__, __LINE__, K, FD, AP, LP)
#else
  #define mysql_socket_accept(K, FD, AP, LP) \
    inline_mysql_socket_accept(FD, AP, LP)
#endif

/**
  @def mysql_socket_close(FD)
  Close a socket and sever any connections.
  @c mysql_socket_close is a replacement for @c close.
  @param FD Instrumented socket descriptor returned by socket() or accept()
*/
#ifdef HAVE_PSI_SOCKET_INTERFACE
  #define mysql_socket_close(FD) \
    inline_mysql_socket_close(__FILE__, __LINE__, FD)
#else
  #define mysql_socket_close(FD) \
    inline_mysql_socket_close(FD)
#endif

/**
  @def mysql_socket_shutdown(FD, H)
  Disable receives and/or sends on a socket.
  @c mysql_socket_shutdown is a replacement for @c shutdown.
  @param FD Instrumented socket descriptor returned by socket() or accept()
  @param H  Specifies which operations to shutdown
*/
#ifdef HAVE_PSI_SOCKET_INTERFACE
  #define mysql_socket_shutdown(FD, H) \
    inline_mysql_socket_shutdown(__FILE__, __LINE__, FD, H)
#else
  #define mysql_socket_shutdown(FD, H) \
    inline_mysql_socket_shutdown(FD, H)
#endif

#ifdef HAVE_PSI_SOCKET_INTERFACE
static inline void inline_mysql_socket_register(
  const char *category,
  PSI_socket_info *info,
  int count)
{
  PSI_SOCKET_CALL(register_socket)(category, info, count);
}
#endif

/** mysql_socket_socket */

static inline MYSQL_SOCKET
inline_mysql_socket_socket
(
#ifdef HAVE_PSI_SOCKET_INTERFACE
  PSI_socket_key key,
#endif
  int domain, int type, int protocol)
{
  MYSQL_SOCKET mysql_socket= MYSQL_INVALID_SOCKET;
  mysql_socket.fd= socket(domain, type, protocol);

#ifdef HAVE_PSI_SOCKET_INTERFACE
  if (likely(mysql_socket.fd != INVALID_SOCKET))
  {
    mysql_socket.m_psi= PSI_SOCKET_CALL(init_socket)
      (key, (const my_socket*)&mysql_socket.fd, NULL, 0);
  }
#endif
  return mysql_socket;
}

/** mysql_socket_bind */

static inline int
inline_mysql_socket_bind
(
#ifdef HAVE_PSI_SOCKET_INTERFACE
  const char *src_file, uint src_line,
#endif
  MYSQL_SOCKET mysql_socket, const struct sockaddr *addr, socklen_t len)
{
  int result;

#ifdef HAVE_PSI_SOCKET_INTERFACE
  if (mysql_socket.m_psi != NULL)
  {
    /* Instrumentation start */
    PSI_socket_locker_state state;
    PSI_socket_locker *locker;
    locker= PSI_SOCKET_CALL(start_socket_wait)
      (&state, mysql_socket.m_psi, PSI_SOCKET_BIND, (size_t)0, src_file, src_line);

    /* Instrumented code */
    result= bind(mysql_socket.fd, addr, len);

    /* Instrumentation end */
    if (result == 0)
      PSI_SOCKET_CALL(set_socket_info)(mysql_socket.m_psi, NULL, addr, len);

    if (locker != NULL)
      PSI_SOCKET_CALL(end_socket_wait)(locker, (size_t)0);

    return result;
  }
#endif

  /* Non instrumented code */
  result= bind(mysql_socket.fd, addr, len);
  return result;
}

/** mysql_socket_getsockname */

static inline int
inline_mysql_socket_getsockname
(
#ifdef HAVE_PSI_SOCKET_INTERFACE
  const char *src_file, uint src_line,
#endif
 MYSQL_SOCKET mysql_socket, struct sockaddr *addr, socklen_t *len)
{
  int result;

#ifdef HAVE_PSI_SOCKET_INTERFACE
  if (mysql_socket.m_psi != NULL)
  {
    /* Instrumentation start */
    PSI_socket_locker *locker;
    PSI_socket_locker_state state;
    locker= PSI_SOCKET_CALL(start_socket_wait)
      (&state, mysql_socket.m_psi, PSI_SOCKET_BIND, (size_t)0, src_file, src_line);

    /* Instrumented code */
    result= getsockname(mysql_socket.fd, addr, len);

    /* Instrumentation end */
    if (locker != NULL)
      PSI_SOCKET_CALL(end_socket_wait)(locker, (size_t)0);

    return result;
  }
#endif

  /* Non instrumented code */
  result= getsockname(mysql_socket.fd, addr, len);

  return result;
}

/** mysql_socket_connect */

static inline int
inline_mysql_socket_connect
(
#ifdef HAVE_PSI_SOCKET_INTERFACE
  const char *src_file, uint src_line,
#endif
 MYSQL_SOCKET mysql_socket, const struct sockaddr *addr, socklen_t len)
{
  int result;

#ifdef HAVE_PSI_SOCKET_INTERFACE
  if (mysql_socket.m_psi != NULL)
  {
    /* Instrumentation start */
    PSI_socket_locker *locker;
    PSI_socket_locker_state state;
    locker= PSI_SOCKET_CALL(start_socket_wait)
      (&state, mysql_socket.m_psi, PSI_SOCKET_CONNECT, (size_t)0, src_file, src_line);

    /* Instrumented code */
    result= connect(mysql_socket.fd, addr, len);

    /* Instrumentation end */
    if (locker != NULL)
      PSI_SOCKET_CALL(end_socket_wait)(locker, (size_t)0);

    return result;
  }
#endif

  /* Non instrumented code */
  result= connect(mysql_socket.fd, addr, len);

  return result;
}

/** mysql_socket_getpeername */

static inline int
inline_mysql_socket_getpeername
(
#ifdef HAVE_PSI_SOCKET_INTERFACE
  const char *src_file, uint src_line,
#endif
 MYSQL_SOCKET mysql_socket, struct sockaddr *addr, socklen_t *len)
{
  int result;

#ifdef HAVE_PSI_SOCKET_INTERFACE
  if (mysql_socket.m_psi != NULL)
  {
    /* Instrumentation start */
    PSI_socket_locker *locker;
    PSI_socket_locker_state state;
    locker= PSI_SOCKET_CALL(start_socket_wait)
      (&state, mysql_socket.m_psi, PSI_SOCKET_BIND, (size_t)0, src_file, src_line);

    /* Instrumented code */
    result= getpeername(mysql_socket.fd, addr, len);

    /* Instrumentation end */
    if (locker != NULL)
      PSI_SOCKET_CALL(end_socket_wait)(locker, (size_t)0);

    return result;
  }
#endif

  /* Non instrumented code */
  result= getpeername(mysql_socket.fd, addr, len);

  return result;
}

/** mysql_socket_send */

static inline ssize_t
inline_mysql_socket_send
(
#ifdef HAVE_PSI_SOCKET_INTERFACE
  const char *src_file, uint src_line,
#endif
 MYSQL_SOCKET mysql_socket, const SOCKBUF_T *buf, size_t n, int flags)
{
  ssize_t result;

#ifdef HAVE_PSI_SOCKET_INTERFACE
  if (mysql_socket.m_psi != NULL)
  {
    /* Instrumentation start */
    PSI_socket_locker *locker;
    PSI_socket_locker_state state;
    locker= PSI_SOCKET_CALL(start_socket_wait)
      (&state, mysql_socket.m_psi, PSI_SOCKET_SEND, n, src_file, src_line);

    /* Instrumented code */
    result= send(mysql_socket.fd, buf, IF_WIN((int),) n, flags);

    /* Instrumentation end */
    if (locker != NULL)
    {
      size_t bytes_written;
      bytes_written= (result > -1) ? result : 0;
      PSI_SOCKET_CALL(end_socket_wait)(locker, bytes_written);
    }

    return result;
  }
#endif

  /* Non instrumented code */
  result= send(mysql_socket.fd, buf, IF_WIN((int),) n, flags);

  return result;
}

/** mysql_socket_recv */

static inline ssize_t
inline_mysql_socket_recv
(
#ifdef HAVE_PSI_SOCKET_INTERFACE
  const char *src_file, uint src_line,
#endif
 MYSQL_SOCKET mysql_socket,  SOCKBUF_T *buf, size_t n, int flags)
{
  ssize_t result;

#ifdef HAVE_PSI_SOCKET_INTERFACE
  if (mysql_socket.m_psi != NULL)
  {
    /* Instrumentation start */
    PSI_socket_locker *locker;
    PSI_socket_locker_state state;
    locker= PSI_SOCKET_CALL(start_socket_wait)
      (&state, mysql_socket.m_psi, PSI_SOCKET_RECV, (size_t)0, src_file, src_line);

    /* Instrumented code */
    result= recv(mysql_socket.fd, buf, IF_WIN((int),) n, flags);

    /* Instrumentation end */
    if (locker != NULL)
    {
      size_t bytes_read;
      bytes_read= (result > -1) ? result : 0;
      PSI_SOCKET_CALL(end_socket_wait)(locker, bytes_read);
    }

    return result;
  }
#endif

  /* Non instrumented code */
  result= recv(mysql_socket.fd, buf, IF_WIN((int),) n, flags);

  return result;
}

/** mysql_socket_sendto */

static inline ssize_t
inline_mysql_socket_sendto
(
#ifdef HAVE_PSI_SOCKET_INTERFACE
  const char *src_file, uint src_line,
#endif
 MYSQL_SOCKET mysql_socket, const SOCKBUF_T *buf, size_t n, int flags, const struct sockaddr *addr, socklen_t addr_len)
{
  ssize_t result;

#ifdef HAVE_PSI_SOCKET_INTERFACE
  if (mysql_socket.m_psi != NULL)
  {
    /* Instrumentation start */
    PSI_socket_locker *locker;
    PSI_socket_locker_state state;
    locker= PSI_SOCKET_CALL(start_socket_wait)
      (&state, mysql_socket.m_psi, PSI_SOCKET_SEND, n, src_file, src_line);

    /* Instrumented code */
    result= sendto(mysql_socket.fd, buf, IF_WIN((int),) n, flags, addr, addr_len);

    /* Instrumentation end */
    if (locker != NULL)
    {
      size_t bytes_written;
      bytes_written = (result > -1) ? result : 0;
      PSI_SOCKET_CALL(end_socket_wait)(locker, bytes_written);
    }

    return result;
  }
#endif

  /* Non instrumented code */
  result= sendto(mysql_socket.fd, buf, IF_WIN((int),) n, flags, addr, addr_len);

  return result;
}

/** mysql_socket_recvfrom */

static inline ssize_t
inline_mysql_socket_recvfrom
(
#ifdef HAVE_PSI_SOCKET_INTERFACE
  const char *src_file, uint src_line,
#endif
 MYSQL_SOCKET mysql_socket, SOCKBUF_T *buf, size_t n, int flags,
 struct sockaddr *addr, socklen_t *addr_len)
{
  ssize_t result;

#ifdef HAVE_PSI_SOCKET_INTERFACE
  if (mysql_socket.m_psi != NULL)
  {
    /* Instrumentation start */
    PSI_socket_locker *locker;
    PSI_socket_locker_state state;
    locker= PSI_SOCKET_CALL(start_socket_wait)
      (&state, mysql_socket.m_psi, PSI_SOCKET_RECV, (size_t)0, src_file, src_line);

    /* Instrumented code */
    result= recvfrom(mysql_socket.fd, buf, IF_WIN((int),) n, flags, addr, addr_len);

    /* Instrumentation end */
    if (locker != NULL)
    {
      size_t bytes_read;
      bytes_read = (result > -1) ? result : 0;
      PSI_SOCKET_CALL(end_socket_wait)(locker, bytes_read);
    }

    return result;
  }
#endif

  /* Non instrumented code */
  result= recvfrom(mysql_socket.fd, buf, IF_WIN((int),) n, flags, addr, addr_len);

  return result;
}

/** mysql_socket_getsockopt */

static inline int
inline_mysql_socket_getsockopt
(
#ifdef HAVE_PSI_SOCKET_INTERFACE
  const char *src_file, uint src_line,
#endif
 MYSQL_SOCKET mysql_socket, int level, int optname, SOCKBUF_T *optval, socklen_t *optlen)
{
  int result;

#ifdef HAVE_PSI_SOCKET_INTERFACE
  if (mysql_socket.m_psi != NULL)
  {
    /* Instrumentation start */
    PSI_socket_locker *locker;
    PSI_socket_locker_state state;
    locker= PSI_SOCKET_CALL(start_socket_wait)
      (&state, mysql_socket.m_psi, PSI_SOCKET_OPT, (size_t)0, src_file, src_line);

    /* Instrumented code */
    result= getsockopt(mysql_socket.fd, level, optname, optval, optlen);

    /* Instrumentation end */
    if (locker != NULL)
      PSI_SOCKET_CALL(end_socket_wait)(locker, (size_t)0);

    return result;
  }
#endif

  /* Non instrumented code */
  result= getsockopt(mysql_socket.fd, level, optname, optval, optlen);

  return result;
}

/** mysql_socket_setsockopt */

static inline int
inline_mysql_socket_setsockopt
(
#ifdef HAVE_PSI_SOCKET_INTERFACE
  const char *src_file, uint src_line,
#endif
 MYSQL_SOCKET mysql_socket, int level, int optname, const SOCKBUF_T *optval,
 socklen_t optlen)
{
  int result;

#ifdef HAVE_PSI_SOCKET_INTERFACE
  if (mysql_socket.m_psi)
  {
    /* Instrumentation start */
    PSI_socket_locker *locker;
    PSI_socket_locker_state state;
    locker= PSI_SOCKET_CALL(start_socket_wait)
      (&state, mysql_socket.m_psi, PSI_SOCKET_OPT, (size_t)0, src_file, src_line);

    /* Instrumented code */
    result= setsockopt(mysql_socket.fd, level, optname, optval, optlen);

    /* Instrumentation end */
    if (locker != NULL)
      PSI_SOCKET_CALL(end_socket_wait)(locker, (size_t)0);

    return result;
  }
#endif

  /* Non instrumented code */
  result= setsockopt(mysql_socket.fd, level, optname, optval, optlen);

  return result;
}

/** mysql_socket_listen */

static inline int
inline_mysql_socket_listen
(
#ifdef HAVE_PSI_SOCKET_INTERFACE
  const char *src_file, uint src_line,
#endif
 MYSQL_SOCKET mysql_socket, int backlog)
{
  int result;

#ifdef HAVE_PSI_SOCKET_INTERFACE
  if (mysql_socket.m_psi != NULL)
  {
    /* Instrumentation start */
    PSI_socket_locker *locker;
    PSI_socket_locker_state state;
    locker= PSI_SOCKET_CALL(start_socket_wait)
      (&state, mysql_socket.m_psi, PSI_SOCKET_CONNECT, (size_t)0, src_file, src_line);

    /* Instrumented code */
    result= listen(mysql_socket.fd, backlog);

    /* Instrumentation end */
    if (locker != NULL)
      PSI_SOCKET_CALL(end_socket_wait)(locker, (size_t)0);

    return result;
  }
#endif

  /* Non instrumented code */
  result= listen(mysql_socket.fd, backlog);

  return result;
}

/** mysql_socket_accept */

static inline MYSQL_SOCKET
inline_mysql_socket_accept
(
#ifdef HAVE_PSI_SOCKET_INTERFACE
  const char *src_file, uint src_line, PSI_socket_key key,
#endif
  MYSQL_SOCKET socket_listen, struct sockaddr *addr, socklen_t *addr_len)
{
  MYSQL_SOCKET socket_accept= MYSQL_INVALID_SOCKET;
  socklen_t addr_length= (addr_len != NULL) ? *addr_len : 0;

#ifdef HAVE_PSI_SOCKET_INTERFACE
  if (socket_listen.m_psi != NULL)
  {
    /* Instrumentation start */
    PSI_socket_locker *locker;
    PSI_socket_locker_state state;
    locker= PSI_SOCKET_CALL(start_socket_wait)
      (&state, socket_listen.m_psi, PSI_SOCKET_CONNECT, (size_t)0, src_file, src_line);

    /* Instrumented code */
    socket_accept.fd= accept(socket_listen.fd, addr, &addr_length);

    /* Instrumentation end */
    if (locker != NULL)
      PSI_SOCKET_CALL(end_socket_wait)(locker, (size_t)0);
  }
  else
#endif
  {
    /* Non instrumented code */
    socket_accept.fd= accept(socket_listen.fd, addr, &addr_length);
  }

#ifdef HAVE_PSI_SOCKET_INTERFACE
  if (likely(socket_accept.fd != INVALID_SOCKET))
  {
    /* Initialize the instrument with the new socket descriptor and address */
    socket_accept.m_psi= PSI_SOCKET_CALL(init_socket)
      (key, (const my_socket*)&socket_accept.fd, addr, addr_length);
  }
#endif

  return socket_accept;
}

/** mysql_socket_close */

static inline int
inline_mysql_socket_close
(
#ifdef HAVE_PSI_SOCKET_INTERFACE
  const char *src_file, uint src_line,
#endif
  MYSQL_SOCKET mysql_socket)
{
  int result;

#ifdef HAVE_PSI_SOCKET_INTERFACE
  if (mysql_socket.m_psi != NULL)
  {
    /* Instrumentation start */
    PSI_socket_locker *locker;
    PSI_socket_locker_state state;
    locker= PSI_SOCKET_CALL(start_socket_wait)
      (&state, mysql_socket.m_psi, PSI_SOCKET_CLOSE, (size_t)0, src_file, src_line);

    /* Instrumented code */
    result= closesocket(mysql_socket.fd);

    /* Instrumentation end */
    if (locker != NULL)
      PSI_SOCKET_CALL(end_socket_wait)(locker, (size_t)0);
    /* Remove the instrumentation for this socket. */
    if (mysql_socket.m_psi != NULL)
      PSI_SOCKET_CALL(destroy_socket)(mysql_socket.m_psi);

    return result;
  }
#endif

  /* Non instrumented code */
  result= closesocket(mysql_socket.fd);

  return result;
}

/** mysql_socket_shutdown */

static inline int
inline_mysql_socket_shutdown
(
#ifdef HAVE_PSI_SOCKET_INTERFACE
  const char *src_file, uint src_line,
#endif
  MYSQL_SOCKET mysql_socket, int how)
{
  int result;

#ifdef __WIN__
  static LPFN_DISCONNECTEX DisconnectEx = NULL;
  if (DisconnectEx == NULL)
  {
    DWORD dwBytesReturned;
    GUID guidDisconnectEx = WSAID_DISCONNECTEX;
    WSAIoctl(mysql_socket.fd, SIO_GET_EXTENSION_FUNCTION_POINTER,
             &guidDisconnectEx, sizeof(GUID),
             &DisconnectEx, sizeof(DisconnectEx), 
             &dwBytesReturned, NULL, NULL);
  }
#endif

/* Instrumentation start */
#ifdef HAVE_PSI_SOCKET_INTERFACE
  if (mysql_socket.m_psi != NULL)
  {
    PSI_socket_locker *locker;
    PSI_socket_locker_state state;
    locker= PSI_SOCKET_CALL(start_socket_wait)
      (&state, mysql_socket.m_psi, PSI_SOCKET_SHUTDOWN, (size_t)0, src_file, src_line);

    /* Instrumented code */
#ifdef __WIN__
    if (DisconnectEx)
      result= (DisconnectEx(mysql_socket.fd, (LPOVERLAPPED) NULL,
                            (DWORD) 0, (DWORD) 0) == TRUE) ? 0 : -1;
    else
#endif
      result= shutdown(mysql_socket.fd, how);

    /* Instrumentation end */
    if (locker != NULL)
      PSI_SOCKET_CALL(end_socket_wait)(locker, (size_t)0);

    return result;
  }
#endif

  /* Non instrumented code */
#ifdef __WIN__
  if (DisconnectEx)
    result= (DisconnectEx(mysql_socket.fd, (LPOVERLAPPED) NULL,
                          (DWORD) 0, (DWORD) 0) == TRUE) ? 0 : -1;
  else
#endif
    result= shutdown(mysql_socket.fd, how);

  return result;
}

/** @} (end of group Socket_instrumentation) */

#endif

