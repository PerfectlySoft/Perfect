/* Copyright (c) 2008, 2015, Oracle and/or its affiliates. All rights reserved.

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

#ifndef MYSQL_PERFORMANCE_SCHEMA_INTERFACE_H
#define MYSQL_PERFORMANCE_SCHEMA_INTERFACE_H

#ifdef EMBEDDED_LIBRARY
#define DISABLE_PSI_MUTEX
#define DISABLE_PSI_RWLOCK
#define DISABLE_PSI_COND
#define DISABLE_PSI_FILE
#define DISABLE_PSI_TABLE
#define DISABLE_PSI_SOCKET
#define DISABLE_PSI_STAGE
#define DISABLE_PSI_STATEMENT
#define DISABLE_PSI_IDLE
#define DISABLE_PSI_STATEMENT_DIGEST
#endif /* EMBEDDED_LIBRARY */

#ifndef MY_GLOBAL_INCLUDED
/*
  Make sure a .c or .cc file contains an include to my_global.h first.
  When this include is missing, all the #ifdef HAVE_XXX have no effect,
  and the resulting binary won't build, or won't link,
  or will crash at runtime
  since various structures will have different binary definitions.
*/
#error "You must include my_global.h in the code for the build to be correct."
#endif

C_MODE_START

struct TABLE_SHARE;

struct sql_digest_storage;

/**
  @file mysql/psi/psi.h
  Performance schema instrumentation interface.

  @defgroup Instrumentation_interface Instrumentation Interface
  @ingroup Performance_schema
  @{
*/

/**
  Interface for an instrumented mutex.
  This is an opaque structure.
*/
struct PSI_mutex;
typedef struct PSI_mutex PSI_mutex;

/**
  Interface for an instrumented rwlock.
  This is an opaque structure.
*/
struct PSI_rwlock;
typedef struct PSI_rwlock PSI_rwlock;

/**
  Interface for an instrumented condition.
  This is an opaque structure.
*/
struct PSI_cond;
typedef struct PSI_cond PSI_cond;

/**
  Interface for an instrumented table share.
  This is an opaque structure.
*/
struct PSI_table_share;
typedef struct PSI_table_share PSI_table_share;

/**
  Interface for an instrumented table handle.
  This is an opaque structure.
*/
struct PSI_table;
typedef struct PSI_table PSI_table;

/**
  Interface for an instrumented thread.
  This is an opaque structure.
*/
struct PSI_thread;
typedef struct PSI_thread PSI_thread;

/**
  Interface for an instrumented file handle.
  This is an opaque structure.
*/
struct PSI_file;
typedef struct PSI_file PSI_file;

/**
  Interface for an instrumented socket descriptor.
  This is an opaque structure.
*/
struct PSI_socket;
typedef struct PSI_socket PSI_socket;

/**
  Interface for an instrumented table operation.
  This is an opaque structure.
*/
struct PSI_table_locker;
typedef struct PSI_table_locker PSI_table_locker;

/**
  Interface for an instrumented statement.
  This is an opaque structure.
*/
struct PSI_statement_locker;
typedef struct PSI_statement_locker PSI_statement_locker;

/**
  Interface for an instrumented idle operation.
  This is an opaque structure.
*/
struct PSI_idle_locker;
typedef struct PSI_idle_locker PSI_idle_locker;

/**
  Interface for an instrumented statement digest operation.
  This is an opaque structure.
*/
struct PSI_digest_locker;
typedef struct PSI_digest_locker PSI_digest_locker;

/** Entry point for the performance schema interface. */
struct PSI_bootstrap
{
  /**
    ABI interface finder.
    Calling this method with an interface version number returns either
    an instance of the ABI for this version, or NULL.
    @param version the interface version number to find
    @return a versioned interface (PSI_v1, PSI_v2 or PSI)
    @sa PSI_VERSION_1
    @sa PSI_v1
    @sa PSI_VERSION_2
    @sa PSI_v2
    @sa PSI_CURRENT_VERSION
    @sa PSI
  */
  void* (*get_interface)(int version);
};
typedef struct PSI_bootstrap PSI_bootstrap;

#ifdef HAVE_PSI_INTERFACE

/**
  @def DISABLE_PSI_MUTEX
  Compiling option to disable the mutex instrumentation.
  This option is mostly intended to be used during development,
  when doing special builds with only a subset of the performance schema instrumentation,
  for code analysis / profiling / performance tuning of a specific instrumentation alone.
  For this reason, DISABLE_PSI_MUTEX is not advertised in the cmake general options.
  To disable mutexes, add -DDISABLE_PSI_MUTEX to CFLAGS.
  @sa DISABLE_PSI_RWLOCK
  @sa DISABLE_PSI_COND
  @sa DISABLE_PSI_FILE
  @sa DISABLE_PSI_THREAD
  @sa DISABLE_PSI_TABLE
  @sa DISABLE_PSI_STAGE
  @sa DISABLE_PSI_STATEMENT
  @sa DISABLE_PSI_SOCKET
  @sa DISABLE_PSI_IDLE
*/

#ifndef DISABLE_PSI_MUTEX
#define HAVE_PSI_MUTEX_INTERFACE
#endif

/**
  @def DISABLE_PSI_RWLOCK
  Compiling option to disable the rwlock instrumentation.
  @sa DISABLE_PSI_MUTEX
*/

#ifndef DISABLE_PSI_RWLOCK
#define HAVE_PSI_RWLOCK_INTERFACE
#endif

/**
  @def DISABLE_PSI_COND
  Compiling option to disable the cond instrumentation.
  @sa DISABLE_PSI_MUTEX
*/

#ifndef DISABLE_PSI_COND
#define HAVE_PSI_COND_INTERFACE
#endif

/**
  @def DISABLE_PSI_FILE
  Compiling option to disable the file instrumentation.
  @sa DISABLE_PSI_MUTEX
*/

#ifndef DISABLE_PSI_FILE
#define HAVE_PSI_FILE_INTERFACE
#endif

/**
  @def DISABLE_PSI_THREAD
  Compiling option to disable the thread instrumentation.
  @sa DISABLE_PSI_MUTEX
*/
#ifndef DISABLE_PSI_THREAD
#define HAVE_PSI_THREAD_INTERFACE
#endif

/**
  @def DISABLE_PSI_TABLE
  Compiling option to disable the table instrumentation.
  @sa DISABLE_PSI_MUTEX
*/

#ifndef DISABLE_PSI_TABLE
#define HAVE_PSI_TABLE_INTERFACE
#endif

/**
  @def DISABLE_PSI_STAGE
  Compiling option to disable the stage instrumentation.
  @sa DISABLE_PSI_MUTEX
*/

#ifndef DISABLE_PSI_STAGE
#define HAVE_PSI_STAGE_INTERFACE
#endif

/**
  @def DISABLE_PSI_STATEMENT
  Compiling option to disable the statement instrumentation.
  @sa DISABLE_PSI_MUTEX
*/

#ifndef DISABLE_PSI_STATEMENT
#define HAVE_PSI_STATEMENT_INTERFACE
#endif

/**
  @def DISABLE_PSI_STATEMENT_DIGEST
  Compiling option to disable the statement digest instrumentation.
*/

#ifndef DISABLE_PSI_STATEMENT
#ifndef DISABLE_PSI_STATEMENT_DIGEST
#define HAVE_PSI_STATEMENT_DIGEST_INTERFACE
#endif
#endif

/**
  @def DISABLE_PSI_SOCKET
  Compiling option to disable the statement instrumentation.
  @sa DISABLE_PSI_MUTEX
*/

#ifndef DISABLE_PSI_SOCKET
#define HAVE_PSI_SOCKET_INTERFACE
#endif

/**
  @def DISABLE_PSI_IDLE
  Compiling option to disable the idle instrumentation.
  @sa DISABLE_PSI_MUTEX
*/

#ifndef DISABLE_PSI_IDLE
#define HAVE_PSI_IDLE_INTERFACE
#endif

/**
  @def PSI_VERSION_1
  Performance Schema Interface number for version 1.
  This version is supported.
*/
#define PSI_VERSION_1 1

/**
  @def PSI_VERSION_2
  Performance Schema Interface number for version 2.
  This version is not implemented, it's a placeholder.
*/
#define PSI_VERSION_2 2

/**
  @def PSI_CURRENT_VERSION
  Performance Schema Interface number for the most recent version.
  The most current version is @c PSI_VERSION_1
*/
#define PSI_CURRENT_VERSION 1

#ifndef USE_PSI_2
#ifndef USE_PSI_1
#define USE_PSI_1
#endif
#endif

/**
  Interface for an instrumented mutex operation.
  This is an opaque structure.
*/
struct PSI_mutex_locker;
typedef struct PSI_mutex_locker PSI_mutex_locker;

/**
  Interface for an instrumented rwlock operation.
  This is an opaque structure.
*/
struct PSI_rwlock_locker;
typedef struct PSI_rwlock_locker PSI_rwlock_locker;

/**
  Interface for an instrumented condition operation.
  This is an opaque structure.
*/
struct PSI_cond_locker;
typedef struct PSI_cond_locker PSI_cond_locker;

/**
  Interface for an instrumented file operation.
  This is an opaque structure.
*/
struct PSI_file_locker;
typedef struct PSI_file_locker PSI_file_locker;

/**
  Interface for an instrumented socket operation.
  This is an opaque structure.
*/
struct PSI_socket_locker;
typedef struct PSI_socket_locker PSI_socket_locker;

/** Operation performed on an instrumented mutex. */
enum PSI_mutex_operation
{
  /** Lock. */
  PSI_MUTEX_LOCK= 0,
  /** Lock attempt. */
  PSI_MUTEX_TRYLOCK= 1
};
typedef enum PSI_mutex_operation PSI_mutex_operation;

/** Operation performed on an instrumented rwlock. */
enum PSI_rwlock_operation
{
  /** Read lock. */
  PSI_RWLOCK_READLOCK= 0,
  /** Write lock. */
  PSI_RWLOCK_WRITELOCK= 1,
  /** Read lock attempt. */
  PSI_RWLOCK_TRYREADLOCK= 2,
  /** Write lock attempt. */
  PSI_RWLOCK_TRYWRITELOCK= 3
};
typedef enum PSI_rwlock_operation PSI_rwlock_operation;

/** Operation performed on an instrumented condition. */
enum PSI_cond_operation
{
  /** Wait. */
  PSI_COND_WAIT= 0,
  /** Wait, with timeout. */
  PSI_COND_TIMEDWAIT= 1
};
typedef enum PSI_cond_operation PSI_cond_operation;

/** Operation performed on an instrumented file. */
enum PSI_file_operation
{
  /** File creation, as in @c create(). */
  PSI_FILE_CREATE= 0,
  /** Temporary file creation, as in @c create_temp_file(). */
  PSI_FILE_CREATE_TMP= 1,
  /** File open, as in @c open(). */
  PSI_FILE_OPEN= 2,
  /** File open, as in @c fopen(). */
  PSI_FILE_STREAM_OPEN= 3,
  /** File close, as in @c close(). */
  PSI_FILE_CLOSE= 4,
  /** File close, as in @c fclose(). */
  PSI_FILE_STREAM_CLOSE= 5,
  /**
    Generic file read, such as @c fgets(), @c fgetc(), @c fread(), @c read(),
    @c pread().
  */
  PSI_FILE_READ= 6,
  /**
    Generic file write, such as @c fputs(), @c fputc(), @c fprintf(),
    @c vfprintf(), @c fwrite(), @c write(), @c pwrite().
  */
  PSI_FILE_WRITE= 7,
  /** Generic file seek, such as @c fseek() or @c seek(). */
  PSI_FILE_SEEK= 8,
  /** Generic file tell, such as @c ftell() or @c tell(). */
  PSI_FILE_TELL= 9,
  /** File flush, as in @c fflush(). */
  PSI_FILE_FLUSH= 10,
  /** File stat, as in @c stat(). */
  PSI_FILE_STAT= 11,
  /** File stat, as in @c fstat(). */
  PSI_FILE_FSTAT= 12,
  /** File chsize, as in @c my_chsize(). */
  PSI_FILE_CHSIZE= 13,
  /** File delete, such as @c my_delete() or @c my_delete_with_symlink(). */
  PSI_FILE_DELETE= 14,
  /** File rename, such as @c my_rename() or @c my_rename_with_symlink(). */
  PSI_FILE_RENAME= 15,
  /** File sync, as in @c fsync() or @c my_sync(). */
  PSI_FILE_SYNC= 16
};
typedef enum PSI_file_operation PSI_file_operation;

/** IO operation performed on an instrumented table. */
enum PSI_table_io_operation
{
  /** Row fetch. */
  PSI_TABLE_FETCH_ROW= 0,
  /** Row write. */
  PSI_TABLE_WRITE_ROW= 1,
  /** Row update. */
  PSI_TABLE_UPDATE_ROW= 2,
  /** Row delete. */
  PSI_TABLE_DELETE_ROW= 3
};
typedef enum PSI_table_io_operation PSI_table_io_operation;

/** Lock operation performed on an instrumented table. */
enum PSI_table_lock_operation
{
  /** Table lock, in the server layer. */
  PSI_TABLE_LOCK= 0,
  /** Table lock, in the storage engine layer. */
  PSI_TABLE_EXTERNAL_LOCK= 1
};
typedef enum PSI_table_lock_operation PSI_table_lock_operation;

/** State of an instrumented socket. */
enum PSI_socket_state
{
  /** Idle, waiting for the next command. */
  PSI_SOCKET_STATE_IDLE= 1,
  /** Active, executing a command. */
  PSI_SOCKET_STATE_ACTIVE= 2
};
typedef enum PSI_socket_state PSI_socket_state;

/** Operation performed on an instrumented socket. */
enum PSI_socket_operation
{
  /** Socket creation, as in @c socket() or @c socketpair(). */
  PSI_SOCKET_CREATE= 0,
  /** Socket connection, as in @c connect(), @c listen() and @c accept(). */
  PSI_SOCKET_CONNECT= 1,
  /** Socket bind, as in @c bind(), @c getsockname() and @c getpeername(). */
  PSI_SOCKET_BIND= 2,
  /** Socket close, as in @c shutdown(). */
  PSI_SOCKET_CLOSE= 3,
  /** Socket send, @c send(). */
  PSI_SOCKET_SEND= 4,
  /** Socket receive, @c recv(). */
  PSI_SOCKET_RECV= 5,
  /** Socket send, @c sendto(). */
  PSI_SOCKET_SENDTO= 6,
  /** Socket receive, @c recvfrom). */
  PSI_SOCKET_RECVFROM= 7,
  /** Socket send, @c sendmsg(). */
  PSI_SOCKET_SENDMSG= 8,
  /** Socket receive, @c recvmsg(). */
  PSI_SOCKET_RECVMSG= 9,
  /** Socket seek, such as @c fseek() or @c seek(). */
  PSI_SOCKET_SEEK= 10,
  /** Socket options, as in @c getsockopt() and @c setsockopt(). */
  PSI_SOCKET_OPT= 11,
  /** Socket status, as in @c sockatmark() and @c isfdtype(). */
  PSI_SOCKET_STAT= 12,
  /** Socket shutdown, as in @c shutdown(). */
  PSI_SOCKET_SHUTDOWN= 13,
  /** Socket select, as in @c select() and @c poll(). */
  PSI_SOCKET_SELECT= 14
};
typedef enum PSI_socket_operation PSI_socket_operation;

/**
  Instrumented mutex key.
  To instrument a mutex, a mutex key must be obtained using @c register_mutex.
  Using a zero key always disable the instrumentation.
*/
typedef unsigned int PSI_mutex_key;

/**
  Instrumented rwlock key.
  To instrument a rwlock, a rwlock key must be obtained
  using @c register_rwlock.
  Using a zero key always disable the instrumentation.
*/
typedef unsigned int PSI_rwlock_key;

/**
  Instrumented cond key.
  To instrument a condition, a condition key must be obtained
  using @c register_cond.
  Using a zero key always disable the instrumentation.
*/
typedef unsigned int PSI_cond_key;

/**
  Instrumented thread key.
  To instrument a thread, a thread key must be obtained
  using @c register_thread.
  Using a zero key always disable the instrumentation.
*/
typedef unsigned int PSI_thread_key;

/**
  Instrumented file key.
  To instrument a file, a file key must be obtained using @c register_file.
  Using a zero key always disable the instrumentation.
*/
typedef unsigned int PSI_file_key;

/**
  Instrumented stage key.
  To instrument a stage, a stage key must be obtained using @c register_stage.
  Using a zero key always disable the instrumentation.
*/
typedef unsigned int PSI_stage_key;

/**
  Instrumented statement key.
  To instrument a statement, a statement key must be obtained using @c register_statement.
  Using a zero key always disable the instrumentation.
*/
typedef unsigned int PSI_statement_key;

/**
  Instrumented socket key.
  To instrument a socket, a socket key must be obtained using @c register_socket.
  Using a zero key always disable the instrumentation.
*/
typedef unsigned int PSI_socket_key;

/**
  @def USE_PSI_1
  Define USE_PSI_1 to use the interface version 1.
*/

/**
  @def USE_PSI_2
  Define USE_PSI_2 to use the interface version 2.
*/

/**
  @def HAVE_PSI_1
  Define HAVE_PSI_1 if the interface version 1 needs to be compiled in.
*/

/**
  @def HAVE_PSI_2
  Define HAVE_PSI_2 if the interface version 2 needs to be compiled in.
*/

/**
  Global flag.
  This flag indicate that an instrumentation point is a global variable,
  or a singleton.
*/
#define PSI_FLAG_GLOBAL (1 << 0)

/**
  Global flag.
  This flag indicate that an instrumentation point is a general placeholder,
  that can mutate into a more specific instrumentation point.
*/
#define PSI_FLAG_MUTABLE (1 << 1)

#ifdef USE_PSI_1
#define HAVE_PSI_1
#endif

#ifdef HAVE_PSI_1

/**
  @defgroup Group_PSI_v1 Application Binary Interface, version 1
  @ingroup Instrumentation_interface
  @{
*/

/**
  Mutex information.
  @since PSI_VERSION_1
  This structure is used to register an instrumented mutex.
*/
struct PSI_mutex_info_v1
{
  /**
    Pointer to the key assigned to the registered mutex.
  */
  PSI_mutex_key *m_key;
  /**
    The name of the mutex to register.
  */
  const char *m_name;
  /**
    The flags of the mutex to register.
    @sa PSI_FLAG_GLOBAL
  */
  int m_flags;
};

/**
  Rwlock information.
  @since PSI_VERSION_1
  This structure is used to register an instrumented rwlock.
*/
struct PSI_rwlock_info_v1
{
  /**
    Pointer to the key assigned to the registered rwlock.
  */
  PSI_rwlock_key *m_key;
  /**
    The name of the rwlock to register.
  */
  const char *m_name;
  /**
    The flags of the rwlock to register.
    @sa PSI_FLAG_GLOBAL
  */
  int m_flags;
};

/**
  Condition information.
  @since PSI_VERSION_1
  This structure is used to register an instrumented cond.
*/
struct PSI_cond_info_v1
{
  /**
    Pointer to the key assigned to the registered cond.
  */
  PSI_cond_key *m_key;
  /**
    The name of the cond to register.
  */
  const char *m_name;
  /**
    The flags of the cond to register.
    @sa PSI_FLAG_GLOBAL
  */
  int m_flags;
};

/**
  Thread instrument information.
  @since PSI_VERSION_1
  This structure is used to register an instrumented thread.
*/
struct PSI_thread_info_v1
{
  /**
    Pointer to the key assigned to the registered thread.
  */
  PSI_thread_key *m_key;
  /**
    The name of the thread instrument to register.
  */
  const char *m_name;
  /**
    The flags of the thread to register.
    @sa PSI_FLAG_GLOBAL
  */
  int m_flags;
};

/**
  File instrument information.
  @since PSI_VERSION_1
  This structure is used to register an instrumented file.
*/
struct PSI_file_info_v1
{
  /**
    Pointer to the key assigned to the registered file.
  */
  PSI_file_key *m_key;
  /**
    The name of the file instrument to register.
  */
  const char *m_name;
  /**
    The flags of the file instrument to register.
    @sa PSI_FLAG_GLOBAL
  */
  int m_flags;
};

/**
  Stage instrument information.
  @since PSI_VERSION_1
  This structure is used to register an instrumented stage.
*/
struct PSI_stage_info_v1
{
  /** The registered stage key. */
  PSI_stage_key m_key;
  /** The name of the stage instrument to register. */
  const char *m_name;
  /** The flags of the stage instrument to register. */
  int m_flags;
};

/**
  Statement instrument information.
  @since PSI_VERSION_1
  This structure is used to register an instrumented statement.
*/
struct PSI_statement_info_v1
{
  /** The registered statement key. */
  PSI_statement_key m_key;
  /** The name of the statement instrument to register. */
  const char *m_name;
  /** The flags of the statement instrument to register. */
  int m_flags;
};

/**
  Socket instrument information.
  @since PSI_VERSION_1
  This structure is used to register an instrumented socket.
*/
struct PSI_socket_info_v1
{
  /**
    Pointer to the key assigned to the registered socket.
  */
  PSI_socket_key *m_key;
  /**
    The name of the socket instrument to register.
  */
  const char *m_name;
  /**
    The flags of the socket instrument to register.
    @sa PSI_FLAG_GLOBAL
  */
  int m_flags;
};

/**
  State data storage for @c start_idle_wait_v1_t.
  This structure provide temporary storage to an idle locker.
  The content of this structure is considered opaque,
  the fields are only hints of what an implementation
  of the psi interface can use.
  This memory is provided by the instrumented code for performance reasons.
  @sa start_idle_wait_v1_t.
*/
struct PSI_idle_locker_state_v1
{
  /** Internal state. */
  uint m_flags;
  /** Current thread. */
  struct PSI_thread *m_thread;
  /** Timer start. */
  ulonglong m_timer_start;
  /** Timer function. */
  ulonglong (*m_timer)(void);
  /** Internal data. */
  void *m_wait;
};

/**
  State data storage for @c start_mutex_wait_v1_t.
  This structure provide temporary storage to a mutex locker.
  The content of this structure is considered opaque,
  the fields are only hints of what an implementation
  of the psi interface can use.
  This memory is provided by the instrumented code for performance reasons.
  @sa start_mutex_wait_v1_t
*/
struct PSI_mutex_locker_state_v1
{
  /** Internal state. */
  uint m_flags;
  /** Current operation. */
  enum PSI_mutex_operation m_operation;
  /** Current mutex. */
  struct PSI_mutex *m_mutex;
  /** Current thread. */
  struct PSI_thread *m_thread;
  /** Timer start. */
  ulonglong m_timer_start;
  /** Timer function. */
  ulonglong (*m_timer)(void);
  /** Internal data. */
  void *m_wait;
};

/**
  State data storage for @c start_rwlock_rdwait_v1_t, @c start_rwlock_wrwait_v1_t.
  This structure provide temporary storage to a rwlock locker.
  The content of this structure is considered opaque,
  the fields are only hints of what an implementation
  of the psi interface can use.
  This memory is provided by the instrumented code for performance reasons.
  @sa start_rwlock_rdwait_v1_t
  @sa start_rwlock_wrwait_v1_t
*/
struct PSI_rwlock_locker_state_v1
{
  /** Internal state. */
  uint m_flags;
  /** Current operation. */
  enum PSI_rwlock_operation m_operation;
  /** Current rwlock. */
  struct PSI_rwlock *m_rwlock;
  /** Current thread. */
  struct PSI_thread *m_thread;
  /** Timer start. */
  ulonglong m_timer_start;
  /** Timer function. */
  ulonglong (*m_timer)(void);
  /** Internal data. */
  void *m_wait;
};

/**
  State data storage for @c start_cond_wait_v1_t.
  This structure provide temporary storage to a condition locker.
  The content of this structure is considered opaque,
  the fields are only hints of what an implementation
  of the psi interface can use.
  This memory is provided by the instrumented code for performance reasons.
  @sa start_cond_wait_v1_t
*/
struct PSI_cond_locker_state_v1
{
  /** Internal state. */
  uint m_flags;
  /** Current operation. */
  enum PSI_cond_operation m_operation;
  /** Current condition. */
  struct PSI_cond *m_cond;
  /** Current mutex. */
  struct PSI_mutex *m_mutex;
  /** Current thread. */
  struct PSI_thread *m_thread;
  /** Timer start. */
  ulonglong m_timer_start;
  /** Timer function. */
  ulonglong (*m_timer)(void);
  /** Internal data. */
  void *m_wait;
};

/**
  State data storage for @c get_thread_file_name_locker_v1_t.
  This structure provide temporary storage to a file locker.
  The content of this structure is considered opaque,
  the fields are only hints of what an implementation
  of the psi interface can use.
  This memory is provided by the instrumented code for performance reasons.
  @sa get_thread_file_name_locker_v1_t
  @sa get_thread_file_stream_locker_v1_t
  @sa get_thread_file_descriptor_locker_v1_t
*/
struct PSI_file_locker_state_v1
{
  /** Internal state. */
  uint m_flags;
  /** Current operation. */
  enum PSI_file_operation m_operation;
  /** Current file. */
  struct PSI_file *m_file;
  /** Current file name. */
  const char *m_name;
  /** Current file class. */
  void *m_class;
  /** Current thread. */
  struct PSI_thread *m_thread;
  /** Operation number of bytes. */
  size_t m_number_of_bytes;
  /** Timer start. */
  ulonglong m_timer_start;
  /** Timer function. */
  ulonglong (*m_timer)(void);
  /** Internal data. */
  void *m_wait;
};

/**
  State data storage for @c start_table_io_wait_v1_t,
  @c start_table_lock_wait_v1_t.
  This structure provide temporary storage to a table locker.
  The content of this structure is considered opaque,
  the fields are only hints of what an implementation
  of the psi interface can use.
  This memory is provided by the instrumented code for performance reasons.
  @sa start_table_io_wait_v1_t
  @sa start_table_lock_wait_v1_t
*/
struct PSI_table_locker_state_v1
{
  /** Internal state. */
  uint m_flags;
  /** Current io operation. */
  enum PSI_table_io_operation m_io_operation;
  /** Current table handle. */
  struct PSI_table *m_table;
  /** Current table share. */
  struct PSI_table_share *m_table_share;
  /** Current thread. */
  struct PSI_thread *m_thread;
  /** Timer start. */
  ulonglong m_timer_start;
  /** Timer function. */
  ulonglong (*m_timer)(void);
  /** Internal data. */
  void *m_wait;
  /**
    Implementation specific.
    For table io, the table io index.
    For table lock, the lock type.
  */
  uint m_index;
};

/* Duplicate of NAME_LEN, to avoid dependency on mysql_com.h */
#define PSI_SCHEMA_NAME_LEN (64 * 3)

/**
  State data storage for @c get_thread_statement_locker_v1_t,
  @c get_thread_statement_locker_v1_t.
  This structure provide temporary storage to a statement locker.
  The content of this structure is considered opaque,
  the fields are only hints of what an implementation
  of the psi interface can use.
  This memory is provided by the instrumented code for performance reasons.
  @sa get_thread_statement_locker_v1_t
*/
struct PSI_statement_locker_state_v1
{
  /** Discarded flag. */
  my_bool m_discarded;
  /** Metric, no index used flag. */
  uchar m_no_index_used;
  /** Metric, no good index used flag. */
  uchar m_no_good_index_used;
  /** Internal state. */
  uint m_flags;
  /** Instrumentation class. */
  void *m_class;
  /** Current thread. */
  struct PSI_thread *m_thread;
  /** Timer start. */
  ulonglong m_timer_start;
  /** Timer function. */
  ulonglong (*m_timer)(void);
  /** Internal data. */
  void *m_statement;
  /** Locked time. */
  ulonglong m_lock_time;
  /** Rows sent. */
  ulonglong m_rows_sent;
  /** Rows examined. */
  ulonglong m_rows_examined;
  /** Metric, temporary tables created on disk. */
  ulong m_created_tmp_disk_tables;
  /** Metric, temporary tables created. */
  ulong m_created_tmp_tables;
  /** Metric, number of select full join. */
  ulong m_select_full_join;
  /** Metric, number of select full range join. */
  ulong m_select_full_range_join;
  /** Metric, number of select range. */
  ulong m_select_range;
  /** Metric, number of select range check. */
  ulong m_select_range_check;
  /** Metric, number of select scan. */
  ulong m_select_scan;
  /** Metric, number of sort merge passes. */
  ulong m_sort_merge_passes;
  /** Metric, number of sort merge. */
  ulong m_sort_range;
  /** Metric, number of sort rows. */
  ulong m_sort_rows;
  /** Metric, number of sort scans. */
  ulong m_sort_scan;
  /** Statement digest. */
  const struct sql_digest_storage *m_digest;
  /** Current schema name. */
  char m_schema_name[PSI_SCHEMA_NAME_LEN];
  /** Length in bytes of @c m_schema_name. */
  uint m_schema_name_length;
};

/**
  State data storage for @c start_socket_wait_v1_t.
  This structure provide temporary storage to a socket locker.
  The content of this structure is considered opaque,
  the fields are only hints of what an implementation
  of the psi interface can use.
  This memory is provided by the instrumented code for performance reasons.
  @sa start_socket_wait_v1_t
*/
struct PSI_socket_locker_state_v1
{
  /** Internal state. */
  uint m_flags;
  /** Current socket. */
  struct PSI_socket *m_socket;
  /** Current thread. */
  struct PSI_thread *m_thread;
  /** Operation number of bytes. */
  size_t m_number_of_bytes;
  /** Timer start. */
  ulonglong m_timer_start;
  /** Timer function. */
  ulonglong (*m_timer)(void);
  /** Current operation. */
  enum PSI_socket_operation m_operation;
  /** Source file. */
  const char* m_src_file;
  /** Source line number. */
  int m_src_line;
  /** Internal data. */
  void *m_wait;
};

/* Using typedef to make reuse between PSI_v1 and PSI_v2 easier later. */

/**
  Mutex registration API.
  @param category a category name (typically a plugin name)
  @param info an array of mutex info to register
  @param count the size of the info array
*/
typedef void (*register_mutex_v1_t)
  (const char *category, struct PSI_mutex_info_v1 *info, int count);

/**
  Rwlock registration API.
  @param category a category name (typically a plugin name)
  @param info an array of rwlock info to register
  @param count the size of the info array
*/
typedef void (*register_rwlock_v1_t)
  (const char *category, struct PSI_rwlock_info_v1 *info, int count);

/**
  Cond registration API.
  @param category a category name (typically a plugin name)
  @param info an array of cond info to register
  @param count the size of the info array
*/
typedef void (*register_cond_v1_t)
  (const char *category, struct PSI_cond_info_v1 *info, int count);

/**
  Thread registration API.
  @param category a category name (typically a plugin name)
  @param info an array of thread info to register
  @param count the size of the info array
*/
typedef void (*register_thread_v1_t)
  (const char *category, struct PSI_thread_info_v1 *info, int count);

/**
  File registration API.
  @param category a category name (typically a plugin name)
  @param info an array of file info to register
  @param count the size of the info array
*/
typedef void (*register_file_v1_t)
  (const char *category, struct PSI_file_info_v1 *info, int count);

/**
  Stage registration API.
  @param category a category name
  @param info an array of stage info to register
  @param count the size of the info array
*/
typedef void (*register_stage_v1_t)
  (const char *category, struct PSI_stage_info_v1 **info, int count);

/**
  Statement registration API.
  @param category a category name
  @param info an array of stage info to register
  @param count the size of the info array
*/
typedef void (*register_statement_v1_t)
  (const char *category, struct PSI_statement_info_v1 *info, int count);

/**
  Socket registration API.
  @param category a category name (typically a plugin name)
  @param info an array of socket info to register
  @param count the size of the info array
*/
typedef void (*register_socket_v1_t)
  (const char *category, struct PSI_socket_info_v1 *info, int count);

/**
  Mutex instrumentation initialisation API.
  @param key the registered mutex key
  @param identity the address of the mutex itself
  @return an instrumented mutex
*/
typedef struct PSI_mutex* (*init_mutex_v1_t)
  (PSI_mutex_key key, const void *identity);

/**
  Mutex instrumentation destruction API.
  @param mutex the mutex to destroy
*/
typedef void (*destroy_mutex_v1_t)(struct PSI_mutex *mutex);

/**
  Rwlock instrumentation initialisation API.
  @param key the registered rwlock key
  @param identity the address of the rwlock itself
  @return an instrumented rwlock
*/
typedef struct PSI_rwlock* (*init_rwlock_v1_t)
  (PSI_rwlock_key key, const void *identity);

/**
  Rwlock instrumentation destruction API.
  @param rwlock the rwlock to destroy
*/
typedef void (*destroy_rwlock_v1_t)(struct PSI_rwlock *rwlock);

/**
  Cond instrumentation initialisation API.
  @param key the registered key
  @param identity the address of the rwlock itself
  @return an instrumented cond
*/
typedef struct PSI_cond* (*init_cond_v1_t)
  (PSI_cond_key key, const void *identity);

/**
  Cond instrumentation destruction API.
  @param cond the rcond to destroy
*/
typedef void (*destroy_cond_v1_t)(struct PSI_cond *cond);

/**
  Socket instrumentation initialisation API.
  @param key the registered mutex key
  @param socket descriptor
  @param addr the socket ip address
  @param addr_len length of socket ip address
  @return an instrumented socket
*/
typedef struct PSI_socket* (*init_socket_v1_t)
  (PSI_socket_key key, const my_socket *fd,
  const struct sockaddr *addr, socklen_t addr_len);

/**
  socket instrumentation destruction API.
  @param socket the socket to destroy
*/
typedef void (*destroy_socket_v1_t)(struct PSI_socket *socket);

/**
  Acquire a table share instrumentation.
  @param temporary True for temporary tables
  @param share The SQL layer table share
  @return a table share instrumentation, or NULL
*/
typedef struct PSI_table_share* (*get_table_share_v1_t)
  (my_bool temporary, struct TABLE_SHARE *share);

/**
  Release a table share.
  @param info the table share to release
*/
typedef void (*release_table_share_v1_t)(struct PSI_table_share *share);

/**
  Drop a table share.
  @param temporary True for temporary tables
  @param schema_name the table schema name
  @param schema_name_length the table schema name length
  @param table_name the table name
  @param table_name_length the table name length
*/
typedef void (*drop_table_share_v1_t)
  (my_bool temporary, const char *schema_name, int schema_name_length,
   const char *table_name, int table_name_length);

/**
  Open an instrumentation table handle.
  @param share the table to open
  @param identity table handle identity
  @return a table handle, or NULL
*/
typedef struct PSI_table* (*open_table_v1_t)
  (struct PSI_table_share *share, const void *identity);

/**
  Unbind a table handle from the current thread.
  This operation happens when an opened table is added to the open table cache.
  @param table the table to unbind
*/
typedef void (*unbind_table_v1_t)
  (struct PSI_table *table);

/**
  Rebind a table handle to the current thread.
  This operation happens when a table from the open table cache
  is reused for a thread.
  @param table the table to unbind
*/
typedef PSI_table* (*rebind_table_v1_t)
  (PSI_table_share *share, const void *identity, PSI_table *table);

/**
  Close an instrumentation table handle.
  Note that the table handle is invalid after this call.
  @param table the table handle to close
*/
typedef void (*close_table_v1_t)(struct PSI_table *table);

/**
  Create a file instrumentation for a created file.
  This method does not create the file itself, but is used to notify the
  instrumentation interface that a file was just created.
  @param key the file instrumentation key for this file
  @param name the file name
  @param file the file handle
*/
typedef void (*create_file_v1_t)(PSI_file_key key, const char *name,
                                 File file);

/**
  Spawn a thread.
  This method creates a new thread, with instrumentation.
  @param key the instrumentation key for this thread
  @param thread the resulting thread
  @param attr the thread attributes
  @param start_routine the thread start routine
  @param arg the thread start routine argument
*/
typedef int (*spawn_thread_v1_t)(PSI_thread_key key,
                                 pthread_t *thread,
                                 const pthread_attr_t *attr,
                                 void *(*start_routine)(void*), void *arg);

/**
  Create instrumentation for a thread.
  @param key the registered key
  @param identity an address typical of the thread
  @return an instrumented thread
*/
typedef struct PSI_thread* (*new_thread_v1_t)
  (PSI_thread_key key, const void *identity, ulonglong thread_id);

/**
  Assign an id to an instrumented thread.
  @param thread the instrumented thread
  @param id the id to assign
*/
typedef void (*set_thread_id_v1_t)(struct PSI_thread *thread,
                                   ulonglong id);

/**
  Get the instrumentation for the running thread.
  For this function to return a result,
  the thread instrumentation must have been attached to the
  running thread using @c set_thread()
  @return the instrumentation for the running thread
*/
typedef struct PSI_thread* (*get_thread_v1_t)(void);

/**
  Assign a user name to the instrumented thread.
  @param user the user name
  @param user_len the user name length
*/
typedef void (*set_thread_user_v1_t)(const char *user, int user_len);

/**
  Assign a user name and host name to the instrumented thread.
  @param user the user name
  @param user_len the user name length
  @param host the host name
  @param host_len the host name length
*/
typedef void (*set_thread_user_host_v1_t)(const char *user, int user_len,
                                          const char *host, int host_len);

/**
  Assign a current database to the instrumented thread.
  @param db the database name
  @param db_len the database name length
*/
typedef void (*set_thread_db_v1_t)(const char* db, int db_len);

/**
  Assign a current command to the instrumented thread.
  @param command the current command
*/
typedef void (*set_thread_command_v1_t)(int command);

/**
  Assign a start time to the instrumented thread.
  @param start_time the thread start time
*/
typedef void (*set_thread_start_time_v1_t)(time_t start_time);

/**
  Assign a state to the instrumented thread.
  @param state the thread state
*/
typedef void (*set_thread_state_v1_t)(const char* state);

/**
  Assign a process info to the instrumented thread.
  @param info the process into string
  @param info_len the process into string length
*/
typedef void (*set_thread_info_v1_t)(const char* info, uint info_len);

/**
  Attach a thread instrumentation to the running thread.
  In case of thread pools, this method should be called when
  a worker thread picks a work item and runs it.
  Also, this method should be called if the instrumented code does not
  keep the pointer returned by @c new_thread() and relies on @c get_thread()
  instead.
  @param thread the thread instrumentation
*/
typedef void (*set_thread_v1_t)(struct PSI_thread *thread);

/** Delete the current thread instrumentation. */
typedef void (*delete_current_thread_v1_t)(void);

/** Delete a thread instrumentation. */
typedef void (*delete_thread_v1_t)(struct PSI_thread *thread);

/**
  Get a file instrumentation locker, for opening or creating a file.
  @param state data storage for the locker
  @param key the file instrumentation key
  @param op the operation to perform
  @param name the file name
  @param identity a pointer representative of this file.
  @return a file locker, or NULL
*/
typedef struct PSI_file_locker* (*get_thread_file_name_locker_v1_t)
  (struct PSI_file_locker_state_v1 *state,
   PSI_file_key key, enum PSI_file_operation op, const char *name,
   const void *identity);

/**
  Get a file stream instrumentation locker.
  @param state data storage for the locker
  @param file the file stream to access
  @param op the operation to perform
  @return a file locker, or NULL
*/
typedef struct PSI_file_locker* (*get_thread_file_stream_locker_v1_t)
  (struct PSI_file_locker_state_v1 *state,
   struct PSI_file *file, enum PSI_file_operation op);

/**
  Get a file instrumentation locker.
  @param state data storage for the locker
  @param file the file descriptor to access
  @param op the operation to perform
  @return a file locker, or NULL
*/
typedef struct PSI_file_locker* (*get_thread_file_descriptor_locker_v1_t)
  (struct PSI_file_locker_state_v1 *state,
   File file, enum PSI_file_operation op);

/**
  Record a mutex instrumentation unlock event.
  @param mutex the mutex instrumentation
*/
typedef void (*unlock_mutex_v1_t)
  (struct PSI_mutex *mutex);

/**
  Record a rwlock instrumentation unlock event.
  @param rwlock the rwlock instrumentation
*/
typedef void (*unlock_rwlock_v1_t)
  (struct PSI_rwlock *rwlock);

/**
  Record a condition instrumentation signal event.
  @param cond the cond instrumentation
*/
typedef void (*signal_cond_v1_t)
  (struct PSI_cond *cond);

/**
  Record a condition instrumentation broadcast event.
  @param cond the cond instrumentation
*/
typedef void (*broadcast_cond_v1_t)
  (struct PSI_cond *cond);

typedef struct PSI_idle_locker* (*start_idle_wait_v1_t)
  (struct PSI_idle_locker_state_v1 *state, const char *src_file, uint src_line);

typedef void (*end_idle_wait_v1_t)
  (struct PSI_idle_locker *locker);

/**
  Record a mutex instrumentation wait start event.
  @param state data storage for the locker
  @param mutex the instrumented mutex to lock
  @param op the operation to perform
  @param file the source file name
  @param line the source line number
  @return a mutex locker, or NULL
*/
typedef struct PSI_mutex_locker* (*start_mutex_wait_v1_t)
  (struct PSI_mutex_locker_state_v1 *state,
   struct PSI_mutex *mutex,
   enum PSI_mutex_operation op,
   const char *src_file, uint src_line);

/**
  Record a mutex instrumentation wait end event.
  @param locker a thread locker for the running thread
  @param rc the wait operation return code
*/
typedef void (*end_mutex_wait_v1_t)
  (struct PSI_mutex_locker *locker, int rc);

/**
  Record a rwlock instrumentation read wait start event.
  @param locker a thread locker for the running thread
  @param must must block: 1 for lock, 0 for trylock
*/
typedef struct PSI_rwlock_locker* (*start_rwlock_rdwait_v1_t)
  (struct PSI_rwlock_locker_state_v1 *state,
   struct PSI_rwlock *rwlock,
   enum PSI_rwlock_operation op,
   const char *src_file, uint src_line);

/**
  Record a rwlock instrumentation read wait end event.
  @param locker a thread locker for the running thread
  @param rc the wait operation return code
*/
typedef void (*end_rwlock_rdwait_v1_t)
  (struct PSI_rwlock_locker *locker, int rc);

/**
  Record a rwlock instrumentation write wait start event.
  @param locker a thread locker for the running thread
  @param must must block: 1 for lock, 0 for trylock
*/
typedef struct PSI_rwlock_locker* (*start_rwlock_wrwait_v1_t)
  (struct PSI_rwlock_locker_state_v1 *state,
   struct PSI_rwlock *rwlock,
   enum PSI_rwlock_operation op,
   const char *src_file, uint src_line);

/**
  Record a rwlock instrumentation write wait end event.
  @param locker a thread locker for the running thread
  @param rc the wait operation return code
*/
typedef void (*end_rwlock_wrwait_v1_t)
  (struct PSI_rwlock_locker *locker, int rc);

/**
  Record a condition instrumentation wait start event.
  @param locker a thread locker for the running thread
  @param must must block: 1 for wait, 0 for timedwait
*/
typedef struct PSI_cond_locker* (*start_cond_wait_v1_t)
  (struct PSI_cond_locker_state_v1 *state,
   struct PSI_cond *cond,
   struct PSI_mutex *mutex,
   enum PSI_cond_operation op,
   const char *src_file, uint src_line);

/**
  Record a condition instrumentation wait end event.
  @param locker a thread locker for the running thread
  @param rc the wait operation return code
*/
typedef void (*end_cond_wait_v1_t)
  (struct PSI_cond_locker *locker, int rc);

/**
  Record a table instrumentation io wait start event.
  @param locker a table locker for the running thread
  @param file the source file name
  @param line the source line number
*/
typedef struct PSI_table_locker* (*start_table_io_wait_v1_t)
  (struct PSI_table_locker_state_v1 *state,
   struct PSI_table *table,
   enum PSI_table_io_operation op,
   uint index,
   const char *src_file, uint src_line);

/**
  Record a table instrumentation io wait end event.
  @param locker a table locker for the running thread
*/
typedef void (*end_table_io_wait_v1_t)(struct PSI_table_locker *locker);

/**
  Record a table instrumentation lock wait start event.
  @param locker a table locker for the running thread
  @param file the source file name
  @param line the source line number
*/
typedef struct PSI_table_locker* (*start_table_lock_wait_v1_t)
  (struct PSI_table_locker_state_v1 *state,
   struct PSI_table *table,
   enum PSI_table_lock_operation op,
   ulong flags,
   const char *src_file, uint src_line);

/**
  Record a table instrumentation lock wait end event.
  @param locker a table locker for the running thread
*/
typedef void (*end_table_lock_wait_v1_t)(struct PSI_table_locker *locker);

/**
  Start a file instrumentation open operation.
  @param locker the file locker
  @param op the operation to perform
  @param src_file the source file name
  @param src_line the source line number
*/
typedef void (*start_file_open_wait_v1_t)
  (struct PSI_file_locker *locker, const char *src_file, uint src_line);

/**
  End a file instrumentation open operation, for file streams.
  @param locker the file locker.
  @param result the opened file (NULL indicates failure, non NULL success).
  @return an instrumented file handle
*/
typedef struct PSI_file* (*end_file_open_wait_v1_t)
  (struct PSI_file_locker *locker, void *result);

/**
  End a file instrumentation open operation, for non stream files.
  @param locker the file locker.
  @param file the file number assigned by open() or create() for this file.
*/
typedef void (*end_file_open_wait_and_bind_to_descriptor_v1_t)
  (struct PSI_file_locker *locker, File file);

/**
  Record a file instrumentation start event.
  @param locker a file locker for the running thread
  @param op file operation to be performed
  @param count the number of bytes requested, or 0 if not applicable
  @param src_file the source file name
  @param src_line the source line number
*/
typedef void (*start_file_wait_v1_t)
  (struct PSI_file_locker *locker, size_t count,
   const char *src_file, uint src_line);

/**
  Record a file instrumentation end event.
  Note that for file close operations, the instrumented file handle
  associated with the file (which was provided to obtain a locker)
  is invalid after this call.
  @param locker a file locker for the running thread
  @param count the number of bytes actually used in the operation,
  or 0 if not applicable, or -1 if the operation failed
  @sa get_thread_file_name_locker
  @sa get_thread_file_stream_locker
  @sa get_thread_file_descriptor_locker
*/
typedef void (*end_file_wait_v1_t)
  (struct PSI_file_locker *locker, size_t count);

/**
  Start a file instrumentation close operation.
  @param locker the file locker
  @param op the operation to perform
  @param src_file the source file name
  @param src_line the source line number
*/
typedef void (*start_file_close_wait_v1_t)
  (struct PSI_file_locker *locker, const char *src_file, uint src_line);

/**
  End a file instrumentation close operation.
  @param locker the file locker.
  @param rc the close operation return code (0 for success).
  @return an instrumented file handle
*/
typedef void (*end_file_close_wait_v1_t)
  (struct PSI_file_locker *locker, int rc);

/**
  Start a new stage, and implicitly end the previous stage.
  @param key the key of the new stage
  @param src_file the source file name
  @param src_line the source line number
*/
typedef void (*start_stage_v1_t)
  (PSI_stage_key key, const char *src_file, int src_line);

/** End the current stage. */
typedef void (*end_stage_v1_t) (void);

/**
  Get a statement instrumentation locker.
  @param state data storage for the locker
  @param key the statement instrumentation key
  @param charset client character set
  @return a statement locker, or NULL
*/
typedef struct PSI_statement_locker* (*get_thread_statement_locker_v1_t)
  (struct PSI_statement_locker_state_v1 *state,
   PSI_statement_key key, const void *charset);

/**
  Refine a statement locker to a more specific key.
  Note that only events declared mutable can be refined.
  @param the statement locker for the current event
  @param key the new key for the event
  @sa PSI_FLAG_MUTABLE
*/
typedef struct PSI_statement_locker* (*refine_statement_v1_t)
  (struct PSI_statement_locker *locker,
   PSI_statement_key key);

/**
  Start a new statement event.
  @param locker the statement locker for this event
  @param db the active database name for this statement
  @param db_length the active database name length for this statement
  @param src_file source file name
  @param src_line source line number
*/
typedef void (*start_statement_v1_t)
  (struct PSI_statement_locker *locker,
   const char *db, uint db_length,
   const char *src_file, uint src_line);

/**
  Set the statement text for a statement event.
  @param locker the current statement locker
  @param text the statement text
  @param text_len the statement text length
*/
typedef void (*set_statement_text_v1_t)
  (struct PSI_statement_locker *locker,
   const char *text, uint text_len);

/**
  Set a statement event lock time.
  @param locker the statement locker
  @param lock_time the locked time, in microseconds
*/
typedef void (*set_statement_lock_time_t)
  (struct PSI_statement_locker *locker, ulonglong lock_time);

/**
  Set a statement event rows sent metric.
  @param locker the statement locker
  @param count the number of rows sent
*/
typedef void (*set_statement_rows_sent_t)
  (struct PSI_statement_locker *locker, ulonglong count);

/**
  Set a statement event rows examined metric.
  @param locker the statement locker
  @param count the number of rows examined
*/
typedef void (*set_statement_rows_examined_t)
  (struct PSI_statement_locker *locker, ulonglong count);

/**
  Increment a statement event "created tmp disk tables" metric.
  @param locker the statement locker
  @param count the metric increment value
*/
typedef void (*inc_statement_created_tmp_disk_tables_t)
  (struct PSI_statement_locker *locker, ulong count);

/**
  Increment a statement event "created tmp tables" metric.
  @param locker the statement locker
  @param count the metric increment value
*/
typedef void (*inc_statement_created_tmp_tables_t)
  (struct PSI_statement_locker *locker, ulong count);

/**
  Increment a statement event "select full join" metric.
  @param locker the statement locker
  @param count the metric increment value
*/
typedef void (*inc_statement_select_full_join_t)
  (struct PSI_statement_locker *locker, ulong count);

/**
  Increment a statement event "select full range join" metric.
  @param locker the statement locker
  @param count the metric increment value
*/
typedef void (*inc_statement_select_full_range_join_t)
  (struct PSI_statement_locker *locker, ulong count);

/**
  Increment a statement event "select range join" metric.
  @param locker the statement locker
  @param count the metric increment value
*/
typedef void (*inc_statement_select_range_t)
  (struct PSI_statement_locker *locker, ulong count);

/**
  Increment a statement event "select range check" metric.
  @param locker the statement locker
  @param count the metric increment value
*/
typedef void (*inc_statement_select_range_check_t)
  (struct PSI_statement_locker *locker, ulong count);

/**
  Increment a statement event "select scan" metric.
  @param locker the statement locker
  @param count the metric increment value
*/
typedef void (*inc_statement_select_scan_t)
  (struct PSI_statement_locker *locker, ulong count);

/**
  Increment a statement event "sort merge passes" metric.
  @param locker the statement locker
  @param count the metric increment value
*/
typedef void (*inc_statement_sort_merge_passes_t)
  (struct PSI_statement_locker *locker, ulong count);

/**
  Increment a statement event "sort range" metric.
  @param locker the statement locker
  @param count the metric increment value
*/
typedef void (*inc_statement_sort_range_t)
  (struct PSI_statement_locker *locker, ulong count);

/**
  Increment a statement event "sort rows" metric.
  @param locker the statement locker
  @param count the metric increment value
*/
typedef void (*inc_statement_sort_rows_t)
  (struct PSI_statement_locker *locker, ulong count);

/**
  Increment a statement event "sort scan" metric.
  @param locker the statement locker
  @param count the metric increment value
*/
typedef void (*inc_statement_sort_scan_t)
  (struct PSI_statement_locker *locker, ulong count);

/**
  Set a statement event "no index used" metric.
  @param locker the statement locker
  @param count the metric value
*/
typedef void (*set_statement_no_index_used_t)
  (struct PSI_statement_locker *locker);

/**
  Set a statement event "no good index used" metric.
  @param locker the statement locker
  @param count the metric value
*/
typedef void (*set_statement_no_good_index_used_t)
  (struct PSI_statement_locker *locker);

/**
  End a statement event.
  @param locker the statement locker
  @param stmt_da the statement diagnostics area.
  @sa Diagnostics_area
*/
typedef void (*end_statement_v1_t)
  (struct PSI_statement_locker *locker, void *stmt_da);

/**
  Record a socket instrumentation start event.
  @param locker a socket locker for the running thread
  @param op socket operation to be performed
  @param count the number of bytes requested, or 0 if not applicable
  @param src_file the source file name
  @param src_line the source line number
*/
typedef struct PSI_socket_locker* (*start_socket_wait_v1_t)
  (struct PSI_socket_locker_state_v1 *state,
   struct PSI_socket *socket,
   enum PSI_socket_operation op,
   size_t count,
   const char *src_file, uint src_line);

/**
  Record a socket instrumentation end event.
  Note that for socket close operations, the instrumented socket handle
  associated with the socket (which was provided to obtain a locker)
  is invalid after this call.
  @param locker a socket locker for the running thread
  @param count the number of bytes actually used in the operation,
  or 0 if not applicable, or -1 if the operation failed
  @sa get_thread_socket_locker
*/
typedef void (*end_socket_wait_v1_t)
  (struct PSI_socket_locker *locker, size_t count);

/**
  Set the socket state for an instrumented socket.
    @param socket the instrumented socket
    @param state socket state
  */
typedef void (*set_socket_state_v1_t)(struct PSI_socket *socket,
                                      enum PSI_socket_state state);

/**
  Set the socket info for an instrumented socket.
  @param socket the instrumented socket
  @param fd the socket descriptor
  @param addr the socket ip address
  @param addr_len length of socket ip address
  @param thread_id associated thread id
*/
typedef void (*set_socket_info_v1_t)(struct PSI_socket *socket,
                                     const my_socket *fd,
                                     const struct sockaddr *addr,
                                     socklen_t addr_len);

/**
  Bind a socket to the thread that owns it.
  @param socket instrumented socket
*/
typedef void (*set_socket_thread_owner_v1_t)(struct PSI_socket *socket);

/**
  Get a digest locker for the current statement.
  @param locker a statement locker for the running thread
*/
typedef struct PSI_digest_locker * (*digest_start_v1_t)
  (struct PSI_statement_locker *locker);

typedef void (*digest_end_v1_t)
  (struct PSI_digest_locker *locker, const struct sql_digest_storage *digest);

/**
  Stores an array of connection attributes
  @param buffer         char array of length encoded connection attributes
                        in network format
  @param length         legnth of the data in buffer
  @param from_cs        charset in which @buffer is encodded
  @return state
    @retval  non-0    attributes truncated
    @retval  0        stored the attribute
*/
typedef int (*set_thread_connect_attrs_v1_t)(const char *buffer, uint length,
                                             const void *from_cs);

/**
  Performance Schema Interface, version 1.
  @since PSI_VERSION_1
*/
struct PSI_v1
{
  /** @sa register_mutex_v1_t. */
  register_mutex_v1_t register_mutex;
  /** @sa register_rwlock_v1_t. */
  register_rwlock_v1_t register_rwlock;
  /** @sa register_cond_v1_t. */
  register_cond_v1_t register_cond;
  /** @sa register_thread_v1_t. */
  register_thread_v1_t register_thread;
  /** @sa register_file_v1_t. */
  register_file_v1_t register_file;
  /** @sa register_stage_v1_t. */
  register_stage_v1_t register_stage;
  /** @sa register_statement_v1_t. */
  register_statement_v1_t register_statement;
  /** @sa register_socket_v1_t. */
  register_socket_v1_t register_socket;
  /** @sa init_mutex_v1_t. */
  init_mutex_v1_t init_mutex;
  /** @sa destroy_mutex_v1_t. */
  destroy_mutex_v1_t destroy_mutex;
  /** @sa init_rwlock_v1_t. */
  init_rwlock_v1_t init_rwlock;
  /** @sa destroy_rwlock_v1_t. */
  destroy_rwlock_v1_t destroy_rwlock;
  /** @sa init_cond_v1_t. */
  init_cond_v1_t init_cond;
  /** @sa destroy_cond_v1_t. */
  destroy_cond_v1_t destroy_cond;
  /** @sa init_socket_v1_t. */
  init_socket_v1_t init_socket;
  /** @sa destroy_socket_v1_t. */
  destroy_socket_v1_t destroy_socket;
  /** @sa get_table_share_v1_t. */
  get_table_share_v1_t get_table_share;
  /** @sa release_table_share_v1_t. */
  release_table_share_v1_t release_table_share;
  /** @sa drop_table_share_v1_t. */
  drop_table_share_v1_t drop_table_share;
  /** @sa open_table_v1_t. */
  open_table_v1_t open_table;
  /** @sa unbind_table_v1_t. */
  unbind_table_v1_t unbind_table;
  /** @sa rebind_table_v1_t. */
  rebind_table_v1_t rebind_table;
  /** @sa close_table_v1_t. */
  close_table_v1_t close_table;
  /** @sa create_file_v1_t. */
  create_file_v1_t create_file;
  /** @sa spawn_thread_v1_t. */
  spawn_thread_v1_t spawn_thread;
  /** @sa new_thread_v1_t. */
  new_thread_v1_t new_thread;
  /** @sa set_thread_id_v1_t. */
  set_thread_id_v1_t set_thread_id;
  /** @sa get_thread_v1_t. */
  get_thread_v1_t get_thread;
  /** @sa set_thread_user_v1_t. */
  set_thread_user_v1_t set_thread_user;
  /** @sa set_thread_user_host_v1_t. */
  set_thread_user_host_v1_t set_thread_user_host;
  /** @sa set_thread_db_v1_t. */
  set_thread_db_v1_t set_thread_db;
  /** @sa set_thread_command_v1_t. */
  set_thread_command_v1_t set_thread_command;
  /** @sa set_thread_start_time_v1_t. */
  set_thread_start_time_v1_t set_thread_start_time;
  /** @sa set_thread_state_v1_t. */
  set_thread_state_v1_t set_thread_state;
  /** @sa set_thread_info_v1_t. */
  set_thread_info_v1_t set_thread_info;
  /** @sa set_thread_v1_t. */
  set_thread_v1_t set_thread;
  /** @sa delete_current_thread_v1_t. */
  delete_current_thread_v1_t delete_current_thread;
  /** @sa delete_thread_v1_t. */
  delete_thread_v1_t delete_thread;
  /** @sa get_thread_file_name_locker_v1_t. */
  get_thread_file_name_locker_v1_t get_thread_file_name_locker;
  /** @sa get_thread_file_stream_locker_v1_t. */
  get_thread_file_stream_locker_v1_t get_thread_file_stream_locker;
  /** @sa get_thread_file_descriptor_locker_v1_t. */
  get_thread_file_descriptor_locker_v1_t get_thread_file_descriptor_locker;
  /** @sa unlock_mutex_v1_t. */
  unlock_mutex_v1_t unlock_mutex;
  /** @sa unlock_rwlock_v1_t. */
  unlock_rwlock_v1_t unlock_rwlock;
  /** @sa signal_cond_v1_t. */
  signal_cond_v1_t signal_cond;
  /** @sa broadcast_cond_v1_t. */
  broadcast_cond_v1_t broadcast_cond;
  /** @sa start_idle_wait_v1_t. */
  start_idle_wait_v1_t start_idle_wait;
  /** @sa end_idle_wait_v1_t. */
  end_idle_wait_v1_t end_idle_wait;
  /** @sa start_mutex_wait_v1_t. */
  start_mutex_wait_v1_t start_mutex_wait;
  /** @sa end_mutex_wait_v1_t. */
  end_mutex_wait_v1_t end_mutex_wait;
  /** @sa start_rwlock_rdwait_v1_t. */
  start_rwlock_rdwait_v1_t start_rwlock_rdwait;
  /** @sa end_rwlock_rdwait_v1_t. */
  end_rwlock_rdwait_v1_t end_rwlock_rdwait;
  /** @sa start_rwlock_wrwait_v1_t. */
  start_rwlock_wrwait_v1_t start_rwlock_wrwait;
  /** @sa end_rwlock_wrwait_v1_t. */
  end_rwlock_wrwait_v1_t end_rwlock_wrwait;
  /** @sa start_cond_wait_v1_t. */
  start_cond_wait_v1_t start_cond_wait;
  /** @sa end_cond_wait_v1_t. */
  end_cond_wait_v1_t end_cond_wait;
  /** @sa start_table_io_wait_v1_t. */
  start_table_io_wait_v1_t start_table_io_wait;
  /** @sa end_table_io_wait_v1_t. */
  end_table_io_wait_v1_t end_table_io_wait;
  /** @sa start_table_lock_wait_v1_t. */
  start_table_lock_wait_v1_t start_table_lock_wait;
  /** @sa end_table_lock_wait_v1_t. */
  end_table_lock_wait_v1_t end_table_lock_wait;
  /** @sa start_file_open_wait_v1_t. */
  start_file_open_wait_v1_t start_file_open_wait;
  /** @sa end_file_open_wait_v1_t. */
  end_file_open_wait_v1_t end_file_open_wait;
  /** @sa end_file_open_wait_and_bind_to_descriptor_v1_t. */
  end_file_open_wait_and_bind_to_descriptor_v1_t
    end_file_open_wait_and_bind_to_descriptor;
  /** @sa start_file_wait_v1_t. */
  start_file_wait_v1_t start_file_wait;
  /** @sa end_file_wait_v1_t. */
  end_file_wait_v1_t end_file_wait;
  /** @sa start_file_close_wait_v1_t. */
  start_file_close_wait_v1_t start_file_close_wait;
  /** @sa end_file_close_wait_v1_t. */
  end_file_close_wait_v1_t end_file_close_wait;
  /** @sa start_stage_v1_t. */
  start_stage_v1_t start_stage;
  /** @sa end_stage_v1_t. */
  end_stage_v1_t end_stage;
  /** @sa get_thread_statement_locker_v1_t. */
  get_thread_statement_locker_v1_t get_thread_statement_locker;
  /** @sa refine_statement_v1_t. */
  refine_statement_v1_t refine_statement;
  /** @sa start_statement_v1_t. */
  start_statement_v1_t start_statement;
  /** @sa set_statement_text_v1_t. */
  set_statement_text_v1_t set_statement_text;
  /** @sa set_statement_lock_time_t. */
  set_statement_lock_time_t set_statement_lock_time;
  /** @sa set_statement_rows_sent_t. */
  set_statement_rows_sent_t set_statement_rows_sent;
  /** @sa set_statement_rows_examined_t. */
  set_statement_rows_examined_t set_statement_rows_examined;
  /** @sa inc_statement_created_tmp_disk_tables. */
  inc_statement_created_tmp_disk_tables_t inc_statement_created_tmp_disk_tables;
  /** @sa inc_statement_created_tmp_tables. */
  inc_statement_created_tmp_tables_t inc_statement_created_tmp_tables;
  /** @sa inc_statement_select_full_join. */
  inc_statement_select_full_join_t inc_statement_select_full_join;
  /** @sa inc_statement_select_full_range_join. */
  inc_statement_select_full_range_join_t inc_statement_select_full_range_join;
  /** @sa inc_statement_select_range. */
  inc_statement_select_range_t inc_statement_select_range;
  /** @sa inc_statement_select_range_check. */
  inc_statement_select_range_check_t inc_statement_select_range_check;
  /** @sa inc_statement_select_scan. */
  inc_statement_select_scan_t inc_statement_select_scan;
  /** @sa inc_statement_sort_merge_passes. */
  inc_statement_sort_merge_passes_t inc_statement_sort_merge_passes;
  /** @sa inc_statement_sort_range. */
  inc_statement_sort_range_t inc_statement_sort_range;
  /** @sa inc_statement_sort_rows. */
  inc_statement_sort_rows_t inc_statement_sort_rows;
  /** @sa inc_statement_sort_scan. */
  inc_statement_sort_scan_t inc_statement_sort_scan;
  /** @sa set_statement_no_index_used. */
  set_statement_no_index_used_t set_statement_no_index_used;
  /** @sa set_statement_no_good_index_used. */
  set_statement_no_good_index_used_t set_statement_no_good_index_used;
  /** @sa end_statement_v1_t. */
  end_statement_v1_t end_statement;
  /** @sa start_socket_wait_v1_t. */
  start_socket_wait_v1_t start_socket_wait;
  /** @sa end_socket_wait_v1_t. */
  end_socket_wait_v1_t end_socket_wait;
  /** @sa set_socket_state_v1_t. */
  set_socket_state_v1_t set_socket_state;
  /** @sa set_socket_info_v1_t. */
  set_socket_info_v1_t set_socket_info;
  /** @sa set_socket_thread_owner_v1_t. */
  set_socket_thread_owner_v1_t set_socket_thread_owner;
  /** @sa digest_start_v1_t. */
  digest_start_v1_t digest_start;
  /** @sa digest_end_v1_t. */
  digest_end_v1_t digest_end;
  /** @sa set_thread_connect_attrs_v1_t. */
  set_thread_connect_attrs_v1_t set_thread_connect_attrs;
};

/** @} (end of group Group_PSI_v1) */

#endif /* HAVE_PSI_1 */

#ifdef USE_PSI_2
#define HAVE_PSI_2
#endif

#ifdef HAVE_PSI_2

/**
  @defgroup Group_PSI_v2 Application Binary Interface, version 2
  @ingroup Instrumentation_interface
  @{
*/

/**
  Performance Schema Interface, version 2.
  This is a placeholder, this interface is not defined yet.
  @since PSI_VERSION_2
*/
struct PSI_v2
{
  /** Placeholder */
  int placeholder;
  /* ... extended interface ... */
};

/** Placeholder */
struct PSI_mutex_info_v2
{
  /** Placeholder */
  int placeholder;
};

/** Placeholder */
struct PSI_rwlock_info_v2
{
  /** Placeholder */
  int placeholder;
};

/** Placeholder */
struct PSI_cond_info_v2
{
  /** Placeholder */
  int placeholder;
};

/** Placeholder */
struct PSI_thread_info_v2
{
  /** Placeholder */
  int placeholder;
};

/** Placeholder */
struct PSI_file_info_v2
{
  /** Placeholder */
  int placeholder;
};

/** Placeholder */
struct PSI_stage_info_v2
{
  /** Placeholder */
  int placeholder;
};

/** Placeholder */
struct PSI_statement_info_v2
{
  /** Placeholder */
  int placeholder;
};

/** Placeholder */
struct PSI_idle_locker_state_v2
{
  /** Placeholder */
  int placeholder;
};

/** Placeholder */
struct PSI_mutex_locker_state_v2
{
  /** Placeholder */
  int placeholder;
};

/** Placeholder */
struct PSI_rwlock_locker_state_v2
{
  /** Placeholder */
  int placeholder;
};

/** Placeholder */
struct PSI_cond_locker_state_v2
{
  /** Placeholder */
  int placeholder;
};

/** Placeholder */
struct PSI_file_locker_state_v2
{
  /** Placeholder */
  int placeholder;
};

/** Placeholder */
struct PSI_table_locker_state_v2
{
  /** Placeholder */
  int placeholder;
};

/** Placeholder */
struct PSI_statement_locker_state_v2
{
  /** Placeholder */
  int placeholder;
};

/** Placeholder */
struct PSI_socket_locker_state_v2
{
  /** Placeholder */
  int placeholder;
};

/** @} (end of group Group_PSI_v2) */

#endif /* HAVE_PSI_2 */

/**
  @typedef PSI
  The instrumentation interface for the current version.
  @sa PSI_CURRENT_VERSION
*/

/**
  @typedef PSI_mutex_info
  The mutex information structure for the current version.
*/

/**
  @typedef PSI_rwlock_info
  The rwlock information structure for the current version.
*/

/**
  @typedef PSI_cond_info
  The cond information structure for the current version.
*/

/**
  @typedef PSI_thread_info
  The thread information structure for the current version.
*/

/**
  @typedef PSI_file_info
  The file information structure for the current version.
*/

/* Export the required version */
#ifdef USE_PSI_1
typedef struct PSI_v1 PSI;
typedef struct PSI_mutex_info_v1 PSI_mutex_info;
typedef struct PSI_rwlock_info_v1 PSI_rwlock_info;
typedef struct PSI_cond_info_v1 PSI_cond_info;
typedef struct PSI_thread_info_v1 PSI_thread_info;
typedef struct PSI_file_info_v1 PSI_file_info;
typedef struct PSI_stage_info_v1 PSI_stage_info;
typedef struct PSI_statement_info_v1 PSI_statement_info;
typedef struct PSI_socket_info_v1 PSI_socket_info;
typedef struct PSI_idle_locker_state_v1 PSI_idle_locker_state;
typedef struct PSI_mutex_locker_state_v1 PSI_mutex_locker_state;
typedef struct PSI_rwlock_locker_state_v1 PSI_rwlock_locker_state;
typedef struct PSI_cond_locker_state_v1 PSI_cond_locker_state;
typedef struct PSI_file_locker_state_v1 PSI_file_locker_state;
typedef struct PSI_table_locker_state_v1 PSI_table_locker_state;
typedef struct PSI_statement_locker_state_v1 PSI_statement_locker_state;
typedef struct PSI_socket_locker_state_v1 PSI_socket_locker_state;
#endif

#ifdef USE_PSI_2
typedef struct PSI_v2 PSI;
typedef struct PSI_mutex_info_v2 PSI_mutex_info;
typedef struct PSI_rwlock_info_v2 PSI_rwlock_info;
typedef struct PSI_cond_info_v2 PSI_cond_info;
typedef struct PSI_thread_info_v2 PSI_thread_info;
typedef struct PSI_file_info_v2 PSI_file_info;
typedef struct PSI_stage_info_v2 PSI_stage_info;
typedef struct PSI_statement_info_v2 PSI_statement_info;
typedef struct PSI_socket_info_v2 PSI_socket_info;
typedef struct PSI_idle_locker_state_v2 PSI_idle_locker_state;
typedef struct PSI_mutex_locker_state_v2 PSI_mutex_locker_state;
typedef struct PSI_rwlock_locker_state_v2 PSI_rwlock_locker_state;
typedef struct PSI_cond_locker_state_v2 PSI_cond_locker_state;
typedef struct PSI_file_locker_state_v2 PSI_file_locker_state;
typedef struct PSI_table_locker_state_v2 PSI_table_locker_state;
typedef struct PSI_statement_locker_state_v2 PSI_statement_locker_state;
typedef struct PSI_socket_locker_state_v2 PSI_socket_locker_state;
#endif

#else /* HAVE_PSI_INTERFACE */

/**
  Dummy structure, used to declare PSI_server when no instrumentation
  is available.
  The content does not matter, since PSI_server will be NULL.
*/
struct PSI_none
{
  int opaque;
};
typedef struct PSI_none PSI;

/**
  Stage instrument information.
  @since PSI_VERSION_1
  This structure is used to register an instrumented stage.
*/
struct PSI_stage_info_none
{
  /** Unused stage key. */
  unsigned int m_key;
  /** The name of the stage instrument. */
  const char *m_name;
  /** Unused stage flags. */
  int m_flags;
};

/**
  The stage instrumentation has to co exist with the legacy
  THD::set_proc_info instrumentation.
  To avoid duplication of the instrumentation in the server,
  the common PSI_stage_info structure is used,
  so we export it here, even when not building
  with HAVE_PSI_INTERFACE.
*/
typedef struct PSI_stage_info_none PSI_stage_info;

#endif /* HAVE_PSI_INTERFACE */

extern MYSQL_PLUGIN_IMPORT PSI *PSI_server;

/*
  Allow to override PSI_XXX_CALL at compile time
  with more efficient implementations, if available.
  If nothing better is available,
  make a dynamic call using the PSI_server function pointer.
*/

#ifndef PSI_MUTEX_CALL
#define PSI_MUTEX_CALL(M) PSI_DYNAMIC_CALL(M)
#endif

#ifndef PSI_RWLOCK_CALL
#define PSI_RWLOCK_CALL(M) PSI_DYNAMIC_CALL(M)
#endif

#ifndef PSI_COND_CALL
#define PSI_COND_CALL(M) PSI_DYNAMIC_CALL(M)
#endif

#ifndef PSI_THREAD_CALL
#define PSI_THREAD_CALL(M) PSI_DYNAMIC_CALL(M)
#endif

#ifndef PSI_FILE_CALL
#define PSI_FILE_CALL(M) PSI_DYNAMIC_CALL(M)
#endif

#ifndef PSI_SOCKET_CALL
#define PSI_SOCKET_CALL(M) PSI_DYNAMIC_CALL(M)
#endif

#ifndef PSI_STAGE_CALL
#define PSI_STAGE_CALL(M) PSI_DYNAMIC_CALL(M)
#endif

#ifndef PSI_STATEMENT_CALL
#define PSI_STATEMENT_CALL(M) PSI_DYNAMIC_CALL(M)
#endif

#ifndef PSI_DIGEST_CALL
#define PSI_DIGEST_CALL(M) PSI_DYNAMIC_CALL(M)
#endif

#ifndef PSI_TABLE_CALL
#define PSI_TABLE_CALL(M) PSI_DYNAMIC_CALL(M)
#endif

#ifndef PSI_IDLE_CALL
#define PSI_IDLE_CALL(M) PSI_DYNAMIC_CALL(M)
#endif

#define PSI_DYNAMIC_CALL(M) PSI_server->M

/** @} */

C_MODE_END
#endif /* MYSQL_PERFORMANCE_SCHEMA_INTERFACE_H */

