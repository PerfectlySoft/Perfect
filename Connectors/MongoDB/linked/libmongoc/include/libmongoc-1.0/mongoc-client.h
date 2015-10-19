/*
 * Copyright 2013 MongoDB, Inc.
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

#ifndef MONGOC_CLIENT_H
#define MONGOC_CLIENT_H

#if !defined (MONGOC_INSIDE) && !defined (MONGOC_COMPILATION)
# error "Only <mongoc.h> can be included directly."
#endif

#include <bson.h>

#include "mongoc-collection.h"
#include "mongoc-config.h"
#include "mongoc-cursor.h"
#include "mongoc-database.h"
#include "mongoc-gridfs.h"
#include "mongoc-index.h"
#include "mongoc-read-prefs.h"
#ifdef MONGOC_ENABLE_SSL
# include "mongoc-ssl.h"
#endif
#include "mongoc-stream.h"
#include "mongoc-uri.h"
#include "mongoc-write-concern.h"


BSON_BEGIN_DECLS


#define MONGOC_NAMESPACE_MAX 128


#ifndef MONGOC_DEFAULT_CONNECTTIMEOUTMS
#define MONGOC_DEFAULT_CONNECTTIMEOUTMS (10 * 1000L)
#endif


#ifndef MONGOC_DEFAULT_SOCKETTIMEOUTMS
/*
 * NOTE: The default socket timeout for connections is 5 minutes. This
 *       means that if your MongoDB server dies or becomes unavailable
 *       it will take 5 minutes to detect this.
 *
 *       You can change this by providing sockettimeoutms= in your
 *       connection URI.
 */
#define MONGOC_DEFAULT_SOCKETTIMEOUTMS (1000L * 60L * 5L)
#endif


/**
 * mongoc_client_t:
 *
 * The mongoc_client_t structure maintains information about a connection to
 * a MongoDB server.
 */
typedef struct _mongoc_client_t mongoc_client_t;


/**
 * mongoc_stream_initiator_t:
 * @uri: The uri and options for the stream.
 * @host: The host and port (or UNIX domain socket path) to connect to.
 * @error: A location for an error.
 *
 * Creates a new mongoc_stream_t for the host and port. This can be used
 * by language bindings to create network transports other than those
 * built into libmongoc. An example of such would be the streams API
 * provided by PHP.
 *
 * Returns: A newly allocated mongoc_stream_t or NULL on failure.
 */
typedef mongoc_stream_t *(*mongoc_stream_initiator_t) (const mongoc_uri_t       *uri,
                                                       const mongoc_host_list_t *host,
                                                       void                     *user_data,
                                                       bson_error_t             *error);


mongoc_client_t               *mongoc_client_new                  (const char                   *uri_string);
mongoc_client_t               *mongoc_client_new_from_uri         (const mongoc_uri_t           *uri);
const mongoc_uri_t            *mongoc_client_get_uri              (const mongoc_client_t        *client);
void                           mongoc_client_set_stream_initiator (mongoc_client_t              *client,
                                                                   mongoc_stream_initiator_t     initiator,
                                                                   void                         *user_data);
mongoc_cursor_t               *mongoc_client_command              (mongoc_client_t              *client,
                                                                   const char                   *db_name,
                                                                   mongoc_query_flags_t          flags,
                                                                   uint32_t                      skip,
                                                                   uint32_t                      limit,
                                                                   uint32_t                      batch_size,
                                                                   const bson_t                 *query,
                                                                   const bson_t                 *fields,
                                                                   const mongoc_read_prefs_t    *read_prefs);
void                           mongoc_client_kill_cursor          (mongoc_client_t *client,
                                                                   int64_t          cursor_id);
bool                           mongoc_client_command_simple       (mongoc_client_t              *client,
                                                                   const char                   *db_name,
                                                                   const bson_t                 *command,
                                                                   const mongoc_read_prefs_t    *read_prefs,
                                                                   bson_t                       *reply,
                                                                   bson_error_t                 *error);
void                           mongoc_client_destroy              (mongoc_client_t              *client);
mongoc_database_t             *mongoc_client_get_database         (mongoc_client_t              *client,
                                                                   const char                   *name);
mongoc_gridfs_t               *mongoc_client_get_gridfs           (mongoc_client_t              *client,
                                                                   const char                   *db,
                                                                   const char                   *prefix,
                                                                   bson_error_t                 *error);
mongoc_collection_t           *mongoc_client_get_collection       (mongoc_client_t              *client,
                                                                   const char                   *db,
                                                                   const char                   *collection);
char                         **mongoc_client_get_database_names   (mongoc_client_t              *client,
                                                                   bson_error_t                 *error);
mongoc_cursor_t               *mongoc_client_find_databases       (mongoc_client_t              *client,
                                                                   bson_error_t                 *error);
bool                           mongoc_client_get_server_status    (mongoc_client_t              *client,
                                                                   mongoc_read_prefs_t          *read_prefs,
                                                                   bson_t                       *reply,
                                                                   bson_error_t                 *error);
int32_t                        mongoc_client_get_max_message_size (mongoc_client_t              *client);
int32_t                        mongoc_client_get_max_bson_size    (mongoc_client_t              *client);
const mongoc_write_concern_t  *mongoc_client_get_write_concern    (const mongoc_client_t        *client);
void                           mongoc_client_set_write_concern    (mongoc_client_t              *client,
                                                                   const mongoc_write_concern_t *write_concern);
const mongoc_read_prefs_t     *mongoc_client_get_read_prefs       (const mongoc_client_t        *client);
void                           mongoc_client_set_read_prefs       (mongoc_client_t              *client,
                                                                   const mongoc_read_prefs_t    *read_prefs);
#ifdef MONGOC_ENABLE_SSL
void                           mongoc_client_set_ssl_opts         (mongoc_client_t              *client,
                                                                   const mongoc_ssl_opt_t       *opts);
#endif


BSON_END_DECLS


#endif /* MONGOC_CLIENT_H */
