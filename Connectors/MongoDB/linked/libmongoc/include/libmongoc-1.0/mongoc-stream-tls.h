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

#ifndef MONGOC_STREAM_TLS_H
#define MONGOC_STREAM_TLS_H

#if !defined (MONGOC_INSIDE) && !defined (MONGOC_COMPILATION)
# error "Only <mongoc.h> can be included directly."
#endif

#include <bson.h>

#include "mongoc-ssl.h"
#include "mongoc-stream.h"


BSON_BEGIN_DECLS


bool             mongoc_stream_tls_do_handshake  (mongoc_stream_t  *stream,
                                                  int32_t           timeout_msec);
bool             mongoc_stream_tls_check_cert    (mongoc_stream_t  *stream,
                                                  const char       *host);
mongoc_stream_t *mongoc_stream_tls_new           (mongoc_stream_t  *base_stream,
                                                  mongoc_ssl_opt_t *opt,
                                                  int               client);


BSON_END_DECLS


#endif /* MONGOC_STREAM_TLS_H */
