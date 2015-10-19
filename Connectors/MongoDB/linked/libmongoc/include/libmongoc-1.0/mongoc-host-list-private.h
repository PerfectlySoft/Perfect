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

#ifndef MONGOC_HOST_LIST_PRIVATE_H
#define MONGOC_HOST_LIST_PRIVATE_H

#if !defined (MONGOC_I_AM_A_DRIVER) && !defined (MONGOC_COMPILATION)
#error "Only <mongoc.h> can be included directly."
#endif

#include "mongoc-host-list.h"


BSON_BEGIN_DECLS


bool _mongoc_host_list_from_string (mongoc_host_list_t *host_list,
                                    const char         *host_and_port);


BSON_END_DECLS


#endif /* MONGOC_HOST_LIST_PRIVATE_H */
