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

#ifndef MONGOC_WRITE_COMMAND_PRIVATE_H
#define MONGOC_WRITE_COMMAND_PRIVATE_H

#if !defined (MONGOC_I_AM_A_DRIVER) && !defined (MONGOC_COMPILATION)
#error "Only <mongoc.h> can be included directly."
#endif

#include <bson.h>

#include "mongoc-client.h"
#include "mongoc-write-concern.h"


BSON_BEGIN_DECLS


#define MONGOC_WRITE_COMMAND_DELETE 0
#define MONGOC_WRITE_COMMAND_INSERT 1
#define MONGOC_WRITE_COMMAND_UPDATE 2


typedef struct
{
   int      type;
   uint32_t hint;
   bson_t  *documents;
   uint32_t n_documents;
   union {
      struct {
         uint8_t   ordered : 1;
         uint8_t   multi : 1;
      } delete;
      struct {
         uint8_t   ordered : 1;
         uint8_t   allow_bulk_op_insert : 1;
      } insert;
      struct {
         uint8_t   ordered : 1;
      } update;
   } u;
} mongoc_write_command_t;


typedef struct
{
   /* true after a legacy update prevents us from calculating nModified */
   bool         omit_nModified;
   uint32_t     nInserted;
   uint32_t     nMatched;
   uint32_t     nModified;
   uint32_t     nRemoved;
   uint32_t     nUpserted;
   /* like [{"index": int, "_id": value}, ...] */
   bson_t       writeErrors;
   /* like [{"index": int, "code": int, "errmsg": str}, ...] */
   bson_t       upserted;
   bson_t       writeConcernError;
   bool         failed;
   bson_error_t error;
   uint32_t     upsert_append_count;
} mongoc_write_result_t;


void _mongoc_write_command_destroy     (mongoc_write_command_t        *command);
void _mongoc_write_command_init_insert (mongoc_write_command_t        *command,
                                        const bson_t * const          *documents,
                                        uint32_t                       n_documents,
                                        bool                           ordered,
                                        bool                           allow_bulk_op_insert);
void _mongoc_write_command_init_delete (mongoc_write_command_t        *command,
                                        const bson_t                  *selectors,
                                        bool                           multi,
                                        bool                           ordered);
void _mongoc_write_command_init_update (mongoc_write_command_t        *command,
                                        const bson_t                  *selector,
                                        const bson_t                  *update,
                                        bool                           upsert,
                                        bool                           multi,
                                        bool                           ordered);
void _mongoc_write_command_insert_append (mongoc_write_command_t      *command,
                                          const bson_t * const        *documents,
                                          uint32_t                     n_documents);

void _mongoc_write_command_update_append (mongoc_write_command_t      *command,
                                          const bson_t                *selector,
                                          const bson_t                *update,
                                          bool                         upsert,
                                          bool                         multi);

void _mongoc_write_command_delete_append (mongoc_write_command_t *command,
                                          const bson_t           *selector);

void _mongoc_write_command_execute     (mongoc_write_command_t        *command,
                                        mongoc_client_t               *client,
                                        uint32_t                       hint,
                                        const char                    *database,
                                        const char                    *collection,
                                        const mongoc_write_concern_t  *write_concern,
                                        uint32_t                       offset,                                        mongoc_write_result_t         *result);
void _mongoc_write_result_init         (mongoc_write_result_t         *result);
void _mongoc_write_result_merge        (mongoc_write_result_t         *result,
                                        mongoc_write_command_t        *command,
                                        const bson_t                  *reply,
                                        uint32_t                       offset);
void _mongoc_write_result_merge_legacy (mongoc_write_result_t         *result,
                                        mongoc_write_command_t        *command,
                                        const bson_t                  *reply,
                                        uint32_t                       offset);
bool _mongoc_write_result_complete     (mongoc_write_result_t         *result,
                                        bson_t                        *reply,
                                        bson_error_t                  *error);
void _mongoc_write_result_destroy      (mongoc_write_result_t         *result);


BSON_END_DECLS


#endif /* MONGOC_WRITE_COMMAND_PRIVATE_H */
