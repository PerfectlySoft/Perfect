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

#ifndef MONGOC_SASL_PRIVATE_H
#define MONGOC_SASL_PRIVATE_H

#if !defined (MONGOC_I_AM_A_DRIVER) && !defined (MONGOC_COMPILATION)
#error "Only <mongoc.h> can be included directly."
#endif

#include <bson.h>
#include <sasl/sasl.h>
#include <sasl/saslutil.h>


BSON_BEGIN_DECLS


typedef struct _mongoc_sasl_t mongoc_sasl_t;


struct _mongoc_sasl_t
{
   sasl_callback_t  callbacks [4];
   sasl_conn_t     *conn;
   bool      done;
   int              step;
   char            *mechanism;
   char            *user;
   char            *pass;
   char            *service_name;
   char            *service_host;
   sasl_interact_t *interact;
};


void _mongoc_sasl_init             (mongoc_sasl_t      *sasl);
void _mongoc_sasl_set_pass         (mongoc_sasl_t      *sasl,
                                    const char         *pass);
void _mongoc_sasl_set_user         (mongoc_sasl_t      *sasl,
                                    const char         *user);
void _mongoc_sasl_set_mechanism    (mongoc_sasl_t      *sasl,
                                    const char         *mechanism);
void _mongoc_sasl_set_service_name (mongoc_sasl_t      *sasl,
                                    const char         *service_name);
void _mongoc_sasl_set_service_host (mongoc_sasl_t      *sasl,
                                    const char         *service_host);
void _mongoc_sasl_destroy          (mongoc_sasl_t      *sasl);
bool _mongoc_sasl_step             (mongoc_sasl_t      *sasl,
                                    const uint8_t      *inbuf,
                                    uint32_t            inbuflen,
                                    uint8_t            *outbuf,
                                    uint32_t            outbufmax,
                                    uint32_t           *outbuflen,
                                    bson_error_t       *error);


BSON_END_DECLS


#endif /* MONGOC_SASL_PRIVATE_H */
