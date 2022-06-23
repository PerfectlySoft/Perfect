/* crypto/ecdsa/ecs_asn1.c */
/* ====================================================================
 * Copyright (c) 2000-2002 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#include "ecs_locl.h"
#include "err.h"
#include "asn1t.h"

ASN1_SEQUENCE(ECDSA_SIG) = {
        ASN1_SIMPLE(ECDSA_SIG, r, CBIGNUM),
        ASN1_SIMPLE(ECDSA_SIG, s, CBIGNUM)
} ASN1_SEQUENCE_END(ECDSA_SIG)

DECLARE_ASN1_FUNCTIONS_const(ECDSA_SIG)
DECLARE_ASN1_ENCODE_FUNCTIONS_const(ECDSA_SIG, ECDSA_SIG)
IMPLEMENT_ASN1_FUNCTIONS_const(ECDSA_SIG)
/* crypto/ecdsa/ecs_err.c */
/* ====================================================================
 * Copyright (c) 1999-2011 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

/*
 * NOTE: this file was auto generated by the mkerr.pl script: any changes
 * made to it will be overwritten when the script next updates this file,
 * only reason strings will be preserved.
 */

#include <stdio.h>
// #include "err.h"
#include "ecdsa.h"

/* BEGIN ERROR CODES */
#ifndef OPENSSL_NO_ERR

# define ERR_FUNC(func) ERR_PACK(ERR_LIB_ECDSA,func,0)
# define ERR_REASON(reason) ERR_PACK(ERR_LIB_ECDSA,0,reason)

static ERR_STRING_DATA ECDSA_str_functs[] = {
    {ERR_FUNC(ECDSA_F_ECDSA_CHECK), "ECDSA_CHECK"},
    {ERR_FUNC(ECDSA_F_ECDSA_DATA_NEW_METHOD), "ECDSA_DATA_NEW_METHOD"},
    {ERR_FUNC(ECDSA_F_ECDSA_DO_SIGN), "ECDSA_do_sign"},
    {ERR_FUNC(ECDSA_F_ECDSA_DO_VERIFY), "ECDSA_do_verify"},
    {ERR_FUNC(ECDSA_F_ECDSA_METHOD_NEW), "ECDSA_METHOD_new"},
    {ERR_FUNC(ECDSA_F_ECDSA_SIGN_SETUP), "ECDSA_sign_setup"},
    {0, NULL}
};

static ERR_STRING_DATA ECDSA_str_reasons[] = {
    {ERR_REASON(ECDSA_R_BAD_SIGNATURE), "bad signature"},
    {ERR_REASON(ECDSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE),
     "data too large for key size"},
    {ERR_REASON(ECDSA_R_ERR_EC_LIB), "err ec lib"},
    {ERR_REASON(ECDSA_R_MISSING_PARAMETERS), "missing parameters"},
    {ERR_REASON(ECDSA_R_NEED_NEW_SETUP_VALUES), "need new setup values"},
    {ERR_REASON(ECDSA_R_NON_FIPS_METHOD), "non fips method"},
    {ERR_REASON(ECDSA_R_RANDOM_NUMBER_GENERATION_FAILED),
     "random number generation failed"},
    {ERR_REASON(ECDSA_R_SIGNATURE_MALLOC_FAILED), "signature malloc failed"},
    {0, NULL}
};

#endif

void ERR_load_ECDSA_strings(void)
{
#ifndef OPENSSL_NO_ERR

    if (ERR_func_error_string(ECDSA_str_functs[0].error) == NULL) {
        ERR_load_strings(0, ECDSA_str_functs);
        ERR_load_strings(0, ECDSA_str_reasons);
    }
#endif
}
/* crypto/ecdsa/ecs_lib.c */
/* ====================================================================
 * Copyright (c) 1998-2005 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#include <string.h>
// #include "ecs_locl.h"
#ifndef OPENSSL_NO_ENGINE
# include "engine.h"
#endif
// #include "err.h"
#include "bn.h"
#ifdef OPENSSL_FIPS
# include <fips.h>
#endif

const char ECDSA_version[] = "ECDSA" OPENSSL_VERSION_PTEXT;

static const ECDSA_METHOD *default_ECDSA_method = NULL;

static void *ecdsa_data_new(void);
static void *ecdsa_data_dup(void *);
static void ecdsa_data_free(void *);

void ECDSA_set_default_method(const ECDSA_METHOD *meth)
{
    default_ECDSA_method = meth;
}

const ECDSA_METHOD *ECDSA_get_default_method(void)
{
    if (!default_ECDSA_method) {
#ifdef OPENSSL_FIPS
        if (FIPS_mode())
            return FIPS_ecdsa_openssl();
        else
            return ECDSA_OpenSSL();
#else
        default_ECDSA_method = ECDSA_OpenSSL();
#endif
    }
    return default_ECDSA_method;
}

int ECDSA_set_method(EC_KEY *eckey, const ECDSA_METHOD *meth)
{
    ECDSA_DATA *ecdsa;

    ecdsa = ecdsa_check(eckey);

    if (ecdsa == NULL)
        return 0;

#ifndef OPENSSL_NO_ENGINE
    if (ecdsa->engine) {
        ENGINE_finish(ecdsa->engine);
        ecdsa->engine = NULL;
    }
#endif
    ecdsa->meth = meth;

    return 1;
}

static ECDSA_DATA *ECDSA_DATA_new_method(ENGINE *engine)
{
    ECDSA_DATA *ret;

    ret = (ECDSA_DATA *)OPENSSL_malloc(sizeof(ECDSA_DATA));
    if (ret == NULL) {
        ECDSAerr(ECDSA_F_ECDSA_DATA_NEW_METHOD, ERR_R_MALLOC_FAILURE);
        return (NULL);
    }

    ret->init = NULL;

    ret->meth = ECDSA_get_default_method();
    ret->engine = engine;
#ifndef OPENSSL_NO_ENGINE
    if (!ret->engine)
        ret->engine = ENGINE_get_default_ECDSA();
    if (ret->engine) {
        ret->meth = ENGINE_get_ECDSA(ret->engine);
        if (!ret->meth) {
            ECDSAerr(ECDSA_F_ECDSA_DATA_NEW_METHOD, ERR_R_ENGINE_LIB);
            ENGINE_finish(ret->engine);
            OPENSSL_free(ret);
            return NULL;
        }
    }
#endif

    ret->flags = ret->meth->flags;
    CRYPTO_new_ex_data(CRYPTO_EX_INDEX_ECDSA, ret, &ret->ex_data);
#if 0
    if ((ret->meth->init != NULL) && !ret->meth->init(ret)) {
        CRYPTO_free_ex_data(CRYPTO_EX_INDEX_ECDSA, ret, &ret->ex_data);
        OPENSSL_free(ret);
        ret = NULL;
    }
#endif
    return (ret);
}

static void *ecdsa_data_new(void)
{
    return (void *)ECDSA_DATA_new_method(NULL);
}

static void *ecdsa_data_dup(void *data)
{
    ECDSA_DATA *r = (ECDSA_DATA *)data;

    /* XXX: dummy operation */
    if (r == NULL)
        return NULL;

    return ecdsa_data_new();
}

static void ecdsa_data_free(void *data)
{
    ECDSA_DATA *r = (ECDSA_DATA *)data;

#ifndef OPENSSL_NO_ENGINE
    if (r->engine)
        ENGINE_finish(r->engine);
#endif
    CRYPTO_free_ex_data(CRYPTO_EX_INDEX_ECDSA, r, &r->ex_data);

    OPENSSL_cleanse((void *)r, sizeof(ECDSA_DATA));

    OPENSSL_free(r);
}

ECDSA_DATA *ecdsa_check(EC_KEY *key)
{
    ECDSA_DATA *ecdsa_data;

    void *data = EC_KEY_get_key_method_data(key, ecdsa_data_dup,
                                            ecdsa_data_free, ecdsa_data_free);
    if (data == NULL) {
        ecdsa_data = (ECDSA_DATA *)ecdsa_data_new();
        if (ecdsa_data == NULL)
            return NULL;
        data = EC_KEY_insert_key_method_data(key, (void *)ecdsa_data,
                                             ecdsa_data_dup, ecdsa_data_free,
                                             ecdsa_data_free);
        if (data != NULL) {
            /*
             * Another thread raced us to install the key_method data and
             * won.
             */
            ecdsa_data_free(ecdsa_data);
            ecdsa_data = (ECDSA_DATA *)data;
        } else if (EC_KEY_get_key_method_data(key, ecdsa_data_dup,
                                              ecdsa_data_free,
                                              ecdsa_data_free) != ecdsa_data) {
            /* Or an out of memory error in EC_KEY_insert_key_method_data. */
            ecdsa_data_free(ecdsa_data);
            return NULL;
        }
    } else {
        ecdsa_data = (ECDSA_DATA *)data;
    }
#ifdef OPENSSL_FIPS
    if (FIPS_mode() && !(ecdsa_data->flags & ECDSA_FLAG_FIPS_METHOD)
        && !(EC_KEY_get_flags(key) & EC_FLAG_NON_FIPS_ALLOW)) {
        ECDSAerr(ECDSA_F_ECDSA_CHECK, ECDSA_R_NON_FIPS_METHOD);
        return NULL;
    }
#endif

    return ecdsa_data;
}

int ECDSA_size(const EC_KEY *r)
{
    int ret, i;
    ASN1_INTEGER bs;
    BIGNUM *order = NULL;
    unsigned char buf[4];
    const EC_GROUP *group;

    if (r == NULL)
        return 0;
    group = EC_KEY_get0_group(r);
    if (group == NULL)
        return 0;

    if ((order = BN_new()) == NULL)
        return 0;
    if (!EC_GROUP_get_order(group, order, NULL)) {
        BN_clear_free(order);
        return 0;
    }
    i = BN_num_bits(order);
    bs.length = (i + 7) / 8;
    bs.data = buf;
    bs.type = V_ASN1_INTEGER;
    /* If the top bit is set the asn1 encoding is 1 larger. */
    buf[0] = 0xff;

    i = i2d_ASN1_INTEGER(&bs, NULL);
    i += i;                     /* r and s */
    ret = ASN1_object_size(1, i, V_ASN1_SEQUENCE);
    BN_clear_free(order);
    return (ret);
}

int ECDSA_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func,
                           CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func)
{
    return CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_ECDSA, argl, argp,
                                   new_func, dup_func, free_func);
}

int ECDSA_set_ex_data(EC_KEY *d, int idx, void *arg)
{
    ECDSA_DATA *ecdsa;
    ecdsa = ecdsa_check(d);
    if (ecdsa == NULL)
        return 0;
    return (CRYPTO_set_ex_data(&ecdsa->ex_data, idx, arg));
}

void *ECDSA_get_ex_data(EC_KEY *d, int idx)
{
    ECDSA_DATA *ecdsa;
    ecdsa = ecdsa_check(d);
    if (ecdsa == NULL)
        return NULL;
    return (CRYPTO_get_ex_data(&ecdsa->ex_data, idx));
}

ECDSA_METHOD *ECDSA_METHOD_new(const ECDSA_METHOD *ecdsa_meth)
{
    ECDSA_METHOD *ret;

    ret = OPENSSL_malloc(sizeof(ECDSA_METHOD));
    if (ret == NULL) {
        ECDSAerr(ECDSA_F_ECDSA_METHOD_NEW, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    if (ecdsa_meth)
        *ret = *ecdsa_meth;
    else {
        ret->ecdsa_sign_setup = 0;
        ret->ecdsa_do_sign = 0;
        ret->ecdsa_do_verify = 0;
        ret->name = NULL;
        ret->flags = 0;
    }
    ret->flags |= ECDSA_METHOD_FLAG_ALLOCATED;
    return ret;
}

void ECDSA_METHOD_set_sign(ECDSA_METHOD *ecdsa_method,
                           ECDSA_SIG *(*ecdsa_do_sign) (const unsigned char
                                                        *dgst, int dgst_len,
                                                        const BIGNUM *inv,
                                                        const BIGNUM *rp,
                                                        EC_KEY *eckey))
{
    ecdsa_method->ecdsa_do_sign = ecdsa_do_sign;
}

void ECDSA_METHOD_set_sign_setup(ECDSA_METHOD *ecdsa_method,
                                 int (*ecdsa_sign_setup) (EC_KEY *eckey,
                                                          BN_CTX *ctx,
                                                          BIGNUM **kinv,
                                                          BIGNUM **r))
{
    ecdsa_method->ecdsa_sign_setup = ecdsa_sign_setup;
}

void ECDSA_METHOD_set_verify(ECDSA_METHOD *ecdsa_method,
                             int (*ecdsa_do_verify) (const unsigned char
                                                     *dgst, int dgst_len,
                                                     const ECDSA_SIG *sig,
                                                     EC_KEY *eckey))
{
    ecdsa_method->ecdsa_do_verify = ecdsa_do_verify;
}

void ECDSA_METHOD_set_flags(ECDSA_METHOD *ecdsa_method, int flags)
{
    ecdsa_method->flags = flags | ECDSA_METHOD_FLAG_ALLOCATED;
}

void ECDSA_METHOD_set_name(ECDSA_METHOD *ecdsa_method, char *name)
{
    ecdsa_method->name = name;
}

void ECDSA_METHOD_free(ECDSA_METHOD *ecdsa_method)
{
    if (ecdsa_method->flags & ECDSA_METHOD_FLAG_ALLOCATED)
        OPENSSL_free(ecdsa_method);
}

void ECDSA_METHOD_set_app_data(ECDSA_METHOD *ecdsa_method, void *app)
{
    ecdsa_method->app_data = app;
}

void *ECDSA_METHOD_get_app_data(ECDSA_METHOD *ecdsa_method)
{
    return ecdsa_method->app_data;
}
/* crypto/ecdsa/ecs_ossl.c */
/*
 * Written by Nils Larsch for the OpenSSL project
 */
/* ====================================================================
 * Copyright (c) 1998-2018 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

// #include "ecs_locl.h"
// #include "err.h"
#include "obj_mac.h"
// #include "bn.h"
#include "bn_int.h"

static ECDSA_SIG *ecdsa_do_sign(const unsigned char *dgst, int dlen,
                                const BIGNUM *, const BIGNUM *,
                                EC_KEY *eckey);
static int ecdsa_sign_setup(EC_KEY *eckey, BN_CTX *ctx_in, BIGNUM **kinvp,
                            BIGNUM **rp);
static int ecdsa_do_verify(const unsigned char *dgst, int dgst_len,
                           const ECDSA_SIG *sig, EC_KEY *eckey);

static ECDSA_METHOD openssl_ecdsa_meth = {
    "OpenSSL ECDSA method",
    ecdsa_do_sign,
    ecdsa_sign_setup,
    ecdsa_do_verify,
#if 0
    NULL,                       /* init */
    NULL,                       /* finish */
#endif
    0,                          /* flags */
    NULL                        /* app_data */
};

const ECDSA_METHOD *ECDSA_OpenSSL(void)
{
    return &openssl_ecdsa_meth;
}

static int ecdsa_sign_setup(EC_KEY *eckey, BN_CTX *ctx_in, BIGNUM **kinvp,
                            BIGNUM **rp)
{
    BN_CTX *ctx = NULL;
    BIGNUM *k = NULL, *r = NULL, *order = NULL, *X = NULL;
    EC_POINT *tmp_point = NULL;
    const EC_GROUP *group;
    int ret = 0;
    int order_bits;

    if (eckey == NULL || (group = EC_KEY_get0_group(eckey)) == NULL) {
        ECDSAerr(ECDSA_F_ECDSA_SIGN_SETUP, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    if (ctx_in == NULL) {
        if ((ctx = BN_CTX_new()) == NULL) {
            ECDSAerr(ECDSA_F_ECDSA_SIGN_SETUP, ERR_R_MALLOC_FAILURE);
            return 0;
        }
    } else
        ctx = ctx_in;

    k = BN_new();               /* this value is later returned in *kinvp */
    r = BN_new();               /* this value is later returned in *rp */
    order = BN_new();
    X = BN_new();
    if (!k || !r || !order || !X) {
        ECDSAerr(ECDSA_F_ECDSA_SIGN_SETUP, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    if ((tmp_point = EC_POINT_new(group)) == NULL) {
        ECDSAerr(ECDSA_F_ECDSA_SIGN_SETUP, ERR_R_EC_LIB);
        goto err;
    }
    if (!EC_GROUP_get_order(group, order, ctx)) {
        ECDSAerr(ECDSA_F_ECDSA_SIGN_SETUP, ERR_R_EC_LIB);
        goto err;
    }

    /* Preallocate space */
    order_bits = BN_num_bits(order);
    if (!BN_set_bit(k, order_bits)
        || !BN_set_bit(r, order_bits)
        || !BN_set_bit(X, order_bits))
        goto err;

    do {
        /* get random k */
        do
            if (!BN_rand_range(k, order)) {
                ECDSAerr(ECDSA_F_ECDSA_SIGN_SETUP,
                         ECDSA_R_RANDOM_NUMBER_GENERATION_FAILED);
                goto err;
            }
        while (BN_is_zero(k)) ;

        /*
         * We do not want timing information to leak the length of k, so we
         * compute G*k using an equivalent scalar of fixed bit-length.
         *
         * We unconditionally perform both of these additions to prevent a
         * small timing information leakage.  We then choose the sum that is
         * one bit longer than the order.  This guarantees the code
         * path used in the constant time implementations elsewhere.
         *
         * TODO: revisit the BN_copy aiming for a memory access agnostic
         * conditional copy.
         */
        if (!BN_add(r, k, order)
            || !BN_add(X, r, order)
            || !BN_copy(k, BN_num_bits(r) > order_bits ? r : X))
            goto err;

        /* compute r the x-coordinate of generator * k */
        if (!EC_POINT_mul(group, tmp_point, k, NULL, NULL, ctx)) {
            ECDSAerr(ECDSA_F_ECDSA_SIGN_SETUP, ERR_R_EC_LIB);
            goto err;
        }
        if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) ==
            NID_X9_62_prime_field) {
            if (!EC_POINT_get_affine_coordinates_GFp
                (group, tmp_point, X, NULL, ctx)) {
                ECDSAerr(ECDSA_F_ECDSA_SIGN_SETUP, ERR_R_EC_LIB);
                goto err;
            }
        }
#ifndef OPENSSL_NO_EC2M
        else {                  /* NID_X9_62_characteristic_two_field */

            if (!EC_POINT_get_affine_coordinates_GF2m(group,
                                                      tmp_point, X, NULL,
                                                      ctx)) {
                ECDSAerr(ECDSA_F_ECDSA_SIGN_SETUP, ERR_R_EC_LIB);
                goto err;
            }
        }
#endif
        if (!BN_nnmod(r, X, order, ctx)) {
            ECDSAerr(ECDSA_F_ECDSA_SIGN_SETUP, ERR_R_BN_LIB);
            goto err;
        }
    }
    while (BN_is_zero(r));

    /* compute the inverse of k */
    if (EC_GROUP_get_mont_data(group) != NULL) {
        /*
         * We want inverse in constant time, therefore we utilize the fact
         * order must be prime and use Fermats Little Theorem instead.
         */
        if (!BN_set_word(X, 2)) {
            ECDSAerr(ECDSA_F_ECDSA_SIGN_SETUP, ERR_R_BN_LIB);
            goto err;
        }
        if (!BN_mod_sub(X, order, X, order, ctx)) {
            ECDSAerr(ECDSA_F_ECDSA_SIGN_SETUP, ERR_R_BN_LIB);
            goto err;
        }
        BN_set_flags(X, BN_FLG_CONSTTIME);
        if (!BN_mod_exp_mont_consttime
            (k, k, X, order, ctx, EC_GROUP_get_mont_data(group))) {
            ECDSAerr(ECDSA_F_ECDSA_SIGN_SETUP, ERR_R_BN_LIB);
            goto err;
        }
    } else {
        if (!BN_mod_inverse(k, k, order, ctx)) {
            ECDSAerr(ECDSA_F_ECDSA_SIGN_SETUP, ERR_R_BN_LIB);
            goto err;
        }
    }

    /* clear old values if necessary */
    if (*rp != NULL)
        BN_clear_free(*rp);
    if (*kinvp != NULL)
        BN_clear_free(*kinvp);
    /* save the pre-computed values  */
    *rp = r;
    *kinvp = k;
    ret = 1;
 err:
    if (!ret) {
        if (k != NULL)
            BN_clear_free(k);
        if (r != NULL)
            BN_clear_free(r);
    }
    if (ctx_in == NULL)
        BN_CTX_free(ctx);
    if (order != NULL)
        BN_free(order);
    if (tmp_point != NULL)
        EC_POINT_free(tmp_point);
    if (X)
        BN_clear_free(X);
    return (ret);
}

static ECDSA_SIG *ecdsa_do_sign(const unsigned char *dgst, int dgst_len,
                                const BIGNUM *in_kinv, const BIGNUM *in_r,
                                EC_KEY *eckey)
{
    int ok = 0, i;
    BIGNUM *kinv = NULL, *s, *m = NULL, *order = NULL;
    const BIGNUM *ckinv;
    BN_CTX *ctx = NULL;
    const EC_GROUP *group;
    ECDSA_SIG *ret;
    ECDSA_DATA *ecdsa;
    const BIGNUM *priv_key;
    BN_MONT_CTX *mont_data;

    ecdsa = ecdsa_check(eckey);
    group = EC_KEY_get0_group(eckey);
    priv_key = EC_KEY_get0_private_key(eckey);

    if (group == NULL || priv_key == NULL || ecdsa == NULL) {
        ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    ret = ECDSA_SIG_new();
    if (!ret) {
        ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    s = ret->s;

    if ((ctx = BN_CTX_new()) == NULL || (order = BN_new()) == NULL ||
        (m = BN_new()) == NULL) {
        ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (!EC_GROUP_get_order(group, order, ctx)) {
        ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_EC_LIB);
        goto err;
    }
    mont_data = EC_GROUP_get_mont_data(group);

    i = BN_num_bits(order);
    /*
     * Need to truncate digest if it is too long: first truncate whole bytes.
     */
    if (8 * dgst_len > i)
        dgst_len = (i + 7) / 8;
    if (!BN_bin2bn(dgst, dgst_len, m)) {
        ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_BN_LIB);
        goto err;
    }
    /* If still too long truncate remaining bits with a shift */
    if ((8 * dgst_len > i) && !BN_rshift(m, m, 8 - (i & 0x7))) {
        ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_BN_LIB);
        goto err;
    }
    do {
        if (in_kinv == NULL || in_r == NULL) {
            if (!ECDSA_sign_setup(eckey, ctx, &kinv, &ret->r)) {
                ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_ECDSA_LIB);
                goto err;
            }
            ckinv = kinv;
        } else {
            ckinv = in_kinv;
            if (BN_copy(ret->r, in_r) == NULL) {
                ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_MALLOC_FAILURE);
                goto err;
            }
        }

        /*
         * With only one multiplicant being in Montgomery domain
         * multiplication yields real result without post-conversion.
         * Also note that all operations but last are performed with
         * zero-padded vectors. Last operation, BN_mod_mul_montgomery
         * below, returns user-visible value with removed zero padding.
         */
        if (!bn_to_mont_fixed_top(s, ret->r, mont_data, ctx)
            || !bn_mul_mont_fixed_top(s, s, priv_key, mont_data, ctx)) {
            goto err;
        }
        if (!bn_mod_add_fixed_top(s, s, m, order)) {
            ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_BN_LIB);
            goto err;
        }
        /*
         * |s| can still be larger than modulus, because |m| can be. In
         * such case we count on Montgomery reduction to tie it up.
         */
        if (!bn_to_mont_fixed_top(s, s, mont_data, ctx)
            || !BN_mod_mul_montgomery(s, s, ckinv, mont_data, ctx)) {
            ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_BN_LIB);
            goto err;
        }
        if (BN_is_zero(s)) {
            /*
             * if kinv and r have been supplied by the caller don't to
             * generate new kinv and r values
             */
            if (in_kinv != NULL && in_r != NULL) {
                ECDSAerr(ECDSA_F_ECDSA_DO_SIGN,
                         ECDSA_R_NEED_NEW_SETUP_VALUES);
                goto err;
            }
        } else
            /* s != 0 => we have a valid signature */
            break;
    }
    while (1);

    ok = 1;
 err:
    if (!ok) {
        ECDSA_SIG_free(ret);
        ret = NULL;
    }
    if (ctx)
        BN_CTX_free(ctx);
    if (m)
        BN_clear_free(m);
    if (order)
        BN_free(order);
    if (kinv)
        BN_clear_free(kinv);
    return ret;
}

static int ecdsa_do_verify(const unsigned char *dgst, int dgst_len,
                           const ECDSA_SIG *sig, EC_KEY *eckey)
{
    int ret = -1, i;
    BN_CTX *ctx;
    BIGNUM *order, *u1, *u2, *m, *X;
    EC_POINT *point = NULL;
    const EC_GROUP *group;
    const EC_POINT *pub_key;

    /* check input values */
    if (eckey == NULL || (group = EC_KEY_get0_group(eckey)) == NULL ||
        (pub_key = EC_KEY_get0_public_key(eckey)) == NULL || sig == NULL) {
        ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ECDSA_R_MISSING_PARAMETERS);
        return -1;
    }

    ctx = BN_CTX_new();
    if (!ctx) {
        ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ERR_R_MALLOC_FAILURE);
        return -1;
    }
    BN_CTX_start(ctx);
    order = BN_CTX_get(ctx);
    u1 = BN_CTX_get(ctx);
    u2 = BN_CTX_get(ctx);
    m = BN_CTX_get(ctx);
    X = BN_CTX_get(ctx);
    if (!X) {
        ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ERR_R_BN_LIB);
        goto err;
    }

    if (!EC_GROUP_get_order(group, order, ctx)) {
        ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ERR_R_EC_LIB);
        goto err;
    }

    if (BN_is_zero(sig->r) || BN_is_negative(sig->r) ||
        BN_ucmp(sig->r, order) >= 0 || BN_is_zero(sig->s) ||
        BN_is_negative(sig->s) || BN_ucmp(sig->s, order) >= 0) {
        ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ECDSA_R_BAD_SIGNATURE);
        ret = 0;                /* signature is invalid */
        goto err;
    }
    /* calculate tmp1 = inv(S) mod order */
    if (!BN_mod_inverse(u2, sig->s, order, ctx)) {
        ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ERR_R_BN_LIB);
        goto err;
    }
    /* digest -> m */
    i = BN_num_bits(order);
    /*
     * Need to truncate digest if it is too long: first truncate whole bytes.
     */
    if (8 * dgst_len > i)
        dgst_len = (i + 7) / 8;
    if (!BN_bin2bn(dgst, dgst_len, m)) {
        ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ERR_R_BN_LIB);
        goto err;
    }
    /* If still too long truncate remaining bits with a shift */
    if ((8 * dgst_len > i) && !BN_rshift(m, m, 8 - (i & 0x7))) {
        ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ERR_R_BN_LIB);
        goto err;
    }
    /* u1 = m * tmp mod order */
    if (!BN_mod_mul(u1, m, u2, order, ctx)) {
        ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ERR_R_BN_LIB);
        goto err;
    }
    /* u2 = r * w mod q */
    if (!BN_mod_mul(u2, sig->r, u2, order, ctx)) {
        ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ERR_R_BN_LIB);
        goto err;
    }

    if ((point = EC_POINT_new(group)) == NULL) {
        ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    if (!EC_POINT_mul(group, point, u1, pub_key, u2, ctx)) {
        ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ERR_R_EC_LIB);
        goto err;
    }
    if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) ==
        NID_X9_62_prime_field) {
        if (!EC_POINT_get_affine_coordinates_GFp(group, point, X, NULL, ctx)) {
            ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ERR_R_EC_LIB);
            goto err;
        }
    }
#ifndef OPENSSL_NO_EC2M
    else {                      /* NID_X9_62_characteristic_two_field */

        if (!EC_POINT_get_affine_coordinates_GF2m(group, point, X, NULL, ctx)) {
            ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ERR_R_EC_LIB);
            goto err;
        }
    }
#endif
    if (!BN_nnmod(u1, X, order, ctx)) {
        ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ERR_R_BN_LIB);
        goto err;
    }
    /*  if the signature is correct u1 is equal to sig->r */
    ret = (BN_ucmp(u1, sig->r) == 0);
 err:
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    if (point)
        EC_POINT_free(point);
    return ret;
}
/* crypto/ecdsa/ecdsa_sign.c */
/* ====================================================================
 * Copyright (c) 1998-2002 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

// #include "ecs_locl.h"
#ifndef OPENSSL_NO_ENGINE
# include "engine.h"
#endif
#include "rand.h"

ECDSA_SIG *ECDSA_do_sign(const unsigned char *dgst, int dlen, EC_KEY *eckey)
{
    return ECDSA_do_sign_ex(dgst, dlen, NULL, NULL, eckey);
}

ECDSA_SIG *ECDSA_do_sign_ex(const unsigned char *dgst, int dlen,
                            const BIGNUM *kinv, const BIGNUM *rp,
                            EC_KEY *eckey)
{
    ECDSA_DATA *ecdsa = ecdsa_check(eckey);
    if (ecdsa == NULL)
        return NULL;
    return ecdsa->meth->ecdsa_do_sign(dgst, dlen, kinv, rp, eckey);
}

int ECDSA_sign(int type, const unsigned char *dgst, int dlen, unsigned char
               *sig, unsigned int *siglen, EC_KEY *eckey)
{
    return ECDSA_sign_ex(type, dgst, dlen, sig, siglen, NULL, NULL, eckey);
}

int ECDSA_sign_ex(int type, const unsigned char *dgst, int dlen, unsigned char
                  *sig, unsigned int *siglen, const BIGNUM *kinv,
                  const BIGNUM *r, EC_KEY *eckey)
{
    ECDSA_SIG *s;
    RAND_seed(dgst, dlen);
    s = ECDSA_do_sign_ex(dgst, dlen, kinv, r, eckey);
    if (s == NULL) {
        *siglen = 0;
        return 0;
    }
    *siglen = i2d_ECDSA_SIG(s, &sig);
    ECDSA_SIG_free(s);
    return 1;
}

int ECDSA_sign_setup(EC_KEY *eckey, BN_CTX *ctx_in, BIGNUM **kinvp,
                     BIGNUM **rp)
{
    ECDSA_DATA *ecdsa = ecdsa_check(eckey);
    if (ecdsa == NULL)
        return 0;
    return ecdsa->meth->ecdsa_sign_setup(eckey, ctx_in, kinvp, rp);
}
/* crypto/ecdsa/ecdsa_vrf.c */
/*
 * Written by Nils Larsch for the OpenSSL project
 */
/* ====================================================================
 * Copyright (c) 1998-2002 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

// #include "ecs_locl.h"
#include <string.h>
#ifndef OPENSSL_NO_ENGINE
# include "engine.h"
#endif

/*-
 * returns
 *      1: correct signature
 *      0: incorrect signature
 *     -1: error
 */
int ECDSA_do_verify(const unsigned char *dgst, int dgst_len,
                    const ECDSA_SIG *sig, EC_KEY *eckey)
{
    ECDSA_DATA *ecdsa = ecdsa_check(eckey);
    if (ecdsa == NULL)
        return 0;
    return ecdsa->meth->ecdsa_do_verify(dgst, dgst_len, sig, eckey);
}

/*-
 * returns
 *      1: correct signature
 *      0: incorrect signature
 *     -1: error
 */
int ECDSA_verify(int type, const unsigned char *dgst, int dgst_len,
                 const unsigned char *sigbuf, int sig_len, EC_KEY *eckey)
{
    ECDSA_SIG *s;
    const unsigned char *p = sigbuf;
    unsigned char *der = NULL;
    int derlen = -1;
    int ret = -1;

    s = ECDSA_SIG_new();
    if (s == NULL)
        return (ret);
    if (d2i_ECDSA_SIG(&s, &p, sig_len) == NULL)
        goto err;
    /* Ensure signature uses DER and doesn't have trailing garbage */
    derlen = i2d_ECDSA_SIG(s, &der);
    if (derlen != sig_len || memcmp(sigbuf, der, derlen))
        goto err;
    ret = ECDSA_do_verify(dgst, dgst_len, s, eckey);
 err:
    if (derlen > 0) {
        OPENSSL_cleanse(der, derlen);
        OPENSSL_free(der);
    }
    ECDSA_SIG_free(s);
    return (ret);
}
