/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 2007.
 */
/* ====================================================================
 * Copyright (c) 2007 The OpenSSL Project.  All rights reserved.
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

#include <stdio.h>
#include "cryptlib.h"
#include "evp.h"
#include "asn1_locl.h"

#define HMAC_TEST_PRIVATE_KEY_FORMAT

/*
 * HMAC "ASN1" method. This is just here to indicate the maximum HMAC output
 * length and to free up an HMAC key.
 */

static int hmac_size(const EVP_PKEY *pkey)
{
    return EVP_MAX_MD_SIZE;
}

static void hmac_key_free(EVP_PKEY *pkey)
{
    ASN1_OCTET_STRING *os = (ASN1_OCTET_STRING *)pkey->pkey.ptr;
    if (os) {
        if (os->data)
            OPENSSL_cleanse(os->data, os->length);
        ASN1_OCTET_STRING_free(os);
    }
}

static int hmac_pkey_ctrl(EVP_PKEY *pkey, int op, long arg1, void *arg2)
{
    switch (op) {
    case ASN1_PKEY_CTRL_DEFAULT_MD_NID:
        *(int *)arg2 = NID_sha256;
        return 1;

    default:
        return -2;
    }
}

#ifdef HMAC_TEST_PRIVATE_KEY_FORMAT
/*
 * A bogus private key format for test purposes. This is simply the HMAC key
 * with "HMAC PRIVATE KEY" in the headers. When enabled the genpkey utility
 * can be used to "generate" HMAC keys.
 */

static int old_hmac_decode(EVP_PKEY *pkey,
                           const unsigned char **pder, int derlen)
{
    ASN1_OCTET_STRING *os;
    os = ASN1_OCTET_STRING_new();
    if (!os || !ASN1_OCTET_STRING_set(os, *pder, derlen))
        goto err;
    if (!EVP_PKEY_assign(pkey, EVP_PKEY_HMAC, os))
        goto err;
    return 1;

 err:
    ASN1_OCTET_STRING_free(os);
    return 0;
}

static int old_hmac_encode(const EVP_PKEY *pkey, unsigned char **pder)
{
    int inc;
    ASN1_OCTET_STRING *os = (ASN1_OCTET_STRING *)pkey->pkey.ptr;
    if (pder) {
        if (!*pder) {
            *pder = OPENSSL_malloc(os->length);
            inc = 0;
        } else
            inc = 1;

        memcpy(*pder, os->data, os->length);

        if (inc)
            *pder += os->length;
    }

    return os->length;
}

#endif

const EVP_PKEY_ASN1_METHOD hmac_asn1_meth = {
    EVP_PKEY_HMAC,
    EVP_PKEY_HMAC,
    0,

    "HMAC",
    "OpenSSL HMAC method",

    0, 0, 0, 0,

    0, 0, 0,

    hmac_size,
    0,
    0, 0, 0, 0, 0, 0, 0,

    hmac_key_free,
    hmac_pkey_ctrl,
#ifdef HMAC_TEST_PRIVATE_KEY_FORMAT
    old_hmac_decode,
    old_hmac_encode
#else
    0, 0
#endif
};
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 2007.
 */
/* ====================================================================
 * Copyright (c) 2007 The OpenSSL Project.  All rights reserved.
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

#include <stdio.h>
// #include "cryptlib.h"
#include "x509.h"
#include "x509v3.h"
// #include "evp.h"
#include "hmac.h"
#include "evp_locl.h"

/* HMAC pkey context structure */

typedef struct {
    const EVP_MD *md;           /* MD for HMAC use */
    ASN1_OCTET_STRING ktmp;     /* Temp storage for key */
    HMAC_CTX ctx;
} HMAC_PKEY_CTX;

static int pkey_hmac_init(EVP_PKEY_CTX *ctx)
{
    HMAC_PKEY_CTX *hctx;
    hctx = OPENSSL_malloc(sizeof(HMAC_PKEY_CTX));
    if (!hctx)
        return 0;
    hctx->md = NULL;
    hctx->ktmp.data = NULL;
    hctx->ktmp.length = 0;
    hctx->ktmp.flags = 0;
    hctx->ktmp.type = V_ASN1_OCTET_STRING;
    HMAC_CTX_init(&hctx->ctx);

    ctx->data = hctx;
    ctx->keygen_info_count = 0;

    return 1;
}

static int pkey_hmac_copy(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src)
{
    HMAC_PKEY_CTX *sctx, *dctx;
    if (!pkey_hmac_init(dst))
        return 0;
    sctx = src->data;
    dctx = dst->data;
    dctx->md = sctx->md;
    if (!HMAC_CTX_copy(&dctx->ctx, &sctx->ctx))
        goto err;
    if (sctx->ktmp.data != NULL) {
        if (!ASN1_OCTET_STRING_set(&dctx->ktmp,
                                   sctx->ktmp.data, sctx->ktmp.length))
            goto err;
    }
    return 1;
 err:
    HMAC_CTX_cleanup(&dctx->ctx);
    OPENSSL_free(dctx);
    return 0;
}

static void pkey_hmac_cleanup(EVP_PKEY_CTX *ctx)
{
    HMAC_PKEY_CTX *hctx = ctx->data;
    HMAC_CTX_cleanup(&hctx->ctx);
    if (hctx->ktmp.data) {
        if (hctx->ktmp.length)
            OPENSSL_cleanse(hctx->ktmp.data, hctx->ktmp.length);
        OPENSSL_free(hctx->ktmp.data);
        hctx->ktmp.data = NULL;
    }
    OPENSSL_free(hctx);
}

static int pkey_hmac_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    ASN1_OCTET_STRING *hkey = NULL;
    HMAC_PKEY_CTX *hctx = ctx->data;
    if (!hctx->ktmp.data)
        return 0;
    hkey = ASN1_OCTET_STRING_dup(&hctx->ktmp);
    if (!hkey)
        return 0;
    EVP_PKEY_assign(pkey, EVP_PKEY_HMAC, hkey);

    return 1;
}

static int int_update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    HMAC_PKEY_CTX *hctx = ctx->pctx->data;
    if (!HMAC_Update(&hctx->ctx, data, count))
        return 0;
    return 1;
}

static int hmac_signctx_init(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx)
{
    HMAC_PKEY_CTX *hctx = ctx->data;
    HMAC_CTX_set_flags(&hctx->ctx, mctx->flags & ~EVP_MD_CTX_FLAG_NO_INIT);
    EVP_MD_CTX_set_flags(mctx, EVP_MD_CTX_FLAG_NO_INIT);
    mctx->update = int_update;
    return 1;
}

static int hmac_signctx(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
                        EVP_MD_CTX *mctx)
{
    unsigned int hlen;
    HMAC_PKEY_CTX *hctx = ctx->data;
    int l = EVP_MD_CTX_size(mctx);

    if (l < 0)
        return 0;
    *siglen = l;
    if (!sig)
        return 1;

    if (!HMAC_Final(&hctx->ctx, sig, &hlen))
        return 0;
    *siglen = (size_t)hlen;
    return 1;
}

static int pkey_hmac_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
    HMAC_PKEY_CTX *hctx = ctx->data;
    ASN1_OCTET_STRING *key;
    switch (type) {

    case EVP_PKEY_CTRL_SET_MAC_KEY:
        if ((!p2 && p1 > 0) || (p1 < -1))
            return 0;
        if (!ASN1_OCTET_STRING_set(&hctx->ktmp, p2, p1))
            return 0;
        break;

    case EVP_PKEY_CTRL_MD:
        hctx->md = p2;
        break;

    case EVP_PKEY_CTRL_DIGESTINIT:
        key = (ASN1_OCTET_STRING *)ctx->pkey->pkey.ptr;
        if (!HMAC_Init_ex(&hctx->ctx, key->data, key->length, hctx->md,
                          ctx->engine))
            return 0;
        break;

    default:
        return -2;

    }
    return 1;
}

static int pkey_hmac_ctrl_str(EVP_PKEY_CTX *ctx,
                              const char *type, const char *value)
{
    if (!value) {
        return 0;
    }
    if (!strcmp(type, "key")) {
        void *p = (void *)value;
        return pkey_hmac_ctrl(ctx, EVP_PKEY_CTRL_SET_MAC_KEY, -1, p);
    }
    if (!strcmp(type, "hexkey")) {
        unsigned char *key;
        int r;
        long keylen;
        key = string_to_hex(value, &keylen);
        if (!key)
            return 0;
        r = pkey_hmac_ctrl(ctx, EVP_PKEY_CTRL_SET_MAC_KEY, keylen, key);
        OPENSSL_free(key);
        return r;
    }
    return -2;
}

const EVP_PKEY_METHOD hmac_pkey_meth = {
    EVP_PKEY_HMAC,
    0,
    pkey_hmac_init,
    pkey_hmac_copy,
    pkey_hmac_cleanup,

    0, 0,

    0,
    pkey_hmac_keygen,

    0, 0,

    0, 0,

    0, 0,

    hmac_signctx_init,
    hmac_signctx,

    0, 0,

    0, 0,

    0, 0,

    0, 0,

    pkey_hmac_ctrl,
    pkey_hmac_ctrl_str
};
