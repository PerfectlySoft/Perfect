/* pmeth_fn.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 2006.
 */
/* ====================================================================
 * Copyright (c) 2006 The OpenSSL Project.  All rights reserved.
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
#include <stdlib.h>
#include "cryptlib.h"
#include "objects.h"
#include "evp.h"
#include "evp_locl.h"

#define M_check_autoarg(ctx, arg, arglen, err) \
    if (ctx->pmeth->flags & EVP_PKEY_FLAG_AUTOARGLEN) {           \
        size_t pksize = (size_t)EVP_PKEY_size(ctx->pkey);         \
                                                                  \
        if (pksize == 0) {                                        \
            EVPerr(err, EVP_R_INVALID_KEY); /*ckerr_ignore*/      \
            return 0;                                             \
        }                                                         \
        if (!arg) {                                               \
            *arglen = pksize;                                     \
            return 1;                                             \
        }                                                         \
        if (*arglen < pksize) {                                   \
            EVPerr(err, EVP_R_BUFFER_TOO_SMALL); /*ckerr_ignore*/ \
            return 0;                                             \
        }                                                         \
    }

int EVP_PKEY_sign_init(EVP_PKEY_CTX *ctx)
{
    int ret;
    if (!ctx || !ctx->pmeth || !ctx->pmeth->sign) {
        EVPerr(EVP_F_EVP_PKEY_SIGN_INIT,
               EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        return -2;
    }
    ctx->operation = EVP_PKEY_OP_SIGN;
    if (!ctx->pmeth->sign_init)
        return 1;
    ret = ctx->pmeth->sign_init(ctx);
    if (ret <= 0)
        ctx->operation = EVP_PKEY_OP_UNDEFINED;
    return ret;
}

int EVP_PKEY_sign(EVP_PKEY_CTX *ctx,
                  unsigned char *sig, size_t *siglen,
                  const unsigned char *tbs, size_t tbslen)
{
    if (!ctx || !ctx->pmeth || !ctx->pmeth->sign) {
        EVPerr(EVP_F_EVP_PKEY_SIGN,
               EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        return -2;
    }
    if (ctx->operation != EVP_PKEY_OP_SIGN) {
        EVPerr(EVP_F_EVP_PKEY_SIGN, EVP_R_OPERATON_NOT_INITIALIZED);
        return -1;
    }
    M_check_autoarg(ctx, sig, siglen, EVP_F_EVP_PKEY_SIGN)
        return ctx->pmeth->sign(ctx, sig, siglen, tbs, tbslen);
}

int EVP_PKEY_verify_init(EVP_PKEY_CTX *ctx)
{
    int ret;
    if (!ctx || !ctx->pmeth || !ctx->pmeth->verify) {
        EVPerr(EVP_F_EVP_PKEY_VERIFY_INIT,
               EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        return -2;
    }
    ctx->operation = EVP_PKEY_OP_VERIFY;
    if (!ctx->pmeth->verify_init)
        return 1;
    ret = ctx->pmeth->verify_init(ctx);
    if (ret <= 0)
        ctx->operation = EVP_PKEY_OP_UNDEFINED;
    return ret;
}

int EVP_PKEY_verify(EVP_PKEY_CTX *ctx,
                    const unsigned char *sig, size_t siglen,
                    const unsigned char *tbs, size_t tbslen)
{
    if (!ctx || !ctx->pmeth || !ctx->pmeth->verify) {
        EVPerr(EVP_F_EVP_PKEY_VERIFY,
               EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        return -2;
    }
    if (ctx->operation != EVP_PKEY_OP_VERIFY) {
        EVPerr(EVP_F_EVP_PKEY_VERIFY, EVP_R_OPERATON_NOT_INITIALIZED);
        return -1;
    }
    return ctx->pmeth->verify(ctx, sig, siglen, tbs, tbslen);
}

int EVP_PKEY_verify_recover_init(EVP_PKEY_CTX *ctx)
{
    int ret;
    if (!ctx || !ctx->pmeth || !ctx->pmeth->verify_recover) {
        EVPerr(EVP_F_EVP_PKEY_VERIFY_RECOVER_INIT,
               EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        return -2;
    }
    ctx->operation = EVP_PKEY_OP_VERIFYRECOVER;
    if (!ctx->pmeth->verify_recover_init)
        return 1;
    ret = ctx->pmeth->verify_recover_init(ctx);
    if (ret <= 0)
        ctx->operation = EVP_PKEY_OP_UNDEFINED;
    return ret;
}

int EVP_PKEY_verify_recover(EVP_PKEY_CTX *ctx,
                            unsigned char *rout, size_t *routlen,
                            const unsigned char *sig, size_t siglen)
{
    if (!ctx || !ctx->pmeth || !ctx->pmeth->verify_recover) {
        EVPerr(EVP_F_EVP_PKEY_VERIFY_RECOVER,
               EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        return -2;
    }
    if (ctx->operation != EVP_PKEY_OP_VERIFYRECOVER) {
        EVPerr(EVP_F_EVP_PKEY_VERIFY_RECOVER, EVP_R_OPERATON_NOT_INITIALIZED);
        return -1;
    }
    M_check_autoarg(ctx, rout, routlen, EVP_F_EVP_PKEY_VERIFY_RECOVER)
        return ctx->pmeth->verify_recover(ctx, rout, routlen, sig, siglen);
}

int EVP_PKEY_encrypt_init(EVP_PKEY_CTX *ctx)
{
    int ret;
    if (!ctx || !ctx->pmeth || !ctx->pmeth->encrypt) {
        EVPerr(EVP_F_EVP_PKEY_ENCRYPT_INIT,
               EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        return -2;
    }
    ctx->operation = EVP_PKEY_OP_ENCRYPT;
    if (!ctx->pmeth->encrypt_init)
        return 1;
    ret = ctx->pmeth->encrypt_init(ctx);
    if (ret <= 0)
        ctx->operation = EVP_PKEY_OP_UNDEFINED;
    return ret;
}

int EVP_PKEY_encrypt(EVP_PKEY_CTX *ctx,
                     unsigned char *out, size_t *outlen,
                     const unsigned char *in, size_t inlen)
{
    if (!ctx || !ctx->pmeth || !ctx->pmeth->encrypt) {
        EVPerr(EVP_F_EVP_PKEY_ENCRYPT,
               EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        return -2;
    }
    if (ctx->operation != EVP_PKEY_OP_ENCRYPT) {
        EVPerr(EVP_F_EVP_PKEY_ENCRYPT, EVP_R_OPERATON_NOT_INITIALIZED);
        return -1;
    }
    M_check_autoarg(ctx, out, outlen, EVP_F_EVP_PKEY_ENCRYPT)
        return ctx->pmeth->encrypt(ctx, out, outlen, in, inlen);
}

int EVP_PKEY_decrypt_init(EVP_PKEY_CTX *ctx)
{
    int ret;
    if (!ctx || !ctx->pmeth || !ctx->pmeth->decrypt) {
        EVPerr(EVP_F_EVP_PKEY_DECRYPT_INIT,
               EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        return -2;
    }
    ctx->operation = EVP_PKEY_OP_DECRYPT;
    if (!ctx->pmeth->decrypt_init)
        return 1;
    ret = ctx->pmeth->decrypt_init(ctx);
    if (ret <= 0)
        ctx->operation = EVP_PKEY_OP_UNDEFINED;
    return ret;
}

int EVP_PKEY_decrypt(EVP_PKEY_CTX *ctx,
                     unsigned char *out, size_t *outlen,
                     const unsigned char *in, size_t inlen)
{
    if (!ctx || !ctx->pmeth || !ctx->pmeth->decrypt) {
        EVPerr(EVP_F_EVP_PKEY_DECRYPT,
               EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        return -2;
    }
    if (ctx->operation != EVP_PKEY_OP_DECRYPT) {
        EVPerr(EVP_F_EVP_PKEY_DECRYPT, EVP_R_OPERATON_NOT_INITIALIZED);
        return -1;
    }
    M_check_autoarg(ctx, out, outlen, EVP_F_EVP_PKEY_DECRYPT)
        return ctx->pmeth->decrypt(ctx, out, outlen, in, inlen);
}

int EVP_PKEY_derive_init(EVP_PKEY_CTX *ctx)
{
    int ret;
    if (!ctx || !ctx->pmeth || !ctx->pmeth->derive) {
        EVPerr(EVP_F_EVP_PKEY_DERIVE_INIT,
               EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        return -2;
    }
    ctx->operation = EVP_PKEY_OP_DERIVE;
    if (!ctx->pmeth->derive_init)
        return 1;
    ret = ctx->pmeth->derive_init(ctx);
    if (ret <= 0)
        ctx->operation = EVP_PKEY_OP_UNDEFINED;
    return ret;
}

int EVP_PKEY_derive_set_peer(EVP_PKEY_CTX *ctx, EVP_PKEY *peer)
{
    int ret;
    if (!ctx || !ctx->pmeth
        || !(ctx->pmeth->derive || ctx->pmeth->encrypt || ctx->pmeth->decrypt)
        || !ctx->pmeth->ctrl) {
        EVPerr(EVP_F_EVP_PKEY_DERIVE_SET_PEER,
               EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        return -2;
    }
    if (ctx->operation != EVP_PKEY_OP_DERIVE
        && ctx->operation != EVP_PKEY_OP_ENCRYPT
        && ctx->operation != EVP_PKEY_OP_DECRYPT) {
        EVPerr(EVP_F_EVP_PKEY_DERIVE_SET_PEER,
               EVP_R_OPERATON_NOT_INITIALIZED);
        return -1;
    }

    ret = ctx->pmeth->ctrl(ctx, EVP_PKEY_CTRL_PEER_KEY, 0, peer);

    if (ret <= 0)
        return ret;

    if (ret == 2)
        return 1;

    if (!ctx->pkey) {
        EVPerr(EVP_F_EVP_PKEY_DERIVE_SET_PEER, EVP_R_NO_KEY_SET);
        return -1;
    }

    if (ctx->pkey->type != peer->type) {
        EVPerr(EVP_F_EVP_PKEY_DERIVE_SET_PEER, EVP_R_DIFFERENT_KEY_TYPES);
        return -1;
    }

    /*
     * ran@cryptocom.ru: For clarity.  The error is if parameters in peer are
     * present (!missing) but don't match.  EVP_PKEY_cmp_parameters may return
     * 1 (match), 0 (don't match) and -2 (comparison is not defined).  -1
     * (different key types) is impossible here because it is checked earlier.
     * -2 is OK for us here, as well as 1, so we can check for 0 only.
     */
    if (!EVP_PKEY_missing_parameters(peer) &&
        !EVP_PKEY_cmp_parameters(ctx->pkey, peer)) {
        EVPerr(EVP_F_EVP_PKEY_DERIVE_SET_PEER, EVP_R_DIFFERENT_PARAMETERS);
        return -1;
    }

    if (ctx->peerkey)
        EVP_PKEY_free(ctx->peerkey);
    ctx->peerkey = peer;

    ret = ctx->pmeth->ctrl(ctx, EVP_PKEY_CTRL_PEER_KEY, 1, peer);

    if (ret <= 0) {
        ctx->peerkey = NULL;
        return ret;
    }

    CRYPTO_add(&peer->references, 1, CRYPTO_LOCK_EVP_PKEY);
    return 1;
}

int EVP_PKEY_derive(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *pkeylen)
{
    if (!ctx || !ctx->pmeth || !ctx->pmeth->derive) {
        EVPerr(EVP_F_EVP_PKEY_DERIVE,
               EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        return -2;
    }
    if (ctx->operation != EVP_PKEY_OP_DERIVE) {
        EVPerr(EVP_F_EVP_PKEY_DERIVE, EVP_R_OPERATON_NOT_INITIALIZED);
        return -1;
    }
    M_check_autoarg(ctx, key, pkeylen, EVP_F_EVP_PKEY_DERIVE)
        return ctx->pmeth->derive(ctx, key, pkeylen);
}
/* pmeth_gn.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 2006.
 */
/* ====================================================================
 * Copyright (c) 2006 The OpenSSL Project.  All rights reserved.
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
#include <stdlib.h>
// #include "cryptlib.h"
// #include "objects.h"
// #include "evp.h"
#include "bn.h"
// #include "evp_locl.h"

int EVP_PKEY_paramgen_init(EVP_PKEY_CTX *ctx)
{
    int ret;
    if (!ctx || !ctx->pmeth || !ctx->pmeth->paramgen) {
        EVPerr(EVP_F_EVP_PKEY_PARAMGEN_INIT,
               EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        return -2;
    }
    ctx->operation = EVP_PKEY_OP_PARAMGEN;
    if (!ctx->pmeth->paramgen_init)
        return 1;
    ret = ctx->pmeth->paramgen_init(ctx);
    if (ret <= 0)
        ctx->operation = EVP_PKEY_OP_UNDEFINED;
    return ret;
}

int EVP_PKEY_paramgen(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey)
{
    int ret;
    if (!ctx || !ctx->pmeth || !ctx->pmeth->paramgen) {
        EVPerr(EVP_F_EVP_PKEY_PARAMGEN,
               EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        return -2;
    }

    if (ctx->operation != EVP_PKEY_OP_PARAMGEN) {
        EVPerr(EVP_F_EVP_PKEY_PARAMGEN, EVP_R_OPERATON_NOT_INITIALIZED);
        return -1;
    }

    if (ppkey == NULL)
        return -1;

    if (*ppkey == NULL)
        *ppkey = EVP_PKEY_new();

    if (*ppkey == NULL) {
        EVPerr(EVP_F_EVP_PKEY_PARAMGEN, ERR_R_MALLOC_FAILURE);
        return -1;
    }

    ret = ctx->pmeth->paramgen(ctx, *ppkey);
    if (ret <= 0) {
        EVP_PKEY_free(*ppkey);
        *ppkey = NULL;
    }
    return ret;
}

int EVP_PKEY_keygen_init(EVP_PKEY_CTX *ctx)
{
    int ret;
    if (!ctx || !ctx->pmeth || !ctx->pmeth->keygen) {
        EVPerr(EVP_F_EVP_PKEY_KEYGEN_INIT,
               EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        return -2;
    }
    ctx->operation = EVP_PKEY_OP_KEYGEN;
    if (!ctx->pmeth->keygen_init)
        return 1;
    ret = ctx->pmeth->keygen_init(ctx);
    if (ret <= 0)
        ctx->operation = EVP_PKEY_OP_UNDEFINED;
    return ret;
}

int EVP_PKEY_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey)
{
    int ret;

    if (!ctx || !ctx->pmeth || !ctx->pmeth->keygen) {
        EVPerr(EVP_F_EVP_PKEY_KEYGEN,
               EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        return -2;
    }
    if (ctx->operation != EVP_PKEY_OP_KEYGEN) {
        EVPerr(EVP_F_EVP_PKEY_KEYGEN, EVP_R_OPERATON_NOT_INITIALIZED);
        return -1;
    }

    if (!ppkey)
        return -1;

    if (*ppkey == NULL)
        *ppkey = EVP_PKEY_new();
    if (*ppkey == NULL)
        return -1;

    ret = ctx->pmeth->keygen(ctx, *ppkey);
    if (ret <= 0) {
        EVP_PKEY_free(*ppkey);
        *ppkey = NULL;
    }
    return ret;
}

void EVP_PKEY_CTX_set_cb(EVP_PKEY_CTX *ctx, EVP_PKEY_gen_cb *cb)
{
    ctx->pkey_gencb = cb;
}

EVP_PKEY_gen_cb *EVP_PKEY_CTX_get_cb(EVP_PKEY_CTX *ctx)
{
    return ctx->pkey_gencb;
}

/*
 * "translation callback" to call EVP_PKEY_CTX callbacks using BN_GENCB style
 * callbacks.
 */

static int trans_cb(int a, int b, BN_GENCB *gcb)
{
    EVP_PKEY_CTX *ctx = gcb->arg;
    ctx->keygen_info[0] = a;
    ctx->keygen_info[1] = b;
    return ctx->pkey_gencb(ctx);
}

void evp_pkey_set_cb_translate(BN_GENCB *cb, EVP_PKEY_CTX *ctx)
{
    BN_GENCB_set(cb, trans_cb, ctx)
}

int EVP_PKEY_CTX_get_keygen_info(EVP_PKEY_CTX *ctx, int idx)
{
    if (idx == -1)
        return ctx->keygen_info_count;
    if (idx < 0 || idx > ctx->keygen_info_count)
        return 0;
    return ctx->keygen_info[idx];
}

EVP_PKEY *EVP_PKEY_new_mac_key(int type, ENGINE *e,
                               const unsigned char *key, int keylen)
{
    EVP_PKEY_CTX *mac_ctx = NULL;
    EVP_PKEY *mac_key = NULL;
    mac_ctx = EVP_PKEY_CTX_new_id(type, e);
    if (!mac_ctx)
        return NULL;
    if (EVP_PKEY_keygen_init(mac_ctx) <= 0)
        goto merr;
    if (EVP_PKEY_CTX_ctrl(mac_ctx, -1, EVP_PKEY_OP_KEYGEN,
                          EVP_PKEY_CTRL_SET_MAC_KEY,
                          keylen, (void *)key) <= 0)
        goto merr;
    if (EVP_PKEY_keygen(mac_ctx, &mac_key) <= 0)
        goto merr;
 merr:
    if (mac_ctx)
        EVP_PKEY_CTX_free(mac_ctx);
    return mac_key;
}
/* pmeth_lib.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 2006.
 */
/* ====================================================================
 * Copyright (c) 2006 The OpenSSL Project.  All rights reserved.
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
#include <stdlib.h>
// #include "cryptlib.h"
// #include "objects.h"
// #include "evp.h"
#ifndef OPENSSL_NO_ENGINE
# include "engine.h"
#endif
#include "asn1_locl.h"
// #include "evp_locl.h"

typedef int sk_cmp_fn_type(const char *const *a, const char *const *b);

DECLARE_STACK_OF(EVP_PKEY_METHOD)
STACK_OF(EVP_PKEY_METHOD) *app_pkey_methods = NULL;

extern const EVP_PKEY_METHOD rsa_pkey_meth, dh_pkey_meth, dsa_pkey_meth;
extern const EVP_PKEY_METHOD ec_pkey_meth, hmac_pkey_meth, cmac_pkey_meth;
extern const EVP_PKEY_METHOD dhx_pkey_meth;

static const EVP_PKEY_METHOD *standard_methods[] = {
#ifndef OPENSSL_NO_RSA
    &rsa_pkey_meth,
#endif
#ifndef OPENSSL_NO_DH
    &dh_pkey_meth,
#endif
#ifndef OPENSSL_NO_DSA
    &dsa_pkey_meth,
#endif
#ifndef OPENSSL_NO_EC
    &ec_pkey_meth,
#endif
    &hmac_pkey_meth,
#ifndef OPENSSL_NO_CMAC
    &cmac_pkey_meth,
#endif
#ifndef OPENSSL_NO_DH
    &dhx_pkey_meth
#endif
};

DECLARE_OBJ_BSEARCH_CMP_FN(const EVP_PKEY_METHOD *, const EVP_PKEY_METHOD *,
                           pmeth);

static int pmeth_cmp(const EVP_PKEY_METHOD *const *a,
                     const EVP_PKEY_METHOD *const *b)
{
    return ((*a)->pkey_id - (*b)->pkey_id);
}

IMPLEMENT_OBJ_BSEARCH_CMP_FN(const EVP_PKEY_METHOD *, const EVP_PKEY_METHOD *,
                             pmeth);

const EVP_PKEY_METHOD *EVP_PKEY_meth_find(int type)
{
    EVP_PKEY_METHOD tmp;
    const EVP_PKEY_METHOD *t = &tmp, **ret;
    tmp.pkey_id = type;
    if (app_pkey_methods) {
        int idx;
        idx = sk_EVP_PKEY_METHOD_find(app_pkey_methods, &tmp);
        if (idx >= 0)
            return sk_EVP_PKEY_METHOD_value(app_pkey_methods, idx);
    }
    ret = OBJ_bsearch_pmeth(&t, standard_methods,
                            sizeof(standard_methods) /
                            sizeof(EVP_PKEY_METHOD *));
    if (!ret || !*ret)
        return NULL;
    return *ret;
}

static EVP_PKEY_CTX *int_ctx_new(EVP_PKEY *pkey, ENGINE *e, int id)
{
    EVP_PKEY_CTX *ret;
    const EVP_PKEY_METHOD *pmeth;
    if (id == -1) {
        if (!pkey || !pkey->ameth)
            return NULL;
        id = pkey->ameth->pkey_id;
    }
#ifndef OPENSSL_NO_ENGINE
    if (pkey && pkey->engine)
        e = pkey->engine;
    /* Try to find an ENGINE which implements this method */
    if (e) {
        if (!ENGINE_init(e)) {
            EVPerr(EVP_F_INT_CTX_NEW, ERR_R_ENGINE_LIB);
            return NULL;
        }
    } else
        e = ENGINE_get_pkey_meth_engine(id);

    /*
     * If an ENGINE handled this method look it up. Othewise use internal
     * tables.
     */

    if (e)
        pmeth = ENGINE_get_pkey_meth(e, id);
    else
#endif
        pmeth = EVP_PKEY_meth_find(id);

    if (pmeth == NULL) {
        EVPerr(EVP_F_INT_CTX_NEW, EVP_R_UNSUPPORTED_ALGORITHM);
        return NULL;
    }

    ret = OPENSSL_malloc(sizeof(EVP_PKEY_CTX));
    if (!ret) {
#ifndef OPENSSL_NO_ENGINE
        if (e)
            ENGINE_finish(e);
#endif
        EVPerr(EVP_F_INT_CTX_NEW, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    ret->engine = e;
    ret->pmeth = pmeth;
    ret->operation = EVP_PKEY_OP_UNDEFINED;
    ret->pkey = pkey;
    ret->peerkey = NULL;
    ret->pkey_gencb = 0;
    if (pkey)
        CRYPTO_add(&pkey->references, 1, CRYPTO_LOCK_EVP_PKEY);
    ret->data = NULL;

    if (pmeth->init) {
        if (pmeth->init(ret) <= 0) {
            ret->pmeth = NULL;
            EVP_PKEY_CTX_free(ret);
            return NULL;
        }
    }

    return ret;
}

EVP_PKEY_METHOD *EVP_PKEY_meth_new(int id, int flags)
{
    EVP_PKEY_METHOD *pmeth;

    pmeth = OPENSSL_malloc(sizeof(EVP_PKEY_METHOD));
    if (!pmeth)
        return NULL;

    memset(pmeth, 0, sizeof(EVP_PKEY_METHOD));

    pmeth->pkey_id = id;
    pmeth->flags = flags | EVP_PKEY_FLAG_DYNAMIC;
    return pmeth;
}

void EVP_PKEY_meth_get0_info(int *ppkey_id, int *pflags,
                             const EVP_PKEY_METHOD *meth)
{
    if (ppkey_id)
        *ppkey_id = meth->pkey_id;
    if (pflags)
        *pflags = meth->flags;
}

void EVP_PKEY_meth_copy(EVP_PKEY_METHOD *dst, const EVP_PKEY_METHOD *src)
{

    dst->init = src->init;
    dst->copy = src->copy;
    dst->cleanup = src->cleanup;

    dst->paramgen_init = src->paramgen_init;
    dst->paramgen = src->paramgen;

    dst->keygen_init = src->keygen_init;
    dst->keygen = src->keygen;

    dst->sign_init = src->sign_init;
    dst->sign = src->sign;

    dst->verify_init = src->verify_init;
    dst->verify = src->verify;

    dst->verify_recover_init = src->verify_recover_init;
    dst->verify_recover = src->verify_recover;

    dst->signctx_init = src->signctx_init;
    dst->signctx = src->signctx;

    dst->verifyctx_init = src->verifyctx_init;
    dst->verifyctx = src->verifyctx;

    dst->encrypt_init = src->encrypt_init;
    dst->encrypt = src->encrypt;

    dst->decrypt_init = src->decrypt_init;
    dst->decrypt = src->decrypt;

    dst->derive_init = src->derive_init;
    dst->derive = src->derive;

    dst->ctrl = src->ctrl;
    dst->ctrl_str = src->ctrl_str;
}

void EVP_PKEY_meth_free(EVP_PKEY_METHOD *pmeth)
{
    if (pmeth && (pmeth->flags & EVP_PKEY_FLAG_DYNAMIC))
        OPENSSL_free(pmeth);
}

EVP_PKEY_CTX *EVP_PKEY_CTX_new(EVP_PKEY *pkey, ENGINE *e)
{
    return int_ctx_new(pkey, e, -1);
}

EVP_PKEY_CTX *EVP_PKEY_CTX_new_id(int id, ENGINE *e)
{
    return int_ctx_new(NULL, e, id);
}

EVP_PKEY_CTX *EVP_PKEY_CTX_dup(EVP_PKEY_CTX *pctx)
{
    EVP_PKEY_CTX *rctx;
    if (!pctx->pmeth || !pctx->pmeth->copy)
        return NULL;
#ifndef OPENSSL_NO_ENGINE
    /* Make sure it's safe to copy a pkey context using an ENGINE */
    if (pctx->engine && !ENGINE_init(pctx->engine)) {
        EVPerr(EVP_F_EVP_PKEY_CTX_DUP, ERR_R_ENGINE_LIB);
        return 0;
    }
#endif
    rctx = OPENSSL_malloc(sizeof(EVP_PKEY_CTX));
    if (!rctx)
        return NULL;

    rctx->pmeth = pctx->pmeth;
#ifndef OPENSSL_NO_ENGINE
    rctx->engine = pctx->engine;
#endif

    if (pctx->pkey)
        CRYPTO_add(&pctx->pkey->references, 1, CRYPTO_LOCK_EVP_PKEY);

    rctx->pkey = pctx->pkey;

    if (pctx->peerkey)
        CRYPTO_add(&pctx->peerkey->references, 1, CRYPTO_LOCK_EVP_PKEY);

    rctx->peerkey = pctx->peerkey;

    rctx->data = NULL;
    rctx->app_data = NULL;
    rctx->operation = pctx->operation;

    if (pctx->pmeth->copy(rctx, pctx) > 0)
        return rctx;

    rctx->pmeth = NULL;
    EVP_PKEY_CTX_free(rctx);
    return NULL;

}

int EVP_PKEY_meth_add0(const EVP_PKEY_METHOD *pmeth)
{
    if (app_pkey_methods == NULL) {
        app_pkey_methods = sk_EVP_PKEY_METHOD_new(pmeth_cmp);
        if (!app_pkey_methods)
            return 0;
    }
    if (!sk_EVP_PKEY_METHOD_push(app_pkey_methods, pmeth))
        return 0;
    sk_EVP_PKEY_METHOD_sort(app_pkey_methods);
    return 1;
}

void EVP_PKEY_CTX_free(EVP_PKEY_CTX *ctx)
{
    if (ctx == NULL)
        return;
    if (ctx->pmeth && ctx->pmeth->cleanup)
        ctx->pmeth->cleanup(ctx);
    if (ctx->pkey)
        EVP_PKEY_free(ctx->pkey);
    if (ctx->peerkey)
        EVP_PKEY_free(ctx->peerkey);
#ifndef OPENSSL_NO_ENGINE
    if (ctx->engine)
        /*
         * The EVP_PKEY_CTX we used belongs to an ENGINE, release the
         * functional reference we held for this reason.
         */
        ENGINE_finish(ctx->engine);
#endif
    OPENSSL_free(ctx);
}

int EVP_PKEY_CTX_ctrl(EVP_PKEY_CTX *ctx, int keytype, int optype,
                      int cmd, int p1, void *p2)
{
    int ret;
    if (!ctx || !ctx->pmeth || !ctx->pmeth->ctrl) {
        EVPerr(EVP_F_EVP_PKEY_CTX_CTRL, EVP_R_COMMAND_NOT_SUPPORTED);
        return -2;
    }
    if ((keytype != -1) && (ctx->pmeth->pkey_id != keytype))
        return -1;

    if (ctx->operation == EVP_PKEY_OP_UNDEFINED) {
        EVPerr(EVP_F_EVP_PKEY_CTX_CTRL, EVP_R_NO_OPERATION_SET);
        return -1;
    }

    if ((optype != -1) && !(ctx->operation & optype)) {
        EVPerr(EVP_F_EVP_PKEY_CTX_CTRL, EVP_R_INVALID_OPERATION);
        return -1;
    }

    ret = ctx->pmeth->ctrl(ctx, cmd, p1, p2);

    if (ret == -2)
        EVPerr(EVP_F_EVP_PKEY_CTX_CTRL, EVP_R_COMMAND_NOT_SUPPORTED);

    return ret;

}

int EVP_PKEY_CTX_ctrl_str(EVP_PKEY_CTX *ctx,
                          const char *name, const char *value)
{
    if (!ctx || !ctx->pmeth || !ctx->pmeth->ctrl_str) {
        EVPerr(EVP_F_EVP_PKEY_CTX_CTRL_STR, EVP_R_COMMAND_NOT_SUPPORTED);
        return -2;
    }
    if (!strcmp(name, "digest")) {
        const EVP_MD *md;
        if (!value || !(md = EVP_get_digestbyname(value))) {
            EVPerr(EVP_F_EVP_PKEY_CTX_CTRL_STR, EVP_R_INVALID_DIGEST);
            return 0;
        }
        return EVP_PKEY_CTX_set_signature_md(ctx, md);
    }
    return ctx->pmeth->ctrl_str(ctx, name, value);
}

int EVP_PKEY_CTX_get_operation(EVP_PKEY_CTX *ctx)
{
    return ctx->operation;
}

void EVP_PKEY_CTX_set0_keygen_info(EVP_PKEY_CTX *ctx, int *dat, int datlen)
{
    ctx->keygen_info = dat;
    ctx->keygen_info_count = datlen;
}

void EVP_PKEY_CTX_set_data(EVP_PKEY_CTX *ctx, void *data)
{
    ctx->data = data;
}

void *EVP_PKEY_CTX_get_data(EVP_PKEY_CTX *ctx)
{
    return ctx->data;
}

EVP_PKEY *EVP_PKEY_CTX_get0_pkey(EVP_PKEY_CTX *ctx)
{
    return ctx->pkey;
}

EVP_PKEY *EVP_PKEY_CTX_get0_peerkey(EVP_PKEY_CTX *ctx)
{
    return ctx->peerkey;
}

void EVP_PKEY_CTX_set_app_data(EVP_PKEY_CTX *ctx, void *data)
{
    ctx->app_data = data;
}

void *EVP_PKEY_CTX_get_app_data(EVP_PKEY_CTX *ctx)
{
    return ctx->app_data;
}

void EVP_PKEY_meth_set_init(EVP_PKEY_METHOD *pmeth,
                            int (*init) (EVP_PKEY_CTX *ctx))
{
    pmeth->init = init;
}

void EVP_PKEY_meth_set_copy(EVP_PKEY_METHOD *pmeth,
                            int (*copy) (EVP_PKEY_CTX *dst,
                                         EVP_PKEY_CTX *src))
{
    pmeth->copy = copy;
}

void EVP_PKEY_meth_set_cleanup(EVP_PKEY_METHOD *pmeth,
                               void (*cleanup) (EVP_PKEY_CTX *ctx))
{
    pmeth->cleanup = cleanup;
}

void EVP_PKEY_meth_set_paramgen(EVP_PKEY_METHOD *pmeth,
                                int (*paramgen_init) (EVP_PKEY_CTX *ctx),
                                int (*paramgen) (EVP_PKEY_CTX *ctx,
                                                 EVP_PKEY *pkey))
{
    pmeth->paramgen_init = paramgen_init;
    pmeth->paramgen = paramgen;
}

void EVP_PKEY_meth_set_keygen(EVP_PKEY_METHOD *pmeth,
                              int (*keygen_init) (EVP_PKEY_CTX *ctx),
                              int (*keygen) (EVP_PKEY_CTX *ctx,
                                             EVP_PKEY *pkey))
{
    pmeth->keygen_init = keygen_init;
    pmeth->keygen = keygen;
}

void EVP_PKEY_meth_set_sign(EVP_PKEY_METHOD *pmeth,
                            int (*sign_init) (EVP_PKEY_CTX *ctx),
                            int (*sign) (EVP_PKEY_CTX *ctx,
                                         unsigned char *sig, size_t *siglen,
                                         const unsigned char *tbs,
                                         size_t tbslen))
{
    pmeth->sign_init = sign_init;
    pmeth->sign = sign;
}

void EVP_PKEY_meth_set_verify(EVP_PKEY_METHOD *pmeth,
                              int (*verify_init) (EVP_PKEY_CTX *ctx),
                              int (*verify) (EVP_PKEY_CTX *ctx,
                                             const unsigned char *sig,
                                             size_t siglen,
                                             const unsigned char *tbs,
                                             size_t tbslen))
{
    pmeth->verify_init = verify_init;
    pmeth->verify = verify;
}

void EVP_PKEY_meth_set_verify_recover(EVP_PKEY_METHOD *pmeth,
                                      int (*verify_recover_init) (EVP_PKEY_CTX
                                                                  *ctx),
                                      int (*verify_recover) (EVP_PKEY_CTX
                                                             *ctx,
                                                             unsigned char
                                                             *sig,
                                                             size_t *siglen,
                                                             const unsigned
                                                             char *tbs,
                                                             size_t tbslen))
{
    pmeth->verify_recover_init = verify_recover_init;
    pmeth->verify_recover = verify_recover;
}

void EVP_PKEY_meth_set_signctx(EVP_PKEY_METHOD *pmeth,
                               int (*signctx_init) (EVP_PKEY_CTX *ctx,
                                                    EVP_MD_CTX *mctx),
                               int (*signctx) (EVP_PKEY_CTX *ctx,
                                               unsigned char *sig,
                                               size_t *siglen,
                                               EVP_MD_CTX *mctx))
{
    pmeth->signctx_init = signctx_init;
    pmeth->signctx = signctx;
}

void EVP_PKEY_meth_set_verifyctx(EVP_PKEY_METHOD *pmeth,
                                 int (*verifyctx_init) (EVP_PKEY_CTX *ctx,
                                                        EVP_MD_CTX *mctx),
                                 int (*verifyctx) (EVP_PKEY_CTX *ctx,
                                                   const unsigned char *sig,
                                                   int siglen,
                                                   EVP_MD_CTX *mctx))
{
    pmeth->verifyctx_init = verifyctx_init;
    pmeth->verifyctx = verifyctx;
}

void EVP_PKEY_meth_set_encrypt(EVP_PKEY_METHOD *pmeth,
                               int (*encrypt_init) (EVP_PKEY_CTX *ctx),
                               int (*encryptfn) (EVP_PKEY_CTX *ctx,
                                                 unsigned char *out,
                                                 size_t *outlen,
                                                 const unsigned char *in,
                                                 size_t inlen))
{
    pmeth->encrypt_init = encrypt_init;
    pmeth->encrypt = encryptfn;
}

void EVP_PKEY_meth_set_decrypt(EVP_PKEY_METHOD *pmeth,
                               int (*decrypt_init) (EVP_PKEY_CTX *ctx),
                               int (*decrypt) (EVP_PKEY_CTX *ctx,
                                               unsigned char *out,
                                               size_t *outlen,
                                               const unsigned char *in,
                                               size_t inlen))
{
    pmeth->decrypt_init = decrypt_init;
    pmeth->decrypt = decrypt;
}

void EVP_PKEY_meth_set_derive(EVP_PKEY_METHOD *pmeth,
                              int (*derive_init) (EVP_PKEY_CTX *ctx),
                              int (*derive) (EVP_PKEY_CTX *ctx,
                                             unsigned char *key,
                                             size_t *keylen))
{
    pmeth->derive_init = derive_init;
    pmeth->derive = derive;
}

void EVP_PKEY_meth_set_ctrl(EVP_PKEY_METHOD *pmeth,
                            int (*ctrl) (EVP_PKEY_CTX *ctx, int type, int p1,
                                         void *p2),
                            int (*ctrl_str) (EVP_PKEY_CTX *ctx,
                                             const char *type,
                                             const char *value))
{
    pmeth->ctrl = ctrl;
    pmeth->ctrl_str = ctrl_str;
}

void EVP_PKEY_meth_get_init(EVP_PKEY_METHOD *pmeth,
                            int (**pinit) (EVP_PKEY_CTX *ctx))
{
    *pinit = pmeth->init;
}

void EVP_PKEY_meth_get_copy(EVP_PKEY_METHOD *pmeth,
                            int (**pcopy) (EVP_PKEY_CTX *dst,
                                           EVP_PKEY_CTX *src))
{
    *pcopy = pmeth->copy;
}

void EVP_PKEY_meth_get_cleanup(EVP_PKEY_METHOD *pmeth,
                               void (**pcleanup) (EVP_PKEY_CTX *ctx))
{
    *pcleanup = pmeth->cleanup;
}

void EVP_PKEY_meth_get_paramgen(EVP_PKEY_METHOD *pmeth,
                                int (**pparamgen_init) (EVP_PKEY_CTX *ctx),
                                int (**pparamgen) (EVP_PKEY_CTX *ctx,
                                                   EVP_PKEY *pkey))
{
    if (pparamgen_init)
        *pparamgen_init = pmeth->paramgen_init;
    if (pparamgen)
        *pparamgen = pmeth->paramgen;
}

void EVP_PKEY_meth_get_keygen(EVP_PKEY_METHOD *pmeth,
                              int (**pkeygen_init) (EVP_PKEY_CTX *ctx),
                              int (**pkeygen) (EVP_PKEY_CTX *ctx,
                                               EVP_PKEY *pkey))
{
    if (pkeygen_init)
        *pkeygen_init = pmeth->keygen_init;
    if (pkeygen)
        *pkeygen = pmeth->keygen;
}

void EVP_PKEY_meth_get_sign(EVP_PKEY_METHOD *pmeth,
                            int (**psign_init) (EVP_PKEY_CTX *ctx),
                            int (**psign) (EVP_PKEY_CTX *ctx,
                                           unsigned char *sig, size_t *siglen,
                                           const unsigned char *tbs,
                                           size_t tbslen))
{
    if (psign_init)
        *psign_init = pmeth->sign_init;
    if (psign)
        *psign = pmeth->sign;
}

void EVP_PKEY_meth_get_verify(EVP_PKEY_METHOD *pmeth,
                              int (**pverify_init) (EVP_PKEY_CTX *ctx),
                              int (**pverify) (EVP_PKEY_CTX *ctx,
                                               const unsigned char *sig,
                                               size_t siglen,
                                               const unsigned char *tbs,
                                               size_t tbslen))
{
    if (pverify_init)
        *pverify_init = pmeth->verify_init;
    if (pverify)
        *pverify = pmeth->verify;
}

void EVP_PKEY_meth_get_verify_recover(EVP_PKEY_METHOD *pmeth,
                                      int (**pverify_recover_init) (EVP_PKEY_CTX
                                                                    *ctx),
                                      int (**pverify_recover) (EVP_PKEY_CTX
                                                               *ctx,
                                                               unsigned char
                                                               *sig,
                                                               size_t *siglen,
                                                               const unsigned
                                                               char *tbs,
                                                               size_t tbslen))
{
    if (pverify_recover_init)
        *pverify_recover_init = pmeth->verify_recover_init;
    if (pverify_recover)
        *pverify_recover = pmeth->verify_recover;
}

void EVP_PKEY_meth_get_signctx(EVP_PKEY_METHOD *pmeth,
                               int (**psignctx_init) (EVP_PKEY_CTX *ctx,
                                                      EVP_MD_CTX *mctx),
                               int (**psignctx) (EVP_PKEY_CTX *ctx,
                                                 unsigned char *sig,
                                                 size_t *siglen,
                                                 EVP_MD_CTX *mctx))
{
    if (psignctx_init)
        *psignctx_init = pmeth->signctx_init;
    if (psignctx)
        *psignctx = pmeth->signctx;
}

void EVP_PKEY_meth_get_verifyctx(EVP_PKEY_METHOD *pmeth,
                                 int (**pverifyctx_init) (EVP_PKEY_CTX *ctx,
                                                          EVP_MD_CTX *mctx),
                                 int (**pverifyctx) (EVP_PKEY_CTX *ctx,
                                                     const unsigned char *sig,
                                                     int siglen,
                                                     EVP_MD_CTX *mctx))
{
    if (pverifyctx_init)
        *pverifyctx_init = pmeth->verifyctx_init;
    if (pverifyctx)
        *pverifyctx = pmeth->verifyctx;
}

void EVP_PKEY_meth_get_encrypt(EVP_PKEY_METHOD *pmeth,
                               int (**pencrypt_init) (EVP_PKEY_CTX *ctx),
                               int (**pencryptfn) (EVP_PKEY_CTX *ctx,
                                                   unsigned char *out,
                                                   size_t *outlen,
                                                   const unsigned char *in,
                                                   size_t inlen))
{
    if (pencrypt_init)
        *pencrypt_init = pmeth->encrypt_init;
    if (pencryptfn)
        *pencryptfn = pmeth->encrypt;
}

void EVP_PKEY_meth_get_decrypt(EVP_PKEY_METHOD *pmeth,
                               int (**pdecrypt_init) (EVP_PKEY_CTX *ctx),
                               int (**pdecrypt) (EVP_PKEY_CTX *ctx,
                                                 unsigned char *out,
                                                 size_t *outlen,
                                                 const unsigned char *in,
                                                 size_t inlen))
{
    if (pdecrypt_init)
        *pdecrypt_init = pmeth->decrypt_init;
    if (pdecrypt)
        *pdecrypt = pmeth->decrypt;
}

void EVP_PKEY_meth_get_derive(EVP_PKEY_METHOD *pmeth,
                              int (**pderive_init) (EVP_PKEY_CTX *ctx),
                              int (**pderive) (EVP_PKEY_CTX *ctx,
                                               unsigned char *key,
                                               size_t *keylen))
{
    if (pderive_init)
        *pderive_init = pmeth->derive_init;
    if (pderive)
        *pderive = pmeth->derive;
}

void EVP_PKEY_meth_get_ctrl(EVP_PKEY_METHOD *pmeth,
                            int (**pctrl) (EVP_PKEY_CTX *ctx, int type, int p1,
                                           void *p2),
                            int (**pctrl_str) (EVP_PKEY_CTX *ctx,
                                               const char *type,
                                               const char *value))
{
    if (pctrl)
        *pctrl = pmeth->ctrl;
    if (pctrl_str)
        *pctrl_str = pmeth->ctrl_str;
}
