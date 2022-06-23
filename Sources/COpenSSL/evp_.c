/* evp_acnf.c */
/*
 * Written by Stephen Henson (steve@openssl.org) for the OpenSSL project
 * 2001.
 */
/* ====================================================================
 * Copyright (c) 2001 The OpenSSL Project.  All rights reserved.
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

#include "cryptlib.h"
#include "evp.h"
#include "conf.h"

/*
 * Load all algorithms and configure OpenSSL. This function is called
 * automatically when OPENSSL_LOAD_CONF is set.
 */

void OPENSSL_add_all_algorithms_conf(void)
{
    OPENSSL_add_all_algorithms_noconf();
    OPENSSL_config(NULL);
}
/* crypto/asn1/evp_asn1.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

#include <stdio.h>
// #include "cryptlib.h"
#include "asn1.h"
#include "asn1_mac.h"

int ASN1_TYPE_set_octetstring(ASN1_TYPE *a, unsigned char *data, int len)
{
    ASN1_STRING *os;

    if ((os = M_ASN1_OCTET_STRING_new()) == NULL)
        return (0);
    if (!M_ASN1_OCTET_STRING_set(os, data, len)) {
        M_ASN1_OCTET_STRING_free(os);
        return 0;
    }
    ASN1_TYPE_set(a, V_ASN1_OCTET_STRING, os);
    return (1);
}

/* int max_len:  for returned value    */
int ASN1_TYPE_get_octetstring(ASN1_TYPE *a, unsigned char *data, int max_len)
{
    int ret, num;
    unsigned char *p;

    if ((a->type != V_ASN1_OCTET_STRING) || (a->value.octet_string == NULL)) {
        ASN1err(ASN1_F_ASN1_TYPE_GET_OCTETSTRING, ASN1_R_DATA_IS_WRONG);
        return (-1);
    }
    p = M_ASN1_STRING_data(a->value.octet_string);
    ret = M_ASN1_STRING_length(a->value.octet_string);
    if (ret < max_len)
        num = ret;
    else
        num = max_len;
    memcpy(data, p, num);
    return (ret);
}

int ASN1_TYPE_set_int_octetstring(ASN1_TYPE *a, long num, unsigned char *data,
                                  int len)
{
    int n, size;
    ASN1_OCTET_STRING os, *osp;
    ASN1_INTEGER in;
    unsigned char *p;
    unsigned char buf[32];      /* when they have 256bit longs, I'll be in
                                 * trouble */
    in.data = buf;
    in.length = 32;
    os.data = data;
    os.type = V_ASN1_OCTET_STRING;
    os.length = len;
    ASN1_INTEGER_set(&in, num);
    n = i2d_ASN1_INTEGER(&in, NULL);
    n += M_i2d_ASN1_OCTET_STRING(&os, NULL);

    size = ASN1_object_size(1, n, V_ASN1_SEQUENCE);

    if ((osp = ASN1_STRING_new()) == NULL)
        return (0);
    /* Grow the 'string' */
    if (!ASN1_STRING_set(osp, NULL, size)) {
        ASN1_STRING_free(osp);
        return (0);
    }

    M_ASN1_STRING_length_set(osp, size);
    p = M_ASN1_STRING_data(osp);

    ASN1_put_object(&p, 1, n, V_ASN1_SEQUENCE, V_ASN1_UNIVERSAL);
    i2d_ASN1_INTEGER(&in, &p);
    M_i2d_ASN1_OCTET_STRING(&os, &p);

    ASN1_TYPE_set(a, V_ASN1_SEQUENCE, osp);
    return (1);
}

/*
 * we return the actual length..., num may be missing, in which case, set it
 * to zero
 */
/* int max_len:  for returned value    */
int ASN1_TYPE_get_int_octetstring(ASN1_TYPE *a, long *num,
                                  unsigned char *data, int max_len)
{
    int ret = -1, n;
    ASN1_INTEGER *ai = NULL;
    ASN1_OCTET_STRING *os = NULL;
    const unsigned char *p;
    long length;
    ASN1_const_CTX c;

    if ((a->type != V_ASN1_SEQUENCE) || (a->value.sequence == NULL)) {
        goto err;
    }
    p = M_ASN1_STRING_data(a->value.sequence);
    length = M_ASN1_STRING_length(a->value.sequence);

    c.pp = &p;
    c.p = p;
    c.max = p + length;
    c.error = ASN1_R_DATA_IS_WRONG;

    M_ASN1_D2I_start_sequence();
    c.q = c.p;
    if ((ai = d2i_ASN1_INTEGER(NULL, &c.p, c.slen)) == NULL)
        goto err;
    c.slen -= (c.p - c.q);
    c.q = c.p;
    if ((os = d2i_ASN1_OCTET_STRING(NULL, &c.p, c.slen)) == NULL)
        goto err;
    c.slen -= (c.p - c.q);
    if (!M_ASN1_D2I_end_sequence())
        goto err;

    if (num != NULL)
        *num = ASN1_INTEGER_get(ai);

    ret = M_ASN1_STRING_length(os);
    if (max_len > ret)
        n = ret;
    else
        n = max_len;

    if (data != NULL)
        memcpy(data, M_ASN1_STRING_data(os), n);
    if (0) {
 err:
        ASN1err(ASN1_F_ASN1_TYPE_GET_INT_OCTETSTRING, ASN1_R_DATA_IS_WRONG);
    }
    if (os != NULL)
        M_ASN1_OCTET_STRING_free(os);
    if (ai != NULL)
        M_ASN1_INTEGER_free(ai);
    return (ret);
}
/* evp_cnf.c */
/*
 * Written by Stephen Henson (steve@openssl.org) for the OpenSSL project
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
#include <ctype.h>
#include "crypto.h"
// #include "cryptlib.h"
// #include "conf.h"
#include "dso.h"
#include "x509.h"
#include "x509v3.h"
#ifdef OPENSSL_FIPS
# include <fips.h>
#endif

/* Algorithm configuration module. */

static int alg_module_init(CONF_IMODULE *md, const CONF *cnf)
{
    int i;
    const char *oid_section;
    STACK_OF(CONF_VALUE) *sktmp;
    CONF_VALUE *oval;
    oid_section = CONF_imodule_get_value(md);
    if (!(sktmp = NCONF_get_section(cnf, oid_section))) {
        EVPerr(EVP_F_ALG_MODULE_INIT, EVP_R_ERROR_LOADING_SECTION);
        return 0;
    }
    for (i = 0; i < sk_CONF_VALUE_num(sktmp); i++) {
        oval = sk_CONF_VALUE_value(sktmp, i);
        if (!strcmp(oval->name, "fips_mode")) {
            int m;
            if (!X509V3_get_value_bool(oval, &m)) {
                EVPerr(EVP_F_ALG_MODULE_INIT, EVP_R_INVALID_FIPS_MODE);
                return 0;
            }
            if (m > 0) {
#ifdef OPENSSL_FIPS
                if (!FIPS_mode() && !FIPS_mode_set(1)) {
                    EVPerr(EVP_F_ALG_MODULE_INIT,
                           EVP_R_ERROR_SETTING_FIPS_MODE);
                    return 0;
                }
#else
                EVPerr(EVP_F_ALG_MODULE_INIT, EVP_R_FIPS_MODE_NOT_SUPPORTED);
                return 0;
#endif
            }
        } else {
            EVPerr(EVP_F_ALG_MODULE_INIT, EVP_R_UNKNOWN_OPTION);
            ERR_add_error_data(4, "name=", oval->name,
                               ", value=", oval->value);
        }

    }
    return 1;
}

void EVP_add_alg_module(void)
{
    CONF_module_add("alg_section", alg_module_init, 0);
}
/* crypto/evp/evp_enc.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

#include <stdio.h>
// #include "cryptlib.h"
// #include "evp.h"
#include "err.h"
#include "rand.h"
#ifndef OPENSSL_NO_ENGINE
# include "engine.h"
#endif
#ifdef OPENSSL_FIPS
# include <fips.h>
#endif
#include "evp_locl.h"

#ifdef OPENSSL_FIPS
# define M_do_cipher(ctx, out, in, inl) FIPS_cipher(ctx, out, in, inl)
#else
# define M_do_cipher(ctx, out, in, inl) ctx->cipher->do_cipher(ctx, out, in, inl)
#endif

const char EVP_version[] = "EVP" OPENSSL_VERSION_PTEXT;

void EVP_CIPHER_CTX_init(EVP_CIPHER_CTX *ctx)
{
    memset(ctx, 0, sizeof(EVP_CIPHER_CTX));
    /* ctx->cipher=NULL; */
}

EVP_CIPHER_CTX *EVP_CIPHER_CTX_new(void)
{
    EVP_CIPHER_CTX *ctx = OPENSSL_malloc(sizeof(*ctx));
    if (ctx)
        EVP_CIPHER_CTX_init(ctx);
    return ctx;
}

int EVP_CipherInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                   const unsigned char *key, const unsigned char *iv, int enc)
{
    if (cipher)
        EVP_CIPHER_CTX_init(ctx);
    return EVP_CipherInit_ex(ctx, cipher, NULL, key, iv, enc);
}

int EVP_CipherInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                      ENGINE *impl, const unsigned char *key,
                      const unsigned char *iv, int enc)
{
    if (enc == -1)
        enc = ctx->encrypt;
    else {
        if (enc)
            enc = 1;
        ctx->encrypt = enc;
    }
#ifndef OPENSSL_NO_ENGINE
    /*
     * Whether it's nice or not, "Inits" can be used on "Final"'d contexts so
     * this context may already have an ENGINE! Try to avoid releasing the
     * previous handle, re-querying for an ENGINE, and having a
     * reinitialisation, when it may all be unecessary.
     */
    if (ctx->engine && ctx->cipher && (!cipher ||
                                       (cipher
                                        && (cipher->nid ==
                                            ctx->cipher->nid))))
        goto skip_to_init;
#endif
    if (cipher) {
        /*
         * Ensure a context left lying around from last time is cleared (the
         * previous check attempted to avoid this if the same ENGINE and
         * EVP_CIPHER could be used).
         */
        if (ctx->cipher) {
            unsigned long flags = ctx->flags;
            EVP_CIPHER_CTX_cleanup(ctx);
            /* Restore encrypt and flags */
            ctx->encrypt = enc;
            ctx->flags = flags;
        }
#ifndef OPENSSL_NO_ENGINE
        if (impl) {
            if (!ENGINE_init(impl)) {
                EVPerr(EVP_F_EVP_CIPHERINIT_EX, EVP_R_INITIALIZATION_ERROR);
                return 0;
            }
        } else
            /* Ask if an ENGINE is reserved for this job */
            impl = ENGINE_get_cipher_engine(cipher->nid);
        if (impl) {
            /* There's an ENGINE for this job ... (apparently) */
            const EVP_CIPHER *c = ENGINE_get_cipher(impl, cipher->nid);
            if (!c) {
                /*
                 * One positive side-effect of US's export control history,
                 * is that we should at least be able to avoid using US
                 * mispellings of "initialisation"?
                 */
                EVPerr(EVP_F_EVP_CIPHERINIT_EX, EVP_R_INITIALIZATION_ERROR);
                return 0;
            }
            /* We'll use the ENGINE's private cipher definition */
            cipher = c;
            /*
             * Store the ENGINE functional reference so we know 'cipher' came
             * from an ENGINE and we need to release it when done.
             */
            ctx->engine = impl;
        } else
            ctx->engine = NULL;
#endif

#ifdef OPENSSL_FIPS
        if (FIPS_mode()) {
            const EVP_CIPHER *fcipher = NULL;
            if (cipher)
                fcipher = evp_get_fips_cipher(cipher);
            if (fcipher)
                cipher = fcipher;
            return FIPS_cipherinit(ctx, cipher, key, iv, enc);
        }
#endif
        ctx->cipher = cipher;
        if (ctx->cipher->ctx_size) {
            ctx->cipher_data = OPENSSL_malloc(ctx->cipher->ctx_size);
            if (!ctx->cipher_data) {
                ctx->cipher = NULL;
                EVPerr(EVP_F_EVP_CIPHERINIT_EX, ERR_R_MALLOC_FAILURE);
                return 0;
            }
        } else {
            ctx->cipher_data = NULL;
        }
        ctx->key_len = cipher->key_len;
        /* Preserve wrap enable flag, zero everything else */
        ctx->flags &= EVP_CIPHER_CTX_FLAG_WRAP_ALLOW;
        if (ctx->cipher->flags & EVP_CIPH_CTRL_INIT) {
            if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_INIT, 0, NULL)) {
                ctx->cipher = NULL;
                EVPerr(EVP_F_EVP_CIPHERINIT_EX, EVP_R_INITIALIZATION_ERROR);
                return 0;
            }
        }
    } else if (!ctx->cipher) {
        EVPerr(EVP_F_EVP_CIPHERINIT_EX, EVP_R_NO_CIPHER_SET);
        return 0;
    }
#ifndef OPENSSL_NO_ENGINE
 skip_to_init:
#endif
#ifdef OPENSSL_FIPS
    if (FIPS_mode())
        return FIPS_cipherinit(ctx, cipher, key, iv, enc);
#endif
    /* we assume block size is a power of 2 in *cryptUpdate */
    OPENSSL_assert(ctx->cipher->block_size == 1
                   || ctx->cipher->block_size == 8
                   || ctx->cipher->block_size == 16);

    if (!(ctx->flags & EVP_CIPHER_CTX_FLAG_WRAP_ALLOW)
        && EVP_CIPHER_CTX_mode(ctx) == EVP_CIPH_WRAP_MODE) {
        EVPerr(EVP_F_EVP_CIPHERINIT_EX, EVP_R_WRAP_MODE_NOT_ALLOWED);
        return 0;
    }

    if (!(EVP_CIPHER_CTX_flags(ctx) & EVP_CIPH_CUSTOM_IV)) {
        switch (EVP_CIPHER_CTX_mode(ctx)) {

        case EVP_CIPH_STREAM_CIPHER:
        case EVP_CIPH_ECB_MODE:
            break;

        case EVP_CIPH_CFB_MODE:
        case EVP_CIPH_OFB_MODE:

            ctx->num = 0;
            /* fall-through */

        case EVP_CIPH_CBC_MODE:

            OPENSSL_assert(EVP_CIPHER_CTX_iv_length(ctx) <=
                           (int)sizeof(ctx->iv));
            if (iv)
                memcpy(ctx->oiv, iv, EVP_CIPHER_CTX_iv_length(ctx));
            memcpy(ctx->iv, ctx->oiv, EVP_CIPHER_CTX_iv_length(ctx));
            break;

        case EVP_CIPH_CTR_MODE:
            ctx->num = 0;
            /* Don't reuse IV for CTR mode */
            if (iv)
                memcpy(ctx->iv, iv, EVP_CIPHER_CTX_iv_length(ctx));
            break;

        default:
            return 0;
            break;
        }
    }

    if (key || (ctx->cipher->flags & EVP_CIPH_ALWAYS_CALL_INIT)) {
        if (!ctx->cipher->init(ctx, key, iv, enc))
            return 0;
    }
    ctx->buf_len = 0;
    ctx->final_used = 0;
    ctx->block_mask = ctx->cipher->block_size - 1;
    return 1;
}

int EVP_CipherUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
                     const unsigned char *in, int inl)
{
    if (ctx->encrypt)
        return EVP_EncryptUpdate(ctx, out, outl, in, inl);
    else
        return EVP_DecryptUpdate(ctx, out, outl, in, inl);
}

int EVP_CipherFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl)
{
    if (ctx->encrypt)
        return EVP_EncryptFinal_ex(ctx, out, outl);
    else
        return EVP_DecryptFinal_ex(ctx, out, outl);
}

int EVP_CipherFinal(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl)
{
    if (ctx->encrypt)
        return EVP_EncryptFinal(ctx, out, outl);
    else
        return EVP_DecryptFinal(ctx, out, outl);
}

int EVP_EncryptInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                    const unsigned char *key, const unsigned char *iv)
{
    return EVP_CipherInit(ctx, cipher, key, iv, 1);
}

int EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                       ENGINE *impl, const unsigned char *key,
                       const unsigned char *iv)
{
    return EVP_CipherInit_ex(ctx, cipher, impl, key, iv, 1);
}

int EVP_DecryptInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                    const unsigned char *key, const unsigned char *iv)
{
    return EVP_CipherInit(ctx, cipher, key, iv, 0);
}

int EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                       ENGINE *impl, const unsigned char *key,
                       const unsigned char *iv)
{
    return EVP_CipherInit_ex(ctx, cipher, impl, key, iv, 0);
}

int EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
                      const unsigned char *in, int inl)
{
    int i, j, bl;

    if (ctx->cipher->flags & EVP_CIPH_FLAG_CUSTOM_CIPHER) {
        i = M_do_cipher(ctx, out, in, inl);
        if (i < 0)
            return 0;
        else
            *outl = i;
        return 1;
    }

    if (inl <= 0) {
        *outl = 0;
        return inl == 0;
    }

    if (ctx->buf_len == 0 && (inl & (ctx->block_mask)) == 0) {
        if (M_do_cipher(ctx, out, in, inl)) {
            *outl = inl;
            return 1;
        } else {
            *outl = 0;
            return 0;
        }
    }
    i = ctx->buf_len;
    bl = ctx->cipher->block_size;
    OPENSSL_assert(bl <= (int)sizeof(ctx->buf));
    if (i != 0) {
        if (bl - i > inl) {
            memcpy(&(ctx->buf[i]), in, inl);
            ctx->buf_len += inl;
            *outl = 0;
            return 1;
        } else {
            j = bl - i;
            memcpy(&(ctx->buf[i]), in, j);
            if (!M_do_cipher(ctx, out, ctx->buf, bl))
                return 0;
            inl -= j;
            in += j;
            out += bl;
            *outl = bl;
        }
    } else
        *outl = 0;
    i = inl & (bl - 1);
    inl -= i;
    if (inl > 0) {
        if (!M_do_cipher(ctx, out, in, inl))
            return 0;
        *outl += inl;
    }

    if (i != 0)
        memcpy(ctx->buf, &(in[inl]), i);
    ctx->buf_len = i;
    return 1;
}

int EVP_EncryptFinal(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl)
{
    int ret;
    ret = EVP_EncryptFinal_ex(ctx, out, outl);
    return ret;
}

int EVP_EncryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl)
{
    int n, ret;
    unsigned int i, b, bl;

    if (ctx->cipher->flags & EVP_CIPH_FLAG_CUSTOM_CIPHER) {
        ret = M_do_cipher(ctx, out, NULL, 0);
        if (ret < 0)
            return 0;
        else
            *outl = ret;
        return 1;
    }

    b = ctx->cipher->block_size;
    OPENSSL_assert(b <= sizeof(ctx->buf));
    if (b == 1) {
        *outl = 0;
        return 1;
    }
    bl = ctx->buf_len;
    if (ctx->flags & EVP_CIPH_NO_PADDING) {
        if (bl) {
            EVPerr(EVP_F_EVP_ENCRYPTFINAL_EX,
                   EVP_R_DATA_NOT_MULTIPLE_OF_BLOCK_LENGTH);
            return 0;
        }
        *outl = 0;
        return 1;
    }

    n = b - bl;
    for (i = bl; i < b; i++)
        ctx->buf[i] = n;
    ret = M_do_cipher(ctx, out, ctx->buf, b);

    if (ret)
        *outl = b;

    return ret;
}

int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
                      const unsigned char *in, int inl)
{
    int fix_len;
    unsigned int b;

    if (ctx->cipher->flags & EVP_CIPH_FLAG_CUSTOM_CIPHER) {
        fix_len = M_do_cipher(ctx, out, in, inl);
        if (fix_len < 0) {
            *outl = 0;
            return 0;
        } else
            *outl = fix_len;
        return 1;
    }

    if (inl <= 0) {
        *outl = 0;
        return inl == 0;
    }

    if (ctx->flags & EVP_CIPH_NO_PADDING)
        return EVP_EncryptUpdate(ctx, out, outl, in, inl);

    b = ctx->cipher->block_size;
    OPENSSL_assert(b <= sizeof(ctx->final));

    if (ctx->final_used) {
        memcpy(out, ctx->final, b);
        out += b;
        fix_len = 1;
    } else
        fix_len = 0;

    if (!EVP_EncryptUpdate(ctx, out, outl, in, inl))
        return 0;

    /*
     * if we have 'decrypted' a multiple of block size, make sure we have a
     * copy of this last block
     */
    if (b > 1 && !ctx->buf_len) {
        *outl -= b;
        ctx->final_used = 1;
        memcpy(ctx->final, &out[*outl], b);
    } else
        ctx->final_used = 0;

    if (fix_len)
        *outl += b;

    return 1;
}

int EVP_DecryptFinal(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl)
{
    int ret;
    ret = EVP_DecryptFinal_ex(ctx, out, outl);
    return ret;
}

int EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl)
{
    int i, n;
    unsigned int b;
    *outl = 0;

    if (ctx->cipher->flags & EVP_CIPH_FLAG_CUSTOM_CIPHER) {
        i = M_do_cipher(ctx, out, NULL, 0);
        if (i < 0)
            return 0;
        else
            *outl = i;
        return 1;
    }

    b = ctx->cipher->block_size;
    if (ctx->flags & EVP_CIPH_NO_PADDING) {
        if (ctx->buf_len) {
            EVPerr(EVP_F_EVP_DECRYPTFINAL_EX,
                   EVP_R_DATA_NOT_MULTIPLE_OF_BLOCK_LENGTH);
            return 0;
        }
        *outl = 0;
        return 1;
    }
    if (b > 1) {
        if (ctx->buf_len || !ctx->final_used) {
            EVPerr(EVP_F_EVP_DECRYPTFINAL_EX, EVP_R_WRONG_FINAL_BLOCK_LENGTH);
            return (0);
        }
        OPENSSL_assert(b <= sizeof(ctx->final));

        /*
         * The following assumes that the ciphertext has been authenticated.
         * Otherwise it provides a padding oracle.
         */
        n = ctx->final[b - 1];
        if (n == 0 || n > (int)b) {
            EVPerr(EVP_F_EVP_DECRYPTFINAL_EX, EVP_R_BAD_DECRYPT);
            return (0);
        }
        for (i = 0; i < n; i++) {
            if (ctx->final[--b] != n) {
                EVPerr(EVP_F_EVP_DECRYPTFINAL_EX, EVP_R_BAD_DECRYPT);
                return (0);
            }
        }
        n = ctx->cipher->block_size - n;
        for (i = 0; i < n; i++)
            out[i] = ctx->final[i];
        *outl = n;
    } else
        *outl = 0;
    return (1);
}

void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *ctx)
{
    if (ctx) {
        EVP_CIPHER_CTX_cleanup(ctx);
        OPENSSL_free(ctx);
    }
}

int EVP_CIPHER_CTX_cleanup(EVP_CIPHER_CTX *c)
{
#ifndef OPENSSL_FIPS
    if (c->cipher != NULL) {
        if (c->cipher->cleanup && !c->cipher->cleanup(c))
            return 0;
        /* Cleanse cipher context data */
        if (c->cipher_data)
            OPENSSL_cleanse(c->cipher_data, c->cipher->ctx_size);
    }
    if (c->cipher_data)
        OPENSSL_free(c->cipher_data);
#endif
#ifndef OPENSSL_NO_ENGINE
    if (c->engine)
        /*
         * The EVP_CIPHER we used belongs to an ENGINE, release the
         * functional reference we held for this reason.
         */
        ENGINE_finish(c->engine);
#endif
#ifdef OPENSSL_FIPS
    FIPS_cipher_ctx_cleanup(c);
#endif
    memset(c, 0, sizeof(EVP_CIPHER_CTX));
    return 1;
}

int EVP_CIPHER_CTX_set_key_length(EVP_CIPHER_CTX *c, int keylen)
{
    if (c->cipher->flags & EVP_CIPH_CUSTOM_KEY_LENGTH)
        return EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_SET_KEY_LENGTH, keylen, NULL);
    if (c->key_len == keylen)
        return 1;
    if ((keylen > 0) && (c->cipher->flags & EVP_CIPH_VARIABLE_LENGTH)) {
        c->key_len = keylen;
        return 1;
    }
    EVPerr(EVP_F_EVP_CIPHER_CTX_SET_KEY_LENGTH, EVP_R_INVALID_KEY_LENGTH);
    return 0;
}

int EVP_CIPHER_CTX_set_padding(EVP_CIPHER_CTX *ctx, int pad)
{
    if (pad)
        ctx->flags &= ~EVP_CIPH_NO_PADDING;
    else
        ctx->flags |= EVP_CIPH_NO_PADDING;
    return 1;
}

int EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr)
{
    int ret;
    if (!ctx->cipher) {
        EVPerr(EVP_F_EVP_CIPHER_CTX_CTRL, EVP_R_NO_CIPHER_SET);
        return 0;
    }

    if (!ctx->cipher->ctrl) {
        EVPerr(EVP_F_EVP_CIPHER_CTX_CTRL, EVP_R_CTRL_NOT_IMPLEMENTED);
        return 0;
    }

    ret = ctx->cipher->ctrl(ctx, type, arg, ptr);
    if (ret == -1) {
        EVPerr(EVP_F_EVP_CIPHER_CTX_CTRL,
               EVP_R_CTRL_OPERATION_NOT_IMPLEMENTED);
        return 0;
    }
    return ret;
}

int EVP_CIPHER_CTX_rand_key(EVP_CIPHER_CTX *ctx, unsigned char *key)
{
    if (ctx->cipher->flags & EVP_CIPH_RAND_KEY)
        return EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_RAND_KEY, 0, key);
    if (RAND_bytes(key, ctx->key_len) <= 0)
        return 0;
    return 1;
}

int EVP_CIPHER_CTX_copy(EVP_CIPHER_CTX *out, const EVP_CIPHER_CTX *in)
{
    if ((in == NULL) || (in->cipher == NULL)) {
        EVPerr(EVP_F_EVP_CIPHER_CTX_COPY, EVP_R_INPUT_NOT_INITIALIZED);
        return 0;
    }
#ifndef OPENSSL_NO_ENGINE
    /* Make sure it's safe to copy a cipher context using an ENGINE */
    if (in->engine && !ENGINE_init(in->engine)) {
        EVPerr(EVP_F_EVP_CIPHER_CTX_COPY, ERR_R_ENGINE_LIB);
        return 0;
    }
#endif

    EVP_CIPHER_CTX_cleanup(out);
    memcpy(out, in, sizeof(*out));

    if (in->cipher_data && in->cipher->ctx_size) {
        out->cipher_data = OPENSSL_malloc(in->cipher->ctx_size);
        if (!out->cipher_data) {
            out->cipher = NULL;
            EVPerr(EVP_F_EVP_CIPHER_CTX_COPY, ERR_R_MALLOC_FAILURE);
            return 0;
        }
        memcpy(out->cipher_data, in->cipher_data, in->cipher->ctx_size);
    }

    if (in->cipher->flags & EVP_CIPH_CUSTOM_COPY)
        if (!in->cipher->ctrl((EVP_CIPHER_CTX *)in, EVP_CTRL_COPY, 0, out)) {
            out->cipher = NULL;
            EVPerr(EVP_F_EVP_CIPHER_CTX_COPY, EVP_R_INITIALIZATION_ERROR);
            return 0;
        }
    return 1;
}
/* crypto/evp/evp_err.c */
/* ====================================================================
 * Copyright (c) 1999-2016 The OpenSSL Project.  All rights reserved.
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
// #include "evp.h"

/* BEGIN ERROR CODES */
#ifndef OPENSSL_NO_ERR

# define ERR_FUNC(func) ERR_PACK(ERR_LIB_EVP,func,0)
# define ERR_REASON(reason) ERR_PACK(ERR_LIB_EVP,0,reason)

static ERR_STRING_DATA EVP_str_functs[] = {
    {ERR_FUNC(EVP_F_AESNI_INIT_KEY), "AESNI_INIT_KEY"},
    {ERR_FUNC(EVP_F_AESNI_XTS_CIPHER), "AESNI_XTS_CIPHER"},
    {ERR_FUNC(EVP_F_AES_INIT_KEY), "AES_INIT_KEY"},
    {ERR_FUNC(EVP_F_AES_T4_INIT_KEY), "AES_T4_INIT_KEY"},
    {ERR_FUNC(EVP_F_AES_XTS), "AES_XTS"},
    {ERR_FUNC(EVP_F_AES_XTS_CIPHER), "AES_XTS_CIPHER"},
    {ERR_FUNC(EVP_F_ALG_MODULE_INIT), "ALG_MODULE_INIT"},
    {ERR_FUNC(EVP_F_CAMELLIA_INIT_KEY), "CAMELLIA_INIT_KEY"},
    {ERR_FUNC(EVP_F_CMAC_INIT), "CMAC_INIT"},
    {ERR_FUNC(EVP_F_CMLL_T4_INIT_KEY), "CMLL_T4_INIT_KEY"},
    {ERR_FUNC(EVP_F_D2I_PKEY), "D2I_PKEY"},
    {ERR_FUNC(EVP_F_DO_SIGVER_INIT), "DO_SIGVER_INIT"},
    {ERR_FUNC(EVP_F_DSAPKEY2PKCS8), "DSAPKEY2PKCS8"},
    {ERR_FUNC(EVP_F_DSA_PKEY2PKCS8), "DSA_PKEY2PKCS8"},
    {ERR_FUNC(EVP_F_ECDSA_PKEY2PKCS8), "ECDSA_PKEY2PKCS8"},
    {ERR_FUNC(EVP_F_ECKEY_PKEY2PKCS8), "ECKEY_PKEY2PKCS8"},
    {ERR_FUNC(EVP_F_EVP_CIPHERINIT_EX), "EVP_CipherInit_ex"},
    {ERR_FUNC(EVP_F_EVP_CIPHER_CTX_COPY), "EVP_CIPHER_CTX_copy"},
    {ERR_FUNC(EVP_F_EVP_CIPHER_CTX_CTRL), "EVP_CIPHER_CTX_ctrl"},
    {ERR_FUNC(EVP_F_EVP_CIPHER_CTX_SET_KEY_LENGTH),
     "EVP_CIPHER_CTX_set_key_length"},
    {ERR_FUNC(EVP_F_EVP_DECRYPTFINAL_EX), "EVP_DecryptFinal_ex"},
    {ERR_FUNC(EVP_F_EVP_DIGESTINIT_EX), "EVP_DigestInit_ex"},
    {ERR_FUNC(EVP_F_EVP_ENCRYPTFINAL_EX), "EVP_EncryptFinal_ex"},
    {ERR_FUNC(EVP_F_EVP_MD_CTX_COPY_EX), "EVP_MD_CTX_copy_ex"},
    {ERR_FUNC(EVP_F_EVP_MD_SIZE), "EVP_MD_size"},
    {ERR_FUNC(EVP_F_EVP_OPENINIT), "EVP_OpenInit"},
    {ERR_FUNC(EVP_F_EVP_PBE_ALG_ADD), "EVP_PBE_alg_add"},
    {ERR_FUNC(EVP_F_EVP_PBE_ALG_ADD_TYPE), "EVP_PBE_alg_add_type"},
    {ERR_FUNC(EVP_F_EVP_PBE_CIPHERINIT), "EVP_PBE_CipherInit"},
    {ERR_FUNC(EVP_F_EVP_PKCS82PKEY), "EVP_PKCS82PKEY"},
    {ERR_FUNC(EVP_F_EVP_PKCS82PKEY_BROKEN), "EVP_PKCS82PKEY_BROKEN"},
    {ERR_FUNC(EVP_F_EVP_PKEY2PKCS8_BROKEN), "EVP_PKEY2PKCS8_broken"},
    {ERR_FUNC(EVP_F_EVP_PKEY_COPY_PARAMETERS), "EVP_PKEY_copy_parameters"},
    {ERR_FUNC(EVP_F_EVP_PKEY_CTX_CTRL), "EVP_PKEY_CTX_ctrl"},
    {ERR_FUNC(EVP_F_EVP_PKEY_CTX_CTRL_STR), "EVP_PKEY_CTX_ctrl_str"},
    {ERR_FUNC(EVP_F_EVP_PKEY_CTX_DUP), "EVP_PKEY_CTX_dup"},
    {ERR_FUNC(EVP_F_EVP_PKEY_DECRYPT), "EVP_PKEY_decrypt"},
    {ERR_FUNC(EVP_F_EVP_PKEY_DECRYPT_INIT), "EVP_PKEY_decrypt_init"},
    {ERR_FUNC(EVP_F_EVP_PKEY_DECRYPT_OLD), "EVP_PKEY_decrypt_old"},
    {ERR_FUNC(EVP_F_EVP_PKEY_DERIVE), "EVP_PKEY_derive"},
    {ERR_FUNC(EVP_F_EVP_PKEY_DERIVE_INIT), "EVP_PKEY_derive_init"},
    {ERR_FUNC(EVP_F_EVP_PKEY_DERIVE_SET_PEER), "EVP_PKEY_derive_set_peer"},
    {ERR_FUNC(EVP_F_EVP_PKEY_ENCRYPT), "EVP_PKEY_encrypt"},
    {ERR_FUNC(EVP_F_EVP_PKEY_ENCRYPT_INIT), "EVP_PKEY_encrypt_init"},
    {ERR_FUNC(EVP_F_EVP_PKEY_ENCRYPT_OLD), "EVP_PKEY_encrypt_old"},
    {ERR_FUNC(EVP_F_EVP_PKEY_GET1_DH), "EVP_PKEY_get1_DH"},
    {ERR_FUNC(EVP_F_EVP_PKEY_GET1_DSA), "EVP_PKEY_get1_DSA"},
    {ERR_FUNC(EVP_F_EVP_PKEY_GET1_ECDSA), "EVP_PKEY_GET1_ECDSA"},
    {ERR_FUNC(EVP_F_EVP_PKEY_GET1_EC_KEY), "EVP_PKEY_get1_EC_KEY"},
    {ERR_FUNC(EVP_F_EVP_PKEY_GET1_RSA), "EVP_PKEY_get1_RSA"},
    {ERR_FUNC(EVP_F_EVP_PKEY_KEYGEN), "EVP_PKEY_keygen"},
    {ERR_FUNC(EVP_F_EVP_PKEY_KEYGEN_INIT), "EVP_PKEY_keygen_init"},
    {ERR_FUNC(EVP_F_EVP_PKEY_NEW), "EVP_PKEY_new"},
    {ERR_FUNC(EVP_F_EVP_PKEY_PARAMGEN), "EVP_PKEY_paramgen"},
    {ERR_FUNC(EVP_F_EVP_PKEY_PARAMGEN_INIT), "EVP_PKEY_paramgen_init"},
    {ERR_FUNC(EVP_F_EVP_PKEY_SIGN), "EVP_PKEY_sign"},
    {ERR_FUNC(EVP_F_EVP_PKEY_SIGN_INIT), "EVP_PKEY_sign_init"},
    {ERR_FUNC(EVP_F_EVP_PKEY_VERIFY), "EVP_PKEY_verify"},
    {ERR_FUNC(EVP_F_EVP_PKEY_VERIFY_INIT), "EVP_PKEY_verify_init"},
    {ERR_FUNC(EVP_F_EVP_PKEY_VERIFY_RECOVER), "EVP_PKEY_verify_recover"},
    {ERR_FUNC(EVP_F_EVP_PKEY_VERIFY_RECOVER_INIT),
     "EVP_PKEY_verify_recover_init"},
    {ERR_FUNC(EVP_F_EVP_RIJNDAEL), "EVP_RIJNDAEL"},
    {ERR_FUNC(EVP_F_EVP_SIGNFINAL), "EVP_SignFinal"},
    {ERR_FUNC(EVP_F_EVP_VERIFYFINAL), "EVP_VerifyFinal"},
    {ERR_FUNC(EVP_F_FIPS_CIPHERINIT), "FIPS_CIPHERINIT"},
    {ERR_FUNC(EVP_F_FIPS_CIPHER_CTX_COPY), "FIPS_CIPHER_CTX_COPY"},
    {ERR_FUNC(EVP_F_FIPS_CIPHER_CTX_CTRL), "FIPS_CIPHER_CTX_CTRL"},
    {ERR_FUNC(EVP_F_FIPS_CIPHER_CTX_SET_KEY_LENGTH),
     "FIPS_CIPHER_CTX_SET_KEY_LENGTH"},
    {ERR_FUNC(EVP_F_FIPS_DIGESTINIT), "FIPS_DIGESTINIT"},
    {ERR_FUNC(EVP_F_FIPS_MD_CTX_COPY), "FIPS_MD_CTX_COPY"},
    {ERR_FUNC(EVP_F_HMAC_INIT_EX), "HMAC_Init_ex"},
    {ERR_FUNC(EVP_F_INT_CTX_NEW), "INT_CTX_NEW"},
    {ERR_FUNC(EVP_F_PKCS5_PBE_KEYIVGEN), "PKCS5_PBE_keyivgen"},
    {ERR_FUNC(EVP_F_PKCS5_V2_PBE_KEYIVGEN), "PKCS5_v2_PBE_keyivgen"},
    {ERR_FUNC(EVP_F_PKCS5_V2_PBKDF2_KEYIVGEN), "PKCS5_V2_PBKDF2_KEYIVGEN"},
    {ERR_FUNC(EVP_F_PKCS8_SET_BROKEN), "PKCS8_set_broken"},
    {ERR_FUNC(EVP_F_PKEY_SET_TYPE), "PKEY_SET_TYPE"},
    {ERR_FUNC(EVP_F_RC2_MAGIC_TO_METH), "RC2_MAGIC_TO_METH"},
    {ERR_FUNC(EVP_F_RC5_CTRL), "RC5_CTRL"},
    {0, NULL}
};

static ERR_STRING_DATA EVP_str_reasons[] = {
    {ERR_REASON(EVP_R_AES_IV_SETUP_FAILED), "aes iv setup failed"},
    {ERR_REASON(EVP_R_AES_KEY_SETUP_FAILED), "aes key setup failed"},
    {ERR_REASON(EVP_R_ASN1_LIB), "asn1 lib"},
    {ERR_REASON(EVP_R_BAD_BLOCK_LENGTH), "bad block length"},
    {ERR_REASON(EVP_R_BAD_DECRYPT), "bad decrypt"},
    {ERR_REASON(EVP_R_BAD_KEY_LENGTH), "bad key length"},
    {ERR_REASON(EVP_R_BN_DECODE_ERROR), "bn decode error"},
    {ERR_REASON(EVP_R_BN_PUBKEY_ERROR), "bn pubkey error"},
    {ERR_REASON(EVP_R_BUFFER_TOO_SMALL), "buffer too small"},
    {ERR_REASON(EVP_R_CAMELLIA_KEY_SETUP_FAILED),
     "camellia key setup failed"},
    {ERR_REASON(EVP_R_CIPHER_PARAMETER_ERROR), "cipher parameter error"},
    {ERR_REASON(EVP_R_COMMAND_NOT_SUPPORTED), "command not supported"},
    {ERR_REASON(EVP_R_CTRL_NOT_IMPLEMENTED), "ctrl not implemented"},
    {ERR_REASON(EVP_R_CTRL_OPERATION_NOT_IMPLEMENTED),
     "ctrl operation not implemented"},
    {ERR_REASON(EVP_R_DATA_NOT_MULTIPLE_OF_BLOCK_LENGTH),
     "data not multiple of block length"},
    {ERR_REASON(EVP_R_DECODE_ERROR), "decode error"},
    {ERR_REASON(EVP_R_DIFFERENT_KEY_TYPES), "different key types"},
    {ERR_REASON(EVP_R_DIFFERENT_PARAMETERS), "different parameters"},
    {ERR_REASON(EVP_R_DISABLED_FOR_FIPS), "disabled for fips"},
    {ERR_REASON(EVP_R_ENCODE_ERROR), "encode error"},
    {ERR_REASON(EVP_R_ERROR_LOADING_SECTION), "error loading section"},
    {ERR_REASON(EVP_R_ERROR_SETTING_FIPS_MODE), "error setting fips mode"},
    {ERR_REASON(EVP_R_EVP_PBE_CIPHERINIT_ERROR), "evp pbe cipherinit error"},
    {ERR_REASON(EVP_R_EXPECTING_AN_RSA_KEY), "expecting an rsa key"},
    {ERR_REASON(EVP_R_EXPECTING_A_DH_KEY), "expecting a dh key"},
    {ERR_REASON(EVP_R_EXPECTING_A_DSA_KEY), "expecting a dsa key"},
    {ERR_REASON(EVP_R_EXPECTING_A_ECDSA_KEY), "expecting a ecdsa key"},
    {ERR_REASON(EVP_R_EXPECTING_A_EC_KEY), "expecting a ec key"},
    {ERR_REASON(EVP_R_FIPS_MODE_NOT_SUPPORTED), "fips mode not supported"},
    {ERR_REASON(EVP_R_INITIALIZATION_ERROR), "initialization error"},
    {ERR_REASON(EVP_R_INPUT_NOT_INITIALIZED), "input not initialized"},
    {ERR_REASON(EVP_R_INVALID_DIGEST), "invalid digest"},
    {ERR_REASON(EVP_R_INVALID_FIPS_MODE), "invalid fips mode"},
    {ERR_REASON(EVP_R_INVALID_KEY), "invalid key"},
    {ERR_REASON(EVP_R_INVALID_KEY_LENGTH), "invalid key length"},
    {ERR_REASON(EVP_R_INVALID_OPERATION), "invalid operation"},
    {ERR_REASON(EVP_R_IV_TOO_LARGE), "iv too large"},
    {ERR_REASON(EVP_R_KEYGEN_FAILURE), "keygen failure"},
    {ERR_REASON(EVP_R_MESSAGE_DIGEST_IS_NULL), "message digest is null"},
    {ERR_REASON(EVP_R_METHOD_NOT_SUPPORTED), "method not supported"},
    {ERR_REASON(EVP_R_MISSING_PARAMETERS), "missing parameters"},
    {ERR_REASON(EVP_R_NO_CIPHER_SET), "no cipher set"},
    {ERR_REASON(EVP_R_NO_DEFAULT_DIGEST), "no default digest"},
    {ERR_REASON(EVP_R_NO_DIGEST_SET), "no digest set"},
    {ERR_REASON(EVP_R_NO_DSA_PARAMETERS), "no dsa parameters"},
    {ERR_REASON(EVP_R_NO_KEY_SET), "no key set"},
    {ERR_REASON(EVP_R_NO_OPERATION_SET), "no operation set"},
    {ERR_REASON(EVP_R_NO_SIGN_FUNCTION_CONFIGURED),
     "no sign function configured"},
    {ERR_REASON(EVP_R_NO_VERIFY_FUNCTION_CONFIGURED),
     "no verify function configured"},
    {ERR_REASON(EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE),
     "operation not supported for this keytype"},
    {ERR_REASON(EVP_R_OPERATON_NOT_INITIALIZED), "operaton not initialized"},
    {ERR_REASON(EVP_R_PKCS8_UNKNOWN_BROKEN_TYPE),
     "pkcs8 unknown broken type"},
    {ERR_REASON(EVP_R_PRIVATE_KEY_DECODE_ERROR), "private key decode error"},
    {ERR_REASON(EVP_R_PRIVATE_KEY_ENCODE_ERROR), "private key encode error"},
    {ERR_REASON(EVP_R_PUBLIC_KEY_NOT_RSA), "public key not rsa"},
    {ERR_REASON(EVP_R_TOO_LARGE), "too large"},
    {ERR_REASON(EVP_R_UNKNOWN_CIPHER), "unknown cipher"},
    {ERR_REASON(EVP_R_UNKNOWN_DIGEST), "unknown digest"},
    {ERR_REASON(EVP_R_UNKNOWN_OPTION), "unknown option"},
    {ERR_REASON(EVP_R_UNKNOWN_PBE_ALGORITHM), "unknown pbe algorithm"},
    {ERR_REASON(EVP_R_UNSUPORTED_NUMBER_OF_ROUNDS),
     "unsuported number of rounds"},
    {ERR_REASON(EVP_R_UNSUPPORTED_ALGORITHM), "unsupported algorithm"},
    {ERR_REASON(EVP_R_UNSUPPORTED_CIPHER), "unsupported cipher"},
    {ERR_REASON(EVP_R_UNSUPPORTED_KEYLENGTH), "unsupported keylength"},
    {ERR_REASON(EVP_R_UNSUPPORTED_KEY_DERIVATION_FUNCTION),
     "unsupported key derivation function"},
    {ERR_REASON(EVP_R_UNSUPPORTED_KEY_SIZE), "unsupported key size"},
    {ERR_REASON(EVP_R_UNSUPPORTED_PRF), "unsupported prf"},
    {ERR_REASON(EVP_R_UNSUPPORTED_PRIVATE_KEY_ALGORITHM),
     "unsupported private key algorithm"},
    {ERR_REASON(EVP_R_UNSUPPORTED_SALT_TYPE), "unsupported salt type"},
    {ERR_REASON(EVP_R_WRAP_MODE_NOT_ALLOWED), "wrap mode not allowed"},
    {ERR_REASON(EVP_R_WRONG_FINAL_BLOCK_LENGTH), "wrong final block length"},
    {ERR_REASON(EVP_R_WRONG_PUBLIC_KEY_TYPE), "wrong public key type"},
    {0, NULL}
};

#endif

void ERR_load_EVP_strings(void)
{
#ifndef OPENSSL_NO_ERR

    if (ERR_func_error_string(EVP_str_functs[0].error) == NULL) {
        ERR_load_strings(0, EVP_str_functs);
        ERR_load_strings(0, EVP_str_reasons);
    }
#endif
}
/* crypto/evp/evp_key.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

#include <stdio.h>
// #include "cryptlib.h"
// #include "x509.h"
#include "objects.h"
// #include "evp.h"
#include "ui.h"

/* should be init to zeros. */
static char prompt_string[80];

void EVP_set_pw_prompt(const char *prompt)
{
    if (prompt == NULL)
        prompt_string[0] = '\0';
    else {
        strncpy(prompt_string, prompt, 79);
        prompt_string[79] = '\0';
    }
}

char *EVP_get_pw_prompt(void)
{
    if (prompt_string[0] == '\0')
        return (NULL);
    else
        return (prompt_string);
}

/*
 * For historical reasons, the standard function for reading passwords is in
 * the DES library -- if someone ever wants to disable DES, this function
 * will fail
 */
int EVP_read_pw_string(char *buf, int len, const char *prompt, int verify)
{
    return EVP_read_pw_string_min(buf, 0, len, prompt, verify);
}

int EVP_read_pw_string_min(char *buf, int min, int len, const char *prompt,
                           int verify)
{
    int ret = -1;
    char buff[BUFSIZ];
    UI *ui;

    if ((prompt == NULL) && (prompt_string[0] != '\0'))
        prompt = prompt_string;
    ui = UI_new();
    if (ui == NULL)
        return ret;
    if (UI_add_input_string(ui, prompt, 0, buf, min,
                            (len >= BUFSIZ) ? BUFSIZ - 1 : len) < 0
        || (verify
            && UI_add_verify_string(ui, prompt, 0, buff, min,
                                    (len >= BUFSIZ) ? BUFSIZ - 1 : len,
                                    buf) < 0))
        goto end;
    ret = UI_process(ui);
    OPENSSL_cleanse(buff, BUFSIZ);
 end:
    UI_free(ui);
    return ret;
}

int EVP_BytesToKey(const EVP_CIPHER *type, const EVP_MD *md,
                   const unsigned char *salt, const unsigned char *data,
                   int datal, int count, unsigned char *key,
                   unsigned char *iv)
{
    EVP_MD_CTX c;
    unsigned char md_buf[EVP_MAX_MD_SIZE];
    int niv, nkey, addmd = 0;
    unsigned int mds = 0, i;
    int rv = 0;
    nkey = type->key_len;
    niv = type->iv_len;
    OPENSSL_assert(nkey <= EVP_MAX_KEY_LENGTH);
    OPENSSL_assert(niv <= EVP_MAX_IV_LENGTH);

    if (data == NULL)
        return (nkey);

    EVP_MD_CTX_init(&c);
    for (;;) {
        if (!EVP_DigestInit_ex(&c, md, NULL))
            goto err;
        if (addmd++)
            if (!EVP_DigestUpdate(&c, &(md_buf[0]), mds))
                goto err;
        if (!EVP_DigestUpdate(&c, data, datal))
            goto err;
        if (salt != NULL)
            if (!EVP_DigestUpdate(&c, salt, PKCS5_SALT_LEN))
                goto err;
        if (!EVP_DigestFinal_ex(&c, &(md_buf[0]), &mds))
            goto err;

        for (i = 1; i < (unsigned int)count; i++) {
            if (!EVP_DigestInit_ex(&c, md, NULL))
                goto err;
            if (!EVP_DigestUpdate(&c, &(md_buf[0]), mds))
                goto err;
            if (!EVP_DigestFinal_ex(&c, &(md_buf[0]), &mds))
                goto err;
        }
        i = 0;
        if (nkey) {
            for (;;) {
                if (nkey == 0)
                    break;
                if (i == mds)
                    break;
                if (key != NULL)
                    *(key++) = md_buf[i];
                nkey--;
                i++;
            }
        }
        if (niv && (i != mds)) {
            for (;;) {
                if (niv == 0)
                    break;
                if (i == mds)
                    break;
                if (iv != NULL)
                    *(iv++) = md_buf[i];
                niv--;
                i++;
            }
        }
        if ((nkey == 0) && (niv == 0))
            break;
    }
    rv = type->key_len;
 err:
    EVP_MD_CTX_cleanup(&c);
    OPENSSL_cleanse(md_buf, sizeof(md_buf));
    return rv;
}
/* crypto/evp/evp_lib.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

#include <stdio.h>
// #include "cryptlib.h"
// #include "evp.h"
// #include "objects.h"
#ifdef OPENSSL_FIPS
# include <fips.h>
# include "evp_locl.h"
#endif

int EVP_CIPHER_param_to_asn1(EVP_CIPHER_CTX *c, ASN1_TYPE *type)
{
    int ret;

    if (c->cipher->set_asn1_parameters != NULL)
        ret = c->cipher->set_asn1_parameters(c, type);
    else if (c->cipher->flags & EVP_CIPH_FLAG_DEFAULT_ASN1) {
        switch (EVP_CIPHER_CTX_mode(c)) {
        case EVP_CIPH_WRAP_MODE:
            if (EVP_CIPHER_CTX_nid(c) == NID_id_smime_alg_CMS3DESwrap)
                ASN1_TYPE_set(type, V_ASN1_NULL, NULL);
            ret = 1;
            break;

        case EVP_CIPH_GCM_MODE:
        case EVP_CIPH_CCM_MODE:
        case EVP_CIPH_XTS_MODE:
            ret = -1;
            break;

        default:
            ret = EVP_CIPHER_set_asn1_iv(c, type);
        }
    } else
        ret = -1;
    return (ret);
}

int EVP_CIPHER_asn1_to_param(EVP_CIPHER_CTX *c, ASN1_TYPE *type)
{
    int ret;

    if (c->cipher->get_asn1_parameters != NULL)
        ret = c->cipher->get_asn1_parameters(c, type);
    else if (c->cipher->flags & EVP_CIPH_FLAG_DEFAULT_ASN1) {
        switch (EVP_CIPHER_CTX_mode(c)) {

        case EVP_CIPH_WRAP_MODE:
            ret = 1;
            break;

        case EVP_CIPH_GCM_MODE:
        case EVP_CIPH_CCM_MODE:
        case EVP_CIPH_XTS_MODE:
            ret = -1;
            break;

        default:
            ret = EVP_CIPHER_get_asn1_iv(c, type);
            break;
        }
    } else
        ret = -1;
    return (ret);
}

int EVP_CIPHER_get_asn1_iv(EVP_CIPHER_CTX *c, ASN1_TYPE *type)
{
    int i = 0;
    unsigned int l;

    if (type != NULL) {
        l = EVP_CIPHER_CTX_iv_length(c);
        OPENSSL_assert(l <= sizeof(c->iv));
        i = ASN1_TYPE_get_octetstring(type, c->oiv, l);
        if (i != (int)l)
            return (-1);
        else if (i > 0)
            memcpy(c->iv, c->oiv, l);
    }
    return (i);
}

int EVP_CIPHER_set_asn1_iv(EVP_CIPHER_CTX *c, ASN1_TYPE *type)
{
    int i = 0;
    unsigned int j;

    if (type != NULL) {
        j = EVP_CIPHER_CTX_iv_length(c);
        OPENSSL_assert(j <= sizeof(c->iv));
        i = ASN1_TYPE_set_octetstring(type, c->oiv, j);
    }
    return (i);
}

/* Convert the various cipher NIDs and dummies to a proper OID NID */
int EVP_CIPHER_type(const EVP_CIPHER *ctx)
{
    int nid;
    ASN1_OBJECT *otmp;
    nid = EVP_CIPHER_nid(ctx);

    switch (nid) {

    case NID_rc2_cbc:
    case NID_rc2_64_cbc:
    case NID_rc2_40_cbc:

        return NID_rc2_cbc;

    case NID_rc4:
    case NID_rc4_40:

        return NID_rc4;

    case NID_aes_128_cfb128:
    case NID_aes_128_cfb8:
    case NID_aes_128_cfb1:

        return NID_aes_128_cfb128;

    case NID_aes_192_cfb128:
    case NID_aes_192_cfb8:
    case NID_aes_192_cfb1:

        return NID_aes_192_cfb128;

    case NID_aes_256_cfb128:
    case NID_aes_256_cfb8:
    case NID_aes_256_cfb1:

        return NID_aes_256_cfb128;

    case NID_des_cfb64:
    case NID_des_cfb8:
    case NID_des_cfb1:

        return NID_des_cfb64;

    case NID_des_ede3_cfb64:
    case NID_des_ede3_cfb8:
    case NID_des_ede3_cfb1:

        return NID_des_cfb64;

    default:
        /* Check it has an OID and it is valid */
        otmp = OBJ_nid2obj(nid);
        if (!otmp || !otmp->data)
            nid = NID_undef;
        ASN1_OBJECT_free(otmp);
        return nid;
    }
}

int EVP_CIPHER_block_size(const EVP_CIPHER *e)
{
    return e->block_size;
}

int EVP_CIPHER_CTX_block_size(const EVP_CIPHER_CTX *ctx)
{
    return ctx->cipher->block_size;
}

int EVP_Cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
               const unsigned char *in, unsigned int inl)
{
    return ctx->cipher->do_cipher(ctx, out, in, inl);
}

const EVP_CIPHER *EVP_CIPHER_CTX_cipher(const EVP_CIPHER_CTX *ctx)
{
    return ctx->cipher;
}

unsigned long EVP_CIPHER_flags(const EVP_CIPHER *cipher)
{
#ifdef OPENSSL_FIPS
    const EVP_CIPHER *fcipher;
    fcipher = evp_get_fips_cipher(cipher);
    if (fcipher && fcipher->flags & EVP_CIPH_FLAG_FIPS)
        return cipher->flags | EVP_CIPH_FLAG_FIPS;
#endif
    return cipher->flags;
}

unsigned long EVP_CIPHER_CTX_flags(const EVP_CIPHER_CTX *ctx)
{
#ifdef OPENSSL_FIPS
    return EVP_CIPHER_flags(ctx->cipher);
#else
    return ctx->cipher->flags;
#endif
}

void *EVP_CIPHER_CTX_get_app_data(const EVP_CIPHER_CTX *ctx)
{
    return ctx->app_data;
}

void EVP_CIPHER_CTX_set_app_data(EVP_CIPHER_CTX *ctx, void *data)
{
    ctx->app_data = data;
}

int EVP_CIPHER_iv_length(const EVP_CIPHER *cipher)
{
    return cipher->iv_len;
}

int EVP_CIPHER_CTX_iv_length(const EVP_CIPHER_CTX *ctx)
{
    return ctx->cipher->iv_len;
}

int EVP_CIPHER_key_length(const EVP_CIPHER *cipher)
{
    return cipher->key_len;
}

int EVP_CIPHER_CTX_key_length(const EVP_CIPHER_CTX *ctx)
{
    return ctx->key_len;
}

int EVP_CIPHER_nid(const EVP_CIPHER *cipher)
{
    return cipher->nid;
}

int EVP_CIPHER_CTX_nid(const EVP_CIPHER_CTX *ctx)
{
    return ctx->cipher->nid;
}

int EVP_MD_block_size(const EVP_MD *md)
{
    return md->block_size;
}

int EVP_MD_type(const EVP_MD *md)
{
    return md->type;
}

int EVP_MD_pkey_type(const EVP_MD *md)
{
    return md->pkey_type;
}

int EVP_MD_size(const EVP_MD *md)
{
    if (!md) {
        EVPerr(EVP_F_EVP_MD_SIZE, EVP_R_MESSAGE_DIGEST_IS_NULL);
        return -1;
    }
    return md->md_size;
}

#ifdef OPENSSL_FIPS

const EVP_MD *evp_get_fips_md(const EVP_MD *md)
{
    int nid = EVP_MD_type(md);
    if (nid == NID_dsa)
        return FIPS_evp_dss1();
    else if (nid == NID_dsaWithSHA)
        return FIPS_evp_dss();
    else if (nid == NID_ecdsa_with_SHA1)
        return FIPS_evp_ecdsa();
    else
        return FIPS_get_digestbynid(nid);
}

const EVP_CIPHER *evp_get_fips_cipher(const EVP_CIPHER *cipher)
{
    int nid = cipher->nid;
    if (nid == NID_undef)
        return FIPS_evp_enc_null();
    else
        return FIPS_get_cipherbynid(nid);
}

#endif

unsigned long EVP_MD_flags(const EVP_MD *md)
{
#ifdef OPENSSL_FIPS
    const EVP_MD *fmd;
    fmd = evp_get_fips_md(md);
    if (fmd && fmd->flags & EVP_MD_FLAG_FIPS)
        return md->flags | EVP_MD_FLAG_FIPS;
#endif
    return md->flags;
}

const EVP_MD *EVP_MD_CTX_md(const EVP_MD_CTX *ctx)
{
    if (!ctx)
        return NULL;
    return ctx->digest;
}

void EVP_MD_CTX_set_flags(EVP_MD_CTX *ctx, int flags)
{
    ctx->flags |= flags;
}

void EVP_MD_CTX_clear_flags(EVP_MD_CTX *ctx, int flags)
{
    ctx->flags &= ~flags;
}

int EVP_MD_CTX_test_flags(const EVP_MD_CTX *ctx, int flags)
{
    return (ctx->flags & flags);
}

void EVP_CIPHER_CTX_set_flags(EVP_CIPHER_CTX *ctx, int flags)
{
    ctx->flags |= flags;
}

void EVP_CIPHER_CTX_clear_flags(EVP_CIPHER_CTX *ctx, int flags)
{
    ctx->flags &= ~flags;
}

int EVP_CIPHER_CTX_test_flags(const EVP_CIPHER_CTX *ctx, int flags)
{
    return (ctx->flags & flags);
}
/* evp_pbe.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 1999.
 */
/* ====================================================================
 * Copyright (c) 1999-2006 The OpenSSL Project.  All rights reserved.
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
// #include "evp.h"
#include "pkcs12.h"
// #include "x509.h"
// #include "evp_locl.h"

/* Password based encryption (PBE) functions */

DECLARE_STACK_OF(EVP_PBE_CTL)
static STACK_OF(EVP_PBE_CTL) *pbe_algs;

/* Setup a cipher context from a PBE algorithm */

typedef struct {
    int pbe_type;
    int pbe_nid;
    int cipher_nid;
    int md_nid;
    EVP_PBE_KEYGEN *keygen;
} EVP_PBE_CTL;

static const EVP_PBE_CTL builtin_pbe[] = {
    {EVP_PBE_TYPE_OUTER, NID_pbeWithMD2AndDES_CBC,
     NID_des_cbc, NID_md2, PKCS5_PBE_keyivgen},
    {EVP_PBE_TYPE_OUTER, NID_pbeWithMD5AndDES_CBC,
     NID_des_cbc, NID_md5, PKCS5_PBE_keyivgen},
    {EVP_PBE_TYPE_OUTER, NID_pbeWithSHA1AndRC2_CBC,
     NID_rc2_64_cbc, NID_sha1, PKCS5_PBE_keyivgen},

#ifndef OPENSSL_NO_HMAC
    {EVP_PBE_TYPE_OUTER, NID_id_pbkdf2, -1, -1, PKCS5_v2_PBKDF2_keyivgen},
#endif

    {EVP_PBE_TYPE_OUTER, NID_pbe_WithSHA1And128BitRC4,
     NID_rc4, NID_sha1, PKCS12_PBE_keyivgen},
    {EVP_PBE_TYPE_OUTER, NID_pbe_WithSHA1And40BitRC4,
     NID_rc4_40, NID_sha1, PKCS12_PBE_keyivgen},
    {EVP_PBE_TYPE_OUTER, NID_pbe_WithSHA1And3_Key_TripleDES_CBC,
     NID_des_ede3_cbc, NID_sha1, PKCS12_PBE_keyivgen},
    {EVP_PBE_TYPE_OUTER, NID_pbe_WithSHA1And2_Key_TripleDES_CBC,
     NID_des_ede_cbc, NID_sha1, PKCS12_PBE_keyivgen},
    {EVP_PBE_TYPE_OUTER, NID_pbe_WithSHA1And128BitRC2_CBC,
     NID_rc2_cbc, NID_sha1, PKCS12_PBE_keyivgen},
    {EVP_PBE_TYPE_OUTER, NID_pbe_WithSHA1And40BitRC2_CBC,
     NID_rc2_40_cbc, NID_sha1, PKCS12_PBE_keyivgen},

#ifndef OPENSSL_NO_HMAC
    {EVP_PBE_TYPE_OUTER, NID_pbes2, -1, -1, PKCS5_v2_PBE_keyivgen},
#endif
    {EVP_PBE_TYPE_OUTER, NID_pbeWithMD2AndRC2_CBC,
     NID_rc2_64_cbc, NID_md2, PKCS5_PBE_keyivgen},
    {EVP_PBE_TYPE_OUTER, NID_pbeWithMD5AndRC2_CBC,
     NID_rc2_64_cbc, NID_md5, PKCS5_PBE_keyivgen},
    {EVP_PBE_TYPE_OUTER, NID_pbeWithSHA1AndDES_CBC,
     NID_des_cbc, NID_sha1, PKCS5_PBE_keyivgen},

    {EVP_PBE_TYPE_PRF, NID_hmacWithSHA1, -1, NID_sha1, 0},
    {EVP_PBE_TYPE_PRF, NID_hmacWithMD5, -1, NID_md5, 0},
    {EVP_PBE_TYPE_PRF, NID_hmacWithSHA224, -1, NID_sha224, 0},
    {EVP_PBE_TYPE_PRF, NID_hmacWithSHA256, -1, NID_sha256, 0},
    {EVP_PBE_TYPE_PRF, NID_hmacWithSHA384, -1, NID_sha384, 0},
    {EVP_PBE_TYPE_PRF, NID_hmacWithSHA512, -1, NID_sha512, 0},
    {EVP_PBE_TYPE_PRF, NID_id_HMACGostR3411_94, -1, NID_id_GostR3411_94, 0},
};

#ifdef TEST
int main(int argc, char **argv)
{
    int i, nid_md, nid_cipher;
    EVP_PBE_CTL *tpbe, *tpbe2;
    /*
     * OpenSSL_add_all_algorithms();
     */

    for (i = 0; i < sizeof(builtin_pbe) / sizeof(EVP_PBE_CTL); i++) {
        tpbe = builtin_pbe + i;
        fprintf(stderr, "%d %d %s ", tpbe->pbe_type, tpbe->pbe_nid,
                OBJ_nid2sn(tpbe->pbe_nid));
        if (EVP_PBE_find(tpbe->pbe_type, tpbe->pbe_nid,
                         &nid_cipher, &nid_md, 0))
            fprintf(stderr, "Found %s %s\n",
                    OBJ_nid2sn(nid_cipher), OBJ_nid2sn(nid_md));
        else
            fprintf(stderr, "Find ERROR!!\n");
    }

    return 0;
}
#endif

int EVP_PBE_CipherInit(ASN1_OBJECT *pbe_obj, const char *pass, int passlen,
                       ASN1_TYPE *param, EVP_CIPHER_CTX *ctx, int en_de)
{
    const EVP_CIPHER *cipher;
    const EVP_MD *md;
    int cipher_nid, md_nid;
    EVP_PBE_KEYGEN *keygen;

    if (!EVP_PBE_find(EVP_PBE_TYPE_OUTER, OBJ_obj2nid(pbe_obj),
                      &cipher_nid, &md_nid, &keygen)) {
        char obj_tmp[80];
        EVPerr(EVP_F_EVP_PBE_CIPHERINIT, EVP_R_UNKNOWN_PBE_ALGORITHM);
        if (!pbe_obj)
            BUF_strlcpy(obj_tmp, "NULL", sizeof(obj_tmp));
        else
            i2t_ASN1_OBJECT(obj_tmp, sizeof(obj_tmp), pbe_obj);
        ERR_add_error_data(2, "TYPE=", obj_tmp);
        return 0;
    }

    if (!pass)
        passlen = 0;
    else if (passlen == -1)
        passlen = strlen(pass);

    if (cipher_nid == -1)
        cipher = NULL;
    else {
        cipher = EVP_get_cipherbynid(cipher_nid);
        if (!cipher) {
            EVPerr(EVP_F_EVP_PBE_CIPHERINIT, EVP_R_UNKNOWN_CIPHER);
            return 0;
        }
    }

    if (md_nid == -1)
        md = NULL;
    else {
        md = EVP_get_digestbynid(md_nid);
        if (!md) {
            EVPerr(EVP_F_EVP_PBE_CIPHERINIT, EVP_R_UNKNOWN_DIGEST);
            return 0;
        }
    }

    if (!keygen(ctx, pass, passlen, param, cipher, md, en_de)) {
        EVPerr(EVP_F_EVP_PBE_CIPHERINIT, EVP_R_KEYGEN_FAILURE);
        return 0;
    }
    return 1;
}

DECLARE_OBJ_BSEARCH_CMP_FN(EVP_PBE_CTL, EVP_PBE_CTL, pbe2);

static int pbe2_cmp(const EVP_PBE_CTL *pbe1, const EVP_PBE_CTL *pbe2)
{
    int ret = pbe1->pbe_type - pbe2->pbe_type;
    if (ret)
        return ret;
    else
        return pbe1->pbe_nid - pbe2->pbe_nid;
}

IMPLEMENT_OBJ_BSEARCH_CMP_FN(EVP_PBE_CTL, EVP_PBE_CTL, pbe2);

static int pbe_cmp(const EVP_PBE_CTL *const *a, const EVP_PBE_CTL *const *b)
{
    int ret = (*a)->pbe_type - (*b)->pbe_type;
    if (ret)
        return ret;
    else
        return (*a)->pbe_nid - (*b)->pbe_nid;
}

/* Add a PBE algorithm */

int EVP_PBE_alg_add_type(int pbe_type, int pbe_nid, int cipher_nid,
                         int md_nid, EVP_PBE_KEYGEN *keygen)
{
    EVP_PBE_CTL *pbe_tmp;

    if (pbe_algs == NULL) {
        pbe_algs = sk_EVP_PBE_CTL_new(pbe_cmp);
        if (pbe_algs == NULL)
            goto err;
    }

    if ((pbe_tmp = OPENSSL_malloc(sizeof(*pbe_tmp))) == NULL)
        goto err;

    pbe_tmp->pbe_type = pbe_type;
    pbe_tmp->pbe_nid = pbe_nid;
    pbe_tmp->cipher_nid = cipher_nid;
    pbe_tmp->md_nid = md_nid;
    pbe_tmp->keygen = keygen;

    sk_EVP_PBE_CTL_push(pbe_algs, pbe_tmp);
    return 1;

 err:
    EVPerr(EVP_F_EVP_PBE_ALG_ADD_TYPE, ERR_R_MALLOC_FAILURE);
    return 0;
}

int EVP_PBE_alg_add(int nid, const EVP_CIPHER *cipher, const EVP_MD *md,
                    EVP_PBE_KEYGEN *keygen)
{
    int cipher_nid, md_nid;
    if (cipher)
        cipher_nid = EVP_CIPHER_nid(cipher);
    else
        cipher_nid = -1;
    if (md)
        md_nid = EVP_MD_type(md);
    else
        md_nid = -1;

    return EVP_PBE_alg_add_type(EVP_PBE_TYPE_OUTER, nid,
                                cipher_nid, md_nid, keygen);
}

int EVP_PBE_find(int type, int pbe_nid,
                 int *pcnid, int *pmnid, EVP_PBE_KEYGEN **pkeygen)
{
    EVP_PBE_CTL *pbetmp = NULL, pbelu;
    int i;
    if (pbe_nid == NID_undef)
        return 0;

    pbelu.pbe_type = type;
    pbelu.pbe_nid = pbe_nid;

    if (pbe_algs) {
        i = sk_EVP_PBE_CTL_find(pbe_algs, &pbelu);
        if (i != -1)
            pbetmp = sk_EVP_PBE_CTL_value(pbe_algs, i);
    }
    if (pbetmp == NULL) {
        pbetmp = OBJ_bsearch_pbe2(&pbelu, builtin_pbe,
                                  sizeof(builtin_pbe) / sizeof(EVP_PBE_CTL));
    }
    if (pbetmp == NULL)
        return 0;
    if (pcnid)
        *pcnid = pbetmp->cipher_nid;
    if (pmnid)
        *pmnid = pbetmp->md_nid;
    if (pkeygen)
        *pkeygen = pbetmp->keygen;
    return 1;
}

static void free_evp_pbe_ctl(EVP_PBE_CTL *pbe)
{
    OPENSSL_freeFunc(pbe);
}

void EVP_PBE_cleanup(void)
{
    sk_EVP_PBE_CTL_pop_free(pbe_algs, free_evp_pbe_ctl);
    pbe_algs = NULL;
}
/* evp_pkey.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 1999.
 */
/* ====================================================================
 * Copyright (c) 1999-2005 The OpenSSL Project.  All rights reserved.
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
// #include "x509.h"
// #include "rand.h"
#include "asn1_locl.h"

/* Extract a private key from a PKCS8 structure */

EVP_PKEY *EVP_PKCS82PKEY(PKCS8_PRIV_KEY_INFO *p8)
{
    EVP_PKEY *pkey = NULL;
    ASN1_OBJECT *algoid;
    char obj_tmp[80];

    if (!PKCS8_pkey_get0(&algoid, NULL, NULL, NULL, p8))
        return NULL;

    if (!(pkey = EVP_PKEY_new())) {
        EVPerr(EVP_F_EVP_PKCS82PKEY, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    if (!EVP_PKEY_set_type(pkey, OBJ_obj2nid(algoid))) {
        EVPerr(EVP_F_EVP_PKCS82PKEY, EVP_R_UNSUPPORTED_PRIVATE_KEY_ALGORITHM);
        i2t_ASN1_OBJECT(obj_tmp, 80, algoid);
        ERR_add_error_data(2, "TYPE=", obj_tmp);
        goto error;
    }

    if (pkey->ameth->priv_decode) {
        if (!pkey->ameth->priv_decode(pkey, p8)) {
            EVPerr(EVP_F_EVP_PKCS82PKEY, EVP_R_PRIVATE_KEY_DECODE_ERROR);
            goto error;
        }
    } else {
        EVPerr(EVP_F_EVP_PKCS82PKEY, EVP_R_METHOD_NOT_SUPPORTED);
        goto error;
    }

    return pkey;

 error:
    EVP_PKEY_free(pkey);
    return NULL;
}

PKCS8_PRIV_KEY_INFO *EVP_PKEY2PKCS8(EVP_PKEY *pkey)
{
    return EVP_PKEY2PKCS8_broken(pkey, PKCS8_OK);
}

/* Turn a private key into a PKCS8 structure */

PKCS8_PRIV_KEY_INFO *EVP_PKEY2PKCS8_broken(EVP_PKEY *pkey, int broken)
{
    PKCS8_PRIV_KEY_INFO *p8;

    if (!(p8 = PKCS8_PRIV_KEY_INFO_new())) {
        EVPerr(EVP_F_EVP_PKEY2PKCS8_BROKEN, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    p8->broken = broken;

    if (pkey->ameth) {
        if (pkey->ameth->priv_encode) {
            if (!pkey->ameth->priv_encode(p8, pkey)) {
                EVPerr(EVP_F_EVP_PKEY2PKCS8_BROKEN,
                       EVP_R_PRIVATE_KEY_ENCODE_ERROR);
                goto error;
            }
        } else {
            EVPerr(EVP_F_EVP_PKEY2PKCS8_BROKEN, EVP_R_METHOD_NOT_SUPPORTED);
            goto error;
        }
    } else {
        EVPerr(EVP_F_EVP_PKEY2PKCS8_BROKEN,
               EVP_R_UNSUPPORTED_PRIVATE_KEY_ALGORITHM);
        goto error;
    }
    RAND_add(p8->pkey->value.octet_string->data,
             p8->pkey->value.octet_string->length, 0.0);
    return p8;
 error:
    PKCS8_PRIV_KEY_INFO_free(p8);
    return NULL;
}

PKCS8_PRIV_KEY_INFO *PKCS8_set_broken(PKCS8_PRIV_KEY_INFO *p8, int broken)
{
    switch (broken) {

    case PKCS8_OK:
        p8->broken = PKCS8_OK;
        return p8;
        break;

    case PKCS8_NO_OCTET:
        p8->broken = PKCS8_NO_OCTET;
        p8->pkey->type = V_ASN1_SEQUENCE;
        return p8;
        break;

    default:
        EVPerr(EVP_F_PKCS8_SET_BROKEN, EVP_R_PKCS8_UNKNOWN_BROKEN_TYPE);
        return NULL;
    }
}

/* EVP_PKEY attribute functions */

int EVP_PKEY_get_attr_count(const EVP_PKEY *key)
{
    return X509at_get_attr_count(key->attributes);
}

int EVP_PKEY_get_attr_by_NID(const EVP_PKEY *key, int nid, int lastpos)
{
    return X509at_get_attr_by_NID(key->attributes, nid, lastpos);
}

int EVP_PKEY_get_attr_by_OBJ(const EVP_PKEY *key, ASN1_OBJECT *obj,
                             int lastpos)
{
    return X509at_get_attr_by_OBJ(key->attributes, obj, lastpos);
}

X509_ATTRIBUTE *EVP_PKEY_get_attr(const EVP_PKEY *key, int loc)
{
    return X509at_get_attr(key->attributes, loc);
}

X509_ATTRIBUTE *EVP_PKEY_delete_attr(EVP_PKEY *key, int loc)
{
    return X509at_delete_attr(key->attributes, loc);
}

int EVP_PKEY_add1_attr(EVP_PKEY *key, X509_ATTRIBUTE *attr)
{
    if (X509at_add1_attr(&key->attributes, attr))
        return 1;
    return 0;
}

int EVP_PKEY_add1_attr_by_OBJ(EVP_PKEY *key,
                              const ASN1_OBJECT *obj, int type,
                              const unsigned char *bytes, int len)
{
    if (X509at_add1_attr_by_OBJ(&key->attributes, obj, type, bytes, len))
        return 1;
    return 0;
}

int EVP_PKEY_add1_attr_by_NID(EVP_PKEY *key,
                              int nid, int type,
                              const unsigned char *bytes, int len)
{
    if (X509at_add1_attr_by_NID(&key->attributes, nid, type, bytes, len))
        return 1;
    return 0;
}

int EVP_PKEY_add1_attr_by_txt(EVP_PKEY *key,
                              const char *attrname, int type,
                              const unsigned char *bytes, int len)
{
    if (X509at_add1_attr_by_txt(&key->attributes, attrname, type, bytes, len))
        return 1;
    return 0;
}
