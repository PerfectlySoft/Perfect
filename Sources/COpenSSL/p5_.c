/* p5_crpt.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 1999.
 */
/* ====================================================================
 * Copyright (c) 1999 The OpenSSL Project.  All rights reserved.
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
#include "x509.h"
#include "evp.h"

/*
 * Doesn't do anything now: Builtin PBE algorithms in static table.
 */

void PKCS5_PBE_add(void)
{
}

int PKCS5_PBE_keyivgen(EVP_CIPHER_CTX *cctx, const char *pass, int passlen,
                       ASN1_TYPE *param, const EVP_CIPHER *cipher,
                       const EVP_MD *md, int en_de)
{
    EVP_MD_CTX ctx;
    unsigned char md_tmp[EVP_MAX_MD_SIZE];
    unsigned char key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];
    int i;
    PBEPARAM *pbe;
    int saltlen, iter;
    unsigned char *salt;
    const unsigned char *pbuf;
    int mdsize;
    int rv = 0;
    EVP_MD_CTX_init(&ctx);

    /* Extract useful info from parameter */
    if (param == NULL || param->type != V_ASN1_SEQUENCE ||
        param->value.sequence == NULL) {
        EVPerr(EVP_F_PKCS5_PBE_KEYIVGEN, EVP_R_DECODE_ERROR);
        return 0;
    }

    pbuf = param->value.sequence->data;
    if (!(pbe = d2i_PBEPARAM(NULL, &pbuf, param->value.sequence->length))) {
        EVPerr(EVP_F_PKCS5_PBE_KEYIVGEN, EVP_R_DECODE_ERROR);
        return 0;
    }

    if (!pbe->iter)
        iter = 1;
    else
        iter = ASN1_INTEGER_get(pbe->iter);
    salt = pbe->salt->data;
    saltlen = pbe->salt->length;

    if (!pass)
        passlen = 0;
    else if (passlen == -1)
        passlen = strlen(pass);

    if (!EVP_DigestInit_ex(&ctx, md, NULL))
        goto err;
    if (!EVP_DigestUpdate(&ctx, pass, passlen))
        goto err;
    if (!EVP_DigestUpdate(&ctx, salt, saltlen))
        goto err;
    PBEPARAM_free(pbe);
    if (!EVP_DigestFinal_ex(&ctx, md_tmp, NULL))
        goto err;
    mdsize = EVP_MD_size(md);
    if (mdsize < 0)
        return 0;
    for (i = 1; i < iter; i++) {
        if (!EVP_DigestInit_ex(&ctx, md, NULL))
            goto err;
        if (!EVP_DigestUpdate(&ctx, md_tmp, mdsize))
            goto err;
        if (!EVP_DigestFinal_ex(&ctx, md_tmp, NULL))
            goto err;
    }
    OPENSSL_assert(EVP_CIPHER_key_length(cipher) <= (int)sizeof(md_tmp));
    memcpy(key, md_tmp, EVP_CIPHER_key_length(cipher));
    OPENSSL_assert(EVP_CIPHER_iv_length(cipher) <= 16);
    memcpy(iv, md_tmp + (16 - EVP_CIPHER_iv_length(cipher)),
           EVP_CIPHER_iv_length(cipher));
    if (!EVP_CipherInit_ex(cctx, cipher, NULL, key, iv, en_de))
        goto err;
    OPENSSL_cleanse(md_tmp, EVP_MAX_MD_SIZE);
    OPENSSL_cleanse(key, EVP_MAX_KEY_LENGTH);
    OPENSSL_cleanse(iv, EVP_MAX_IV_LENGTH);
    rv = 1;
 err:
    EVP_MD_CTX_cleanup(&ctx);
    return rv;
}
/* p5_crpt2.c */
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
#include <stdlib.h>
// #include "cryptlib.h"
#if !defined(OPENSSL_NO_HMAC) && !defined(OPENSSL_NO_SHA)
# include "x509.h"
# include "evp.h"
# include "hmac.h"
# include "evp_locl.h"

/* set this to print out info about the keygen algorithm */
/* #define DEBUG_PKCS5V2 */

# ifdef DEBUG_PKCS5V2
static void h__dump(const unsigned char *p, int len);
# endif

/*
 * This is an implementation of PKCS#5 v2.0 password based encryption key
 * derivation function PBKDF2. SHA1 version verified against test vectors
 * posted by Peter Gutmann <pgut001@cs.auckland.ac.nz> to the PKCS-TNG
 * <pkcs-tng@rsa.com> mailing list.
 */

int PKCS5_PBKDF2_HMAC(const char *pass, int passlen,
                      const unsigned char *salt, int saltlen, int iter,
                      const EVP_MD *digest, int keylen, unsigned char *out)
{
    unsigned char digtmp[EVP_MAX_MD_SIZE], *p, itmp[4];
    int cplen, j, k, tkeylen, mdlen;
    unsigned long i = 1;
    HMAC_CTX hctx_tpl, hctx;

    mdlen = EVP_MD_size(digest);
    if (mdlen < 0)
        return 0;

    HMAC_CTX_init(&hctx_tpl);
    p = out;
    tkeylen = keylen;
    if (!pass)
        passlen = 0;
    else if (passlen == -1)
        passlen = strlen(pass);
    if (!HMAC_Init_ex(&hctx_tpl, pass, passlen, digest, NULL)) {
        HMAC_CTX_cleanup(&hctx_tpl);
        return 0;
    }
    while (tkeylen) {
        if (tkeylen > mdlen)
            cplen = mdlen;
        else
            cplen = tkeylen;
        /*
         * We are unlikely to ever use more than 256 blocks (5120 bits!) but
         * just in case...
         */
        itmp[0] = (unsigned char)((i >> 24) & 0xff);
        itmp[1] = (unsigned char)((i >> 16) & 0xff);
        itmp[2] = (unsigned char)((i >> 8) & 0xff);
        itmp[3] = (unsigned char)(i & 0xff);
        if (!HMAC_CTX_copy(&hctx, &hctx_tpl)) {
            HMAC_CTX_cleanup(&hctx_tpl);
            return 0;
        }
        if (!HMAC_Update(&hctx, salt, saltlen)
            || !HMAC_Update(&hctx, itmp, 4)
            || !HMAC_Final(&hctx, digtmp, NULL)) {
            HMAC_CTX_cleanup(&hctx_tpl);
            HMAC_CTX_cleanup(&hctx);
            return 0;
        }
        HMAC_CTX_cleanup(&hctx);
        memcpy(p, digtmp, cplen);
        for (j = 1; j < iter; j++) {
            if (!HMAC_CTX_copy(&hctx, &hctx_tpl)) {
                HMAC_CTX_cleanup(&hctx_tpl);
                return 0;
            }
            if (!HMAC_Update(&hctx, digtmp, mdlen)
                || !HMAC_Final(&hctx, digtmp, NULL)) {
                HMAC_CTX_cleanup(&hctx_tpl);
                HMAC_CTX_cleanup(&hctx);
                return 0;
            }
            HMAC_CTX_cleanup(&hctx);
            for (k = 0; k < cplen; k++)
                p[k] ^= digtmp[k];
        }
        tkeylen -= cplen;
        i++;
        p += cplen;
    }
    HMAC_CTX_cleanup(&hctx_tpl);
# ifdef DEBUG_PKCS5V2
    fprintf(stderr, "Password:\n");
    h__dump(pass, passlen);
    fprintf(stderr, "Salt:\n");
    h__dump(salt, saltlen);
    fprintf(stderr, "Iteration count %d\n", iter);
    fprintf(stderr, "Key:\n");
    h__dump(out, keylen);
# endif
    return 1;
}

int PKCS5_PBKDF2_HMAC_SHA1(const char *pass, int passlen,
                           const unsigned char *salt, int saltlen, int iter,
                           int keylen, unsigned char *out)
{
    return PKCS5_PBKDF2_HMAC(pass, passlen, salt, saltlen, iter, EVP_sha1(),
                             keylen, out);
}

# ifdef DO_TEST
main()
{
    unsigned char out[4];
    unsigned char salt[] = { 0x12, 0x34, 0x56, 0x78 };
    PKCS5_PBKDF2_HMAC_SHA1("password", -1, salt, 4, 5, 4, out);
    fprintf(stderr, "Out %02X %02X %02X %02X\n",
            out[0], out[1], out[2], out[3]);
}

# endif

/*
 * Now the key derivation function itself. This is a bit evil because it has
 * to check the ASN1 parameters are valid: and there are quite a few of
 * them...
 */

int PKCS5_v2_PBE_keyivgen(EVP_CIPHER_CTX *ctx, const char *pass, int passlen,
                          ASN1_TYPE *param, const EVP_CIPHER *c,
                          const EVP_MD *md, int en_de)
{
    const unsigned char *pbuf;
    int plen;
    PBE2PARAM *pbe2 = NULL;
    const EVP_CIPHER *cipher;

    int rv = 0;

    if (param == NULL || param->type != V_ASN1_SEQUENCE ||
        param->value.sequence == NULL) {
        EVPerr(EVP_F_PKCS5_V2_PBE_KEYIVGEN, EVP_R_DECODE_ERROR);
        goto err;
    }

    pbuf = param->value.sequence->data;
    plen = param->value.sequence->length;
    if (!(pbe2 = d2i_PBE2PARAM(NULL, &pbuf, plen))) {
        EVPerr(EVP_F_PKCS5_V2_PBE_KEYIVGEN, EVP_R_DECODE_ERROR);
        goto err;
    }

    /* See if we recognise the key derivation function */

    if (OBJ_obj2nid(pbe2->keyfunc->algorithm) != NID_id_pbkdf2) {
        EVPerr(EVP_F_PKCS5_V2_PBE_KEYIVGEN,
               EVP_R_UNSUPPORTED_KEY_DERIVATION_FUNCTION);
        goto err;
    }

    /*
     * lets see if we recognise the encryption algorithm.
     */

    cipher = EVP_get_cipherbyobj(pbe2->encryption->algorithm);

    if (!cipher) {
        EVPerr(EVP_F_PKCS5_V2_PBE_KEYIVGEN, EVP_R_UNSUPPORTED_CIPHER);
        goto err;
    }

    /* Fixup cipher based on AlgorithmIdentifier */
    if (!EVP_CipherInit_ex(ctx, cipher, NULL, NULL, NULL, en_de))
        goto err;
    if (EVP_CIPHER_asn1_to_param(ctx, pbe2->encryption->parameter) < 0) {
        EVPerr(EVP_F_PKCS5_V2_PBE_KEYIVGEN, EVP_R_CIPHER_PARAMETER_ERROR);
        goto err;
    }
    rv = PKCS5_v2_PBKDF2_keyivgen(ctx, pass, passlen,
                                  pbe2->keyfunc->parameter, c, md, en_de);
 err:
    PBE2PARAM_free(pbe2);
    return rv;
}

int PKCS5_v2_PBKDF2_keyivgen(EVP_CIPHER_CTX *ctx, const char *pass,
                             int passlen, ASN1_TYPE *param,
                             const EVP_CIPHER *c, const EVP_MD *md, int en_de)
{
    unsigned char *salt, key[EVP_MAX_KEY_LENGTH];
    const unsigned char *pbuf;
    int saltlen, iter, plen;
    int rv = 0;
    unsigned int keylen = 0;
    int prf_nid, hmac_md_nid;
    PBKDF2PARAM *kdf = NULL;
    const EVP_MD *prfmd;

    if (EVP_CIPHER_CTX_cipher(ctx) == NULL) {
        EVPerr(EVP_F_PKCS5_V2_PBKDF2_KEYIVGEN, EVP_R_NO_CIPHER_SET);
        goto err;
    }
    keylen = EVP_CIPHER_CTX_key_length(ctx);
    OPENSSL_assert(keylen <= sizeof(key));

    /* Decode parameter */

    if (!param || (param->type != V_ASN1_SEQUENCE)) {
        EVPerr(EVP_F_PKCS5_V2_PBKDF2_KEYIVGEN, EVP_R_DECODE_ERROR);
        goto err;
    }

    pbuf = param->value.sequence->data;
    plen = param->value.sequence->length;

    if (!(kdf = d2i_PBKDF2PARAM(NULL, &pbuf, plen))) {
        EVPerr(EVP_F_PKCS5_V2_PBKDF2_KEYIVGEN, EVP_R_DECODE_ERROR);
        goto err;
    }

    keylen = EVP_CIPHER_CTX_key_length(ctx);

    /* Now check the parameters of the kdf */

    if (kdf->keylength && (ASN1_INTEGER_get(kdf->keylength) != (int)keylen)) {
        EVPerr(EVP_F_PKCS5_V2_PBKDF2_KEYIVGEN, EVP_R_UNSUPPORTED_KEYLENGTH);
        goto err;
    }

    if (kdf->prf)
        prf_nid = OBJ_obj2nid(kdf->prf->algorithm);
    else
        prf_nid = NID_hmacWithSHA1;

    if (!EVP_PBE_find(EVP_PBE_TYPE_PRF, prf_nid, NULL, &hmac_md_nid, 0)) {
        EVPerr(EVP_F_PKCS5_V2_PBKDF2_KEYIVGEN, EVP_R_UNSUPPORTED_PRF);
        goto err;
    }

    prfmd = EVP_get_digestbynid(hmac_md_nid);
    if (prfmd == NULL) {
        EVPerr(EVP_F_PKCS5_V2_PBKDF2_KEYIVGEN, EVP_R_UNSUPPORTED_PRF);
        goto err;
    }

    if (kdf->salt->type != V_ASN1_OCTET_STRING) {
        EVPerr(EVP_F_PKCS5_V2_PBKDF2_KEYIVGEN, EVP_R_UNSUPPORTED_SALT_TYPE);
        goto err;
    }

    /* it seems that its all OK */
    salt = kdf->salt->value.octet_string->data;
    saltlen = kdf->salt->value.octet_string->length;
    iter = ASN1_INTEGER_get(kdf->iter);
    if (!PKCS5_PBKDF2_HMAC(pass, passlen, salt, saltlen, iter, prfmd,
                           keylen, key))
        goto err;
    rv = EVP_CipherInit_ex(ctx, NULL, NULL, key, NULL, en_de);
 err:
    OPENSSL_cleanse(key, keylen);
    PBKDF2PARAM_free(kdf);
    return rv;
}

# ifdef DEBUG_PKCS5V2
static void h__dump(const unsigned char *p, int len)
{
    for (; len--; p++)
        fprintf(stderr, "%02X ", *p);
    fprintf(stderr, "\n");
}
# endif
#endif
/* p5_pbe.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 1999.
 */
/* ====================================================================
 * Copyright (c) 1999 The OpenSSL Project.  All rights reserved.
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
#include "asn1t.h"
// #include "x509.h"
#include "rand.h"

/* PKCS#5 password based encryption structure */

ASN1_SEQUENCE(PBEPARAM) = {
        ASN1_SIMPLE(PBEPARAM, salt, ASN1_OCTET_STRING),
        ASN1_SIMPLE(PBEPARAM, iter, ASN1_INTEGER)
} ASN1_SEQUENCE_END(PBEPARAM)

IMPLEMENT_ASN1_FUNCTIONS(PBEPARAM)

/* Set an algorithm identifier for a PKCS#5 PBE algorithm */

int PKCS5_pbe_set0_algor(X509_ALGOR *algor, int alg, int iter,
                         const unsigned char *salt, int saltlen)
{
    PBEPARAM *pbe = NULL;
    ASN1_STRING *pbe_str = NULL;
    unsigned char *sstr;

    pbe = PBEPARAM_new();
    if (!pbe) {
        ASN1err(ASN1_F_PKCS5_PBE_SET0_ALGOR, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    if (iter <= 0)
        iter = PKCS5_DEFAULT_ITER;
    if (!ASN1_INTEGER_set(pbe->iter, iter)) {
        ASN1err(ASN1_F_PKCS5_PBE_SET0_ALGOR, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    if (!saltlen)
        saltlen = PKCS5_SALT_LEN;
    if (!ASN1_STRING_set(pbe->salt, NULL, saltlen)) {
        ASN1err(ASN1_F_PKCS5_PBE_SET0_ALGOR, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    sstr = ASN1_STRING_data(pbe->salt);
    if (salt)
        memcpy(sstr, salt, saltlen);
    else if (RAND_bytes(sstr, saltlen) <= 0)
        goto err;

    if (!ASN1_item_pack(pbe, ASN1_ITEM_rptr(PBEPARAM), &pbe_str)) {
        ASN1err(ASN1_F_PKCS5_PBE_SET0_ALGOR, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    PBEPARAM_free(pbe);
    pbe = NULL;

    if (X509_ALGOR_set0(algor, OBJ_nid2obj(alg), V_ASN1_SEQUENCE, pbe_str))
        return 1;

 err:
    if (pbe != NULL)
        PBEPARAM_free(pbe);
    if (pbe_str != NULL)
        ASN1_STRING_free(pbe_str);
    return 0;
}

/* Return an algorithm identifier for a PKCS#5 PBE algorithm */

X509_ALGOR *PKCS5_pbe_set(int alg, int iter,
                          const unsigned char *salt, int saltlen)
{
    X509_ALGOR *ret;
    ret = X509_ALGOR_new();
    if (!ret) {
        ASN1err(ASN1_F_PKCS5_PBE_SET, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    if (PKCS5_pbe_set0_algor(ret, alg, iter, salt, saltlen))
        return ret;

    X509_ALGOR_free(ret);
    return NULL;
}
/* p5_pbev2.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 1999-2004.
 */
/* ====================================================================
 * Copyright (c) 1999 The OpenSSL Project.  All rights reserved.
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
// #include "asn1t.h"
// #include "x509.h"
// #include "rand.h"

/* PKCS#5 v2.0 password based encryption structures */

ASN1_SEQUENCE(PBE2PARAM) = {
        ASN1_SIMPLE(PBE2PARAM, keyfunc, X509_ALGOR),
        ASN1_SIMPLE(PBE2PARAM, encryption, X509_ALGOR)
} ASN1_SEQUENCE_END(PBE2PARAM)

IMPLEMENT_ASN1_FUNCTIONS(PBE2PARAM)

ASN1_SEQUENCE(PBKDF2PARAM) = {
        ASN1_SIMPLE(PBKDF2PARAM, salt, ASN1_ANY),
        ASN1_SIMPLE(PBKDF2PARAM, iter, ASN1_INTEGER),
        ASN1_OPT(PBKDF2PARAM, keylength, ASN1_INTEGER),
        ASN1_OPT(PBKDF2PARAM, prf, X509_ALGOR)
} ASN1_SEQUENCE_END(PBKDF2PARAM)

IMPLEMENT_ASN1_FUNCTIONS(PBKDF2PARAM)

/*
 * Return an algorithm identifier for a PKCS#5 v2.0 PBE algorithm: yes I know
 * this is horrible! Extended version to allow application supplied PRF NID
 * and IV.
 */

X509_ALGOR *PKCS5_pbe2_set_iv(const EVP_CIPHER *cipher, int iter,
                              unsigned char *salt, int saltlen,
                              unsigned char *aiv, int prf_nid)
{
    X509_ALGOR *scheme = NULL, *ret = NULL;
    int alg_nid, keylen;
    EVP_CIPHER_CTX ctx;
    unsigned char iv[EVP_MAX_IV_LENGTH];
    PBE2PARAM *pbe2 = NULL;

    alg_nid = EVP_CIPHER_type(cipher);
    if (alg_nid == NID_undef) {
        ASN1err(ASN1_F_PKCS5_PBE2_SET_IV,
                ASN1_R_CIPHER_HAS_NO_OBJECT_IDENTIFIER);
        goto err;
    }

    if (!(pbe2 = PBE2PARAM_new()))
        goto merr;

    /* Setup the AlgorithmIdentifier for the encryption scheme */
    scheme = pbe2->encryption;

    scheme->algorithm = OBJ_nid2obj(alg_nid);
    if (!(scheme->parameter = ASN1_TYPE_new()))
        goto merr;

    /* Create random IV */
    if (EVP_CIPHER_iv_length(cipher)) {
        if (aiv)
            memcpy(iv, aiv, EVP_CIPHER_iv_length(cipher));
        else if (RAND_bytes(iv, EVP_CIPHER_iv_length(cipher)) <= 0)
            goto err;
    }

    EVP_CIPHER_CTX_init(&ctx);

    /* Dummy cipherinit to just setup the IV, and PRF */
    if (!EVP_CipherInit_ex(&ctx, cipher, NULL, NULL, iv, 0))
        goto err;
    if (EVP_CIPHER_param_to_asn1(&ctx, scheme->parameter) < 0) {
        ASN1err(ASN1_F_PKCS5_PBE2_SET_IV, ASN1_R_ERROR_SETTING_CIPHER_PARAMS);
        EVP_CIPHER_CTX_cleanup(&ctx);
        goto err;
    }
    /*
     * If prf NID unspecified see if cipher has a preference. An error is OK
     * here: just means use default PRF.
     */
    if ((prf_nid == -1) &&
        EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_PBE_PRF_NID, 0, &prf_nid) <= 0) {
        ERR_clear_error();
        prf_nid = NID_hmacWithSHA1;
    }
    EVP_CIPHER_CTX_cleanup(&ctx);

    /* If its RC2 then we'd better setup the key length */

    if (alg_nid == NID_rc2_cbc)
        keylen = EVP_CIPHER_key_length(cipher);
    else
        keylen = -1;

    /* Setup keyfunc */

    X509_ALGOR_free(pbe2->keyfunc);

    pbe2->keyfunc = PKCS5_pbkdf2_set(iter, salt, saltlen, prf_nid, keylen);

    if (!pbe2->keyfunc)
        goto merr;

    /* Now set up top level AlgorithmIdentifier */

    if (!(ret = X509_ALGOR_new()))
        goto merr;
    if (!(ret->parameter = ASN1_TYPE_new()))
        goto merr;

    ret->algorithm = OBJ_nid2obj(NID_pbes2);

    /* Encode PBE2PARAM into parameter */

    if (!ASN1_item_pack(pbe2, ASN1_ITEM_rptr(PBE2PARAM),
                        &ret->parameter->value.sequence))
         goto merr;
    ret->parameter->type = V_ASN1_SEQUENCE;

    PBE2PARAM_free(pbe2);
    pbe2 = NULL;

    return ret;

 merr:
    ASN1err(ASN1_F_PKCS5_PBE2_SET_IV, ERR_R_MALLOC_FAILURE);

 err:
    PBE2PARAM_free(pbe2);
    /* Note 'scheme' is freed as part of pbe2 */
    X509_ALGOR_free(ret);

    return NULL;
}

X509_ALGOR *PKCS5_pbe2_set(const EVP_CIPHER *cipher, int iter,
                           unsigned char *salt, int saltlen)
{
    return PKCS5_pbe2_set_iv(cipher, iter, salt, saltlen, NULL, -1);
}

X509_ALGOR *PKCS5_pbkdf2_set(int iter, unsigned char *salt, int saltlen,
                             int prf_nid, int keylen)
{
    X509_ALGOR *keyfunc = NULL;
    PBKDF2PARAM *kdf = NULL;
    ASN1_OCTET_STRING *osalt = NULL;

    if (!(kdf = PBKDF2PARAM_new()))
        goto merr;
    if (!(osalt = M_ASN1_OCTET_STRING_new()))
        goto merr;

    kdf->salt->value.octet_string = osalt;
    kdf->salt->type = V_ASN1_OCTET_STRING;

    if (!saltlen)
        saltlen = PKCS5_SALT_LEN;
    if (!(osalt->data = OPENSSL_malloc(saltlen)))
        goto merr;

    osalt->length = saltlen;

    if (salt)
        memcpy(osalt->data, salt, saltlen);
    else if (RAND_bytes(osalt->data, saltlen) <= 0)
        goto merr;

    if (iter <= 0)
        iter = PKCS5_DEFAULT_ITER;

    if (!ASN1_INTEGER_set(kdf->iter, iter))
        goto merr;

    /* If have a key len set it up */

    if (keylen > 0) {
        if (!(kdf->keylength = M_ASN1_INTEGER_new()))
            goto merr;
        if (!ASN1_INTEGER_set(kdf->keylength, keylen))
            goto merr;
    }

    /* prf can stay NULL if we are using hmacWithSHA1 */
    if (prf_nid > 0 && prf_nid != NID_hmacWithSHA1) {
        kdf->prf = X509_ALGOR_new();
        if (!kdf->prf)
            goto merr;
        X509_ALGOR_set0(kdf->prf, OBJ_nid2obj(prf_nid), V_ASN1_NULL, NULL);
    }

    /* Finally setup the keyfunc structure */

    keyfunc = X509_ALGOR_new();
    if (!keyfunc)
        goto merr;

    keyfunc->algorithm = OBJ_nid2obj(NID_id_pbkdf2);

    /* Encode PBKDF2PARAM into parameter of pbe2 */

    if (!(keyfunc->parameter = ASN1_TYPE_new()))
        goto merr;

    if (!ASN1_item_pack(kdf, ASN1_ITEM_rptr(PBKDF2PARAM),
                        &keyfunc->parameter->value.sequence))
         goto merr;
    keyfunc->parameter->type = V_ASN1_SEQUENCE;

    PBKDF2PARAM_free(kdf);
    return keyfunc;

 merr:
    ASN1err(ASN1_F_PKCS5_PBKDF2_SET, ERR_R_MALLOC_FAILURE);
    PBKDF2PARAM_free(kdf);
    X509_ALGOR_free(keyfunc);
    return NULL;
}
