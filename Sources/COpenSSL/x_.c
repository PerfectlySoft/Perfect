/* x_algor.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 2000.
 */
/* ====================================================================
 * Copyright (c) 2000 The OpenSSL Project.  All rights reserved.
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

#include <stddef.h>
#include "x509.h"
#include "asn1.h"
#include "asn1t.h"

ASN1_SEQUENCE(X509_ALGOR) = {
        ASN1_SIMPLE(X509_ALGOR, algorithm, ASN1_OBJECT),
        ASN1_OPT(X509_ALGOR, parameter, ASN1_ANY)
} ASN1_SEQUENCE_END(X509_ALGOR)

ASN1_ITEM_TEMPLATE(X509_ALGORS) =
        ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SEQUENCE_OF, 0, algorithms, X509_ALGOR)
ASN1_ITEM_TEMPLATE_END(X509_ALGORS)

IMPLEMENT_ASN1_FUNCTIONS(X509_ALGOR)
IMPLEMENT_ASN1_ENCODE_FUNCTIONS_fname(X509_ALGORS, X509_ALGORS, X509_ALGORS)
IMPLEMENT_ASN1_DUP_FUNCTION(X509_ALGOR)

IMPLEMENT_STACK_OF(X509_ALGOR)
IMPLEMENT_ASN1_SET_OF(X509_ALGOR)

int X509_ALGOR_set0(X509_ALGOR *alg, ASN1_OBJECT *aobj, int ptype, void *pval)
{
    if (!alg)
        return 0;
    if (ptype != V_ASN1_UNDEF) {
        if (alg->parameter == NULL)
            alg->parameter = ASN1_TYPE_new();
        if (alg->parameter == NULL)
            return 0;
    }
    if (alg) {
        if (alg->algorithm)
            ASN1_OBJECT_free(alg->algorithm);
        alg->algorithm = aobj;
    }
    if (ptype == 0)
        return 1;
    if (ptype == V_ASN1_UNDEF) {
        if (alg->parameter) {
            ASN1_TYPE_free(alg->parameter);
            alg->parameter = NULL;
        }
    } else
        ASN1_TYPE_set(alg->parameter, ptype, pval);
    return 1;
}

void X509_ALGOR_get0(ASN1_OBJECT **paobj, int *pptype, void **ppval,
                     X509_ALGOR *algor)
{
    if (paobj)
        *paobj = algor->algorithm;
    if (pptype) {
        if (algor->parameter == NULL) {
            *pptype = V_ASN1_UNDEF;
            return;
        } else
            *pptype = algor->parameter->type;
        if (ppval)
            *ppval = algor->parameter->value.ptr;
    }
}

/* Set up an X509_ALGOR DigestAlgorithmIdentifier from an EVP_MD */

void X509_ALGOR_set_md(X509_ALGOR *alg, const EVP_MD *md)
{
    int param_type;

    if (md->flags & EVP_MD_FLAG_DIGALGID_ABSENT)
        param_type = V_ASN1_UNDEF;
    else
        param_type = V_ASN1_NULL;

    X509_ALGOR_set0(alg, OBJ_nid2obj(EVP_MD_type(md)), param_type, NULL);

}

int X509_ALGOR_cmp(const X509_ALGOR *a, const X509_ALGOR *b)
{
    int rv;
    rv = OBJ_cmp(a->algorithm, b->algorithm);
    if (rv)
        return rv;
    if (!a->parameter && !b->parameter)
        return 0;
    return ASN1_TYPE_cmp(a->parameter, b->parameter);
}
/* crypto/x509/x_all.c */
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
#include "stack.h"
#include "cryptlib.h"
#include "buffer.h"
// #include "asn1.h"
#include "evp.h"
// #include "x509.h"
#include "ocsp.h"
#ifndef OPENSSL_NO_RSA
# include "rsa.h"
#endif
#ifndef OPENSSL_NO_DSA
# include "dsa.h"
#endif

int X509_verify(X509 *a, EVP_PKEY *r)
{
    if (X509_ALGOR_cmp(a->sig_alg, a->cert_info->signature))
        return 0;
    return (ASN1_item_verify(ASN1_ITEM_rptr(X509_CINF), a->sig_alg,
                             a->signature, a->cert_info, r));
}

int X509_REQ_verify(X509_REQ *a, EVP_PKEY *r)
{
    return (ASN1_item_verify(ASN1_ITEM_rptr(X509_REQ_INFO),
                             a->sig_alg, a->signature, a->req_info, r));
}

int NETSCAPE_SPKI_verify(NETSCAPE_SPKI *a, EVP_PKEY *r)
{
    return (ASN1_item_verify(ASN1_ITEM_rptr(NETSCAPE_SPKAC),
                             a->sig_algor, a->signature, a->spkac, r));
}

int X509_sign(X509 *x, EVP_PKEY *pkey, const EVP_MD *md)
{
    x->cert_info->enc.modified = 1;
    return (ASN1_item_sign(ASN1_ITEM_rptr(X509_CINF), x->cert_info->signature,
                           x->sig_alg, x->signature, x->cert_info, pkey, md));
}

int X509_sign_ctx(X509 *x, EVP_MD_CTX *ctx)
{
    x->cert_info->enc.modified = 1;
    return ASN1_item_sign_ctx(ASN1_ITEM_rptr(X509_CINF),
                              x->cert_info->signature,
                              x->sig_alg, x->signature, x->cert_info, ctx);
}

int X509_http_nbio(OCSP_REQ_CTX *rctx, X509 **pcert)
{
    return OCSP_REQ_CTX_nbio_d2i(rctx,
                                 (ASN1_VALUE **)pcert, ASN1_ITEM_rptr(X509));
}

int X509_REQ_sign(X509_REQ *x, EVP_PKEY *pkey, const EVP_MD *md)
{
    return (ASN1_item_sign(ASN1_ITEM_rptr(X509_REQ_INFO), x->sig_alg, NULL,
                           x->signature, x->req_info, pkey, md));
}

int X509_REQ_sign_ctx(X509_REQ *x, EVP_MD_CTX *ctx)
{
    return ASN1_item_sign_ctx(ASN1_ITEM_rptr(X509_REQ_INFO),
                              x->sig_alg, NULL, x->signature, x->req_info,
                              ctx);
}

int X509_CRL_sign(X509_CRL *x, EVP_PKEY *pkey, const EVP_MD *md)
{
    x->crl->enc.modified = 1;
    return (ASN1_item_sign(ASN1_ITEM_rptr(X509_CRL_INFO), x->crl->sig_alg,
                           x->sig_alg, x->signature, x->crl, pkey, md));
}

int X509_CRL_sign_ctx(X509_CRL *x, EVP_MD_CTX *ctx)
{
    x->crl->enc.modified = 1;
    return ASN1_item_sign_ctx(ASN1_ITEM_rptr(X509_CRL_INFO),
                              x->crl->sig_alg, x->sig_alg, x->signature,
                              x->crl, ctx);
}

int X509_CRL_http_nbio(OCSP_REQ_CTX *rctx, X509_CRL **pcrl)
{
    return OCSP_REQ_CTX_nbio_d2i(rctx,
                                 (ASN1_VALUE **)pcrl,
                                 ASN1_ITEM_rptr(X509_CRL));
}

int NETSCAPE_SPKI_sign(NETSCAPE_SPKI *x, EVP_PKEY *pkey, const EVP_MD *md)
{
    return (ASN1_item_sign(ASN1_ITEM_rptr(NETSCAPE_SPKAC), x->sig_algor, NULL,
                           x->signature, x->spkac, pkey, md));
}

#ifndef OPENSSL_NO_FP_API
X509 *d2i_X509_fp(FILE *fp, X509 **x509)
{
    return ASN1_item_d2i_fp(ASN1_ITEM_rptr(X509), fp, x509);
}

int i2d_X509_fp(FILE *fp, X509 *x509)
{
    return ASN1_item_i2d_fp(ASN1_ITEM_rptr(X509), fp, x509);
}
#endif

X509 *d2i_X509_bio(BIO *bp, X509 **x509)
{
    return ASN1_item_d2i_bio(ASN1_ITEM_rptr(X509), bp, x509);
}

int i2d_X509_bio(BIO *bp, X509 *x509)
{
    return ASN1_item_i2d_bio(ASN1_ITEM_rptr(X509), bp, x509);
}

#ifndef OPENSSL_NO_FP_API
X509_CRL *d2i_X509_CRL_fp(FILE *fp, X509_CRL **crl)
{
    return ASN1_item_d2i_fp(ASN1_ITEM_rptr(X509_CRL), fp, crl);
}

int i2d_X509_CRL_fp(FILE *fp, X509_CRL *crl)
{
    return ASN1_item_i2d_fp(ASN1_ITEM_rptr(X509_CRL), fp, crl);
}
#endif

X509_CRL *d2i_X509_CRL_bio(BIO *bp, X509_CRL **crl)
{
    return ASN1_item_d2i_bio(ASN1_ITEM_rptr(X509_CRL), bp, crl);
}

int i2d_X509_CRL_bio(BIO *bp, X509_CRL *crl)
{
    return ASN1_item_i2d_bio(ASN1_ITEM_rptr(X509_CRL), bp, crl);
}

#ifndef OPENSSL_NO_FP_API
PKCS7 *d2i_PKCS7_fp(FILE *fp, PKCS7 **p7)
{
    return ASN1_item_d2i_fp(ASN1_ITEM_rptr(PKCS7), fp, p7);
}

int i2d_PKCS7_fp(FILE *fp, PKCS7 *p7)
{
    return ASN1_item_i2d_fp(ASN1_ITEM_rptr(PKCS7), fp, p7);
}
#endif

PKCS7 *d2i_PKCS7_bio(BIO *bp, PKCS7 **p7)
{
    return ASN1_item_d2i_bio(ASN1_ITEM_rptr(PKCS7), bp, p7);
}

int i2d_PKCS7_bio(BIO *bp, PKCS7 *p7)
{
    return ASN1_item_i2d_bio(ASN1_ITEM_rptr(PKCS7), bp, p7);
}

#ifndef OPENSSL_NO_FP_API
X509_REQ *d2i_X509_REQ_fp(FILE *fp, X509_REQ **req)
{
    return ASN1_item_d2i_fp(ASN1_ITEM_rptr(X509_REQ), fp, req);
}

int i2d_X509_REQ_fp(FILE *fp, X509_REQ *req)
{
    return ASN1_item_i2d_fp(ASN1_ITEM_rptr(X509_REQ), fp, req);
}
#endif

X509_REQ *d2i_X509_REQ_bio(BIO *bp, X509_REQ **req)
{
    return ASN1_item_d2i_bio(ASN1_ITEM_rptr(X509_REQ), bp, req);
}

int i2d_X509_REQ_bio(BIO *bp, X509_REQ *req)
{
    return ASN1_item_i2d_bio(ASN1_ITEM_rptr(X509_REQ), bp, req);
}

#ifndef OPENSSL_NO_RSA

# ifndef OPENSSL_NO_FP_API
RSA *d2i_RSAPrivateKey_fp(FILE *fp, RSA **rsa)
{
    return ASN1_item_d2i_fp(ASN1_ITEM_rptr(RSAPrivateKey), fp, rsa);
}

int i2d_RSAPrivateKey_fp(FILE *fp, RSA *rsa)
{
    return ASN1_item_i2d_fp(ASN1_ITEM_rptr(RSAPrivateKey), fp, rsa);
}

RSA *d2i_RSAPublicKey_fp(FILE *fp, RSA **rsa)
{
    return ASN1_item_d2i_fp(ASN1_ITEM_rptr(RSAPublicKey), fp, rsa);
}

RSA *d2i_RSA_PUBKEY_fp(FILE *fp, RSA **rsa)
{
    return ASN1_d2i_fp((void *(*)(void))
                       RSA_new, (D2I_OF(void)) d2i_RSA_PUBKEY, fp,
                       (void **)rsa);
}

int i2d_RSAPublicKey_fp(FILE *fp, RSA *rsa)
{
    return ASN1_item_i2d_fp(ASN1_ITEM_rptr(RSAPublicKey), fp, rsa);
}

int i2d_RSA_PUBKEY_fp(FILE *fp, RSA *rsa)
{
    return ASN1_i2d_fp((I2D_OF(void))i2d_RSA_PUBKEY, fp, rsa);
}
# endif

RSA *d2i_RSAPrivateKey_bio(BIO *bp, RSA **rsa)
{
    return ASN1_item_d2i_bio(ASN1_ITEM_rptr(RSAPrivateKey), bp, rsa);
}

int i2d_RSAPrivateKey_bio(BIO *bp, RSA *rsa)
{
    return ASN1_item_i2d_bio(ASN1_ITEM_rptr(RSAPrivateKey), bp, rsa);
}

RSA *d2i_RSAPublicKey_bio(BIO *bp, RSA **rsa)
{
    return ASN1_item_d2i_bio(ASN1_ITEM_rptr(RSAPublicKey), bp, rsa);
}

RSA *d2i_RSA_PUBKEY_bio(BIO *bp, RSA **rsa)
{
    return ASN1_d2i_bio_of(RSA, RSA_new, d2i_RSA_PUBKEY, bp, rsa);
}

int i2d_RSAPublicKey_bio(BIO *bp, RSA *rsa)
{
    return ASN1_item_i2d_bio(ASN1_ITEM_rptr(RSAPublicKey), bp, rsa);
}

int i2d_RSA_PUBKEY_bio(BIO *bp, RSA *rsa)
{
    return ASN1_i2d_bio_of(RSA, i2d_RSA_PUBKEY, bp, rsa);
}
#endif

#ifndef OPENSSL_NO_DSA
# ifndef OPENSSL_NO_FP_API
DSA *d2i_DSAPrivateKey_fp(FILE *fp, DSA **dsa)
{
    return ASN1_d2i_fp_of(DSA, DSA_new, d2i_DSAPrivateKey, fp, dsa);
}

int i2d_DSAPrivateKey_fp(FILE *fp, DSA *dsa)
{
    return ASN1_i2d_fp_of_const(DSA, i2d_DSAPrivateKey, fp, dsa);
}

DSA *d2i_DSA_PUBKEY_fp(FILE *fp, DSA **dsa)
{
    return ASN1_d2i_fp_of(DSA, DSA_new, d2i_DSA_PUBKEY, fp, dsa);
}

int i2d_DSA_PUBKEY_fp(FILE *fp, DSA *dsa)
{
    return ASN1_i2d_fp_of(DSA, i2d_DSA_PUBKEY, fp, dsa);
}
# endif

DSA *d2i_DSAPrivateKey_bio(BIO *bp, DSA **dsa)
{
    return ASN1_d2i_bio_of(DSA, DSA_new, d2i_DSAPrivateKey, bp, dsa);
}

int i2d_DSAPrivateKey_bio(BIO *bp, DSA *dsa)
{
    return ASN1_i2d_bio_of_const(DSA, i2d_DSAPrivateKey, bp, dsa);
}

DSA *d2i_DSA_PUBKEY_bio(BIO *bp, DSA **dsa)
{
    return ASN1_d2i_bio_of(DSA, DSA_new, d2i_DSA_PUBKEY, bp, dsa);
}

int i2d_DSA_PUBKEY_bio(BIO *bp, DSA *dsa)
{
    return ASN1_i2d_bio_of(DSA, i2d_DSA_PUBKEY, bp, dsa);
}

#endif

#ifndef OPENSSL_NO_EC
# ifndef OPENSSL_NO_FP_API
EC_KEY *d2i_EC_PUBKEY_fp(FILE *fp, EC_KEY **eckey)
{
    return ASN1_d2i_fp_of(EC_KEY, EC_KEY_new, d2i_EC_PUBKEY, fp, eckey);
}

int i2d_EC_PUBKEY_fp(FILE *fp, EC_KEY *eckey)
{
    return ASN1_i2d_fp_of(EC_KEY, i2d_EC_PUBKEY, fp, eckey);
}

EC_KEY *d2i_ECPrivateKey_fp(FILE *fp, EC_KEY **eckey)
{
    return ASN1_d2i_fp_of(EC_KEY, EC_KEY_new, d2i_ECPrivateKey, fp, eckey);
}

int i2d_ECPrivateKey_fp(FILE *fp, EC_KEY *eckey)
{
    return ASN1_i2d_fp_of(EC_KEY, i2d_ECPrivateKey, fp, eckey);
}
# endif
EC_KEY *d2i_EC_PUBKEY_bio(BIO *bp, EC_KEY **eckey)
{
    return ASN1_d2i_bio_of(EC_KEY, EC_KEY_new, d2i_EC_PUBKEY, bp, eckey);
}

int i2d_EC_PUBKEY_bio(BIO *bp, EC_KEY *ecdsa)
{
    return ASN1_i2d_bio_of(EC_KEY, i2d_EC_PUBKEY, bp, ecdsa);
}

EC_KEY *d2i_ECPrivateKey_bio(BIO *bp, EC_KEY **eckey)
{
    return ASN1_d2i_bio_of(EC_KEY, EC_KEY_new, d2i_ECPrivateKey, bp, eckey);
}

int i2d_ECPrivateKey_bio(BIO *bp, EC_KEY *eckey)
{
    return ASN1_i2d_bio_of(EC_KEY, i2d_ECPrivateKey, bp, eckey);
}
#endif

int X509_pubkey_digest(const X509 *data, const EVP_MD *type,
                       unsigned char *md, unsigned int *len)
{
    ASN1_BIT_STRING *key;
    key = X509_get0_pubkey_bitstr(data);
    if (!key)
        return 0;
    return EVP_Digest(key->data, key->length, md, len, type, NULL);
}

int X509_digest(const X509 *data, const EVP_MD *type, unsigned char *md,
                unsigned int *len)
{
    return (ASN1_item_digest
            (ASN1_ITEM_rptr(X509), type, (char *)data, md, len));
}

int X509_CRL_digest(const X509_CRL *data, const EVP_MD *type,
                    unsigned char *md, unsigned int *len)
{
    return (ASN1_item_digest
            (ASN1_ITEM_rptr(X509_CRL), type, (char *)data, md, len));
}

int X509_REQ_digest(const X509_REQ *data, const EVP_MD *type,
                    unsigned char *md, unsigned int *len)
{
    return (ASN1_item_digest
            (ASN1_ITEM_rptr(X509_REQ), type, (char *)data, md, len));
}

int X509_NAME_digest(const X509_NAME *data, const EVP_MD *type,
                     unsigned char *md, unsigned int *len)
{
    return (ASN1_item_digest
            (ASN1_ITEM_rptr(X509_NAME), type, (char *)data, md, len));
}

int PKCS7_ISSUER_AND_SERIAL_digest(PKCS7_ISSUER_AND_SERIAL *data,
                                   const EVP_MD *type, unsigned char *md,
                                   unsigned int *len)
{
    return (ASN1_item_digest(ASN1_ITEM_rptr(PKCS7_ISSUER_AND_SERIAL), type,
                             (char *)data, md, len));
}

#ifndef OPENSSL_NO_FP_API
X509_SIG *d2i_PKCS8_fp(FILE *fp, X509_SIG **p8)
{
    return ASN1_d2i_fp_of(X509_SIG, X509_SIG_new, d2i_X509_SIG, fp, p8);
}

int i2d_PKCS8_fp(FILE *fp, X509_SIG *p8)
{
    return ASN1_i2d_fp_of(X509_SIG, i2d_X509_SIG, fp, p8);
}
#endif

X509_SIG *d2i_PKCS8_bio(BIO *bp, X509_SIG **p8)
{
    return ASN1_d2i_bio_of(X509_SIG, X509_SIG_new, d2i_X509_SIG, bp, p8);
}

int i2d_PKCS8_bio(BIO *bp, X509_SIG *p8)
{
    return ASN1_i2d_bio_of(X509_SIG, i2d_X509_SIG, bp, p8);
}

#ifndef OPENSSL_NO_FP_API
PKCS8_PRIV_KEY_INFO *d2i_PKCS8_PRIV_KEY_INFO_fp(FILE *fp,
                                                PKCS8_PRIV_KEY_INFO **p8inf)
{
    return ASN1_d2i_fp_of(PKCS8_PRIV_KEY_INFO, PKCS8_PRIV_KEY_INFO_new,
                          d2i_PKCS8_PRIV_KEY_INFO, fp, p8inf);
}

int i2d_PKCS8_PRIV_KEY_INFO_fp(FILE *fp, PKCS8_PRIV_KEY_INFO *p8inf)
{
    return ASN1_i2d_fp_of(PKCS8_PRIV_KEY_INFO, i2d_PKCS8_PRIV_KEY_INFO, fp,
                          p8inf);
}

int i2d_PKCS8PrivateKeyInfo_fp(FILE *fp, EVP_PKEY *key)
{
    PKCS8_PRIV_KEY_INFO *p8inf;
    int ret;
    p8inf = EVP_PKEY2PKCS8(key);
    if (!p8inf)
        return 0;
    ret = i2d_PKCS8_PRIV_KEY_INFO_fp(fp, p8inf);
    PKCS8_PRIV_KEY_INFO_free(p8inf);
    return ret;
}

int i2d_PrivateKey_fp(FILE *fp, EVP_PKEY *pkey)
{
    return ASN1_i2d_fp_of(EVP_PKEY, i2d_PrivateKey, fp, pkey);
}

EVP_PKEY *d2i_PrivateKey_fp(FILE *fp, EVP_PKEY **a)
{
    return ASN1_d2i_fp_of(EVP_PKEY, EVP_PKEY_new, d2i_AutoPrivateKey, fp, a);
}

int i2d_PUBKEY_fp(FILE *fp, EVP_PKEY *pkey)
{
    return ASN1_i2d_fp_of(EVP_PKEY, i2d_PUBKEY, fp, pkey);
}

EVP_PKEY *d2i_PUBKEY_fp(FILE *fp, EVP_PKEY **a)
{
    return ASN1_d2i_fp_of(EVP_PKEY, EVP_PKEY_new, d2i_PUBKEY, fp, a);
}

#endif

PKCS8_PRIV_KEY_INFO *d2i_PKCS8_PRIV_KEY_INFO_bio(BIO *bp,
                                                 PKCS8_PRIV_KEY_INFO **p8inf)
{
    return ASN1_d2i_bio_of(PKCS8_PRIV_KEY_INFO, PKCS8_PRIV_KEY_INFO_new,
                           d2i_PKCS8_PRIV_KEY_INFO, bp, p8inf);
}

int i2d_PKCS8_PRIV_KEY_INFO_bio(BIO *bp, PKCS8_PRIV_KEY_INFO *p8inf)
{
    return ASN1_i2d_bio_of(PKCS8_PRIV_KEY_INFO, i2d_PKCS8_PRIV_KEY_INFO, bp,
                           p8inf);
}

int i2d_PKCS8PrivateKeyInfo_bio(BIO *bp, EVP_PKEY *key)
{
    PKCS8_PRIV_KEY_INFO *p8inf;
    int ret;
    p8inf = EVP_PKEY2PKCS8(key);
    if (!p8inf)
        return 0;
    ret = i2d_PKCS8_PRIV_KEY_INFO_bio(bp, p8inf);
    PKCS8_PRIV_KEY_INFO_free(p8inf);
    return ret;
}

int i2d_PrivateKey_bio(BIO *bp, EVP_PKEY *pkey)
{
    return ASN1_i2d_bio_of(EVP_PKEY, i2d_PrivateKey, bp, pkey);
}

EVP_PKEY *d2i_PrivateKey_bio(BIO *bp, EVP_PKEY **a)
{
    return ASN1_d2i_bio_of(EVP_PKEY, EVP_PKEY_new, d2i_AutoPrivateKey, bp, a);
}

int i2d_PUBKEY_bio(BIO *bp, EVP_PKEY *pkey)
{
    return ASN1_i2d_bio_of(EVP_PKEY, i2d_PUBKEY, bp, pkey);
}

EVP_PKEY *d2i_PUBKEY_bio(BIO *bp, EVP_PKEY **a)
{
    return ASN1_d2i_bio_of(EVP_PKEY, EVP_PKEY_new, d2i_PUBKEY, bp, a);
}
/* crypto/asn1/x_attrib.c */
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
#include "objects.h"
// #include "asn1t.h"
// #include "x509.h"

/*-
 * X509_ATTRIBUTE: this has the following form:
 *
 * typedef struct x509_attributes_st
 *      {
 *      ASN1_OBJECT *object;
 *      int single;
 *      union   {
 *              char            *ptr;
 *              STACK_OF(ASN1_TYPE) *set;
 *              ASN1_TYPE       *single;
 *              } value;
 *      } X509_ATTRIBUTE;
 *
 * this needs some extra thought because the CHOICE type is
 * merged with the main structure and because the value can
 * be anything at all we *must* try the SET OF first because
 * the ASN1_ANY type will swallow anything including the whole
 * SET OF structure.
 */

ASN1_CHOICE(X509_ATTRIBUTE_SET) = {
        ASN1_SET_OF(X509_ATTRIBUTE, value.set, ASN1_ANY),
        ASN1_SIMPLE(X509_ATTRIBUTE, value.single, ASN1_ANY)
} ASN1_CHOICE_END_selector(X509_ATTRIBUTE, X509_ATTRIBUTE_SET, single)

ASN1_SEQUENCE(X509_ATTRIBUTE) = {
        ASN1_SIMPLE(X509_ATTRIBUTE, object, ASN1_OBJECT),
        /* CHOICE type merged with parent */
        ASN1_EX_COMBINE(0, 0, X509_ATTRIBUTE_SET)
} ASN1_SEQUENCE_END(X509_ATTRIBUTE)

IMPLEMENT_ASN1_FUNCTIONS(X509_ATTRIBUTE)
IMPLEMENT_ASN1_DUP_FUNCTION(X509_ATTRIBUTE)

X509_ATTRIBUTE *X509_ATTRIBUTE_create(int nid, int atrtype, void *value)
{
    X509_ATTRIBUTE *ret = NULL;
    ASN1_TYPE *val = NULL;

    if ((ret = X509_ATTRIBUTE_new()) == NULL)
        return (NULL);
    ret->object = OBJ_nid2obj(nid);
    ret->single = 0;
    if ((ret->value.set = sk_ASN1_TYPE_new_null()) == NULL)
        goto err;
    if ((val = ASN1_TYPE_new()) == NULL)
        goto err;
    if (!sk_ASN1_TYPE_push(ret->value.set, val))
        goto err;

    ASN1_TYPE_set(val, atrtype, value);
    return (ret);
 err:
    if (ret != NULL)
        X509_ATTRIBUTE_free(ret);
    if (val != NULL)
        ASN1_TYPE_free(val);
    return (NULL);
}
/* x_bignum.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 2000.
 */
/* ====================================================================
 * Copyright (c) 2000 The OpenSSL Project.  All rights reserved.
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
#include "bn.h"

/*
 * Custom primitive type for BIGNUM handling. This reads in an ASN1_INTEGER
 * as a BIGNUM directly. Currently it ignores the sign which isn't a problem
 * since all BIGNUMs used are non negative and anything that looks negative
 * is normally due to an encoding error.
 */

#define BN_SENSITIVE    1

static int bn_new(ASN1_VALUE **pval, const ASN1_ITEM *it);
static void bn_free(ASN1_VALUE **pval, const ASN1_ITEM *it);

static int bn_i2c(ASN1_VALUE **pval, unsigned char *cont, int *putype,
                  const ASN1_ITEM *it);
static int bn_c2i(ASN1_VALUE **pval, const unsigned char *cont, int len,
                  int utype, char *free_cont, const ASN1_ITEM *it);
static int bn_print(BIO *out, ASN1_VALUE **pval, const ASN1_ITEM *it,
                    int indent, const ASN1_PCTX *pctx);

static ASN1_PRIMITIVE_FUNCS bignum_pf = {
    NULL, 0,
    bn_new,
    bn_free,
    0,
    bn_c2i,
    bn_i2c,
    bn_print
};

ASN1_ITEM_start(BIGNUM)
        ASN1_ITYPE_PRIMITIVE, V_ASN1_INTEGER, NULL, 0, &bignum_pf, 0, "BIGNUM"
ASN1_ITEM_end(BIGNUM)

ASN1_ITEM_start(CBIGNUM)
        ASN1_ITYPE_PRIMITIVE, V_ASN1_INTEGER, NULL, 0, &bignum_pf, BN_SENSITIVE, "BIGNUM"
ASN1_ITEM_end(CBIGNUM)

static int bn_new(ASN1_VALUE **pval, const ASN1_ITEM *it)
{
    *pval = (ASN1_VALUE *)BN_new();
    if (*pval)
        return 1;
    else
        return 0;
}

static void bn_free(ASN1_VALUE **pval, const ASN1_ITEM *it)
{
    if (!*pval)
        return;
    if (it->size & BN_SENSITIVE)
        BN_clear_free((BIGNUM *)*pval);
    else
        BN_free((BIGNUM *)*pval);
    *pval = NULL;
}

static int bn_i2c(ASN1_VALUE **pval, unsigned char *cont, int *putype,
                  const ASN1_ITEM *it)
{
    BIGNUM *bn;
    int pad;
    if (!*pval)
        return -1;
    bn = (BIGNUM *)*pval;
    /* If MSB set in an octet we need a padding byte */
    if (BN_num_bits(bn) & 0x7)
        pad = 0;
    else
        pad = 1;
    if (cont) {
        if (pad)
            *cont++ = 0;
        BN_bn2bin(bn, cont);
    }
    return pad + BN_num_bytes(bn);
}

static int bn_c2i(ASN1_VALUE **pval, const unsigned char *cont, int len,
                  int utype, char *free_cont, const ASN1_ITEM *it)
{
    BIGNUM *bn;

    if (*pval == NULL && !bn_new(pval, it))
        return 0;
    bn = (BIGNUM *)*pval;
    if (!BN_bin2bn(cont, len, bn)) {
        bn_free(pval, it);
        return 0;
    }
    return 1;
}

static int bn_print(BIO *out, ASN1_VALUE **pval, const ASN1_ITEM *it,
                    int indent, const ASN1_PCTX *pctx)
{
    if (!BN_print(out, *(BIGNUM **)pval))
        return 0;
    if (BIO_puts(out, "\n") <= 0)
        return 0;
    return 1;
}
/* crypto/asn1/x_crl.c */
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
// #include "asn1t.h"
#include "asn1_locl.h"
// #include "x509.h"
#include "x509v3.h"

static int X509_REVOKED_cmp(const X509_REVOKED *const *a,
                            const X509_REVOKED *const *b);
static void setup_idp(X509_CRL *crl, ISSUING_DIST_POINT *idp);

ASN1_SEQUENCE(X509_REVOKED) = {
        ASN1_SIMPLE(X509_REVOKED,serialNumber, ASN1_INTEGER),
        ASN1_SIMPLE(X509_REVOKED,revocationDate, ASN1_TIME),
        ASN1_SEQUENCE_OF_OPT(X509_REVOKED,extensions, X509_EXTENSION)
} ASN1_SEQUENCE_END(X509_REVOKED)

static int def_crl_verify(X509_CRL *crl, EVP_PKEY *r);
static int def_crl_lookup(X509_CRL *crl,
                          X509_REVOKED **ret, ASN1_INTEGER *serial,
                          X509_NAME *issuer);

static X509_CRL_METHOD int_crl_meth = {
    0,
    0, 0,
    def_crl_lookup,
    def_crl_verify
};

static const X509_CRL_METHOD *default_crl_method = &int_crl_meth;

/*
 * The X509_CRL_INFO structure needs a bit of customisation. Since we cache
 * the original encoding the signature wont be affected by reordering of the
 * revoked field.
 */
static int crl_inf_cb(int operation, ASN1_VALUE **pval, const ASN1_ITEM *it,
                      void *exarg)
{
    X509_CRL_INFO *a = (X509_CRL_INFO *)*pval;

    if (!a || !a->revoked)
        return 1;
    switch (operation) {
        /*
         * Just set cmp function here. We don't sort because that would
         * affect the output of X509_CRL_print().
         */
    case ASN1_OP_D2I_POST:
        (void)sk_X509_REVOKED_set_cmp_func(a->revoked, X509_REVOKED_cmp);
        break;
    }
    return 1;
}


ASN1_SEQUENCE_enc(X509_CRL_INFO, enc, crl_inf_cb) = {
        ASN1_OPT(X509_CRL_INFO, version, ASN1_INTEGER),
        ASN1_SIMPLE(X509_CRL_INFO, sig_alg, X509_ALGOR),
        ASN1_SIMPLE(X509_CRL_INFO, issuer, X509_NAME),
        ASN1_SIMPLE(X509_CRL_INFO, lastUpdate, ASN1_TIME),
        ASN1_OPT(X509_CRL_INFO, nextUpdate, ASN1_TIME),
        ASN1_SEQUENCE_OF_OPT(X509_CRL_INFO, revoked, X509_REVOKED),
        ASN1_EXP_SEQUENCE_OF_OPT(X509_CRL_INFO, extensions, X509_EXTENSION, 0)
} ASN1_SEQUENCE_END_enc(X509_CRL_INFO, X509_CRL_INFO)

/*
 * Set CRL entry issuer according to CRL certificate issuer extension. Check
 * for unhandled critical CRL entry extensions.
 */

static int crl_set_issuers(X509_CRL *crl)
{

    int i, j;
    GENERAL_NAMES *gens, *gtmp;
    STACK_OF(X509_REVOKED) *revoked;

    revoked = X509_CRL_get_REVOKED(crl);

    gens = NULL;
    for (i = 0; i < sk_X509_REVOKED_num(revoked); i++) {
        X509_REVOKED *rev = sk_X509_REVOKED_value(revoked, i);
        STACK_OF(X509_EXTENSION) *exts;
        ASN1_ENUMERATED *reason;
        X509_EXTENSION *ext;
        gtmp = X509_REVOKED_get_ext_d2i(rev,
                                        NID_certificate_issuer, &j, NULL);
        if (!gtmp && (j != -1)) {
            crl->flags |= EXFLAG_INVALID;
            return 1;
        }

        if (gtmp) {
            gens = gtmp;
            if (!crl->issuers) {
                crl->issuers = sk_GENERAL_NAMES_new_null();
                if (!crl->issuers)
                    return 0;
            }
            if (!sk_GENERAL_NAMES_push(crl->issuers, gtmp))
                return 0;
        }
        rev->issuer = gens;

        reason = X509_REVOKED_get_ext_d2i(rev, NID_crl_reason, &j, NULL);
        if (!reason && (j != -1)) {
            crl->flags |= EXFLAG_INVALID;
            return 1;
        }

        if (reason) {
            rev->reason = ASN1_ENUMERATED_get(reason);
            ASN1_ENUMERATED_free(reason);
        } else
            rev->reason = CRL_REASON_NONE;

        /* Check for critical CRL entry extensions */

        exts = rev->extensions;

        for (j = 0; j < sk_X509_EXTENSION_num(exts); j++) {
            ext = sk_X509_EXTENSION_value(exts, j);
            if (ext->critical > 0) {
                if (OBJ_obj2nid(ext->object) == NID_certificate_issuer)
                    continue;
                crl->flags |= EXFLAG_CRITICAL;
                break;
            }
        }

    }

    return 1;

}

/*
 * The X509_CRL structure needs a bit of customisation. Cache some extensions
 * and hash of the whole CRL.
 */
static int crl_cb(int operation, ASN1_VALUE **pval, const ASN1_ITEM *it,
                  void *exarg)
{
    X509_CRL *crl = (X509_CRL *)*pval;
    STACK_OF(X509_EXTENSION) *exts;
    X509_EXTENSION *ext;
    int idx;

    switch (operation) {
    case ASN1_OP_NEW_POST:
        crl->idp = NULL;
        crl->akid = NULL;
        crl->flags = 0;
        crl->idp_flags = 0;
        crl->idp_reasons = CRLDP_ALL_REASONS;
        crl->meth = default_crl_method;
        crl->meth_data = NULL;
        crl->issuers = NULL;
        crl->crl_number = NULL;
        crl->base_crl_number = NULL;
        break;

    case ASN1_OP_D2I_POST:
#ifndef OPENSSL_NO_SHA
        X509_CRL_digest(crl, EVP_sha1(), crl->sha1_hash, NULL);
#endif
        crl->idp = X509_CRL_get_ext_d2i(crl,
                                        NID_issuing_distribution_point, NULL,
                                        NULL);
        if (crl->idp)
            setup_idp(crl, crl->idp);

        crl->akid = X509_CRL_get_ext_d2i(crl,
                                         NID_authority_key_identifier, NULL,
                                         NULL);

        crl->crl_number = X509_CRL_get_ext_d2i(crl,
                                               NID_crl_number, NULL, NULL);

        crl->base_crl_number = X509_CRL_get_ext_d2i(crl,
                                                    NID_delta_crl, NULL,
                                                    NULL);
        /* Delta CRLs must have CRL number */
        if (crl->base_crl_number && !crl->crl_number)
            crl->flags |= EXFLAG_INVALID;

        /*
         * See if we have any unhandled critical CRL extensions and indicate
         * this in a flag. We only currently handle IDP so anything else
         * critical sets the flag. This code accesses the X509_CRL structure
         * directly: applications shouldn't do this.
         */

        exts = crl->crl->extensions;

        for (idx = 0; idx < sk_X509_EXTENSION_num(exts); idx++) {
            int nid;

            ext = sk_X509_EXTENSION_value(exts, idx);
            nid = OBJ_obj2nid(ext->object);
            if (nid == NID_freshest_crl)
                crl->flags |= EXFLAG_FRESHEST;
            if (ext->critical > 0) {
                /* We handle IDP and deltas */
                if ((nid == NID_issuing_distribution_point)
                    || (nid == NID_authority_key_identifier)
                    || (nid == NID_delta_crl))
                    continue;
                crl->flags |= EXFLAG_CRITICAL;
                break;
            }
        }

        if (!crl_set_issuers(crl))
            return 0;

        if (crl->meth->crl_init) {
            if (crl->meth->crl_init(crl) == 0)
                return 0;
        }
        break;

    case ASN1_OP_FREE_POST:
        if (crl->meth->crl_free) {
            if (!crl->meth->crl_free(crl))
                return 0;
        }
        if (crl->akid)
            AUTHORITY_KEYID_free(crl->akid);
        if (crl->idp)
            ISSUING_DIST_POINT_free(crl->idp);
        ASN1_INTEGER_free(crl->crl_number);
        ASN1_INTEGER_free(crl->base_crl_number);
        sk_GENERAL_NAMES_pop_free(crl->issuers, GENERAL_NAMES_free);
        break;
    }
    return 1;
}

/* Convert IDP into a more convenient form */

static void setup_idp(X509_CRL *crl, ISSUING_DIST_POINT *idp)
{
    int idp_only = 0;
    /* Set various flags according to IDP */
    crl->idp_flags |= IDP_PRESENT;
    if (idp->onlyuser > 0) {
        idp_only++;
        crl->idp_flags |= IDP_ONLYUSER;
    }
    if (idp->onlyCA > 0) {
        idp_only++;
        crl->idp_flags |= IDP_ONLYCA;
    }
    if (idp->onlyattr > 0) {
        idp_only++;
        crl->idp_flags |= IDP_ONLYATTR;
    }

    if (idp_only > 1)
        crl->idp_flags |= IDP_INVALID;

    if (idp->indirectCRL > 0)
        crl->idp_flags |= IDP_INDIRECT;

    if (idp->onlysomereasons) {
        crl->idp_flags |= IDP_REASONS;
        if (idp->onlysomereasons->length > 0)
            crl->idp_reasons = idp->onlysomereasons->data[0];
        if (idp->onlysomereasons->length > 1)
            crl->idp_reasons |= (idp->onlysomereasons->data[1] << 8);
        crl->idp_reasons &= CRLDP_ALL_REASONS;
    }

    DIST_POINT_set_dpname(idp->distpoint, X509_CRL_get_issuer(crl));
}

ASN1_SEQUENCE_ref(X509_CRL, crl_cb, CRYPTO_LOCK_X509_CRL) = {
        ASN1_SIMPLE(X509_CRL, crl, X509_CRL_INFO),
        ASN1_SIMPLE(X509_CRL, sig_alg, X509_ALGOR),
        ASN1_SIMPLE(X509_CRL, signature, ASN1_BIT_STRING)
} ASN1_SEQUENCE_END_ref(X509_CRL, X509_CRL)

IMPLEMENT_ASN1_FUNCTIONS(X509_REVOKED)

IMPLEMENT_ASN1_DUP_FUNCTION(X509_REVOKED)

IMPLEMENT_ASN1_FUNCTIONS(X509_CRL_INFO)

IMPLEMENT_ASN1_FUNCTIONS(X509_CRL)

IMPLEMENT_ASN1_DUP_FUNCTION(X509_CRL)

static int X509_REVOKED_cmp(const X509_REVOKED *const *a,
                            const X509_REVOKED *const *b)
{
    return (ASN1_STRING_cmp((ASN1_STRING *)(*a)->serialNumber,
                            (ASN1_STRING *)(*b)->serialNumber));
}

int X509_CRL_add0_revoked(X509_CRL *crl, X509_REVOKED *rev)
{
    X509_CRL_INFO *inf;
    inf = crl->crl;
    if (!inf->revoked)
        inf->revoked = sk_X509_REVOKED_new(X509_REVOKED_cmp);
    if (!inf->revoked || !sk_X509_REVOKED_push(inf->revoked, rev)) {
        ASN1err(ASN1_F_X509_CRL_ADD0_REVOKED, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    inf->enc.modified = 1;
    return 1;
}

int X509_CRL_verify(X509_CRL *crl, EVP_PKEY *r)
{
    if (crl->meth->crl_verify)
        return crl->meth->crl_verify(crl, r);
    return 0;
}

int X509_CRL_get0_by_serial(X509_CRL *crl,
                            X509_REVOKED **ret, ASN1_INTEGER *serial)
{
    if (crl->meth->crl_lookup)
        return crl->meth->crl_lookup(crl, ret, serial, NULL);
    return 0;
}

int X509_CRL_get0_by_cert(X509_CRL *crl, X509_REVOKED **ret, X509 *x)
{
    if (crl->meth->crl_lookup)
        return crl->meth->crl_lookup(crl, ret,
                                     X509_get_serialNumber(x),
                                     X509_get_issuer_name(x));
    return 0;
}

static int def_crl_verify(X509_CRL *crl, EVP_PKEY *r)
{
    return (ASN1_item_verify(ASN1_ITEM_rptr(X509_CRL_INFO),
                             crl->sig_alg, crl->signature, crl->crl, r));
}

static int crl_revoked_issuer_match(X509_CRL *crl, X509_NAME *nm,
                                    X509_REVOKED *rev)
{
    int i;

    if (!rev->issuer) {
        if (!nm)
            return 1;
        if (!X509_NAME_cmp(nm, X509_CRL_get_issuer(crl)))
            return 1;
        return 0;
    }

    if (!nm)
        nm = X509_CRL_get_issuer(crl);

    for (i = 0; i < sk_GENERAL_NAME_num(rev->issuer); i++) {
        GENERAL_NAME *gen = sk_GENERAL_NAME_value(rev->issuer, i);
        if (gen->type != GEN_DIRNAME)
            continue;
        if (!X509_NAME_cmp(nm, gen->d.directoryName))
            return 1;
    }
    return 0;

}

static int def_crl_lookup(X509_CRL *crl,
                          X509_REVOKED **ret, ASN1_INTEGER *serial,
                          X509_NAME *issuer)
{
    X509_REVOKED rtmp, *rev;
    int idx;
    rtmp.serialNumber = serial;
    /*
     * Sort revoked into serial number order if not already sorted. Do this
     * under a lock to avoid race condition.
     */
    if (!sk_X509_REVOKED_is_sorted(crl->crl->revoked)) {
        CRYPTO_w_lock(CRYPTO_LOCK_X509_CRL);
        sk_X509_REVOKED_sort(crl->crl->revoked);
        CRYPTO_w_unlock(CRYPTO_LOCK_X509_CRL);
    }
    idx = sk_X509_REVOKED_find(crl->crl->revoked, &rtmp);
    if (idx < 0)
        return 0;
    /* Need to look for matching name */
    for (; idx < sk_X509_REVOKED_num(crl->crl->revoked); idx++) {
        rev = sk_X509_REVOKED_value(crl->crl->revoked, idx);
        if (ASN1_INTEGER_cmp(rev->serialNumber, serial))
            return 0;
        if (crl_revoked_issuer_match(crl, issuer, rev)) {
            if (ret)
                *ret = rev;
            if (rev->reason == CRL_REASON_REMOVE_FROM_CRL)
                return 2;
            return 1;
        }
    }
    return 0;
}

void X509_CRL_set_default_method(const X509_CRL_METHOD *meth)
{
    if (meth == NULL)
        default_crl_method = &int_crl_meth;
    else
        default_crl_method = meth;
}

X509_CRL_METHOD *X509_CRL_METHOD_new(int (*crl_init) (X509_CRL *crl),
                                     int (*crl_free) (X509_CRL *crl),
                                     int (*crl_lookup) (X509_CRL *crl,
                                                        X509_REVOKED **ret,
                                                        ASN1_INTEGER *ser,
                                                        X509_NAME *issuer),
                                     int (*crl_verify) (X509_CRL *crl,
                                                        EVP_PKEY *pk))
{
    X509_CRL_METHOD *m;
    m = OPENSSL_malloc(sizeof(X509_CRL_METHOD));
    if (!m)
        return NULL;
    m->crl_init = crl_init;
    m->crl_free = crl_free;
    m->crl_lookup = crl_lookup;
    m->crl_verify = crl_verify;
    m->flags = X509_CRL_METHOD_DYNAMIC;
    return m;
}

void X509_CRL_METHOD_free(X509_CRL_METHOD *m)
{
    if (!(m->flags & X509_CRL_METHOD_DYNAMIC))
        return;
    OPENSSL_free(m);
}

void X509_CRL_set_meth_data(X509_CRL *crl, void *dat)
{
    crl->meth_data = dat;
}

void *X509_CRL_get_meth_data(X509_CRL *crl)
{
    return crl->meth_data;
}

IMPLEMENT_STACK_OF(X509_REVOKED)

IMPLEMENT_ASN1_SET_OF(X509_REVOKED)

IMPLEMENT_STACK_OF(X509_CRL)

IMPLEMENT_ASN1_SET_OF(X509_CRL)
/* x_exten.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 2000.
 */
/* ====================================================================
 * Copyright (c) 2000 The OpenSSL Project.  All rights reserved.
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

#include <stddef.h>
// #include "x509.h"
// #include "asn1.h"
// #include "asn1t.h"

ASN1_SEQUENCE(X509_EXTENSION) = {
        ASN1_SIMPLE(X509_EXTENSION, object, ASN1_OBJECT),
        ASN1_OPT(X509_EXTENSION, critical, ASN1_BOOLEAN),
        ASN1_SIMPLE(X509_EXTENSION, value, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(X509_EXTENSION)

ASN1_ITEM_TEMPLATE(X509_EXTENSIONS) =
        ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SEQUENCE_OF, 0, Extension, X509_EXTENSION)
ASN1_ITEM_TEMPLATE_END(X509_EXTENSIONS)

IMPLEMENT_ASN1_FUNCTIONS(X509_EXTENSION)
IMPLEMENT_ASN1_ENCODE_FUNCTIONS_fname(X509_EXTENSIONS, X509_EXTENSIONS, X509_EXTENSIONS)
IMPLEMENT_ASN1_DUP_FUNCTION(X509_EXTENSION)
/* crypto/asn1/x_info.c */
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
// #include "asn1.h"
// #include "x509.h"

X509_INFO *X509_INFO_new(void)
{
    X509_INFO *ret = NULL;

    ret = (X509_INFO *)OPENSSL_malloc(sizeof(X509_INFO));
    if (ret == NULL) {
        ASN1err(ASN1_F_X509_INFO_NEW, ERR_R_MALLOC_FAILURE);
        return (NULL);
    }

    ret->enc_cipher.cipher = NULL;
    ret->enc_len = 0;
    ret->enc_data = NULL;

    ret->references = 1;
    ret->x509 = NULL;
    ret->crl = NULL;
    ret->x_pkey = NULL;
    return (ret);
}

void X509_INFO_free(X509_INFO *x)
{
    int i;

    if (x == NULL)
        return;

    i = CRYPTO_add(&x->references, -1, CRYPTO_LOCK_X509_INFO);
#ifdef REF_PRINT
    REF_PRINT("X509_INFO", x);
#endif
    if (i > 0)
        return;
#ifdef REF_CHECK
    if (i < 0) {
        fprintf(stderr, "X509_INFO_free, bad reference count\n");
        abort();
    }
#endif

    if (x->x509 != NULL)
        X509_free(x->x509);
    if (x->crl != NULL)
        X509_CRL_free(x->crl);
    if (x->x_pkey != NULL)
        X509_PKEY_free(x->x_pkey);
    if (x->enc_data != NULL)
        OPENSSL_free(x->enc_data);
    OPENSSL_free(x);
}

IMPLEMENT_STACK_OF(X509_INFO)
/* x_long.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 2000.
 */
/* ====================================================================
 * Copyright (c) 2000 The OpenSSL Project.  All rights reserved.
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
// #include "bn.h"

/*
 * Custom primitive type for long handling. This converts between an
 * ASN1_INTEGER and a long directly.
 */

static int long_new(ASN1_VALUE **pval, const ASN1_ITEM *it);
static void long_free(ASN1_VALUE **pval, const ASN1_ITEM *it);

static int long_i2c(ASN1_VALUE **pval, unsigned char *cont, int *putype,
                    const ASN1_ITEM *it);
static int long_c2i(ASN1_VALUE **pval, const unsigned char *cont, int len,
                    int utype, char *free_cont, const ASN1_ITEM *it);
static int long_print(BIO *out, ASN1_VALUE **pval, const ASN1_ITEM *it,
                      int indent, const ASN1_PCTX *pctx);

static ASN1_PRIMITIVE_FUNCS long_pf = {
    NULL, 0,
    long_new,
    long_free,
    long_free,                  /* Clear should set to initial value */
    long_c2i,
    long_i2c,
    long_print
};

ASN1_ITEM_start(LONG)
        ASN1_ITYPE_PRIMITIVE, V_ASN1_INTEGER, NULL, 0, &long_pf, ASN1_LONG_UNDEF, "LONG"
ASN1_ITEM_end(LONG)

ASN1_ITEM_start(ZLONG)
        ASN1_ITYPE_PRIMITIVE, V_ASN1_INTEGER, NULL, 0, &long_pf, 0, "ZLONG"
ASN1_ITEM_end(ZLONG)

static int long_new(ASN1_VALUE **pval, const ASN1_ITEM *it)
{
    *(long *)pval = it->size;
    return 1;
}

static void long_free(ASN1_VALUE **pval, const ASN1_ITEM *it)
{
    *(long *)pval = it->size;
}

static int long_i2c(ASN1_VALUE **pval, unsigned char *cont, int *putype,
                    const ASN1_ITEM *it)
{
    long ltmp;
    unsigned long utmp;
    int clen, pad, i;
    /* this exists to bypass broken gcc optimization */
    char *cp = (char *)pval;

    /* use memcpy, because we may not be long aligned */
    memcpy(&ltmp, cp, sizeof(long));

    if (ltmp == it->size)
        return -1;
    /*
     * Convert the long to positive: we subtract one if negative so we can
     * cleanly handle the padding if only the MSB of the leading octet is
     * set.
     */
    if (ltmp < 0)
        utmp = 0 - (unsigned long)ltmp - 1;
    else
        utmp = ltmp;
    clen = BN_num_bits_word(utmp);
    /* If MSB of leading octet set we need to pad */
    if (!(clen & 0x7))
        pad = 1;
    else
        pad = 0;

    /* Convert number of bits to number of octets */
    clen = (clen + 7) >> 3;

    if (cont) {
        if (pad)
            *cont++ = (ltmp < 0) ? 0xff : 0;
        for (i = clen - 1; i >= 0; i--) {
            cont[i] = (unsigned char)(utmp & 0xff);
            if (ltmp < 0)
                cont[i] ^= 0xff;
            utmp >>= 8;
        }
    }
    return clen + pad;
}

static int long_c2i(ASN1_VALUE **pval, const unsigned char *cont, int len,
                    int utype, char *free_cont, const ASN1_ITEM *it)
{
    int neg = -1, i;
    long ltmp;
    unsigned long utmp = 0;
    char *cp = (char *)pval;

    if (len) {
        /*
         * Check possible pad byte.  Worst case, we're skipping past actual
         * content, but since that's only with 0x00 and 0xff and we set neg
         * accordingly, the result will be correct in the end anyway.
         */
        switch (cont[0]) {
        case 0xff:
            cont++;
            len--;
            neg = 1;
            break;
        case 0:
            cont++;
            len--;
            neg = 0;
            break;
        }
    }
    if (len > (int)sizeof(long)) {
        ASN1err(ASN1_F_LONG_C2I, ASN1_R_INTEGER_TOO_LARGE_FOR_LONG);
        return 0;
    }
    if (neg == -1) {
        /* Is it negative? */
        if (len && (cont[0] & 0x80))
            neg = 1;
        else
            neg = 0;
    }
    utmp = 0;
    for (i = 0; i < len; i++) {
        utmp <<= 8;
        if (neg)
            utmp |= cont[i] ^ 0xff;
        else
            utmp |= cont[i];
    }
    ltmp = (long)utmp;
    if (neg) {
        ltmp = -ltmp;
        ltmp--;
    }
    if (ltmp == it->size) {
        ASN1err(ASN1_F_LONG_C2I, ASN1_R_INTEGER_TOO_LARGE_FOR_LONG);
        return 0;
    }
    memcpy(cp, &ltmp, sizeof(long));
    return 1;
}

static int long_print(BIO *out, ASN1_VALUE **pval, const ASN1_ITEM *it,
                      int indent, const ASN1_PCTX *pctx)
{
    return BIO_printf(out, "%ld\n", *(long *)pval);
}
/* crypto/asn1/x_name.c */
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
#include <ctype.h>
// #include "cryptlib.h"
// #include "asn1t.h"
// #include "x509.h"
// #include "asn1_locl.h"

typedef STACK_OF(X509_NAME_ENTRY) STACK_OF_X509_NAME_ENTRY;
DECLARE_STACK_OF(STACK_OF_X509_NAME_ENTRY)

/*
 * Maximum length of X509_NAME: much larger than anything we should
 * ever see in practice.
 */

#define X509_NAME_MAX (1024 * 1024)

static int x509_name_ex_d2i(ASN1_VALUE **val,
                            const unsigned char **in, long len,
                            const ASN1_ITEM *it,
                            int tag, int aclass, char opt, ASN1_TLC *ctx);

static int x509_name_ex_i2d(ASN1_VALUE **val, unsigned char **out,
                            const ASN1_ITEM *it, int tag, int aclass);
static int x509_name_ex_new(ASN1_VALUE **val, const ASN1_ITEM *it);
static void x509_name_ex_free(ASN1_VALUE **val, const ASN1_ITEM *it);

static int x509_name_encode(X509_NAME *a);
static int x509_name_canon(X509_NAME *a);
static int asn1_string_canon(ASN1_STRING *out, ASN1_STRING *in);
static int i2d_name_canon(STACK_OF(STACK_OF_X509_NAME_ENTRY) * intname,
                          unsigned char **in);

static int x509_name_ex_print(BIO *out, ASN1_VALUE **pval,
                              int indent,
                              const char *fname, const ASN1_PCTX *pctx);

ASN1_SEQUENCE(X509_NAME_ENTRY) = {
        ASN1_SIMPLE(X509_NAME_ENTRY, object, ASN1_OBJECT),
        ASN1_SIMPLE(X509_NAME_ENTRY, value, ASN1_PRINTABLE)
} ASN1_SEQUENCE_END(X509_NAME_ENTRY)

IMPLEMENT_ASN1_FUNCTIONS(X509_NAME_ENTRY)
IMPLEMENT_ASN1_DUP_FUNCTION(X509_NAME_ENTRY)

/*
 * For the "Name" type we need a SEQUENCE OF { SET OF X509_NAME_ENTRY } so
 * declare two template wrappers for this
 */

ASN1_ITEM_TEMPLATE(X509_NAME_ENTRIES) =
        ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SET_OF, 0, RDNS, X509_NAME_ENTRY)
ASN1_ITEM_TEMPLATE_END(X509_NAME_ENTRIES)

ASN1_ITEM_TEMPLATE(X509_NAME_INTERNAL) =
        ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SEQUENCE_OF, 0, Name, X509_NAME_ENTRIES)
ASN1_ITEM_TEMPLATE_END(X509_NAME_INTERNAL)

/*
 * Normally that's where it would end: we'd have two nested STACK structures
 * representing the ASN1. Unfortunately X509_NAME uses a completely different
 * form and caches encodings so we have to process the internal form and
 * convert to the external form.
 */

const ASN1_EXTERN_FUNCS x509_name_ff = {
    NULL,
    x509_name_ex_new,
    x509_name_ex_free,
    0,                          /* Default clear behaviour is OK */
    x509_name_ex_d2i,
    x509_name_ex_i2d,
    x509_name_ex_print
};

IMPLEMENT_EXTERN_ASN1(X509_NAME, V_ASN1_SEQUENCE, x509_name_ff)

IMPLEMENT_ASN1_FUNCTIONS(X509_NAME)

IMPLEMENT_ASN1_DUP_FUNCTION(X509_NAME)

static int x509_name_ex_new(ASN1_VALUE **val, const ASN1_ITEM *it)
{
    X509_NAME *ret = NULL;
    ret = OPENSSL_malloc(sizeof(X509_NAME));
    if (!ret)
        goto memerr;
    if ((ret->entries = sk_X509_NAME_ENTRY_new_null()) == NULL)
        goto memerr;
    if ((ret->bytes = BUF_MEM_new()) == NULL)
        goto memerr;
    ret->canon_enc = NULL;
    ret->canon_enclen = 0;
    ret->modified = 1;
    *val = (ASN1_VALUE *)ret;
    return 1;

 memerr:
    ASN1err(ASN1_F_X509_NAME_EX_NEW, ERR_R_MALLOC_FAILURE);
    if (ret) {
        if (ret->entries)
            sk_X509_NAME_ENTRY_free(ret->entries);
        OPENSSL_free(ret);
    }
    return 0;
}

static void x509_name_ex_free(ASN1_VALUE **pval, const ASN1_ITEM *it)
{
    X509_NAME *a;
    if (!pval || !*pval)
        return;
    a = (X509_NAME *)*pval;

    BUF_MEM_free(a->bytes);
    sk_X509_NAME_ENTRY_pop_free(a->entries, X509_NAME_ENTRY_free);
    if (a->canon_enc)
        OPENSSL_free(a->canon_enc);
    OPENSSL_free(a);
    *pval = NULL;
}

static void local_sk_X509_NAME_ENTRY_free(STACK_OF(X509_NAME_ENTRY) *ne)
{
    sk_X509_NAME_ENTRY_free(ne);
}

static void local_sk_X509_NAME_ENTRY_pop_free(STACK_OF(X509_NAME_ENTRY) *ne)
{
    sk_X509_NAME_ENTRY_pop_free(ne, X509_NAME_ENTRY_free);
}

static int x509_name_ex_d2i(ASN1_VALUE **val,
                            const unsigned char **in, long len,
                            const ASN1_ITEM *it, int tag, int aclass,
                            char opt, ASN1_TLC *ctx)
{
    const unsigned char *p = *in, *q;
    union {
        STACK_OF(STACK_OF_X509_NAME_ENTRY) *s;
        ASN1_VALUE *a;
    } intname = {
        NULL
    };
    union {
        X509_NAME *x;
        ASN1_VALUE *a;
    } nm = {
        NULL
    };
    int i, j, ret;
    STACK_OF(X509_NAME_ENTRY) *entries;
    X509_NAME_ENTRY *entry;
    if (len > X509_NAME_MAX)
        len = X509_NAME_MAX;
    q = p;

    /* Get internal representation of Name */
    ret = ASN1_item_ex_d2i(&intname.a,
                           &p, len, ASN1_ITEM_rptr(X509_NAME_INTERNAL),
                           tag, aclass, opt, ctx);

    if (ret <= 0)
        return ret;

    if (*val)
        x509_name_ex_free(val, NULL);
    if (!x509_name_ex_new(&nm.a, NULL))
        goto err;
    /* We've decoded it: now cache encoding */
    if (!BUF_MEM_grow(nm.x->bytes, p - q))
        goto err;
    memcpy(nm.x->bytes->data, q, p - q);

    /* Convert internal representation to X509_NAME structure */
    for (i = 0; i < sk_STACK_OF_X509_NAME_ENTRY_num(intname.s); i++) {
        entries = sk_STACK_OF_X509_NAME_ENTRY_value(intname.s, i);
        for (j = 0; j < sk_X509_NAME_ENTRY_num(entries); j++) {
            entry = sk_X509_NAME_ENTRY_value(entries, j);
            entry->set = i;
            if (!sk_X509_NAME_ENTRY_push(nm.x->entries, entry))
                goto err;
            sk_X509_NAME_ENTRY_set(entries, j, NULL);
        }
    }
    ret = x509_name_canon(nm.x);
    if (!ret)
        goto err;
    sk_STACK_OF_X509_NAME_ENTRY_pop_free(intname.s,
                                         local_sk_X509_NAME_ENTRY_free);
    nm.x->modified = 0;
    *val = nm.a;
    *in = p;
    return ret;
 err:
    if (nm.x != NULL)
        X509_NAME_free(nm.x);
    sk_STACK_OF_X509_NAME_ENTRY_pop_free(intname.s,
                                         local_sk_X509_NAME_ENTRY_pop_free);
    ASN1err(ASN1_F_X509_NAME_EX_D2I, ERR_R_NESTED_ASN1_ERROR);
    return 0;
}

static int x509_name_ex_i2d(ASN1_VALUE **val, unsigned char **out,
                            const ASN1_ITEM *it, int tag, int aclass)
{
    int ret;
    X509_NAME *a = (X509_NAME *)*val;
    if (a->modified) {
        ret = x509_name_encode(a);
        if (ret < 0)
            return ret;
        ret = x509_name_canon(a);
        if (ret < 0)
            return ret;
    }
    ret = a->bytes->length;
    if (out != NULL) {
        memcpy(*out, a->bytes->data, ret);
        *out += ret;
    }
    return ret;
}

static int x509_name_encode(X509_NAME *a)
{
    union {
        STACK_OF(STACK_OF_X509_NAME_ENTRY) *s;
        ASN1_VALUE *a;
    } intname = {
        NULL
    };
    int len;
    unsigned char *p;
    STACK_OF(X509_NAME_ENTRY) *entries = NULL;
    X509_NAME_ENTRY *entry;
    int i, set = -1;
    intname.s = sk_STACK_OF_X509_NAME_ENTRY_new_null();
    if (!intname.s)
        goto memerr;
    for (i = 0; i < sk_X509_NAME_ENTRY_num(a->entries); i++) {
        entry = sk_X509_NAME_ENTRY_value(a->entries, i);
        if (entry->set != set) {
            entries = sk_X509_NAME_ENTRY_new_null();
            if (!entries)
                goto memerr;
            if (!sk_STACK_OF_X509_NAME_ENTRY_push(intname.s, entries)) {
                sk_X509_NAME_ENTRY_free(entries);
                goto memerr;
            }
            set = entry->set;
        }
        if (!sk_X509_NAME_ENTRY_push(entries, entry))
            goto memerr;
    }
    len = ASN1_item_ex_i2d(&intname.a, NULL,
                           ASN1_ITEM_rptr(X509_NAME_INTERNAL), -1, -1);
    if (!BUF_MEM_grow(a->bytes, len))
        goto memerr;
    p = (unsigned char *)a->bytes->data;
    ASN1_item_ex_i2d(&intname.a,
                     &p, ASN1_ITEM_rptr(X509_NAME_INTERNAL), -1, -1);
    sk_STACK_OF_X509_NAME_ENTRY_pop_free(intname.s,
                                         local_sk_X509_NAME_ENTRY_free);
    a->modified = 0;
    return len;
 memerr:
    sk_STACK_OF_X509_NAME_ENTRY_pop_free(intname.s,
                                         local_sk_X509_NAME_ENTRY_free);
    ASN1err(ASN1_F_X509_NAME_ENCODE, ERR_R_MALLOC_FAILURE);
    return -1;
}

static int x509_name_ex_print(BIO *out, ASN1_VALUE **pval,
                              int indent,
                              const char *fname, const ASN1_PCTX *pctx)
{
    if (X509_NAME_print_ex(out, (X509_NAME *)*pval,
                           indent, pctx->nm_flags) <= 0)
        return 0;
    return 2;
}

/*
 * This function generates the canonical encoding of the Name structure. In
 * it all strings are converted to UTF8, leading, trailing and multiple
 * spaces collapsed, converted to lower case and the leading SEQUENCE header
 * removed. In future we could also normalize the UTF8 too. By doing this
 * comparison of Name structures can be rapidly perfomed by just using
 * memcmp() of the canonical encoding. By omitting the leading SEQUENCE name
 * constraints of type dirName can also be checked with a simple memcmp().
 */

static int x509_name_canon(X509_NAME *a)
{
    unsigned char *p;
    STACK_OF(STACK_OF_X509_NAME_ENTRY) *intname = NULL;
    STACK_OF(X509_NAME_ENTRY) *entries = NULL;
    X509_NAME_ENTRY *entry, *tmpentry = NULL;
    int i, set = -1, ret = 0;

    if (a->canon_enc) {
        OPENSSL_free(a->canon_enc);
        a->canon_enc = NULL;
    }
    /* Special case: empty X509_NAME => null encoding */
    if (sk_X509_NAME_ENTRY_num(a->entries) == 0) {
        a->canon_enclen = 0;
        return 1;
    }
    intname = sk_STACK_OF_X509_NAME_ENTRY_new_null();
    if (!intname)
        goto err;
    for (i = 0; i < sk_X509_NAME_ENTRY_num(a->entries); i++) {
        entry = sk_X509_NAME_ENTRY_value(a->entries, i);
        if (entry->set != set) {
            entries = sk_X509_NAME_ENTRY_new_null();
            if (!entries)
                goto err;
            if (!sk_STACK_OF_X509_NAME_ENTRY_push(intname, entries)) {
                sk_X509_NAME_ENTRY_free(entries);
                goto err;
            }
            set = entry->set;
        }
        tmpentry = X509_NAME_ENTRY_new();
        if (!tmpentry)
            goto err;
        tmpentry->object = OBJ_dup(entry->object);
        if (!asn1_string_canon(tmpentry->value, entry->value))
            goto err;
        if (!sk_X509_NAME_ENTRY_push(entries, tmpentry))
            goto err;
        tmpentry = NULL;
    }

    /* Finally generate encoding */

    a->canon_enclen = i2d_name_canon(intname, NULL);

    p = OPENSSL_malloc(a->canon_enclen);

    if (!p)
        goto err;

    a->canon_enc = p;

    i2d_name_canon(intname, &p);

    ret = 1;

 err:

    if (tmpentry)
        X509_NAME_ENTRY_free(tmpentry);
    if (intname)
        sk_STACK_OF_X509_NAME_ENTRY_pop_free(intname,
                                             local_sk_X509_NAME_ENTRY_pop_free);
    return ret;
}

/* Bitmap of all the types of string that will be canonicalized. */

#define ASN1_MASK_CANON \
        (B_ASN1_UTF8STRING | B_ASN1_BMPSTRING | B_ASN1_UNIVERSALSTRING \
        | B_ASN1_PRINTABLESTRING | B_ASN1_T61STRING | B_ASN1_IA5STRING \
        | B_ASN1_VISIBLESTRING)

static int asn1_string_canon(ASN1_STRING *out, ASN1_STRING *in)
{
    unsigned char *to, *from;
    int len, i;

    /* If type not in bitmask just copy string across */
    if (!(ASN1_tag2bit(in->type) & ASN1_MASK_CANON)) {
        if (!ASN1_STRING_copy(out, in))
            return 0;
        return 1;
    }

    out->type = V_ASN1_UTF8STRING;
    out->length = ASN1_STRING_to_UTF8(&out->data, in);
    if (out->length == -1)
        return 0;

    to = out->data;
    from = to;

    len = out->length;

    /*
     * Convert string in place to canonical form. Ultimately we may need to
     * handle a wider range of characters but for now ignore anything with
     * MSB set and rely on the isspace() and tolower() functions.
     */

    /* Ignore leading spaces */
    while ((len > 0) && !(*from & 0x80) && isspace(*from)) {
        from++;
        len--;
    }

    to = from + len - 1;

    /* Ignore trailing spaces */
    while ((len > 0) && !(*to & 0x80) && isspace(*to)) {
        to--;
        len--;
    }

    to = out->data;

    i = 0;
    while (i < len) {
        /* If MSB set just copy across */
        if (*from & 0x80) {
            *to++ = *from++;
            i++;
        }
        /* Collapse multiple spaces */
        else if (isspace(*from)) {
            /* Copy one space across */
            *to++ = ' ';
            /*
             * Ignore subsequent spaces. Note: don't need to check len here
             * because we know the last character is a non-space so we can't
             * overflow.
             */
            do {
                from++;
                i++;
            }
            while (!(*from & 0x80) && isspace(*from));
        } else {
            *to++ = tolower(*from);
            from++;
            i++;
        }
    }

    out->length = to - out->data;

    return 1;

}

static int i2d_name_canon(STACK_OF(STACK_OF_X509_NAME_ENTRY) * _intname,
                          unsigned char **in)
{
    int i, len, ltmp;
    ASN1_VALUE *v;
    STACK_OF(ASN1_VALUE) *intname = (STACK_OF(ASN1_VALUE) *)_intname;

    len = 0;
    for (i = 0; i < sk_ASN1_VALUE_num(intname); i++) {
        v = sk_ASN1_VALUE_value(intname, i);
        ltmp = ASN1_item_ex_i2d(&v, in,
                                ASN1_ITEM_rptr(X509_NAME_ENTRIES), -1, -1);
        if (ltmp < 0)
            return ltmp;
        len += ltmp;
    }
    return len;
}

int X509_NAME_set(X509_NAME **xn, X509_NAME *name)
{
    if ((name = X509_NAME_dup(name)) == NULL)
        return 0;
    X509_NAME_free(*xn);
    *xn = name;
    return 1;
}

IMPLEMENT_STACK_OF(X509_NAME_ENTRY)

IMPLEMENT_ASN1_SET_OF(X509_NAME_ENTRY)
/* x_nx509.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 2005.
 */
/* ====================================================================
 * Copyright (c) 2005 The OpenSSL Project.  All rights reserved.
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

#include <stddef.h>
// #include "x509.h"
// #include "asn1.h"
// #include "asn1t.h"

/* Old netscape certificate wrapper format */

ASN1_SEQUENCE(NETSCAPE_X509) = {
        ASN1_SIMPLE(NETSCAPE_X509, header, ASN1_OCTET_STRING),
        ASN1_OPT(NETSCAPE_X509, cert, X509)
} ASN1_SEQUENCE_END(NETSCAPE_X509)

IMPLEMENT_ASN1_FUNCTIONS(NETSCAPE_X509)
/* crypto/asn1/x_pkey.c */
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
#include "asn1_mac.h"
// #include "x509.h"

/* need to implement */
int i2d_X509_PKEY(X509_PKEY *a, unsigned char **pp)
{
    return (0);
}

X509_PKEY *d2i_X509_PKEY(X509_PKEY **a, const unsigned char **pp, long length)
{
    int i;
    M_ASN1_D2I_vars(a, X509_PKEY *, X509_PKEY_new);

    M_ASN1_D2I_Init();
    M_ASN1_D2I_start_sequence();
    M_ASN1_D2I_get_x(X509_ALGOR, ret->enc_algor, d2i_X509_ALGOR);
    M_ASN1_D2I_get_x(ASN1_OCTET_STRING, ret->enc_pkey, d2i_ASN1_OCTET_STRING);

    ret->cipher.cipher =
        EVP_get_cipherbyname(OBJ_nid2ln
                             (OBJ_obj2nid(ret->enc_algor->algorithm)));
    if (ret->cipher.cipher == NULL) {
        c.error = ASN1_R_UNSUPPORTED_CIPHER;
        c.line = __LINE__;
        goto err;
    }
    if (ret->enc_algor->parameter->type == V_ASN1_OCTET_STRING) {
        i = ret->enc_algor->parameter->value.octet_string->length;
        if (i > EVP_MAX_IV_LENGTH) {
            c.error = ASN1_R_IV_TOO_LARGE;
            c.line = __LINE__;
            goto err;
        }
        memcpy(ret->cipher.iv,
               ret->enc_algor->parameter->value.octet_string->data, i);
    } else
        memset(ret->cipher.iv, 0, EVP_MAX_IV_LENGTH);
    M_ASN1_D2I_Finish(a, X509_PKEY_free, ASN1_F_D2I_X509_PKEY);
}

X509_PKEY *X509_PKEY_new(void)
{
    X509_PKEY *ret = NULL;
    ASN1_CTX c;

    ret = OPENSSL_malloc(sizeof(X509_PKEY));
    if (ret == NULL) {
        c.line = __LINE__;
        goto err;
    }
    ret->version = 0;
    ret->enc_algor = X509_ALGOR_new();
    ret->enc_pkey = M_ASN1_OCTET_STRING_new();
    ret->dec_pkey = NULL;
    ret->key_length = 0;
    ret->key_data = NULL;
    ret->key_free = 0;
    ret->cipher.cipher = NULL;
    memset(ret->cipher.iv, 0, EVP_MAX_IV_LENGTH);
    ret->references = 1;
    if (ret->enc_algor == NULL || ret->enc_pkey == NULL) {
        c.line = __LINE__;
        goto err;
    }
    return ret;
err:
    X509_PKEY_free(ret);
    ASN1_MAC_H_err(ASN1_F_X509_PKEY_NEW, ERR_R_MALLOC_FAILURE, c.line);
    return NULL;
}

void X509_PKEY_free(X509_PKEY *x)
{
    int i;

    if (x == NULL)
        return;

    i = CRYPTO_add(&x->references, -1, CRYPTO_LOCK_X509_PKEY);
#ifdef REF_PRINT
    REF_PRINT("X509_PKEY", x);
#endif
    if (i > 0)
        return;
#ifdef REF_CHECK
    if (i < 0) {
        fprintf(stderr, "X509_PKEY_free, bad reference count\n");
        abort();
    }
#endif

    if (x->enc_algor != NULL)
        X509_ALGOR_free(x->enc_algor);
    if (x->enc_pkey != NULL)
        M_ASN1_OCTET_STRING_free(x->enc_pkey);
    if (x->dec_pkey != NULL)
        EVP_PKEY_free(x->dec_pkey);
    if ((x->key_data != NULL) && (x->key_free))
        OPENSSL_free(x->key_data);
    OPENSSL_free(x);
}
/* crypto/asn1/x_pubkey.c */
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
// #include "asn1t.h"
// #include "x509.h"
// #include "asn1_locl.h"
#ifndef OPENSSL_NO_RSA
# include "rsa.h"
#endif
#ifndef OPENSSL_NO_DSA
# include "dsa.h"
#endif

/* Minor tweak to operation: free up EVP_PKEY */
static int pubkey_cb(int operation, ASN1_VALUE **pval, const ASN1_ITEM *it,
                     void *exarg)
{
    if (operation == ASN1_OP_FREE_POST) {
        X509_PUBKEY *pubkey = (X509_PUBKEY *)*pval;
        EVP_PKEY_free(pubkey->pkey);
    }
    return 1;
}

ASN1_SEQUENCE_cb(X509_PUBKEY, pubkey_cb) = {
        ASN1_SIMPLE(X509_PUBKEY, algor, X509_ALGOR),
        ASN1_SIMPLE(X509_PUBKEY, public_key, ASN1_BIT_STRING)
} ASN1_SEQUENCE_END_cb(X509_PUBKEY, X509_PUBKEY)

IMPLEMENT_ASN1_FUNCTIONS(X509_PUBKEY)

int X509_PUBKEY_set(X509_PUBKEY **x, EVP_PKEY *pkey)
{
    X509_PUBKEY *pk = NULL;

    if (x == NULL)
        return (0);

    if ((pk = X509_PUBKEY_new()) == NULL)
        goto error;

    if (pkey->ameth) {
        if (pkey->ameth->pub_encode) {
            if (!pkey->ameth->pub_encode(pk, pkey)) {
                X509err(X509_F_X509_PUBKEY_SET,
                        X509_R_PUBLIC_KEY_ENCODE_ERROR);
                goto error;
            }
        } else {
            X509err(X509_F_X509_PUBKEY_SET, X509_R_METHOD_NOT_SUPPORTED);
            goto error;
        }
    } else {
        X509err(X509_F_X509_PUBKEY_SET, X509_R_UNSUPPORTED_ALGORITHM);
        goto error;
    }

    if (*x != NULL)
        X509_PUBKEY_free(*x);

    *x = pk;

    return 1;
 error:
    if (pk != NULL)
        X509_PUBKEY_free(pk);
    return 0;
}

EVP_PKEY *X509_PUBKEY_get(X509_PUBKEY *key)
{
    EVP_PKEY *ret = NULL;

    if (key == NULL)
        goto error;

    if (key->pkey != NULL) {
        CRYPTO_add(&key->pkey->references, 1, CRYPTO_LOCK_EVP_PKEY);
        return key->pkey;
    }

    if (key->public_key == NULL)
        goto error;

    if ((ret = EVP_PKEY_new()) == NULL) {
        X509err(X509_F_X509_PUBKEY_GET, ERR_R_MALLOC_FAILURE);
        goto error;
    }

    if (!EVP_PKEY_set_type(ret, OBJ_obj2nid(key->algor->algorithm))) {
        X509err(X509_F_X509_PUBKEY_GET, X509_R_UNSUPPORTED_ALGORITHM);
        goto error;
    }

    if (ret->ameth->pub_decode) {
        if (!ret->ameth->pub_decode(ret, key)) {
            X509err(X509_F_X509_PUBKEY_GET, X509_R_PUBLIC_KEY_DECODE_ERROR);
            goto error;
        }
    } else {
        X509err(X509_F_X509_PUBKEY_GET, X509_R_METHOD_NOT_SUPPORTED);
        goto error;
    }

    /* Check to see if another thread set key->pkey first */
    CRYPTO_w_lock(CRYPTO_LOCK_EVP_PKEY);
    if (key->pkey) {
        CRYPTO_w_unlock(CRYPTO_LOCK_EVP_PKEY);
        EVP_PKEY_free(ret);
        ret = key->pkey;
    } else {
        key->pkey = ret;
        CRYPTO_w_unlock(CRYPTO_LOCK_EVP_PKEY);
    }
    CRYPTO_add(&ret->references, 1, CRYPTO_LOCK_EVP_PKEY);

    return ret;

 error:
    if (ret != NULL)
        EVP_PKEY_free(ret);
    return (NULL);
}

/*
 * Now two pseudo ASN1 routines that take an EVP_PKEY structure and encode or
 * decode as X509_PUBKEY
 */

EVP_PKEY *d2i_PUBKEY(EVP_PKEY **a, const unsigned char **pp, long length)
{
    X509_PUBKEY *xpk;
    EVP_PKEY *pktmp;
    const unsigned char *q;
    q = *pp;
    xpk = d2i_X509_PUBKEY(NULL, &q, length);
    if (!xpk)
        return NULL;
    pktmp = X509_PUBKEY_get(xpk);
    X509_PUBKEY_free(xpk);
    if (!pktmp)
        return NULL;
    *pp = q;
    if (a) {
        EVP_PKEY_free(*a);
        *a = pktmp;
    }
    return pktmp;
}

int i2d_PUBKEY(EVP_PKEY *a, unsigned char **pp)
{
    X509_PUBKEY *xpk = NULL;
    int ret;
    if (!a)
        return 0;
    if (!X509_PUBKEY_set(&xpk, a))
        return 0;
    ret = i2d_X509_PUBKEY(xpk, pp);
    X509_PUBKEY_free(xpk);
    return ret;
}

/*
 * The following are equivalents but which return RSA and DSA keys
 */
#ifndef OPENSSL_NO_RSA
RSA *d2i_RSA_PUBKEY(RSA **a, const unsigned char **pp, long length)
{
    EVP_PKEY *pkey;
    RSA *key;
    const unsigned char *q;
    q = *pp;
    pkey = d2i_PUBKEY(NULL, &q, length);
    if (!pkey)
        return NULL;
    key = EVP_PKEY_get1_RSA(pkey);
    EVP_PKEY_free(pkey);
    if (!key)
        return NULL;
    *pp = q;
    if (a) {
        RSA_free(*a);
        *a = key;
    }
    return key;
}

int i2d_RSA_PUBKEY(RSA *a, unsigned char **pp)
{
    EVP_PKEY *pktmp;
    int ret;
    if (!a)
        return 0;
    pktmp = EVP_PKEY_new();
    if (!pktmp) {
        ASN1err(ASN1_F_I2D_RSA_PUBKEY, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    EVP_PKEY_set1_RSA(pktmp, a);
    ret = i2d_PUBKEY(pktmp, pp);
    EVP_PKEY_free(pktmp);
    return ret;
}
#endif

#ifndef OPENSSL_NO_DSA
DSA *d2i_DSA_PUBKEY(DSA **a, const unsigned char **pp, long length)
{
    EVP_PKEY *pkey;
    DSA *key;
    const unsigned char *q;
    q = *pp;
    pkey = d2i_PUBKEY(NULL, &q, length);
    if (!pkey)
        return NULL;
    key = EVP_PKEY_get1_DSA(pkey);
    EVP_PKEY_free(pkey);
    if (!key)
        return NULL;
    *pp = q;
    if (a) {
        DSA_free(*a);
        *a = key;
    }
    return key;
}

int i2d_DSA_PUBKEY(DSA *a, unsigned char **pp)
{
    EVP_PKEY *pktmp;
    int ret;
    if (!a)
        return 0;
    pktmp = EVP_PKEY_new();
    if (!pktmp) {
        ASN1err(ASN1_F_I2D_DSA_PUBKEY, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    EVP_PKEY_set1_DSA(pktmp, a);
    ret = i2d_PUBKEY(pktmp, pp);
    EVP_PKEY_free(pktmp);
    return ret;
}
#endif

#ifndef OPENSSL_NO_EC
EC_KEY *d2i_EC_PUBKEY(EC_KEY **a, const unsigned char **pp, long length)
{
    EVP_PKEY *pkey;
    EC_KEY *key;
    const unsigned char *q;
    q = *pp;
    pkey = d2i_PUBKEY(NULL, &q, length);
    if (!pkey)
        return (NULL);
    key = EVP_PKEY_get1_EC_KEY(pkey);
    EVP_PKEY_free(pkey);
    if (!key)
        return (NULL);
    *pp = q;
    if (a) {
        EC_KEY_free(*a);
        *a = key;
    }
    return (key);
}

int i2d_EC_PUBKEY(EC_KEY *a, unsigned char **pp)
{
    EVP_PKEY *pktmp;
    int ret;
    if (!a)
        return (0);
    if ((pktmp = EVP_PKEY_new()) == NULL) {
        ASN1err(ASN1_F_I2D_EC_PUBKEY, ERR_R_MALLOC_FAILURE);
        return (0);
    }
    EVP_PKEY_set1_EC_KEY(pktmp, a);
    ret = i2d_PUBKEY(pktmp, pp);
    EVP_PKEY_free(pktmp);
    return (ret);
}
#endif

int X509_PUBKEY_set0_param(X509_PUBKEY *pub, ASN1_OBJECT *aobj,
                           int ptype, void *pval,
                           unsigned char *penc, int penclen)
{
    if (!X509_ALGOR_set0(pub->algor, aobj, ptype, pval))
        return 0;
    if (penc) {
        if (pub->public_key->data)
            OPENSSL_free(pub->public_key->data);
        pub->public_key->data = penc;
        pub->public_key->length = penclen;
        /* Set number of unused bits to zero */
        pub->public_key->flags &= ~(ASN1_STRING_FLAG_BITS_LEFT | 0x07);
        pub->public_key->flags |= ASN1_STRING_FLAG_BITS_LEFT;
    }
    return 1;
}

int X509_PUBKEY_get0_param(ASN1_OBJECT **ppkalg,
                           const unsigned char **pk, int *ppklen,
                           X509_ALGOR **pa, X509_PUBKEY *pub)
{
    if (ppkalg)
        *ppkalg = pub->algor->algorithm;
    if (pk) {
        *pk = pub->public_key->data;
        *ppklen = pub->public_key->length;
    }
    if (pa)
        *pa = pub->algor;
    return 1;
}
/* crypto/asn1/x_req.c */
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
// #include "asn1t.h"
// #include "x509.h"

/*-
 * X509_REQ_INFO is handled in an unusual way to get round
 * invalid encodings. Some broken certificate requests don't
 * encode the attributes field if it is empty. This is in
 * violation of PKCS#10 but we need to tolerate it. We do
 * this by making the attributes field OPTIONAL then using
 * the callback to initialise it to an empty STACK.
 *
 * This means that the field will be correctly encoded unless
 * we NULL out the field.
 *
 * As a result we no longer need the req_kludge field because
 * the information is now contained in the attributes field:
 * 1. If it is NULL then it's the invalid omission.
 * 2. If it is empty it is the correct encoding.
 * 3. If it is not empty then some attributes are present.
 *
 */

static int rinf_cb(int operation, ASN1_VALUE **pval, const ASN1_ITEM *it,
                   void *exarg)
{
    X509_REQ_INFO *rinf = (X509_REQ_INFO *)*pval;

    if (operation == ASN1_OP_NEW_POST) {
        rinf->attributes = sk_X509_ATTRIBUTE_new_null();
        if (!rinf->attributes)
            return 0;
    }
    return 1;
}

ASN1_SEQUENCE_enc(X509_REQ_INFO, enc, rinf_cb) = {
        ASN1_SIMPLE(X509_REQ_INFO, version, ASN1_INTEGER),
        ASN1_SIMPLE(X509_REQ_INFO, subject, X509_NAME),
        ASN1_SIMPLE(X509_REQ_INFO, pubkey, X509_PUBKEY),
        /* This isn't really OPTIONAL but it gets round invalid
         * encodings
         */
        ASN1_IMP_SET_OF_OPT(X509_REQ_INFO, attributes, X509_ATTRIBUTE, 0)
} ASN1_SEQUENCE_END_enc(X509_REQ_INFO, X509_REQ_INFO)

IMPLEMENT_ASN1_FUNCTIONS(X509_REQ_INFO)

ASN1_SEQUENCE_ref(X509_REQ, 0, CRYPTO_LOCK_X509_REQ) = {
        ASN1_SIMPLE(X509_REQ, req_info, X509_REQ_INFO),
        ASN1_SIMPLE(X509_REQ, sig_alg, X509_ALGOR),
        ASN1_SIMPLE(X509_REQ, signature, ASN1_BIT_STRING)
} ASN1_SEQUENCE_END_ref(X509_REQ, X509_REQ)

IMPLEMENT_ASN1_FUNCTIONS(X509_REQ)

IMPLEMENT_ASN1_DUP_FUNCTION(X509_REQ)
/* crypto/asn1/x_sig.c */
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
// #include "asn1t.h"
// #include "x509.h"

ASN1_SEQUENCE(X509_SIG) = {
        ASN1_SIMPLE(X509_SIG, algor, X509_ALGOR),
        ASN1_SIMPLE(X509_SIG, digest, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(X509_SIG)

IMPLEMENT_ASN1_FUNCTIONS(X509_SIG)
/* crypto/asn1/x_spki.c */
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

 /*
  * This module was send to me my Pat Richards <patr@x509.com> who wrote it.
  * It is under my Copyright with his permission
  */

#include <stdio.h>
// #include "cryptlib.h"
// #include "x509.h"
// #include "asn1t.h"

ASN1_SEQUENCE(NETSCAPE_SPKAC) = {
        ASN1_SIMPLE(NETSCAPE_SPKAC, pubkey, X509_PUBKEY),
        ASN1_SIMPLE(NETSCAPE_SPKAC, challenge, ASN1_IA5STRING)
} ASN1_SEQUENCE_END(NETSCAPE_SPKAC)

IMPLEMENT_ASN1_FUNCTIONS(NETSCAPE_SPKAC)

ASN1_SEQUENCE(NETSCAPE_SPKI) = {
        ASN1_SIMPLE(NETSCAPE_SPKI, spkac, NETSCAPE_SPKAC),
        ASN1_SIMPLE(NETSCAPE_SPKI, sig_algor, X509_ALGOR),
        ASN1_SIMPLE(NETSCAPE_SPKI, signature, ASN1_BIT_STRING)
} ASN1_SEQUENCE_END(NETSCAPE_SPKI)

IMPLEMENT_ASN1_FUNCTIONS(NETSCAPE_SPKI)
/* crypto/asn1/x_val.c */
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
// #include "asn1t.h"
// #include "x509.h"

ASN1_SEQUENCE(X509_VAL) = {
        ASN1_SIMPLE(X509_VAL, notBefore, ASN1_TIME),
        ASN1_SIMPLE(X509_VAL, notAfter, ASN1_TIME)
} ASN1_SEQUENCE_END(X509_VAL)

IMPLEMENT_ASN1_FUNCTIONS(X509_VAL)
/* crypto/asn1/x_x509.c */
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
// #include "asn1t.h"
// #include "x509.h"
// #include "x509v3.h"

ASN1_SEQUENCE_enc(X509_CINF, enc, 0) = {
        ASN1_EXP_OPT(X509_CINF, version, ASN1_INTEGER, 0),
        ASN1_SIMPLE(X509_CINF, serialNumber, ASN1_INTEGER),
        ASN1_SIMPLE(X509_CINF, signature, X509_ALGOR),
        ASN1_SIMPLE(X509_CINF, issuer, X509_NAME),
        ASN1_SIMPLE(X509_CINF, validity, X509_VAL),
        ASN1_SIMPLE(X509_CINF, subject, X509_NAME),
        ASN1_SIMPLE(X509_CINF, key, X509_PUBKEY),
        ASN1_IMP_OPT(X509_CINF, issuerUID, ASN1_BIT_STRING, 1),
        ASN1_IMP_OPT(X509_CINF, subjectUID, ASN1_BIT_STRING, 2),
        ASN1_EXP_SEQUENCE_OF_OPT(X509_CINF, extensions, X509_EXTENSION, 3)
} ASN1_SEQUENCE_END_enc(X509_CINF, X509_CINF)

IMPLEMENT_ASN1_FUNCTIONS(X509_CINF)
/* X509 top level structure needs a bit of customisation */

extern void policy_cache_free(X509_POLICY_CACHE *cache);

static int x509_cb(int operation, ASN1_VALUE **pval, const ASN1_ITEM *it,
                   void *exarg)
{
    X509 *ret = (X509 *)*pval;

    switch (operation) {

    case ASN1_OP_NEW_POST:
        ret->valid = 0;
        ret->name = NULL;
        ret->ex_flags = 0;
        ret->ex_pathlen = -1;
        ret->skid = NULL;
        ret->akid = NULL;
#ifndef OPENSSL_NO_RFC3779
        ret->rfc3779_addr = NULL;
        ret->rfc3779_asid = NULL;
#endif
        ret->aux = NULL;
        ret->crldp = NULL;
        CRYPTO_new_ex_data(CRYPTO_EX_INDEX_X509, ret, &ret->ex_data);
        break;

    case ASN1_OP_D2I_POST:
        if (ret->name != NULL)
            OPENSSL_free(ret->name);
        ret->name = X509_NAME_oneline(ret->cert_info->subject, NULL, 0);
        break;

    case ASN1_OP_FREE_POST:
        CRYPTO_free_ex_data(CRYPTO_EX_INDEX_X509, ret, &ret->ex_data);
        X509_CERT_AUX_free(ret->aux);
        ASN1_OCTET_STRING_free(ret->skid);
        AUTHORITY_KEYID_free(ret->akid);
        CRL_DIST_POINTS_free(ret->crldp);
        policy_cache_free(ret->policy_cache);
        GENERAL_NAMES_free(ret->altname);
        NAME_CONSTRAINTS_free(ret->nc);
#ifndef OPENSSL_NO_RFC3779
        sk_IPAddressFamily_pop_free(ret->rfc3779_addr, IPAddressFamily_free);
        ASIdentifiers_free(ret->rfc3779_asid);
#endif

        if (ret->name != NULL)
            OPENSSL_free(ret->name);
        break;

    }

    return 1;

}

ASN1_SEQUENCE_ref(X509, x509_cb, CRYPTO_LOCK_X509) = {
        ASN1_SIMPLE(X509, cert_info, X509_CINF),
        ASN1_SIMPLE(X509, sig_alg, X509_ALGOR),
        ASN1_SIMPLE(X509, signature, ASN1_BIT_STRING)
} ASN1_SEQUENCE_END_ref(X509, X509)

IMPLEMENT_ASN1_FUNCTIONS(X509)

IMPLEMENT_ASN1_DUP_FUNCTION(X509)

int X509_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func,
                          CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func)
{
    return CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_X509, argl, argp,
                                   new_func, dup_func, free_func);
}

int X509_set_ex_data(X509 *r, int idx, void *arg)
{
    return (CRYPTO_set_ex_data(&r->ex_data, idx, arg));
}

void *X509_get_ex_data(X509 *r, int idx)
{
    return (CRYPTO_get_ex_data(&r->ex_data, idx));
}

/*
 * X509_AUX ASN1 routines. X509_AUX is the name given to a certificate with
 * extra info tagged on the end. Since these functions set how a certificate
 * is trusted they should only be used when the certificate comes from a
 * reliable source such as local storage.
 */

X509 *d2i_X509_AUX(X509 **a, const unsigned char **pp, long length)
{
    const unsigned char *q;
    X509 *ret;
    int freeret = 0;

    /* Save start position */
    q = *pp;

    if (!a || *a == NULL) {
        freeret = 1;
    }
    ret = d2i_X509(a, &q, length);
    /* If certificate unreadable then forget it */
    if (!ret)
        return NULL;
    /* update length */
    length -= q - *pp;
    if (length > 0 && !d2i_X509_CERT_AUX(&ret->aux, &q, length))
        goto err;
    *pp = q;
    return ret;
 err:
    if (freeret) {
        X509_free(ret);
        if (a)
            *a = NULL;
    }
    return NULL;
}

/*
 * Serialize trusted certificate to *pp or just return the required buffer
 * length if pp == NULL.  We ultimately want to avoid modifying *pp in the
 * error path, but that depends on similar hygiene in lower-level functions.
 * Here we avoid compounding the problem.
 */
static int i2d_x509_aux_internal(X509 *a, unsigned char **pp)
{
    int length, tmplen;
    unsigned char *start = pp != NULL ? *pp : NULL;

    OPENSSL_assert(pp == NULL || *pp != NULL);

    /*
     * This might perturb *pp on error, but fixing that belongs in i2d_X509()
     * not here.  It should be that if a == NULL length is zero, but we check
     * both just in case.
     */
    length = i2d_X509(a, pp);
    if (length <= 0 || a == NULL)
        return length;

    tmplen = i2d_X509_CERT_AUX(a->aux, pp);
    if (tmplen < 0) {
        if (start != NULL)
            *pp = start;
        return tmplen;
    }
    length += tmplen;

    return length;
}

/*
 * Serialize trusted certificate to *pp, or just return the required buffer
 * length if pp == NULL.
 *
 * When pp is not NULL, but *pp == NULL, we allocate the buffer, but since
 * we're writing two ASN.1 objects back to back, we can't have i2d_X509() do
 * the allocation, nor can we allow i2d_X509_CERT_AUX() to increment the
 * allocated buffer.
 */
int i2d_X509_AUX(X509 *a, unsigned char **pp)
{
    int length;
    unsigned char *tmp;

    /* Buffer provided by caller */
    if (pp == NULL || *pp != NULL)
        return i2d_x509_aux_internal(a, pp);

    /* Obtain the combined length */
    if ((length = i2d_x509_aux_internal(a, NULL)) <= 0)
        return length;

    /* Allocate requisite combined storage */
    *pp = tmp = OPENSSL_malloc(length);
    if (tmp == NULL)
        return -1; /* Push error onto error stack? */

    /* Encode, but keep *pp at the originally malloced pointer */
    length = i2d_x509_aux_internal(a, &tmp);
    if (length <= 0) {
        OPENSSL_free(*pp);
        *pp = NULL;
    }
    return length;
}

int i2d_re_X509_tbs(X509 *x, unsigned char **pp)
{
    x->cert_info->enc.modified = 1;
    return i2d_X509_CINF(x->cert_info, pp);
}

void X509_get0_signature(ASN1_BIT_STRING **psig, X509_ALGOR **palg,
                         const X509 *x)
{
    if (psig)
        *psig = x->signature;
    if (palg)
        *palg = x->sig_alg;
}

int X509_get_signature_nid(const X509 *x)
{
    return OBJ_obj2nid(x->sig_alg->algorithm);
}
/* a_x509a.c */
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
// #include "evp.h"
// #include "asn1t.h"
// #include "x509.h"

/*
 * X509_CERT_AUX routines. These are used to encode additional user
 * modifiable data about a certificate. This data is appended to the X509
 * encoding when the *_X509_AUX routines are used. This means that the
 * "traditional" X509 routines will simply ignore the extra data.
 */

static X509_CERT_AUX *aux_get(X509 *x);

ASN1_SEQUENCE(X509_CERT_AUX) = {
        ASN1_SEQUENCE_OF_OPT(X509_CERT_AUX, trust, ASN1_OBJECT),
        ASN1_IMP_SEQUENCE_OF_OPT(X509_CERT_AUX, reject, ASN1_OBJECT, 0),
        ASN1_OPT(X509_CERT_AUX, alias, ASN1_UTF8STRING),
        ASN1_OPT(X509_CERT_AUX, keyid, ASN1_OCTET_STRING),
        ASN1_IMP_SEQUENCE_OF_OPT(X509_CERT_AUX, other, X509_ALGOR, 1)
} ASN1_SEQUENCE_END(X509_CERT_AUX)

IMPLEMENT_ASN1_FUNCTIONS(X509_CERT_AUX)

static X509_CERT_AUX *aux_get(X509 *x)
{
    if (!x)
        return NULL;
    if (!x->aux && !(x->aux = X509_CERT_AUX_new()))
        return NULL;
    return x->aux;
}

int X509_alias_set1(X509 *x, unsigned char *name, int len)
{
    X509_CERT_AUX *aux;
    if (!name) {
        if (!x || !x->aux || !x->aux->alias)
            return 1;
        ASN1_UTF8STRING_free(x->aux->alias);
        x->aux->alias = NULL;
        return 1;
    }
    if (!(aux = aux_get(x)))
        return 0;
    if (!aux->alias && !(aux->alias = ASN1_UTF8STRING_new()))
        return 0;
    return ASN1_STRING_set(aux->alias, name, len);
}

int X509_keyid_set1(X509 *x, unsigned char *id, int len)
{
    X509_CERT_AUX *aux;
    if (!id) {
        if (!x || !x->aux || !x->aux->keyid)
            return 1;
        ASN1_OCTET_STRING_free(x->aux->keyid);
        x->aux->keyid = NULL;
        return 1;
    }
    if (!(aux = aux_get(x)))
        return 0;
    if (!aux->keyid && !(aux->keyid = ASN1_OCTET_STRING_new()))
        return 0;
    return ASN1_STRING_set(aux->keyid, id, len);
}

unsigned char *X509_alias_get0(X509 *x, int *len)
{
    if (!x->aux || !x->aux->alias)
        return NULL;
    if (len)
        *len = x->aux->alias->length;
    return x->aux->alias->data;
}

unsigned char *X509_keyid_get0(X509 *x, int *len)
{
    if (!x->aux || !x->aux->keyid)
        return NULL;
    if (len)
        *len = x->aux->keyid->length;
    return x->aux->keyid->data;
}

int X509_add1_trust_object(X509 *x, ASN1_OBJECT *obj)
{
    X509_CERT_AUX *aux;
    ASN1_OBJECT *objtmp;
    if (!(objtmp = OBJ_dup(obj)))
        return 0;
    if (!(aux = aux_get(x)))
        return 0;
    if (!aux->trust && !(aux->trust = sk_ASN1_OBJECT_new_null()))
        return 0;
    return sk_ASN1_OBJECT_push(aux->trust, objtmp);
}

int X509_add1_reject_object(X509 *x, ASN1_OBJECT *obj)
{
    X509_CERT_AUX *aux;
    ASN1_OBJECT *objtmp;
    if (!(objtmp = OBJ_dup(obj)))
        return 0;
    if (!(aux = aux_get(x)))
        goto err;
    if (!aux->reject && !(aux->reject = sk_ASN1_OBJECT_new_null()))
        goto err;
    return sk_ASN1_OBJECT_push(aux->reject, objtmp);
 err:
    ASN1_OBJECT_free(objtmp);
    return 0;
}

void X509_trust_clear(X509 *x)
{
    if (x->aux && x->aux->trust) {
        sk_ASN1_OBJECT_pop_free(x->aux->trust, ASN1_OBJECT_free);
        x->aux->trust = NULL;
    }
}

void X509_reject_clear(X509 *x)
{
    if (x->aux && x->aux->reject) {
        sk_ASN1_OBJECT_pop_free(x->aux->reject, ASN1_OBJECT_free);
        x->aux->reject = NULL;
    }
}

ASN1_SEQUENCE(X509_CERT_PAIR) = {
        ASN1_EXP_OPT(X509_CERT_PAIR, forward, X509, 0),
        ASN1_EXP_OPT(X509_CERT_PAIR, reverse, X509, 1)
} ASN1_SEQUENCE_END(X509_CERT_PAIR)

IMPLEMENT_ASN1_FUNCTIONS(X509_CERT_PAIR)
