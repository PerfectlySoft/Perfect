/* crypto/pem/pem_all.c */
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
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
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
#include "bio.h"
#include "evp.h"
#include "x509.h"
#include "pkcs7.h"
#include "pem.h"
#ifndef OPENSSL_NO_RSA
# include "rsa.h"
#endif
#ifndef OPENSSL_NO_DSA
# include "dsa.h"
#endif
#ifndef OPENSSL_NO_DH
# include "dh.h"
#endif

#ifndef OPENSSL_NO_RSA
static RSA *pkey_get_rsa(EVP_PKEY *key, RSA **rsa);
#endif
#ifndef OPENSSL_NO_DSA
static DSA *pkey_get_dsa(EVP_PKEY *key, DSA **dsa);
#endif

#ifndef OPENSSL_NO_EC
static EC_KEY *pkey_get_eckey(EVP_PKEY *key, EC_KEY **eckey);
#endif

IMPLEMENT_PEM_rw(X509_REQ, X509_REQ, PEM_STRING_X509_REQ, X509_REQ)

IMPLEMENT_PEM_write(X509_REQ_NEW, X509_REQ, PEM_STRING_X509_REQ_OLD, X509_REQ)
IMPLEMENT_PEM_rw(X509_CRL, X509_CRL, PEM_STRING_X509_CRL, X509_CRL)
IMPLEMENT_PEM_rw(PKCS7, PKCS7, PEM_STRING_PKCS7, PKCS7)

IMPLEMENT_PEM_rw(NETSCAPE_CERT_SEQUENCE, NETSCAPE_CERT_SEQUENCE,
                 PEM_STRING_X509, NETSCAPE_CERT_SEQUENCE)
#ifndef OPENSSL_NO_RSA
/*
 * We treat RSA or DSA private keys as a special case. For private keys we
 * read in an EVP_PKEY structure with PEM_read_bio_PrivateKey() and extract
 * the relevant private key: this means can handle "traditional" and PKCS#8
 * formats transparently.
 */
static RSA *pkey_get_rsa(EVP_PKEY *key, RSA **rsa)
{
    RSA *rtmp;
    if (!key)
        return NULL;
    rtmp = EVP_PKEY_get1_RSA(key);
    EVP_PKEY_free(key);
    if (!rtmp)
        return NULL;
    if (rsa) {
        RSA_free(*rsa);
        *rsa = rtmp;
    }
    return rtmp;
}

RSA *PEM_read_bio_RSAPrivateKey(BIO *bp, RSA **rsa, pem_password_cb *cb,
                                void *u)
{
    EVP_PKEY *pktmp;
    pktmp = PEM_read_bio_PrivateKey(bp, NULL, cb, u);
    return pkey_get_rsa(pktmp, rsa);
}

# ifndef OPENSSL_NO_FP_API

RSA *PEM_read_RSAPrivateKey(FILE *fp, RSA **rsa, pem_password_cb *cb, void *u)
{
    EVP_PKEY *pktmp;
    pktmp = PEM_read_PrivateKey(fp, NULL, cb, u);
    return pkey_get_rsa(pktmp, rsa);
}

# endif

# ifdef OPENSSL_FIPS

int PEM_write_bio_RSAPrivateKey(BIO *bp, RSA *x, const EVP_CIPHER *enc,
                                unsigned char *kstr, int klen,
                                pem_password_cb *cb, void *u)
{
    if (FIPS_mode()) {
        EVP_PKEY *k;
        int ret;
        k = EVP_PKEY_new();
        if (!k)
            return 0;
        EVP_PKEY_set1_RSA(k, x);

        ret = PEM_write_bio_PrivateKey(bp, k, enc, kstr, klen, cb, u);
        EVP_PKEY_free(k);
        return ret;
    } else
        return PEM_ASN1_write_bio((i2d_of_void *)i2d_RSAPrivateKey,
                                  PEM_STRING_RSA, bp, x, enc, kstr, klen, cb,
                                  u);
}

#  ifndef OPENSSL_NO_FP_API
int PEM_write_RSAPrivateKey(FILE *fp, RSA *x, const EVP_CIPHER *enc,
                            unsigned char *kstr, int klen,
                            pem_password_cb *cb, void *u)
{
    if (FIPS_mode()) {
        EVP_PKEY *k;
        int ret;
        k = EVP_PKEY_new();
        if (!k)
            return 0;

        EVP_PKEY_set1_RSA(k, x);

        ret = PEM_write_PrivateKey(fp, k, enc, kstr, klen, cb, u);
        EVP_PKEY_free(k);
        return ret;
    } else
        return PEM_ASN1_write((i2d_of_void *)i2d_RSAPrivateKey,
                              PEM_STRING_RSA, fp, x, enc, kstr, klen, cb, u);
}
#  endif

# else

IMPLEMENT_PEM_write_cb_const(RSAPrivateKey, RSA, PEM_STRING_RSA,
                             RSAPrivateKey)
# endif
IMPLEMENT_PEM_rw_const(RSAPublicKey, RSA, PEM_STRING_RSA_PUBLIC,
                       RSAPublicKey) IMPLEMENT_PEM_rw(RSA_PUBKEY, RSA,
                                                      PEM_STRING_PUBLIC,
                                                      RSA_PUBKEY)
#endif
#ifndef OPENSSL_NO_DSA
static DSA *pkey_get_dsa(EVP_PKEY *key, DSA **dsa)
{
    DSA *dtmp;
    if (!key)
        return NULL;
    dtmp = EVP_PKEY_get1_DSA(key);
    EVP_PKEY_free(key);
    if (!dtmp)
        return NULL;
    if (dsa) {
        DSA_free(*dsa);
        *dsa = dtmp;
    }
    return dtmp;
}

DSA *PEM_read_bio_DSAPrivateKey(BIO *bp, DSA **dsa, pem_password_cb *cb,
                                void *u)
{
    EVP_PKEY *pktmp;
    pktmp = PEM_read_bio_PrivateKey(bp, NULL, cb, u);
    return pkey_get_dsa(pktmp, dsa); /* will free pktmp */
}

# ifdef OPENSSL_FIPS

int PEM_write_bio_DSAPrivateKey(BIO *bp, DSA *x, const EVP_CIPHER *enc,
                                unsigned char *kstr, int klen,
                                pem_password_cb *cb, void *u)
{
    if (FIPS_mode()) {
        EVP_PKEY *k;
        int ret;
        k = EVP_PKEY_new();
        if (!k)
            return 0;
        EVP_PKEY_set1_DSA(k, x);

        ret = PEM_write_bio_PrivateKey(bp, k, enc, kstr, klen, cb, u);
        EVP_PKEY_free(k);
        return ret;
    } else
        return PEM_ASN1_write_bio((i2d_of_void *)i2d_DSAPrivateKey,
                                  PEM_STRING_DSA, bp, x, enc, kstr, klen, cb,
                                  u);
}

#  ifndef OPENSSL_NO_FP_API
int PEM_write_DSAPrivateKey(FILE *fp, DSA *x, const EVP_CIPHER *enc,
                            unsigned char *kstr, int klen,
                            pem_password_cb *cb, void *u)
{
    if (FIPS_mode()) {
        EVP_PKEY *k;
        int ret;
        k = EVP_PKEY_new();
        if (!k)
            return 0;
        EVP_PKEY_set1_DSA(k, x);
        ret = PEM_write_PrivateKey(fp, k, enc, kstr, klen, cb, u);
        EVP_PKEY_free(k);
        return ret;
    } else
        return PEM_ASN1_write((i2d_of_void *)i2d_DSAPrivateKey,
                              PEM_STRING_DSA, fp, x, enc, kstr, klen, cb, u);
}
#  endif

# else

IMPLEMENT_PEM_write_cb_const(DSAPrivateKey, DSA, PEM_STRING_DSA,
                             DSAPrivateKey)
# endif
    IMPLEMENT_PEM_rw(DSA_PUBKEY, DSA, PEM_STRING_PUBLIC, DSA_PUBKEY)
# ifndef OPENSSL_NO_FP_API
DSA *PEM_read_DSAPrivateKey(FILE *fp, DSA **dsa, pem_password_cb *cb, void *u)
{
    EVP_PKEY *pktmp;
    pktmp = PEM_read_PrivateKey(fp, NULL, cb, u);
    return pkey_get_dsa(pktmp, dsa); /* will free pktmp */
}

# endif

IMPLEMENT_PEM_rw_const(DSAparams, DSA, PEM_STRING_DSAPARAMS, DSAparams)
#endif
#ifndef OPENSSL_NO_EC
static EC_KEY *pkey_get_eckey(EVP_PKEY *key, EC_KEY **eckey)
{
    EC_KEY *dtmp;
    if (!key)
        return NULL;
    dtmp = EVP_PKEY_get1_EC_KEY(key);
    EVP_PKEY_free(key);
    if (!dtmp)
        return NULL;
    if (eckey) {
        EC_KEY_free(*eckey);
        *eckey = dtmp;
    }
    return dtmp;
}

EC_KEY *PEM_read_bio_ECPrivateKey(BIO *bp, EC_KEY **key, pem_password_cb *cb,
                                  void *u)
{
    EVP_PKEY *pktmp;
    pktmp = PEM_read_bio_PrivateKey(bp, NULL, cb, u);
    return pkey_get_eckey(pktmp, key); /* will free pktmp */
}

IMPLEMENT_PEM_rw_const(ECPKParameters, EC_GROUP, PEM_STRING_ECPARAMETERS,
                       ECPKParameters)
# ifdef OPENSSL_FIPS
int PEM_write_bio_ECPrivateKey(BIO *bp, EC_KEY *x, const EVP_CIPHER *enc,
                               unsigned char *kstr, int klen,
                               pem_password_cb *cb, void *u)
{
    if (FIPS_mode()) {
        EVP_PKEY *k;
        int ret;
        k = EVP_PKEY_new();
        if (!k)
            return 0;
        EVP_PKEY_set1_EC_KEY(k, x);

        ret = PEM_write_bio_PrivateKey(bp, k, enc, kstr, klen, cb, u);
        EVP_PKEY_free(k);
        return ret;
    } else
        return PEM_ASN1_write_bio((i2d_of_void *)i2d_ECPrivateKey,
                                  PEM_STRING_ECPRIVATEKEY,
                                  bp, x, enc, kstr, klen, cb, u);
}

#  ifndef OPENSSL_NO_FP_API
int PEM_write_ECPrivateKey(FILE *fp, EC_KEY *x, const EVP_CIPHER *enc,
                           unsigned char *kstr, int klen,
                           pem_password_cb *cb, void *u)
{
    if (FIPS_mode()) {
        EVP_PKEY *k;
        int ret;
        k = EVP_PKEY_new();
        if (!k)
            return 0;
        EVP_PKEY_set1_EC_KEY(k, x);
        ret = PEM_write_PrivateKey(fp, k, enc, kstr, klen, cb, u);
        EVP_PKEY_free(k);
        return ret;
    } else
        return PEM_ASN1_write((i2d_of_void *)i2d_ECPrivateKey,
                              PEM_STRING_ECPRIVATEKEY,
                              fp, x, enc, kstr, klen, cb, u);
}
#  endif

# else
    IMPLEMENT_PEM_write_cb(ECPrivateKey, EC_KEY, PEM_STRING_ECPRIVATEKEY,
                       ECPrivateKey)
# endif
IMPLEMENT_PEM_rw(EC_PUBKEY, EC_KEY, PEM_STRING_PUBLIC, EC_PUBKEY)
# ifndef OPENSSL_NO_FP_API
EC_KEY *PEM_read_ECPrivateKey(FILE *fp, EC_KEY **eckey, pem_password_cb *cb,
                              void *u)
{
    EVP_PKEY *pktmp;
    pktmp = PEM_read_PrivateKey(fp, NULL, cb, u);
    return pkey_get_eckey(pktmp, eckey); /* will free pktmp */
}

# endif

#endif

#ifndef OPENSSL_NO_DH

IMPLEMENT_PEM_write_const(DHparams, DH, PEM_STRING_DHPARAMS, DHparams)
    IMPLEMENT_PEM_write_const(DHxparams, DH, PEM_STRING_DHXPARAMS, DHxparams)
#endif
IMPLEMENT_PEM_rw(PUBKEY, EVP_PKEY, PEM_STRING_PUBLIC, PUBKEY)
/* crypto/pem/pem_err.c */
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
#include "err.h"
// #include "pem.h"

/* BEGIN ERROR CODES */
#ifndef OPENSSL_NO_ERR

# define ERR_FUNC(func) ERR_PACK(ERR_LIB_PEM,func,0)
# define ERR_REASON(reason) ERR_PACK(ERR_LIB_PEM,0,reason)

static ERR_STRING_DATA PEM_str_functs[] = {
    {ERR_FUNC(PEM_F_B2I_DSS), "B2I_DSS"},
    {ERR_FUNC(PEM_F_B2I_PVK_BIO), "b2i_PVK_bio"},
    {ERR_FUNC(PEM_F_B2I_RSA), "B2I_RSA"},
    {ERR_FUNC(PEM_F_CHECK_BITLEN_DSA), "CHECK_BITLEN_DSA"},
    {ERR_FUNC(PEM_F_CHECK_BITLEN_RSA), "CHECK_BITLEN_RSA"},
    {ERR_FUNC(PEM_F_D2I_PKCS8PRIVATEKEY_BIO), "d2i_PKCS8PrivateKey_bio"},
    {ERR_FUNC(PEM_F_D2I_PKCS8PRIVATEKEY_FP), "d2i_PKCS8PrivateKey_fp"},
    {ERR_FUNC(PEM_F_DO_B2I), "DO_B2I"},
    {ERR_FUNC(PEM_F_DO_B2I_BIO), "DO_B2I_BIO"},
    {ERR_FUNC(PEM_F_DO_BLOB_HEADER), "DO_BLOB_HEADER"},
    {ERR_FUNC(PEM_F_DO_PK8PKEY), "DO_PK8PKEY"},
    {ERR_FUNC(PEM_F_DO_PK8PKEY_FP), "DO_PK8PKEY_FP"},
    {ERR_FUNC(PEM_F_DO_PVK_BODY), "DO_PVK_BODY"},
    {ERR_FUNC(PEM_F_DO_PVK_HEADER), "DO_PVK_HEADER"},
    {ERR_FUNC(PEM_F_I2B_PVK), "I2B_PVK"},
    {ERR_FUNC(PEM_F_I2B_PVK_BIO), "i2b_PVK_bio"},
    {ERR_FUNC(PEM_F_LOAD_IV), "LOAD_IV"},
    {ERR_FUNC(PEM_F_PEM_ASN1_READ), "PEM_ASN1_read"},
    {ERR_FUNC(PEM_F_PEM_ASN1_READ_BIO), "PEM_ASN1_read_bio"},
    {ERR_FUNC(PEM_F_PEM_ASN1_WRITE), "PEM_ASN1_write"},
    {ERR_FUNC(PEM_F_PEM_ASN1_WRITE_BIO), "PEM_ASN1_write_bio"},
    {ERR_FUNC(PEM_F_PEM_DEF_CALLBACK), "PEM_def_callback"},
    {ERR_FUNC(PEM_F_PEM_DO_HEADER), "PEM_do_header"},
    {ERR_FUNC(PEM_F_PEM_F_PEM_WRITE_PKCS8PRIVATEKEY),
     "PEM_F_PEM_WRITE_PKCS8PRIVATEKEY"},
    {ERR_FUNC(PEM_F_PEM_GET_EVP_CIPHER_INFO), "PEM_get_EVP_CIPHER_INFO"},
    {ERR_FUNC(PEM_F_PEM_PK8PKEY), "PEM_PK8PKEY"},
    {ERR_FUNC(PEM_F_PEM_READ), "PEM_read"},
    {ERR_FUNC(PEM_F_PEM_READ_BIO), "PEM_read_bio"},
    {ERR_FUNC(PEM_F_PEM_READ_BIO_DHPARAMS), "PEM_READ_BIO_DHPARAMS"},
    {ERR_FUNC(PEM_F_PEM_READ_BIO_PARAMETERS), "PEM_read_bio_Parameters"},
    {ERR_FUNC(PEM_F_PEM_READ_BIO_PRIVATEKEY), "PEM_READ_BIO_PRIVATEKEY"},
    {ERR_FUNC(PEM_F_PEM_READ_DHPARAMS), "PEM_READ_DHPARAMS"},
    {ERR_FUNC(PEM_F_PEM_READ_PRIVATEKEY), "PEM_READ_PRIVATEKEY"},
    {ERR_FUNC(PEM_F_PEM_SEALFINAL), "PEM_SealFinal"},
    {ERR_FUNC(PEM_F_PEM_SEALINIT), "PEM_SealInit"},
    {ERR_FUNC(PEM_F_PEM_SIGNFINAL), "PEM_SignFinal"},
    {ERR_FUNC(PEM_F_PEM_WRITE), "PEM_write"},
    {ERR_FUNC(PEM_F_PEM_WRITE_BIO), "PEM_write_bio"},
    {ERR_FUNC(PEM_F_PEM_WRITE_PRIVATEKEY), "PEM_WRITE_PRIVATEKEY"},
    {ERR_FUNC(PEM_F_PEM_X509_INFO_READ), "PEM_X509_INFO_read"},
    {ERR_FUNC(PEM_F_PEM_X509_INFO_READ_BIO), "PEM_X509_INFO_read_bio"},
    {ERR_FUNC(PEM_F_PEM_X509_INFO_WRITE_BIO), "PEM_X509_INFO_write_bio"},
    {0, NULL}
};

static ERR_STRING_DATA PEM_str_reasons[] = {
    {ERR_REASON(PEM_R_BAD_BASE64_DECODE), "bad base64 decode"},
    {ERR_REASON(PEM_R_BAD_DECRYPT), "bad decrypt"},
    {ERR_REASON(PEM_R_BAD_END_LINE), "bad end line"},
    {ERR_REASON(PEM_R_BAD_IV_CHARS), "bad iv chars"},
    {ERR_REASON(PEM_R_BAD_MAGIC_NUMBER), "bad magic number"},
    {ERR_REASON(PEM_R_BAD_PASSWORD_READ), "bad password read"},
    {ERR_REASON(PEM_R_BAD_VERSION_NUMBER), "bad version number"},
    {ERR_REASON(PEM_R_BIO_WRITE_FAILURE), "bio write failure"},
    {ERR_REASON(PEM_R_CIPHER_IS_NULL), "cipher is null"},
    {ERR_REASON(PEM_R_ERROR_CONVERTING_PRIVATE_KEY),
     "error converting private key"},
    {ERR_REASON(PEM_R_EXPECTING_PRIVATE_KEY_BLOB),
     "expecting private key blob"},
    {ERR_REASON(PEM_R_EXPECTING_PUBLIC_KEY_BLOB),
     "expecting public key blob"},
    {ERR_REASON(PEM_R_HEADER_TOO_LONG), "header too long"},
    {ERR_REASON(PEM_R_INCONSISTENT_HEADER), "inconsistent header"},
    {ERR_REASON(PEM_R_KEYBLOB_HEADER_PARSE_ERROR),
     "keyblob header parse error"},
    {ERR_REASON(PEM_R_KEYBLOB_TOO_SHORT), "keyblob too short"},
    {ERR_REASON(PEM_R_NOT_DEK_INFO), "not dek info"},
    {ERR_REASON(PEM_R_NOT_ENCRYPTED), "not encrypted"},
    {ERR_REASON(PEM_R_NOT_PROC_TYPE), "not proc type"},
    {ERR_REASON(PEM_R_NO_START_LINE), "no start line"},
    {ERR_REASON(PEM_R_PROBLEMS_GETTING_PASSWORD),
     "problems getting password"},
    {ERR_REASON(PEM_R_PUBLIC_KEY_NO_RSA), "public key no rsa"},
    {ERR_REASON(PEM_R_PVK_DATA_TOO_SHORT), "pvk data too short"},
    {ERR_REASON(PEM_R_PVK_TOO_SHORT), "pvk too short"},
    {ERR_REASON(PEM_R_READ_KEY), "read key"},
    {ERR_REASON(PEM_R_SHORT_HEADER), "short header"},
    {ERR_REASON(PEM_R_UNSUPPORTED_CIPHER), "unsupported cipher"},
    {ERR_REASON(PEM_R_UNSUPPORTED_ENCRYPTION), "unsupported encryption"},
    {ERR_REASON(PEM_R_UNSUPPORTED_KEY_COMPONENTS),
     "unsupported key components"},
    {0, NULL}
};

#endif

void ERR_load_PEM_strings(void)
{
#ifndef OPENSSL_NO_ERR

    if (ERR_func_error_string(PEM_str_functs[0].error) == NULL) {
        ERR_load_strings(0, PEM_str_functs);
        ERR_load_strings(0, PEM_str_reasons);
    }
#endif
}
/* crypto/pem/pem_info.c */
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
#include "buffer.h"
#include "objects.h"
// #include "evp.h"
// #include "x509.h"
// #include "pem.h"
#ifndef OPENSSL_NO_RSA
# include "rsa.h"
#endif
#ifndef OPENSSL_NO_DSA
# include "dsa.h"
#endif

#ifndef OPENSSL_NO_FP_API
STACK_OF(X509_INFO) *PEM_X509_INFO_read(FILE *fp, STACK_OF(X509_INFO) *sk,
                                        pem_password_cb *cb, void *u)
{
    BIO *b;
    STACK_OF(X509_INFO) *ret;

    if ((b = BIO_new(BIO_s_file())) == NULL) {
        PEMerr(PEM_F_PEM_X509_INFO_READ, ERR_R_BUF_LIB);
        return (0);
    }
    BIO_set_fp(b, fp, BIO_NOCLOSE);
    ret = PEM_X509_INFO_read_bio(b, sk, cb, u);
    BIO_free(b);
    return (ret);
}
#endif

STACK_OF(X509_INFO) *PEM_X509_INFO_read_bio(BIO *bp, STACK_OF(X509_INFO) *sk,
                                            pem_password_cb *cb, void *u)
{
    X509_INFO *xi = NULL;
    char *name = NULL, *header = NULL;
    void *pp;
    unsigned char *data = NULL;
    const unsigned char *p;
    long len, error = 0;
    int ok = 0;
    STACK_OF(X509_INFO) *ret = NULL;
    unsigned int i, raw, ptype;
    d2i_of_void *d2i = 0;

    if (sk == NULL) {
        if ((ret = sk_X509_INFO_new_null()) == NULL) {
            PEMerr(PEM_F_PEM_X509_INFO_READ_BIO, ERR_R_MALLOC_FAILURE);
            goto err;
        }
    } else
        ret = sk;

    if ((xi = X509_INFO_new()) == NULL)
        goto err;
    for (;;) {
        raw = 0;
        ptype = 0;
        i = PEM_read_bio(bp, &name, &header, &data, &len);
        if (i == 0) {
            error = ERR_GET_REASON(ERR_peek_last_error());
            if (error == PEM_R_NO_START_LINE) {
                ERR_clear_error();
                break;
            }
            goto err;
        }
 start:
        if ((strcmp(name, PEM_STRING_X509) == 0) ||
            (strcmp(name, PEM_STRING_X509_OLD) == 0)) {
            d2i = (D2I_OF(void)) d2i_X509;
            if (xi->x509 != NULL) {
                if (!sk_X509_INFO_push(ret, xi))
                    goto err;
                if ((xi = X509_INFO_new()) == NULL)
                    goto err;
                goto start;
            }
            pp = &(xi->x509);
        } else if ((strcmp(name, PEM_STRING_X509_TRUSTED) == 0)) {
            d2i = (D2I_OF(void)) d2i_X509_AUX;
            if (xi->x509 != NULL) {
                if (!sk_X509_INFO_push(ret, xi))
                    goto err;
                if ((xi = X509_INFO_new()) == NULL)
                    goto err;
                goto start;
            }
            pp = &(xi->x509);
        } else if (strcmp(name, PEM_STRING_X509_CRL) == 0) {
            d2i = (D2I_OF(void)) d2i_X509_CRL;
            if (xi->crl != NULL) {
                if (!sk_X509_INFO_push(ret, xi))
                    goto err;
                if ((xi = X509_INFO_new()) == NULL)
                    goto err;
                goto start;
            }
            pp = &(xi->crl);
        } else
#ifndef OPENSSL_NO_RSA
        if (strcmp(name, PEM_STRING_RSA) == 0) {
            d2i = (D2I_OF(void)) d2i_RSAPrivateKey;
            if (xi->x_pkey != NULL) {
                if (!sk_X509_INFO_push(ret, xi))
                    goto err;
                if ((xi = X509_INFO_new()) == NULL)
                    goto err;
                goto start;
            }

            xi->enc_data = NULL;
            xi->enc_len = 0;

            xi->x_pkey = X509_PKEY_new();
            if (xi->x_pkey == NULL)
                goto err;
            ptype = EVP_PKEY_RSA;
            pp = &xi->x_pkey->dec_pkey;
            if ((int)strlen(header) > 10) /* assume encrypted */
                raw = 1;
        } else
#endif
#ifndef OPENSSL_NO_DSA
        if (strcmp(name, PEM_STRING_DSA) == 0) {
            d2i = (D2I_OF(void)) d2i_DSAPrivateKey;
            if (xi->x_pkey != NULL) {
                if (!sk_X509_INFO_push(ret, xi))
                    goto err;
                if ((xi = X509_INFO_new()) == NULL)
                    goto err;
                goto start;
            }

            xi->enc_data = NULL;
            xi->enc_len = 0;

            xi->x_pkey = X509_PKEY_new();
            if (xi->x_pkey == NULL)
                goto err;
            ptype = EVP_PKEY_DSA;
            pp = &xi->x_pkey->dec_pkey;
            if ((int)strlen(header) > 10) /* assume encrypted */
                raw = 1;
        } else
#endif
#ifndef OPENSSL_NO_EC
        if (strcmp(name, PEM_STRING_ECPRIVATEKEY) == 0) {
            d2i = (D2I_OF(void)) d2i_ECPrivateKey;
            if (xi->x_pkey != NULL) {
                if (!sk_X509_INFO_push(ret, xi))
                    goto err;
                if ((xi = X509_INFO_new()) == NULL)
                    goto err;
                goto start;
            }

            xi->enc_data = NULL;
            xi->enc_len = 0;

            xi->x_pkey = X509_PKEY_new();
            if (xi->x_pkey == NULL)
                goto err;
            ptype = EVP_PKEY_EC;
            pp = &xi->x_pkey->dec_pkey;
            if ((int)strlen(header) > 10) /* assume encrypted */
                raw = 1;
        } else
#endif
        {
            d2i = NULL;
            pp = NULL;
        }

        if (d2i != NULL) {
            if (!raw) {
                EVP_CIPHER_INFO cipher;

                if (!PEM_get_EVP_CIPHER_INFO(header, &cipher))
                    goto err;
                if (!PEM_do_header(&cipher, data, &len, cb, u))
                    goto err;
                p = data;
                if (ptype) {
                    if (!d2i_PrivateKey(ptype, pp, &p, len)) {
                        PEMerr(PEM_F_PEM_X509_INFO_READ_BIO, ERR_R_ASN1_LIB);
                        goto err;
                    }
                } else if (d2i(pp, &p, len) == NULL) {
                    PEMerr(PEM_F_PEM_X509_INFO_READ_BIO, ERR_R_ASN1_LIB);
                    goto err;
                }
            } else {            /* encrypted RSA data */
                if (!PEM_get_EVP_CIPHER_INFO(header, &xi->enc_cipher))
                    goto err;
                xi->enc_data = (char *)data;
                xi->enc_len = (int)len;
                data = NULL;
            }
        } else {
            /* unknown */
        }
        if (name != NULL)
            OPENSSL_free(name);
        if (header != NULL)
            OPENSSL_free(header);
        if (data != NULL)
            OPENSSL_free(data);
        name = NULL;
        header = NULL;
        data = NULL;
    }

    /*
     * if the last one hasn't been pushed yet and there is anything in it
     * then add it to the stack ...
     */
    if ((xi->x509 != NULL) || (xi->crl != NULL) ||
        (xi->x_pkey != NULL) || (xi->enc_data != NULL)) {
        if (!sk_X509_INFO_push(ret, xi))
            goto err;
        xi = NULL;
    }
    ok = 1;
 err:
    if (xi != NULL)
        X509_INFO_free(xi);
    if (!ok) {
        for (i = 0; ((int)i) < sk_X509_INFO_num(ret); i++) {
            xi = sk_X509_INFO_value(ret, i);
            X509_INFO_free(xi);
        }
        if (ret != sk)
            sk_X509_INFO_free(ret);
        ret = NULL;
    }

    if (name != NULL)
        OPENSSL_free(name);
    if (header != NULL)
        OPENSSL_free(header);
    if (data != NULL)
        OPENSSL_free(data);
    return (ret);
}

/* A TJH addition */
int PEM_X509_INFO_write_bio(BIO *bp, X509_INFO *xi, EVP_CIPHER *enc,
                            unsigned char *kstr, int klen,
                            pem_password_cb *cb, void *u)
{
    EVP_CIPHER_CTX ctx;
    int i, ret = 0;
    unsigned char *data = NULL;
    const char *objstr = NULL;
    char buf[PEM_BUFSIZE];
    unsigned char *iv = NULL;

    if (enc != NULL) {
        objstr = OBJ_nid2sn(EVP_CIPHER_nid(enc));
        if (objstr == NULL) {
            PEMerr(PEM_F_PEM_X509_INFO_WRITE_BIO, PEM_R_UNSUPPORTED_CIPHER);
            goto err;
        }
    }

    /*
     * now for the fun part ... if we have a private key then we have to be
     * able to handle a not-yet-decrypted key being written out correctly ...
     * if it is decrypted or it is non-encrypted then we use the base code
     */
    if (xi->x_pkey != NULL) {
        if ((xi->enc_data != NULL) && (xi->enc_len > 0)) {
            if (enc == NULL) {
                PEMerr(PEM_F_PEM_X509_INFO_WRITE_BIO, PEM_R_CIPHER_IS_NULL);
                goto err;
            }

            /* copy from weirdo names into more normal things */
            iv = xi->enc_cipher.iv;
            data = (unsigned char *)xi->enc_data;
            i = xi->enc_len;

            /*
             * we take the encryption data from the internal stuff rather
             * than what the user has passed us ... as we have to match
             * exactly for some strange reason
             */
            objstr = OBJ_nid2sn(EVP_CIPHER_nid(xi->enc_cipher.cipher));
            if (objstr == NULL) {
                PEMerr(PEM_F_PEM_X509_INFO_WRITE_BIO,
                       PEM_R_UNSUPPORTED_CIPHER);
                goto err;
            }

            /* create the right magic header stuff */
            OPENSSL_assert(strlen(objstr) + 23 + 2 * enc->iv_len + 13 <=
                           sizeof(buf));
            buf[0] = '\0';
            PEM_proc_type(buf, PEM_TYPE_ENCRYPTED);
            PEM_dek_info(buf, objstr, enc->iv_len, (char *)iv);

            /* use the normal code to write things out */
            i = PEM_write_bio(bp, PEM_STRING_RSA, buf, data, i);
            if (i <= 0)
                goto err;
        } else {
            /* Add DSA/DH */
#ifndef OPENSSL_NO_RSA
            /* normal optionally encrypted stuff */
            if (PEM_write_bio_RSAPrivateKey(bp,
                                            xi->x_pkey->dec_pkey->pkey.rsa,
                                            enc, kstr, klen, cb, u) <= 0)
                goto err;
#endif
        }
    }

    /* if we have a certificate then write it out now */
    if ((xi->x509 != NULL) && (PEM_write_bio_X509(bp, xi->x509) <= 0))
        goto err;

    /*
     * we are ignoring anything else that is loaded into the X509_INFO
     * structure for the moment ... as I don't need it so I'm not coding it
     * here and Eric can do it when this makes it into the base library --tjh
     */

    ret = 1;

 err:
    OPENSSL_cleanse((char *)&ctx, sizeof(ctx));
    OPENSSL_cleanse(buf, PEM_BUFSIZE);
    return (ret);
}
/* crypto/pem/pem_lib.c */
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
// #include "buffer.h"
// #include "objects.h"
// #include "evp.h"
#include "rand.h"
// #include "x509.h"
// #include "pem.h"
#include "pkcs12.h"
#include "asn1_locl.h"
#ifndef OPENSSL_NO_DES
# include "des.h"
#endif
#ifndef OPENSSL_NO_ENGINE
# include "engine.h"
#endif

const char PEM_version[] = "PEM" OPENSSL_VERSION_PTEXT;

#define MIN_LENGTH      4

static int load_iv(char **fromp, unsigned char *to, int num);
static int check_pem(const char *nm, const char *name);
int pem_check_suffix(const char *pem_str, const char *suffix);

int PEM_def_callback(char *buf, int num, int rwflag, void *userdata)
{
    int i, min_len;
    const char *prompt;

    /* We assume that the user passes a default password as userdata */
    if (userdata) {
        i = strlen(userdata);
        i = (i > num) ? num : i;
        memcpy(buf, userdata, i);
        return i;
    }

    prompt = EVP_get_pw_prompt();
    if (prompt == NULL)
        prompt = "Enter PEM pass phrase:";

    /*
     * rwflag == 0 means decryption
     * rwflag == 1 means encryption
     *
     * We assume that for encryption, we want a minimum length, while for
     * decryption, we cannot know any minimum length, so we assume zero.
     */
    min_len = rwflag ? MIN_LENGTH : 0;

    i = EVP_read_pw_string_min(buf, min_len, num, prompt, rwflag);
    if (i != 0) {
        PEMerr(PEM_F_PEM_DEF_CALLBACK, PEM_R_PROBLEMS_GETTING_PASSWORD);
        memset(buf, 0, (unsigned int)num);
        return -1;
    }
    return strlen(buf);
}

void PEM_proc_type(char *buf, int type)
{
    const char *str;

    if (type == PEM_TYPE_ENCRYPTED)
        str = "ENCRYPTED";
    else if (type == PEM_TYPE_MIC_CLEAR)
        str = "MIC-CLEAR";
    else if (type == PEM_TYPE_MIC_ONLY)
        str = "MIC-ONLY";
    else
        str = "BAD-TYPE";

    BUF_strlcat(buf, "Proc-Type: 4,", PEM_BUFSIZE);
    BUF_strlcat(buf, str, PEM_BUFSIZE);
    BUF_strlcat(buf, "\n", PEM_BUFSIZE);
}

void PEM_dek_info(char *buf, const char *type, int len, char *str)
{
    static const unsigned char map[17] = "0123456789ABCDEF";
    long i;
    int j;

    BUF_strlcat(buf, "DEK-Info: ", PEM_BUFSIZE);
    BUF_strlcat(buf, type, PEM_BUFSIZE);
    BUF_strlcat(buf, ",", PEM_BUFSIZE);
    j = strlen(buf);
    if (j + (len * 2) + 1 > PEM_BUFSIZE)
        return;
    for (i = 0; i < len; i++) {
        buf[j + i * 2] = map[(str[i] >> 4) & 0x0f];
        buf[j + i * 2 + 1] = map[(str[i]) & 0x0f];
    }
    buf[j + i * 2] = '\n';
    buf[j + i * 2 + 1] = '\0';
}

#ifndef OPENSSL_NO_FP_API
void *PEM_ASN1_read(d2i_of_void *d2i, const char *name, FILE *fp, void **x,
                    pem_password_cb *cb, void *u)
{
    BIO *b;
    void *ret;

    if ((b = BIO_new(BIO_s_file())) == NULL) {
        PEMerr(PEM_F_PEM_ASN1_READ, ERR_R_BUF_LIB);
        return (0);
    }
    BIO_set_fp(b, fp, BIO_NOCLOSE);
    ret = PEM_ASN1_read_bio(d2i, name, b, x, cb, u);
    BIO_free(b);
    return (ret);
}
#endif

static int check_pem(const char *nm, const char *name)
{
    /* Normal matching nm and name */
    if (!strcmp(nm, name))
        return 1;

    /* Make PEM_STRING_EVP_PKEY match any private key */

    if (!strcmp(name, PEM_STRING_EVP_PKEY)) {
        int slen;
        const EVP_PKEY_ASN1_METHOD *ameth;
        if (!strcmp(nm, PEM_STRING_PKCS8))
            return 1;
        if (!strcmp(nm, PEM_STRING_PKCS8INF))
            return 1;
        slen = pem_check_suffix(nm, "PRIVATE KEY");
        if (slen > 0) {
            /*
             * NB: ENGINE implementations wont contain a deprecated old
             * private key decode function so don't look for them.
             */
            ameth = EVP_PKEY_asn1_find_str(NULL, nm, slen);
            if (ameth && ameth->old_priv_decode)
                return 1;
        }
        return 0;
    }

    if (!strcmp(name, PEM_STRING_PARAMETERS)) {
        int slen;
        const EVP_PKEY_ASN1_METHOD *ameth;
        slen = pem_check_suffix(nm, "PARAMETERS");
        if (slen > 0) {
            ENGINE *e;
            ameth = EVP_PKEY_asn1_find_str(&e, nm, slen);
            if (ameth) {
                int r;
                if (ameth->param_decode)
                    r = 1;
                else
                    r = 0;
#ifndef OPENSSL_NO_ENGINE
                if (e)
                    ENGINE_finish(e);
#endif
                return r;
            }
        }
        return 0;
    }
    /* If reading DH parameters handle X9.42 DH format too */
    if (!strcmp(nm, PEM_STRING_DHXPARAMS) &&
        !strcmp(name, PEM_STRING_DHPARAMS))
        return 1;

    /* Permit older strings */

    if (!strcmp(nm, PEM_STRING_X509_OLD) && !strcmp(name, PEM_STRING_X509))
        return 1;

    if (!strcmp(nm, PEM_STRING_X509_REQ_OLD) &&
        !strcmp(name, PEM_STRING_X509_REQ))
        return 1;

    /* Allow normal certs to be read as trusted certs */
    if (!strcmp(nm, PEM_STRING_X509) &&
        !strcmp(name, PEM_STRING_X509_TRUSTED))
        return 1;

    if (!strcmp(nm, PEM_STRING_X509_OLD) &&
        !strcmp(name, PEM_STRING_X509_TRUSTED))
        return 1;

    /* Some CAs use PKCS#7 with CERTIFICATE headers */
    if (!strcmp(nm, PEM_STRING_X509) && !strcmp(name, PEM_STRING_PKCS7))
        return 1;

    if (!strcmp(nm, PEM_STRING_PKCS7_SIGNED) &&
        !strcmp(name, PEM_STRING_PKCS7))
        return 1;

#ifndef OPENSSL_NO_CMS
    if (!strcmp(nm, PEM_STRING_X509) && !strcmp(name, PEM_STRING_CMS))
        return 1;
    /* Allow CMS to be read from PKCS#7 headers */
    if (!strcmp(nm, PEM_STRING_PKCS7) && !strcmp(name, PEM_STRING_CMS))
        return 1;
#endif

    return 0;
}

int PEM_bytes_read_bio(unsigned char **pdata, long *plen, char **pnm,
                       const char *name, BIO *bp, pem_password_cb *cb,
                       void *u)
{
    EVP_CIPHER_INFO cipher;
    char *nm = NULL, *header = NULL;
    unsigned char *data = NULL;
    long len;
    int ret = 0;

    for (;;) {
        if (!PEM_read_bio(bp, &nm, &header, &data, &len)) {
            if (ERR_GET_REASON(ERR_peek_error()) == PEM_R_NO_START_LINE)
                ERR_add_error_data(2, "Expecting: ", name);
            return 0;
        }
        if (check_pem(nm, name))
            break;
        OPENSSL_free(nm);
        OPENSSL_free(header);
        OPENSSL_free(data);
    }
    if (!PEM_get_EVP_CIPHER_INFO(header, &cipher))
        goto err;
    if (!PEM_do_header(&cipher, data, &len, cb, u))
        goto err;

    *pdata = data;
    *plen = len;

    if (pnm)
        *pnm = nm;

    ret = 1;

 err:
    if (!ret || !pnm)
        OPENSSL_free(nm);
    OPENSSL_free(header);
    if (!ret)
        OPENSSL_free(data);
    return ret;
}

#ifndef OPENSSL_NO_FP_API
int PEM_ASN1_write(i2d_of_void *i2d, const char *name, FILE *fp,
                   void *x, const EVP_CIPHER *enc, unsigned char *kstr,
                   int klen, pem_password_cb *callback, void *u)
{
    BIO *b;
    int ret;

    if ((b = BIO_new(BIO_s_file())) == NULL) {
        PEMerr(PEM_F_PEM_ASN1_WRITE, ERR_R_BUF_LIB);
        return (0);
    }
    BIO_set_fp(b, fp, BIO_NOCLOSE);
    ret = PEM_ASN1_write_bio(i2d, name, b, x, enc, kstr, klen, callback, u);
    BIO_free(b);
    return (ret);
}
#endif

int PEM_ASN1_write_bio(i2d_of_void *i2d, const char *name, BIO *bp,
                       void *x, const EVP_CIPHER *enc, unsigned char *kstr,
                       int klen, pem_password_cb *callback, void *u)
{
    EVP_CIPHER_CTX ctx;
    int dsize = 0, i, j, ret = 0;
    unsigned char *p, *data = NULL;
    const char *objstr = NULL;
    char buf[PEM_BUFSIZE];
    unsigned char key[EVP_MAX_KEY_LENGTH];
    unsigned char iv[EVP_MAX_IV_LENGTH];

    if (enc != NULL) {
        objstr = OBJ_nid2sn(EVP_CIPHER_nid(enc));
        if (objstr == NULL || EVP_CIPHER_iv_length(enc) == 0) {
            PEMerr(PEM_F_PEM_ASN1_WRITE_BIO, PEM_R_UNSUPPORTED_CIPHER);
            goto err;
        }
    }

    if ((dsize = i2d(x, NULL)) < 0) {
        PEMerr(PEM_F_PEM_ASN1_WRITE_BIO, ERR_R_ASN1_LIB);
        dsize = 0;
        goto err;
    }
    /* dzise + 8 bytes are needed */
    /* actually it needs the cipher block size extra... */
    data = (unsigned char *)OPENSSL_malloc((unsigned int)dsize + 20);
    if (data == NULL) {
        PEMerr(PEM_F_PEM_ASN1_WRITE_BIO, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    p = data;
    i = i2d(x, &p);

    if (enc != NULL) {
        if (kstr == NULL) {
            if (callback == NULL)
                klen = PEM_def_callback(buf, PEM_BUFSIZE, 1, u);
            else
                klen = (*callback) (buf, PEM_BUFSIZE, 1, u);
            if (klen <= 0) {
                PEMerr(PEM_F_PEM_ASN1_WRITE_BIO, PEM_R_READ_KEY);
                goto err;
            }
#ifdef CHARSET_EBCDIC
            /* Convert the pass phrase from EBCDIC */
            ebcdic2ascii(buf, buf, klen);
#endif
            kstr = (unsigned char *)buf;
        }
        RAND_add(data, i, 0);   /* put in the RSA key. */
        OPENSSL_assert(enc->iv_len <= (int)sizeof(iv));
        if (RAND_bytes(iv, enc->iv_len) <= 0) /* Generate a salt */
            goto err;
        /*
         * The 'iv' is used as the iv and as a salt.  It is NOT taken from
         * the BytesToKey function
         */
        if (!EVP_BytesToKey(enc, EVP_md5(), iv, kstr, klen, 1, key, NULL))
            goto err;

        if (kstr == (unsigned char *)buf)
            OPENSSL_cleanse(buf, PEM_BUFSIZE);

        OPENSSL_assert(strlen(objstr) + 23 + 2 * enc->iv_len + 13 <=
                       sizeof(buf));

        buf[0] = '\0';
        PEM_proc_type(buf, PEM_TYPE_ENCRYPTED);
        PEM_dek_info(buf, objstr, enc->iv_len, (char *)iv);
        /* k=strlen(buf); */

        EVP_CIPHER_CTX_init(&ctx);
        ret = 1;
        if (!EVP_EncryptInit_ex(&ctx, enc, NULL, key, iv)
            || !EVP_EncryptUpdate(&ctx, data, &j, data, i)
            || !EVP_EncryptFinal_ex(&ctx, &(data[j]), &i))
            ret = 0;
        EVP_CIPHER_CTX_cleanup(&ctx);
        if (ret == 0)
            goto err;
        i += j;
    } else {
        ret = 1;
        buf[0] = '\0';
    }
    i = PEM_write_bio(bp, name, buf, data, i);
    if (i <= 0)
        ret = 0;
 err:
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(iv, sizeof(iv));
    OPENSSL_cleanse((char *)&ctx, sizeof(ctx));
    OPENSSL_cleanse(buf, PEM_BUFSIZE);
    if (data != NULL) {
        OPENSSL_cleanse(data, (unsigned int)dsize);
        OPENSSL_free(data);
    }
    return (ret);
}

int PEM_do_header(EVP_CIPHER_INFO *cipher, unsigned char *data, long *plen,
                  pem_password_cb *callback, void *u)
{
    int i = 0, j, o, klen;
    long len;
    EVP_CIPHER_CTX ctx;
    unsigned char key[EVP_MAX_KEY_LENGTH];
    char buf[PEM_BUFSIZE];

    len = *plen;

    if (cipher->cipher == NULL)
        return (1);
    if (callback == NULL)
        klen = PEM_def_callback(buf, PEM_BUFSIZE, 0, u);
    else
        klen = callback(buf, PEM_BUFSIZE, 0, u);
    if (klen < 0) {
        PEMerr(PEM_F_PEM_DO_HEADER, PEM_R_BAD_PASSWORD_READ);
        return (0);
    }
#ifdef CHARSET_EBCDIC
    /* Convert the pass phrase from EBCDIC */
    ebcdic2ascii(buf, buf, klen);
#endif

    if (!EVP_BytesToKey(cipher->cipher, EVP_md5(), &(cipher->iv[0]),
                        (unsigned char *)buf, klen, 1, key, NULL))
        return 0;

    j = (int)len;
    EVP_CIPHER_CTX_init(&ctx);
    o = EVP_DecryptInit_ex(&ctx, cipher->cipher, NULL, key, &(cipher->iv[0]));
    if (o)
        o = EVP_DecryptUpdate(&ctx, data, &i, data, j);
    if (o)
        o = EVP_DecryptFinal_ex(&ctx, &(data[i]), &j);
    EVP_CIPHER_CTX_cleanup(&ctx);
    OPENSSL_cleanse((char *)buf, sizeof(buf));
    OPENSSL_cleanse((char *)key, sizeof(key));
    if (o)
        j += i;
    else {
        PEMerr(PEM_F_PEM_DO_HEADER, PEM_R_BAD_DECRYPT);
        return (0);
    }
    *plen = j;
    return (1);
}

int PEM_get_EVP_CIPHER_INFO(char *header, EVP_CIPHER_INFO *cipher)
{
    const EVP_CIPHER *enc = NULL;
    char *p, c;
    char **header_pp = &header;

    cipher->cipher = NULL;
    memset(cipher->iv, 0, sizeof(cipher->iv));
    if ((header == NULL) || (*header == '\0') || (*header == '\n'))
        return (1);
    if (strncmp(header, "Proc-Type: ", 11) != 0) {
        PEMerr(PEM_F_PEM_GET_EVP_CIPHER_INFO, PEM_R_NOT_PROC_TYPE);
        return (0);
    }
    header += 11;
    if (*header != '4')
        return (0);
    header++;
    if (*header != ',')
        return (0);
    header++;
    if (strncmp(header, "ENCRYPTED", 9) != 0) {
        PEMerr(PEM_F_PEM_GET_EVP_CIPHER_INFO, PEM_R_NOT_ENCRYPTED);
        return (0);
    }
    for (; (*header != '\n') && (*header != '\0'); header++) ;
    if (*header == '\0') {
        PEMerr(PEM_F_PEM_GET_EVP_CIPHER_INFO, PEM_R_SHORT_HEADER);
        return (0);
    }
    header++;
    if (strncmp(header, "DEK-Info: ", 10) != 0) {
        PEMerr(PEM_F_PEM_GET_EVP_CIPHER_INFO, PEM_R_NOT_DEK_INFO);
        return (0);
    }
    header += 10;

    p = header;
    for (;;) {
        c = *header;
#ifndef CHARSET_EBCDIC
        if (!(((c >= 'A') && (c <= 'Z')) || (c == '-') ||
              ((c >= '0') && (c <= '9'))))
            break;
#else
        if (!(isupper((unsigned char)c) || (c == '-')
            || isdigit((unsigned char)c)))
            break;
#endif
        header++;
    }
    *header = '\0';
    cipher->cipher = enc = EVP_get_cipherbyname(p);
    *header = c;
    header++;

    if (enc == NULL) {
        PEMerr(PEM_F_PEM_GET_EVP_CIPHER_INFO, PEM_R_UNSUPPORTED_ENCRYPTION);
        return (0);
    }
    if (!load_iv(header_pp, &(cipher->iv[0]), enc->iv_len))
        return (0);

    return (1);
}

static int load_iv(char **fromp, unsigned char *to, int num)
{
    int v, i;
    char *from;

    from = *fromp;
    for (i = 0; i < num; i++)
        to[i] = 0;
    num *= 2;
    for (i = 0; i < num; i++) {
        if ((*from >= '0') && (*from <= '9'))
            v = *from - '0';
        else if ((*from >= 'A') && (*from <= 'F'))
            v = *from - 'A' + 10;
        else if ((*from >= 'a') && (*from <= 'f'))
            v = *from - 'a' + 10;
        else {
            PEMerr(PEM_F_LOAD_IV, PEM_R_BAD_IV_CHARS);
            return (0);
        }
        from++;
        to[i / 2] |= v << (long)((!(i & 1)) * 4);
    }

    *fromp = from;
    return (1);
}

#ifndef OPENSSL_NO_FP_API
int PEM_write(FILE *fp, const char *name, const char *header,
              const unsigned char *data, long len)
{
    BIO *b;
    int ret;

    if ((b = BIO_new(BIO_s_file())) == NULL) {
        PEMerr(PEM_F_PEM_WRITE, ERR_R_BUF_LIB);
        return (0);
    }
    BIO_set_fp(b, fp, BIO_NOCLOSE);
    ret = PEM_write_bio(b, name, header, data, len);
    BIO_free(b);
    return (ret);
}
#endif

int PEM_write_bio(BIO *bp, const char *name, const char *header,
                  const unsigned char *data, long len)
{
    int nlen, n, i, j, outl;
    unsigned char *buf = NULL;
    EVP_ENCODE_CTX ctx;
    int reason = ERR_R_BUF_LIB;

    EVP_EncodeInit(&ctx);
    nlen = strlen(name);

    if ((BIO_write(bp, "-----BEGIN ", 11) != 11) ||
        (BIO_write(bp, name, nlen) != nlen) ||
        (BIO_write(bp, "-----\n", 6) != 6))
        goto err;

    i = strlen(header);
    if (i > 0) {
        if ((BIO_write(bp, header, i) != i) || (BIO_write(bp, "\n", 1) != 1))
            goto err;
    }

    buf = OPENSSL_malloc(PEM_BUFSIZE * 8);
    if (buf == NULL) {
        reason = ERR_R_MALLOC_FAILURE;
        goto err;
    }

    i = j = 0;
    while (len > 0) {
        n = (int)((len > (PEM_BUFSIZE * 5)) ? (PEM_BUFSIZE * 5) : len);
        EVP_EncodeUpdate(&ctx, buf, &outl, &(data[j]), n);
        if ((outl) && (BIO_write(bp, (char *)buf, outl) != outl))
            goto err;
        i += outl;
        len -= n;
        j += n;
    }
    EVP_EncodeFinal(&ctx, buf, &outl);
    if ((outl > 0) && (BIO_write(bp, (char *)buf, outl) != outl))
        goto err;
    OPENSSL_cleanse(buf, PEM_BUFSIZE * 8);
    OPENSSL_free(buf);
    buf = NULL;
    if ((BIO_write(bp, "-----END ", 9) != 9) ||
        (BIO_write(bp, name, nlen) != nlen) ||
        (BIO_write(bp, "-----\n", 6) != 6))
        goto err;
    return (i + outl);
 err:
    if (buf) {
        OPENSSL_cleanse(buf, PEM_BUFSIZE * 8);
        OPENSSL_free(buf);
    }
    PEMerr(PEM_F_PEM_WRITE_BIO, reason);
    return (0);
}

#ifndef OPENSSL_NO_FP_API
int PEM_read(FILE *fp, char **name, char **header, unsigned char **data,
             long *len)
{
    BIO *b;
    int ret;

    if ((b = BIO_new(BIO_s_file())) == NULL) {
        PEMerr(PEM_F_PEM_READ, ERR_R_BUF_LIB);
        return (0);
    }
    BIO_set_fp(b, fp, BIO_NOCLOSE);
    ret = PEM_read_bio(b, name, header, data, len);
    BIO_free(b);
    return (ret);
}
#endif

int PEM_read_bio(BIO *bp, char **name, char **header, unsigned char **data,
                 long *len)
{
    EVP_ENCODE_CTX ctx;
    int end = 0, i, k, bl = 0, hl = 0, nohead = 0;
    char buf[256];
    BUF_MEM *nameB;
    BUF_MEM *headerB;
    BUF_MEM *dataB, *tmpB;

    nameB = BUF_MEM_new();
    headerB = BUF_MEM_new();
    dataB = BUF_MEM_new();
    if ((nameB == NULL) || (headerB == NULL) || (dataB == NULL)) {
        BUF_MEM_free(nameB);
        BUF_MEM_free(headerB);
        BUF_MEM_free(dataB);
        PEMerr(PEM_F_PEM_READ_BIO, ERR_R_MALLOC_FAILURE);
        return (0);
    }

    buf[254] = '\0';
    for (;;) {
        i = BIO_gets(bp, buf, 254);

        if (i <= 0) {
            PEMerr(PEM_F_PEM_READ_BIO, PEM_R_NO_START_LINE);
            goto err;
        }

        while ((i >= 0) && (buf[i] <= ' '))
            i--;
        buf[++i] = '\n';
        buf[++i] = '\0';

        if (strncmp(buf, "-----BEGIN ", 11) == 0) {
            i = strlen(&(buf[11]));

            if (strncmp(&(buf[11 + i - 6]), "-----\n", 6) != 0)
                continue;
            if (!BUF_MEM_grow(nameB, i + 9)) {
                PEMerr(PEM_F_PEM_READ_BIO, ERR_R_MALLOC_FAILURE);
                goto err;
            }
            memcpy(nameB->data, &(buf[11]), i - 6);
            nameB->data[i - 6] = '\0';
            break;
        }
    }
    hl = 0;
    if (!BUF_MEM_grow(headerB, 256)) {
        PEMerr(PEM_F_PEM_READ_BIO, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    headerB->data[0] = '\0';
    for (;;) {
        i = BIO_gets(bp, buf, 254);
        if (i <= 0)
            break;

        while ((i >= 0) && (buf[i] <= ' '))
            i--;
        buf[++i] = '\n';
        buf[++i] = '\0';

        if (buf[0] == '\n')
            break;
        if (!BUF_MEM_grow(headerB, hl + i + 9)) {
            PEMerr(PEM_F_PEM_READ_BIO, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        if (strncmp(buf, "-----END ", 9) == 0) {
            nohead = 1;
            break;
        }
        memcpy(&(headerB->data[hl]), buf, i);
        headerB->data[hl + i] = '\0';
        hl += i;
    }

    bl = 0;
    if (!BUF_MEM_grow(dataB, 1024)) {
        PEMerr(PEM_F_PEM_READ_BIO, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    dataB->data[0] = '\0';
    if (!nohead) {
        for (;;) {
            i = BIO_gets(bp, buf, 254);
            if (i <= 0)
                break;

            while ((i >= 0) && (buf[i] <= ' '))
                i--;
            buf[++i] = '\n';
            buf[++i] = '\0';

            if (i != 65)
                end = 1;
            if (strncmp(buf, "-----END ", 9) == 0)
                break;
            if (i > 65)
                break;
            if (!BUF_MEM_grow_clean(dataB, i + bl + 9)) {
                PEMerr(PEM_F_PEM_READ_BIO, ERR_R_MALLOC_FAILURE);
                goto err;
            }
            memcpy(&(dataB->data[bl]), buf, i);
            dataB->data[bl + i] = '\0';
            bl += i;
            if (end) {
                buf[0] = '\0';
                i = BIO_gets(bp, buf, 254);
                if (i <= 0)
                    break;

                while ((i >= 0) && (buf[i] <= ' '))
                    i--;
                buf[++i] = '\n';
                buf[++i] = '\0';

                break;
            }
        }
    } else {
        tmpB = headerB;
        headerB = dataB;
        dataB = tmpB;
        bl = hl;
    }
    i = strlen(nameB->data);
    if ((strncmp(buf, "-----END ", 9) != 0) ||
        (strncmp(nameB->data, &(buf[9]), i) != 0) ||
        (strncmp(&(buf[9 + i]), "-----\n", 6) != 0)) {
        PEMerr(PEM_F_PEM_READ_BIO, PEM_R_BAD_END_LINE);
        goto err;
    }

    EVP_DecodeInit(&ctx);
    i = EVP_DecodeUpdate(&ctx,
                         (unsigned char *)dataB->data, &bl,
                         (unsigned char *)dataB->data, bl);
    if (i < 0) {
        PEMerr(PEM_F_PEM_READ_BIO, PEM_R_BAD_BASE64_DECODE);
        goto err;
    }
    i = EVP_DecodeFinal(&ctx, (unsigned char *)&(dataB->data[bl]), &k);
    if (i < 0) {
        PEMerr(PEM_F_PEM_READ_BIO, PEM_R_BAD_BASE64_DECODE);
        goto err;
    }
    bl += k;

    if (bl == 0)
        goto err;
    *name = nameB->data;
    *header = headerB->data;
    *data = (unsigned char *)dataB->data;
    *len = bl;
    OPENSSL_free(nameB);
    OPENSSL_free(headerB);
    OPENSSL_free(dataB);
    return (1);
 err:
    BUF_MEM_free(nameB);
    BUF_MEM_free(headerB);
    BUF_MEM_free(dataB);
    return (0);
}

/*
 * Check pem string and return prefix length. If for example the pem_str ==
 * "RSA PRIVATE KEY" and suffix = "PRIVATE KEY" the return value is 3 for the
 * string "RSA".
 */

int pem_check_suffix(const char *pem_str, const char *suffix)
{
    int pem_len = strlen(pem_str);
    int suffix_len = strlen(suffix);
    const char *p;
    if (suffix_len + 1 >= pem_len)
        return 0;
    p = pem_str + pem_len - suffix_len;
    if (strcmp(p, suffix))
        return 0;
    p--;
    if (*p != ' ')
        return 0;
    return p - pem_str;
}
/* crypto/pem/pem_oth.c */
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
// #include "buffer.h"
// #include "objects.h"
// #include "evp.h"
// #include "rand.h"
// #include "x509.h"
// #include "pem.h"

/* Handle 'other' PEMs: not private keys */

void *PEM_ASN1_read_bio(d2i_of_void *d2i, const char *name, BIO *bp, void **x,
                        pem_password_cb *cb, void *u)
{
    const unsigned char *p = NULL;
    unsigned char *data = NULL;
    long len;
    char *ret = NULL;

    if (!PEM_bytes_read_bio(&data, &len, NULL, name, bp, cb, u))
        return NULL;
    p = data;
    ret = d2i(x, &p, len);
    if (ret == NULL)
        PEMerr(PEM_F_PEM_ASN1_READ_BIO, ERR_R_ASN1_LIB);
    OPENSSL_free(data);
    return (ret);
}
/* crypto/pem/pem_pkey.c */
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
// #include "buffer.h"
// #include "objects.h"
// #include "evp.h"
// #include "rand.h"
// #include "x509.h"
// #include "pkcs12.h"
// #include "pem.h"

static int do_pk8pkey(BIO *bp, EVP_PKEY *x, int isder,
                      int nid, const EVP_CIPHER *enc,
                      char *kstr, int klen, pem_password_cb *cb, void *u);
static int do_pk8pkey_fp(FILE *bp, EVP_PKEY *x, int isder,
                         int nid, const EVP_CIPHER *enc,
                         char *kstr, int klen, pem_password_cb *cb, void *u);

/*
 * These functions write a private key in PKCS#8 format: it is a "drop in"
 * replacement for PEM_write_bio_PrivateKey() and friends. As usual if 'enc'
 * is NULL then it uses the unencrypted private key form. The 'nid' versions
 * uses PKCS#5 v1.5 PBE algorithms whereas the others use PKCS#5 v2.0.
 */

int PEM_write_bio_PKCS8PrivateKey_nid(BIO *bp, EVP_PKEY *x, int nid,
                                      char *kstr, int klen,
                                      pem_password_cb *cb, void *u)
{
    return do_pk8pkey(bp, x, 0, nid, NULL, kstr, klen, cb, u);
}

int PEM_write_bio_PKCS8PrivateKey(BIO *bp, EVP_PKEY *x, const EVP_CIPHER *enc,
                                  char *kstr, int klen,
                                  pem_password_cb *cb, void *u)
{
    return do_pk8pkey(bp, x, 0, -1, enc, kstr, klen, cb, u);
}

int i2d_PKCS8PrivateKey_bio(BIO *bp, EVP_PKEY *x, const EVP_CIPHER *enc,
                            char *kstr, int klen,
                            pem_password_cb *cb, void *u)
{
    return do_pk8pkey(bp, x, 1, -1, enc, kstr, klen, cb, u);
}

int i2d_PKCS8PrivateKey_nid_bio(BIO *bp, EVP_PKEY *x, int nid,
                                char *kstr, int klen,
                                pem_password_cb *cb, void *u)
{
    return do_pk8pkey(bp, x, 1, nid, NULL, kstr, klen, cb, u);
}

static int do_pk8pkey(BIO *bp, EVP_PKEY *x, int isder, int nid,
                      const EVP_CIPHER *enc, char *kstr, int klen,
                      pem_password_cb *cb, void *u)
{
    X509_SIG *p8;
    PKCS8_PRIV_KEY_INFO *p8inf;
    char buf[PEM_BUFSIZE];
    int ret;
    if (!(p8inf = EVP_PKEY2PKCS8(x))) {
        PEMerr(PEM_F_DO_PK8PKEY, PEM_R_ERROR_CONVERTING_PRIVATE_KEY);
        return 0;
    }
    if (enc || (nid != -1)) {
        if (!kstr) {
            if (!cb)
                klen = PEM_def_callback(buf, PEM_BUFSIZE, 1, u);
            else
                klen = cb(buf, PEM_BUFSIZE, 1, u);
            if (klen <= 0) {
                PEMerr(PEM_F_DO_PK8PKEY, PEM_R_READ_KEY);
                PKCS8_PRIV_KEY_INFO_free(p8inf);
                return 0;
            }

            kstr = buf;
        }
        p8 = PKCS8_encrypt(nid, enc, kstr, klen, NULL, 0, 0, p8inf);
        if (kstr == buf)
            OPENSSL_cleanse(buf, klen);
        PKCS8_PRIV_KEY_INFO_free(p8inf);
        if (p8 == NULL)
            return 0;
        if (isder)
            ret = i2d_PKCS8_bio(bp, p8);
        else
            ret = PEM_write_bio_PKCS8(bp, p8);
        X509_SIG_free(p8);
        return ret;
    } else {
        if (isder)
            ret = i2d_PKCS8_PRIV_KEY_INFO_bio(bp, p8inf);
        else
            ret = PEM_write_bio_PKCS8_PRIV_KEY_INFO(bp, p8inf);
        PKCS8_PRIV_KEY_INFO_free(p8inf);
        return ret;
    }
}

EVP_PKEY *d2i_PKCS8PrivateKey_bio(BIO *bp, EVP_PKEY **x, pem_password_cb *cb,
                                  void *u)
{
    PKCS8_PRIV_KEY_INFO *p8inf = NULL;
    X509_SIG *p8 = NULL;
    int klen;
    EVP_PKEY *ret;
    char psbuf[PEM_BUFSIZE];
    p8 = d2i_PKCS8_bio(bp, NULL);
    if (!p8)
        return NULL;
    if (cb)
        klen = cb(psbuf, PEM_BUFSIZE, 0, u);
    else
        klen = PEM_def_callback(psbuf, PEM_BUFSIZE, 0, u);
    if (klen < 0) {
        PEMerr(PEM_F_D2I_PKCS8PRIVATEKEY_BIO, PEM_R_BAD_PASSWORD_READ);
        X509_SIG_free(p8);
        return NULL;
    }
    p8inf = PKCS8_decrypt(p8, psbuf, klen);
    X509_SIG_free(p8);
    OPENSSL_cleanse(psbuf, klen);
    if (!p8inf)
        return NULL;
    ret = EVP_PKCS82PKEY(p8inf);
    PKCS8_PRIV_KEY_INFO_free(p8inf);
    if (!ret)
        return NULL;
    if (x) {
        if (*x)
            EVP_PKEY_free(*x);
        *x = ret;
    }
    return ret;
}

#ifndef OPENSSL_NO_FP_API

int i2d_PKCS8PrivateKey_fp(FILE *fp, EVP_PKEY *x, const EVP_CIPHER *enc,
                           char *kstr, int klen, pem_password_cb *cb, void *u)
{
    return do_pk8pkey_fp(fp, x, 1, -1, enc, kstr, klen, cb, u);
}

int i2d_PKCS8PrivateKey_nid_fp(FILE *fp, EVP_PKEY *x, int nid,
                               char *kstr, int klen,
                               pem_password_cb *cb, void *u)
{
    return do_pk8pkey_fp(fp, x, 1, nid, NULL, kstr, klen, cb, u);
}

int PEM_write_PKCS8PrivateKey_nid(FILE *fp, EVP_PKEY *x, int nid,
                                  char *kstr, int klen,
                                  pem_password_cb *cb, void *u)
{
    return do_pk8pkey_fp(fp, x, 0, nid, NULL, kstr, klen, cb, u);
}

int PEM_write_PKCS8PrivateKey(FILE *fp, EVP_PKEY *x, const EVP_CIPHER *enc,
                              char *kstr, int klen, pem_password_cb *cb,
                              void *u)
{
    return do_pk8pkey_fp(fp, x, 0, -1, enc, kstr, klen, cb, u);
}

static int do_pk8pkey_fp(FILE *fp, EVP_PKEY *x, int isder, int nid,
                         const EVP_CIPHER *enc, char *kstr, int klen,
                         pem_password_cb *cb, void *u)
{
    BIO *bp;
    int ret;
    if (!(bp = BIO_new_fp(fp, BIO_NOCLOSE))) {
        PEMerr(PEM_F_DO_PK8PKEY_FP, ERR_R_BUF_LIB);
        return (0);
    }
    ret = do_pk8pkey(bp, x, isder, nid, enc, kstr, klen, cb, u);
    BIO_free(bp);
    return ret;
}

EVP_PKEY *d2i_PKCS8PrivateKey_fp(FILE *fp, EVP_PKEY **x, pem_password_cb *cb,
                                 void *u)
{
    BIO *bp;
    EVP_PKEY *ret;
    if (!(bp = BIO_new_fp(fp, BIO_NOCLOSE))) {
        PEMerr(PEM_F_D2I_PKCS8PRIVATEKEY_FP, ERR_R_BUF_LIB);
        return NULL;
    }
    ret = d2i_PKCS8PrivateKey_bio(bp, x, cb, u);
    BIO_free(bp);
    return ret;
}

#endif

IMPLEMENT_PEM_rw(PKCS8, X509_SIG, PEM_STRING_PKCS8, X509_SIG)


IMPLEMENT_PEM_rw(PKCS8_PRIV_KEY_INFO, PKCS8_PRIV_KEY_INFO, PEM_STRING_PKCS8INF,
             PKCS8_PRIV_KEY_INFO)
/* crypto/pem/pem_pkey.c */
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
// #include "buffer.h"
// #include "objects.h"
// #include "evp.h"
// #include "rand.h"
// #include "x509.h"
// #include "pkcs12.h"
// #include "pem.h"
#ifndef OPENSSL_NO_ENGINE
# include "engine.h"
#endif
#ifndef OPENSSL_NO_DH
# include "dh.h"
#endif
// #include "asn1_locl.h"

int pem_check_suffix(const char *pem_str, const char *suffix);

EVP_PKEY *PEM_read_bio_PrivateKey(BIO *bp, EVP_PKEY **x, pem_password_cb *cb,
                                  void *u)
{
    char *nm = NULL;
    const unsigned char *p = NULL;
    unsigned char *data = NULL;
    long len;
    int slen;
    EVP_PKEY *ret = NULL;

    if (!PEM_bytes_read_bio(&data, &len, &nm, PEM_STRING_EVP_PKEY, bp, cb, u))
        return NULL;
    p = data;

    if (strcmp(nm, PEM_STRING_PKCS8INF) == 0) {
        PKCS8_PRIV_KEY_INFO *p8inf;
        p8inf = d2i_PKCS8_PRIV_KEY_INFO(NULL, &p, len);
        if (!p8inf)
            goto p8err;
        ret = EVP_PKCS82PKEY(p8inf);
        if (x) {
            if (*x)
                EVP_PKEY_free((EVP_PKEY *)*x);
            *x = ret;
        }
        PKCS8_PRIV_KEY_INFO_free(p8inf);
    } else if (strcmp(nm, PEM_STRING_PKCS8) == 0) {
        PKCS8_PRIV_KEY_INFO *p8inf;
        X509_SIG *p8;
        int klen;
        char psbuf[PEM_BUFSIZE];
        p8 = d2i_X509_SIG(NULL, &p, len);
        if (!p8)
            goto p8err;
        if (cb)
            klen = cb(psbuf, PEM_BUFSIZE, 0, u);
        else
            klen = PEM_def_callback(psbuf, PEM_BUFSIZE, 0, u);
        if (klen < 0) {
            PEMerr(PEM_F_PEM_READ_BIO_PRIVATEKEY, PEM_R_BAD_PASSWORD_READ);
            X509_SIG_free(p8);
            goto err;
        }
        p8inf = PKCS8_decrypt(p8, psbuf, klen);
        X509_SIG_free(p8);
        OPENSSL_cleanse(psbuf, klen);
        if (!p8inf)
            goto p8err;
        ret = EVP_PKCS82PKEY(p8inf);
        if (x) {
            if (*x)
                EVP_PKEY_free((EVP_PKEY *)*x);
            *x = ret;
        }
        PKCS8_PRIV_KEY_INFO_free(p8inf);
    } else if ((slen = pem_check_suffix(nm, "PRIVATE KEY")) > 0) {
        const EVP_PKEY_ASN1_METHOD *ameth;
        ameth = EVP_PKEY_asn1_find_str(NULL, nm, slen);
        if (!ameth || !ameth->old_priv_decode)
            goto p8err;
        ret = d2i_PrivateKey(ameth->pkey_id, x, &p, len);
    }
 p8err:
    if (ret == NULL)
        PEMerr(PEM_F_PEM_READ_BIO_PRIVATEKEY, ERR_R_ASN1_LIB);
 err:
    OPENSSL_free(nm);
    OPENSSL_cleanse(data, len);
    OPENSSL_free(data);
    return (ret);
}

int PEM_write_bio_PrivateKey(BIO *bp, EVP_PKEY *x, const EVP_CIPHER *enc,
                             unsigned char *kstr, int klen,
                             pem_password_cb *cb, void *u)
{
    char pem_str[80];
    if (!x->ameth || x->ameth->priv_encode)
        return PEM_write_bio_PKCS8PrivateKey(bp, x, enc,
                                             (char *)kstr, klen, cb, u);

    BIO_snprintf(pem_str, 80, "%s PRIVATE KEY", x->ameth->pem_str);
    return PEM_ASN1_write_bio((i2d_of_void *)i2d_PrivateKey,
                              pem_str, bp, x, enc, kstr, klen, cb, u);
}

EVP_PKEY *PEM_read_bio_Parameters(BIO *bp, EVP_PKEY **x)
{
    char *nm = NULL;
    const unsigned char *p = NULL;
    unsigned char *data = NULL;
    long len;
    int slen;
    EVP_PKEY *ret = NULL;

    if (!PEM_bytes_read_bio(&data, &len, &nm, PEM_STRING_PARAMETERS,
                            bp, 0, NULL))
        return NULL;
    p = data;

    if ((slen = pem_check_suffix(nm, "PARAMETERS")) > 0) {
        ret = EVP_PKEY_new();
        if (!ret)
            goto err;
        if (!EVP_PKEY_set_type_str(ret, nm, slen)
            || !ret->ameth->param_decode
            || !ret->ameth->param_decode(ret, &p, len)) {
            EVP_PKEY_free(ret);
            ret = NULL;
            goto err;
        }
        if (x) {
            if (*x)
                EVP_PKEY_free((EVP_PKEY *)*x);
            *x = ret;
        }
    }
 err:
    if (ret == NULL)
        PEMerr(PEM_F_PEM_READ_BIO_PARAMETERS, ERR_R_ASN1_LIB);
    OPENSSL_free(nm);
    OPENSSL_free(data);
    return (ret);
}

int PEM_write_bio_Parameters(BIO *bp, EVP_PKEY *x)
{
    char pem_str[80];
    if (!x->ameth || !x->ameth->param_encode)
        return 0;

    BIO_snprintf(pem_str, 80, "%s PARAMETERS", x->ameth->pem_str);
    return PEM_ASN1_write_bio((i2d_of_void *)x->ameth->param_encode,
                              pem_str, bp, x, NULL, NULL, 0, 0, NULL);
}

#ifndef OPENSSL_NO_FP_API
EVP_PKEY *PEM_read_PrivateKey(FILE *fp, EVP_PKEY **x, pem_password_cb *cb,
                              void *u)
{
    BIO *b;
    EVP_PKEY *ret;

    if ((b = BIO_new(BIO_s_file())) == NULL) {
        PEMerr(PEM_F_PEM_READ_PRIVATEKEY, ERR_R_BUF_LIB);
        return (0);
    }
    BIO_set_fp(b, fp, BIO_NOCLOSE);
    ret = PEM_read_bio_PrivateKey(b, x, cb, u);
    BIO_free(b);
    return (ret);
}

int PEM_write_PrivateKey(FILE *fp, EVP_PKEY *x, const EVP_CIPHER *enc,
                         unsigned char *kstr, int klen,
                         pem_password_cb *cb, void *u)
{
    BIO *b;
    int ret;

    if ((b = BIO_new_fp(fp, BIO_NOCLOSE)) == NULL) {
        PEMerr(PEM_F_PEM_WRITE_PRIVATEKEY, ERR_R_BUF_LIB);
        return 0;
    }
    ret = PEM_write_bio_PrivateKey(b, x, enc, kstr, klen, cb, u);
    BIO_free(b);
    return ret;
}

#endif

#ifndef OPENSSL_NO_DH

/* Transparently read in PKCS#3 or X9.42 DH parameters */

DH *PEM_read_bio_DHparams(BIO *bp, DH **x, pem_password_cb *cb, void *u)
{
    char *nm = NULL;
    const unsigned char *p = NULL;
    unsigned char *data = NULL;
    long len;
    DH *ret = NULL;

    if (!PEM_bytes_read_bio(&data, &len, &nm, PEM_STRING_DHPARAMS, bp, cb, u))
        return NULL;
    p = data;

    if (!strcmp(nm, PEM_STRING_DHXPARAMS))
        ret = d2i_DHxparams(x, &p, len);
    else
        ret = d2i_DHparams(x, &p, len);

    if (ret == NULL)
        PEMerr(PEM_F_PEM_READ_BIO_DHPARAMS, ERR_R_ASN1_LIB);
    OPENSSL_free(nm);
    OPENSSL_free(data);
    return ret;
}

# ifndef OPENSSL_NO_FP_API
DH *PEM_read_DHparams(FILE *fp, DH **x, pem_password_cb *cb, void *u)
{
    BIO *b;
    DH *ret;

    if ((b = BIO_new(BIO_s_file())) == NULL) {
        PEMerr(PEM_F_PEM_READ_DHPARAMS, ERR_R_BUF_LIB);
        return (0);
    }
    BIO_set_fp(b, fp, BIO_NOCLOSE);
    ret = PEM_read_bio_DHparams(b, x, cb, u);
    BIO_free(b);
    return (ret);
}
# endif

#endif
/* crypto/pem/pem_seal.c */
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

#include "opensslconf.h" /* for OPENSSL_NO_RSA */
#ifndef OPENSSL_NO_RSA
# include <stdio.h>
# include "cryptlib.h"
# include "evp.h"
# include "rand.h"
# include "objects.h"
# include "x509.h"
# include "pem.h"
# include "rsa.h"

int PEM_SealInit(PEM_ENCODE_SEAL_CTX *ctx, EVP_CIPHER *type, EVP_MD *md_type,
                 unsigned char **ek, int *ekl, unsigned char *iv,
                 EVP_PKEY **pubk, int npubk)
{
    unsigned char key[EVP_MAX_KEY_LENGTH];
    int ret = -1;
    int i, j, max = 0;
    char *s = NULL;

    for (i = 0; i < npubk; i++) {
        if (pubk[i]->type != EVP_PKEY_RSA) {
            PEMerr(PEM_F_PEM_SEALINIT, PEM_R_PUBLIC_KEY_NO_RSA);
            goto err;
        }
        j = RSA_size(pubk[i]->pkey.rsa);
        if (j > max)
            max = j;
    }
    s = (char *)OPENSSL_malloc(max * 2);
    if (s == NULL) {
        PEMerr(PEM_F_PEM_SEALINIT, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    EVP_EncodeInit(&ctx->encode);

    EVP_MD_CTX_init(&ctx->md);
    if (!EVP_SignInit(&ctx->md, md_type))
        goto err;

    EVP_CIPHER_CTX_init(&ctx->cipher);
    ret = EVP_SealInit(&ctx->cipher, type, ek, ekl, iv, pubk, npubk);
    if (ret <= 0)
        goto err;

    /* base64 encode the keys */
    for (i = 0; i < npubk; i++) {
        j = EVP_EncodeBlock((unsigned char *)s, ek[i],
                            RSA_size(pubk[i]->pkey.rsa));
        ekl[i] = j;
        memcpy(ek[i], s, j + 1);
    }

    ret = npubk;
 err:
    if (s != NULL)
        OPENSSL_free(s);
    OPENSSL_cleanse(key, EVP_MAX_KEY_LENGTH);
    return (ret);
}

void PEM_SealUpdate(PEM_ENCODE_SEAL_CTX *ctx, unsigned char *out, int *outl,
                    unsigned char *in, int inl)
{
    unsigned char buffer[1600];
    int i, j;

    *outl = 0;
    EVP_SignUpdate(&ctx->md, in, inl);
    for (;;) {
        if (inl <= 0)
            break;
        if (inl > 1200)
            i = 1200;
        else
            i = inl;
        EVP_EncryptUpdate(&ctx->cipher, buffer, &j, in, i);
        EVP_EncodeUpdate(&ctx->encode, out, &j, buffer, j);
        *outl += j;
        out += j;
        in += i;
        inl -= i;
    }
}

int PEM_SealFinal(PEM_ENCODE_SEAL_CTX *ctx, unsigned char *sig, int *sigl,
                  unsigned char *out, int *outl, EVP_PKEY *priv)
{
    unsigned char *s = NULL;
    int ret = 0, j;
    unsigned int i;

    if (priv->type != EVP_PKEY_RSA) {
        PEMerr(PEM_F_PEM_SEALFINAL, PEM_R_PUBLIC_KEY_NO_RSA);
        goto err;
    }
    i = RSA_size(priv->pkey.rsa);
    if (i < 100)
        i = 100;
    s = (unsigned char *)OPENSSL_malloc(i * 2);
    if (s == NULL) {
        PEMerr(PEM_F_PEM_SEALFINAL, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (!EVP_EncryptFinal_ex(&ctx->cipher, s, (int *)&i))
        goto err;
    EVP_EncodeUpdate(&ctx->encode, out, &j, s, i);
    *outl = j;
    out += j;
    EVP_EncodeFinal(&ctx->encode, out, &j);
    *outl += j;

    if (!EVP_SignFinal(&ctx->md, s, &i, priv))
        goto err;
    *sigl = EVP_EncodeBlock(sig, s, i);

    ret = 1;
 err:
    EVP_MD_CTX_cleanup(&ctx->md);
    EVP_CIPHER_CTX_cleanup(&ctx->cipher);
    if (s != NULL)
        OPENSSL_free(s);
    return (ret);
}
#else                           /* !OPENSSL_NO_RSA */

# if PEDANTIC
static void *dummy = &dummy;
# endif

#endif
/* crypto/pem/pem_sign.c */
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
// #include "rand.h"
// #include "evp.h"
// #include "objects.h"
// #include "x509.h"
// #include "pem.h"

void PEM_SignInit(EVP_MD_CTX *ctx, EVP_MD *type)
{
    EVP_DigestInit_ex(ctx, type, NULL);
}

void PEM_SignUpdate(EVP_MD_CTX *ctx, unsigned char *data, unsigned int count)
{
    EVP_DigestUpdate(ctx, data, count);
}

int PEM_SignFinal(EVP_MD_CTX *ctx, unsigned char *sigret,
                  unsigned int *siglen, EVP_PKEY *pkey)
{
    unsigned char *m;
    int i, ret = 0;
    unsigned int m_len;

    m = (unsigned char *)OPENSSL_malloc(EVP_PKEY_size(pkey) + 2);
    if (m == NULL) {
        PEMerr(PEM_F_PEM_SIGNFINAL, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (EVP_SignFinal(ctx, m, &m_len, pkey) <= 0)
        goto err;

    i = EVP_EncodeBlock(sigret, m, m_len);
    *siglen = i;
    ret = 1;
 err:
    /* ctx has been zeroed by EVP_SignFinal() */
    if (m != NULL)
        OPENSSL_free(m);
    return (ret);
}
/* pem_x509.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
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

#include <stdio.h>
// #include "cryptlib.h"
// #include "bio.h"
// #include "evp.h"
// #include "x509.h"
// #include "pkcs7.h"
// #include "pem.h"

IMPLEMENT_PEM_rw(X509, X509, PEM_STRING_X509, X509)
/* pem_xaux.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
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

#include <stdio.h>
// #include "cryptlib.h"
// #include "bio.h"
// #include "evp.h"
// #include "x509.h"
// #include "pkcs7.h"
// #include "pem.h"

IMPLEMENT_PEM_rw(X509_AUX, X509, PEM_STRING_X509_TRUSTED, X509_AUX)
IMPLEMENT_PEM_rw(X509_CERT_PAIR, X509_CERT_PAIR, PEM_STRING_X509_PAIR,
                 X509_CERT_PAIR)
