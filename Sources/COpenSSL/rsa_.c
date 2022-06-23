/* crypto/rsa/rsa_ameth.c */
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
#include "cryptlib.h"
#include "asn1t.h"
#include "x509.h"
#include "rsa.h"
#include "bn.h"
#ifndef OPENSSL_NO_CMS
# include "cms.h"
#endif
#include "asn1_locl.h"

#ifndef OPENSSL_NO_CMS
static int rsa_cms_sign(CMS_SignerInfo *si);
static int rsa_cms_verify(CMS_SignerInfo *si);
static int rsa_cms_decrypt(CMS_RecipientInfo *ri);
static int rsa_cms_encrypt(CMS_RecipientInfo *ri);
#endif

static int rsa_pub_encode(X509_PUBKEY *pk, const EVP_PKEY *pkey)
{
    unsigned char *penc = NULL;
    int penclen;
    penclen = i2d_RSAPublicKey(pkey->pkey.rsa, &penc);
    if (penclen <= 0)
        return 0;
    if (X509_PUBKEY_set0_param(pk, OBJ_nid2obj(EVP_PKEY_RSA),
                               V_ASN1_NULL, NULL, penc, penclen))
        return 1;

    OPENSSL_free(penc);
    return 0;
}

static int rsa_pub_decode(EVP_PKEY *pkey, X509_PUBKEY *pubkey)
{
    const unsigned char *p;
    int pklen;
    RSA *rsa = NULL;
    if (!X509_PUBKEY_get0_param(NULL, &p, &pklen, NULL, pubkey))
        return 0;
    if (!(rsa = d2i_RSAPublicKey(NULL, &p, pklen))) {
        RSAerr(RSA_F_RSA_PUB_DECODE, ERR_R_RSA_LIB);
        return 0;
    }
    EVP_PKEY_assign_RSA(pkey, rsa);
    return 1;
}

static int rsa_pub_cmp(const EVP_PKEY *a, const EVP_PKEY *b)
{
    if (BN_cmp(b->pkey.rsa->n, a->pkey.rsa->n) != 0
        || BN_cmp(b->pkey.rsa->e, a->pkey.rsa->e) != 0)
        return 0;
    return 1;
}

static int old_rsa_priv_decode(EVP_PKEY *pkey,
                               const unsigned char **pder, int derlen)
{
    RSA *rsa;
    if (!(rsa = d2i_RSAPrivateKey(NULL, pder, derlen))) {
        RSAerr(RSA_F_OLD_RSA_PRIV_DECODE, ERR_R_RSA_LIB);
        return 0;
    }
    EVP_PKEY_assign_RSA(pkey, rsa);
    return 1;
}

static int old_rsa_priv_encode(const EVP_PKEY *pkey, unsigned char **pder)
{
    return i2d_RSAPrivateKey(pkey->pkey.rsa, pder);
}

static int rsa_priv_encode(PKCS8_PRIV_KEY_INFO *p8, const EVP_PKEY *pkey)
{
    unsigned char *rk = NULL;
    int rklen;
    rklen = i2d_RSAPrivateKey(pkey->pkey.rsa, &rk);

    if (rklen <= 0) {
        RSAerr(RSA_F_RSA_PRIV_ENCODE, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    if (!PKCS8_pkey_set0(p8, OBJ_nid2obj(NID_rsaEncryption), 0,
                         V_ASN1_NULL, NULL, rk, rklen)) {
        RSAerr(RSA_F_RSA_PRIV_ENCODE, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    return 1;
}

static int rsa_priv_decode(EVP_PKEY *pkey, PKCS8_PRIV_KEY_INFO *p8)
{
    const unsigned char *p;
    int pklen;
    if (!PKCS8_pkey_get0(NULL, &p, &pklen, NULL, p8))
        return 0;
    return old_rsa_priv_decode(pkey, &p, pklen);
}

static int int_rsa_size(const EVP_PKEY *pkey)
{
    return RSA_size(pkey->pkey.rsa);
}

static int rsa_bits(const EVP_PKEY *pkey)
{
    return BN_num_bits(pkey->pkey.rsa->n);
}

static void int_rsa_free(EVP_PKEY *pkey)
{
    RSA_free(pkey->pkey.rsa);
}

static void update_buflen(const BIGNUM *b, size_t *pbuflen)
{
    size_t i;
    if (!b)
        return;
    if (*pbuflen < (i = (size_t)BN_num_bytes(b)))
        *pbuflen = i;
}

static int do_rsa_print(BIO *bp, const RSA *x, int off, int priv)
{
    char *str;
    const char *s;
    unsigned char *m = NULL;
    int ret = 0, mod_len = 0;
    size_t buf_len = 0;

    update_buflen(x->n, &buf_len);
    update_buflen(x->e, &buf_len);

    if (priv) {
        update_buflen(x->d, &buf_len);
        update_buflen(x->p, &buf_len);
        update_buflen(x->q, &buf_len);
        update_buflen(x->dmp1, &buf_len);
        update_buflen(x->dmq1, &buf_len);
        update_buflen(x->iqmp, &buf_len);
    }

    m = (unsigned char *)OPENSSL_malloc(buf_len + 10);
    if (m == NULL) {
        RSAerr(RSA_F_DO_RSA_PRINT, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (x->n != NULL)
        mod_len = BN_num_bits(x->n);

    if (!BIO_indent(bp, off, 128))
        goto err;

    if (priv && x->d) {
        if (BIO_printf(bp, "Private-Key: (%d bit)\n", mod_len)
            <= 0)
            goto err;
        str = "modulus:";
        s = "publicExponent:";
    } else {
        if (BIO_printf(bp, "Public-Key: (%d bit)\n", mod_len)
            <= 0)
            goto err;
        str = "Modulus:";
        s = "Exponent:";
    }
    if (!ASN1_bn_print(bp, str, x->n, m, off))
        goto err;
    if (!ASN1_bn_print(bp, s, x->e, m, off))
        goto err;
    if (priv) {
        if (!ASN1_bn_print(bp, "privateExponent:", x->d, m, off))
            goto err;
        if (!ASN1_bn_print(bp, "prime1:", x->p, m, off))
            goto err;
        if (!ASN1_bn_print(bp, "prime2:", x->q, m, off))
            goto err;
        if (!ASN1_bn_print(bp, "exponent1:", x->dmp1, m, off))
            goto err;
        if (!ASN1_bn_print(bp, "exponent2:", x->dmq1, m, off))
            goto err;
        if (!ASN1_bn_print(bp, "coefficient:", x->iqmp, m, off))
            goto err;
    }
    ret = 1;
 err:
    if (m != NULL)
        OPENSSL_free(m);
    return (ret);
}

static int rsa_pub_print(BIO *bp, const EVP_PKEY *pkey, int indent,
                         ASN1_PCTX *ctx)
{
    return do_rsa_print(bp, pkey->pkey.rsa, indent, 0);
}

static int rsa_priv_print(BIO *bp, const EVP_PKEY *pkey, int indent,
                          ASN1_PCTX *ctx)
{
    return do_rsa_print(bp, pkey->pkey.rsa, indent, 1);
}

/* Given an MGF1 Algorithm ID decode to an Algorithm Identifier */
static X509_ALGOR *rsa_mgf1_decode(X509_ALGOR *alg)
{
    const unsigned char *p;
    int plen;
    if (alg == NULL || alg->parameter == NULL)
        return NULL;
    if (OBJ_obj2nid(alg->algorithm) != NID_mgf1)
        return NULL;
    if (alg->parameter->type != V_ASN1_SEQUENCE)
        return NULL;

    p = alg->parameter->value.sequence->data;
    plen = alg->parameter->value.sequence->length;
    return d2i_X509_ALGOR(NULL, &p, plen);
}

static RSA_PSS_PARAMS *rsa_pss_decode(const X509_ALGOR *alg,
                                      X509_ALGOR **pmaskHash)
{
    const unsigned char *p;
    int plen;
    RSA_PSS_PARAMS *pss;

    *pmaskHash = NULL;

    if (!alg->parameter || alg->parameter->type != V_ASN1_SEQUENCE)
        return NULL;
    p = alg->parameter->value.sequence->data;
    plen = alg->parameter->value.sequence->length;
    pss = d2i_RSA_PSS_PARAMS(NULL, &p, plen);

    if (!pss)
        return NULL;

    *pmaskHash = rsa_mgf1_decode(pss->maskGenAlgorithm);

    return pss;
}

static int rsa_pss_param_print(BIO *bp, RSA_PSS_PARAMS *pss,
                               X509_ALGOR *maskHash, int indent)
{
    int rv = 0;
    if (!pss) {
        if (BIO_puts(bp, " (INVALID PSS PARAMETERS)\n") <= 0)
            return 0;
        return 1;
    }
    if (BIO_puts(bp, "\n") <= 0)
        goto err;
    if (!BIO_indent(bp, indent, 128))
        goto err;
    if (BIO_puts(bp, "Hash Algorithm: ") <= 0)
        goto err;

    if (pss->hashAlgorithm) {
        if (i2a_ASN1_OBJECT(bp, pss->hashAlgorithm->algorithm) <= 0)
            goto err;
    } else if (BIO_puts(bp, "sha1 (default)") <= 0)
        goto err;

    if (BIO_puts(bp, "\n") <= 0)
        goto err;

    if (!BIO_indent(bp, indent, 128))
        goto err;

    if (BIO_puts(bp, "Mask Algorithm: ") <= 0)
        goto err;
    if (pss->maskGenAlgorithm) {
        if (i2a_ASN1_OBJECT(bp, pss->maskGenAlgorithm->algorithm) <= 0)
            goto err;
        if (BIO_puts(bp, " with ") <= 0)
            goto err;
        if (maskHash) {
            if (i2a_ASN1_OBJECT(bp, maskHash->algorithm) <= 0)
                goto err;
        } else if (BIO_puts(bp, "INVALID") <= 0)
            goto err;
    } else if (BIO_puts(bp, "mgf1 with sha1 (default)") <= 0)
        goto err;
    BIO_puts(bp, "\n");

    if (!BIO_indent(bp, indent, 128))
        goto err;
    if (BIO_puts(bp, "Salt Length: 0x") <= 0)
        goto err;
    if (pss->saltLength) {
        if (i2a_ASN1_INTEGER(bp, pss->saltLength) <= 0)
            goto err;
    } else if (BIO_puts(bp, "14 (default)") <= 0)
        goto err;
    BIO_puts(bp, "\n");

    if (!BIO_indent(bp, indent, 128))
        goto err;
    if (BIO_puts(bp, "Trailer Field: 0x") <= 0)
        goto err;
    if (pss->trailerField) {
        if (i2a_ASN1_INTEGER(bp, pss->trailerField) <= 0)
            goto err;
    } else if (BIO_puts(bp, "BC (default)") <= 0)
        goto err;
    BIO_puts(bp, "\n");

    rv = 1;

 err:
    return rv;

}

static int rsa_sig_print(BIO *bp, const X509_ALGOR *sigalg,
                         const ASN1_STRING *sig, int indent, ASN1_PCTX *pctx)
{
    if (OBJ_obj2nid(sigalg->algorithm) == NID_rsassaPss) {
        int rv;
        RSA_PSS_PARAMS *pss;
        X509_ALGOR *maskHash;
        pss = rsa_pss_decode(sigalg, &maskHash);
        rv = rsa_pss_param_print(bp, pss, maskHash, indent);
        if (pss)
            RSA_PSS_PARAMS_free(pss);
        if (maskHash)
            X509_ALGOR_free(maskHash);
        if (!rv)
            return 0;
    } else if (!sig && BIO_puts(bp, "\n") <= 0)
        return 0;
    if (sig)
        return X509_signature_dump(bp, sig, indent);
    return 1;
}

static int rsa_pkey_ctrl(EVP_PKEY *pkey, int op, long arg1, void *arg2)
{
    X509_ALGOR *alg = NULL;
    switch (op) {

    case ASN1_PKEY_CTRL_PKCS7_SIGN:
        if (arg1 == 0)
            PKCS7_SIGNER_INFO_get0_algs(arg2, NULL, NULL, &alg);
        break;

    case ASN1_PKEY_CTRL_PKCS7_ENCRYPT:
        if (arg1 == 0)
            PKCS7_RECIP_INFO_get0_alg(arg2, &alg);
        break;
#ifndef OPENSSL_NO_CMS
    case ASN1_PKEY_CTRL_CMS_SIGN:
        if (arg1 == 0)
            return rsa_cms_sign(arg2);
        else if (arg1 == 1)
            return rsa_cms_verify(arg2);
        break;

    case ASN1_PKEY_CTRL_CMS_ENVELOPE:
        if (arg1 == 0)
            return rsa_cms_encrypt(arg2);
        else if (arg1 == 1)
            return rsa_cms_decrypt(arg2);
        break;

    case ASN1_PKEY_CTRL_CMS_RI_TYPE:
        *(int *)arg2 = CMS_RECIPINFO_TRANS;
        return 1;
#endif

    case ASN1_PKEY_CTRL_DEFAULT_MD_NID:
        *(int *)arg2 = NID_sha256;
        return 1;

    default:
        return -2;

    }

    if (alg)
        X509_ALGOR_set0(alg, OBJ_nid2obj(NID_rsaEncryption), V_ASN1_NULL, 0);

    return 1;

}

/* allocate and set algorithm ID from EVP_MD, default SHA1 */
static int rsa_md_to_algor(X509_ALGOR **palg, const EVP_MD *md)
{
    if (EVP_MD_type(md) == NID_sha1)
        return 1;
    *palg = X509_ALGOR_new();
    if (!*palg)
        return 0;
    X509_ALGOR_set_md(*palg, md);
    return 1;
}

/* Allocate and set MGF1 algorithm ID from EVP_MD */
static int rsa_md_to_mgf1(X509_ALGOR **palg, const EVP_MD *mgf1md)
{
    X509_ALGOR *algtmp = NULL;
    ASN1_STRING *stmp = NULL;
    *palg = NULL;
    if (EVP_MD_type(mgf1md) == NID_sha1)
        return 1;
    /* need to embed algorithm ID inside another */
    if (!rsa_md_to_algor(&algtmp, mgf1md))
        goto err;
    if (!ASN1_item_pack(algtmp, ASN1_ITEM_rptr(X509_ALGOR), &stmp))
         goto err;
    *palg = X509_ALGOR_new();
    if (!*palg)
        goto err;
    X509_ALGOR_set0(*palg, OBJ_nid2obj(NID_mgf1), V_ASN1_SEQUENCE, stmp);
    stmp = NULL;
 err:
    if (stmp)
        ASN1_STRING_free(stmp);
    if (algtmp)
        X509_ALGOR_free(algtmp);
    if (*palg)
        return 1;
    return 0;
}

/* convert algorithm ID to EVP_MD, default SHA1 */
static const EVP_MD *rsa_algor_to_md(X509_ALGOR *alg)
{
    const EVP_MD *md;
    if (!alg)
        return EVP_sha1();
    md = EVP_get_digestbyobj(alg->algorithm);
    if (md == NULL)
        RSAerr(RSA_F_RSA_ALGOR_TO_MD, RSA_R_UNKNOWN_DIGEST);
    return md;
}

/* convert MGF1 algorithm ID to EVP_MD, default SHA1 */
static const EVP_MD *rsa_mgf1_to_md(X509_ALGOR *alg, X509_ALGOR *maskHash)
{
    const EVP_MD *md;
    if (!alg)
        return EVP_sha1();
    /* Check mask and lookup mask hash algorithm */
    if (OBJ_obj2nid(alg->algorithm) != NID_mgf1) {
        RSAerr(RSA_F_RSA_MGF1_TO_MD, RSA_R_UNSUPPORTED_MASK_ALGORITHM);
        return NULL;
    }
    if (!maskHash) {
        RSAerr(RSA_F_RSA_MGF1_TO_MD, RSA_R_UNSUPPORTED_MASK_PARAMETER);
        return NULL;
    }
    md = EVP_get_digestbyobj(maskHash->algorithm);
    if (md == NULL) {
        RSAerr(RSA_F_RSA_MGF1_TO_MD, RSA_R_UNKNOWN_MASK_DIGEST);
        return NULL;
    }
    return md;
}

/*
 * Convert EVP_PKEY_CTX is PSS mode into corresponding algorithm parameter,
 * suitable for setting an AlgorithmIdentifier.
 */

static ASN1_STRING *rsa_ctx_to_pss(EVP_PKEY_CTX *pkctx)
{
    const EVP_MD *sigmd, *mgf1md;
    RSA_PSS_PARAMS *pss = NULL;
    ASN1_STRING *os = NULL;
    EVP_PKEY *pk = EVP_PKEY_CTX_get0_pkey(pkctx);
    int saltlen, rv = 0;
    if (EVP_PKEY_CTX_get_signature_md(pkctx, &sigmd) <= 0)
        goto err;
    if (EVP_PKEY_CTX_get_rsa_mgf1_md(pkctx, &mgf1md) <= 0)
        goto err;
    if (!EVP_PKEY_CTX_get_rsa_pss_saltlen(pkctx, &saltlen))
        goto err;
    if (saltlen == -1)
        saltlen = EVP_MD_size(sigmd);
    else if (saltlen == -2) {
        saltlen = EVP_PKEY_size(pk) - EVP_MD_size(sigmd) - 2;
        if (((EVP_PKEY_bits(pk) - 1) & 0x7) == 0)
            saltlen--;
    }
    pss = RSA_PSS_PARAMS_new();
    if (!pss)
        goto err;
    if (saltlen != 20) {
        pss->saltLength = ASN1_INTEGER_new();
        if (!pss->saltLength)
            goto err;
        if (!ASN1_INTEGER_set(pss->saltLength, saltlen))
            goto err;
    }
    if (!rsa_md_to_algor(&pss->hashAlgorithm, sigmd))
        goto err;
    if (!rsa_md_to_mgf1(&pss->maskGenAlgorithm, mgf1md))
        goto err;
    /* Finally create string with pss parameter encoding. */
    if (!ASN1_item_pack(pss, ASN1_ITEM_rptr(RSA_PSS_PARAMS), &os))
         goto err;
    rv = 1;
 err:
    if (pss)
        RSA_PSS_PARAMS_free(pss);
    if (rv)
        return os;
    if (os)
        ASN1_STRING_free(os);
    return NULL;
}

/*
 * From PSS AlgorithmIdentifier set public key parameters. If pkey isn't NULL
 * then the EVP_MD_CTX is setup and initalised. If it is NULL parameters are
 * passed to pkctx instead.
 */

static int rsa_pss_to_ctx(EVP_MD_CTX *ctx, EVP_PKEY_CTX *pkctx,
                          X509_ALGOR *sigalg, EVP_PKEY *pkey)
{
    int rv = -1;
    int saltlen;
    const EVP_MD *mgf1md = NULL, *md = NULL;
    RSA_PSS_PARAMS *pss;
    X509_ALGOR *maskHash;
    /* Sanity check: make sure it is PSS */
    if (OBJ_obj2nid(sigalg->algorithm) != NID_rsassaPss) {
        RSAerr(RSA_F_RSA_PSS_TO_CTX, RSA_R_UNSUPPORTED_SIGNATURE_TYPE);
        return -1;
    }
    /* Decode PSS parameters */
    pss = rsa_pss_decode(sigalg, &maskHash);

    if (pss == NULL) {
        RSAerr(RSA_F_RSA_PSS_TO_CTX, RSA_R_INVALID_PSS_PARAMETERS);
        goto err;
    }
    mgf1md = rsa_mgf1_to_md(pss->maskGenAlgorithm, maskHash);
    if (!mgf1md)
        goto err;
    md = rsa_algor_to_md(pss->hashAlgorithm);
    if (!md)
        goto err;

    if (pss->saltLength) {
        saltlen = ASN1_INTEGER_get(pss->saltLength);

        /*
         * Could perform more salt length sanity checks but the main RSA
         * routines will trap other invalid values anyway.
         */
        if (saltlen < 0) {
            RSAerr(RSA_F_RSA_PSS_TO_CTX, RSA_R_INVALID_SALT_LENGTH);
            goto err;
        }
    } else
        saltlen = 20;

    /*
     * low-level routines support only trailer field 0xbc (value 1) and
     * PKCS#1 says we should reject any other value anyway.
     */
    if (pss->trailerField && ASN1_INTEGER_get(pss->trailerField) != 1) {
        RSAerr(RSA_F_RSA_PSS_TO_CTX, RSA_R_INVALID_TRAILER);
        goto err;
    }

    /* We have all parameters now set up context */

    if (pkey) {
        if (!EVP_DigestVerifyInit(ctx, &pkctx, md, NULL, pkey))
            goto err;
    } else {
        const EVP_MD *checkmd;
        if (EVP_PKEY_CTX_get_signature_md(pkctx, &checkmd) <= 0)
            goto err;
        if (EVP_MD_type(md) != EVP_MD_type(checkmd)) {
            RSAerr(RSA_F_RSA_PSS_TO_CTX, RSA_R_DIGEST_DOES_NOT_MATCH);
            goto err;
        }
    }

    if (EVP_PKEY_CTX_set_rsa_padding(pkctx, RSA_PKCS1_PSS_PADDING) <= 0)
        goto err;

    if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pkctx, saltlen) <= 0)
        goto err;

    if (EVP_PKEY_CTX_set_rsa_mgf1_md(pkctx, mgf1md) <= 0)
        goto err;
    /* Carry on */
    rv = 1;

 err:
    RSA_PSS_PARAMS_free(pss);
    if (maskHash)
        X509_ALGOR_free(maskHash);
    return rv;
}

#ifndef OPENSSL_NO_CMS
static int rsa_cms_verify(CMS_SignerInfo *si)
{
    int nid, nid2;
    X509_ALGOR *alg;
    EVP_PKEY_CTX *pkctx = CMS_SignerInfo_get0_pkey_ctx(si);
    CMS_SignerInfo_get0_algs(si, NULL, NULL, NULL, &alg);
    nid = OBJ_obj2nid(alg->algorithm);
    if (nid == NID_rsaEncryption)
        return 1;
    if (nid == NID_rsassaPss)
        return rsa_pss_to_ctx(NULL, pkctx, alg, NULL);
    /* Workaround for some implementation that use a signature OID */
    if (OBJ_find_sigid_algs(nid, NULL, &nid2)) {
        if (nid2 == NID_rsaEncryption)
            return 1;
    }
    return 0;
}
#endif

/*
 * Customised RSA item verification routine. This is called when a signature
 * is encountered requiring special handling. We currently only handle PSS.
 */

static int rsa_item_verify(EVP_MD_CTX *ctx, const ASN1_ITEM *it, void *asn,
                           X509_ALGOR *sigalg, ASN1_BIT_STRING *sig,
                           EVP_PKEY *pkey)
{
    /* Sanity check: make sure it is PSS */
    if (OBJ_obj2nid(sigalg->algorithm) != NID_rsassaPss) {
        RSAerr(RSA_F_RSA_ITEM_VERIFY, RSA_R_UNSUPPORTED_SIGNATURE_TYPE);
        return -1;
    }
    if (rsa_pss_to_ctx(ctx, NULL, sigalg, pkey) > 0) {
        /* Carry on */
        return 2;
    }
    return -1;
}

#ifndef OPENSSL_NO_CMS
static int rsa_cms_sign(CMS_SignerInfo *si)
{
    int pad_mode = RSA_PKCS1_PADDING;
    X509_ALGOR *alg;
    EVP_PKEY_CTX *pkctx = CMS_SignerInfo_get0_pkey_ctx(si);
    ASN1_STRING *os = NULL;
    CMS_SignerInfo_get0_algs(si, NULL, NULL, NULL, &alg);
    if (pkctx) {
        if (EVP_PKEY_CTX_get_rsa_padding(pkctx, &pad_mode) <= 0)
            return 0;
    }
    if (pad_mode == RSA_PKCS1_PADDING) {
        X509_ALGOR_set0(alg, OBJ_nid2obj(NID_rsaEncryption), V_ASN1_NULL, 0);
        return 1;
    }
    /* We don't support it */
    if (pad_mode != RSA_PKCS1_PSS_PADDING)
        return 0;
    os = rsa_ctx_to_pss(pkctx);
    if (!os)
        return 0;
    X509_ALGOR_set0(alg, OBJ_nid2obj(NID_rsassaPss), V_ASN1_SEQUENCE, os);
    return 1;
}
#endif

static int rsa_item_sign(EVP_MD_CTX *ctx, const ASN1_ITEM *it, void *asn,
                         X509_ALGOR *alg1, X509_ALGOR *alg2,
                         ASN1_BIT_STRING *sig)
{
    int pad_mode;
    EVP_PKEY_CTX *pkctx = ctx->pctx;
    if (EVP_PKEY_CTX_get_rsa_padding(pkctx, &pad_mode) <= 0)
        return 0;
    if (pad_mode == RSA_PKCS1_PADDING)
        return 2;
    if (pad_mode == RSA_PKCS1_PSS_PADDING) {
        ASN1_STRING *os1 = NULL;
        os1 = rsa_ctx_to_pss(pkctx);
        if (!os1)
            return 0;
        /* Duplicate parameters if we have to */
        if (alg2) {
            ASN1_STRING *os2 = ASN1_STRING_dup(os1);
            if (!os2) {
                ASN1_STRING_free(os1);
                return 0;
            }
            X509_ALGOR_set0(alg2, OBJ_nid2obj(NID_rsassaPss),
                            V_ASN1_SEQUENCE, os2);
        }
        X509_ALGOR_set0(alg1, OBJ_nid2obj(NID_rsassaPss),
                        V_ASN1_SEQUENCE, os1);
        return 3;
    }
    return 2;
}

#ifndef OPENSSL_NO_CMS
static RSA_OAEP_PARAMS *rsa_oaep_decode(const X509_ALGOR *alg,
                                        X509_ALGOR **pmaskHash)
{
    const unsigned char *p;
    int plen;
    RSA_OAEP_PARAMS *pss;

    *pmaskHash = NULL;

    if (!alg->parameter || alg->parameter->type != V_ASN1_SEQUENCE)
        return NULL;
    p = alg->parameter->value.sequence->data;
    plen = alg->parameter->value.sequence->length;
    pss = d2i_RSA_OAEP_PARAMS(NULL, &p, plen);

    if (!pss)
        return NULL;

    *pmaskHash = rsa_mgf1_decode(pss->maskGenFunc);

    return pss;
}

static int rsa_cms_decrypt(CMS_RecipientInfo *ri)
{
    EVP_PKEY_CTX *pkctx;
    X509_ALGOR *cmsalg;
    int nid;
    int rv = -1;
    unsigned char *label = NULL;
    int labellen = 0;
    const EVP_MD *mgf1md = NULL, *md = NULL;
    RSA_OAEP_PARAMS *oaep;
    X509_ALGOR *maskHash;
    pkctx = CMS_RecipientInfo_get0_pkey_ctx(ri);
    if (!pkctx)
        return 0;
    if (!CMS_RecipientInfo_ktri_get0_algs(ri, NULL, NULL, &cmsalg))
        return -1;
    nid = OBJ_obj2nid(cmsalg->algorithm);
    if (nid == NID_rsaEncryption)
        return 1;
    if (nid != NID_rsaesOaep) {
        RSAerr(RSA_F_RSA_CMS_DECRYPT, RSA_R_UNSUPPORTED_ENCRYPTION_TYPE);
        return -1;
    }
    /* Decode OAEP parameters */
    oaep = rsa_oaep_decode(cmsalg, &maskHash);

    if (oaep == NULL) {
        RSAerr(RSA_F_RSA_CMS_DECRYPT, RSA_R_INVALID_OAEP_PARAMETERS);
        goto err;
    }

    mgf1md = rsa_mgf1_to_md(oaep->maskGenFunc, maskHash);
    if (!mgf1md)
        goto err;
    md = rsa_algor_to_md(oaep->hashFunc);
    if (!md)
        goto err;

    if (oaep->pSourceFunc) {
        X509_ALGOR *plab = oaep->pSourceFunc;
        if (OBJ_obj2nid(plab->algorithm) != NID_pSpecified) {
            RSAerr(RSA_F_RSA_CMS_DECRYPT, RSA_R_UNSUPPORTED_LABEL_SOURCE);
            goto err;
        }
        if (plab->parameter->type != V_ASN1_OCTET_STRING) {
            RSAerr(RSA_F_RSA_CMS_DECRYPT, RSA_R_INVALID_LABEL);
            goto err;
        }

        label = plab->parameter->value.octet_string->data;
        /* Stop label being freed when OAEP parameters are freed */
        plab->parameter->value.octet_string->data = NULL;
        labellen = plab->parameter->value.octet_string->length;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(pkctx, RSA_PKCS1_OAEP_PADDING) <= 0)
        goto err;
    if (EVP_PKEY_CTX_set_rsa_oaep_md(pkctx, md) <= 0)
        goto err;
    if (EVP_PKEY_CTX_set_rsa_mgf1_md(pkctx, mgf1md) <= 0)
        goto err;
    if (EVP_PKEY_CTX_set0_rsa_oaep_label(pkctx, label, labellen) <= 0)
        goto err;
    /* Carry on */
    rv = 1;

 err:
    RSA_OAEP_PARAMS_free(oaep);
    if (maskHash)
        X509_ALGOR_free(maskHash);
    return rv;
}

static int rsa_cms_encrypt(CMS_RecipientInfo *ri)
{
    const EVP_MD *md, *mgf1md;
    RSA_OAEP_PARAMS *oaep = NULL;
    ASN1_STRING *os = NULL;
    X509_ALGOR *alg;
    EVP_PKEY_CTX *pkctx = CMS_RecipientInfo_get0_pkey_ctx(ri);
    int pad_mode = RSA_PKCS1_PADDING, rv = 0, labellen;
    unsigned char *label;
    CMS_RecipientInfo_ktri_get0_algs(ri, NULL, NULL, &alg);
    if (pkctx) {
        if (EVP_PKEY_CTX_get_rsa_padding(pkctx, &pad_mode) <= 0)
            return 0;
    }
    if (pad_mode == RSA_PKCS1_PADDING) {
        X509_ALGOR_set0(alg, OBJ_nid2obj(NID_rsaEncryption), V_ASN1_NULL, 0);
        return 1;
    }
    /* Not supported */
    if (pad_mode != RSA_PKCS1_OAEP_PADDING)
        return 0;
    if (EVP_PKEY_CTX_get_rsa_oaep_md(pkctx, &md) <= 0)
        goto err;
    if (EVP_PKEY_CTX_get_rsa_mgf1_md(pkctx, &mgf1md) <= 0)
        goto err;
    labellen = EVP_PKEY_CTX_get0_rsa_oaep_label(pkctx, &label);
    if (labellen < 0)
        goto err;
    oaep = RSA_OAEP_PARAMS_new();
    if (!oaep)
        goto err;
    if (!rsa_md_to_algor(&oaep->hashFunc, md))
        goto err;
    if (!rsa_md_to_mgf1(&oaep->maskGenFunc, mgf1md))
        goto err;
    if (labellen > 0) {
        ASN1_OCTET_STRING *los = ASN1_OCTET_STRING_new();
        oaep->pSourceFunc = X509_ALGOR_new();
        if (!oaep->pSourceFunc)
            goto err;
        if (!los)
            goto err;
        if (!ASN1_OCTET_STRING_set(los, label, labellen)) {
            ASN1_OCTET_STRING_free(los);
            goto err;
        }
        X509_ALGOR_set0(oaep->pSourceFunc, OBJ_nid2obj(NID_pSpecified),
                        V_ASN1_OCTET_STRING, los);
    }
    /* create string with pss parameter encoding. */
    if (!ASN1_item_pack(oaep, ASN1_ITEM_rptr(RSA_OAEP_PARAMS), &os))
         goto err;
    X509_ALGOR_set0(alg, OBJ_nid2obj(NID_rsaesOaep), V_ASN1_SEQUENCE, os);
    os = NULL;
    rv = 1;
 err:
    if (oaep)
        RSA_OAEP_PARAMS_free(oaep);
    if (os)
        ASN1_STRING_free(os);
    return rv;
}
#endif

const EVP_PKEY_ASN1_METHOD rsa_asn1_meths[] = {
    {
     EVP_PKEY_RSA,
     EVP_PKEY_RSA,
     ASN1_PKEY_SIGPARAM_NULL,

     "RSA",
     "OpenSSL RSA method",

     rsa_pub_decode,
     rsa_pub_encode,
     rsa_pub_cmp,
     rsa_pub_print,

     rsa_priv_decode,
     rsa_priv_encode,
     rsa_priv_print,

     int_rsa_size,
     rsa_bits,

     0, 0, 0, 0, 0, 0,

     rsa_sig_print,
     int_rsa_free,
     rsa_pkey_ctrl,
     old_rsa_priv_decode,
     old_rsa_priv_encode,
     rsa_item_verify,
     rsa_item_sign},

    {
     EVP_PKEY_RSA2,
     EVP_PKEY_RSA,
     ASN1_PKEY_ALIAS}
};
/* rsa_asn1.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 2000.
 */
/* ====================================================================
 * Copyright (c) 2000-2005 The OpenSSL Project.  All rights reserved.
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
// #include "bn.h"
// #include "rsa.h"
// #include "x509.h"
// #include "asn1t.h"

/* Override the default free and new methods */
static int rsa_cb(int operation, ASN1_VALUE **pval, const ASN1_ITEM *it,
                  void *exarg)
{
    if (operation == ASN1_OP_NEW_PRE) {
        *pval = (ASN1_VALUE *)RSA_new();
        if (*pval)
            return 2;
        return 0;
    } else if (operation == ASN1_OP_FREE_PRE) {
        RSA_free((RSA *)*pval);
        *pval = NULL;
        return 2;
    }
    return 1;
}

ASN1_SEQUENCE_cb(RSAPrivateKey, rsa_cb) = {
        ASN1_SIMPLE(RSA, version, LONG),
        ASN1_SIMPLE(RSA, n, BIGNUM),
        ASN1_SIMPLE(RSA, e, BIGNUM),
        ASN1_SIMPLE(RSA, d, BIGNUM),
        ASN1_SIMPLE(RSA, p, BIGNUM),
        ASN1_SIMPLE(RSA, q, BIGNUM),
        ASN1_SIMPLE(RSA, dmp1, BIGNUM),
        ASN1_SIMPLE(RSA, dmq1, BIGNUM),
        ASN1_SIMPLE(RSA, iqmp, BIGNUM)
} ASN1_SEQUENCE_END_cb(RSA, RSAPrivateKey)


ASN1_SEQUENCE_cb(RSAPublicKey, rsa_cb) = {
        ASN1_SIMPLE(RSA, n, BIGNUM),
        ASN1_SIMPLE(RSA, e, BIGNUM),
} ASN1_SEQUENCE_END_cb(RSA, RSAPublicKey)

ASN1_SEQUENCE(RSA_PSS_PARAMS) = {
        ASN1_EXP_OPT(RSA_PSS_PARAMS, hashAlgorithm, X509_ALGOR,0),
        ASN1_EXP_OPT(RSA_PSS_PARAMS, maskGenAlgorithm, X509_ALGOR,1),
        ASN1_EXP_OPT(RSA_PSS_PARAMS, saltLength, ASN1_INTEGER,2),
        ASN1_EXP_OPT(RSA_PSS_PARAMS, trailerField, ASN1_INTEGER,3)
} ASN1_SEQUENCE_END(RSA_PSS_PARAMS)

IMPLEMENT_ASN1_FUNCTIONS(RSA_PSS_PARAMS)

ASN1_SEQUENCE(RSA_OAEP_PARAMS) = {
        ASN1_EXP_OPT(RSA_OAEP_PARAMS, hashFunc, X509_ALGOR, 0),
        ASN1_EXP_OPT(RSA_OAEP_PARAMS, maskGenFunc, X509_ALGOR, 1),
        ASN1_EXP_OPT(RSA_OAEP_PARAMS, pSourceFunc, X509_ALGOR, 2),
} ASN1_SEQUENCE_END(RSA_OAEP_PARAMS)

IMPLEMENT_ASN1_FUNCTIONS(RSA_OAEP_PARAMS)

IMPLEMENT_ASN1_ENCODE_FUNCTIONS_const_fname(RSA, RSAPrivateKey, RSAPrivateKey)

IMPLEMENT_ASN1_ENCODE_FUNCTIONS_const_fname(RSA, RSAPublicKey, RSAPublicKey)

RSA *RSAPublicKey_dup(RSA *rsa)
{
    return ASN1_item_dup(ASN1_ITEM_rptr(RSAPublicKey), rsa);
}

RSA *RSAPrivateKey_dup(RSA *rsa)
{
    return ASN1_item_dup(ASN1_ITEM_rptr(RSAPrivateKey), rsa);
}
/* crypto/rsa/rsa_chk.c  */
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
 */

// #include "bn.h"
#include "err.h"
// #include "rsa.h"

int RSA_check_key(const RSA *key)
{
    BIGNUM *i, *j, *k, *l, *m;
    BN_CTX *ctx;
    int ret = 1;

    if (!key->p || !key->q || !key->n || !key->e || !key->d) {
        RSAerr(RSA_F_RSA_CHECK_KEY, RSA_R_VALUE_MISSING);
        return 0;
    }

    i = BN_new();
    j = BN_new();
    k = BN_new();
    l = BN_new();
    m = BN_new();
    ctx = BN_CTX_new();
    if (i == NULL || j == NULL || k == NULL || l == NULL
            || m == NULL || ctx == NULL) {
        ret = -1;
        RSAerr(RSA_F_RSA_CHECK_KEY, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (BN_is_one(key->e)) {
        ret = 0;
        RSAerr(RSA_F_RSA_CHECK_KEY, RSA_R_BAD_E_VALUE);
    }
    if (!BN_is_odd(key->e)) {
        ret = 0;
        RSAerr(RSA_F_RSA_CHECK_KEY, RSA_R_BAD_E_VALUE);
    }

    /* p prime? */
    if (BN_is_prime_ex(key->p, BN_prime_checks, NULL, NULL) != 1) {
        ret = 0;
        RSAerr(RSA_F_RSA_CHECK_KEY, RSA_R_P_NOT_PRIME);
    }

    /* q prime? */
    if (BN_is_prime_ex(key->q, BN_prime_checks, NULL, NULL) != 1) {
        ret = 0;
        RSAerr(RSA_F_RSA_CHECK_KEY, RSA_R_Q_NOT_PRIME);
    }

    /* n = p*q? */
    if (!BN_mul(i, key->p, key->q, ctx)) {
        ret = -1;
        goto err;
    }
    if (BN_cmp(i, key->n) != 0) {
        ret = 0;
        RSAerr(RSA_F_RSA_CHECK_KEY, RSA_R_N_DOES_NOT_EQUAL_P_Q);
    }

    /* d*e = 1  mod lcm(p-1,q-1)? */
    if (!BN_sub(i, key->p, BN_value_one())) {
        ret = -1;
        goto err;
    }
    if (!BN_sub(j, key->q, BN_value_one())) {
        ret = -1;
        goto err;
    }

    /* now compute k = lcm(i,j) */
    if (!BN_mul(l, i, j, ctx)) {
        ret = -1;
        goto err;
    }
    if (!BN_gcd(m, i, j, ctx)) {
        ret = -1;
        goto err;
    }
    if (!BN_div(k, NULL, l, m, ctx)) { /* remainder is 0 */
        ret = -1;
        goto err;
    }
    if (!BN_mod_mul(i, key->d, key->e, k, ctx)) {
        ret = -1;
        goto err;
    }

    if (!BN_is_one(i)) {
        ret = 0;
        RSAerr(RSA_F_RSA_CHECK_KEY, RSA_R_D_E_NOT_CONGRUENT_TO_1);
    }

    if (key->dmp1 != NULL && key->dmq1 != NULL && key->iqmp != NULL) {
        /* dmp1 = d mod (p-1)? */
        if (!BN_sub(i, key->p, BN_value_one())) {
            ret = -1;
            goto err;
        }
        if (!BN_mod(j, key->d, i, ctx)) {
            ret = -1;
            goto err;
        }
        if (BN_cmp(j, key->dmp1) != 0) {
            ret = 0;
            RSAerr(RSA_F_RSA_CHECK_KEY, RSA_R_DMP1_NOT_CONGRUENT_TO_D);
        }

        /* dmq1 = d mod (q-1)? */
        if (!BN_sub(i, key->q, BN_value_one())) {
            ret = -1;
            goto err;
        }
        if (!BN_mod(j, key->d, i, ctx)) {
            ret = -1;
            goto err;
        }
        if (BN_cmp(j, key->dmq1) != 0) {
            ret = 0;
            RSAerr(RSA_F_RSA_CHECK_KEY, RSA_R_DMQ1_NOT_CONGRUENT_TO_D);
        }

        /* iqmp = q^-1 mod p? */
        if (!BN_mod_inverse(i, key->q, key->p, ctx)) {
            ret = -1;
            goto err;
        }
        if (BN_cmp(i, key->iqmp) != 0) {
            ret = 0;
            RSAerr(RSA_F_RSA_CHECK_KEY, RSA_R_IQMP_NOT_INVERSE_OF_Q);
        }
    }

 err:
    BN_free(i);
    BN_free(j);
    BN_free(k);
    BN_free(l);
    BN_free(m);
    BN_CTX_free(ctx);
    return ret;
}
/* crypto/rsa/rsa_lib.c */
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
#include "crypto.h"
// #include "cryptlib.h"
#include "lhash.h"
// #include "bn.h"
// #include "rsa.h"
#include "rand.h"
#ifndef OPENSSL_NO_ENGINE
# include "engine.h"
#endif

int RSA_size(const RSA *r)
{
    return (BN_num_bytes(r->n));
}

int RSA_public_encrypt(int flen, const unsigned char *from, unsigned char *to,
                       RSA *rsa, int padding)
{
#ifdef OPENSSL_FIPS
    if (FIPS_mode() && !(rsa->meth->flags & RSA_FLAG_FIPS_METHOD)
        && !(rsa->flags & RSA_FLAG_NON_FIPS_ALLOW)) {
        RSAerr(RSA_F_RSA_PUBLIC_ENCRYPT, RSA_R_NON_FIPS_RSA_METHOD);
        return -1;
    }
#endif
    return (rsa->meth->rsa_pub_enc(flen, from, to, rsa, padding));
}

int RSA_private_encrypt(int flen, const unsigned char *from,
                        unsigned char *to, RSA *rsa, int padding)
{
#ifdef OPENSSL_FIPS
    if (FIPS_mode() && !(rsa->meth->flags & RSA_FLAG_FIPS_METHOD)
        && !(rsa->flags & RSA_FLAG_NON_FIPS_ALLOW)) {
        RSAerr(RSA_F_RSA_PRIVATE_ENCRYPT, RSA_R_NON_FIPS_RSA_METHOD);
        return -1;
    }
#endif
    return (rsa->meth->rsa_priv_enc(flen, from, to, rsa, padding));
}

int RSA_private_decrypt(int flen, const unsigned char *from,
                        unsigned char *to, RSA *rsa, int padding)
{
#ifdef OPENSSL_FIPS
    if (FIPS_mode() && !(rsa->meth->flags & RSA_FLAG_FIPS_METHOD)
        && !(rsa->flags & RSA_FLAG_NON_FIPS_ALLOW)) {
        RSAerr(RSA_F_RSA_PRIVATE_DECRYPT, RSA_R_NON_FIPS_RSA_METHOD);
        return -1;
    }
#endif
    return (rsa->meth->rsa_priv_dec(flen, from, to, rsa, padding));
}

int RSA_public_decrypt(int flen, const unsigned char *from, unsigned char *to,
                       RSA *rsa, int padding)
{
#ifdef OPENSSL_FIPS
    if (FIPS_mode() && !(rsa->meth->flags & RSA_FLAG_FIPS_METHOD)
        && !(rsa->flags & RSA_FLAG_NON_FIPS_ALLOW)) {
        RSAerr(RSA_F_RSA_PUBLIC_DECRYPT, RSA_R_NON_FIPS_RSA_METHOD);
        return -1;
    }
#endif
    return (rsa->meth->rsa_pub_dec(flen, from, to, rsa, padding));
}

int RSA_flags(const RSA *r)
{
    return ((r == NULL) ? 0 : r->meth->flags);
}

void RSA_blinding_off(RSA *rsa)
{
    if (rsa->blinding != NULL) {
        BN_BLINDING_free(rsa->blinding);
        rsa->blinding = NULL;
    }
    rsa->flags &= ~RSA_FLAG_BLINDING;
    rsa->flags |= RSA_FLAG_NO_BLINDING;
}

int RSA_blinding_on(RSA *rsa, BN_CTX *ctx)
{
    int ret = 0;

    if (rsa->blinding != NULL)
        RSA_blinding_off(rsa);

    rsa->blinding = RSA_setup_blinding(rsa, ctx);
    if (rsa->blinding == NULL)
        goto err;

    rsa->flags |= RSA_FLAG_BLINDING;
    rsa->flags &= ~RSA_FLAG_NO_BLINDING;
    ret = 1;
 err:
    return (ret);
}

static BIGNUM *rsa_get_public_exp(const BIGNUM *d, const BIGNUM *p,
                                  const BIGNUM *q, BN_CTX *ctx)
{
    BIGNUM *ret = NULL, *r0, *r1, *r2;

    if (d == NULL || p == NULL || q == NULL)
        return NULL;

    BN_CTX_start(ctx);
    r0 = BN_CTX_get(ctx);
    r1 = BN_CTX_get(ctx);
    r2 = BN_CTX_get(ctx);
    if (r2 == NULL)
        goto err;

    if (!BN_sub(r1, p, BN_value_one()))
        goto err;
    if (!BN_sub(r2, q, BN_value_one()))
        goto err;
    if (!BN_mul(r0, r1, r2, ctx))
        goto err;

    ret = BN_mod_inverse(NULL, d, r0, ctx);
 err:
    BN_CTX_end(ctx);
    return ret;
}

BN_BLINDING *RSA_setup_blinding(RSA *rsa, BN_CTX *in_ctx)
{
    BIGNUM local_n;
    BIGNUM *e, *n;
    BN_CTX *ctx;
    BN_BLINDING *ret = NULL;

    if (in_ctx == NULL) {
        if ((ctx = BN_CTX_new()) == NULL)
            return 0;
    } else
        ctx = in_ctx;

    BN_CTX_start(ctx);
    e = BN_CTX_get(ctx);
    if (e == NULL) {
        RSAerr(RSA_F_RSA_SETUP_BLINDING, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (rsa->e == NULL) {
        e = rsa_get_public_exp(rsa->d, rsa->p, rsa->q, ctx);
        if (e == NULL) {
            RSAerr(RSA_F_RSA_SETUP_BLINDING, RSA_R_NO_PUBLIC_EXPONENT);
            goto err;
        }
    } else
        e = rsa->e;

    if ((RAND_status() == 0) && rsa->d != NULL && rsa->d->d != NULL) {
        /*
         * if PRNG is not properly seeded, resort to secret exponent as
         * unpredictable seed
         */
        RAND_add(rsa->d->d, rsa->d->dmax * sizeof(rsa->d->d[0]), 0.0);
    }

    if (!(rsa->flags & RSA_FLAG_NO_CONSTTIME)) {
        /* Set BN_FLG_CONSTTIME flag */
        n = &local_n;
        BN_with_flags(n, rsa->n, BN_FLG_CONSTTIME);
    } else
        n = rsa->n;

    ret = BN_BLINDING_create_param(NULL, e, n, ctx,
                                   rsa->meth->bn_mod_exp, rsa->_method_mod_n);
    if (ret == NULL) {
        RSAerr(RSA_F_RSA_SETUP_BLINDING, ERR_R_BN_LIB);
        goto err;
    }
    CRYPTO_THREADID_current(BN_BLINDING_thread_id(ret));
 err:
    BN_CTX_end(ctx);
    if (in_ctx == NULL)
        BN_CTX_free(ctx);
    if (rsa->e == NULL)
        BN_free(e);

    return ret;
}
/* crypto/rsa/rsa_depr.c */
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

/*
 * NB: This file contains deprecated functions (compatibility wrappers to the
 * "new" versions).
 */

#include <stdio.h>
#include <time.h>
// #include "cryptlib.h"
// #include "bn.h"
// #include "rsa.h"

#ifdef OPENSSL_NO_DEPRECATED

static void *dummy = &dummy;

#else

RSA *RSA_generate_key(int bits, unsigned long e_value,
                      void (*callback) (int, int, void *), void *cb_arg)
{
    BN_GENCB cb;
    int i;
    RSA *rsa = RSA_new();
    BIGNUM *e = BN_new();

    if (!rsa || !e)
        goto err;

    /*
     * The problem is when building with 8, 16, or 32 BN_ULONG, unsigned long
     * can be larger
     */
    for (i = 0; i < (int)sizeof(unsigned long) * 8; i++) {
        if (e_value & (1UL << i))
            if (BN_set_bit(e, i) == 0)
                goto err;
    }

    BN_GENCB_set_old(&cb, callback, cb_arg);

    if (RSA_generate_key_ex(rsa, bits, e, &cb)) {
        BN_free(e);
        return rsa;
    }
 err:
    if (e)
        BN_free(e);
    if (rsa)
        RSA_free(rsa);
    return 0;
}
#endif
/* crypto/rsa/rsa_eay.c */
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
// #include "cryptlib.h"
// #include "bn.h"
// #include "rsa.h"
// #include "rand.h"
#include "bn_int.h"

#ifndef RSA_NULL

static int RSA_eay_public_encrypt(int flen, const unsigned char *from,
                                  unsigned char *to, RSA *rsa, int padding);
static int RSA_eay_private_encrypt(int flen, const unsigned char *from,
                                   unsigned char *to, RSA *rsa, int padding);
static int RSA_eay_public_decrypt(int flen, const unsigned char *from,
                                  unsigned char *to, RSA *rsa, int padding);
static int RSA_eay_private_decrypt(int flen, const unsigned char *from,
                                   unsigned char *to, RSA *rsa, int padding);
static int RSA_eay_mod_exp(BIGNUM *r0, const BIGNUM *i, RSA *rsa,
                           BN_CTX *ctx);
static int RSA_eay_init(RSA *rsa);
static int RSA_eay_finish(RSA *rsa);
static RSA_METHOD rsa_pkcs1_eay_meth = {
    "Eric Young's PKCS#1 RSA",
    RSA_eay_public_encrypt,
    RSA_eay_public_decrypt,     /* signature verification */
    RSA_eay_private_encrypt,    /* signing */
    RSA_eay_private_decrypt,
    RSA_eay_mod_exp,
    BN_mod_exp_mont,            /* XXX probably we should not use Montgomery
                                 * if e == 3 */
    RSA_eay_init,
    RSA_eay_finish,
    0,                          /* flags */
    NULL,
    0,                          /* rsa_sign */
    0,                          /* rsa_verify */
    NULL                        /* rsa_keygen */
};

const RSA_METHOD *RSA_PKCS1_SSLeay(void)
{
    return (&rsa_pkcs1_eay_meth);
}

static int RSA_eay_public_encrypt(int flen, const unsigned char *from,
                                  unsigned char *to, RSA *rsa, int padding)
{
    BIGNUM *f, *ret;
    int i, num = 0, r = -1;
    unsigned char *buf = NULL;
    BN_CTX *ctx = NULL;

    if (BN_num_bits(rsa->n) > OPENSSL_RSA_MAX_MODULUS_BITS) {
        RSAerr(RSA_F_RSA_EAY_PUBLIC_ENCRYPT, RSA_R_MODULUS_TOO_LARGE);
        return -1;
    }

    if (BN_ucmp(rsa->n, rsa->e) <= 0) {
        RSAerr(RSA_F_RSA_EAY_PUBLIC_ENCRYPT, RSA_R_BAD_E_VALUE);
        return -1;
    }

    /* for large moduli, enforce exponent limit */
    if (BN_num_bits(rsa->n) > OPENSSL_RSA_SMALL_MODULUS_BITS) {
        if (BN_num_bits(rsa->e) > OPENSSL_RSA_MAX_PUBEXP_BITS) {
            RSAerr(RSA_F_RSA_EAY_PUBLIC_ENCRYPT, RSA_R_BAD_E_VALUE);
            return -1;
        }
    }

    if ((ctx = BN_CTX_new()) == NULL)
        goto err;
    BN_CTX_start(ctx);
    f = BN_CTX_get(ctx);
    ret = BN_CTX_get(ctx);
    num = BN_num_bytes(rsa->n);
    buf = OPENSSL_malloc(num);
    if (!f || !ret || !buf) {
        RSAerr(RSA_F_RSA_EAY_PUBLIC_ENCRYPT, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    switch (padding) {
    case RSA_PKCS1_PADDING:
        i = RSA_padding_add_PKCS1_type_2(buf, num, from, flen);
        break;
# ifndef OPENSSL_NO_SHA
    case RSA_PKCS1_OAEP_PADDING:
        i = RSA_padding_add_PKCS1_OAEP(buf, num, from, flen, NULL, 0);
        break;
# endif
    case RSA_SSLV23_PADDING:
        i = RSA_padding_add_SSLv23(buf, num, from, flen);
        break;
    case RSA_NO_PADDING:
        i = RSA_padding_add_none(buf, num, from, flen);
        break;
    default:
        RSAerr(RSA_F_RSA_EAY_PUBLIC_ENCRYPT, RSA_R_UNKNOWN_PADDING_TYPE);
        goto err;
    }
    if (i <= 0)
        goto err;

    if (BN_bin2bn(buf, num, f) == NULL)
        goto err;

    if (BN_ucmp(f, rsa->n) >= 0) {
        /* usually the padding functions would catch this */
        RSAerr(RSA_F_RSA_EAY_PUBLIC_ENCRYPT,
               RSA_R_DATA_TOO_LARGE_FOR_MODULUS);
        goto err;
    }

    if (rsa->flags & RSA_FLAG_CACHE_PUBLIC)
        if (!BN_MONT_CTX_set_locked(&rsa->_method_mod_n, CRYPTO_LOCK_RSA,
                                    rsa->n, ctx))
            goto err;

    if (!rsa->meth->bn_mod_exp(ret, f, rsa->e, rsa->n, ctx,
                               rsa->_method_mod_n))
        goto err;

    /*
     * BN_bn2binpad puts in leading 0 bytes if the number is less than
     * the length of the modulus.
     */
    r = bn_bn2binpad(ret, to, num);
 err:
    if (ctx != NULL) {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    if (buf != NULL) {
        OPENSSL_cleanse(buf, num);
        OPENSSL_free(buf);
    }
    return (r);
}

static BN_BLINDING *rsa_get_blinding(RSA *rsa, int *local, BN_CTX *ctx)
{
    BN_BLINDING *ret;
    int got_write_lock = 0;
    CRYPTO_THREADID cur;

    CRYPTO_r_lock(CRYPTO_LOCK_RSA);

    if (rsa->blinding == NULL) {
        CRYPTO_r_unlock(CRYPTO_LOCK_RSA);
        CRYPTO_w_lock(CRYPTO_LOCK_RSA);
        got_write_lock = 1;

        if (rsa->blinding == NULL)
            rsa->blinding = RSA_setup_blinding(rsa, ctx);
    }

    ret = rsa->blinding;
    if (ret == NULL)
        goto err;

    CRYPTO_THREADID_current(&cur);
    if (!CRYPTO_THREADID_cmp(&cur, BN_BLINDING_thread_id(ret))) {
        /* rsa->blinding is ours! */

        *local = 1;
    } else {
        /* resort to rsa->mt_blinding instead */

        /*
         * instructs rsa_blinding_convert(), rsa_blinding_invert() that the
         * BN_BLINDING is shared, meaning that accesses require locks, and
         * that the blinding factor must be stored outside the BN_BLINDING
         */
        *local = 0;

        if (rsa->mt_blinding == NULL) {
            if (!got_write_lock) {
                CRYPTO_r_unlock(CRYPTO_LOCK_RSA);
                CRYPTO_w_lock(CRYPTO_LOCK_RSA);
                got_write_lock = 1;
            }

            if (rsa->mt_blinding == NULL)
                rsa->mt_blinding = RSA_setup_blinding(rsa, ctx);
        }
        ret = rsa->mt_blinding;
    }

 err:
    if (got_write_lock)
        CRYPTO_w_unlock(CRYPTO_LOCK_RSA);
    else
        CRYPTO_r_unlock(CRYPTO_LOCK_RSA);
    return ret;
}

static int rsa_blinding_convert(BN_BLINDING *b, BIGNUM *f, BIGNUM *unblind,
                                BN_CTX *ctx)
{
    if (unblind == NULL)
        /*
         * Local blinding: store the unblinding factor in BN_BLINDING.
         */
        return BN_BLINDING_convert_ex(f, NULL, b, ctx);
    else {
        /*
         * Shared blinding: store the unblinding factor outside BN_BLINDING.
         */
        int ret;
        CRYPTO_w_lock(CRYPTO_LOCK_RSA_BLINDING);
        ret = BN_BLINDING_convert_ex(f, unblind, b, ctx);
        CRYPTO_w_unlock(CRYPTO_LOCK_RSA_BLINDING);
        return ret;
    }
}

static int rsa_blinding_invert(BN_BLINDING *b, BIGNUM *f, BIGNUM *unblind,
                               BN_CTX *ctx)
{
    /*
     * For local blinding, unblind is set to NULL, and BN_BLINDING_invert_ex
     * will use the unblinding factor stored in BN_BLINDING. If BN_BLINDING
     * is shared between threads, unblind must be non-null:
     * BN_BLINDING_invert_ex will then use the local unblinding factor, and
     * will only read the modulus from BN_BLINDING. In both cases it's safe
     * to access the blinding without a lock.
     */
    return BN_BLINDING_invert_ex(f, unblind, b, ctx);
}

/* signing */
static int RSA_eay_private_encrypt(int flen, const unsigned char *from,
                                   unsigned char *to, RSA *rsa, int padding)
{
    BIGNUM *f, *ret, *res;
    int i, num = 0, r = -1;
    unsigned char *buf = NULL;
    BN_CTX *ctx = NULL;
    int local_blinding = 0;
    /*
     * Used only if the blinding structure is shared. A non-NULL unblind
     * instructs rsa_blinding_convert() and rsa_blinding_invert() to store
     * the unblinding factor outside the blinding structure.
     */
    BIGNUM *unblind = NULL;
    BN_BLINDING *blinding = NULL;

    if ((ctx = BN_CTX_new()) == NULL)
        goto err;
    BN_CTX_start(ctx);
    f = BN_CTX_get(ctx);
    ret = BN_CTX_get(ctx);
    num = BN_num_bytes(rsa->n);
    buf = OPENSSL_malloc(num);
    if (!f || !ret || !buf) {
        RSAerr(RSA_F_RSA_EAY_PRIVATE_ENCRYPT, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    switch (padding) {
    case RSA_PKCS1_PADDING:
        i = RSA_padding_add_PKCS1_type_1(buf, num, from, flen);
        break;
    case RSA_X931_PADDING:
        i = RSA_padding_add_X931(buf, num, from, flen);
        break;
    case RSA_NO_PADDING:
        i = RSA_padding_add_none(buf, num, from, flen);
        break;
    case RSA_SSLV23_PADDING:
    default:
        RSAerr(RSA_F_RSA_EAY_PRIVATE_ENCRYPT, RSA_R_UNKNOWN_PADDING_TYPE);
        goto err;
    }
    if (i <= 0)
        goto err;

    if (BN_bin2bn(buf, num, f) == NULL)
        goto err;

    if (BN_ucmp(f, rsa->n) >= 0) {
        /* usually the padding functions would catch this */
        RSAerr(RSA_F_RSA_EAY_PRIVATE_ENCRYPT,
               RSA_R_DATA_TOO_LARGE_FOR_MODULUS);
        goto err;
    }

    if (!(rsa->flags & RSA_FLAG_NO_BLINDING)) {
        blinding = rsa_get_blinding(rsa, &local_blinding, ctx);
        if (blinding == NULL) {
            RSAerr(RSA_F_RSA_EAY_PRIVATE_ENCRYPT, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    }

    if (blinding != NULL) {
        if (!local_blinding && ((unblind = BN_CTX_get(ctx)) == NULL)) {
            RSAerr(RSA_F_RSA_EAY_PRIVATE_ENCRYPT, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        if (!rsa_blinding_convert(blinding, f, unblind, ctx))
            goto err;
    }

    if ((rsa->flags & RSA_FLAG_EXT_PKEY) ||
        ((rsa->p != NULL) &&
         (rsa->q != NULL) &&
         (rsa->dmp1 != NULL) && (rsa->dmq1 != NULL) && (rsa->iqmp != NULL))) {
        if (!rsa->meth->rsa_mod_exp(ret, f, rsa, ctx))
            goto err;
    } else {
        BIGNUM local_d;
        BIGNUM *d = NULL;

        if (!(rsa->flags & RSA_FLAG_NO_CONSTTIME)) {
            BN_init(&local_d);
            d = &local_d;
            BN_with_flags(d, rsa->d, BN_FLG_CONSTTIME);
        } else
            d = rsa->d;

        if (rsa->flags & RSA_FLAG_CACHE_PUBLIC)
            if (!BN_MONT_CTX_set_locked(&rsa->_method_mod_n, CRYPTO_LOCK_RSA,
                                        rsa->n, ctx))
                goto err;

        if (!rsa->meth->bn_mod_exp(ret, f, d, rsa->n, ctx,
                                   rsa->_method_mod_n))
            goto err;
    }

    if (blinding)
        if (!rsa_blinding_invert(blinding, ret, unblind, ctx))
            goto err;

    if (padding == RSA_X931_PADDING) {
        BN_sub(f, rsa->n, ret);
        if (BN_cmp(ret, f) > 0)
            res = f;
        else
            res = ret;
    } else
        res = ret;

    /*
     * BN_bn2binpad puts in leading 0 bytes if the number is less than
     * the length of the modulus.
     */
    r = bn_bn2binpad(res, to, num);
 err:
    if (ctx != NULL) {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    if (buf != NULL) {
        OPENSSL_cleanse(buf, num);
        OPENSSL_free(buf);
    }
    return (r);
}

static int RSA_eay_private_decrypt(int flen, const unsigned char *from,
                                   unsigned char *to, RSA *rsa, int padding)
{
    BIGNUM *f, *ret;
    int j, num = 0, r = -1;
    unsigned char *buf = NULL;
    BN_CTX *ctx = NULL;
    int local_blinding = 0;
    /*
     * Used only if the blinding structure is shared. A non-NULL unblind
     * instructs rsa_blinding_convert() and rsa_blinding_invert() to store
     * the unblinding factor outside the blinding structure.
     */
    BIGNUM *unblind = NULL;
    BN_BLINDING *blinding = NULL;

    if ((ctx = BN_CTX_new()) == NULL)
        goto err;
    BN_CTX_start(ctx);
    f = BN_CTX_get(ctx);
    ret = BN_CTX_get(ctx);
    num = BN_num_bytes(rsa->n);
    buf = OPENSSL_malloc(num);
    if (!f || !ret || !buf) {
        RSAerr(RSA_F_RSA_EAY_PRIVATE_DECRYPT, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    /*
     * This check was for equality but PGP does evil things and chops off the
     * top '0' bytes
     */
    if (flen > num) {
        RSAerr(RSA_F_RSA_EAY_PRIVATE_DECRYPT,
               RSA_R_DATA_GREATER_THAN_MOD_LEN);
        goto err;
    }

    /* make data into a big number */
    if (BN_bin2bn(from, (int)flen, f) == NULL)
        goto err;

    if (BN_ucmp(f, rsa->n) >= 0) {
        RSAerr(RSA_F_RSA_EAY_PRIVATE_DECRYPT,
               RSA_R_DATA_TOO_LARGE_FOR_MODULUS);
        goto err;
    }

    if (!(rsa->flags & RSA_FLAG_NO_BLINDING)) {
        blinding = rsa_get_blinding(rsa, &local_blinding, ctx);
        if (blinding == NULL) {
            RSAerr(RSA_F_RSA_EAY_PRIVATE_DECRYPT, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    }

    if (blinding != NULL) {
        if (!local_blinding && ((unblind = BN_CTX_get(ctx)) == NULL)) {
            RSAerr(RSA_F_RSA_EAY_PRIVATE_DECRYPT, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        if (!rsa_blinding_convert(blinding, f, unblind, ctx))
            goto err;
    }

    /* do the decrypt */
    if ((rsa->flags & RSA_FLAG_EXT_PKEY) ||
        ((rsa->p != NULL) &&
         (rsa->q != NULL) &&
         (rsa->dmp1 != NULL) && (rsa->dmq1 != NULL) && (rsa->iqmp != NULL))) {
        if (!rsa->meth->rsa_mod_exp(ret, f, rsa, ctx))
            goto err;
    } else {
        BIGNUM local_d;
        BIGNUM *d = NULL;

        if (!(rsa->flags & RSA_FLAG_NO_CONSTTIME)) {
            d = &local_d;
            BN_with_flags(d, rsa->d, BN_FLG_CONSTTIME);
        } else
            d = rsa->d;

        if (rsa->flags & RSA_FLAG_CACHE_PUBLIC)
            if (!BN_MONT_CTX_set_locked(&rsa->_method_mod_n, CRYPTO_LOCK_RSA,
                                        rsa->n, ctx))
                goto err;
        if (!rsa->meth->bn_mod_exp(ret, f, d, rsa->n, ctx,
                                   rsa->_method_mod_n))
            goto err;
    }

    if (blinding)
        if (!rsa_blinding_invert(blinding, ret, unblind, ctx))
            goto err;

    j = bn_bn2binpad(ret, buf, num);

    switch (padding) {
    case RSA_PKCS1_PADDING:
        r = RSA_padding_check_PKCS1_type_2(to, num, buf, j, num);
        break;
# ifndef OPENSSL_NO_SHA
    case RSA_PKCS1_OAEP_PADDING:
        r = RSA_padding_check_PKCS1_OAEP(to, num, buf, j, num, NULL, 0);
        break;
# endif
    case RSA_SSLV23_PADDING:
        r = RSA_padding_check_SSLv23(to, num, buf, j, num);
        break;
    case RSA_NO_PADDING:
        memcpy(to, buf, (r = j));
        break;
    default:
        RSAerr(RSA_F_RSA_EAY_PRIVATE_DECRYPT, RSA_R_UNKNOWN_PADDING_TYPE);
        goto err;
    }
    if (r < 0)
        RSAerr(RSA_F_RSA_EAY_PRIVATE_DECRYPT, RSA_R_PADDING_CHECK_FAILED);

 err:
    if (ctx != NULL) {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    if (buf != NULL) {
        OPENSSL_cleanse(buf, num);
        OPENSSL_free(buf);
    }
    return (r);
}

/* signature verification */
static int RSA_eay_public_decrypt(int flen, const unsigned char *from,
                                  unsigned char *to, RSA *rsa, int padding)
{
    BIGNUM *f, *ret;
    int i, num = 0, r = -1;
    unsigned char *buf = NULL;
    BN_CTX *ctx = NULL;

    if (BN_num_bits(rsa->n) > OPENSSL_RSA_MAX_MODULUS_BITS) {
        RSAerr(RSA_F_RSA_EAY_PUBLIC_DECRYPT, RSA_R_MODULUS_TOO_LARGE);
        return -1;
    }

    if (BN_ucmp(rsa->n, rsa->e) <= 0) {
        RSAerr(RSA_F_RSA_EAY_PUBLIC_DECRYPT, RSA_R_BAD_E_VALUE);
        return -1;
    }

    /* for large moduli, enforce exponent limit */
    if (BN_num_bits(rsa->n) > OPENSSL_RSA_SMALL_MODULUS_BITS) {
        if (BN_num_bits(rsa->e) > OPENSSL_RSA_MAX_PUBEXP_BITS) {
            RSAerr(RSA_F_RSA_EAY_PUBLIC_DECRYPT, RSA_R_BAD_E_VALUE);
            return -1;
        }
    }

    if ((ctx = BN_CTX_new()) == NULL)
        goto err;
    BN_CTX_start(ctx);
    f = BN_CTX_get(ctx);
    ret = BN_CTX_get(ctx);
    num = BN_num_bytes(rsa->n);
    buf = OPENSSL_malloc(num);
    if (!f || !ret || !buf) {
        RSAerr(RSA_F_RSA_EAY_PUBLIC_DECRYPT, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    /*
     * This check was for equality but PGP does evil things and chops off the
     * top '0' bytes
     */
    if (flen > num) {
        RSAerr(RSA_F_RSA_EAY_PUBLIC_DECRYPT, RSA_R_DATA_GREATER_THAN_MOD_LEN);
        goto err;
    }

    if (BN_bin2bn(from, flen, f) == NULL)
        goto err;

    if (BN_ucmp(f, rsa->n) >= 0) {
        RSAerr(RSA_F_RSA_EAY_PUBLIC_DECRYPT,
               RSA_R_DATA_TOO_LARGE_FOR_MODULUS);
        goto err;
    }

    if (rsa->flags & RSA_FLAG_CACHE_PUBLIC)
        if (!BN_MONT_CTX_set_locked(&rsa->_method_mod_n, CRYPTO_LOCK_RSA,
                                    rsa->n, ctx))
            goto err;

    if (!rsa->meth->bn_mod_exp(ret, f, rsa->e, rsa->n, ctx,
                               rsa->_method_mod_n))
        goto err;

    if ((padding == RSA_X931_PADDING) && ((ret->d[0] & 0xf) != 12))
        if (!BN_sub(ret, rsa->n, ret))
            goto err;

    i = bn_bn2binpad(ret, buf, num);

    switch (padding) {
    case RSA_PKCS1_PADDING:
        r = RSA_padding_check_PKCS1_type_1(to, num, buf, i, num);
        break;
    case RSA_X931_PADDING:
        r = RSA_padding_check_X931(to, num, buf, i, num);
        break;
    case RSA_NO_PADDING:
        memcpy(to, buf, (r = i));
        break;
    default:
        RSAerr(RSA_F_RSA_EAY_PUBLIC_DECRYPT, RSA_R_UNKNOWN_PADDING_TYPE);
        goto err;
    }
    if (r < 0)
        RSAerr(RSA_F_RSA_EAY_PUBLIC_DECRYPT, RSA_R_PADDING_CHECK_FAILED);

 err:
    if (ctx != NULL) {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    if (buf != NULL) {
        OPENSSL_cleanse(buf, num);
        OPENSSL_free(buf);
    }
    return (r);
}

static int RSA_eay_mod_exp(BIGNUM *r0, const BIGNUM *I, RSA *rsa, BN_CTX *ctx)
{
    BIGNUM *r1, *m1, *vrfy;
    BIGNUM local_dmp1, local_dmq1, local_c, local_r1;
    BIGNUM *dmp1, *dmq1, *c, *pr1;
    int ret = 0, smooth = 0;

    BN_CTX_start(ctx);
    r1 = BN_CTX_get(ctx);
    m1 = BN_CTX_get(ctx);
    vrfy = BN_CTX_get(ctx);

    {
        BIGNUM local_p, local_q;
        BIGNUM *p = NULL, *q = NULL;

        /*
         * Make sure BN_mod_inverse in Montgomery intialization uses the
         * BN_FLG_CONSTTIME flag (unless RSA_FLAG_NO_CONSTTIME is set)
         */
        if (!(rsa->flags & RSA_FLAG_NO_CONSTTIME)) {
            BN_init(&local_p);
            p = &local_p;
            BN_with_flags(p, rsa->p, BN_FLG_CONSTTIME);

            BN_init(&local_q);
            q = &local_q;
            BN_with_flags(q, rsa->q, BN_FLG_CONSTTIME);
        } else {
            p = rsa->p;
            q = rsa->q;
        }

        if (rsa->flags & RSA_FLAG_CACHE_PRIVATE) {
            if (!BN_MONT_CTX_set_locked(&rsa->_method_mod_p, CRYPTO_LOCK_RSA,
                                        p, ctx))
                goto err;
            if (!BN_MONT_CTX_set_locked(&rsa->_method_mod_q, CRYPTO_LOCK_RSA,
                                        q, ctx))
                goto err;

            smooth = (rsa->meth->bn_mod_exp == BN_mod_exp_mont)
                     && (BN_num_bits(q) == BN_num_bits(p));
        }
    }

    if (rsa->flags & RSA_FLAG_CACHE_PUBLIC)
        if (!BN_MONT_CTX_set_locked(&rsa->_method_mod_n, CRYPTO_LOCK_RSA,
                                    rsa->n, ctx))
            goto err;

    if (smooth) {
        /*
         * Conversion from Montgomery domain, a.k.a. Montgomery reduction,
         * accepts values in [0-m*2^w) range. w is m's bit width rounded up
         * to limb width. So that at the very least if |I| is fully reduced,
         * i.e. less than p*q, we can count on from-to round to perform
         * below modulo operations on |I|. Unlike BN_mod it's constant time.
         */
        if (/* m1 = I moq q */
            !bn_from_mont_fixed_top(m1, I, rsa->_method_mod_q, ctx)
            || !bn_to_mont_fixed_top(m1, m1, rsa->_method_mod_q, ctx)
            /* m1 = m1^dmq1 mod q */
            || !BN_mod_exp_mont_consttime(m1, m1, rsa->dmq1, rsa->q, ctx,
                                          rsa->_method_mod_q)
            /* r1 = I mod p */
            || !bn_from_mont_fixed_top(r1, I, rsa->_method_mod_p, ctx)
            || !bn_to_mont_fixed_top(r1, r1, rsa->_method_mod_p, ctx)
            /* r1 = r1^dmp1 mod p */
            || !BN_mod_exp_mont_consttime(r1, r1, rsa->dmp1, rsa->p, ctx,
                                          rsa->_method_mod_p)
            /* r1 = (r1 - m1) mod p */
            /*
             * bn_mod_sub_fixed_top is not regular modular subtraction,
             * it can tolerate subtrahend to be larger than modulus, but
             * not bit-wise wider. This makes up for uncommon q>p case,
             * when |m1| can be larger than |rsa->p|.
             */
            || !bn_mod_sub_fixed_top(r1, r1, m1, rsa->p)

            /* r1 = r1 * iqmp mod p */
            || !bn_to_mont_fixed_top(r1, r1, rsa->_method_mod_p, ctx)
            || !bn_mul_mont_fixed_top(r1, r1, rsa->iqmp, rsa->_method_mod_p,
                                      ctx)
            /* r0 = r1 * q + m1 */
            || !bn_mul_fixed_top(r0, r1, rsa->q, ctx)
            || !bn_mod_add_fixed_top(r0, r0, m1, rsa->n))
            goto err;

        goto tail;
    }

    /* compute I mod q */
    if (!(rsa->flags & RSA_FLAG_NO_CONSTTIME)) {
        c = &local_c;
        BN_with_flags(c, I, BN_FLG_CONSTTIME);
        if (!BN_mod(r1, c, rsa->q, ctx))
            goto err;
    } else {
        if (!BN_mod(r1, I, rsa->q, ctx))
            goto err;
    }

    /* compute r1^dmq1 mod q */
    if (!(rsa->flags & RSA_FLAG_NO_CONSTTIME)) {
        dmq1 = &local_dmq1;
        BN_with_flags(dmq1, rsa->dmq1, BN_FLG_CONSTTIME);
    } else
        dmq1 = rsa->dmq1;
    if (!rsa->meth->bn_mod_exp(m1, r1, dmq1, rsa->q, ctx, rsa->_method_mod_q))
        goto err;

    /* compute I mod p */
    if (!(rsa->flags & RSA_FLAG_NO_CONSTTIME)) {
        c = &local_c;
        BN_with_flags(c, I, BN_FLG_CONSTTIME);
        if (!BN_mod(r1, c, rsa->p, ctx))
            goto err;
    } else {
        if (!BN_mod(r1, I, rsa->p, ctx))
            goto err;
    }

    /* compute r1^dmp1 mod p */
    if (!(rsa->flags & RSA_FLAG_NO_CONSTTIME)) {
        dmp1 = &local_dmp1;
        BN_with_flags(dmp1, rsa->dmp1, BN_FLG_CONSTTIME);
    } else
        dmp1 = rsa->dmp1;
    if (!rsa->meth->bn_mod_exp(r0, r1, dmp1, rsa->p, ctx, rsa->_method_mod_p))
        goto err;

    if (!BN_sub(r0, r0, m1))
        goto err;
    /*
     * This will help stop the size of r0 increasing, which does affect the
     * multiply if it optimised for a power of 2 size
     */
    if (BN_is_negative(r0))
        if (!BN_add(r0, r0, rsa->p))
            goto err;

    if (!BN_mul(r1, r0, rsa->iqmp, ctx))
        goto err;

    /* Turn BN_FLG_CONSTTIME flag on before division operation */
    if (!(rsa->flags & RSA_FLAG_NO_CONSTTIME)) {
        pr1 = &local_r1;
        BN_with_flags(pr1, r1, BN_FLG_CONSTTIME);
    } else
        pr1 = r1;
    if (!BN_mod(r0, pr1, rsa->p, ctx))
        goto err;

    /*
     * If p < q it is occasionally possible for the correction of adding 'p'
     * if r0 is negative above to leave the result still negative. This can
     * break the private key operations: the following second correction
     * should *always* correct this rare occurrence. This will *never* happen
     * with OpenSSL generated keys because they ensure p > q [steve]
     */
    if (BN_is_negative(r0))
        if (!BN_add(r0, r0, rsa->p))
            goto err;
    if (!BN_mul(r1, r0, rsa->q, ctx))
        goto err;
    if (!BN_add(r0, r1, m1))
        goto err;

 tail:
    if (rsa->e && rsa->n) {
        if (rsa->meth->bn_mod_exp == BN_mod_exp_mont) {
            if (!BN_mod_exp_mont(vrfy, r0, rsa->e, rsa->n, ctx,
                                 rsa->_method_mod_n))
                goto err;
        } else {
            bn_correct_top(r0);
            if (!rsa->meth->bn_mod_exp(vrfy, r0, rsa->e, rsa->n, ctx,
                                       rsa->_method_mod_n))
                goto err;
        }
        /*
         * If 'I' was greater than (or equal to) rsa->n, the operation will
         * be equivalent to using 'I mod n'. However, the result of the
         * verify will *always* be less than 'n' so we don't check for
         * absolute equality, just congruency.
         */
        if (!BN_sub(vrfy, vrfy, I))
            goto err;
        if (BN_is_zero(vrfy)) {
            bn_correct_top(r0);
            ret = 1;
            goto err;   /* not actually error */
        }
        if (!BN_mod(vrfy, vrfy, rsa->n, ctx))
            goto err;
        if (BN_is_negative(vrfy))
            if (!BN_add(vrfy, vrfy, rsa->n))
                goto err;
        if (!BN_is_zero(vrfy)) {
            /*
             * 'I' and 'vrfy' aren't congruent mod n. Don't leak
             * miscalculated CRT output, just do a raw (slower) mod_exp and
             * return that instead.
             */

            BIGNUM local_d;
            BIGNUM *d = NULL;

            if (!(rsa->flags & RSA_FLAG_NO_CONSTTIME)) {
                d = &local_d;
                BN_with_flags(d, rsa->d, BN_FLG_CONSTTIME);
            } else
                d = rsa->d;
            if (!rsa->meth->bn_mod_exp(r0, I, d, rsa->n, ctx,
                                       rsa->_method_mod_n))
                goto err;
        }
    }
    /*
     * It's unfortunate that we have to bn_correct_top(r0). What hopefully
     * saves the day is that correction is highly unlike, and private key
     * operations are customarily performed on blinded message. Which means
     * that attacker won't observe correlation with chosen plaintext.
     * Secondly, remaining code would still handle it in same computational
     * time and even conceal memory access pattern around corrected top.
     */
    bn_correct_top(r0);
    ret = 1;
 err:
    BN_CTX_end(ctx);
    return (ret);
}

static int RSA_eay_init(RSA *rsa)
{
    rsa->flags |= RSA_FLAG_CACHE_PUBLIC | RSA_FLAG_CACHE_PRIVATE;
    return (1);
}

static int RSA_eay_finish(RSA *rsa)
{
    if (rsa->_method_mod_n != NULL)
        BN_MONT_CTX_free(rsa->_method_mod_n);
    if (rsa->_method_mod_p != NULL)
        BN_MONT_CTX_free(rsa->_method_mod_p);
    if (rsa->_method_mod_q != NULL)
        BN_MONT_CTX_free(rsa->_method_mod_q);
    return (1);
}

#endif
/* crypto/rsa/rsa_err.c */
/* ====================================================================
 * Copyright (c) 1999-2014 The OpenSSL Project.  All rights reserved.
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
// #include "rsa.h"

/* BEGIN ERROR CODES */
#ifndef OPENSSL_NO_ERR

# define ERR_FUNC(func) ERR_PACK(ERR_LIB_RSA,func,0)
# define ERR_REASON(reason) ERR_PACK(ERR_LIB_RSA,0,reason)

static ERR_STRING_DATA RSA_str_functs[] = {
    {ERR_FUNC(RSA_F_CHECK_PADDING_MD), "CHECK_PADDING_MD"},
    {ERR_FUNC(RSA_F_DO_RSA_PRINT), "DO_RSA_PRINT"},
    {ERR_FUNC(RSA_F_INT_RSA_VERIFY), "INT_RSA_VERIFY"},
    {ERR_FUNC(RSA_F_MEMORY_LOCK), "MEMORY_LOCK"},
    {ERR_FUNC(RSA_F_OLD_RSA_PRIV_DECODE), "OLD_RSA_PRIV_DECODE"},
    {ERR_FUNC(RSA_F_PKEY_RSA_CTRL), "PKEY_RSA_CTRL"},
    {ERR_FUNC(RSA_F_PKEY_RSA_CTRL_STR), "PKEY_RSA_CTRL_STR"},
    {ERR_FUNC(RSA_F_PKEY_RSA_SIGN), "PKEY_RSA_SIGN"},
    {ERR_FUNC(RSA_F_PKEY_RSA_VERIFY), "PKEY_RSA_VERIFY"},
    {ERR_FUNC(RSA_F_PKEY_RSA_VERIFYRECOVER), "PKEY_RSA_VERIFYRECOVER"},
    {ERR_FUNC(RSA_F_RSA_ALGOR_TO_MD), "RSA_ALGOR_TO_MD"},
    {ERR_FUNC(RSA_F_RSA_BUILTIN_KEYGEN), "RSA_BUILTIN_KEYGEN"},
    {ERR_FUNC(RSA_F_RSA_CHECK_KEY), "RSA_check_key"},
    {ERR_FUNC(RSA_F_RSA_CMS_DECRYPT), "RSA_CMS_DECRYPT"},
    {ERR_FUNC(RSA_F_RSA_EAY_PRIVATE_DECRYPT), "RSA_EAY_PRIVATE_DECRYPT"},
    {ERR_FUNC(RSA_F_RSA_EAY_PRIVATE_ENCRYPT), "RSA_EAY_PRIVATE_ENCRYPT"},
    {ERR_FUNC(RSA_F_RSA_EAY_PUBLIC_DECRYPT), "RSA_EAY_PUBLIC_DECRYPT"},
    {ERR_FUNC(RSA_F_RSA_EAY_PUBLIC_ENCRYPT), "RSA_EAY_PUBLIC_ENCRYPT"},
    {ERR_FUNC(RSA_F_RSA_GENERATE_KEY), "RSA_generate_key"},
    {ERR_FUNC(RSA_F_RSA_GENERATE_KEY_EX), "RSA_generate_key_ex"},
    {ERR_FUNC(RSA_F_RSA_ITEM_VERIFY), "RSA_ITEM_VERIFY"},
    {ERR_FUNC(RSA_F_RSA_MEMORY_LOCK), "RSA_memory_lock"},
    {ERR_FUNC(RSA_F_RSA_MGF1_TO_MD), "RSA_MGF1_TO_MD"},
    {ERR_FUNC(RSA_F_RSA_NEW_METHOD), "RSA_new_method"},
    {ERR_FUNC(RSA_F_RSA_NULL), "RSA_NULL"},
    {ERR_FUNC(RSA_F_RSA_NULL_MOD_EXP), "RSA_NULL_MOD_EXP"},
    {ERR_FUNC(RSA_F_RSA_NULL_PRIVATE_DECRYPT), "RSA_NULL_PRIVATE_DECRYPT"},
    {ERR_FUNC(RSA_F_RSA_NULL_PRIVATE_ENCRYPT), "RSA_NULL_PRIVATE_ENCRYPT"},
    {ERR_FUNC(RSA_F_RSA_NULL_PUBLIC_DECRYPT), "RSA_NULL_PUBLIC_DECRYPT"},
    {ERR_FUNC(RSA_F_RSA_NULL_PUBLIC_ENCRYPT), "RSA_NULL_PUBLIC_ENCRYPT"},
    {ERR_FUNC(RSA_F_RSA_PADDING_ADD_NONE), "RSA_padding_add_none"},
    {ERR_FUNC(RSA_F_RSA_PADDING_ADD_PKCS1_OAEP),
     "RSA_padding_add_PKCS1_OAEP"},
    {ERR_FUNC(RSA_F_RSA_PADDING_ADD_PKCS1_OAEP_MGF1),
     "RSA_padding_add_PKCS1_OAEP_mgf1"},
    {ERR_FUNC(RSA_F_RSA_PADDING_ADD_PKCS1_PSS), "RSA_padding_add_PKCS1_PSS"},
    {ERR_FUNC(RSA_F_RSA_PADDING_ADD_PKCS1_PSS_MGF1),
     "RSA_padding_add_PKCS1_PSS_mgf1"},
    {ERR_FUNC(RSA_F_RSA_PADDING_ADD_PKCS1_TYPE_1),
     "RSA_padding_add_PKCS1_type_1"},
    {ERR_FUNC(RSA_F_RSA_PADDING_ADD_PKCS1_TYPE_2),
     "RSA_padding_add_PKCS1_type_2"},
    {ERR_FUNC(RSA_F_RSA_PADDING_ADD_SSLV23), "RSA_padding_add_SSLv23"},
    {ERR_FUNC(RSA_F_RSA_PADDING_ADD_X931), "RSA_padding_add_X931"},
    {ERR_FUNC(RSA_F_RSA_PADDING_CHECK_NONE), "RSA_padding_check_none"},
    {ERR_FUNC(RSA_F_RSA_PADDING_CHECK_PKCS1_OAEP),
     "RSA_padding_check_PKCS1_OAEP"},
    {ERR_FUNC(RSA_F_RSA_PADDING_CHECK_PKCS1_OAEP_MGF1),
     "RSA_padding_check_PKCS1_OAEP_mgf1"},
    {ERR_FUNC(RSA_F_RSA_PADDING_CHECK_PKCS1_TYPE_1),
     "RSA_padding_check_PKCS1_type_1"},
    {ERR_FUNC(RSA_F_RSA_PADDING_CHECK_PKCS1_TYPE_2),
     "RSA_padding_check_PKCS1_type_2"},
    {ERR_FUNC(RSA_F_RSA_PADDING_CHECK_SSLV23), "RSA_padding_check_SSLv23"},
    {ERR_FUNC(RSA_F_RSA_PADDING_CHECK_X931), "RSA_padding_check_X931"},
    {ERR_FUNC(RSA_F_RSA_PRINT), "RSA_print"},
    {ERR_FUNC(RSA_F_RSA_PRINT_FP), "RSA_print_fp"},
    {ERR_FUNC(RSA_F_RSA_PRIVATE_DECRYPT), "RSA_private_decrypt"},
    {ERR_FUNC(RSA_F_RSA_PRIVATE_ENCRYPT), "RSA_private_encrypt"},
    {ERR_FUNC(RSA_F_RSA_PRIV_DECODE), "RSA_PRIV_DECODE"},
    {ERR_FUNC(RSA_F_RSA_PRIV_ENCODE), "RSA_PRIV_ENCODE"},
    {ERR_FUNC(RSA_F_RSA_PSS_TO_CTX), "RSA_PSS_TO_CTX"},
    {ERR_FUNC(RSA_F_RSA_PUBLIC_DECRYPT), "RSA_public_decrypt"},
    {ERR_FUNC(RSA_F_RSA_PUBLIC_ENCRYPT), "RSA_public_encrypt"},
    {ERR_FUNC(RSA_F_RSA_PUB_DECODE), "RSA_PUB_DECODE"},
    {ERR_FUNC(RSA_F_RSA_SETUP_BLINDING), "RSA_setup_blinding"},
    {ERR_FUNC(RSA_F_RSA_SIGN), "RSA_sign"},
    {ERR_FUNC(RSA_F_RSA_SIGN_ASN1_OCTET_STRING),
     "RSA_sign_ASN1_OCTET_STRING"},
    {ERR_FUNC(RSA_F_RSA_VERIFY), "RSA_verify"},
    {ERR_FUNC(RSA_F_RSA_VERIFY_ASN1_OCTET_STRING),
     "RSA_verify_ASN1_OCTET_STRING"},
    {ERR_FUNC(RSA_F_RSA_VERIFY_PKCS1_PSS), "RSA_verify_PKCS1_PSS"},
    {ERR_FUNC(RSA_F_RSA_VERIFY_PKCS1_PSS_MGF1), "RSA_verify_PKCS1_PSS_mgf1"},
    {0, NULL}
};

static ERR_STRING_DATA RSA_str_reasons[] = {
    {ERR_REASON(RSA_R_ALGORITHM_MISMATCH), "algorithm mismatch"},
    {ERR_REASON(RSA_R_BAD_E_VALUE), "bad e value"},
    {ERR_REASON(RSA_R_BAD_FIXED_HEADER_DECRYPT), "bad fixed header decrypt"},
    {ERR_REASON(RSA_R_BAD_PAD_BYTE_COUNT), "bad pad byte count"},
    {ERR_REASON(RSA_R_BAD_SIGNATURE), "bad signature"},
    {ERR_REASON(RSA_R_BLOCK_TYPE_IS_NOT_01), "block type is not 01"},
    {ERR_REASON(RSA_R_BLOCK_TYPE_IS_NOT_02), "block type is not 02"},
    {ERR_REASON(RSA_R_DATA_GREATER_THAN_MOD_LEN),
     "data greater than mod len"},
    {ERR_REASON(RSA_R_DATA_TOO_LARGE), "data too large"},
    {ERR_REASON(RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE),
     "data too large for key size"},
    {ERR_REASON(RSA_R_DATA_TOO_LARGE_FOR_MODULUS),
     "data too large for modulus"},
    {ERR_REASON(RSA_R_DATA_TOO_SMALL), "data too small"},
    {ERR_REASON(RSA_R_DATA_TOO_SMALL_FOR_KEY_SIZE),
     "data too small for key size"},
    {ERR_REASON(RSA_R_DIGEST_DOES_NOT_MATCH), "digest does not match"},
    {ERR_REASON(RSA_R_DIGEST_TOO_BIG_FOR_RSA_KEY),
     "digest too big for rsa key"},
    {ERR_REASON(RSA_R_DMP1_NOT_CONGRUENT_TO_D), "dmp1 not congruent to d"},
    {ERR_REASON(RSA_R_DMQ1_NOT_CONGRUENT_TO_D), "dmq1 not congruent to d"},
    {ERR_REASON(RSA_R_D_E_NOT_CONGRUENT_TO_1), "d e not congruent to 1"},
    {ERR_REASON(RSA_R_FIRST_OCTET_INVALID), "first octet invalid"},
    {ERR_REASON(RSA_R_ILLEGAL_OR_UNSUPPORTED_PADDING_MODE),
     "illegal or unsupported padding mode"},
    {ERR_REASON(RSA_R_INVALID_DIGEST), "invalid digest"},
    {ERR_REASON(RSA_R_INVALID_DIGEST_LENGTH), "invalid digest length"},
    {ERR_REASON(RSA_R_INVALID_HEADER), "invalid header"},
    {ERR_REASON(RSA_R_INVALID_KEYBITS), "invalid keybits"},
    {ERR_REASON(RSA_R_INVALID_LABEL), "invalid label"},
    {ERR_REASON(RSA_R_INVALID_MESSAGE_LENGTH), "invalid message length"},
    {ERR_REASON(RSA_R_INVALID_MGF1_MD), "invalid mgf1 md"},
    {ERR_REASON(RSA_R_INVALID_OAEP_PARAMETERS), "invalid oaep parameters"},
    {ERR_REASON(RSA_R_INVALID_PADDING), "invalid padding"},
    {ERR_REASON(RSA_R_INVALID_PADDING_MODE), "invalid padding mode"},
    {ERR_REASON(RSA_R_INVALID_PSS_PARAMETERS), "invalid pss parameters"},
    {ERR_REASON(RSA_R_INVALID_PSS_SALTLEN), "invalid pss saltlen"},
    {ERR_REASON(RSA_R_INVALID_SALT_LENGTH), "invalid salt length"},
    {ERR_REASON(RSA_R_INVALID_TRAILER), "invalid trailer"},
    {ERR_REASON(RSA_R_INVALID_X931_DIGEST), "invalid x931 digest"},
    {ERR_REASON(RSA_R_IQMP_NOT_INVERSE_OF_Q), "iqmp not inverse of q"},
    {ERR_REASON(RSA_R_KEY_SIZE_TOO_SMALL), "key size too small"},
    {ERR_REASON(RSA_R_LAST_OCTET_INVALID), "last octet invalid"},
    {ERR_REASON(RSA_R_MODULUS_TOO_LARGE), "modulus too large"},
    {ERR_REASON(RSA_R_NON_FIPS_RSA_METHOD), "non fips rsa method"},
    {ERR_REASON(RSA_R_NO_PUBLIC_EXPONENT), "no public exponent"},
    {ERR_REASON(RSA_R_NULL_BEFORE_BLOCK_MISSING),
     "null before block missing"},
    {ERR_REASON(RSA_R_N_DOES_NOT_EQUAL_P_Q), "n does not equal p q"},
    {ERR_REASON(RSA_R_OAEP_DECODING_ERROR), "oaep decoding error"},
    {ERR_REASON(RSA_R_OPERATION_NOT_ALLOWED_IN_FIPS_MODE),
     "operation not allowed in fips mode"},
    {ERR_REASON(RSA_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE),
     "operation not supported for this keytype"},
    {ERR_REASON(RSA_R_PADDING_CHECK_FAILED), "padding check failed"},
    {ERR_REASON(RSA_R_PKCS_DECODING_ERROR), "pkcs decoding error"},
    {ERR_REASON(RSA_R_P_NOT_PRIME), "p not prime"},
    {ERR_REASON(RSA_R_Q_NOT_PRIME), "q not prime"},
    {ERR_REASON(RSA_R_RSA_OPERATIONS_NOT_SUPPORTED),
     "rsa operations not supported"},
    {ERR_REASON(RSA_R_SLEN_CHECK_FAILED), "salt length check failed"},
    {ERR_REASON(RSA_R_SLEN_RECOVERY_FAILED), "salt length recovery failed"},
    {ERR_REASON(RSA_R_SSLV3_ROLLBACK_ATTACK), "sslv3 rollback attack"},
    {ERR_REASON(RSA_R_THE_ASN1_OBJECT_IDENTIFIER_IS_NOT_KNOWN_FOR_THIS_MD),
     "the asn1 object identifier is not known for this md"},
    {ERR_REASON(RSA_R_UNKNOWN_ALGORITHM_TYPE), "unknown algorithm type"},
    {ERR_REASON(RSA_R_UNKNOWN_DIGEST), "unknown digest"},
    {ERR_REASON(RSA_R_UNKNOWN_MASK_DIGEST), "unknown mask digest"},
    {ERR_REASON(RSA_R_UNKNOWN_PADDING_TYPE), "unknown padding type"},
    {ERR_REASON(RSA_R_UNKNOWN_PSS_DIGEST), "unknown pss digest"},
    {ERR_REASON(RSA_R_UNSUPPORTED_ENCRYPTION_TYPE),
     "unsupported encryption type"},
    {ERR_REASON(RSA_R_UNSUPPORTED_LABEL_SOURCE), "unsupported label source"},
    {ERR_REASON(RSA_R_UNSUPPORTED_MASK_ALGORITHM),
     "unsupported mask algorithm"},
    {ERR_REASON(RSA_R_UNSUPPORTED_MASK_PARAMETER),
     "unsupported mask parameter"},
    {ERR_REASON(RSA_R_UNSUPPORTED_SIGNATURE_TYPE),
     "unsupported signature type"},
    {ERR_REASON(RSA_R_VALUE_MISSING), "value missing"},
    {ERR_REASON(RSA_R_WRONG_SIGNATURE_LENGTH), "wrong signature length"},
    {0, NULL}
};

#endif

void ERR_load_RSA_strings(void)
{
#ifndef OPENSSL_NO_ERR

    if (ERR_func_error_string(RSA_str_functs[0].error) == NULL) {
        ERR_load_strings(0, RSA_str_functs);
        ERR_load_strings(0, RSA_str_reasons);
    }
#endif
}
/* crypto/rsa/rsa_gen.c */
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
 * NB: these functions have been "upgraded", the deprecated versions (which
 * are compatibility wrappers using these functions) are in rsa_depr.c. -
 * Geoff
 */

#include <stdio.h>
#include <time.h>
// #include "cryptlib.h"
// #include "bn.h"
// #include "rsa.h"
#ifdef OPENSSL_FIPS
# include <fips.h>
extern int FIPS_rsa_x931_generate_key_ex(RSA *rsa, int bits, BIGNUM *e,
                                         BN_GENCB *cb);
#endif

static int rsa_builtin_keygen(RSA *rsa, int bits, BIGNUM *e_value,
                              BN_GENCB *cb);

/*
 * NB: this wrapper would normally be placed in rsa_lib.c and the static
 * implementation would probably be in rsa_eay.c. Nonetheless, is kept here
 * so that we don't introduce a new linker dependency. Eg. any application
 * that wasn't previously linking object code related to key-generation won't
 * have to now just because key-generation is part of RSA_METHOD.
 */
int RSA_generate_key_ex(RSA *rsa, int bits, BIGNUM *e_value, BN_GENCB *cb)
{
#ifdef OPENSSL_FIPS
    if (FIPS_mode() && !(rsa->meth->flags & RSA_FLAG_FIPS_METHOD)
        && !(rsa->flags & RSA_FLAG_NON_FIPS_ALLOW)) {
        RSAerr(RSA_F_RSA_GENERATE_KEY_EX, RSA_R_NON_FIPS_RSA_METHOD);
        return 0;
    }
#endif
    if (rsa->meth->rsa_keygen)
        return rsa->meth->rsa_keygen(rsa, bits, e_value, cb);
#ifdef OPENSSL_FIPS
    if (FIPS_mode())
        return FIPS_rsa_x931_generate_key_ex(rsa, bits, e_value, cb);
#endif
    return rsa_builtin_keygen(rsa, bits, e_value, cb);
}

static int rsa_builtin_keygen(RSA *rsa, int bits, BIGNUM *e_value,
                              BN_GENCB *cb)
{
    BIGNUM *r0 = NULL, *r1 = NULL, *r2 = NULL, *r3 = NULL, *tmp;
    BIGNUM local_r0, local_d, local_p;
    BIGNUM *pr0, *d, *p;
    int bitsp, bitsq, ok = -1, n = 0;
    BN_CTX *ctx = NULL;
    unsigned long error = 0;

    /*
     * When generating ridiculously small keys, we can get stuck
     * continually regenerating the same prime values.
     */
    if (bits < 16) {
        ok = 0;             /* we set our own err */
        RSAerr(RSA_F_RSA_BUILTIN_KEYGEN, RSA_R_KEY_SIZE_TOO_SMALL);
        goto err;
    }

    ctx = BN_CTX_new();
    if (ctx == NULL)
        goto err;
    BN_CTX_start(ctx);
    r0 = BN_CTX_get(ctx);
    r1 = BN_CTX_get(ctx);
    r2 = BN_CTX_get(ctx);
    r3 = BN_CTX_get(ctx);
    if (r3 == NULL)
        goto err;

    bitsp = (bits + 1) / 2;
    bitsq = bits - bitsp;

    /* We need the RSA components non-NULL */
    if (!rsa->n && ((rsa->n = BN_new()) == NULL))
        goto err;
    if (!rsa->d && ((rsa->d = BN_new()) == NULL))
        goto err;
    if (!rsa->e && ((rsa->e = BN_new()) == NULL))
        goto err;
    if (!rsa->p && ((rsa->p = BN_new()) == NULL))
        goto err;
    if (!rsa->q && ((rsa->q = BN_new()) == NULL))
        goto err;
    if (!rsa->dmp1 && ((rsa->dmp1 = BN_new()) == NULL))
        goto err;
    if (!rsa->dmq1 && ((rsa->dmq1 = BN_new()) == NULL))
        goto err;
    if (!rsa->iqmp && ((rsa->iqmp = BN_new()) == NULL))
        goto err;

    if (BN_copy(rsa->e, e_value) == NULL)
        goto err;

    BN_set_flags(rsa->p, BN_FLG_CONSTTIME);
    BN_set_flags(rsa->q, BN_FLG_CONSTTIME);
    BN_set_flags(r2, BN_FLG_CONSTTIME);
    /* generate p and q */
    for (;;) {
        if (!BN_generate_prime_ex(rsa->p, bitsp, 0, NULL, NULL, cb))
            goto err;
        if (!BN_sub(r2, rsa->p, BN_value_one()))
            goto err;
        ERR_set_mark();
        if (BN_mod_inverse(r1, r2, rsa->e, ctx) != NULL) {
            /* GCD == 1 since inverse exists */
            break;
        }
        error = ERR_peek_last_error();
        if (ERR_GET_LIB(error) == ERR_LIB_BN
            && ERR_GET_REASON(error) == BN_R_NO_INVERSE) {
            /* GCD != 1 */
            ERR_pop_to_mark();
        } else {
            goto err;
        }
        if (!BN_GENCB_call(cb, 2, n++))
            goto err;
    }
    if (!BN_GENCB_call(cb, 3, 0))
        goto err;
    for (;;) {
        do {
            if (!BN_generate_prime_ex(rsa->q, bitsq, 0, NULL, NULL, cb))
                goto err;
        } while (BN_cmp(rsa->p, rsa->q) == 0);
        if (!BN_sub(r2, rsa->q, BN_value_one()))
            goto err;
        ERR_set_mark();
        if (BN_mod_inverse(r1, r2, rsa->e, ctx) != NULL) {
            /* GCD == 1 since inverse exists */
            break;
        }
        error = ERR_peek_last_error();
        if (ERR_GET_LIB(error) == ERR_LIB_BN
            && ERR_GET_REASON(error) == BN_R_NO_INVERSE) {
            /* GCD != 1 */
            ERR_pop_to_mark();
        } else {
            goto err;
        }
        if (!BN_GENCB_call(cb, 2, n++))
            goto err;
    }
    if (!BN_GENCB_call(cb, 3, 1))
        goto err;
    if (BN_cmp(rsa->p, rsa->q) < 0) {
        tmp = rsa->p;
        rsa->p = rsa->q;
        rsa->q = tmp;
    }

    /* calculate n */
    if (!BN_mul(rsa->n, rsa->p, rsa->q, ctx))
        goto err;

    /* calculate d */
    if (!BN_sub(r1, rsa->p, BN_value_one()))
        goto err;               /* p-1 */
    if (!BN_sub(r2, rsa->q, BN_value_one()))
        goto err;               /* q-1 */
    if (!BN_mul(r0, r1, r2, ctx))
        goto err;               /* (p-1)(q-1) */
    if (!(rsa->flags & RSA_FLAG_NO_CONSTTIME)) {
        pr0 = &local_r0;
        BN_with_flags(pr0, r0, BN_FLG_CONSTTIME);
    } else
        pr0 = r0;
    if (!BN_mod_inverse(rsa->d, rsa->e, pr0, ctx))
        goto err;               /* d */

    /* set up d for correct BN_FLG_CONSTTIME flag */
    if (!(rsa->flags & RSA_FLAG_NO_CONSTTIME)) {
        d = &local_d;
        BN_with_flags(d, rsa->d, BN_FLG_CONSTTIME);
    } else
        d = rsa->d;

    /* calculate d mod (p-1) */
    if (!BN_mod(rsa->dmp1, d, r1, ctx))
        goto err;

    /* calculate d mod (q-1) */
    if (!BN_mod(rsa->dmq1, d, r2, ctx))
        goto err;

    /* calculate inverse of q mod p */
    if (!(rsa->flags & RSA_FLAG_NO_CONSTTIME)) {
        p = &local_p;
        BN_with_flags(p, rsa->p, BN_FLG_CONSTTIME);
    } else
        p = rsa->p;
    if (!BN_mod_inverse(rsa->iqmp, rsa->q, p, ctx))
        goto err;

    ok = 1;
 err:
    if (ok == -1) {
        RSAerr(RSA_F_RSA_BUILTIN_KEYGEN, ERR_LIB_BN);
        ok = 0;
    }
    if (ctx != NULL) {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }

    return ok;
}
/* crypto/rsa/rsa_lib.c */
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
// #include "crypto.h"
// #include "cryptlib.h"
// #include "lhash.h"
// #include "bn.h"
// #include "rsa.h"
// #include "rand.h"
#ifndef OPENSSL_NO_ENGINE
# include "engine.h"
#endif

#ifdef OPENSSL_FIPS
# include <fips.h>
#endif

const char RSA_version[] = "RSA" OPENSSL_VERSION_PTEXT;

static const RSA_METHOD *default_RSA_meth = NULL;

RSA *RSA_new(void)
{
    RSA *r = RSA_new_method(NULL);

    return r;
}

void RSA_set_default_method(const RSA_METHOD *meth)
{
    default_RSA_meth = meth;
}

const RSA_METHOD *RSA_get_default_method(void)
{
    if (default_RSA_meth == NULL) {
#ifdef OPENSSL_FIPS
        if (FIPS_mode())
            return FIPS_rsa_pkcs1_ssleay();
        else
            return RSA_PKCS1_SSLeay();
#else
# ifdef RSA_NULL
        default_RSA_meth = RSA_null_method();
# else
        default_RSA_meth = RSA_PKCS1_SSLeay();
# endif
#endif
    }

    return default_RSA_meth;
}

const RSA_METHOD *RSA_get_method(const RSA *rsa)
{
    return rsa->meth;
}

int RSA_set_method(RSA *rsa, const RSA_METHOD *meth)
{
    /*
     * NB: The caller is specifically setting a method, so it's not up to us
     * to deal with which ENGINE it comes from.
     */
    const RSA_METHOD *mtmp;
    mtmp = rsa->meth;
    if (mtmp->finish)
        mtmp->finish(rsa);
#ifndef OPENSSL_NO_ENGINE
    if (rsa->engine) {
        ENGINE_finish(rsa->engine);
        rsa->engine = NULL;
    }
#endif
    rsa->meth = meth;
    if (meth->init)
        meth->init(rsa);
    return 1;
}

RSA *RSA_new_method(ENGINE *engine)
{
    RSA *ret;

    ret = (RSA *)OPENSSL_malloc(sizeof(RSA));
    if (ret == NULL) {
        RSAerr(RSA_F_RSA_NEW_METHOD, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    memset(ret,0,sizeof(RSA));

    ret->meth = RSA_get_default_method();
#ifndef OPENSSL_NO_ENGINE
    if (engine) {
        if (!ENGINE_init(engine)) {
            RSAerr(RSA_F_RSA_NEW_METHOD, ERR_R_ENGINE_LIB);
            OPENSSL_free(ret);
            return NULL;
        }
        ret->engine = engine;
    } else
        ret->engine = ENGINE_get_default_RSA();
    if (ret->engine) {
        ret->meth = ENGINE_get_RSA(ret->engine);
        if (!ret->meth) {
            RSAerr(RSA_F_RSA_NEW_METHOD, ERR_R_ENGINE_LIB);
            ENGINE_finish(ret->engine);
            OPENSSL_free(ret);
            return NULL;
        }
    }
#endif

    ret->pad = 0;
    ret->version = 0;
    ret->n = NULL;
    ret->e = NULL;
    ret->d = NULL;
    ret->p = NULL;
    ret->q = NULL;
    ret->dmp1 = NULL;
    ret->dmq1 = NULL;
    ret->iqmp = NULL;
    ret->references = 1;
    ret->_method_mod_n = NULL;
    ret->_method_mod_p = NULL;
    ret->_method_mod_q = NULL;
    ret->blinding = NULL;
    ret->mt_blinding = NULL;
    ret->bignum_data = NULL;
    ret->flags = ret->meth->flags & ~RSA_FLAG_NON_FIPS_ALLOW;
    if (!CRYPTO_new_ex_data(CRYPTO_EX_INDEX_RSA, ret, &ret->ex_data)) {
#ifndef OPENSSL_NO_ENGINE
        if (ret->engine)
            ENGINE_finish(ret->engine);
#endif
        OPENSSL_free(ret);
        return (NULL);
    }

    if ((ret->meth->init != NULL) && !ret->meth->init(ret)) {
#ifndef OPENSSL_NO_ENGINE
        if (ret->engine)
            ENGINE_finish(ret->engine);
#endif
        CRYPTO_free_ex_data(CRYPTO_EX_INDEX_RSA, ret, &ret->ex_data);
        OPENSSL_free(ret);
        ret = NULL;
    }
    return (ret);
}

void RSA_free(RSA *r)
{
    int i;

    if (r == NULL)
        return;

    i = CRYPTO_add(&r->references, -1, CRYPTO_LOCK_RSA);
#ifdef REF_PRINT
    REF_PRINT("RSA", r);
#endif
    if (i > 0)
        return;
#ifdef REF_CHECK
    if (i < 0) {
        fprintf(stderr, "RSA_free, bad reference count\n");
        abort();
    }
#endif

    if (r->meth->finish)
        r->meth->finish(r);
#ifndef OPENSSL_NO_ENGINE
    if (r->engine)
        ENGINE_finish(r->engine);
#endif

    CRYPTO_free_ex_data(CRYPTO_EX_INDEX_RSA, r, &r->ex_data);

    if (r->n != NULL)
        BN_clear_free(r->n);
    if (r->e != NULL)
        BN_clear_free(r->e);
    if (r->d != NULL)
        BN_clear_free(r->d);
    if (r->p != NULL)
        BN_clear_free(r->p);
    if (r->q != NULL)
        BN_clear_free(r->q);
    if (r->dmp1 != NULL)
        BN_clear_free(r->dmp1);
    if (r->dmq1 != NULL)
        BN_clear_free(r->dmq1);
    if (r->iqmp != NULL)
        BN_clear_free(r->iqmp);
    if (r->blinding != NULL)
        BN_BLINDING_free(r->blinding);
    if (r->mt_blinding != NULL)
        BN_BLINDING_free(r->mt_blinding);
    if (r->bignum_data != NULL)
        OPENSSL_free_locked(r->bignum_data);
    OPENSSL_free(r);
}

int RSA_up_ref(RSA *r)
{
    int i = CRYPTO_add(&r->references, 1, CRYPTO_LOCK_RSA);
#ifdef REF_PRINT
    REF_PRINT("RSA", r);
#endif
#ifdef REF_CHECK
    if (i < 2) {
        fprintf(stderr, "RSA_up_ref, bad reference count\n");
        abort();
    }
#endif
    return ((i > 1) ? 1 : 0);
}

int RSA_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func,
                         CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func)
{
    return CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_RSA, argl, argp,
                                   new_func, dup_func, free_func);
}

int RSA_set_ex_data(RSA *r, int idx, void *arg)
{
    return (CRYPTO_set_ex_data(&r->ex_data, idx, arg));
}

void *RSA_get_ex_data(const RSA *r, int idx)
{
    return (CRYPTO_get_ex_data(&r->ex_data, idx));
}

int RSA_memory_lock(RSA *r)
{
    int i, j, k, off;
    char *p;
    BIGNUM *bn, **t[6], *b;
    BN_ULONG *ul;

    if (r->d == NULL)
        return (1);
    t[0] = &r->d;
    t[1] = &r->p;
    t[2] = &r->q;
    t[3] = &r->dmp1;
    t[4] = &r->dmq1;
    t[5] = &r->iqmp;
    k = sizeof(BIGNUM) * 6;
    off = k / sizeof(BN_ULONG) + 1;
    j = 1;
    for (i = 0; i < 6; i++)
        j += (*t[i])->top;
    if ((p = OPENSSL_malloc_locked((off + j) * sizeof(BN_ULONG))) == NULL) {
        RSAerr(RSA_F_RSA_MEMORY_LOCK, ERR_R_MALLOC_FAILURE);
        return (0);
    }
    bn = (BIGNUM *)p;
    ul = (BN_ULONG *)&(p[off]);
    for (i = 0; i < 6; i++) {
        b = *(t[i]);
        *(t[i]) = &(bn[i]);
        memcpy((char *)&(bn[i]), (char *)b, sizeof(BIGNUM));
        bn[i].flags = BN_FLG_STATIC_DATA;
        bn[i].d = ul;
        memcpy((char *)ul, b->d, sizeof(BN_ULONG) * b->top);
        ul += b->top;
        BN_clear_free(b);
    }

    /* I should fix this so it can still be done */
    r->flags &= ~(RSA_FLAG_CACHE_PRIVATE | RSA_FLAG_CACHE_PUBLIC);

    r->bignum_data = p;
    return (1);
}
/* crypto/rsa/rsa_none.c */
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
// #include "bn.h"
// #include "rsa.h"
// #include "rand.h"

int RSA_padding_add_none(unsigned char *to, int tlen,
                         const unsigned char *from, int flen)
{
    if (flen > tlen) {
        RSAerr(RSA_F_RSA_PADDING_ADD_NONE, RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE);
        return (0);
    }

    if (flen < tlen) {
        RSAerr(RSA_F_RSA_PADDING_ADD_NONE, RSA_R_DATA_TOO_SMALL_FOR_KEY_SIZE);
        return (0);
    }

    memcpy(to, from, (unsigned int)flen);
    return (1);
}

int RSA_padding_check_none(unsigned char *to, int tlen,
                           const unsigned char *from, int flen, int num)
{

    if (flen > tlen) {
        RSAerr(RSA_F_RSA_PADDING_CHECK_NONE, RSA_R_DATA_TOO_LARGE);
        return (-1);
    }

    memset(to, 0, tlen - flen);
    memcpy(to + tlen - flen, from, flen);
    return (tlen);
}
/* rsa_null.c */
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
// #include "bn.h"
// #include "rsa.h"
// #include "rand.h"

/*
 * This is a dummy RSA implementation that just returns errors when called.
 * It is designed to allow some RSA functions to work while stopping those
 * covered by the RSA patent. That is RSA, encryption, decryption, signing
 * and verify is not allowed but RSA key generation, key checking and other
 * operations (like storing RSA keys) are permitted.
 */

static int RSA_null_public_encrypt(int flen, const unsigned char *from,
                                   unsigned char *to, RSA *rsa, int padding);
static int RSA_null_private_encrypt(int flen, const unsigned char *from,
                                    unsigned char *to, RSA *rsa, int padding);
static int RSA_null_public_decrypt(int flen, const unsigned char *from,
                                   unsigned char *to, RSA *rsa, int padding);
static int RSA_null_private_decrypt(int flen, const unsigned char *from,
                                    unsigned char *to, RSA *rsa, int padding);
#if 0                           /* not currently used */
static int RSA_null_mod_exp(const BIGNUM *r0, const BIGNUM *i, RSA *rsa);
#endif
static int RSA_null_init(RSA *rsa);
static int RSA_null_finish(RSA *rsa);
static RSA_METHOD rsa_null_meth = {
    "Null RSA",
    RSA_null_public_encrypt,
    RSA_null_public_decrypt,
    RSA_null_private_encrypt,
    RSA_null_private_decrypt,
    NULL,
    NULL,
    RSA_null_init,
    RSA_null_finish,
    0,
    NULL,
    NULL,
    NULL,
    NULL
};

const RSA_METHOD *RSA_null_method(void)
{
    return (&rsa_null_meth);
}

static int RSA_null_public_encrypt(int flen, const unsigned char *from,
                                   unsigned char *to, RSA *rsa, int padding)
{
    RSAerr(RSA_F_RSA_NULL_PUBLIC_ENCRYPT, RSA_R_RSA_OPERATIONS_NOT_SUPPORTED);
    return -1;
}

static int RSA_null_private_encrypt(int flen, const unsigned char *from,
                                    unsigned char *to, RSA *rsa, int padding)
{
    RSAerr(RSA_F_RSA_NULL_PRIVATE_ENCRYPT,
           RSA_R_RSA_OPERATIONS_NOT_SUPPORTED);
    return -1;
}

static int RSA_null_private_decrypt(int flen, const unsigned char *from,
                                    unsigned char *to, RSA *rsa, int padding)
{
    RSAerr(RSA_F_RSA_NULL_PRIVATE_DECRYPT,
           RSA_R_RSA_OPERATIONS_NOT_SUPPORTED);
    return -1;
}

static int RSA_null_public_decrypt(int flen, const unsigned char *from,
                                   unsigned char *to, RSA *rsa, int padding)
{
    RSAerr(RSA_F_RSA_NULL_PUBLIC_DECRYPT, RSA_R_RSA_OPERATIONS_NOT_SUPPORTED);
    return -1;
}

#if 0                           /* not currently used */
static int RSA_null_mod_exp(BIGNUM *r0, BIGNUM *I, RSA *rsa)
{
    ... err(RSA_F_RSA_NULL_MOD_EXP, RSA_R_RSA_OPERATIONS_NOT_SUPPORTED);
    return -1;
}
#endif

static int RSA_null_init(RSA *rsa)
{
    return (1);
}

static int RSA_null_finish(RSA *rsa)
{
    return (1);
}
/* crypto/rsa/rsa_oaep.c */
/*
 * Written by Ulf Moeller. This software is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied.
 */

/* EME-OAEP as defined in RFC 2437 (PKCS #1 v2.0) */

/*
 * See Victor Shoup, "OAEP reconsidered," Nov. 2000, <URL:
 * http://www.shoup.net/papers/oaep.ps.Z> for problems with the security
 * proof for the original OAEP scheme, which EME-OAEP is based on. A new
 * proof can be found in E. Fujisaki, T. Okamoto, D. Pointcheval, J. Stern,
 * "RSA-OEAP is Still Alive!", Dec. 2000, <URL:
 * http://eprint.iacr.org/2000/061/>. The new proof has stronger requirements
 * for the underlying permutation: "partial-one-wayness" instead of
 * one-wayness.  For the RSA function, this is an equivalent notion.
 */

#include "constant_time_locl.h"

#if !defined(OPENSSL_NO_SHA) && !defined(OPENSSL_NO_SHA1)
# include <stdio.h>
# include "cryptlib.h"
# include "bn.h"
# include "rsa.h"
# include "evp.h"
# include "rand.h"
# include "sha.h"

int RSA_padding_add_PKCS1_OAEP(unsigned char *to, int tlen,
                               const unsigned char *from, int flen,
                               const unsigned char *param, int plen)
{
    return RSA_padding_add_PKCS1_OAEP_mgf1(to, tlen, from, flen,
                                           param, plen, NULL, NULL);
}

int RSA_padding_add_PKCS1_OAEP_mgf1(unsigned char *to, int tlen,
                                    const unsigned char *from, int flen,
                                    const unsigned char *param, int plen,
                                    const EVP_MD *md, const EVP_MD *mgf1md)
{
    int i, emlen = tlen - 1;
    unsigned char *db, *seed;
    unsigned char *dbmask, seedmask[EVP_MAX_MD_SIZE];
    int mdlen;

    if (md == NULL)
        md = EVP_sha1();
    if (mgf1md == NULL)
        mgf1md = md;

    mdlen = EVP_MD_size(md);

    if (flen > emlen - 2 * mdlen - 1) {
        RSAerr(RSA_F_RSA_PADDING_ADD_PKCS1_OAEP_MGF1,
               RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE);
        return 0;
    }

    if (emlen < 2 * mdlen + 1) {
        RSAerr(RSA_F_RSA_PADDING_ADD_PKCS1_OAEP_MGF1,
               RSA_R_KEY_SIZE_TOO_SMALL);
        return 0;
    }

    to[0] = 0;
    seed = to + 1;
    db = to + mdlen + 1;

    if (!EVP_Digest((void *)param, plen, db, NULL, md, NULL))
        return 0;
    memset(db + mdlen, 0, emlen - flen - 2 * mdlen - 1);
    db[emlen - flen - mdlen - 1] = 0x01;
    memcpy(db + emlen - flen - mdlen, from, (unsigned int)flen);
    if (RAND_bytes(seed, mdlen) <= 0)
        return 0;
# ifdef PKCS_TESTVECT
    memcpy(seed,
           "\xaa\xfd\x12\xf6\x59\xca\xe6\x34\x89\xb4\x79\xe5\x07\x6d\xde\xc2\xf0\x6c\xb5\x8f",
           20);
# endif

    dbmask = OPENSSL_malloc(emlen - mdlen);
    if (dbmask == NULL) {
        RSAerr(RSA_F_RSA_PADDING_ADD_PKCS1_OAEP_MGF1, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    if (PKCS1_MGF1(dbmask, emlen - mdlen, seed, mdlen, mgf1md) < 0)
        goto err;
    for (i = 0; i < emlen - mdlen; i++)
        db[i] ^= dbmask[i];

    if (PKCS1_MGF1(seedmask, mdlen, db, emlen - mdlen, mgf1md) < 0)
        goto err;
    for (i = 0; i < mdlen; i++)
        seed[i] ^= seedmask[i];

    OPENSSL_free(dbmask);
    return 1;

 err:
    OPENSSL_free(dbmask);
    return 0;
}

int RSA_padding_check_PKCS1_OAEP(unsigned char *to, int tlen,
                                 const unsigned char *from, int flen, int num,
                                 const unsigned char *param, int plen)
{
    return RSA_padding_check_PKCS1_OAEP_mgf1(to, tlen, from, flen, num,
                                             param, plen, NULL, NULL);
}

int RSA_padding_check_PKCS1_OAEP_mgf1(unsigned char *to, int tlen,
                                      const unsigned char *from, int flen,
                                      int num, const unsigned char *param,
                                      int plen, const EVP_MD *md,
                                      const EVP_MD *mgf1md)
{
    int i, dblen = 0, mlen = -1, one_index = 0, msg_index;
    unsigned int good, found_one_byte;
    const unsigned char *maskedseed, *maskeddb;
    /*
     * |em| is the encoded message, zero-padded to exactly |num| bytes: em =
     * Y || maskedSeed || maskedDB
     */
    unsigned char *db = NULL, *em = NULL, seed[EVP_MAX_MD_SIZE],
        phash[EVP_MAX_MD_SIZE];
    int mdlen;

    if (md == NULL)
        md = EVP_sha1();
    if (mgf1md == NULL)
        mgf1md = md;

    mdlen = EVP_MD_size(md);

    if (tlen <= 0 || flen <= 0)
        return -1;
    /*
     * |num| is the length of the modulus; |flen| is the length of the
     * encoded message. Therefore, for any |from| that was obtained by
     * decrypting a ciphertext, we must have |flen| <= |num|. Similarly,
     * num < 2 * mdlen + 2 must hold for the modulus irrespective of
     * the ciphertext, see PKCS #1 v2.2, section 7.1.2.
     * This does not leak any side-channel information.
     */
    if (num < flen || num < 2 * mdlen + 2)
        goto decoding_err;

    dblen = num - mdlen - 1;
    db = OPENSSL_malloc(dblen);
    if (db == NULL) {
        RSAerr(RSA_F_RSA_PADDING_CHECK_PKCS1_OAEP_MGF1, ERR_R_MALLOC_FAILURE);
        goto cleanup;
    }

    if (flen != num) {
        em = OPENSSL_malloc(num);
        if (em == NULL) {
            RSAerr(RSA_F_RSA_PADDING_CHECK_PKCS1_OAEP_MGF1,
                   ERR_R_MALLOC_FAILURE);
            goto cleanup;
        }

        /*
         * Caller is encouraged to pass zero-padded message created with
         * BN_bn2binpad, but if it doesn't, we do this zero-padding copy
         * to avoid leaking that information. The copy still leaks some
         * side-channel information, but it's impossible to have a fixed
         * memory access pattern since we can't read out of the bounds of
         * |from|.
         */
        memset(em, 0, num);
        memcpy(em + num - flen, from, flen);
        from = em;
    }

    /*
     * The first byte must be zero, however we must not leak if this is
     * true. See James H. Manger, "A Chosen Ciphertext  Attack on RSA
     * Optimal Asymmetric Encryption Padding (OAEP) [...]", CRYPTO 2001).
     */
    good = constant_time_is_zero(from[0]);

    maskedseed = from + 1;
    maskeddb = from + 1 + mdlen;

    if (PKCS1_MGF1(seed, mdlen, maskeddb, dblen, mgf1md))
        goto cleanup;
    for (i = 0; i < mdlen; i++)
        seed[i] ^= maskedseed[i];

    if (PKCS1_MGF1(db, dblen, seed, mdlen, mgf1md))
        goto cleanup;
    for (i = 0; i < dblen; i++)
        db[i] ^= maskeddb[i];

    if (!EVP_Digest((void *)param, plen, phash, NULL, md, NULL))
        goto cleanup;

    good &= constant_time_is_zero(CRYPTO_memcmp(db, phash, mdlen));

    found_one_byte = 0;
    for (i = mdlen; i < dblen; i++) {
        /*
         * Padding consists of a number of 0-bytes, followed by a 1.
         */
        unsigned int equals1 = constant_time_eq(db[i], 1);
        unsigned int equals0 = constant_time_is_zero(db[i]);
        one_index = constant_time_select_int(~found_one_byte & equals1,
                                             i, one_index);
        found_one_byte |= equals1;
        good &= (found_one_byte | equals0);
    }

    good &= found_one_byte;

    /*
     * At this point |good| is zero unless the plaintext was valid,
     * so plaintext-awareness ensures timing side-channels are no longer a
     * concern.
     */
    if (!good)
        goto decoding_err;

    msg_index = one_index + 1;
    mlen = dblen - msg_index;

    if (tlen < mlen) {
        RSAerr(RSA_F_RSA_PADDING_CHECK_PKCS1_OAEP_MGF1, RSA_R_DATA_TOO_LARGE);
        mlen = -1;
    } else {
        memcpy(to, db + msg_index, mlen);
        goto cleanup;
    }

 decoding_err:
    /*
     * To avoid chosen ciphertext attacks, the error message should not
     * reveal which kind of decoding error happened.
     */
    RSAerr(RSA_F_RSA_PADDING_CHECK_PKCS1_OAEP_MGF1,
           RSA_R_OAEP_DECODING_ERROR);
 cleanup:
    if (db != NULL) {
        OPENSSL_cleanse(db, dblen);
        OPENSSL_free(db);
    }
    if (em != NULL) {
        OPENSSL_cleanse(em, num);
        OPENSSL_free(em);
    }
    return mlen;
}

int PKCS1_MGF1(unsigned char *mask, long len,
               const unsigned char *seed, long seedlen, const EVP_MD *dgst)
{
    long i, outlen = 0;
    unsigned char cnt[4];
    EVP_MD_CTX c;
    unsigned char md[EVP_MAX_MD_SIZE];
    int mdlen;
    int rv = -1;

    EVP_MD_CTX_init(&c);
    mdlen = EVP_MD_size(dgst);
    if (mdlen < 0)
        goto err;
    for (i = 0; outlen < len; i++) {
        cnt[0] = (unsigned char)((i >> 24) & 255);
        cnt[1] = (unsigned char)((i >> 16) & 255);
        cnt[2] = (unsigned char)((i >> 8)) & 255;
        cnt[3] = (unsigned char)(i & 255);
        if (!EVP_DigestInit_ex(&c, dgst, NULL)
            || !EVP_DigestUpdate(&c, seed, seedlen)
            || !EVP_DigestUpdate(&c, cnt, 4))
            goto err;
        if (outlen + mdlen <= len) {
            if (!EVP_DigestFinal_ex(&c, mask + outlen, NULL))
                goto err;
            outlen += mdlen;
        } else {
            if (!EVP_DigestFinal_ex(&c, md, NULL))
                goto err;
            memcpy(mask + outlen, md, len - outlen);
            outlen = len;
        }
    }
    rv = 0;
 err:
    EVP_MD_CTX_cleanup(&c);
    return rv;
}

#endif
/* crypto/rsa/rsa_pk1.c */
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

// #include "constant_time_locl.h"

#include <stdio.h>
// #include "cryptlib.h"
// #include "bn.h"
// #include "rsa.h"
// #include "rand.h"

int RSA_padding_add_PKCS1_type_1(unsigned char *to, int tlen,
                                 const unsigned char *from, int flen)
{
    int j;
    unsigned char *p;

    if (flen > (tlen - RSA_PKCS1_PADDING_SIZE)) {
        RSAerr(RSA_F_RSA_PADDING_ADD_PKCS1_TYPE_1,
               RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE);
        return (0);
    }

    p = (unsigned char *)to;

    *(p++) = 0;
    *(p++) = 1;                 /* Private Key BT (Block Type) */

    /* pad out with 0xff data */
    j = tlen - 3 - flen;
    memset(p, 0xff, j);
    p += j;
    *(p++) = '\0';
    memcpy(p, from, (unsigned int)flen);
    return (1);
}

int RSA_padding_check_PKCS1_type_1(unsigned char *to, int tlen,
                                   const unsigned char *from, int flen,
                                   int num)
{
    int i, j;
    const unsigned char *p;

    p = from;

    /*
     * The format is
     * 00 || 01 || PS || 00 || D
     * PS - padding string, at least 8 bytes of FF
     * D  - data.
     */

    if (num < 11)
        return -1;

    /* Accept inputs with and without the leading 0-byte. */
    if (num == flen) {
        if ((*p++) != 0x00) {
            RSAerr(RSA_F_RSA_PADDING_CHECK_PKCS1_TYPE_1,
                   RSA_R_INVALID_PADDING);
            return -1;
        }
        flen--;
    }

    if ((num != (flen + 1)) || (*(p++) != 01)) {
        RSAerr(RSA_F_RSA_PADDING_CHECK_PKCS1_TYPE_1,
               RSA_R_BLOCK_TYPE_IS_NOT_01);
        return (-1);
    }

    /* scan over padding data */
    j = flen - 1;               /* one for type. */
    for (i = 0; i < j; i++) {
        if (*p != 0xff) {       /* should decrypt to 0xff */
            if (*p == 0) {
                p++;
                break;
            } else {
                RSAerr(RSA_F_RSA_PADDING_CHECK_PKCS1_TYPE_1,
                       RSA_R_BAD_FIXED_HEADER_DECRYPT);
                return (-1);
            }
        }
        p++;
    }

    if (i == j) {
        RSAerr(RSA_F_RSA_PADDING_CHECK_PKCS1_TYPE_1,
               RSA_R_NULL_BEFORE_BLOCK_MISSING);
        return (-1);
    }

    if (i < 8) {
        RSAerr(RSA_F_RSA_PADDING_CHECK_PKCS1_TYPE_1,
               RSA_R_BAD_PAD_BYTE_COUNT);
        return (-1);
    }
    i++;                        /* Skip over the '\0' */
    j -= i;
    if (j > tlen) {
        RSAerr(RSA_F_RSA_PADDING_CHECK_PKCS1_TYPE_1, RSA_R_DATA_TOO_LARGE);
        return (-1);
    }
    memcpy(to, p, (unsigned int)j);

    return (j);
}

int RSA_padding_add_PKCS1_type_2(unsigned char *to, int tlen,
                                 const unsigned char *from, int flen)
{
    int i, j;
    unsigned char *p;

    if (flen > (tlen - 11)) {
        RSAerr(RSA_F_RSA_PADDING_ADD_PKCS1_TYPE_2,
               RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE);
        return (0);
    }

    p = (unsigned char *)to;

    *(p++) = 0;
    *(p++) = 2;                 /* Public Key BT (Block Type) */

    /* pad out with non-zero random data */
    j = tlen - 3 - flen;

    if (RAND_bytes(p, j) <= 0)
        return (0);
    for (i = 0; i < j; i++) {
        if (*p == '\0')
            do {
                if (RAND_bytes(p, 1) <= 0)
                    return (0);
            } while (*p == '\0');
        p++;
    }

    *(p++) = '\0';

    memcpy(p, from, (unsigned int)flen);
    return (1);
}

int RSA_padding_check_PKCS1_type_2(unsigned char *to, int tlen,
                                   const unsigned char *from, int flen,
                                   int num)
{
    int i;
    /* |em| is the encoded message, zero-padded to exactly |num| bytes */
    unsigned char *em = NULL;
    unsigned int good, found_zero_byte;
    int zero_index = 0, msg_index, mlen = -1;

    if (tlen < 0 || flen < 0)
        return -1;

    /*
     * PKCS#1 v1.5 decryption. See "PKCS #1 v2.2: RSA Cryptography Standard",
     * section 7.2.2.
     */

    if (flen > num)
        goto err;

    if (num < 11)
        goto err;

    if (flen != num) {
        em = OPENSSL_malloc(num);
        if (em == NULL) {
            RSAerr(RSA_F_RSA_PADDING_CHECK_PKCS1_TYPE_2, ERR_R_MALLOC_FAILURE);
            return -1;
        }
        /*
         * Caller is encouraged to pass zero-padded message created with
         * BN_bn2binpad, but if it doesn't, we do this zero-padding copy
         * to avoid leaking that information. The copy still leaks some
         * side-channel information, but it's impossible to have a fixed
         * memory access pattern since we can't read out of the bounds of
         * |from|.
         */
        memset(em, 0, num);
        memcpy(em + num - flen, from, flen);
        from = em;
    }

    good = constant_time_is_zero(from[0]);
    good &= constant_time_eq(from[1], 2);

    found_zero_byte = 0;
    for (i = 2; i < num; i++) {
        unsigned int equals0 = constant_time_is_zero(from[i]);
        zero_index =
            constant_time_select_int(~found_zero_byte & equals0, i,
                                     zero_index);
        found_zero_byte |= equals0;
    }

    /*
     * PS must be at least 8 bytes long, and it starts two bytes into |from|.
     * If we never found a 0-byte, then |zero_index| is 0 and the check
     * also fails.
     */
    good &= constant_time_ge((unsigned int)(zero_index), 2 + 8);

    /*
     * Skip the zero byte. This is incorrect if we never found a zero-byte
     * but in this case we also do not copy the message out.
     */
    msg_index = zero_index + 1;
    mlen = num - msg_index;

    /*
     * For good measure, do this check in constant time as well; it could
     * leak something if |tlen| was assuming valid padding.
     */
    good &= constant_time_ge((unsigned int)(tlen), (unsigned int)(mlen));

    /*
     * We can't continue in constant-time because we need to copy the result
     * and we cannot fake its length. This unavoidably leaks timing
     * information at the API boundary.
     */
    if (!good) {
        mlen = -1;
        goto err;
    }

    memcpy(to, from + msg_index, mlen);

 err:
    if (em != NULL) {
        OPENSSL_cleanse(em, num);
        OPENSSL_free(em);
    }
    if (mlen == -1)
        RSAerr(RSA_F_RSA_PADDING_CHECK_PKCS1_TYPE_2,
               RSA_R_PKCS_DECODING_ERROR);
    return mlen;
}
/* crypto/rsa/rsa_pmeth.c */
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
// #include "cryptlib.h"
// #include "asn1t.h"
// #include "x509.h"
// #include "rsa.h"
// #include "bn.h"
#include "evp.h"
#include "x509v3.h"
#ifndef OPENSSL_NO_CMS
# include "cms.h"
#endif
#ifdef OPENSSL_FIPS
# include <fips.h>
#endif
#include "evp_locl.h"
#include "rsa_locl.h"

/* RSA pkey context structure */

typedef struct {
    /* Key gen parameters */
    int nbits;
    BIGNUM *pub_exp;
    /* Keygen callback info */
    int gentmp[2];
    /* RSA padding mode */
    int pad_mode;
    /* message digest */
    const EVP_MD *md;
    /* message digest for MGF1 */
    const EVP_MD *mgf1md;
    /* PSS salt length */
    int saltlen;
    /* Temp buffer */
    unsigned char *tbuf;
    /* OAEP label */
    unsigned char *oaep_label;
    size_t oaep_labellen;
} RSA_PKEY_CTX;

static int pkey_rsa_init(EVP_PKEY_CTX *ctx)
{
    RSA_PKEY_CTX *rctx;
    rctx = OPENSSL_malloc(sizeof(RSA_PKEY_CTX));
    if (!rctx)
        return 0;
    rctx->nbits = 1024;
    rctx->pub_exp = NULL;
    rctx->pad_mode = RSA_PKCS1_PADDING;
    rctx->md = NULL;
    rctx->mgf1md = NULL;
    rctx->tbuf = NULL;

    rctx->saltlen = -2;

    rctx->oaep_label = NULL;
    rctx->oaep_labellen = 0;

    ctx->data = rctx;
    ctx->keygen_info = rctx->gentmp;
    ctx->keygen_info_count = 2;

    return 1;
}

static int pkey_rsa_copy(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src)
{
    RSA_PKEY_CTX *dctx, *sctx;
    if (!pkey_rsa_init(dst))
        return 0;
    sctx = src->data;
    dctx = dst->data;
    dctx->nbits = sctx->nbits;
    if (sctx->pub_exp) {
        dctx->pub_exp = BN_dup(sctx->pub_exp);
        if (!dctx->pub_exp)
            return 0;
    }
    dctx->pad_mode = sctx->pad_mode;
    dctx->md = sctx->md;
    dctx->mgf1md = sctx->mgf1md;
    if (sctx->oaep_label) {
        if (dctx->oaep_label)
            OPENSSL_free(dctx->oaep_label);
        dctx->oaep_label = BUF_memdup(sctx->oaep_label, sctx->oaep_labellen);
        if (!dctx->oaep_label)
            return 0;
        dctx->oaep_labellen = sctx->oaep_labellen;
    }
    return 1;
}

static int setup_tbuf(RSA_PKEY_CTX *ctx, EVP_PKEY_CTX *pk)
{
    if (ctx->tbuf)
        return 1;
    ctx->tbuf = OPENSSL_malloc(EVP_PKEY_size(pk->pkey));
    if (!ctx->tbuf)
        return 0;
    return 1;
}

static void pkey_rsa_cleanup(EVP_PKEY_CTX *ctx)
{
    RSA_PKEY_CTX *rctx = ctx->data;
    if (rctx) {
        if (rctx->pub_exp)
            BN_free(rctx->pub_exp);
        if (rctx->tbuf)
            OPENSSL_free(rctx->tbuf);
        if (rctx->oaep_label)
            OPENSSL_free(rctx->oaep_label);
        OPENSSL_free(rctx);
    }
}

#ifdef OPENSSL_FIPS
/*
 * FIP checker. Return value indicates status of context parameters: 1 :
 * redirect to FIPS. 0 : don't redirect to FIPS. -1 : illegal operation in
 * FIPS mode.
 */

static int pkey_fips_check_rsa(const RSA *rsa, const EVP_MD **pmd,
                               const EVP_MD **pmgf1md)
{
    int rv = -1;

    if (!FIPS_mode())
        return 0;
    if (rsa->flags & RSA_FLAG_NON_FIPS_ALLOW)
        rv = 0;
    if (!(rsa->meth->flags & RSA_FLAG_FIPS_METHOD) && rv)
        return -1;
    if (*pmd != NULL) {
        *pmd = FIPS_get_digestbynid(EVP_MD_type(*pmd));
        if (*pmd == NULL || !((*pmd)->flags & EVP_MD_FLAG_FIPS))
            return rv;
    }
    if (*pmgf1md != NULL) {
        *pmgf1md = FIPS_get_digestbynid(EVP_MD_type(*pmgf1md));
        if (*pmgf1md == NULL || !((*pmgf1md)->flags & EVP_MD_FLAG_FIPS))
            return rv;
    }
    return 1;
}
#endif

static int pkey_rsa_sign(EVP_PKEY_CTX *ctx, unsigned char *sig,
                         size_t *siglen, const unsigned char *tbs,
                         size_t tbslen)
{
    int ret;
    RSA_PKEY_CTX *rctx = ctx->data;
    RSA *rsa = ctx->pkey->pkey.rsa;
    const EVP_MD *md = rctx->md;
    const EVP_MD *mgf1md = rctx->mgf1md;

#ifdef OPENSSL_FIPS
    ret = pkey_fips_check_rsa(rsa, &md, &mgf1md);
    if (ret < 0) {
        RSAerr(RSA_F_PKEY_RSA_SIGN, RSA_R_OPERATION_NOT_ALLOWED_IN_FIPS_MODE);
        return -1;
    }
#endif

    if (md != NULL) {
        if (tbslen != (size_t)EVP_MD_size(md)) {
            RSAerr(RSA_F_PKEY_RSA_SIGN, RSA_R_INVALID_DIGEST_LENGTH);
            return -1;
        }
#ifdef OPENSSL_FIPS
        if (ret > 0) {
            unsigned int slen;
            ret = FIPS_rsa_sign_digest(rsa, tbs, tbslen, md, rctx->pad_mode,
                                       rctx->saltlen, mgf1md, sig, &slen);
            if (ret > 0)
                *siglen = slen;
            else
                *siglen = 0;
            return ret;
        }
#endif

        if (EVP_MD_type(md) == NID_mdc2) {
            unsigned int sltmp;
            if (rctx->pad_mode != RSA_PKCS1_PADDING)
                return -1;
            ret = RSA_sign_ASN1_OCTET_STRING(NID_mdc2, tbs, tbslen, sig, &sltmp,
                                             rsa);

            if (ret <= 0)
                return ret;
            ret = sltmp;
        } else if (rctx->pad_mode == RSA_X931_PADDING) {
            if ((size_t)EVP_PKEY_size(ctx->pkey) < tbslen + 1) {
                RSAerr(RSA_F_PKEY_RSA_SIGN, RSA_R_KEY_SIZE_TOO_SMALL);
                return -1;
            }
            if (!setup_tbuf(rctx, ctx)) {
                RSAerr(RSA_F_PKEY_RSA_SIGN, ERR_R_MALLOC_FAILURE);
                return -1;
            }
            memcpy(rctx->tbuf, tbs, tbslen);
            rctx->tbuf[tbslen] = RSA_X931_hash_id(EVP_MD_type(md));
            ret = RSA_private_encrypt(tbslen + 1, rctx->tbuf,
                                      sig, rsa, RSA_X931_PADDING);
        } else if (rctx->pad_mode == RSA_PKCS1_PADDING) {
            unsigned int sltmp;
            ret = RSA_sign(EVP_MD_type(md), tbs, tbslen, sig, &sltmp, rsa);
            if (ret <= 0)
                return ret;
            ret = sltmp;
        } else if (rctx->pad_mode == RSA_PKCS1_PSS_PADDING) {
            if (!setup_tbuf(rctx, ctx))
                return -1;
            if (!RSA_padding_add_PKCS1_PSS_mgf1(rsa, rctx->tbuf, tbs,
                                                md, mgf1md, rctx->saltlen))
                return -1;
            ret = RSA_private_encrypt(RSA_size(rsa), rctx->tbuf,
                                      sig, rsa, RSA_NO_PADDING);
        } else
            return -1;
    } else
        ret = RSA_private_encrypt(tbslen, tbs, sig, ctx->pkey->pkey.rsa,
                                  rctx->pad_mode);
    if (ret < 0)
        return ret;
    *siglen = ret;
    return 1;
}

static int pkey_rsa_verifyrecover(EVP_PKEY_CTX *ctx,
                                  unsigned char *rout, size_t *routlen,
                                  const unsigned char *sig, size_t siglen)
{
    int ret;
    RSA_PKEY_CTX *rctx = ctx->data;

    if (rctx->md) {
        if (rctx->pad_mode == RSA_X931_PADDING) {
            if (!setup_tbuf(rctx, ctx))
                return -1;
            ret = RSA_public_decrypt(siglen, sig,
                                     rctx->tbuf, ctx->pkey->pkey.rsa,
                                     RSA_X931_PADDING);
            if (ret < 1)
                return 0;
            ret--;
            if (rctx->tbuf[ret] != RSA_X931_hash_id(EVP_MD_type(rctx->md))) {
                RSAerr(RSA_F_PKEY_RSA_VERIFYRECOVER,
                       RSA_R_ALGORITHM_MISMATCH);
                return 0;
            }
            if (ret != EVP_MD_size(rctx->md)) {
                RSAerr(RSA_F_PKEY_RSA_VERIFYRECOVER,
                       RSA_R_INVALID_DIGEST_LENGTH);
                return 0;
            }
            if (rout)
                memcpy(rout, rctx->tbuf, ret);
        } else if (rctx->pad_mode == RSA_PKCS1_PADDING) {
            size_t sltmp;
            ret = int_rsa_verify(EVP_MD_type(rctx->md),
                                 NULL, 0, rout, &sltmp,
                                 sig, siglen, ctx->pkey->pkey.rsa);
            if (ret <= 0)
                return 0;
            ret = sltmp;
        } else
            return -1;
    } else
        ret = RSA_public_decrypt(siglen, sig, rout, ctx->pkey->pkey.rsa,
                                 rctx->pad_mode);
    if (ret < 0)
        return ret;
    *routlen = ret;
    return 1;
}

static int pkey_rsa_verify(EVP_PKEY_CTX *ctx,
                           const unsigned char *sig, size_t siglen,
                           const unsigned char *tbs, size_t tbslen)
{
    RSA_PKEY_CTX *rctx = ctx->data;
    RSA *rsa = ctx->pkey->pkey.rsa;
    const EVP_MD *md = rctx->md;
    const EVP_MD *mgf1md = rctx->mgf1md;
    size_t rslen;

#ifdef OPENSSL_FIPS
    int rv = pkey_fips_check_rsa(rsa, &md, &mgf1md);

    if (rv < 0) {
        RSAerr(RSA_F_PKEY_RSA_VERIFY,
               RSA_R_OPERATION_NOT_ALLOWED_IN_FIPS_MODE);
        return -1;
    }
#endif
    if (md != NULL) {
#ifdef OPENSSL_FIPS
        if (rv > 0) {
            return FIPS_rsa_verify_digest(rsa, tbs, tbslen, md, rctx->pad_mode,
                                          rctx->saltlen, mgf1md, sig, siglen);

        }
#endif
        if (rctx->pad_mode == RSA_PKCS1_PADDING)
            return RSA_verify(EVP_MD_type(md), tbs, tbslen,
                              sig, siglen, rsa);
        if (tbslen != (size_t)EVP_MD_size(md)) {
            RSAerr(RSA_F_PKEY_RSA_VERIFY, RSA_R_INVALID_DIGEST_LENGTH);
            return -1;
        }
        if (rctx->pad_mode == RSA_X931_PADDING) {
            if (pkey_rsa_verifyrecover(ctx, NULL, &rslen, sig, siglen) <= 0)
                return 0;
        } else if (rctx->pad_mode == RSA_PKCS1_PSS_PADDING) {
            int ret;
            if (!setup_tbuf(rctx, ctx))
                return -1;
            ret = RSA_public_decrypt(siglen, sig, rctx->tbuf,
                                     rsa, RSA_NO_PADDING);
            if (ret <= 0)
                return 0;
            ret = RSA_verify_PKCS1_PSS_mgf1(rsa, tbs, md, mgf1md,
                                            rctx->tbuf, rctx->saltlen);
            if (ret <= 0)
                return 0;
            return 1;
        } else
            return -1;
    } else {
        if (!setup_tbuf(rctx, ctx))
            return -1;
        rslen = RSA_public_decrypt(siglen, sig, rctx->tbuf,
                                   rsa, rctx->pad_mode);
        if (rslen == 0)
            return 0;
    }

    if ((rslen != tbslen) || memcmp(tbs, rctx->tbuf, rslen))
        return 0;

    return 1;

}

static int pkey_rsa_encrypt(EVP_PKEY_CTX *ctx,
                            unsigned char *out, size_t *outlen,
                            const unsigned char *in, size_t inlen)
{
    int ret;
    RSA_PKEY_CTX *rctx = ctx->data;
    if (rctx->pad_mode == RSA_PKCS1_OAEP_PADDING) {
        int klen = RSA_size(ctx->pkey->pkey.rsa);
        if (!setup_tbuf(rctx, ctx))
            return -1;
        if (!RSA_padding_add_PKCS1_OAEP_mgf1(rctx->tbuf, klen,
                                             in, inlen,
                                             rctx->oaep_label,
                                             rctx->oaep_labellen,
                                             rctx->md, rctx->mgf1md))
            return -1;
        ret = RSA_public_encrypt(klen, rctx->tbuf, out,
                                 ctx->pkey->pkey.rsa, RSA_NO_PADDING);
    } else
        ret = RSA_public_encrypt(inlen, in, out, ctx->pkey->pkey.rsa,
                                 rctx->pad_mode);
    if (ret < 0)
        return ret;
    *outlen = ret;
    return 1;
}

static int pkey_rsa_decrypt(EVP_PKEY_CTX *ctx,
                            unsigned char *out, size_t *outlen,
                            const unsigned char *in, size_t inlen)
{
    int ret;
    RSA_PKEY_CTX *rctx = ctx->data;
    if (rctx->pad_mode == RSA_PKCS1_OAEP_PADDING) {
        if (!setup_tbuf(rctx, ctx))
            return -1;
        ret = RSA_private_decrypt(inlen, in, rctx->tbuf,
                                  ctx->pkey->pkey.rsa, RSA_NO_PADDING);
        if (ret <= 0)
            return ret;
        ret = RSA_padding_check_PKCS1_OAEP_mgf1(out, ret, rctx->tbuf,
                                                ret, ret,
                                                rctx->oaep_label,
                                                rctx->oaep_labellen,
                                                rctx->md, rctx->mgf1md);
    } else
        ret = RSA_private_decrypt(inlen, in, out, ctx->pkey->pkey.rsa,
                                  rctx->pad_mode);
    if (ret < 0)
        return ret;
    *outlen = ret;
    return 1;
}

static int check_padding_md(const EVP_MD *md, int padding)
{
    if (!md)
        return 1;

    if (padding == RSA_NO_PADDING) {
        RSAerr(RSA_F_CHECK_PADDING_MD, RSA_R_INVALID_PADDING_MODE);
        return 0;
    }

    if (padding == RSA_X931_PADDING) {
        if (RSA_X931_hash_id(EVP_MD_type(md)) == -1) {
            RSAerr(RSA_F_CHECK_PADDING_MD, RSA_R_INVALID_X931_DIGEST);
            return 0;
        }
        return 1;
    }

    return 1;
}

static int pkey_rsa_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
    RSA_PKEY_CTX *rctx = ctx->data;
    switch (type) {
    case EVP_PKEY_CTRL_RSA_PADDING:
        if ((p1 >= RSA_PKCS1_PADDING) && (p1 <= RSA_PKCS1_PSS_PADDING)) {
            if (!check_padding_md(rctx->md, p1))
                return 0;
            if (p1 == RSA_PKCS1_PSS_PADDING) {
                if (!(ctx->operation &
                      (EVP_PKEY_OP_SIGN | EVP_PKEY_OP_VERIFY)))
                    goto bad_pad;
                if (!rctx->md)
                    rctx->md = EVP_sha1();
            }
            if (p1 == RSA_PKCS1_OAEP_PADDING) {
                if (!(ctx->operation & EVP_PKEY_OP_TYPE_CRYPT))
                    goto bad_pad;
                if (!rctx->md)
                    rctx->md = EVP_sha1();
            }
            rctx->pad_mode = p1;
            return 1;
        }
 bad_pad:
        RSAerr(RSA_F_PKEY_RSA_CTRL,
               RSA_R_ILLEGAL_OR_UNSUPPORTED_PADDING_MODE);
        return -2;

    case EVP_PKEY_CTRL_GET_RSA_PADDING:
        *(int *)p2 = rctx->pad_mode;
        return 1;

    case EVP_PKEY_CTRL_RSA_PSS_SALTLEN:
    case EVP_PKEY_CTRL_GET_RSA_PSS_SALTLEN:
        if (rctx->pad_mode != RSA_PKCS1_PSS_PADDING) {
            RSAerr(RSA_F_PKEY_RSA_CTRL, RSA_R_INVALID_PSS_SALTLEN);
            return -2;
        }
        if (type == EVP_PKEY_CTRL_GET_RSA_PSS_SALTLEN)
            *(int *)p2 = rctx->saltlen;
        else {
            if (p1 < -2)
                return -2;
            rctx->saltlen = p1;
        }
        return 1;

    case EVP_PKEY_CTRL_RSA_KEYGEN_BITS:
        if (p1 < 256) {
            RSAerr(RSA_F_PKEY_RSA_CTRL, RSA_R_INVALID_KEYBITS);
            return -2;
        }
        rctx->nbits = p1;
        return 1;

    case EVP_PKEY_CTRL_RSA_KEYGEN_PUBEXP:
        if (p2 == NULL || !BN_is_odd((BIGNUM *)p2) || BN_is_one((BIGNUM *)p2)) {
            RSAerr(RSA_F_PKEY_RSA_CTRL, RSA_R_BAD_E_VALUE);
            return -2;
        }
        BN_free(rctx->pub_exp);
        rctx->pub_exp = p2;
        return 1;

    case EVP_PKEY_CTRL_RSA_OAEP_MD:
    case EVP_PKEY_CTRL_GET_RSA_OAEP_MD:
        if (rctx->pad_mode != RSA_PKCS1_OAEP_PADDING) {
            RSAerr(RSA_F_PKEY_RSA_CTRL, RSA_R_INVALID_PADDING_MODE);
            return -2;
        }
        if (type == EVP_PKEY_CTRL_GET_RSA_OAEP_MD)
            *(const EVP_MD **)p2 = rctx->md;
        else
            rctx->md = p2;
        return 1;

    case EVP_PKEY_CTRL_MD:
        if (!check_padding_md(p2, rctx->pad_mode))
            return 0;
        rctx->md = p2;
        return 1;

    case EVP_PKEY_CTRL_GET_MD:
        *(const EVP_MD **)p2 = rctx->md;
        return 1;

    case EVP_PKEY_CTRL_RSA_MGF1_MD:
    case EVP_PKEY_CTRL_GET_RSA_MGF1_MD:
        if (rctx->pad_mode != RSA_PKCS1_PSS_PADDING
            && rctx->pad_mode != RSA_PKCS1_OAEP_PADDING) {
            RSAerr(RSA_F_PKEY_RSA_CTRL, RSA_R_INVALID_MGF1_MD);
            return -2;
        }
        if (type == EVP_PKEY_CTRL_GET_RSA_MGF1_MD) {
            if (rctx->mgf1md)
                *(const EVP_MD **)p2 = rctx->mgf1md;
            else
                *(const EVP_MD **)p2 = rctx->md;
        } else
            rctx->mgf1md = p2;
        return 1;

    case EVP_PKEY_CTRL_RSA_OAEP_LABEL:
        if (rctx->pad_mode != RSA_PKCS1_OAEP_PADDING) {
            RSAerr(RSA_F_PKEY_RSA_CTRL, RSA_R_INVALID_PADDING_MODE);
            return -2;
        }
        if (rctx->oaep_label)
            OPENSSL_free(rctx->oaep_label);
        if (p2 && p1 > 0) {
            rctx->oaep_label = p2;
            rctx->oaep_labellen = p1;
        } else {
            rctx->oaep_label = NULL;
            rctx->oaep_labellen = 0;
        }
        return 1;

    case EVP_PKEY_CTRL_GET_RSA_OAEP_LABEL:
        if (rctx->pad_mode != RSA_PKCS1_OAEP_PADDING) {
            RSAerr(RSA_F_PKEY_RSA_CTRL, RSA_R_INVALID_PADDING_MODE);
            return -2;
        }
        *(unsigned char **)p2 = rctx->oaep_label;
        return rctx->oaep_labellen;

    case EVP_PKEY_CTRL_DIGESTINIT:
    case EVP_PKEY_CTRL_PKCS7_ENCRYPT:
    case EVP_PKEY_CTRL_PKCS7_DECRYPT:
    case EVP_PKEY_CTRL_PKCS7_SIGN:
        return 1;
#ifndef OPENSSL_NO_CMS
    case EVP_PKEY_CTRL_CMS_DECRYPT:
    case EVP_PKEY_CTRL_CMS_ENCRYPT:
    case EVP_PKEY_CTRL_CMS_SIGN:
        return 1;
#endif
    case EVP_PKEY_CTRL_PEER_KEY:
        RSAerr(RSA_F_PKEY_RSA_CTRL,
               RSA_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        return -2;

    default:
        return -2;

    }
}

static int pkey_rsa_ctrl_str(EVP_PKEY_CTX *ctx,
                             const char *type, const char *value)
{
    if (!value) {
        RSAerr(RSA_F_PKEY_RSA_CTRL_STR, RSA_R_VALUE_MISSING);
        return 0;
    }
    if (!strcmp(type, "rsa_padding_mode")) {
        int pm;
        if (!strcmp(value, "pkcs1"))
            pm = RSA_PKCS1_PADDING;
        else if (!strcmp(value, "sslv23"))
            pm = RSA_SSLV23_PADDING;
        else if (!strcmp(value, "none"))
            pm = RSA_NO_PADDING;
        else if (!strcmp(value, "oeap"))
            pm = RSA_PKCS1_OAEP_PADDING;
        else if (!strcmp(value, "oaep"))
            pm = RSA_PKCS1_OAEP_PADDING;
        else if (!strcmp(value, "x931"))
            pm = RSA_X931_PADDING;
        else if (!strcmp(value, "pss"))
            pm = RSA_PKCS1_PSS_PADDING;
        else {
            RSAerr(RSA_F_PKEY_RSA_CTRL_STR, RSA_R_UNKNOWN_PADDING_TYPE);
            return -2;
        }
        return EVP_PKEY_CTX_set_rsa_padding(ctx, pm);
    }

    if (!strcmp(type, "rsa_pss_saltlen")) {
        int saltlen;
        saltlen = atoi(value);
        return EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, saltlen);
    }

    if (!strcmp(type, "rsa_keygen_bits")) {
        int nbits;
        nbits = atoi(value);
        return EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, nbits);
    }

    if (!strcmp(type, "rsa_keygen_pubexp")) {
        int ret;
        BIGNUM *pubexp = NULL;
        if (!BN_asc2bn(&pubexp, value))
            return 0;
        ret = EVP_PKEY_CTX_set_rsa_keygen_pubexp(ctx, pubexp);
        if (ret <= 0)
            BN_free(pubexp);
        return ret;
    }

    if (!strcmp(type, "rsa_mgf1_md")) {
        const EVP_MD *md;
        if (!(md = EVP_get_digestbyname(value))) {
            RSAerr(RSA_F_PKEY_RSA_CTRL_STR, RSA_R_INVALID_DIGEST);
            return 0;
        }
        return EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, md);
    }

    if (!strcmp(type, "rsa_oaep_md")) {
        const EVP_MD *md;
        if (!(md = EVP_get_digestbyname(value))) {
            RSAerr(RSA_F_PKEY_RSA_CTRL_STR, RSA_R_INVALID_DIGEST);
            return 0;
        }
        return EVP_PKEY_CTX_set_rsa_oaep_md(ctx, md);
    }
    if (!strcmp(type, "rsa_oaep_label")) {
        unsigned char *lab;
        long lablen;
        int ret;
        lab = string_to_hex(value, &lablen);
        if (!lab)
            return 0;
        ret = EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, lab, lablen);
        if (ret <= 0)
            OPENSSL_free(lab);
        return ret;
    }

    return -2;
}

static int pkey_rsa_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    RSA *rsa = NULL;
    RSA_PKEY_CTX *rctx = ctx->data;
    BN_GENCB *pcb, cb;
    int ret;
    if (!rctx->pub_exp) {
        rctx->pub_exp = BN_new();
        if (!rctx->pub_exp || !BN_set_word(rctx->pub_exp, RSA_F4))
            return 0;
    }
    rsa = RSA_new();
    if (!rsa)
        return 0;
    if (ctx->pkey_gencb) {
        pcb = &cb;
        evp_pkey_set_cb_translate(pcb, ctx);
    } else
        pcb = NULL;
    ret = RSA_generate_key_ex(rsa, rctx->nbits, rctx->pub_exp, pcb);
    if (ret > 0)
        EVP_PKEY_assign_RSA(pkey, rsa);
    else
        RSA_free(rsa);
    return ret;
}

const EVP_PKEY_METHOD rsa_pkey_meth = {
    EVP_PKEY_RSA,
    EVP_PKEY_FLAG_AUTOARGLEN,
    pkey_rsa_init,
    pkey_rsa_copy,
    pkey_rsa_cleanup,

    0, 0,

    0,
    pkey_rsa_keygen,

    0,
    pkey_rsa_sign,

    0,
    pkey_rsa_verify,

    0,
    pkey_rsa_verifyrecover,

    0, 0, 0, 0,

    0,
    pkey_rsa_encrypt,

    0,
    pkey_rsa_decrypt,

    0, 0,

    pkey_rsa_ctrl,
    pkey_rsa_ctrl_str
};
/* crypto/rsa/rsa_prn.c */
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
// #include "cryptlib.h"
// #include "rsa.h"
// #include "evp.h"

#ifndef OPENSSL_NO_FP_API
int RSA_print_fp(FILE *fp, const RSA *x, int off)
{
    BIO *b;
    int ret;

    if ((b = BIO_new(BIO_s_file())) == NULL) {
        RSAerr(RSA_F_RSA_PRINT_FP, ERR_R_BUF_LIB);
        return (0);
    }
    BIO_set_fp(b, fp, BIO_NOCLOSE);
    ret = RSA_print(b, x, off);
    BIO_free(b);
    return (ret);
}
#endif

int RSA_print(BIO *bp, const RSA *x, int off)
{
    EVP_PKEY *pk;
    int ret;
    pk = EVP_PKEY_new();
    if (!pk || !EVP_PKEY_set1_RSA(pk, (RSA *)x))
        return 0;
    ret = EVP_PKEY_print_private(bp, pk, off, NULL);
    EVP_PKEY_free(pk);
    return ret;
}
/* rsa_pss.c */
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

#include <stdio.h>
// #include "cryptlib.h"
// #include "bn.h"
// #include "rsa.h"
// #include "evp.h"
// #include "rand.h"
#include "sha.h"

static const unsigned char zeroes[] = { 0, 0, 0, 0, 0, 0, 0, 0 };

#if defined(_MSC_VER) && defined(_ARM_)
# pragma optimize("g", off)
#endif

int RSA_verify_PKCS1_PSS(RSA *rsa, const unsigned char *mHash,
                         const EVP_MD *Hash, const unsigned char *EM,
                         int sLen)
{
    return RSA_verify_PKCS1_PSS_mgf1(rsa, mHash, Hash, NULL, EM, sLen);
}

int RSA_verify_PKCS1_PSS_mgf1(RSA *rsa, const unsigned char *mHash,
                              const EVP_MD *Hash, const EVP_MD *mgf1Hash,
                              const unsigned char *EM, int sLen)
{
    int i;
    int ret = 0;
    int hLen, maskedDBLen, MSBits, emLen;
    const unsigned char *H;
    unsigned char *DB = NULL;
    EVP_MD_CTX ctx;
    unsigned char H_[EVP_MAX_MD_SIZE];
    EVP_MD_CTX_init(&ctx);

    if (mgf1Hash == NULL)
        mgf1Hash = Hash;

    hLen = EVP_MD_size(Hash);
    if (hLen < 0)
        goto err;
    /*-
     * Negative sLen has special meanings:
     *      -1      sLen == hLen
     *      -2      salt length is autorecovered from signature
     *      -N      reserved
     */
    if (sLen == -1)
        sLen = hLen;
    else if (sLen == -2)
        sLen = -2;
    else if (sLen < -2) {
        RSAerr(RSA_F_RSA_VERIFY_PKCS1_PSS_MGF1, RSA_R_SLEN_CHECK_FAILED);
        goto err;
    }

    MSBits = (BN_num_bits(rsa->n) - 1) & 0x7;
    emLen = RSA_size(rsa);
    if (EM[0] & (0xFF << MSBits)) {
        RSAerr(RSA_F_RSA_VERIFY_PKCS1_PSS_MGF1, RSA_R_FIRST_OCTET_INVALID);
        goto err;
    }
    if (MSBits == 0) {
        EM++;
        emLen--;
    }
    if (emLen < hLen + 2) {
        RSAerr(RSA_F_RSA_VERIFY_PKCS1_PSS_MGF1, RSA_R_DATA_TOO_LARGE);
        goto err;
    }
    if (sLen > emLen - hLen - 2) { /* sLen can be small negative */
        RSAerr(RSA_F_RSA_VERIFY_PKCS1_PSS_MGF1, RSA_R_DATA_TOO_LARGE);
        goto err;
    }
    if (EM[emLen - 1] != 0xbc) {
        RSAerr(RSA_F_RSA_VERIFY_PKCS1_PSS_MGF1, RSA_R_LAST_OCTET_INVALID);
        goto err;
    }
    maskedDBLen = emLen - hLen - 1;
    H = EM + maskedDBLen;
    DB = OPENSSL_malloc(maskedDBLen);
    if (!DB) {
        RSAerr(RSA_F_RSA_VERIFY_PKCS1_PSS_MGF1, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    if (PKCS1_MGF1(DB, maskedDBLen, H, hLen, mgf1Hash) < 0)
        goto err;
    for (i = 0; i < maskedDBLen; i++)
        DB[i] ^= EM[i];
    if (MSBits)
        DB[0] &= 0xFF >> (8 - MSBits);
    for (i = 0; DB[i] == 0 && i < (maskedDBLen - 1); i++) ;
    if (DB[i++] != 0x1) {
        RSAerr(RSA_F_RSA_VERIFY_PKCS1_PSS_MGF1, RSA_R_SLEN_RECOVERY_FAILED);
        goto err;
    }
    if (sLen >= 0 && (maskedDBLen - i) != sLen) {
        RSAerr(RSA_F_RSA_VERIFY_PKCS1_PSS_MGF1, RSA_R_SLEN_CHECK_FAILED);
        goto err;
    }
    if (!EVP_DigestInit_ex(&ctx, Hash, NULL)
        || !EVP_DigestUpdate(&ctx, zeroes, sizeof(zeroes))
        || !EVP_DigestUpdate(&ctx, mHash, hLen))
        goto err;
    if (maskedDBLen - i) {
        if (!EVP_DigestUpdate(&ctx, DB + i, maskedDBLen - i))
            goto err;
    }
    if (!EVP_DigestFinal_ex(&ctx, H_, NULL))
        goto err;
    if (memcmp(H_, H, hLen)) {
        RSAerr(RSA_F_RSA_VERIFY_PKCS1_PSS_MGF1, RSA_R_BAD_SIGNATURE);
        ret = 0;
    } else
        ret = 1;

 err:
    if (DB)
        OPENSSL_free(DB);
    EVP_MD_CTX_cleanup(&ctx);

    return ret;

}

int RSA_padding_add_PKCS1_PSS(RSA *rsa, unsigned char *EM,
                              const unsigned char *mHash,
                              const EVP_MD *Hash, int sLen)
{
    return RSA_padding_add_PKCS1_PSS_mgf1(rsa, EM, mHash, Hash, NULL, sLen);
}

int RSA_padding_add_PKCS1_PSS_mgf1(RSA *rsa, unsigned char *EM,
                                   const unsigned char *mHash,
                                   const EVP_MD *Hash, const EVP_MD *mgf1Hash,
                                   int sLen)
{
    int i;
    int ret = 0;
    int hLen, maskedDBLen, MSBits, emLen;
    unsigned char *H, *salt = NULL, *p;
    EVP_MD_CTX ctx;

    if (mgf1Hash == NULL)
        mgf1Hash = Hash;

    hLen = EVP_MD_size(Hash);
    if (hLen < 0)
        goto err;
    /*-
     * Negative sLen has special meanings:
     *      -1      sLen == hLen
     *      -2      salt length is maximized
     *      -N      reserved
     */
    if (sLen == -1)
        sLen = hLen;
    else if (sLen == -2)
        sLen = -2;
    else if (sLen < -2) {
        RSAerr(RSA_F_RSA_PADDING_ADD_PKCS1_PSS_MGF1, RSA_R_SLEN_CHECK_FAILED);
        goto err;
    }

    MSBits = (BN_num_bits(rsa->n) - 1) & 0x7;
    emLen = RSA_size(rsa);
    if (MSBits == 0) {
        *EM++ = 0;
        emLen--;
    }
    if (emLen < hLen + 2) {
        RSAerr(RSA_F_RSA_PADDING_ADD_PKCS1_PSS_MGF1,
               RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE);
        goto err;
    }
    if (sLen == -2) {
        sLen = emLen - hLen - 2;
    } else if (sLen > emLen - hLen - 2) {
        RSAerr(RSA_F_RSA_PADDING_ADD_PKCS1_PSS_MGF1,
               RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE);
        goto err;
    }
    if (sLen > 0) {
        salt = OPENSSL_malloc(sLen);
        if (!salt) {
            RSAerr(RSA_F_RSA_PADDING_ADD_PKCS1_PSS_MGF1,
                   ERR_R_MALLOC_FAILURE);
            goto err;
        }
        if (RAND_bytes(salt, sLen) <= 0)
            goto err;
    }
    maskedDBLen = emLen - hLen - 1;
    H = EM + maskedDBLen;
    EVP_MD_CTX_init(&ctx);
    if (!EVP_DigestInit_ex(&ctx, Hash, NULL)
        || !EVP_DigestUpdate(&ctx, zeroes, sizeof(zeroes))
        || !EVP_DigestUpdate(&ctx, mHash, hLen))
        goto err;
    if (sLen && !EVP_DigestUpdate(&ctx, salt, sLen))
        goto err;
    if (!EVP_DigestFinal_ex(&ctx, H, NULL))
        goto err;
    EVP_MD_CTX_cleanup(&ctx);

    /* Generate dbMask in place then perform XOR on it */
    if (PKCS1_MGF1(EM, maskedDBLen, H, hLen, mgf1Hash))
        goto err;

    p = EM;

    /*
     * Initial PS XORs with all zeroes which is a NOP so just update pointer.
     * Note from a test above this value is guaranteed to be non-negative.
     */
    p += emLen - sLen - hLen - 2;
    *p++ ^= 0x1;
    if (sLen > 0) {
        for (i = 0; i < sLen; i++)
            *p++ ^= salt[i];
    }
    if (MSBits)
        EM[0] &= 0xFF >> (8 - MSBits);

    /* H is already in place so just set final 0xbc */

    EM[emLen - 1] = 0xbc;

    ret = 1;

 err:
    if (salt)
        OPENSSL_free(salt);

    return ret;

}

#if defined(_MSC_VER)
# pragma optimize("",on)
#endif
/* crypto/rsa/rsa_saos.c */
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
// #include "bn.h"
// #include "rsa.h"
#include "objects.h"
// #include "x509.h"

int RSA_sign_ASN1_OCTET_STRING(int type,
                               const unsigned char *m, unsigned int m_len,
                               unsigned char *sigret, unsigned int *siglen,
                               RSA *rsa)
{
    ASN1_OCTET_STRING sig;
    int i, j, ret = 1;
    unsigned char *p, *s;

    sig.type = V_ASN1_OCTET_STRING;
    sig.length = m_len;
    sig.data = (unsigned char *)m;

    i = i2d_ASN1_OCTET_STRING(&sig, NULL);
    j = RSA_size(rsa);
    if (i > (j - RSA_PKCS1_PADDING_SIZE)) {
        RSAerr(RSA_F_RSA_SIGN_ASN1_OCTET_STRING,
               RSA_R_DIGEST_TOO_BIG_FOR_RSA_KEY);
        return (0);
    }
    s = (unsigned char *)OPENSSL_malloc((unsigned int)j + 1);
    if (s == NULL) {
        RSAerr(RSA_F_RSA_SIGN_ASN1_OCTET_STRING, ERR_R_MALLOC_FAILURE);
        return (0);
    }
    p = s;
    i2d_ASN1_OCTET_STRING(&sig, &p);
    i = RSA_private_encrypt(i, s, sigret, rsa, RSA_PKCS1_PADDING);
    if (i <= 0)
        ret = 0;
    else
        *siglen = i;

    OPENSSL_cleanse(s, (unsigned int)j + 1);
    OPENSSL_free(s);
    return (ret);
}

int RSA_verify_ASN1_OCTET_STRING(int dtype,
                                 const unsigned char *m,
                                 unsigned int m_len, unsigned char *sigbuf,
                                 unsigned int siglen, RSA *rsa)
{
    int i, ret = 0;
    unsigned char *s;
    const unsigned char *p;
    ASN1_OCTET_STRING *sig = NULL;

    if (siglen != (unsigned int)RSA_size(rsa)) {
        RSAerr(RSA_F_RSA_VERIFY_ASN1_OCTET_STRING,
               RSA_R_WRONG_SIGNATURE_LENGTH);
        return (0);
    }

    s = (unsigned char *)OPENSSL_malloc((unsigned int)siglen);
    if (s == NULL) {
        RSAerr(RSA_F_RSA_VERIFY_ASN1_OCTET_STRING, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    i = RSA_public_decrypt((int)siglen, sigbuf, s, rsa, RSA_PKCS1_PADDING);

    if (i <= 0)
        goto err;

    p = s;
    sig = d2i_ASN1_OCTET_STRING(NULL, &p, (long)i);
    if (sig == NULL)
        goto err;

    if (((unsigned int)sig->length != m_len) ||
        (memcmp(m, sig->data, m_len) != 0)) {
        RSAerr(RSA_F_RSA_VERIFY_ASN1_OCTET_STRING, RSA_R_BAD_SIGNATURE);
    } else
        ret = 1;
 err:
    if (sig != NULL)
        M_ASN1_OCTET_STRING_free(sig);
    if (s != NULL) {
        OPENSSL_cleanse(s, (unsigned int)siglen);
        OPENSSL_free(s);
    }
    return (ret);
}
/* crypto/rsa/rsa_sign.c */
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
// #include "bn.h"
// #include "rsa.h"
// #include "objects.h"
// #include "x509.h"
// #include "rsa_locl.h"

/* Size of an SSL signature: MD5+SHA1 */
#define SSL_SIG_LENGTH  36

int RSA_sign(int type, const unsigned char *m, unsigned int m_len,
             unsigned char *sigret, unsigned int *siglen, RSA *rsa)
{
    X509_SIG sig;
    ASN1_TYPE parameter;
    int i, j, ret = 1;
    unsigned char *p, *tmps = NULL;
    const unsigned char *s = NULL;
    X509_ALGOR algor;
    ASN1_OCTET_STRING digest;
#ifdef OPENSSL_FIPS
    if (FIPS_mode() && !(rsa->meth->flags & RSA_FLAG_FIPS_METHOD)
        && !(rsa->flags & RSA_FLAG_NON_FIPS_ALLOW)) {
        RSAerr(RSA_F_RSA_SIGN, RSA_R_NON_FIPS_RSA_METHOD);
        return 0;
    }
#endif
    if ((rsa->meth->flags & RSA_FLAG_SIGN_VER) && rsa->meth->rsa_sign) {
        return rsa->meth->rsa_sign(type, m, m_len, sigret, siglen, rsa);
    }
    /* Special case: SSL signature, just check the length */
    if (type == NID_md5_sha1) {
        if (m_len != SSL_SIG_LENGTH) {
            RSAerr(RSA_F_RSA_SIGN, RSA_R_INVALID_MESSAGE_LENGTH);
            return (0);
        }
        i = SSL_SIG_LENGTH;
        s = m;
    } else {
        sig.algor = &algor;
        sig.algor->algorithm = OBJ_nid2obj(type);
        if (sig.algor->algorithm == NULL) {
            RSAerr(RSA_F_RSA_SIGN, RSA_R_UNKNOWN_ALGORITHM_TYPE);
            return (0);
        }
        if (sig.algor->algorithm->length == 0) {
            RSAerr(RSA_F_RSA_SIGN,
                   RSA_R_THE_ASN1_OBJECT_IDENTIFIER_IS_NOT_KNOWN_FOR_THIS_MD);
            return (0);
        }
        parameter.type = V_ASN1_NULL;
        parameter.value.ptr = NULL;
        sig.algor->parameter = &parameter;

        sig.digest = &digest;
        sig.digest->data = (unsigned char *)m; /* TMP UGLY CAST */
        sig.digest->length = m_len;

        i = i2d_X509_SIG(&sig, NULL);
    }
    j = RSA_size(rsa);
    if (i > (j - RSA_PKCS1_PADDING_SIZE)) {
        RSAerr(RSA_F_RSA_SIGN, RSA_R_DIGEST_TOO_BIG_FOR_RSA_KEY);
        return (0);
    }
    if (type != NID_md5_sha1) {
        tmps = (unsigned char *)OPENSSL_malloc((unsigned int)j + 1);
        if (tmps == NULL) {
            RSAerr(RSA_F_RSA_SIGN, ERR_R_MALLOC_FAILURE);
            return (0);
        }
        p = tmps;
        i2d_X509_SIG(&sig, &p);
        s = tmps;
    }
    i = RSA_private_encrypt(i, s, sigret, rsa, RSA_PKCS1_PADDING);
    if (i <= 0)
        ret = 0;
    else
        *siglen = i;

    if (type != NID_md5_sha1) {
        OPENSSL_cleanse(tmps, (unsigned int)j + 1);
        OPENSSL_free(tmps);
    }
    return (ret);
}

/*
 * Check DigestInfo structure does not contain extraneous data by reencoding
 * using DER and checking encoding against original.
 */
static int rsa_check_digestinfo(X509_SIG *sig, const unsigned char *dinfo,
                                int dinfolen)
{
    unsigned char *der = NULL;
    int derlen;
    int ret = 0;
    derlen = i2d_X509_SIG(sig, &der);
    if (derlen <= 0)
        return 0;
    if (derlen == dinfolen && !memcmp(dinfo, der, derlen))
        ret = 1;
    OPENSSL_cleanse(der, derlen);
    OPENSSL_free(der);
    return ret;
}

int int_rsa_verify(int dtype, const unsigned char *m,
                   unsigned int m_len,
                   unsigned char *rm, size_t *prm_len,
                   const unsigned char *sigbuf, size_t siglen, RSA *rsa)
{
    int i, ret = 0, sigtype;
    unsigned char *s;
    X509_SIG *sig = NULL;

#ifdef OPENSSL_FIPS
    if (FIPS_mode() && !(rsa->meth->flags & RSA_FLAG_FIPS_METHOD)
        && !(rsa->flags & RSA_FLAG_NON_FIPS_ALLOW)) {
        RSAerr(RSA_F_INT_RSA_VERIFY, RSA_R_NON_FIPS_RSA_METHOD);
        return 0;
    }
#endif

    if (siglen != (unsigned int)RSA_size(rsa)) {
        RSAerr(RSA_F_INT_RSA_VERIFY, RSA_R_WRONG_SIGNATURE_LENGTH);
        return (0);
    }

    if ((dtype == NID_md5_sha1) && rm) {
        i = RSA_public_decrypt((int)siglen,
                               sigbuf, rm, rsa, RSA_PKCS1_PADDING);
        if (i <= 0)
            return 0;
        *prm_len = i;
        return 1;
    }

    s = (unsigned char *)OPENSSL_malloc((unsigned int)siglen);
    if (s == NULL) {
        RSAerr(RSA_F_INT_RSA_VERIFY, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    if ((dtype == NID_md5_sha1) && (m_len != SSL_SIG_LENGTH)) {
        RSAerr(RSA_F_INT_RSA_VERIFY, RSA_R_INVALID_MESSAGE_LENGTH);
        goto err;
    }
    i = RSA_public_decrypt((int)siglen, sigbuf, s, rsa, RSA_PKCS1_PADDING);

    if (i <= 0)
        goto err;
    /*
     * Oddball MDC2 case: signature can be OCTET STRING. check for correct
     * tag and length octets.
     */
    if (dtype == NID_mdc2 && i == 18 && s[0] == 0x04 && s[1] == 0x10) {
        if (rm) {
            memcpy(rm, s + 2, 16);
            *prm_len = 16;
            ret = 1;
        } else if (memcmp(m, s + 2, 16)) {
            RSAerr(RSA_F_INT_RSA_VERIFY, RSA_R_BAD_SIGNATURE);
        } else {
            ret = 1;
        }
    } else if (dtype == NID_md5_sha1) {
        /* Special case: SSL signature */
        if ((i != SSL_SIG_LENGTH) || memcmp(s, m, SSL_SIG_LENGTH))
            RSAerr(RSA_F_INT_RSA_VERIFY, RSA_R_BAD_SIGNATURE);
        else
            ret = 1;
    } else {
        const unsigned char *p = s;
        sig = d2i_X509_SIG(NULL, &p, (long)i);

        if (sig == NULL)
            goto err;

        /* Excess data can be used to create forgeries */
        if (p != s + i || !rsa_check_digestinfo(sig, s, i)) {
            RSAerr(RSA_F_INT_RSA_VERIFY, RSA_R_BAD_SIGNATURE);
            goto err;
        }

        /*
         * Parameters to the signature algorithm can also be used to create
         * forgeries
         */
        if (sig->algor->parameter
            && ASN1_TYPE_get(sig->algor->parameter) != V_ASN1_NULL) {
            RSAerr(RSA_F_INT_RSA_VERIFY, RSA_R_BAD_SIGNATURE);
            goto err;
        }

        sigtype = OBJ_obj2nid(sig->algor->algorithm);

#ifdef RSA_DEBUG
        /* put a backward compatibility flag in EAY */
        fprintf(stderr, "in(%s) expect(%s)\n", OBJ_nid2ln(sigtype),
                OBJ_nid2ln(dtype));
#endif
        if (sigtype != dtype) {
            RSAerr(RSA_F_INT_RSA_VERIFY, RSA_R_ALGORITHM_MISMATCH);
            goto err;
        }
        if (rm) {
            const EVP_MD *md;
            md = EVP_get_digestbynid(dtype);
            if (md && (EVP_MD_size(md) != sig->digest->length))
                RSAerr(RSA_F_INT_RSA_VERIFY, RSA_R_INVALID_DIGEST_LENGTH);
            else {
                memcpy(rm, sig->digest->data, sig->digest->length);
                *prm_len = sig->digest->length;
                ret = 1;
            }
        } else if (((unsigned int)sig->digest->length != m_len) ||
                   (memcmp(m, sig->digest->data, m_len) != 0)) {
            RSAerr(RSA_F_INT_RSA_VERIFY, RSA_R_BAD_SIGNATURE);
        } else
            ret = 1;
    }
 err:
    if (sig != NULL)
        X509_SIG_free(sig);
    if (s != NULL) {
        OPENSSL_cleanse(s, (unsigned int)siglen);
        OPENSSL_free(s);
    }
    return (ret);
}

int RSA_verify(int dtype, const unsigned char *m, unsigned int m_len,
               const unsigned char *sigbuf, unsigned int siglen, RSA *rsa)
{

    if ((rsa->meth->flags & RSA_FLAG_SIGN_VER) && rsa->meth->rsa_verify) {
        return rsa->meth->rsa_verify(dtype, m, m_len, sigbuf, siglen, rsa);
    }

    return int_rsa_verify(dtype, m, m_len, NULL, NULL, sigbuf, siglen, rsa);
}
/* crypto/rsa/rsa_ssl.c */
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
// #include "bn.h"
// #include "rsa.h"
// #include "rand.h"

int RSA_padding_add_SSLv23(unsigned char *to, int tlen,
                           const unsigned char *from, int flen)
{
    int i, j;
    unsigned char *p;

    if (flen > (tlen - 11)) {
        RSAerr(RSA_F_RSA_PADDING_ADD_SSLV23,
               RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE);
        return (0);
    }

    p = (unsigned char *)to;

    *(p++) = 0;
    *(p++) = 2;                 /* Public Key BT (Block Type) */

    /* pad out with non-zero random data */
    j = tlen - 3 - 8 - flen;

    if (RAND_bytes(p, j) <= 0)
        return (0);
    for (i = 0; i < j; i++) {
        if (*p == '\0')
            do {
                if (RAND_bytes(p, 1) <= 0)
                    return (0);
            } while (*p == '\0');
        p++;
    }

    memset(p, 3, 8);
    p += 8;
    *(p++) = '\0';

    memcpy(p, from, (unsigned int)flen);
    return (1);
}

int RSA_padding_check_SSLv23(unsigned char *to, int tlen,
                             const unsigned char *from, int flen, int num)
{
    int i, j, k;
    const unsigned char *p;

    p = from;
    if (flen < 10) {
        RSAerr(RSA_F_RSA_PADDING_CHECK_SSLV23, RSA_R_DATA_TOO_SMALL);
        return (-1);
    }
    /* Accept even zero-padded input */
    if (flen == num) {
        if (*(p++) != 0) {
            RSAerr(RSA_F_RSA_PADDING_CHECK_SSLV23, RSA_R_BLOCK_TYPE_IS_NOT_02);
            return -1;
        }
        flen--;
    }
    if ((num != (flen + 1)) || (*(p++) != 02)) {
        RSAerr(RSA_F_RSA_PADDING_CHECK_SSLV23, RSA_R_BLOCK_TYPE_IS_NOT_02);
        return (-1);
    }

    /* scan over padding data */
    j = flen - 1;               /* one for type */
    for (i = 0; i < j; i++)
        if (*(p++) == 0)
            break;

    if ((i == j) || (i < 8)) {
        RSAerr(RSA_F_RSA_PADDING_CHECK_SSLV23,
               RSA_R_NULL_BEFORE_BLOCK_MISSING);
        return (-1);
    }
    for (k = -9; k < -1; k++) {
        if (p[k] != 0x03)
            break;
    }
    if (k == -1) {
        RSAerr(RSA_F_RSA_PADDING_CHECK_SSLV23, RSA_R_SSLV3_ROLLBACK_ATTACK);
        return (-1);
    }

    i++;                        /* Skip over the '\0' */
    j -= i;
    if (j > tlen) {
        RSAerr(RSA_F_RSA_PADDING_CHECK_SSLV23, RSA_R_DATA_TOO_LARGE);
        return (-1);
    }
    memcpy(to, p, (unsigned int)j);

    return (j);
}
/* rsa_x931.c */
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

#include <stdio.h>
// #include "cryptlib.h"
// #include "bn.h"
// #include "rsa.h"
// #include "rand.h"
// #include "objects.h"

int RSA_padding_add_X931(unsigned char *to, int tlen,
                         const unsigned char *from, int flen)
{
    int j;
    unsigned char *p;

    /*
     * Absolute minimum amount of padding is 1 header nibble, 1 padding
     * nibble and 2 trailer bytes: but 1 hash if is already in 'from'.
     */

    j = tlen - flen - 2;

    if (j < 0) {
        RSAerr(RSA_F_RSA_PADDING_ADD_X931, RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE);
        return -1;
    }

    p = (unsigned char *)to;

    /* If no padding start and end nibbles are in one byte */
    if (j == 0)
        *p++ = 0x6A;
    else {
        *p++ = 0x6B;
        if (j > 1) {
            memset(p, 0xBB, j - 1);
            p += j - 1;
        }
        *p++ = 0xBA;
    }
    memcpy(p, from, (unsigned int)flen);
    p += flen;
    *p = 0xCC;
    return (1);
}

int RSA_padding_check_X931(unsigned char *to, int tlen,
                           const unsigned char *from, int flen, int num)
{
    int i = 0, j;
    const unsigned char *p;

    p = from;
    if ((num != flen) || ((*p != 0x6A) && (*p != 0x6B))) {
        RSAerr(RSA_F_RSA_PADDING_CHECK_X931, RSA_R_INVALID_HEADER);
        return -1;
    }

    if (*p++ == 0x6B) {
        j = flen - 3;
        for (i = 0; i < j; i++) {
            unsigned char c = *p++;
            if (c == 0xBA)
                break;
            if (c != 0xBB) {
                RSAerr(RSA_F_RSA_PADDING_CHECK_X931, RSA_R_INVALID_PADDING);
                return -1;
            }
        }

        j -= i;

        if (i == 0) {
            RSAerr(RSA_F_RSA_PADDING_CHECK_X931, RSA_R_INVALID_PADDING);
            return -1;
        }

    } else
        j = flen - 2;

    if (p[j] != 0xCC) {
        RSAerr(RSA_F_RSA_PADDING_CHECK_X931, RSA_R_INVALID_TRAILER);
        return -1;
    }

    memcpy(to, p, (unsigned int)j);

    return (j);
}

/* Translate between X931 hash ids and NIDs */

int RSA_X931_hash_id(int nid)
{
    switch (nid) {
    case NID_sha1:
        return 0x33;

    case NID_sha256:
        return 0x34;

    case NID_sha384:
        return 0x36;

    case NID_sha512:
        return 0x35;

    }
    return -1;
}
