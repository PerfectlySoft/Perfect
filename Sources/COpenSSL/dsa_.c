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
#include "x509.h"
#include "asn1.h"
#include "dsa.h"
#include "bn.h"
#ifndef OPENSSL_NO_CMS
# include "cms.h"
#endif
#include "asn1_locl.h"

static int dsa_pub_decode(EVP_PKEY *pkey, X509_PUBKEY *pubkey)
{
    const unsigned char *p, *pm;
    int pklen, pmlen;
    int ptype;
    void *pval;
    ASN1_STRING *pstr;
    X509_ALGOR *palg;
    ASN1_INTEGER *public_key = NULL;

    DSA *dsa = NULL;

    if (!X509_PUBKEY_get0_param(NULL, &p, &pklen, &palg, pubkey))
        return 0;
    X509_ALGOR_get0(NULL, &ptype, &pval, palg);

    if (ptype == V_ASN1_SEQUENCE) {
        pstr = pval;
        pm = pstr->data;
        pmlen = pstr->length;

        if (!(dsa = d2i_DSAparams(NULL, &pm, pmlen))) {
            DSAerr(DSA_F_DSA_PUB_DECODE, DSA_R_DECODE_ERROR);
            goto err;
        }

    } else if ((ptype == V_ASN1_NULL) || (ptype == V_ASN1_UNDEF)) {
        if (!(dsa = DSA_new())) {
            DSAerr(DSA_F_DSA_PUB_DECODE, ERR_R_MALLOC_FAILURE);
            goto err;
        }
    } else {
        DSAerr(DSA_F_DSA_PUB_DECODE, DSA_R_PARAMETER_ENCODING_ERROR);
        goto err;
    }

    if (!(public_key = d2i_ASN1_INTEGER(NULL, &p, pklen))) {
        DSAerr(DSA_F_DSA_PUB_DECODE, DSA_R_DECODE_ERROR);
        goto err;
    }

    if (!(dsa->pub_key = ASN1_INTEGER_to_BN(public_key, NULL))) {
        DSAerr(DSA_F_DSA_PUB_DECODE, DSA_R_BN_DECODE_ERROR);
        goto err;
    }

    ASN1_INTEGER_free(public_key);
    EVP_PKEY_assign_DSA(pkey, dsa);
    return 1;

 err:
    if (public_key)
        ASN1_INTEGER_free(public_key);
    if (dsa)
        DSA_free(dsa);
    return 0;

}

static int dsa_pub_encode(X509_PUBKEY *pk, const EVP_PKEY *pkey)
{
    DSA *dsa;
    int ptype;
    unsigned char *penc = NULL;
    int penclen;
    ASN1_STRING *str = NULL;
    ASN1_OBJECT *aobj;

    dsa = pkey->pkey.dsa;
    if (pkey->save_parameters && dsa->p && dsa->q && dsa->g) {
        str = ASN1_STRING_new();
        if (!str) {
            DSAerr(DSA_F_DSA_PUB_ENCODE, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        str->length = i2d_DSAparams(dsa, &str->data);
        if (str->length <= 0) {
            DSAerr(DSA_F_DSA_PUB_ENCODE, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        ptype = V_ASN1_SEQUENCE;
    } else
        ptype = V_ASN1_UNDEF;

    dsa->write_params = 0;

    penclen = i2d_DSAPublicKey(dsa, &penc);

    if (penclen <= 0) {
        DSAerr(DSA_F_DSA_PUB_ENCODE, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    aobj = OBJ_nid2obj(EVP_PKEY_DSA);
    if (aobj == NULL)
        goto err;

    if (X509_PUBKEY_set0_param(pk, aobj, ptype, str, penc, penclen))
        return 1;

 err:
    if (penc)
        OPENSSL_free(penc);
    if (str)
        ASN1_STRING_free(str);

    return 0;
}

/*
 * In PKCS#8 DSA: you just get a private key integer and parameters in the
 * AlgorithmIdentifier the pubkey must be recalculated.
 */

static int dsa_priv_decode(EVP_PKEY *pkey, PKCS8_PRIV_KEY_INFO *p8)
{
    const unsigned char *p, *pm;
    int pklen, pmlen;
    int ptype;
    void *pval;
    ASN1_STRING *pstr;
    X509_ALGOR *palg;
    ASN1_INTEGER *privkey = NULL;
    BN_CTX *ctx = NULL;

    STACK_OF(ASN1_TYPE) *ndsa = NULL;
    DSA *dsa = NULL;

    int ret = 0;

    if (!PKCS8_pkey_get0(NULL, &p, &pklen, &palg, p8))
        return 0;
    X509_ALGOR_get0(NULL, &ptype, &pval, palg);

    /* Check for broken DSA PKCS#8, UGH! */
    if (*p == (V_ASN1_SEQUENCE | V_ASN1_CONSTRUCTED)) {
        ASN1_TYPE *t1, *t2;
        if (!(ndsa = d2i_ASN1_SEQUENCE_ANY(NULL, &p, pklen)))
            goto decerr;
        if (sk_ASN1_TYPE_num(ndsa) != 2)
            goto decerr;
        /*-
         * Handle Two broken types:
         * SEQUENCE {parameters, priv_key}
         * SEQUENCE {pub_key, priv_key}
         */

        t1 = sk_ASN1_TYPE_value(ndsa, 0);
        t2 = sk_ASN1_TYPE_value(ndsa, 1);
        if (t1->type == V_ASN1_SEQUENCE) {
            p8->broken = PKCS8_EMBEDDED_PARAM;
            pval = t1->value.ptr;
        } else if (ptype == V_ASN1_SEQUENCE)
            p8->broken = PKCS8_NS_DB;
        else
            goto decerr;

        if (t2->type != V_ASN1_INTEGER)
            goto decerr;

        privkey = t2->value.integer;
    } else {
        const unsigned char *q = p;
        if (!(privkey = d2i_ASN1_INTEGER(NULL, &p, pklen)))
            goto decerr;
        if (privkey->type == V_ASN1_NEG_INTEGER) {
            p8->broken = PKCS8_NEG_PRIVKEY;
            ASN1_STRING_clear_free(privkey);
            if (!(privkey = d2i_ASN1_UINTEGER(NULL, &q, pklen)))
                goto decerr;
        }
        if (ptype != V_ASN1_SEQUENCE)
            goto decerr;
    }

    pstr = pval;
    pm = pstr->data;
    pmlen = pstr->length;
    if (!(dsa = d2i_DSAparams(NULL, &pm, pmlen)))
        goto decerr;
    /* We have parameters now set private key */
    if (!(dsa->priv_key = ASN1_INTEGER_to_BN(privkey, NULL))) {
        DSAerr(DSA_F_DSA_PRIV_DECODE, DSA_R_BN_ERROR);
        goto dsaerr;
    }
    /* Calculate public key */
    if (!(dsa->pub_key = BN_new())) {
        DSAerr(DSA_F_DSA_PRIV_DECODE, ERR_R_MALLOC_FAILURE);
        goto dsaerr;
    }
    if (!(ctx = BN_CTX_new())) {
        DSAerr(DSA_F_DSA_PRIV_DECODE, ERR_R_MALLOC_FAILURE);
        goto dsaerr;
    }

    BN_set_flags(dsa->priv_key, BN_FLG_CONSTTIME);
    if (!BN_mod_exp(dsa->pub_key, dsa->g, dsa->priv_key, dsa->p, ctx)) {
        DSAerr(DSA_F_DSA_PRIV_DECODE, DSA_R_BN_ERROR);
        goto dsaerr;
    }

    EVP_PKEY_assign_DSA(pkey, dsa);

    ret = 1;
    goto done;

 decerr:
    DSAerr(DSA_F_DSA_PRIV_DECODE, DSA_R_DECODE_ERROR);
 dsaerr:
    DSA_free(dsa);
 done:
    BN_CTX_free(ctx);
    if (ndsa)
        sk_ASN1_TYPE_pop_free(ndsa, ASN1_TYPE_free);
    else
        ASN1_STRING_clear_free(privkey);
    return ret;
}

static int dsa_priv_encode(PKCS8_PRIV_KEY_INFO *p8, const EVP_PKEY *pkey)
{
    ASN1_STRING *params = NULL;
    ASN1_INTEGER *prkey = NULL;
    unsigned char *dp = NULL;
    int dplen;

    if (!pkey->pkey.dsa || !pkey->pkey.dsa->priv_key) {
        DSAerr(DSA_F_DSA_PRIV_ENCODE, DSA_R_MISSING_PARAMETERS);
        goto err;
    }

    params = ASN1_STRING_new();

    if (!params) {
        DSAerr(DSA_F_DSA_PRIV_ENCODE, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    params->length = i2d_DSAparams(pkey->pkey.dsa, &params->data);
    if (params->length <= 0) {
        DSAerr(DSA_F_DSA_PRIV_ENCODE, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    params->type = V_ASN1_SEQUENCE;

    /* Get private key into integer */
    prkey = BN_to_ASN1_INTEGER(pkey->pkey.dsa->priv_key, NULL);

    if (!prkey) {
        DSAerr(DSA_F_DSA_PRIV_ENCODE, DSA_R_BN_ERROR);
        goto err;
    }

    dplen = i2d_ASN1_INTEGER(prkey, &dp);

    ASN1_STRING_clear_free(prkey);
    prkey = NULL;

    if (!PKCS8_pkey_set0(p8, OBJ_nid2obj(NID_dsa), 0,
                         V_ASN1_SEQUENCE, params, dp, dplen))
        goto err;

    return 1;

 err:
    if (dp != NULL)
        OPENSSL_free(dp);
    if (params != NULL)
        ASN1_STRING_free(params);
    if (prkey != NULL)
        ASN1_STRING_clear_free(prkey);
    return 0;
}

static int int_dsa_size(const EVP_PKEY *pkey)
{
    return (DSA_size(pkey->pkey.dsa));
}

static int dsa_bits(const EVP_PKEY *pkey)
{
    return BN_num_bits(pkey->pkey.dsa->p);
}

static int dsa_missing_parameters(const EVP_PKEY *pkey)
{
    DSA *dsa;
    dsa = pkey->pkey.dsa;
    if (dsa == NULL || dsa->p == NULL || dsa->q == NULL || dsa->g == NULL)
        return 1;
    return 0;
}

static int dsa_copy_parameters(EVP_PKEY *to, const EVP_PKEY *from)
{
    BIGNUM *a;

    if ((a = BN_dup(from->pkey.dsa->p)) == NULL)
        return 0;
    if (to->pkey.dsa->p != NULL)
        BN_free(to->pkey.dsa->p);
    to->pkey.dsa->p = a;

    if ((a = BN_dup(from->pkey.dsa->q)) == NULL)
        return 0;
    if (to->pkey.dsa->q != NULL)
        BN_free(to->pkey.dsa->q);
    to->pkey.dsa->q = a;

    if ((a = BN_dup(from->pkey.dsa->g)) == NULL)
        return 0;
    if (to->pkey.dsa->g != NULL)
        BN_free(to->pkey.dsa->g);
    to->pkey.dsa->g = a;
    return 1;
}

static int dsa_cmp_parameters(const EVP_PKEY *a, const EVP_PKEY *b)
{
    if (BN_cmp(a->pkey.dsa->p, b->pkey.dsa->p) ||
        BN_cmp(a->pkey.dsa->q, b->pkey.dsa->q) ||
        BN_cmp(a->pkey.dsa->g, b->pkey.dsa->g))
        return 0;
    else
        return 1;
}

static int dsa_pub_cmp(const EVP_PKEY *a, const EVP_PKEY *b)
{
    if (BN_cmp(b->pkey.dsa->pub_key, a->pkey.dsa->pub_key) != 0)
        return 0;
    else
        return 1;
}

static void int_dsa_free(EVP_PKEY *pkey)
{
    DSA_free(pkey->pkey.dsa);
}

static void update_buflen(const BIGNUM *b, size_t *pbuflen)
{
    size_t i;
    if (!b)
        return;
    if (*pbuflen < (i = (size_t)BN_num_bytes(b)))
        *pbuflen = i;
}

static int do_dsa_print(BIO *bp, const DSA *x, int off, int ptype)
{
    unsigned char *m = NULL;
    int ret = 0;
    size_t buf_len = 0;
    const char *ktype = NULL;

    const BIGNUM *priv_key, *pub_key;

    if (ptype == 2)
        priv_key = x->priv_key;
    else
        priv_key = NULL;

    if (ptype > 0)
        pub_key = x->pub_key;
    else
        pub_key = NULL;

    if (ptype == 2)
        ktype = "Private-Key";
    else if (ptype == 1)
        ktype = "Public-Key";
    else
        ktype = "DSA-Parameters";

    update_buflen(x->p, &buf_len);
    update_buflen(x->q, &buf_len);
    update_buflen(x->g, &buf_len);
    update_buflen(priv_key, &buf_len);
    update_buflen(pub_key, &buf_len);

    m = (unsigned char *)OPENSSL_malloc(buf_len + 10);
    if (m == NULL) {
        DSAerr(DSA_F_DO_DSA_PRINT, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (priv_key) {
        if (!BIO_indent(bp, off, 128))
            goto err;
        if (BIO_printf(bp, "%s: (%d bit)\n", ktype, BN_num_bits(x->p))
            <= 0)
            goto err;
    }

    if (!ASN1_bn_print(bp, "priv:", priv_key, m, off))
        goto err;
    if (!ASN1_bn_print(bp, "pub: ", pub_key, m, off))
        goto err;
    if (!ASN1_bn_print(bp, "P:   ", x->p, m, off))
        goto err;
    if (!ASN1_bn_print(bp, "Q:   ", x->q, m, off))
        goto err;
    if (!ASN1_bn_print(bp, "G:   ", x->g, m, off))
        goto err;
    ret = 1;
 err:
    if (m != NULL)
        OPENSSL_free(m);
    return (ret);
}

static int dsa_param_decode(EVP_PKEY *pkey,
                            const unsigned char **pder, int derlen)
{
    DSA *dsa;
    if (!(dsa = d2i_DSAparams(NULL, pder, derlen))) {
        DSAerr(DSA_F_DSA_PARAM_DECODE, ERR_R_DSA_LIB);
        return 0;
    }
    EVP_PKEY_assign_DSA(pkey, dsa);
    return 1;
}

static int dsa_param_encode(const EVP_PKEY *pkey, unsigned char **pder)
{
    return i2d_DSAparams(pkey->pkey.dsa, pder);
}

static int dsa_param_print(BIO *bp, const EVP_PKEY *pkey, int indent,
                           ASN1_PCTX *ctx)
{
    return do_dsa_print(bp, pkey->pkey.dsa, indent, 0);
}

static int dsa_pub_print(BIO *bp, const EVP_PKEY *pkey, int indent,
                         ASN1_PCTX *ctx)
{
    return do_dsa_print(bp, pkey->pkey.dsa, indent, 1);
}

static int dsa_priv_print(BIO *bp, const EVP_PKEY *pkey, int indent,
                          ASN1_PCTX *ctx)
{
    return do_dsa_print(bp, pkey->pkey.dsa, indent, 2);
}

static int old_dsa_priv_decode(EVP_PKEY *pkey,
                               const unsigned char **pder, int derlen)
{
    DSA *dsa;
    if (!(dsa = d2i_DSAPrivateKey(NULL, pder, derlen))) {
        DSAerr(DSA_F_OLD_DSA_PRIV_DECODE, ERR_R_DSA_LIB);
        return 0;
    }
    EVP_PKEY_assign_DSA(pkey, dsa);
    return 1;
}

static int old_dsa_priv_encode(const EVP_PKEY *pkey, unsigned char **pder)
{
    return i2d_DSAPrivateKey(pkey->pkey.dsa, pder);
}

static int dsa_sig_print(BIO *bp, const X509_ALGOR *sigalg,
                         const ASN1_STRING *sig, int indent, ASN1_PCTX *pctx)
{
    DSA_SIG *dsa_sig;
    const unsigned char *p;
    if (!sig) {
        if (BIO_puts(bp, "\n") <= 0)
            return 0;
        else
            return 1;
    }
    p = sig->data;
    dsa_sig = d2i_DSA_SIG(NULL, &p, sig->length);
    if (dsa_sig) {
        int rv = 0;
        size_t buf_len = 0;
        unsigned char *m = NULL;
        update_buflen(dsa_sig->r, &buf_len);
        update_buflen(dsa_sig->s, &buf_len);
        m = OPENSSL_malloc(buf_len + 10);
        if (m == NULL) {
            DSAerr(DSA_F_DSA_SIG_PRINT, ERR_R_MALLOC_FAILURE);
            goto err;
        }

        if (BIO_write(bp, "\n", 1) != 1)
            goto err;

        if (!ASN1_bn_print(bp, "r:   ", dsa_sig->r, m, indent))
            goto err;
        if (!ASN1_bn_print(bp, "s:   ", dsa_sig->s, m, indent))
            goto err;
        rv = 1;
 err:
        if (m)
            OPENSSL_free(m);
        DSA_SIG_free(dsa_sig);
        return rv;
    }
    return X509_signature_dump(bp, sig, indent);
}

static int dsa_pkey_ctrl(EVP_PKEY *pkey, int op, long arg1, void *arg2)
{
    switch (op) {
    case ASN1_PKEY_CTRL_PKCS7_SIGN:
        if (arg1 == 0) {
            int snid, hnid;
            X509_ALGOR *alg1, *alg2;
            PKCS7_SIGNER_INFO_get0_algs(arg2, NULL, &alg1, &alg2);
            if (alg1 == NULL || alg1->algorithm == NULL)
                return -1;
            hnid = OBJ_obj2nid(alg1->algorithm);
            if (hnid == NID_undef)
                return -1;
            if (!OBJ_find_sigid_by_algs(&snid, hnid, EVP_PKEY_id(pkey)))
                return -1;
            X509_ALGOR_set0(alg2, OBJ_nid2obj(snid), V_ASN1_UNDEF, 0);
        }
        return 1;
#ifndef OPENSSL_NO_CMS
    case ASN1_PKEY_CTRL_CMS_SIGN:
        if (arg1 == 0) {
            int snid, hnid;
            X509_ALGOR *alg1, *alg2;
            CMS_SignerInfo_get0_algs(arg2, NULL, NULL, &alg1, &alg2);
            if (alg1 == NULL || alg1->algorithm == NULL)
                return -1;
            hnid = OBJ_obj2nid(alg1->algorithm);
            if (hnid == NID_undef)
                return -1;
            if (!OBJ_find_sigid_by_algs(&snid, hnid, EVP_PKEY_id(pkey)))
                return -1;
            X509_ALGOR_set0(alg2, OBJ_nid2obj(snid), V_ASN1_UNDEF, 0);
        }
        return 1;

    case ASN1_PKEY_CTRL_CMS_RI_TYPE:
        *(int *)arg2 = CMS_RECIPINFO_NONE;
        return 1;
#endif

    case ASN1_PKEY_CTRL_DEFAULT_MD_NID:
        *(int *)arg2 = NID_sha256;
        return 2;

    default:
        return -2;

    }

}

/* NB these are sorted in pkey_id order, lowest first */

const EVP_PKEY_ASN1_METHOD dsa_asn1_meths[] = {

    {
     EVP_PKEY_DSA2,
     EVP_PKEY_DSA,
     ASN1_PKEY_ALIAS},

    {
     EVP_PKEY_DSA1,
     EVP_PKEY_DSA,
     ASN1_PKEY_ALIAS},

    {
     EVP_PKEY_DSA4,
     EVP_PKEY_DSA,
     ASN1_PKEY_ALIAS},

    {
     EVP_PKEY_DSA3,
     EVP_PKEY_DSA,
     ASN1_PKEY_ALIAS},

    {
     EVP_PKEY_DSA,
     EVP_PKEY_DSA,
     0,

     "DSA",
     "OpenSSL DSA method",

     dsa_pub_decode,
     dsa_pub_encode,
     dsa_pub_cmp,
     dsa_pub_print,

     dsa_priv_decode,
     dsa_priv_encode,
     dsa_priv_print,

     int_dsa_size,
     dsa_bits,

     dsa_param_decode,
     dsa_param_encode,
     dsa_missing_parameters,
     dsa_copy_parameters,
     dsa_cmp_parameters,
     dsa_param_print,
     dsa_sig_print,

     int_dsa_free,
     dsa_pkey_ctrl,
     old_dsa_priv_decode,
     old_dsa_priv_encode}
};
/* dsa_asn1.c */
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
// #include "dsa.h"
// #include "asn1.h"
#include "asn1t.h"
#include "rand.h"

/* Override the default new methods */
static int sig_cb(int operation, ASN1_VALUE **pval, const ASN1_ITEM *it,
                  void *exarg)
{
    if (operation == ASN1_OP_NEW_PRE) {
        DSA_SIG *sig;
        sig = OPENSSL_malloc(sizeof(DSA_SIG));
        if (!sig) {
            DSAerr(DSA_F_SIG_CB, ERR_R_MALLOC_FAILURE);
            return 0;
        }
        sig->r = NULL;
        sig->s = NULL;
        *pval = (ASN1_VALUE *)sig;
        return 2;
    }
    return 1;
}

ASN1_SEQUENCE_cb(DSA_SIG, sig_cb) = {
        ASN1_SIMPLE(DSA_SIG, r, CBIGNUM),
        ASN1_SIMPLE(DSA_SIG, s, CBIGNUM)
} ASN1_SEQUENCE_END_cb(DSA_SIG, DSA_SIG)

IMPLEMENT_ASN1_ENCODE_FUNCTIONS_const_fname(DSA_SIG, DSA_SIG, DSA_SIG)

/* Override the default free and new methods */
static int dsa_cb(int operation, ASN1_VALUE **pval, const ASN1_ITEM *it,
                  void *exarg)
{
    if (operation == ASN1_OP_NEW_PRE) {
        *pval = (ASN1_VALUE *)DSA_new();
        if (*pval)
            return 2;
        return 0;
    } else if (operation == ASN1_OP_FREE_PRE) {
        DSA_free((DSA *)*pval);
        *pval = NULL;
        return 2;
    }
    return 1;
}

ASN1_SEQUENCE_cb(DSAPrivateKey, dsa_cb) = {
        ASN1_SIMPLE(DSA, version, LONG),
        ASN1_SIMPLE(DSA, p, BIGNUM),
        ASN1_SIMPLE(DSA, q, BIGNUM),
        ASN1_SIMPLE(DSA, g, BIGNUM),
        ASN1_SIMPLE(DSA, pub_key, BIGNUM),
        ASN1_SIMPLE(DSA, priv_key, BIGNUM)
} ASN1_SEQUENCE_END_cb(DSA, DSAPrivateKey)

IMPLEMENT_ASN1_ENCODE_FUNCTIONS_const_fname(DSA, DSAPrivateKey, DSAPrivateKey)

ASN1_SEQUENCE_cb(DSAparams, dsa_cb) = {
        ASN1_SIMPLE(DSA, p, BIGNUM),
        ASN1_SIMPLE(DSA, q, BIGNUM),
        ASN1_SIMPLE(DSA, g, BIGNUM),
} ASN1_SEQUENCE_END_cb(DSA, DSAparams)

IMPLEMENT_ASN1_ENCODE_FUNCTIONS_const_fname(DSA, DSAparams, DSAparams)

/*
 * DSA public key is a bit trickier... its effectively a CHOICE type decided
 * by a field called write_params which can either write out just the public
 * key as an INTEGER or the parameters and public key in a SEQUENCE
 */

ASN1_SEQUENCE(dsa_pub_internal) = {
        ASN1_SIMPLE(DSA, pub_key, BIGNUM),
        ASN1_SIMPLE(DSA, p, BIGNUM),
        ASN1_SIMPLE(DSA, q, BIGNUM),
        ASN1_SIMPLE(DSA, g, BIGNUM)
} ASN1_SEQUENCE_END_name(DSA, dsa_pub_internal)

ASN1_CHOICE_cb(DSAPublicKey, dsa_cb) = {
        ASN1_SIMPLE(DSA, pub_key, BIGNUM),
        ASN1_EX_COMBINE(0, 0, dsa_pub_internal)
} ASN1_CHOICE_END_cb(DSA, DSAPublicKey, write_params)

IMPLEMENT_ASN1_ENCODE_FUNCTIONS_const_fname(DSA, DSAPublicKey, DSAPublicKey)

DSA *DSAparams_dup(DSA *dsa)
{
    return ASN1_item_dup(ASN1_ITEM_rptr(DSAparams), dsa);
}

int DSA_sign(int type, const unsigned char *dgst, int dlen,
             unsigned char *sig, unsigned int *siglen, DSA *dsa)
{
    DSA_SIG *s;
    RAND_seed(dgst, dlen);
    s = DSA_do_sign(dgst, dlen, dsa);
    if (s == NULL) {
        *siglen = 0;
        return (0);
    }
    *siglen = i2d_DSA_SIG(s, &sig);
    DSA_SIG_free(s);
    return (1);
}

/* data has already been hashed (probably with SHA or SHA-1). */
/*-
 * returns
 *      1: correct signature
 *      0: incorrect signature
 *     -1: error
 */
int DSA_verify(int type, const unsigned char *dgst, int dgst_len,
               const unsigned char *sigbuf, int siglen, DSA *dsa)
{
    DSA_SIG *s;
    const unsigned char *p = sigbuf;
    unsigned char *der = NULL;
    int derlen = -1;
    int ret = -1;

    s = DSA_SIG_new();
    if (s == NULL)
        return (ret);
    if (d2i_DSA_SIG(&s, &p, siglen) == NULL)
        goto err;
    /* Ensure signature uses DER and doesn't have trailing garbage */
    derlen = i2d_DSA_SIG(s, &der);
    if (derlen != siglen || memcmp(sigbuf, der, derlen))
        goto err;
    ret = DSA_do_verify(dgst, dgst_len, s, dsa);
 err:
    if (derlen > 0) {
        OPENSSL_cleanse(der, derlen);
        OPENSSL_free(der);
    }
    DSA_SIG_free(s);
    return (ret);
}
/* crypto/dsa/dsa_depr.c */
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
 * This file contains deprecated function(s) that are now wrappers to the new
 * version(s).
 */

#undef GENUINE_DSA

#ifdef GENUINE_DSA
/*
 * Parameter generation follows the original release of FIPS PUB 186,
 * Appendix 2.2 (i.e. use SHA as defined in FIPS PUB 180)
 */
# define HASH    EVP_sha()
#else
/*
 * Parameter generation follows the updated Appendix 2.2 for FIPS PUB 186,
 * also Appendix 2.2 of FIPS PUB 186-1 (i.e. use SHA as defined in FIPS PUB
 * 180-1)
 */
# define HASH    EVP_sha1()
#endif

static void *dummy = &dummy;

#ifndef OPENSSL_NO_SHA

# include <stdio.h>
# include <time.h>
# include "cryptlib.h"
# include "evp.h"
# include "bn.h"
# include "dsa.h"
# include "rand.h"
# include "sha.h"

# ifndef OPENSSL_NO_DEPRECATED
DSA *DSA_generate_parameters(int bits,
                             unsigned char *seed_in, int seed_len,
                             int *counter_ret, unsigned long *h_ret,
                             void (*callback) (int, int, void *),
                             void *cb_arg)
{
    BN_GENCB cb;
    DSA *ret;

    if ((ret = DSA_new()) == NULL)
        return NULL;

    BN_GENCB_set_old(&cb, callback, cb_arg);

    if (DSA_generate_parameters_ex(ret, bits, seed_in, seed_len,
                                   counter_ret, h_ret, &cb))
        return ret;
    DSA_free(ret);
    return NULL;
}
# endif
#endif
/* crypto/dsa/dsa_err.c */
/* ====================================================================
 * Copyright (c) 1999-2018 The OpenSSL Project.  All rights reserved.
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
// #include "dsa.h"

/* BEGIN ERROR CODES */
#ifndef OPENSSL_NO_ERR

# define ERR_FUNC(func) ERR_PACK(ERR_LIB_DSA,func,0)
# define ERR_REASON(reason) ERR_PACK(ERR_LIB_DSA,0,reason)

static ERR_STRING_DATA DSA_str_functs[] = {
    {ERR_FUNC(DSA_F_D2I_DSA_SIG), "d2i_DSA_SIG"},
    {ERR_FUNC(DSA_F_DO_DSA_PRINT), "DO_DSA_PRINT"},
    {ERR_FUNC(DSA_F_DSAPARAMS_PRINT), "DSAparams_print"},
    {ERR_FUNC(DSA_F_DSAPARAMS_PRINT_FP), "DSAparams_print_fp"},
    {ERR_FUNC(DSA_F_DSA_BUILTIN_PARAMGEN2), "DSA_BUILTIN_PARAMGEN2"},
    {ERR_FUNC(DSA_F_DSA_DO_SIGN), "DSA_do_sign"},
    {ERR_FUNC(DSA_F_DSA_DO_VERIFY), "DSA_do_verify"},
    {ERR_FUNC(DSA_F_DSA_GENERATE_KEY), "DSA_generate_key"},
    {ERR_FUNC(DSA_F_DSA_GENERATE_PARAMETERS_EX),
     "DSA_generate_parameters_ex"},
    {ERR_FUNC(DSA_F_DSA_NEW_METHOD), "DSA_new_method"},
    {ERR_FUNC(DSA_F_DSA_PARAM_DECODE), "DSA_PARAM_DECODE"},
    {ERR_FUNC(DSA_F_DSA_PRINT_FP), "DSA_print_fp"},
    {ERR_FUNC(DSA_F_DSA_PRIV_DECODE), "DSA_PRIV_DECODE"},
    {ERR_FUNC(DSA_F_DSA_PRIV_ENCODE), "DSA_PRIV_ENCODE"},
    {ERR_FUNC(DSA_F_DSA_PUB_DECODE), "DSA_PUB_DECODE"},
    {ERR_FUNC(DSA_F_DSA_PUB_ENCODE), "DSA_PUB_ENCODE"},
    {ERR_FUNC(DSA_F_DSA_SIGN), "DSA_sign"},
    {ERR_FUNC(DSA_F_DSA_SIGN_SETUP), "DSA_sign_setup"},
    {ERR_FUNC(DSA_F_DSA_SIG_NEW), "DSA_SIG_new"},
    {ERR_FUNC(DSA_F_DSA_SIG_PRINT), "DSA_SIG_PRINT"},
    {ERR_FUNC(DSA_F_DSA_VERIFY), "DSA_verify"},
    {ERR_FUNC(DSA_F_I2D_DSA_SIG), "i2d_DSA_SIG"},
    {ERR_FUNC(DSA_F_OLD_DSA_PRIV_DECODE), "OLD_DSA_PRIV_DECODE"},
    {ERR_FUNC(DSA_F_PKEY_DSA_CTRL), "PKEY_DSA_CTRL"},
    {ERR_FUNC(DSA_F_PKEY_DSA_CTRL_STR), "PKEY_DSA_CTRL_STR"},
    {ERR_FUNC(DSA_F_PKEY_DSA_KEYGEN), "PKEY_DSA_KEYGEN"},
    {ERR_FUNC(DSA_F_SIG_CB), "SIG_CB"},
    {0, NULL}
};

static ERR_STRING_DATA DSA_str_reasons[] = {
    {ERR_REASON(DSA_R_BAD_Q_VALUE), "bad q value"},
    {ERR_REASON(DSA_R_BN_DECODE_ERROR), "bn decode error"},
    {ERR_REASON(DSA_R_BN_ERROR), "bn error"},
    {ERR_REASON(DSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE),
     "data too large for key size"},
    {ERR_REASON(DSA_R_DECODE_ERROR), "decode error"},
    {ERR_REASON(DSA_R_INVALID_DIGEST_TYPE), "invalid digest type"},
    {ERR_REASON(DSA_R_INVALID_PARAMETERS), "invalid parameters"},
    {ERR_REASON(DSA_R_MISSING_PARAMETERS), "missing parameters"},
    {ERR_REASON(DSA_R_MODULUS_TOO_LARGE), "modulus too large"},
    {ERR_REASON(DSA_R_NEED_NEW_SETUP_VALUES), "need new setup values"},
    {ERR_REASON(DSA_R_NON_FIPS_DSA_METHOD), "non fips dsa method"},
    {ERR_REASON(DSA_R_NO_PARAMETERS_SET), "no parameters set"},
    {ERR_REASON(DSA_R_PARAMETER_ENCODING_ERROR), "parameter encoding error"},
    {ERR_REASON(DSA_R_Q_NOT_PRIME), "q not prime"},
    {0, NULL}
};

#endif

void ERR_load_DSA_strings(void)
{
#ifndef OPENSSL_NO_ERR

    if (ERR_func_error_string(DSA_str_functs[0].error) == NULL) {
        ERR_load_strings(0, DSA_str_functs);
        ERR_load_strings(0, DSA_str_reasons);
    }
#endif
}
/* crypto/dsa/dsa_gen.c */
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

#undef GENUINE_DSA

#ifdef GENUINE_DSA
/*
 * Parameter generation follows the original release of FIPS PUB 186,
 * Appendix 2.2 (i.e. use SHA as defined in FIPS PUB 180)
 */
# define HASH    EVP_sha()
#else
/*
 * Parameter generation follows the updated Appendix 2.2 for FIPS PUB 186,
 * also Appendix 2.2 of FIPS PUB 186-1 (i.e. use SHA as defined in FIPS PUB
 * 180-1)
 */
# define HASH    EVP_sha1()
#endif

#include "opensslconf.h" /* To see if OPENSSL_NO_SHA is defined */

#ifndef OPENSSL_NO_SHA

# include <stdio.h>
# include "cryptlib.h"
# include "evp.h"
# include "bn.h"
# include "rand.h"
# include "sha.h"
# include "dsa_locl.h"

# ifdef OPENSSL_FIPS
/* Workaround bug in prototype */
#  define fips_dsa_builtin_paramgen2 fips_dsa_paramgen_bad
#  include <fips.h>
# endif

int DSA_generate_parameters_ex(DSA *ret, int bits,
                               const unsigned char *seed_in, int seed_len,
                               int *counter_ret, unsigned long *h_ret,
                               BN_GENCB *cb)
{
# ifdef OPENSSL_FIPS
    if (FIPS_mode() && !(ret->meth->flags & DSA_FLAG_FIPS_METHOD)
        && !(ret->flags & DSA_FLAG_NON_FIPS_ALLOW)) {
        DSAerr(DSA_F_DSA_GENERATE_PARAMETERS_EX, DSA_R_NON_FIPS_DSA_METHOD);
        return 0;
    }
# endif
    if (ret->meth->dsa_paramgen)
        return ret->meth->dsa_paramgen(ret, bits, seed_in, seed_len,
                                       counter_ret, h_ret, cb);
# ifdef OPENSSL_FIPS
    else if (FIPS_mode()) {
        return FIPS_dsa_generate_parameters_ex(ret, bits,
                                               seed_in, seed_len,
                                               counter_ret, h_ret, cb);
    }
# endif
    else {
        const EVP_MD *evpmd = bits >= 2048 ? EVP_sha256() : EVP_sha1();
        size_t qbits = EVP_MD_size(evpmd) * 8;

        return dsa_builtin_paramgen(ret, bits, qbits, evpmd,
                                    seed_in, seed_len, NULL, counter_ret,
                                    h_ret, cb);
    }
}

int dsa_builtin_paramgen(DSA *ret, size_t bits, size_t qbits,
                         const EVP_MD *evpmd, const unsigned char *seed_in,
                         size_t seed_len, unsigned char *seed_out,
                         int *counter_ret, unsigned long *h_ret, BN_GENCB *cb)
{
    int ok = 0;
    unsigned char seed[SHA256_DIGEST_LENGTH];
    unsigned char md[SHA256_DIGEST_LENGTH];
    unsigned char buf[SHA256_DIGEST_LENGTH], buf2[SHA256_DIGEST_LENGTH];
    BIGNUM *r0, *W, *X, *c, *test;
    BIGNUM *g = NULL, *q = NULL, *p = NULL;
    BN_MONT_CTX *mont = NULL;
    int i, k, n = 0, m = 0, qsize = qbits >> 3;
    int counter = 0;
    int r = 0;
    BN_CTX *ctx = NULL;
    unsigned int h = 2;

    if (qsize != SHA_DIGEST_LENGTH && qsize != SHA224_DIGEST_LENGTH &&
        qsize != SHA256_DIGEST_LENGTH)
        /* invalid q size */
        return 0;

    if (evpmd == NULL) {
        if (qsize == SHA_DIGEST_LENGTH)
            evpmd = EVP_sha1();
        else if (qsize == SHA224_DIGEST_LENGTH)
            evpmd = EVP_sha224();
        else
            evpmd = EVP_sha256();
    } else {
        qsize = EVP_MD_size(evpmd);
    }

    if (bits < 512)
        bits = 512;

    bits = (bits + 63) / 64 * 64;

    /*
     * NB: seed_len == 0 is special case: copy generated seed to seed_in if
     * it is not NULL.
     */
    if (seed_len && (seed_len < (size_t)qsize))
        seed_in = NULL;         /* seed buffer too small -- ignore */
    if (seed_len > (size_t)qsize)
        seed_len = qsize;       /* App. 2.2 of FIPS PUB 186 allows larger
                                 * SEED, but our internal buffers are
                                 * restricted to 160 bits */
    if (seed_in != NULL)
        memcpy(seed, seed_in, seed_len);

    if ((mont = BN_MONT_CTX_new()) == NULL)
        goto err;

    if ((ctx = BN_CTX_new()) == NULL)
        goto err;

    BN_CTX_start(ctx);

    r0 = BN_CTX_get(ctx);
    g = BN_CTX_get(ctx);
    W = BN_CTX_get(ctx);
    q = BN_CTX_get(ctx);
    X = BN_CTX_get(ctx);
    c = BN_CTX_get(ctx);
    p = BN_CTX_get(ctx);
    test = BN_CTX_get(ctx);

    if (test == NULL)
        goto err;

    if (!BN_lshift(test, BN_value_one(), bits - 1))
        goto err;

    for (;;) {
        for (;;) {              /* find q */
            int seed_is_random;

            /* step 1 */
            if (!BN_GENCB_call(cb, 0, m++))
                goto err;

            if (!seed_len || !seed_in) {
                if (RAND_bytes(seed, qsize) <= 0)
                    goto err;
                seed_is_random = 1;
            } else {
                seed_is_random = 0;
                seed_len = 0;   /* use random seed if 'seed_in' turns out to
                                 * be bad */
            }
            memcpy(buf, seed, qsize);
            memcpy(buf2, seed, qsize);
            /* precompute "SEED + 1" for step 7: */
            for (i = qsize - 1; i >= 0; i--) {
                buf[i]++;
                if (buf[i] != 0)
                    break;
            }

            /* step 2 */
            if (!EVP_Digest(seed, qsize, md, NULL, evpmd, NULL))
                goto err;
            if (!EVP_Digest(buf, qsize, buf2, NULL, evpmd, NULL))
                goto err;
            for (i = 0; i < qsize; i++)
                md[i] ^= buf2[i];

            /* step 3 */
            md[0] |= 0x80;
            md[qsize - 1] |= 0x01;
            if (!BN_bin2bn(md, qsize, q))
                goto err;

            /* step 4 */
            r = BN_is_prime_fasttest_ex(q, DSS_prime_checks, ctx,
                                        seed_is_random, cb);
            if (r > 0)
                break;
            if (r != 0)
                goto err;

            /* do a callback call */
            /* step 5 */
        }

        if (!BN_GENCB_call(cb, 2, 0))
            goto err;
        if (!BN_GENCB_call(cb, 3, 0))
            goto err;

        /* step 6 */
        counter = 0;
        /* "offset = 2" */

        n = (bits - 1) / 160;

        for (;;) {
            if ((counter != 0) && !BN_GENCB_call(cb, 0, counter))
                goto err;

            /* step 7 */
            BN_zero(W);
            /* now 'buf' contains "SEED + offset - 1" */
            for (k = 0; k <= n; k++) {
                /*
                 * obtain "SEED + offset + k" by incrementing:
                 */
                for (i = qsize - 1; i >= 0; i--) {
                    buf[i]++;
                    if (buf[i] != 0)
                        break;
                }

                if (!EVP_Digest(buf, qsize, md, NULL, evpmd, NULL))
                    goto err;

                /* step 8 */
                if (!BN_bin2bn(md, qsize, r0))
                    goto err;
                if (!BN_lshift(r0, r0, (qsize << 3) * k))
                    goto err;
                if (!BN_add(W, W, r0))
                    goto err;
            }

            /* more of step 8 */
            if (!BN_mask_bits(W, bits - 1))
                goto err;
            if (!BN_copy(X, W))
                goto err;
            if (!BN_add(X, X, test))
                goto err;

            /* step 9 */
            if (!BN_lshift1(r0, q))
                goto err;
            if (!BN_mod(c, X, r0, ctx))
                goto err;
            if (!BN_sub(r0, c, BN_value_one()))
                goto err;
            if (!BN_sub(p, X, r0))
                goto err;

            /* step 10 */
            if (BN_cmp(p, test) >= 0) {
                /* step 11 */
                r = BN_is_prime_fasttest_ex(p, DSS_prime_checks, ctx, 1, cb);
                if (r > 0)
                    goto end;   /* found it */
                if (r != 0)
                    goto err;
            }

            /* step 13 */
            counter++;
            /* "offset = offset + n + 1" */

            /* step 14 */
            if (counter >= 4096)
                break;
        }
    }
 end:
    if (!BN_GENCB_call(cb, 2, 1))
        goto err;

    /* We now need to generate g */
    /* Set r0=(p-1)/q */
    if (!BN_sub(test, p, BN_value_one()))
        goto err;
    if (!BN_div(r0, NULL, test, q, ctx))
        goto err;

    if (!BN_set_word(test, h))
        goto err;
    if (!BN_MONT_CTX_set(mont, p, ctx))
        goto err;

    for (;;) {
        /* g=test^r0%p */
        if (!BN_mod_exp_mont(g, test, r0, p, ctx, mont))
            goto err;
        if (!BN_is_one(g))
            break;
        if (!BN_add(test, test, BN_value_one()))
            goto err;
        h++;
    }

    if (!BN_GENCB_call(cb, 3, 1))
        goto err;

    ok = 1;
 err:
    if (ok) {
        if (ret->p)
            BN_free(ret->p);
        if (ret->q)
            BN_free(ret->q);
        if (ret->g)
            BN_free(ret->g);
        ret->p = BN_dup(p);
        ret->q = BN_dup(q);
        ret->g = BN_dup(g);
        if (ret->p == NULL || ret->q == NULL || ret->g == NULL) {
            ok = 0;
            goto err;
        }
        if (counter_ret != NULL)
            *counter_ret = counter;
        if (h_ret != NULL)
            *h_ret = h;
        if (seed_out)
            memcpy(seed_out, seed, qsize);
    }
    if (ctx) {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    if (mont != NULL)
        BN_MONT_CTX_free(mont);
    return ok;
}

# ifdef OPENSSL_FIPS
#  undef fips_dsa_builtin_paramgen2
extern int fips_dsa_builtin_paramgen2(DSA *ret, size_t L, size_t N,
                                      const EVP_MD *evpmd,
                                      const unsigned char *seed_in,
                                      size_t seed_len, int idx,
                                      unsigned char *seed_out,
                                      int *counter_ret, unsigned long *h_ret,
                                      BN_GENCB *cb);
# endif

/*
 * This is a parameter generation algorithm for the DSA2 algorithm as
 * described in FIPS 186-3.
 */

int dsa_builtin_paramgen2(DSA *ret, size_t L, size_t N,
                          const EVP_MD *evpmd, const unsigned char *seed_in,
                          size_t seed_len, int idx, unsigned char *seed_out,
                          int *counter_ret, unsigned long *h_ret,
                          BN_GENCB *cb)
{
    int ok = -1;
    unsigned char *seed = NULL, *seed_tmp = NULL;
    unsigned char md[EVP_MAX_MD_SIZE];
    int mdsize;
    BIGNUM *r0, *W, *X, *c, *test;
    BIGNUM *g = NULL, *q = NULL, *p = NULL;
    BN_MONT_CTX *mont = NULL;
    int i, k, n = 0, m = 0, qsize = N >> 3;
    int counter = 0;
    int r = 0;
    BN_CTX *ctx = NULL;
    EVP_MD_CTX mctx;
    unsigned int h = 2;

# ifdef OPENSSL_FIPS

    if (FIPS_mode())
        return fips_dsa_builtin_paramgen2(ret, L, N, evpmd,
                                          seed_in, seed_len, idx,
                                          seed_out, counter_ret, h_ret, cb);
# endif

    EVP_MD_CTX_init(&mctx);

    /* make sure L > N, otherwise we'll get trapped in an infinite loop */
    if (L <= N) {
        DSAerr(DSA_F_DSA_BUILTIN_PARAMGEN2, DSA_R_INVALID_PARAMETERS);
        goto err;
    }

    if (evpmd == NULL) {
        if (N == 160)
            evpmd = EVP_sha1();
        else if (N == 224)
            evpmd = EVP_sha224();
        else
            evpmd = EVP_sha256();
    }

    mdsize = EVP_MD_size(evpmd);
    /* If unverificable g generation only don't need seed */
    if (!ret->p || !ret->q || idx >= 0) {
        if (seed_len == 0)
            seed_len = mdsize;

        seed = OPENSSL_malloc(seed_len);

        if (seed_out)
            seed_tmp = seed_out;
        else
            seed_tmp = OPENSSL_malloc(seed_len);

        if (!seed || !seed_tmp)
            goto err;

        if (seed_in)
            memcpy(seed, seed_in, seed_len);

    }

    if ((ctx = BN_CTX_new()) == NULL)
        goto err;

    if ((mont = BN_MONT_CTX_new()) == NULL)
        goto err;

    BN_CTX_start(ctx);
    r0 = BN_CTX_get(ctx);
    g = BN_CTX_get(ctx);
    W = BN_CTX_get(ctx);
    X = BN_CTX_get(ctx);
    c = BN_CTX_get(ctx);
    test = BN_CTX_get(ctx);

    /* if p, q already supplied generate g only */
    if (ret->p && ret->q) {
        p = ret->p;
        q = ret->q;
        if (idx >= 0)
            memcpy(seed_tmp, seed, seed_len);
        goto g_only;
    } else {
        p = BN_CTX_get(ctx);
        q = BN_CTX_get(ctx);
        if (q == NULL)
            goto err;
    }

    if (!BN_lshift(test, BN_value_one(), L - 1))
        goto err;
    for (;;) {
        for (;;) {              /* find q */
            unsigned char *pmd;
            /* step 1 */
            if (!BN_GENCB_call(cb, 0, m++))
                goto err;

            if (!seed_in) {
                if (RAND_bytes(seed, seed_len) <= 0)
                    goto err;
            }
            /* step 2 */
            if (!EVP_Digest(seed, seed_len, md, NULL, evpmd, NULL))
                goto err;
            /* Take least significant bits of md */
            if (mdsize > qsize)
                pmd = md + mdsize - qsize;
            else
                pmd = md;

            if (mdsize < qsize)
                memset(md + mdsize, 0, qsize - mdsize);

            /* step 3 */
            pmd[0] |= 0x80;
            pmd[qsize - 1] |= 0x01;
            if (!BN_bin2bn(pmd, qsize, q))
                goto err;

            /* step 4 */
            r = BN_is_prime_fasttest_ex(q, DSS_prime_checks, ctx,
                                        seed_in ? 1 : 0, cb);
            if (r > 0)
                break;
            if (r != 0)
                goto err;
            /* Provided seed didn't produce a prime: error */
            if (seed_in) {
                ok = 0;
                DSAerr(DSA_F_DSA_BUILTIN_PARAMGEN2, DSA_R_Q_NOT_PRIME);
                goto err;
            }

            /* do a callback call */
            /* step 5 */
        }
        /* Copy seed to seed_out before we mess with it */
        if (seed_out)
            memcpy(seed_out, seed, seed_len);

        if (!BN_GENCB_call(cb, 2, 0))
            goto err;
        if (!BN_GENCB_call(cb, 3, 0))
            goto err;

        /* step 6 */
        counter = 0;
        /* "offset = 1" */

        n = (L - 1) / (mdsize << 3);

        for (;;) {
            if ((counter != 0) && !BN_GENCB_call(cb, 0, counter))
                goto err;

            /* step 7 */
            BN_zero(W);
            /* now 'buf' contains "SEED + offset - 1" */
            for (k = 0; k <= n; k++) {
                /*
                 * obtain "SEED + offset + k" by incrementing:
                 */
                for (i = seed_len - 1; i >= 0; i--) {
                    seed[i]++;
                    if (seed[i] != 0)
                        break;
                }

                if (!EVP_Digest(seed, seed_len, md, NULL, evpmd, NULL))
                    goto err;

                /* step 8 */
                if (!BN_bin2bn(md, mdsize, r0))
                    goto err;
                if (!BN_lshift(r0, r0, (mdsize << 3) * k))
                    goto err;
                if (!BN_add(W, W, r0))
                    goto err;
            }

            /* more of step 8 */
            if (!BN_mask_bits(W, L - 1))
                goto err;
            if (!BN_copy(X, W))
                goto err;
            if (!BN_add(X, X, test))
                goto err;

            /* step 9 */
            if (!BN_lshift1(r0, q))
                goto err;
            if (!BN_mod(c, X, r0, ctx))
                goto err;
            if (!BN_sub(r0, c, BN_value_one()))
                goto err;
            if (!BN_sub(p, X, r0))
                goto err;

            /* step 10 */
            if (BN_cmp(p, test) >= 0) {
                /* step 11 */
                r = BN_is_prime_fasttest_ex(p, DSS_prime_checks, ctx, 1, cb);
                if (r > 0)
                    goto end;   /* found it */
                if (r != 0)
                    goto err;
            }

            /* step 13 */
            counter++;
            /* "offset = offset + n + 1" */

            /* step 14 */
            if (counter >= (int)(4 * L))
                break;
        }
        if (seed_in) {
            ok = 0;
            DSAerr(DSA_F_DSA_BUILTIN_PARAMGEN2, DSA_R_INVALID_PARAMETERS);
            goto err;
        }
    }
 end:
    if (!BN_GENCB_call(cb, 2, 1))
        goto err;

 g_only:

    /* We now need to generate g */
    /* Set r0=(p-1)/q */
    if (!BN_sub(test, p, BN_value_one()))
        goto err;
    if (!BN_div(r0, NULL, test, q, ctx))
        goto err;

    if (idx < 0) {
        if (!BN_set_word(test, h))
            goto err;
    } else
        h = 1;
    if (!BN_MONT_CTX_set(mont, p, ctx))
        goto err;

    for (;;) {
        static const unsigned char ggen[4] = { 0x67, 0x67, 0x65, 0x6e };
        if (idx >= 0) {
            md[0] = idx & 0xff;
            md[1] = (h >> 8) & 0xff;
            md[2] = h & 0xff;
            if (!EVP_DigestInit_ex(&mctx, evpmd, NULL))
                goto err;
            if (!EVP_DigestUpdate(&mctx, seed_tmp, seed_len))
                goto err;
            if (!EVP_DigestUpdate(&mctx, ggen, sizeof(ggen)))
                goto err;
            if (!EVP_DigestUpdate(&mctx, md, 3))
                goto err;
            if (!EVP_DigestFinal_ex(&mctx, md, NULL))
                goto err;
            if (!BN_bin2bn(md, mdsize, test))
                goto err;
        }
        /* g=test^r0%p */
        if (!BN_mod_exp_mont(g, test, r0, p, ctx, mont))
            goto err;
        if (!BN_is_one(g))
            break;
        if (idx < 0 && !BN_add(test, test, BN_value_one()))
            goto err;
        h++;
        if (idx >= 0 && h > 0xffff)
            goto err;
    }

    if (!BN_GENCB_call(cb, 3, 1))
        goto err;

    ok = 1;
 err:
    if (ok == 1) {
        if (p != ret->p) {
            if (ret->p)
                BN_free(ret->p);
            ret->p = BN_dup(p);
        }
        if (q != ret->q) {
            if (ret->q)
                BN_free(ret->q);
            ret->q = BN_dup(q);
        }
        if (ret->g)
            BN_free(ret->g);
        ret->g = BN_dup(g);
        if (ret->p == NULL || ret->q == NULL || ret->g == NULL) {
            ok = -1;
            goto err;
        }
        if (counter_ret != NULL)
            *counter_ret = counter;
        if (h_ret != NULL)
            *h_ret = h;
    }
    if (seed)
        OPENSSL_free(seed);
    if (seed_out != seed_tmp)
        OPENSSL_free(seed_tmp);
    if (ctx) {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    if (mont != NULL)
        BN_MONT_CTX_free(mont);
    EVP_MD_CTX_cleanup(&mctx);
    return ok;
}

int dsa_paramgen_check_g(DSA *dsa)
{
    BN_CTX *ctx;
    BIGNUM *tmp;
    BN_MONT_CTX *mont = NULL;
    int rv = -1;
    ctx = BN_CTX_new();
    if (!ctx)
        return -1;
    BN_CTX_start(ctx);
    if (BN_cmp(dsa->g, BN_value_one()) <= 0)
        return 0;
    if (BN_cmp(dsa->g, dsa->p) >= 0)
        return 0;
    tmp = BN_CTX_get(ctx);
    if (!tmp)
        goto err;
    if ((mont = BN_MONT_CTX_new()) == NULL)
        goto err;
    if (!BN_MONT_CTX_set(mont, dsa->p, ctx))
        goto err;
    /* Work out g^q mod p */
    if (!BN_mod_exp_mont(tmp, dsa->g, dsa->q, dsa->p, ctx, mont))
        goto err;
    if (!BN_cmp(tmp, BN_value_one()))
        rv = 1;
    else
        rv = 0;
 err:
    BN_CTX_end(ctx);
    if (mont)
        BN_MONT_CTX_free(mont);
    BN_CTX_free(ctx);
    return rv;

}
#endif
/* crypto/dsa/dsa_key.c */
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
#include <time.h>
// #include "cryptlib.h"
#ifndef OPENSSL_NO_SHA
# include "bn.h"
# include "dsa.h"
# include "rand.h"

# ifdef OPENSSL_FIPS
#  include <fips.h>
# endif

static int dsa_builtin_keygen(DSA *dsa);

int DSA_generate_key(DSA *dsa)
{
# ifdef OPENSSL_FIPS
    if (FIPS_mode() && !(dsa->meth->flags & DSA_FLAG_FIPS_METHOD)
        && !(dsa->flags & DSA_FLAG_NON_FIPS_ALLOW)) {
        DSAerr(DSA_F_DSA_GENERATE_KEY, DSA_R_NON_FIPS_DSA_METHOD);
        return 0;
    }
# endif
    if (dsa->meth->dsa_keygen)
        return dsa->meth->dsa_keygen(dsa);
# ifdef OPENSSL_FIPS
    if (FIPS_mode())
        return FIPS_dsa_generate_key(dsa);
# endif
    return dsa_builtin_keygen(dsa);
}

static int dsa_builtin_keygen(DSA *dsa)
{
    int ok = 0;
    BN_CTX *ctx = NULL;
    BIGNUM *pub_key = NULL, *priv_key = NULL;

    if ((ctx = BN_CTX_new()) == NULL)
        goto err;

    if (dsa->priv_key == NULL) {
        if ((priv_key = BN_new()) == NULL)
            goto err;
    } else
        priv_key = dsa->priv_key;

    do
        if (!BN_rand_range(priv_key, dsa->q))
            goto err;
    while (BN_is_zero(priv_key)) ;

    if (dsa->pub_key == NULL) {
        if ((pub_key = BN_new()) == NULL)
            goto err;
    } else
        pub_key = dsa->pub_key;

    {
        BIGNUM local_prk;
        BIGNUM *prk;

        if ((dsa->flags & DSA_FLAG_NO_EXP_CONSTTIME) == 0) {
            BN_init(&local_prk);
            prk = &local_prk;
            BN_with_flags(prk, priv_key, BN_FLG_CONSTTIME);
        } else
            prk = priv_key;

        if (!BN_mod_exp(pub_key, dsa->g, prk, dsa->p, ctx))
            goto err;
    }

    dsa->priv_key = priv_key;
    dsa->pub_key = pub_key;
    ok = 1;

 err:
    if ((pub_key != NULL) && (dsa->pub_key == NULL))
        BN_free(pub_key);
    if ((priv_key != NULL) && (dsa->priv_key == NULL))
        BN_free(priv_key);
    if (ctx != NULL)
        BN_CTX_free(ctx);
    return (ok);
}
#endif
/* crypto/dsa/dsa_lib.c */
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

/* Original version from Steven Schoch <schoch@sheba.arc.nasa.gov> */

#include <stdio.h>
// #include "cryptlib.h"
// #include "bn.h"
// #include "dsa.h"
// #include "asn1.h"
#ifndef OPENSSL_NO_ENGINE
# include "engine.h"
#endif
#ifndef OPENSSL_NO_DH
# include "dh.h"
#endif

#ifdef OPENSSL_FIPS
# include <fips.h>
#endif

const char DSA_version[] = "DSA" OPENSSL_VERSION_PTEXT;

static const DSA_METHOD *default_DSA_method = NULL;

void DSA_set_default_method(const DSA_METHOD *meth)
{
    default_DSA_method = meth;
}

const DSA_METHOD *DSA_get_default_method(void)
{
    if (!default_DSA_method) {
#ifdef OPENSSL_FIPS
        if (FIPS_mode())
            return FIPS_dsa_openssl();
        else
            return DSA_OpenSSL();
#else
        default_DSA_method = DSA_OpenSSL();
#endif
    }
    return default_DSA_method;
}

DSA *DSA_new(void)
{
    return DSA_new_method(NULL);
}

int DSA_set_method(DSA *dsa, const DSA_METHOD *meth)
{
    /*
     * NB: The caller is specifically setting a method, so it's not up to us
     * to deal with which ENGINE it comes from.
     */
    const DSA_METHOD *mtmp;
    mtmp = dsa->meth;
    if (mtmp->finish)
        mtmp->finish(dsa);
#ifndef OPENSSL_NO_ENGINE
    if (dsa->engine) {
        ENGINE_finish(dsa->engine);
        dsa->engine = NULL;
    }
#endif
    dsa->meth = meth;
    if (meth->init)
        meth->init(dsa);
    return 1;
}

DSA *DSA_new_method(ENGINE *engine)
{
    DSA *ret;

    ret = (DSA *)OPENSSL_malloc(sizeof(DSA));
    if (ret == NULL) {
        DSAerr(DSA_F_DSA_NEW_METHOD, ERR_R_MALLOC_FAILURE);
        return (NULL);
    }
    ret->meth = DSA_get_default_method();
#ifndef OPENSSL_NO_ENGINE
    if (engine) {
        if (!ENGINE_init(engine)) {
            DSAerr(DSA_F_DSA_NEW_METHOD, ERR_R_ENGINE_LIB);
            OPENSSL_free(ret);
            return NULL;
        }
        ret->engine = engine;
    } else
        ret->engine = ENGINE_get_default_DSA();
    if (ret->engine) {
        ret->meth = ENGINE_get_DSA(ret->engine);
        if (!ret->meth) {
            DSAerr(DSA_F_DSA_NEW_METHOD, ERR_R_ENGINE_LIB);
            ENGINE_finish(ret->engine);
            OPENSSL_free(ret);
            return NULL;
        }
    }
#endif

    ret->pad = 0;
    ret->version = 0;
    ret->write_params = 1;
    ret->p = NULL;
    ret->q = NULL;
    ret->g = NULL;

    ret->pub_key = NULL;
    ret->priv_key = NULL;

    ret->kinv = NULL;
    ret->r = NULL;
    ret->method_mont_p = NULL;

    ret->references = 1;
    ret->flags = ret->meth->flags & ~DSA_FLAG_NON_FIPS_ALLOW;
    CRYPTO_new_ex_data(CRYPTO_EX_INDEX_DSA, ret, &ret->ex_data);
    if ((ret->meth->init != NULL) && !ret->meth->init(ret)) {
#ifndef OPENSSL_NO_ENGINE
        if (ret->engine)
            ENGINE_finish(ret->engine);
#endif
        CRYPTO_free_ex_data(CRYPTO_EX_INDEX_DSA, ret, &ret->ex_data);
        OPENSSL_free(ret);
        ret = NULL;
    }

    return (ret);
}

void DSA_free(DSA *r)
{
    int i;

    if (r == NULL)
        return;

    i = CRYPTO_add(&r->references, -1, CRYPTO_LOCK_DSA);
#ifdef REF_PRINT
    REF_PRINT("DSA", r);
#endif
    if (i > 0)
        return;
#ifdef REF_CHECK
    if (i < 0) {
        fprintf(stderr, "DSA_free, bad reference count\n");
        abort();
    }
#endif

    if (r->meth->finish)
        r->meth->finish(r);
#ifndef OPENSSL_NO_ENGINE
    if (r->engine)
        ENGINE_finish(r->engine);
#endif

    CRYPTO_free_ex_data(CRYPTO_EX_INDEX_DSA, r, &r->ex_data);

    if (r->p != NULL)
        BN_clear_free(r->p);
    if (r->q != NULL)
        BN_clear_free(r->q);
    if (r->g != NULL)
        BN_clear_free(r->g);
    if (r->pub_key != NULL)
        BN_clear_free(r->pub_key);
    if (r->priv_key != NULL)
        BN_clear_free(r->priv_key);
    if (r->kinv != NULL)
        BN_clear_free(r->kinv);
    if (r->r != NULL)
        BN_clear_free(r->r);
    OPENSSL_free(r);
}

int DSA_up_ref(DSA *r)
{
    int i = CRYPTO_add(&r->references, 1, CRYPTO_LOCK_DSA);
#ifdef REF_PRINT
    REF_PRINT("DSA", r);
#endif
#ifdef REF_CHECK
    if (i < 2) {
        fprintf(stderr, "DSA_up_ref, bad reference count\n");
        abort();
    }
#endif
    return ((i > 1) ? 1 : 0);
}

int DSA_size(const DSA *r)
{
    int ret, i;
    ASN1_INTEGER bs;
    unsigned char buf[4];       /* 4 bytes looks really small. However,
                                 * i2d_ASN1_INTEGER() will not look beyond
                                 * the first byte, as long as the second
                                 * parameter is NULL. */

    i = BN_num_bits(r->q);
    bs.length = (i + 7) / 8;
    bs.data = buf;
    bs.type = V_ASN1_INTEGER;
    /* If the top bit is set the asn1 encoding is 1 larger. */
    buf[0] = 0xff;

    i = i2d_ASN1_INTEGER(&bs, NULL);
    i += i;                     /* r and s */
    ret = ASN1_object_size(1, i, V_ASN1_SEQUENCE);
    return (ret);
}

int DSA_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func,
                         CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func)
{
    return CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_DSA, argl, argp,
                                   new_func, dup_func, free_func);
}

int DSA_set_ex_data(DSA *d, int idx, void *arg)
{
    return (CRYPTO_set_ex_data(&d->ex_data, idx, arg));
}

void *DSA_get_ex_data(DSA *d, int idx)
{
    return (CRYPTO_get_ex_data(&d->ex_data, idx));
}

#ifndef OPENSSL_NO_DH
DH *DSA_dup_DH(const DSA *r)
{
    /*
     * DSA has p, q, g, optional pub_key, optional priv_key. DH has p,
     * optional length, g, optional pub_key, optional priv_key, optional q.
     */

    DH *ret = NULL;

    if (r == NULL)
        goto err;
    ret = DH_new();
    if (ret == NULL)
        goto err;
    if (r->p != NULL)
        if ((ret->p = BN_dup(r->p)) == NULL)
            goto err;
    if (r->q != NULL) {
        ret->length = BN_num_bits(r->q);
        if ((ret->q = BN_dup(r->q)) == NULL)
            goto err;
    }
    if (r->g != NULL)
        if ((ret->g = BN_dup(r->g)) == NULL)
            goto err;
    if (r->pub_key != NULL)
        if ((ret->pub_key = BN_dup(r->pub_key)) == NULL)
            goto err;
    if (r->priv_key != NULL)
        if ((ret->priv_key = BN_dup(r->priv_key)) == NULL)
            goto err;

    return ret;

 err:
    if (ret != NULL)
        DH_free(ret);
    return NULL;
}
#endif
/* crypto/dsa/dsa_ossl.c */
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

/* Original version from Steven Schoch <schoch@sheba.arc.nasa.gov> */

#include <stdio.h>
// #include "cryptlib.h"
// #include "bn.h"
#include "sha.h"
// #include "dsa.h"
// #include "rand.h"
// #include "asn1.h"

static DSA_SIG *dsa_do_sign(const unsigned char *dgst, int dlen, DSA *dsa);
static int dsa_sign_setup(DSA *dsa, BN_CTX *ctx_in, BIGNUM **kinvp,
                          BIGNUM **rp);
static int dsa_do_verify(const unsigned char *dgst, int dgst_len,
                         DSA_SIG *sig, DSA *dsa);
static int dsa_init(DSA *dsa);
static int dsa_finish(DSA *dsa);
static BIGNUM *dsa_mod_inverse_fermat(const BIGNUM *k, const BIGNUM *q,
                                      BN_CTX *ctx);

static DSA_METHOD openssl_dsa_meth = {
    "OpenSSL DSA method",
    dsa_do_sign,
    dsa_sign_setup,
    dsa_do_verify,
    NULL,                       /* dsa_mod_exp, */
    NULL,                       /* dsa_bn_mod_exp, */
    dsa_init,
    dsa_finish,
    0,
    NULL,
    NULL,
    NULL
};

/*-
 * These macro wrappers replace attempts to use the dsa_mod_exp() and
 * bn_mod_exp() handlers in the DSA_METHOD structure. We avoid the problem of
 * having a the macro work as an expression by bundling an "err_instr". So;
 *
 *     if (!dsa->meth->bn_mod_exp(dsa, r,dsa->g,&k,dsa->p,ctx,
 *                 dsa->method_mont_p)) goto err;
 *
 * can be replaced by;
 *
 *     DSA_BN_MOD_EXP(goto err, dsa, r, dsa->g, &k, dsa->p, ctx,
 *                 dsa->method_mont_p);
 */

#define DSA_MOD_EXP(err_instr,dsa,rr,a1,p1,a2,p2,m,ctx,in_mont) \
        do { \
        int _tmp_res53; \
        if ((dsa)->meth->dsa_mod_exp) \
                _tmp_res53 = (dsa)->meth->dsa_mod_exp((dsa), (rr), (a1), (p1), \
                                (a2), (p2), (m), (ctx), (in_mont)); \
        else \
                _tmp_res53 = BN_mod_exp2_mont((rr), (a1), (p1), (a2), (p2), \
                                (m), (ctx), (in_mont)); \
        if (!_tmp_res53) err_instr; \
        } while(0)
#define DSA_BN_MOD_EXP(err_instr,dsa,r,a,p,m,ctx,m_ctx) \
        do { \
        int _tmp_res53; \
        if ((dsa)->meth->bn_mod_exp) \
                _tmp_res53 = (dsa)->meth->bn_mod_exp((dsa), (r), (a), (p), \
                                (m), (ctx), (m_ctx)); \
        else \
                _tmp_res53 = BN_mod_exp_mont((r), (a), (p), (m), (ctx), (m_ctx)); \
        if (!_tmp_res53) err_instr; \
        } while(0)

const DSA_METHOD *DSA_OpenSSL(void)
{
    return &openssl_dsa_meth;
}

static DSA_SIG *dsa_do_sign(const unsigned char *dgst, int dlen, DSA *dsa)
{
    BIGNUM *kinv = NULL, *r = NULL, *s = NULL;
    BIGNUM *m, *blind, *blindm, *tmp;
    BN_CTX *ctx = NULL;
    int reason = ERR_R_BN_LIB;
    DSA_SIG *ret = NULL;
    int noredo = 0;

    if (dsa->p == NULL || dsa->q == NULL || dsa->g == NULL) {
        reason = DSA_R_MISSING_PARAMETERS;
        goto err;
    }

    s = BN_new();
    if (s == NULL)
        goto err;
    ctx = BN_CTX_new();
    if (ctx == NULL)
        goto err;
    m = BN_CTX_get(ctx);
    blind = BN_CTX_get(ctx);
    blindm = BN_CTX_get(ctx);
    tmp = BN_CTX_get(ctx);
    if (tmp == NULL)
        goto err;

 redo:
    if ((dsa->kinv == NULL) || (dsa->r == NULL)) {
        if (!DSA_sign_setup(dsa, ctx, &kinv, &r))
            goto err;
    } else {
        kinv = dsa->kinv;
        dsa->kinv = NULL;
        r = dsa->r;
        dsa->r = NULL;
        noredo = 1;
    }

    if (dlen > BN_num_bytes(dsa->q))
        /*
         * if the digest length is greater than the size of q use the
         * BN_num_bits(dsa->q) leftmost bits of the digest, see fips 186-3,
         * 4.2
         */
        dlen = BN_num_bytes(dsa->q);
    if (BN_bin2bn(dgst, dlen, m) == NULL)
        goto err;

    /*
     * The normal signature calculation is:
     *
     *   s := k^-1 * (m + r * priv_key) mod q
     *
     * We will blind this to protect against side channel attacks
     *
     *   s := blind^-1 * k^-1 * (blind * m + blind * r * priv_key) mod q
     */

    /* Generate a blinding value */
    do {
        if (!BN_rand(blind, BN_num_bits(dsa->q) - 1, -1, 0))
            goto err;
    } while (BN_is_zero(blind));
    BN_set_flags(blind, BN_FLG_CONSTTIME);
    BN_set_flags(blindm, BN_FLG_CONSTTIME);
    BN_set_flags(tmp, BN_FLG_CONSTTIME);

    /* tmp := blind * priv_key * r mod q */
    if (!BN_mod_mul(tmp, blind, dsa->priv_key, dsa->q, ctx))
        goto err;
    if (!BN_mod_mul(tmp, tmp, r, dsa->q, ctx))
        goto err;

    /* blindm := blind * m mod q */
    if (!BN_mod_mul(blindm, blind, m, dsa->q, ctx))
        goto err;

    /* s : = (blind * priv_key * r) + (blind * m) mod q */
    if (!BN_mod_add_quick(s, tmp, blindm, dsa->q))
        goto err;

    /* s := s * k^-1 mod q */
    if (!BN_mod_mul(s, s, kinv, dsa->q, ctx))
        goto err;

    /* s:= s * blind^-1 mod q */
    if (BN_mod_inverse(blind, blind, dsa->q, ctx) == NULL)
        goto err;
    if (!BN_mod_mul(s, s, blind, dsa->q, ctx))
        goto err;

    /*
     * Redo if r or s is zero as required by FIPS 186-3: this is very
     * unlikely.
     */
    if (BN_is_zero(r) || BN_is_zero(s)) {
        if (noredo) {
            reason = DSA_R_NEED_NEW_SETUP_VALUES;
            goto err;
        }
        goto redo;
    }
    ret = DSA_SIG_new();
    if (ret == NULL)
        goto err;
    ret->r = r;
    ret->s = s;

 err:
    if (ret == NULL) {
        DSAerr(DSA_F_DSA_DO_SIGN, reason);
        BN_free(r);
        BN_free(s);
    }
    BN_CTX_free(ctx);
    BN_clear_free(kinv);
    return ret;
}

static int dsa_sign_setup(DSA *dsa, BN_CTX *ctx_in, BIGNUM **kinvp,
                          BIGNUM **rp)
{
    BN_CTX *ctx;
    BIGNUM k, kq, *K, *kinv = NULL, *r = NULL;
    BIGNUM l, m;
    int ret = 0;
    int q_bits;

    if (!dsa->p || !dsa->q || !dsa->g) {
        DSAerr(DSA_F_DSA_SIGN_SETUP, DSA_R_MISSING_PARAMETERS);
        return 0;
    }

    BN_init(&k);
    BN_init(&kq);
    BN_init(&l);
    BN_init(&m);

    if (ctx_in == NULL) {
        if ((ctx = BN_CTX_new()) == NULL)
            goto err;
    } else
        ctx = ctx_in;

    if ((r = BN_new()) == NULL)
        goto err;

    /* Preallocate space */
    q_bits = BN_num_bits(dsa->q) + sizeof(dsa->q->d[0]) * 16;
    if (!BN_set_bit(&k, q_bits)
        || !BN_set_bit(&l, q_bits)
        || !BN_set_bit(&m, q_bits))
        goto err;

    /* Get random k */
    do
        if (!BN_rand_range(&k, dsa->q))
            goto err;
    while (BN_is_zero(&k));

    if ((dsa->flags & DSA_FLAG_NO_EXP_CONSTTIME) == 0) {
        BN_set_flags(&k, BN_FLG_CONSTTIME);
        BN_set_flags(&l, BN_FLG_CONSTTIME);
    }

    if (dsa->flags & DSA_FLAG_CACHE_MONT_P) {
        if (!BN_MONT_CTX_set_locked(&dsa->method_mont_p,
                                    CRYPTO_LOCK_DSA, dsa->p, ctx))
            goto err;
    }

    /* Compute r = (g^k mod p) mod q */

    if ((dsa->flags & DSA_FLAG_NO_EXP_CONSTTIME) == 0) {
        /*
         * We do not want timing information to leak the length of k, so we
         * compute G^k using an equivalent scalar of fixed bit-length.
         *
         * We unconditionally perform both of these additions to prevent a
         * small timing information leakage.  We then choose the sum that is
         * one bit longer than the modulus.
         *
         * TODO: revisit the BN_copy aiming for a memory access agnostic
         * conditional copy.
         */
        if (!BN_add(&l, &k, dsa->q)
            || !BN_add(&m, &l, dsa->q)
            || !BN_copy(&kq, BN_num_bits(&l) > q_bits ? &l : &m))
            goto err;

        BN_set_flags(&kq, BN_FLG_CONSTTIME);

        K = &kq;
    } else {
        K = &k;
    }

    DSA_BN_MOD_EXP(goto err, dsa, r, dsa->g, K, dsa->p, ctx,
                   dsa->method_mont_p);
    if (!BN_mod(r, r, dsa->q, ctx))
        goto err;

    /* Compute part of 's = inv(k) (m + xr) mod q' */
    if ((kinv = dsa_mod_inverse_fermat(&k, dsa->q, ctx)) == NULL)
        goto err;

    if (*kinvp != NULL)
        BN_clear_free(*kinvp);
    *kinvp = kinv;
    kinv = NULL;
    if (*rp != NULL)
        BN_clear_free(*rp);
    *rp = r;
    ret = 1;
 err:
    if (!ret) {
        DSAerr(DSA_F_DSA_SIGN_SETUP, ERR_R_BN_LIB);
        if (r != NULL)
            BN_clear_free(r);
    }
    if (ctx_in == NULL)
        BN_CTX_free(ctx);
    BN_clear_free(&k);
    BN_clear_free(&kq);
    BN_clear_free(&l);
    BN_clear_free(&m);
    return ret;
}

static int dsa_do_verify(const unsigned char *dgst, int dgst_len,
                         DSA_SIG *sig, DSA *dsa)
{
    BN_CTX *ctx;
    BIGNUM u1, u2, t1;
    BN_MONT_CTX *mont = NULL;
    int ret = -1, i;
    if (!dsa->p || !dsa->q || !dsa->g) {
        DSAerr(DSA_F_DSA_DO_VERIFY, DSA_R_MISSING_PARAMETERS);
        return -1;
    }

    i = BN_num_bits(dsa->q);
    /* fips 186-3 allows only different sizes for q */
    if (i != 160 && i != 224 && i != 256) {
        DSAerr(DSA_F_DSA_DO_VERIFY, DSA_R_BAD_Q_VALUE);
        return -1;
    }

    if (BN_num_bits(dsa->p) > OPENSSL_DSA_MAX_MODULUS_BITS) {
        DSAerr(DSA_F_DSA_DO_VERIFY, DSA_R_MODULUS_TOO_LARGE);
        return -1;
    }
    BN_init(&u1);
    BN_init(&u2);
    BN_init(&t1);

    if ((ctx = BN_CTX_new()) == NULL)
        goto err;

    if (BN_is_zero(sig->r) || BN_is_negative(sig->r) ||
        BN_ucmp(sig->r, dsa->q) >= 0) {
        ret = 0;
        goto err;
    }
    if (BN_is_zero(sig->s) || BN_is_negative(sig->s) ||
        BN_ucmp(sig->s, dsa->q) >= 0) {
        ret = 0;
        goto err;
    }

    /*
     * Calculate W = inv(S) mod Q save W in u2
     */
    if ((BN_mod_inverse(&u2, sig->s, dsa->q, ctx)) == NULL)
        goto err;

    /* save M in u1 */
    if (dgst_len > (i >> 3))
        /*
         * if the digest length is greater than the size of q use the
         * BN_num_bits(dsa->q) leftmost bits of the digest, see fips 186-3,
         * 4.2
         */
        dgst_len = (i >> 3);
    if (BN_bin2bn(dgst, dgst_len, &u1) == NULL)
        goto err;

    /* u1 = M * w mod q */
    if (!BN_mod_mul(&u1, &u1, &u2, dsa->q, ctx))
        goto err;

    /* u2 = r * w mod q */
    if (!BN_mod_mul(&u2, sig->r, &u2, dsa->q, ctx))
        goto err;

    if (dsa->flags & DSA_FLAG_CACHE_MONT_P) {
        mont = BN_MONT_CTX_set_locked(&dsa->method_mont_p,
                                      CRYPTO_LOCK_DSA, dsa->p, ctx);
        if (!mont)
            goto err;
    }

    DSA_MOD_EXP(goto err, dsa, &t1, dsa->g, &u1, dsa->pub_key, &u2, dsa->p,
                ctx, mont);
    /* BN_copy(&u1,&t1); */
    /* let u1 = u1 mod q */
    if (!BN_mod(&u1, &t1, dsa->q, ctx))
        goto err;

    /*
     * V is now in u1.  If the signature is correct, it will be equal to R.
     */
    ret = (BN_ucmp(&u1, sig->r) == 0);

 err:
    if (ret < 0)
        DSAerr(DSA_F_DSA_DO_VERIFY, ERR_R_BN_LIB);
    if (ctx != NULL)
        BN_CTX_free(ctx);
    BN_free(&u1);
    BN_free(&u2);
    BN_free(&t1);
    return (ret);
}

static int dsa_init(DSA *dsa)
{
    dsa->flags |= DSA_FLAG_CACHE_MONT_P;
    return (1);
}

static int dsa_finish(DSA *dsa)
{
    if (dsa->method_mont_p)
        BN_MONT_CTX_free(dsa->method_mont_p);
    return (1);
}

/*
 * Compute the inverse of k modulo q.
 * Since q is prime, Fermat's Little Theorem applies, which reduces this to
 * mod-exp operation.  Both the exponent and modulus are public information
 * so a mod-exp that doesn't leak the base is sufficient.  A newly allocated
 * BIGNUM is returned which the caller must free.
 */
static BIGNUM *dsa_mod_inverse_fermat(const BIGNUM *k, const BIGNUM *q,
                                      BN_CTX *ctx)
{
    BIGNUM *res = NULL;
    BIGNUM *r, e;

    if ((r = BN_new()) == NULL)
        return NULL;

    BN_init(&e);

    if (BN_set_word(r, 2)
            && BN_sub(&e, q, r)
            && BN_mod_exp_mont(r, k, &e, q, ctx, NULL))
        res = r;
    else
        BN_free(r);
    BN_free(&e);
    return res;
}
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 2006.
 */
/* ====================================================================
 * Copyright (c) 2006-2018 The OpenSSL Project.  All rights reserved.
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
#include "evp.h"
// #include "bn.h"
#include "evp_locl.h"
#include "dsa_locl.h"

/* DSA pkey context structure */

typedef struct {
    /* Parameter gen parameters */
    int nbits;                  /* size of p in bits (default: 1024) */
    int qbits;                  /* size of q in bits (default: 160) */
    const EVP_MD *pmd;          /* MD for parameter generation */
    /* Keygen callback info */
    int gentmp[2];
    /* message digest */
    const EVP_MD *md;           /* MD for the signature */
} DSA_PKEY_CTX;

static int pkey_dsa_init(EVP_PKEY_CTX *ctx)
{
    DSA_PKEY_CTX *dctx;
    dctx = OPENSSL_malloc(sizeof(DSA_PKEY_CTX));
    if (!dctx)
        return 0;
    dctx->nbits = 1024;
    dctx->qbits = 160;
    dctx->pmd = NULL;
    dctx->md = NULL;

    ctx->data = dctx;
    ctx->keygen_info = dctx->gentmp;
    ctx->keygen_info_count = 2;

    return 1;
}

static int pkey_dsa_copy(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src)
{
    DSA_PKEY_CTX *dctx, *sctx;
    if (!pkey_dsa_init(dst))
        return 0;
    sctx = src->data;
    dctx = dst->data;
    dctx->nbits = sctx->nbits;
    dctx->qbits = sctx->qbits;
    dctx->pmd = sctx->pmd;
    dctx->md = sctx->md;
    return 1;
}

static void pkey_dsa_cleanup(EVP_PKEY_CTX *ctx)
{
    DSA_PKEY_CTX *dctx = ctx->data;
    if (dctx)
        OPENSSL_free(dctx);
}

static int pkey_dsa_sign(EVP_PKEY_CTX *ctx, unsigned char *sig,
                         size_t *siglen, const unsigned char *tbs,
                         size_t tbslen)
{
    int ret, type;
    unsigned int sltmp;
    DSA_PKEY_CTX *dctx = ctx->data;
    DSA *dsa = ctx->pkey->pkey.dsa;

    if (dctx->md)
        type = EVP_MD_type(dctx->md);
    else
        type = NID_sha1;

    ret = DSA_sign(type, tbs, tbslen, sig, &sltmp, dsa);

    if (ret <= 0)
        return ret;
    *siglen = sltmp;
    return 1;
}

static int pkey_dsa_verify(EVP_PKEY_CTX *ctx,
                           const unsigned char *sig, size_t siglen,
                           const unsigned char *tbs, size_t tbslen)
{
    int ret, type;
    DSA_PKEY_CTX *dctx = ctx->data;
    DSA *dsa = ctx->pkey->pkey.dsa;

    if (dctx->md)
        type = EVP_MD_type(dctx->md);
    else
        type = NID_sha1;

    ret = DSA_verify(type, tbs, tbslen, sig, siglen, dsa);

    return ret;
}

static int pkey_dsa_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
    DSA_PKEY_CTX *dctx = ctx->data;
    switch (type) {
    case EVP_PKEY_CTRL_DSA_PARAMGEN_BITS:
        if (p1 < 256)
            return -2;
        dctx->nbits = p1;
        return 1;

    case EVP_PKEY_CTRL_DSA_PARAMGEN_Q_BITS:
        if (p1 != 160 && p1 != 224 && p1 && p1 != 256)
            return -2;
        dctx->qbits = p1;
        return 1;

    case EVP_PKEY_CTRL_DSA_PARAMGEN_MD:
        if (EVP_MD_type((const EVP_MD *)p2) != NID_sha1 &&
            EVP_MD_type((const EVP_MD *)p2) != NID_sha224 &&
            EVP_MD_type((const EVP_MD *)p2) != NID_sha256) {
            DSAerr(DSA_F_PKEY_DSA_CTRL, DSA_R_INVALID_DIGEST_TYPE);
            return 0;
        }
        dctx->pmd = p2;
        return 1;

    case EVP_PKEY_CTRL_MD:
        if (EVP_MD_type((const EVP_MD *)p2) != NID_sha1 &&
            EVP_MD_type((const EVP_MD *)p2) != NID_dsa &&
            EVP_MD_type((const EVP_MD *)p2) != NID_dsaWithSHA &&
            EVP_MD_type((const EVP_MD *)p2) != NID_sha224 &&
            EVP_MD_type((const EVP_MD *)p2) != NID_sha256 &&
            EVP_MD_type((const EVP_MD *)p2) != NID_sha384 &&
            EVP_MD_type((const EVP_MD *)p2) != NID_sha512) {
            DSAerr(DSA_F_PKEY_DSA_CTRL, DSA_R_INVALID_DIGEST_TYPE);
            return 0;
        }
        dctx->md = p2;
        return 1;

    case EVP_PKEY_CTRL_GET_MD:
        *(const EVP_MD **)p2 = dctx->md;
        return 1;

    case EVP_PKEY_CTRL_DIGESTINIT:
    case EVP_PKEY_CTRL_PKCS7_SIGN:
    case EVP_PKEY_CTRL_CMS_SIGN:
        return 1;

    case EVP_PKEY_CTRL_PEER_KEY:
        DSAerr(DSA_F_PKEY_DSA_CTRL,
               EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        return -2;
    default:
        return -2;

    }
}

static int pkey_dsa_ctrl_str(EVP_PKEY_CTX *ctx,
                             const char *type, const char *value)
{
    if (!strcmp(type, "dsa_paramgen_bits")) {
        int nbits;
        nbits = atoi(value);
        return EVP_PKEY_CTX_set_dsa_paramgen_bits(ctx, nbits);
    }
    if (!strcmp(type, "dsa_paramgen_q_bits")) {
        int qbits = atoi(value);
        return EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DSA, EVP_PKEY_OP_PARAMGEN,
                                 EVP_PKEY_CTRL_DSA_PARAMGEN_Q_BITS, qbits,
                                 NULL);
    }
    if (strcmp(type, "dsa_paramgen_md") == 0) {
        const EVP_MD *md = EVP_get_digestbyname(value);

        if (md == NULL) {
            DSAerr(DSA_F_PKEY_DSA_CTRL_STR, DSA_R_INVALID_DIGEST_TYPE);
            return 0;
        }
        return EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DSA, EVP_PKEY_OP_PARAMGEN,
                                 EVP_PKEY_CTRL_DSA_PARAMGEN_MD, 0,
                                 (void *)md);
    }
    return -2;
}

static int pkey_dsa_paramgen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    DSA *dsa = NULL;
    DSA_PKEY_CTX *dctx = ctx->data;
    BN_GENCB *pcb, cb;
    int ret;
    if (ctx->pkey_gencb) {
        pcb = &cb;
        evp_pkey_set_cb_translate(pcb, ctx);
    } else
        pcb = NULL;
    dsa = DSA_new();
    if (!dsa)
        return 0;
    ret = dsa_builtin_paramgen(dsa, dctx->nbits, dctx->qbits, dctx->pmd,
                               NULL, 0, NULL, NULL, NULL, pcb);
    if (ret)
        EVP_PKEY_assign_DSA(pkey, dsa);
    else
        DSA_free(dsa);
    return ret;
}

static int pkey_dsa_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    DSA *dsa = NULL;
    if (ctx->pkey == NULL) {
        DSAerr(DSA_F_PKEY_DSA_KEYGEN, DSA_R_NO_PARAMETERS_SET);
        return 0;
    }
    dsa = DSA_new();
    if (!dsa)
        return 0;
    EVP_PKEY_assign_DSA(pkey, dsa);
    /* Note: if error return, pkey is freed by parent routine */
    if (!EVP_PKEY_copy_parameters(pkey, ctx->pkey))
        return 0;
    return DSA_generate_key(pkey->pkey.dsa);
}

const EVP_PKEY_METHOD dsa_pkey_meth = {
    EVP_PKEY_DSA,
    EVP_PKEY_FLAG_AUTOARGLEN,
    pkey_dsa_init,
    pkey_dsa_copy,
    pkey_dsa_cleanup,

    0,
    pkey_dsa_paramgen,

    0,
    pkey_dsa_keygen,

    0,
    pkey_dsa_sign,

    0,
    pkey_dsa_verify,

    0, 0,

    0, 0, 0, 0,

    0, 0,

    0, 0,

    0, 0,

    pkey_dsa_ctrl,
    pkey_dsa_ctrl_str
};
/* crypto/dsa/dsa_prn.c */
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
// #include "evp.h"
// #include "dsa.h"

#ifndef OPENSSL_NO_FP_API
int DSA_print_fp(FILE *fp, const DSA *x, int off)
{
    BIO *b;
    int ret;

    if ((b = BIO_new(BIO_s_file())) == NULL) {
        DSAerr(DSA_F_DSA_PRINT_FP, ERR_R_BUF_LIB);
        return (0);
    }
    BIO_set_fp(b, fp, BIO_NOCLOSE);
    ret = DSA_print(b, x, off);
    BIO_free(b);
    return (ret);
}

int DSAparams_print_fp(FILE *fp, const DSA *x)
{
    BIO *b;
    int ret;

    if ((b = BIO_new(BIO_s_file())) == NULL) {
        DSAerr(DSA_F_DSAPARAMS_PRINT_FP, ERR_R_BUF_LIB);
        return (0);
    }
    BIO_set_fp(b, fp, BIO_NOCLOSE);
    ret = DSAparams_print(b, x);
    BIO_free(b);
    return (ret);
}
#endif

int DSA_print(BIO *bp, const DSA *x, int off)
{
    EVP_PKEY *pk;
    int ret;
    pk = EVP_PKEY_new();
    if (!pk || !EVP_PKEY_set1_DSA(pk, (DSA *)x))
        return 0;
    ret = EVP_PKEY_print_private(bp, pk, off, NULL);
    EVP_PKEY_free(pk);
    return ret;
}

int DSAparams_print(BIO *bp, const DSA *x)
{
    EVP_PKEY *pk;
    int ret;
    pk = EVP_PKEY_new();
    if (!pk || !EVP_PKEY_set1_DSA(pk, (DSA *)x))
        return 0;
    ret = EVP_PKEY_print_params(bp, pk, 4, NULL);
    EVP_PKEY_free(pk);
    return ret;
}
/* crypto/dsa/dsa_sign.c */
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

/* Original version from Steven Schoch <schoch@sheba.arc.nasa.gov> */

// #include "cryptlib.h"
// #include "dsa.h"
// #include "rand.h"
// #include "bn.h"

DSA_SIG *DSA_do_sign(const unsigned char *dgst, int dlen, DSA *dsa)
{
#ifdef OPENSSL_FIPS
    if (FIPS_mode() && !(dsa->meth->flags & DSA_FLAG_FIPS_METHOD)
        && !(dsa->flags & DSA_FLAG_NON_FIPS_ALLOW)) {
        DSAerr(DSA_F_DSA_DO_SIGN, DSA_R_NON_FIPS_DSA_METHOD);
        return NULL;
    }
#endif
    return dsa->meth->dsa_do_sign(dgst, dlen, dsa);
}

int DSA_sign_setup(DSA *dsa, BN_CTX *ctx_in, BIGNUM **kinvp, BIGNUM **rp)
{
#ifdef OPENSSL_FIPS
    if (FIPS_mode() && !(dsa->meth->flags & DSA_FLAG_FIPS_METHOD)
        && !(dsa->flags & DSA_FLAG_NON_FIPS_ALLOW)) {
        DSAerr(DSA_F_DSA_SIGN_SETUP, DSA_R_NON_FIPS_DSA_METHOD);
        return 0;
    }
#endif
    return dsa->meth->dsa_sign_setup(dsa, ctx_in, kinvp, rp);
}

DSA_SIG *DSA_SIG_new(void)
{
    DSA_SIG *sig;
    sig = OPENSSL_malloc(sizeof(DSA_SIG));
    if (!sig)
        return NULL;
    sig->r = NULL;
    sig->s = NULL;
    return sig;
}

void DSA_SIG_free(DSA_SIG *sig)
{
    if (sig) {
        if (sig->r)
            BN_free(sig->r);
        if (sig->s)
            BN_free(sig->s);
        OPENSSL_free(sig);
    }
}
/* crypto/dsa/dsa_vrf.c */
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

/* Original version from Steven Schoch <schoch@sheba.arc.nasa.gov> */

// #include "cryptlib.h"
// #include "dsa.h"

int DSA_do_verify(const unsigned char *dgst, int dgst_len, DSA_SIG *sig,
                  DSA *dsa)
{
#ifdef OPENSSL_FIPS
    if (FIPS_mode() && !(dsa->meth->flags & DSA_FLAG_FIPS_METHOD)
        && !(dsa->flags & DSA_FLAG_NON_FIPS_ALLOW)) {
        DSAerr(DSA_F_DSA_DO_VERIFY, DSA_R_NON_FIPS_DSA_METHOD);
        return -1;
    }
#endif
    return dsa->meth->dsa_do_verify(dgst, dgst_len, sig, dsa);
}
