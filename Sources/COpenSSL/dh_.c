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
#include "dh.h"
#include "bn.h"
#include "asn1_locl.h"
#ifndef OPENSSL_NO_CMS
# include "cms.h"
#endif

extern const EVP_PKEY_ASN1_METHOD dhx_asn1_meth;

/*
 * i2d/d2i like DH parameter functions which use the appropriate routine for
 * PKCS#3 DH or X9.42 DH.
 */

static DH *d2i_dhp(const EVP_PKEY *pkey, const unsigned char **pp,
                   long length)
{
    if (pkey->ameth == &dhx_asn1_meth)
        return d2i_DHxparams(NULL, pp, length);
    return d2i_DHparams(NULL, pp, length);
}

static int i2d_dhp(const EVP_PKEY *pkey, const DH *a, unsigned char **pp)
{
    if (pkey->ameth == &dhx_asn1_meth)
        return i2d_DHxparams(a, pp);
    return i2d_DHparams(a, pp);
}

static void int_dh_free(EVP_PKEY *pkey)
{
    DH_free(pkey->pkey.dh);
}

static int dh_pub_decode(EVP_PKEY *pkey, X509_PUBKEY *pubkey)
{
    const unsigned char *p, *pm;
    int pklen, pmlen;
    int ptype;
    void *pval;
    ASN1_STRING *pstr;
    X509_ALGOR *palg;
    ASN1_INTEGER *public_key = NULL;

    DH *dh = NULL;

    if (!X509_PUBKEY_get0_param(NULL, &p, &pklen, &palg, pubkey))
        return 0;
    X509_ALGOR_get0(NULL, &ptype, &pval, palg);

    if (ptype != V_ASN1_SEQUENCE) {
        DHerr(DH_F_DH_PUB_DECODE, DH_R_PARAMETER_ENCODING_ERROR);
        goto err;
    }

    pstr = pval;
    pm = pstr->data;
    pmlen = pstr->length;

    if (!(dh = d2i_dhp(pkey, &pm, pmlen))) {
        DHerr(DH_F_DH_PUB_DECODE, DH_R_DECODE_ERROR);
        goto err;
    }

    if (!(public_key = d2i_ASN1_INTEGER(NULL, &p, pklen))) {
        DHerr(DH_F_DH_PUB_DECODE, DH_R_DECODE_ERROR);
        goto err;
    }

    /* We have parameters now set public key */
    if (!(dh->pub_key = ASN1_INTEGER_to_BN(public_key, NULL))) {
        DHerr(DH_F_DH_PUB_DECODE, DH_R_BN_DECODE_ERROR);
        goto err;
    }

    ASN1_INTEGER_free(public_key);
    EVP_PKEY_assign(pkey, pkey->ameth->pkey_id, dh);
    return 1;

 err:
    if (public_key)
        ASN1_INTEGER_free(public_key);
    if (dh)
        DH_free(dh);
    return 0;

}

static int dh_pub_encode(X509_PUBKEY *pk, const EVP_PKEY *pkey)
{
    DH *dh;
    int ptype;
    unsigned char *penc = NULL;
    int penclen;
    ASN1_STRING *str;
    ASN1_INTEGER *pub_key = NULL;

    dh = pkey->pkey.dh;

    str = ASN1_STRING_new();
    if (!str) {
        DHerr(DH_F_DH_PUB_ENCODE, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    str->length = i2d_dhp(pkey, dh, &str->data);
    if (str->length <= 0) {
        DHerr(DH_F_DH_PUB_ENCODE, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    ptype = V_ASN1_SEQUENCE;

    pub_key = BN_to_ASN1_INTEGER(dh->pub_key, NULL);
    if (!pub_key)
        goto err;

    penclen = i2d_ASN1_INTEGER(pub_key, &penc);

    ASN1_INTEGER_free(pub_key);

    if (penclen <= 0) {
        DHerr(DH_F_DH_PUB_ENCODE, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (X509_PUBKEY_set0_param(pk, OBJ_nid2obj(pkey->ameth->pkey_id),
                               ptype, str, penc, penclen))
        return 1;

 err:
    if (penc)
        OPENSSL_free(penc);
    if (str)
        ASN1_STRING_free(str);

    return 0;
}

/*
 * PKCS#8 DH is defined in PKCS#11 of all places. It is similar to DH in that
 * the AlgorithmIdentifier contains the paramaters, the private key is
 * explcitly included and the pubkey must be recalculated.
 */

static int dh_priv_decode(EVP_PKEY *pkey, PKCS8_PRIV_KEY_INFO *p8)
{
    const unsigned char *p, *pm;
    int pklen, pmlen;
    int ptype;
    void *pval;
    ASN1_STRING *pstr;
    X509_ALGOR *palg;
    ASN1_INTEGER *privkey = NULL;

    DH *dh = NULL;

    if (!PKCS8_pkey_get0(NULL, &p, &pklen, &palg, p8))
        return 0;

    X509_ALGOR_get0(NULL, &ptype, &pval, palg);

    if (ptype != V_ASN1_SEQUENCE)
        goto decerr;

    if (!(privkey = d2i_ASN1_INTEGER(NULL, &p, pklen)))
        goto decerr;

    pstr = pval;
    pm = pstr->data;
    pmlen = pstr->length;
    if (!(dh = d2i_dhp(pkey, &pm, pmlen)))
        goto decerr;
    /* We have parameters now set private key */
    if (!(dh->priv_key = ASN1_INTEGER_to_BN(privkey, NULL))) {
        DHerr(DH_F_DH_PRIV_DECODE, DH_R_BN_ERROR);
        goto dherr;
    }
    /* Calculate public key */
    if (!DH_generate_key(dh))
        goto dherr;

    EVP_PKEY_assign(pkey, pkey->ameth->pkey_id, dh);

    ASN1_STRING_clear_free(privkey);

    return 1;

 decerr:
    DHerr(DH_F_DH_PRIV_DECODE, EVP_R_DECODE_ERROR);
 dherr:
    DH_free(dh);
    ASN1_STRING_clear_free(privkey);
    return 0;
}

static int dh_priv_encode(PKCS8_PRIV_KEY_INFO *p8, const EVP_PKEY *pkey)
{
    ASN1_STRING *params = NULL;
    ASN1_INTEGER *prkey = NULL;
    unsigned char *dp = NULL;
    int dplen;

    params = ASN1_STRING_new();

    if (!params) {
        DHerr(DH_F_DH_PRIV_ENCODE, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    params->length = i2d_dhp(pkey, pkey->pkey.dh, &params->data);
    if (params->length <= 0) {
        DHerr(DH_F_DH_PRIV_ENCODE, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    params->type = V_ASN1_SEQUENCE;

    /* Get private key into integer */
    prkey = BN_to_ASN1_INTEGER(pkey->pkey.dh->priv_key, NULL);

    if (!prkey) {
        DHerr(DH_F_DH_PRIV_ENCODE, DH_R_BN_ERROR);
        goto err;
    }

    dplen = i2d_ASN1_INTEGER(prkey, &dp);

    ASN1_STRING_clear_free(prkey);
    prkey = NULL;

    if (!PKCS8_pkey_set0(p8, OBJ_nid2obj(pkey->ameth->pkey_id), 0,
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

static void update_buflen(const BIGNUM *b, size_t *pbuflen)
{
    size_t i;
    if (!b)
        return;
    if (*pbuflen < (i = (size_t)BN_num_bytes(b)))
        *pbuflen = i;
}

static int dh_param_decode(EVP_PKEY *pkey,
                           const unsigned char **pder, int derlen)
{
    DH *dh;
    if (!(dh = d2i_dhp(pkey, pder, derlen))) {
        DHerr(DH_F_DH_PARAM_DECODE, ERR_R_DH_LIB);
        return 0;
    }
    EVP_PKEY_assign(pkey, pkey->ameth->pkey_id, dh);
    return 1;
}

static int dh_param_encode(const EVP_PKEY *pkey, unsigned char **pder)
{
    return i2d_dhp(pkey, pkey->pkey.dh, pder);
}

static int do_dh_print(BIO *bp, const DH *x, int indent,
                       ASN1_PCTX *ctx, int ptype)
{
    unsigned char *m = NULL;
    int reason = ERR_R_BUF_LIB, ret = 0;
    size_t buf_len = 0;

    const char *ktype = NULL;

    BIGNUM *priv_key, *pub_key;

    if (ptype == 2)
        priv_key = x->priv_key;
    else
        priv_key = NULL;

    if (ptype > 0)
        pub_key = x->pub_key;
    else
        pub_key = NULL;

    update_buflen(x->p, &buf_len);

    if (buf_len == 0) {
        reason = ERR_R_PASSED_NULL_PARAMETER;
        goto err;
    }

    update_buflen(x->g, &buf_len);
    update_buflen(x->q, &buf_len);
    update_buflen(x->j, &buf_len);
    update_buflen(x->counter, &buf_len);
    update_buflen(pub_key, &buf_len);
    update_buflen(priv_key, &buf_len);

    if (ptype == 2)
        ktype = "DH Private-Key";
    else if (ptype == 1)
        ktype = "DH Public-Key";
    else
        ktype = "DH Parameters";

    m = OPENSSL_malloc(buf_len + 10);
    if (m == NULL) {
        reason = ERR_R_MALLOC_FAILURE;
        goto err;
    }

    BIO_indent(bp, indent, 128);
    if (BIO_printf(bp, "%s: (%d bit)\n", ktype, BN_num_bits(x->p)) <= 0)
        goto err;
    indent += 4;

    if (!ASN1_bn_print(bp, "private-key:", priv_key, m, indent))
        goto err;
    if (!ASN1_bn_print(bp, "public-key:", pub_key, m, indent))
        goto err;

    if (!ASN1_bn_print(bp, "prime:", x->p, m, indent))
        goto err;
    if (!ASN1_bn_print(bp, "generator:", x->g, m, indent))
        goto err;
    if (x->q && !ASN1_bn_print(bp, "subgroup order:", x->q, m, indent))
        goto err;
    if (x->j && !ASN1_bn_print(bp, "subgroup factor:", x->j, m, indent))
        goto err;
    if (x->seed) {
        int i;
        BIO_indent(bp, indent, 128);
        BIO_puts(bp, "seed:");
        for (i = 0; i < x->seedlen; i++) {
            if ((i % 15) == 0) {
                if (BIO_puts(bp, "\n") <= 0
                    || !BIO_indent(bp, indent + 4, 128))
                    goto err;
            }
            if (BIO_printf(bp, "%02x%s", x->seed[i],
                           ((i + 1) == x->seedlen) ? "" : ":") <= 0)
                goto err;
        }
        if (BIO_write(bp, "\n", 1) <= 0)
            return (0);
    }
    if (x->counter && !ASN1_bn_print(bp, "counter:", x->counter, m, indent))
        goto err;
    if (x->length != 0) {
        BIO_indent(bp, indent, 128);
        if (BIO_printf(bp, "recommended-private-length: %d bits\n",
                       (int)x->length) <= 0)
            goto err;
    }

    ret = 1;
    if (0) {
 err:
        DHerr(DH_F_DO_DH_PRINT, reason);
    }
    if (m != NULL)
        OPENSSL_free(m);
    return (ret);
}

static int int_dh_size(const EVP_PKEY *pkey)
{
    return (DH_size(pkey->pkey.dh));
}

static int dh_bits(const EVP_PKEY *pkey)
{
    return BN_num_bits(pkey->pkey.dh->p);
}

static int dh_cmp_parameters(const EVP_PKEY *a, const EVP_PKEY *b)
{
    if (BN_cmp(a->pkey.dh->p, b->pkey.dh->p) ||
        BN_cmp(a->pkey.dh->g, b->pkey.dh->g))
        return 0;
    else if (a->ameth == &dhx_asn1_meth) {
        if (BN_cmp(a->pkey.dh->q, b->pkey.dh->q))
            return 0;
    }
    return 1;
}

static int int_dh_bn_cpy(BIGNUM **dst, const BIGNUM *src)
{
    BIGNUM *a;
    if (src) {
        a = BN_dup(src);
        if (!a)
            return 0;
    } else
        a = NULL;
    if (*dst)
        BN_free(*dst);
    *dst = a;
    return 1;
}

static int int_dh_param_copy(DH *to, const DH *from, int is_x942)
{
    if (is_x942 == -1)
        is_x942 = ! !from->q;
    if (!int_dh_bn_cpy(&to->p, from->p))
        return 0;
    if (!int_dh_bn_cpy(&to->g, from->g))
        return 0;
    if (is_x942) {
        if (!int_dh_bn_cpy(&to->q, from->q))
            return 0;
        if (!int_dh_bn_cpy(&to->j, from->j))
            return 0;
        if (to->seed) {
            OPENSSL_free(to->seed);
            to->seed = NULL;
            to->seedlen = 0;
        }
        if (from->seed) {
            to->seed = BUF_memdup(from->seed, from->seedlen);
            if (!to->seed)
                return 0;
            to->seedlen = from->seedlen;
        }
    } else
        to->length = from->length;
    return 1;
}

DH *DHparams_dup(DH *dh)
{
    DH *ret;
    ret = DH_new();
    if (!ret)
        return NULL;
    if (!int_dh_param_copy(ret, dh, -1)) {
        DH_free(ret);
        return NULL;
    }
    return ret;
}

static int dh_copy_parameters(EVP_PKEY *to, const EVP_PKEY *from)
{
    return int_dh_param_copy(to->pkey.dh, from->pkey.dh,
                             from->ameth == &dhx_asn1_meth);
}

static int dh_missing_parameters(const EVP_PKEY *a)
{
    if (a->pkey.dh == NULL || a->pkey.dh->p == NULL || a->pkey.dh->g == NULL)
        return 1;
    return 0;
}

static int dh_pub_cmp(const EVP_PKEY *a, const EVP_PKEY *b)
{
    if (dh_cmp_parameters(a, b) == 0)
        return 0;
    if (BN_cmp(b->pkey.dh->pub_key, a->pkey.dh->pub_key) != 0)
        return 0;
    else
        return 1;
}

static int dh_param_print(BIO *bp, const EVP_PKEY *pkey, int indent,
                          ASN1_PCTX *ctx)
{
    return do_dh_print(bp, pkey->pkey.dh, indent, ctx, 0);
}

static int dh_public_print(BIO *bp, const EVP_PKEY *pkey, int indent,
                           ASN1_PCTX *ctx)
{
    return do_dh_print(bp, pkey->pkey.dh, indent, ctx, 1);
}

static int dh_private_print(BIO *bp, const EVP_PKEY *pkey, int indent,
                            ASN1_PCTX *ctx)
{
    return do_dh_print(bp, pkey->pkey.dh, indent, ctx, 2);
}

int DHparams_print(BIO *bp, const DH *x)
{
    return do_dh_print(bp, x, 4, NULL, 0);
}

#ifndef OPENSSL_NO_CMS
static int dh_cms_decrypt(CMS_RecipientInfo *ri);
static int dh_cms_encrypt(CMS_RecipientInfo *ri);
#endif

static int dh_pkey_ctrl(EVP_PKEY *pkey, int op, long arg1, void *arg2)
{
    switch (op) {
#ifndef OPENSSL_NO_CMS

    case ASN1_PKEY_CTRL_CMS_ENVELOPE:
        if (arg1 == 1)
            return dh_cms_decrypt(arg2);
        else if (arg1 == 0)
            return dh_cms_encrypt(arg2);
        return -2;

    case ASN1_PKEY_CTRL_CMS_RI_TYPE:
        *(int *)arg2 = CMS_RECIPINFO_AGREE;
        return 1;
#endif
    default:
        return -2;
    }

}

const EVP_PKEY_ASN1_METHOD dh_asn1_meth = {
    EVP_PKEY_DH,
    EVP_PKEY_DH,
    0,

    "DH",
    "OpenSSL PKCS#3 DH method",

    dh_pub_decode,
    dh_pub_encode,
    dh_pub_cmp,
    dh_public_print,

    dh_priv_decode,
    dh_priv_encode,
    dh_private_print,

    int_dh_size,
    dh_bits,

    dh_param_decode,
    dh_param_encode,
    dh_missing_parameters,
    dh_copy_parameters,
    dh_cmp_parameters,
    dh_param_print,
    0,

    int_dh_free,
    0
};

const EVP_PKEY_ASN1_METHOD dhx_asn1_meth = {
    EVP_PKEY_DHX,
    EVP_PKEY_DHX,
    0,

    "X9.42 DH",
    "OpenSSL X9.42 DH method",

    dh_pub_decode,
    dh_pub_encode,
    dh_pub_cmp,
    dh_public_print,

    dh_priv_decode,
    dh_priv_encode,
    dh_private_print,

    int_dh_size,
    dh_bits,

    dh_param_decode,
    dh_param_encode,
    dh_missing_parameters,
    dh_copy_parameters,
    dh_cmp_parameters,
    dh_param_print,
    0,

    int_dh_free,
    dh_pkey_ctrl
};

#ifndef OPENSSL_NO_CMS

static int dh_cms_set_peerkey(EVP_PKEY_CTX *pctx,
                              X509_ALGOR *alg, ASN1_BIT_STRING *pubkey)
{
    ASN1_OBJECT *aoid;
    int atype;
    void *aval;
    ASN1_INTEGER *public_key = NULL;
    int rv = 0;
    EVP_PKEY *pkpeer = NULL, *pk = NULL;
    DH *dhpeer = NULL;
    const unsigned char *p;
    int plen;

    X509_ALGOR_get0(&aoid, &atype, &aval, alg);
    if (OBJ_obj2nid(aoid) != NID_dhpublicnumber)
        goto err;
    /* Only absent parameters allowed in RFC XXXX */
    if (atype != V_ASN1_UNDEF && atype == V_ASN1_NULL)
        goto err;

    pk = EVP_PKEY_CTX_get0_pkey(pctx);
    if (!pk)
        goto err;
    if (pk->type != EVP_PKEY_DHX)
        goto err;
    /* Get parameters from parent key */
    dhpeer = DHparams_dup(pk->pkey.dh);
    /* We have parameters now set public key */
    plen = ASN1_STRING_length(pubkey);
    p = ASN1_STRING_data(pubkey);
    if (!p || !plen)
        goto err;

    if (!(public_key = d2i_ASN1_INTEGER(NULL, &p, plen))) {
        DHerr(DH_F_DH_CMS_SET_PEERKEY, DH_R_DECODE_ERROR);
        goto err;
    }

    /* We have parameters now set public key */
    if (!(dhpeer->pub_key = ASN1_INTEGER_to_BN(public_key, NULL))) {
        DHerr(DH_F_DH_CMS_SET_PEERKEY, DH_R_BN_DECODE_ERROR);
        goto err;
    }

    pkpeer = EVP_PKEY_new();
    if (!pkpeer)
        goto err;
    EVP_PKEY_assign(pkpeer, pk->ameth->pkey_id, dhpeer);
    dhpeer = NULL;
    if (EVP_PKEY_derive_set_peer(pctx, pkpeer) > 0)
        rv = 1;
 err:
    if (public_key)
        ASN1_INTEGER_free(public_key);
    if (pkpeer)
        EVP_PKEY_free(pkpeer);
    if (dhpeer)
        DH_free(dhpeer);
    return rv;
}

static int dh_cms_set_shared_info(EVP_PKEY_CTX *pctx, CMS_RecipientInfo *ri)
{
    int rv = 0;

    X509_ALGOR *alg, *kekalg = NULL;
    ASN1_OCTET_STRING *ukm;
    const unsigned char *p;
    unsigned char *dukm = NULL;
    size_t dukmlen = 0;
    int keylen, plen;
    const EVP_CIPHER *kekcipher;
    EVP_CIPHER_CTX *kekctx;

    if (!CMS_RecipientInfo_kari_get0_alg(ri, &alg, &ukm))
        goto err;

    /*
     * For DH we only have one OID permissible. If ever any more get defined
     * we will need something cleverer.
     */
    if (OBJ_obj2nid(alg->algorithm) != NID_id_smime_alg_ESDH) {
        DHerr(DH_F_DH_CMS_SET_SHARED_INFO, DH_R_KDF_PARAMETER_ERROR);
        goto err;
    }

    if (EVP_PKEY_CTX_set_dh_kdf_type(pctx, EVP_PKEY_DH_KDF_X9_42) <= 0)
        goto err;

    if (EVP_PKEY_CTX_set_dh_kdf_md(pctx, EVP_sha1()) <= 0)
        goto err;

    if (alg->parameter->type != V_ASN1_SEQUENCE)
        goto err;

    p = alg->parameter->value.sequence->data;
    plen = alg->parameter->value.sequence->length;
    kekalg = d2i_X509_ALGOR(NULL, &p, plen);
    if (!kekalg)
        goto err;
    kekctx = CMS_RecipientInfo_kari_get0_ctx(ri);
    if (!kekctx)
        goto err;
    kekcipher = EVP_get_cipherbyobj(kekalg->algorithm);
    if (!kekcipher || EVP_CIPHER_mode(kekcipher) != EVP_CIPH_WRAP_MODE)
        goto err;
    if (!EVP_EncryptInit_ex(kekctx, kekcipher, NULL, NULL, NULL))
        goto err;
    if (EVP_CIPHER_asn1_to_param(kekctx, kekalg->parameter) <= 0)
        goto err;

    keylen = EVP_CIPHER_CTX_key_length(kekctx);
    if (EVP_PKEY_CTX_set_dh_kdf_outlen(pctx, keylen) <= 0)
        goto err;
    /* Use OBJ_nid2obj to ensure we use built in OID that isn't freed */
    if (EVP_PKEY_CTX_set0_dh_kdf_oid(pctx,
                                     OBJ_nid2obj(EVP_CIPHER_type(kekcipher)))
        <= 0)
        goto err;

    if (ukm) {
        dukmlen = ASN1_STRING_length(ukm);
        dukm = BUF_memdup(ASN1_STRING_data(ukm), dukmlen);
        if (!dukm)
            goto err;
    }

    if (EVP_PKEY_CTX_set0_dh_kdf_ukm(pctx, dukm, dukmlen) <= 0)
        goto err;
    dukm = NULL;

    rv = 1;
 err:
    if (kekalg)
        X509_ALGOR_free(kekalg);
    if (dukm)
        OPENSSL_free(dukm);
    return rv;
}

static int dh_cms_decrypt(CMS_RecipientInfo *ri)
{
    EVP_PKEY_CTX *pctx;
    pctx = CMS_RecipientInfo_get0_pkey_ctx(ri);
    if (!pctx)
        return 0;
    /* See if we need to set peer key */
    if (!EVP_PKEY_CTX_get0_peerkey(pctx)) {
        X509_ALGOR *alg;
        ASN1_BIT_STRING *pubkey;
        if (!CMS_RecipientInfo_kari_get0_orig_id(ri, &alg, &pubkey,
                                                 NULL, NULL, NULL))
            return 0;
        if (!alg || !pubkey)
            return 0;
        if (!dh_cms_set_peerkey(pctx, alg, pubkey)) {
            DHerr(DH_F_DH_CMS_DECRYPT, DH_R_PEER_KEY_ERROR);
            return 0;
        }
    }
    /* Set DH derivation parameters and initialise unwrap context */
    if (!dh_cms_set_shared_info(pctx, ri)) {
        DHerr(DH_F_DH_CMS_DECRYPT, DH_R_SHARED_INFO_ERROR);
        return 0;
    }
    return 1;
}

static int dh_cms_encrypt(CMS_RecipientInfo *ri)
{
    EVP_PKEY_CTX *pctx;
    EVP_PKEY *pkey;
    EVP_CIPHER_CTX *ctx;
    int keylen;
    X509_ALGOR *talg, *wrap_alg = NULL;
    ASN1_OBJECT *aoid;
    ASN1_BIT_STRING *pubkey;
    ASN1_STRING *wrap_str;
    ASN1_OCTET_STRING *ukm;
    unsigned char *penc = NULL, *dukm = NULL;
    int penclen;
    size_t dukmlen = 0;
    int rv = 0;
    int kdf_type, wrap_nid;
    const EVP_MD *kdf_md;
    pctx = CMS_RecipientInfo_get0_pkey_ctx(ri);
    if (!pctx)
        return 0;
    /* Get ephemeral key */
    pkey = EVP_PKEY_CTX_get0_pkey(pctx);
    if (!CMS_RecipientInfo_kari_get0_orig_id(ri, &talg, &pubkey,
                                             NULL, NULL, NULL))
        goto err;
    X509_ALGOR_get0(&aoid, NULL, NULL, talg);
    /* Is everything uninitialised? */
    if (aoid == OBJ_nid2obj(NID_undef)) {
        ASN1_INTEGER *pubk;
        pubk = BN_to_ASN1_INTEGER(pkey->pkey.dh->pub_key, NULL);
        if (!pubk)
            goto err;
        /* Set the key */

        penclen = i2d_ASN1_INTEGER(pubk, &penc);
        ASN1_INTEGER_free(pubk);
        if (penclen <= 0)
            goto err;
        ASN1_STRING_set0(pubkey, penc, penclen);
        pubkey->flags &= ~(ASN1_STRING_FLAG_BITS_LEFT | 0x07);
        pubkey->flags |= ASN1_STRING_FLAG_BITS_LEFT;

        penc = NULL;
        X509_ALGOR_set0(talg, OBJ_nid2obj(NID_dhpublicnumber),
                        V_ASN1_UNDEF, NULL);
    }

    /* See if custom paraneters set */
    kdf_type = EVP_PKEY_CTX_get_dh_kdf_type(pctx);
    if (kdf_type <= 0)
        goto err;
    if (!EVP_PKEY_CTX_get_dh_kdf_md(pctx, &kdf_md))
        goto err;

    if (kdf_type == EVP_PKEY_DH_KDF_NONE) {
        kdf_type = EVP_PKEY_DH_KDF_X9_42;
        if (EVP_PKEY_CTX_set_dh_kdf_type(pctx, kdf_type) <= 0)
            goto err;
    } else if (kdf_type != EVP_PKEY_DH_KDF_X9_42)
        /* Unknown KDF */
        goto err;
    if (kdf_md == NULL) {
        /* Only SHA1 supported */
        kdf_md = EVP_sha1();
        if (EVP_PKEY_CTX_set_dh_kdf_md(pctx, kdf_md) <= 0)
            goto err;
    } else if (EVP_MD_type(kdf_md) != NID_sha1)
        /* Unsupported digest */
        goto err;

    if (!CMS_RecipientInfo_kari_get0_alg(ri, &talg, &ukm))
        goto err;

    /* Get wrap NID */
    ctx = CMS_RecipientInfo_kari_get0_ctx(ri);
    wrap_nid = EVP_CIPHER_CTX_type(ctx);
    if (EVP_PKEY_CTX_set0_dh_kdf_oid(pctx, OBJ_nid2obj(wrap_nid)) <= 0)
        goto err;
    keylen = EVP_CIPHER_CTX_key_length(ctx);

    /* Package wrap algorithm in an AlgorithmIdentifier */

    wrap_alg = X509_ALGOR_new();
    if (!wrap_alg)
        goto err;
    wrap_alg->algorithm = OBJ_nid2obj(wrap_nid);
    wrap_alg->parameter = ASN1_TYPE_new();
    if (!wrap_alg->parameter)
        goto err;
    if (EVP_CIPHER_param_to_asn1(ctx, wrap_alg->parameter) <= 0)
        goto err;
    if (ASN1_TYPE_get(wrap_alg->parameter) == NID_undef) {
        ASN1_TYPE_free(wrap_alg->parameter);
        wrap_alg->parameter = NULL;
    }

    if (EVP_PKEY_CTX_set_dh_kdf_outlen(pctx, keylen) <= 0)
        goto err;

    if (ukm) {
        dukmlen = ASN1_STRING_length(ukm);
        dukm = BUF_memdup(ASN1_STRING_data(ukm), dukmlen);
        if (!dukm)
            goto err;
    }

    if (EVP_PKEY_CTX_set0_dh_kdf_ukm(pctx, dukm, dukmlen) <= 0)
        goto err;
    dukm = NULL;

    /*
     * Now need to wrap encoding of wrap AlgorithmIdentifier into parameter
     * of another AlgorithmIdentifier.
     */
    penc = NULL;
    penclen = i2d_X509_ALGOR(wrap_alg, &penc);
    if (!penc || !penclen)
        goto err;
    wrap_str = ASN1_STRING_new();
    if (!wrap_str)
        goto err;
    ASN1_STRING_set0(wrap_str, penc, penclen);
    penc = NULL;
    X509_ALGOR_set0(talg, OBJ_nid2obj(NID_id_smime_alg_ESDH),
                    V_ASN1_SEQUENCE, wrap_str);

    rv = 1;

 err:
    if (penc)
        OPENSSL_free(penc);
    if (wrap_alg)
        X509_ALGOR_free(wrap_alg);
    return rv;
}

#endif
/* dh_asn1.c */
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
// #include "dh.h"
#include "objects.h"
#include "asn1t.h"

/* Override the default free and new methods */
static int dh_cb(int operation, ASN1_VALUE **pval, const ASN1_ITEM *it,
                 void *exarg)
{
    if (operation == ASN1_OP_NEW_PRE) {
        *pval = (ASN1_VALUE *)DH_new();
        if (*pval)
            return 2;
        return 0;
    } else if (operation == ASN1_OP_FREE_PRE) {
        DH_free((DH *)*pval);
        *pval = NULL;
        return 2;
    }
    return 1;
}

ASN1_SEQUENCE_cb(DHparams, dh_cb) = {
        ASN1_SIMPLE(DH, p, BIGNUM),
        ASN1_SIMPLE(DH, g, BIGNUM),
        ASN1_OPT(DH, length, ZLONG),
} ASN1_SEQUENCE_END_cb(DH, DHparams)

IMPLEMENT_ASN1_ENCODE_FUNCTIONS_const_fname(DH, DHparams, DHparams)

/*
 * Internal only structures for handling X9.42 DH: this gets translated to or
 * from a DH structure straight away.
 */

typedef struct {
    ASN1_BIT_STRING *seed;
    BIGNUM *counter;
} int_dhvparams;

typedef struct {
    BIGNUM *p;
    BIGNUM *q;
    BIGNUM *g;
    BIGNUM *j;
    int_dhvparams *vparams;
} int_dhx942_dh;

ASN1_SEQUENCE(DHvparams) = {
        ASN1_SIMPLE(int_dhvparams, seed, ASN1_BIT_STRING),
        ASN1_SIMPLE(int_dhvparams, counter, BIGNUM)
} ASN1_SEQUENCE_END_name(int_dhvparams, DHvparams)

ASN1_SEQUENCE(DHxparams) = {
        ASN1_SIMPLE(int_dhx942_dh, p, BIGNUM),
        ASN1_SIMPLE(int_dhx942_dh, g, BIGNUM),
        ASN1_SIMPLE(int_dhx942_dh, q, BIGNUM),
        ASN1_OPT(int_dhx942_dh, j, BIGNUM),
        ASN1_OPT(int_dhx942_dh, vparams, DHvparams),
} ASN1_SEQUENCE_END_name(int_dhx942_dh, DHxparams)

int_dhx942_dh *d2i_int_dhx(int_dhx942_dh **a,
                           const unsigned char **pp, long length);
int i2d_int_dhx(const int_dhx942_dh *a, unsigned char **pp);

IMPLEMENT_ASN1_ENCODE_FUNCTIONS_const_fname(int_dhx942_dh, DHxparams, int_dhx)

/* Application leve function: read in X9.42 DH parameters into DH structure */

DH *d2i_DHxparams(DH **a, const unsigned char **pp, long length)
{
    int_dhx942_dh *dhx = NULL;
    DH *dh = NULL;
    dh = DH_new();
    if (!dh)
        return NULL;
    dhx = d2i_int_dhx(NULL, pp, length);
    if (!dhx) {
        DH_free(dh);
        return NULL;
    }

    if (a) {
        if (*a)
            DH_free(*a);
        *a = dh;
    }

    dh->p = dhx->p;
    dh->q = dhx->q;
    dh->g = dhx->g;
    dh->j = dhx->j;

    if (dhx->vparams) {
        dh->seed = dhx->vparams->seed->data;
        dh->seedlen = dhx->vparams->seed->length;
        dh->counter = dhx->vparams->counter;
        dhx->vparams->seed->data = NULL;
        ASN1_BIT_STRING_free(dhx->vparams->seed);
        OPENSSL_free(dhx->vparams);
        dhx->vparams = NULL;
    }

    OPENSSL_free(dhx);
    return dh;
}

int i2d_DHxparams(const DH *dh, unsigned char **pp)
{
    int_dhx942_dh dhx;
    int_dhvparams dhv;
    ASN1_BIT_STRING bs;
    dhx.p = dh->p;
    dhx.g = dh->g;
    dhx.q = dh->q;
    dhx.j = dh->j;
    if (dh->counter && dh->seed && dh->seedlen > 0) {
        bs.flags = ASN1_STRING_FLAG_BITS_LEFT;
        bs.data = dh->seed;
        bs.length = dh->seedlen;
        dhv.seed = &bs;
        dhv.counter = dh->counter;
        dhx.vparams = &dhv;
    } else
        dhx.vparams = NULL;

    return i2d_int_dhx(&dhx, pp);
}
/* crypto/dh/dh_check.c */
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
// #include "dh.h"

/*-
 * Check that p is a safe prime and
 * if g is 2, 3 or 5, check that it is a suitable generator
 * where
 * for 2, p mod 24 == 11
 * for 3, p mod 12 == 5
 * for 5, p mod 10 == 3 or 7
 * should hold.
 */

int DH_check(const DH *dh, int *ret)
{
    int ok = 0;
    BN_CTX *ctx = NULL;
    BN_ULONG l;
    BIGNUM *t1 = NULL, *t2 = NULL;

    *ret = 0;
    ctx = BN_CTX_new();
    if (ctx == NULL)
        goto err;
    BN_CTX_start(ctx);
    t1 = BN_CTX_get(ctx);
    if (t1 == NULL)
        goto err;
    t2 = BN_CTX_get(ctx);
    if (t2 == NULL)
        goto err;

    if (dh->q) {
        if (BN_cmp(dh->g, BN_value_one()) <= 0)
            *ret |= DH_NOT_SUITABLE_GENERATOR;
        else if (BN_cmp(dh->g, dh->p) >= 0)
            *ret |= DH_NOT_SUITABLE_GENERATOR;
        else {
            /* Check g^q == 1 mod p */
            if (!BN_mod_exp(t1, dh->g, dh->q, dh->p, ctx))
                goto err;
            if (!BN_is_one(t1))
                *ret |= DH_NOT_SUITABLE_GENERATOR;
        }
        if (!BN_is_prime_ex(dh->q, BN_prime_checks, ctx, NULL))
            *ret |= DH_CHECK_Q_NOT_PRIME;
        /* Check p == 1 mod q  i.e. q divides p - 1 */
        if (!BN_div(t1, t2, dh->p, dh->q, ctx))
            goto err;
        if (!BN_is_one(t2))
            *ret |= DH_CHECK_INVALID_Q_VALUE;
        if (dh->j && BN_cmp(dh->j, t1))
            *ret |= DH_CHECK_INVALID_J_VALUE;

    } else if (BN_is_word(dh->g, DH_GENERATOR_2)) {
        l = BN_mod_word(dh->p, 24);
        if (l != 11)
            *ret |= DH_NOT_SUITABLE_GENERATOR;
    }
#if 0
    else if (BN_is_word(dh->g, DH_GENERATOR_3)) {
        l = BN_mod_word(dh->p, 12);
        if (l != 5)
            *ret |= DH_NOT_SUITABLE_GENERATOR;
    }
#endif
    else if (BN_is_word(dh->g, DH_GENERATOR_5)) {
        l = BN_mod_word(dh->p, 10);
        if ((l != 3) && (l != 7))
            *ret |= DH_NOT_SUITABLE_GENERATOR;
    } else
        *ret |= DH_UNABLE_TO_CHECK_GENERATOR;

    if (!BN_is_prime_ex(dh->p, BN_prime_checks, ctx, NULL))
        *ret |= DH_CHECK_P_NOT_PRIME;
    else if (!dh->q) {
        if (!BN_rshift1(t1, dh->p))
            goto err;
        if (!BN_is_prime_ex(t1, BN_prime_checks, ctx, NULL))
            *ret |= DH_CHECK_P_NOT_SAFE_PRIME;
    }
    ok = 1;
 err:
    if (ctx != NULL) {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    return (ok);
}

int DH_check_pub_key(const DH *dh, const BIGNUM *pub_key, int *ret)
{
    int ok = 0;
    BIGNUM *tmp = NULL;
    BN_CTX *ctx = NULL;

    *ret = 0;
    ctx = BN_CTX_new();
    if (ctx == NULL)
        goto err;
    BN_CTX_start(ctx);
    tmp = BN_CTX_get(ctx);
    if (tmp == NULL || !BN_set_word(tmp, 1))
        goto err;
    if (BN_cmp(pub_key, tmp) <= 0)
        *ret |= DH_CHECK_PUBKEY_TOO_SMALL;
    if (BN_copy(tmp, dh->p) == NULL || !BN_sub_word(tmp, 1))
        goto err;
    if (BN_cmp(pub_key, tmp) >= 0)
        *ret |= DH_CHECK_PUBKEY_TOO_LARGE;

    if (dh->q != NULL) {
        /* Check pub_key^q == 1 mod p */
        if (!BN_mod_exp(tmp, pub_key, dh->q, dh->p, ctx))
            goto err;
        if (!BN_is_one(tmp))
            *ret |= DH_CHECK_PUBKEY_INVALID;
    }

    ok = 1;
 err:
    if (ctx != NULL) {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    return (ok);
}
/* crypto/dh/dh_depr.c */
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

/* This file contains deprecated functions as wrappers to the new ones */

#include <stdio.h>
// #include "cryptlib.h"
// #include "bn.h"
// #include "dh.h"

static void *dummy = &dummy;

#ifndef OPENSSL_NO_DEPRECATED
DH *DH_generate_parameters(int prime_len, int generator,
                           void (*callback) (int, int, void *), void *cb_arg)
{
    BN_GENCB cb;
    DH *ret = NULL;

    if ((ret = DH_new()) == NULL)
        return NULL;

    BN_GENCB_set_old(&cb, callback, cb_arg);

    if (DH_generate_parameters_ex(ret, prime_len, generator, &cb))
        return ret;
    DH_free(ret);
    return NULL;
}
#endif
/* crypto/dh/dh_err.c */
/* ====================================================================
 * Copyright (c) 1999-2013 The OpenSSL Project.  All rights reserved.
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
// #include "dh.h"

/* BEGIN ERROR CODES */
#ifndef OPENSSL_NO_ERR

# define ERR_FUNC(func) ERR_PACK(ERR_LIB_DH,func,0)
# define ERR_REASON(reason) ERR_PACK(ERR_LIB_DH,0,reason)

static ERR_STRING_DATA DH_str_functs[] = {
    {ERR_FUNC(DH_F_COMPUTE_KEY), "COMPUTE_KEY"},
    {ERR_FUNC(DH_F_DHPARAMS_PRINT_FP), "DHparams_print_fp"},
    {ERR_FUNC(DH_F_DH_BUILTIN_GENPARAMS), "DH_BUILTIN_GENPARAMS"},
    {ERR_FUNC(DH_F_DH_CMS_DECRYPT), "DH_CMS_DECRYPT"},
    {ERR_FUNC(DH_F_DH_CMS_SET_PEERKEY), "DH_CMS_SET_PEERKEY"},
    {ERR_FUNC(DH_F_DH_CMS_SET_SHARED_INFO), "DH_CMS_SET_SHARED_INFO"},
    {ERR_FUNC(DH_F_DH_COMPUTE_KEY), "DH_compute_key"},
    {ERR_FUNC(DH_F_DH_GENERATE_KEY), "DH_generate_key"},
    {ERR_FUNC(DH_F_DH_GENERATE_PARAMETERS_EX), "DH_generate_parameters_ex"},
    {ERR_FUNC(DH_F_DH_NEW_METHOD), "DH_new_method"},
    {ERR_FUNC(DH_F_DH_PARAM_DECODE), "DH_PARAM_DECODE"},
    {ERR_FUNC(DH_F_DH_PRIV_DECODE), "DH_PRIV_DECODE"},
    {ERR_FUNC(DH_F_DH_PRIV_ENCODE), "DH_PRIV_ENCODE"},
    {ERR_FUNC(DH_F_DH_PUB_DECODE), "DH_PUB_DECODE"},
    {ERR_FUNC(DH_F_DH_PUB_ENCODE), "DH_PUB_ENCODE"},
    {ERR_FUNC(DH_F_DO_DH_PRINT), "DO_DH_PRINT"},
    {ERR_FUNC(DH_F_GENERATE_KEY), "GENERATE_KEY"},
    {ERR_FUNC(DH_F_GENERATE_PARAMETERS), "GENERATE_PARAMETERS"},
    {ERR_FUNC(DH_F_PKEY_DH_DERIVE), "PKEY_DH_DERIVE"},
    {ERR_FUNC(DH_F_PKEY_DH_KEYGEN), "PKEY_DH_KEYGEN"},
    {0, NULL}
};

static ERR_STRING_DATA DH_str_reasons[] = {
    {ERR_REASON(DH_R_BAD_GENERATOR), "bad generator"},
    {ERR_REASON(DH_R_BN_DECODE_ERROR), "bn decode error"},
    {ERR_REASON(DH_R_BN_ERROR), "bn error"},
    {ERR_REASON(DH_R_DECODE_ERROR), "decode error"},
    {ERR_REASON(DH_R_INVALID_PUBKEY), "invalid public key"},
    {ERR_REASON(DH_R_KDF_PARAMETER_ERROR), "kdf parameter error"},
    {ERR_REASON(DH_R_KEYS_NOT_SET), "keys not set"},
    {ERR_REASON(DH_R_KEY_SIZE_TOO_SMALL), "key size too small"},
    {ERR_REASON(DH_R_MODULUS_TOO_LARGE), "modulus too large"},
    {ERR_REASON(DH_R_NON_FIPS_METHOD), "non fips method"},
    {ERR_REASON(DH_R_NO_PARAMETERS_SET), "no parameters set"},
    {ERR_REASON(DH_R_NO_PRIVATE_VALUE), "no private value"},
    {ERR_REASON(DH_R_PARAMETER_ENCODING_ERROR), "parameter encoding error"},
    {ERR_REASON(DH_R_PEER_KEY_ERROR), "peer key error"},
    {ERR_REASON(DH_R_SHARED_INFO_ERROR), "shared info error"},
    {0, NULL}
};

#endif

void ERR_load_DH_strings(void)
{
#ifndef OPENSSL_NO_ERR

    if (ERR_func_error_string(DH_str_functs[0].error) == NULL) {
        ERR_load_strings(0, DH_str_functs);
        ERR_load_strings(0, DH_str_reasons);
    }
#endif
}
/* crypto/dh/dh_gen.c */
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
 * NB: These functions have been upgraded - the previous prototypes are in
 * dh_depr.c as wrappers to these ones.  - Geoff
 */

#include <stdio.h>
// #include "cryptlib.h"
// #include "bn.h"
// #include "dh.h"

#ifdef OPENSSL_FIPS
# include <fips.h>
#endif

static int dh_builtin_genparams(DH *ret, int prime_len, int generator,
                                BN_GENCB *cb);

int DH_generate_parameters_ex(DH *ret, int prime_len, int generator,
                              BN_GENCB *cb)
{
#ifdef OPENSSL_FIPS
    if (FIPS_mode() && !(ret->meth->flags & DH_FLAG_FIPS_METHOD)
        && !(ret->flags & DH_FLAG_NON_FIPS_ALLOW)) {
        DHerr(DH_F_DH_GENERATE_PARAMETERS_EX, DH_R_NON_FIPS_METHOD);
        return 0;
    }
#endif
    if (ret->meth->generate_params)
        return ret->meth->generate_params(ret, prime_len, generator, cb);
#ifdef OPENSSL_FIPS
    if (FIPS_mode())
        return FIPS_dh_generate_parameters_ex(ret, prime_len, generator, cb);
#endif
    return dh_builtin_genparams(ret, prime_len, generator, cb);
}

/*-
 * We generate DH parameters as follows
 * find a prime q which is prime_len/2 bits long.
 * p=(2*q)+1 or (p-1)/2 = q
 * For this case, g is a generator if
 * g^((p-1)/q) mod p != 1 for values of q which are the factors of p-1.
 * Since the factors of p-1 are q and 2, we just need to check
 * g^2 mod p != 1 and g^q mod p != 1.
 *
 * Having said all that,
 * there is another special case method for the generators 2, 3 and 5.
 * for 2, p mod 24 == 11
 * for 3, p mod 12 == 5  <<<<< does not work for safe primes.
 * for 5, p mod 10 == 3 or 7
 *
 * Thanks to Phil Karn <karn@qualcomm.com> for the pointers about the
 * special generators and for answering some of my questions.
 *
 * I've implemented the second simple method :-).
 * Since DH should be using a safe prime (both p and q are prime),
 * this generator function can take a very very long time to run.
 */
/*
 * Actually there is no reason to insist that 'generator' be a generator.
 * It's just as OK (and in some sense better) to use a generator of the
 * order-q subgroup.
 */
static int dh_builtin_genparams(DH *ret, int prime_len, int generator,
                                BN_GENCB *cb)
{
    BIGNUM *t1, *t2;
    int g, ok = -1;
    BN_CTX *ctx = NULL;

    ctx = BN_CTX_new();
    if (ctx == NULL)
        goto err;
    BN_CTX_start(ctx);
    t1 = BN_CTX_get(ctx);
    t2 = BN_CTX_get(ctx);
    if (t1 == NULL || t2 == NULL)
        goto err;

    /* Make sure 'ret' has the necessary elements */
    if (!ret->p && ((ret->p = BN_new()) == NULL))
        goto err;
    if (!ret->g && ((ret->g = BN_new()) == NULL))
        goto err;

    if (generator <= 1) {
        DHerr(DH_F_DH_BUILTIN_GENPARAMS, DH_R_BAD_GENERATOR);
        goto err;
    }
    if (generator == DH_GENERATOR_2) {
        if (!BN_set_word(t1, 24))
            goto err;
        if (!BN_set_word(t2, 11))
            goto err;
        g = 2;
    }
#if 0                           /* does not work for safe primes */
    else if (generator == DH_GENERATOR_3) {
        if (!BN_set_word(t1, 12))
            goto err;
        if (!BN_set_word(t2, 5))
            goto err;
        g = 3;
    }
#endif
    else if (generator == DH_GENERATOR_5) {
        if (!BN_set_word(t1, 10))
            goto err;
        if (!BN_set_word(t2, 3))
            goto err;
        /*
         * BN_set_word(t3,7); just have to miss out on these ones :-(
         */
        g = 5;
    } else {
        /*
         * in the general case, don't worry if 'generator' is a generator or
         * not: since we are using safe primes, it will generate either an
         * order-q or an order-2q group, which both is OK
         */
        if (!BN_set_word(t1, 2))
            goto err;
        if (!BN_set_word(t2, 1))
            goto err;
        g = generator;
    }

    if (!BN_generate_prime_ex(ret->p, prime_len, 1, t1, t2, cb))
        goto err;
    if (!BN_GENCB_call(cb, 3, 0))
        goto err;
    if (!BN_set_word(ret->g, g))
        goto err;
    ok = 1;
 err:
    if (ok == -1) {
        DHerr(DH_F_DH_BUILTIN_GENPARAMS, ERR_R_BN_LIB);
        ok = 0;
    }

    if (ctx != NULL) {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    return ok;
}
/* crypto/dh/dh_kdf.c */
/*
 * Written by Stephen Henson for the OpenSSL project.
 */
/* ====================================================================
 * Copyright (c) 2013 The OpenSSL Project.  All rights reserved.
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
 */

#include "e_os.h"

#ifndef OPENSSL_NO_CMS
#include <string.h>
// #include "dh.h"
#include "evp.h"
// #include "asn1.h"
#include "cms.h"

/* Key derivation from X9.42/RFC2631 */

#define DH_KDF_MAX      (1L << 30)

/* Skip past an ASN1 structure: for OBJECT skip content octets too */

static int skip_asn1(unsigned char **pp, long *plen, int exptag)
{
    const unsigned char *q = *pp;
    int i, tag, xclass;
    long tmplen;
    i = ASN1_get_object(&q, &tmplen, &tag, &xclass, *plen);
    if (i & 0x80)
        return 0;
    if (tag != exptag || xclass != V_ASN1_UNIVERSAL)
        return 0;
    if (tag == V_ASN1_OBJECT)
        q += tmplen;
    *plen -= q - *pp;
    *pp = (unsigned char *)q;
    return 1;
}

/*
 * Encode the DH shared info structure, return an offset to the counter value
 * so we can update the structure without reencoding it.
 */

static int dh_sharedinfo_encode(unsigned char **pder, unsigned char **pctr,
                                ASN1_OBJECT *key_oid, size_t outlen,
                                const unsigned char *ukm, size_t ukmlen)
{
    unsigned char *p;
    int derlen;
    long tlen;
    /* "magic" value to check offset is sane */
    static unsigned char ctr[4] = { 0xF3, 0x17, 0x22, 0x53 };
    X509_ALGOR atmp;
    ASN1_OCTET_STRING ctr_oct, ukm_oct, *pukm_oct;
    ASN1_TYPE ctr_atype;
    if (ukmlen > DH_KDF_MAX || outlen > DH_KDF_MAX)
        return 0;
    ctr_oct.data = ctr;
    ctr_oct.length = 4;
    ctr_oct.flags = 0;
    ctr_oct.type = V_ASN1_OCTET_STRING;
    ctr_atype.type = V_ASN1_OCTET_STRING;
    ctr_atype.value.octet_string = &ctr_oct;
    atmp.algorithm = key_oid;
    atmp.parameter = &ctr_atype;
    if (ukm) {
        ukm_oct.type = V_ASN1_OCTET_STRING;
        ukm_oct.flags = 0;
        ukm_oct.data = (unsigned char *)ukm;
        ukm_oct.length = ukmlen;
        pukm_oct = &ukm_oct;
    } else
        pukm_oct = NULL;
    derlen = CMS_SharedInfo_encode(pder, &atmp, pukm_oct, outlen);
    if (derlen <= 0)
        return 0;
    p = *pder;
    tlen = derlen;
    if (!skip_asn1(&p, &tlen, V_ASN1_SEQUENCE))
        return 0;
    if (!skip_asn1(&p, &tlen, V_ASN1_SEQUENCE))
        return 0;
    if (!skip_asn1(&p, &tlen, V_ASN1_OBJECT))
        return 0;
    if (!skip_asn1(&p, &tlen, V_ASN1_OCTET_STRING))
        return 0;
    if (CRYPTO_memcmp(p, ctr, 4))
        return 0;
    *pctr = p;
    return derlen;
}

int DH_KDF_X9_42(unsigned char *out, size_t outlen,
                 const unsigned char *Z, size_t Zlen,
                 ASN1_OBJECT *key_oid,
                 const unsigned char *ukm, size_t ukmlen, const EVP_MD *md)
{
    EVP_MD_CTX mctx;
    int rv = 0;
    unsigned int i;
    size_t mdlen;
    unsigned char *der = NULL, *ctr;
    int derlen;
    if (Zlen > DH_KDF_MAX)
        return 0;
    mdlen = EVP_MD_size(md);
    EVP_MD_CTX_init(&mctx);
    derlen = dh_sharedinfo_encode(&der, &ctr, key_oid, outlen, ukm, ukmlen);
    if (derlen == 0)
        goto err;
    for (i = 1;; i++) {
        unsigned char mtmp[EVP_MAX_MD_SIZE];
        EVP_DigestInit_ex(&mctx, md, NULL);
        if (!EVP_DigestUpdate(&mctx, Z, Zlen))
            goto err;
        ctr[3] = i & 0xFF;
        ctr[2] = (i >> 8) & 0xFF;
        ctr[1] = (i >> 16) & 0xFF;
        ctr[0] = (i >> 24) & 0xFF;
        if (!EVP_DigestUpdate(&mctx, der, derlen))
            goto err;
        if (outlen >= mdlen) {
            if (!EVP_DigestFinal(&mctx, out, NULL))
                goto err;
            outlen -= mdlen;
            if (outlen == 0)
                break;
            out += mdlen;
        } else {
            if (!EVP_DigestFinal(&mctx, mtmp, NULL))
                goto err;
            memcpy(out, mtmp, outlen);
            OPENSSL_cleanse(mtmp, mdlen);
            break;
        }
    }
    rv = 1;
 err:
    if (der)
        OPENSSL_free(der);
    EVP_MD_CTX_cleanup(&mctx);
    return rv;
}
#endif
/* crypto/dh/dh_key.c */
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
#include "rand.h"
// #include "dh.h"

static int generate_key(DH *dh);
static int compute_key(unsigned char *key, const BIGNUM *pub_key, DH *dh);
static int dh_bn_mod_exp(const DH *dh, BIGNUM *r,
                         const BIGNUM *a, const BIGNUM *p,
                         const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx);
static int dh_init(DH *dh);
static int dh_finish(DH *dh);

int DH_generate_key(DH *dh)
{
#ifdef OPENSSL_FIPS
    if (FIPS_mode() && !(dh->meth->flags & DH_FLAG_FIPS_METHOD)
        && !(dh->flags & DH_FLAG_NON_FIPS_ALLOW)) {
        DHerr(DH_F_DH_GENERATE_KEY, DH_R_NON_FIPS_METHOD);
        return 0;
    }
#endif
    return dh->meth->generate_key(dh);
}

int DH_compute_key(unsigned char *key, const BIGNUM *pub_key, DH *dh)
{
#ifdef OPENSSL_FIPS
    if (FIPS_mode() && !(dh->meth->flags & DH_FLAG_FIPS_METHOD)
        && !(dh->flags & DH_FLAG_NON_FIPS_ALLOW)) {
        DHerr(DH_F_DH_COMPUTE_KEY, DH_R_NON_FIPS_METHOD);
        return 0;
    }
#endif
    return dh->meth->compute_key(key, pub_key, dh);
}

int DH_compute_key_padded(unsigned char *key, const BIGNUM *pub_key, DH *dh)
{
    int rv, pad;
    rv = dh->meth->compute_key(key, pub_key, dh);
    if (rv <= 0)
        return rv;
    pad = BN_num_bytes(dh->p) - rv;
    if (pad > 0) {
        memmove(key + pad, key, rv);
        memset(key, 0, pad);
    }
    return rv + pad;
}

static DH_METHOD dh_ossl = {
    "OpenSSL DH Method",
    generate_key,
    compute_key,
    dh_bn_mod_exp,
    dh_init,
    dh_finish,
    0,
    NULL,
    NULL
};

const DH_METHOD *DH_OpenSSL(void)
{
    return &dh_ossl;
}

static int generate_key(DH *dh)
{
    int ok = 0;
    int generate_new_key = 0;
    unsigned l;
    BN_CTX *ctx = NULL;
    BN_MONT_CTX *mont = NULL;
    BIGNUM *pub_key = NULL, *priv_key = NULL;

    if (BN_num_bits(dh->p) > OPENSSL_DH_MAX_MODULUS_BITS) {
        DHerr(DH_F_GENERATE_KEY, DH_R_MODULUS_TOO_LARGE);
        return 0;
    }

    ctx = BN_CTX_new();
    if (ctx == NULL)
        goto err;

    if (dh->priv_key == NULL) {
        priv_key = BN_new();
        if (priv_key == NULL)
            goto err;
        generate_new_key = 1;
    } else
        priv_key = dh->priv_key;

    if (dh->pub_key == NULL) {
        pub_key = BN_new();
        if (pub_key == NULL)
            goto err;
    } else
        pub_key = dh->pub_key;

    if (dh->flags & DH_FLAG_CACHE_MONT_P) {
        mont = BN_MONT_CTX_set_locked(&dh->method_mont_p,
                                      CRYPTO_LOCK_DH, dh->p, ctx);
        if (!mont)
            goto err;
    }

    if (generate_new_key) {
        if (dh->q) {
            do {
                if (!BN_rand_range(priv_key, dh->q))
                    goto err;
            }
            while (BN_is_zero(priv_key) || BN_is_one(priv_key));
        } else {
            /* secret exponent length */
            l = dh->length ? dh->length : BN_num_bits(dh->p) - 1;
            if (!BN_rand(priv_key, l, 0, 0))
                goto err;
        }
    }

    {
        BIGNUM local_prk;
        BIGNUM *prk;

        if ((dh->flags & DH_FLAG_NO_EXP_CONSTTIME) == 0) {
            BN_init(&local_prk);
            prk = &local_prk;
            BN_with_flags(prk, priv_key, BN_FLG_CONSTTIME);
        } else
            prk = priv_key;

        if (!dh->meth->bn_mod_exp(dh, pub_key, dh->g, prk, dh->p, ctx, mont))
            goto err;
    }

    dh->pub_key = pub_key;
    dh->priv_key = priv_key;
    ok = 1;
 err:
    if (ok != 1)
        DHerr(DH_F_GENERATE_KEY, ERR_R_BN_LIB);

    if ((pub_key != NULL) && (dh->pub_key == NULL))
        BN_free(pub_key);
    if ((priv_key != NULL) && (dh->priv_key == NULL))
        BN_free(priv_key);
    BN_CTX_free(ctx);
    return (ok);
}

static int compute_key(unsigned char *key, const BIGNUM *pub_key, DH *dh)
{
    BN_CTX *ctx = NULL;
    BN_MONT_CTX *mont = NULL;
    BIGNUM *tmp;
    int ret = -1;
    int check_result;

    if (BN_num_bits(dh->p) > OPENSSL_DH_MAX_MODULUS_BITS) {
        DHerr(DH_F_COMPUTE_KEY, DH_R_MODULUS_TOO_LARGE);
        goto err;
    }

    ctx = BN_CTX_new();
    if (ctx == NULL)
        goto err;
    BN_CTX_start(ctx);
    tmp = BN_CTX_get(ctx);
    if (tmp == NULL)
        goto err;

    if (dh->priv_key == NULL) {
        DHerr(DH_F_COMPUTE_KEY, DH_R_NO_PRIVATE_VALUE);
        goto err;
    }

    if (dh->flags & DH_FLAG_CACHE_MONT_P) {
        mont = BN_MONT_CTX_set_locked(&dh->method_mont_p,
                                      CRYPTO_LOCK_DH, dh->p, ctx);
        if ((dh->flags & DH_FLAG_NO_EXP_CONSTTIME) == 0) {
            /* XXX */
            BN_set_flags(dh->priv_key, BN_FLG_CONSTTIME);
        }
        if (!mont)
            goto err;
    }

    if (!DH_check_pub_key(dh, pub_key, &check_result) || check_result) {
        DHerr(DH_F_COMPUTE_KEY, DH_R_INVALID_PUBKEY);
        goto err;
    }

    if (!dh->
        meth->bn_mod_exp(dh, tmp, pub_key, dh->priv_key, dh->p, ctx, mont)) {
        DHerr(DH_F_COMPUTE_KEY, ERR_R_BN_LIB);
        goto err;
    }

    ret = BN_bn2bin(tmp, key);
 err:
    if (ctx != NULL) {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    return (ret);
}

static int dh_bn_mod_exp(const DH *dh, BIGNUM *r,
                         const BIGNUM *a, const BIGNUM *p,
                         const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx)
{
    /*
     * If a is only one word long and constant time is false, use the faster
     * exponenentiation function.
     */
    if (a->top == 1 && ((dh->flags & DH_FLAG_NO_EXP_CONSTTIME) != 0)) {
        BN_ULONG A = a->d[0];
        return BN_mod_exp_mont_word(r, A, p, m, ctx, m_ctx);
    } else
        return BN_mod_exp_mont(r, a, p, m, ctx, m_ctx);
}

static int dh_init(DH *dh)
{
    dh->flags |= DH_FLAG_CACHE_MONT_P;
    return (1);
}

static int dh_finish(DH *dh)
{
    if (dh->method_mont_p)
        BN_MONT_CTX_free(dh->method_mont_p);
    return (1);
}
/* crypto/dh/dh_lib.c */
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
// #include "dh.h"
#ifndef OPENSSL_NO_ENGINE
# include "engine.h"
#endif

#ifdef OPENSSL_FIPS
# include <fips.h>
#endif

const char DH_version[] = "Diffie-Hellman" OPENSSL_VERSION_PTEXT;

static const DH_METHOD *default_DH_method = NULL;

void DH_set_default_method(const DH_METHOD *meth)
{
    default_DH_method = meth;
}

const DH_METHOD *DH_get_default_method(void)
{
    if (!default_DH_method) {
#ifdef OPENSSL_FIPS
        if (FIPS_mode())
            return FIPS_dh_openssl();
        else
            return DH_OpenSSL();
#else
        default_DH_method = DH_OpenSSL();
#endif
    }
    return default_DH_method;
}

int DH_set_method(DH *dh, const DH_METHOD *meth)
{
    /*
     * NB: The caller is specifically setting a method, so it's not up to us
     * to deal with which ENGINE it comes from.
     */
    const DH_METHOD *mtmp;
    mtmp = dh->meth;
    if (mtmp->finish)
        mtmp->finish(dh);
#ifndef OPENSSL_NO_ENGINE
    if (dh->engine) {
        ENGINE_finish(dh->engine);
        dh->engine = NULL;
    }
#endif
    dh->meth = meth;
    if (meth->init)
        meth->init(dh);
    return 1;
}

DH *DH_new(void)
{
    return DH_new_method(NULL);
}

DH *DH_new_method(ENGINE *engine)
{
    DH *ret;

    ret = (DH *)OPENSSL_malloc(sizeof(DH));
    if (ret == NULL) {
        DHerr(DH_F_DH_NEW_METHOD, ERR_R_MALLOC_FAILURE);
        return (NULL);
    }

    ret->meth = DH_get_default_method();
#ifndef OPENSSL_NO_ENGINE
    if (engine) {
        if (!ENGINE_init(engine)) {
            DHerr(DH_F_DH_NEW_METHOD, ERR_R_ENGINE_LIB);
            OPENSSL_free(ret);
            return NULL;
        }
        ret->engine = engine;
    } else
        ret->engine = ENGINE_get_default_DH();
    if (ret->engine) {
        ret->meth = ENGINE_get_DH(ret->engine);
        if (!ret->meth) {
            DHerr(DH_F_DH_NEW_METHOD, ERR_R_ENGINE_LIB);
            ENGINE_finish(ret->engine);
            OPENSSL_free(ret);
            return NULL;
        }
    }
#endif

    ret->pad = 0;
    ret->version = 0;
    ret->p = NULL;
    ret->g = NULL;
    ret->length = 0;
    ret->pub_key = NULL;
    ret->priv_key = NULL;
    ret->q = NULL;
    ret->j = NULL;
    ret->seed = NULL;
    ret->seedlen = 0;
    ret->counter = NULL;
    ret->method_mont_p = NULL;
    ret->references = 1;
    ret->flags = ret->meth->flags & ~DH_FLAG_NON_FIPS_ALLOW;
    CRYPTO_new_ex_data(CRYPTO_EX_INDEX_DH, ret, &ret->ex_data);
    if ((ret->meth->init != NULL) && !ret->meth->init(ret)) {
#ifndef OPENSSL_NO_ENGINE
        if (ret->engine)
            ENGINE_finish(ret->engine);
#endif
        CRYPTO_free_ex_data(CRYPTO_EX_INDEX_DH, ret, &ret->ex_data);
        OPENSSL_free(ret);
        ret = NULL;
    }
    return (ret);
}

void DH_free(DH *r)
{
    int i;
    if (r == NULL)
        return;
    i = CRYPTO_add(&r->references, -1, CRYPTO_LOCK_DH);
#ifdef REF_PRINT
    REF_PRINT("DH", r);
#endif
    if (i > 0)
        return;
#ifdef REF_CHECK
    if (i < 0) {
        fprintf(stderr, "DH_free, bad reference count\n");
        abort();
    }
#endif

    if (r->meth->finish)
        r->meth->finish(r);
#ifndef OPENSSL_NO_ENGINE
    if (r->engine)
        ENGINE_finish(r->engine);
#endif

    CRYPTO_free_ex_data(CRYPTO_EX_INDEX_DH, r, &r->ex_data);

    if (r->p != NULL)
        BN_clear_free(r->p);
    if (r->g != NULL)
        BN_clear_free(r->g);
    if (r->q != NULL)
        BN_clear_free(r->q);
    if (r->j != NULL)
        BN_clear_free(r->j);
    if (r->seed)
        OPENSSL_free(r->seed);
    if (r->counter != NULL)
        BN_clear_free(r->counter);
    if (r->pub_key != NULL)
        BN_clear_free(r->pub_key);
    if (r->priv_key != NULL)
        BN_clear_free(r->priv_key);
    OPENSSL_free(r);
}

int DH_up_ref(DH *r)
{
    int i = CRYPTO_add(&r->references, 1, CRYPTO_LOCK_DH);
#ifdef REF_PRINT
    REF_PRINT("DH", r);
#endif
#ifdef REF_CHECK
    if (i < 2) {
        fprintf(stderr, "DH_up, bad reference count\n");
        abort();
    }
#endif
    return ((i > 1) ? 1 : 0);
}

int DH_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func,
                        CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func)
{
    return CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_DH, argl, argp,
                                   new_func, dup_func, free_func);
}

int DH_set_ex_data(DH *d, int idx, void *arg)
{
    return (CRYPTO_set_ex_data(&d->ex_data, idx, arg));
}

void *DH_get_ex_data(DH *d, int idx)
{
    return (CRYPTO_get_ex_data(&d->ex_data, idx));
}

int DH_size(const DH *dh)
{
    return (BN_num_bytes(dh->p));
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
// #include "evp.h"
// #include "dh.h"
// #include "bn.h"
#ifndef OPENSSL_NO_DSA
# include "dsa.h"
#endif
// #include "objects.h"
#include "evp_locl.h"

/* DH pkey context structure */

typedef struct {
    /* Parameter gen parameters */
    int prime_len;
    int generator;
    int use_dsa;
    int subprime_len;
    /* message digest used for parameter generation */
    const EVP_MD *md;
    int rfc5114_param;
    /* Keygen callback info */
    int gentmp[2];
    /* KDF (if any) to use for DH */
    char kdf_type;
    /* OID to use for KDF */
    ASN1_OBJECT *kdf_oid;
    /* Message digest to use for key derivation */
    const EVP_MD *kdf_md;
    /* User key material */
    unsigned char *kdf_ukm;
    size_t kdf_ukmlen;
    /* KDF output length */
    size_t kdf_outlen;
} DH_PKEY_CTX;

static int pkey_dh_init(EVP_PKEY_CTX *ctx)
{
    DH_PKEY_CTX *dctx;
    dctx = OPENSSL_malloc(sizeof(DH_PKEY_CTX));
    if (!dctx)
        return 0;
    dctx->prime_len = 1024;
    dctx->subprime_len = -1;
    dctx->generator = 2;
    dctx->use_dsa = 0;
    dctx->md = NULL;
    dctx->rfc5114_param = 0;

    dctx->kdf_type = EVP_PKEY_DH_KDF_NONE;
    dctx->kdf_oid = NULL;
    dctx->kdf_md = NULL;
    dctx->kdf_ukm = NULL;
    dctx->kdf_ukmlen = 0;
    dctx->kdf_outlen = 0;

    ctx->data = dctx;
    ctx->keygen_info = dctx->gentmp;
    ctx->keygen_info_count = 2;

    return 1;
}

static int pkey_dh_copy(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src)
{
    DH_PKEY_CTX *dctx, *sctx;
    if (!pkey_dh_init(dst))
        return 0;
    sctx = src->data;
    dctx = dst->data;
    dctx->prime_len = sctx->prime_len;
    dctx->subprime_len = sctx->subprime_len;
    dctx->generator = sctx->generator;
    dctx->use_dsa = sctx->use_dsa;
    dctx->md = sctx->md;
    dctx->rfc5114_param = sctx->rfc5114_param;

    dctx->kdf_type = sctx->kdf_type;
    dctx->kdf_oid = OBJ_dup(sctx->kdf_oid);
    if (!dctx->kdf_oid)
        return 0;
    dctx->kdf_md = sctx->kdf_md;
    if (dctx->kdf_ukm) {
        dctx->kdf_ukm = BUF_memdup(sctx->kdf_ukm, sctx->kdf_ukmlen);
        dctx->kdf_ukmlen = sctx->kdf_ukmlen;
    }
    dctx->kdf_outlen = sctx->kdf_outlen;
    return 1;
}

static void pkey_dh_cleanup(EVP_PKEY_CTX *ctx)
{
    DH_PKEY_CTX *dctx = ctx->data;
    if (dctx) {
        if (dctx->kdf_ukm)
            OPENSSL_free(dctx->kdf_ukm);
        if (dctx->kdf_oid)
            ASN1_OBJECT_free(dctx->kdf_oid);
        OPENSSL_free(dctx);
    }
}

static int pkey_dh_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
    DH_PKEY_CTX *dctx = ctx->data;
    switch (type) {
    case EVP_PKEY_CTRL_DH_PARAMGEN_PRIME_LEN:
        if (p1 < 256)
            return -2;
        dctx->prime_len = p1;
        return 1;

    case EVP_PKEY_CTRL_DH_PARAMGEN_SUBPRIME_LEN:
        if (dctx->use_dsa == 0)
            return -2;
        dctx->subprime_len = p1;
        return 1;

    case EVP_PKEY_CTRL_DH_PARAMGEN_GENERATOR:
        if (dctx->use_dsa)
            return -2;
        dctx->generator = p1;
        return 1;

    case EVP_PKEY_CTRL_DH_PARAMGEN_TYPE:
#ifdef OPENSSL_NO_DSA
        if (p1 != 0)
            return -2;
#else
        if (p1 < 0 || p1 > 2)
            return -2;
#endif
        dctx->use_dsa = p1;
        return 1;

    case EVP_PKEY_CTRL_DH_RFC5114:
        if (p1 < 1 || p1 > 3)
            return -2;
        dctx->rfc5114_param = p1;
        return 1;

    case EVP_PKEY_CTRL_PEER_KEY:
        /* Default behaviour is OK */
        return 1;

    case EVP_PKEY_CTRL_DH_KDF_TYPE:
        if (p1 == -2)
            return dctx->kdf_type;
#ifdef OPENSSL_NO_CMS
        if (p1 != EVP_PKEY_DH_KDF_NONE)
#else
        if (p1 != EVP_PKEY_DH_KDF_NONE && p1 != EVP_PKEY_DH_KDF_X9_42)
#endif
            return -2;
        dctx->kdf_type = p1;
        return 1;

    case EVP_PKEY_CTRL_DH_KDF_MD:
        dctx->kdf_md = p2;
        return 1;

    case EVP_PKEY_CTRL_GET_DH_KDF_MD:
        *(const EVP_MD **)p2 = dctx->kdf_md;
        return 1;

    case EVP_PKEY_CTRL_DH_KDF_OUTLEN:
        if (p1 <= 0)
            return -2;
        dctx->kdf_outlen = (size_t)p1;
        return 1;

    case EVP_PKEY_CTRL_GET_DH_KDF_OUTLEN:
        *(int *)p2 = dctx->kdf_outlen;
        return 1;

    case EVP_PKEY_CTRL_DH_KDF_UKM:
        if (dctx->kdf_ukm)
            OPENSSL_free(dctx->kdf_ukm);
        dctx->kdf_ukm = p2;
        if (p2)
            dctx->kdf_ukmlen = p1;
        else
            dctx->kdf_ukmlen = 0;
        return 1;

    case EVP_PKEY_CTRL_GET_DH_KDF_UKM:
        *(unsigned char **)p2 = dctx->kdf_ukm;
        return dctx->kdf_ukmlen;

    case EVP_PKEY_CTRL_DH_KDF_OID:
        if (dctx->kdf_oid)
            ASN1_OBJECT_free(dctx->kdf_oid);
        dctx->kdf_oid = p2;
        return 1;

    case EVP_PKEY_CTRL_GET_DH_KDF_OID:
        *(ASN1_OBJECT **)p2 = dctx->kdf_oid;
        return 1;

    default:
        return -2;

    }
}

static int pkey_dh_ctrl_str(EVP_PKEY_CTX *ctx,
                            const char *type, const char *value)
{
    if (!strcmp(type, "dh_paramgen_prime_len")) {
        int len;
        len = atoi(value);
        return EVP_PKEY_CTX_set_dh_paramgen_prime_len(ctx, len);
    }
    if (!strcmp(type, "dh_rfc5114")) {
        DH_PKEY_CTX *dctx = ctx->data;
        int len;
        len = atoi(value);
        if (len < 0 || len > 3)
            return -2;
        dctx->rfc5114_param = len;
        return 1;
    }
    if (!strcmp(type, "dh_paramgen_generator")) {
        int len;
        len = atoi(value);
        return EVP_PKEY_CTX_set_dh_paramgen_generator(ctx, len);
    }
    if (!strcmp(type, "dh_paramgen_subprime_len")) {
        int len;
        len = atoi(value);
        return EVP_PKEY_CTX_set_dh_paramgen_subprime_len(ctx, len);
    }
    if (!strcmp(type, "dh_paramgen_type")) {
        int typ;
        typ = atoi(value);
        return EVP_PKEY_CTX_set_dh_paramgen_type(ctx, typ);
    }
    return -2;
}

#ifndef OPENSSL_NO_DSA

extern int dsa_builtin_paramgen(DSA *ret, size_t bits, size_t qbits,
                                const EVP_MD *evpmd,
                                const unsigned char *seed_in, size_t seed_len,
                                unsigned char *seed_out, int *counter_ret,
                                unsigned long *h_ret, BN_GENCB *cb);

extern int dsa_builtin_paramgen2(DSA *ret, size_t L, size_t N,
                                 const EVP_MD *evpmd,
                                 const unsigned char *seed_in,
                                 size_t seed_len, int idx,
                                 unsigned char *seed_out, int *counter_ret,
                                 unsigned long *h_ret, BN_GENCB *cb);

static DSA *dsa_dh_generate(DH_PKEY_CTX *dctx, BN_GENCB *pcb)
{
    DSA *ret;
    int rv = 0;
    int prime_len = dctx->prime_len;
    int subprime_len = dctx->subprime_len;
    const EVP_MD *md = dctx->md;
    if (dctx->use_dsa > 2)
        return NULL;
    ret = DSA_new();
    if (!ret)
        return NULL;
    if (subprime_len == -1) {
        if (prime_len >= 2048)
            subprime_len = 256;
        else
            subprime_len = 160;
    }
    if (md == NULL) {
        if (prime_len >= 2048)
            md = EVP_sha256();
        else
            md = EVP_sha1();
    }
    if (dctx->use_dsa == 1)
        rv = dsa_builtin_paramgen(ret, prime_len, subprime_len, md,
                                  NULL, 0, NULL, NULL, NULL, pcb);
    else if (dctx->use_dsa == 2)
        rv = dsa_builtin_paramgen2(ret, prime_len, subprime_len, md,
                                   NULL, 0, -1, NULL, NULL, NULL, pcb);
    if (rv <= 0) {
        DSA_free(ret);
        return NULL;
    }
    return ret;
}

#endif

static int pkey_dh_paramgen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    DH *dh = NULL;
    DH_PKEY_CTX *dctx = ctx->data;
    BN_GENCB *pcb, cb;
    int ret;
    if (dctx->rfc5114_param) {
        switch (dctx->rfc5114_param) {
        case 1:
            dh = DH_get_1024_160();
            break;

        case 2:
            dh = DH_get_2048_224();
            break;

        case 3:
            dh = DH_get_2048_256();
            break;

        default:
            return -2;
        }
        EVP_PKEY_assign(pkey, EVP_PKEY_DHX, dh);
        return 1;
    }

    if (ctx->pkey_gencb) {
        pcb = &cb;
        evp_pkey_set_cb_translate(pcb, ctx);
    } else
        pcb = NULL;
#ifndef OPENSSL_NO_DSA
    if (dctx->use_dsa) {
        DSA *dsa_dh;
        dsa_dh = dsa_dh_generate(dctx, pcb);
        if (!dsa_dh)
            return 0;
        dh = DSA_dup_DH(dsa_dh);
        DSA_free(dsa_dh);
        if (!dh)
            return 0;
        EVP_PKEY_assign(pkey, EVP_PKEY_DHX, dh);
        return 1;
    }
#endif
    dh = DH_new();
    if (!dh)
        return 0;
    ret = DH_generate_parameters_ex(dh,
                                    dctx->prime_len, dctx->generator, pcb);

    if (ret)
        EVP_PKEY_assign_DH(pkey, dh);
    else
        DH_free(dh);
    return ret;
}

static int pkey_dh_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    DH *dh = NULL;
    if (ctx->pkey == NULL) {
        DHerr(DH_F_PKEY_DH_KEYGEN, DH_R_NO_PARAMETERS_SET);
        return 0;
    }
    dh = DH_new();
    if (!dh)
        return 0;
    EVP_PKEY_assign(pkey, ctx->pmeth->pkey_id, dh);
    /* Note: if error return, pkey is freed by parent routine */
    if (!EVP_PKEY_copy_parameters(pkey, ctx->pkey))
        return 0;
    return DH_generate_key(pkey->pkey.dh);
}

static int pkey_dh_derive(EVP_PKEY_CTX *ctx, unsigned char *key,
                          size_t *keylen)
{
    int ret;
    DH *dh;
    DH_PKEY_CTX *dctx = ctx->data;
    BIGNUM *dhpub;
    if (!ctx->pkey || !ctx->peerkey) {
        DHerr(DH_F_PKEY_DH_DERIVE, DH_R_KEYS_NOT_SET);
        return 0;
    }
    dh = ctx->pkey->pkey.dh;
    dhpub = ctx->peerkey->pkey.dh->pub_key;
    if (dctx->kdf_type == EVP_PKEY_DH_KDF_NONE) {
        if (key == NULL) {
            *keylen = DH_size(dh);
            return 1;
        }
        ret = DH_compute_key(key, dhpub, dh);
        if (ret < 0)
            return ret;
        *keylen = ret;
        return 1;
    }
#ifndef OPENSSL_NO_CMS
    else if (dctx->kdf_type == EVP_PKEY_DH_KDF_X9_42) {
        unsigned char *Z = NULL;
        size_t Zlen = 0;
        if (!dctx->kdf_outlen || !dctx->kdf_oid)
            return 0;
        if (key == NULL) {
            *keylen = dctx->kdf_outlen;
            return 1;
        }
        if (*keylen != dctx->kdf_outlen)
            return 0;
        ret = 0;
        Zlen = DH_size(dh);
        Z = OPENSSL_malloc(Zlen);
        if (!Z) {
            goto err;
        }
        if (DH_compute_key_padded(Z, dhpub, dh) <= 0)
            goto err;
        if (!DH_KDF_X9_42(key, *keylen, Z, Zlen, dctx->kdf_oid,
                          dctx->kdf_ukm, dctx->kdf_ukmlen, dctx->kdf_md))
            goto err;
        *keylen = dctx->kdf_outlen;
        ret = 1;
 err:
        if (Z) {
            OPENSSL_cleanse(Z, Zlen);
            OPENSSL_free(Z);
        }
        return ret;
    }
#endif
    return 0;
}

const EVP_PKEY_METHOD dh_pkey_meth = {
    EVP_PKEY_DH,
    0,
    pkey_dh_init,
    pkey_dh_copy,
    pkey_dh_cleanup,

    0,
    pkey_dh_paramgen,

    0,
    pkey_dh_keygen,

    0,
    0,

    0,
    0,

    0, 0,

    0, 0, 0, 0,

    0, 0,

    0, 0,

    0,
    pkey_dh_derive,

    pkey_dh_ctrl,
    pkey_dh_ctrl_str
};

const EVP_PKEY_METHOD dhx_pkey_meth = {
    EVP_PKEY_DHX,
    0,
    pkey_dh_init,
    pkey_dh_copy,
    pkey_dh_cleanup,

    0,
    pkey_dh_paramgen,

    0,
    pkey_dh_keygen,

    0,
    0,

    0,
    0,

    0, 0,

    0, 0, 0, 0,

    0, 0,

    0, 0,

    0,
    pkey_dh_derive,

    pkey_dh_ctrl,
    pkey_dh_ctrl_str
};
/* crypto/asn1/t_pkey.c */
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
// #include "dh.h"

#ifndef OPENSSL_NO_FP_API
int DHparams_print_fp(FILE *fp, const DH *x)
{
    BIO *b;
    int ret;

    if ((b = BIO_new(BIO_s_file())) == NULL) {
        DHerr(DH_F_DHPARAMS_PRINT_FP, ERR_R_BUF_LIB);
        return (0);
    }
    BIO_set_fp(b, fp, BIO_NOCLOSE);
    ret = DHparams_print(b, x);
    BIO_free(b);
    return (ret);
}
#endif
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 2011.
 */
/* ====================================================================
 * Copyright (c) 2011 The OpenSSL Project.  All rights reserved.
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
// #include "dh.h"
// #include "bn.h"

/* DH parameters from RFC5114 */

#if BN_BITS2 == 64
static const BN_ULONG dh1024_160_p[] = {
    0xDF1FB2BC2E4A4371ULL, 0xE68CFDA76D4DA708ULL, 0x45BF37DF365C1A65ULL,
    0xA151AF5F0DC8B4BDULL, 0xFAA31A4FF55BCCC0ULL, 0x4EFFD6FAE5644738ULL,
    0x98488E9C219A7372ULL, 0xACCBDD7D90C4BD70ULL, 0x24975C3CD49B83BFULL,
    0x13ECB4AEA9061123ULL, 0x9838EF1E2EE652C0ULL, 0x6073E28675A23D18ULL,
    0x9A6A9DCA52D23B61ULL, 0x52C99FBCFB06A3C6ULL, 0xDE92DE5EAE5D54ECULL,
    0xB10B8F96A080E01DULL
};

static const BN_ULONG dh1024_160_g[] = {
    0x855E6EEB22B3B2E5ULL, 0x858F4DCEF97C2A24ULL, 0x2D779D5918D08BC8ULL,
    0xD662A4D18E73AFA3ULL, 0x1DBF0A0169B6A28AULL, 0xA6A24C087A091F53ULL,
    0x909D0D2263F80A76ULL, 0xD7FBD7D3B9A92EE1ULL, 0x5E91547F9E2749F4ULL,
    0x160217B4B01B886AULL, 0x777E690F5504F213ULL, 0x266FEA1E5C41564BULL,
    0xD6406CFF14266D31ULL, 0xF8104DD258AC507FULL, 0x6765A442EFB99905ULL,
    0xA4D1CBD5C3FD3412ULL
};

static const BN_ULONG dh1024_160_q[] = {
    0x64B7CB9D49462353ULL, 0x81A8DF278ABA4E7DULL, 0x00000000F518AA87ULL
};

static const BN_ULONG dh2048_224_p[] = {
    0x0AC4DFFE0C10E64FULL, 0xCF9DE5384E71B81CULL, 0x7EF363E2FFA31F71ULL,
    0xE3FB73C16B8E75B9ULL, 0xC9B53DCF4BA80A29ULL, 0x23F10B0E16E79763ULL,
    0xC52172E413042E9BULL, 0xBE60E69CC928B2B9ULL, 0x80CD86A1B9E587E8ULL,
    0x315D75E198C641A4ULL, 0xCDF93ACC44328387ULL, 0x15987D9ADC0A486DULL,
    0x7310F7121FD5A074ULL, 0x278273C7DE31EFDCULL, 0x1602E714415D9330ULL,
    0x81286130BC8985DBULL, 0xB3BF8A3170918836ULL, 0x6A00E0A0B9C49708ULL,
    0xC6BA0B2C8BBC27BEULL, 0xC9F98D11ED34DBF6ULL, 0x7AD5B7D0B6C12207ULL,
    0xD91E8FEF55B7394BULL, 0x9037C9EDEFDA4DF8ULL, 0x6D3F8152AD6AC212ULL,
    0x1DE6B85A1274A0A6ULL, 0xEB3D688A309C180EULL, 0xAF9A3C407BA1DF15ULL,
    0xE6FA141DF95A56DBULL, 0xB54B1597B61D0A75ULL, 0xA20D64E5683B9FD1ULL,
    0xD660FAA79559C51FULL, 0xAD107E1E9123A9D0ULL
};

static const BN_ULONG dh2048_224_g[] = {
    0x84B890D3191F2BFAULL, 0x81BC087F2A7065B3ULL, 0x19C418E1F6EC0179ULL,
    0x7B5A0F1C71CFFF4CULL, 0xEDFE72FE9B6AA4BDULL, 0x81E1BCFE94B30269ULL,
    0x566AFBB48D6C0191ULL, 0xB539CCE3409D13CDULL, 0x6AA21E7F5F2FF381ULL,
    0xD9E263E4770589EFULL, 0x10E183EDD19963DDULL, 0xB70A8137150B8EEBULL,
    0x051AE3D428C8F8ACULL, 0xBB77A86F0C1AB15BULL, 0x6E3025E316A330EFULL,
    0x19529A45D6F83456ULL, 0xF180EB34118E98D1ULL, 0xB5F6C6B250717CBEULL,
    0x09939D54DA7460CDULL, 0xE247150422EA1ED4ULL, 0xB8A762D0521BC98AULL,
    0xF4D027275AC1348BULL, 0xC17669101999024AULL, 0xBE5E9001A8D66AD7ULL,
    0xC57DB17C620A8652ULL, 0xAB739D7700C29F52ULL, 0xDD921F01A70C4AFAULL,
    0xA6824A4E10B9A6F0ULL, 0x74866A08CFE4FFE3ULL, 0x6CDEBE7B89998CAFULL,
    0x9DF30B5C8FFDAC50ULL, 0xAC4032EF4F2D9AE3ULL
};

static const BN_ULONG dh2048_224_q[] = {
    0xBF389A99B36371EBULL, 0x1F80535A4738CEBCULL, 0xC58D93FE99717710ULL,
    0x00000000801C0D34ULL
};

static const BN_ULONG dh2048_256_p[] = {
    0xDB094AE91E1A1597ULL, 0x693877FAD7EF09CAULL, 0x6116D2276E11715FULL,
    0xA4B54330C198AF12ULL, 0x75F26375D7014103ULL, 0xC3A3960A54E710C3ULL,
    0xDED4010ABD0BE621ULL, 0xC0B857F689962856ULL, 0xB3CA3F7971506026ULL,
    0x1CCACB83E6B486F6ULL, 0x67E144E514056425ULL, 0xF6A167B5A41825D9ULL,
    0x3AD8347796524D8EULL, 0xF13C6D9A51BFA4ABULL, 0x2D52526735488A0EULL,
    0xB63ACAE1CAA6B790ULL, 0x4FDB70C581B23F76ULL, 0xBC39A0BF12307F5CULL,
    0xB941F54EB1E59BB8ULL, 0x6C5BFC11D45F9088ULL, 0x22E0B1EF4275BF7BULL,
    0x91F9E6725B4758C0ULL, 0x5A8A9D306BCF67EDULL, 0x209E0C6497517ABDULL,
    0x3BF4296D830E9A7CULL, 0x16C3D91134096FAAULL, 0xFAF7DF4561B2AA30ULL,
    0xE00DF8F1D61957D4ULL, 0x5D2CEED4435E3B00ULL, 0x8CEEF608660DD0F2ULL,
    0xFFBBD19C65195999ULL, 0x87A8E61DB4B6663CULL
};

static const BN_ULONG dh2048_256_g[] = {
    0x664B4C0F6CC41659ULL, 0x5E2327CFEF98C582ULL, 0xD647D148D4795451ULL,
    0x2F63078490F00EF8ULL, 0x184B523D1DB246C3ULL, 0xC7891428CDC67EB6ULL,
    0x7FD028370DF92B52ULL, 0xB3353BBB64E0EC37ULL, 0xECD06E1557CD0915ULL,
    0xB7D2BBD2DF016199ULL, 0xC8484B1E052588B9ULL, 0xDB2A3B7313D3FE14ULL,
    0xD052B985D182EA0AULL, 0xA4BD1BFFE83B9C80ULL, 0xDFC967C1FB3F2E55ULL,
    0xB5045AF2767164E1ULL, 0x1D14348F6F2F9193ULL, 0x64E67982428EBC83ULL,
    0x8AC376D282D6ED38ULL, 0x777DE62AAAB8A862ULL, 0xDDF463E5E9EC144BULL,
    0x0196F931C77A57F2ULL, 0xA55AE31341000A65ULL, 0x901228F8C28CBB18ULL,
    0xBC3773BF7E8C6F62ULL, 0xBE3A6C1B0C6B47B1ULL, 0xFF4FED4AAC0BB555ULL,
    0x10DBC15077BE463FULL, 0x07F4793A1A0BA125ULL, 0x4CA7B18F21EF2054ULL,
    0x2E77506660EDBD48ULL, 0x3FB32C9B73134D0BULL
};

static const BN_ULONG dh2048_256_q[] = {
    0xA308B0FE64F5FBD3ULL, 0x99B1A47D1EB3750BULL, 0xB447997640129DA2ULL,
    0x8CF83642A709A097ULL
};

#elif BN_BITS2 == 32

static const BN_ULONG dh1024_160_p[] = {
    0x2E4A4371, 0xDF1FB2BC, 0x6D4DA708, 0xE68CFDA7, 0x365C1A65, 0x45BF37DF,
    0x0DC8B4BD, 0xA151AF5F, 0xF55BCCC0, 0xFAA31A4F, 0xE5644738, 0x4EFFD6FA,
    0x219A7372, 0x98488E9C, 0x90C4BD70, 0xACCBDD7D, 0xD49B83BF, 0x24975C3C,
    0xA9061123, 0x13ECB4AE, 0x2EE652C0, 0x9838EF1E, 0x75A23D18, 0x6073E286,
    0x52D23B61, 0x9A6A9DCA, 0xFB06A3C6, 0x52C99FBC, 0xAE5D54EC, 0xDE92DE5E,
    0xA080E01D, 0xB10B8F96
};

static const BN_ULONG dh1024_160_g[] = {
    0x22B3B2E5, 0x855E6EEB, 0xF97C2A24, 0x858F4DCE, 0x18D08BC8, 0x2D779D59,
    0x8E73AFA3, 0xD662A4D1, 0x69B6A28A, 0x1DBF0A01, 0x7A091F53, 0xA6A24C08,
    0x63F80A76, 0x909D0D22, 0xB9A92EE1, 0xD7FBD7D3, 0x9E2749F4, 0x5E91547F,
    0xB01B886A, 0x160217B4, 0x5504F213, 0x777E690F, 0x5C41564B, 0x266FEA1E,
    0x14266D31, 0xD6406CFF, 0x58AC507F, 0xF8104DD2, 0xEFB99905, 0x6765A442,
    0xC3FD3412, 0xA4D1CBD5
};

static const BN_ULONG dh1024_160_q[] = {
    0x49462353, 0x64B7CB9D, 0x8ABA4E7D, 0x81A8DF27, 0xF518AA87
};

static const BN_ULONG dh2048_224_p[] = {
    0x0C10E64F, 0x0AC4DFFE, 0x4E71B81C, 0xCF9DE538, 0xFFA31F71, 0x7EF363E2,
    0x6B8E75B9, 0xE3FB73C1, 0x4BA80A29, 0xC9B53DCF, 0x16E79763, 0x23F10B0E,
    0x13042E9B, 0xC52172E4, 0xC928B2B9, 0xBE60E69C, 0xB9E587E8, 0x80CD86A1,
    0x98C641A4, 0x315D75E1, 0x44328387, 0xCDF93ACC, 0xDC0A486D, 0x15987D9A,
    0x1FD5A074, 0x7310F712, 0xDE31EFDC, 0x278273C7, 0x415D9330, 0x1602E714,
    0xBC8985DB, 0x81286130, 0x70918836, 0xB3BF8A31, 0xB9C49708, 0x6A00E0A0,
    0x8BBC27BE, 0xC6BA0B2C, 0xED34DBF6, 0xC9F98D11, 0xB6C12207, 0x7AD5B7D0,
    0x55B7394B, 0xD91E8FEF, 0xEFDA4DF8, 0x9037C9ED, 0xAD6AC212, 0x6D3F8152,
    0x1274A0A6, 0x1DE6B85A, 0x309C180E, 0xEB3D688A, 0x7BA1DF15, 0xAF9A3C40,
    0xF95A56DB, 0xE6FA141D, 0xB61D0A75, 0xB54B1597, 0x683B9FD1, 0xA20D64E5,
    0x9559C51F, 0xD660FAA7, 0x9123A9D0, 0xAD107E1E
};

static const BN_ULONG dh2048_224_g[] = {
    0x191F2BFA, 0x84B890D3, 0x2A7065B3, 0x81BC087F, 0xF6EC0179, 0x19C418E1,
    0x71CFFF4C, 0x7B5A0F1C, 0x9B6AA4BD, 0xEDFE72FE, 0x94B30269, 0x81E1BCFE,
    0x8D6C0191, 0x566AFBB4, 0x409D13CD, 0xB539CCE3, 0x5F2FF381, 0x6AA21E7F,
    0x770589EF, 0xD9E263E4, 0xD19963DD, 0x10E183ED, 0x150B8EEB, 0xB70A8137,
    0x28C8F8AC, 0x051AE3D4, 0x0C1AB15B, 0xBB77A86F, 0x16A330EF, 0x6E3025E3,
    0xD6F83456, 0x19529A45, 0x118E98D1, 0xF180EB34, 0x50717CBE, 0xB5F6C6B2,
    0xDA7460CD, 0x09939D54, 0x22EA1ED4, 0xE2471504, 0x521BC98A, 0xB8A762D0,
    0x5AC1348B, 0xF4D02727, 0x1999024A, 0xC1766910, 0xA8D66AD7, 0xBE5E9001,
    0x620A8652, 0xC57DB17C, 0x00C29F52, 0xAB739D77, 0xA70C4AFA, 0xDD921F01,
    0x10B9A6F0, 0xA6824A4E, 0xCFE4FFE3, 0x74866A08, 0x89998CAF, 0x6CDEBE7B,
    0x8FFDAC50, 0x9DF30B5C, 0x4F2D9AE3, 0xAC4032EF
};

static const BN_ULONG dh2048_224_q[] = {
    0xB36371EB, 0xBF389A99, 0x4738CEBC, 0x1F80535A, 0x99717710, 0xC58D93FE,
    0x801C0D34
};

static const BN_ULONG dh2048_256_p[] = {
    0x1E1A1597, 0xDB094AE9, 0xD7EF09CA, 0x693877FA, 0x6E11715F, 0x6116D227,
    0xC198AF12, 0xA4B54330, 0xD7014103, 0x75F26375, 0x54E710C3, 0xC3A3960A,
    0xBD0BE621, 0xDED4010A, 0x89962856, 0xC0B857F6, 0x71506026, 0xB3CA3F79,
    0xE6B486F6, 0x1CCACB83, 0x14056425, 0x67E144E5, 0xA41825D9, 0xF6A167B5,
    0x96524D8E, 0x3AD83477, 0x51BFA4AB, 0xF13C6D9A, 0x35488A0E, 0x2D525267,
    0xCAA6B790, 0xB63ACAE1, 0x81B23F76, 0x4FDB70C5, 0x12307F5C, 0xBC39A0BF,
    0xB1E59BB8, 0xB941F54E, 0xD45F9088, 0x6C5BFC11, 0x4275BF7B, 0x22E0B1EF,
    0x5B4758C0, 0x91F9E672, 0x6BCF67ED, 0x5A8A9D30, 0x97517ABD, 0x209E0C64,
    0x830E9A7C, 0x3BF4296D, 0x34096FAA, 0x16C3D911, 0x61B2AA30, 0xFAF7DF45,
    0xD61957D4, 0xE00DF8F1, 0x435E3B00, 0x5D2CEED4, 0x660DD0F2, 0x8CEEF608,
    0x65195999, 0xFFBBD19C, 0xB4B6663C, 0x87A8E61D
};

static const BN_ULONG dh2048_256_g[] = {
    0x6CC41659, 0x664B4C0F, 0xEF98C582, 0x5E2327CF, 0xD4795451, 0xD647D148,
    0x90F00EF8, 0x2F630784, 0x1DB246C3, 0x184B523D, 0xCDC67EB6, 0xC7891428,
    0x0DF92B52, 0x7FD02837, 0x64E0EC37, 0xB3353BBB, 0x57CD0915, 0xECD06E15,
    0xDF016199, 0xB7D2BBD2, 0x052588B9, 0xC8484B1E, 0x13D3FE14, 0xDB2A3B73,
    0xD182EA0A, 0xD052B985, 0xE83B9C80, 0xA4BD1BFF, 0xFB3F2E55, 0xDFC967C1,
    0x767164E1, 0xB5045AF2, 0x6F2F9193, 0x1D14348F, 0x428EBC83, 0x64E67982,
    0x82D6ED38, 0x8AC376D2, 0xAAB8A862, 0x777DE62A, 0xE9EC144B, 0xDDF463E5,
    0xC77A57F2, 0x0196F931, 0x41000A65, 0xA55AE313, 0xC28CBB18, 0x901228F8,
    0x7E8C6F62, 0xBC3773BF, 0x0C6B47B1, 0xBE3A6C1B, 0xAC0BB555, 0xFF4FED4A,
    0x77BE463F, 0x10DBC150, 0x1A0BA125, 0x07F4793A, 0x21EF2054, 0x4CA7B18F,
    0x60EDBD48, 0x2E775066, 0x73134D0B, 0x3FB32C9B
};

static const BN_ULONG dh2048_256_q[] = {
    0x64F5FBD3, 0xA308B0FE, 0x1EB3750B, 0x99B1A47D, 0x40129DA2, 0xB4479976,
    0xA709A097, 0x8CF83642
};

#else
# error "unsupported BN_BITS2"
#endif

/* Macro to make a BIGNUM from static data */

#define make_dh_bn(x) static const BIGNUM _bignum_##x = { (BN_ULONG *) x, \
                        sizeof(x)/sizeof(BN_ULONG),\
                        sizeof(x)/sizeof(BN_ULONG),\
                        0, BN_FLG_STATIC_DATA }

/*
 * Macro to make a DH structure from BIGNUM data. NB: although just copying
 * the BIGNUM static pointers would be more efficient we can't as they get
 * wiped using BN_clear_free() when DH_free() is called.
 */

#define make_dh(x) \
DH * DH_get_##x(void) \
        { \
        DH *dh; \
        make_dh_bn(dh##x##_p); \
        make_dh_bn(dh##x##_q); \
        make_dh_bn(dh##x##_g); \
        dh = DH_new(); \
        if (!dh) \
                return NULL; \
        dh->p = BN_dup(&_bignum_dh##x##_p); \
        dh->g = BN_dup(&_bignum_dh##x##_g); \
        dh->q = BN_dup(&_bignum_dh##x##_q); \
        if (!dh->p || !dh->q || !dh->g) \
                { \
                DH_free(dh); \
                return NULL; \
                } \
        return dh; \
        }

make_dh(1024_160)
make_dh(2048_224)
make_dh(2048_256)
