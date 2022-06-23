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
#include "cryptlib.h"
#include "x509.h"
#include "ec.h"
#include "bn.h"
#ifndef OPENSSL_NO_CMS
# include "cms.h"
#endif
#include "asn1t.h"
#include "asn1_locl.h"
#include "ec_lcl.h"

#ifndef OPENSSL_NO_CMS
static int ecdh_cms_decrypt(CMS_RecipientInfo *ri);
static int ecdh_cms_encrypt(CMS_RecipientInfo *ri);
#endif

static int eckey_param2type(int *pptype, void **ppval, EC_KEY *ec_key)
{
    const EC_GROUP *group;
    int nid;
    if (ec_key == NULL || (group = EC_KEY_get0_group(ec_key)) == NULL) {
        ECerr(EC_F_ECKEY_PARAM2TYPE, EC_R_MISSING_PARAMETERS);
        return 0;
    }
    if (EC_GROUP_get_asn1_flag(group)
        && (nid = EC_GROUP_get_curve_name(group)))
        /* we have a 'named curve' => just set the OID */
    {
        *ppval = OBJ_nid2obj(nid);
        *pptype = V_ASN1_OBJECT;
    } else {                    /* explicit parameters */

        ASN1_STRING *pstr = NULL;
        pstr = ASN1_STRING_new();
        if (!pstr)
            return 0;
        pstr->length = i2d_ECParameters(ec_key, &pstr->data);
        if (pstr->length <= 0) {
            ASN1_STRING_free(pstr);
            ECerr(EC_F_ECKEY_PARAM2TYPE, ERR_R_EC_LIB);
            return 0;
        }
        *ppval = pstr;
        *pptype = V_ASN1_SEQUENCE;
    }
    return 1;
}

static int eckey_pub_encode(X509_PUBKEY *pk, const EVP_PKEY *pkey)
{
    EC_KEY *ec_key = pkey->pkey.ec;
    void *pval = NULL;
    int ptype;
    unsigned char *penc = NULL, *p;
    int penclen;

    if (!eckey_param2type(&ptype, &pval, ec_key)) {
        ECerr(EC_F_ECKEY_PUB_ENCODE, ERR_R_EC_LIB);
        return 0;
    }
    penclen = i2o_ECPublicKey(ec_key, NULL);
    if (penclen <= 0)
        goto err;
    penc = OPENSSL_malloc(penclen);
    if (!penc)
        goto err;
    p = penc;
    penclen = i2o_ECPublicKey(ec_key, &p);
    if (penclen <= 0)
        goto err;
    if (X509_PUBKEY_set0_param(pk, OBJ_nid2obj(EVP_PKEY_EC),
                               ptype, pval, penc, penclen))
        return 1;
 err:
    if (ptype == V_ASN1_OBJECT)
        ASN1_OBJECT_free(pval);
    else
        ASN1_STRING_free(pval);
    if (penc)
        OPENSSL_free(penc);
    return 0;
}

static EC_KEY *eckey_type2param(int ptype, void *pval)
{
    EC_KEY *eckey = NULL;
    EC_GROUP *group = NULL;

    if (ptype == V_ASN1_SEQUENCE) {
        const ASN1_STRING *pstr = pval;
        const unsigned char *pm = pstr->data;
        int pmlen = pstr->length;

        if ((eckey = d2i_ECParameters(NULL, &pm, pmlen)) == NULL) {
            ECerr(EC_F_ECKEY_TYPE2PARAM, EC_R_DECODE_ERROR);
            goto ecerr;
        }
    } else if (ptype == V_ASN1_OBJECT) {
        const ASN1_OBJECT *poid = pval;

        /*
         * type == V_ASN1_OBJECT => the parameters are given by an asn1 OID
         */
        if ((eckey = EC_KEY_new()) == NULL) {
            ECerr(EC_F_ECKEY_TYPE2PARAM, ERR_R_MALLOC_FAILURE);
            goto ecerr;
        }
        group = EC_GROUP_new_by_curve_name(OBJ_obj2nid(poid));
        if (group == NULL)
            goto ecerr;
        EC_GROUP_set_asn1_flag(group, OPENSSL_EC_NAMED_CURVE);
        if (EC_KEY_set_group(eckey, group) == 0)
            goto ecerr;
        EC_GROUP_free(group);
    } else {
        ECerr(EC_F_ECKEY_TYPE2PARAM, EC_R_DECODE_ERROR);
        goto ecerr;
    }

    return eckey;

 ecerr:
    EC_KEY_free(eckey);
    EC_GROUP_free(group);
    return NULL;
}

static int eckey_pub_decode(EVP_PKEY *pkey, X509_PUBKEY *pubkey)
{
    const unsigned char *p = NULL;
    void *pval;
    int ptype, pklen;
    EC_KEY *eckey = NULL;
    X509_ALGOR *palg;

    if (!X509_PUBKEY_get0_param(NULL, &p, &pklen, &palg, pubkey))
        return 0;
    X509_ALGOR_get0(NULL, &ptype, &pval, palg);

    eckey = eckey_type2param(ptype, pval);

    if (!eckey) {
        ECerr(EC_F_ECKEY_PUB_DECODE, ERR_R_EC_LIB);
        return 0;
    }

    /* We have parameters now set public key */
    if (!o2i_ECPublicKey(&eckey, &p, pklen)) {
        ECerr(EC_F_ECKEY_PUB_DECODE, EC_R_DECODE_ERROR);
        goto ecerr;
    }

    EVP_PKEY_assign_EC_KEY(pkey, eckey);
    return 1;

 ecerr:
    if (eckey)
        EC_KEY_free(eckey);
    return 0;
}

static int eckey_pub_cmp(const EVP_PKEY *a, const EVP_PKEY *b)
{
    int r;
    const EC_GROUP *group = EC_KEY_get0_group(b->pkey.ec);
    const EC_POINT *pa = EC_KEY_get0_public_key(a->pkey.ec),
        *pb = EC_KEY_get0_public_key(b->pkey.ec);
    if (group == NULL || pa == NULL || pb == NULL)
        return -2;
    r = EC_POINT_cmp(group, pa, pb, NULL);
    if (r == 0)
        return 1;
    if (r == 1)
        return 0;
    return -2;
}

static int eckey_priv_decode(EVP_PKEY *pkey, PKCS8_PRIV_KEY_INFO *p8)
{
    const unsigned char *p = NULL;
    void *pval;
    int ptype, pklen;
    EC_KEY *eckey = NULL;
    X509_ALGOR *palg;

    if (!PKCS8_pkey_get0(NULL, &p, &pklen, &palg, p8))
        return 0;
    X509_ALGOR_get0(NULL, &ptype, &pval, palg);

    eckey = eckey_type2param(ptype, pval);

    if (!eckey)
        goto ecliberr;

    /* We have parameters now set private key */
    if (!d2i_ECPrivateKey(&eckey, &p, pklen)) {
        ECerr(EC_F_ECKEY_PRIV_DECODE, EC_R_DECODE_ERROR);
        goto ecerr;
    }

    /* calculate public key (if necessary) */
    if (EC_KEY_get0_public_key(eckey) == NULL) {
        const BIGNUM *priv_key;
        const EC_GROUP *group;
        EC_POINT *pub_key;
        /*
         * the public key was not included in the SEC1 private key =>
         * calculate the public key
         */
        group = EC_KEY_get0_group(eckey);
        pub_key = EC_POINT_new(group);
        if (pub_key == NULL) {
            ECerr(EC_F_ECKEY_PRIV_DECODE, ERR_R_EC_LIB);
            goto ecliberr;
        }
        if (!EC_POINT_copy(pub_key, EC_GROUP_get0_generator(group))) {
            EC_POINT_free(pub_key);
            ECerr(EC_F_ECKEY_PRIV_DECODE, ERR_R_EC_LIB);
            goto ecliberr;
        }
        priv_key = EC_KEY_get0_private_key(eckey);
        if (!EC_POINT_mul(group, pub_key, priv_key, NULL, NULL, NULL)) {
            EC_POINT_free(pub_key);
            ECerr(EC_F_ECKEY_PRIV_DECODE, ERR_R_EC_LIB);
            goto ecliberr;
        }
        if (EC_KEY_set_public_key(eckey, pub_key) == 0) {
            EC_POINT_free(pub_key);
            ECerr(EC_F_ECKEY_PRIV_DECODE, ERR_R_EC_LIB);
            goto ecliberr;
        }
        EC_POINT_free(pub_key);
    }

    EVP_PKEY_assign_EC_KEY(pkey, eckey);
    return 1;

 ecliberr:
    ECerr(EC_F_ECKEY_PRIV_DECODE, ERR_R_EC_LIB);
 ecerr:
    if (eckey)
        EC_KEY_free(eckey);
    return 0;
}

static int eckey_priv_encode(PKCS8_PRIV_KEY_INFO *p8, const EVP_PKEY *pkey)
{
    EC_KEY ec_key = *(pkey->pkey.ec);
    unsigned char *ep, *p;
    int eplen, ptype;
    void *pval;
    unsigned int old_flags;

    if (!eckey_param2type(&ptype, &pval, &ec_key)) {
        ECerr(EC_F_ECKEY_PRIV_ENCODE, EC_R_DECODE_ERROR);
        return 0;
    }

    /* set the private key */

    /*
     * do not include the parameters in the SEC1 private key see PKCS#11
     * 12.11
     */
    old_flags = EC_KEY_get_enc_flags(&ec_key);
    EC_KEY_set_enc_flags(&ec_key, old_flags | EC_PKEY_NO_PARAMETERS);

    eplen = i2d_ECPrivateKey(&ec_key, NULL);
    if (!eplen) {
        ECerr(EC_F_ECKEY_PRIV_ENCODE, ERR_R_EC_LIB);
        return 0;
    }
    ep = (unsigned char *)OPENSSL_malloc(eplen);
    if (!ep) {
        ECerr(EC_F_ECKEY_PRIV_ENCODE, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    p = ep;
    if (!i2d_ECPrivateKey(&ec_key, &p)) {
        OPENSSL_free(ep);
        ECerr(EC_F_ECKEY_PRIV_ENCODE, ERR_R_EC_LIB);
        return 0;
    }

    if (!PKCS8_pkey_set0(p8, OBJ_nid2obj(NID_X9_62_id_ecPublicKey), 0,
                         ptype, pval, ep, eplen)) {
        OPENSSL_free(ep);
        return 0;
    }

    return 1;
}

static int int_ec_size(const EVP_PKEY *pkey)
{
    return ECDSA_size(pkey->pkey.ec);
}

static int ec_bits(const EVP_PKEY *pkey)
{
    BIGNUM *order = BN_new();
    const EC_GROUP *group;
    int ret;

    if (!order) {
        ERR_clear_error();
        return 0;
    }
    group = EC_KEY_get0_group(pkey->pkey.ec);
    if (!EC_GROUP_get_order(group, order, NULL)) {
        ERR_clear_error();
        return 0;
    }

    ret = BN_num_bits(order);
    BN_free(order);
    return ret;
}

static int ec_missing_parameters(const EVP_PKEY *pkey)
{
    if (pkey->pkey.ec == NULL || EC_KEY_get0_group(pkey->pkey.ec) == NULL)
        return 1;
    return 0;
}

static int ec_copy_parameters(EVP_PKEY *to, const EVP_PKEY *from)
{
    EC_GROUP *group = EC_GROUP_dup(EC_KEY_get0_group(from->pkey.ec));
    if (group == NULL)
        return 0;
    if (EC_KEY_set_group(to->pkey.ec, group) == 0)
        return 0;
    EC_GROUP_free(group);
    return 1;
}

static int ec_cmp_parameters(const EVP_PKEY *a, const EVP_PKEY *b)
{
    const EC_GROUP *group_a = EC_KEY_get0_group(a->pkey.ec),
        *group_b = EC_KEY_get0_group(b->pkey.ec);
    if (group_a == NULL || group_b == NULL)
        return -2;
    if (EC_GROUP_cmp(group_a, group_b, NULL))
        return 0;
    else
        return 1;
}

static void int_ec_free(EVP_PKEY *pkey)
{
    EC_KEY_free(pkey->pkey.ec);
}

static int do_EC_KEY_print(BIO *bp, const EC_KEY *x, int off, int ktype)
{
    unsigned char *buffer = NULL;
    const char *ecstr;
    size_t buf_len = 0, i;
    int ret = 0, reason = ERR_R_BIO_LIB;
    BIGNUM *pub_key = NULL, *order = NULL;
    BN_CTX *ctx = NULL;
    const EC_GROUP *group;
    const EC_POINT *public_key;
    const BIGNUM *priv_key;

    if (x == NULL || (group = EC_KEY_get0_group(x)) == NULL) {
        reason = ERR_R_PASSED_NULL_PARAMETER;
        goto err;
    }

    ctx = BN_CTX_new();
    if (ctx == NULL) {
        reason = ERR_R_MALLOC_FAILURE;
        goto err;
    }

    if (ktype > 0) {
        public_key = EC_KEY_get0_public_key(x);
        if (public_key != NULL) {
            if ((pub_key = EC_POINT_point2bn(group, public_key,
                                             EC_KEY_get_conv_form(x), NULL,
                                             ctx)) == NULL) {
                reason = ERR_R_EC_LIB;
                goto err;
            }
            buf_len = (size_t)BN_num_bytes(pub_key);
        }
    }

    if (ktype == 2) {
        priv_key = EC_KEY_get0_private_key(x);
        if (priv_key && (i = (size_t)BN_num_bytes(priv_key)) > buf_len)
            buf_len = i;
    } else
        priv_key = NULL;

    if (ktype > 0) {
        buf_len += 10;
        if ((buffer = OPENSSL_malloc(buf_len)) == NULL) {
            reason = ERR_R_MALLOC_FAILURE;
            goto err;
        }
    }
    if (ktype == 2)
        ecstr = "Private-Key";
    else if (ktype == 1)
        ecstr = "Public-Key";
    else
        ecstr = "ECDSA-Parameters";

    if (!BIO_indent(bp, off, 128))
        goto err;
    if ((order = BN_new()) == NULL)
        goto err;
    if (!EC_GROUP_get_order(group, order, NULL))
        goto err;
    if (BIO_printf(bp, "%s: (%d bit)\n", ecstr, BN_num_bits(order)) <= 0)
        goto err;

    if ((priv_key != NULL) && !ASN1_bn_print(bp, "priv:", priv_key,
                                             buffer, off))
        goto err;
    if ((pub_key != NULL) && !ASN1_bn_print(bp, "pub: ", pub_key,
                                            buffer, off))
        goto err;
    if (!ECPKParameters_print(bp, group, off))
        goto err;
    ret = 1;
 err:
    if (!ret)
        ECerr(EC_F_DO_EC_KEY_PRINT, reason);
    if (pub_key)
        BN_free(pub_key);
    if (order)
        BN_free(order);
    if (ctx)
        BN_CTX_free(ctx);
    if (buffer != NULL)
        OPENSSL_free(buffer);
    return (ret);
}

static int eckey_param_decode(EVP_PKEY *pkey,
                              const unsigned char **pder, int derlen)
{
    EC_KEY *eckey;
    if (!(eckey = d2i_ECParameters(NULL, pder, derlen))) {
        ECerr(EC_F_ECKEY_PARAM_DECODE, ERR_R_EC_LIB);
        return 0;
    }
    EVP_PKEY_assign_EC_KEY(pkey, eckey);
    return 1;
}

static int eckey_param_encode(const EVP_PKEY *pkey, unsigned char **pder)
{
    return i2d_ECParameters(pkey->pkey.ec, pder);
}

static int eckey_param_print(BIO *bp, const EVP_PKEY *pkey, int indent,
                             ASN1_PCTX *ctx)
{
    return do_EC_KEY_print(bp, pkey->pkey.ec, indent, 0);
}

static int eckey_pub_print(BIO *bp, const EVP_PKEY *pkey, int indent,
                           ASN1_PCTX *ctx)
{
    return do_EC_KEY_print(bp, pkey->pkey.ec, indent, 1);
}

static int eckey_priv_print(BIO *bp, const EVP_PKEY *pkey, int indent,
                            ASN1_PCTX *ctx)
{
    return do_EC_KEY_print(bp, pkey->pkey.ec, indent, 2);
}

static int old_ec_priv_decode(EVP_PKEY *pkey,
                              const unsigned char **pder, int derlen)
{
    EC_KEY *ec;
    if (!(ec = d2i_ECPrivateKey(NULL, pder, derlen))) {
        ECerr(EC_F_OLD_EC_PRIV_DECODE, EC_R_DECODE_ERROR);
        return 0;
    }
    EVP_PKEY_assign_EC_KEY(pkey, ec);
    return 1;
}

static int old_ec_priv_encode(const EVP_PKEY *pkey, unsigned char **pder)
{
    return i2d_ECPrivateKey(pkey->pkey.ec, pder);
}

static int ec_pkey_ctrl(EVP_PKEY *pkey, int op, long arg1, void *arg2)
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

    case ASN1_PKEY_CTRL_CMS_ENVELOPE:
        if (arg1 == 1)
            return ecdh_cms_decrypt(arg2);
        else if (arg1 == 0)
            return ecdh_cms_encrypt(arg2);
        return -2;

    case ASN1_PKEY_CTRL_CMS_RI_TYPE:
        *(int *)arg2 = CMS_RECIPINFO_AGREE;
        return 1;
#endif

    case ASN1_PKEY_CTRL_DEFAULT_MD_NID:
        *(int *)arg2 = NID_sha256;
        return 2;

    default:
        return -2;

    }

}

const EVP_PKEY_ASN1_METHOD eckey_asn1_meth = {
    EVP_PKEY_EC,
    EVP_PKEY_EC,
    0,
    "EC",
    "OpenSSL EC algorithm",

    eckey_pub_decode,
    eckey_pub_encode,
    eckey_pub_cmp,
    eckey_pub_print,

    eckey_priv_decode,
    eckey_priv_encode,
    eckey_priv_print,

    int_ec_size,
    ec_bits,

    eckey_param_decode,
    eckey_param_encode,
    ec_missing_parameters,
    ec_copy_parameters,
    ec_cmp_parameters,
    eckey_param_print,
    0,

    int_ec_free,
    ec_pkey_ctrl,
    old_ec_priv_decode,
    old_ec_priv_encode
};

#ifndef OPENSSL_NO_CMS

static int ecdh_cms_set_peerkey(EVP_PKEY_CTX *pctx,
                                X509_ALGOR *alg, ASN1_BIT_STRING *pubkey)
{
    ASN1_OBJECT *aoid;
    int atype;
    void *aval;
    int rv = 0;
    EVP_PKEY *pkpeer = NULL;
    EC_KEY *ecpeer = NULL;
    const unsigned char *p;
    int plen;
    X509_ALGOR_get0(&aoid, &atype, &aval, alg);
    if (OBJ_obj2nid(aoid) != NID_X9_62_id_ecPublicKey)
        goto err;
    /* If absent parameters get group from main key */
    if (atype == V_ASN1_UNDEF || atype == V_ASN1_NULL) {
        const EC_GROUP *grp;
        EVP_PKEY *pk;
        pk = EVP_PKEY_CTX_get0_pkey(pctx);
        if (!pk)
            goto err;
        grp = EC_KEY_get0_group(pk->pkey.ec);
        ecpeer = EC_KEY_new();
        if (!ecpeer)
            goto err;
        if (!EC_KEY_set_group(ecpeer, grp))
            goto err;
    } else {
        ecpeer = eckey_type2param(atype, aval);
        if (!ecpeer)
            goto err;
    }
    /* We have parameters now set public key */
    plen = ASN1_STRING_length(pubkey);
    p = ASN1_STRING_data(pubkey);
    if (!p || !plen)
        goto err;
    if (!o2i_ECPublicKey(&ecpeer, &p, plen))
        goto err;
    pkpeer = EVP_PKEY_new();
    if (!pkpeer)
        goto err;
    EVP_PKEY_set1_EC_KEY(pkpeer, ecpeer);
    if (EVP_PKEY_derive_set_peer(pctx, pkpeer) > 0)
        rv = 1;
 err:
    if (ecpeer)
        EC_KEY_free(ecpeer);
    if (pkpeer)
        EVP_PKEY_free(pkpeer);
    return rv;
}

/* Set KDF parameters based on KDF NID */
static int ecdh_cms_set_kdf_param(EVP_PKEY_CTX *pctx, int eckdf_nid)
{
    int kdf_nid, kdfmd_nid, cofactor;
    const EVP_MD *kdf_md;
    if (eckdf_nid == NID_undef)
        return 0;

    /* Lookup KDF type, cofactor mode and digest */
    if (!OBJ_find_sigid_algs(eckdf_nid, &kdfmd_nid, &kdf_nid))
        return 0;

    if (kdf_nid == NID_dh_std_kdf)
        cofactor = 0;
    else if (kdf_nid == NID_dh_cofactor_kdf)
        cofactor = 1;
    else
        return 0;

    if (EVP_PKEY_CTX_set_ecdh_cofactor_mode(pctx, cofactor) <= 0)
        return 0;

    if (EVP_PKEY_CTX_set_ecdh_kdf_type(pctx, EVP_PKEY_ECDH_KDF_X9_62) <= 0)
        return 0;

    kdf_md = EVP_get_digestbynid(kdfmd_nid);
    if (!kdf_md)
        return 0;

    if (EVP_PKEY_CTX_set_ecdh_kdf_md(pctx, kdf_md) <= 0)
        return 0;
    return 1;
}

static int ecdh_cms_set_shared_info(EVP_PKEY_CTX *pctx, CMS_RecipientInfo *ri)
{
    int rv = 0;

    X509_ALGOR *alg, *kekalg = NULL;
    ASN1_OCTET_STRING *ukm;
    const unsigned char *p;
    unsigned char *der = NULL;
    int plen, keylen;
    const EVP_CIPHER *kekcipher;
    EVP_CIPHER_CTX *kekctx;

    if (!CMS_RecipientInfo_kari_get0_alg(ri, &alg, &ukm))
        return 0;

    if (!ecdh_cms_set_kdf_param(pctx, OBJ_obj2nid(alg->algorithm))) {
        ECerr(EC_F_ECDH_CMS_SET_SHARED_INFO, EC_R_KDF_PARAMETER_ERROR);
        return 0;
    }

    if (alg->parameter->type != V_ASN1_SEQUENCE)
        return 0;

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
    if (EVP_PKEY_CTX_set_ecdh_kdf_outlen(pctx, keylen) <= 0)
        goto err;

    plen = CMS_SharedInfo_encode(&der, kekalg, ukm, keylen);

    if (!plen)
        goto err;

    if (EVP_PKEY_CTX_set0_ecdh_kdf_ukm(pctx, der, plen) <= 0)
        goto err;
    der = NULL;

    rv = 1;
 err:
    if (kekalg)
        X509_ALGOR_free(kekalg);
    if (der)
        OPENSSL_free(der);
    return rv;
}

static int ecdh_cms_decrypt(CMS_RecipientInfo *ri)
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
        if (!ecdh_cms_set_peerkey(pctx, alg, pubkey)) {
            ECerr(EC_F_ECDH_CMS_DECRYPT, EC_R_PEER_KEY_ERROR);
            return 0;
        }
    }
    /* Set ECDH derivation parameters and initialise unwrap context */
    if (!ecdh_cms_set_shared_info(pctx, ri)) {
        ECerr(EC_F_ECDH_CMS_DECRYPT, EC_R_SHARED_INFO_ERROR);
        return 0;
    }
    return 1;
}

static int ecdh_cms_encrypt(CMS_RecipientInfo *ri)
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
    unsigned char *penc = NULL;
    int penclen;
    int rv = 0;
    int ecdh_nid, kdf_type, kdf_nid, wrap_nid;
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

        EC_KEY *eckey = pkey->pkey.ec;
        /* Set the key */
        unsigned char *p;

        penclen = i2o_ECPublicKey(eckey, NULL);
        if (penclen <= 0)
            goto err;
        penc = OPENSSL_malloc(penclen);
        if (!penc)
            goto err;
        p = penc;
        penclen = i2o_ECPublicKey(eckey, &p);
        if (penclen <= 0)
            goto err;
        ASN1_STRING_set0(pubkey, penc, penclen);
        pubkey->flags &= ~(ASN1_STRING_FLAG_BITS_LEFT | 0x07);
        pubkey->flags |= ASN1_STRING_FLAG_BITS_LEFT;

        penc = NULL;
        X509_ALGOR_set0(talg, OBJ_nid2obj(NID_X9_62_id_ecPublicKey),
                        V_ASN1_UNDEF, NULL);
    }

    /* See if custom paraneters set */
    kdf_type = EVP_PKEY_CTX_get_ecdh_kdf_type(pctx);
    if (kdf_type <= 0)
        goto err;
    if (!EVP_PKEY_CTX_get_ecdh_kdf_md(pctx, &kdf_md))
        goto err;
    ecdh_nid = EVP_PKEY_CTX_get_ecdh_cofactor_mode(pctx);
    if (ecdh_nid < 0)
        goto err;
    else if (ecdh_nid == 0)
        ecdh_nid = NID_dh_std_kdf;
    else if (ecdh_nid == 1)
        ecdh_nid = NID_dh_cofactor_kdf;

    if (kdf_type == EVP_PKEY_ECDH_KDF_NONE) {
        kdf_type = EVP_PKEY_ECDH_KDF_X9_62;
        if (EVP_PKEY_CTX_set_ecdh_kdf_type(pctx, kdf_type) <= 0)
            goto err;
    } else
        /* Uknown KDF */
        goto err;
    if (kdf_md == NULL) {
        /* Fixme later for better MD */
        kdf_md = EVP_sha1();
        if (EVP_PKEY_CTX_set_ecdh_kdf_md(pctx, kdf_md) <= 0)
            goto err;
    }

    if (!CMS_RecipientInfo_kari_get0_alg(ri, &talg, &ukm))
        goto err;

    /* Lookup NID for KDF+cofactor+digest */

    if (!OBJ_find_sigid_by_algs(&kdf_nid, EVP_MD_type(kdf_md), ecdh_nid))
        goto err;
    /* Get wrap NID */
    ctx = CMS_RecipientInfo_kari_get0_ctx(ri);
    wrap_nid = EVP_CIPHER_CTX_type(ctx);
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

    if (EVP_PKEY_CTX_set_ecdh_kdf_outlen(pctx, keylen) <= 0)
        goto err;

    penclen = CMS_SharedInfo_encode(&penc, wrap_alg, ukm, keylen);

    if (!penclen)
        goto err;

    if (EVP_PKEY_CTX_set0_ecdh_kdf_ukm(pctx, penc, penclen) <= 0)
        goto err;
    penc = NULL;

    /*
     * Now need to wrap encoding of wrap AlgorithmIdentifier into parameter
     * of another AlgorithmIdentifier.
     */
    penclen = i2d_X509_ALGOR(wrap_alg, &penc);
    if (!penc || !penclen)
        goto err;
    wrap_str = ASN1_STRING_new();
    if (!wrap_str)
        goto err;
    ASN1_STRING_set0(wrap_str, penc, penclen);
    penc = NULL;
    X509_ALGOR_set0(talg, OBJ_nid2obj(kdf_nid), V_ASN1_SEQUENCE, wrap_str);

    rv = 1;

 err:
    if (penc)
        OPENSSL_free(penc);
    if (wrap_alg)
        X509_ALGOR_free(wrap_alg);
    return rv;
}

#endif
/* crypto/ec/ec_asn1.c */
/*
 * Written by Nils Larsch for the OpenSSL project.
 */
/* ====================================================================
 * Copyright (c) 2000-2003 The OpenSSL Project.  All rights reserved.
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

#include <string.h>
// #include "ec_lcl.h"
#include "err.h"
// #include "asn1t.h"
#include "objects.h"

#define OSSL_NELEM(x)    (sizeof(x)/sizeof(x[0]))

int EC_GROUP_get_basis_type(const EC_GROUP *group)
{
    int i;

    if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) !=
        NID_X9_62_characteristic_two_field)
        /* everything else is currently not supported */
        return 0;

    /* Find the last non-zero element of group->poly[] */
    for (i = 0;
         i < (int)OSSL_NELEM(group->poly) && group->poly[i] != 0;
         i++)
        continue;

    if (i == 4)
        return NID_X9_62_ppBasis;
    else if (i == 2)
        return NID_X9_62_tpBasis;
    else
        /* everything else is currently not supported */
        return 0;
}

#ifndef OPENSSL_NO_EC2M
int EC_GROUP_get_trinomial_basis(const EC_GROUP *group, unsigned int *k)
{
    if (group == NULL)
        return 0;

    if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) !=
        NID_X9_62_characteristic_two_field
        || !((group->poly[0] != 0) && (group->poly[1] != 0)
             && (group->poly[2] == 0))) {
        ECerr(EC_F_EC_GROUP_GET_TRINOMIAL_BASIS,
              ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }

    if (k)
        *k = group->poly[1];

    return 1;
}

int EC_GROUP_get_pentanomial_basis(const EC_GROUP *group, unsigned int *k1,
                                   unsigned int *k2, unsigned int *k3)
{
    if (group == NULL)
        return 0;

    if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) !=
        NID_X9_62_characteristic_two_field
        || !((group->poly[0] != 0) && (group->poly[1] != 0)
             && (group->poly[2] != 0) && (group->poly[3] != 0)
             && (group->poly[4] == 0))) {
        ECerr(EC_F_EC_GROUP_GET_PENTANOMIAL_BASIS,
              ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }

    if (k1)
        *k1 = group->poly[3];
    if (k2)
        *k2 = group->poly[2];
    if (k3)
        *k3 = group->poly[1];

    return 1;
}
#endif

/* some structures needed for the asn1 encoding */
typedef struct x9_62_pentanomial_st {
    long k1;
    long k2;
    long k3;
} X9_62_PENTANOMIAL;

typedef struct x9_62_characteristic_two_st {
    long m;
    ASN1_OBJECT *type;
    union {
        char *ptr;
        /* NID_X9_62_onBasis */
        ASN1_NULL *onBasis;
        /* NID_X9_62_tpBasis */
        ASN1_INTEGER *tpBasis;
        /* NID_X9_62_ppBasis */
        X9_62_PENTANOMIAL *ppBasis;
        /* anything else */
        ASN1_TYPE *other;
    } p;
} X9_62_CHARACTERISTIC_TWO;

typedef struct x9_62_fieldid_st {
    ASN1_OBJECT *fieldType;
    union {
        char *ptr;
        /* NID_X9_62_prime_field */
        ASN1_INTEGER *prime;
        /* NID_X9_62_characteristic_two_field */
        X9_62_CHARACTERISTIC_TWO *char_two;
        /* anything else */
        ASN1_TYPE *other;
    } p;
} X9_62_FIELDID;

typedef struct x9_62_curve_st {
    ASN1_OCTET_STRING *a;
    ASN1_OCTET_STRING *b;
    ASN1_BIT_STRING *seed;
} X9_62_CURVE;

typedef struct ec_parameters_st {
    long version;
    X9_62_FIELDID *fieldID;
    X9_62_CURVE *curve;
    ASN1_OCTET_STRING *base;
    ASN1_INTEGER *order;
    ASN1_INTEGER *cofactor;
} ECPARAMETERS;

struct ecpk_parameters_st {
    int type;
    union {
        ASN1_OBJECT *named_curve;
        ECPARAMETERS *parameters;
        ASN1_NULL *implicitlyCA;
    } value;
} /* ECPKPARAMETERS */ ;

/* SEC1 ECPrivateKey */
typedef struct ec_privatekey_st {
    long version;
    ASN1_OCTET_STRING *privateKey;
    ECPKPARAMETERS *parameters;
    ASN1_BIT_STRING *publicKey;
} EC_PRIVATEKEY;

/* the OpenSSL ASN.1 definitions */
ASN1_SEQUENCE(X9_62_PENTANOMIAL) = {
        ASN1_SIMPLE(X9_62_PENTANOMIAL, k1, LONG),
        ASN1_SIMPLE(X9_62_PENTANOMIAL, k2, LONG),
        ASN1_SIMPLE(X9_62_PENTANOMIAL, k3, LONG)
} ASN1_SEQUENCE_END(X9_62_PENTANOMIAL)

DECLARE_ASN1_ALLOC_FUNCTIONS(X9_62_PENTANOMIAL)
IMPLEMENT_ASN1_ALLOC_FUNCTIONS(X9_62_PENTANOMIAL)

ASN1_ADB_TEMPLATE(char_two_def) = ASN1_SIMPLE(X9_62_CHARACTERISTIC_TWO, p.other, ASN1_ANY);

ASN1_ADB(X9_62_CHARACTERISTIC_TWO) = {
        ADB_ENTRY(NID_X9_62_onBasis, ASN1_SIMPLE(X9_62_CHARACTERISTIC_TWO, p.onBasis, ASN1_NULL)),
        ADB_ENTRY(NID_X9_62_tpBasis, ASN1_SIMPLE(X9_62_CHARACTERISTIC_TWO, p.tpBasis, ASN1_INTEGER)),
        ADB_ENTRY(NID_X9_62_ppBasis, ASN1_SIMPLE(X9_62_CHARACTERISTIC_TWO, p.ppBasis, X9_62_PENTANOMIAL))
} ASN1_ADB_END(X9_62_CHARACTERISTIC_TWO, 0, type, 0, &char_two_def_tt, NULL);

ASN1_SEQUENCE(X9_62_CHARACTERISTIC_TWO) = {
        ASN1_SIMPLE(X9_62_CHARACTERISTIC_TWO, m, LONG),
        ASN1_SIMPLE(X9_62_CHARACTERISTIC_TWO, type, ASN1_OBJECT),
        ASN1_ADB_OBJECT(X9_62_CHARACTERISTIC_TWO)
} ASN1_SEQUENCE_END(X9_62_CHARACTERISTIC_TWO)

DECLARE_ASN1_ALLOC_FUNCTIONS(X9_62_CHARACTERISTIC_TWO)
IMPLEMENT_ASN1_ALLOC_FUNCTIONS(X9_62_CHARACTERISTIC_TWO)

ASN1_ADB_TEMPLATE(fieldID_def) = ASN1_SIMPLE(X9_62_FIELDID, p.other, ASN1_ANY);

ASN1_ADB(X9_62_FIELDID) = {
        ADB_ENTRY(NID_X9_62_prime_field, ASN1_SIMPLE(X9_62_FIELDID, p.prime, ASN1_INTEGER)),
        ADB_ENTRY(NID_X9_62_characteristic_two_field, ASN1_SIMPLE(X9_62_FIELDID, p.char_two, X9_62_CHARACTERISTIC_TWO))
} ASN1_ADB_END(X9_62_FIELDID, 0, fieldType, 0, &fieldID_def_tt, NULL);

ASN1_SEQUENCE(X9_62_FIELDID) = {
        ASN1_SIMPLE(X9_62_FIELDID, fieldType, ASN1_OBJECT),
        ASN1_ADB_OBJECT(X9_62_FIELDID)
} ASN1_SEQUENCE_END(X9_62_FIELDID)

ASN1_SEQUENCE(X9_62_CURVE) = {
        ASN1_SIMPLE(X9_62_CURVE, a, ASN1_OCTET_STRING),
        ASN1_SIMPLE(X9_62_CURVE, b, ASN1_OCTET_STRING),
        ASN1_OPT(X9_62_CURVE, seed, ASN1_BIT_STRING)
} ASN1_SEQUENCE_END(X9_62_CURVE)

ASN1_SEQUENCE(ECPARAMETERS) = {
        ASN1_SIMPLE(ECPARAMETERS, version, LONG),
        ASN1_SIMPLE(ECPARAMETERS, fieldID, X9_62_FIELDID),
        ASN1_SIMPLE(ECPARAMETERS, curve, X9_62_CURVE),
        ASN1_SIMPLE(ECPARAMETERS, base, ASN1_OCTET_STRING),
        ASN1_SIMPLE(ECPARAMETERS, order, ASN1_INTEGER),
        ASN1_OPT(ECPARAMETERS, cofactor, ASN1_INTEGER)
} ASN1_SEQUENCE_END(ECPARAMETERS)

DECLARE_ASN1_ALLOC_FUNCTIONS(ECPARAMETERS)
IMPLEMENT_ASN1_ALLOC_FUNCTIONS(ECPARAMETERS)

ASN1_CHOICE(ECPKPARAMETERS) = {
        ASN1_SIMPLE(ECPKPARAMETERS, value.named_curve, ASN1_OBJECT),
        ASN1_SIMPLE(ECPKPARAMETERS, value.parameters, ECPARAMETERS),
        ASN1_SIMPLE(ECPKPARAMETERS, value.implicitlyCA, ASN1_NULL)
} ASN1_CHOICE_END(ECPKPARAMETERS)

DECLARE_ASN1_FUNCTIONS_const(ECPKPARAMETERS)
DECLARE_ASN1_ENCODE_FUNCTIONS_const(ECPKPARAMETERS, ECPKPARAMETERS)
IMPLEMENT_ASN1_FUNCTIONS_const(ECPKPARAMETERS)

ASN1_SEQUENCE(EC_PRIVATEKEY) = {
        ASN1_SIMPLE(EC_PRIVATEKEY, version, LONG),
        ASN1_SIMPLE(EC_PRIVATEKEY, privateKey, ASN1_OCTET_STRING),
        ASN1_EXP_OPT(EC_PRIVATEKEY, parameters, ECPKPARAMETERS, 0),
        ASN1_EXP_OPT(EC_PRIVATEKEY, publicKey, ASN1_BIT_STRING, 1)
} ASN1_SEQUENCE_END(EC_PRIVATEKEY)

DECLARE_ASN1_FUNCTIONS_const(EC_PRIVATEKEY)
DECLARE_ASN1_ENCODE_FUNCTIONS_const(EC_PRIVATEKEY, EC_PRIVATEKEY)
IMPLEMENT_ASN1_FUNCTIONS_const(EC_PRIVATEKEY)

/* some declarations of internal function */

/* ec_asn1_group2field() sets the values in a X9_62_FIELDID object */
static int ec_asn1_group2fieldid(const EC_GROUP *, X9_62_FIELDID *);
/* ec_asn1_group2curve() sets the values in a X9_62_CURVE object */
static int ec_asn1_group2curve(const EC_GROUP *, X9_62_CURVE *);
/*
 * ec_asn1_parameters2group() creates a EC_GROUP object from a ECPARAMETERS
 * object
 */
static EC_GROUP *ec_asn1_parameters2group(const ECPARAMETERS *);
/*
 * ec_asn1_group2parameters() creates a ECPARAMETERS object from a EC_GROUP
 * object
 */
static ECPARAMETERS *ec_asn1_group2parameters(const EC_GROUP *,
                                              ECPARAMETERS *);
/*
 * ec_asn1_pkparameters2group() creates a EC_GROUP object from a
 * ECPKPARAMETERS object
 */
static EC_GROUP *ec_asn1_pkparameters2group(const ECPKPARAMETERS *);
/*
 * ec_asn1_group2pkparameters() creates a ECPKPARAMETERS object from a
 * EC_GROUP object
 */
static ECPKPARAMETERS *ec_asn1_group2pkparameters(const EC_GROUP *,
                                                  ECPKPARAMETERS *);

/* the function definitions */

static int ec_asn1_group2fieldid(const EC_GROUP *group, X9_62_FIELDID *field)
{
    int ok = 0, nid;
    BIGNUM *tmp = NULL;

    if (group == NULL || field == NULL)
        return 0;

    /* clear the old values (if necessary) */
    if (field->fieldType != NULL)
        ASN1_OBJECT_free(field->fieldType);
    if (field->p.other != NULL)
        ASN1_TYPE_free(field->p.other);

    nid = EC_METHOD_get_field_type(EC_GROUP_method_of(group));
    /* set OID for the field */
    if ((field->fieldType = OBJ_nid2obj(nid)) == NULL) {
        ECerr(EC_F_EC_ASN1_GROUP2FIELDID, ERR_R_OBJ_LIB);
        goto err;
    }

    if (nid == NID_X9_62_prime_field) {
        if ((tmp = BN_new()) == NULL) {
            ECerr(EC_F_EC_ASN1_GROUP2FIELDID, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        /* the parameters are specified by the prime number p */
        if (!EC_GROUP_get_curve_GFp(group, tmp, NULL, NULL, NULL)) {
            ECerr(EC_F_EC_ASN1_GROUP2FIELDID, ERR_R_EC_LIB);
            goto err;
        }
        /* set the prime number */
        field->p.prime = BN_to_ASN1_INTEGER(tmp, NULL);
        if (field->p.prime == NULL) {
            ECerr(EC_F_EC_ASN1_GROUP2FIELDID, ERR_R_ASN1_LIB);
            goto err;
        }
    } else                      /* nid == NID_X9_62_characteristic_two_field */
#ifdef OPENSSL_NO_EC2M
    {
        ECerr(EC_F_EC_ASN1_GROUP2FIELDID, EC_R_GF2M_NOT_SUPPORTED);
        goto err;
    }
#else
    {
        int field_type;
        X9_62_CHARACTERISTIC_TWO *char_two;

        field->p.char_two = X9_62_CHARACTERISTIC_TWO_new();
        char_two = field->p.char_two;

        if (char_two == NULL) {
            ECerr(EC_F_EC_ASN1_GROUP2FIELDID, ERR_R_MALLOC_FAILURE);
            goto err;
        }

        char_two->m = (long)EC_GROUP_get_degree(group);

        field_type = EC_GROUP_get_basis_type(group);

        if (field_type == 0) {
            ECerr(EC_F_EC_ASN1_GROUP2FIELDID, ERR_R_EC_LIB);
            goto err;
        }
        /* set base type OID */
        if ((char_two->type = OBJ_nid2obj(field_type)) == NULL) {
            ECerr(EC_F_EC_ASN1_GROUP2FIELDID, ERR_R_OBJ_LIB);
            goto err;
        }

        if (field_type == NID_X9_62_tpBasis) {
            unsigned int k;

            if (!EC_GROUP_get_trinomial_basis(group, &k))
                goto err;

            char_two->p.tpBasis = ASN1_INTEGER_new();
            if (!char_two->p.tpBasis) {
                ECerr(EC_F_EC_ASN1_GROUP2FIELDID, ERR_R_MALLOC_FAILURE);
                goto err;
            }
            if (!ASN1_INTEGER_set(char_two->p.tpBasis, (long)k)) {
                ECerr(EC_F_EC_ASN1_GROUP2FIELDID, ERR_R_ASN1_LIB);
                goto err;
            }
        } else if (field_type == NID_X9_62_ppBasis) {
            unsigned int k1, k2, k3;

            if (!EC_GROUP_get_pentanomial_basis(group, &k1, &k2, &k3))
                goto err;

            char_two->p.ppBasis = X9_62_PENTANOMIAL_new();
            if (!char_two->p.ppBasis) {
                ECerr(EC_F_EC_ASN1_GROUP2FIELDID, ERR_R_MALLOC_FAILURE);
                goto err;
            }

            /* set k? values */
            char_two->p.ppBasis->k1 = (long)k1;
            char_two->p.ppBasis->k2 = (long)k2;
            char_two->p.ppBasis->k3 = (long)k3;
        } else {                /* field_type == NID_X9_62_onBasis */

            /* for ONB the parameters are (asn1) NULL */
            char_two->p.onBasis = ASN1_NULL_new();
            if (!char_two->p.onBasis) {
                ECerr(EC_F_EC_ASN1_GROUP2FIELDID, ERR_R_MALLOC_FAILURE);
                goto err;
            }
        }
    }
#endif

    ok = 1;

 err:if (tmp)
        BN_free(tmp);
    return (ok);
}

static int ec_asn1_group2curve(const EC_GROUP *group, X9_62_CURVE *curve)
{
    int ok = 0, nid;
    BIGNUM *tmp_1 = NULL, *tmp_2 = NULL;
    unsigned char *buffer_1 = NULL, *buffer_2 = NULL,
        *a_buf = NULL, *b_buf = NULL;
    size_t len_1, len_2;
    unsigned char char_zero = 0;

    if (!group || !curve || !curve->a || !curve->b)
        return 0;

    if ((tmp_1 = BN_new()) == NULL || (tmp_2 = BN_new()) == NULL) {
        ECerr(EC_F_EC_ASN1_GROUP2CURVE, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    nid = EC_METHOD_get_field_type(EC_GROUP_method_of(group));

    /* get a and b */
    if (nid == NID_X9_62_prime_field) {
        if (!EC_GROUP_get_curve_GFp(group, NULL, tmp_1, tmp_2, NULL)) {
            ECerr(EC_F_EC_ASN1_GROUP2CURVE, ERR_R_EC_LIB);
            goto err;
        }
    }
#ifndef OPENSSL_NO_EC2M
    else {                      /* nid == NID_X9_62_characteristic_two_field */

        if (!EC_GROUP_get_curve_GF2m(group, NULL, tmp_1, tmp_2, NULL)) {
            ECerr(EC_F_EC_ASN1_GROUP2CURVE, ERR_R_EC_LIB);
            goto err;
        }
    }
#endif
    len_1 = (size_t)BN_num_bytes(tmp_1);
    len_2 = (size_t)BN_num_bytes(tmp_2);

    if (len_1 == 0) {
        /* len_1 == 0 => a == 0 */
        a_buf = &char_zero;
        len_1 = 1;
    } else {
        if ((buffer_1 = OPENSSL_malloc(len_1)) == NULL) {
            ECerr(EC_F_EC_ASN1_GROUP2CURVE, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        if ((len_1 = BN_bn2bin(tmp_1, buffer_1)) == 0) {
            ECerr(EC_F_EC_ASN1_GROUP2CURVE, ERR_R_BN_LIB);
            goto err;
        }
        a_buf = buffer_1;
    }

    if (len_2 == 0) {
        /* len_2 == 0 => b == 0 */
        b_buf = &char_zero;
        len_2 = 1;
    } else {
        if ((buffer_2 = OPENSSL_malloc(len_2)) == NULL) {
            ECerr(EC_F_EC_ASN1_GROUP2CURVE, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        if ((len_2 = BN_bn2bin(tmp_2, buffer_2)) == 0) {
            ECerr(EC_F_EC_ASN1_GROUP2CURVE, ERR_R_BN_LIB);
            goto err;
        }
        b_buf = buffer_2;
    }

    /* set a and b */
    if (!M_ASN1_OCTET_STRING_set(curve->a, a_buf, len_1) ||
        !M_ASN1_OCTET_STRING_set(curve->b, b_buf, len_2)) {
        ECerr(EC_F_EC_ASN1_GROUP2CURVE, ERR_R_ASN1_LIB);
        goto err;
    }

    /* set the seed (optional) */
    if (group->seed) {
        if (!curve->seed)
            if ((curve->seed = ASN1_BIT_STRING_new()) == NULL) {
                ECerr(EC_F_EC_ASN1_GROUP2CURVE, ERR_R_MALLOC_FAILURE);
                goto err;
            }
        curve->seed->flags &= ~(ASN1_STRING_FLAG_BITS_LEFT | 0x07);
        curve->seed->flags |= ASN1_STRING_FLAG_BITS_LEFT;
        if (!ASN1_BIT_STRING_set(curve->seed, group->seed,
                                 (int)group->seed_len)) {
            ECerr(EC_F_EC_ASN1_GROUP2CURVE, ERR_R_ASN1_LIB);
            goto err;
        }
    } else {
        if (curve->seed) {
            ASN1_BIT_STRING_free(curve->seed);
            curve->seed = NULL;
        }
    }

    ok = 1;

 err:if (buffer_1)
        OPENSSL_free(buffer_1);
    if (buffer_2)
        OPENSSL_free(buffer_2);
    if (tmp_1)
        BN_free(tmp_1);
    if (tmp_2)
        BN_free(tmp_2);
    return (ok);
}

static ECPARAMETERS *ec_asn1_group2parameters(const EC_GROUP *group,
                                              ECPARAMETERS *param)
{
    int ok = 0;
    size_t len = 0;
    ECPARAMETERS *ret = NULL;
    BIGNUM *tmp = NULL;
    unsigned char *buffer = NULL;
    const EC_POINT *point = NULL;
    point_conversion_form_t form;

    if ((tmp = BN_new()) == NULL) {
        ECerr(EC_F_EC_ASN1_GROUP2PARAMETERS, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (param == NULL) {
        if ((ret = ECPARAMETERS_new()) == NULL) {
            ECerr(EC_F_EC_ASN1_GROUP2PARAMETERS, ERR_R_MALLOC_FAILURE);
            goto err;
        }
    } else
        ret = param;

    /* set the version (always one) */
    ret->version = (long)0x1;

    /* set the fieldID */
    if (!ec_asn1_group2fieldid(group, ret->fieldID)) {
        ECerr(EC_F_EC_ASN1_GROUP2PARAMETERS, ERR_R_EC_LIB);
        goto err;
    }

    /* set the curve */
    if (!ec_asn1_group2curve(group, ret->curve)) {
        ECerr(EC_F_EC_ASN1_GROUP2PARAMETERS, ERR_R_EC_LIB);
        goto err;
    }

    /* set the base point */
    if ((point = EC_GROUP_get0_generator(group)) == NULL) {
        ECerr(EC_F_EC_ASN1_GROUP2PARAMETERS, EC_R_UNDEFINED_GENERATOR);
        goto err;
    }

    form = EC_GROUP_get_point_conversion_form(group);

    len = EC_POINT_point2oct(group, point, form, NULL, len, NULL);
    if (len == 0) {
        ECerr(EC_F_EC_ASN1_GROUP2PARAMETERS, ERR_R_EC_LIB);
        goto err;
    }
    if ((buffer = OPENSSL_malloc(len)) == NULL) {
        ECerr(EC_F_EC_ASN1_GROUP2PARAMETERS, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    if (!EC_POINT_point2oct(group, point, form, buffer, len, NULL)) {
        ECerr(EC_F_EC_ASN1_GROUP2PARAMETERS, ERR_R_EC_LIB);
        goto err;
    }
    if (ret->base == NULL && (ret->base = ASN1_OCTET_STRING_new()) == NULL) {
        ECerr(EC_F_EC_ASN1_GROUP2PARAMETERS, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    if (!ASN1_OCTET_STRING_set(ret->base, buffer, len)) {
        ECerr(EC_F_EC_ASN1_GROUP2PARAMETERS, ERR_R_ASN1_LIB);
        goto err;
    }

    /* set the order */
    if (!EC_GROUP_get_order(group, tmp, NULL)) {
        ECerr(EC_F_EC_ASN1_GROUP2PARAMETERS, ERR_R_EC_LIB);
        goto err;
    }
    ret->order = BN_to_ASN1_INTEGER(tmp, ret->order);
    if (ret->order == NULL) {
        ECerr(EC_F_EC_ASN1_GROUP2PARAMETERS, ERR_R_ASN1_LIB);
        goto err;
    }

    /* set the cofactor (optional) */
    if (EC_GROUP_get_cofactor(group, tmp, NULL)) {
        ret->cofactor = BN_to_ASN1_INTEGER(tmp, ret->cofactor);
        if (ret->cofactor == NULL) {
            ECerr(EC_F_EC_ASN1_GROUP2PARAMETERS, ERR_R_ASN1_LIB);
            goto err;
        }
    }

    ok = 1;

 err:if (!ok) {
        if (ret && !param)
            ECPARAMETERS_free(ret);
        ret = NULL;
    }
    if (tmp)
        BN_free(tmp);
    if (buffer)
        OPENSSL_free(buffer);
    return (ret);
}

ECPKPARAMETERS *ec_asn1_group2pkparameters(const EC_GROUP *group,
                                           ECPKPARAMETERS *params)
{
    int ok = 1, tmp;
    ECPKPARAMETERS *ret = params;

    if (ret == NULL) {
        if ((ret = ECPKPARAMETERS_new()) == NULL) {
            ECerr(EC_F_EC_ASN1_GROUP2PKPARAMETERS, ERR_R_MALLOC_FAILURE);
            return NULL;
        }
    } else {
        if (ret->type == 0 && ret->value.named_curve)
            ASN1_OBJECT_free(ret->value.named_curve);
        else if (ret->type == 1 && ret->value.parameters)
            ECPARAMETERS_free(ret->value.parameters);
    }

    if (EC_GROUP_get_asn1_flag(group)) {
        /*
         * use the asn1 OID to describe the the elliptic curve parameters
         */
        tmp = EC_GROUP_get_curve_name(group);
        if (tmp) {
            ret->type = 0;
            if ((ret->value.named_curve = OBJ_nid2obj(tmp)) == NULL)
                ok = 0;
        } else
            /* we don't kmow the nid => ERROR */
            ok = 0;
    } else {
        /* use the ECPARAMETERS structure */
        ret->type = 1;
        if ((ret->value.parameters =
             ec_asn1_group2parameters(group, NULL)) == NULL)
            ok = 0;
    }

    if (!ok) {
        ECPKPARAMETERS_free(ret);
        return NULL;
    }
    return ret;
}

static EC_GROUP *ec_asn1_parameters2group(const ECPARAMETERS *params)
{
    int ok = 0, tmp;
    EC_GROUP *ret = NULL;
    BIGNUM *p = NULL, *a = NULL, *b = NULL;
    EC_POINT *point = NULL;
    long field_bits;

    if (!params->fieldID || !params->fieldID->fieldType ||
        !params->fieldID->p.ptr) {
        ECerr(EC_F_EC_ASN1_PARAMETERS2GROUP, EC_R_ASN1_ERROR);
        goto err;
    }

    /* now extract the curve parameters a and b */
    if (!params->curve || !params->curve->a ||
        !params->curve->a->data || !params->curve->b ||
        !params->curve->b->data) {
        ECerr(EC_F_EC_ASN1_PARAMETERS2GROUP, EC_R_ASN1_ERROR);
        goto err;
    }
    a = BN_bin2bn(params->curve->a->data, params->curve->a->length, NULL);
    if (a == NULL) {
        ECerr(EC_F_EC_ASN1_PARAMETERS2GROUP, ERR_R_BN_LIB);
        goto err;
    }
    b = BN_bin2bn(params->curve->b->data, params->curve->b->length, NULL);
    if (b == NULL) {
        ECerr(EC_F_EC_ASN1_PARAMETERS2GROUP, ERR_R_BN_LIB);
        goto err;
    }

    /* get the field parameters */
    tmp = OBJ_obj2nid(params->fieldID->fieldType);
    if (tmp == NID_X9_62_characteristic_two_field)
#ifdef OPENSSL_NO_EC2M
    {
        ECerr(EC_F_EC_ASN1_PARAMETERS2GROUP, EC_R_GF2M_NOT_SUPPORTED);
        goto err;
    }
#else
    {
        X9_62_CHARACTERISTIC_TWO *char_two;

        char_two = params->fieldID->p.char_two;

        field_bits = char_two->m;
        if (field_bits > OPENSSL_ECC_MAX_FIELD_BITS) {
            ECerr(EC_F_EC_ASN1_PARAMETERS2GROUP, EC_R_FIELD_TOO_LARGE);
            goto err;
        }

        if ((p = BN_new()) == NULL) {
            ECerr(EC_F_EC_ASN1_PARAMETERS2GROUP, ERR_R_MALLOC_FAILURE);
            goto err;
        }

        /* get the base type */
        tmp = OBJ_obj2nid(char_two->type);

        if (tmp == NID_X9_62_tpBasis) {
            long tmp_long;

            if (!char_two->p.tpBasis) {
                ECerr(EC_F_EC_ASN1_PARAMETERS2GROUP, EC_R_ASN1_ERROR);
                goto err;
            }

            tmp_long = ASN1_INTEGER_get(char_two->p.tpBasis);

            if (!(char_two->m > tmp_long && tmp_long > 0)) {
                ECerr(EC_F_EC_ASN1_PARAMETERS2GROUP,
                      EC_R_INVALID_TRINOMIAL_BASIS);
                goto err;
            }

            /* create the polynomial */
            if (!BN_set_bit(p, (int)char_two->m))
                goto err;
            if (!BN_set_bit(p, (int)tmp_long))
                goto err;
            if (!BN_set_bit(p, 0))
                goto err;
        } else if (tmp == NID_X9_62_ppBasis) {
            X9_62_PENTANOMIAL *penta;

            penta = char_two->p.ppBasis;
            if (!penta) {
                ECerr(EC_F_EC_ASN1_PARAMETERS2GROUP, EC_R_ASN1_ERROR);
                goto err;
            }

            if (!
                (char_two->m > penta->k3 && penta->k3 > penta->k2
                 && penta->k2 > penta->k1 && penta->k1 > 0)) {
                ECerr(EC_F_EC_ASN1_PARAMETERS2GROUP,
                      EC_R_INVALID_PENTANOMIAL_BASIS);
                goto err;
            }

            /* create the polynomial */
            if (!BN_set_bit(p, (int)char_two->m))
                goto err;
            if (!BN_set_bit(p, (int)penta->k1))
                goto err;
            if (!BN_set_bit(p, (int)penta->k2))
                goto err;
            if (!BN_set_bit(p, (int)penta->k3))
                goto err;
            if (!BN_set_bit(p, 0))
                goto err;
        } else if (tmp == NID_X9_62_onBasis) {
            ECerr(EC_F_EC_ASN1_PARAMETERS2GROUP, EC_R_NOT_IMPLEMENTED);
            goto err;
        } else {                /* error */

            ECerr(EC_F_EC_ASN1_PARAMETERS2GROUP, EC_R_ASN1_ERROR);
            goto err;
        }

        /* create the EC_GROUP structure */
        ret = EC_GROUP_new_curve_GF2m(p, a, b, NULL);
    }
#endif
    else if (tmp == NID_X9_62_prime_field) {
        /* we have a curve over a prime field */
        /* extract the prime number */
        if (!params->fieldID->p.prime) {
            ECerr(EC_F_EC_ASN1_PARAMETERS2GROUP, EC_R_ASN1_ERROR);
            goto err;
        }
        p = ASN1_INTEGER_to_BN(params->fieldID->p.prime, NULL);
        if (p == NULL) {
            ECerr(EC_F_EC_ASN1_PARAMETERS2GROUP, ERR_R_ASN1_LIB);
            goto err;
        }

        if (BN_is_negative(p) || BN_is_zero(p)) {
            ECerr(EC_F_EC_ASN1_PARAMETERS2GROUP, EC_R_INVALID_FIELD);
            goto err;
        }

        field_bits = BN_num_bits(p);
        if (field_bits > OPENSSL_ECC_MAX_FIELD_BITS) {
            ECerr(EC_F_EC_ASN1_PARAMETERS2GROUP, EC_R_FIELD_TOO_LARGE);
            goto err;
        }

        /* create the EC_GROUP structure */
        ret = EC_GROUP_new_curve_GFp(p, a, b, NULL);
    } else {
        ECerr(EC_F_EC_ASN1_PARAMETERS2GROUP, EC_R_INVALID_FIELD);
        goto err;
    }

    if (ret == NULL) {
        ECerr(EC_F_EC_ASN1_PARAMETERS2GROUP, ERR_R_EC_LIB);
        goto err;
    }

    /* extract seed (optional) */
    if (params->curve->seed != NULL) {
        if (ret->seed != NULL)
            OPENSSL_free(ret->seed);
        if (!(ret->seed = OPENSSL_malloc(params->curve->seed->length))) {
            ECerr(EC_F_EC_ASN1_PARAMETERS2GROUP, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        memcpy(ret->seed, params->curve->seed->data,
               params->curve->seed->length);
        ret->seed_len = params->curve->seed->length;
    }

    if (!params->order || !params->base || !params->base->data) {
        ECerr(EC_F_EC_ASN1_PARAMETERS2GROUP, EC_R_ASN1_ERROR);
        goto err;
    }

    if ((point = EC_POINT_new(ret)) == NULL)
        goto err;

    /* set the point conversion form */
    EC_GROUP_set_point_conversion_form(ret, (point_conversion_form_t)
                                       (params->base->data[0] & ~0x01));

    /* extract the ec point */
    if (!EC_POINT_oct2point(ret, point, params->base->data,
                            params->base->length, NULL)) {
        ECerr(EC_F_EC_ASN1_PARAMETERS2GROUP, ERR_R_EC_LIB);
        goto err;
    }

    /* extract the order */
    if ((a = ASN1_INTEGER_to_BN(params->order, a)) == NULL) {
        ECerr(EC_F_EC_ASN1_PARAMETERS2GROUP, ERR_R_ASN1_LIB);
        goto err;
    }
    if (BN_is_negative(a) || BN_is_zero(a)) {
        ECerr(EC_F_EC_ASN1_PARAMETERS2GROUP, EC_R_INVALID_GROUP_ORDER);
        goto err;
    }
    if (BN_num_bits(a) > (int)field_bits + 1) { /* Hasse bound */
        ECerr(EC_F_EC_ASN1_PARAMETERS2GROUP, EC_R_INVALID_GROUP_ORDER);
        goto err;
    }

    /* extract the cofactor (optional) */
    if (params->cofactor == NULL) {
        if (b) {
            BN_free(b);
            b = NULL;
        }
    } else if ((b = ASN1_INTEGER_to_BN(params->cofactor, b)) == NULL) {
        ECerr(EC_F_EC_ASN1_PARAMETERS2GROUP, ERR_R_ASN1_LIB);
        goto err;
    }
    /* set the generator, order and cofactor (if present) */
    if (!EC_GROUP_set_generator(ret, point, a, b)) {
        ECerr(EC_F_EC_ASN1_PARAMETERS2GROUP, ERR_R_EC_LIB);
        goto err;
    }

    ok = 1;

 err:if (!ok) {
        if (ret)
            EC_GROUP_clear_free(ret);
        ret = NULL;
    }

    if (p)
        BN_free(p);
    if (a)
        BN_free(a);
    if (b)
        BN_free(b);
    if (point)
        EC_POINT_free(point);
    return (ret);
}

EC_GROUP *ec_asn1_pkparameters2group(const ECPKPARAMETERS *params)
{
    EC_GROUP *ret = NULL;
    int tmp = 0;

    if (params == NULL) {
        ECerr(EC_F_EC_ASN1_PKPARAMETERS2GROUP, EC_R_MISSING_PARAMETERS);
        return NULL;
    }

    if (params->type == 0) {    /* the curve is given by an OID */
        tmp = OBJ_obj2nid(params->value.named_curve);
        if ((ret = EC_GROUP_new_by_curve_name(tmp)) == NULL) {
            ECerr(EC_F_EC_ASN1_PKPARAMETERS2GROUP,
                  EC_R_EC_GROUP_NEW_BY_NAME_FAILURE);
            return NULL;
        }
        EC_GROUP_set_asn1_flag(ret, OPENSSL_EC_NAMED_CURVE);
    } else if (params->type == 1) { /* the parameters are given by a
                                     * ECPARAMETERS structure */
        ret = ec_asn1_parameters2group(params->value.parameters);
        if (!ret) {
            ECerr(EC_F_EC_ASN1_PKPARAMETERS2GROUP, ERR_R_EC_LIB);
            return NULL;
        }
        EC_GROUP_set_asn1_flag(ret, 0x0);
    } else if (params->type == 2) { /* implicitlyCA */
        return NULL;
    } else {
        ECerr(EC_F_EC_ASN1_PKPARAMETERS2GROUP, EC_R_ASN1_ERROR);
        return NULL;
    }

    return ret;
}

/* EC_GROUP <-> DER encoding of ECPKPARAMETERS */

EC_GROUP *d2i_ECPKParameters(EC_GROUP **a, const unsigned char **in, long len)
{
    EC_GROUP *group = NULL;
    ECPKPARAMETERS *params = NULL;
    const unsigned char *p = *in;

    if ((params = d2i_ECPKPARAMETERS(NULL, &p, len)) == NULL) {
        ECerr(EC_F_D2I_ECPKPARAMETERS, EC_R_D2I_ECPKPARAMETERS_FAILURE);
        ECPKPARAMETERS_free(params);
        return NULL;
    }

    if ((group = ec_asn1_pkparameters2group(params)) == NULL) {
        ECerr(EC_F_D2I_ECPKPARAMETERS, EC_R_PKPARAMETERS2GROUP_FAILURE);
        ECPKPARAMETERS_free(params);
        return NULL;
    }

    if (a && *a)
        EC_GROUP_clear_free(*a);
    if (a)
        *a = group;

    ECPKPARAMETERS_free(params);
    *in = p;
    return (group);
}

int i2d_ECPKParameters(const EC_GROUP *a, unsigned char **out)
{
    int ret = 0;
    ECPKPARAMETERS *tmp = ec_asn1_group2pkparameters(a, NULL);
    if (tmp == NULL) {
        ECerr(EC_F_I2D_ECPKPARAMETERS, EC_R_GROUP2PKPARAMETERS_FAILURE);
        return 0;
    }
    if ((ret = i2d_ECPKPARAMETERS(tmp, out)) == 0) {
        ECerr(EC_F_I2D_ECPKPARAMETERS, EC_R_I2D_ECPKPARAMETERS_FAILURE);
        ECPKPARAMETERS_free(tmp);
        return 0;
    }
    ECPKPARAMETERS_free(tmp);
    return (ret);
}

/* some EC_KEY functions */

EC_KEY *d2i_ECPrivateKey(EC_KEY **a, const unsigned char **in, long len)
{
    int ok = 0;
    EC_KEY *ret = NULL;
    EC_PRIVATEKEY *priv_key = NULL;
    const unsigned char *p = *in;

    if ((priv_key = d2i_EC_PRIVATEKEY(NULL, &p, len)) == NULL) {
        ECerr(EC_F_D2I_ECPRIVATEKEY, ERR_R_EC_LIB);
        return NULL;
    }

    if (a == NULL || *a == NULL) {
        if ((ret = EC_KEY_new()) == NULL) {
            ECerr(EC_F_D2I_ECPRIVATEKEY, ERR_R_MALLOC_FAILURE);
            goto err;
        }
    } else
        ret = *a;

    if (priv_key->parameters) {
        if (ret->group)
            EC_GROUP_clear_free(ret->group);
        ret->group = ec_asn1_pkparameters2group(priv_key->parameters);
    }

    if (ret->group == NULL) {
        ECerr(EC_F_D2I_ECPRIVATEKEY, ERR_R_EC_LIB);
        goto err;
    }

    ret->version = priv_key->version;

    if (priv_key->privateKey) {
        ret->priv_key = BN_bin2bn(M_ASN1_STRING_data(priv_key->privateKey),
                                  M_ASN1_STRING_length(priv_key->privateKey),
                                  ret->priv_key);
        if (ret->priv_key == NULL) {
            ECerr(EC_F_D2I_ECPRIVATEKEY, ERR_R_BN_LIB);
            goto err;
        }
    } else {
        ECerr(EC_F_D2I_ECPRIVATEKEY, EC_R_MISSING_PRIVATE_KEY);
        goto err;
    }

    if (ret->pub_key)
        EC_POINT_clear_free(ret->pub_key);
    ret->pub_key = EC_POINT_new(ret->group);
    if (ret->pub_key == NULL) {
        ECerr(EC_F_D2I_ECPRIVATEKEY, ERR_R_EC_LIB);
        goto err;
    }

    if (priv_key->publicKey) {
        const unsigned char *pub_oct;
        int pub_oct_len;

        pub_oct = M_ASN1_STRING_data(priv_key->publicKey);
        pub_oct_len = M_ASN1_STRING_length(priv_key->publicKey);
        /*
         * The first byte - point conversion form - must be present.
         */
        if (pub_oct_len <= 0) {
            ECerr(EC_F_D2I_ECPRIVATEKEY, EC_R_BUFFER_TOO_SMALL);
            goto err;
        }
        /* Save the point conversion form. */
        ret->conv_form = (point_conversion_form_t) (pub_oct[0] & ~0x01);
        if (!EC_POINT_oct2point(ret->group, ret->pub_key,
                                pub_oct, (size_t)(pub_oct_len), NULL)) {
            ECerr(EC_F_D2I_ECPRIVATEKEY, ERR_R_EC_LIB);
            goto err;
        }
    } else {
        if (!EC_POINT_mul
            (ret->group, ret->pub_key, ret->priv_key, NULL, NULL, NULL)) {
            ECerr(EC_F_D2I_ECPRIVATEKEY, ERR_R_EC_LIB);
            goto err;
        }
        /* Remember the original private-key-only encoding. */
        ret->enc_flag |= EC_PKEY_NO_PUBKEY;
    }

    if (a)
        *a = ret;
    *in = p;
    ok = 1;
 err:
    if (!ok) {
        if (ret && (a == NULL || *a != ret))
            EC_KEY_free(ret);
        ret = NULL;
    }

    if (priv_key)
        EC_PRIVATEKEY_free(priv_key);

    return (ret);
}

int i2d_ECPrivateKey(EC_KEY *a, unsigned char **out)
{
    int ret = 0, ok = 0;
    unsigned char *buffer = NULL;
    size_t buf_len = 0, tmp_len, bn_len;
    EC_PRIVATEKEY *priv_key = NULL;

    if (a == NULL || a->group == NULL || a->priv_key == NULL ||
        (!(a->enc_flag & EC_PKEY_NO_PUBKEY) && a->pub_key == NULL)) {
        ECerr(EC_F_I2D_ECPRIVATEKEY, ERR_R_PASSED_NULL_PARAMETER);
        goto err;
    }

    if ((priv_key = EC_PRIVATEKEY_new()) == NULL) {
        ECerr(EC_F_I2D_ECPRIVATEKEY, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    priv_key->version = a->version;

    bn_len = (size_t)BN_num_bytes(a->priv_key);

    /* Octetstring may need leading zeros if BN is to short */

    buf_len = (EC_GROUP_get_degree(a->group) + 7) / 8;

    if (bn_len > buf_len) {
        ECerr(EC_F_I2D_ECPRIVATEKEY, EC_R_BUFFER_TOO_SMALL);
        goto err;
    }

    buffer = OPENSSL_malloc(buf_len);
    if (buffer == NULL) {
        ECerr(EC_F_I2D_ECPRIVATEKEY, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (!BN_bn2bin(a->priv_key, buffer + buf_len - bn_len)) {
        ECerr(EC_F_I2D_ECPRIVATEKEY, ERR_R_BN_LIB);
        goto err;
    }

    if (buf_len - bn_len > 0) {
        memset(buffer, 0, buf_len - bn_len);
    }

    if (!M_ASN1_OCTET_STRING_set(priv_key->privateKey, buffer, buf_len)) {
        ECerr(EC_F_I2D_ECPRIVATEKEY, ERR_R_ASN1_LIB);
        goto err;
    }

    if (!(a->enc_flag & EC_PKEY_NO_PARAMETERS)) {
        if ((priv_key->parameters =
             ec_asn1_group2pkparameters(a->group,
                                        priv_key->parameters)) == NULL) {
            ECerr(EC_F_I2D_ECPRIVATEKEY, ERR_R_EC_LIB);
            goto err;
        }
    }

    if (!(a->enc_flag & EC_PKEY_NO_PUBKEY)) {
        priv_key->publicKey = M_ASN1_BIT_STRING_new();
        if (priv_key->publicKey == NULL) {
            ECerr(EC_F_I2D_ECPRIVATEKEY, ERR_R_MALLOC_FAILURE);
            goto err;
        }

        tmp_len = EC_POINT_point2oct(a->group, a->pub_key,
                                     a->conv_form, NULL, 0, NULL);

        if (tmp_len > buf_len) {
            unsigned char *tmp_buffer = OPENSSL_realloc(buffer, tmp_len);
            if (!tmp_buffer) {
                ECerr(EC_F_I2D_ECPRIVATEKEY, ERR_R_MALLOC_FAILURE);
                goto err;
            }
            buffer = tmp_buffer;
            buf_len = tmp_len;
        }

        if (!EC_POINT_point2oct(a->group, a->pub_key,
                                a->conv_form, buffer, buf_len, NULL)) {
            ECerr(EC_F_I2D_ECPRIVATEKEY, ERR_R_EC_LIB);
            goto err;
        }

        priv_key->publicKey->flags &= ~(ASN1_STRING_FLAG_BITS_LEFT | 0x07);
        priv_key->publicKey->flags |= ASN1_STRING_FLAG_BITS_LEFT;
        if (!M_ASN1_BIT_STRING_set(priv_key->publicKey, buffer, buf_len)) {
            ECerr(EC_F_I2D_ECPRIVATEKEY, ERR_R_ASN1_LIB);
            goto err;
        }
    }

    if ((ret = i2d_EC_PRIVATEKEY(priv_key, out)) == 0) {
        ECerr(EC_F_I2D_ECPRIVATEKEY, ERR_R_EC_LIB);
        goto err;
    }
    ok = 1;
 err:
    if (buffer)
        OPENSSL_free(buffer);
    if (priv_key)
        EC_PRIVATEKEY_free(priv_key);
    return (ok ? ret : 0);
}

int i2d_ECParameters(EC_KEY *a, unsigned char **out)
{
    if (a == NULL) {
        ECerr(EC_F_I2D_ECPARAMETERS, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    return i2d_ECPKParameters(a->group, out);
}

EC_KEY *d2i_ECParameters(EC_KEY **a, const unsigned char **in, long len)
{
    EC_KEY *ret;

    if (in == NULL || *in == NULL) {
        ECerr(EC_F_D2I_ECPARAMETERS, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    if (a == NULL || *a == NULL) {
        if ((ret = EC_KEY_new()) == NULL) {
            ECerr(EC_F_D2I_ECPARAMETERS, ERR_R_MALLOC_FAILURE);
            return NULL;
        }
    } else
        ret = *a;

    if (!d2i_ECPKParameters(&ret->group, in, len)) {
        ECerr(EC_F_D2I_ECPARAMETERS, ERR_R_EC_LIB);
        if (a == NULL || *a != ret)
             EC_KEY_free(ret);
        return NULL;
    }

    if (a)
        *a = ret;

    return ret;
}

EC_KEY *o2i_ECPublicKey(EC_KEY **a, const unsigned char **in, long len)
{
    EC_KEY *ret = NULL;

    if (a == NULL || (*a) == NULL || (*a)->group == NULL) {
        /*
         * sorry, but a EC_GROUP-structur is necessary to set the public key
         */
        ECerr(EC_F_O2I_ECPUBLICKEY, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    ret = *a;
    if (ret->pub_key == NULL &&
        (ret->pub_key = EC_POINT_new(ret->group)) == NULL) {
        ECerr(EC_F_O2I_ECPUBLICKEY, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    if (!EC_POINT_oct2point(ret->group, ret->pub_key, *in, len, NULL)) {
        ECerr(EC_F_O2I_ECPUBLICKEY, ERR_R_EC_LIB);
        return 0;
    }
    /* save the point conversion form */
    ret->conv_form = (point_conversion_form_t) (*in[0] & ~0x01);
    *in += len;
    return ret;
}

int i2o_ECPublicKey(EC_KEY *a, unsigned char **out)
{
    size_t buf_len = 0;
    int new_buffer = 0;

    if (a == NULL) {
        ECerr(EC_F_I2O_ECPUBLICKEY, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    buf_len = EC_POINT_point2oct(a->group, a->pub_key,
                                 a->conv_form, NULL, 0, NULL);

    if (out == NULL || buf_len == 0)
        /* out == NULL => just return the length of the octet string */
        return buf_len;

    if (*out == NULL) {
        if ((*out = OPENSSL_malloc(buf_len)) == NULL) {
            ECerr(EC_F_I2O_ECPUBLICKEY, ERR_R_MALLOC_FAILURE);
            return 0;
        }
        new_buffer = 1;
    }
    if (!EC_POINT_point2oct(a->group, a->pub_key, a->conv_form,
                            *out, buf_len, NULL)) {
        ECerr(EC_F_I2O_ECPUBLICKEY, ERR_R_EC_LIB);
        if (new_buffer) {
            OPENSSL_free(*out);
            *out = NULL;
        }
        return 0;
    }
    if (!new_buffer)
        *out += buf_len;
    return buf_len;
}
/* crypto/ec/ec_check.c */
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

// #include "ec_lcl.h"
// #include "err.h"

int EC_GROUP_check(const EC_GROUP *group, BN_CTX *ctx)
{
    int ret = 0;
    BIGNUM *order;
    BN_CTX *new_ctx = NULL;
    EC_POINT *point = NULL;

    if (ctx == NULL) {
        ctx = new_ctx = BN_CTX_new();
        if (ctx == NULL) {
            ECerr(EC_F_EC_GROUP_CHECK, ERR_R_MALLOC_FAILURE);
            goto err;
        }
    }
    BN_CTX_start(ctx);
    if ((order = BN_CTX_get(ctx)) == NULL)
        goto err;

    /* check the discriminant */
    if (!EC_GROUP_check_discriminant(group, ctx)) {
        ECerr(EC_F_EC_GROUP_CHECK, EC_R_DISCRIMINANT_IS_ZERO);
        goto err;
    }

    /* check the generator */
    if (group->generator == NULL) {
        ECerr(EC_F_EC_GROUP_CHECK, EC_R_UNDEFINED_GENERATOR);
        goto err;
    }
    if (EC_POINT_is_on_curve(group, group->generator, ctx) <= 0) {
        ECerr(EC_F_EC_GROUP_CHECK, EC_R_POINT_IS_NOT_ON_CURVE);
        goto err;
    }

    /* check the order of the generator */
    if ((point = EC_POINT_new(group)) == NULL)
        goto err;
    if (!EC_GROUP_get_order(group, order, ctx))
        goto err;
    if (BN_is_zero(order)) {
        ECerr(EC_F_EC_GROUP_CHECK, EC_R_UNDEFINED_ORDER);
        goto err;
    }

    if (!EC_POINT_mul(group, point, order, NULL, NULL, ctx))
        goto err;
    if (!EC_POINT_is_at_infinity(group, point)) {
        ECerr(EC_F_EC_GROUP_CHECK, EC_R_INVALID_GROUP_ORDER);
        goto err;
    }

    ret = 1;

 err:
    if (ctx != NULL)
        BN_CTX_end(ctx);
    if (new_ctx != NULL)
        BN_CTX_free(new_ctx);
    if (point)
        EC_POINT_free(point);
    return ret;
}
/* crypto/ec/ec_curve.c */
/*
 * Written by Nils Larsch for the OpenSSL project.
 */
/* ====================================================================
 * Copyright (c) 1998-2010 The OpenSSL Project.  All rights reserved.
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
/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 *
 * Portions of the attached software ("Contribution") are developed by
 * SUN MICROSYSTEMS, INC., and are contributed to the OpenSSL project.
 *
 * The Contribution is licensed pursuant to the OpenSSL open source
 * license provided above.
 *
 * The elliptic curve binary polynomial software is originally written by
 * Sheueling Chang Shantz and Douglas Stebila of Sun Microsystems Laboratories.
 *
 */

#include <string.h>
// #include "ec_lcl.h"
// #include "err.h"
// #include "obj_mac.h"
#include "opensslconf.h"

#ifdef OPENSSL_FIPS
# include <fips.h>
#endif

typedef struct {
    int field_type,             /* either NID_X9_62_prime_field or
                                 * NID_X9_62_characteristic_two_field */
     seed_len, param_len;
    unsigned int cofactor;      /* promoted to BN_ULONG */
} EC_CURVE_DATA;

/* the nist prime curves */
static const struct {
    EC_CURVE_DATA h;
    unsigned char data[20 + 24 * 6];
} _EC_NIST_PRIME_192 = {
    {
        NID_X9_62_prime_field, 20, 24, 1
    },
    {
        /* seed */
        0x30, 0x45, 0xAE, 0x6F, 0xC8, 0x42, 0x2F, 0x64, 0xED, 0x57, 0x95, 0x28,
        0xD3, 0x81, 0x20, 0xEA, 0xE1, 0x21, 0x96, 0xD5,
        /* p */
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        /* a */
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC,
        /* b */
        0x64, 0x21, 0x05, 0x19, 0xE5, 0x9C, 0x80, 0xE7, 0x0F, 0xA7, 0xE9, 0xAB,
        0x72, 0x24, 0x30, 0x49, 0xFE, 0xB8, 0xDE, 0xEC, 0xC1, 0x46, 0xB9, 0xB1,
        /* x */
        0x18, 0x8D, 0xA8, 0x0E, 0xB0, 0x30, 0x90, 0xF6, 0x7C, 0xBF, 0x20, 0xEB,
        0x43, 0xA1, 0x88, 0x00, 0xF4, 0xFF, 0x0A, 0xFD, 0x82, 0xFF, 0x10, 0x12,
        /* y */
        0x07, 0x19, 0x2b, 0x95, 0xff, 0xc8, 0xda, 0x78, 0x63, 0x10, 0x11, 0xed,
        0x6b, 0x24, 0xcd, 0xd5, 0x73, 0xf9, 0x77, 0xa1, 0x1e, 0x79, 0x48, 0x11,
        /* order */
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0x99, 0xDE, 0xF8, 0x36, 0x14, 0x6B, 0xC9, 0xB1, 0xB4, 0xD2, 0x28, 0x31
    }
};

static const struct {
    EC_CURVE_DATA h;
    unsigned char data[20 + 28 * 6];
} _EC_NIST_PRIME_224 = {
    {
        NID_X9_62_prime_field, 20, 28, 1
    },
    {
        /* seed */
        0xBD, 0x71, 0x34, 0x47, 0x99, 0xD5, 0xC7, 0xFC, 0xDC, 0x45, 0xB5, 0x9F,
        0xA3, 0xB9, 0xAB, 0x8F, 0x6A, 0x94, 0x8B, 0xC5,
        /* p */
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x01,
        /* a */
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFE,
        /* b */
        0xB4, 0x05, 0x0A, 0x85, 0x0C, 0x04, 0xB3, 0xAB, 0xF5, 0x41, 0x32, 0x56,
        0x50, 0x44, 0xB0, 0xB7, 0xD7, 0xBF, 0xD8, 0xBA, 0x27, 0x0B, 0x39, 0x43,
        0x23, 0x55, 0xFF, 0xB4,
        /* x */
        0xB7, 0x0E, 0x0C, 0xBD, 0x6B, 0xB4, 0xBF, 0x7F, 0x32, 0x13, 0x90, 0xB9,
        0x4A, 0x03, 0xC1, 0xD3, 0x56, 0xC2, 0x11, 0x22, 0x34, 0x32, 0x80, 0xD6,
        0x11, 0x5C, 0x1D, 0x21,
        /* y */
        0xbd, 0x37, 0x63, 0x88, 0xb5, 0xf7, 0x23, 0xfb, 0x4c, 0x22, 0xdf, 0xe6,
        0xcd, 0x43, 0x75, 0xa0, 0x5a, 0x07, 0x47, 0x64, 0x44, 0xd5, 0x81, 0x99,
        0x85, 0x00, 0x7e, 0x34,
        /* order */
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0x16, 0xA2, 0xE0, 0xB8, 0xF0, 0x3E, 0x13, 0xDD, 0x29, 0x45,
        0x5C, 0x5C, 0x2A, 0x3D
    }
};

static const struct {
    EC_CURVE_DATA h;
    unsigned char data[20 + 48 * 6];
} _EC_NIST_PRIME_384 = {
    {
        NID_X9_62_prime_field, 20, 48, 1
    },
    {
        /* seed */
        0xA3, 0x35, 0x92, 0x6A, 0xA3, 0x19, 0xA2, 0x7A, 0x1D, 0x00, 0x89, 0x6A,
        0x67, 0x73, 0xA4, 0x82, 0x7A, 0xCD, 0xAC, 0x73,
        /* p */
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
        /* a */
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFC,
        /* b */
        0xB3, 0x31, 0x2F, 0xA7, 0xE2, 0x3E, 0xE7, 0xE4, 0x98, 0x8E, 0x05, 0x6B,
        0xE3, 0xF8, 0x2D, 0x19, 0x18, 0x1D, 0x9C, 0x6E, 0xFE, 0x81, 0x41, 0x12,
        0x03, 0x14, 0x08, 0x8F, 0x50, 0x13, 0x87, 0x5A, 0xC6, 0x56, 0x39, 0x8D,
        0x8A, 0x2E, 0xD1, 0x9D, 0x2A, 0x85, 0xC8, 0xED, 0xD3, 0xEC, 0x2A, 0xEF,
        /* x */
        0xAA, 0x87, 0xCA, 0x22, 0xBE, 0x8B, 0x05, 0x37, 0x8E, 0xB1, 0xC7, 0x1E,
        0xF3, 0x20, 0xAD, 0x74, 0x6E, 0x1D, 0x3B, 0x62, 0x8B, 0xA7, 0x9B, 0x98,
        0x59, 0xF7, 0x41, 0xE0, 0x82, 0x54, 0x2A, 0x38, 0x55, 0x02, 0xF2, 0x5D,
        0xBF, 0x55, 0x29, 0x6C, 0x3A, 0x54, 0x5E, 0x38, 0x72, 0x76, 0x0A, 0xB7,
        /* y */
        0x36, 0x17, 0xde, 0x4a, 0x96, 0x26, 0x2c, 0x6f, 0x5d, 0x9e, 0x98, 0xbf,
        0x92, 0x92, 0xdc, 0x29, 0xf8, 0xf4, 0x1d, 0xbd, 0x28, 0x9a, 0x14, 0x7c,
        0xe9, 0xda, 0x31, 0x13, 0xb5, 0xf0, 0xb8, 0xc0, 0x0a, 0x60, 0xb1, 0xce,
        0x1d, 0x7e, 0x81, 0x9d, 0x7a, 0x43, 0x1d, 0x7c, 0x90, 0xea, 0x0e, 0x5f,
        /* order */
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xC7, 0x63, 0x4D, 0x81, 0xF4, 0x37, 0x2D, 0xDF, 0x58, 0x1A, 0x0D, 0xB2,
        0x48, 0xB0, 0xA7, 0x7A, 0xEC, 0xEC, 0x19, 0x6A, 0xCC, 0xC5, 0x29, 0x73
    }
};

static const struct {
    EC_CURVE_DATA h;
    unsigned char data[20 + 66 * 6];
} _EC_NIST_PRIME_521 = {
    {
        NID_X9_62_prime_field, 20, 66, 1
    },
    {
        /* seed */
        0xD0, 0x9E, 0x88, 0x00, 0x29, 0x1C, 0xB8, 0x53, 0x96, 0xCC, 0x67, 0x17,
        0x39, 0x32, 0x84, 0xAA, 0xA0, 0xDA, 0x64, 0xBA,
        /* p */
        0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        /* a */
        0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC,
        /* b */
        0x00, 0x51, 0x95, 0x3E, 0xB9, 0x61, 0x8E, 0x1C, 0x9A, 0x1F, 0x92, 0x9A,
        0x21, 0xA0, 0xB6, 0x85, 0x40, 0xEE, 0xA2, 0xDA, 0x72, 0x5B, 0x99, 0xB3,
        0x15, 0xF3, 0xB8, 0xB4, 0x89, 0x91, 0x8E, 0xF1, 0x09, 0xE1, 0x56, 0x19,
        0x39, 0x51, 0xEC, 0x7E, 0x93, 0x7B, 0x16, 0x52, 0xC0, 0xBD, 0x3B, 0xB1,
        0xBF, 0x07, 0x35, 0x73, 0xDF, 0x88, 0x3D, 0x2C, 0x34, 0xF1, 0xEF, 0x45,
        0x1F, 0xD4, 0x6B, 0x50, 0x3F, 0x00,
        /* x */
        0x00, 0xC6, 0x85, 0x8E, 0x06, 0xB7, 0x04, 0x04, 0xE9, 0xCD, 0x9E, 0x3E,
        0xCB, 0x66, 0x23, 0x95, 0xB4, 0x42, 0x9C, 0x64, 0x81, 0x39, 0x05, 0x3F,
        0xB5, 0x21, 0xF8, 0x28, 0xAF, 0x60, 0x6B, 0x4D, 0x3D, 0xBA, 0xA1, 0x4B,
        0x5E, 0x77, 0xEF, 0xE7, 0x59, 0x28, 0xFE, 0x1D, 0xC1, 0x27, 0xA2, 0xFF,
        0xA8, 0xDE, 0x33, 0x48, 0xB3, 0xC1, 0x85, 0x6A, 0x42, 0x9B, 0xF9, 0x7E,
        0x7E, 0x31, 0xC2, 0xE5, 0xBD, 0x66,
        /* y */
        0x01, 0x18, 0x39, 0x29, 0x6a, 0x78, 0x9a, 0x3b, 0xc0, 0x04, 0x5c, 0x8a,
        0x5f, 0xb4, 0x2c, 0x7d, 0x1b, 0xd9, 0x98, 0xf5, 0x44, 0x49, 0x57, 0x9b,
        0x44, 0x68, 0x17, 0xaf, 0xbd, 0x17, 0x27, 0x3e, 0x66, 0x2c, 0x97, 0xee,
        0x72, 0x99, 0x5e, 0xf4, 0x26, 0x40, 0xc5, 0x50, 0xb9, 0x01, 0x3f, 0xad,
        0x07, 0x61, 0x35, 0x3c, 0x70, 0x86, 0xa2, 0x72, 0xc2, 0x40, 0x88, 0xbe,
        0x94, 0x76, 0x9f, 0xd1, 0x66, 0x50,
        /* order */
        0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFA, 0x51, 0x86,
        0x87, 0x83, 0xBF, 0x2F, 0x96, 0x6B, 0x7F, 0xCC, 0x01, 0x48, 0xF7, 0x09,
        0xA5, 0xD0, 0x3B, 0xB5, 0xC9, 0xB8, 0x89, 0x9C, 0x47, 0xAE, 0xBB, 0x6F,
        0xB7, 0x1E, 0x91, 0x38, 0x64, 0x09
    }
};

/* the x9.62 prime curves (minus the nist prime curves) */
static const struct {
    EC_CURVE_DATA h;
    unsigned char data[20 + 24 * 6];
} _EC_X9_62_PRIME_192V2 = {
    {
        NID_X9_62_prime_field, 20, 24, 1
    },
    {
        /* seed */
        0x31, 0xA9, 0x2E, 0xE2, 0x02, 0x9F, 0xD1, 0x0D, 0x90, 0x1B, 0x11, 0x3E,
        0x99, 0x07, 0x10, 0xF0, 0xD2, 0x1A, 0xC6, 0xB6,
        /* p */
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        /* a */
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC,
        /* b */
        0xCC, 0x22, 0xD6, 0xDF, 0xB9, 0x5C, 0x6B, 0x25, 0xE4, 0x9C, 0x0D, 0x63,
        0x64, 0xA4, 0xE5, 0x98, 0x0C, 0x39, 0x3A, 0xA2, 0x16, 0x68, 0xD9, 0x53,
        /* x */
        0xEE, 0xA2, 0xBA, 0xE7, 0xE1, 0x49, 0x78, 0x42, 0xF2, 0xDE, 0x77, 0x69,
        0xCF, 0xE9, 0xC9, 0x89, 0xC0, 0x72, 0xAD, 0x69, 0x6F, 0x48, 0x03, 0x4A,
        /* y */
        0x65, 0x74, 0xd1, 0x1d, 0x69, 0xb6, 0xec, 0x7a, 0x67, 0x2b, 0xb8, 0x2a,
        0x08, 0x3d, 0xf2, 0xf2, 0xb0, 0x84, 0x7d, 0xe9, 0x70, 0xb2, 0xde, 0x15,
        /* order */
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
        0x5F, 0xB1, 0xA7, 0x24, 0xDC, 0x80, 0x41, 0x86, 0x48, 0xD8, 0xDD, 0x31
    }
};

static const struct {
    EC_CURVE_DATA h;
    unsigned char data[20 + 24 * 6];
} _EC_X9_62_PRIME_192V3 = {
    {
        NID_X9_62_prime_field, 20, 24, 1
    },
    {
        /* seed */
        0xC4, 0x69, 0x68, 0x44, 0x35, 0xDE, 0xB3, 0x78, 0xC4, 0xB6, 0x5C, 0xA9,
        0x59, 0x1E, 0x2A, 0x57, 0x63, 0x05, 0x9A, 0x2E,
        /* p */
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        /* a */
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC,
        /* b */
        0x22, 0x12, 0x3D, 0xC2, 0x39, 0x5A, 0x05, 0xCA, 0xA7, 0x42, 0x3D, 0xAE,
        0xCC, 0xC9, 0x47, 0x60, 0xA7, 0xD4, 0x62, 0x25, 0x6B, 0xD5, 0x69, 0x16,
        /* x */
        0x7D, 0x29, 0x77, 0x81, 0x00, 0xC6, 0x5A, 0x1D, 0xA1, 0x78, 0x37, 0x16,
        0x58, 0x8D, 0xCE, 0x2B, 0x8B, 0x4A, 0xEE, 0x8E, 0x22, 0x8F, 0x18, 0x96,
        /* y */
        0x38, 0xa9, 0x0f, 0x22, 0x63, 0x73, 0x37, 0x33, 0x4b, 0x49, 0xdc, 0xb6,
        0x6a, 0x6d, 0xc8, 0xf9, 0x97, 0x8a, 0xca, 0x76, 0x48, 0xa9, 0x43, 0xb0,
        /* order */
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0x7A, 0x62, 0xD0, 0x31, 0xC8, 0x3F, 0x42, 0x94, 0xF6, 0x40, 0xEC, 0x13
    }
};

static const struct {
    EC_CURVE_DATA h;
    unsigned char data[20 + 30 * 6];
} _EC_X9_62_PRIME_239V1 = {
    {
        NID_X9_62_prime_field, 20, 30, 1
    },
    {
        /* seed */
        0xE4, 0x3B, 0xB4, 0x60, 0xF0, 0xB8, 0x0C, 0xC0, 0xC0, 0xB0, 0x75, 0x79,
        0x8E, 0x94, 0x80, 0x60, 0xF8, 0x32, 0x1B, 0x7D,
        /* p */
        0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        /* a */
        0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC,
        /* b */
        0x6B, 0x01, 0x6C, 0x3B, 0xDC, 0xF1, 0x89, 0x41, 0xD0, 0xD6, 0x54, 0x92,
        0x14, 0x75, 0xCA, 0x71, 0xA9, 0xDB, 0x2F, 0xB2, 0x7D, 0x1D, 0x37, 0x79,
        0x61, 0x85, 0xC2, 0x94, 0x2C, 0x0A,
        /* x */
        0x0F, 0xFA, 0x96, 0x3C, 0xDC, 0xA8, 0x81, 0x6C, 0xCC, 0x33, 0xB8, 0x64,
        0x2B, 0xED, 0xF9, 0x05, 0xC3, 0xD3, 0x58, 0x57, 0x3D, 0x3F, 0x27, 0xFB,
        0xBD, 0x3B, 0x3C, 0xB9, 0xAA, 0xAF,
        /* y */
        0x7d, 0xeb, 0xe8, 0xe4, 0xe9, 0x0a, 0x5d, 0xae, 0x6e, 0x40, 0x54, 0xca,
        0x53, 0x0b, 0xa0, 0x46, 0x54, 0xb3, 0x68, 0x18, 0xce, 0x22, 0x6b, 0x39,
        0xfc, 0xcb, 0x7b, 0x02, 0xf1, 0xae,
        /* order */
        0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0x7F, 0xFF, 0xFF, 0x9E, 0x5E, 0x9A, 0x9F, 0x5D, 0x90, 0x71, 0xFB, 0xD1,
        0x52, 0x26, 0x88, 0x90, 0x9D, 0x0B
    }
};

static const struct {
    EC_CURVE_DATA h;
    unsigned char data[20 + 30 * 6];
} _EC_X9_62_PRIME_239V2 = {
    {
        NID_X9_62_prime_field, 20, 30, 1
    },
    {
        /* seed */
        0xE8, 0xB4, 0x01, 0x16, 0x04, 0x09, 0x53, 0x03, 0xCA, 0x3B, 0x80, 0x99,
        0x98, 0x2B, 0xE0, 0x9F, 0xCB, 0x9A, 0xE6, 0x16,
        /* p */
        0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        /* a */
        0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC,
        /* b */
        0x61, 0x7F, 0xAB, 0x68, 0x32, 0x57, 0x6C, 0xBB, 0xFE, 0xD5, 0x0D, 0x99,
        0xF0, 0x24, 0x9C, 0x3F, 0xEE, 0x58, 0xB9, 0x4B, 0xA0, 0x03, 0x8C, 0x7A,
        0xE8, 0x4C, 0x8C, 0x83, 0x2F, 0x2C,
        /* x */
        0x38, 0xAF, 0x09, 0xD9, 0x87, 0x27, 0x70, 0x51, 0x20, 0xC9, 0x21, 0xBB,
        0x5E, 0x9E, 0x26, 0x29, 0x6A, 0x3C, 0xDC, 0xF2, 0xF3, 0x57, 0x57, 0xA0,
        0xEA, 0xFD, 0x87, 0xB8, 0x30, 0xE7,
        /* y */
        0x5b, 0x01, 0x25, 0xe4, 0xdb, 0xea, 0x0e, 0xc7, 0x20, 0x6d, 0xa0, 0xfc,
        0x01, 0xd9, 0xb0, 0x81, 0x32, 0x9f, 0xb5, 0x55, 0xde, 0x6e, 0xf4, 0x60,
        0x23, 0x7d, 0xff, 0x8b, 0xe4, 0xba,
        /* order */
        0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0x80, 0x00, 0x00, 0xCF, 0xA7, 0xE8, 0x59, 0x43, 0x77, 0xD4, 0x14, 0xC0,
        0x38, 0x21, 0xBC, 0x58, 0x20, 0x63
    }
};

static const struct {
    EC_CURVE_DATA h;
    unsigned char data[20 + 30 * 6];
} _EC_X9_62_PRIME_239V3 = {
    {
        NID_X9_62_prime_field, 20, 30, 1
    },
    {
        /* seed */
        0x7D, 0x73, 0x74, 0x16, 0x8F, 0xFE, 0x34, 0x71, 0xB6, 0x0A, 0x85, 0x76,
        0x86, 0xA1, 0x94, 0x75, 0xD3, 0xBF, 0xA2, 0xFF,
        /* p */
        0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        /* a */
        0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC,
        /* b */
        0x25, 0x57, 0x05, 0xFA, 0x2A, 0x30, 0x66, 0x54, 0xB1, 0xF4, 0xCB, 0x03,
        0xD6, 0xA7, 0x50, 0xA3, 0x0C, 0x25, 0x01, 0x02, 0xD4, 0x98, 0x87, 0x17,
        0xD9, 0xBA, 0x15, 0xAB, 0x6D, 0x3E,
        /* x */
        0x67, 0x68, 0xAE, 0x8E, 0x18, 0xBB, 0x92, 0xCF, 0xCF, 0x00, 0x5C, 0x94,
        0x9A, 0xA2, 0xC6, 0xD9, 0x48, 0x53, 0xD0, 0xE6, 0x60, 0xBB, 0xF8, 0x54,
        0xB1, 0xC9, 0x50, 0x5F, 0xE9, 0x5A,
        /* y */
        0x16, 0x07, 0xe6, 0x89, 0x8f, 0x39, 0x0c, 0x06, 0xbc, 0x1d, 0x55, 0x2b,
        0xad, 0x22, 0x6f, 0x3b, 0x6f, 0xcf, 0xe4, 0x8b, 0x6e, 0x81, 0x84, 0x99,
        0xaf, 0x18, 0xe3, 0xed, 0x6c, 0xf3,
        /* order */
        0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0x7F, 0xFF, 0xFF, 0x97, 0x5D, 0xEB, 0x41, 0xB3, 0xA6, 0x05, 0x7C, 0x3C,
        0x43, 0x21, 0x46, 0x52, 0x65, 0x51
    }
};

static const struct {
    EC_CURVE_DATA h;
    unsigned char data[20 + 32 * 6];
} _EC_X9_62_PRIME_256V1 = {
    {
        NID_X9_62_prime_field, 20, 32, 1
    },
    {
        /* seed */
        0xC4, 0x9D, 0x36, 0x08, 0x86, 0xE7, 0x04, 0x93, 0x6A, 0x66, 0x78, 0xE1,
        0x13, 0x9D, 0x26, 0xB7, 0x81, 0x9F, 0x7E, 0x90,
        /* p */
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        /* a */
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC,
        /* b */
        0x5A, 0xC6, 0x35, 0xD8, 0xAA, 0x3A, 0x93, 0xE7, 0xB3, 0xEB, 0xBD, 0x55,
        0x76, 0x98, 0x86, 0xBC, 0x65, 0x1D, 0x06, 0xB0, 0xCC, 0x53, 0xB0, 0xF6,
        0x3B, 0xCE, 0x3C, 0x3E, 0x27, 0xD2, 0x60, 0x4B,
        /* x */
        0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47, 0xF8, 0xBC, 0xE6, 0xE5,
        0x63, 0xA4, 0x40, 0xF2, 0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0,
        0xF4, 0xA1, 0x39, 0x45, 0xD8, 0x98, 0xC2, 0x96,
        /* y */
        0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a,
        0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce,
        0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
        /* order */
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84,
        0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51
    }
};

/* the secg prime curves (minus the nist and x9.62 prime curves) */
static const struct {
    EC_CURVE_DATA h;
    unsigned char data[20 + 14 * 6];
} _EC_SECG_PRIME_112R1 = {
    {
        NID_X9_62_prime_field, 20, 14, 1
    },
    {
        /* seed */
        0x00, 0xF5, 0x0B, 0x02, 0x8E, 0x4D, 0x69, 0x6E, 0x67, 0x68, 0x75, 0x61,
        0x51, 0x75, 0x29, 0x04, 0x72, 0x78, 0x3F, 0xB1,
        /* p */
        0xDB, 0x7C, 0x2A, 0xBF, 0x62, 0xE3, 0x5E, 0x66, 0x80, 0x76, 0xBE, 0xAD,
        0x20, 0x8B,
        /* a */
        0xDB, 0x7C, 0x2A, 0xBF, 0x62, 0xE3, 0x5E, 0x66, 0x80, 0x76, 0xBE, 0xAD,
        0x20, 0x88,
        /* b */
        0x65, 0x9E, 0xF8, 0xBA, 0x04, 0x39, 0x16, 0xEE, 0xDE, 0x89, 0x11, 0x70,
        0x2B, 0x22,
        /* x */
        0x09, 0x48, 0x72, 0x39, 0x99, 0x5A, 0x5E, 0xE7, 0x6B, 0x55, 0xF9, 0xC2,
        0xF0, 0x98,
        /* y */
        0xa8, 0x9c, 0xe5, 0xaf, 0x87, 0x24, 0xc0, 0xa2, 0x3e, 0x0e, 0x0f, 0xf7,
        0x75, 0x00,
        /* order */
        0xDB, 0x7C, 0x2A, 0xBF, 0x62, 0xE3, 0x5E, 0x76, 0x28, 0xDF, 0xAC, 0x65,
        0x61, 0xC5
    }
};

static const struct {
    EC_CURVE_DATA h;
    unsigned char data[20 + 14 * 6];
} _EC_SECG_PRIME_112R2 = {
    {
        NID_X9_62_prime_field, 20, 14, 4
    },
    {
        /* seed */
        0x00, 0x27, 0x57, 0xA1, 0x11, 0x4D, 0x69, 0x6E, 0x67, 0x68, 0x75, 0x61,
        0x51, 0x75, 0x53, 0x16, 0xC0, 0x5E, 0x0B, 0xD4,
        /* p */
        0xDB, 0x7C, 0x2A, 0xBF, 0x62, 0xE3, 0x5E, 0x66, 0x80, 0x76, 0xBE, 0xAD,
        0x20, 0x8B,
        /* a */
        0x61, 0x27, 0xC2, 0x4C, 0x05, 0xF3, 0x8A, 0x0A, 0xAA, 0xF6, 0x5C, 0x0E,
        0xF0, 0x2C,
        /* b */
        0x51, 0xDE, 0xF1, 0x81, 0x5D, 0xB5, 0xED, 0x74, 0xFC, 0xC3, 0x4C, 0x85,
        0xD7, 0x09,
        /* x */
        0x4B, 0xA3, 0x0A, 0xB5, 0xE8, 0x92, 0xB4, 0xE1, 0x64, 0x9D, 0xD0, 0x92,
        0x86, 0x43,
        /* y */
        0xad, 0xcd, 0x46, 0xf5, 0x88, 0x2e, 0x37, 0x47, 0xde, 0xf3, 0x6e, 0x95,
        0x6e, 0x97,
        /* order */
        0x36, 0xDF, 0x0A, 0xAF, 0xD8, 0xB8, 0xD7, 0x59, 0x7C, 0xA1, 0x05, 0x20,
        0xD0, 0x4B
    }
};

static const struct {
    EC_CURVE_DATA h;
    unsigned char data[20 + 16 * 6];
} _EC_SECG_PRIME_128R1 = {
    {
        NID_X9_62_prime_field, 20, 16, 1
    },
    {
        /* seed */
        0x00, 0x0E, 0x0D, 0x4D, 0x69, 0x6E, 0x67, 0x68, 0x75, 0x61, 0x51, 0x75,
        0x0C, 0xC0, 0x3A, 0x44, 0x73, 0xD0, 0x36, 0x79,
        /* p */
        0xFF, 0xFF, 0xFF, 0xFD, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        /* a */
        0xFF, 0xFF, 0xFF, 0xFD, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFC,
        /* b */
        0xE8, 0x75, 0x79, 0xC1, 0x10, 0x79, 0xF4, 0x3D, 0xD8, 0x24, 0x99, 0x3C,
        0x2C, 0xEE, 0x5E, 0xD3,
        /* x */
        0x16, 0x1F, 0xF7, 0x52, 0x8B, 0x89, 0x9B, 0x2D, 0x0C, 0x28, 0x60, 0x7C,
        0xA5, 0x2C, 0x5B, 0x86,
        /* y */
        0xcf, 0x5a, 0xc8, 0x39, 0x5b, 0xaf, 0xeb, 0x13, 0xc0, 0x2d, 0xa2, 0x92,
        0xdd, 0xed, 0x7a, 0x83,
        /* order */
        0xFF, 0xFF, 0xFF, 0xFE, 0x00, 0x00, 0x00, 0x00, 0x75, 0xA3, 0x0D, 0x1B,
        0x90, 0x38, 0xA1, 0x15
    }
};

static const struct {
    EC_CURVE_DATA h;
    unsigned char data[20 + 16 * 6];
} _EC_SECG_PRIME_128R2 = {
    {
        NID_X9_62_prime_field, 20, 16, 4
    },
    {
        /* seed */
        0x00, 0x4D, 0x69, 0x6E, 0x67, 0x68, 0x75, 0x61, 0x51, 0x75, 0x12, 0xD8,
        0xF0, 0x34, 0x31, 0xFC, 0xE6, 0x3B, 0x88, 0xF4,
        /* p */
        0xFF, 0xFF, 0xFF, 0xFD, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        /* a */
        0xD6, 0x03, 0x19, 0x98, 0xD1, 0xB3, 0xBB, 0xFE, 0xBF, 0x59, 0xCC, 0x9B,
        0xBF, 0xF9, 0xAE, 0xE1,
        /* b */
        0x5E, 0xEE, 0xFC, 0xA3, 0x80, 0xD0, 0x29, 0x19, 0xDC, 0x2C, 0x65, 0x58,
        0xBB, 0x6D, 0x8A, 0x5D,
        /* x */
        0x7B, 0x6A, 0xA5, 0xD8, 0x5E, 0x57, 0x29, 0x83, 0xE6, 0xFB, 0x32, 0xA7,
        0xCD, 0xEB, 0xC1, 0x40,
        /* y */
        0x27, 0xb6, 0x91, 0x6a, 0x89, 0x4d, 0x3a, 0xee, 0x71, 0x06, 0xfe, 0x80,
        0x5f, 0xc3, 0x4b, 0x44,
        /* order */
        0x3F, 0xFF, 0xFF, 0xFF, 0x7F, 0xFF, 0xFF, 0xFF, 0xBE, 0x00, 0x24, 0x72,
        0x06, 0x13, 0xB5, 0xA3
    }
};

static const struct {
    EC_CURVE_DATA h;
    unsigned char data[0 + 21 * 6];
} _EC_SECG_PRIME_160K1 = {
    {
        NID_X9_62_prime_field, 0, 21, 1
    },
    {
        /* no seed */
        /* p */
        0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xAC, 0x73,
        /* a */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        /* b */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07,
        /* x */
        0x00, 0x3B, 0x4C, 0x38, 0x2C, 0xE3, 0x7A, 0xA1, 0x92, 0xA4, 0x01, 0x9E,
        0x76, 0x30, 0x36, 0xF4, 0xF5, 0xDD, 0x4D, 0x7E, 0xBB,
        /* y */
        0x00, 0x93, 0x8c, 0xf9, 0x35, 0x31, 0x8f, 0xdc, 0xed, 0x6b, 0xc2, 0x82,
        0x86, 0x53, 0x17, 0x33, 0xc3, 0xf0, 0x3c, 0x4f, 0xee,
        /* order */
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xB8,
        0xFA, 0x16, 0xDF, 0xAB, 0x9A, 0xCA, 0x16, 0xB6, 0xB3
    }
};

static const struct {
    EC_CURVE_DATA h;
    unsigned char data[20 + 21 * 6];
} _EC_SECG_PRIME_160R1 = {
    {
        NID_X9_62_prime_field, 20, 21, 1
    },
    {
        /* seed */
        0x10, 0x53, 0xCD, 0xE4, 0x2C, 0x14, 0xD6, 0x96, 0xE6, 0x76, 0x87, 0x56,
        0x15, 0x17, 0x53, 0x3B, 0xF3, 0xF8, 0x33, 0x45,
        /* p */
        0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F, 0xFF, 0xFF, 0xFF,
        /* a */
        0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F, 0xFF, 0xFF, 0xFC,
        /* b */
        0x00, 0x1C, 0x97, 0xBE, 0xFC, 0x54, 0xBD, 0x7A, 0x8B, 0x65, 0xAC, 0xF8,
        0x9F, 0x81, 0xD4, 0xD4, 0xAD, 0xC5, 0x65, 0xFA, 0x45,
        /* x */
        0x00, 0x4A, 0x96, 0xB5, 0x68, 0x8E, 0xF5, 0x73, 0x28, 0x46, 0x64, 0x69,
        0x89, 0x68, 0xC3, 0x8B, 0xB9, 0x13, 0xCB, 0xFC, 0x82,
        /* y */
        0x00, 0x23, 0xa6, 0x28, 0x55, 0x31, 0x68, 0x94, 0x7d, 0x59, 0xdc, 0xc9,
        0x12, 0x04, 0x23, 0x51, 0x37, 0x7a, 0xc5, 0xfb, 0x32,
        /* order */
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xF4,
        0xC8, 0xF9, 0x27, 0xAE, 0xD3, 0xCA, 0x75, 0x22, 0x57
    }
};

static const struct {
    EC_CURVE_DATA h;
    unsigned char data[20 + 21 * 6];
} _EC_SECG_PRIME_160R2 = {
    {
        NID_X9_62_prime_field, 20, 21, 1
    },
    {
        /* seed */
        0xB9, 0x9B, 0x99, 0xB0, 0x99, 0xB3, 0x23, 0xE0, 0x27, 0x09, 0xA4, 0xD6,
        0x96, 0xE6, 0x76, 0x87, 0x56, 0x15, 0x17, 0x51,
        /* p */
        0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xAC, 0x73,
        /* a */
        0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xAC, 0x70,
        /* b */
        0x00, 0xB4, 0xE1, 0x34, 0xD3, 0xFB, 0x59, 0xEB, 0x8B, 0xAB, 0x57, 0x27,
        0x49, 0x04, 0x66, 0x4D, 0x5A, 0xF5, 0x03, 0x88, 0xBA,
        /* x */
        0x00, 0x52, 0xDC, 0xB0, 0x34, 0x29, 0x3A, 0x11, 0x7E, 0x1F, 0x4F, 0xF1,
        0x1B, 0x30, 0xF7, 0x19, 0x9D, 0x31, 0x44, 0xCE, 0x6D,
        /* y */
        0x00, 0xfe, 0xaf, 0xfe, 0xf2, 0xe3, 0x31, 0xf2, 0x96, 0xe0, 0x71, 0xfa,
        0x0d, 0xf9, 0x98, 0x2c, 0xfe, 0xa7, 0xd4, 0x3f, 0x2e,
        /* order */
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x35,
        0x1E, 0xE7, 0x86, 0xA8, 0x18, 0xF3, 0xA1, 0xA1, 0x6B
    }
};

static const struct {
    EC_CURVE_DATA h;
    unsigned char data[0 + 24 * 6];
} _EC_SECG_PRIME_192K1 = {
    {
        NID_X9_62_prime_field, 0, 24, 1
    },
    {
        /* no seed */
        /* p */
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xEE, 0x37,
        /* a */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        /* b */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
        /* x */
        0xDB, 0x4F, 0xF1, 0x0E, 0xC0, 0x57, 0xE9, 0xAE, 0x26, 0xB0, 0x7D, 0x02,
        0x80, 0xB7, 0xF4, 0x34, 0x1D, 0xA5, 0xD1, 0xB1, 0xEA, 0xE0, 0x6C, 0x7D,
        /* y */
        0x9b, 0x2f, 0x2f, 0x6d, 0x9c, 0x56, 0x28, 0xa7, 0x84, 0x41, 0x63, 0xd0,
        0x15, 0xbe, 0x86, 0x34, 0x40, 0x82, 0xaa, 0x88, 0xd9, 0x5e, 0x2f, 0x9d,
        /* order */
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
        0x26, 0xF2, 0xFC, 0x17, 0x0F, 0x69, 0x46, 0x6A, 0x74, 0xDE, 0xFD, 0x8D
    }
};

static const struct {
    EC_CURVE_DATA h;
    unsigned char data[0 + 29 * 6];
} _EC_SECG_PRIME_224K1 = {
    {
        NID_X9_62_prime_field, 0, 29, 1
    },
    {
        /* no seed */
        /* p */
        0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFE, 0xFF, 0xFF, 0xE5, 0x6D,
        /* a */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00,
        /* b */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x05,
        /* x */
        0x00, 0xA1, 0x45, 0x5B, 0x33, 0x4D, 0xF0, 0x99, 0xDF, 0x30, 0xFC, 0x28,
        0xA1, 0x69, 0xA4, 0x67, 0xE9, 0xE4, 0x70, 0x75, 0xA9, 0x0F, 0x7E, 0x65,
        0x0E, 0xB6, 0xB7, 0xA4, 0x5C,
        /* y */
        0x00, 0x7e, 0x08, 0x9f, 0xed, 0x7f, 0xba, 0x34, 0x42, 0x82, 0xca, 0xfb,
        0xd6, 0xf7, 0xe3, 0x19, 0xf7, 0xc0, 0xb0, 0xbd, 0x59, 0xe2, 0xca, 0x4b,
        0xdb, 0x55, 0x6d, 0x61, 0xa5,
        /* order */
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x01, 0xDC, 0xE8, 0xD2, 0xEC, 0x61, 0x84, 0xCA, 0xF0, 0xA9,
        0x71, 0x76, 0x9F, 0xB1, 0xF7
    }
};

static const struct {
    EC_CURVE_DATA h;
    unsigned char data[0 + 32 * 6];
} _EC_SECG_PRIME_256K1 = {
    {
        NID_X9_62_prime_field, 0, 32, 1
    },
    {
        /* no seed */
        /* p */
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFC, 0x2F,
        /* a */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        /* b */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07,
        /* x */
        0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95,
        0xCE, 0x87, 0x0B, 0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9,
        0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98,
        /* y */
        0x48, 0x3a, 0xda, 0x77, 0x26, 0xa3, 0xc4, 0x65, 0x5d, 0xa4, 0xfb, 0xfc,
        0x0e, 0x11, 0x08, 0xa8, 0xfd, 0x17, 0xb4, 0x48, 0xa6, 0x85, 0x54, 0x19,
        0x9c, 0x47, 0xd0, 0x8f, 0xfb, 0x10, 0xd4, 0xb8,
        /* order */
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
        0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41
    }
};

/* some wap/wtls curves */
static const struct {
    EC_CURVE_DATA h;
    unsigned char data[0 + 15 * 6];
} _EC_WTLS_8 = {
    {
        NID_X9_62_prime_field, 0, 15, 1
    },
    {
        /* no seed */
        /* p */
        0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFD, 0xE7,
        /* a */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00,
        /* b */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x03,
        /* x */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x01,
        /* y */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x02,
        /* order */
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xEC, 0xEA, 0x55, 0x1A,
        0xD8, 0x37, 0xE9
    }
};

static const struct {
    EC_CURVE_DATA h;
    unsigned char data[0 + 21 * 6];
} _EC_WTLS_9 = {
    {
        NID_X9_62_prime_field, 0, 21, 1
    },
    {
        /* no seed */
        /* p */
        0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC, 0x80, 0x8F,
        /* a */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        /* b */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
        /* x */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        /* y */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        /* order */
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xCD,
        0xC9, 0x8A, 0xE0, 0xE2, 0xDE, 0x57, 0x4A, 0xBF, 0x33
    }
};

static const struct {
    EC_CURVE_DATA h;
    unsigned char data[0 + 28 * 6];
} _EC_WTLS_12 = {
    {
        NID_X9_62_prime_field, 0, 28, 1
    },
    {
        /* no seed */
        /* p */
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x01,
        /* a */
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFE,
        /* b */
        0xB4, 0x05, 0x0A, 0x85, 0x0C, 0x04, 0xB3, 0xAB, 0xF5, 0x41, 0x32, 0x56,
        0x50, 0x44, 0xB0, 0xB7, 0xD7, 0xBF, 0xD8, 0xBA, 0x27, 0x0B, 0x39, 0x43,
        0x23, 0x55, 0xFF, 0xB4,
        /* x */
        0xB7, 0x0E, 0x0C, 0xBD, 0x6B, 0xB4, 0xBF, 0x7F, 0x32, 0x13, 0x90, 0xB9,
        0x4A, 0x03, 0xC1, 0xD3, 0x56, 0xC2, 0x11, 0x22, 0x34, 0x32, 0x80, 0xD6,
        0x11, 0x5C, 0x1D, 0x21,
        /* y */
        0xbd, 0x37, 0x63, 0x88, 0xb5, 0xf7, 0x23, 0xfb, 0x4c, 0x22, 0xdf, 0xe6,
        0xcd, 0x43, 0x75, 0xa0, 0x5a, 0x07, 0x47, 0x64, 0x44, 0xd5, 0x81, 0x99,
        0x85, 0x00, 0x7e, 0x34,
        /* order */
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0x16, 0xA2, 0xE0, 0xB8, 0xF0, 0x3E, 0x13, 0xDD, 0x29, 0x45,
        0x5C, 0x5C, 0x2A, 0x3D
    }
};

#ifndef OPENSSL_NO_EC2M

/* characteristic two curves */
static const struct {
    EC_CURVE_DATA h;
    unsigned char data[20 + 15 * 6];
} _EC_SECG_CHAR2_113R1 = {
    {
        NID_X9_62_characteristic_two_field, 20, 15, 2
    },
    {
        /* seed */
        0x10, 0xE7, 0x23, 0xAB, 0x14, 0xD6, 0x96, 0xE6, 0x76, 0x87, 0x56, 0x15,
        0x17, 0x56, 0xFE, 0xBF, 0x8F, 0xCB, 0x49, 0xA9,
        /* p */
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x02, 0x01,
        /* a */
        0x00, 0x30, 0x88, 0x25, 0x0C, 0xA6, 0xE7, 0xC7, 0xFE, 0x64, 0x9C, 0xE8,
        0x58, 0x20, 0xF7,
        /* b */
        0x00, 0xE8, 0xBE, 0xE4, 0xD3, 0xE2, 0x26, 0x07, 0x44, 0x18, 0x8B, 0xE0,
        0xE9, 0xC7, 0x23,
        /* x */
        0x00, 0x9D, 0x73, 0x61, 0x6F, 0x35, 0xF4, 0xAB, 0x14, 0x07, 0xD7, 0x35,
        0x62, 0xC1, 0x0F,
        /* y */
        0x00, 0xA5, 0x28, 0x30, 0x27, 0x79, 0x58, 0xEE, 0x84, 0xD1, 0x31, 0x5E,
        0xD3, 0x18, 0x86,
        /* order */
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xD9, 0xCC, 0xEC, 0x8A,
        0x39, 0xE5, 0x6F
    }
};

static const struct {
    EC_CURVE_DATA h;
    unsigned char data[20 + 15 * 6];
} _EC_SECG_CHAR2_113R2 = {
    {
        NID_X9_62_characteristic_two_field, 20, 15, 2
    },
    {
        /* seed */
        0x10, 0xC0, 0xFB, 0x15, 0x76, 0x08, 0x60, 0xDE, 0xF1, 0xEE, 0xF4, 0xD6,
        0x96, 0xE6, 0x76, 0x87, 0x56, 0x15, 0x17, 0x5D,
        /* p */
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x02, 0x01,
        /* a */
        0x00, 0x68, 0x99, 0x18, 0xDB, 0xEC, 0x7E, 0x5A, 0x0D, 0xD6, 0xDF, 0xC0,
        0xAA, 0x55, 0xC7,
        /* b */
        0x00, 0x95, 0xE9, 0xA9, 0xEC, 0x9B, 0x29, 0x7B, 0xD4, 0xBF, 0x36, 0xE0,
        0x59, 0x18, 0x4F,
        /* x */
        0x01, 0xA5, 0x7A, 0x6A, 0x7B, 0x26, 0xCA, 0x5E, 0xF5, 0x2F, 0xCD, 0xB8,
        0x16, 0x47, 0x97,
        /* y */
        0x00, 0xB3, 0xAD, 0xC9, 0x4E, 0xD1, 0xFE, 0x67, 0x4C, 0x06, 0xE6, 0x95,
        0xBA, 0xBA, 0x1D,
        /* order */
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x78, 0x9B, 0x24,
        0x96, 0xAF, 0x93
    }
};

static const struct {
    EC_CURVE_DATA h;
    unsigned char data[20 + 17 * 6];
} _EC_SECG_CHAR2_131R1 = {
    {
        NID_X9_62_characteristic_two_field, 20, 17, 2
    },
    {
        /* seed */
        0x4D, 0x69, 0x6E, 0x67, 0x68, 0x75, 0x61, 0x51, 0x75, 0x98, 0x5B, 0xD3,
        0xAD, 0xBA, 0xDA, 0x21, 0xB4, 0x3A, 0x97, 0xE2,
        /* p */
        0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x01, 0x0D,
        /* a */
        0x07, 0xA1, 0x1B, 0x09, 0xA7, 0x6B, 0x56, 0x21, 0x44, 0x41, 0x8F, 0xF3,
        0xFF, 0x8C, 0x25, 0x70, 0xB8,
        /* b */
        0x02, 0x17, 0xC0, 0x56, 0x10, 0x88, 0x4B, 0x63, 0xB9, 0xC6, 0xC7, 0x29,
        0x16, 0x78, 0xF9, 0xD3, 0x41,
        /* x */
        0x00, 0x81, 0xBA, 0xF9, 0x1F, 0xDF, 0x98, 0x33, 0xC4, 0x0F, 0x9C, 0x18,
        0x13, 0x43, 0x63, 0x83, 0x99,
        /* y */
        0x07, 0x8C, 0x6E, 0x7E, 0xA3, 0x8C, 0x00, 0x1F, 0x73, 0xC8, 0x13, 0x4B,
        0x1B, 0x4E, 0xF9, 0xE1, 0x50,
        /* order */
        0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x31, 0x23, 0x95,
        0x3A, 0x94, 0x64, 0xB5, 0x4D
    }
};

static const struct {
    EC_CURVE_DATA h;
    unsigned char data[20 + 17 * 6];
} _EC_SECG_CHAR2_131R2 = {
    {
        NID_X9_62_characteristic_two_field, 20, 17, 2
    },
    {
        /* seed */
        0x98, 0x5B, 0xD3, 0xAD, 0xBA, 0xD4, 0xD6, 0x96, 0xE6, 0x76, 0x87, 0x56,
        0x15, 0x17, 0x5A, 0x21, 0xB4, 0x3A, 0x97, 0xE3,
        /* p */
        0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x01, 0x0D,
        /* a */
        0x03, 0xE5, 0xA8, 0x89, 0x19, 0xD7, 0xCA, 0xFC, 0xBF, 0x41, 0x5F, 0x07,
        0xC2, 0x17, 0x65, 0x73, 0xB2,
        /* b */
        0x04, 0xB8, 0x26, 0x6A, 0x46, 0xC5, 0x56, 0x57, 0xAC, 0x73, 0x4C, 0xE3,
        0x8F, 0x01, 0x8F, 0x21, 0x92,
        /* x */
        0x03, 0x56, 0xDC, 0xD8, 0xF2, 0xF9, 0x50, 0x31, 0xAD, 0x65, 0x2D, 0x23,
        0x95, 0x1B, 0xB3, 0x66, 0xA8,
        /* y */
        0x06, 0x48, 0xF0, 0x6D, 0x86, 0x79, 0x40, 0xA5, 0x36, 0x6D, 0x9E, 0x26,
        0x5D, 0xE9, 0xEB, 0x24, 0x0F,
        /* order */
        0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x69, 0x54, 0xA2,
        0x33, 0x04, 0x9B, 0xA9, 0x8F
    }
};

static const struct {
    EC_CURVE_DATA h;
    unsigned char data[0 + 21 * 6];
} _EC_NIST_CHAR2_163K = {
    {
        NID_X9_62_characteristic_two_field, 0, 21, 2
    },
    {
        /* no seed */
        /* p */
        0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC9,
        /* a */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        /* b */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        /* x */
        0x02, 0xFE, 0x13, 0xC0, 0x53, 0x7B, 0xBC, 0x11, 0xAC, 0xAA, 0x07, 0xD7,
        0x93, 0xDE, 0x4E, 0x6D, 0x5E, 0x5C, 0x94, 0xEE, 0xE8,
        /* y */
        0x02, 0x89, 0x07, 0x0F, 0xB0, 0x5D, 0x38, 0xFF, 0x58, 0x32, 0x1F, 0x2E,
        0x80, 0x05, 0x36, 0xD5, 0x38, 0xCC, 0xDA, 0xA3, 0xD9,
        /* order */
        0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x01,
        0x08, 0xA2, 0xE0, 0xCC, 0x0D, 0x99, 0xF8, 0xA5, 0xEF
    }
};

static const struct {
    EC_CURVE_DATA h;
    unsigned char data[0 + 21 * 6];
} _EC_SECG_CHAR2_163R1 = {
    {
        NID_X9_62_characteristic_two_field, 0, 21, 2
    },
    {
        /* no seed */
# if 0
        /*
        * The algorithm used to derive the curve parameters from the seed
        * used here is slightly different than the algorithm described in
        * X9.62 .
        */
        0x24, 0xB7, 0xB1, 0x37, 0xC8, 0xA1, 0x4D, 0x69, 0x6E, 0x67, 0x68, 0x75,
        0x61, 0x51, 0x75, 0x6F, 0xD0, 0xDA, 0x2E, 0x5C,
# endif
        /* p */
        0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC9,
        /* a */
        0x07, 0xB6, 0x88, 0x2C, 0xAA, 0xEF, 0xA8, 0x4F, 0x95, 0x54, 0xFF, 0x84,
        0x28, 0xBD, 0x88, 0xE2, 0x46, 0xD2, 0x78, 0x2A, 0xE2,
        /* b */
        0x07, 0x13, 0x61, 0x2D, 0xCD, 0xDC, 0xB4, 0x0A, 0xAB, 0x94, 0x6B, 0xDA,
        0x29, 0xCA, 0x91, 0xF7, 0x3A, 0xF9, 0x58, 0xAF, 0xD9,
        /* x */
        0x03, 0x69, 0x97, 0x96, 0x97, 0xAB, 0x43, 0x89, 0x77, 0x89, 0x56, 0x67,
        0x89, 0x56, 0x7F, 0x78, 0x7A, 0x78, 0x76, 0xA6, 0x54,
        /* y */
        0x00, 0x43, 0x5E, 0xDB, 0x42, 0xEF, 0xAF, 0xB2, 0x98, 0x9D, 0x51, 0xFE,
        0xFC, 0xE3, 0xC8, 0x09, 0x88, 0xF4, 0x1F, 0xF8, 0x83,
        /* order */
        0x03, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x48,
        0xAA, 0xB6, 0x89, 0xC2, 0x9C, 0xA7, 0x10, 0x27, 0x9B
    }
};

static const struct {
    EC_CURVE_DATA h;
    unsigned char data[0 + 21 * 6];
} _EC_NIST_CHAR2_163B = {
    {
        NID_X9_62_characteristic_two_field, 0, 21, 2
    },
    {
        /* no seed */
# if 0
        /*
        * The seed here was used to created the curve parameters in normal
        * basis representation (and not the polynomial representation used
        * here)
        */
        0x85, 0xE2, 0x5B, 0xFE, 0x5C, 0x86, 0x22, 0x6C, 0xDB, 0x12, 0x01, 0x6F,
        0x75, 0x53, 0xF9, 0xD0, 0xE6, 0x93, 0xA2, 0x68,
# endif
        /* p */
        0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC9,
        /* a */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        /* b */
        0x02, 0x0A, 0x60, 0x19, 0x07, 0xB8, 0xC9, 0x53, 0xCA, 0x14, 0x81, 0xEB,
        0x10, 0x51, 0x2F, 0x78, 0x74, 0x4A, 0x32, 0x05, 0xFD,
        /* x */
        0x03, 0xF0, 0xEB, 0xA1, 0x62, 0x86, 0xA2, 0xD5, 0x7E, 0xA0, 0x99, 0x11,
        0x68, 0xD4, 0x99, 0x46, 0x37, 0xE8, 0x34, 0x3E, 0x36,
        /* y */
        0x00, 0xD5, 0x1F, 0xBC, 0x6C, 0x71, 0xA0, 0x09, 0x4F, 0xA2, 0xCD, 0xD5,
        0x45, 0xB1, 0x1C, 0x5C, 0x0C, 0x79, 0x73, 0x24, 0xF1,
        /* order */
        0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x92,
        0xFE, 0x77, 0xE7, 0x0C, 0x12, 0xA4, 0x23, 0x4C, 0x33
    }
};

static const struct {
    EC_CURVE_DATA h;
    unsigned char data[20 + 25 * 6];
} _EC_SECG_CHAR2_193R1 = {
    {
        NID_X9_62_characteristic_two_field, 20, 25, 2
    },
    {
        /* seed */
        0x10, 0x3F, 0xAE, 0xC7, 0x4D, 0x69, 0x6E, 0x67, 0x68, 0x75, 0x61, 0x51,
        0x75, 0x77, 0x7F, 0xC5, 0xB1, 0x91, 0xEF, 0x30,
        /* p */
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80,
        0x01,
        /* a */
        0x00, 0x17, 0x85, 0x8F, 0xEB, 0x7A, 0x98, 0x97, 0x51, 0x69, 0xE1, 0x71,
        0xF7, 0x7B, 0x40, 0x87, 0xDE, 0x09, 0x8A, 0xC8, 0xA9, 0x11, 0xDF, 0x7B,
        0x01,
        /* b */
        0x00, 0xFD, 0xFB, 0x49, 0xBF, 0xE6, 0xC3, 0xA8, 0x9F, 0xAC, 0xAD, 0xAA,
        0x7A, 0x1E, 0x5B, 0xBC, 0x7C, 0xC1, 0xC2, 0xE5, 0xD8, 0x31, 0x47, 0x88,
        0x14,
        /* x */
        0x01, 0xF4, 0x81, 0xBC, 0x5F, 0x0F, 0xF8, 0x4A, 0x74, 0xAD, 0x6C, 0xDF,
        0x6F, 0xDE, 0xF4, 0xBF, 0x61, 0x79, 0x62, 0x53, 0x72, 0xD8, 0xC0, 0xC5,
        0xE1,
        /* y */
        0x00, 0x25, 0xE3, 0x99, 0xF2, 0x90, 0x37, 0x12, 0xCC, 0xF3, 0xEA, 0x9E,
        0x3A, 0x1A, 0xD1, 0x7F, 0xB0, 0xB3, 0x20, 0x1B, 0x6A, 0xF7, 0xCE, 0x1B,
        0x05,
        /* order */
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0xC7, 0xF3, 0x4A, 0x77, 0x8F, 0x44, 0x3A, 0xCC, 0x92, 0x0E, 0xBA,
        0x49
    }
};

static const struct {
    EC_CURVE_DATA h;
    unsigned char data[20 + 25 * 6];
} _EC_SECG_CHAR2_193R2 = {
    {
        NID_X9_62_characteristic_two_field, 20, 25, 2
    },
    {
        /* seed */
        0x10, 0xB7, 0xB4, 0xD6, 0x96, 0xE6, 0x76, 0x87, 0x56, 0x15, 0x17, 0x51,
        0x37, 0xC8, 0xA1, 0x6F, 0xD0, 0xDA, 0x22, 0x11,
        /* p */
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80,
        0x01,
        /* a */
        0x01, 0x63, 0xF3, 0x5A, 0x51, 0x37, 0xC2, 0xCE, 0x3E, 0xA6, 0xED, 0x86,
        0x67, 0x19, 0x0B, 0x0B, 0xC4, 0x3E, 0xCD, 0x69, 0x97, 0x77, 0x02, 0x70,
        0x9B,
        /* b */
        0x00, 0xC9, 0xBB, 0x9E, 0x89, 0x27, 0xD4, 0xD6, 0x4C, 0x37, 0x7E, 0x2A,
        0xB2, 0x85, 0x6A, 0x5B, 0x16, 0xE3, 0xEF, 0xB7, 0xF6, 0x1D, 0x43, 0x16,
        0xAE,
        /* x */
        0x00, 0xD9, 0xB6, 0x7D, 0x19, 0x2E, 0x03, 0x67, 0xC8, 0x03, 0xF3, 0x9E,
        0x1A, 0x7E, 0x82, 0xCA, 0x14, 0xA6, 0x51, 0x35, 0x0A, 0xAE, 0x61, 0x7E,
        0x8F,
        /* y */
        0x01, 0xCE, 0x94, 0x33, 0x56, 0x07, 0xC3, 0x04, 0xAC, 0x29, 0xE7, 0xDE,
        0xFB, 0xD9, 0xCA, 0x01, 0xF5, 0x96, 0xF9, 0x27, 0x22, 0x4C, 0xDE, 0xCF,
        0x6C,
        /* order */
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x5A, 0xAB, 0x56, 0x1B, 0x00, 0x54, 0x13, 0xCC, 0xD4, 0xEE, 0x99,
        0xD5
    }
};

static const struct {
    EC_CURVE_DATA h;
    unsigned char data[0 + 30 * 6];
} _EC_NIST_CHAR2_233K = {
    {
        NID_X9_62_characteristic_two_field, 0, 30, 4
    },
    {
        /* no seed */
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        /* a */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        /* b */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        /* x */
        0x01, 0x72, 0x32, 0xBA, 0x85, 0x3A, 0x7E, 0x73, 0x1A, 0xF1, 0x29, 0xF2,
        0x2F, 0xF4, 0x14, 0x95, 0x63, 0xA4, 0x19, 0xC2, 0x6B, 0xF5, 0x0A, 0x4C,
        0x9D, 0x6E, 0xEF, 0xAD, 0x61, 0x26,
        /* y */
        0x01, 0xDB, 0x53, 0x7D, 0xEC, 0xE8, 0x19, 0xB7, 0xF7, 0x0F, 0x55, 0x5A,
        0x67, 0xC4, 0x27, 0xA8, 0xCD, 0x9B, 0xF1, 0x8A, 0xEB, 0x9B, 0x56, 0xE0,
        0xC1, 0x10, 0x56, 0xFA, 0xE6, 0xA3,
        /* order */
        0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x06, 0x9D, 0x5B, 0xB9, 0x15, 0xBC, 0xD4, 0x6E, 0xFB,
        0x1A, 0xD5, 0xF1, 0x73, 0xAB, 0xDF
    }
};

static const struct {
    EC_CURVE_DATA h;
    unsigned char data[20 + 30 * 6];
} _EC_NIST_CHAR2_233B = {
    {
        NID_X9_62_characteristic_two_field, 20, 30, 2
    },
    {
        /* seed */
        0x74, 0xD5, 0x9F, 0xF0, 0x7F, 0x6B, 0x41, 0x3D, 0x0E, 0xA1, 0x4B, 0x34,
        0x4B, 0x20, 0xA2, 0xDB, 0x04, 0x9B, 0x50, 0xC3,
        /* p */
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        /* a */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        /* b */
        0x00, 0x66, 0x64, 0x7E, 0xDE, 0x6C, 0x33, 0x2C, 0x7F, 0x8C, 0x09, 0x23,
        0xBB, 0x58, 0x21, 0x3B, 0x33, 0x3B, 0x20, 0xE9, 0xCE, 0x42, 0x81, 0xFE,
        0x11, 0x5F, 0x7D, 0x8F, 0x90, 0xAD,
        /* x */
        0x00, 0xFA, 0xC9, 0xDF, 0xCB, 0xAC, 0x83, 0x13, 0xBB, 0x21, 0x39, 0xF1,
        0xBB, 0x75, 0x5F, 0xEF, 0x65, 0xBC, 0x39, 0x1F, 0x8B, 0x36, 0xF8, 0xF8,
        0xEB, 0x73, 0x71, 0xFD, 0x55, 0x8B,
        /* y */
        0x01, 0x00, 0x6A, 0x08, 0xA4, 0x19, 0x03, 0x35, 0x06, 0x78, 0xE5, 0x85,
        0x28, 0xBE, 0xBF, 0x8A, 0x0B, 0xEF, 0xF8, 0x67, 0xA7, 0xCA, 0x36, 0x71,
        0x6F, 0x7E, 0x01, 0xF8, 0x10, 0x52,
        /* order */
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x13, 0xE9, 0x74, 0xE7, 0x2F, 0x8A, 0x69, 0x22, 0x03,
        0x1D, 0x26, 0x03, 0xCF, 0xE0, 0xD7
    }
};

static const struct {
    EC_CURVE_DATA h;
    unsigned char data[0 + 30 * 6];
} _EC_SECG_CHAR2_239K1 = {
    {
        NID_X9_62_characteristic_two_field, 0, 30, 4
    },
    {
        /* no seed */
        0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        /* a */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        /* b */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        /* x */
        0x29, 0xA0, 0xB6, 0xA8, 0x87, 0xA9, 0x83, 0xE9, 0x73, 0x09, 0x88, 0xA6,
        0x87, 0x27, 0xA8, 0xB2, 0xD1, 0x26, 0xC4, 0x4C, 0xC2, 0xCC, 0x7B, 0x2A,
        0x65, 0x55, 0x19, 0x30, 0x35, 0xDC,
        /* y */
        0x76, 0x31, 0x08, 0x04, 0xF1, 0x2E, 0x54, 0x9B, 0xDB, 0x01, 0x1C, 0x10,
        0x30, 0x89, 0xE7, 0x35, 0x10, 0xAC, 0xB2, 0x75, 0xFC, 0x31, 0x2A, 0x5D,
        0xC6, 0xB7, 0x65, 0x53, 0xF0, 0xCA,
        /* order */
        0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x5A, 0x79, 0xFE, 0xC6, 0x7C, 0xB6, 0xE9, 0x1F, 0x1C,
        0x1D, 0xA8, 0x00, 0xE4, 0x78, 0xA5
    }
};

static const struct {
    EC_CURVE_DATA h;
    unsigned char data[0 + 36 * 6];
} _EC_NIST_CHAR2_283K = {
    {
        NID_X9_62_characteristic_two_field, 0, 36, 4
    },
    {
        /* no seed */
        0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0xA1,
        /* a */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        /* b */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        /* x */
        0x05, 0x03, 0x21, 0x3F, 0x78, 0xCA, 0x44, 0x88, 0x3F, 0x1A, 0x3B, 0x81,
        0x62, 0xF1, 0x88, 0xE5, 0x53, 0xCD, 0x26, 0x5F, 0x23, 0xC1, 0x56, 0x7A,
        0x16, 0x87, 0x69, 0x13, 0xB0, 0xC2, 0xAC, 0x24, 0x58, 0x49, 0x28, 0x36,
        /* y */
        0x01, 0xCC, 0xDA, 0x38, 0x0F, 0x1C, 0x9E, 0x31, 0x8D, 0x90, 0xF9, 0x5D,
        0x07, 0xE5, 0x42, 0x6F, 0xE8, 0x7E, 0x45, 0xC0, 0xE8, 0x18, 0x46, 0x98,
        0xE4, 0x59, 0x62, 0x36, 0x4E, 0x34, 0x11, 0x61, 0x77, 0xDD, 0x22, 0x59,
        /* order */
        0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xE9, 0xAE, 0x2E, 0xD0, 0x75, 0x77,
        0x26, 0x5D, 0xFF, 0x7F, 0x94, 0x45, 0x1E, 0x06, 0x1E, 0x16, 0x3C, 0x61
    }
};

static const struct {
    EC_CURVE_DATA h;
    unsigned char data[20 + 36 * 6];
} _EC_NIST_CHAR2_283B = {
    {
        NID_X9_62_characteristic_two_field, 20, 36, 2
    },
    {
        /* no seed */
        0x77, 0xE2, 0xB0, 0x73, 0x70, 0xEB, 0x0F, 0x83, 0x2A, 0x6D, 0xD5, 0xB6,
        0x2D, 0xFC, 0x88, 0xCD, 0x06, 0xBB, 0x84, 0xBE,
        /* p */
        0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0xA1,
        /* a */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        /* b */
        0x02, 0x7B, 0x68, 0x0A, 0xC8, 0xB8, 0x59, 0x6D, 0xA5, 0xA4, 0xAF, 0x8A,
        0x19, 0xA0, 0x30, 0x3F, 0xCA, 0x97, 0xFD, 0x76, 0x45, 0x30, 0x9F, 0xA2,
        0xA5, 0x81, 0x48, 0x5A, 0xF6, 0x26, 0x3E, 0x31, 0x3B, 0x79, 0xA2, 0xF5,
        /* x */
        0x05, 0xF9, 0x39, 0x25, 0x8D, 0xB7, 0xDD, 0x90, 0xE1, 0x93, 0x4F, 0x8C,
        0x70, 0xB0, 0xDF, 0xEC, 0x2E, 0xED, 0x25, 0xB8, 0x55, 0x7E, 0xAC, 0x9C,
        0x80, 0xE2, 0xE1, 0x98, 0xF8, 0xCD, 0xBE, 0xCD, 0x86, 0xB1, 0x20, 0x53,
        /* y */
        0x03, 0x67, 0x68, 0x54, 0xFE, 0x24, 0x14, 0x1C, 0xB9, 0x8F, 0xE6, 0xD4,
        0xB2, 0x0D, 0x02, 0xB4, 0x51, 0x6F, 0xF7, 0x02, 0x35, 0x0E, 0xDD, 0xB0,
        0x82, 0x67, 0x79, 0xC8, 0x13, 0xF0, 0xDF, 0x45, 0xBE, 0x81, 0x12, 0xF4,
        /* order */
        0x03, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xEF, 0x90, 0x39, 0x96, 0x60, 0xFC,
        0x93, 0x8A, 0x90, 0x16, 0x5B, 0x04, 0x2A, 0x7C, 0xEF, 0xAD, 0xB3, 0x07
    }
};

static const struct {
    EC_CURVE_DATA h;
    unsigned char data[0 + 52 * 6];
} _EC_NIST_CHAR2_409K = {
    {
        NID_X9_62_characteristic_two_field, 0, 52, 4
    },
    {
        /* no seed */
        /* p */
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x01,
        /* a */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        /* b */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x01,
        /* x */
        0x00, 0x60, 0xF0, 0x5F, 0x65, 0x8F, 0x49, 0xC1, 0xAD, 0x3A, 0xB1, 0x89,
        0x0F, 0x71, 0x84, 0x21, 0x0E, 0xFD, 0x09, 0x87, 0xE3, 0x07, 0xC8, 0x4C,
        0x27, 0xAC, 0xCF, 0xB8, 0xF9, 0xF6, 0x7C, 0xC2, 0xC4, 0x60, 0x18, 0x9E,
        0xB5, 0xAA, 0xAA, 0x62, 0xEE, 0x22, 0x2E, 0xB1, 0xB3, 0x55, 0x40, 0xCF,
        0xE9, 0x02, 0x37, 0x46,
        /* y */
        0x01, 0xE3, 0x69, 0x05, 0x0B, 0x7C, 0x4E, 0x42, 0xAC, 0xBA, 0x1D, 0xAC,
        0xBF, 0x04, 0x29, 0x9C, 0x34, 0x60, 0x78, 0x2F, 0x91, 0x8E, 0xA4, 0x27,
        0xE6, 0x32, 0x51, 0x65, 0xE9, 0xEA, 0x10, 0xE3, 0xDA, 0x5F, 0x6C, 0x42,
        0xE9, 0xC5, 0x52, 0x15, 0xAA, 0x9C, 0xA2, 0x7A, 0x58, 0x63, 0xEC, 0x48,
        0xD8, 0xE0, 0x28, 0x6B,
        /* order */
        0x00, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFE, 0x5F, 0x83, 0xB2, 0xD4, 0xEA, 0x20, 0x40, 0x0E, 0xC4,
        0x55, 0x7D, 0x5E, 0xD3, 0xE3, 0xE7, 0xCA, 0x5B, 0x4B, 0x5C, 0x83, 0xB8,
        0xE0, 0x1E, 0x5F, 0xCF
    }
};

static const struct {
    EC_CURVE_DATA h;
    unsigned char data[20 + 52 * 6];
} _EC_NIST_CHAR2_409B = {
    {
        NID_X9_62_characteristic_two_field, 20, 52, 2
    },
    {
        /* seed */
        0x40, 0x99, 0xB5, 0xA4, 0x57, 0xF9, 0xD6, 0x9F, 0x79, 0x21, 0x3D, 0x09,
        0x4C, 0x4B, 0xCD, 0x4D, 0x42, 0x62, 0x21, 0x0B,
        /* p */
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x01,
        /* a */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x01,
        /* b */
        0x00, 0x21, 0xA5, 0xC2, 0xC8, 0xEE, 0x9F, 0xEB, 0x5C, 0x4B, 0x9A, 0x75,
        0x3B, 0x7B, 0x47, 0x6B, 0x7F, 0xD6, 0x42, 0x2E, 0xF1, 0xF3, 0xDD, 0x67,
        0x47, 0x61, 0xFA, 0x99, 0xD6, 0xAC, 0x27, 0xC8, 0xA9, 0xA1, 0x97, 0xB2,
        0x72, 0x82, 0x2F, 0x6C, 0xD5, 0x7A, 0x55, 0xAA, 0x4F, 0x50, 0xAE, 0x31,
        0x7B, 0x13, 0x54, 0x5F,
        /* x */
        0x01, 0x5D, 0x48, 0x60, 0xD0, 0x88, 0xDD, 0xB3, 0x49, 0x6B, 0x0C, 0x60,
        0x64, 0x75, 0x62, 0x60, 0x44, 0x1C, 0xDE, 0x4A, 0xF1, 0x77, 0x1D, 0x4D,
        0xB0, 0x1F, 0xFE, 0x5B, 0x34, 0xE5, 0x97, 0x03, 0xDC, 0x25, 0x5A, 0x86,
        0x8A, 0x11, 0x80, 0x51, 0x56, 0x03, 0xAE, 0xAB, 0x60, 0x79, 0x4E, 0x54,
        0xBB, 0x79, 0x96, 0xA7,
        /* y */
        0x00, 0x61, 0xB1, 0xCF, 0xAB, 0x6B, 0xE5, 0xF3, 0x2B, 0xBF, 0xA7, 0x83,
        0x24, 0xED, 0x10, 0x6A, 0x76, 0x36, 0xB9, 0xC5, 0xA7, 0xBD, 0x19, 0x8D,
        0x01, 0x58, 0xAA, 0x4F, 0x54, 0x88, 0xD0, 0x8F, 0x38, 0x51, 0x4F, 0x1F,
        0xDF, 0x4B, 0x4F, 0x40, 0xD2, 0x18, 0x1B, 0x36, 0x81, 0xC3, 0x64, 0xBA,
        0x02, 0x73, 0xC7, 0x06,
        /* order */
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x01, 0xE2, 0xAA, 0xD6, 0xA6, 0x12, 0xF3, 0x33, 0x07, 0xBE,
        0x5F, 0xA4, 0x7C, 0x3C, 0x9E, 0x05, 0x2F, 0x83, 0x81, 0x64, 0xCD, 0x37,
        0xD9, 0xA2, 0x11, 0x73
    }
};

static const struct {
    EC_CURVE_DATA h;
    unsigned char data[0 + 72 * 6];
} _EC_NIST_CHAR2_571K = {
    {
        NID_X9_62_characteristic_two_field, 0, 72, 4
    },
    {
        /* no seed */
        /* p */
        0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x25,
        /* a */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        /* b */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        /* x */
        0x02, 0x6E, 0xB7, 0xA8, 0x59, 0x92, 0x3F, 0xBC, 0x82, 0x18, 0x96, 0x31,
        0xF8, 0x10, 0x3F, 0xE4, 0xAC, 0x9C, 0xA2, 0x97, 0x00, 0x12, 0xD5, 0xD4,
        0x60, 0x24, 0x80, 0x48, 0x01, 0x84, 0x1C, 0xA4, 0x43, 0x70, 0x95, 0x84,
        0x93, 0xB2, 0x05, 0xE6, 0x47, 0xDA, 0x30, 0x4D, 0xB4, 0xCE, 0xB0, 0x8C,
        0xBB, 0xD1, 0xBA, 0x39, 0x49, 0x47, 0x76, 0xFB, 0x98, 0x8B, 0x47, 0x17,
        0x4D, 0xCA, 0x88, 0xC7, 0xE2, 0x94, 0x52, 0x83, 0xA0, 0x1C, 0x89, 0x72,
        /* y */
        0x03, 0x49, 0xDC, 0x80, 0x7F, 0x4F, 0xBF, 0x37, 0x4F, 0x4A, 0xEA, 0xDE,
        0x3B, 0xCA, 0x95, 0x31, 0x4D, 0xD5, 0x8C, 0xEC, 0x9F, 0x30, 0x7A, 0x54,
        0xFF, 0xC6, 0x1E, 0xFC, 0x00, 0x6D, 0x8A, 0x2C, 0x9D, 0x49, 0x79, 0xC0,
        0xAC, 0x44, 0xAE, 0xA7, 0x4F, 0xBE, 0xBB, 0xB9, 0xF7, 0x72, 0xAE, 0xDC,
        0xB6, 0x20, 0xB0, 0x1A, 0x7B, 0xA7, 0xAF, 0x1B, 0x32, 0x04, 0x30, 0xC8,
        0x59, 0x19, 0x84, 0xF6, 0x01, 0xCD, 0x4C, 0x14, 0x3E, 0xF1, 0xC7, 0xA3,
        /* order */
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x13, 0x18, 0x50, 0xE1, 0xF1, 0x9A, 0x63, 0xE4, 0xB3, 0x91, 0xA8, 0xDB,
        0x91, 0x7F, 0x41, 0x38, 0xB6, 0x30, 0xD8, 0x4B, 0xE5, 0xD6, 0x39, 0x38,
        0x1E, 0x91, 0xDE, 0xB4, 0x5C, 0xFE, 0x77, 0x8F, 0x63, 0x7C, 0x10, 0x01
    }
};

static const struct {
    EC_CURVE_DATA h;
    unsigned char data[20 + 72 * 6];
} _EC_NIST_CHAR2_571B = {
    {
        NID_X9_62_characteristic_two_field, 20, 72, 2
    },
    {
        /* seed */
        0x2A, 0xA0, 0x58, 0xF7, 0x3A, 0x0E, 0x33, 0xAB, 0x48, 0x6B, 0x0F, 0x61,
        0x04, 0x10, 0xC5, 0x3A, 0x7F, 0x13, 0x23, 0x10,
        /* p */
        0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x25,
        /* a */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        /* b */
        0x02, 0xF4, 0x0E, 0x7E, 0x22, 0x21, 0xF2, 0x95, 0xDE, 0x29, 0x71, 0x17,
        0xB7, 0xF3, 0xD6, 0x2F, 0x5C, 0x6A, 0x97, 0xFF, 0xCB, 0x8C, 0xEF, 0xF1,
        0xCD, 0x6B, 0xA8, 0xCE, 0x4A, 0x9A, 0x18, 0xAD, 0x84, 0xFF, 0xAB, 0xBD,
        0x8E, 0xFA, 0x59, 0x33, 0x2B, 0xE7, 0xAD, 0x67, 0x56, 0xA6, 0x6E, 0x29,
        0x4A, 0xFD, 0x18, 0x5A, 0x78, 0xFF, 0x12, 0xAA, 0x52, 0x0E, 0x4D, 0xE7,
        0x39, 0xBA, 0xCA, 0x0C, 0x7F, 0xFE, 0xFF, 0x7F, 0x29, 0x55, 0x72, 0x7A,
        /* x */
        0x03, 0x03, 0x00, 0x1D, 0x34, 0xB8, 0x56, 0x29, 0x6C, 0x16, 0xC0, 0xD4,
        0x0D, 0x3C, 0xD7, 0x75, 0x0A, 0x93, 0xD1, 0xD2, 0x95, 0x5F, 0xA8, 0x0A,
        0xA5, 0xF4, 0x0F, 0xC8, 0xDB, 0x7B, 0x2A, 0xBD, 0xBD, 0xE5, 0x39, 0x50,
        0xF4, 0xC0, 0xD2, 0x93, 0xCD, 0xD7, 0x11, 0xA3, 0x5B, 0x67, 0xFB, 0x14,
        0x99, 0xAE, 0x60, 0x03, 0x86, 0x14, 0xF1, 0x39, 0x4A, 0xBF, 0xA3, 0xB4,
        0xC8, 0x50, 0xD9, 0x27, 0xE1, 0xE7, 0x76, 0x9C, 0x8E, 0xEC, 0x2D, 0x19,
        /* y */
        0x03, 0x7B, 0xF2, 0x73, 0x42, 0xDA, 0x63, 0x9B, 0x6D, 0xCC, 0xFF, 0xFE,
        0xB7, 0x3D, 0x69, 0xD7, 0x8C, 0x6C, 0x27, 0xA6, 0x00, 0x9C, 0xBB, 0xCA,
        0x19, 0x80, 0xF8, 0x53, 0x39, 0x21, 0xE8, 0xA6, 0x84, 0x42, 0x3E, 0x43,
        0xBA, 0xB0, 0x8A, 0x57, 0x62, 0x91, 0xAF, 0x8F, 0x46, 0x1B, 0xB2, 0xA8,
        0xB3, 0x53, 0x1D, 0x2F, 0x04, 0x85, 0xC1, 0x9B, 0x16, 0xE2, 0xF1, 0x51,
        0x6E, 0x23, 0xDD, 0x3C, 0x1A, 0x48, 0x27, 0xAF, 0x1B, 0x8A, 0xC1, 0x5B,
        /* order */
        0x03, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xE6, 0x61, 0xCE, 0x18, 0xFF, 0x55, 0x98, 0x73, 0x08, 0x05, 0x9B, 0x18,
        0x68, 0x23, 0x85, 0x1E, 0xC7, 0xDD, 0x9C, 0xA1, 0x16, 0x1D, 0xE9, 0x3D,
        0x51, 0x74, 0xD6, 0x6E, 0x83, 0x82, 0xE9, 0xBB, 0x2F, 0xE8, 0x4E, 0x47
    }
};

static const struct {
    EC_CURVE_DATA h;
    unsigned char data[20 + 21 * 6];
} _EC_X9_62_CHAR2_163V1 = {
    {
        NID_X9_62_characteristic_two_field, 20, 21, 2
    },
    {
        /* seed */
        0xD2, 0xC0, 0xFB, 0x15, 0x76, 0x08, 0x60, 0xDE, 0xF1, 0xEE, 0xF4, 0xD6,
        0x96, 0xE6, 0x76, 0x87, 0x56, 0x15, 0x17, 0x54,
        /* p */
        0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x07,
        /* a */
        0x07, 0x25, 0x46, 0xB5, 0x43, 0x52, 0x34, 0xA4, 0x22, 0xE0, 0x78, 0x96,
        0x75, 0xF4, 0x32, 0xC8, 0x94, 0x35, 0xDE, 0x52, 0x42,
        /* b */
        0x00, 0xC9, 0x51, 0x7D, 0x06, 0xD5, 0x24, 0x0D, 0x3C, 0xFF, 0x38, 0xC7,
        0x4B, 0x20, 0xB6, 0xCD, 0x4D, 0x6F, 0x9D, 0xD4, 0xD9,
        /* x */
        0x07, 0xAF, 0x69, 0x98, 0x95, 0x46, 0x10, 0x3D, 0x79, 0x32, 0x9F, 0xCC,
        0x3D, 0x74, 0x88, 0x0F, 0x33, 0xBB, 0xE8, 0x03, 0xCB,
        /* y */
        0x01, 0xEC, 0x23, 0x21, 0x1B, 0x59, 0x66, 0xAD, 0xEA, 0x1D, 0x3F, 0x87,
        0xF7, 0xEA, 0x58, 0x48, 0xAE, 0xF0, 0xB7, 0xCA, 0x9F,
        /* order */
        0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xE6,
        0x0F, 0xC8, 0x82, 0x1C, 0xC7, 0x4D, 0xAE, 0xAF, 0xC1
    }
};

static const struct {
    EC_CURVE_DATA h;
    unsigned char data[20 + 21 * 6];
} _EC_X9_62_CHAR2_163V2 = {
    {
        NID_X9_62_characteristic_two_field, 20, 21, 2
    },
    {
        /* seed */
        0x53, 0x81, 0x4C, 0x05, 0x0D, 0x44, 0xD6, 0x96, 0xE6, 0x76, 0x87, 0x56,
        0x15, 0x17, 0x58, 0x0C, 0xA4, 0xE2, 0x9F, 0xFD,
        /* p */
        0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x07,
        /* a */
        0x01, 0x08, 0xB3, 0x9E, 0x77, 0xC4, 0xB1, 0x08, 0xBE, 0xD9, 0x81, 0xED,
        0x0E, 0x89, 0x0E, 0x11, 0x7C, 0x51, 0x1C, 0xF0, 0x72,
        /* b */
        0x06, 0x67, 0xAC, 0xEB, 0x38, 0xAF, 0x4E, 0x48, 0x8C, 0x40, 0x74, 0x33,
        0xFF, 0xAE, 0x4F, 0x1C, 0x81, 0x16, 0x38, 0xDF, 0x20,
        /* x */
        0x00, 0x24, 0x26, 0x6E, 0x4E, 0xB5, 0x10, 0x6D, 0x0A, 0x96, 0x4D, 0x92,
        0xC4, 0x86, 0x0E, 0x26, 0x71, 0xDB, 0x9B, 0x6C, 0xC5,
        /* y */
        0x07, 0x9F, 0x68, 0x4D, 0xDF, 0x66, 0x84, 0xC5, 0xCD, 0x25, 0x8B, 0x38,
        0x90, 0x02, 0x1B, 0x23, 0x86, 0xDF, 0xD1, 0x9F, 0xC5,
        /* order */
        0x03, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFD, 0xF6,
        0x4D, 0xE1, 0x15, 0x1A, 0xDB, 0xB7, 0x8F, 0x10, 0xA7
    }
};

static const struct {
    EC_CURVE_DATA h;
    unsigned char data[20 + 21 * 6];
} _EC_X9_62_CHAR2_163V3 = {
    {
        NID_X9_62_characteristic_two_field, 20, 21, 2
    },
    {
        /* seed */
        0x50, 0xCB, 0xF1, 0xD9, 0x5C, 0xA9, 0x4D, 0x69, 0x6E, 0x67, 0x68, 0x75,
        0x61, 0x51, 0x75, 0xF1, 0x6A, 0x36, 0xA3, 0xB8,
        /* p */
        0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x07,
        /* a */
        0x07, 0xA5, 0x26, 0xC6, 0x3D, 0x3E, 0x25, 0xA2, 0x56, 0xA0, 0x07, 0x69,
        0x9F, 0x54, 0x47, 0xE3, 0x2A, 0xE4, 0x56, 0xB5, 0x0E,
        /* b */
        0x03, 0xF7, 0x06, 0x17, 0x98, 0xEB, 0x99, 0xE2, 0x38, 0xFD, 0x6F, 0x1B,
        0xF9, 0x5B, 0x48, 0xFE, 0xEB, 0x48, 0x54, 0x25, 0x2B,
        /* x */
        0x02, 0xF9, 0xF8, 0x7B, 0x7C, 0x57, 0x4D, 0x0B, 0xDE, 0xCF, 0x8A, 0x22,
        0xE6, 0x52, 0x47, 0x75, 0xF9, 0x8C, 0xDE, 0xBD, 0xCB,
        /* y */
        0x05, 0xB9, 0x35, 0x59, 0x0C, 0x15, 0x5E, 0x17, 0xEA, 0x48, 0xEB, 0x3F,
        0xF3, 0x71, 0x8B, 0x89, 0x3D, 0xF5, 0x9A, 0x05, 0xD0,
        /* order */
        0x03, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0x1A,
        0xEE, 0x14, 0x0F, 0x11, 0x0A, 0xFF, 0x96, 0x13, 0x09
    }
};

static const struct {
    EC_CURVE_DATA h;
    unsigned char data[0 + 23 * 6];
} _EC_X9_62_CHAR2_176V1 = {
    {
        NID_X9_62_characteristic_two_field, 0, 23, 0xFF6E
    },
    {
        /* no seed */
        /* p */
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x07,
        /* a */
        0x00, 0xE4, 0xE6, 0xDB, 0x29, 0x95, 0x06, 0x5C, 0x40, 0x7D, 0x9D, 0x39,
        0xB8, 0xD0, 0x96, 0x7B, 0x96, 0x70, 0x4B, 0xA8, 0xE9, 0xC9, 0x0B,
        /* b */
        0x00, 0x5D, 0xDA, 0x47, 0x0A, 0xBE, 0x64, 0x14, 0xDE, 0x8E, 0xC1, 0x33,
        0xAE, 0x28, 0xE9, 0xBB, 0xD7, 0xFC, 0xEC, 0x0A, 0xE0, 0xFF, 0xF2,
        /* x */
        0x00, 0x8D, 0x16, 0xC2, 0x86, 0x67, 0x98, 0xB6, 0x00, 0xF9, 0xF0, 0x8B,
        0xB4, 0xA8, 0xE8, 0x60, 0xF3, 0x29, 0x8C, 0xE0, 0x4A, 0x57, 0x98,
        /* y */
        0x00, 0x6F, 0xA4, 0x53, 0x9C, 0x2D, 0xAD, 0xDD, 0xD6, 0xBA, 0xB5, 0x16,
        0x7D, 0x61, 0xB4, 0x36, 0xE1, 0xD9, 0x2B, 0xB1, 0x6A, 0x56, 0x2C,
        /* order */
        0x00, 0x00, 0x01, 0x00, 0x92, 0x53, 0x73, 0x97, 0xEC, 0xA4, 0xF6, 0x14,
        0x57, 0x99, 0xD6, 0x2B, 0x0A, 0x19, 0xCE, 0x06, 0xFE, 0x26, 0xAD
    }
};

static const struct {
    EC_CURVE_DATA h;
    unsigned char data[20 + 24 * 6];
} _EC_X9_62_CHAR2_191V1 = {
    {
        NID_X9_62_characteristic_two_field, 20, 24, 2
    },
    {
        /* seed */
        0x4E, 0x13, 0xCA, 0x54, 0x27, 0x44, 0xD6, 0x96, 0xE6, 0x76, 0x87, 0x56,
        0x15, 0x17, 0x55, 0x2F, 0x27, 0x9A, 0x8C, 0x84,
        /* p */
        0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x01,
        /* a */
        0x28, 0x66, 0x53, 0x7B, 0x67, 0x67, 0x52, 0x63, 0x6A, 0x68, 0xF5, 0x65,
        0x54, 0xE1, 0x26, 0x40, 0x27, 0x6B, 0x64, 0x9E, 0xF7, 0x52, 0x62, 0x67,
        /* b */
        0x2E, 0x45, 0xEF, 0x57, 0x1F, 0x00, 0x78, 0x6F, 0x67, 0xB0, 0x08, 0x1B,
        0x94, 0x95, 0xA3, 0xD9, 0x54, 0x62, 0xF5, 0xDE, 0x0A, 0xA1, 0x85, 0xEC,
        /* x */
        0x36, 0xB3, 0xDA, 0xF8, 0xA2, 0x32, 0x06, 0xF9, 0xC4, 0xF2, 0x99, 0xD7,
        0xB2, 0x1A, 0x9C, 0x36, 0x91, 0x37, 0xF2, 0xC8, 0x4A, 0xE1, 0xAA, 0x0D,
        /* y */
        0x76, 0x5B, 0xE7, 0x34, 0x33, 0xB3, 0xF9, 0x5E, 0x33, 0x29, 0x32, 0xE7,
        0x0E, 0xA2, 0x45, 0xCA, 0x24, 0x18, 0xEA, 0x0E, 0xF9, 0x80, 0x18, 0xFB,
        /* order */
        0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x04, 0xA2, 0x0E, 0x90, 0xC3, 0x90, 0x67, 0xC8, 0x93, 0xBB, 0xB9, 0xA5
    }
};

static const struct {
    EC_CURVE_DATA h;
    unsigned char data[20 + 24 * 6];
} _EC_X9_62_CHAR2_191V2 = {
    {
        NID_X9_62_characteristic_two_field, 20, 24, 4
    },
    {
        /* seed */
        0x08, 0x71, 0xEF, 0x2F, 0xEF, 0x24, 0xD6, 0x96, 0xE6, 0x76, 0x87, 0x56,
        0x15, 0x17, 0x58, 0xBE, 0xE0, 0xD9, 0x5C, 0x15,
        /* p */
        0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x01,
        /* a */
        0x40, 0x10, 0x28, 0x77, 0x4D, 0x77, 0x77, 0xC7, 0xB7, 0x66, 0x6D, 0x13,
        0x66, 0xEA, 0x43, 0x20, 0x71, 0x27, 0x4F, 0x89, 0xFF, 0x01, 0xE7, 0x18,
        /* b */
        0x06, 0x20, 0x04, 0x8D, 0x28, 0xBC, 0xBD, 0x03, 0xB6, 0x24, 0x9C, 0x99,
        0x18, 0x2B, 0x7C, 0x8C, 0xD1, 0x97, 0x00, 0xC3, 0x62, 0xC4, 0x6A, 0x01,
        /* x */
        0x38, 0x09, 0xB2, 0xB7, 0xCC, 0x1B, 0x28, 0xCC, 0x5A, 0x87, 0x92, 0x6A,
        0xAD, 0x83, 0xFD, 0x28, 0x78, 0x9E, 0x81, 0xE2, 0xC9, 0xE3, 0xBF, 0x10,
        /* y */
        0x17, 0x43, 0x43, 0x86, 0x62, 0x6D, 0x14, 0xF3, 0xDB, 0xF0, 0x17, 0x60,
        0xD9, 0x21, 0x3A, 0x3E, 0x1C, 0xF3, 0x7A, 0xEC, 0x43, 0x7D, 0x66, 0x8A,
        /* order */
        0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x50, 0x50, 0x8C, 0xB8, 0x9F, 0x65, 0x28, 0x24, 0xE0, 0x6B, 0x81, 0x73
    }
};

static const struct {
    EC_CURVE_DATA h;
    unsigned char data[20 + 24 * 6];
} _EC_X9_62_CHAR2_191V3 = {
    {
        NID_X9_62_characteristic_two_field, 20, 24, 6
    },
    {
        /* seed */
        0xE0, 0x53, 0x51, 0x2D, 0xC6, 0x84, 0xD6, 0x96, 0xE6, 0x76, 0x87, 0x56,
        0x15, 0x17, 0x50, 0x67, 0xAE, 0x78, 0x6D, 0x1F,
        /* p */
        0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x01,
        /* a */
        0x6C, 0x01, 0x07, 0x47, 0x56, 0x09, 0x91, 0x22, 0x22, 0x10, 0x56, 0x91,
        0x1C, 0x77, 0xD7, 0x7E, 0x77, 0xA7, 0x77, 0xE7, 0xE7, 0xE7, 0x7F, 0xCB,
        /* b */
        0x71, 0xFE, 0x1A, 0xF9, 0x26, 0xCF, 0x84, 0x79, 0x89, 0xEF, 0xEF, 0x8D,
        0xB4, 0x59, 0xF6, 0x63, 0x94, 0xD9, 0x0F, 0x32, 0xAD, 0x3F, 0x15, 0xE8,
        /* x */
        0x37, 0x5D, 0x4C, 0xE2, 0x4F, 0xDE, 0x43, 0x44, 0x89, 0xDE, 0x87, 0x46,
        0xE7, 0x17, 0x86, 0x01, 0x50, 0x09, 0xE6, 0x6E, 0x38, 0xA9, 0x26, 0xDD,
        /* y */
        0x54, 0x5A, 0x39, 0x17, 0x61, 0x96, 0x57, 0x5D, 0x98, 0x59, 0x99, 0x36,
        0x6E, 0x6A, 0xD3, 0x4C, 0xE0, 0xA7, 0x7C, 0xD7, 0x12, 0x7B, 0x06, 0xBE,
        /* order */
        0x15, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
        0x61, 0x0C, 0x0B, 0x19, 0x68, 0x12, 0xBF, 0xB6, 0x28, 0x8A, 0x3E, 0xA3
    }
};

static const struct {
    EC_CURVE_DATA h;
    unsigned char data[0 + 27 * 6];
} _EC_X9_62_CHAR2_208W1 = {
    {
        NID_X9_62_characteristic_two_field, 0, 27, 0xFE48
    },
    {
        /* no seed */
        /* p */
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x07,
        /* a */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00,
        /* b */
        0x00, 0xC8, 0x61, 0x9E, 0xD4, 0x5A, 0x62, 0xE6, 0x21, 0x2E, 0x11, 0x60,
        0x34, 0x9E, 0x2B, 0xFA, 0x84, 0x44, 0x39, 0xFA, 0xFC, 0x2A, 0x3F, 0xD1,
        0x63, 0x8F, 0x9E,
        /* x */
        0x00, 0x89, 0xFD, 0xFB, 0xE4, 0xAB, 0xE1, 0x93, 0xDF, 0x95, 0x59, 0xEC,
        0xF0, 0x7A, 0xC0, 0xCE, 0x78, 0x55, 0x4E, 0x27, 0x84, 0xEB, 0x8C, 0x1E,
        0xD1, 0xA5, 0x7A,
        /* y */
        0x00, 0x0F, 0x55, 0xB5, 0x1A, 0x06, 0xE7, 0x8E, 0x9A, 0xC3, 0x8A, 0x03,
        0x5F, 0xF5, 0x20, 0xD8, 0xB0, 0x17, 0x81, 0xBE, 0xB1, 0xA6, 0xBB, 0x08,
        0x61, 0x7D, 0xE3,
        /* order */
        0x00, 0x00, 0x01, 0x01, 0xBA, 0xF9, 0x5C, 0x97, 0x23, 0xC5, 0x7B, 0x6C,
        0x21, 0xDA, 0x2E, 0xFF, 0x2D, 0x5E, 0xD5, 0x88, 0xBD, 0xD5, 0x71, 0x7E,
        0x21, 0x2F, 0x9D
    }
};

static const struct {
    EC_CURVE_DATA h;
    unsigned char data[20 + 30 * 6];
} _EC_X9_62_CHAR2_239V1 = {
    {
        NID_X9_62_characteristic_two_field, 20, 30, 4
    },
    {
        /* seed */
        0xD3, 0x4B, 0x9A, 0x4D, 0x69, 0x6E, 0x67, 0x68, 0x75, 0x61, 0x51, 0x75,
        0xCA, 0x71, 0xB9, 0x20, 0xBF, 0xEF, 0xB0, 0x5D,
        /* p */
        0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10, 0x00, 0x00, 0x00, 0x01,
        /* a */
        0x32, 0x01, 0x08, 0x57, 0x07, 0x7C, 0x54, 0x31, 0x12, 0x3A, 0x46, 0xB8,
        0x08, 0x90, 0x67, 0x56, 0xF5, 0x43, 0x42, 0x3E, 0x8D, 0x27, 0x87, 0x75,
        0x78, 0x12, 0x57, 0x78, 0xAC, 0x76,
        /* b */
        0x79, 0x04, 0x08, 0xF2, 0xEE, 0xDA, 0xF3, 0x92, 0xB0, 0x12, 0xED, 0xEF,
        0xB3, 0x39, 0x2F, 0x30, 0xF4, 0x32, 0x7C, 0x0C, 0xA3, 0xF3, 0x1F, 0xC3,
        0x83, 0xC4, 0x22, 0xAA, 0x8C, 0x16,
        /* x */
        0x57, 0x92, 0x70, 0x98, 0xFA, 0x93, 0x2E, 0x7C, 0x0A, 0x96, 0xD3, 0xFD,
        0x5B, 0x70, 0x6E, 0xF7, 0xE5, 0xF5, 0xC1, 0x56, 0xE1, 0x6B, 0x7E, 0x7C,
        0x86, 0x03, 0x85, 0x52, 0xE9, 0x1D,
        /* y */
        0x61, 0xD8, 0xEE, 0x50, 0x77, 0xC3, 0x3F, 0xEC, 0xF6, 0xF1, 0xA1, 0x6B,
        0x26, 0x8D, 0xE4, 0x69, 0xC3, 0xC7, 0x74, 0x4E, 0xA9, 0xA9, 0x71, 0x64,
        0x9F, 0xC7, 0xA9, 0x61, 0x63, 0x05,
        /* order */
        0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x0F, 0x4D, 0x42, 0xFF, 0xE1, 0x49, 0x2A, 0x49, 0x93,
        0xF1, 0xCA, 0xD6, 0x66, 0xE4, 0x47
    }
};

static const struct {
    EC_CURVE_DATA h;
    unsigned char data[20 + 30 * 6];
} _EC_X9_62_CHAR2_239V2 = {
    {
        NID_X9_62_characteristic_two_field, 20, 30, 6
    },
    {
        /* seed */
        0x2A, 0xA6, 0x98, 0x2F, 0xDF, 0xA4, 0xD6, 0x96, 0xE6, 0x76, 0x87, 0x56,
        0x15, 0x17, 0x5D, 0x26, 0x67, 0x27, 0x27, 0x7D,
        /* p */
        0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10, 0x00, 0x00, 0x00, 0x01,
        /* a */
        0x42, 0x30, 0x01, 0x77, 0x57, 0xA7, 0x67, 0xFA, 0xE4, 0x23, 0x98, 0x56,
        0x9B, 0x74, 0x63, 0x25, 0xD4, 0x53, 0x13, 0xAF, 0x07, 0x66, 0x26, 0x64,
        0x79, 0xB7, 0x56, 0x54, 0xE6, 0x5F,
        /* b */
        0x50, 0x37, 0xEA, 0x65, 0x41, 0x96, 0xCF, 0xF0, 0xCD, 0x82, 0xB2, 0xC1,
        0x4A, 0x2F, 0xCF, 0x2E, 0x3F, 0xF8, 0x77, 0x52, 0x85, 0xB5, 0x45, 0x72,
        0x2F, 0x03, 0xEA, 0xCD, 0xB7, 0x4B,
        /* x */
        0x28, 0xF9, 0xD0, 0x4E, 0x90, 0x00, 0x69, 0xC8, 0xDC, 0x47, 0xA0, 0x85,
        0x34, 0xFE, 0x76, 0xD2, 0xB9, 0x00, 0xB7, 0xD7, 0xEF, 0x31, 0xF5, 0x70,
        0x9F, 0x20, 0x0C, 0x4C, 0xA2, 0x05,
        /* y */
        0x56, 0x67, 0x33, 0x4C, 0x45, 0xAF, 0xF3, 0xB5, 0xA0, 0x3B, 0xAD, 0x9D,
        0xD7, 0x5E, 0x2C, 0x71, 0xA9, 0x93, 0x62, 0x56, 0x7D, 0x54, 0x53, 0xF7,
        0xFA, 0x6E, 0x22, 0x7E, 0xC8, 0x33,
        /* order */
        0x15, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
        0x55, 0x55, 0x55, 0x3C, 0x6F, 0x28, 0x85, 0x25, 0x9C, 0x31, 0xE3, 0xFC,
        0xDF, 0x15, 0x46, 0x24, 0x52, 0x2D
    }
};

static const struct {
    EC_CURVE_DATA h;
    unsigned char data[20 + 30 * 6];
} _EC_X9_62_CHAR2_239V3 = {
    {
        NID_X9_62_characteristic_two_field, 20, 30, 0xA
    },
    {
        /* seed */
        0x9E, 0x07, 0x6F, 0x4D, 0x69, 0x6E, 0x67, 0x68, 0x75, 0x61, 0x51, 0x75,
        0xE1, 0x1E, 0x9F, 0xDD, 0x77, 0xF9, 0x20, 0x41,
        /* p */
        0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10, 0x00, 0x00, 0x00, 0x01,
        /* a */
        0x01, 0x23, 0x87, 0x74, 0x66, 0x6A, 0x67, 0x76, 0x6D, 0x66, 0x76, 0xF7,
        0x78, 0xE6, 0x76, 0xB6, 0x69, 0x99, 0x17, 0x66, 0x66, 0xE6, 0x87, 0x66,
        0x6D, 0x87, 0x66, 0xC6, 0x6A, 0x9F,
        /* b */
        0x6A, 0x94, 0x19, 0x77, 0xBA, 0x9F, 0x6A, 0x43, 0x51, 0x99, 0xAC, 0xFC,
        0x51, 0x06, 0x7E, 0xD5, 0x87, 0xF5, 0x19, 0xC5, 0xEC, 0xB5, 0x41, 0xB8,
        0xE4, 0x41, 0x11, 0xDE, 0x1D, 0x40,
        /* x */
        0x70, 0xF6, 0xE9, 0xD0, 0x4D, 0x28, 0x9C, 0x4E, 0x89, 0x91, 0x3C, 0xE3,
        0x53, 0x0B, 0xFD, 0xE9, 0x03, 0x97, 0x7D, 0x42, 0xB1, 0x46, 0xD5, 0x39,
        0xBF, 0x1B, 0xDE, 0x4E, 0x9C, 0x92,
        /* y */
        0x2E, 0x5A, 0x0E, 0xAF, 0x6E, 0x5E, 0x13, 0x05, 0xB9, 0x00, 0x4D, 0xCE,
        0x5C, 0x0E, 0xD7, 0xFE, 0x59, 0xA3, 0x56, 0x08, 0xF3, 0x38, 0x37, 0xC8,
        0x16, 0xD8, 0x0B, 0x79, 0xF4, 0x61,
        /* order */
        0x0C, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
        0xCC, 0xCC, 0xCC, 0xAC, 0x49, 0x12, 0xD2, 0xD9, 0xDF, 0x90, 0x3E, 0xF9,
        0x88, 0x8B, 0x8A, 0x0E, 0x4C, 0xFF
    }
};

static const struct {
    EC_CURVE_DATA h;
    unsigned char data[0 + 35 * 6];
} _EC_X9_62_CHAR2_272W1 = {
    {
        NID_X9_62_characteristic_two_field, 0, 35, 0xFF06
    },
    {
        /* no seed */
        /* p */
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0B,
        /* a */
        0x00, 0x91, 0xA0, 0x91, 0xF0, 0x3B, 0x5F, 0xBA, 0x4A, 0xB2, 0xCC, 0xF4,
        0x9C, 0x4E, 0xDD, 0x22, 0x0F, 0xB0, 0x28, 0x71, 0x2D, 0x42, 0xBE, 0x75,
        0x2B, 0x2C, 0x40, 0x09, 0x4D, 0xBA, 0xCD, 0xB5, 0x86, 0xFB, 0x20,
        /* b */
        0x00, 0x71, 0x67, 0xEF, 0xC9, 0x2B, 0xB2, 0xE3, 0xCE, 0x7C, 0x8A, 0xAA,
        0xFF, 0x34, 0xE1, 0x2A, 0x9C, 0x55, 0x70, 0x03, 0xD7, 0xC7, 0x3A, 0x6F,
        0xAF, 0x00, 0x3F, 0x99, 0xF6, 0xCC, 0x84, 0x82, 0xE5, 0x40, 0xF7,
        /* x */
        0x00, 0x61, 0x08, 0xBA, 0xBB, 0x2C, 0xEE, 0xBC, 0xF7, 0x87, 0x05, 0x8A,
        0x05, 0x6C, 0xBE, 0x0C, 0xFE, 0x62, 0x2D, 0x77, 0x23, 0xA2, 0x89, 0xE0,
        0x8A, 0x07, 0xAE, 0x13, 0xEF, 0x0D, 0x10, 0xD1, 0x71, 0xDD, 0x8D,
        /* y */
        0x00, 0x10, 0xC7, 0x69, 0x57, 0x16, 0x85, 0x1E, 0xEF, 0x6B, 0xA7, 0xF6,
        0x87, 0x2E, 0x61, 0x42, 0xFB, 0xD2, 0x41, 0xB8, 0x30, 0xFF, 0x5E, 0xFC,
        0xAC, 0xEC, 0xCA, 0xB0, 0x5E, 0x02, 0x00, 0x5D, 0xDE, 0x9D, 0x23,
        /* order */
        0x00, 0x00, 0x01, 0x00, 0xFA, 0xF5, 0x13, 0x54, 0xE0, 0xE3, 0x9E, 0x48,
        0x92, 0xDF, 0x6E, 0x31, 0x9C, 0x72, 0xC8, 0x16, 0x16, 0x03, 0xFA, 0x45,
        0xAA, 0x7B, 0x99, 0x8A, 0x16, 0x7B, 0x8F, 0x1E, 0x62, 0x95, 0x21
    }
};

static const struct {
    EC_CURVE_DATA h;
    unsigned char data[0 + 39 * 6];
} _EC_X9_62_CHAR2_304W1 = {
    {
        NID_X9_62_characteristic_two_field, 0, 39, 0xFE2E
    },
    {
        /* no seed */
        /* p */
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x08, 0x07,
        /* a */
        0x00, 0xFD, 0x0D, 0x69, 0x31, 0x49, 0xA1, 0x18, 0xF6, 0x51, 0xE6, 0xDC,
        0xE6, 0x80, 0x20, 0x85, 0x37, 0x7E, 0x5F, 0x88, 0x2D, 0x1B, 0x51, 0x0B,
        0x44, 0x16, 0x00, 0x74, 0xC1, 0x28, 0x80, 0x78, 0x36, 0x5A, 0x03, 0x96,
        0xC8, 0xE6, 0x81,
        /* b */
        0x00, 0xBD, 0xDB, 0x97, 0xE5, 0x55, 0xA5, 0x0A, 0x90, 0x8E, 0x43, 0xB0,
        0x1C, 0x79, 0x8E, 0xA5, 0xDA, 0xA6, 0x78, 0x8F, 0x1E, 0xA2, 0x79, 0x4E,
        0xFC, 0xF5, 0x71, 0x66, 0xB8, 0xC1, 0x40, 0x39, 0x60, 0x1E, 0x55, 0x82,
        0x73, 0x40, 0xBE,
        /* x */
        0x00, 0x19, 0x7B, 0x07, 0x84, 0x5E, 0x9B, 0xE2, 0xD9, 0x6A, 0xDB, 0x0F,
        0x5F, 0x3C, 0x7F, 0x2C, 0xFF, 0xBD, 0x7A, 0x3E, 0xB8, 0xB6, 0xFE, 0xC3,
        0x5C, 0x7F, 0xD6, 0x7F, 0x26, 0xDD, 0xF6, 0x28, 0x5A, 0x64, 0x4F, 0x74,
        0x0A, 0x26, 0x14,
        /* y */
        0x00, 0xE1, 0x9F, 0xBE, 0xB7, 0x6E, 0x0D, 0xA1, 0x71, 0x51, 0x7E, 0xCF,
        0x40, 0x1B, 0x50, 0x28, 0x9B, 0xF0, 0x14, 0x10, 0x32, 0x88, 0x52, 0x7A,
        0x9B, 0x41, 0x6A, 0x10, 0x5E, 0x80, 0x26, 0x0B, 0x54, 0x9F, 0xDC, 0x1B,
        0x92, 0xC0, 0x3B,
        /* order */
        0x00, 0x00, 0x01, 0x01, 0xD5, 0x56, 0x57, 0x2A, 0xAB, 0xAC, 0x80, 0x01,
        0x01, 0xD5, 0x56, 0x57, 0x2A, 0xAB, 0xAC, 0x80, 0x01, 0x02, 0x2D, 0x5C,
        0x91, 0xDD, 0x17, 0x3F, 0x8F, 0xB5, 0x61, 0xDA, 0x68, 0x99, 0x16, 0x44,
        0x43, 0x05, 0x1D
    }
};

static const struct {
    EC_CURVE_DATA h;
    unsigned char data[20 + 45 * 6];
} _EC_X9_62_CHAR2_359V1 = {
    {
        NID_X9_62_characteristic_two_field, 20, 45, 0x4C
    },
    {
        /* seed */
        0x2B, 0x35, 0x49, 0x20, 0xB7, 0x24, 0xD6, 0x96, 0xE6, 0x76, 0x87, 0x56,
        0x15, 0x17, 0x58, 0x5B, 0xA1, 0x33, 0x2D, 0xC6,
        /* p */
        0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        /* a */
        0x56, 0x67, 0x67, 0x6A, 0x65, 0x4B, 0x20, 0x75, 0x4F, 0x35, 0x6E, 0xA9,
        0x20, 0x17, 0xD9, 0x46, 0x56, 0x7C, 0x46, 0x67, 0x55, 0x56, 0xF1, 0x95,
        0x56, 0xA0, 0x46, 0x16, 0xB5, 0x67, 0xD2, 0x23, 0xA5, 0xE0, 0x56, 0x56,
        0xFB, 0x54, 0x90, 0x16, 0xA9, 0x66, 0x56, 0xA5, 0x57,
        /* b */
        0x24, 0x72, 0xE2, 0xD0, 0x19, 0x7C, 0x49, 0x36, 0x3F, 0x1F, 0xE7, 0xF5,
        0xB6, 0xDB, 0x07, 0x5D, 0x52, 0xB6, 0x94, 0x7D, 0x13, 0x5D, 0x8C, 0xA4,
        0x45, 0x80, 0x5D, 0x39, 0xBC, 0x34, 0x56, 0x26, 0x08, 0x96, 0x87, 0x74,
        0x2B, 0x63, 0x29, 0xE7, 0x06, 0x80, 0x23, 0x19, 0x88,
        /* x */
        0x3C, 0x25, 0x8E, 0xF3, 0x04, 0x77, 0x67, 0xE7, 0xED, 0xE0, 0xF1, 0xFD,
        0xAA, 0x79, 0xDA, 0xEE, 0x38, 0x41, 0x36, 0x6A, 0x13, 0x2E, 0x16, 0x3A,
        0xCE, 0xD4, 0xED, 0x24, 0x01, 0xDF, 0x9C, 0x6B, 0xDC, 0xDE, 0x98, 0xE8,
        0xE7, 0x07, 0xC0, 0x7A, 0x22, 0x39, 0xB1, 0xB0, 0x97,
        /* y */
        0x53, 0xD7, 0xE0, 0x85, 0x29, 0x54, 0x70, 0x48, 0x12, 0x1E, 0x9C, 0x95,
        0xF3, 0x79, 0x1D, 0xD8, 0x04, 0x96, 0x39, 0x48, 0xF3, 0x4F, 0xAE, 0x7B,
        0xF4, 0x4E, 0xA8, 0x23, 0x65, 0xDC, 0x78, 0x68, 0xFE, 0x57, 0xE4, 0xAE,
        0x2D, 0xE2, 0x11, 0x30, 0x5A, 0x40, 0x71, 0x04, 0xBD,
        /* order */
        0x01, 0xAF, 0x28, 0x6B, 0xCA, 0x1A, 0xF2, 0x86, 0xBC, 0xA1, 0xAF, 0x28,
        0x6B, 0xCA, 0x1A, 0xF2, 0x86, 0xBC, 0xA1, 0xAF, 0x28, 0x6B, 0xC9, 0xFB,
        0x8F, 0x6B, 0x85, 0xC5, 0x56, 0x89, 0x2C, 0x20, 0xA7, 0xEB, 0x96, 0x4F,
        0xE7, 0x71, 0x9E, 0x74, 0xF4, 0x90, 0x75, 0x8D, 0x3B
    }
};

static const struct {
    EC_CURVE_DATA h;
    unsigned char data[0 + 47 * 6];
} _EC_X9_62_CHAR2_368W1 = {
    {
        NID_X9_62_characteristic_two_field, 0, 47, 0xFF70
    },
    {
        /* no seed */
        /* p */
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07,
        /* a */
        0x00, 0xE0, 0xD2, 0xEE, 0x25, 0x09, 0x52, 0x06, 0xF5, 0xE2, 0xA4, 0xF9,
        0xED, 0x22, 0x9F, 0x1F, 0x25, 0x6E, 0x79, 0xA0, 0xE2, 0xB4, 0x55, 0x97,
        0x0D, 0x8D, 0x0D, 0x86, 0x5B, 0xD9, 0x47, 0x78, 0xC5, 0x76, 0xD6, 0x2F,
        0x0A, 0xB7, 0x51, 0x9C, 0xCD, 0x2A, 0x1A, 0x90, 0x6A, 0xE3, 0x0D,
        /* b */
        0x00, 0xFC, 0x12, 0x17, 0xD4, 0x32, 0x0A, 0x90, 0x45, 0x2C, 0x76, 0x0A,
        0x58, 0xED, 0xCD, 0x30, 0xC8, 0xDD, 0x06, 0x9B, 0x3C, 0x34, 0x45, 0x38,
        0x37, 0xA3, 0x4E, 0xD5, 0x0C, 0xB5, 0x49, 0x17, 0xE1, 0xC2, 0x11, 0x2D,
        0x84, 0xD1, 0x64, 0xF4, 0x44, 0xF8, 0xF7, 0x47, 0x86, 0x04, 0x6A,
        /* x */
        0x00, 0x10, 0x85, 0xE2, 0x75, 0x53, 0x81, 0xDC, 0xCC, 0xE3, 0xC1, 0x55,
        0x7A, 0xFA, 0x10, 0xC2, 0xF0, 0xC0, 0xC2, 0x82, 0x56, 0x46, 0xC5, 0xB3,
        0x4A, 0x39, 0x4C, 0xBC, 0xFA, 0x8B, 0xC1, 0x6B, 0x22, 0xE7, 0xE7, 0x89,
        0xE9, 0x27, 0xBE, 0x21, 0x6F, 0x02, 0xE1, 0xFB, 0x13, 0x6A, 0x5F,
        /* y */
        0x00, 0x7B, 0x3E, 0xB1, 0xBD, 0xDC, 0xBA, 0x62, 0xD5, 0xD8, 0xB2, 0x05,
        0x9B, 0x52, 0x57, 0x97, 0xFC, 0x73, 0x82, 0x2C, 0x59, 0x05, 0x9C, 0x62,
        0x3A, 0x45, 0xFF, 0x38, 0x43, 0xCE, 0xE8, 0xF8, 0x7C, 0xD1, 0x85, 0x5A,
        0xDA, 0xA8, 0x1E, 0x2A, 0x07, 0x50, 0xB8, 0x0F, 0xDA, 0x23, 0x10,
        /* order */
        0x00, 0x00, 0x01, 0x00, 0x90, 0x51, 0x2D, 0xA9, 0xAF, 0x72, 0xB0, 0x83,
        0x49, 0xD9, 0x8A, 0x5D, 0xD4, 0xC7, 0xB0, 0x53, 0x2E, 0xCA, 0x51, 0xCE,
        0x03, 0xE2, 0xD1, 0x0F, 0x3B, 0x7A, 0xC5, 0x79, 0xBD, 0x87, 0xE9, 0x09,
        0xAE, 0x40, 0xA6, 0xF1, 0x31, 0xE9, 0xCF, 0xCE, 0x5B, 0xD9, 0x67
    }
};

static const struct {
    EC_CURVE_DATA h;
    unsigned char data[0 + 54 * 6];
} _EC_X9_62_CHAR2_431R1 = {
    {
        NID_X9_62_characteristic_two_field, 0, 54, 0x2760
    },
    {
        /* no seed */
        /* p */
        0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        /* a */
        0x1A, 0x82, 0x7E, 0xF0, 0x0D, 0xD6, 0xFC, 0x0E, 0x23, 0x4C, 0xAF, 0x04,
        0x6C, 0x6A, 0x5D, 0x8A, 0x85, 0x39, 0x5B, 0x23, 0x6C, 0xC4, 0xAD, 0x2C,
        0xF3, 0x2A, 0x0C, 0xAD, 0xBD, 0xC9, 0xDD, 0xF6, 0x20, 0xB0, 0xEB, 0x99,
        0x06, 0xD0, 0x95, 0x7F, 0x6C, 0x6F, 0xEA, 0xCD, 0x61, 0x54, 0x68, 0xDF,
        0x10, 0x4D, 0xE2, 0x96, 0xCD, 0x8F,
        /* b */
        0x10, 0xD9, 0xB4, 0xA3, 0xD9, 0x04, 0x7D, 0x8B, 0x15, 0x43, 0x59, 0xAB,
        0xFB, 0x1B, 0x7F, 0x54, 0x85, 0xB0, 0x4C, 0xEB, 0x86, 0x82, 0x37, 0xDD,
        0xC9, 0xDE, 0xDA, 0x98, 0x2A, 0x67, 0x9A, 0x5A, 0x91, 0x9B, 0x62, 0x6D,
        0x4E, 0x50, 0xA8, 0xDD, 0x73, 0x1B, 0x10, 0x7A, 0x99, 0x62, 0x38, 0x1F,
        0xB5, 0xD8, 0x07, 0xBF, 0x26, 0x18,
        /* x */
        0x12, 0x0F, 0xC0, 0x5D, 0x3C, 0x67, 0xA9, 0x9D, 0xE1, 0x61, 0xD2, 0xF4,
        0x09, 0x26, 0x22, 0xFE, 0xCA, 0x70, 0x1B, 0xE4, 0xF5, 0x0F, 0x47, 0x58,
        0x71, 0x4E, 0x8A, 0x87, 0xBB, 0xF2, 0xA6, 0x58, 0xEF, 0x8C, 0x21, 0xE7,
        0xC5, 0xEF, 0xE9, 0x65, 0x36, 0x1F, 0x6C, 0x29, 0x99, 0xC0, 0xC2, 0x47,
        0xB0, 0xDB, 0xD7, 0x0C, 0xE6, 0xB7,
        /* y */
        0x20, 0xD0, 0xAF, 0x89, 0x03, 0xA9, 0x6F, 0x8D, 0x5F, 0xA2, 0xC2, 0x55,
        0x74, 0x5D, 0x3C, 0x45, 0x1B, 0x30, 0x2C, 0x93, 0x46, 0xD9, 0xB7, 0xE4,
        0x85, 0xE7, 0xBC, 0xE4, 0x1F, 0x6B, 0x59, 0x1F, 0x3E, 0x8F, 0x6A, 0xDD,
        0xCB, 0xB0, 0xBC, 0x4C, 0x2F, 0x94, 0x7A, 0x7D, 0xE1, 0xA8, 0x9B, 0x62,
        0x5D, 0x6A, 0x59, 0x8B, 0x37, 0x60,
        /* order */
        0x00, 0x03, 0x40, 0x34, 0x03, 0x40, 0x34, 0x03, 0x40, 0x34, 0x03, 0x40,
        0x34, 0x03, 0x40, 0x34, 0x03, 0x40, 0x34, 0x03, 0x40, 0x34, 0x03, 0x40,
        0x34, 0x03, 0x40, 0x34, 0x03, 0x23, 0xC3, 0x13, 0xFA, 0xB5, 0x05, 0x89,
        0x70, 0x3B, 0x5E, 0xC6, 0x8D, 0x35, 0x87, 0xFE, 0xC6, 0x0D, 0x16, 0x1C,
        0xC1, 0x49, 0xC1, 0xAD, 0x4A, 0x91
    }
};

static const struct {
    EC_CURVE_DATA h;
    unsigned char data[0 + 15 * 6];
} _EC_WTLS_1 = {
    {
        NID_X9_62_characteristic_two_field, 0, 15, 2
    },
    {
        /* no seed */
        /* p */
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x02, 0x01,
        /* a */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x01,
        /* b */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x01,
        /* x */
        0x01, 0x66, 0x79, 0x79, 0xA4, 0x0B, 0xA4, 0x97, 0xE5, 0xD5, 0xC2, 0x70,
        0x78, 0x06, 0x17,
        /* y */
        0x00, 0xF4, 0x4B, 0x4A, 0xF1, 0xEC, 0xC2, 0x63, 0x0E, 0x08, 0x78, 0x5C,
        0xEB, 0xCC, 0x15,
        /* order */
        0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFD, 0xBF, 0x91, 0xAF,
        0x6D, 0xEA, 0x73
    }
};

/* IPSec curves */
/*
 * NOTE: The of curves over a extension field of non prime degree is not
 * recommended (Weil-descent). As the group order is not a prime this curve
 * is not suitable for ECDSA.
 */
static const struct {
    EC_CURVE_DATA h;
    unsigned char data[0 + 20 * 6];
} _EC_IPSEC_155_ID3 = {
    {
        NID_X9_62_characteristic_two_field, 0, 20, 3
    },
    {
        /* no seed */
        /* p */
        0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        /* a */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        /* b */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x33, 0x8f,
        /* x */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7b,
        /* y */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xc8,
        /* order */
        0x02, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xC7, 0xF3,
        0xC7, 0x88, 0x1B, 0xD0, 0x86, 0x8F, 0xA8, 0x6C
    }
};

/*
 * NOTE: The of curves over a extension field of non prime degree is not
 * recommended (Weil-descent). As the group order is not a prime this curve
 * is not suitable for ECDSA.
 */
static const struct {
    EC_CURVE_DATA h;
    unsigned char data[0 + 24 * 6];
} _EC_IPSEC_185_ID4 = {
    {
        NID_X9_62_characteristic_two_field, 0, 24, 2
    },
    {
        /* no seed */
        /* p */
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        /* a */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        /* b */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1e, 0xe9,
        /* x */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18,
        /* y */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d,
        /* order */
        0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xED, 0xF9, 0x7C, 0x44, 0xDB, 0x9F, 0x24, 0x20, 0xBA, 0xFC, 0xA7, 0x5E
    }
};

#endif

/*
 * These curves were added by Annie Yousar <a.yousar@informatik.hu-berlin.de>
 * For the definition of RFC 5639 curves see
 * http://www.ietf.org/rfc/rfc5639.txt These curves are generated verifiable
 * at random, nevertheless the seed is omitted as parameter because the
 * generation mechanism is different from those defined in ANSI X9.62.
 */

static const struct {
    EC_CURVE_DATA h;
    unsigned char data[0 + 20 * 6];
} _EC_brainpoolP160r1 = {
    {
        NID_X9_62_prime_field, 0, 20, 1
    },
    {
        /* no seed */
        /* p */
        0xE9, 0x5E, 0x4A, 0x5F, 0x73, 0x70, 0x59, 0xDC, 0x60, 0xDF, 0xC7, 0xAD,
        0x95, 0xB3, 0xD8, 0x13, 0x95, 0x15, 0x62, 0x0F,
        /* a */
        0x34, 0x0E, 0x7B, 0xE2, 0xA2, 0x80, 0xEB, 0x74, 0xE2, 0xBE, 0x61, 0xBA,
        0xDA, 0x74, 0x5D, 0x97, 0xE8, 0xF7, 0xC3, 0x00,
        /* b */
        0x1E, 0x58, 0x9A, 0x85, 0x95, 0x42, 0x34, 0x12, 0x13, 0x4F, 0xAA, 0x2D,
        0xBD, 0xEC, 0x95, 0xC8, 0xD8, 0x67, 0x5E, 0x58,
        /* x */
        0xBE, 0xD5, 0xAF, 0x16, 0xEA, 0x3F, 0x6A, 0x4F, 0x62, 0x93, 0x8C, 0x46,
        0x31, 0xEB, 0x5A, 0xF7, 0xBD, 0xBC, 0xDB, 0xC3,
        /* y */
        0x16, 0x67, 0xCB, 0x47, 0x7A, 0x1A, 0x8E, 0xC3, 0x38, 0xF9, 0x47, 0x41,
        0x66, 0x9C, 0x97, 0x63, 0x16, 0xDA, 0x63, 0x21,
        /* order */
        0xE9, 0x5E, 0x4A, 0x5F, 0x73, 0x70, 0x59, 0xDC, 0x60, 0xDF, 0x59, 0x91,
        0xD4, 0x50, 0x29, 0x40, 0x9E, 0x60, 0xFC, 0x09
    }
};

static const struct {
    EC_CURVE_DATA h;
    unsigned char data[0 + 20 * 6];
} _EC_brainpoolP160t1 = {
    {
        NID_X9_62_prime_field, 0, 20, 1
    },
    {
        /* no seed */
        /* p */
        0xE9, 0x5E, 0x4A, 0x5F, 0x73, 0x70, 0x59, 0xDC, 0x60, 0xDF, 0xC7, 0xAD,
        0x95, 0xB3, 0xD8, 0x13, 0x95, 0x15, 0x62, 0x0F,
        /* a */
        0xE9, 0x5E, 0x4A, 0x5F, 0x73, 0x70, 0x59, 0xDC, 0x60, 0xDF, 0xC7, 0xAD,
        0x95, 0xB3, 0xD8, 0x13, 0x95, 0x15, 0x62, 0x0C,
        /* b */
        0x7A, 0x55, 0x6B, 0x6D, 0xAE, 0x53, 0x5B, 0x7B, 0x51, 0xED, 0x2C, 0x4D,
        0x7D, 0xAA, 0x7A, 0x0B, 0x5C, 0x55, 0xF3, 0x80,
        /* x */
        0xB1, 0x99, 0xB1, 0x3B, 0x9B, 0x34, 0xEF, 0xC1, 0x39, 0x7E, 0x64, 0xBA,
        0xEB, 0x05, 0xAC, 0xC2, 0x65, 0xFF, 0x23, 0x78,
        /* y */
        0xAD, 0xD6, 0x71, 0x8B, 0x7C, 0x7C, 0x19, 0x61, 0xF0, 0x99, 0x1B, 0x84,
        0x24, 0x43, 0x77, 0x21, 0x52, 0xC9, 0xE0, 0xAD,
        /* order */
        0xE9, 0x5E, 0x4A, 0x5F, 0x73, 0x70, 0x59, 0xDC, 0x60, 0xDF, 0x59, 0x91,
        0xD4, 0x50, 0x29, 0x40, 0x9E, 0x60, 0xFC, 0x09
    }
};

static const struct {
    EC_CURVE_DATA h;
    unsigned char data[0 + 24 * 6];
} _EC_brainpoolP192r1 = {
    {
        NID_X9_62_prime_field, 0, 24, 1
    },
    {
        /* no seed */
        /* p */
        0xC3, 0x02, 0xF4, 0x1D, 0x93, 0x2A, 0x36, 0xCD, 0xA7, 0xA3, 0x46, 0x30,
        0x93, 0xD1, 0x8D, 0xB7, 0x8F, 0xCE, 0x47, 0x6D, 0xE1, 0xA8, 0x62, 0x97,
        /* a */
        0x6A, 0x91, 0x17, 0x40, 0x76, 0xB1, 0xE0, 0xE1, 0x9C, 0x39, 0xC0, 0x31,
        0xFE, 0x86, 0x85, 0xC1, 0xCA, 0xE0, 0x40, 0xE5, 0xC6, 0x9A, 0x28, 0xEF,
        /* b */
        0x46, 0x9A, 0x28, 0xEF, 0x7C, 0x28, 0xCC, 0xA3, 0xDC, 0x72, 0x1D, 0x04,
        0x4F, 0x44, 0x96, 0xBC, 0xCA, 0x7E, 0xF4, 0x14, 0x6F, 0xBF, 0x25, 0xC9,
        /* x */
        0xC0, 0xA0, 0x64, 0x7E, 0xAA, 0xB6, 0xA4, 0x87, 0x53, 0xB0, 0x33, 0xC5,
        0x6C, 0xB0, 0xF0, 0x90, 0x0A, 0x2F, 0x5C, 0x48, 0x53, 0x37, 0x5F, 0xD6,
        /* y */
        0x14, 0xB6, 0x90, 0x86, 0x6A, 0xBD, 0x5B, 0xB8, 0x8B, 0x5F, 0x48, 0x28,
        0xC1, 0x49, 0x00, 0x02, 0xE6, 0x77, 0x3F, 0xA2, 0xFA, 0x29, 0x9B, 0x8F,
        /* order */
        0xC3, 0x02, 0xF4, 0x1D, 0x93, 0x2A, 0x36, 0xCD, 0xA7, 0xA3, 0x46, 0x2F,
        0x9E, 0x9E, 0x91, 0x6B, 0x5B, 0xE8, 0xF1, 0x02, 0x9A, 0xC4, 0xAC, 0xC1
    }
};

static const struct {
    EC_CURVE_DATA h;
    unsigned char data[0 + 24 * 6];
} _EC_brainpoolP192t1 = {
    {
        NID_X9_62_prime_field, 0, 24, 1
    },
    {
        /* no seed */
        /* p */
        0xC3, 0x02, 0xF4, 0x1D, 0x93, 0x2A, 0x36, 0xCD, 0xA7, 0xA3, 0x46, 0x30,
        0x93, 0xD1, 0x8D, 0xB7, 0x8F, 0xCE, 0x47, 0x6D, 0xE1, 0xA8, 0x62, 0x97,
        /* a */
        0xC3, 0x02, 0xF4, 0x1D, 0x93, 0x2A, 0x36, 0xCD, 0xA7, 0xA3, 0x46, 0x30,
        0x93, 0xD1, 0x8D, 0xB7, 0x8F, 0xCE, 0x47, 0x6D, 0xE1, 0xA8, 0x62, 0x94,
        /* b */
        0x13, 0xD5, 0x6F, 0xFA, 0xEC, 0x78, 0x68, 0x1E, 0x68, 0xF9, 0xDE, 0xB4,
        0x3B, 0x35, 0xBE, 0xC2, 0xFB, 0x68, 0x54, 0x2E, 0x27, 0x89, 0x7B, 0x79,
        /* x */
        0x3A, 0xE9, 0xE5, 0x8C, 0x82, 0xF6, 0x3C, 0x30, 0x28, 0x2E, 0x1F, 0xE7,
        0xBB, 0xF4, 0x3F, 0xA7, 0x2C, 0x44, 0x6A, 0xF6, 0xF4, 0x61, 0x81, 0x29,
        /* y */
        0x09, 0x7E, 0x2C, 0x56, 0x67, 0xC2, 0x22, 0x3A, 0x90, 0x2A, 0xB5, 0xCA,
        0x44, 0x9D, 0x00, 0x84, 0xB7, 0xE5, 0xB3, 0xDE, 0x7C, 0xCC, 0x01, 0xC9,
        /* order */
        0xC3, 0x02, 0xF4, 0x1D, 0x93, 0x2A, 0x36, 0xCD, 0xA7, 0xA3, 0x46, 0x2F,
        0x9E, 0x9E, 0x91, 0x6B, 0x5B, 0xE8, 0xF1, 0x02, 0x9A, 0xC4, 0xAC, 0xC1
    }
};

static const struct {
    EC_CURVE_DATA h;
    unsigned char data[0 + 28 * 6];
} _EC_brainpoolP224r1 = {
    {
        NID_X9_62_prime_field, 0, 28, 1
    },
    {
        /* no seed */
        /* p */
        0xD7, 0xC1, 0x34, 0xAA, 0x26, 0x43, 0x66, 0x86, 0x2A, 0x18, 0x30, 0x25,
        0x75, 0xD1, 0xD7, 0x87, 0xB0, 0x9F, 0x07, 0x57, 0x97, 0xDA, 0x89, 0xF5,
        0x7E, 0xC8, 0xC0, 0xFF,
        /* a */
        0x68, 0xA5, 0xE6, 0x2C, 0xA9, 0xCE, 0x6C, 0x1C, 0x29, 0x98, 0x03, 0xA6,
        0xC1, 0x53, 0x0B, 0x51, 0x4E, 0x18, 0x2A, 0xD8, 0xB0, 0x04, 0x2A, 0x59,
        0xCA, 0xD2, 0x9F, 0x43,
        /* b */
        0x25, 0x80, 0xF6, 0x3C, 0xCF, 0xE4, 0x41, 0x38, 0x87, 0x07, 0x13, 0xB1,
        0xA9, 0x23, 0x69, 0xE3, 0x3E, 0x21, 0x35, 0xD2, 0x66, 0xDB, 0xB3, 0x72,
        0x38, 0x6C, 0x40, 0x0B,
        /* x */
        0x0D, 0x90, 0x29, 0xAD, 0x2C, 0x7E, 0x5C, 0xF4, 0x34, 0x08, 0x23, 0xB2,
        0xA8, 0x7D, 0xC6, 0x8C, 0x9E, 0x4C, 0xE3, 0x17, 0x4C, 0x1E, 0x6E, 0xFD,
        0xEE, 0x12, 0xC0, 0x7D,
        /* y */
        0x58, 0xAA, 0x56, 0xF7, 0x72, 0xC0, 0x72, 0x6F, 0x24, 0xC6, 0xB8, 0x9E,
        0x4E, 0xCD, 0xAC, 0x24, 0x35, 0x4B, 0x9E, 0x99, 0xCA, 0xA3, 0xF6, 0xD3,
        0x76, 0x14, 0x02, 0xCD,
        /* order */
        0xD7, 0xC1, 0x34, 0xAA, 0x26, 0x43, 0x66, 0x86, 0x2A, 0x18, 0x30, 0x25,
        0x75, 0xD0, 0xFB, 0x98, 0xD1, 0x16, 0xBC, 0x4B, 0x6D, 0xDE, 0xBC, 0xA3,
        0xA5, 0xA7, 0x93, 0x9F
    }
};

static const struct {
    EC_CURVE_DATA h;
    unsigned char data[0 + 28 * 6];
} _EC_brainpoolP224t1 = {
    {
        NID_X9_62_prime_field, 0, 28, 1
    },
    {
        /* no seed */
        /* p */
        0xD7, 0xC1, 0x34, 0xAA, 0x26, 0x43, 0x66, 0x86, 0x2A, 0x18, 0x30, 0x25,
        0x75, 0xD1, 0xD7, 0x87, 0xB0, 0x9F, 0x07, 0x57, 0x97, 0xDA, 0x89, 0xF5,
        0x7E, 0xC8, 0xC0, 0xFF,
        /* a */
        0xD7, 0xC1, 0x34, 0xAA, 0x26, 0x43, 0x66, 0x86, 0x2A, 0x18, 0x30, 0x25,
        0x75, 0xD1, 0xD7, 0x87, 0xB0, 0x9F, 0x07, 0x57, 0x97, 0xDA, 0x89, 0xF5,
        0x7E, 0xC8, 0xC0, 0xFC,
        /* b */
        0x4B, 0x33, 0x7D, 0x93, 0x41, 0x04, 0xCD, 0x7B, 0xEF, 0x27, 0x1B, 0xF6,
        0x0C, 0xED, 0x1E, 0xD2, 0x0D, 0xA1, 0x4C, 0x08, 0xB3, 0xBB, 0x64, 0xF1,
        0x8A, 0x60, 0x88, 0x8D,
        /* x */
        0x6A, 0xB1, 0xE3, 0x44, 0xCE, 0x25, 0xFF, 0x38, 0x96, 0x42, 0x4E, 0x7F,
        0xFE, 0x14, 0x76, 0x2E, 0xCB, 0x49, 0xF8, 0x92, 0x8A, 0xC0, 0xC7, 0x60,
        0x29, 0xB4, 0xD5, 0x80,
        /* y */
        0x03, 0x74, 0xE9, 0xF5, 0x14, 0x3E, 0x56, 0x8C, 0xD2, 0x3F, 0x3F, 0x4D,
        0x7C, 0x0D, 0x4B, 0x1E, 0x41, 0xC8, 0xCC, 0x0D, 0x1C, 0x6A, 0xBD, 0x5F,
        0x1A, 0x46, 0xDB, 0x4C,
        /* order */
        0xD7, 0xC1, 0x34, 0xAA, 0x26, 0x43, 0x66, 0x86, 0x2A, 0x18, 0x30, 0x25,
        0x75, 0xD0, 0xFB, 0x98, 0xD1, 0x16, 0xBC, 0x4B, 0x6D, 0xDE, 0xBC, 0xA3,
        0xA5, 0xA7, 0x93, 0x9F
    }
};

static const struct {
    EC_CURVE_DATA h;
    unsigned char data[0 + 32 * 6];
} _EC_brainpoolP256r1 = {
    {
        NID_X9_62_prime_field, 0, 32, 1
    },
    {
        /* no seed */
        /* p */
        0xA9, 0xFB, 0x57, 0xDB, 0xA1, 0xEE, 0xA9, 0xBC, 0x3E, 0x66, 0x0A, 0x90,
        0x9D, 0x83, 0x8D, 0x72, 0x6E, 0x3B, 0xF6, 0x23, 0xD5, 0x26, 0x20, 0x28,
        0x20, 0x13, 0x48, 0x1D, 0x1F, 0x6E, 0x53, 0x77,
        /* a */
        0x7D, 0x5A, 0x09, 0x75, 0xFC, 0x2C, 0x30, 0x57, 0xEE, 0xF6, 0x75, 0x30,
        0x41, 0x7A, 0xFF, 0xE7, 0xFB, 0x80, 0x55, 0xC1, 0x26, 0xDC, 0x5C, 0x6C,
        0xE9, 0x4A, 0x4B, 0x44, 0xF3, 0x30, 0xB5, 0xD9,
        /* b */
        0x26, 0xDC, 0x5C, 0x6C, 0xE9, 0x4A, 0x4B, 0x44, 0xF3, 0x30, 0xB5, 0xD9,
        0xBB, 0xD7, 0x7C, 0xBF, 0x95, 0x84, 0x16, 0x29, 0x5C, 0xF7, 0xE1, 0xCE,
        0x6B, 0xCC, 0xDC, 0x18, 0xFF, 0x8C, 0x07, 0xB6,
        /* x */
        0x8B, 0xD2, 0xAE, 0xB9, 0xCB, 0x7E, 0x57, 0xCB, 0x2C, 0x4B, 0x48, 0x2F,
        0xFC, 0x81, 0xB7, 0xAF, 0xB9, 0xDE, 0x27, 0xE1, 0xE3, 0xBD, 0x23, 0xC2,
        0x3A, 0x44, 0x53, 0xBD, 0x9A, 0xCE, 0x32, 0x62,
        /* y */
        0x54, 0x7E, 0xF8, 0x35, 0xC3, 0xDA, 0xC4, 0xFD, 0x97, 0xF8, 0x46, 0x1A,
        0x14, 0x61, 0x1D, 0xC9, 0xC2, 0x77, 0x45, 0x13, 0x2D, 0xED, 0x8E, 0x54,
        0x5C, 0x1D, 0x54, 0xC7, 0x2F, 0x04, 0x69, 0x97,
        /* order */
        0xA9, 0xFB, 0x57, 0xDB, 0xA1, 0xEE, 0xA9, 0xBC, 0x3E, 0x66, 0x0A, 0x90,
        0x9D, 0x83, 0x8D, 0x71, 0x8C, 0x39, 0x7A, 0xA3, 0xB5, 0x61, 0xA6, 0xF7,
        0x90, 0x1E, 0x0E, 0x82, 0x97, 0x48, 0x56, 0xA7
    }
};

static const struct {
    EC_CURVE_DATA h;
    unsigned char data[0 + 32 * 6];
} _EC_brainpoolP256t1 = {
    {
        NID_X9_62_prime_field, 0, 32, 1
    },
    {
        /* no seed */
        /* p */
        0xA9, 0xFB, 0x57, 0xDB, 0xA1, 0xEE, 0xA9, 0xBC, 0x3E, 0x66, 0x0A, 0x90,
        0x9D, 0x83, 0x8D, 0x72, 0x6E, 0x3B, 0xF6, 0x23, 0xD5, 0x26, 0x20, 0x28,
        0x20, 0x13, 0x48, 0x1D, 0x1F, 0x6E, 0x53, 0x77,
        /* a */
        0xA9, 0xFB, 0x57, 0xDB, 0xA1, 0xEE, 0xA9, 0xBC, 0x3E, 0x66, 0x0A, 0x90,
        0x9D, 0x83, 0x8D, 0x72, 0x6E, 0x3B, 0xF6, 0x23, 0xD5, 0x26, 0x20, 0x28,
        0x20, 0x13, 0x48, 0x1D, 0x1F, 0x6E, 0x53, 0x74,
        /* b */
        0x66, 0x2C, 0x61, 0xC4, 0x30, 0xD8, 0x4E, 0xA4, 0xFE, 0x66, 0xA7, 0x73,
        0x3D, 0x0B, 0x76, 0xB7, 0xBF, 0x93, 0xEB, 0xC4, 0xAF, 0x2F, 0x49, 0x25,
        0x6A, 0xE5, 0x81, 0x01, 0xFE, 0xE9, 0x2B, 0x04,
        /* x */
        0xA3, 0xE8, 0xEB, 0x3C, 0xC1, 0xCF, 0xE7, 0xB7, 0x73, 0x22, 0x13, 0xB2,
        0x3A, 0x65, 0x61, 0x49, 0xAF, 0xA1, 0x42, 0xC4, 0x7A, 0xAF, 0xBC, 0x2B,
        0x79, 0xA1, 0x91, 0x56, 0x2E, 0x13, 0x05, 0xF4,
        /* y */
        0x2D, 0x99, 0x6C, 0x82, 0x34, 0x39, 0xC5, 0x6D, 0x7F, 0x7B, 0x22, 0xE1,
        0x46, 0x44, 0x41, 0x7E, 0x69, 0xBC, 0xB6, 0xDE, 0x39, 0xD0, 0x27, 0x00,
        0x1D, 0xAB, 0xE8, 0xF3, 0x5B, 0x25, 0xC9, 0xBE,
        /* order */
        0xA9, 0xFB, 0x57, 0xDB, 0xA1, 0xEE, 0xA9, 0xBC, 0x3E, 0x66, 0x0A, 0x90,
        0x9D, 0x83, 0x8D, 0x71, 0x8C, 0x39, 0x7A, 0xA3, 0xB5, 0x61, 0xA6, 0xF7,
        0x90, 0x1E, 0x0E, 0x82, 0x97, 0x48, 0x56, 0xA7
    }
};

static const struct {
    EC_CURVE_DATA h;
    unsigned char data[0 + 40 * 6];
} _EC_brainpoolP320r1 = {
    {
        NID_X9_62_prime_field, 0, 40, 1
    },
    {
        /* no seed */
        /* p */
        0xD3, 0x5E, 0x47, 0x20, 0x36, 0xBC, 0x4F, 0xB7, 0xE1, 0x3C, 0x78, 0x5E,
        0xD2, 0x01, 0xE0, 0x65, 0xF9, 0x8F, 0xCF, 0xA6, 0xF6, 0xF4, 0x0D, 0xEF,
        0x4F, 0x92, 0xB9, 0xEC, 0x78, 0x93, 0xEC, 0x28, 0xFC, 0xD4, 0x12, 0xB1,
        0xF1, 0xB3, 0x2E, 0x27,
        /* a */
        0x3E, 0xE3, 0x0B, 0x56, 0x8F, 0xBA, 0xB0, 0xF8, 0x83, 0xCC, 0xEB, 0xD4,
        0x6D, 0x3F, 0x3B, 0xB8, 0xA2, 0xA7, 0x35, 0x13, 0xF5, 0xEB, 0x79, 0xDA,
        0x66, 0x19, 0x0E, 0xB0, 0x85, 0xFF, 0xA9, 0xF4, 0x92, 0xF3, 0x75, 0xA9,
        0x7D, 0x86, 0x0E, 0xB4,
        /* b */
        0x52, 0x08, 0x83, 0x94, 0x9D, 0xFD, 0xBC, 0x42, 0xD3, 0xAD, 0x19, 0x86,
        0x40, 0x68, 0x8A, 0x6F, 0xE1, 0x3F, 0x41, 0x34, 0x95, 0x54, 0xB4, 0x9A,
        0xCC, 0x31, 0xDC, 0xCD, 0x88, 0x45, 0x39, 0x81, 0x6F, 0x5E, 0xB4, 0xAC,
        0x8F, 0xB1, 0xF1, 0xA6,
        /* x */
        0x43, 0xBD, 0x7E, 0x9A, 0xFB, 0x53, 0xD8, 0xB8, 0x52, 0x89, 0xBC, 0xC4,
        0x8E, 0xE5, 0xBF, 0xE6, 0xF2, 0x01, 0x37, 0xD1, 0x0A, 0x08, 0x7E, 0xB6,
        0xE7, 0x87, 0x1E, 0x2A, 0x10, 0xA5, 0x99, 0xC7, 0x10, 0xAF, 0x8D, 0x0D,
        0x39, 0xE2, 0x06, 0x11,
        /* y */
        0x14, 0xFD, 0xD0, 0x55, 0x45, 0xEC, 0x1C, 0xC8, 0xAB, 0x40, 0x93, 0x24,
        0x7F, 0x77, 0x27, 0x5E, 0x07, 0x43, 0xFF, 0xED, 0x11, 0x71, 0x82, 0xEA,
        0xA9, 0xC7, 0x78, 0x77, 0xAA, 0xAC, 0x6A, 0xC7, 0xD3, 0x52, 0x45, 0xD1,
        0x69, 0x2E, 0x8E, 0xE1,
        /* order */
        0xD3, 0x5E, 0x47, 0x20, 0x36, 0xBC, 0x4F, 0xB7, 0xE1, 0x3C, 0x78, 0x5E,
        0xD2, 0x01, 0xE0, 0x65, 0xF9, 0x8F, 0xCF, 0xA5, 0xB6, 0x8F, 0x12, 0xA3,
        0x2D, 0x48, 0x2E, 0xC7, 0xEE, 0x86, 0x58, 0xE9, 0x86, 0x91, 0x55, 0x5B,
        0x44, 0xC5, 0x93, 0x11
    }
};

static const struct {
    EC_CURVE_DATA h;
    unsigned char data[0 + 40 * 6];
} _EC_brainpoolP320t1 = {
    {
        NID_X9_62_prime_field, 0, 40, 1
    },
    {
        /* no seed */
        /* p */
        0xD3, 0x5E, 0x47, 0x20, 0x36, 0xBC, 0x4F, 0xB7, 0xE1, 0x3C, 0x78, 0x5E,
        0xD2, 0x01, 0xE0, 0x65, 0xF9, 0x8F, 0xCF, 0xA6, 0xF6, 0xF4, 0x0D, 0xEF,
        0x4F, 0x92, 0xB9, 0xEC, 0x78, 0x93, 0xEC, 0x28, 0xFC, 0xD4, 0x12, 0xB1,
        0xF1, 0xB3, 0x2E, 0x27,
        /* a */
        0xD3, 0x5E, 0x47, 0x20, 0x36, 0xBC, 0x4F, 0xB7, 0xE1, 0x3C, 0x78, 0x5E,
        0xD2, 0x01, 0xE0, 0x65, 0xF9, 0x8F, 0xCF, 0xA6, 0xF6, 0xF4, 0x0D, 0xEF,
        0x4F, 0x92, 0xB9, 0xEC, 0x78, 0x93, 0xEC, 0x28, 0xFC, 0xD4, 0x12, 0xB1,
        0xF1, 0xB3, 0x2E, 0x24,
        /* b */
        0xA7, 0xF5, 0x61, 0xE0, 0x38, 0xEB, 0x1E, 0xD5, 0x60, 0xB3, 0xD1, 0x47,
        0xDB, 0x78, 0x20, 0x13, 0x06, 0x4C, 0x19, 0xF2, 0x7E, 0xD2, 0x7C, 0x67,
        0x80, 0xAA, 0xF7, 0x7F, 0xB8, 0xA5, 0x47, 0xCE, 0xB5, 0xB4, 0xFE, 0xF4,
        0x22, 0x34, 0x03, 0x53,
        /* x */
        0x92, 0x5B, 0xE9, 0xFB, 0x01, 0xAF, 0xC6, 0xFB, 0x4D, 0x3E, 0x7D, 0x49,
        0x90, 0x01, 0x0F, 0x81, 0x34, 0x08, 0xAB, 0x10, 0x6C, 0x4F, 0x09, 0xCB,
        0x7E, 0xE0, 0x78, 0x68, 0xCC, 0x13, 0x6F, 0xFF, 0x33, 0x57, 0xF6, 0x24,
        0xA2, 0x1B, 0xED, 0x52,
        /* y */
        0x63, 0xBA, 0x3A, 0x7A, 0x27, 0x48, 0x3E, 0xBF, 0x66, 0x71, 0xDB, 0xEF,
        0x7A, 0xBB, 0x30, 0xEB, 0xEE, 0x08, 0x4E, 0x58, 0xA0, 0xB0, 0x77, 0xAD,
        0x42, 0xA5, 0xA0, 0x98, 0x9D, 0x1E, 0xE7, 0x1B, 0x1B, 0x9B, 0xC0, 0x45,
        0x5F, 0xB0, 0xD2, 0xC3,
        /* order */
        0xD3, 0x5E, 0x47, 0x20, 0x36, 0xBC, 0x4F, 0xB7, 0xE1, 0x3C, 0x78, 0x5E,
        0xD2, 0x01, 0xE0, 0x65, 0xF9, 0x8F, 0xCF, 0xA5, 0xB6, 0x8F, 0x12, 0xA3,
        0x2D, 0x48, 0x2E, 0xC7, 0xEE, 0x86, 0x58, 0xE9, 0x86, 0x91, 0x55, 0x5B,
        0x44, 0xC5, 0x93, 0x11
    }
};

static const struct {
    EC_CURVE_DATA h;
    unsigned char data[0 + 48 * 6];
} _EC_brainpoolP384r1 = {
    {
        NID_X9_62_prime_field, 0, 48, 1
    },
    {
        /* no seed */
        /* p */
        0x8C, 0xB9, 0x1E, 0x82, 0xA3, 0x38, 0x6D, 0x28, 0x0F, 0x5D, 0x6F, 0x7E,
        0x50, 0xE6, 0x41, 0xDF, 0x15, 0x2F, 0x71, 0x09, 0xED, 0x54, 0x56, 0xB4,
        0x12, 0xB1, 0xDA, 0x19, 0x7F, 0xB7, 0x11, 0x23, 0xAC, 0xD3, 0xA7, 0x29,
        0x90, 0x1D, 0x1A, 0x71, 0x87, 0x47, 0x00, 0x13, 0x31, 0x07, 0xEC, 0x53,
        /* a */
        0x7B, 0xC3, 0x82, 0xC6, 0x3D, 0x8C, 0x15, 0x0C, 0x3C, 0x72, 0x08, 0x0A,
        0xCE, 0x05, 0xAF, 0xA0, 0xC2, 0xBE, 0xA2, 0x8E, 0x4F, 0xB2, 0x27, 0x87,
        0x13, 0x91, 0x65, 0xEF, 0xBA, 0x91, 0xF9, 0x0F, 0x8A, 0xA5, 0x81, 0x4A,
        0x50, 0x3A, 0xD4, 0xEB, 0x04, 0xA8, 0xC7, 0xDD, 0x22, 0xCE, 0x28, 0x26,
        /* b */
        0x04, 0xA8, 0xC7, 0xDD, 0x22, 0xCE, 0x28, 0x26, 0x8B, 0x39, 0xB5, 0x54,
        0x16, 0xF0, 0x44, 0x7C, 0x2F, 0xB7, 0x7D, 0xE1, 0x07, 0xDC, 0xD2, 0xA6,
        0x2E, 0x88, 0x0E, 0xA5, 0x3E, 0xEB, 0x62, 0xD5, 0x7C, 0xB4, 0x39, 0x02,
        0x95, 0xDB, 0xC9, 0x94, 0x3A, 0xB7, 0x86, 0x96, 0xFA, 0x50, 0x4C, 0x11,
        /* x */
        0x1D, 0x1C, 0x64, 0xF0, 0x68, 0xCF, 0x45, 0xFF, 0xA2, 0xA6, 0x3A, 0x81,
        0xB7, 0xC1, 0x3F, 0x6B, 0x88, 0x47, 0xA3, 0xE7, 0x7E, 0xF1, 0x4F, 0xE3,
        0xDB, 0x7F, 0xCA, 0xFE, 0x0C, 0xBD, 0x10, 0xE8, 0xE8, 0x26, 0xE0, 0x34,
        0x36, 0xD6, 0x46, 0xAA, 0xEF, 0x87, 0xB2, 0xE2, 0x47, 0xD4, 0xAF, 0x1E,
        /* y */
        0x8A, 0xBE, 0x1D, 0x75, 0x20, 0xF9, 0xC2, 0xA4, 0x5C, 0xB1, 0xEB, 0x8E,
        0x95, 0xCF, 0xD5, 0x52, 0x62, 0xB7, 0x0B, 0x29, 0xFE, 0xEC, 0x58, 0x64,
        0xE1, 0x9C, 0x05, 0x4F, 0xF9, 0x91, 0x29, 0x28, 0x0E, 0x46, 0x46, 0x21,
        0x77, 0x91, 0x81, 0x11, 0x42, 0x82, 0x03, 0x41, 0x26, 0x3C, 0x53, 0x15,
        /* order */
        0x8C, 0xB9, 0x1E, 0x82, 0xA3, 0x38, 0x6D, 0x28, 0x0F, 0x5D, 0x6F, 0x7E,
        0x50, 0xE6, 0x41, 0xDF, 0x15, 0x2F, 0x71, 0x09, 0xED, 0x54, 0x56, 0xB3,
        0x1F, 0x16, 0x6E, 0x6C, 0xAC, 0x04, 0x25, 0xA7, 0xCF, 0x3A, 0xB6, 0xAF,
        0x6B, 0x7F, 0xC3, 0x10, 0x3B, 0x88, 0x32, 0x02, 0xE9, 0x04, 0x65, 0x65
    }
};

static const struct {
    EC_CURVE_DATA h;
    unsigned char data[0 + 48 * 6];
} _EC_brainpoolP384t1 = {
    {
        NID_X9_62_prime_field, 0, 48, 1
    },
    {
        /* no seed */
        /* p */
        0x8C, 0xB9, 0x1E, 0x82, 0xA3, 0x38, 0x6D, 0x28, 0x0F, 0x5D, 0x6F, 0x7E,
        0x50, 0xE6, 0x41, 0xDF, 0x15, 0x2F, 0x71, 0x09, 0xED, 0x54, 0x56, 0xB4,
        0x12, 0xB1, 0xDA, 0x19, 0x7F, 0xB7, 0x11, 0x23, 0xAC, 0xD3, 0xA7, 0x29,
        0x90, 0x1D, 0x1A, 0x71, 0x87, 0x47, 0x00, 0x13, 0x31, 0x07, 0xEC, 0x53,
        /* a */
        0x8C, 0xB9, 0x1E, 0x82, 0xA3, 0x38, 0x6D, 0x28, 0x0F, 0x5D, 0x6F, 0x7E,
        0x50, 0xE6, 0x41, 0xDF, 0x15, 0x2F, 0x71, 0x09, 0xED, 0x54, 0x56, 0xB4,
        0x12, 0xB1, 0xDA, 0x19, 0x7F, 0xB7, 0x11, 0x23, 0xAC, 0xD3, 0xA7, 0x29,
        0x90, 0x1D, 0x1A, 0x71, 0x87, 0x47, 0x00, 0x13, 0x31, 0x07, 0xEC, 0x50,
        /* b */
        0x7F, 0x51, 0x9E, 0xAD, 0xA7, 0xBD, 0xA8, 0x1B, 0xD8, 0x26, 0xDB, 0xA6,
        0x47, 0x91, 0x0F, 0x8C, 0x4B, 0x93, 0x46, 0xED, 0x8C, 0xCD, 0xC6, 0x4E,
        0x4B, 0x1A, 0xBD, 0x11, 0x75, 0x6D, 0xCE, 0x1D, 0x20, 0x74, 0xAA, 0x26,
        0x3B, 0x88, 0x80, 0x5C, 0xED, 0x70, 0x35, 0x5A, 0x33, 0xB4, 0x71, 0xEE,
        /* x */
        0x18, 0xDE, 0x98, 0xB0, 0x2D, 0xB9, 0xA3, 0x06, 0xF2, 0xAF, 0xCD, 0x72,
        0x35, 0xF7, 0x2A, 0x81, 0x9B, 0x80, 0xAB, 0x12, 0xEB, 0xD6, 0x53, 0x17,
        0x24, 0x76, 0xFE, 0xCD, 0x46, 0x2A, 0xAB, 0xFF, 0xC4, 0xFF, 0x19, 0x1B,
        0x94, 0x6A, 0x5F, 0x54, 0xD8, 0xD0, 0xAA, 0x2F, 0x41, 0x88, 0x08, 0xCC,
        /* y */
        0x25, 0xAB, 0x05, 0x69, 0x62, 0xD3, 0x06, 0x51, 0xA1, 0x14, 0xAF, 0xD2,
        0x75, 0x5A, 0xD3, 0x36, 0x74, 0x7F, 0x93, 0x47, 0x5B, 0x7A, 0x1F, 0xCA,
        0x3B, 0x88, 0xF2, 0xB6, 0xA2, 0x08, 0xCC, 0xFE, 0x46, 0x94, 0x08, 0x58,
        0x4D, 0xC2, 0xB2, 0x91, 0x26, 0x75, 0xBF, 0x5B, 0x9E, 0x58, 0x29, 0x28,
        /* order */
        0x8C, 0xB9, 0x1E, 0x82, 0xA3, 0x38, 0x6D, 0x28, 0x0F, 0x5D, 0x6F, 0x7E,
        0x50, 0xE6, 0x41, 0xDF, 0x15, 0x2F, 0x71, 0x09, 0xED, 0x54, 0x56, 0xB3,
        0x1F, 0x16, 0x6E, 0x6C, 0xAC, 0x04, 0x25, 0xA7, 0xCF, 0x3A, 0xB6, 0xAF,
        0x6B, 0x7F, 0xC3, 0x10, 0x3B, 0x88, 0x32, 0x02, 0xE9, 0x04, 0x65, 0x65
    }
};

static const struct {
    EC_CURVE_DATA h;
    unsigned char data[0 + 64 * 6];
} _EC_brainpoolP512r1 = {
    {
        NID_X9_62_prime_field, 0, 64, 1
    },
    {
        /* no seed */
        /* p */
        0xAA, 0xDD, 0x9D, 0xB8, 0xDB, 0xE9, 0xC4, 0x8B, 0x3F, 0xD4, 0xE6, 0xAE,
        0x33, 0xC9, 0xFC, 0x07, 0xCB, 0x30, 0x8D, 0xB3, 0xB3, 0xC9, 0xD2, 0x0E,
        0xD6, 0x63, 0x9C, 0xCA, 0x70, 0x33, 0x08, 0x71, 0x7D, 0x4D, 0x9B, 0x00,
        0x9B, 0xC6, 0x68, 0x42, 0xAE, 0xCD, 0xA1, 0x2A, 0xE6, 0xA3, 0x80, 0xE6,
        0x28, 0x81, 0xFF, 0x2F, 0x2D, 0x82, 0xC6, 0x85, 0x28, 0xAA, 0x60, 0x56,
        0x58, 0x3A, 0x48, 0xF3,
        /* a */
        0x78, 0x30, 0xA3, 0x31, 0x8B, 0x60, 0x3B, 0x89, 0xE2, 0x32, 0x71, 0x45,
        0xAC, 0x23, 0x4C, 0xC5, 0x94, 0xCB, 0xDD, 0x8D, 0x3D, 0xF9, 0x16, 0x10,
        0xA8, 0x34, 0x41, 0xCA, 0xEA, 0x98, 0x63, 0xBC, 0x2D, 0xED, 0x5D, 0x5A,
        0xA8, 0x25, 0x3A, 0xA1, 0x0A, 0x2E, 0xF1, 0xC9, 0x8B, 0x9A, 0xC8, 0xB5,
        0x7F, 0x11, 0x17, 0xA7, 0x2B, 0xF2, 0xC7, 0xB9, 0xE7, 0xC1, 0xAC, 0x4D,
        0x77, 0xFC, 0x94, 0xCA,
        /* b */
        0x3D, 0xF9, 0x16, 0x10, 0xA8, 0x34, 0x41, 0xCA, 0xEA, 0x98, 0x63, 0xBC,
        0x2D, 0xED, 0x5D, 0x5A, 0xA8, 0x25, 0x3A, 0xA1, 0x0A, 0x2E, 0xF1, 0xC9,
        0x8B, 0x9A, 0xC8, 0xB5, 0x7F, 0x11, 0x17, 0xA7, 0x2B, 0xF2, 0xC7, 0xB9,
        0xE7, 0xC1, 0xAC, 0x4D, 0x77, 0xFC, 0x94, 0xCA, 0xDC, 0x08, 0x3E, 0x67,
        0x98, 0x40, 0x50, 0xB7, 0x5E, 0xBA, 0xE5, 0xDD, 0x28, 0x09, 0xBD, 0x63,
        0x80, 0x16, 0xF7, 0x23,
        /* x */
        0x81, 0xAE, 0xE4, 0xBD, 0xD8, 0x2E, 0xD9, 0x64, 0x5A, 0x21, 0x32, 0x2E,
        0x9C, 0x4C, 0x6A, 0x93, 0x85, 0xED, 0x9F, 0x70, 0xB5, 0xD9, 0x16, 0xC1,
        0xB4, 0x3B, 0x62, 0xEE, 0xF4, 0xD0, 0x09, 0x8E, 0xFF, 0x3B, 0x1F, 0x78,
        0xE2, 0xD0, 0xD4, 0x8D, 0x50, 0xD1, 0x68, 0x7B, 0x93, 0xB9, 0x7D, 0x5F,
        0x7C, 0x6D, 0x50, 0x47, 0x40, 0x6A, 0x5E, 0x68, 0x8B, 0x35, 0x22, 0x09,
        0xBC, 0xB9, 0xF8, 0x22,
        /* y */
        0x7D, 0xDE, 0x38, 0x5D, 0x56, 0x63, 0x32, 0xEC, 0xC0, 0xEA, 0xBF, 0xA9,
        0xCF, 0x78, 0x22, 0xFD, 0xF2, 0x09, 0xF7, 0x00, 0x24, 0xA5, 0x7B, 0x1A,
        0xA0, 0x00, 0xC5, 0x5B, 0x88, 0x1F, 0x81, 0x11, 0xB2, 0xDC, 0xDE, 0x49,
        0x4A, 0x5F, 0x48, 0x5E, 0x5B, 0xCA, 0x4B, 0xD8, 0x8A, 0x27, 0x63, 0xAE,
        0xD1, 0xCA, 0x2B, 0x2F, 0xA8, 0xF0, 0x54, 0x06, 0x78, 0xCD, 0x1E, 0x0F,
        0x3A, 0xD8, 0x08, 0x92,
        /* order */
        0xAA, 0xDD, 0x9D, 0xB8, 0xDB, 0xE9, 0xC4, 0x8B, 0x3F, 0xD4, 0xE6, 0xAE,
        0x33, 0xC9, 0xFC, 0x07, 0xCB, 0x30, 0x8D, 0xB3, 0xB3, 0xC9, 0xD2, 0x0E,
        0xD6, 0x63, 0x9C, 0xCA, 0x70, 0x33, 0x08, 0x70, 0x55, 0x3E, 0x5C, 0x41,
        0x4C, 0xA9, 0x26, 0x19, 0x41, 0x86, 0x61, 0x19, 0x7F, 0xAC, 0x10, 0x47,
        0x1D, 0xB1, 0xD3, 0x81, 0x08, 0x5D, 0xDA, 0xDD, 0xB5, 0x87, 0x96, 0x82,
        0x9C, 0xA9, 0x00, 0x69
    }
};

static const struct {
    EC_CURVE_DATA h;
    unsigned char data[0 + 64 * 6];
} _EC_brainpoolP512t1 = {
    {
        NID_X9_62_prime_field, 0, 64, 1
    },
    {
        /* no seed */
        /* p */
        0xAA, 0xDD, 0x9D, 0xB8, 0xDB, 0xE9, 0xC4, 0x8B, 0x3F, 0xD4, 0xE6, 0xAE,
        0x33, 0xC9, 0xFC, 0x07, 0xCB, 0x30, 0x8D, 0xB3, 0xB3, 0xC9, 0xD2, 0x0E,
        0xD6, 0x63, 0x9C, 0xCA, 0x70, 0x33, 0x08, 0x71, 0x7D, 0x4D, 0x9B, 0x00,
        0x9B, 0xC6, 0x68, 0x42, 0xAE, 0xCD, 0xA1, 0x2A, 0xE6, 0xA3, 0x80, 0xE6,
        0x28, 0x81, 0xFF, 0x2F, 0x2D, 0x82, 0xC6, 0x85, 0x28, 0xAA, 0x60, 0x56,
        0x58, 0x3A, 0x48, 0xF3,
        /* a */
        0xAA, 0xDD, 0x9D, 0xB8, 0xDB, 0xE9, 0xC4, 0x8B, 0x3F, 0xD4, 0xE6, 0xAE,
        0x33, 0xC9, 0xFC, 0x07, 0xCB, 0x30, 0x8D, 0xB3, 0xB3, 0xC9, 0xD2, 0x0E,
        0xD6, 0x63, 0x9C, 0xCA, 0x70, 0x33, 0x08, 0x71, 0x7D, 0x4D, 0x9B, 0x00,
        0x9B, 0xC6, 0x68, 0x42, 0xAE, 0xCD, 0xA1, 0x2A, 0xE6, 0xA3, 0x80, 0xE6,
        0x28, 0x81, 0xFF, 0x2F, 0x2D, 0x82, 0xC6, 0x85, 0x28, 0xAA, 0x60, 0x56,
        0x58, 0x3A, 0x48, 0xF0,
        /* b */
        0x7C, 0xBB, 0xBC, 0xF9, 0x44, 0x1C, 0xFA, 0xB7, 0x6E, 0x18, 0x90, 0xE4,
        0x68, 0x84, 0xEA, 0xE3, 0x21, 0xF7, 0x0C, 0x0B, 0xCB, 0x49, 0x81, 0x52,
        0x78, 0x97, 0x50, 0x4B, 0xEC, 0x3E, 0x36, 0xA6, 0x2B, 0xCD, 0xFA, 0x23,
        0x04, 0x97, 0x65, 0x40, 0xF6, 0x45, 0x00, 0x85, 0xF2, 0xDA, 0xE1, 0x45,
        0xC2, 0x25, 0x53, 0xB4, 0x65, 0x76, 0x36, 0x89, 0x18, 0x0E, 0xA2, 0x57,
        0x18, 0x67, 0x42, 0x3E,
        /* x */
        0x64, 0x0E, 0xCE, 0x5C, 0x12, 0x78, 0x87, 0x17, 0xB9, 0xC1, 0xBA, 0x06,
        0xCB, 0xC2, 0xA6, 0xFE, 0xBA, 0x85, 0x84, 0x24, 0x58, 0xC5, 0x6D, 0xDE,
        0x9D, 0xB1, 0x75, 0x8D, 0x39, 0xC0, 0x31, 0x3D, 0x82, 0xBA, 0x51, 0x73,
        0x5C, 0xDB, 0x3E, 0xA4, 0x99, 0xAA, 0x77, 0xA7, 0xD6, 0x94, 0x3A, 0x64,
        0xF7, 0xA3, 0xF2, 0x5F, 0xE2, 0x6F, 0x06, 0xB5, 0x1B, 0xAA, 0x26, 0x96,
        0xFA, 0x90, 0x35, 0xDA,
        /* y */
        0x5B, 0x53, 0x4B, 0xD5, 0x95, 0xF5, 0xAF, 0x0F, 0xA2, 0xC8, 0x92, 0x37,
        0x6C, 0x84, 0xAC, 0xE1, 0xBB, 0x4E, 0x30, 0x19, 0xB7, 0x16, 0x34, 0xC0,
        0x11, 0x31, 0x15, 0x9C, 0xAE, 0x03, 0xCE, 0xE9, 0xD9, 0x93, 0x21, 0x84,
        0xBE, 0xEF, 0x21, 0x6B, 0xD7, 0x1D, 0xF2, 0xDA, 0xDF, 0x86, 0xA6, 0x27,
        0x30, 0x6E, 0xCF, 0xF9, 0x6D, 0xBB, 0x8B, 0xAC, 0xE1, 0x98, 0xB6, 0x1E,
        0x00, 0xF8, 0xB3, 0x32,
        /* order */
        0xAA, 0xDD, 0x9D, 0xB8, 0xDB, 0xE9, 0xC4, 0x8B, 0x3F, 0xD4, 0xE6, 0xAE,
        0x33, 0xC9, 0xFC, 0x07, 0xCB, 0x30, 0x8D, 0xB3, 0xB3, 0xC9, 0xD2, 0x0E,
        0xD6, 0x63, 0x9C, 0xCA, 0x70, 0x33, 0x08, 0x70, 0x55, 0x3E, 0x5C, 0x41,
        0x4C, 0xA9, 0x26, 0x19, 0x41, 0x86, 0x61, 0x19, 0x7F, 0xAC, 0x10, 0x47,
        0x1D, 0xB1, 0xD3, 0x81, 0x08, 0x5D, 0xDA, 0xDD, 0xB5, 0x87, 0x96, 0x82,
        0x9C, 0xA9, 0x00, 0x69
    }
};

typedef struct _ec_list_element_st {
    int nid;
    const EC_CURVE_DATA *data;
    const EC_METHOD *(*meth) (void);
    const char *comment;
} ec_list_element;

static const ec_list_element curve_list[] = {
    /* prime field curves */
    /* secg curves */
    {NID_secp112r1, &_EC_SECG_PRIME_112R1.h, 0,
     "SECG/WTLS curve over a 112 bit prime field"},
    {NID_secp112r2, &_EC_SECG_PRIME_112R2.h, 0,
     "SECG curve over a 112 bit prime field"},
    {NID_secp128r1, &_EC_SECG_PRIME_128R1.h, 0,
     "SECG curve over a 128 bit prime field"},
    {NID_secp128r2, &_EC_SECG_PRIME_128R2.h, 0,
     "SECG curve over a 128 bit prime field"},
    {NID_secp160k1, &_EC_SECG_PRIME_160K1.h, 0,
     "SECG curve over a 160 bit prime field"},
    {NID_secp160r1, &_EC_SECG_PRIME_160R1.h, 0,
     "SECG curve over a 160 bit prime field"},
    {NID_secp160r2, &_EC_SECG_PRIME_160R2.h, 0,
     "SECG/WTLS curve over a 160 bit prime field"},
    /* SECG secp192r1 is the same as X9.62 prime192v1 and hence omitted */
    {NID_secp192k1, &_EC_SECG_PRIME_192K1.h, 0,
     "SECG curve over a 192 bit prime field"},
    {NID_secp224k1, &_EC_SECG_PRIME_224K1.h, 0,
     "SECG curve over a 224 bit prime field"},
#ifndef OPENSSL_NO_EC_NISTP_64_GCC_128
    {NID_secp224r1, &_EC_NIST_PRIME_224.h, EC_GFp_nistp224_method,
     "NIST/SECG curve over a 224 bit prime field"},
#else
    {NID_secp224r1, &_EC_NIST_PRIME_224.h, 0,
     "NIST/SECG curve over a 224 bit prime field"},
#endif
    {NID_secp256k1, &_EC_SECG_PRIME_256K1.h, 0,
     "SECG curve over a 256 bit prime field"},
    /* SECG secp256r1 is the same as X9.62 prime256v1 and hence omitted */
    {NID_secp384r1, &_EC_NIST_PRIME_384.h, 0,
     "NIST/SECG curve over a 384 bit prime field"},
#ifndef OPENSSL_NO_EC_NISTP_64_GCC_128
    {NID_secp521r1, &_EC_NIST_PRIME_521.h, EC_GFp_nistp521_method,
     "NIST/SECG curve over a 521 bit prime field"},
#else
    {NID_secp521r1, &_EC_NIST_PRIME_521.h, 0,
     "NIST/SECG curve over a 521 bit prime field"},
#endif
    /* X9.62 curves */
    {NID_X9_62_prime192v1, &_EC_NIST_PRIME_192.h, 0,
     "NIST/X9.62/SECG curve over a 192 bit prime field"},
    {NID_X9_62_prime192v2, &_EC_X9_62_PRIME_192V2.h, 0,
     "X9.62 curve over a 192 bit prime field"},
    {NID_X9_62_prime192v3, &_EC_X9_62_PRIME_192V3.h, 0,
     "X9.62 curve over a 192 bit prime field"},
    {NID_X9_62_prime239v1, &_EC_X9_62_PRIME_239V1.h, 0,
     "X9.62 curve over a 239 bit prime field"},
    {NID_X9_62_prime239v2, &_EC_X9_62_PRIME_239V2.h, 0,
     "X9.62 curve over a 239 bit prime field"},
    {NID_X9_62_prime239v3, &_EC_X9_62_PRIME_239V3.h, 0,
     "X9.62 curve over a 239 bit prime field"},
    {NID_X9_62_prime256v1, &_EC_X9_62_PRIME_256V1.h,
#if defined(ECP_NISTZ256_ASM)
     EC_GFp_nistz256_method,
#elif !defined(OPENSSL_NO_EC_NISTP_64_GCC_128)
     EC_GFp_nistp256_method,
#else
     0,
#endif
     "X9.62/SECG curve over a 256 bit prime field"},
#ifndef OPENSSL_NO_EC2M
    /* characteristic two field curves */
    /* NIST/SECG curves */
    {NID_sect113r1, &_EC_SECG_CHAR2_113R1.h, 0,
     "SECG curve over a 113 bit binary field"},
    {NID_sect113r2, &_EC_SECG_CHAR2_113R2.h, 0,
     "SECG curve over a 113 bit binary field"},
    {NID_sect131r1, &_EC_SECG_CHAR2_131R1.h, 0,
     "SECG/WTLS curve over a 131 bit binary field"},
    {NID_sect131r2, &_EC_SECG_CHAR2_131R2.h, 0,
     "SECG curve over a 131 bit binary field"},
    {NID_sect163k1, &_EC_NIST_CHAR2_163K.h, 0,
     "NIST/SECG/WTLS curve over a 163 bit binary field"},
    {NID_sect163r1, &_EC_SECG_CHAR2_163R1.h, 0,
     "SECG curve over a 163 bit binary field"},
    {NID_sect163r2, &_EC_NIST_CHAR2_163B.h, 0,
     "NIST/SECG curve over a 163 bit binary field"},
    {NID_sect193r1, &_EC_SECG_CHAR2_193R1.h, 0,
     "SECG curve over a 193 bit binary field"},
    {NID_sect193r2, &_EC_SECG_CHAR2_193R2.h, 0,
     "SECG curve over a 193 bit binary field"},
    {NID_sect233k1, &_EC_NIST_CHAR2_233K.h, 0,
     "NIST/SECG/WTLS curve over a 233 bit binary field"},
    {NID_sect233r1, &_EC_NIST_CHAR2_233B.h, 0,
     "NIST/SECG/WTLS curve over a 233 bit binary field"},
    {NID_sect239k1, &_EC_SECG_CHAR2_239K1.h, 0,
     "SECG curve over a 239 bit binary field"},
    {NID_sect283k1, &_EC_NIST_CHAR2_283K.h, 0,
     "NIST/SECG curve over a 283 bit binary field"},
    {NID_sect283r1, &_EC_NIST_CHAR2_283B.h, 0,
     "NIST/SECG curve over a 283 bit binary field"},
    {NID_sect409k1, &_EC_NIST_CHAR2_409K.h, 0,
     "NIST/SECG curve over a 409 bit binary field"},
    {NID_sect409r1, &_EC_NIST_CHAR2_409B.h, 0,
     "NIST/SECG curve over a 409 bit binary field"},
    {NID_sect571k1, &_EC_NIST_CHAR2_571K.h, 0,
     "NIST/SECG curve over a 571 bit binary field"},
    {NID_sect571r1, &_EC_NIST_CHAR2_571B.h, 0,
     "NIST/SECG curve over a 571 bit binary field"},
    /* X9.62 curves */
    {NID_X9_62_c2pnb163v1, &_EC_X9_62_CHAR2_163V1.h, 0,
     "X9.62 curve over a 163 bit binary field"},
    {NID_X9_62_c2pnb163v2, &_EC_X9_62_CHAR2_163V2.h, 0,
     "X9.62 curve over a 163 bit binary field"},
    {NID_X9_62_c2pnb163v3, &_EC_X9_62_CHAR2_163V3.h, 0,
     "X9.62 curve over a 163 bit binary field"},
    {NID_X9_62_c2pnb176v1, &_EC_X9_62_CHAR2_176V1.h, 0,
     "X9.62 curve over a 176 bit binary field"},
    {NID_X9_62_c2tnb191v1, &_EC_X9_62_CHAR2_191V1.h, 0,
     "X9.62 curve over a 191 bit binary field"},
    {NID_X9_62_c2tnb191v2, &_EC_X9_62_CHAR2_191V2.h, 0,
     "X9.62 curve over a 191 bit binary field"},
    {NID_X9_62_c2tnb191v3, &_EC_X9_62_CHAR2_191V3.h, 0,
     "X9.62 curve over a 191 bit binary field"},
    {NID_X9_62_c2pnb208w1, &_EC_X9_62_CHAR2_208W1.h, 0,
     "X9.62 curve over a 208 bit binary field"},
    {NID_X9_62_c2tnb239v1, &_EC_X9_62_CHAR2_239V1.h, 0,
     "X9.62 curve over a 239 bit binary field"},
    {NID_X9_62_c2tnb239v2, &_EC_X9_62_CHAR2_239V2.h, 0,
     "X9.62 curve over a 239 bit binary field"},
    {NID_X9_62_c2tnb239v3, &_EC_X9_62_CHAR2_239V3.h, 0,
     "X9.62 curve over a 239 bit binary field"},
    {NID_X9_62_c2pnb272w1, &_EC_X9_62_CHAR2_272W1.h, 0,
     "X9.62 curve over a 272 bit binary field"},
    {NID_X9_62_c2pnb304w1, &_EC_X9_62_CHAR2_304W1.h, 0,
     "X9.62 curve over a 304 bit binary field"},
    {NID_X9_62_c2tnb359v1, &_EC_X9_62_CHAR2_359V1.h, 0,
     "X9.62 curve over a 359 bit binary field"},
    {NID_X9_62_c2pnb368w1, &_EC_X9_62_CHAR2_368W1.h, 0,
     "X9.62 curve over a 368 bit binary field"},
    {NID_X9_62_c2tnb431r1, &_EC_X9_62_CHAR2_431R1.h, 0,
     "X9.62 curve over a 431 bit binary field"},
    /*
     * the WAP/WTLS curves [unlike SECG, spec has its own OIDs for curves
     * from X9.62]
     */
    {NID_wap_wsg_idm_ecid_wtls1, &_EC_WTLS_1.h, 0,
     "WTLS curve over a 113 bit binary field"},
    {NID_wap_wsg_idm_ecid_wtls3, &_EC_NIST_CHAR2_163K.h, 0,
     "NIST/SECG/WTLS curve over a 163 bit binary field"},
    {NID_wap_wsg_idm_ecid_wtls4, &_EC_SECG_CHAR2_113R1.h, 0,
     "SECG curve over a 113 bit binary field"},
    {NID_wap_wsg_idm_ecid_wtls5, &_EC_X9_62_CHAR2_163V1.h, 0,
     "X9.62 curve over a 163 bit binary field"},
#endif
    {NID_wap_wsg_idm_ecid_wtls6, &_EC_SECG_PRIME_112R1.h, 0,
     "SECG/WTLS curve over a 112 bit prime field"},
    {NID_wap_wsg_idm_ecid_wtls7, &_EC_SECG_PRIME_160R2.h, 0,
     "SECG/WTLS curve over a 160 bit prime field"},
    {NID_wap_wsg_idm_ecid_wtls8, &_EC_WTLS_8.h, 0,
     "WTLS curve over a 112 bit prime field"},
    {NID_wap_wsg_idm_ecid_wtls9, &_EC_WTLS_9.h, 0,
     "WTLS curve over a 160 bit prime field"},
#ifndef OPENSSL_NO_EC2M
    {NID_wap_wsg_idm_ecid_wtls10, &_EC_NIST_CHAR2_233K.h, 0,
     "NIST/SECG/WTLS curve over a 233 bit binary field"},
    {NID_wap_wsg_idm_ecid_wtls11, &_EC_NIST_CHAR2_233B.h, 0,
     "NIST/SECG/WTLS curve over a 233 bit binary field"},
#endif
    {NID_wap_wsg_idm_ecid_wtls12, &_EC_WTLS_12.h, 0,
     "WTLS curvs over a 224 bit prime field"},
#ifndef OPENSSL_NO_EC2M
    /* IPSec curves */
    {NID_ipsec3, &_EC_IPSEC_155_ID3.h, 0,
     "\n\tIPSec/IKE/Oakley curve #3 over a 155 bit binary field.\n"
     "\tNot suitable for ECDSA.\n\tQuestionable extension field!"},
    {NID_ipsec4, &_EC_IPSEC_185_ID4.h, 0,
     "\n\tIPSec/IKE/Oakley curve #4 over a 185 bit binary field.\n"
     "\tNot suitable for ECDSA.\n\tQuestionable extension field!"},
#endif
    /* brainpool curves */
    {NID_brainpoolP160r1, &_EC_brainpoolP160r1.h, 0,
     "RFC 5639 curve over a 160 bit prime field"},
    {NID_brainpoolP160t1, &_EC_brainpoolP160t1.h, 0,
     "RFC 5639 curve over a 160 bit prime field"},
    {NID_brainpoolP192r1, &_EC_brainpoolP192r1.h, 0,
     "RFC 5639 curve over a 192 bit prime field"},
    {NID_brainpoolP192t1, &_EC_brainpoolP192t1.h, 0,
     "RFC 5639 curve over a 192 bit prime field"},
    {NID_brainpoolP224r1, &_EC_brainpoolP224r1.h, 0,
     "RFC 5639 curve over a 224 bit prime field"},
    {NID_brainpoolP224t1, &_EC_brainpoolP224t1.h, 0,
     "RFC 5639 curve over a 224 bit prime field"},
    {NID_brainpoolP256r1, &_EC_brainpoolP256r1.h, 0,
     "RFC 5639 curve over a 256 bit prime field"},
    {NID_brainpoolP256t1, &_EC_brainpoolP256t1.h, 0,
     "RFC 5639 curve over a 256 bit prime field"},
    {NID_brainpoolP320r1, &_EC_brainpoolP320r1.h, 0,
     "RFC 5639 curve over a 320 bit prime field"},
    {NID_brainpoolP320t1, &_EC_brainpoolP320t1.h, 0,
     "RFC 5639 curve over a 320 bit prime field"},
    {NID_brainpoolP384r1, &_EC_brainpoolP384r1.h, 0,
     "RFC 5639 curve over a 384 bit prime field"},
    {NID_brainpoolP384t1, &_EC_brainpoolP384t1.h, 0,
     "RFC 5639 curve over a 384 bit prime field"},
    {NID_brainpoolP512r1, &_EC_brainpoolP512r1.h, 0,
     "RFC 5639 curve over a 512 bit prime field"},
    {NID_brainpoolP512t1, &_EC_brainpoolP512t1.h, 0,
     "RFC 5639 curve over a 512 bit prime field"},
};

#define curve_list_length (sizeof(curve_list)/sizeof(ec_list_element))

static EC_GROUP *ec_group_new_from_data(const ec_list_element curve)
{
    EC_GROUP *group = NULL;
    EC_POINT *P = NULL;
    BN_CTX *ctx = NULL;
    BIGNUM *p = NULL, *a = NULL, *b = NULL, *x = NULL, *y = NULL, *order =
        NULL;
    int ok = 0;
    int seed_len, param_len;
    const EC_METHOD *meth;
    const EC_CURVE_DATA *data;
    const unsigned char *params;

    if ((ctx = BN_CTX_new()) == NULL) {
        ECerr(EC_F_EC_GROUP_NEW_FROM_DATA, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    data = curve.data;
    seed_len = data->seed_len;
    param_len = data->param_len;
    params = (const unsigned char *)(data + 1); /* skip header */
    params += seed_len;         /* skip seed */

    if (!(p = BN_bin2bn(params + 0 * param_len, param_len, NULL))
        || !(a = BN_bin2bn(params + 1 * param_len, param_len, NULL))
        || !(b = BN_bin2bn(params + 2 * param_len, param_len, NULL))) {
        ECerr(EC_F_EC_GROUP_NEW_FROM_DATA, ERR_R_BN_LIB);
        goto err;
    }

    if (curve.meth != 0) {
        meth = curve.meth();
        if (((group = EC_GROUP_new(meth)) == NULL) ||
            (!(group->meth->group_set_curve(group, p, a, b, ctx)))) {
            ECerr(EC_F_EC_GROUP_NEW_FROM_DATA, ERR_R_EC_LIB);
            goto err;
        }
    } else if (data->field_type == NID_X9_62_prime_field) {
        if ((group = EC_GROUP_new_curve_GFp(p, a, b, ctx)) == NULL) {
            ECerr(EC_F_EC_GROUP_NEW_FROM_DATA, ERR_R_EC_LIB);
            goto err;
        }
    }
#ifndef OPENSSL_NO_EC2M
    else {                      /* field_type ==
                                 * NID_X9_62_characteristic_two_field */

        if ((group = EC_GROUP_new_curve_GF2m(p, a, b, ctx)) == NULL) {
            ECerr(EC_F_EC_GROUP_NEW_FROM_DATA, ERR_R_EC_LIB);
            goto err;
        }
    }
#endif

    if ((P = EC_POINT_new(group)) == NULL) {
        ECerr(EC_F_EC_GROUP_NEW_FROM_DATA, ERR_R_EC_LIB);
        goto err;
    }

    if (!(x = BN_bin2bn(params + 3 * param_len, param_len, NULL))
        || !(y = BN_bin2bn(params + 4 * param_len, param_len, NULL))) {
        ECerr(EC_F_EC_GROUP_NEW_FROM_DATA, ERR_R_BN_LIB);
        goto err;
    }
    if (!EC_POINT_set_affine_coordinates_GFp(group, P, x, y, ctx)) {
        ECerr(EC_F_EC_GROUP_NEW_FROM_DATA, ERR_R_EC_LIB);
        goto err;
    }
    if (!(order = BN_bin2bn(params + 5 * param_len, param_len, NULL))
        || !BN_set_word(x, (BN_ULONG)data->cofactor)) {
        ECerr(EC_F_EC_GROUP_NEW_FROM_DATA, ERR_R_BN_LIB);
        goto err;
    }
    if (!EC_GROUP_set_generator(group, P, order, x)) {
        ECerr(EC_F_EC_GROUP_NEW_FROM_DATA, ERR_R_EC_LIB);
        goto err;
    }
    if (seed_len) {
        if (!EC_GROUP_set_seed(group, params - seed_len, seed_len)) {
            ECerr(EC_F_EC_GROUP_NEW_FROM_DATA, ERR_R_EC_LIB);
            goto err;
        }
    }
    ok = 1;
 err:
    if (!ok) {
        EC_GROUP_free(group);
        group = NULL;
    }
    if (P)
        EC_POINT_free(P);
    if (ctx)
        BN_CTX_free(ctx);
    if (p)
        BN_free(p);
    if (a)
        BN_free(a);
    if (b)
        BN_free(b);
    if (order)
        BN_free(order);
    if (x)
        BN_free(x);
    if (y)
        BN_free(y);
    return group;
}

EC_GROUP *EC_GROUP_new_by_curve_name(int nid)
{
    size_t i;
    EC_GROUP *ret = NULL;

#ifdef OPENSSL_FIPS
    if (FIPS_mode())
        return FIPS_ec_group_new_by_curve_name(nid);
#endif
    if (nid <= 0)
        return NULL;

    for (i = 0; i < curve_list_length; i++)
        if (curve_list[i].nid == nid) {
            ret = ec_group_new_from_data(curve_list[i]);
            break;
        }

    if (ret == NULL) {
        ECerr(EC_F_EC_GROUP_NEW_BY_CURVE_NAME, EC_R_UNKNOWN_GROUP);
        return NULL;
    }

    EC_GROUP_set_curve_name(ret, nid);

    return ret;
}

size_t EC_get_builtin_curves(EC_builtin_curve *r, size_t nitems)
{
    size_t i, min;

    if (r == NULL || nitems == 0)
        return curve_list_length;

    min = nitems < curve_list_length ? nitems : curve_list_length;

    for (i = 0; i < min; i++) {
        r[i].nid = curve_list[i].nid;
        r[i].comment = curve_list[i].comment;
    }

    return curve_list_length;
}

/* Functions to translate between common NIST curve names and NIDs */

typedef struct {
    const char *name;           /* NIST Name of curve */
    int nid;                    /* Curve NID */
} EC_NIST_NAME;

static EC_NIST_NAME nist_curves[] = {
    {"B-163", NID_sect163r2},
    {"B-233", NID_sect233r1},
    {"B-283", NID_sect283r1},
    {"B-409", NID_sect409r1},
    {"B-571", NID_sect571r1},
    {"K-163", NID_sect163k1},
    {"K-233", NID_sect233k1},
    {"K-283", NID_sect283k1},
    {"K-409", NID_sect409k1},
    {"K-571", NID_sect571k1},
    {"P-192", NID_X9_62_prime192v1},
    {"P-224", NID_secp224r1},
    {"P-256", NID_X9_62_prime256v1},
    {"P-384", NID_secp384r1},
    {"P-521", NID_secp521r1}
};

const char *EC_curve_nid2nist(int nid)
{
    size_t i;
    for (i = 0; i < sizeof(nist_curves) / sizeof(EC_NIST_NAME); i++) {
        if (nist_curves[i].nid == nid)
            return nist_curves[i].name;
    }
    return NULL;
}

int EC_curve_nist2nid(const char *name)
{
    size_t i;
    for (i = 0; i < sizeof(nist_curves) / sizeof(EC_NIST_NAME); i++) {
        if (!strcmp(nist_curves[i].name, name))
            return nist_curves[i].nid;
    }
    return NID_undef;
}
/* crypto/ec/ec_cvt.c */
/*
 * Originally written by Bodo Moeller for the OpenSSL project.
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
/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 *
 * Portions of the attached software ("Contribution") are developed by
 * SUN MICROSYSTEMS, INC., and are contributed to the OpenSSL project.
 *
 * The Contribution is licensed pursuant to the OpenSSL open source
 * license provided above.
 *
 * The elliptic curve binary polynomial software is originally written by
 * Sheueling Chang Shantz and Douglas Stebila of Sun Microsystems Laboratories.
 *
 */

// #include "err.h"
// #include "ec_lcl.h"

#ifdef OPENSSL_FIPS
# include <fips.h>
#endif

EC_GROUP *EC_GROUP_new_curve_GFp(const BIGNUM *p, const BIGNUM *a,
                                 const BIGNUM *b, BN_CTX *ctx)
{
    const EC_METHOD *meth;
    EC_GROUP *ret;

#ifdef OPENSSL_FIPS
    if (FIPS_mode())
        return FIPS_ec_group_new_curve_gfp(p, a, b, ctx);
#endif
#if defined(OPENSSL_BN_ASM_MONT)
    /*
     * This might appear controversial, but the fact is that generic
     * prime method was observed to deliver better performance even
     * for NIST primes on a range of platforms, e.g.: 60%-15%
     * improvement on IA-64, ~25% on ARM, 30%-90% on P4, 20%-25%
     * in 32-bit build and 35%--12% in 64-bit build on Core2...
     * Coefficients are relative to optimized bn_nist.c for most
     * intensive ECDSA verify and ECDH operations for 192- and 521-
     * bit keys respectively. Choice of these boundary values is
     * arguable, because the dependency of improvement coefficient
     * from key length is not a "monotone" curve. For example while
     * 571-bit result is 23% on ARM, 384-bit one is -1%. But it's
     * generally faster, sometimes "respectfully" faster, sometimes
     * "tolerably" slower... What effectively happens is that loop
     * with bn_mul_add_words is put against bn_mul_mont, and the
     * latter "wins" on short vectors. Correct solution should be
     * implementing dedicated NxN multiplication subroutines for
     * small N. But till it materializes, let's stick to generic
     * prime method...
     *                                              <appro>
     */
    meth = EC_GFp_mont_method();
#else
    meth = EC_GFp_nist_method();
#endif

    ret = EC_GROUP_new(meth);
    if (ret == NULL)
        return NULL;

    if (!EC_GROUP_set_curve_GFp(ret, p, a, b, ctx)) {
        unsigned long err;

        err = ERR_peek_last_error();

        if (!(ERR_GET_LIB(err) == ERR_LIB_EC &&
              ((ERR_GET_REASON(err) == EC_R_NOT_A_NIST_PRIME) ||
               (ERR_GET_REASON(err) == EC_R_NOT_A_SUPPORTED_NIST_PRIME)))) {
            /* real error */

            EC_GROUP_clear_free(ret);
            return NULL;
        }

        /*
         * not an actual error, we just cannot use EC_GFp_nist_method
         */

        ERR_clear_error();

        EC_GROUP_clear_free(ret);
        meth = EC_GFp_mont_method();

        ret = EC_GROUP_new(meth);
        if (ret == NULL)
            return NULL;

        if (!EC_GROUP_set_curve_GFp(ret, p, a, b, ctx)) {
            EC_GROUP_clear_free(ret);
            return NULL;
        }
    }

    return ret;
}

#ifndef OPENSSL_NO_EC2M
EC_GROUP *EC_GROUP_new_curve_GF2m(const BIGNUM *p, const BIGNUM *a,
                                  const BIGNUM *b, BN_CTX *ctx)
{
    const EC_METHOD *meth;
    EC_GROUP *ret;

# ifdef OPENSSL_FIPS
    if (FIPS_mode())
        return FIPS_ec_group_new_curve_gf2m(p, a, b, ctx);
# endif
    meth = EC_GF2m_simple_method();

    ret = EC_GROUP_new(meth);
    if (ret == NULL)
        return NULL;

    if (!EC_GROUP_set_curve_GF2m(ret, p, a, b, ctx)) {
        EC_GROUP_clear_free(ret);
        return NULL;
    }

    return ret;
}
#endif
/* crypto/ec/ec_err.c */
/* ====================================================================
 * Copyright (c) 1999-2015 The OpenSSL Project.  All rights reserved.
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
// #include "ec.h"

/* BEGIN ERROR CODES */
#ifndef OPENSSL_NO_ERR

# define ERR_FUNC(func) ERR_PACK(ERR_LIB_EC,func,0)
# define ERR_REASON(reason) ERR_PACK(ERR_LIB_EC,0,reason)

static ERR_STRING_DATA EC_str_functs[] = {
    {ERR_FUNC(EC_F_BN_TO_FELEM), "BN_TO_FELEM"},
    {ERR_FUNC(EC_F_COMPUTE_WNAF), "COMPUTE_WNAF"},
    {ERR_FUNC(EC_F_D2I_ECPARAMETERS), "d2i_ECParameters"},
    {ERR_FUNC(EC_F_D2I_ECPKPARAMETERS), "d2i_ECPKParameters"},
    {ERR_FUNC(EC_F_D2I_ECPRIVATEKEY), "d2i_ECPrivateKey"},
    {ERR_FUNC(EC_F_DO_EC_KEY_PRINT), "DO_EC_KEY_PRINT"},
    {ERR_FUNC(EC_F_ECDH_CMS_DECRYPT), "ECDH_CMS_DECRYPT"},
    {ERR_FUNC(EC_F_ECDH_CMS_SET_SHARED_INFO), "ECDH_CMS_SET_SHARED_INFO"},
    {ERR_FUNC(EC_F_ECKEY_PARAM2TYPE), "ECKEY_PARAM2TYPE"},
    {ERR_FUNC(EC_F_ECKEY_PARAM_DECODE), "ECKEY_PARAM_DECODE"},
    {ERR_FUNC(EC_F_ECKEY_PRIV_DECODE), "ECKEY_PRIV_DECODE"},
    {ERR_FUNC(EC_F_ECKEY_PRIV_ENCODE), "ECKEY_PRIV_ENCODE"},
    {ERR_FUNC(EC_F_ECKEY_PUB_DECODE), "ECKEY_PUB_DECODE"},
    {ERR_FUNC(EC_F_ECKEY_PUB_ENCODE), "ECKEY_PUB_ENCODE"},
    {ERR_FUNC(EC_F_ECKEY_TYPE2PARAM), "ECKEY_TYPE2PARAM"},
    {ERR_FUNC(EC_F_ECPARAMETERS_PRINT), "ECParameters_print"},
    {ERR_FUNC(EC_F_ECPARAMETERS_PRINT_FP), "ECParameters_print_fp"},
    {ERR_FUNC(EC_F_ECPKPARAMETERS_PRINT), "ECPKParameters_print"},
    {ERR_FUNC(EC_F_ECPKPARAMETERS_PRINT_FP), "ECPKParameters_print_fp"},
    {ERR_FUNC(EC_F_ECP_NISTZ256_GET_AFFINE), "ecp_nistz256_get_affine"},
    {ERR_FUNC(EC_F_ECP_NISTZ256_MULT_PRECOMPUTE),
     "ecp_nistz256_mult_precompute"},
    {ERR_FUNC(EC_F_ECP_NISTZ256_POINTS_MUL), "ecp_nistz256_points_mul"},
    {ERR_FUNC(EC_F_ECP_NISTZ256_PRE_COMP_NEW), "ecp_nistz256_pre_comp_new"},
    {ERR_FUNC(EC_F_ECP_NISTZ256_SET_WORDS), "ecp_nistz256_set_words"},
    {ERR_FUNC(EC_F_ECP_NISTZ256_WINDOWED_MUL), "ecp_nistz256_windowed_mul"},
    {ERR_FUNC(EC_F_ECP_NIST_MOD_192), "ECP_NIST_MOD_192"},
    {ERR_FUNC(EC_F_ECP_NIST_MOD_224), "ECP_NIST_MOD_224"},
    {ERR_FUNC(EC_F_ECP_NIST_MOD_256), "ECP_NIST_MOD_256"},
    {ERR_FUNC(EC_F_ECP_NIST_MOD_521), "ECP_NIST_MOD_521"},
    {ERR_FUNC(EC_F_EC_ASN1_GROUP2CURVE), "EC_ASN1_GROUP2CURVE"},
    {ERR_FUNC(EC_F_EC_ASN1_GROUP2FIELDID), "EC_ASN1_GROUP2FIELDID"},
    {ERR_FUNC(EC_F_EC_ASN1_GROUP2PARAMETERS), "EC_ASN1_GROUP2PARAMETERS"},
    {ERR_FUNC(EC_F_EC_ASN1_GROUP2PKPARAMETERS), "EC_ASN1_GROUP2PKPARAMETERS"},
    {ERR_FUNC(EC_F_EC_ASN1_PARAMETERS2GROUP), "EC_ASN1_PARAMETERS2GROUP"},
    {ERR_FUNC(EC_F_EC_ASN1_PKPARAMETERS2GROUP), "EC_ASN1_PKPARAMETERS2GROUP"},
    {ERR_FUNC(EC_F_EC_EX_DATA_SET_DATA), "EC_EX_DATA_set_data"},
    {ERR_FUNC(EC_F_EC_GF2M_MONTGOMERY_POINT_MULTIPLY),
     "EC_GF2M_MONTGOMERY_POINT_MULTIPLY"},
    {ERR_FUNC(EC_F_EC_GF2M_SIMPLE_GROUP_CHECK_DISCRIMINANT),
     "ec_GF2m_simple_group_check_discriminant"},
    {ERR_FUNC(EC_F_EC_GF2M_SIMPLE_GROUP_SET_CURVE),
     "ec_GF2m_simple_group_set_curve"},
    {ERR_FUNC(EC_F_EC_GF2M_SIMPLE_OCT2POINT), "ec_GF2m_simple_oct2point"},
    {ERR_FUNC(EC_F_EC_GF2M_SIMPLE_POINT2OCT), "ec_GF2m_simple_point2oct"},
    {ERR_FUNC(EC_F_EC_GF2M_SIMPLE_POINT_GET_AFFINE_COORDINATES),
     "ec_GF2m_simple_point_get_affine_coordinates"},
    {ERR_FUNC(EC_F_EC_GF2M_SIMPLE_POINT_SET_AFFINE_COORDINATES),
     "ec_GF2m_simple_point_set_affine_coordinates"},
    {ERR_FUNC(EC_F_EC_GF2M_SIMPLE_SET_COMPRESSED_COORDINATES),
     "ec_GF2m_simple_set_compressed_coordinates"},
    {ERR_FUNC(EC_F_EC_GFP_MONT_FIELD_DECODE), "ec_GFp_mont_field_decode"},
    {ERR_FUNC(EC_F_EC_GFP_MONT_FIELD_ENCODE), "ec_GFp_mont_field_encode"},
    {ERR_FUNC(EC_F_EC_GFP_MONT_FIELD_MUL), "ec_GFp_mont_field_mul"},
    {ERR_FUNC(EC_F_EC_GFP_MONT_FIELD_SET_TO_ONE),
     "ec_GFp_mont_field_set_to_one"},
    {ERR_FUNC(EC_F_EC_GFP_MONT_FIELD_SQR), "ec_GFp_mont_field_sqr"},
    {ERR_FUNC(EC_F_EC_GFP_MONT_GROUP_SET_CURVE),
     "ec_GFp_mont_group_set_curve"},
    {ERR_FUNC(EC_F_EC_GFP_MONT_GROUP_SET_CURVE_GFP),
     "EC_GFP_MONT_GROUP_SET_CURVE_GFP"},
    {ERR_FUNC(EC_F_EC_GFP_NISTP224_GROUP_SET_CURVE),
     "ec_GFp_nistp224_group_set_curve"},
    {ERR_FUNC(EC_F_EC_GFP_NISTP224_POINTS_MUL), "ec_GFp_nistp224_points_mul"},
    {ERR_FUNC(EC_F_EC_GFP_NISTP224_POINT_GET_AFFINE_COORDINATES),
     "ec_GFp_nistp224_point_get_affine_coordinates"},
    {ERR_FUNC(EC_F_EC_GFP_NISTP256_GROUP_SET_CURVE),
     "ec_GFp_nistp256_group_set_curve"},
    {ERR_FUNC(EC_F_EC_GFP_NISTP256_POINTS_MUL), "ec_GFp_nistp256_points_mul"},
    {ERR_FUNC(EC_F_EC_GFP_NISTP256_POINT_GET_AFFINE_COORDINATES),
     "ec_GFp_nistp256_point_get_affine_coordinates"},
    {ERR_FUNC(EC_F_EC_GFP_NISTP521_GROUP_SET_CURVE),
     "ec_GFp_nistp521_group_set_curve"},
    {ERR_FUNC(EC_F_EC_GFP_NISTP521_POINTS_MUL), "ec_GFp_nistp521_points_mul"},
    {ERR_FUNC(EC_F_EC_GFP_NISTP521_POINT_GET_AFFINE_COORDINATES),
     "ec_GFp_nistp521_point_get_affine_coordinates"},
    {ERR_FUNC(EC_F_EC_GFP_NIST_FIELD_MUL), "ec_GFp_nist_field_mul"},
    {ERR_FUNC(EC_F_EC_GFP_NIST_FIELD_SQR), "ec_GFp_nist_field_sqr"},
    {ERR_FUNC(EC_F_EC_GFP_NIST_GROUP_SET_CURVE),
     "ec_GFp_nist_group_set_curve"},
    {ERR_FUNC(EC_F_EC_GFP_SIMPLE_GROUP_CHECK_DISCRIMINANT),
     "ec_GFp_simple_group_check_discriminant"},
    {ERR_FUNC(EC_F_EC_GFP_SIMPLE_GROUP_SET_CURVE),
     "ec_GFp_simple_group_set_curve"},
    {ERR_FUNC(EC_F_EC_GFP_SIMPLE_GROUP_SET_CURVE_GFP),
     "EC_GFP_SIMPLE_GROUP_SET_CURVE_GFP"},
    {ERR_FUNC(EC_F_EC_GFP_SIMPLE_GROUP_SET_GENERATOR),
     "EC_GFP_SIMPLE_GROUP_SET_GENERATOR"},
    {ERR_FUNC(EC_F_EC_GFP_SIMPLE_MAKE_AFFINE), "ec_GFp_simple_make_affine"},
    {ERR_FUNC(EC_F_EC_GFP_SIMPLE_OCT2POINT), "ec_GFp_simple_oct2point"},
    {ERR_FUNC(EC_F_EC_GFP_SIMPLE_POINT2OCT), "ec_GFp_simple_point2oct"},
    {ERR_FUNC(EC_F_EC_GFP_SIMPLE_POINTS_MAKE_AFFINE),
     "ec_GFp_simple_points_make_affine"},
    {ERR_FUNC(EC_F_EC_GFP_SIMPLE_POINT_GET_AFFINE_COORDINATES),
     "ec_GFp_simple_point_get_affine_coordinates"},
    {ERR_FUNC(EC_F_EC_GFP_SIMPLE_POINT_GET_AFFINE_COORDINATES_GFP),
     "EC_GFP_SIMPLE_POINT_GET_AFFINE_COORDINATES_GFP"},
    {ERR_FUNC(EC_F_EC_GFP_SIMPLE_POINT_SET_AFFINE_COORDINATES),
     "ec_GFp_simple_point_set_affine_coordinates"},
    {ERR_FUNC(EC_F_EC_GFP_SIMPLE_POINT_SET_AFFINE_COORDINATES_GFP),
     "EC_GFP_SIMPLE_POINT_SET_AFFINE_COORDINATES_GFP"},
    {ERR_FUNC(EC_F_EC_GFP_SIMPLE_SET_COMPRESSED_COORDINATES),
     "ec_GFp_simple_set_compressed_coordinates"},
    {ERR_FUNC(EC_F_EC_GFP_SIMPLE_SET_COMPRESSED_COORDINATES_GFP),
     "EC_GFP_SIMPLE_SET_COMPRESSED_COORDINATES_GFP"},
    {ERR_FUNC(EC_F_EC_GROUP_CHECK), "EC_GROUP_check"},
    {ERR_FUNC(EC_F_EC_GROUP_CHECK_DISCRIMINANT),
     "EC_GROUP_check_discriminant"},
    {ERR_FUNC(EC_F_EC_GROUP_COPY), "EC_GROUP_copy"},
    {ERR_FUNC(EC_F_EC_GROUP_GET0_GENERATOR), "EC_GROUP_get0_generator"},
    {ERR_FUNC(EC_F_EC_GROUP_GET_COFACTOR), "EC_GROUP_get_cofactor"},
    {ERR_FUNC(EC_F_EC_GROUP_GET_CURVE_GF2M), "EC_GROUP_get_curve_GF2m"},
    {ERR_FUNC(EC_F_EC_GROUP_GET_CURVE_GFP), "EC_GROUP_get_curve_GFp"},
    {ERR_FUNC(EC_F_EC_GROUP_GET_DEGREE), "EC_GROUP_get_degree"},
    {ERR_FUNC(EC_F_EC_GROUP_GET_ORDER), "EC_GROUP_get_order"},
    {ERR_FUNC(EC_F_EC_GROUP_GET_PENTANOMIAL_BASIS),
     "EC_GROUP_get_pentanomial_basis"},
    {ERR_FUNC(EC_F_EC_GROUP_GET_TRINOMIAL_BASIS),
     "EC_GROUP_get_trinomial_basis"},
    {ERR_FUNC(EC_F_EC_GROUP_NEW), "EC_GROUP_new"},
    {ERR_FUNC(EC_F_EC_GROUP_NEW_BY_CURVE_NAME), "EC_GROUP_new_by_curve_name"},
    {ERR_FUNC(EC_F_EC_GROUP_NEW_FROM_DATA), "EC_GROUP_NEW_FROM_DATA"},
    {ERR_FUNC(EC_F_EC_GROUP_PRECOMPUTE_MULT), "EC_GROUP_precompute_mult"},
    {ERR_FUNC(EC_F_EC_GROUP_SET_CURVE_GF2M), "EC_GROUP_set_curve_GF2m"},
    {ERR_FUNC(EC_F_EC_GROUP_SET_CURVE_GFP), "EC_GROUP_set_curve_GFp"},
    {ERR_FUNC(EC_F_EC_GROUP_SET_EXTRA_DATA), "EC_GROUP_SET_EXTRA_DATA"},
    {ERR_FUNC(EC_F_EC_GROUP_SET_GENERATOR), "EC_GROUP_set_generator"},
    {ERR_FUNC(EC_F_EC_KEY_CHECK_KEY), "EC_KEY_check_key"},
    {ERR_FUNC(EC_F_EC_KEY_COPY), "EC_KEY_copy"},
    {ERR_FUNC(EC_F_EC_KEY_GENERATE_KEY), "EC_KEY_generate_key"},
    {ERR_FUNC(EC_F_EC_KEY_NEW), "EC_KEY_new"},
    {ERR_FUNC(EC_F_EC_KEY_PRINT), "EC_KEY_print"},
    {ERR_FUNC(EC_F_EC_KEY_PRINT_FP), "EC_KEY_print_fp"},
    {ERR_FUNC(EC_F_EC_KEY_SET_PUBLIC_KEY_AFFINE_COORDINATES),
     "EC_KEY_set_public_key_affine_coordinates"},
    {ERR_FUNC(EC_F_EC_POINTS_MAKE_AFFINE), "EC_POINTs_make_affine"},
    {ERR_FUNC(EC_F_EC_POINT_ADD), "EC_POINT_add"},
    {ERR_FUNC(EC_F_EC_POINT_CMP), "EC_POINT_cmp"},
    {ERR_FUNC(EC_F_EC_POINT_COPY), "EC_POINT_copy"},
    {ERR_FUNC(EC_F_EC_POINT_DBL), "EC_POINT_dbl"},
    {ERR_FUNC(EC_F_EC_POINT_GET_AFFINE_COORDINATES_GF2M),
     "EC_POINT_get_affine_coordinates_GF2m"},
    {ERR_FUNC(EC_F_EC_POINT_GET_AFFINE_COORDINATES_GFP),
     "EC_POINT_get_affine_coordinates_GFp"},
    {ERR_FUNC(EC_F_EC_POINT_GET_JPROJECTIVE_COORDINATES_GFP),
     "EC_POINT_get_Jprojective_coordinates_GFp"},
    {ERR_FUNC(EC_F_EC_POINT_INVERT), "EC_POINT_invert"},
    {ERR_FUNC(EC_F_EC_POINT_IS_AT_INFINITY), "EC_POINT_is_at_infinity"},
    {ERR_FUNC(EC_F_EC_POINT_IS_ON_CURVE), "EC_POINT_is_on_curve"},
    {ERR_FUNC(EC_F_EC_POINT_MAKE_AFFINE), "EC_POINT_make_affine"},
    {ERR_FUNC(EC_F_EC_POINT_MUL), "EC_POINT_mul"},
    {ERR_FUNC(EC_F_EC_POINT_NEW), "EC_POINT_new"},
    {ERR_FUNC(EC_F_EC_POINT_OCT2POINT), "EC_POINT_oct2point"},
    {ERR_FUNC(EC_F_EC_POINT_POINT2OCT), "EC_POINT_point2oct"},
    {ERR_FUNC(EC_F_EC_POINT_SET_AFFINE_COORDINATES_GF2M),
     "EC_POINT_set_affine_coordinates_GF2m"},
    {ERR_FUNC(EC_F_EC_POINT_SET_AFFINE_COORDINATES_GFP),
     "EC_POINT_set_affine_coordinates_GFp"},
    {ERR_FUNC(EC_F_EC_POINT_SET_COMPRESSED_COORDINATES_GF2M),
     "EC_POINT_set_compressed_coordinates_GF2m"},
    {ERR_FUNC(EC_F_EC_POINT_SET_COMPRESSED_COORDINATES_GFP),
     "EC_POINT_set_compressed_coordinates_GFp"},
    {ERR_FUNC(EC_F_EC_POINT_SET_JPROJECTIVE_COORDINATES_GFP),
     "EC_POINT_set_Jprojective_coordinates_GFp"},
    {ERR_FUNC(EC_F_EC_POINT_SET_TO_INFINITY), "EC_POINT_set_to_infinity"},
    {ERR_FUNC(EC_F_EC_PRE_COMP_DUP), "EC_PRE_COMP_DUP"},
    {ERR_FUNC(EC_F_EC_PRE_COMP_NEW), "EC_PRE_COMP_NEW"},
    {ERR_FUNC(EC_F_EC_WNAF_MUL), "ec_wNAF_mul"},
    {ERR_FUNC(EC_F_EC_WNAF_PRECOMPUTE_MULT), "ec_wNAF_precompute_mult"},
    {ERR_FUNC(EC_F_I2D_ECPARAMETERS), "i2d_ECParameters"},
    {ERR_FUNC(EC_F_I2D_ECPKPARAMETERS), "i2d_ECPKParameters"},
    {ERR_FUNC(EC_F_I2D_ECPRIVATEKEY), "i2d_ECPrivateKey"},
    {ERR_FUNC(EC_F_I2O_ECPUBLICKEY), "i2o_ECPublicKey"},
    {ERR_FUNC(EC_F_NISTP224_PRE_COMP_NEW), "NISTP224_PRE_COMP_NEW"},
    {ERR_FUNC(EC_F_NISTP256_PRE_COMP_NEW), "NISTP256_PRE_COMP_NEW"},
    {ERR_FUNC(EC_F_NISTP521_PRE_COMP_NEW), "NISTP521_PRE_COMP_NEW"},
    {ERR_FUNC(EC_F_O2I_ECPUBLICKEY), "o2i_ECPublicKey"},
    {ERR_FUNC(EC_F_OLD_EC_PRIV_DECODE), "OLD_EC_PRIV_DECODE"},
    {ERR_FUNC(EC_F_PKEY_EC_CTRL), "PKEY_EC_CTRL"},
    {ERR_FUNC(EC_F_PKEY_EC_CTRL_STR), "PKEY_EC_CTRL_STR"},
    {ERR_FUNC(EC_F_PKEY_EC_DERIVE), "PKEY_EC_DERIVE"},
    {ERR_FUNC(EC_F_PKEY_EC_KEYGEN), "PKEY_EC_KEYGEN"},
    {ERR_FUNC(EC_F_PKEY_EC_PARAMGEN), "PKEY_EC_PARAMGEN"},
    {ERR_FUNC(EC_F_PKEY_EC_SIGN), "PKEY_EC_SIGN"},
    {0, NULL}
};

static ERR_STRING_DATA EC_str_reasons[] = {
    {ERR_REASON(EC_R_ASN1_ERROR), "asn1 error"},
    {ERR_REASON(EC_R_ASN1_UNKNOWN_FIELD), "asn1 unknown field"},
    {ERR_REASON(EC_R_BIGNUM_OUT_OF_RANGE), "bignum out of range"},
    {ERR_REASON(EC_R_BUFFER_TOO_SMALL), "buffer too small"},
    {ERR_REASON(EC_R_COORDINATES_OUT_OF_RANGE), "coordinates out of range"},
    {ERR_REASON(EC_R_D2I_ECPKPARAMETERS_FAILURE),
     "d2i ecpkparameters failure"},
    {ERR_REASON(EC_R_DECODE_ERROR), "decode error"},
    {ERR_REASON(EC_R_DISCRIMINANT_IS_ZERO), "discriminant is zero"},
    {ERR_REASON(EC_R_EC_GROUP_NEW_BY_NAME_FAILURE),
     "ec group new by name failure"},
    {ERR_REASON(EC_R_FIELD_TOO_LARGE), "field too large"},
    {ERR_REASON(EC_R_GF2M_NOT_SUPPORTED), "gf2m not supported"},
    {ERR_REASON(EC_R_GROUP2PKPARAMETERS_FAILURE),
     "group2pkparameters failure"},
    {ERR_REASON(EC_R_I2D_ECPKPARAMETERS_FAILURE),
     "i2d ecpkparameters failure"},
    {ERR_REASON(EC_R_INCOMPATIBLE_OBJECTS), "incompatible objects"},
    {ERR_REASON(EC_R_INVALID_ARGUMENT), "invalid argument"},
    {ERR_REASON(EC_R_INVALID_COMPRESSED_POINT), "invalid compressed point"},
    {ERR_REASON(EC_R_INVALID_COMPRESSION_BIT), "invalid compression bit"},
    {ERR_REASON(EC_R_INVALID_CURVE), "invalid curve"},
    {ERR_REASON(EC_R_INVALID_DIGEST), "invalid digest"},
    {ERR_REASON(EC_R_INVALID_DIGEST_TYPE), "invalid digest type"},
    {ERR_REASON(EC_R_INVALID_ENCODING), "invalid encoding"},
    {ERR_REASON(EC_R_INVALID_FIELD), "invalid field"},
    {ERR_REASON(EC_R_INVALID_FORM), "invalid form"},
    {ERR_REASON(EC_R_INVALID_GROUP_ORDER), "invalid group order"},
    {ERR_REASON(EC_R_INVALID_PENTANOMIAL_BASIS), "invalid pentanomial basis"},
    {ERR_REASON(EC_R_INVALID_PRIVATE_KEY), "invalid private key"},
    {ERR_REASON(EC_R_INVALID_TRINOMIAL_BASIS), "invalid trinomial basis"},
    {ERR_REASON(EC_R_KDF_PARAMETER_ERROR), "kdf parameter error"},
    {ERR_REASON(EC_R_KEYS_NOT_SET), "keys not set"},
    {ERR_REASON(EC_R_MISSING_PARAMETERS), "missing parameters"},
    {ERR_REASON(EC_R_MISSING_PRIVATE_KEY), "missing private key"},
    {ERR_REASON(EC_R_NOT_A_NIST_PRIME), "not a NIST prime"},
    {ERR_REASON(EC_R_NOT_A_SUPPORTED_NIST_PRIME),
     "not a supported NIST prime"},
    {ERR_REASON(EC_R_NOT_IMPLEMENTED), "not implemented"},
    {ERR_REASON(EC_R_NOT_INITIALIZED), "not initialized"},
    {ERR_REASON(EC_R_NO_FIELD_MOD), "no field mod"},
    {ERR_REASON(EC_R_NO_PARAMETERS_SET), "no parameters set"},
    {ERR_REASON(EC_R_PASSED_NULL_PARAMETER), "passed null parameter"},
    {ERR_REASON(EC_R_PEER_KEY_ERROR), "peer key error"},
    {ERR_REASON(EC_R_PKPARAMETERS2GROUP_FAILURE),
     "pkparameters2group failure"},
    {ERR_REASON(EC_R_POINT_AT_INFINITY), "point at infinity"},
    {ERR_REASON(EC_R_POINT_IS_NOT_ON_CURVE), "point is not on curve"},
    {ERR_REASON(EC_R_SHARED_INFO_ERROR), "shared info error"},
    {ERR_REASON(EC_R_SLOT_FULL), "slot full"},
    {ERR_REASON(EC_R_UNDEFINED_GENERATOR), "undefined generator"},
    {ERR_REASON(EC_R_UNDEFINED_ORDER), "undefined order"},
    {ERR_REASON(EC_R_UNKNOWN_GROUP), "unknown group"},
    {ERR_REASON(EC_R_UNKNOWN_ORDER), "unknown order"},
    {ERR_REASON(EC_R_UNSUPPORTED_FIELD), "unsupported field"},
    {ERR_REASON(EC_R_WRONG_CURVE_PARAMETERS), "wrong curve parameters"},
    {ERR_REASON(EC_R_WRONG_ORDER), "wrong order"},
    {0, NULL}
};

#endif

void ERR_load_EC_strings(void)
{
#ifndef OPENSSL_NO_ERR

    if (ERR_func_error_string(EC_str_functs[0].error) == NULL) {
        ERR_load_strings(0, EC_str_functs);
        ERR_load_strings(0, EC_str_reasons);
    }
#endif
}
/* crypto/ec/ec_key.c */
/*
 * Written by Nils Larsch for the OpenSSL project.
 */
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
/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 * Portions originally developed by SUN MICROSYSTEMS, INC., and
 * contributed to the OpenSSL project.
 */

#include <string.h>
// #include "ec_lcl.h"
// #include "err.h"
#ifdef OPENSSL_FIPS
# include <fips.h>
#endif

EC_KEY *EC_KEY_new(void)
{
    EC_KEY *ret;

    ret = (EC_KEY *)OPENSSL_malloc(sizeof(EC_KEY));
    if (ret == NULL) {
        ECerr(EC_F_EC_KEY_NEW, ERR_R_MALLOC_FAILURE);
        return (NULL);
    }

    ret->version = 1;
    ret->flags = 0;
    ret->group = NULL;
    ret->pub_key = NULL;
    ret->priv_key = NULL;
    ret->enc_flag = 0;
    ret->conv_form = POINT_CONVERSION_UNCOMPRESSED;
    ret->references = 1;
    ret->method_data = NULL;
    return (ret);
}

EC_KEY *EC_KEY_new_by_curve_name(int nid)
{
    EC_KEY *ret = EC_KEY_new();
    if (ret == NULL)
        return NULL;
    ret->group = EC_GROUP_new_by_curve_name(nid);
    if (ret->group == NULL) {
        EC_KEY_free(ret);
        return NULL;
    }
    return ret;
}

void EC_KEY_free(EC_KEY *r)
{
    int i;

    if (r == NULL)
        return;

    i = CRYPTO_add(&r->references, -1, CRYPTO_LOCK_EC);
#ifdef REF_PRINT
    REF_PRINT("EC_KEY", r);
#endif
    if (i > 0)
        return;
#ifdef REF_CHECK
    if (i < 0) {
        fprintf(stderr, "EC_KEY_free, bad reference count\n");
        abort();
    }
#endif

    if (r->group != NULL)
        EC_GROUP_free(r->group);
    if (r->pub_key != NULL)
        EC_POINT_free(r->pub_key);
    if (r->priv_key != NULL)
        BN_clear_free(r->priv_key);

    EC_EX_DATA_free_all_data(&r->method_data);

    OPENSSL_cleanse((void *)r, sizeof(EC_KEY));

    OPENSSL_free(r);
}

EC_KEY *EC_KEY_copy(EC_KEY *dest, const EC_KEY *src)
{
    EC_EXTRA_DATA *d;

    if (dest == NULL || src == NULL) {
        ECerr(EC_F_EC_KEY_COPY, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }
    /* copy the parameters */
    if (src->group) {
        const EC_METHOD *meth = EC_GROUP_method_of(src->group);
        /* clear the old group */
        if (dest->group)
            EC_GROUP_free(dest->group);
        dest->group = EC_GROUP_new(meth);
        if (dest->group == NULL)
            return NULL;
        if (!EC_GROUP_copy(dest->group, src->group))
            return NULL;
    }
    /*  copy the public key */
    if (src->pub_key && src->group) {
        if (dest->pub_key)
            EC_POINT_free(dest->pub_key);
        dest->pub_key = EC_POINT_new(src->group);
        if (dest->pub_key == NULL)
            return NULL;
        if (!EC_POINT_copy(dest->pub_key, src->pub_key))
            return NULL;
    }
    /* copy the private key */
    if (src->priv_key) {
        if (dest->priv_key == NULL) {
            dest->priv_key = BN_new();
            if (dest->priv_key == NULL)
                return NULL;
        }
        if (!BN_copy(dest->priv_key, src->priv_key))
            return NULL;
    }
    /* copy method/extra data */
    EC_EX_DATA_free_all_data(&dest->method_data);

    for (d = src->method_data; d != NULL; d = d->next) {
        void *t = d->dup_func(d->data);

        if (t == NULL)
            return 0;
        if (!EC_EX_DATA_set_data
            (&dest->method_data, t, d->dup_func, d->free_func,
             d->clear_free_func))
            return 0;
    }

    /* copy the rest */
    dest->enc_flag = src->enc_flag;
    dest->conv_form = src->conv_form;
    dest->version = src->version;
    dest->flags = src->flags;

    return dest;
}

EC_KEY *EC_KEY_dup(const EC_KEY *ec_key)
{
    EC_KEY *ret = EC_KEY_new();
    if (ret == NULL)
        return NULL;
    if (EC_KEY_copy(ret, ec_key) == NULL) {
        EC_KEY_free(ret);
        return NULL;
    }
    return ret;
}

int EC_KEY_up_ref(EC_KEY *r)
{
    int i = CRYPTO_add(&r->references, 1, CRYPTO_LOCK_EC);
#ifdef REF_PRINT
    REF_PRINT("EC_KEY", r);
#endif
#ifdef REF_CHECK
    if (i < 2) {
        fprintf(stderr, "EC_KEY_up, bad reference count\n");
        abort();
    }
#endif
    return ((i > 1) ? 1 : 0);
}

int EC_KEY_generate_key(EC_KEY *eckey)
{
    int ok = 0;
    BN_CTX *ctx = NULL;
    BIGNUM *priv_key = NULL, *order = NULL;
    EC_POINT *pub_key = NULL;

#ifdef OPENSSL_FIPS
    if (FIPS_mode())
        return FIPS_ec_key_generate_key(eckey);
#endif

    if (!eckey || !eckey->group) {
        ECerr(EC_F_EC_KEY_GENERATE_KEY, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    if ((order = BN_new()) == NULL)
        goto err;
    if ((ctx = BN_CTX_new()) == NULL)
        goto err;

    if (eckey->priv_key == NULL) {
        priv_key = BN_new();
        if (priv_key == NULL)
            goto err;
    } else
        priv_key = eckey->priv_key;

    if (!EC_GROUP_get_order(eckey->group, order, ctx))
        goto err;

    do
        if (!BN_rand_range(priv_key, order))
            goto err;
    while (BN_is_zero(priv_key)) ;

    if (eckey->pub_key == NULL) {
        pub_key = EC_POINT_new(eckey->group);
        if (pub_key == NULL)
            goto err;
    } else
        pub_key = eckey->pub_key;

    if (!EC_POINT_mul(eckey->group, pub_key, priv_key, NULL, NULL, ctx))
        goto err;

    eckey->priv_key = priv_key;
    eckey->pub_key = pub_key;

    ok = 1;

 err:
    if (order)
        BN_free(order);
    if (pub_key != NULL && eckey->pub_key == NULL)
        EC_POINT_free(pub_key);
    if (priv_key != NULL && eckey->priv_key == NULL)
        BN_free(priv_key);
    if (ctx != NULL)
        BN_CTX_free(ctx);
    return (ok);
}

int EC_KEY_check_key(const EC_KEY *eckey)
{
    int ok = 0;
    BN_CTX *ctx = NULL;
    const BIGNUM *order = NULL;
    EC_POINT *point = NULL;

    if (!eckey || !eckey->group || !eckey->pub_key) {
        ECerr(EC_F_EC_KEY_CHECK_KEY, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    if (EC_POINT_is_at_infinity(eckey->group, eckey->pub_key)) {
        ECerr(EC_F_EC_KEY_CHECK_KEY, EC_R_POINT_AT_INFINITY);
        goto err;
    }

    if ((ctx = BN_CTX_new()) == NULL)
        goto err;
    if ((point = EC_POINT_new(eckey->group)) == NULL)
        goto err;

    /* testing whether the pub_key is on the elliptic curve */
    if (EC_POINT_is_on_curve(eckey->group, eckey->pub_key, ctx) <= 0) {
        ECerr(EC_F_EC_KEY_CHECK_KEY, EC_R_POINT_IS_NOT_ON_CURVE);
        goto err;
    }
    /* testing whether pub_key * order is the point at infinity */
    order = &eckey->group->order;
    if (BN_is_zero(order)) {
        ECerr(EC_F_EC_KEY_CHECK_KEY, EC_R_INVALID_GROUP_ORDER);
        goto err;
    }
    if (!EC_POINT_mul(eckey->group, point, NULL, eckey->pub_key, order, ctx)) {
        ECerr(EC_F_EC_KEY_CHECK_KEY, ERR_R_EC_LIB);
        goto err;
    }
    if (!EC_POINT_is_at_infinity(eckey->group, point)) {
        ECerr(EC_F_EC_KEY_CHECK_KEY, EC_R_WRONG_ORDER);
        goto err;
    }
    /*
     * in case the priv_key is present : check if generator * priv_key ==
     * pub_key
     */
    if (eckey->priv_key) {
        if (BN_cmp(eckey->priv_key, order) >= 0) {
            ECerr(EC_F_EC_KEY_CHECK_KEY, EC_R_WRONG_ORDER);
            goto err;
        }
        if (!EC_POINT_mul(eckey->group, point, eckey->priv_key,
                          NULL, NULL, ctx)) {
            ECerr(EC_F_EC_KEY_CHECK_KEY, ERR_R_EC_LIB);
            goto err;
        }
        if (EC_POINT_cmp(eckey->group, point, eckey->pub_key, ctx) != 0) {
            ECerr(EC_F_EC_KEY_CHECK_KEY, EC_R_INVALID_PRIVATE_KEY);
            goto err;
        }
    }
    ok = 1;
 err:
    if (ctx != NULL)
        BN_CTX_free(ctx);
    if (point != NULL)
        EC_POINT_free(point);
    return (ok);
}

int EC_KEY_set_public_key_affine_coordinates(EC_KEY *key, BIGNUM *x,
                                             BIGNUM *y)
{
    BN_CTX *ctx = NULL;
    BIGNUM *tx, *ty;
    EC_POINT *point = NULL;
    int ok = 0;
#ifndef OPENSSL_NO_EC2M
    int tmp_nid, is_char_two = 0;
#endif

    if (!key || !key->group || !x || !y) {
        ECerr(EC_F_EC_KEY_SET_PUBLIC_KEY_AFFINE_COORDINATES,
              ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    ctx = BN_CTX_new();
    if (ctx == NULL)
        return 0;
    BN_CTX_start(ctx);
    point = EC_POINT_new(key->group);

    if (!point)
        goto err;

    tx = BN_CTX_get(ctx);
    ty = BN_CTX_get(ctx);
    if (ty == NULL)
        goto err;

#ifndef OPENSSL_NO_EC2M
    tmp_nid = EC_METHOD_get_field_type(EC_GROUP_method_of(key->group));

    if (tmp_nid == NID_X9_62_characteristic_two_field)
        is_char_two = 1;

    if (is_char_two) {
        if (!EC_POINT_set_affine_coordinates_GF2m(key->group, point,
                                                  x, y, ctx))
            goto err;
        if (!EC_POINT_get_affine_coordinates_GF2m(key->group, point,
                                                  tx, ty, ctx))
            goto err;
    } else
#endif
    {
        if (!EC_POINT_set_affine_coordinates_GFp(key->group, point,
                                                 x, y, ctx))
            goto err;
        if (!EC_POINT_get_affine_coordinates_GFp(key->group, point,
                                                 tx, ty, ctx))
            goto err;
    }
    /*
     * Check if retrieved coordinates match originals: if not values are out
     * of range.
     */
    if (BN_cmp(x, tx) || BN_cmp(y, ty)) {
        ECerr(EC_F_EC_KEY_SET_PUBLIC_KEY_AFFINE_COORDINATES,
              EC_R_COORDINATES_OUT_OF_RANGE);
        goto err;
    }

    if (!EC_KEY_set_public_key(key, point))
        goto err;

    if (EC_KEY_check_key(key) == 0)
        goto err;

    ok = 1;

 err:
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    EC_POINT_free(point);
    return ok;

}

const EC_GROUP *EC_KEY_get0_group(const EC_KEY *key)
{
    return key->group;
}

int EC_KEY_set_group(EC_KEY *key, const EC_GROUP *group)
{
    if (key->group != NULL)
        EC_GROUP_free(key->group);
    key->group = EC_GROUP_dup(group);
    return (key->group == NULL) ? 0 : 1;
}

const BIGNUM *EC_KEY_get0_private_key(const EC_KEY *key)
{
    return key->priv_key;
}

int EC_KEY_set_private_key(EC_KEY *key, const BIGNUM *priv_key)
{
    if (key->priv_key)
        BN_clear_free(key->priv_key);
    key->priv_key = BN_dup(priv_key);
    return (key->priv_key == NULL) ? 0 : 1;
}

const EC_POINT *EC_KEY_get0_public_key(const EC_KEY *key)
{
    return key->pub_key;
}

int EC_KEY_set_public_key(EC_KEY *key, const EC_POINT *pub_key)
{
    if (key->pub_key != NULL)
        EC_POINT_free(key->pub_key);
    key->pub_key = EC_POINT_dup(pub_key, key->group);
    return (key->pub_key == NULL) ? 0 : 1;
}

unsigned int EC_KEY_get_enc_flags(const EC_KEY *key)
{
    return key->enc_flag;
}

void EC_KEY_set_enc_flags(EC_KEY *key, unsigned int flags)
{
    key->enc_flag = flags;
}

point_conversion_form_t EC_KEY_get_conv_form(const EC_KEY *key)
{
    return key->conv_form;
}

void EC_KEY_set_conv_form(EC_KEY *key, point_conversion_form_t cform)
{
    key->conv_form = cform;
    if (key->group != NULL)
        EC_GROUP_set_point_conversion_form(key->group, cform);
}

void *EC_KEY_get_key_method_data(EC_KEY *key,
                                 void *(*dup_func) (void *),
                                 void (*free_func) (void *),
                                 void (*clear_free_func) (void *))
{
    void *ret;

    CRYPTO_r_lock(CRYPTO_LOCK_EC);
    ret =
        EC_EX_DATA_get_data(key->method_data, dup_func, free_func,
                            clear_free_func);
    CRYPTO_r_unlock(CRYPTO_LOCK_EC);

    return ret;
}

void *EC_KEY_insert_key_method_data(EC_KEY *key, void *data,
                                    void *(*dup_func) (void *),
                                    void (*free_func) (void *),
                                    void (*clear_free_func) (void *))
{
    EC_EXTRA_DATA *ex_data;

    CRYPTO_w_lock(CRYPTO_LOCK_EC);
    ex_data =
        EC_EX_DATA_get_data(key->method_data, dup_func, free_func,
                            clear_free_func);
    if (ex_data == NULL)
        EC_EX_DATA_set_data(&key->method_data, data, dup_func, free_func,
                            clear_free_func);
    CRYPTO_w_unlock(CRYPTO_LOCK_EC);

    return ex_data;
}

void EC_KEY_set_asn1_flag(EC_KEY *key, int flag)
{
    if (key->group != NULL)
        EC_GROUP_set_asn1_flag(key->group, flag);
}

int EC_KEY_precompute_mult(EC_KEY *key, BN_CTX *ctx)
{
    if (key->group == NULL)
        return 0;
    return EC_GROUP_precompute_mult(key->group, ctx);
}

int EC_KEY_get_flags(const EC_KEY *key)
{
    return key->flags;
}

void EC_KEY_set_flags(EC_KEY *key, int flags)
{
    key->flags |= flags;
}

void EC_KEY_clear_flags(EC_KEY *key, int flags)
{
    key->flags &= ~flags;
}
/* crypto/ec/ec_lib.c */
/*
 * Originally written by Bodo Moeller for the OpenSSL project.
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
/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 * Binary polynomial ECC support in OpenSSL originally developed by
 * SUN MICROSYSTEMS, INC., and contributed to the OpenSSL project.
 */

#include <string.h>

// #include "err.h"
#include "opensslv.h"

// #include "ec_lcl.h"

const char EC_version[] = "EC" OPENSSL_VERSION_PTEXT;

/* local function prototypes */

static int ec_precompute_mont_data(EC_GROUP *group);

/* functions for EC_GROUP objects */

EC_GROUP *EC_GROUP_new(const EC_METHOD *meth)
{
    EC_GROUP *ret;

    if (meth == NULL) {
        ECerr(EC_F_EC_GROUP_NEW, EC_R_SLOT_FULL);
        return NULL;
    }
    if (meth->group_init == 0) {
        ECerr(EC_F_EC_GROUP_NEW, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return NULL;
    }

    ret = OPENSSL_malloc(sizeof(*ret));
    if (ret == NULL) {
        ECerr(EC_F_EC_GROUP_NEW, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    ret->meth = meth;

    ret->extra_data = NULL;
    ret->mont_data = NULL;

    ret->generator = NULL;
    BN_init(&ret->order);
    BN_init(&ret->cofactor);

    ret->curve_name = 0;
    ret->asn1_flag = ~EC_GROUP_ASN1_FLAG_MASK;
    ret->asn1_form = POINT_CONVERSION_UNCOMPRESSED;

    ret->seed = NULL;
    ret->seed_len = 0;

    if (!meth->group_init(ret)) {
        OPENSSL_free(ret);
        return NULL;
    }

    return ret;
}

void EC_GROUP_free(EC_GROUP *group)
{
    if (!group)
        return;

    if (group->meth->group_finish != 0)
        group->meth->group_finish(group);

    EC_EX_DATA_free_all_data(&group->extra_data);

    if (EC_GROUP_VERSION(group) && group->mont_data)
        BN_MONT_CTX_free(group->mont_data);

    if (group->generator != NULL)
        EC_POINT_free(group->generator);
    BN_free(&group->order);
    BN_free(&group->cofactor);

    if (group->seed)
        OPENSSL_free(group->seed);

    OPENSSL_free(group);
}

void EC_GROUP_clear_free(EC_GROUP *group)
{
    if (!group)
        return;

    if (group->meth->group_clear_finish != 0)
        group->meth->group_clear_finish(group);
    else if (group->meth->group_finish != 0)
        group->meth->group_finish(group);

    EC_EX_DATA_clear_free_all_data(&group->extra_data);

    if (EC_GROUP_VERSION(group) && group->mont_data)
        BN_MONT_CTX_free(group->mont_data);

    if (group->generator != NULL)
        EC_POINT_clear_free(group->generator);
    BN_clear_free(&group->order);
    BN_clear_free(&group->cofactor);

    if (group->seed) {
        OPENSSL_cleanse(group->seed, group->seed_len);
        OPENSSL_free(group->seed);
    }

    OPENSSL_cleanse(group, sizeof(*group));
    OPENSSL_free(group);
}

int EC_GROUP_copy(EC_GROUP *dest, const EC_GROUP *src)
{
    EC_EXTRA_DATA *d;

    if (dest->meth->group_copy == 0) {
        ECerr(EC_F_EC_GROUP_COPY, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }
    if (dest->meth != src->meth) {
        ECerr(EC_F_EC_GROUP_COPY, EC_R_INCOMPATIBLE_OBJECTS);
        return 0;
    }
    if (dest == src)
        return 1;

    EC_EX_DATA_free_all_data(&dest->extra_data);

    for (d = src->extra_data; d != NULL; d = d->next) {
        void *t = d->dup_func(d->data);

        if (t == NULL)
            return 0;
        if (!EC_EX_DATA_set_data
            (&dest->extra_data, t, d->dup_func, d->free_func,
             d->clear_free_func))
            return 0;
    }

    if (EC_GROUP_VERSION(src) && src->mont_data != NULL) {
        if (dest->mont_data == NULL) {
            dest->mont_data = BN_MONT_CTX_new();
            if (dest->mont_data == NULL)
                return 0;
        }
        if (!BN_MONT_CTX_copy(dest->mont_data, src->mont_data))
            return 0;
    } else {
        /* src->generator == NULL */
        if (EC_GROUP_VERSION(dest) && dest->mont_data != NULL) {
            BN_MONT_CTX_free(dest->mont_data);
            dest->mont_data = NULL;
        }
    }

    if (src->generator != NULL) {
        if (dest->generator == NULL) {
            dest->generator = EC_POINT_new(dest);
            if (dest->generator == NULL)
                return 0;
        }
        if (!EC_POINT_copy(dest->generator, src->generator))
            return 0;
    } else {
        /* src->generator == NULL */
        if (dest->generator != NULL) {
            EC_POINT_clear_free(dest->generator);
            dest->generator = NULL;
        }
    }

    if (!BN_copy(&dest->order, &src->order))
        return 0;
    if (!BN_copy(&dest->cofactor, &src->cofactor))
        return 0;

    dest->curve_name = src->curve_name;
    dest->asn1_flag = src->asn1_flag;
    dest->asn1_form = src->asn1_form;

    if (src->seed) {
        if (dest->seed)
            OPENSSL_free(dest->seed);
        dest->seed = OPENSSL_malloc(src->seed_len);
        if (dest->seed == NULL)
            return 0;
        if (!memcpy(dest->seed, src->seed, src->seed_len))
            return 0;
        dest->seed_len = src->seed_len;
    } else {
        if (dest->seed)
            OPENSSL_free(dest->seed);
        dest->seed = NULL;
        dest->seed_len = 0;
    }

    return dest->meth->group_copy(dest, src);
}

EC_GROUP *EC_GROUP_dup(const EC_GROUP *a)
{
    EC_GROUP *t = NULL;
    int ok = 0;

    if (a == NULL)
        return NULL;

    if ((t = EC_GROUP_new(a->meth)) == NULL)
        return (NULL);
    if (!EC_GROUP_copy(t, a))
        goto err;

    ok = 1;

 err:
    if (!ok) {
        if (t)
            EC_GROUP_free(t);
        return NULL;
    } else
        return t;
}

const EC_METHOD *EC_GROUP_method_of(const EC_GROUP *group)
{
    return group->meth;
}

int EC_METHOD_get_field_type(const EC_METHOD *meth)
{
    return meth->field_type;
}

int EC_GROUP_set_generator(EC_GROUP *group, const EC_POINT *generator,
                           const BIGNUM *order, const BIGNUM *cofactor)
{
    if (generator == NULL) {
        ECerr(EC_F_EC_GROUP_SET_GENERATOR, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    if (group->generator == NULL) {
        group->generator = EC_POINT_new(group);
        if (group->generator == NULL)
            return 0;
    }
    if (!EC_POINT_copy(group->generator, generator))
        return 0;

    if (order != NULL) {
        if (!BN_copy(&group->order, order))
            return 0;
    } else
        BN_zero(&group->order);

    if (cofactor != NULL) {
        if (!BN_copy(&group->cofactor, cofactor))
            return 0;
    } else
        BN_zero(&group->cofactor);

    /*-
     * Access to the `mont_data` field of an EC_GROUP struct should always be
     * guarded by an EC_GROUP_VERSION(group) check to avoid OOB accesses, as the
     * group might come from the FIPS module, which does not define the
     * `mont_data` field inside the EC_GROUP structure.
     */
    if (EC_GROUP_VERSION(group)) {
        /*-
         * Some groups have an order with
         * factors of two, which makes the Montgomery setup fail.
         * |group->mont_data| will be NULL in this case.
         */
        if (BN_is_odd(&group->order))
            return ec_precompute_mont_data(group);

        BN_MONT_CTX_free(group->mont_data);
        group->mont_data = NULL;
    }

    return 1;
}

const EC_POINT *EC_GROUP_get0_generator(const EC_GROUP *group)
{
    return group->generator;
}

BN_MONT_CTX *EC_GROUP_get_mont_data(const EC_GROUP *group)
{
    return EC_GROUP_VERSION(group) ? group->mont_data : NULL;
}

int EC_GROUP_get_order(const EC_GROUP *group, BIGNUM *order, BN_CTX *ctx)
{
    if (!BN_copy(order, &group->order))
        return 0;

    return !BN_is_zero(order);
}

int EC_GROUP_get_cofactor(const EC_GROUP *group, BIGNUM *cofactor,
                          BN_CTX *ctx)
{
    if (!BN_copy(cofactor, &group->cofactor))
        return 0;

    return !BN_is_zero(&group->cofactor);
}

void EC_GROUP_set_curve_name(EC_GROUP *group, int nid)
{
    group->curve_name = nid;
}

int EC_GROUP_get_curve_name(const EC_GROUP *group)
{
    return group->curve_name;
}

void EC_GROUP_set_asn1_flag(EC_GROUP *group, int flag)
{
    group->asn1_flag &= ~EC_GROUP_ASN1_FLAG_MASK;
    group->asn1_flag |= flag & EC_GROUP_ASN1_FLAG_MASK;
}

int EC_GROUP_get_asn1_flag(const EC_GROUP *group)
{
    return group->asn1_flag & EC_GROUP_ASN1_FLAG_MASK;
}

void EC_GROUP_set_point_conversion_form(EC_GROUP *group,
                                        point_conversion_form_t form)
{
    group->asn1_form = form;
}

point_conversion_form_t EC_GROUP_get_point_conversion_form(const EC_GROUP
                                                           *group)
{
    return group->asn1_form;
}

size_t EC_GROUP_set_seed(EC_GROUP *group, const unsigned char *p, size_t len)
{
    if (group->seed) {
        OPENSSL_free(group->seed);
        group->seed = NULL;
        group->seed_len = 0;
    }

    if (!len || !p)
        return 1;

    if ((group->seed = OPENSSL_malloc(len)) == NULL)
        return 0;
    memcpy(group->seed, p, len);
    group->seed_len = len;

    return len;
}

unsigned char *EC_GROUP_get0_seed(const EC_GROUP *group)
{
    return group->seed;
}

size_t EC_GROUP_get_seed_len(const EC_GROUP *group)
{
    return group->seed_len;
}

int EC_GROUP_set_curve_GFp(EC_GROUP *group, const BIGNUM *p, const BIGNUM *a,
                           const BIGNUM *b, BN_CTX *ctx)
{
    if (group->meth->group_set_curve == 0) {
        ECerr(EC_F_EC_GROUP_SET_CURVE_GFP, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }
    return group->meth->group_set_curve(group, p, a, b, ctx);
}

int EC_GROUP_get_curve_GFp(const EC_GROUP *group, BIGNUM *p, BIGNUM *a,
                           BIGNUM *b, BN_CTX *ctx)
{
    if (group->meth->group_get_curve == 0) {
        ECerr(EC_F_EC_GROUP_GET_CURVE_GFP, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }
    return group->meth->group_get_curve(group, p, a, b, ctx);
}

#ifndef OPENSSL_NO_EC2M
int EC_GROUP_set_curve_GF2m(EC_GROUP *group, const BIGNUM *p, const BIGNUM *a,
                            const BIGNUM *b, BN_CTX *ctx)
{
    if (group->meth->group_set_curve == 0) {
        ECerr(EC_F_EC_GROUP_SET_CURVE_GF2M,
              ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }
    return group->meth->group_set_curve(group, p, a, b, ctx);
}

int EC_GROUP_get_curve_GF2m(const EC_GROUP *group, BIGNUM *p, BIGNUM *a,
                            BIGNUM *b, BN_CTX *ctx)
{
    if (group->meth->group_get_curve == 0) {
        ECerr(EC_F_EC_GROUP_GET_CURVE_GF2M,
              ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }
    return group->meth->group_get_curve(group, p, a, b, ctx);
}
#endif

int EC_GROUP_get_degree(const EC_GROUP *group)
{
    if (group->meth->group_get_degree == 0) {
        ECerr(EC_F_EC_GROUP_GET_DEGREE, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }
    return group->meth->group_get_degree(group);
}

int EC_GROUP_check_discriminant(const EC_GROUP *group, BN_CTX *ctx)
{
    if (group->meth->group_check_discriminant == 0) {
        ECerr(EC_F_EC_GROUP_CHECK_DISCRIMINANT,
              ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }
    return group->meth->group_check_discriminant(group, ctx);
}

int EC_GROUP_cmp(const EC_GROUP *a, const EC_GROUP *b, BN_CTX *ctx)
{
    int r = 0;
    BIGNUM *a1, *a2, *a3, *b1, *b2, *b3;
    BN_CTX *ctx_new = NULL;

    /* compare the field types */
    if (EC_METHOD_get_field_type(EC_GROUP_method_of(a)) !=
        EC_METHOD_get_field_type(EC_GROUP_method_of(b)))
        return 1;
    /* compare the curve name (if present in both) */
    if (EC_GROUP_get_curve_name(a) && EC_GROUP_get_curve_name(b) &&
        EC_GROUP_get_curve_name(a) != EC_GROUP_get_curve_name(b))
        return 1;

    if (!ctx)
        ctx_new = ctx = BN_CTX_new();
    if (!ctx)
        return -1;

    BN_CTX_start(ctx);
    a1 = BN_CTX_get(ctx);
    a2 = BN_CTX_get(ctx);
    a3 = BN_CTX_get(ctx);
    b1 = BN_CTX_get(ctx);
    b2 = BN_CTX_get(ctx);
    b3 = BN_CTX_get(ctx);
    if (!b3) {
        BN_CTX_end(ctx);
        if (ctx_new)
            BN_CTX_free(ctx);
        return -1;
    }

    /*
     * XXX This approach assumes that the external representation of curves
     * over the same field type is the same.
     */
    if (!a->meth->group_get_curve(a, a1, a2, a3, ctx) ||
        !b->meth->group_get_curve(b, b1, b2, b3, ctx))
        r = 1;

    if (r || BN_cmp(a1, b1) || BN_cmp(a2, b2) || BN_cmp(a3, b3))
        r = 1;

    /* XXX EC_POINT_cmp() assumes that the methods are equal */
    if (r || EC_POINT_cmp(a, EC_GROUP_get0_generator(a),
                          EC_GROUP_get0_generator(b), ctx))
        r = 1;

    if (!r) {
        /* compare the order and cofactor */
        if (!EC_GROUP_get_order(a, a1, ctx) ||
            !EC_GROUP_get_order(b, b1, ctx) ||
            !EC_GROUP_get_cofactor(a, a2, ctx) ||
            !EC_GROUP_get_cofactor(b, b2, ctx)) {
            BN_CTX_end(ctx);
            if (ctx_new)
                BN_CTX_free(ctx);
            return -1;
        }
        if (BN_cmp(a1, b1) || BN_cmp(a2, b2))
            r = 1;
    }

    BN_CTX_end(ctx);
    if (ctx_new)
        BN_CTX_free(ctx);

    return r;
}

/* this has 'package' visibility */
int EC_EX_DATA_set_data(EC_EXTRA_DATA **ex_data, void *data,
                        void *(*dup_func) (void *),
                        void (*free_func) (void *),
                        void (*clear_free_func) (void *))
{
    EC_EXTRA_DATA *d;

    if (ex_data == NULL)
        return 0;

    for (d = *ex_data; d != NULL; d = d->next) {
        if (d->dup_func == dup_func && d->free_func == free_func
            && d->clear_free_func == clear_free_func) {
            ECerr(EC_F_EC_EX_DATA_SET_DATA, EC_R_SLOT_FULL);
            return 0;
        }
    }

    if (data == NULL)
        /* no explicit entry needed */
        return 1;

    d = OPENSSL_malloc(sizeof(*d));
    if (d == NULL)
        return 0;

    d->data = data;
    d->dup_func = dup_func;
    d->free_func = free_func;
    d->clear_free_func = clear_free_func;

    d->next = *ex_data;
    *ex_data = d;

    return 1;
}

/* this has 'package' visibility */
void *EC_EX_DATA_get_data(const EC_EXTRA_DATA *ex_data,
                          void *(*dup_func) (void *),
                          void (*free_func) (void *),
                          void (*clear_free_func) (void *))
{
    const EC_EXTRA_DATA *d;

    for (d = ex_data; d != NULL; d = d->next) {
        if (d->dup_func == dup_func && d->free_func == free_func
            && d->clear_free_func == clear_free_func)
            return d->data;
    }

    return NULL;
}

/* this has 'package' visibility */
void EC_EX_DATA_free_data(EC_EXTRA_DATA **ex_data,
                          void *(*dup_func) (void *),
                          void (*free_func) (void *),
                          void (*clear_free_func) (void *))
{
    EC_EXTRA_DATA **p;

    if (ex_data == NULL)
        return;

    for (p = ex_data; *p != NULL; p = &((*p)->next)) {
        if ((*p)->dup_func == dup_func && (*p)->free_func == free_func
            && (*p)->clear_free_func == clear_free_func) {
            EC_EXTRA_DATA *next = (*p)->next;

            (*p)->free_func((*p)->data);
            OPENSSL_free(*p);

            *p = next;
            return;
        }
    }
}

/* this has 'package' visibility */
void EC_EX_DATA_clear_free_data(EC_EXTRA_DATA **ex_data,
                                void *(*dup_func) (void *),
                                void (*free_func) (void *),
                                void (*clear_free_func) (void *))
{
    EC_EXTRA_DATA **p;

    if (ex_data == NULL)
        return;

    for (p = ex_data; *p != NULL; p = &((*p)->next)) {
        if ((*p)->dup_func == dup_func && (*p)->free_func == free_func
            && (*p)->clear_free_func == clear_free_func) {
            EC_EXTRA_DATA *next = (*p)->next;

            (*p)->clear_free_func((*p)->data);
            OPENSSL_free(*p);

            *p = next;
            return;
        }
    }
}

/* this has 'package' visibility */
void EC_EX_DATA_free_all_data(EC_EXTRA_DATA **ex_data)
{
    EC_EXTRA_DATA *d;

    if (ex_data == NULL)
        return;

    d = *ex_data;
    while (d) {
        EC_EXTRA_DATA *next = d->next;

        d->free_func(d->data);
        OPENSSL_free(d);

        d = next;
    }
    *ex_data = NULL;
}

/* this has 'package' visibility */
void EC_EX_DATA_clear_free_all_data(EC_EXTRA_DATA **ex_data)
{
    EC_EXTRA_DATA *d;

    if (ex_data == NULL)
        return;

    d = *ex_data;
    while (d) {
        EC_EXTRA_DATA *next = d->next;

        d->clear_free_func(d->data);
        OPENSSL_free(d);

        d = next;
    }
    *ex_data = NULL;
}

/* functions for EC_POINT objects */

EC_POINT *EC_POINT_new(const EC_GROUP *group)
{
    EC_POINT *ret;

    if (group == NULL) {
        ECerr(EC_F_EC_POINT_NEW, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }
    if (group->meth->point_init == 0) {
        ECerr(EC_F_EC_POINT_NEW, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return NULL;
    }

    ret = OPENSSL_malloc(sizeof(*ret));
    if (ret == NULL) {
        ECerr(EC_F_EC_POINT_NEW, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    ret->meth = group->meth;

    if (!ret->meth->point_init(ret)) {
        OPENSSL_free(ret);
        return NULL;
    }

    return ret;
}

void EC_POINT_free(EC_POINT *point)
{
    if (!point)
        return;

    if (point->meth->point_finish != 0)
        point->meth->point_finish(point);
    OPENSSL_free(point);
}

void EC_POINT_clear_free(EC_POINT *point)
{
    if (!point)
        return;

    if (point->meth->point_clear_finish != 0)
        point->meth->point_clear_finish(point);
    else if (point->meth->point_finish != 0)
        point->meth->point_finish(point);
    OPENSSL_cleanse(point, sizeof(*point));
    OPENSSL_free(point);
}

int EC_POINT_copy(EC_POINT *dest, const EC_POINT *src)
{
    if (dest->meth->point_copy == 0) {
        ECerr(EC_F_EC_POINT_COPY, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }
    if (dest->meth != src->meth) {
        ECerr(EC_F_EC_POINT_COPY, EC_R_INCOMPATIBLE_OBJECTS);
        return 0;
    }
    if (dest == src)
        return 1;
    return dest->meth->point_copy(dest, src);
}

EC_POINT *EC_POINT_dup(const EC_POINT *a, const EC_GROUP *group)
{
    EC_POINT *t;
    int r;

    if (a == NULL)
        return NULL;

    t = EC_POINT_new(group);
    if (t == NULL)
        return (NULL);
    r = EC_POINT_copy(t, a);
    if (!r) {
        EC_POINT_free(t);
        return NULL;
    } else
        return t;
}

const EC_METHOD *EC_POINT_method_of(const EC_POINT *point)
{
    return point->meth;
}

int EC_POINT_set_to_infinity(const EC_GROUP *group, EC_POINT *point)
{
    if (group->meth->point_set_to_infinity == 0) {
        ECerr(EC_F_EC_POINT_SET_TO_INFINITY,
              ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }
    if (group->meth != point->meth) {
        ECerr(EC_F_EC_POINT_SET_TO_INFINITY, EC_R_INCOMPATIBLE_OBJECTS);
        return 0;
    }
    return group->meth->point_set_to_infinity(group, point);
}

int EC_POINT_set_Jprojective_coordinates_GFp(const EC_GROUP *group,
                                             EC_POINT *point, const BIGNUM *x,
                                             const BIGNUM *y, const BIGNUM *z,
                                             BN_CTX *ctx)
{
    if (group->meth->point_set_Jprojective_coordinates_GFp == 0) {
        ECerr(EC_F_EC_POINT_SET_JPROJECTIVE_COORDINATES_GFP,
              ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }
    if (group->meth != point->meth) {
        ECerr(EC_F_EC_POINT_SET_JPROJECTIVE_COORDINATES_GFP,
              EC_R_INCOMPATIBLE_OBJECTS);
        return 0;
    }
    return group->meth->point_set_Jprojective_coordinates_GFp(group, point, x,
                                                              y, z, ctx);
}

int EC_POINT_get_Jprojective_coordinates_GFp(const EC_GROUP *group,
                                             const EC_POINT *point, BIGNUM *x,
                                             BIGNUM *y, BIGNUM *z,
                                             BN_CTX *ctx)
{
    if (group->meth->point_get_Jprojective_coordinates_GFp == 0) {
        ECerr(EC_F_EC_POINT_GET_JPROJECTIVE_COORDINATES_GFP,
              ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }
    if (group->meth != point->meth) {
        ECerr(EC_F_EC_POINT_GET_JPROJECTIVE_COORDINATES_GFP,
              EC_R_INCOMPATIBLE_OBJECTS);
        return 0;
    }
    return group->meth->point_get_Jprojective_coordinates_GFp(group, point, x,
                                                              y, z, ctx);
}

int EC_POINT_set_affine_coordinates_GFp(const EC_GROUP *group,
                                        EC_POINT *point, const BIGNUM *x,
                                        const BIGNUM *y, BN_CTX *ctx)
{
    if (group->meth->point_set_affine_coordinates == 0) {
        ECerr(EC_F_EC_POINT_SET_AFFINE_COORDINATES_GFP,
              ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }
    if (group->meth != point->meth) {
        ECerr(EC_F_EC_POINT_SET_AFFINE_COORDINATES_GFP,
              EC_R_INCOMPATIBLE_OBJECTS);
        return 0;
    }
    return group->meth->point_set_affine_coordinates(group, point, x, y, ctx);
}

#ifndef OPENSSL_NO_EC2M
int EC_POINT_set_affine_coordinates_GF2m(const EC_GROUP *group,
                                         EC_POINT *point, const BIGNUM *x,
                                         const BIGNUM *y, BN_CTX *ctx)
{
    if (group->meth->point_set_affine_coordinates == 0) {
        ECerr(EC_F_EC_POINT_SET_AFFINE_COORDINATES_GF2M,
              ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }
    if (group->meth != point->meth) {
        ECerr(EC_F_EC_POINT_SET_AFFINE_COORDINATES_GF2M,
              EC_R_INCOMPATIBLE_OBJECTS);
        return 0;
    }
    return group->meth->point_set_affine_coordinates(group, point, x, y, ctx);
}
#endif

int EC_POINT_get_affine_coordinates_GFp(const EC_GROUP *group,
                                        const EC_POINT *point, BIGNUM *x,
                                        BIGNUM *y, BN_CTX *ctx)
{
    if (group->meth->point_get_affine_coordinates == 0) {
        ECerr(EC_F_EC_POINT_GET_AFFINE_COORDINATES_GFP,
              ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }
    if (group->meth != point->meth) {
        ECerr(EC_F_EC_POINT_GET_AFFINE_COORDINATES_GFP,
              EC_R_INCOMPATIBLE_OBJECTS);
        return 0;
    }
    return group->meth->point_get_affine_coordinates(group, point, x, y, ctx);
}

#ifndef OPENSSL_NO_EC2M
int EC_POINT_get_affine_coordinates_GF2m(const EC_GROUP *group,
                                         const EC_POINT *point, BIGNUM *x,
                                         BIGNUM *y, BN_CTX *ctx)
{
    if (group->meth->point_get_affine_coordinates == 0) {
        ECerr(EC_F_EC_POINT_GET_AFFINE_COORDINATES_GF2M,
              ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }
    if (group->meth != point->meth) {
        ECerr(EC_F_EC_POINT_GET_AFFINE_COORDINATES_GF2M,
              EC_R_INCOMPATIBLE_OBJECTS);
        return 0;
    }
    return group->meth->point_get_affine_coordinates(group, point, x, y, ctx);
}
#endif

int EC_POINT_add(const EC_GROUP *group, EC_POINT *r, const EC_POINT *a,
                 const EC_POINT *b, BN_CTX *ctx)
{
    if (group->meth->add == 0) {
        ECerr(EC_F_EC_POINT_ADD, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }
    if ((group->meth != r->meth) || (r->meth != a->meth)
        || (a->meth != b->meth)) {
        ECerr(EC_F_EC_POINT_ADD, EC_R_INCOMPATIBLE_OBJECTS);
        return 0;
    }
    return group->meth->add(group, r, a, b, ctx);
}

int EC_POINT_dbl(const EC_GROUP *group, EC_POINT *r, const EC_POINT *a,
                 BN_CTX *ctx)
{
    if (group->meth->dbl == 0) {
        ECerr(EC_F_EC_POINT_DBL, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }
    if ((group->meth != r->meth) || (r->meth != a->meth)) {
        ECerr(EC_F_EC_POINT_DBL, EC_R_INCOMPATIBLE_OBJECTS);
        return 0;
    }
    return group->meth->dbl(group, r, a, ctx);
}

int EC_POINT_invert(const EC_GROUP *group, EC_POINT *a, BN_CTX *ctx)
{
    if (group->meth->invert == 0) {
        ECerr(EC_F_EC_POINT_INVERT, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }
    if (group->meth != a->meth) {
        ECerr(EC_F_EC_POINT_INVERT, EC_R_INCOMPATIBLE_OBJECTS);
        return 0;
    }
    return group->meth->invert(group, a, ctx);
}

int EC_POINT_is_at_infinity(const EC_GROUP *group, const EC_POINT *point)
{
    if (group->meth->is_at_infinity == 0) {
        ECerr(EC_F_EC_POINT_IS_AT_INFINITY,
              ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }
    if (group->meth != point->meth) {
        ECerr(EC_F_EC_POINT_IS_AT_INFINITY, EC_R_INCOMPATIBLE_OBJECTS);
        return 0;
    }
    return group->meth->is_at_infinity(group, point);
}

/*
 * Check whether an EC_POINT is on the curve or not. Note that the return
 * value for this function should NOT be treated as a boolean. Return values:
 *  1: The point is on the curve
 *  0: The point is not on the curve
 * -1: An error occurred
 */
int EC_POINT_is_on_curve(const EC_GROUP *group, const EC_POINT *point,
                         BN_CTX *ctx)
{
    if (group->meth->is_on_curve == 0) {
        ECerr(EC_F_EC_POINT_IS_ON_CURVE, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }
    if (group->meth != point->meth) {
        ECerr(EC_F_EC_POINT_IS_ON_CURVE, EC_R_INCOMPATIBLE_OBJECTS);
        return 0;
    }
    return group->meth->is_on_curve(group, point, ctx);
}

int EC_POINT_cmp(const EC_GROUP *group, const EC_POINT *a, const EC_POINT *b,
                 BN_CTX *ctx)
{
    if (group->meth->point_cmp == 0) {
        ECerr(EC_F_EC_POINT_CMP, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return -1;
    }
    if ((group->meth != a->meth) || (a->meth != b->meth)) {
        ECerr(EC_F_EC_POINT_CMP, EC_R_INCOMPATIBLE_OBJECTS);
        return -1;
    }
    return group->meth->point_cmp(group, a, b, ctx);
}

int EC_POINT_make_affine(const EC_GROUP *group, EC_POINT *point, BN_CTX *ctx)
{
    if (group->meth->make_affine == 0) {
        ECerr(EC_F_EC_POINT_MAKE_AFFINE, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }
    if (group->meth != point->meth) {
        ECerr(EC_F_EC_POINT_MAKE_AFFINE, EC_R_INCOMPATIBLE_OBJECTS);
        return 0;
    }
    return group->meth->make_affine(group, point, ctx);
}

int EC_POINTs_make_affine(const EC_GROUP *group, size_t num,
                          EC_POINT *points[], BN_CTX *ctx)
{
    size_t i;

    if (group->meth->points_make_affine == 0) {
        ECerr(EC_F_EC_POINTS_MAKE_AFFINE, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }
    for (i = 0; i < num; i++) {
        if (group->meth != points[i]->meth) {
            ECerr(EC_F_EC_POINTS_MAKE_AFFINE, EC_R_INCOMPATIBLE_OBJECTS);
            return 0;
        }
    }
    return group->meth->points_make_affine(group, num, points, ctx);
}

/*
 * Functions for point multiplication. If group->meth->mul is 0, we use the
 * wNAF-based implementations in ec_mult.c; otherwise we dispatch through
 * methods.
 */

int EC_POINTs_mul(const EC_GROUP *group, EC_POINT *r, const BIGNUM *scalar,
                  size_t num, const EC_POINT *points[],
                  const BIGNUM *scalars[], BN_CTX *ctx)
{
    if (group->meth->mul == 0)
        /* use default */
        return ec_wNAF_mul(group, r, scalar, num, points, scalars, ctx);

    return group->meth->mul(group, r, scalar, num, points, scalars, ctx);
}

int EC_POINT_mul(const EC_GROUP *group, EC_POINT *r, const BIGNUM *g_scalar,
                 const EC_POINT *point, const BIGNUM *p_scalar, BN_CTX *ctx)
{
    /* just a convenient interface to EC_POINTs_mul() */

    const EC_POINT *points[1];
    const BIGNUM *scalars[1];

    points[0] = point;
    scalars[0] = p_scalar;

    return EC_POINTs_mul(group, r, g_scalar,
                         (point != NULL
                          && p_scalar != NULL), points, scalars, ctx);
}

int EC_GROUP_precompute_mult(EC_GROUP *group, BN_CTX *ctx)
{
    if (group->meth->mul == 0)
        /* use default */
        return ec_wNAF_precompute_mult(group, ctx);

    if (group->meth->precompute_mult != 0)
        return group->meth->precompute_mult(group, ctx);
    else
        return 1;               /* nothing to do, so report success */
}

int EC_GROUP_have_precompute_mult(const EC_GROUP *group)
{
    if (group->meth->mul == 0)
        /* use default */
        return ec_wNAF_have_precompute_mult(group);

    if (group->meth->have_precompute_mult != 0)
        return group->meth->have_precompute_mult(group);
    else
        return 0;               /* cannot tell whether precomputation has
                                 * been performed */
}

/*-
 * ec_precompute_mont_data sets |group->mont_data| from |group->order| and
 * returns one on success. On error it returns zero.
 *
 * Note: this function must be called only after verifying that
 * EC_GROUP_VERSION(group) returns true.
 * The reason for this is that access to the `mont_data` field of an EC_GROUP
 * struct should always be guarded by an EC_GROUP_VERSION(group) check to avoid
 * OOB accesses, as the group might come from the FIPS module, which does not
 * define the `mont_data` field inside the EC_GROUP structure.
 */
static
int ec_precompute_mont_data(EC_GROUP *group)
{
    BN_CTX *ctx = BN_CTX_new();
    int ret = 0;

    if (group->mont_data) {
        BN_MONT_CTX_free(group->mont_data);
        group->mont_data = NULL;
    }

    if (ctx == NULL)
        goto err;

    group->mont_data = BN_MONT_CTX_new();
    if (!group->mont_data)
        goto err;

    if (!BN_MONT_CTX_set(group->mont_data, &group->order, ctx)) {
        BN_MONT_CTX_free(group->mont_data);
        group->mont_data = NULL;
        goto err;
    }

    ret = 1;

 err:

    if (ctx)
        BN_CTX_free(ctx);
    return ret;
}
/* crypto/ec/ec_mult.c */
/*
 * Originally written by Bodo Moeller and Nils Larsch for the OpenSSL project.
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
/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 * Portions of this software developed by SUN MICROSYSTEMS, INC.,
 * and contributed to the OpenSSL project.
 */

#include <string.h>

// #include "err.h"

// #include "ec_lcl.h"

/*
 * This file implements the wNAF-based interleaving multi-exponentiation method
 * Formerly at:
 *   http://www.informatik.tu-darmstadt.de/TI/Mitarbeiter/moeller.html#multiexp
 * You might now find it here:
 *   http://link.springer.com/chapter/10.1007%2F3-540-45537-X_13
 *   http://www.bmoeller.de/pdf/TI-01-08.multiexp.pdf
 * For multiplication with precomputation, we use wNAF splitting, formerly at:
 *   http://www.informatik.tu-darmstadt.de/TI/Mitarbeiter/moeller.html#fastexp
 */

/* structure for precomputed multiples of the generator */
typedef struct ec_pre_comp_st {
    const EC_GROUP *group;      /* parent EC_GROUP object */
    size_t blocksize;           /* block size for wNAF splitting */
    size_t numblocks;           /* max. number of blocks for which we have
                                 * precomputation */
    size_t w;                   /* window size */
    EC_POINT **points;          /* array with pre-calculated multiples of
                                 * generator: 'num' pointers to EC_POINT
                                 * objects followed by a NULL */
    size_t num;                 /* numblocks * 2^(w-1) */
    int references;
} EC_PRE_COMP;

/* functions to manage EC_PRE_COMP within the EC_GROUP extra_data framework */
static void *ec_pre_comp_dup(void *);
static void ec_pre_comp_free(void *);
static void ec_pre_comp_clear_free(void *);

static EC_PRE_COMP *ec_pre_comp_new(const EC_GROUP *group)
{
    EC_PRE_COMP *ret = NULL;

    if (!group)
        return NULL;

    ret = (EC_PRE_COMP *)OPENSSL_malloc(sizeof(EC_PRE_COMP));
    if (!ret) {
        ECerr(EC_F_EC_PRE_COMP_NEW, ERR_R_MALLOC_FAILURE);
        return ret;
    }
    ret->group = group;
    ret->blocksize = 8;         /* default */
    ret->numblocks = 0;
    ret->w = 4;                 /* default */
    ret->points = NULL;
    ret->num = 0;
    ret->references = 1;
    return ret;
}

static void *ec_pre_comp_dup(void *src_)
{
    EC_PRE_COMP *src = src_;

    /* no need to actually copy, these objects never change! */

    CRYPTO_add(&src->references, 1, CRYPTO_LOCK_EC_PRE_COMP);

    return src_;
}

static void ec_pre_comp_free(void *pre_)
{
    int i;
    EC_PRE_COMP *pre = pre_;

    if (!pre)
        return;

    i = CRYPTO_add(&pre->references, -1, CRYPTO_LOCK_EC_PRE_COMP);
    if (i > 0)
        return;

    if (pre->points) {
        EC_POINT **p;

        for (p = pre->points; *p != NULL; p++)
            EC_POINT_free(*p);
        OPENSSL_free(pre->points);
    }
    OPENSSL_free(pre);
}

static void ec_pre_comp_clear_free(void *pre_)
{
    int i;
    EC_PRE_COMP *pre = pre_;

    if (!pre)
        return;

    i = CRYPTO_add(&pre->references, -1, CRYPTO_LOCK_EC_PRE_COMP);
    if (i > 0)
        return;

    if (pre->points) {
        EC_POINT **p;

        for (p = pre->points; *p != NULL; p++) {
            EC_POINT_clear_free(*p);
            OPENSSL_cleanse(p, sizeof(*p));
        }
        OPENSSL_free(pre->points);
    }
    OPENSSL_cleanse(pre, sizeof(*pre));
    OPENSSL_free(pre);
}

/*-
 * Determine the modified width-(w+1) Non-Adjacent Form (wNAF) of 'scalar'.
 * This is an array  r[]  of values that are either zero or odd with an
 * absolute value less than  2^w  satisfying
 *     scalar = \sum_j r[j]*2^j
 * where at most one of any  w+1  consecutive digits is non-zero
 * with the exception that the most significant digit may be only
 * w-1 zeros away from that next non-zero digit.
 */
static signed char *compute_wNAF(const BIGNUM *scalar, int w, size_t *ret_len)
{
    int window_val;
    int ok = 0;
    signed char *r = NULL;
    int sign = 1;
    int bit, next_bit, mask;
    size_t len = 0, j;

    if (BN_is_zero(scalar)) {
        r = OPENSSL_malloc(1);
        if (!r) {
            ECerr(EC_F_COMPUTE_WNAF, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        r[0] = 0;
        *ret_len = 1;
        return r;
    }

    if (w <= 0 || w > 7) {      /* 'signed char' can represent integers with
                                 * absolute values less than 2^7 */
        ECerr(EC_F_COMPUTE_WNAF, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    bit = 1 << w;               /* at most 128 */
    next_bit = bit << 1;        /* at most 256 */
    mask = next_bit - 1;        /* at most 255 */

    if (BN_is_negative(scalar)) {
        sign = -1;
    }

    if (scalar->d == NULL || scalar->top == 0) {
        ECerr(EC_F_COMPUTE_WNAF, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    len = BN_num_bits(scalar);
    r = OPENSSL_malloc(len + 1); /* modified wNAF may be one digit longer
                                  * than binary representation (*ret_len will
                                  * be set to the actual length, i.e. at most
                                  * BN_num_bits(scalar) + 1) */
    if (r == NULL) {
        ECerr(EC_F_COMPUTE_WNAF, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    window_val = scalar->d[0] & mask;
    j = 0;
    while ((window_val != 0) || (j + w + 1 < len)) { /* if j+w+1 >= len,
                                                      * window_val will not
                                                      * increase */
        int digit = 0;

        /* 0 <= window_val <= 2^(w+1) */

        if (window_val & 1) {
            /* 0 < window_val < 2^(w+1) */

            if (window_val & bit) {
                digit = window_val - next_bit; /* -2^w < digit < 0 */

#if 1                           /* modified wNAF */
                if (j + w + 1 >= len) {
                    /*
                     * special case for generating modified wNAFs: no new
                     * bits will be added into window_val, so using a
                     * positive digit here will decrease the total length of
                     * the representation
                     */

                    digit = window_val & (mask >> 1); /* 0 < digit < 2^w */
                }
#endif
            } else {
                digit = window_val; /* 0 < digit < 2^w */
            }

            if (digit <= -bit || digit >= bit || !(digit & 1)) {
                ECerr(EC_F_COMPUTE_WNAF, ERR_R_INTERNAL_ERROR);
                goto err;
            }

            window_val -= digit;

            /*
             * now window_val is 0 or 2^(w+1) in standard wNAF generation;
             * for modified window NAFs, it may also be 2^w
             */
            if (window_val != 0 && window_val != next_bit
                && window_val != bit) {
                ECerr(EC_F_COMPUTE_WNAF, ERR_R_INTERNAL_ERROR);
                goto err;
            }
        }

        r[j++] = sign * digit;

        window_val >>= 1;
        window_val += bit * BN_is_bit_set(scalar, j + w);

        if (window_val > next_bit) {
            ECerr(EC_F_COMPUTE_WNAF, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    }

    if (j > len + 1) {
        ECerr(EC_F_COMPUTE_WNAF, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    len = j;
    ok = 1;

 err:
    if (!ok) {
        OPENSSL_free(r);
        r = NULL;
    }
    if (ok)
        *ret_len = len;
    return r;
}

#define EC_POINT_BN_set_flags(P, flags) do { \
    BN_set_flags(&(P)->X, (flags)); \
    BN_set_flags(&(P)->Y, (flags)); \
    BN_set_flags(&(P)->Z, (flags)); \
} while(0)

/*-
 * This functions computes (in constant time) a point multiplication over the
 * EC group.
 *
 * At a high level, it is Montgomery ladder with conditional swaps.
 *
 * It performs either a fixed scalar point multiplication
 *          (scalar * generator)
 * when point is NULL, or a generic scalar point multiplication
 *          (scalar * point)
 * when point is not NULL.
 *
 * scalar should be in the range [0,n) otherwise all constant time bets are off.
 *
 * NB: This says nothing about EC_POINT_add and EC_POINT_dbl,
 * which of course are not constant time themselves.
 *
 * The product is stored in r.
 *
 * Returns 1 on success, 0 otherwise.
 */
static int ec_mul_consttime(const EC_GROUP *group, EC_POINT *r,
                            const BIGNUM *scalar, const EC_POINT *point,
                            BN_CTX *ctx)
{
    int i, cardinality_bits, group_top, kbit, pbit, Z_is_one;
    EC_POINT *s = NULL;
    BIGNUM *k = NULL;
    BIGNUM *lambda = NULL;
    BIGNUM *cardinality = NULL;
    BN_CTX *new_ctx = NULL;
    int ret = 0;

    if (ctx == NULL && (ctx = new_ctx = BN_CTX_new()) == NULL)
        return 0;

    BN_CTX_start(ctx);

    s = EC_POINT_new(group);
    if (s == NULL)
        goto err;

    if (point == NULL) {
        if (!EC_POINT_copy(s, group->generator))
            goto err;
    } else {
        if (!EC_POINT_copy(s, point))
            goto err;
    }

    EC_POINT_BN_set_flags(s, BN_FLG_CONSTTIME);

    cardinality = BN_CTX_get(ctx);
    lambda = BN_CTX_get(ctx);
    k = BN_CTX_get(ctx);
    if (k == NULL || !BN_mul(cardinality, &group->order, &group->cofactor, ctx))
        goto err;

    /*
     * Group cardinalities are often on a word boundary.
     * So when we pad the scalar, some timing diff might
     * pop if it needs to be expanded due to carries.
     * So expand ahead of time.
     */
    cardinality_bits = BN_num_bits(cardinality);
    group_top = cardinality->top;
    if ((bn_wexpand(k, group_top + 2) == NULL)
        || (bn_wexpand(lambda, group_top + 2) == NULL))
        goto err;

    if (!BN_copy(k, scalar))
        goto err;

    BN_set_flags(k, BN_FLG_CONSTTIME);

    if ((BN_num_bits(k) > cardinality_bits) || (BN_is_negative(k))) {
        /*-
         * this is an unusual input, and we don't guarantee
         * constant-timeness
         */
        if (!BN_nnmod(k, k, cardinality, ctx))
            goto err;
    }

    if (!BN_add(lambda, k, cardinality))
        goto err;
    BN_set_flags(lambda, BN_FLG_CONSTTIME);
    if (!BN_add(k, lambda, cardinality))
        goto err;
    /*
     * lambda := scalar + cardinality
     * k := scalar + 2*cardinality
     */
    kbit = BN_is_bit_set(lambda, cardinality_bits);
    BN_consttime_swap(kbit, k, lambda, group_top + 2);

    group_top = group->field.top;
    if ((bn_wexpand(&s->X, group_top) == NULL)
        || (bn_wexpand(&s->Y, group_top) == NULL)
        || (bn_wexpand(&s->Z, group_top) == NULL)
        || (bn_wexpand(&r->X, group_top) == NULL)
        || (bn_wexpand(&r->Y, group_top) == NULL)
        || (bn_wexpand(&r->Z, group_top) == NULL))
        goto err;

    /* top bit is a 1, in a fixed pos */
    if (!EC_POINT_copy(r, s))
        goto err;

    EC_POINT_BN_set_flags(r, BN_FLG_CONSTTIME);

    if (!EC_POINT_dbl(group, s, s, ctx))
        goto err;

    pbit = 0;

#define EC_POINT_CSWAP(c, a, b, w, t) do {         \
        BN_consttime_swap(c, &(a)->X, &(b)->X, w); \
        BN_consttime_swap(c, &(a)->Y, &(b)->Y, w); \
        BN_consttime_swap(c, &(a)->Z, &(b)->Z, w); \
        t = ((a)->Z_is_one ^ (b)->Z_is_one) & (c); \
        (a)->Z_is_one ^= (t);                      \
        (b)->Z_is_one ^= (t);                      \
} while(0)

    /*-
     * The ladder step, with branches, is
     *
     * k[i] == 0: S = add(R, S), R = dbl(R)
     * k[i] == 1: R = add(S, R), S = dbl(S)
     *
     * Swapping R, S conditionally on k[i] leaves you with state
     *
     * k[i] == 0: T, U = R, S
     * k[i] == 1: T, U = S, R
     *
     * Then perform the ECC ops.
     *
     * U = add(T, U)
     * T = dbl(T)
     *
     * Which leaves you with state
     *
     * k[i] == 0: U = add(R, S), T = dbl(R)
     * k[i] == 1: U = add(S, R), T = dbl(S)
     *
     * Swapping T, U conditionally on k[i] leaves you with state
     *
     * k[i] == 0: R, S = T, U
     * k[i] == 1: R, S = U, T
     *
     * Which leaves you with state
     *
     * k[i] == 0: S = add(R, S), R = dbl(R)
     * k[i] == 1: R = add(S, R), S = dbl(S)
     *
     * So we get the same logic, but instead of a branch it's a
     * conditional swap, followed by ECC ops, then another conditional swap.
     *
     * Optimization: The end of iteration i and start of i-1 looks like
     *
     * ...
     * CSWAP(k[i], R, S)
     * ECC
     * CSWAP(k[i], R, S)
     * (next iteration)
     * CSWAP(k[i-1], R, S)
     * ECC
     * CSWAP(k[i-1], R, S)
     * ...
     *
     * So instead of two contiguous swaps, you can merge the condition
     * bits and do a single swap.
     *
     * k[i]   k[i-1]    Outcome
     * 0      0         No Swap
     * 0      1         Swap
     * 1      0         Swap
     * 1      1         No Swap
     *
     * This is XOR. pbit tracks the previous bit of k.
     */

    for (i = cardinality_bits - 1; i >= 0; i--) {
        kbit = BN_is_bit_set(k, i) ^ pbit;
        EC_POINT_CSWAP(kbit, r, s, group_top, Z_is_one);
        if (!EC_POINT_add(group, s, r, s, ctx))
            goto err;
        if (!EC_POINT_dbl(group, r, r, ctx))
            goto err;
        /*
         * pbit logic merges this cswap with that of the
         * next iteration
         */
        pbit ^= kbit;
    }
    /* one final cswap to move the right value into r */
    EC_POINT_CSWAP(pbit, r, s, group_top, Z_is_one);
#undef EC_POINT_CSWAP

    ret = 1;

 err:
    EC_POINT_free(s);
    BN_CTX_end(ctx);
    BN_CTX_free(new_ctx);

    return ret;
}

#undef EC_POINT_BN_set_flags

/*
 * TODO: table should be optimised for the wNAF-based implementation,
 * sometimes smaller windows will give better performance (thus the
 * boundaries should be increased)
 */
#define EC_window_bits_for_scalar_size(b) \
                ((size_t) \
                 ((b) >= 2000 ? 6 : \
                  (b) >=  800 ? 5 : \
                  (b) >=  300 ? 4 : \
                  (b) >=   70 ? 3 : \
                  (b) >=   20 ? 2 : \
                  1))

/*-
 * Compute
 *      \sum scalars[i]*points[i],
 * also including
 *      scalar*generator
 * in the addition if scalar != NULL
 */
int ec_wNAF_mul(const EC_GROUP *group, EC_POINT *r, const BIGNUM *scalar,
                size_t num, const EC_POINT *points[], const BIGNUM *scalars[],
                BN_CTX *ctx)
{
    BN_CTX *new_ctx = NULL;
    const EC_POINT *generator = NULL;
    EC_POINT *tmp = NULL;
    size_t totalnum;
    size_t blocksize = 0, numblocks = 0; /* for wNAF splitting */
    size_t pre_points_per_block = 0;
    size_t i, j;
    int k;
    int r_is_inverted = 0;
    int r_is_at_infinity = 1;
    size_t *wsize = NULL;       /* individual window sizes */
    signed char **wNAF = NULL;  /* individual wNAFs */
    size_t *wNAF_len = NULL;
    size_t max_len = 0;
    size_t num_val;
    EC_POINT **val = NULL;      /* precomputation */
    EC_POINT **v;
    EC_POINT ***val_sub = NULL; /* pointers to sub-arrays of 'val' or
                                 * 'pre_comp->points' */
    const EC_PRE_COMP *pre_comp = NULL;
    int num_scalar = 0;         /* flag: will be set to 1 if 'scalar' must be
                                 * treated like other scalars, i.e.
                                 * precomputation is not available */
    int ret = 0;

    if (group->meth != r->meth) {
        ECerr(EC_F_EC_WNAF_MUL, EC_R_INCOMPATIBLE_OBJECTS);
        return 0;
    }

    if ((scalar == NULL) && (num == 0)) {
        return EC_POINT_set_to_infinity(group, r);
    }

    if (!BN_is_zero(&group->order) && !BN_is_zero(&group->cofactor)) {
        /*-
         * Handle the common cases where the scalar is secret, enforcing a constant
         * time scalar multiplication algorithm.
         */
        if ((scalar != NULL) && (num == 0)) {
            /*-
             * In this case we want to compute scalar * GeneratorPoint: this
             * codepath is reached most prominently by (ephemeral) key generation
             * of EC cryptosystems (i.e. ECDSA keygen and sign setup, ECDH
             * keygen/first half), where the scalar is always secret. This is why
             * we ignore if BN_FLG_CONSTTIME is actually set and we always call the
             * constant time version.
             */
            return ec_mul_consttime(group, r, scalar, NULL, ctx);
        }
        if ((scalar == NULL) && (num == 1)) {
            /*-
             * In this case we want to compute scalar * GenericPoint: this codepath
             * is reached most prominently by the second half of ECDH, where the
             * secret scalar is multiplied by the peer's public point. To protect
             * the secret scalar, we ignore if BN_FLG_CONSTTIME is actually set and
             * we always call the constant time version.
             */
            return ec_mul_consttime(group, r, scalars[0], points[0], ctx);
        }
    }

    for (i = 0; i < num; i++) {
        if (group->meth != points[i]->meth) {
            ECerr(EC_F_EC_WNAF_MUL, EC_R_INCOMPATIBLE_OBJECTS);
            return 0;
        }
    }

    if (ctx == NULL) {
        ctx = new_ctx = BN_CTX_new();
        if (ctx == NULL)
            goto err;
    }

    if (scalar != NULL) {
        generator = EC_GROUP_get0_generator(group);
        if (generator == NULL) {
            ECerr(EC_F_EC_WNAF_MUL, EC_R_UNDEFINED_GENERATOR);
            goto err;
        }

        /* look if we can use precomputed multiples of generator */

        pre_comp =
            EC_EX_DATA_get_data(group->extra_data, ec_pre_comp_dup,
                                ec_pre_comp_free, ec_pre_comp_clear_free);

        if (pre_comp && pre_comp->numblocks
            && (EC_POINT_cmp(group, generator, pre_comp->points[0], ctx) ==
                0)) {
            blocksize = pre_comp->blocksize;

            /*
             * determine maximum number of blocks that wNAF splitting may
             * yield (NB: maximum wNAF length is bit length plus one)
             */
            numblocks = (BN_num_bits(scalar) / blocksize) + 1;

            /*
             * we cannot use more blocks than we have precomputation for
             */
            if (numblocks > pre_comp->numblocks)
                numblocks = pre_comp->numblocks;

            pre_points_per_block = (size_t)1 << (pre_comp->w - 1);

            /* check that pre_comp looks sane */
            if (pre_comp->num != (pre_comp->numblocks * pre_points_per_block)) {
                ECerr(EC_F_EC_WNAF_MUL, ERR_R_INTERNAL_ERROR);
                goto err;
            }
        } else {
            /* can't use precomputation */
            pre_comp = NULL;
            numblocks = 1;
            num_scalar = 1;     /* treat 'scalar' like 'num'-th element of
                                 * 'scalars' */
        }
    }

    totalnum = num + numblocks;

    wsize = OPENSSL_malloc(totalnum * sizeof(wsize[0]));
    wNAF_len = OPENSSL_malloc(totalnum * sizeof(wNAF_len[0]));
    /* include space for pivot */
    wNAF = OPENSSL_malloc((totalnum + 1) * sizeof(wNAF[0]));
    val_sub = OPENSSL_malloc(totalnum * sizeof(val_sub[0]));

    /* Ensure wNAF is initialised in case we end up going to err */
    if (wNAF)
        wNAF[0] = NULL;         /* preliminary pivot */

    if (!wsize || !wNAF_len || !wNAF || !val_sub) {
        ECerr(EC_F_EC_WNAF_MUL, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    /*
     * num_val will be the total number of temporarily precomputed points
     */
    num_val = 0;

    for (i = 0; i < num + num_scalar; i++) {
        size_t bits;

        bits = i < num ? BN_num_bits(scalars[i]) : BN_num_bits(scalar);
        wsize[i] = EC_window_bits_for_scalar_size(bits);
        num_val += (size_t)1 << (wsize[i] - 1);
        wNAF[i + 1] = NULL;     /* make sure we always have a pivot */
        wNAF[i] =
            compute_wNAF((i < num ? scalars[i] : scalar), wsize[i],
                         &wNAF_len[i]);
        if (wNAF[i] == NULL)
            goto err;
        if (wNAF_len[i] > max_len)
            max_len = wNAF_len[i];
    }

    if (numblocks) {
        /* we go here iff scalar != NULL */

        if (pre_comp == NULL) {
            if (num_scalar != 1) {
                ECerr(EC_F_EC_WNAF_MUL, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            /* we have already generated a wNAF for 'scalar' */
        } else {
            signed char *tmp_wNAF = NULL;
            size_t tmp_len = 0;

            if (num_scalar != 0) {
                ECerr(EC_F_EC_WNAF_MUL, ERR_R_INTERNAL_ERROR);
                goto err;
            }

            /*
             * use the window size for which we have precomputation
             */
            wsize[num] = pre_comp->w;
            tmp_wNAF = compute_wNAF(scalar, wsize[num], &tmp_len);
            if (!tmp_wNAF)
                goto err;

            if (tmp_len <= max_len) {
                /*
                 * One of the other wNAFs is at least as long as the wNAF
                 * belonging to the generator, so wNAF splitting will not buy
                 * us anything.
                 */

                numblocks = 1;
                totalnum = num + 1; /* don't use wNAF splitting */
                wNAF[num] = tmp_wNAF;
                wNAF[num + 1] = NULL;
                wNAF_len[num] = tmp_len;
                if (tmp_len > max_len)
                    max_len = tmp_len;
                /*
                 * pre_comp->points starts with the points that we need here:
                 */
                val_sub[num] = pre_comp->points;
            } else {
                /*
                 * don't include tmp_wNAF directly into wNAF array - use wNAF
                 * splitting and include the blocks
                 */

                signed char *pp;
                EC_POINT **tmp_points;

                if (tmp_len < numblocks * blocksize) {
                    /*
                     * possibly we can do with fewer blocks than estimated
                     */
                    numblocks = (tmp_len + blocksize - 1) / blocksize;
                    if (numblocks > pre_comp->numblocks) {
                        ECerr(EC_F_EC_WNAF_MUL, ERR_R_INTERNAL_ERROR);
                        goto err;
                    }
                    totalnum = num + numblocks;
                }

                /* split wNAF in 'numblocks' parts */
                pp = tmp_wNAF;
                tmp_points = pre_comp->points;

                for (i = num; i < totalnum; i++) {
                    if (i < totalnum - 1) {
                        wNAF_len[i] = blocksize;
                        if (tmp_len < blocksize) {
                            ECerr(EC_F_EC_WNAF_MUL, ERR_R_INTERNAL_ERROR);
                            goto err;
                        }
                        tmp_len -= blocksize;
                    } else
                        /*
                         * last block gets whatever is left (this could be
                         * more or less than 'blocksize'!)
                         */
                        wNAF_len[i] = tmp_len;

                    wNAF[i + 1] = NULL;
                    wNAF[i] = OPENSSL_malloc(wNAF_len[i]);
                    if (wNAF[i] == NULL) {
                        ECerr(EC_F_EC_WNAF_MUL, ERR_R_MALLOC_FAILURE);
                        OPENSSL_free(tmp_wNAF);
                        goto err;
                    }
                    memcpy(wNAF[i], pp, wNAF_len[i]);
                    if (wNAF_len[i] > max_len)
                        max_len = wNAF_len[i];

                    if (*tmp_points == NULL) {
                        ECerr(EC_F_EC_WNAF_MUL, ERR_R_INTERNAL_ERROR);
                        OPENSSL_free(tmp_wNAF);
                        goto err;
                    }
                    val_sub[i] = tmp_points;
                    tmp_points += pre_points_per_block;
                    pp += blocksize;
                }
                OPENSSL_free(tmp_wNAF);
            }
        }
    }

    /*
     * All points we precompute now go into a single array 'val'.
     * 'val_sub[i]' is a pointer to the subarray for the i-th point, or to a
     * subarray of 'pre_comp->points' if we already have precomputation.
     */
    val = OPENSSL_malloc((num_val + 1) * sizeof(val[0]));
    if (val == NULL) {
        ECerr(EC_F_EC_WNAF_MUL, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    val[num_val] = NULL;        /* pivot element */

    /* allocate points for precomputation */
    v = val;
    for (i = 0; i < num + num_scalar; i++) {
        val_sub[i] = v;
        for (j = 0; j < ((size_t)1 << (wsize[i] - 1)); j++) {
            *v = EC_POINT_new(group);
            if (*v == NULL)
                goto err;
            v++;
        }
    }
    if (!(v == val + num_val)) {
        ECerr(EC_F_EC_WNAF_MUL, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    if (!(tmp = EC_POINT_new(group)))
        goto err;

    /*-
     * prepare precomputed values:
     *    val_sub[i][0] :=     points[i]
     *    val_sub[i][1] := 3 * points[i]
     *    val_sub[i][2] := 5 * points[i]
     *    ...
     */
    for (i = 0; i < num + num_scalar; i++) {
        if (i < num) {
            if (!EC_POINT_copy(val_sub[i][0], points[i]))
                goto err;
        } else {
            if (!EC_POINT_copy(val_sub[i][0], generator))
                goto err;
        }

        if (wsize[i] > 1) {
            if (!EC_POINT_dbl(group, tmp, val_sub[i][0], ctx))
                goto err;
            for (j = 1; j < ((size_t)1 << (wsize[i] - 1)); j++) {
                if (!EC_POINT_add
                    (group, val_sub[i][j], val_sub[i][j - 1], tmp, ctx))
                    goto err;
            }
        }
    }

#if 1                           /* optional; EC_window_bits_for_scalar_size
                                 * assumes we do this step */
    if (!EC_POINTs_make_affine(group, num_val, val, ctx))
        goto err;
#endif

    r_is_at_infinity = 1;

    for (k = max_len - 1; k >= 0; k--) {
        if (!r_is_at_infinity) {
            if (!EC_POINT_dbl(group, r, r, ctx))
                goto err;
        }

        for (i = 0; i < totalnum; i++) {
            if (wNAF_len[i] > (size_t)k) {
                int digit = wNAF[i][k];
                int is_neg;

                if (digit) {
                    is_neg = digit < 0;

                    if (is_neg)
                        digit = -digit;

                    if (is_neg != r_is_inverted) {
                        if (!r_is_at_infinity) {
                            if (!EC_POINT_invert(group, r, ctx))
                                goto err;
                        }
                        r_is_inverted = !r_is_inverted;
                    }

                    /* digit > 0 */

                    if (r_is_at_infinity) {
                        if (!EC_POINT_copy(r, val_sub[i][digit >> 1]))
                            goto err;
                        r_is_at_infinity = 0;
                    } else {
                        if (!EC_POINT_add
                            (group, r, r, val_sub[i][digit >> 1], ctx))
                            goto err;
                    }
                }
            }
        }
    }

    if (r_is_at_infinity) {
        if (!EC_POINT_set_to_infinity(group, r))
            goto err;
    } else {
        if (r_is_inverted)
            if (!EC_POINT_invert(group, r, ctx))
                goto err;
    }

    ret = 1;

 err:
    if (new_ctx != NULL)
        BN_CTX_free(new_ctx);
    if (tmp != NULL)
        EC_POINT_free(tmp);
    if (wsize != NULL)
        OPENSSL_free(wsize);
    if (wNAF_len != NULL)
        OPENSSL_free(wNAF_len);
    if (wNAF != NULL) {
        signed char **w;

        for (w = wNAF; *w != NULL; w++)
            OPENSSL_free(*w);

        OPENSSL_free(wNAF);
    }
    if (val != NULL) {
        for (v = val; *v != NULL; v++)
            EC_POINT_clear_free(*v);

        OPENSSL_free(val);
    }
    if (val_sub != NULL) {
        OPENSSL_free(val_sub);
    }
    return ret;
}

/*-
 * ec_wNAF_precompute_mult()
 * creates an EC_PRE_COMP object with preprecomputed multiples of the generator
 * for use with wNAF splitting as implemented in ec_wNAF_mul().
 *
 * 'pre_comp->points' is an array of multiples of the generator
 * of the following form:
 * points[0] =     generator;
 * points[1] = 3 * generator;
 * ...
 * points[2^(w-1)-1] =     (2^(w-1)-1) * generator;
 * points[2^(w-1)]   =     2^blocksize * generator;
 * points[2^(w-1)+1] = 3 * 2^blocksize * generator;
 * ...
 * points[2^(w-1)*(numblocks-1)-1] = (2^(w-1)) *  2^(blocksize*(numblocks-2)) * generator
 * points[2^(w-1)*(numblocks-1)]   =              2^(blocksize*(numblocks-1)) * generator
 * ...
 * points[2^(w-1)*numblocks-1]     = (2^(w-1)) *  2^(blocksize*(numblocks-1)) * generator
 * points[2^(w-1)*numblocks]       = NULL
 */
int ec_wNAF_precompute_mult(EC_GROUP *group, BN_CTX *ctx)
{
    const EC_POINT *generator;
    EC_POINT *tmp_point = NULL, *base = NULL, **var;
    BN_CTX *new_ctx = NULL;
    BIGNUM *order;
    size_t i, bits, w, pre_points_per_block, blocksize, numblocks, num;
    EC_POINT **points = NULL;
    EC_PRE_COMP *pre_comp;
    int ret = 0;

    /* if there is an old EC_PRE_COMP object, throw it away */
    EC_EX_DATA_free_data(&group->extra_data, ec_pre_comp_dup,
                         ec_pre_comp_free, ec_pre_comp_clear_free);

    if ((pre_comp = ec_pre_comp_new(group)) == NULL)
        return 0;

    generator = EC_GROUP_get0_generator(group);
    if (generator == NULL) {
        ECerr(EC_F_EC_WNAF_PRECOMPUTE_MULT, EC_R_UNDEFINED_GENERATOR);
        goto err;
    }

    if (ctx == NULL) {
        ctx = new_ctx = BN_CTX_new();
        if (ctx == NULL)
            goto err;
    }

    BN_CTX_start(ctx);
    order = BN_CTX_get(ctx);
    if (order == NULL)
        goto err;

    if (!EC_GROUP_get_order(group, order, ctx))
        goto err;
    if (BN_is_zero(order)) {
        ECerr(EC_F_EC_WNAF_PRECOMPUTE_MULT, EC_R_UNKNOWN_ORDER);
        goto err;
    }

    bits = BN_num_bits(order);
    /*
     * The following parameters mean we precompute (approximately) one point
     * per bit. TBD: The combination 8, 4 is perfect for 160 bits; for other
     * bit lengths, other parameter combinations might provide better
     * efficiency.
     */
    blocksize = 8;
    w = 4;
    if (EC_window_bits_for_scalar_size(bits) > w) {
        /* let's not make the window too small ... */
        w = EC_window_bits_for_scalar_size(bits);
    }

    numblocks = (bits + blocksize - 1) / blocksize; /* max. number of blocks
                                                     * to use for wNAF
                                                     * splitting */

    pre_points_per_block = (size_t)1 << (w - 1);
    num = pre_points_per_block * numblocks; /* number of points to compute
                                             * and store */

    points = OPENSSL_malloc(sizeof(EC_POINT *) * (num + 1));
    if (!points) {
        ECerr(EC_F_EC_WNAF_PRECOMPUTE_MULT, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    var = points;
    var[num] = NULL;            /* pivot */
    for (i = 0; i < num; i++) {
        if ((var[i] = EC_POINT_new(group)) == NULL) {
            ECerr(EC_F_EC_WNAF_PRECOMPUTE_MULT, ERR_R_MALLOC_FAILURE);
            goto err;
        }
    }

    if (!(tmp_point = EC_POINT_new(group)) || !(base = EC_POINT_new(group))) {
        ECerr(EC_F_EC_WNAF_PRECOMPUTE_MULT, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (!EC_POINT_copy(base, generator))
        goto err;

    /* do the precomputation */
    for (i = 0; i < numblocks; i++) {
        size_t j;

        if (!EC_POINT_dbl(group, tmp_point, base, ctx))
            goto err;

        if (!EC_POINT_copy(*var++, base))
            goto err;

        for (j = 1; j < pre_points_per_block; j++, var++) {
            /*
             * calculate odd multiples of the current base point
             */
            if (!EC_POINT_add(group, *var, tmp_point, *(var - 1), ctx))
                goto err;
        }

        if (i < numblocks - 1) {
            /*
             * get the next base (multiply current one by 2^blocksize)
             */
            size_t k;

            if (blocksize <= 2) {
                ECerr(EC_F_EC_WNAF_PRECOMPUTE_MULT, ERR_R_INTERNAL_ERROR);
                goto err;
            }

            if (!EC_POINT_dbl(group, base, tmp_point, ctx))
                goto err;
            for (k = 2; k < blocksize; k++) {
                if (!EC_POINT_dbl(group, base, base, ctx))
                    goto err;
            }
        }
    }

    if (!EC_POINTs_make_affine(group, num, points, ctx))
        goto err;

    pre_comp->group = group;
    pre_comp->blocksize = blocksize;
    pre_comp->numblocks = numblocks;
    pre_comp->w = w;
    pre_comp->points = points;
    points = NULL;
    pre_comp->num = num;

    if (!EC_EX_DATA_set_data(&group->extra_data, pre_comp,
                             ec_pre_comp_dup, ec_pre_comp_free,
                             ec_pre_comp_clear_free))
        goto err;
    pre_comp = NULL;

    ret = 1;
 err:
    if (ctx != NULL)
        BN_CTX_end(ctx);
    if (new_ctx != NULL)
        BN_CTX_free(new_ctx);
    if (pre_comp)
        ec_pre_comp_free(pre_comp);
    if (points) {
        EC_POINT **p;

        for (p = points; *p != NULL; p++)
            EC_POINT_free(*p);
        OPENSSL_free(points);
    }
    if (tmp_point)
        EC_POINT_free(tmp_point);
    if (base)
        EC_POINT_free(base);
    return ret;
}

int ec_wNAF_have_precompute_mult(const EC_GROUP *group)
{
    if (EC_EX_DATA_get_data
        (group->extra_data, ec_pre_comp_dup, ec_pre_comp_free,
         ec_pre_comp_clear_free) != NULL)
        return 1;
    else
        return 0;
}
/* crypto/ec/ec_lib.c */
/*
 * Originally written by Bodo Moeller for the OpenSSL project.
 */
/* ====================================================================
 * Copyright (c) 1998-2003 The OpenSSL Project.  All rights reserved.
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
/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 * Binary polynomial ECC support in OpenSSL originally developed by
 * SUN MICROSYSTEMS, INC., and contributed to the OpenSSL project.
 */

#include <string.h>

// #include "err.h"
// #include "opensslv.h"

// #include "ec_lcl.h"

int EC_POINT_set_compressed_coordinates_GFp(const EC_GROUP *group,
                                            EC_POINT *point, const BIGNUM *x,
                                            int y_bit, BN_CTX *ctx)
{
    if (group->meth->point_set_compressed_coordinates == 0
        && !(group->meth->flags & EC_FLAGS_DEFAULT_OCT)) {
        ECerr(EC_F_EC_POINT_SET_COMPRESSED_COORDINATES_GFP,
              ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }
    if (group->meth != point->meth) {
        ECerr(EC_F_EC_POINT_SET_COMPRESSED_COORDINATES_GFP,
              EC_R_INCOMPATIBLE_OBJECTS);
        return 0;
    }
    if (group->meth->flags & EC_FLAGS_DEFAULT_OCT) {
        if (group->meth->field_type == NID_X9_62_prime_field)
            return ec_GFp_simple_set_compressed_coordinates(group, point, x,
                                                            y_bit, ctx);
        else
#ifdef OPENSSL_NO_EC2M
        {
            ECerr(EC_F_EC_POINT_SET_COMPRESSED_COORDINATES_GFP,
                  EC_R_GF2M_NOT_SUPPORTED);
            return 0;
        }
#else
            return ec_GF2m_simple_set_compressed_coordinates(group, point, x,
                                                             y_bit, ctx);
#endif
    }
    return group->meth->point_set_compressed_coordinates(group, point, x,
                                                         y_bit, ctx);
}

#ifndef OPENSSL_NO_EC2M
int EC_POINT_set_compressed_coordinates_GF2m(const EC_GROUP *group,
                                             EC_POINT *point, const BIGNUM *x,
                                             int y_bit, BN_CTX *ctx)
{
    if (group->meth->point_set_compressed_coordinates == 0
        && !(group->meth->flags & EC_FLAGS_DEFAULT_OCT)) {
        ECerr(EC_F_EC_POINT_SET_COMPRESSED_COORDINATES_GF2M,
              ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }
    if (group->meth != point->meth) {
        ECerr(EC_F_EC_POINT_SET_COMPRESSED_COORDINATES_GF2M,
              EC_R_INCOMPATIBLE_OBJECTS);
        return 0;
    }
    if (group->meth->flags & EC_FLAGS_DEFAULT_OCT) {
        if (group->meth->field_type == NID_X9_62_prime_field)
            return ec_GFp_simple_set_compressed_coordinates(group, point, x,
                                                            y_bit, ctx);
        else
            return ec_GF2m_simple_set_compressed_coordinates(group, point, x,
                                                             y_bit, ctx);
    }
    return group->meth->point_set_compressed_coordinates(group, point, x,
                                                         y_bit, ctx);
}
#endif

size_t EC_POINT_point2oct(const EC_GROUP *group, const EC_POINT *point,
                          point_conversion_form_t form, unsigned char *buf,
                          size_t len, BN_CTX *ctx)
{
    if (group->meth->point2oct == 0
        && !(group->meth->flags & EC_FLAGS_DEFAULT_OCT)) {
        ECerr(EC_F_EC_POINT_POINT2OCT, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }
    if (group->meth != point->meth) {
        ECerr(EC_F_EC_POINT_POINT2OCT, EC_R_INCOMPATIBLE_OBJECTS);
        return 0;
    }
    if (group->meth->flags & EC_FLAGS_DEFAULT_OCT) {
        if (group->meth->field_type == NID_X9_62_prime_field)
            return ec_GFp_simple_point2oct(group, point, form, buf, len, ctx);
        else
#ifdef OPENSSL_NO_EC2M
        {
            ECerr(EC_F_EC_POINT_POINT2OCT, EC_R_GF2M_NOT_SUPPORTED);
            return 0;
        }
#else
            return ec_GF2m_simple_point2oct(group, point,
                                            form, buf, len, ctx);
#endif
    }

    return group->meth->point2oct(group, point, form, buf, len, ctx);
}

int EC_POINT_oct2point(const EC_GROUP *group, EC_POINT *point,
                       const unsigned char *buf, size_t len, BN_CTX *ctx)
{
    if (group->meth->oct2point == 0
        && !(group->meth->flags & EC_FLAGS_DEFAULT_OCT)) {
        ECerr(EC_F_EC_POINT_OCT2POINT, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }
    if (group->meth != point->meth) {
        ECerr(EC_F_EC_POINT_OCT2POINT, EC_R_INCOMPATIBLE_OBJECTS);
        return 0;
    }
    if (group->meth->flags & EC_FLAGS_DEFAULT_OCT) {
        if (group->meth->field_type == NID_X9_62_prime_field)
            return ec_GFp_simple_oct2point(group, point, buf, len, ctx);
        else
#ifdef OPENSSL_NO_EC2M
        {
            ECerr(EC_F_EC_POINT_OCT2POINT, EC_R_GF2M_NOT_SUPPORTED);
            return 0;
        }
#else
            return ec_GF2m_simple_oct2point(group, point, buf, len, ctx);
#endif
    }
    return group->meth->oct2point(group, point, buf, len, ctx);
}
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
// #include "ec.h"
// #include "ec_lcl.h"
#include "ecdsa.h"
#include "evp.h"
#include "evp_locl.h"

/* EC pkey context structure */

typedef struct {
    /* Key and paramgen group */
    EC_GROUP *gen_group;
    /* message digest */
    const EVP_MD *md;
    /* Duplicate key if custom cofactor needed */
    EC_KEY *co_key;
    /* Cofactor mode */
    signed char cofactor_mode;
    /* KDF (if any) to use for ECDH */
    char kdf_type;
    /* Message digest to use for key derivation */
    const EVP_MD *kdf_md;
    /* User key material */
    unsigned char *kdf_ukm;
    size_t kdf_ukmlen;
    /* KDF output length */
    size_t kdf_outlen;
} EC_PKEY_CTX;

static int pkey_ec_init(EVP_PKEY_CTX *ctx)
{
    EC_PKEY_CTX *dctx;
    dctx = OPENSSL_malloc(sizeof(EC_PKEY_CTX));
    if (!dctx)
        return 0;
    dctx->gen_group = NULL;
    dctx->md = NULL;

    dctx->cofactor_mode = -1;
    dctx->co_key = NULL;
    dctx->kdf_type = EVP_PKEY_ECDH_KDF_NONE;
    dctx->kdf_md = NULL;
    dctx->kdf_outlen = 0;
    dctx->kdf_ukm = NULL;
    dctx->kdf_ukmlen = 0;

    ctx->data = dctx;

    return 1;
}

static int pkey_ec_copy(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src)
{
    EC_PKEY_CTX *dctx, *sctx;
    if (!pkey_ec_init(dst))
        return 0;
    sctx = src->data;
    dctx = dst->data;
    if (sctx->gen_group) {
        dctx->gen_group = EC_GROUP_dup(sctx->gen_group);
        if (!dctx->gen_group)
            return 0;
    }
    dctx->md = sctx->md;

    if (sctx->co_key) {
        dctx->co_key = EC_KEY_dup(sctx->co_key);
        if (!dctx->co_key)
            return 0;
    }
    dctx->kdf_type = sctx->kdf_type;
    dctx->kdf_md = sctx->kdf_md;
    dctx->kdf_outlen = sctx->kdf_outlen;
    if (sctx->kdf_ukm) {
        dctx->kdf_ukm = BUF_memdup(sctx->kdf_ukm, sctx->kdf_ukmlen);
        if (!dctx->kdf_ukm)
            return 0;
    } else
        dctx->kdf_ukm = NULL;
    dctx->kdf_ukmlen = sctx->kdf_ukmlen;
    return 1;
}

static void pkey_ec_cleanup(EVP_PKEY_CTX *ctx)
{
    EC_PKEY_CTX *dctx = ctx->data;
    if (dctx) {
        if (dctx->gen_group)
            EC_GROUP_free(dctx->gen_group);
        if (dctx->co_key)
            EC_KEY_free(dctx->co_key);
        if (dctx->kdf_ukm)
            OPENSSL_free(dctx->kdf_ukm);
        OPENSSL_free(dctx);
    }
}

static int pkey_ec_sign(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
                        const unsigned char *tbs, size_t tbslen)
{
    int ret, type;
    unsigned int sltmp;
    EC_PKEY_CTX *dctx = ctx->data;
    EC_KEY *ec = ctx->pkey->pkey.ec;

    if (!sig) {
        *siglen = ECDSA_size(ec);
        return 1;
    } else if (*siglen < (size_t)ECDSA_size(ec)) {
        ECerr(EC_F_PKEY_EC_SIGN, EC_R_BUFFER_TOO_SMALL);
        return 0;
    }

    if (dctx->md)
        type = EVP_MD_type(dctx->md);
    else
        type = NID_sha1;

    ret = ECDSA_sign(type, tbs, tbslen, sig, &sltmp, ec);

    if (ret <= 0)
        return ret;
    *siglen = (size_t)sltmp;
    return 1;
}

static int pkey_ec_verify(EVP_PKEY_CTX *ctx,
                          const unsigned char *sig, size_t siglen,
                          const unsigned char *tbs, size_t tbslen)
{
    int ret, type;
    EC_PKEY_CTX *dctx = ctx->data;
    EC_KEY *ec = ctx->pkey->pkey.ec;

    if (dctx->md)
        type = EVP_MD_type(dctx->md);
    else
        type = NID_sha1;

    ret = ECDSA_verify(type, tbs, tbslen, sig, siglen, ec);

    return ret;
}

#ifndef OPENSSL_NO_ECDH
static int pkey_ec_derive(EVP_PKEY_CTX *ctx, unsigned char *key,
                          size_t *keylen)
{
    int ret;
    size_t outlen;
    const EC_POINT *pubkey = NULL;
    EC_KEY *eckey;
    EC_PKEY_CTX *dctx = ctx->data;
    if (!ctx->pkey || !ctx->peerkey) {
        ECerr(EC_F_PKEY_EC_DERIVE, EC_R_KEYS_NOT_SET);
        return 0;
    }

    eckey = dctx->co_key ? dctx->co_key : ctx->pkey->pkey.ec;

    if (!key) {
        const EC_GROUP *group;
        group = EC_KEY_get0_group(eckey);
        *keylen = (EC_GROUP_get_degree(group) + 7) / 8;
        return 1;
    }
    pubkey = EC_KEY_get0_public_key(ctx->peerkey->pkey.ec);

    /*
     * NB: unlike PKCS#3 DH, if *outlen is less than maximum size this is not
     * an error, the result is truncated.
     */

    outlen = *keylen;

    ret = ECDH_compute_key(key, outlen, pubkey, eckey, 0);
    if (ret <= 0)
        return 0;
    *keylen = ret;
    return 1;
}

static int pkey_ec_kdf_derive(EVP_PKEY_CTX *ctx,
                              unsigned char *key, size_t *keylen)
{
    EC_PKEY_CTX *dctx = ctx->data;
    unsigned char *ktmp = NULL;
    size_t ktmplen;
    int rv = 0;
    if (dctx->kdf_type == EVP_PKEY_ECDH_KDF_NONE)
        return pkey_ec_derive(ctx, key, keylen);
    if (!key) {
        *keylen = dctx->kdf_outlen;
        return 1;
    }
    if (*keylen != dctx->kdf_outlen)
        return 0;
    if (!pkey_ec_derive(ctx, NULL, &ktmplen))
        return 0;
    ktmp = OPENSSL_malloc(ktmplen);
    if (!ktmp)
        return 0;
    if (!pkey_ec_derive(ctx, ktmp, &ktmplen))
        goto err;
    /* Do KDF stuff */
    if (!ECDH_KDF_X9_62(key, *keylen, ktmp, ktmplen,
                        dctx->kdf_ukm, dctx->kdf_ukmlen, dctx->kdf_md))
        goto err;
    rv = 1;

 err:
    if (ktmp) {
        OPENSSL_cleanse(ktmp, ktmplen);
        OPENSSL_free(ktmp);
    }
    return rv;
}
#endif

static int pkey_ec_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
    EC_PKEY_CTX *dctx = ctx->data;
    EC_GROUP *group;
    switch (type) {
    case EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID:
        group = EC_GROUP_new_by_curve_name(p1);
        if (group == NULL) {
            ECerr(EC_F_PKEY_EC_CTRL, EC_R_INVALID_CURVE);
            return 0;
        }
        if (dctx->gen_group)
            EC_GROUP_free(dctx->gen_group);
        dctx->gen_group = group;
        return 1;

    case EVP_PKEY_CTRL_EC_PARAM_ENC:
        if (!dctx->gen_group) {
            ECerr(EC_F_PKEY_EC_CTRL, EC_R_NO_PARAMETERS_SET);
            return 0;
        }
        EC_GROUP_set_asn1_flag(dctx->gen_group, p1);
        return 1;

#ifndef OPENSSL_NO_ECDH
    case EVP_PKEY_CTRL_EC_ECDH_COFACTOR:
        if (p1 == -2) {
            if (dctx->cofactor_mode != -1)
                return dctx->cofactor_mode;
            else {
                EC_KEY *ec_key = ctx->pkey->pkey.ec;
                return EC_KEY_get_flags(ec_key) & EC_FLAG_COFACTOR_ECDH ? 1 :
                    0;
            }
        } else if (p1 < -1 || p1 > 1)
            return -2;
        dctx->cofactor_mode = p1;
        if (p1 != -1) {
            EC_KEY *ec_key = ctx->pkey->pkey.ec;
            if (!ec_key->group)
                return -2;
            /* If cofactor is 1 cofactor mode does nothing */
            if (BN_is_one(&ec_key->group->cofactor))
                return 1;
            if (!dctx->co_key) {
                dctx->co_key = EC_KEY_dup(ec_key);
                if (!dctx->co_key)
                    return 0;
            }
            if (p1)
                EC_KEY_set_flags(dctx->co_key, EC_FLAG_COFACTOR_ECDH);
            else
                EC_KEY_clear_flags(dctx->co_key, EC_FLAG_COFACTOR_ECDH);
        } else if (dctx->co_key) {
            EC_KEY_free(dctx->co_key);
            dctx->co_key = NULL;
        }
        return 1;
#endif

    case EVP_PKEY_CTRL_EC_KDF_TYPE:
        if (p1 == -2)
            return dctx->kdf_type;
        if (p1 != EVP_PKEY_ECDH_KDF_NONE && p1 != EVP_PKEY_ECDH_KDF_X9_62)
            return -2;
        dctx->kdf_type = p1;
        return 1;

    case EVP_PKEY_CTRL_EC_KDF_MD:
        dctx->kdf_md = p2;
        return 1;

    case EVP_PKEY_CTRL_GET_EC_KDF_MD:
        *(const EVP_MD **)p2 = dctx->kdf_md;
        return 1;

    case EVP_PKEY_CTRL_EC_KDF_OUTLEN:
        if (p1 <= 0)
            return -2;
        dctx->kdf_outlen = (size_t)p1;
        return 1;

    case EVP_PKEY_CTRL_GET_EC_KDF_OUTLEN:
        *(int *)p2 = dctx->kdf_outlen;
        return 1;

    case EVP_PKEY_CTRL_EC_KDF_UKM:
        if (dctx->kdf_ukm)
            OPENSSL_free(dctx->kdf_ukm);
        dctx->kdf_ukm = p2;
        if (p2)
            dctx->kdf_ukmlen = p1;
        else
            dctx->kdf_ukmlen = 0;
        return 1;

    case EVP_PKEY_CTRL_GET_EC_KDF_UKM:
        *(unsigned char **)p2 = dctx->kdf_ukm;
        return dctx->kdf_ukmlen;

    case EVP_PKEY_CTRL_MD:
        if (EVP_MD_type((const EVP_MD *)p2) != NID_sha1 &&
            EVP_MD_type((const EVP_MD *)p2) != NID_ecdsa_with_SHA1 &&
            EVP_MD_type((const EVP_MD *)p2) != NID_sha224 &&
            EVP_MD_type((const EVP_MD *)p2) != NID_sha256 &&
            EVP_MD_type((const EVP_MD *)p2) != NID_sha384 &&
            EVP_MD_type((const EVP_MD *)p2) != NID_sha512) {
            ECerr(EC_F_PKEY_EC_CTRL, EC_R_INVALID_DIGEST_TYPE);
            return 0;
        }
        dctx->md = p2;
        return 1;

    case EVP_PKEY_CTRL_GET_MD:
        *(const EVP_MD **)p2 = dctx->md;
        return 1;

    case EVP_PKEY_CTRL_PEER_KEY:
        /* Default behaviour is OK */
    case EVP_PKEY_CTRL_DIGESTINIT:
    case EVP_PKEY_CTRL_PKCS7_SIGN:
    case EVP_PKEY_CTRL_CMS_SIGN:
        return 1;

    default:
        return -2;

    }
}

static int pkey_ec_ctrl_str(EVP_PKEY_CTX *ctx,
                            const char *type, const char *value)
{
    if (!strcmp(type, "ec_paramgen_curve")) {
        int nid;
        nid = EC_curve_nist2nid(value);
        if (nid == NID_undef)
            nid = OBJ_sn2nid(value);
        if (nid == NID_undef)
            nid = OBJ_ln2nid(value);
        if (nid == NID_undef) {
            ECerr(EC_F_PKEY_EC_CTRL_STR, EC_R_INVALID_CURVE);
            return 0;
        }
        return EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, nid);
    } else if (!strcmp(type, "ec_param_enc")) {
        int param_enc;
        if (!strcmp(value, "explicit"))
            param_enc = 0;
        else if (!strcmp(value, "named_curve"))
            param_enc = OPENSSL_EC_NAMED_CURVE;
        else
            return -2;
        return EVP_PKEY_CTX_set_ec_param_enc(ctx, param_enc);
    } else if (!strcmp(type, "ecdh_kdf_md")) {
        const EVP_MD *md;
        if (!(md = EVP_get_digestbyname(value))) {
            ECerr(EC_F_PKEY_EC_CTRL_STR, EC_R_INVALID_DIGEST);
            return 0;
        }
        return EVP_PKEY_CTX_set_ecdh_kdf_md(ctx, md);
    } else if (!strcmp(type, "ecdh_cofactor_mode")) {
        int co_mode;
        co_mode = atoi(value);
        return EVP_PKEY_CTX_set_ecdh_cofactor_mode(ctx, co_mode);
    }

    return -2;
}

static int pkey_ec_paramgen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    EC_KEY *ec = NULL;
    EC_PKEY_CTX *dctx = ctx->data;
    int ret = 0;
    if (dctx->gen_group == NULL) {
        ECerr(EC_F_PKEY_EC_PARAMGEN, EC_R_NO_PARAMETERS_SET);
        return 0;
    }
    ec = EC_KEY_new();
    if (!ec)
        return 0;
    ret = EC_KEY_set_group(ec, dctx->gen_group);
    if (ret)
        EVP_PKEY_assign_EC_KEY(pkey, ec);
    else
        EC_KEY_free(ec);
    return ret;
}

static int pkey_ec_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    EC_KEY *ec = NULL;
    EC_PKEY_CTX *dctx = ctx->data;
    if (ctx->pkey == NULL && dctx->gen_group == NULL) {
        ECerr(EC_F_PKEY_EC_KEYGEN, EC_R_NO_PARAMETERS_SET);
        return 0;
    }
    ec = EC_KEY_new();
    if (!ec)
        return 0;
    EVP_PKEY_assign_EC_KEY(pkey, ec);
    if (ctx->pkey) {
        /* Note: if error return, pkey is freed by parent routine */
        if (!EVP_PKEY_copy_parameters(pkey, ctx->pkey))
            return 0;
    } else {
        if (!EC_KEY_set_group(ec, dctx->gen_group))
            return 0;
    }
    return EC_KEY_generate_key(pkey->pkey.ec);
}

const EVP_PKEY_METHOD ec_pkey_meth = {
    EVP_PKEY_EC,
    0,
    pkey_ec_init,
    pkey_ec_copy,
    pkey_ec_cleanup,

    0,
    pkey_ec_paramgen,

    0,
    pkey_ec_keygen,

    0,
    pkey_ec_sign,

    0,
    pkey_ec_verify,

    0, 0,

    0, 0, 0, 0,

    0, 0,

    0, 0,

    0,
#ifndef OPENSSL_NO_ECDH
    pkey_ec_kdf_derive,
#else
    0,
#endif

    pkey_ec_ctrl,
    pkey_ec_ctrl_str
};
/* crypto/ec/ec_print.c */
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

#include "crypto.h"
// #include "ec_lcl.h"

BIGNUM *EC_POINT_point2bn(const EC_GROUP *group,
                          const EC_POINT *point,
                          point_conversion_form_t form,
                          BIGNUM *ret, BN_CTX *ctx)
{
    size_t buf_len = 0;
    unsigned char *buf;

    buf_len = EC_POINT_point2oct(group, point, form, NULL, 0, ctx);
    if (buf_len == 0)
        return NULL;

    if ((buf = OPENSSL_malloc(buf_len)) == NULL)
        return NULL;

    if (!EC_POINT_point2oct(group, point, form, buf, buf_len, ctx)) {
        OPENSSL_free(buf);
        return NULL;
    }

    ret = BN_bin2bn(buf, buf_len, ret);

    OPENSSL_free(buf);

    return ret;
}

EC_POINT *EC_POINT_bn2point(const EC_GROUP *group,
                            const BIGNUM *bn, EC_POINT *point, BN_CTX *ctx)
{
    size_t buf_len = 0;
    unsigned char *buf;
    EC_POINT *ret;

    if ((buf_len = BN_num_bytes(bn)) == 0)
        return NULL;
    buf = OPENSSL_malloc(buf_len);
    if (buf == NULL)
        return NULL;

    if (!BN_bn2bin(bn, buf)) {
        OPENSSL_free(buf);
        return NULL;
    }

    if (point == NULL) {
        if ((ret = EC_POINT_new(group)) == NULL) {
            OPENSSL_free(buf);
            return NULL;
        }
    } else
        ret = point;

    if (!EC_POINT_oct2point(group, ret, buf, buf_len, ctx)) {
        if (point == NULL)
            EC_POINT_clear_free(ret);
        OPENSSL_free(buf);
        return NULL;
    }

    OPENSSL_free(buf);
    return ret;
}

static const char *HEX_DIGITS = "0123456789ABCDEF";

/* the return value must be freed (using OPENSSL_free()) */
char *EC_POINT_point2hex(const EC_GROUP *group,
                         const EC_POINT *point,
                         point_conversion_form_t form, BN_CTX *ctx)
{
    char *ret, *p;
    size_t buf_len = 0, i;
    unsigned char *buf, *pbuf;

    buf_len = EC_POINT_point2oct(group, point, form, NULL, 0, ctx);
    if (buf_len == 0)
        return NULL;

    if ((buf = OPENSSL_malloc(buf_len)) == NULL)
        return NULL;

    if (!EC_POINT_point2oct(group, point, form, buf, buf_len, ctx)) {
        OPENSSL_free(buf);
        return NULL;
    }

    ret = (char *)OPENSSL_malloc(buf_len * 2 + 2);
    if (ret == NULL) {
        OPENSSL_free(buf);
        return NULL;
    }
    p = ret;
    pbuf = buf;
    for (i = buf_len; i > 0; i--) {
        int v = (int)*(pbuf++);
        *(p++) = HEX_DIGITS[v >> 4];
        *(p++) = HEX_DIGITS[v & 0x0F];
    }
    *p = '\0';

    OPENSSL_free(buf);

    return ret;
}

EC_POINT *EC_POINT_hex2point(const EC_GROUP *group,
                             const char *buf, EC_POINT *point, BN_CTX *ctx)
{
    EC_POINT *ret = NULL;
    BIGNUM *tmp_bn = NULL;

    if (!BN_hex2bn(&tmp_bn, buf))
        return NULL;

    ret = EC_POINT_bn2point(group, tmp_bn, point, ctx);

    BN_clear_free(tmp_bn);

    return ret;
}
