/**********************************************************************
 *                          gost_ameth.c                              *
 *             Copyright (c) 2005-2006 Cryptocom LTD                  *
 *         This file is distributed under the same license as OpenSSL *
 *                                                                    *
 *       Implementation of RFC 4490/4491 ASN1 method                  *
 *       for OpenSSL                                                  *
 *          Requires OpenSSL 0.9.9 for compilation                    *
 **********************************************************************/
#include <string.h>
#include "crypto.h"
#include "err.h"
#include "engine.h"
#include "evp.h"
#include "asn1.h"
#ifndef OPENSSL_NO_CMS
# include "cms.h"
#endif
#include "gost_params.h"
#include "gost_lcl.h"
#include "e_gost_err.h"

int gost94_nid_by_params(DSA *p)
{
    R3410_params *gost_params;
    BIGNUM *q = BN_new();
    for (gost_params = R3410_paramset; gost_params->q != NULL; gost_params++) {
        BN_dec2bn(&q, gost_params->q);
        if (!BN_cmp(q, p->q)) {
            BN_free(q);
            return gost_params->nid;
        }
    }
    BN_free(q);
    return NID_undef;
}

static ASN1_STRING *encode_gost_algor_params(const EVP_PKEY *key)
{
    ASN1_STRING *params = ASN1_STRING_new();
    GOST_KEY_PARAMS *gkp = GOST_KEY_PARAMS_new();
    int pkey_param_nid = NID_undef;

    if (!params || !gkp) {
        GOSTerr(GOST_F_ENCODE_GOST_ALGOR_PARAMS, ERR_R_MALLOC_FAILURE);
        ASN1_STRING_free(params);
        params = NULL;
        goto err;
    }
    switch (EVP_PKEY_base_id(key)) {
    case NID_id_GostR3410_2001:
        pkey_param_nid =
            EC_GROUP_get_curve_name(EC_KEY_get0_group
                                    (EVP_PKEY_get0((EVP_PKEY *)key)));
        break;
    case NID_id_GostR3410_94:
        pkey_param_nid =
            (int)gost94_nid_by_params(EVP_PKEY_get0((EVP_PKEY *)key));
        if (pkey_param_nid == NID_undef) {
            GOSTerr(GOST_F_ENCODE_GOST_ALGOR_PARAMS,
                    GOST_R_INVALID_GOST94_PARMSET);
            ASN1_STRING_free(params);
            params = NULL;
            goto err;
        }
        break;
    }
    gkp->key_params = OBJ_nid2obj(pkey_param_nid);
    gkp->hash_params = OBJ_nid2obj(NID_id_GostR3411_94_CryptoProParamSet);
    /*
     * gkp->cipher_params = OBJ_nid2obj(cipher_param_nid);
     */
    params->length = i2d_GOST_KEY_PARAMS(gkp, &params->data);
    if (params->length <= 0) {
        GOSTerr(GOST_F_ENCODE_GOST_ALGOR_PARAMS, ERR_R_MALLOC_FAILURE);
        ASN1_STRING_free(params);
        params = NULL;
        goto err;
    }
    params->type = V_ASN1_SEQUENCE;
 err:
    GOST_KEY_PARAMS_free(gkp);
    return params;
}

/*
 * Parses GOST algorithm parameters from X509_ALGOR and modifies pkey setting
 * NID and parameters
 */
static int decode_gost_algor_params(EVP_PKEY *pkey, X509_ALGOR *palg)
{
    ASN1_OBJECT *palg_obj = NULL;
    int ptype = V_ASN1_UNDEF;
    int pkey_nid = NID_undef, param_nid = NID_undef;
    void *_pval;
    ASN1_STRING *pval = NULL;
    const unsigned char *p;
    GOST_KEY_PARAMS *gkp = NULL;

    X509_ALGOR_get0(&palg_obj, &ptype, &_pval, palg);
    pval = _pval;
    if (ptype != V_ASN1_SEQUENCE) {
        GOSTerr(GOST_F_DECODE_GOST_ALGOR_PARAMS,
                GOST_R_BAD_KEY_PARAMETERS_FORMAT);
        return 0;
    }
    p = pval->data;
    pkey_nid = OBJ_obj2nid(palg_obj);

    gkp = d2i_GOST_KEY_PARAMS(NULL, &p, pval->length);
    if (!gkp) {
        GOSTerr(GOST_F_DECODE_GOST_ALGOR_PARAMS,
                GOST_R_BAD_PKEY_PARAMETERS_FORMAT);
        return 0;
    }
    param_nid = OBJ_obj2nid(gkp->key_params);
    GOST_KEY_PARAMS_free(gkp);
    if(!EVP_PKEY_set_type(pkey, pkey_nid)) {
        GOSTerr(GOST_F_DECODE_GOST_ALGOR_PARAMS, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    switch (pkey_nid) {
    case NID_id_GostR3410_94:
        {
            DSA *dsa = EVP_PKEY_get0(pkey);
            if (!dsa) {
                dsa = DSA_new();
                if (!EVP_PKEY_assign(pkey, pkey_nid, dsa))
                    return 0;
            }
            if (!fill_GOST94_params(dsa, param_nid))
                return 0;
            break;
        }
    case NID_id_GostR3410_2001:
        {
            EC_KEY *ec = EVP_PKEY_get0(pkey);
            if (!ec) {
                ec = EC_KEY_new();
                if (!EVP_PKEY_assign(pkey, pkey_nid, ec))
                    return 0;
            }
            if (!fill_GOST2001_params(ec, param_nid))
                return 0;
        }
    }

    return 1;
}

static int gost_set_priv_key(EVP_PKEY *pkey, BIGNUM *priv)
{
    switch (EVP_PKEY_base_id(pkey)) {
    case NID_id_GostR3410_94:
        {
            DSA *dsa = EVP_PKEY_get0(pkey);
            if (!dsa) {
                dsa = DSA_new();
                EVP_PKEY_assign(pkey, EVP_PKEY_base_id(pkey), dsa);
            }
            dsa->priv_key = BN_dup(priv);
            if (!EVP_PKEY_missing_parameters(pkey))
                gost94_compute_public(dsa);
            break;
        }
    case NID_id_GostR3410_2001:
        {
            EC_KEY *ec = EVP_PKEY_get0(pkey);
            if (!ec) {
                ec = EC_KEY_new();
                EVP_PKEY_assign(pkey, EVP_PKEY_base_id(pkey), ec);
            }
            if (!EC_KEY_set_private_key(ec, priv))
                return 0;
            if (!EVP_PKEY_missing_parameters(pkey))
                gost2001_compute_public(ec);
            break;
        }
    }
    return 1;
}

BIGNUM *gost_get0_priv_key(const EVP_PKEY *pkey)
{
    switch (EVP_PKEY_base_id(pkey)) {
    case NID_id_GostR3410_94:
        {
            DSA *dsa = EVP_PKEY_get0((EVP_PKEY *)pkey);
            if (!dsa) {
                return NULL;
            }
            if (!dsa->priv_key)
                return NULL;
            return dsa->priv_key;
            break;
        }
    case NID_id_GostR3410_2001:
        {
            EC_KEY *ec = EVP_PKEY_get0((EVP_PKEY *)pkey);
            const BIGNUM *priv;
            if (!ec) {
                return NULL;
            }
            if (!(priv = EC_KEY_get0_private_key(ec)))
                return NULL;
            return (BIGNUM *)priv;
            break;
        }
    }
    return NULL;
}

static int pkey_ctrl_gost(EVP_PKEY *pkey, int op, long arg1, void *arg2)
{
    switch (op) {
    case ASN1_PKEY_CTRL_PKCS7_SIGN:
        if (arg1 == 0) {
            X509_ALGOR *alg1 = NULL, *alg2 = NULL;
            int nid = EVP_PKEY_base_id(pkey);
            PKCS7_SIGNER_INFO_get0_algs((PKCS7_SIGNER_INFO *)arg2,
                                        NULL, &alg1, &alg2);
            X509_ALGOR_set0(alg1, OBJ_nid2obj(NID_id_GostR3411_94),
                            V_ASN1_NULL, 0);
            if (nid == NID_undef) {
                return (-1);
            }
            X509_ALGOR_set0(alg2, OBJ_nid2obj(nid), V_ASN1_NULL, 0);
        }
        return 1;
#ifndef OPENSSL_NO_CMS
    case ASN1_PKEY_CTRL_CMS_SIGN:
        if (arg1 == 0) {
            X509_ALGOR *alg1 = NULL, *alg2 = NULL;
            int nid = EVP_PKEY_base_id(pkey);
            CMS_SignerInfo_get0_algs((CMS_SignerInfo *)arg2,
                                     NULL, NULL, &alg1, &alg2);
            X509_ALGOR_set0(alg1, OBJ_nid2obj(NID_id_GostR3411_94),
                            V_ASN1_NULL, 0);
            if (nid == NID_undef) {
                return (-1);
            }
            X509_ALGOR_set0(alg2, OBJ_nid2obj(nid), V_ASN1_NULL, 0);
        }
        return 1;
#endif
    case ASN1_PKEY_CTRL_PKCS7_ENCRYPT:
        if (arg1 == 0) {
            X509_ALGOR *alg;
            ASN1_STRING *params = encode_gost_algor_params(pkey);
            if (!params) {
                return -1;
            }
            PKCS7_RECIP_INFO_get0_alg((PKCS7_RECIP_INFO *)arg2, &alg);
            X509_ALGOR_set0(alg, OBJ_nid2obj(pkey->type),
                            V_ASN1_SEQUENCE, params);
        }
        return 1;
#ifndef OPENSSL_NO_CMS
    case ASN1_PKEY_CTRL_CMS_ENVELOPE:
        if (arg1 == 0) {
            X509_ALGOR *alg = NULL;
            ASN1_STRING *params = encode_gost_algor_params(pkey);
            if (!params) {
                return -1;
            }
            CMS_RecipientInfo_ktri_get0_algs((CMS_RecipientInfo *)arg2, NULL,
                                             NULL, &alg);
            X509_ALGOR_set0(alg, OBJ_nid2obj(pkey->type), V_ASN1_SEQUENCE,
                            params);
        }
        return 1;
#endif
    case ASN1_PKEY_CTRL_DEFAULT_MD_NID:
        *(int *)arg2 = NID_id_GostR3411_94;
        return 2;
    }

    return -2;
}

/* --------------------- free functions * ------------------------------*/
static void pkey_free_gost94(EVP_PKEY *key)
{
    if (key->pkey.dsa) {
        DSA_free(key->pkey.dsa);
    }
}

static void pkey_free_gost01(EVP_PKEY *key)
{
    if (key->pkey.ec) {
        EC_KEY_free(key->pkey.ec);
    }
}

/* ------------------ private key functions  -----------------------------*/
static int priv_decode_gost(EVP_PKEY *pk, PKCS8_PRIV_KEY_INFO *p8inf)
{
    const unsigned char *pkey_buf = NULL, *p = NULL;
    int priv_len = 0;
    BIGNUM *pk_num = NULL;
    int ret = 0;
    X509_ALGOR *palg = NULL;
    ASN1_OBJECT *palg_obj = NULL;
    ASN1_INTEGER *priv_key = NULL;

    if (!PKCS8_pkey_get0(&palg_obj, &pkey_buf, &priv_len, &palg, p8inf))
        return 0;
    p = pkey_buf;
    if (!decode_gost_algor_params(pk, palg)) {
        return 0;
    }
    if (V_ASN1_OCTET_STRING == *p) {
        /* New format - Little endian octet string */
        unsigned char rev_buf[32];
        int i;
        ASN1_OCTET_STRING *s = d2i_ASN1_OCTET_STRING(NULL, &p, priv_len);
        if (!s || s->length != 32) {
            GOSTerr(GOST_F_PRIV_DECODE_GOST, EVP_R_DECODE_ERROR);
            return 0;
        }
        for (i = 0; i < 32; i++) {
            rev_buf[31 - i] = s->data[i];
        }
        ASN1_STRING_free(s);
        pk_num = getbnfrombuf(rev_buf, 32);
    } else {
        priv_key = d2i_ASN1_INTEGER(NULL, &p, priv_len);
        if (!priv_key)
            return 0;
        ret = ((pk_num = ASN1_INTEGER_to_BN(priv_key, NULL)) != NULL);
        ASN1_INTEGER_free(priv_key);
        if (!ret) {
            GOSTerr(GOST_F_PRIV_DECODE_GOST, EVP_R_DECODE_ERROR);
            return 0;
        }
    }

    ret = gost_set_priv_key(pk, pk_num);
    BN_free(pk_num);
    return ret;
}

/* ----------------------------------------------------------------------*/
static int priv_encode_gost(PKCS8_PRIV_KEY_INFO *p8, const EVP_PKEY *pk)
{
    ASN1_OBJECT *algobj = OBJ_nid2obj(EVP_PKEY_base_id(pk));
    ASN1_STRING *params = encode_gost_algor_params(pk);
    unsigned char *priv_buf = NULL;
    int priv_len;

    ASN1_INTEGER *asn1key = NULL;
    if (!params) {
        return 0;
    }
    asn1key = BN_to_ASN1_INTEGER(gost_get0_priv_key(pk), NULL);
    priv_len = i2d_ASN1_INTEGER(asn1key, &priv_buf);
    ASN1_INTEGER_free(asn1key);
    return PKCS8_pkey_set0(p8, algobj, 0, V_ASN1_SEQUENCE, params,
                           priv_buf, priv_len);
}

/* --------- printing keys --------------------------------*/
static int print_gost_94(BIO *out, const EVP_PKEY *pkey, int indent,
                         ASN1_PCTX *pctx, int type)
{
    int param_nid = NID_undef;

    if (type == 2) {
        BIGNUM *key;

        if (!BIO_indent(out, indent, 128))
            return 0;
        BIO_printf(out, "Private key: ");
        key = gost_get0_priv_key(pkey);
        if (!key)
            BIO_printf(out, "<undefined>");
        else
            BN_print(out, key);
        BIO_printf(out, "\n");
    }
    if (type >= 1) {
        BIGNUM *pubkey;

        pubkey = ((DSA *)EVP_PKEY_get0((EVP_PKEY *)pkey))->pub_key;
        BIO_indent(out, indent, 128);
        BIO_printf(out, "Public key: ");
        BN_print(out, pubkey);
        BIO_printf(out, "\n");
    }

    param_nid = gost94_nid_by_params(EVP_PKEY_get0((EVP_PKEY *)pkey));
    BIO_indent(out, indent, 128);
    BIO_printf(out, "Parameter set: %s\n", OBJ_nid2ln(param_nid));
    return 1;
}

static int param_print_gost94(BIO *out, const EVP_PKEY *pkey, int indent,
                              ASN1_PCTX *pctx)
{
    return print_gost_94(out, pkey, indent, pctx, 0);
}

static int pub_print_gost94(BIO *out, const EVP_PKEY *pkey, int indent,
                            ASN1_PCTX *pctx)
{
    return print_gost_94(out, pkey, indent, pctx, 1);
}

static int priv_print_gost94(BIO *out, const EVP_PKEY *pkey, int indent,
                             ASN1_PCTX *pctx)
{
    return print_gost_94(out, pkey, indent, pctx, 2);
}

static int print_gost_01(BIO *out, const EVP_PKEY *pkey, int indent,
                         ASN1_PCTX *pctx, int type)
{
    int param_nid = NID_undef;
    if (type == 2) {
        BIGNUM *key;

        if (!BIO_indent(out, indent, 128))
            return 0;
        BIO_printf(out, "Private key: ");
        key = gost_get0_priv_key(pkey);
        if (!key)
            BIO_printf(out, "<undefined)");
        else
            BN_print(out, key);
        BIO_printf(out, "\n");
    }
    if (type >= 1) {
        BN_CTX *ctx = BN_CTX_new();
        BIGNUM *X, *Y;
        const EC_POINT *pubkey;
        const EC_GROUP *group;

        if (!ctx) {
            GOSTerr(GOST_F_PRINT_GOST_01, ERR_R_MALLOC_FAILURE);
            return 0;
        }
        BN_CTX_start(ctx);
        X = BN_CTX_get(ctx);
        Y = BN_CTX_get(ctx);
        pubkey =
            EC_KEY_get0_public_key((EC_KEY *)EVP_PKEY_get0((EVP_PKEY *)pkey));
        group = EC_KEY_get0_group((EC_KEY *)EVP_PKEY_get0((EVP_PKEY *)pkey));
        if (!EC_POINT_get_affine_coordinates_GFp(group, pubkey, X, Y, ctx)) {
            GOSTerr(GOST_F_PRINT_GOST_01, ERR_R_EC_LIB);
            BN_CTX_free(ctx);
            return 0;
        }
        if (!BIO_indent(out, indent, 128))
            return 0;
        BIO_printf(out, "Public key:\n");
        if (!BIO_indent(out, indent + 3, 128))
            return 0;
        BIO_printf(out, "X:");
        BN_print(out, X);
        BIO_printf(out, "\n");
        BIO_indent(out, indent + 3, 128);
        BIO_printf(out, "Y:");
        BN_print(out, Y);
        BIO_printf(out, "\n");
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }

    param_nid =
        EC_GROUP_get_curve_name(EC_KEY_get0_group
                                (EVP_PKEY_get0((EVP_PKEY *)pkey)));
    if (!BIO_indent(out, indent, 128))
        return 0;
    BIO_printf(out, "Parameter set: %s\n", OBJ_nid2ln(param_nid));
    return 1;
}

static int param_print_gost01(BIO *out, const EVP_PKEY *pkey, int indent,
                              ASN1_PCTX *pctx)
{
    return print_gost_01(out, pkey, indent, pctx, 0);
}

static int pub_print_gost01(BIO *out, const EVP_PKEY *pkey, int indent,
                            ASN1_PCTX *pctx)
{
    return print_gost_01(out, pkey, indent, pctx, 1);
}

static int priv_print_gost01(BIO *out, const EVP_PKEY *pkey, int indent,
                             ASN1_PCTX *pctx)
{
    return print_gost_01(out, pkey, indent, pctx, 2);
}

/* ---------------------------------------------------------------------*/
static int param_missing_gost94(const EVP_PKEY *pk)
{
    const DSA *dsa = EVP_PKEY_get0((EVP_PKEY *)pk);
    if (!dsa)
        return 1;
    if (!dsa->q)
        return 1;
    return 0;
}

static int param_missing_gost01(const EVP_PKEY *pk)
{
    const EC_KEY *ec = EVP_PKEY_get0((EVP_PKEY *)pk);
    if (!ec)
        return 1;
    if (!EC_KEY_get0_group(ec))
        return 1;
    return 0;
}

static int param_copy_gost94(EVP_PKEY *to, const EVP_PKEY *from)
{
    const DSA *dfrom = EVP_PKEY_get0((EVP_PKEY *)from);
    DSA *dto = EVP_PKEY_get0(to);
    if (EVP_PKEY_base_id(from) != EVP_PKEY_base_id(to)) {
        GOSTerr(GOST_F_PARAM_COPY_GOST94, GOST_R_INCOMPATIBLE_ALGORITHMS);
        return 0;
    }
    if (!dfrom) {
        GOSTerr(GOST_F_PARAM_COPY_GOST94, GOST_R_KEY_PARAMETERS_MISSING);
        return 0;
    }
    if (!dto) {
        dto = DSA_new();
        EVP_PKEY_assign(to, EVP_PKEY_base_id(from), dto);
    }
#define COPYBIGNUM(a,b,x) if (a->x) BN_free(a->x); a->x=BN_dup(b->x);
    COPYBIGNUM(dto, dfrom, p)
        COPYBIGNUM(dto, dfrom, q)
        COPYBIGNUM(dto, dfrom, g)

        if (dto->priv_key)
        gost94_compute_public(dto);
    return 1;
}

static int param_copy_gost01(EVP_PKEY *to, const EVP_PKEY *from)
{
    EC_KEY *eto = EVP_PKEY_get0(to);
    const EC_KEY *efrom = EVP_PKEY_get0((EVP_PKEY *)from);
    if (EVP_PKEY_base_id(from) != EVP_PKEY_base_id(to)) {
        GOSTerr(GOST_F_PARAM_COPY_GOST01, GOST_R_INCOMPATIBLE_ALGORITHMS);
        return 0;
    }
    if (!efrom) {
        GOSTerr(GOST_F_PARAM_COPY_GOST01, GOST_R_KEY_PARAMETERS_MISSING);
        return 0;
    }
    if (!eto) {
        eto = EC_KEY_new();
        if(!eto) {
            GOSTerr(GOST_F_PARAM_COPY_GOST01, ERR_R_MALLOC_FAILURE);
            return 0;
        }
        if(!EVP_PKEY_assign(to, EVP_PKEY_base_id(from), eto)) {
            GOSTerr(GOST_F_PARAM_COPY_GOST01, ERR_R_INTERNAL_ERROR);
            return 0;
        }
    }
    if(!EC_KEY_set_group(eto, EC_KEY_get0_group(efrom))) {
        GOSTerr(GOST_F_PARAM_COPY_GOST01, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if (EC_KEY_get0_private_key(eto)) {
        gost2001_compute_public(eto);
    }
    return 1;
}

static int param_cmp_gost94(const EVP_PKEY *a, const EVP_PKEY *b)
{
    const DSA *da = EVP_PKEY_get0((EVP_PKEY *)a);
    const DSA *db = EVP_PKEY_get0((EVP_PKEY *)b);
    if (!BN_cmp(da->q, db->q))
        return 1;
    return 0;
}

static int param_cmp_gost01(const EVP_PKEY *a, const EVP_PKEY *b)
{
    if (EC_GROUP_get_curve_name
        (EC_KEY_get0_group(EVP_PKEY_get0((EVP_PKEY *)a))) ==
        EC_GROUP_get_curve_name(EC_KEY_get0_group
                                (EVP_PKEY_get0((EVP_PKEY *)b)))) {
        return 1;
    }
    return 0;

}

/* ---------- Public key functions * --------------------------------------*/
static int pub_decode_gost94(EVP_PKEY *pk, X509_PUBKEY *pub)
{
    X509_ALGOR *palg = NULL;
    const unsigned char *pubkey_buf = NULL;
    unsigned char *databuf;
    ASN1_OBJECT *palgobj = NULL;
    int pub_len, i, j;
    DSA *dsa;
    ASN1_OCTET_STRING *octet = NULL;

    if (!X509_PUBKEY_get0_param(&palgobj, &pubkey_buf, &pub_len, &palg, pub))
        return 0;
    EVP_PKEY_assign(pk, OBJ_obj2nid(palgobj), NULL);
    if (!decode_gost_algor_params(pk, palg))
        return 0;
    octet = d2i_ASN1_OCTET_STRING(NULL, &pubkey_buf, pub_len);
    if (!octet) {
        GOSTerr(GOST_F_PUB_DECODE_GOST94, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    databuf = OPENSSL_malloc(octet->length);
    if (databuf == NULL) {
        GOSTerr(GOST_F_PUB_DECODE_GOST94, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    for (i = 0, j = octet->length - 1; i < octet->length; i++, j--) {
        databuf[j] = octet->data[i];
    }
    dsa = EVP_PKEY_get0(pk);
    dsa->pub_key = BN_bin2bn(databuf, octet->length, NULL);
    ASN1_OCTET_STRING_free(octet);
    OPENSSL_free(databuf);
    return 1;

}

static int pub_encode_gost94(X509_PUBKEY *pub, const EVP_PKEY *pk)
{
    ASN1_OBJECT *algobj = NULL;
    ASN1_OCTET_STRING *octet = NULL;
    void *pval = NULL;
    unsigned char *buf = NULL, *databuf, *sptr;
    int i, j, data_len, ret = 0;

    int ptype = V_ASN1_UNDEF;
    DSA *dsa = EVP_PKEY_get0((EVP_PKEY *)pk);
    algobj = OBJ_nid2obj(EVP_PKEY_base_id(pk));
    if (pk->save_parameters) {
        ASN1_STRING *params = encode_gost_algor_params(pk);
        pval = params;
        ptype = V_ASN1_SEQUENCE;
    }
    data_len = BN_num_bytes(dsa->pub_key);
    databuf = OPENSSL_malloc(data_len);
    if (databuf == NULL)
        return 0;
    BN_bn2bin(dsa->pub_key, databuf);
    octet = ASN1_OCTET_STRING_new();
    ASN1_STRING_set(octet, NULL, data_len);
    sptr = ASN1_STRING_data(octet);
    for (i = 0, j = data_len - 1; i < data_len; i++, j--) {
        sptr[i] = databuf[j];
    }
    OPENSSL_free(databuf);
    ret = i2d_ASN1_OCTET_STRING(octet, &buf);
    ASN1_BIT_STRING_free(octet);
    if (ret < 0)
        return 0;
    return X509_PUBKEY_set0_param(pub, algobj, ptype, pval, buf, ret);
}

static int pub_decode_gost01(EVP_PKEY *pk, X509_PUBKEY *pub)
{
    X509_ALGOR *palg = NULL;
    const unsigned char *pubkey_buf = NULL;
    unsigned char *databuf;
    ASN1_OBJECT *palgobj = NULL;
    int pub_len, i, j;
    EC_POINT *pub_key;
    BIGNUM *X, *Y;
    ASN1_OCTET_STRING *octet = NULL;
    int len;
    const EC_GROUP *group;

    if (!X509_PUBKEY_get0_param(&palgobj, &pubkey_buf, &pub_len, &palg, pub))
        return 0;
    EVP_PKEY_assign(pk, OBJ_obj2nid(palgobj), NULL);
    if (!decode_gost_algor_params(pk, palg))
        return 0;
    group = EC_KEY_get0_group(EVP_PKEY_get0(pk));
    octet = d2i_ASN1_OCTET_STRING(NULL, &pubkey_buf, pub_len);
    if (!octet) {
        GOSTerr(GOST_F_PUB_DECODE_GOST01, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    databuf = OPENSSL_malloc(octet->length);
    if (databuf == NULL) {
        GOSTerr(GOST_F_PUB_DECODE_GOST01, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    for (i = 0, j = octet->length - 1; i < octet->length; i++, j--) {
        databuf[j] = octet->data[i];
    }
    len = octet->length / 2;
    ASN1_OCTET_STRING_free(octet);

    Y = getbnfrombuf(databuf, len);
    X = getbnfrombuf(databuf + len, len);
    OPENSSL_free(databuf);
    pub_key = EC_POINT_new(group);
    if (!EC_POINT_set_affine_coordinates_GFp(group, pub_key, X, Y, NULL)) {
        GOSTerr(GOST_F_PUB_DECODE_GOST01, ERR_R_EC_LIB);
        EC_POINT_free(pub_key);
        BN_free(X);
        BN_free(Y);
        return 0;
    }
    BN_free(X);
    BN_free(Y);
    if (!EC_KEY_set_public_key(EVP_PKEY_get0(pk), pub_key)) {
        GOSTerr(GOST_F_PUB_DECODE_GOST01, ERR_R_EC_LIB);
        EC_POINT_free(pub_key);
        return 0;
    }
    EC_POINT_free(pub_key);
    return 1;

}

static int pub_encode_gost01(X509_PUBKEY *pub, const EVP_PKEY *pk)
{
    ASN1_OBJECT *algobj = NULL;
    ASN1_OCTET_STRING *octet = NULL;
    void *pval = NULL;
    unsigned char *buf = NULL, *databuf, *sptr;
    int i, j, data_len, ret = 0;
    const EC_POINT *pub_key;
    BIGNUM *X, *Y, *order;
    const EC_KEY *ec = EVP_PKEY_get0((EVP_PKEY *)pk);
    int ptype = V_ASN1_UNDEF;

    algobj = OBJ_nid2obj(EVP_PKEY_base_id(pk));
    if (pk->save_parameters) {
        ASN1_STRING *params = encode_gost_algor_params(pk);
        pval = params;
        ptype = V_ASN1_SEQUENCE;
    }
    order = BN_new();
    EC_GROUP_get_order(EC_KEY_get0_group(ec), order, NULL);
    pub_key = EC_KEY_get0_public_key(ec);
    if (!pub_key) {
        GOSTerr(GOST_F_PUB_ENCODE_GOST01, GOST_R_PUBLIC_KEY_UNDEFINED);
        return 0;
    }
    X = BN_new();
    Y = BN_new();
    if(!X || !Y) {
        GOSTerr(GOST_F_PUB_ENCODE_GOST01, ERR_R_MALLOC_FAILURE);
        if(X) BN_free(X);
        if(Y) BN_free(Y);
        BN_free(order);
        return 0;
    }
    if(!EC_POINT_get_affine_coordinates_GFp(EC_KEY_get0_group(ec),
                                        pub_key, X, Y, NULL)) {
        GOSTerr(GOST_F_PUB_ENCODE_GOST01, ERR_R_INTERNAL_ERROR);
        BN_free(X);
        BN_free(Y);
        BN_free(order);
        return 0;
    }
    data_len = 2 * BN_num_bytes(order);
    BN_free(order);
    databuf = OPENSSL_malloc(data_len);
    if (databuf == NULL) {
        GOSTerr(GOST_F_PUB_ENCODE_GOST01, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    memset(databuf, 0, data_len);

    store_bignum(X, databuf + data_len / 2, data_len / 2);
    store_bignum(Y, databuf, data_len / 2);

    BN_free(X);
    BN_free(Y);
    octet = ASN1_OCTET_STRING_new();
    ASN1_STRING_set(octet, NULL, data_len);
    sptr = ASN1_STRING_data(octet);
    for (i = 0, j = data_len - 1; i < data_len; i++, j--) {
        sptr[i] = databuf[j];
    }
    OPENSSL_free(databuf);
    ret = i2d_ASN1_OCTET_STRING(octet, &buf);
    ASN1_BIT_STRING_free(octet);
    if (ret < 0)
        return 0;
    return X509_PUBKEY_set0_param(pub, algobj, ptype, pval, buf, ret);
}

static int pub_cmp_gost94(const EVP_PKEY *a, const EVP_PKEY *b)
{
    const DSA *da = EVP_PKEY_get0((EVP_PKEY *)a);
    const DSA *db = EVP_PKEY_get0((EVP_PKEY *)b);
    if (da && db && da->pub_key && db->pub_key
        && !BN_cmp(da->pub_key, db->pub_key)) {
        return 1;
    }
    return 0;
}

static int pub_cmp_gost01(const EVP_PKEY *a, const EVP_PKEY *b)
{
    const EC_KEY *ea = EVP_PKEY_get0((EVP_PKEY *)a);
    const EC_KEY *eb = EVP_PKEY_get0((EVP_PKEY *)b);
    const EC_POINT *ka, *kb;
    int ret = 0;
    if (!ea || !eb)
        return 0;
    ka = EC_KEY_get0_public_key(ea);
    kb = EC_KEY_get0_public_key(eb);
    if (!ka || !kb)
        return 0;
    ret = (0 == EC_POINT_cmp(EC_KEY_get0_group(ea), ka, kb, NULL));
    return ret;
}

static int pkey_size_gost(const EVP_PKEY *pk)
{
    return 64;
}

static int pkey_bits_gost(const EVP_PKEY *pk)
{
    return 256;
}

/* ---------------------- ASN1 METHOD for GOST MAC  -------------------*/
static void mackey_free_gost(EVP_PKEY *pk)
{
    if (pk->pkey.ptr) {
        OPENSSL_free(pk->pkey.ptr);
    }
}

static int mac_ctrl_gost(EVP_PKEY *pkey, int op, long arg1, void *arg2)
{
    switch (op) {
    case ASN1_PKEY_CTRL_DEFAULT_MD_NID:
        *(int *)arg2 = NID_id_Gost28147_89_MAC;
        return 2;
    }
    return -2;
}

static int gost94_param_encode(const EVP_PKEY *pkey, unsigned char **pder)
{
    int nid = gost94_nid_by_params(EVP_PKEY_get0((EVP_PKEY *)pkey));
    return i2d_ASN1_OBJECT(OBJ_nid2obj(nid), pder);
}

static int gost2001_param_encode(const EVP_PKEY *pkey, unsigned char **pder)
{
    int nid =
        EC_GROUP_get_curve_name(EC_KEY_get0_group
                                (EVP_PKEY_get0((EVP_PKEY *)pkey)));
    return i2d_ASN1_OBJECT(OBJ_nid2obj(nid), pder);
}

static int gost94_param_decode(EVP_PKEY *pkey, const unsigned char **pder,
                               int derlen)
{
    ASN1_OBJECT *obj = NULL;
    DSA *dsa = EVP_PKEY_get0(pkey);
    int nid;
    if (d2i_ASN1_OBJECT(&obj, pder, derlen) == NULL) {
        return 0;
    }
    nid = OBJ_obj2nid(obj);
    ASN1_OBJECT_free(obj);
    if (!dsa) {
        dsa = DSA_new();
        if (!EVP_PKEY_assign(pkey, NID_id_GostR3410_94, dsa))
            return 0;
    }
    if (!fill_GOST94_params(dsa, nid))
        return 0;
    return 1;
}

static int gost2001_param_decode(EVP_PKEY *pkey, const unsigned char **pder,
                                 int derlen)
{
    ASN1_OBJECT *obj = NULL;
    int nid;
    EC_KEY *ec = EVP_PKEY_get0(pkey);
    if (d2i_ASN1_OBJECT(&obj, pder, derlen) == NULL) {
        return 0;
    }
    nid = OBJ_obj2nid(obj);
    ASN1_OBJECT_free(obj);
    if (!ec) {
        ec = EC_KEY_new();
        if (!EVP_PKEY_assign(pkey, NID_id_GostR3410_2001, ec))
            return 0;
    }
    if (!fill_GOST2001_params(ec, nid))
        return 0;
    return 1;
}

/* ----------------------------------------------------------------------*/
int register_ameth_gost(int nid, EVP_PKEY_ASN1_METHOD **ameth,
                        const char *pemstr, const char *info)
{
    *ameth = EVP_PKEY_asn1_new(nid, ASN1_PKEY_SIGPARAM_NULL, pemstr, info);
    if (!*ameth)
        return 0;
    switch (nid) {
    case NID_id_GostR3410_94:
        EVP_PKEY_asn1_set_free(*ameth, pkey_free_gost94);
        EVP_PKEY_asn1_set_private(*ameth,
                                  priv_decode_gost, priv_encode_gost,
                                  priv_print_gost94);

        EVP_PKEY_asn1_set_param(*ameth,
                                gost94_param_decode, gost94_param_encode,
                                param_missing_gost94, param_copy_gost94,
                                param_cmp_gost94, param_print_gost94);
        EVP_PKEY_asn1_set_public(*ameth,
                                 pub_decode_gost94, pub_encode_gost94,
                                 pub_cmp_gost94, pub_print_gost94,
                                 pkey_size_gost, pkey_bits_gost);

        EVP_PKEY_asn1_set_ctrl(*ameth, pkey_ctrl_gost);
        break;
    case NID_id_GostR3410_2001:
        EVP_PKEY_asn1_set_free(*ameth, pkey_free_gost01);
        EVP_PKEY_asn1_set_private(*ameth,
                                  priv_decode_gost, priv_encode_gost,
                                  priv_print_gost01);

        EVP_PKEY_asn1_set_param(*ameth,
                                gost2001_param_decode, gost2001_param_encode,
                                param_missing_gost01, param_copy_gost01,
                                param_cmp_gost01, param_print_gost01);
        EVP_PKEY_asn1_set_public(*ameth,
                                 pub_decode_gost01, pub_encode_gost01,
                                 pub_cmp_gost01, pub_print_gost01,
                                 pkey_size_gost, pkey_bits_gost);

        EVP_PKEY_asn1_set_ctrl(*ameth, pkey_ctrl_gost);
        break;
    case NID_id_Gost28147_89_MAC:
        EVP_PKEY_asn1_set_free(*ameth, mackey_free_gost);
        EVP_PKEY_asn1_set_ctrl(*ameth, mac_ctrl_gost);
        break;
    }
    return 1;
}
/**********************************************************************
 *                          gost_keytrans.c                           *
 *             Copyright (c) 2005-2006 Cryptocom LTD                  *
 *         This file is distributed under the same license as OpenSSL *
 *                                                                    *
 *   ASN1 structure definition for GOST key transport                 *
 *          Requires OpenSSL 0.9.9 for compilation                    *
 **********************************************************************/
#include <stdio.h>
#include "asn1t.h"
#include "x509.h"
// #include "gost_lcl.h"

ASN1_NDEF_SEQUENCE(GOST_KEY_TRANSPORT) = {
        ASN1_SIMPLE(GOST_KEY_TRANSPORT, key_info, GOST_KEY_INFO),
        ASN1_IMP(GOST_KEY_TRANSPORT, key_agreement_info, GOST_KEY_AGREEMENT_INFO, 0)
} ASN1_NDEF_SEQUENCE_END(GOST_KEY_TRANSPORT)

IMPLEMENT_ASN1_FUNCTIONS(GOST_KEY_TRANSPORT)

ASN1_NDEF_SEQUENCE(GOST_KEY_INFO) = {
        ASN1_SIMPLE(GOST_KEY_INFO, encrypted_key, ASN1_OCTET_STRING),
        ASN1_SIMPLE(GOST_KEY_INFO, imit,          ASN1_OCTET_STRING)
} ASN1_NDEF_SEQUENCE_END(GOST_KEY_INFO)

IMPLEMENT_ASN1_FUNCTIONS(GOST_KEY_INFO)

ASN1_NDEF_SEQUENCE(GOST_KEY_AGREEMENT_INFO) = {
        ASN1_SIMPLE(GOST_KEY_AGREEMENT_INFO, cipher, ASN1_OBJECT),
        ASN1_IMP_OPT(GOST_KEY_AGREEMENT_INFO, ephem_key, X509_PUBKEY, 0),
        ASN1_SIMPLE(GOST_KEY_AGREEMENT_INFO, eph_iv, ASN1_OCTET_STRING)
} ASN1_NDEF_SEQUENCE_END(GOST_KEY_AGREEMENT_INFO)

IMPLEMENT_ASN1_FUNCTIONS(GOST_KEY_AGREEMENT_INFO)

ASN1_NDEF_SEQUENCE(GOST_KEY_PARAMS) = {
        ASN1_SIMPLE(GOST_KEY_PARAMS, key_params, ASN1_OBJECT),
        ASN1_SIMPLE(GOST_KEY_PARAMS, hash_params, ASN1_OBJECT),
        ASN1_OPT(GOST_KEY_PARAMS, cipher_params, ASN1_OBJECT),
} ASN1_NDEF_SEQUENCE_END(GOST_KEY_PARAMS)

IMPLEMENT_ASN1_FUNCTIONS(GOST_KEY_PARAMS)

ASN1_NDEF_SEQUENCE(GOST_CIPHER_PARAMS) = {
        ASN1_SIMPLE(GOST_CIPHER_PARAMS, iv, ASN1_OCTET_STRING),
        ASN1_SIMPLE(GOST_CIPHER_PARAMS, enc_param_set, ASN1_OBJECT),
} ASN1_NDEF_SEQUENCE_END(GOST_CIPHER_PARAMS)

IMPLEMENT_ASN1_FUNCTIONS(GOST_CIPHER_PARAMS)

ASN1_NDEF_SEQUENCE(GOST_CLIENT_KEY_EXCHANGE_PARAMS) = { /* FIXME incomplete */
    ASN1_SIMPLE(GOST_CLIENT_KEY_EXCHANGE_PARAMS, gkt, GOST_KEY_TRANSPORT)
}

ASN1_NDEF_SEQUENCE_END(GOST_CLIENT_KEY_EXCHANGE_PARAMS)
IMPLEMENT_ASN1_FUNCTIONS(GOST_CLIENT_KEY_EXCHANGE_PARAMS)
/**********************************************************************
 *                          gost_crypt.c                              *
 *             Copyright (c) 2005-2006 Cryptocom LTD                  *
 *         This file is distributed under the same license as OpenSSL *
 *                                                                    *
 *       OpenSSL interface to GOST 28147-89 cipher functions          *
 *          Requires OpenSSL 0.9.9 for compilation                    *
 **********************************************************************/
#include <string.h>
#include "gost89.h"
#include "rand.h"
// #include "e_gost_err.h"
// #include "gost_lcl.h"

#if !defined(CCGOST_DEBUG) && !defined(DEBUG)
# ifndef NDEBUG
#  define NDEBUG
# endif
#endif
#include <assert.h>

static int gost_cipher_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                            const unsigned char *iv, int enc);
static int gost_cipher_init_cpa(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                                const unsigned char *iv, int enc);
/* Handles block of data in CFB mode */
static int gost_cipher_do_cfb(EVP_CIPHER_CTX *ctx, unsigned char *out,
                              const unsigned char *in, size_t inl);
/* Handles block of data in CNT mode */
static int gost_cipher_do_cnt(EVP_CIPHER_CTX *ctx, unsigned char *out,
                              const unsigned char *in, size_t inl);
/* Cleanup function */
static int gost_cipher_cleanup(EVP_CIPHER_CTX *);
/* set/get cipher parameters */
static int gost89_set_asn1_parameters(EVP_CIPHER_CTX *ctx, ASN1_TYPE *params);
static int gost89_get_asn1_parameters(EVP_CIPHER_CTX *ctx, ASN1_TYPE *params);
/* Control function */
static int gost_cipher_ctl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr);

EVP_CIPHER cipher_gost = {
    NID_id_Gost28147_89,
    1,                          /* block_size */
    32,                         /* key_size */
    8,                          /* iv_len */
    EVP_CIPH_CFB_MODE | EVP_CIPH_NO_PADDING |
        EVP_CIPH_CUSTOM_IV | EVP_CIPH_RAND_KEY | EVP_CIPH_ALWAYS_CALL_INIT,
    gost_cipher_init,
    gost_cipher_do_cfb,
    gost_cipher_cleanup,
    sizeof(struct ossl_gost_cipher_ctx), /* ctx_size */
    gost89_set_asn1_parameters,
    gost89_get_asn1_parameters,
    gost_cipher_ctl,
    NULL,
};

EVP_CIPHER cipher_gost_cpacnt = {
    NID_gost89_cnt,
    1,                          /* block_size */
    32,                         /* key_size */
    8,                          /* iv_len */
    EVP_CIPH_OFB_MODE | EVP_CIPH_NO_PADDING |
        EVP_CIPH_CUSTOM_IV | EVP_CIPH_RAND_KEY | EVP_CIPH_ALWAYS_CALL_INIT,
    gost_cipher_init_cpa,
    gost_cipher_do_cnt,
    gost_cipher_cleanup,
    sizeof(struct ossl_gost_cipher_ctx), /* ctx_size */
    gost89_set_asn1_parameters,
    gost89_get_asn1_parameters,
    gost_cipher_ctl,
    NULL,
};

/* Implementation of GOST 28147-89 in MAC (imitovstavka) mode */
/* Init functions which set specific parameters */
static int gost_imit_init_cpa(EVP_MD_CTX *ctx);
/* process block of data */
static int gost_imit_update(EVP_MD_CTX *ctx, const void *data, size_t count);
/* Return computed value */
static int gost_imit_final(EVP_MD_CTX *ctx, unsigned char *md);
/* Copies context */
static int gost_imit_copy(EVP_MD_CTX *to, const EVP_MD_CTX *from);
static int gost_imit_cleanup(EVP_MD_CTX *ctx);
/* Control function, knows how to set MAC key.*/
static int gost_imit_ctrl(EVP_MD_CTX *ctx, int type, int arg, void *ptr);

EVP_MD imit_gost_cpa = {
    NID_id_Gost28147_89_MAC,
    NID_undef,
    4,
    0,
    gost_imit_init_cpa,
    gost_imit_update,
    gost_imit_final,
    gost_imit_copy,
    gost_imit_cleanup,
    NULL,
    NULL,
    {0, 0, 0, 0, 0},
    8,
    sizeof(struct ossl_gost_imit_ctx),
    gost_imit_ctrl
};

/*
 * Correspondence between gost parameter OIDs and substitution blocks
 * NID field is filed by register_gost_NID function in engine.c
 * upon engine initialization
 */

struct gost_cipher_info gost_cipher_list[] = {
    /*- NID *//*
     * Subst block
     *//*
     * Key meshing
     */
    /*
     * {NID_id_GostR3411_94_CryptoProParamSet,&GostR3411_94_CryptoProParamSet,0},
     */
    {NID_id_Gost28147_89_cc, &GostR3411_94_CryptoProParamSet, 0},
    {NID_id_Gost28147_89_CryptoPro_A_ParamSet, &Gost28147_CryptoProParamSetA,
     1},
    {NID_id_Gost28147_89_CryptoPro_B_ParamSet, &Gost28147_CryptoProParamSetB,
     1},
    {NID_id_Gost28147_89_CryptoPro_C_ParamSet, &Gost28147_CryptoProParamSetC,
     1},
    {NID_id_Gost28147_89_CryptoPro_D_ParamSet, &Gost28147_CryptoProParamSetD,
     1},
    {NID_id_Gost28147_89_TestParamSet, &Gost28147_TestParamSet, 1},
    {NID_undef, NULL, 0}
};

/*
 * get encryption parameters from crypto network settings FIXME For now we
 * use environment var CRYPT_PARAMS as place to store these settings.
 * Actually, it is better to use engine control command, read from
 * configuration file to set them
 */
const struct gost_cipher_info *get_encryption_params(ASN1_OBJECT *obj)
{
    int nid;
    struct gost_cipher_info *param;
    if (!obj) {
        const char *params = get_gost_engine_param(GOST_PARAM_CRYPT_PARAMS);
        if (!params || !strlen(params))
            return &gost_cipher_list[1];

        nid = OBJ_txt2nid(params);
        if (nid == NID_undef) {
            GOSTerr(GOST_F_GET_ENCRYPTION_PARAMS,
                    GOST_R_INVALID_CIPHER_PARAM_OID);
            return NULL;
        }
    } else {
        nid = OBJ_obj2nid(obj);
    }
    for (param = gost_cipher_list; param->sblock != NULL && param->nid != nid;
         param++) ;
    if (!param->sblock) {
        GOSTerr(GOST_F_GET_ENCRYPTION_PARAMS, GOST_R_INVALID_CIPHER_PARAMS);
        return NULL;
    }
    return param;
}

/* Sets cipher param from paramset NID. */
static int gost_cipher_set_param(struct ossl_gost_cipher_ctx *c, int nid)
{
    const struct gost_cipher_info *param;
    param =
        get_encryption_params((nid == NID_undef ? NULL : OBJ_nid2obj(nid)));
    if (!param)
        return 0;

    c->paramNID = param->nid;
    c->key_meshing = param->key_meshing;
    c->count = 0;
    gost_init(&(c->cctx), param->sblock);
    return 1;
}

/* Initializes EVP_CIPHER_CTX by paramset NID */
static int gost_cipher_init_param(EVP_CIPHER_CTX *ctx,
                                  const unsigned char *key,
                                  const unsigned char *iv, int enc,
                                  int paramNID, int mode)
{
    struct ossl_gost_cipher_ctx *c = ctx->cipher_data;
    if (ctx->app_data == NULL) {
        if (!gost_cipher_set_param(c, paramNID))
            return 0;
        ctx->app_data = ctx->cipher_data;
    }
    if (key)
        gost_key(&(c->cctx), key);
    if (iv)
        memcpy(ctx->oiv, iv, EVP_CIPHER_CTX_iv_length(ctx));
    memcpy(ctx->iv, ctx->oiv, EVP_CIPHER_CTX_iv_length(ctx));
    return 1;
}

static int gost_cipher_init_cpa(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                                const unsigned char *iv, int enc)
{
    struct ossl_gost_cipher_ctx *c = ctx->cipher_data;
    gost_init(&(c->cctx), &Gost28147_CryptoProParamSetA);
    c->key_meshing = 1;
    c->count = 0;
    if (key)
        gost_key(&(c->cctx), key);
    if (iv)
        memcpy(ctx->oiv, iv, EVP_CIPHER_CTX_iv_length(ctx));
    memcpy(ctx->iv, ctx->oiv, EVP_CIPHER_CTX_iv_length(ctx));
    return 1;
}

/* Initializes EVP_CIPHER_CTX with default values */
int gost_cipher_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                     const unsigned char *iv, int enc)
{
    return gost_cipher_init_param(ctx, key, iv, enc, NID_undef,
                                  EVP_CIPH_CFB_MODE);
}

/*
 * Wrapper around gostcrypt function from gost89.c which perform key meshing
 * when nesseccary
 */
static void gost_crypt_mesh(void *ctx, unsigned char *iv, unsigned char *buf)
{
    struct ossl_gost_cipher_ctx *c = ctx;
    assert(c->count % 8 == 0 && c->count <= 1024);
    if (c->key_meshing && c->count == 1024) {
        cryptopro_key_meshing(&(c->cctx), iv);
    }
    gostcrypt(&(c->cctx), iv, buf);
    c->count = c->count % 1024 + 8;
}

static void gost_cnt_next(void *ctx, unsigned char *iv, unsigned char *buf)
{
    struct ossl_gost_cipher_ctx *c = ctx;
    word32 g, go;
    unsigned char buf1[8];
    assert(c->count % 8 == 0 && c->count <= 1024);
    if (c->key_meshing && c->count == 1024) {
        cryptopro_key_meshing(&(c->cctx), iv);
    }
    if (c->count == 0) {
        gostcrypt(&(c->cctx), iv, buf1);
    } else {
        memcpy(buf1, iv, 8);
    }
    g = buf1[0] | (buf1[1] << 8) | (buf1[2] << 16) | ((word32) buf1[3] << 24);
    g += 0x01010101;
    buf1[0] = (unsigned char)(g & 0xff);
    buf1[1] = (unsigned char)((g >> 8) & 0xff);
    buf1[2] = (unsigned char)((g >> 16) & 0xff);
    buf1[3] = (unsigned char)((g >> 24) & 0xff);
    g = buf1[4] | (buf1[5] << 8) | (buf1[6] << 16) | ((word32) buf1[7] << 24);
    go = g;
    g += 0x01010104;
    if (go > g)                 /* overflow */
        g++;
    buf1[4] = (unsigned char)(g & 0xff);
    buf1[5] = (unsigned char)((g >> 8) & 0xff);
    buf1[6] = (unsigned char)((g >> 16) & 0xff);
    buf1[7] = (unsigned char)((g >> 24) & 0xff);
    memcpy(iv, buf1, 8);
    gostcrypt(&(c->cctx), buf1, buf);
    c->count = c->count % 1024 + 8;
}

/* GOST encryption in CFB mode */
int gost_cipher_do_cfb(EVP_CIPHER_CTX *ctx, unsigned char *out,
                       const unsigned char *in, size_t inl)
{
    const unsigned char *in_ptr = in;
    unsigned char *out_ptr = out;
    size_t i = 0;
    size_t j = 0;
/* process partial block if any */
    if (ctx->num) {
        for (j = ctx->num, i = 0; j < 8 && i < inl;
             j++, i++, in_ptr++, out_ptr++) {
            if (!ctx->encrypt)
                ctx->buf[j + 8] = *in_ptr;
            *out_ptr = ctx->buf[j] ^ (*in_ptr);
            if (ctx->encrypt)
                ctx->buf[j + 8] = *out_ptr;
        }
        if (j == 8) {
            memcpy(ctx->iv, ctx->buf + 8, 8);
            ctx->num = 0;
        } else {
            ctx->num = j;
            return 1;
        }
    }

    for (; i + 8 < inl; i += 8, in_ptr += 8, out_ptr += 8) {
        /*
         * block cipher current iv
         */
        gost_crypt_mesh(ctx->cipher_data, ctx->iv, ctx->buf);
        /*
         * xor next block of input text with it and output it
         */
        /*
         * output this block
         */
        if (!ctx->encrypt)
            memcpy(ctx->iv, in_ptr, 8);
        for (j = 0; j < 8; j++) {
            out_ptr[j] = ctx->buf[j] ^ in_ptr[j];
        }
        /* Encrypt */
        /* Next iv is next block of cipher text */
        if (ctx->encrypt)
            memcpy(ctx->iv, out_ptr, 8);
    }
/* Process rest of buffer */
    if (i < inl) {
        gost_crypt_mesh(ctx->cipher_data, ctx->iv, ctx->buf);
        if (!ctx->encrypt)
            memcpy(ctx->buf + 8, in_ptr, inl - i);
        for (j = 0; i < inl; j++, i++) {
            out_ptr[j] = ctx->buf[j] ^ in_ptr[j];
        }
        ctx->num = j;
        if (ctx->encrypt)
            memcpy(ctx->buf + 8, out_ptr, j);
    } else {
        ctx->num = 0;
    }
    return 1;
}

static int gost_cipher_do_cnt(EVP_CIPHER_CTX *ctx, unsigned char *out,
                              const unsigned char *in, size_t inl)
{
    const unsigned char *in_ptr = in;
    unsigned char *out_ptr = out;
    size_t i = 0;
    size_t j;
/* process partial block if any */
    if (ctx->num) {
        for (j = ctx->num, i = 0; j < 8 && i < inl;
             j++, i++, in_ptr++, out_ptr++) {
            *out_ptr = ctx->buf[j] ^ (*in_ptr);
        }
        if (j == 8) {
            ctx->num = 0;
        } else {
            ctx->num = j;
            return 1;
        }
    }

    for (; i + 8 < inl; i += 8, in_ptr += 8, out_ptr += 8) {
        /*
         * block cipher current iv
         */
        /* Encrypt */
        gost_cnt_next(ctx->cipher_data, ctx->iv, ctx->buf);
        /*
         * xor next block of input text with it and output it
         */
        /*
         * output this block
         */
        for (j = 0; j < 8; j++) {
            out_ptr[j] = ctx->buf[j] ^ in_ptr[j];
        }
    }
/* Process rest of buffer */
    if (i < inl) {
        gost_cnt_next(ctx->cipher_data, ctx->iv, ctx->buf);
        for (j = 0; i < inl; j++, i++) {
            out_ptr[j] = ctx->buf[j] ^ in_ptr[j];
        }
        ctx->num = j;
    } else {
        ctx->num = 0;
    }
    return 1;
}

/* Cleaning up of EVP_CIPHER_CTX */
int gost_cipher_cleanup(EVP_CIPHER_CTX *ctx)
{
    gost_destroy(&((struct ossl_gost_cipher_ctx *)ctx->cipher_data)->cctx);
    ctx->app_data = NULL;
    return 1;
}

/* Control function for gost cipher */
int gost_cipher_ctl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr)
{
    switch (type) {
    case EVP_CTRL_RAND_KEY:
        {
            if (RAND_bytes((unsigned char *)ptr, ctx->key_len) <= 0) {
                GOSTerr(GOST_F_GOST_CIPHER_CTL,
                        GOST_R_RANDOM_GENERATOR_ERROR);
                return -1;
            }
            break;
        }
    case EVP_CTRL_PBE_PRF_NID:
        if (ptr) {
            *((int *)ptr) = NID_id_HMACGostR3411_94;
            return 1;
        } else {
            return 0;
        }

    default:
        GOSTerr(GOST_F_GOST_CIPHER_CTL,
                GOST_R_UNSUPPORTED_CIPHER_CTL_COMMAND);
        return -1;
    }
    return 1;
}

/* Set cipher parameters from ASN1 structure */
int gost89_set_asn1_parameters(EVP_CIPHER_CTX *ctx, ASN1_TYPE *params)
{
    int len = 0;
    unsigned char *buf = NULL;
    unsigned char *p = NULL;
    struct ossl_gost_cipher_ctx *c = ctx->cipher_data;
    GOST_CIPHER_PARAMS *gcp = GOST_CIPHER_PARAMS_new();
    ASN1_OCTET_STRING *os = NULL;
    if (!gcp) {
        GOSTerr(GOST_F_GOST89_SET_ASN1_PARAMETERS, GOST_R_NO_MEMORY);
        return 0;
    }
    if (!ASN1_OCTET_STRING_set(gcp->iv, ctx->iv, ctx->cipher->iv_len)) {
        GOST_CIPHER_PARAMS_free(gcp);
        GOSTerr(GOST_F_GOST89_SET_ASN1_PARAMETERS, GOST_R_NO_MEMORY);
        return 0;
    }
    ASN1_OBJECT_free(gcp->enc_param_set);
    gcp->enc_param_set = OBJ_nid2obj(c->paramNID);

    len = i2d_GOST_CIPHER_PARAMS(gcp, NULL);
    p = buf = (unsigned char *)OPENSSL_malloc(len);
    if (!buf) {
        GOST_CIPHER_PARAMS_free(gcp);
        GOSTerr(GOST_F_GOST89_SET_ASN1_PARAMETERS, GOST_R_NO_MEMORY);
        return 0;
    }
    i2d_GOST_CIPHER_PARAMS(gcp, &p);
    GOST_CIPHER_PARAMS_free(gcp);

    os = ASN1_OCTET_STRING_new();

    if (!os || !ASN1_OCTET_STRING_set(os, buf, len)) {
        OPENSSL_free(buf);
        GOSTerr(GOST_F_GOST89_SET_ASN1_PARAMETERS, GOST_R_NO_MEMORY);
        return 0;
    }
    OPENSSL_free(buf);

    ASN1_TYPE_set(params, V_ASN1_SEQUENCE, os);
    return 1;
}

/* Store parameters into ASN1 structure */
int gost89_get_asn1_parameters(EVP_CIPHER_CTX *ctx, ASN1_TYPE *params)
{
    int ret = -1;
    int len;
    GOST_CIPHER_PARAMS *gcp = NULL;
    unsigned char *p;
    struct ossl_gost_cipher_ctx *c = ctx->cipher_data;
    if (ASN1_TYPE_get(params) != V_ASN1_SEQUENCE) {
        return ret;
    }

    p = params->value.sequence->data;

    gcp = d2i_GOST_CIPHER_PARAMS(NULL, (const unsigned char **)&p,
                                 params->value.sequence->length);

    len = gcp->iv->length;
    if (len != ctx->cipher->iv_len) {
        GOST_CIPHER_PARAMS_free(gcp);
        GOSTerr(GOST_F_GOST89_GET_ASN1_PARAMETERS, GOST_R_INVALID_IV_LENGTH);
        return -1;
    }
    if (!gost_cipher_set_param(c, OBJ_obj2nid(gcp->enc_param_set))) {
        GOST_CIPHER_PARAMS_free(gcp);
        return -1;
    }
    memcpy(ctx->oiv, gcp->iv->data, len);

    GOST_CIPHER_PARAMS_free(gcp);

    return 1;
}

int gost_imit_init_cpa(EVP_MD_CTX *ctx)
{
    struct ossl_gost_imit_ctx *c = ctx->md_data;
    memset(c->buffer, 0, sizeof(c->buffer));
    memset(c->partial_block, 0, sizeof(c->partial_block));
    c->count = 0;
    c->bytes_left = 0;
    c->key_meshing = 1;
    gost_init(&(c->cctx), &Gost28147_CryptoProParamSetA);
    return 1;
}

static void mac_block_mesh(struct ossl_gost_imit_ctx *c,
                           const unsigned char *data)
{
    unsigned char buffer[8];
    /*
     * We are using local buffer for iv because CryptoPro doesn't interpret
     * internal state of MAC algorithm as iv during keymeshing (but does
     * initialize internal state from iv in key transport
     */
    assert(c->count % 8 == 0 && c->count <= 1024);
    if (c->key_meshing && c->count == 1024) {
        cryptopro_key_meshing(&(c->cctx), buffer);
    }
    mac_block(&(c->cctx), c->buffer, data);
    c->count = c->count % 1024 + 8;
}

int gost_imit_update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    struct ossl_gost_imit_ctx *c = ctx->md_data;
    const unsigned char *p = data;
    size_t bytes = count, i;
    if (!(c->key_set)) {
        GOSTerr(GOST_F_GOST_IMIT_UPDATE, GOST_R_MAC_KEY_NOT_SET);
        return 0;
    }
    if (c->bytes_left) {
        for (i = c->bytes_left; i < 8 && bytes > 0; bytes--, i++, p++) {
            c->partial_block[i] = *p;
        }
        if (i == 8) {
            mac_block_mesh(c, c->partial_block);
        } else {
            c->bytes_left = i;
            return 1;
        }
    }
    while (bytes > 8) {
        mac_block_mesh(c, p);
        p += 8;
        bytes -= 8;
    }
    if (bytes > 0) {
        memcpy(c->partial_block, p, bytes);
    }
    c->bytes_left = bytes;
    return 1;
}

int gost_imit_final(EVP_MD_CTX *ctx, unsigned char *md)
{
    struct ossl_gost_imit_ctx *c = ctx->md_data;
    if (!c->key_set) {
        GOSTerr(GOST_F_GOST_IMIT_FINAL, GOST_R_MAC_KEY_NOT_SET);
        return 0;
    }
    if (c->count == 0 && c->bytes_left) {
        unsigned char buffer[8];
        memset(buffer, 0, 8);
        gost_imit_update(ctx, buffer, 8);
    }
    if (c->bytes_left) {
        int i;
        for (i = c->bytes_left; i < 8; i++) {
            c->partial_block[i] = 0;
        }
        mac_block_mesh(c, c->partial_block);
    }
    get_mac(c->buffer, 32, md);
    return 1;
}

int gost_imit_ctrl(EVP_MD_CTX *ctx, int type, int arg, void *ptr)
{
    switch (type) {
    case EVP_MD_CTRL_KEY_LEN:
        *((unsigned int *)(ptr)) = 32;
        return 1;
    case EVP_MD_CTRL_SET_KEY:
        {
            if (arg != 32) {
                GOSTerr(GOST_F_GOST_IMIT_CTRL, GOST_R_INVALID_MAC_KEY_LENGTH);
                return 0;
            }

            gost_key(&(((struct ossl_gost_imit_ctx *)(ctx->md_data))->cctx),
                     ptr);
            ((struct ossl_gost_imit_ctx *)(ctx->md_data))->key_set = 1;
            return 1;

        }
    default:
        return 0;
    }
}

int gost_imit_copy(EVP_MD_CTX *to, const EVP_MD_CTX *from)
{
    memcpy(to->md_data, from->md_data, sizeof(struct ossl_gost_imit_ctx));
    return 1;
}

/* Clean up imit ctx */
int gost_imit_cleanup(EVP_MD_CTX *ctx)
{
    memset(ctx->md_data, 0, sizeof(struct ossl_gost_imit_ctx));
    return 1;
}
/**********************************************************************
 *                        gost_ctl.c                                  *
 *             Copyright (c) 2005-2006 Cryptocom LTD                  *
 *       This file is distributed under the same license as OpenSSL   *
 *                                                                    *
 *        Implementation of control commands for GOST engine          *
 *            OpenSSL 0.9.9 libraries required                        *
 **********************************************************************/
#include <stdlib.h>
#include <string.h>
// #include "crypto.h"
// #include "err.h"
// #include "engine.h"
#include "buffer.h"
// #include "gost_lcl.h"

static char *gost_params[GOST_PARAM_MAX + 1] = { NULL };
static const char *gost_envnames[] = { "CRYPT_PARAMS" };

const ENGINE_CMD_DEFN gost_cmds[] = {
/*- { GOST_CTRL_RNG,
    "RNG",
    "Type of random number generator to use",
    ENGINE_CMD_FLAG_STRING
    },
    { GOST_CTRL_RNG_PARAMS,
    "RNG_PARAMS",
    "Parameter for random number generator",
    ENGINE_CMD_FLAG_STRING
    },
*/ {GOST_CTRL_CRYPT_PARAMS,
           "CRYPT_PARAMS",
           "OID of default GOST 28147-89 parameters",
           ENGINE_CMD_FLAG_STRING},
    {0, NULL, NULL, 0}
};

void gost_param_free()
{
    int i;
    for (i = 0; i <= GOST_PARAM_MAX; i++)
        if (gost_params[i] != NULL) {
            OPENSSL_free(gost_params[i]);
            gost_params[i] = NULL;
        }

}

int gost_control_func(ENGINE *e, int cmd, long i, void *p, void (*f) (void))
{
    int param = cmd - ENGINE_CMD_BASE;
    int ret = 0;
    if (param < 0 || param > GOST_PARAM_MAX)
        return -1;
    ret = gost_set_default_param(param, p);
    return ret;
}

const char *get_gost_engine_param(int param)
{
    char *tmp;
    if (param < 0 || param > GOST_PARAM_MAX)
        return NULL;
    if (gost_params[param] != NULL) {
        return gost_params[param];
    }
    tmp = getenv(gost_envnames[param]);
    if (tmp) {
        if (gost_params[param])
            OPENSSL_free(gost_params[param]);
        gost_params[param] = BUF_strdup(tmp);
        return gost_params[param];
    }
    return NULL;
}

int gost_set_default_param(int param, const char *value)
{
    const char *tmp;
    if (param < 0 || param > GOST_PARAM_MAX)
        return 0;
    tmp = getenv(gost_envnames[param]);
    /*
     * if there is value in the environment, use it, else -passed string *
     */
    if (!tmp)
        tmp = value;
    if (gost_params[param])
        OPENSSL_free(gost_params[param]);
    gost_params[param] = BUF_strdup(tmp);

    return 1;
}
/**********************************************************************
 *                          gost_eng.c                                *
 *             Copyright (c) 2005-2006 Cryptocom LTD                  *
 *         This file is distributed under the same license as OpenSSL *
 *                                                                    *
 *              Main file of GOST engine                              *
 *       for OpenSSL                                                  *
 *          Requires OpenSSL 0.9.9 for compilation                    *
 **********************************************************************/
#include <string.h>
// #include "crypto.h"
// #include "err.h"
// #include "evp.h"
// #include "engine.h"
#include "obj_mac.h"
// #include "e_gost_err.h"
// #include "gost_lcl.h"
static const char *engine_gost_id = "gost";
static const char *engine_gost_name =
    "Reference implementation of GOST engine";

/* Symmetric cipher and digest function registrar */

static int gost_ciphers(ENGINE *e, const EVP_CIPHER **cipher,
                        const int **nids, int nid);

static int gost_digests(ENGINE *e, const EVP_MD **digest,
                        const int **nids, int ind);

static int gost_pkey_meths(ENGINE *e, EVP_PKEY_METHOD **pmeth,
                           const int **nids, int nid);

static int gost_pkey_asn1_meths(ENGINE *e, EVP_PKEY_ASN1_METHOD **ameth,
                                const int **nids, int nid);

static int gost_cipher_nids[] = { NID_id_Gost28147_89, NID_gost89_cnt, 0 };

static int gost_digest_nids[] =
    { NID_id_GostR3411_94, NID_id_Gost28147_89_MAC, 0 };

static int gost_pkey_meth_nids[] = { NID_id_GostR3410_94,
    NID_id_GostR3410_2001, NID_id_Gost28147_89_MAC, 0
};

static EVP_PKEY_METHOD *pmeth_GostR3410_94 = NULL,
    *pmeth_GostR3410_2001 = NULL, *pmeth_Gost28147_MAC = NULL;

static EVP_PKEY_ASN1_METHOD *ameth_GostR3410_94 = NULL,
    *ameth_GostR3410_2001 = NULL, *ameth_Gost28147_MAC = NULL;

static int gost_engine_init(ENGINE *e)
{
    return 1;
}

static int gost_engine_finish(ENGINE *e)
{
    return 1;
}

static int gost_engine_destroy(ENGINE *e)
{
    gost_param_free();

    pmeth_GostR3410_94 = NULL;
    pmeth_GostR3410_2001 = NULL;
    pmeth_Gost28147_MAC = NULL;
    ameth_GostR3410_94 = NULL;
    ameth_GostR3410_2001 = NULL;
    ameth_Gost28147_MAC = NULL;
    return 1;
}

static int bind_gost(ENGINE *e, const char *id)
{
    int ret = 0;
    if (id && strcmp(id, engine_gost_id))
        return 0;
    if (ameth_GostR3410_94) {
        printf("GOST engine already loaded\n");
        goto end;
    }

    if (!ENGINE_set_id(e, engine_gost_id)) {
        printf("ENGINE_set_id failed\n");
        goto end;
    }
    if (!ENGINE_set_name(e, engine_gost_name)) {
        printf("ENGINE_set_name failed\n");
        goto end;
    }
    if (!ENGINE_set_digests(e, gost_digests)) {
        printf("ENGINE_set_digests failed\n");
        goto end;
    }
    if (!ENGINE_set_ciphers(e, gost_ciphers)) {
        printf("ENGINE_set_ciphers failed\n");
        goto end;
    }
    if (!ENGINE_set_pkey_meths(e, gost_pkey_meths)) {
        printf("ENGINE_set_pkey_meths failed\n");
        goto end;
    }
    if (!ENGINE_set_pkey_asn1_meths(e, gost_pkey_asn1_meths)) {
        printf("ENGINE_set_pkey_asn1_meths failed\n");
        goto end;
    }
    /* Control function and commands */
    if (!ENGINE_set_cmd_defns(e, gost_cmds)) {
        fprintf(stderr, "ENGINE_set_cmd_defns failed\n");
        goto end;
    }
    if (!ENGINE_set_ctrl_function(e, gost_control_func)) {
        fprintf(stderr, "ENGINE_set_ctrl_func failed\n");
        goto end;
    }
    if (!ENGINE_set_destroy_function(e, gost_engine_destroy)
        || !ENGINE_set_init_function(e, gost_engine_init)
        || !ENGINE_set_finish_function(e, gost_engine_finish)) {
        goto end;
    }

    if (!register_ameth_gost
        (NID_id_GostR3410_94, &ameth_GostR3410_94, "GOST94",
         "GOST R 34.10-94"))
        goto end;
    if (!register_ameth_gost
        (NID_id_GostR3410_2001, &ameth_GostR3410_2001, "GOST2001",
         "GOST R 34.10-2001"))
        goto end;
    if (!register_ameth_gost(NID_id_Gost28147_89_MAC, &ameth_Gost28147_MAC,
                             "GOST-MAC", "GOST 28147-89 MAC"))
        goto end;

    if (!register_pmeth_gost(NID_id_GostR3410_94, &pmeth_GostR3410_94, 0))
        goto end;
    if (!register_pmeth_gost(NID_id_GostR3410_2001, &pmeth_GostR3410_2001, 0))
        goto end;
    if (!register_pmeth_gost
        (NID_id_Gost28147_89_MAC, &pmeth_Gost28147_MAC, 0))
        goto end;
    if (!ENGINE_register_ciphers(e)
        || !ENGINE_register_digests(e)
        || !ENGINE_register_pkey_meths(e)
        /* These two actually should go in LIST_ADD command */
        || !EVP_add_cipher(&cipher_gost)
        || !EVP_add_cipher(&cipher_gost_cpacnt)
        || !EVP_add_digest(&digest_gost)
        || !EVP_add_digest(&imit_gost_cpa)
        ) {
        goto end;
    }

    ERR_load_GOST_strings();
    ret = 1;
 end:
    return ret;
}

static int gost_digests(ENGINE *e, const EVP_MD **digest,
                        const int **nids, int nid)
{
    int ok = 1;
    if (!digest) {
        *nids = gost_digest_nids;
        return 2;
    }
    /*
     * printf("Digest no %d requested\n",nid);
     */
    if (nid == NID_id_GostR3411_94) {
        *digest = &digest_gost;
    } else if (nid == NID_id_Gost28147_89_MAC) {
        *digest = &imit_gost_cpa;
    } else {
        ok = 0;
        *digest = NULL;
    }
    return ok;
}

static int gost_ciphers(ENGINE *e, const EVP_CIPHER **cipher,
                        const int **nids, int nid)
{
    int ok = 1;
    if (!cipher) {
        *nids = gost_cipher_nids;
        return 2;               /* two ciphers are supported */
    }

    if (nid == NID_id_Gost28147_89) {
        *cipher = &cipher_gost;
    } else if (nid == NID_gost89_cnt) {
        *cipher = &cipher_gost_cpacnt;
    } else {
        ok = 0;
        *cipher = NULL;
    }
    return ok;
}

static int gost_pkey_meths(ENGINE *e, EVP_PKEY_METHOD **pmeth,
                           const int **nids, int nid)
{
    if (!pmeth) {
        *nids = gost_pkey_meth_nids;
        return 3;
    }

    switch (nid) {
    case NID_id_GostR3410_94:
        *pmeth = pmeth_GostR3410_94;
        return 1;
    case NID_id_GostR3410_2001:
        *pmeth = pmeth_GostR3410_2001;
        return 1;
    case NID_id_Gost28147_89_MAC:
        *pmeth = pmeth_Gost28147_MAC;
        return 1;
    default:;
    }

    *pmeth = NULL;
    return 0;
}

static int gost_pkey_asn1_meths(ENGINE *e, EVP_PKEY_ASN1_METHOD **ameth,
                                const int **nids, int nid)
{
    if (!ameth) {
        *nids = gost_pkey_meth_nids;
        return 3;
    }
    switch (nid) {
    case NID_id_GostR3410_94:
        *ameth = ameth_GostR3410_94;
        return 1;
    case NID_id_GostR3410_2001:
        *ameth = ameth_GostR3410_2001;
        return 1;
    case NID_id_Gost28147_89_MAC:
        *ameth = ameth_Gost28147_MAC;
        return 1;

    default:;
    }

    *ameth = NULL;
    return 0;
}

#ifdef OPENSSL_NO_DYNAMIC_ENGINE
static ENGINE *engine_gost(void)
{
    ENGINE *ret = ENGINE_new();
    if (!ret)
        return NULL;
    if (!bind_gost(ret, engine_gost_id)) {
        ENGINE_free(ret);
        return NULL;
    }
    return ret;
}

void ENGINE_load_gost(void)
{
    ENGINE *toadd;
    if (pmeth_GostR3410_94)
        return;
    toadd = engine_gost();
    if (!toadd)
        return;
    ENGINE_add(toadd);
    ENGINE_free(toadd);
    ERR_clear_error();
}
#else
IMPLEMENT_DYNAMIC_BIND_FN(bind_gost)
IMPLEMENT_DYNAMIC_CHECK_FN()
#endif
/**********************************************************************
 *                          keywrap.c                                 *
 *             Copyright (c) 2005-2006 Cryptocom LTD                  *
 *         This file is distributed under the same license as OpenSSL *
 *                                                                    *
 * Implementation of CryptoPro key wrap algorithm, as defined in      *
 *               RFC 4357 p 6.3 and 6.4                               *
 *                  Doesn't need OpenSSL                              *
 **********************************************************************/
#include <string.h>
// #include "gost89.h"
#include "gost_keywrap.h"

/*-
 * Diversifies key using random UserKey Material
 * Implements RFC 4357 p 6.5 key diversification algorithm
 *
 * inputKey - 32byte key to be diversified
 * ukm - 8byte user key material
 * outputKey - 32byte buffer to store diversified key
 *
 */
void keyDiversifyCryptoPro(gost_ctx * ctx, const unsigned char *inputKey,
                           const unsigned char *ukm, unsigned char *outputKey)
{

    u4 k, s1, s2;
    int i, j, mask;
    unsigned char S[8];
    memcpy(outputKey, inputKey, 32);
    for (i = 0; i < 8; i++) {
        /* Make array of integers from key */
        /* Compute IV S */
        s1 = 0, s2 = 0;
        for (j = 0, mask = 1; j < 8; j++, mask <<= 1) {
            k = ((u4) outputKey[4 * j]) | (outputKey[4 * j + 1] << 8) |
                (outputKey[4 * j + 2] << 16) | (outputKey[4 * j + 3] << 24);
            if (mask & ukm[i]) {
                s1 += k;
            } else {
                s2 += k;
            }
        }
        S[0] = (unsigned char)(s1 & 0xff);
        S[1] = (unsigned char)((s1 >> 8) & 0xff);
        S[2] = (unsigned char)((s1 >> 16) & 0xff);
        S[3] = (unsigned char)((s1 >> 24) & 0xff);
        S[4] = (unsigned char)(s2 & 0xff);
        S[5] = (unsigned char)((s2 >> 8) & 0xff);
        S[6] = (unsigned char)((s2 >> 16) & 0xff);
        S[7] = (unsigned char)((s2 >> 24) & 0xff);
        gost_key(ctx, outputKey);
        gost_enc_cfb(ctx, S, outputKey, outputKey, 4);
    }
}

/*-
 * Wraps key using RFC 4357 6.3
 * ctx - gost encryption context, initialized with some S-boxes
 * keyExchangeKey (KEK) 32-byte (256-bit) shared key
 * ukm - 8 byte (64 bit) user key material,
 * sessionKey - 32-byte (256-bit) key to be wrapped
 * wrappedKey - 44-byte buffer to store wrapped key
 */

int keyWrapCryptoPro(gost_ctx * ctx, const unsigned char *keyExchangeKey,
                     const unsigned char *ukm,
                     const unsigned char *sessionKey,
                     unsigned char *wrappedKey)
{
    unsigned char kek_ukm[32];
    keyDiversifyCryptoPro(ctx, keyExchangeKey, ukm, kek_ukm);
    gost_key(ctx, kek_ukm);
    memcpy(wrappedKey, ukm, 8);
    gost_enc(ctx, sessionKey, wrappedKey + 8, 4);
    gost_mac_iv(ctx, 32, ukm, sessionKey, 32, wrappedKey + 40);
    return 1;
}

/*-
 * Unwraps key using RFC 4357 6.4
 * ctx - gost encryption context, initialized with some S-boxes
 * keyExchangeKey 32-byte shared key
 * wrappedKey  44 byte key to be unwrapped (concatenation of 8-byte UKM,
 * 32 byte  encrypted key and 4 byte MAC
 *
 * sessionKEy - 32byte buffer to store sessionKey in
 * Returns 1 if key is decrypted successfully, and 0 if MAC doesn't match
 */

int keyUnwrapCryptoPro(gost_ctx * ctx, const unsigned char *keyExchangeKey,
                       const unsigned char *wrappedKey,
                       unsigned char *sessionKey)
{
    unsigned char kek_ukm[32], cek_mac[4];
    keyDiversifyCryptoPro(ctx, keyExchangeKey, wrappedKey
                          /* First 8 bytes of wrapped Key is ukm */
                          , kek_ukm);
    gost_key(ctx, kek_ukm);
    gost_dec(ctx, wrappedKey + 8, sessionKey, 4);
    gost_mac_iv(ctx, 32, wrappedKey, sessionKey, 32, cek_mac);
    if (memcmp(cek_mac, wrappedKey + 40, 4)) {
        return 0;
    }
    return 1;
}
/**********************************************************************
 *                          md_gost.c                                 *
 *             Copyright (c) 2005-2006 Cryptocom LTD                  *
 *         This file is distributed under the same license as OpenSSL *
 *                                                                    *
 *       OpenSSL interface to GOST R 34.11-94 hash functions          *
 *          Requires OpenSSL 0.9.9 for compilation                    *
 **********************************************************************/
#include <string.h>
// #include "gost_lcl.h"
#include "gosthash.h"
// #include "e_gost_err.h"

/* implementation of GOST 34.11 hash function See gost_md.c*/
static int gost_digest_init(EVP_MD_CTX *ctx);
static int gost_digest_update(EVP_MD_CTX *ctx, const void *data,
                              size_t count);
static int gost_digest_final(EVP_MD_CTX *ctx, unsigned char *md);
static int gost_digest_copy(EVP_MD_CTX *to, const EVP_MD_CTX *from);
static int gost_digest_cleanup(EVP_MD_CTX *ctx);

EVP_MD digest_gost = {
    NID_id_GostR3411_94,
    NID_undef,
    32,
    EVP_MD_FLAG_PKEY_METHOD_SIGNATURE,
    gost_digest_init,
    gost_digest_update,
    gost_digest_final,
    gost_digest_copy,
    gost_digest_cleanup,
    NULL,
    NULL,
    {NID_undef, NID_undef, 0, 0, 0},
    32,
    sizeof(struct ossl_gost_digest_ctx),
    NULL
};

int gost_digest_init(EVP_MD_CTX *ctx)
{
    struct ossl_gost_digest_ctx *c = ctx->md_data;
    memset(&(c->dctx), 0, sizeof(gost_hash_ctx));
    gost_init(&(c->cctx), &GostR3411_94_CryptoProParamSet);
    c->dctx.cipher_ctx = &(c->cctx);
    return 1;
}

int gost_digest_update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    return hash_block((gost_hash_ctx *) ctx->md_data, data, count);
}

int gost_digest_final(EVP_MD_CTX *ctx, unsigned char *md)
{
    return finish_hash((gost_hash_ctx *) ctx->md_data, md);

}

int gost_digest_copy(EVP_MD_CTX *to, const EVP_MD_CTX *from)
{
    struct ossl_gost_digest_ctx *md_ctx = to->md_data;
    if (to->md_data && from->md_data) {
        memcpy(to->md_data, from->md_data,
               sizeof(struct ossl_gost_digest_ctx));
        md_ctx->dctx.cipher_ctx = &(md_ctx->cctx);
    }
    return 1;
}

int gost_digest_cleanup(EVP_MD_CTX *ctx)
{
    if (ctx->md_data)
        memset(ctx->md_data, 0, sizeof(struct ossl_gost_digest_ctx));
    return 1;
}
/**********************************************************************
 *                        params.c                                    *
 *             Copyright (c) 2005-2006 Cryptocom LTD                  *
 *         This file is distributed under the same license as OpenSSL *
 *                                                                    *
 * Definitions of GOST R 34.10 parameter sets, defined in RFC 4357    *
 *         OpenSSL 0.9.9 libraries required to compile and use        *
 *                              this code                             *
 **********************************************************************/
// #include "gost_params.h"
#include "objects.h"
/* Parameters of GOST 34.10 */

R3410_params R3410_paramset[] = {
/* Paramset A */
    {NID_id_GostR3410_94_CryptoPro_A_ParamSet,
     "100997906755055304772081815535925224869"
     "8410825720534578748235158755771479905292727772441528526992987964833"
     "5669968284202797289605274717317548059048560713474685214192868091256"
     "1502802222185647539190902656116367847270145019066794290930185446216"
     "3997308722217328898303231940973554032134009725883228768509467406639"
     "62",
     "127021248288932417465907042777176443525"
     "7876535089165358128175072657050312609850984974231883334834011809259"
     "9999512098893413065920561499672425412104927434935707492031276956145"
     "1689224110579311248812610229678534638401693520013288995000362260684"
     "2227508135323070045173416336850045410625869714168836867788425378203"
     "83",
     "683631961449557007844441656118272528951"
     "02170888761442055095051287550314083023"}
    ,
    {NID_id_GostR3410_94_CryptoPro_B_ParamSet,
     "429418261486158041438734477379555023926"
     "7234596860714306679811299408947123142002706038521669956384871995765"
     "7284814898909770759462613437669456364882730370838934791080835932647"
     "9767786019153434744009610342313166725786869204821949328786333602033"
     "8479709268434224762105576023501613261478065276102850944540333865234"
     "1",
     "139454871199115825601409655107690713107"
     "0417070599280317977580014543757653577229840941243685222882398330391"
     "1468164807668823692122073732267216074074777170091113455043205380464"
     "7694904686120113087816240740184800477047157336662926249423571248823"
     "9685422217536601433914856808405203368594584948031873412885804895251"
     "63",
     "79885141663410976897627118935756323747307951916507639758300472692338873533959"}
    ,
    {NID_id_GostR3410_94_CryptoPro_C_ParamSet,
     "816552717970881016017893191415300348226"
     "2544051353358162468249467681876621283478212884286545844013955142622"
     "2087723485023722868022275009502224827866201744494021697716482008353"
     "6398202298024892620480898699335508064332313529725332208819456895108"
     "5155178100221003459370588291073071186553005962149936840737128710832"
     "3",
     "110624679233511963040518952417017040248"
     "5862954819831383774196396298584395948970608956170224210628525560327"
     "8638246716655439297654402921844747893079518669992827880792192992701"
     "1428546551433875806377110443534293554066712653034996277099320715774"
     "3542287621283671843703709141350171945045805050291770503634517804938"
     "01",
     "113468861199819350564868233378875198043"
     "267947776488510997961231672532899549103"}
    ,
    {NID_id_GostR3410_94_CryptoPro_D_ParamSet,
     "756976611021707301782128757801610628085"
     "5283803109571158829574281419208532589041660017017859858216341400371"
     "4687551412794400562878935266630754392677014598582103365983119173924"
     "4732511225464712252386803315902707727668715343476086350472025298282"
     "7271461690125050616858238384366331089777463541013033926723743254833"
     "7",
     "905457649621929965904290958774625315611"
     "3056083907389766971404812524422262512556054474620855996091570786713"
     "5849550236741915584185990627801066465809510095784713989819413820871"
     "5964648914493053407920737078890520482730623038837767710173664838239"
     "8574828787891286471201460474326612697849693665518073864436497893214"
     "9",
     "108988435796353506912374591498972192620"
     "190487557619582334771735390599299211593"}
    ,

    {NID_id_GostR3410_94_CryptoPro_XchA_ParamSet,
     "1335318132727206734338595199483190012179423759678474868994823595993"
     "6964252873471246159040332773182141032801252925387191478859899310331"
     "0567744136196364803064721377826656898686468463277710150809401182608"
     "7702016153249904683329312949209127762411378780302243557466062839716"
     "59376426832674269780880061631528163475887",
     "14201174159756348119636828602231808974327613839524373876287257344192"
     "74593935127189736311660784676003608489466235676257952827747192122419"
     "29071046134208380636394084512691828894000571524625445295769349356752"
     "72895683154177544176313938445719175509684710784659566254794231229333"
     "8483924514339614727760681880609734239",
     "91771529896554605945588149018382750217296858393520724172743325725474"
     "374979801"}
    ,
    {NID_id_GostR3410_94_CryptoPro_XchB_ParamSet,
     "8890864727828423151699995801875757891031463338652579140051973659"
     "3048131440685857067369829407947744496306656291505503608252399443"
     "7900272386749145996230867832228661977543992816745254823298629859"
     "8753575466286051738837854736167685769017780335804511440773337196"
     "2538423532919394477873664752824509986617878992443177",
     "1028946126624994859676552074360530315217970499989304888248413244"
     "8474923022758470167998871003604670704877377286176171227694098633"
     "1539089568784129110109512690503345393869871295783467257264868341"
     "7200196629860561193666752429682367397084815179752036423595736533"
     "68957392061769855284593965042530895046088067160269433",
     "9109671391802626916582318050603555673628769498182593088388796888"
     "5281641595199"}
    ,
    {NID_id_GostR3410_94_CryptoPro_XchC_ParamSet,
     "4430618464297584182473135030809859326863990650118941756995270074"
     "8609973181426950235239623239110557450826919295792878938752101867"
     "7047181623251027516953100431855964837602657827828194249605561893"
     "6965865325513137194483136247773653468410118796740709840825496997"
     "9375560722345106704721086025979309968763193072908334",
     "1246996366993477513607147265794064436203408861395055989217248455"
     "7299870737698999651480662364723992859320868822848751165438350943"
     "3276647222625940615560580450040947211826027729977563540237169063"
     "0448079715771649447778447000597419032457722226253269698374446528"
     "35352729304393746106576383349151001715930924115499549",
     "6787876137336591234380295020065682527118129468050147943114675429"
     "4748422492761"}
    ,

    {NID_undef, NULL, NULL, NULL}
};

R3410_2001_params R3410_2001_paramset[] = {
    /* default_cc_sign01_param 1.2.643.2.9.1.8.1 */
    {NID_id_GostR3410_2001_ParamSet_cc,
     /* A */
     "C0000000000000000000000000000000000000000000000000000000000003c4",
     /* B */
     "2d06B4265ebc749ff7d0f1f1f88232e81632e9088fd44b7787d5e407e955080c",
     /* P */
     "C0000000000000000000000000000000000000000000000000000000000003C7",
     /* Q */
     "5fffffffffffffffffffffffffffffff606117a2f4bde428b7458a54b6e87b85",
     /* X */
     "2",
     /* Y */
     "a20e034bf8813ef5c18d01105e726a17eb248b264ae9706f440bedc8ccb6b22c"}
    ,
    /* 1.2.643.2.2.35.0 */
    {NID_id_GostR3410_2001_TestParamSet,
     "7",
     "5FBFF498AA938CE739B8E022FBAFEF40563F6E6A3472FC2A514C0CE9DAE23B7E",
     "8000000000000000000000000000000000000000000000000000000000000431",
     "8000000000000000000000000000000150FE8A1892976154C59CFC193ACCF5B3",
     "2",
     "08E2A8A0E65147D4BD6316030E16D19C85C97F0A9CA267122B96ABBCEA7E8FC8"}
    ,
    /*
     * 1.2.643.2.2.35.1
     */
    {NID_id_GostR3410_2001_CryptoPro_A_ParamSet,
     "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD94",
     "a6",
     "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97",
     "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF6C611070995AD10045841B09B761B893",
     "1",
     "8D91E471E0989CDA27DF505A453F2B7635294F2DDF23E3B122ACC99C9E9F1E14"}
    ,
    /*
     * 1.2.643.2.2.35.2
     */
    {NID_id_GostR3410_2001_CryptoPro_B_ParamSet,
     "8000000000000000000000000000000000000000000000000000000000000C96",
     "3E1AF419A269A5F866A7D3C25C3DF80AE979259373FF2B182F49D4CE7E1BBC8B",
     "8000000000000000000000000000000000000000000000000000000000000C99",
     "800000000000000000000000000000015F700CFFF1A624E5E497161BCC8A198F",
     "1",
     "3FA8124359F96680B83D1C3EB2C070E5C545C9858D03ECFB744BF8D717717EFC"}
    ,
    /*
     * 1.2.643.2.2.35.3
     */
    {NID_id_GostR3410_2001_CryptoPro_C_ParamSet,
     "9B9F605F5A858107AB1EC85E6B41C8AACF846E86789051D37998F7B9022D7598",
     "805a",
     "9B9F605F5A858107AB1EC85E6B41C8AACF846E86789051D37998F7B9022D759B",
     "9B9F605F5A858107AB1EC85E6B41C8AA582CA3511EDDFB74F02F3A6598980BB9",
     "0",
     "41ECE55743711A8C3CBF3783CD08C0EE4D4DC440D4641A8F366E550DFDB3BB67"}
    ,
    /*
     * 1.2.643.2.2.36.0
     */
    {NID_id_GostR3410_2001_CryptoPro_XchA_ParamSet,
     "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD94",
     "a6",
     "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97",
     "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF6C611070995AD10045841B09B761B893",
     "1",
     "8D91E471E0989CDA27DF505A453F2B7635294F2DDF23E3B122ACC99C9E9F1E14"}
    ,
    /*
     * 1.2.643.2.2.36.1
     */
    {NID_id_GostR3410_2001_CryptoPro_XchB_ParamSet,
     "9B9F605F5A858107AB1EC85E6B41C8AACF846E86789051D37998F7B9022D7598",
     "805a",
     "9B9F605F5A858107AB1EC85E6B41C8AACF846E86789051D37998F7B9022D759B",
     "9B9F605F5A858107AB1EC85E6B41C8AA582CA3511EDDFB74F02F3A6598980BB9",
     "0",
     "41ECE55743711A8C3CBF3783CD08C0EE4D4DC440D4641A8F366E550DFDB3BB67"}
    ,
    {0, NULL, NULL, NULL, NULL, NULL, NULL}
};
/**********************************************************************
 *                          gost_pmeth.c                              *
 *             Copyright (c) 2005-2006 Cryptocom LTD                  *
 *         This file is distributed under the same license as OpenSSL *
 *                                                                    *
 *   Implementation of RFC 4357 (GOST R 34.10) Publick key method     *
 *       for OpenSSL                                                  *
 *          Requires OpenSSL 0.9.9 for compilation                    *
 **********************************************************************/
// #include "evp.h"
// #include "objects.h"
#include "ec.h"
#include "x509v3.h"     /* For string_to_hex */
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
// #include "gost_params.h"
// #include "gost_lcl.h"
// #include "e_gost_err.h"
/* -----init, cleanup, copy - uniform for all algs  ---------------*/
/* Allocates new gost_pmeth_data structure and assigns it as data */
static int pkey_gost_init(EVP_PKEY_CTX *ctx)
{
    struct gost_pmeth_data *data;
    EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey(ctx);
    data = OPENSSL_malloc(sizeof(struct gost_pmeth_data));
    if (!data)
        return 0;
    memset(data, 0, sizeof(struct gost_pmeth_data));
    if (pkey && EVP_PKEY_get0(pkey)) {
        switch (EVP_PKEY_base_id(pkey)) {
        case NID_id_GostR3410_94:
            data->sign_param_nid = gost94_nid_by_params(EVP_PKEY_get0(pkey));
            break;
        case NID_id_GostR3410_2001:
            data->sign_param_nid =
                EC_GROUP_get_curve_name(EC_KEY_get0_group
                                        (EVP_PKEY_get0((EVP_PKEY *)pkey)));
            break;
        default:
            return 0;
        }
    }
    EVP_PKEY_CTX_set_data(ctx, data);
    return 1;
}

/* Copies contents of gost_pmeth_data structure */
static int pkey_gost_copy(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src)
{
    struct gost_pmeth_data *dst_data, *src_data;
    if (!pkey_gost_init(dst)) {
        return 0;
    }
    src_data = EVP_PKEY_CTX_get_data(src);
    dst_data = EVP_PKEY_CTX_get_data(dst);
    *dst_data = *src_data;
    if (src_data->shared_ukm) {
        dst_data->shared_ukm = NULL;
    }
    return 1;
}

/* Frees up gost_pmeth_data structure */
static void pkey_gost_cleanup(EVP_PKEY_CTX *ctx)
{
    struct gost_pmeth_data *data = EVP_PKEY_CTX_get_data(ctx);
    if (data->shared_ukm)
        OPENSSL_free(data->shared_ukm);
    OPENSSL_free(data);
}

/* --------------------- control functions  ------------------------------*/
static int pkey_gost_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
    struct gost_pmeth_data *pctx =
        (struct gost_pmeth_data *)EVP_PKEY_CTX_get_data(ctx);
    switch (type) {
    case EVP_PKEY_CTRL_MD:
        {
            if (EVP_MD_type((const EVP_MD *)p2) != NID_id_GostR3411_94) {
                GOSTerr(GOST_F_PKEY_GOST_CTRL, GOST_R_INVALID_DIGEST_TYPE);
                return 0;
            }
            pctx->md = (EVP_MD *)p2;
            return 1;
        }
        break;

    case EVP_PKEY_CTRL_GET_MD:
        *(const EVP_MD **)p2 = pctx->md;
        return 1;

    case EVP_PKEY_CTRL_PKCS7_ENCRYPT:
    case EVP_PKEY_CTRL_PKCS7_DECRYPT:
    case EVP_PKEY_CTRL_PKCS7_SIGN:
    case EVP_PKEY_CTRL_DIGESTINIT:
#ifndef OPENSSL_NO_CMS
    case EVP_PKEY_CTRL_CMS_ENCRYPT:
    case EVP_PKEY_CTRL_CMS_DECRYPT:
    case EVP_PKEY_CTRL_CMS_SIGN:
#endif
        return 1;

    case EVP_PKEY_CTRL_GOST_PARAMSET:
        pctx->sign_param_nid = (int)p1;
        return 1;
    case EVP_PKEY_CTRL_SET_IV:
        pctx->shared_ukm = OPENSSL_malloc((int)p1);
        if (pctx->shared_ukm == NULL)
            return 0;
        memcpy(pctx->shared_ukm, p2, (int)p1);
        return 1;
    case EVP_PKEY_CTRL_PEER_KEY:
        if (p1 == 0 || p1 == 1) /* call from EVP_PKEY_derive_set_peer */
            return 1;
        if (p1 == 2)            /* TLS: peer key used? */
            return pctx->peer_key_used;
        if (p1 == 3)            /* TLS: peer key used! */
            return (pctx->peer_key_used = 1);
        return -2;
    }
    return -2;
}

static int pkey_gost_ctrl94_str(EVP_PKEY_CTX *ctx,
                                const char *type, const char *value)
{
    int param_nid = 0;
    if (!strcmp(type, param_ctrl_string)) {
        if (!value) {
            return 0;
        }
        if (strlen(value) == 1) {
            switch (toupper((unsigned char)value[0])) {
            case 'A':
                param_nid = NID_id_GostR3410_94_CryptoPro_A_ParamSet;
                break;
            case 'B':
                param_nid = NID_id_GostR3410_94_CryptoPro_B_ParamSet;
                break;
            case 'C':
                param_nid = NID_id_GostR3410_94_CryptoPro_C_ParamSet;
                break;
            case 'D':
                param_nid = NID_id_GostR3410_94_CryptoPro_D_ParamSet;
                break;
            default:
                return 0;
                break;
            }
        } else if ((strlen(value) == 2)
                   && (toupper((unsigned char)value[0]) == 'X')) {
            switch (toupper((unsigned char)value[1])) {
            case 'A':
                param_nid = NID_id_GostR3410_94_CryptoPro_XchA_ParamSet;
                break;
            case 'B':
                param_nid = NID_id_GostR3410_94_CryptoPro_XchB_ParamSet;
                break;
            case 'C':
                param_nid = NID_id_GostR3410_94_CryptoPro_XchC_ParamSet;
                break;
            default:
                return 0;
                break;
            }
        } else {
            R3410_params *p = R3410_paramset;
            param_nid = OBJ_txt2nid(value);
            if (param_nid == NID_undef) {
                return 0;
            }
            for (; p->nid != NID_undef; p++) {
                if (p->nid == param_nid)
                    break;
            }
            if (p->nid == NID_undef) {
                GOSTerr(GOST_F_PKEY_GOST_CTRL94_STR, GOST_R_INVALID_PARAMSET);
                return 0;
            }
        }

        return pkey_gost_ctrl(ctx, EVP_PKEY_CTRL_GOST_PARAMSET,
                              param_nid, NULL);
    }
    return -2;
}

static int pkey_gost_ctrl01_str(EVP_PKEY_CTX *ctx,
                                const char *type, const char *value)
{
    int param_nid = 0;
    if (!strcmp(type, param_ctrl_string)) {
        if (!value) {
            return 0;
        }
        if (strlen(value) == 1) {
            switch (toupper((unsigned char)value[0])) {
            case 'A':
                param_nid = NID_id_GostR3410_2001_CryptoPro_A_ParamSet;
                break;
            case 'B':
                param_nid = NID_id_GostR3410_2001_CryptoPro_B_ParamSet;
                break;
            case 'C':
                param_nid = NID_id_GostR3410_2001_CryptoPro_C_ParamSet;
                break;
            case '0':
                param_nid = NID_id_GostR3410_2001_TestParamSet;
                break;
            default:
                return 0;
                break;
            }
        } else if ((strlen(value) == 2)
                   && (toupper((unsigned char)value[0]) == 'X')) {
            switch (toupper((unsigned char)value[1])) {
            case 'A':
                param_nid = NID_id_GostR3410_2001_CryptoPro_XchA_ParamSet;
                break;
            case 'B':
                param_nid = NID_id_GostR3410_2001_CryptoPro_XchB_ParamSet;
                break;
            default:
                return 0;
                break;
            }
        } else {
            R3410_2001_params *p = R3410_2001_paramset;
            param_nid = OBJ_txt2nid(value);
            if (param_nid == NID_undef) {
                return 0;
            }
            for (; p->nid != NID_undef; p++) {
                if (p->nid == param_nid)
                    break;
            }
            if (p->nid == NID_undef) {
                GOSTerr(GOST_F_PKEY_GOST_CTRL01_STR, GOST_R_INVALID_PARAMSET);
                return 0;
            }
        }

        return pkey_gost_ctrl(ctx, EVP_PKEY_CTRL_GOST_PARAMSET,
                              param_nid, NULL);
    }
    return -2;
}

/* --------------------- key generation  --------------------------------*/

static int pkey_gost_paramgen_init(EVP_PKEY_CTX *ctx)
{
    return 1;
}

static int pkey_gost94_paramgen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    struct gost_pmeth_data *data = EVP_PKEY_CTX_get_data(ctx);
    DSA *dsa = NULL;
    if (data->sign_param_nid == NID_undef) {
        GOSTerr(GOST_F_PKEY_GOST94_PARAMGEN, GOST_R_NO_PARAMETERS_SET);
        return 0;
    }
    dsa = DSA_new();
    if (!fill_GOST94_params(dsa, data->sign_param_nid)) {
        DSA_free(dsa);
        return 0;
    }
    EVP_PKEY_assign(pkey, NID_id_GostR3410_94, dsa);
    return 1;
}

static int pkey_gost01_paramgen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    struct gost_pmeth_data *data = EVP_PKEY_CTX_get_data(ctx);
    EC_KEY *ec = NULL;

    if (data->sign_param_nid == NID_undef) {
        GOSTerr(GOST_F_PKEY_GOST01_PARAMGEN, GOST_R_NO_PARAMETERS_SET);
        return 0;
    }
    if (!ec)
        ec = EC_KEY_new();
    if (!fill_GOST2001_params(ec, data->sign_param_nid)) {
        EC_KEY_free(ec);
        return 0;
    }
    EVP_PKEY_assign(pkey, NID_id_GostR3410_2001, ec);
    return 1;
}

/* Generates Gost_R3410_94_cp key */
static int pkey_gost94cp_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    DSA *dsa;
    if (!pkey_gost94_paramgen(ctx, pkey))
        return 0;
    dsa = EVP_PKEY_get0(pkey);
    gost_sign_keygen(dsa);
    return 1;
}

/* Generates GOST_R3410 2001 key and assigns it using specified type */
static int pkey_gost01cp_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    EC_KEY *ec;
    if (!pkey_gost01_paramgen(ctx, pkey))
        return 0;
    ec = EVP_PKEY_get0(pkey);
    gost2001_keygen(ec);
    return 1;
}

/* ----------- sign callbacks --------------------------------------*/

static int pkey_gost94_cp_sign(EVP_PKEY_CTX *ctx, unsigned char *sig,
                               size_t *siglen, const unsigned char *tbs,
                               size_t tbs_len)
{
    DSA_SIG *unpacked_sig = NULL;
    EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey(ctx);
    if (!siglen)
        return 0;
    if (!sig) {
        *siglen = 64;           /* better to check size of pkey->pkey.dsa-q */
        return 1;
    }
    unpacked_sig = gost_do_sign(tbs, tbs_len, EVP_PKEY_get0(pkey));
    if (!unpacked_sig) {
        return 0;
    }
    return pack_sign_cp(unpacked_sig, 32, sig, siglen);
}

static int pkey_gost01_cp_sign(EVP_PKEY_CTX *ctx, unsigned char *sig,
                               size_t *siglen, const unsigned char *tbs,
                               size_t tbs_len)
{
    DSA_SIG *unpacked_sig = NULL;
    EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey(ctx);
    if (!siglen)
        return 0;
    if (!sig) {
        *siglen = 64;           /* better to check size of curve order */
        return 1;
    }
    unpacked_sig = gost2001_do_sign(tbs, tbs_len, EVP_PKEY_get0(pkey));
    if (!unpacked_sig) {
        return 0;
    }
    return pack_sign_cp(unpacked_sig, 32, sig, siglen);
}

/* ------------------- verify callbacks ---------------------------*/

static int pkey_gost94_cp_verify(EVP_PKEY_CTX *ctx, const unsigned char *sig,
                                 size_t siglen, const unsigned char *tbs,
                                 size_t tbs_len)
{
    int ok = 0;
    EVP_PKEY *pub_key = EVP_PKEY_CTX_get0_pkey(ctx);
    DSA_SIG *s = unpack_cp_signature(sig, siglen);
    if (!s)
        return 0;
    if (pub_key)
        ok = gost_do_verify(tbs, tbs_len, s, EVP_PKEY_get0(pub_key));
    DSA_SIG_free(s);
    return ok;
}

static int pkey_gost01_cp_verify(EVP_PKEY_CTX *ctx, const unsigned char *sig,
                                 size_t siglen, const unsigned char *tbs,
                                 size_t tbs_len)
{
    int ok = 0;
    EVP_PKEY *pub_key = EVP_PKEY_CTX_get0_pkey(ctx);
    DSA_SIG *s = unpack_cp_signature(sig, siglen);
    if (!s)
        return 0;
#ifdef DEBUG_SIGN
    fprintf(stderr, "R=");
    BN_print_fp(stderr, s->r);
    fprintf(stderr, "\nS=");
    BN_print_fp(stderr, s->s);
    fprintf(stderr, "\n");
#endif
    if (pub_key)
        ok = gost2001_do_verify(tbs, tbs_len, s, EVP_PKEY_get0(pub_key));
    DSA_SIG_free(s);
    return ok;
}

/* ------------- encrypt init -------------------------------------*/
/* Generates ephermeral key */
static int pkey_gost_encrypt_init(EVP_PKEY_CTX *ctx)
{
    return 1;
}

/* --------------- Derive init ------------------------------------*/
static int pkey_gost_derive_init(EVP_PKEY_CTX *ctx)
{
    return 1;
}

/* -------- PKEY_METHOD for GOST MAC algorithm --------------------*/
static int pkey_gost_mac_init(EVP_PKEY_CTX *ctx)
{
    struct gost_mac_pmeth_data *data;
    data = OPENSSL_malloc(sizeof(struct gost_mac_pmeth_data));
    if (!data)
        return 0;
    memset(data, 0, sizeof(struct gost_mac_pmeth_data));
    EVP_PKEY_CTX_set_data(ctx, data);
    return 1;
}

static void pkey_gost_mac_cleanup(EVP_PKEY_CTX *ctx)
{
    struct gost_mac_pmeth_data *data = EVP_PKEY_CTX_get_data(ctx);
    OPENSSL_free(data);
}

static int pkey_gost_mac_copy(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src)
{
    struct gost_mac_pmeth_data *dst_data, *src_data;
    if (!pkey_gost_mac_init(dst)) {
        return 0;
    }
    src_data = EVP_PKEY_CTX_get_data(src);
    dst_data = EVP_PKEY_CTX_get_data(dst);
    *dst_data = *src_data;
    return 1;
}

static int pkey_gost_mac_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
    struct gost_mac_pmeth_data *data =
        (struct gost_mac_pmeth_data *)EVP_PKEY_CTX_get_data(ctx);

    switch (type) {
    case EVP_PKEY_CTRL_MD:
        {
            if (EVP_MD_type((const EVP_MD *)p2) != NID_id_Gost28147_89_MAC) {
                GOSTerr(GOST_F_PKEY_GOST_MAC_CTRL,
                        GOST_R_INVALID_DIGEST_TYPE);
                return 0;
            }
            data->md = (EVP_MD *)p2;
            return 1;
        }
        break;

    case EVP_PKEY_CTRL_GET_MD:
        *(const EVP_MD **)p2 = data->md;
        return 1;

    case EVP_PKEY_CTRL_PKCS7_ENCRYPT:
    case EVP_PKEY_CTRL_PKCS7_DECRYPT:
    case EVP_PKEY_CTRL_PKCS7_SIGN:
        return 1;
    case EVP_PKEY_CTRL_SET_MAC_KEY:
        if (p1 != 32) {
            GOSTerr(GOST_F_PKEY_GOST_MAC_CTRL, GOST_R_INVALID_MAC_KEY_LENGTH);
            return 0;
        }

        memcpy(data->key, p2, 32);
        data->key_set = 1;
        return 1;
    case EVP_PKEY_CTRL_DIGESTINIT:
        {
            EVP_MD_CTX *mctx = p2;
            void *key;
            if (!data->key_set) {
                EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey(ctx);
                if (!pkey) {
                    GOSTerr(GOST_F_PKEY_GOST_MAC_CTRL,
                            GOST_R_MAC_KEY_NOT_SET);
                    return 0;
                }
                key = EVP_PKEY_get0(pkey);
                if (!key) {
                    GOSTerr(GOST_F_PKEY_GOST_MAC_CTRL,
                            GOST_R_MAC_KEY_NOT_SET);
                    return 0;
                }
            } else {
                key = &(data->key);
            }
            return mctx->digest->md_ctrl(mctx, EVP_MD_CTRL_SET_KEY, 32, key);
        }
    }
    return -2;
}

static int pkey_gost_mac_ctrl_str(EVP_PKEY_CTX *ctx,
                                  const char *type, const char *value)
{
    if (!strcmp(type, key_ctrl_string)) {
        if (strlen(value) != 32) {
            GOSTerr(GOST_F_PKEY_GOST_MAC_CTRL_STR,
                    GOST_R_INVALID_MAC_KEY_LENGTH);
            return 0;
        }
        return pkey_gost_mac_ctrl(ctx, EVP_PKEY_CTRL_SET_MAC_KEY,
                                  32, (char *)value);
    }
    if (!strcmp(type, hexkey_ctrl_string)) {
        long keylen;
        int ret;
        unsigned char *keybuf = string_to_hex(value, &keylen);
        if (!keybuf || keylen != 32) {
            GOSTerr(GOST_F_PKEY_GOST_MAC_CTRL_STR,
                    GOST_R_INVALID_MAC_KEY_LENGTH);
            OPENSSL_free(keybuf);
            return 0;
        }
        ret = pkey_gost_mac_ctrl(ctx, EVP_PKEY_CTRL_SET_MAC_KEY, 32, keybuf);
        OPENSSL_free(keybuf);
        return ret;

    }
    return -2;
}

static int pkey_gost_mac_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    struct gost_mac_pmeth_data *data = EVP_PKEY_CTX_get_data(ctx);
    unsigned char *keydata;
    if (!data->key_set) {
        GOSTerr(GOST_F_PKEY_GOST_MAC_KEYGEN, GOST_R_MAC_KEY_NOT_SET);
        return 0;
    }
    keydata = OPENSSL_malloc(32);
    if (keydata == NULL)
        return 0;
    memcpy(keydata, data->key, 32);
    EVP_PKEY_assign(pkey, NID_id_Gost28147_89_MAC, keydata);
    return 1;
}

static int pkey_gost_mac_signctx_init(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx)
{
    return 1;
}

static int pkey_gost_mac_signctx(EVP_PKEY_CTX *ctx, unsigned char *sig,
                                 size_t *siglen, EVP_MD_CTX *mctx)
{
    unsigned int tmpsiglen = *siglen; /* for platforms where
                                       * sizeof(int)!=sizeof(size_t) */
    int ret;
    if (!sig) {
        *siglen = 4;
        return 1;
    }
    ret = EVP_DigestFinal_ex(mctx, sig, &tmpsiglen);
    *siglen = tmpsiglen;
    return ret;
}

/* ----------------------------------------------------------------*/
int register_pmeth_gost(int id, EVP_PKEY_METHOD **pmeth, int flags)
{
    *pmeth = EVP_PKEY_meth_new(id, flags);
    if (!*pmeth)
        return 0;

    switch (id) {
    case NID_id_GostR3410_94:
        EVP_PKEY_meth_set_ctrl(*pmeth, pkey_gost_ctrl, pkey_gost_ctrl94_str);
        EVP_PKEY_meth_set_keygen(*pmeth, NULL, pkey_gost94cp_keygen);
        EVP_PKEY_meth_set_sign(*pmeth, NULL, pkey_gost94_cp_sign);
        EVP_PKEY_meth_set_verify(*pmeth, NULL, pkey_gost94_cp_verify);
        EVP_PKEY_meth_set_encrypt(*pmeth,
                                  pkey_gost_encrypt_init,
                                  pkey_GOST94cp_encrypt);
        EVP_PKEY_meth_set_decrypt(*pmeth, NULL, pkey_GOST94cp_decrypt);
        EVP_PKEY_meth_set_derive(*pmeth,
                                 pkey_gost_derive_init, pkey_gost94_derive);
        EVP_PKEY_meth_set_paramgen(*pmeth, pkey_gost_paramgen_init,
                                   pkey_gost94_paramgen);
        break;
    case NID_id_GostR3410_2001:
        EVP_PKEY_meth_set_ctrl(*pmeth, pkey_gost_ctrl, pkey_gost_ctrl01_str);
        EVP_PKEY_meth_set_sign(*pmeth, NULL, pkey_gost01_cp_sign);
        EVP_PKEY_meth_set_verify(*pmeth, NULL, pkey_gost01_cp_verify);

        EVP_PKEY_meth_set_keygen(*pmeth, NULL, pkey_gost01cp_keygen);

        EVP_PKEY_meth_set_encrypt(*pmeth,
                                  pkey_gost_encrypt_init,
                                  pkey_GOST01cp_encrypt);
        EVP_PKEY_meth_set_decrypt(*pmeth, NULL, pkey_GOST01cp_decrypt);
        EVP_PKEY_meth_set_derive(*pmeth,
                                 pkey_gost_derive_init, pkey_gost2001_derive);
        EVP_PKEY_meth_set_paramgen(*pmeth, pkey_gost_paramgen_init,
                                   pkey_gost01_paramgen);
        break;
    case NID_id_Gost28147_89_MAC:
        EVP_PKEY_meth_set_ctrl(*pmeth, pkey_gost_mac_ctrl,
                               pkey_gost_mac_ctrl_str);
        EVP_PKEY_meth_set_signctx(*pmeth, pkey_gost_mac_signctx_init,
                                  pkey_gost_mac_signctx);
        EVP_PKEY_meth_set_keygen(*pmeth, NULL, pkey_gost_mac_keygen);
        EVP_PKEY_meth_set_init(*pmeth, pkey_gost_mac_init);
        EVP_PKEY_meth_set_cleanup(*pmeth, pkey_gost_mac_cleanup);
        EVP_PKEY_meth_set_copy(*pmeth, pkey_gost_mac_copy);
        return 1;
    default:                   /* Unsupported method */
        return 0;
    }
    EVP_PKEY_meth_set_init(*pmeth, pkey_gost_init);
    EVP_PKEY_meth_set_cleanup(*pmeth, pkey_gost_cleanup);

    EVP_PKEY_meth_set_copy(*pmeth, pkey_gost_copy);
    /*
     * FIXME derive etc...
     */

    return 1;
}
/**********************************************************************
 *                          gost_sign.c                               *
 *             Copyright (c) 2005-2006 Cryptocom LTD                  *
 *         This file is distributed under the same license as OpenSSL *
 *                                                                    *
 *       Implementation of GOST R 34.10-94 signature algorithm        *
 *       for OpenSSL                                                  *
 *          Requires OpenSSL 0.9.9 for compilation                    *
 **********************************************************************/
#include <string.h>
// #include "rand.h"
#include "bn.h"
#include "dsa.h"
// #include "evp.h"
// #include "err.h"

// #include "gost_params.h"
// #include "gost_lcl.h"
// #include "e_gost_err.h"

#ifdef DEBUG_SIGN
void dump_signature(const char *message, const unsigned char *buffer,
                    size_t len)
{
    size_t i;
    fprintf(stderr, "signature %s Length=%d", message, len);
    for (i = 0; i < len; i++) {
        if (i % 16 == 0)
            fputc('\n', stderr);
        fprintf(stderr, " %02x", buffer[i]);
    }
    fprintf(stderr, "\nEnd of signature\n");
}

void dump_dsa_sig(const char *message, DSA_SIG *sig)
{
    fprintf(stderr, "%s\nR=", message);
    BN_print_fp(stderr, sig->r);
    fprintf(stderr, "\nS=");
    BN_print_fp(stderr, sig->s);
    fprintf(stderr, "\n");
}

#else

# define dump_signature(a,b,c)
# define dump_dsa_sig(a,b)
#endif

/*
 * Computes signature and returns it as DSA_SIG structure
 */
DSA_SIG *gost_do_sign(const unsigned char *dgst, int dlen, DSA *dsa)
{
    BIGNUM *k = NULL, *tmp = NULL, *tmp2 = NULL;
    DSA_SIG *newsig = NULL, *ret = NULL;
    BIGNUM *md = hashsum2bn(dgst);
    /* check if H(M) mod q is zero */
    BN_CTX *ctx = BN_CTX_new();
    if(!ctx) {
        GOSTerr(GOST_F_GOST_DO_SIGN, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    BN_CTX_start(ctx);
    newsig = DSA_SIG_new();
    if (!newsig) {
        GOSTerr(GOST_F_GOST_DO_SIGN, GOST_R_NO_MEMORY);
        goto err;
    }
    tmp = BN_CTX_get(ctx);
    k = BN_CTX_get(ctx);
    tmp2 = BN_CTX_get(ctx);
    if(!tmp || !k || !tmp2) {
        GOSTerr(GOST_F_GOST_DO_SIGN, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    BN_mod(tmp, md, dsa->q, ctx);
    if (BN_is_zero(tmp)) {
        BN_one(md);
    }
    do {
        do {
            /*
             * Generate random number k less than q
             */
            BN_rand_range(k, dsa->q);
            /* generate r = (a^x mod p) mod q */
            BN_mod_exp(tmp, dsa->g, k, dsa->p, ctx);
            if (!(newsig->r)) {
                newsig->r = BN_new();
                if(!newsig->r) {
                    GOSTerr(GOST_F_GOST_DO_SIGN, ERR_R_MALLOC_FAILURE);
                    goto err;
                }
            }
            BN_mod(newsig->r, tmp, dsa->q, ctx);
        }
        while (BN_is_zero(newsig->r));
        /* generate s = (xr + k(Hm)) mod q */
        BN_mod_mul(tmp, dsa->priv_key, newsig->r, dsa->q, ctx);
        BN_mod_mul(tmp2, k, md, dsa->q, ctx);
        if (!newsig->s) {
            newsig->s = BN_new();
            if(!newsig->s) {
                GOSTerr(GOST_F_GOST_DO_SIGN, ERR_R_MALLOC_FAILURE);
                goto err;
            }
        }
        BN_mod_add(newsig->s, tmp, tmp2, dsa->q, ctx);
    }
    while (BN_is_zero(newsig->s));

    ret = newsig;
 err:
    BN_free(md);
    if(ctx) {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    if(!ret && newsig) {
        DSA_SIG_free(newsig);
    }
    return ret;
}

/*
 * Packs signature according to Cryptocom rules
 * and frees up DSA_SIG structure
 */
/*-
int pack_sign_cc(DSA_SIG *s,int order,unsigned char *sig, size_t *siglen)
        {
        *siglen = 2*order;
        memset(sig,0,*siglen);
        store_bignum(s->r, sig,order);
        store_bignum(s->s, sig + order,order);
        dump_signature("serialized",sig,*siglen);
        DSA_SIG_free(s);
        return 1;
        }
*/
/*
 * Packs signature according to Cryptopro rules
 * and frees up DSA_SIG structure
 */
int pack_sign_cp(DSA_SIG *s, int order, unsigned char *sig, size_t *siglen)
{
    *siglen = 2 * order;
    memset(sig, 0, *siglen);
    store_bignum(s->s, sig, order);
    store_bignum(s->r, sig + order, order);
    dump_signature("serialized", sig, *siglen);
    DSA_SIG_free(s);
    return 1;
}

/*
 * Verifies signature passed as DSA_SIG structure
 *
 */

int gost_do_verify(const unsigned char *dgst, int dgst_len,
                   DSA_SIG *sig, DSA *dsa)
{
    BIGNUM *md = NULL, *tmp = NULL;
    BIGNUM *q2 = NULL;
    BIGNUM *u = NULL, *v = NULL, *z1 = NULL, *z2 = NULL;
    BIGNUM *tmp2 = NULL, *tmp3 = NULL;
    int ok = 0;
    BN_CTX *ctx = BN_CTX_new();
    if(!ctx) {
        GOSTerr(GOST_F_GOST_DO_VERIFY, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    BN_CTX_start(ctx);
    if (BN_cmp(sig->s, dsa->q) >= 1 || BN_cmp(sig->r, dsa->q) >= 1) {
        GOSTerr(GOST_F_GOST_DO_VERIFY, GOST_R_SIGNATURE_PARTS_GREATER_THAN_Q);
        goto err;
    }
    md = hashsum2bn(dgst);

    tmp = BN_CTX_get(ctx);
    v = BN_CTX_get(ctx);
    q2 = BN_CTX_get(ctx);
    z1 = BN_CTX_get(ctx);
    z2 = BN_CTX_get(ctx);
    tmp2 = BN_CTX_get(ctx);
    tmp3 = BN_CTX_get(ctx);
    u = BN_CTX_get(ctx);
    if(!tmp || !v || !q2 || !z1 || !z2 || !tmp2 || !tmp3 || !u) {
        GOSTerr(GOST_F_GOST_DO_VERIFY, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    BN_mod(tmp, md, dsa->q, ctx);
    if (BN_is_zero(tmp)) {
        BN_one(md);
    }
    BN_copy(q2, dsa->q);
    BN_sub_word(q2, 2);
    BN_mod_exp(v, md, q2, dsa->q, ctx);
    BN_mod_mul(z1, sig->s, v, dsa->q, ctx);
    BN_sub(tmp, dsa->q, sig->r);
    BN_mod_mul(z2, tmp, v, dsa->p, ctx);
    BN_mod_exp(tmp, dsa->g, z1, dsa->p, ctx);
    BN_mod_exp(tmp2, dsa->pub_key, z2, dsa->p, ctx);
    BN_mod_mul(tmp3, tmp, tmp2, dsa->p, ctx);
    BN_mod(u, tmp3, dsa->q, ctx);
    ok = (BN_cmp(u, sig->r) == 0);

    if (!ok) {
        GOSTerr(GOST_F_GOST_DO_VERIFY, GOST_R_SIGNATURE_MISMATCH);
    }
err:
    if(md) BN_free(md);
    if(ctx) {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    return ok;
}

/*
 * Computes public keys for GOST R 34.10-94 algorithm
 *
 */
int gost94_compute_public(DSA *dsa)
{
    /* Now fill algorithm parameters with correct values */
    BN_CTX *ctx;
    if (!dsa->g) {
        GOSTerr(GOST_F_GOST94_COMPUTE_PUBLIC, GOST_R_KEY_IS_NOT_INITALIZED);
        return 0;
    }
    ctx = BN_CTX_new();
    if(!ctx) {
        GOSTerr(GOST_F_GOST94_COMPUTE_PUBLIC, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    dsa->pub_key = BN_new();
    if(!dsa->pub_key) {
        GOSTerr(GOST_F_GOST94_COMPUTE_PUBLIC, ERR_R_MALLOC_FAILURE);
        BN_CTX_free(ctx);
        return 0;
    }
    /* Compute public key  y = a^x mod p */
    BN_mod_exp(dsa->pub_key, dsa->g, dsa->priv_key, dsa->p, ctx);
    BN_CTX_free(ctx);
    return 1;
}

/*
 * Fill GOST 94 params, searching them in R3410_paramset array
 * by nid of paramset
 *
 */
int fill_GOST94_params(DSA *dsa, int nid)
{
    R3410_params *params = R3410_paramset;
    while (params->nid != NID_undef && params->nid != nid)
        params++;
    if (params->nid == NID_undef) {
        GOSTerr(GOST_F_FILL_GOST94_PARAMS, GOST_R_UNSUPPORTED_PARAMETER_SET);
        return 0;
    }
#define dump_signature(a,b,c)
    if (dsa->p) {
        BN_free(dsa->p);
    }
    dsa->p = NULL;
    BN_dec2bn(&(dsa->p), params->p);
    if (dsa->q) {
        BN_free(dsa->q);
    }
    dsa->q = NULL;
    BN_dec2bn(&(dsa->q), params->q);
    if (dsa->g) {
        BN_free(dsa->g);
    }
    dsa->g = NULL;
    BN_dec2bn(&(dsa->g), params->a);
    return 1;
}

/*
 *  Generate GOST R 34.10-94 keypair
 *
 *
 */
int gost_sign_keygen(DSA *dsa)
{
    dsa->priv_key = BN_new();
    if(!dsa->priv_key) {
        GOSTerr(GOST_F_GOST_SIGN_KEYGEN, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    BN_rand_range(dsa->priv_key, dsa->q);
    return gost94_compute_public(dsa);
}

/* Unpack signature according to cryptocom rules  */
/*-
DSA_SIG *unpack_cc_signature(const unsigned char *sig,size_t siglen)
        {
        DSA_SIG *s;
        s = DSA_SIG_new();
        if (s == NULL)
                {
                GOSTerr(GOST_F_UNPACK_CC_SIGNATURE,GOST_R_NO_MEMORY);
                return(NULL);
                }
        s->r = getbnfrombuf(sig, siglen/2);
        s->s = getbnfrombuf(sig + siglen/2, siglen/2);
        return s;
        }
*/
/* Unpack signature according to cryptopro rules  */
DSA_SIG *unpack_cp_signature(const unsigned char *sig, size_t siglen)
{
    DSA_SIG *s;

    s = DSA_SIG_new();
    if (s == NULL) {
        GOSTerr(GOST_F_UNPACK_CP_SIGNATURE, GOST_R_NO_MEMORY);
        return NULL;
    }
    s->s = getbnfrombuf(sig, siglen / 2);
    s->r = getbnfrombuf(sig + siglen / 2, siglen / 2);
    return s;
}

/* Convert little-endian byte array into bignum */
BIGNUM *hashsum2bn(const unsigned char *dgst)
{
    unsigned char buf[32];
    int i;
    for (i = 0; i < 32; i++) {
        buf[31 - i] = dgst[i];
    }
    return getbnfrombuf(buf, 32);
}

/* Convert byte buffer to bignum, skipping leading zeros*/
BIGNUM *getbnfrombuf(const unsigned char *buf, size_t len)
{
    while (*buf == 0 && len > 0) {
        buf++;
        len--;
    }
    if (len) {
        return BN_bin2bn(buf, len, NULL);
    } else {
        BIGNUM *b = BN_new();
        BN_zero(b);
        return b;
    }
}

/*
 * Pack bignum into byte buffer of given size, filling all leading bytes by
 * zeros
 */
int store_bignum(BIGNUM *bn, unsigned char *buf, int len)
{
    int bytes = BN_num_bytes(bn);
    if (bytes > len)
        return 0;
    memset(buf, 0, len);
    BN_bn2bin(bn, buf + len - bytes);
    return 1;
}
