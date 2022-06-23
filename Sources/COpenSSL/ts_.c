/* crypto/ts/ts_asn1.c */
/*
 * Written by Nils Larsch for the OpenSSL project 2004.
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

#include "ts.h"
#include "err.h"
#include "asn1t.h"

ASN1_SEQUENCE(TS_MSG_IMPRINT) = {
        ASN1_SIMPLE(TS_MSG_IMPRINT, hash_algo, X509_ALGOR),
        ASN1_SIMPLE(TS_MSG_IMPRINT, hashed_msg, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(TS_MSG_IMPRINT)

IMPLEMENT_ASN1_FUNCTIONS_const(TS_MSG_IMPRINT)
IMPLEMENT_ASN1_DUP_FUNCTION(TS_MSG_IMPRINT)
#ifndef OPENSSL_NO_BIO
TS_MSG_IMPRINT *d2i_TS_MSG_IMPRINT_bio(BIO *bp, TS_MSG_IMPRINT **a)
{
    return ASN1_d2i_bio_of(TS_MSG_IMPRINT, TS_MSG_IMPRINT_new,
                           d2i_TS_MSG_IMPRINT, bp, a);
}

int i2d_TS_MSG_IMPRINT_bio(BIO *bp, TS_MSG_IMPRINT *a)
{
    return ASN1_i2d_bio_of_const(TS_MSG_IMPRINT, i2d_TS_MSG_IMPRINT, bp, a);
}
#endif
#ifndef OPENSSL_NO_FP_API
TS_MSG_IMPRINT *d2i_TS_MSG_IMPRINT_fp(FILE *fp, TS_MSG_IMPRINT **a)
{
    return ASN1_d2i_fp_of(TS_MSG_IMPRINT, TS_MSG_IMPRINT_new,
                          d2i_TS_MSG_IMPRINT, fp, a);
}

int i2d_TS_MSG_IMPRINT_fp(FILE *fp, TS_MSG_IMPRINT *a)
{
    return ASN1_i2d_fp_of_const(TS_MSG_IMPRINT, i2d_TS_MSG_IMPRINT, fp, a);
}
#endif

ASN1_SEQUENCE(TS_REQ) = {
        ASN1_SIMPLE(TS_REQ, version, ASN1_INTEGER),
        ASN1_SIMPLE(TS_REQ, msg_imprint, TS_MSG_IMPRINT),
        ASN1_OPT(TS_REQ, policy_id, ASN1_OBJECT),
        ASN1_OPT(TS_REQ, nonce, ASN1_INTEGER),
        ASN1_OPT(TS_REQ, cert_req, ASN1_FBOOLEAN),
        ASN1_IMP_SEQUENCE_OF_OPT(TS_REQ, extensions, X509_EXTENSION, 0)
} ASN1_SEQUENCE_END(TS_REQ)

IMPLEMENT_ASN1_FUNCTIONS_const(TS_REQ)
IMPLEMENT_ASN1_DUP_FUNCTION(TS_REQ)
#ifndef OPENSSL_NO_BIO
TS_REQ *d2i_TS_REQ_bio(BIO *bp, TS_REQ **a)
{
    return ASN1_d2i_bio_of(TS_REQ, TS_REQ_new, d2i_TS_REQ, bp, a);
}

int i2d_TS_REQ_bio(BIO *bp, TS_REQ *a)
{
    return ASN1_i2d_bio_of_const(TS_REQ, i2d_TS_REQ, bp, a);
}
#endif
#ifndef OPENSSL_NO_FP_API
TS_REQ *d2i_TS_REQ_fp(FILE *fp, TS_REQ **a)
{
    return ASN1_d2i_fp_of(TS_REQ, TS_REQ_new, d2i_TS_REQ, fp, a);
}

int i2d_TS_REQ_fp(FILE *fp, TS_REQ *a)
{
    return ASN1_i2d_fp_of_const(TS_REQ, i2d_TS_REQ, fp, a);
}
#endif

ASN1_SEQUENCE(TS_ACCURACY) = {
        ASN1_OPT(TS_ACCURACY, seconds, ASN1_INTEGER),
        ASN1_IMP_OPT(TS_ACCURACY, millis, ASN1_INTEGER, 0),
        ASN1_IMP_OPT(TS_ACCURACY, micros, ASN1_INTEGER, 1)
} ASN1_SEQUENCE_END(TS_ACCURACY)

IMPLEMENT_ASN1_FUNCTIONS_const(TS_ACCURACY)
IMPLEMENT_ASN1_DUP_FUNCTION(TS_ACCURACY)

ASN1_SEQUENCE(TS_TST_INFO) = {
        ASN1_SIMPLE(TS_TST_INFO, version, ASN1_INTEGER),
        ASN1_SIMPLE(TS_TST_INFO, policy_id, ASN1_OBJECT),
        ASN1_SIMPLE(TS_TST_INFO, msg_imprint, TS_MSG_IMPRINT),
        ASN1_SIMPLE(TS_TST_INFO, serial, ASN1_INTEGER),
        ASN1_SIMPLE(TS_TST_INFO, time, ASN1_GENERALIZEDTIME),
        ASN1_OPT(TS_TST_INFO, accuracy, TS_ACCURACY),
        ASN1_OPT(TS_TST_INFO, ordering, ASN1_FBOOLEAN),
        ASN1_OPT(TS_TST_INFO, nonce, ASN1_INTEGER),
        ASN1_EXP_OPT(TS_TST_INFO, tsa, GENERAL_NAME, 0),
        ASN1_IMP_SEQUENCE_OF_OPT(TS_TST_INFO, extensions, X509_EXTENSION, 1)
} ASN1_SEQUENCE_END(TS_TST_INFO)

IMPLEMENT_ASN1_FUNCTIONS_const(TS_TST_INFO)
IMPLEMENT_ASN1_DUP_FUNCTION(TS_TST_INFO)
#ifndef OPENSSL_NO_BIO
TS_TST_INFO *d2i_TS_TST_INFO_bio(BIO *bp, TS_TST_INFO **a)
{
    return ASN1_d2i_bio_of(TS_TST_INFO, TS_TST_INFO_new, d2i_TS_TST_INFO, bp,
                           a);
}

int i2d_TS_TST_INFO_bio(BIO *bp, TS_TST_INFO *a)
{
    return ASN1_i2d_bio_of_const(TS_TST_INFO, i2d_TS_TST_INFO, bp, a);
}
#endif
#ifndef OPENSSL_NO_FP_API
TS_TST_INFO *d2i_TS_TST_INFO_fp(FILE *fp, TS_TST_INFO **a)
{
    return ASN1_d2i_fp_of(TS_TST_INFO, TS_TST_INFO_new, d2i_TS_TST_INFO, fp,
                          a);
}

int i2d_TS_TST_INFO_fp(FILE *fp, TS_TST_INFO *a)
{
    return ASN1_i2d_fp_of_const(TS_TST_INFO, i2d_TS_TST_INFO, fp, a);
}
#endif

ASN1_SEQUENCE(TS_STATUS_INFO) = {
        ASN1_SIMPLE(TS_STATUS_INFO, status, ASN1_INTEGER),
        ASN1_SEQUENCE_OF_OPT(TS_STATUS_INFO, text, ASN1_UTF8STRING),
        ASN1_OPT(TS_STATUS_INFO, failure_info, ASN1_BIT_STRING)
} ASN1_SEQUENCE_END(TS_STATUS_INFO)

IMPLEMENT_ASN1_FUNCTIONS_const(TS_STATUS_INFO)
IMPLEMENT_ASN1_DUP_FUNCTION(TS_STATUS_INFO)

static int ts_resp_set_tst_info(TS_RESP *a)
{
    long status;

    status = ASN1_INTEGER_get(a->status_info->status);

    if (a->token) {
        if (status != 0 && status != 1) {
            TSerr(TS_F_TS_RESP_SET_TST_INFO, TS_R_TOKEN_PRESENT);
            return 0;
        }
        if (a->tst_info != NULL)
            TS_TST_INFO_free(a->tst_info);
        a->tst_info = PKCS7_to_TS_TST_INFO(a->token);
        if (!a->tst_info) {
            TSerr(TS_F_TS_RESP_SET_TST_INFO,
                  TS_R_PKCS7_TO_TS_TST_INFO_FAILED);
            return 0;
        }
    } else if (status == 0 || status == 1) {
        TSerr(TS_F_TS_RESP_SET_TST_INFO, TS_R_TOKEN_NOT_PRESENT);
        return 0;
    }

    return 1;
}

static int ts_resp_cb(int op, ASN1_VALUE **pval, const ASN1_ITEM *it,
                      void *exarg)
{
    TS_RESP *ts_resp = (TS_RESP *)*pval;
    if (op == ASN1_OP_NEW_POST) {
        ts_resp->tst_info = NULL;
    } else if (op == ASN1_OP_FREE_POST) {
        if (ts_resp->tst_info != NULL)
            TS_TST_INFO_free(ts_resp->tst_info);
    } else if (op == ASN1_OP_D2I_POST) {
        if (ts_resp_set_tst_info(ts_resp) == 0)
            return 0;
    }
    return 1;
}

ASN1_SEQUENCE_cb(TS_RESP, ts_resp_cb) = {
        ASN1_SIMPLE(TS_RESP, status_info, TS_STATUS_INFO),
        ASN1_OPT(TS_RESP, token, PKCS7),
} ASN1_SEQUENCE_END_cb(TS_RESP, TS_RESP)

IMPLEMENT_ASN1_FUNCTIONS_const(TS_RESP)

IMPLEMENT_ASN1_DUP_FUNCTION(TS_RESP)

#ifndef OPENSSL_NO_BIO
TS_RESP *d2i_TS_RESP_bio(BIO *bp, TS_RESP **a)
{
    return ASN1_d2i_bio_of(TS_RESP, TS_RESP_new, d2i_TS_RESP, bp, a);
}

int i2d_TS_RESP_bio(BIO *bp, TS_RESP *a)
{
    return ASN1_i2d_bio_of_const(TS_RESP, i2d_TS_RESP, bp, a);
}
#endif
#ifndef OPENSSL_NO_FP_API
TS_RESP *d2i_TS_RESP_fp(FILE *fp, TS_RESP **a)
{
    return ASN1_d2i_fp_of(TS_RESP, TS_RESP_new, d2i_TS_RESP, fp, a);
}

int i2d_TS_RESP_fp(FILE *fp, TS_RESP *a)
{
    return ASN1_i2d_fp_of_const(TS_RESP, i2d_TS_RESP, fp, a);
}
#endif

ASN1_SEQUENCE(ESS_ISSUER_SERIAL) = {
        ASN1_SEQUENCE_OF(ESS_ISSUER_SERIAL, issuer, GENERAL_NAME),
        ASN1_SIMPLE(ESS_ISSUER_SERIAL, serial, ASN1_INTEGER)
} ASN1_SEQUENCE_END(ESS_ISSUER_SERIAL)

IMPLEMENT_ASN1_FUNCTIONS_const(ESS_ISSUER_SERIAL)
IMPLEMENT_ASN1_DUP_FUNCTION(ESS_ISSUER_SERIAL)

ASN1_SEQUENCE(ESS_CERT_ID) = {
        ASN1_SIMPLE(ESS_CERT_ID, hash, ASN1_OCTET_STRING),
        ASN1_OPT(ESS_CERT_ID, issuer_serial, ESS_ISSUER_SERIAL)
} ASN1_SEQUENCE_END(ESS_CERT_ID)

IMPLEMENT_ASN1_FUNCTIONS_const(ESS_CERT_ID)
IMPLEMENT_ASN1_DUP_FUNCTION(ESS_CERT_ID)

ASN1_SEQUENCE(ESS_SIGNING_CERT) = {
        ASN1_SEQUENCE_OF(ESS_SIGNING_CERT, cert_ids, ESS_CERT_ID),
        ASN1_SEQUENCE_OF_OPT(ESS_SIGNING_CERT, policy_info, POLICYINFO)
} ASN1_SEQUENCE_END(ESS_SIGNING_CERT)

IMPLEMENT_ASN1_FUNCTIONS_const(ESS_SIGNING_CERT)
IMPLEMENT_ASN1_DUP_FUNCTION(ESS_SIGNING_CERT)

/* Getting encapsulated TS_TST_INFO object from PKCS7. */
TS_TST_INFO *PKCS7_to_TS_TST_INFO(PKCS7 *token)
{
    PKCS7_SIGNED *pkcs7_signed;
    PKCS7 *enveloped;
    ASN1_TYPE *tst_info_wrapper;
    ASN1_OCTET_STRING *tst_info_der;
    const unsigned char *p;

    if (!PKCS7_type_is_signed(token)) {
        TSerr(TS_F_PKCS7_TO_TS_TST_INFO, TS_R_BAD_PKCS7_TYPE);
        return NULL;
    }

    /* Content must be present. */
    if (PKCS7_get_detached(token)) {
        TSerr(TS_F_PKCS7_TO_TS_TST_INFO, TS_R_DETACHED_CONTENT);
        return NULL;
    }

    /* We have a signed data with content. */
    pkcs7_signed = token->d.sign;
    enveloped = pkcs7_signed->contents;
    if (OBJ_obj2nid(enveloped->type) != NID_id_smime_ct_TSTInfo) {
        TSerr(TS_F_PKCS7_TO_TS_TST_INFO, TS_R_BAD_PKCS7_TYPE);
        return NULL;
    }

    /* We have a DER encoded TST_INFO as the signed data. */
    tst_info_wrapper = enveloped->d.other;
    if (tst_info_wrapper->type != V_ASN1_OCTET_STRING) {
        TSerr(TS_F_PKCS7_TO_TS_TST_INFO, TS_R_BAD_TYPE);
        return NULL;
    }

    /* We have the correct ASN1_OCTET_STRING type. */
    tst_info_der = tst_info_wrapper->value.octet_string;
    /* At last, decode the TST_INFO. */
    p = tst_info_der->data;
    return d2i_TS_TST_INFO(NULL, &p, tst_info_der->length);
}
/* crypto/ts/ts_conf.c */
/*
 * Written by Zoltan Glozik (zglozik@stones.com) for the OpenSSL project
 * 2002.
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

#include <string.h>

#include "crypto.h"
#include "cryptlib.h"
#include "pem.h"
#ifndef OPENSSL_NO_ENGINE
# include "engine.h"
#endif
// #include "ts.h"

/* Macro definitions for the configuration file. */

#define BASE_SECTION                    "tsa"
#define ENV_DEFAULT_TSA                 "default_tsa"
#define ENV_SERIAL                      "serial"
#define ENV_CRYPTO_DEVICE               "crypto_device"
#define ENV_SIGNER_CERT                 "signer_cert"
#define ENV_CERTS                       "certs"
#define ENV_SIGNER_KEY                  "signer_key"
#define ENV_DEFAULT_POLICY              "default_policy"
#define ENV_OTHER_POLICIES              "other_policies"
#define ENV_DIGESTS                     "digests"
#define ENV_ACCURACY                    "accuracy"
#define ENV_ORDERING                    "ordering"
#define ENV_TSA_NAME                    "tsa_name"
#define ENV_ESS_CERT_ID_CHAIN           "ess_cert_id_chain"
#define ENV_VALUE_SECS                  "secs"
#define ENV_VALUE_MILLISECS             "millisecs"
#define ENV_VALUE_MICROSECS             "microsecs"
#define ENV_CLOCK_PRECISION_DIGITS      "clock_precision_digits"
#define ENV_VALUE_YES                   "yes"
#define ENV_VALUE_NO                    "no"

/* Function definitions for certificate and key loading. */

X509 *TS_CONF_load_cert(const char *file)
{
    BIO *cert = NULL;
    X509 *x = NULL;

    if ((cert = BIO_new_file(file, "r")) == NULL)
        goto end;
    x = PEM_read_bio_X509_AUX(cert, NULL, NULL, NULL);
 end:
    if (x == NULL)
        fprintf(stderr, "unable to load certificate: %s\n", file);
    BIO_free(cert);
    return x;
}

STACK_OF(X509) *TS_CONF_load_certs(const char *file)
{
    BIO *certs = NULL;
    STACK_OF(X509) *othercerts = NULL;
    STACK_OF(X509_INFO) *allcerts = NULL;
    int i;

    if (!(certs = BIO_new_file(file, "r")))
        goto end;

    if (!(othercerts = sk_X509_new_null()))
        goto end;
    allcerts = PEM_X509_INFO_read_bio(certs, NULL, NULL, NULL);
    for (i = 0; i < sk_X509_INFO_num(allcerts); i++) {
        X509_INFO *xi = sk_X509_INFO_value(allcerts, i);
        if (xi->x509) {
            sk_X509_push(othercerts, xi->x509);
            xi->x509 = NULL;
        }
    }
 end:
    if (othercerts == NULL)
        fprintf(stderr, "unable to load certificates: %s\n", file);
    sk_X509_INFO_pop_free(allcerts, X509_INFO_free);
    BIO_free(certs);
    return othercerts;
}

EVP_PKEY *TS_CONF_load_key(const char *file, const char *pass)
{
    BIO *key = NULL;
    EVP_PKEY *pkey = NULL;

    if (!(key = BIO_new_file(file, "r")))
        goto end;
    pkey = PEM_read_bio_PrivateKey(key, NULL, NULL, (char *)pass);
 end:
    if (pkey == NULL)
        fprintf(stderr, "unable to load private key: %s\n", file);
    BIO_free(key);
    return pkey;
}

/* Function definitions for handling configuration options. */

static void TS_CONF_lookup_fail(const char *name, const char *tag)
{
    fprintf(stderr, "variable lookup failed for %s::%s\n", name, tag);
}

static void TS_CONF_invalid(const char *name, const char *tag)
{
    fprintf(stderr, "invalid variable value for %s::%s\n", name, tag);
}

const char *TS_CONF_get_tsa_section(CONF *conf, const char *section)
{
    if (!section) {
        section = NCONF_get_string(conf, BASE_SECTION, ENV_DEFAULT_TSA);
        if (!section)
            TS_CONF_lookup_fail(BASE_SECTION, ENV_DEFAULT_TSA);
    }
    return section;
}

int TS_CONF_set_serial(CONF *conf, const char *section, TS_serial_cb cb,
                       TS_RESP_CTX *ctx)
{
    int ret = 0;
    char *serial = NCONF_get_string(conf, section, ENV_SERIAL);
    if (!serial) {
        TS_CONF_lookup_fail(section, ENV_SERIAL);
        goto err;
    }
    TS_RESP_CTX_set_serial_cb(ctx, cb, serial);

    ret = 1;
 err:
    return ret;
}

#ifndef OPENSSL_NO_ENGINE

int TS_CONF_set_crypto_device(CONF *conf, const char *section,
                              const char *device)
{
    int ret = 0;

    if (!device)
        device = NCONF_get_string(conf, section, ENV_CRYPTO_DEVICE);

    if (device && !TS_CONF_set_default_engine(device)) {
        TS_CONF_invalid(section, ENV_CRYPTO_DEVICE);
        goto err;
    }
    ret = 1;
 err:
    return ret;
}

int TS_CONF_set_default_engine(const char *name)
{
    ENGINE *e = NULL;
    int ret = 0;

    /* Leave the default if builtin specified. */
    if (strcmp(name, "builtin") == 0)
        return 1;

    if (!(e = ENGINE_by_id(name)))
        goto err;
    /* Enable the use of the NCipher HSM for forked children. */
    if (strcmp(name, "chil") == 0)
        ENGINE_ctrl(e, ENGINE_CTRL_CHIL_SET_FORKCHECK, 1, 0, 0);
    /* All the operations are going to be carried out by the engine. */
    if (!ENGINE_set_default(e, ENGINE_METHOD_ALL))
        goto err;
    ret = 1;
 err:
    if (!ret) {
        TSerr(TS_F_TS_CONF_SET_DEFAULT_ENGINE, TS_R_COULD_NOT_SET_ENGINE);
        ERR_add_error_data(2, "engine:", name);
    }
    if (e)
        ENGINE_free(e);
    return ret;
}

#endif

int TS_CONF_set_signer_cert(CONF *conf, const char *section,
                            const char *cert, TS_RESP_CTX *ctx)
{
    int ret = 0;
    X509 *cert_obj = NULL;
    if (!cert)
        cert = NCONF_get_string(conf, section, ENV_SIGNER_CERT);
    if (!cert) {
        TS_CONF_lookup_fail(section, ENV_SIGNER_CERT);
        goto err;
    }
    if (!(cert_obj = TS_CONF_load_cert(cert)))
        goto err;
    if (!TS_RESP_CTX_set_signer_cert(ctx, cert_obj))
        goto err;

    ret = 1;
 err:
    X509_free(cert_obj);
    return ret;
}

int TS_CONF_set_certs(CONF *conf, const char *section, const char *certs,
                      TS_RESP_CTX *ctx)
{
    int ret = 0;
    STACK_OF(X509) *certs_obj = NULL;
    if (!certs)
        certs = NCONF_get_string(conf, section, ENV_CERTS);
    /* Certificate chain is optional. */
    if (!certs)
        goto end;
    if (!(certs_obj = TS_CONF_load_certs(certs)))
        goto err;
    if (!TS_RESP_CTX_set_certs(ctx, certs_obj))
        goto err;
 end:
    ret = 1;
 err:
    sk_X509_pop_free(certs_obj, X509_free);
    return ret;
}

int TS_CONF_set_signer_key(CONF *conf, const char *section,
                           const char *key, const char *pass,
                           TS_RESP_CTX *ctx)
{
    int ret = 0;
    EVP_PKEY *key_obj = NULL;
    if (!key)
        key = NCONF_get_string(conf, section, ENV_SIGNER_KEY);
    if (!key) {
        TS_CONF_lookup_fail(section, ENV_SIGNER_KEY);
        goto err;
    }
    if (!(key_obj = TS_CONF_load_key(key, pass)))
        goto err;
    if (!TS_RESP_CTX_set_signer_key(ctx, key_obj))
        goto err;

    ret = 1;
 err:
    EVP_PKEY_free(key_obj);
    return ret;
}

int TS_CONF_set_def_policy(CONF *conf, const char *section,
                           const char *policy, TS_RESP_CTX *ctx)
{
    int ret = 0;
    ASN1_OBJECT *policy_obj = NULL;
    if (!policy)
        policy = NCONF_get_string(conf, section, ENV_DEFAULT_POLICY);
    if (!policy) {
        TS_CONF_lookup_fail(section, ENV_DEFAULT_POLICY);
        goto err;
    }
    if (!(policy_obj = OBJ_txt2obj(policy, 0))) {
        TS_CONF_invalid(section, ENV_DEFAULT_POLICY);
        goto err;
    }
    if (!TS_RESP_CTX_set_def_policy(ctx, policy_obj))
        goto err;

    ret = 1;
 err:
    ASN1_OBJECT_free(policy_obj);
    return ret;
}

int TS_CONF_set_policies(CONF *conf, const char *section, TS_RESP_CTX *ctx)
{
    int ret = 0;
    int i;
    STACK_OF(CONF_VALUE) *list = NULL;
    char *policies = NCONF_get_string(conf, section,
                                      ENV_OTHER_POLICIES);
    /* If no other policy is specified, that's fine. */
    if (policies && !(list = X509V3_parse_list(policies))) {
        TS_CONF_invalid(section, ENV_OTHER_POLICIES);
        goto err;
    }
    for (i = 0; i < sk_CONF_VALUE_num(list); ++i) {
        CONF_VALUE *val = sk_CONF_VALUE_value(list, i);
        const char *extval = val->value ? val->value : val->name;
        ASN1_OBJECT *objtmp;
        if (!(objtmp = OBJ_txt2obj(extval, 0))) {
            TS_CONF_invalid(section, ENV_OTHER_POLICIES);
            goto err;
        }
        if (!TS_RESP_CTX_add_policy(ctx, objtmp))
            goto err;
        ASN1_OBJECT_free(objtmp);
    }

    ret = 1;
 err:
    sk_CONF_VALUE_pop_free(list, X509V3_conf_free);
    return ret;
}

int TS_CONF_set_digests(CONF *conf, const char *section, TS_RESP_CTX *ctx)
{
    int ret = 0;
    int i;
    STACK_OF(CONF_VALUE) *list = NULL;
    char *digests = NCONF_get_string(conf, section, ENV_DIGESTS);
    if (!digests) {
        TS_CONF_lookup_fail(section, ENV_DIGESTS);
        goto err;
    }
    if (!(list = X509V3_parse_list(digests))) {
        TS_CONF_invalid(section, ENV_DIGESTS);
        goto err;
    }
    if (sk_CONF_VALUE_num(list) == 0) {
        TS_CONF_invalid(section, ENV_DIGESTS);
        goto err;
    }
    for (i = 0; i < sk_CONF_VALUE_num(list); ++i) {
        CONF_VALUE *val = sk_CONF_VALUE_value(list, i);
        const char *extval = val->value ? val->value : val->name;
        const EVP_MD *md;
        if (!(md = EVP_get_digestbyname(extval))) {
            TS_CONF_invalid(section, ENV_DIGESTS);
            goto err;
        }
        if (!TS_RESP_CTX_add_md(ctx, md))
            goto err;
    }

    ret = 1;
 err:
    sk_CONF_VALUE_pop_free(list, X509V3_conf_free);
    return ret;
}

int TS_CONF_set_accuracy(CONF *conf, const char *section, TS_RESP_CTX *ctx)
{
    int ret = 0;
    int i;
    int secs = 0, millis = 0, micros = 0;
    STACK_OF(CONF_VALUE) *list = NULL;
    char *accuracy = NCONF_get_string(conf, section, ENV_ACCURACY);

    if (accuracy && !(list = X509V3_parse_list(accuracy))) {
        TS_CONF_invalid(section, ENV_ACCURACY);
        goto err;
    }
    for (i = 0; i < sk_CONF_VALUE_num(list); ++i) {
        CONF_VALUE *val = sk_CONF_VALUE_value(list, i);
        if (strcmp(val->name, ENV_VALUE_SECS) == 0) {
            if (val->value)
                secs = atoi(val->value);
        } else if (strcmp(val->name, ENV_VALUE_MILLISECS) == 0) {
            if (val->value)
                millis = atoi(val->value);
        } else if (strcmp(val->name, ENV_VALUE_MICROSECS) == 0) {
            if (val->value)
                micros = atoi(val->value);
        } else {
            TS_CONF_invalid(section, ENV_ACCURACY);
            goto err;
        }
    }
    if (!TS_RESP_CTX_set_accuracy(ctx, secs, millis, micros))
        goto err;

    ret = 1;
 err:
    sk_CONF_VALUE_pop_free(list, X509V3_conf_free);
    return ret;
}

int TS_CONF_set_clock_precision_digits(CONF *conf, const char *section,
                                       TS_RESP_CTX *ctx)
{
    int ret = 0;
    long digits = 0;

    /*
     * If not specified, set the default value to 0, i.e. sec precision
     */
    if (!NCONF_get_number_e(conf, section, ENV_CLOCK_PRECISION_DIGITS,
                            &digits))
        digits = 0;
    if (digits < 0 || digits > TS_MAX_CLOCK_PRECISION_DIGITS) {
        TS_CONF_invalid(section, ENV_CLOCK_PRECISION_DIGITS);
        goto err;
    }

    if (!TS_RESP_CTX_set_clock_precision_digits(ctx, digits))
        goto err;

    return 1;
 err:
    return ret;
}

static int TS_CONF_add_flag(CONF *conf, const char *section,
                            const char *field, int flag, TS_RESP_CTX *ctx)
{
    /* Default is false. */
    const char *value = NCONF_get_string(conf, section, field);
    if (value) {
        if (strcmp(value, ENV_VALUE_YES) == 0)
            TS_RESP_CTX_add_flags(ctx, flag);
        else if (strcmp(value, ENV_VALUE_NO) != 0) {
            TS_CONF_invalid(section, field);
            return 0;
        }
    }

    return 1;
}

int TS_CONF_set_ordering(CONF *conf, const char *section, TS_RESP_CTX *ctx)
{
    return TS_CONF_add_flag(conf, section, ENV_ORDERING, TS_ORDERING, ctx);
}

int TS_CONF_set_tsa_name(CONF *conf, const char *section, TS_RESP_CTX *ctx)
{
    return TS_CONF_add_flag(conf, section, ENV_TSA_NAME, TS_TSA_NAME, ctx);
}

int TS_CONF_set_ess_cert_id_chain(CONF *conf, const char *section,
                                  TS_RESP_CTX *ctx)
{
    return TS_CONF_add_flag(conf, section, ENV_ESS_CERT_ID_CHAIN,
                            TS_ESS_CERT_ID_CHAIN, ctx);
}
/* crypto/ts/ts_err.c */
/* ====================================================================
 * Copyright (c) 1999-2007 The OpenSSL Project.  All rights reserved.
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
// #include "ts.h"

/* BEGIN ERROR CODES */
#ifndef OPENSSL_NO_ERR

# define ERR_FUNC(func) ERR_PACK(ERR_LIB_TS,func,0)
# define ERR_REASON(reason) ERR_PACK(ERR_LIB_TS,0,reason)

static ERR_STRING_DATA TS_str_functs[] = {
    {ERR_FUNC(TS_F_D2I_TS_RESP), "d2i_TS_RESP"},
    {ERR_FUNC(TS_F_DEF_SERIAL_CB), "DEF_SERIAL_CB"},
    {ERR_FUNC(TS_F_DEF_TIME_CB), "DEF_TIME_CB"},
    {ERR_FUNC(TS_F_ESS_ADD_SIGNING_CERT), "ESS_ADD_SIGNING_CERT"},
    {ERR_FUNC(TS_F_ESS_CERT_ID_NEW_INIT), "ESS_CERT_ID_NEW_INIT"},
    {ERR_FUNC(TS_F_ESS_SIGNING_CERT_NEW_INIT), "ESS_SIGNING_CERT_NEW_INIT"},
    {ERR_FUNC(TS_F_INT_TS_RESP_VERIFY_TOKEN), "INT_TS_RESP_VERIFY_TOKEN"},
    {ERR_FUNC(TS_F_PKCS7_TO_TS_TST_INFO), "PKCS7_to_TS_TST_INFO"},
    {ERR_FUNC(TS_F_TS_ACCURACY_SET_MICROS), "TS_ACCURACY_set_micros"},
    {ERR_FUNC(TS_F_TS_ACCURACY_SET_MILLIS), "TS_ACCURACY_set_millis"},
    {ERR_FUNC(TS_F_TS_ACCURACY_SET_SECONDS), "TS_ACCURACY_set_seconds"},
    {ERR_FUNC(TS_F_TS_CHECK_IMPRINTS), "TS_CHECK_IMPRINTS"},
    {ERR_FUNC(TS_F_TS_CHECK_NONCES), "TS_CHECK_NONCES"},
    {ERR_FUNC(TS_F_TS_CHECK_POLICY), "TS_CHECK_POLICY"},
    {ERR_FUNC(TS_F_TS_CHECK_SIGNING_CERTS), "TS_CHECK_SIGNING_CERTS"},
    {ERR_FUNC(TS_F_TS_CHECK_STATUS_INFO), "TS_CHECK_STATUS_INFO"},
    {ERR_FUNC(TS_F_TS_COMPUTE_IMPRINT), "TS_COMPUTE_IMPRINT"},
    {ERR_FUNC(TS_F_TS_CONF_SET_DEFAULT_ENGINE), "TS_CONF_set_default_engine"},
    {ERR_FUNC(TS_F_TS_GET_STATUS_TEXT), "TS_GET_STATUS_TEXT"},
    {ERR_FUNC(TS_F_TS_MSG_IMPRINT_SET_ALGO), "TS_MSG_IMPRINT_set_algo"},
    {ERR_FUNC(TS_F_TS_REQ_SET_MSG_IMPRINT), "TS_REQ_set_msg_imprint"},
    {ERR_FUNC(TS_F_TS_REQ_SET_NONCE), "TS_REQ_set_nonce"},
    {ERR_FUNC(TS_F_TS_REQ_SET_POLICY_ID), "TS_REQ_set_policy_id"},
    {ERR_FUNC(TS_F_TS_RESP_CREATE_RESPONSE), "TS_RESP_create_response"},
    {ERR_FUNC(TS_F_TS_RESP_CREATE_TST_INFO), "TS_RESP_CREATE_TST_INFO"},
    {ERR_FUNC(TS_F_TS_RESP_CTX_ADD_FAILURE_INFO),
     "TS_RESP_CTX_add_failure_info"},
    {ERR_FUNC(TS_F_TS_RESP_CTX_ADD_MD), "TS_RESP_CTX_add_md"},
    {ERR_FUNC(TS_F_TS_RESP_CTX_ADD_POLICY), "TS_RESP_CTX_add_policy"},
    {ERR_FUNC(TS_F_TS_RESP_CTX_NEW), "TS_RESP_CTX_new"},
    {ERR_FUNC(TS_F_TS_RESP_CTX_SET_ACCURACY), "TS_RESP_CTX_set_accuracy"},
    {ERR_FUNC(TS_F_TS_RESP_CTX_SET_CERTS), "TS_RESP_CTX_set_certs"},
    {ERR_FUNC(TS_F_TS_RESP_CTX_SET_DEF_POLICY), "TS_RESP_CTX_set_def_policy"},
    {ERR_FUNC(TS_F_TS_RESP_CTX_SET_SIGNER_CERT),
     "TS_RESP_CTX_set_signer_cert"},
    {ERR_FUNC(TS_F_TS_RESP_CTX_SET_STATUS_INFO),
     "TS_RESP_CTX_set_status_info"},
    {ERR_FUNC(TS_F_TS_RESP_GET_POLICY), "TS_RESP_GET_POLICY"},
    {ERR_FUNC(TS_F_TS_RESP_SET_GENTIME_WITH_PRECISION),
     "TS_RESP_SET_GENTIME_WITH_PRECISION"},
    {ERR_FUNC(TS_F_TS_RESP_SET_STATUS_INFO), "TS_RESP_set_status_info"},
    {ERR_FUNC(TS_F_TS_RESP_SET_TST_INFO), "TS_RESP_set_tst_info"},
    {ERR_FUNC(TS_F_TS_RESP_SIGN), "TS_RESP_SIGN"},
    {ERR_FUNC(TS_F_TS_RESP_VERIFY_SIGNATURE), "TS_RESP_verify_signature"},
    {ERR_FUNC(TS_F_TS_RESP_VERIFY_TOKEN), "TS_RESP_verify_token"},
    {ERR_FUNC(TS_F_TS_TST_INFO_SET_ACCURACY), "TS_TST_INFO_set_accuracy"},
    {ERR_FUNC(TS_F_TS_TST_INFO_SET_MSG_IMPRINT),
     "TS_TST_INFO_set_msg_imprint"},
    {ERR_FUNC(TS_F_TS_TST_INFO_SET_NONCE), "TS_TST_INFO_set_nonce"},
    {ERR_FUNC(TS_F_TS_TST_INFO_SET_POLICY_ID), "TS_TST_INFO_set_policy_id"},
    {ERR_FUNC(TS_F_TS_TST_INFO_SET_SERIAL), "TS_TST_INFO_set_serial"},
    {ERR_FUNC(TS_F_TS_TST_INFO_SET_TIME), "TS_TST_INFO_set_time"},
    {ERR_FUNC(TS_F_TS_TST_INFO_SET_TSA), "TS_TST_INFO_set_tsa"},
    {ERR_FUNC(TS_F_TS_VERIFY), "TS_VERIFY"},
    {ERR_FUNC(TS_F_TS_VERIFY_CERT), "TS_VERIFY_CERT"},
    {ERR_FUNC(TS_F_TS_VERIFY_CTX_NEW), "TS_VERIFY_CTX_new"},
    {0, NULL}
};

static ERR_STRING_DATA TS_str_reasons[] = {
    {ERR_REASON(TS_R_BAD_PKCS7_TYPE), "bad pkcs7 type"},
    {ERR_REASON(TS_R_BAD_TYPE), "bad type"},
    {ERR_REASON(TS_R_CERTIFICATE_VERIFY_ERROR), "certificate verify error"},
    {ERR_REASON(TS_R_COULD_NOT_SET_ENGINE), "could not set engine"},
    {ERR_REASON(TS_R_COULD_NOT_SET_TIME), "could not set time"},
    {ERR_REASON(TS_R_D2I_TS_RESP_INT_FAILED), "d2i ts resp int failed"},
    {ERR_REASON(TS_R_DETACHED_CONTENT), "detached content"},
    {ERR_REASON(TS_R_ESS_ADD_SIGNING_CERT_ERROR),
     "ess add signing cert error"},
    {ERR_REASON(TS_R_ESS_SIGNING_CERTIFICATE_ERROR),
     "ess signing certificate error"},
    {ERR_REASON(TS_R_INVALID_NULL_POINTER), "invalid null pointer"},
    {ERR_REASON(TS_R_INVALID_SIGNER_CERTIFICATE_PURPOSE),
     "invalid signer certificate purpose"},
    {ERR_REASON(TS_R_MESSAGE_IMPRINT_MISMATCH), "message imprint mismatch"},
    {ERR_REASON(TS_R_NONCE_MISMATCH), "nonce mismatch"},
    {ERR_REASON(TS_R_NONCE_NOT_RETURNED), "nonce not returned"},
    {ERR_REASON(TS_R_NO_CONTENT), "no content"},
    {ERR_REASON(TS_R_NO_TIME_STAMP_TOKEN), "no time stamp token"},
    {ERR_REASON(TS_R_PKCS7_ADD_SIGNATURE_ERROR), "pkcs7 add signature error"},
    {ERR_REASON(TS_R_PKCS7_ADD_SIGNED_ATTR_ERROR),
     "pkcs7 add signed attr error"},
    {ERR_REASON(TS_R_PKCS7_TO_TS_TST_INFO_FAILED),
     "pkcs7 to ts tst info failed"},
    {ERR_REASON(TS_R_POLICY_MISMATCH), "policy mismatch"},
    {ERR_REASON(TS_R_PRIVATE_KEY_DOES_NOT_MATCH_CERTIFICATE),
     "private key does not match certificate"},
    {ERR_REASON(TS_R_RESPONSE_SETUP_ERROR), "response setup error"},
    {ERR_REASON(TS_R_SIGNATURE_FAILURE), "signature failure"},
    {ERR_REASON(TS_R_THERE_MUST_BE_ONE_SIGNER), "there must be one signer"},
    {ERR_REASON(TS_R_TIME_SYSCALL_ERROR), "time syscall error"},
    {ERR_REASON(TS_R_TOKEN_NOT_PRESENT), "token not present"},
    {ERR_REASON(TS_R_TOKEN_PRESENT), "token present"},
    {ERR_REASON(TS_R_TSA_NAME_MISMATCH), "tsa name mismatch"},
    {ERR_REASON(TS_R_TSA_UNTRUSTED), "tsa untrusted"},
    {ERR_REASON(TS_R_TST_INFO_SETUP_ERROR), "tst info setup error"},
    {ERR_REASON(TS_R_TS_DATASIGN), "ts datasign"},
    {ERR_REASON(TS_R_UNACCEPTABLE_POLICY), "unacceptable policy"},
    {ERR_REASON(TS_R_UNSUPPORTED_MD_ALGORITHM), "unsupported md algorithm"},
    {ERR_REASON(TS_R_UNSUPPORTED_VERSION), "unsupported version"},
    {ERR_REASON(TS_R_WRONG_CONTENT_TYPE), "wrong content type"},
    {0, NULL}
};

#endif

void ERR_load_TS_strings(void)
{
#ifndef OPENSSL_NO_ERR

    if (ERR_func_error_string(TS_str_functs[0].error) == NULL) {
        ERR_load_strings(0, TS_str_functs);
        ERR_load_strings(0, TS_str_reasons);
    }
#endif
}
/* crypto/ts/ts_lib.c */
/*
 * Written by Zoltan Glozik (zglozik@stones.com) for the OpenSSL project
 * 2002.
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
#include "objects.h"
#include "bn.h"
#include "x509v3.h"
// #include "ts.h"

/* Local function declarations. */

/* Function definitions. */

int TS_ASN1_INTEGER_print_bio(BIO *bio, const ASN1_INTEGER *num)
{
    BIGNUM num_bn;
    int result = 0;
    char *hex;

    BN_init(&num_bn);
    ASN1_INTEGER_to_BN(num, &num_bn);
    if ((hex = BN_bn2hex(&num_bn))) {
        result = BIO_write(bio, "0x", 2) > 0;
        result = result && BIO_write(bio, hex, strlen(hex)) > 0;
        OPENSSL_free(hex);
    }
    BN_free(&num_bn);

    return result;
}

int TS_OBJ_print_bio(BIO *bio, const ASN1_OBJECT *obj)
{
    char obj_txt[128];

    OBJ_obj2txt(obj_txt, sizeof(obj_txt), obj, 0);
    BIO_printf(bio, "%s\n", obj_txt);

    return 1;
}

int TS_ext_print_bio(BIO *bio, const STACK_OF(X509_EXTENSION) *extensions)
{
    int i, critical, n;
    X509_EXTENSION *ex;
    ASN1_OBJECT *obj;

    BIO_printf(bio, "Extensions:\n");
    n = X509v3_get_ext_count(extensions);
    for (i = 0; i < n; i++) {
        ex = X509v3_get_ext(extensions, i);
        obj = X509_EXTENSION_get_object(ex);
        i2a_ASN1_OBJECT(bio, obj);
        critical = X509_EXTENSION_get_critical(ex);
        BIO_printf(bio, ": %s\n", critical ? "critical" : "");
        if (!X509V3_EXT_print(bio, ex, 0, 4)) {
            BIO_printf(bio, "%4s", "");
            M_ASN1_OCTET_STRING_print(bio, ex->value);
        }
        BIO_write(bio, "\n", 1);
    }

    return 1;
}

int TS_X509_ALGOR_print_bio(BIO *bio, const X509_ALGOR *alg)
{
    int i = OBJ_obj2nid(alg->algorithm);
    return BIO_printf(bio, "Hash Algorithm: %s\n",
                      (i == NID_undef) ? "UNKNOWN" : OBJ_nid2ln(i));
}

int TS_MSG_IMPRINT_print_bio(BIO *bio, TS_MSG_IMPRINT *a)
{
    const ASN1_OCTET_STRING *msg;

    TS_X509_ALGOR_print_bio(bio, TS_MSG_IMPRINT_get_algo(a));

    BIO_printf(bio, "Message data:\n");
    msg = TS_MSG_IMPRINT_get_msg(a);
    BIO_dump_indent(bio, (const char *)M_ASN1_STRING_data(msg),
                    M_ASN1_STRING_length(msg), 4);

    return 1;
}
/* crypto/ts/ts_req_print.c */
/*
 * Written by Zoltan Glozik (zglozik@stones.com) for the OpenSSL project
 * 2002.
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
// #include "objects.h"
// #include "bn.h"
// #include "x509v3.h"
// #include "ts.h"

/* Function definitions. */

int TS_REQ_print_bio(BIO *bio, TS_REQ *a)
{
    int v;
    ASN1_OBJECT *policy_id;
    const ASN1_INTEGER *nonce;

    if (a == NULL)
        return 0;

    v = TS_REQ_get_version(a);
    BIO_printf(bio, "Version: %d\n", v);

    TS_MSG_IMPRINT_print_bio(bio, TS_REQ_get_msg_imprint(a));

    BIO_printf(bio, "Policy OID: ");
    policy_id = TS_REQ_get_policy_id(a);
    if (policy_id == NULL)
        BIO_printf(bio, "unspecified\n");
    else
        TS_OBJ_print_bio(bio, policy_id);

    BIO_printf(bio, "Nonce: ");
    nonce = TS_REQ_get_nonce(a);
    if (nonce == NULL)
        BIO_printf(bio, "unspecified");
    else
        TS_ASN1_INTEGER_print_bio(bio, nonce);
    BIO_write(bio, "\n", 1);

    BIO_printf(bio, "Certificate required: %s\n",
               TS_REQ_get_cert_req(a) ? "yes" : "no");

    TS_ext_print_bio(bio, TS_REQ_get_exts(a));

    return 1;
}
/* crypto/ts/ts_req_utils.c */
/*
 * Written by Zoltan Glozik (zglozik@stones.com) for the OpenSSL project
 * 2002.
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
// #include "objects.h"
// #include "x509v3.h"
// #include "ts.h"

int TS_REQ_set_version(TS_REQ *a, long version)
{
    return ASN1_INTEGER_set(a->version, version);
}

long TS_REQ_get_version(const TS_REQ *a)
{
    return ASN1_INTEGER_get(a->version);
}

int TS_REQ_set_msg_imprint(TS_REQ *a, TS_MSG_IMPRINT *msg_imprint)
{
    TS_MSG_IMPRINT *new_msg_imprint;

    if (a->msg_imprint == msg_imprint)
        return 1;
    new_msg_imprint = TS_MSG_IMPRINT_dup(msg_imprint);
    if (new_msg_imprint == NULL) {
        TSerr(TS_F_TS_REQ_SET_MSG_IMPRINT, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    TS_MSG_IMPRINT_free(a->msg_imprint);
    a->msg_imprint = new_msg_imprint;
    return 1;
}

TS_MSG_IMPRINT *TS_REQ_get_msg_imprint(TS_REQ *a)
{
    return a->msg_imprint;
}

int TS_MSG_IMPRINT_set_algo(TS_MSG_IMPRINT *a, X509_ALGOR *alg)
{
    X509_ALGOR *new_alg;

    if (a->hash_algo == alg)
        return 1;
    new_alg = X509_ALGOR_dup(alg);
    if (new_alg == NULL) {
        TSerr(TS_F_TS_MSG_IMPRINT_SET_ALGO, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    X509_ALGOR_free(a->hash_algo);
    a->hash_algo = new_alg;
    return 1;
}

X509_ALGOR *TS_MSG_IMPRINT_get_algo(TS_MSG_IMPRINT *a)
{
    return a->hash_algo;
}

int TS_MSG_IMPRINT_set_msg(TS_MSG_IMPRINT *a, unsigned char *d, int len)
{
    return ASN1_OCTET_STRING_set(a->hashed_msg, d, len);
}

ASN1_OCTET_STRING *TS_MSG_IMPRINT_get_msg(TS_MSG_IMPRINT *a)
{
    return a->hashed_msg;
}

int TS_REQ_set_policy_id(TS_REQ *a, ASN1_OBJECT *policy)
{
    ASN1_OBJECT *new_policy;

    if (a->policy_id == policy)
        return 1;
    new_policy = OBJ_dup(policy);
    if (new_policy == NULL) {
        TSerr(TS_F_TS_REQ_SET_POLICY_ID, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    ASN1_OBJECT_free(a->policy_id);
    a->policy_id = new_policy;
    return 1;
}

ASN1_OBJECT *TS_REQ_get_policy_id(TS_REQ *a)
{
    return a->policy_id;
}

int TS_REQ_set_nonce(TS_REQ *a, const ASN1_INTEGER *nonce)
{
    ASN1_INTEGER *new_nonce;

    if (a->nonce == nonce)
        return 1;
    new_nonce = ASN1_INTEGER_dup(nonce);
    if (new_nonce == NULL) {
        TSerr(TS_F_TS_REQ_SET_NONCE, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    ASN1_INTEGER_free(a->nonce);
    a->nonce = new_nonce;
    return 1;
}

const ASN1_INTEGER *TS_REQ_get_nonce(const TS_REQ *a)
{
    return a->nonce;
}

int TS_REQ_set_cert_req(TS_REQ *a, int cert_req)
{
    a->cert_req = cert_req ? 0xFF : 0x00;
    return 1;
}

int TS_REQ_get_cert_req(const TS_REQ *a)
{
    return a->cert_req ? 1 : 0;
}

STACK_OF(X509_EXTENSION) *TS_REQ_get_exts(TS_REQ *a)
{
    return a->extensions;
}

void TS_REQ_ext_free(TS_REQ *a)
{
    if (!a)
        return;
    sk_X509_EXTENSION_pop_free(a->extensions, X509_EXTENSION_free);
    a->extensions = NULL;
}

int TS_REQ_get_ext_count(TS_REQ *a)
{
    return X509v3_get_ext_count(a->extensions);
}

int TS_REQ_get_ext_by_NID(TS_REQ *a, int nid, int lastpos)
{
    return X509v3_get_ext_by_NID(a->extensions, nid, lastpos);
}

int TS_REQ_get_ext_by_OBJ(TS_REQ *a, ASN1_OBJECT *obj, int lastpos)
{
    return X509v3_get_ext_by_OBJ(a->extensions, obj, lastpos);
}

int TS_REQ_get_ext_by_critical(TS_REQ *a, int crit, int lastpos)
{
    return X509v3_get_ext_by_critical(a->extensions, crit, lastpos);
}

X509_EXTENSION *TS_REQ_get_ext(TS_REQ *a, int loc)
{
    return X509v3_get_ext(a->extensions, loc);
}

X509_EXTENSION *TS_REQ_delete_ext(TS_REQ *a, int loc)
{
    return X509v3_delete_ext(a->extensions, loc);
}

int TS_REQ_add_ext(TS_REQ *a, X509_EXTENSION *ex, int loc)
{
    return X509v3_add_ext(&a->extensions, ex, loc) != NULL;
}

void *TS_REQ_get_ext_d2i(TS_REQ *a, int nid, int *crit, int *idx)
{
    return X509V3_get_d2i(a->extensions, nid, crit, idx);
}
/* crypto/ts/ts_resp_print.c */
/*
 * Written by Zoltan Glozik (zglozik@stones.com) for the OpenSSL project
 * 2002.
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
// #include "objects.h"
// #include "bn.h"
// #include "x509v3.h"
// #include "ts.h"

struct status_map_st {
    int bit;
    const char *text;
};

/* Local function declarations. */

static int TS_status_map_print(BIO *bio, struct status_map_st *a,
                               ASN1_BIT_STRING *v);
static int TS_ACCURACY_print_bio(BIO *bio, const TS_ACCURACY *accuracy);

/* Function definitions. */

int TS_RESP_print_bio(BIO *bio, TS_RESP *a)
{
    TS_TST_INFO *tst_info;

    BIO_printf(bio, "Status info:\n");
    TS_STATUS_INFO_print_bio(bio, TS_RESP_get_status_info(a));

    BIO_printf(bio, "\nTST info:\n");
    tst_info = TS_RESP_get_tst_info(a);
    if (tst_info != NULL)
        TS_TST_INFO_print_bio(bio, TS_RESP_get_tst_info(a));
    else
        BIO_printf(bio, "Not included.\n");

    return 1;
}

int TS_STATUS_INFO_print_bio(BIO *bio, TS_STATUS_INFO *a)
{
    static const char *status_map[] = {
        "Granted.",
        "Granted with modifications.",
        "Rejected.",
        "Waiting.",
        "Revocation warning.",
        "Revoked."
    };
    static struct status_map_st failure_map[] = {
        {TS_INFO_BAD_ALG,
         "unrecognized or unsupported algorithm identifier"},
        {TS_INFO_BAD_REQUEST,
         "transaction not permitted or supported"},
        {TS_INFO_BAD_DATA_FORMAT,
         "the data submitted has the wrong format"},
        {TS_INFO_TIME_NOT_AVAILABLE,
         "the TSA's time source is not available"},
        {TS_INFO_UNACCEPTED_POLICY,
         "the requested TSA policy is not supported by the TSA"},
        {TS_INFO_UNACCEPTED_EXTENSION,
         "the requested extension is not supported by the TSA"},
        {TS_INFO_ADD_INFO_NOT_AVAILABLE,
         "the additional information requested could not be understood "
         "or is not available"},
        {TS_INFO_SYSTEM_FAILURE,
         "the request cannot be handled due to system failure"},
        {-1, NULL}
    };
    long status;
    int i, lines = 0;

    /* Printing status code. */
    BIO_printf(bio, "Status: ");
    status = ASN1_INTEGER_get(a->status);
    if (0 <= status
        && status < (long)(sizeof(status_map) / sizeof(status_map[0])))
        BIO_printf(bio, "%s\n", status_map[status]);
    else
        BIO_printf(bio, "out of bounds\n");

    /* Printing status description. */
    BIO_printf(bio, "Status description: ");
    for (i = 0; i < sk_ASN1_UTF8STRING_num(a->text); ++i) {
        if (i > 0)
            BIO_puts(bio, "\t");
        ASN1_STRING_print_ex(bio, sk_ASN1_UTF8STRING_value(a->text, i), 0);
        BIO_puts(bio, "\n");
    }
    if (i == 0)
        BIO_printf(bio, "unspecified\n");

    /* Printing failure information. */
    BIO_printf(bio, "Failure info: ");
    if (a->failure_info != NULL)
        lines = TS_status_map_print(bio, failure_map, a->failure_info);
    if (lines == 0)
        BIO_printf(bio, "unspecified");
    BIO_printf(bio, "\n");

    return 1;
}

static int TS_status_map_print(BIO *bio, struct status_map_st *a,
                               ASN1_BIT_STRING *v)
{
    int lines = 0;

    for (; a->bit >= 0; ++a) {
        if (ASN1_BIT_STRING_get_bit(v, a->bit)) {
            if (++lines > 1)
                BIO_printf(bio, ", ");
            BIO_printf(bio, "%s", a->text);
        }
    }

    return lines;
}

int TS_TST_INFO_print_bio(BIO *bio, TS_TST_INFO *a)
{
    int v;
    ASN1_OBJECT *policy_id;
    const ASN1_INTEGER *serial;
    const ASN1_GENERALIZEDTIME *gtime;
    TS_ACCURACY *accuracy;
    const ASN1_INTEGER *nonce;
    GENERAL_NAME *tsa_name;

    if (a == NULL)
        return 0;

    /* Print version. */
    v = TS_TST_INFO_get_version(a);
    BIO_printf(bio, "Version: %d\n", v);

    /* Print policy id. */
    BIO_printf(bio, "Policy OID: ");
    policy_id = TS_TST_INFO_get_policy_id(a);
    TS_OBJ_print_bio(bio, policy_id);

    /* Print message imprint. */
    TS_MSG_IMPRINT_print_bio(bio, TS_TST_INFO_get_msg_imprint(a));

    /* Print serial number. */
    BIO_printf(bio, "Serial number: ");
    serial = TS_TST_INFO_get_serial(a);
    if (serial == NULL)
        BIO_printf(bio, "unspecified");
    else
        TS_ASN1_INTEGER_print_bio(bio, serial);
    BIO_write(bio, "\n", 1);

    /* Print time stamp. */
    BIO_printf(bio, "Time stamp: ");
    gtime = TS_TST_INFO_get_time(a);
    ASN1_GENERALIZEDTIME_print(bio, gtime);
    BIO_write(bio, "\n", 1);

    /* Print accuracy. */
    BIO_printf(bio, "Accuracy: ");
    accuracy = TS_TST_INFO_get_accuracy(a);
    if (accuracy == NULL)
        BIO_printf(bio, "unspecified");
    else
        TS_ACCURACY_print_bio(bio, accuracy);
    BIO_write(bio, "\n", 1);

    /* Print ordering. */
    BIO_printf(bio, "Ordering: %s\n",
               TS_TST_INFO_get_ordering(a) ? "yes" : "no");

    /* Print nonce. */
    BIO_printf(bio, "Nonce: ");
    nonce = TS_TST_INFO_get_nonce(a);
    if (nonce == NULL)
        BIO_printf(bio, "unspecified");
    else
        TS_ASN1_INTEGER_print_bio(bio, nonce);
    BIO_write(bio, "\n", 1);

    /* Print TSA name. */
    BIO_printf(bio, "TSA: ");
    tsa_name = TS_TST_INFO_get_tsa(a);
    if (tsa_name == NULL)
        BIO_printf(bio, "unspecified");
    else {
        STACK_OF(CONF_VALUE) *nval;
        if ((nval = i2v_GENERAL_NAME(NULL, tsa_name, NULL)))
            X509V3_EXT_val_prn(bio, nval, 0, 0);
        sk_CONF_VALUE_pop_free(nval, X509V3_conf_free);
    }
    BIO_write(bio, "\n", 1);

    /* Print extensions. */
    TS_ext_print_bio(bio, TS_TST_INFO_get_exts(a));

    return 1;
}

static int TS_ACCURACY_print_bio(BIO *bio, const TS_ACCURACY *accuracy)
{
    const ASN1_INTEGER *seconds = TS_ACCURACY_get_seconds(accuracy);
    const ASN1_INTEGER *millis = TS_ACCURACY_get_millis(accuracy);
    const ASN1_INTEGER *micros = TS_ACCURACY_get_micros(accuracy);

    if (seconds != NULL)
        TS_ASN1_INTEGER_print_bio(bio, seconds);
    else
        BIO_printf(bio, "unspecified");
    BIO_printf(bio, " seconds, ");
    if (millis != NULL)
        TS_ASN1_INTEGER_print_bio(bio, millis);
    else
        BIO_printf(bio, "unspecified");
    BIO_printf(bio, " millis, ");
    if (micros != NULL)
        TS_ASN1_INTEGER_print_bio(bio, micros);
    else
        BIO_printf(bio, "unspecified");
    BIO_printf(bio, " micros");

    return 1;
}
/* crypto/ts/ts_resp_sign.c */
/*
 * Written by Zoltan Glozik (zglozik@stones.com) for the OpenSSL project
 * 2002.
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

// #include "cryptlib.h"
#include "o_time.h"

#if defined(OPENSSL_SYS_UNIX)
# include <sys/time.h>
#endif

// #include "objects.h"
// #include "ts.h"
#include "pkcs7.h"

/* Private function declarations. */

static ASN1_INTEGER *def_serial_cb(struct TS_resp_ctx *, void *);
static int def_time_cb(struct TS_resp_ctx *, void *, long *sec, long *usec);
static int def_extension_cb(struct TS_resp_ctx *, X509_EXTENSION *, void *);

static void TS_RESP_CTX_init(TS_RESP_CTX *ctx);
static void TS_RESP_CTX_cleanup(TS_RESP_CTX *ctx);
static int TS_RESP_check_request(TS_RESP_CTX *ctx);
static ASN1_OBJECT *TS_RESP_get_policy(TS_RESP_CTX *ctx);
static TS_TST_INFO *TS_RESP_create_tst_info(TS_RESP_CTX *ctx,
                                            ASN1_OBJECT *policy);
static int TS_RESP_process_extensions(TS_RESP_CTX *ctx);
static int TS_RESP_sign(TS_RESP_CTX *ctx);

static ESS_SIGNING_CERT *ESS_SIGNING_CERT_new_init(X509 *signcert,
                                                   STACK_OF(X509) *certs);
static ESS_CERT_ID *ESS_CERT_ID_new_init(X509 *cert, int issuer_needed);
static int TS_TST_INFO_content_new(PKCS7 *p7);
static int ESS_add_signing_cert(PKCS7_SIGNER_INFO *si, ESS_SIGNING_CERT *sc);

static ASN1_GENERALIZEDTIME
*TS_RESP_set_genTime_with_precision(ASN1_GENERALIZEDTIME *, long, long,
                                    unsigned);

/* Default callbacks for response generation. */

static ASN1_INTEGER *def_serial_cb(struct TS_resp_ctx *ctx, void *data)
{
    ASN1_INTEGER *serial = ASN1_INTEGER_new();
    if (!serial)
        goto err;
    if (!ASN1_INTEGER_set(serial, 1))
        goto err;
    return serial;
 err:
    TSerr(TS_F_DEF_SERIAL_CB, ERR_R_MALLOC_FAILURE);
    TS_RESP_CTX_set_status_info(ctx, TS_STATUS_REJECTION,
                                "Error during serial number generation.");
    return NULL;
}

#if defined(OPENSSL_SYS_UNIX)

/* Use the gettimeofday function call. */
static int def_time_cb(struct TS_resp_ctx *ctx, void *data,
                       long *sec, long *usec)
{
    struct timeval tv;
    if (gettimeofday(&tv, NULL) != 0) {
        TSerr(TS_F_DEF_TIME_CB, TS_R_TIME_SYSCALL_ERROR);
        TS_RESP_CTX_set_status_info(ctx, TS_STATUS_REJECTION,
                                    "Time is not available.");
        TS_RESP_CTX_add_failure_info(ctx, TS_INFO_TIME_NOT_AVAILABLE);
        return 0;
    }
    /* Return time to caller. */
    *sec = tv.tv_sec;
    *usec = tv.tv_usec;

    return 1;
}

#else

/* Use the time function call that provides only seconds precision. */
static int def_time_cb(struct TS_resp_ctx *ctx, void *data,
                       long *sec, long *usec)
{
    time_t t;
    if (time(&t) == (time_t)-1) {
        TSerr(TS_F_DEF_TIME_CB, TS_R_TIME_SYSCALL_ERROR);
        TS_RESP_CTX_set_status_info(ctx, TS_STATUS_REJECTION,
                                    "Time is not available.");
        TS_RESP_CTX_add_failure_info(ctx, TS_INFO_TIME_NOT_AVAILABLE);
        return 0;
    }
    /* Return time to caller, only second precision. */
    *sec = (long)t;
    *usec = 0;

    return 1;
}

#endif

static int def_extension_cb(struct TS_resp_ctx *ctx, X509_EXTENSION *ext,
                            void *data)
{
    /* No extensions are processed here. */
    TS_RESP_CTX_set_status_info(ctx, TS_STATUS_REJECTION,
                                "Unsupported extension.");
    TS_RESP_CTX_add_failure_info(ctx, TS_INFO_UNACCEPTED_EXTENSION);
    return 0;
}

/* TS_RESP_CTX management functions. */

TS_RESP_CTX *TS_RESP_CTX_new()
{
    TS_RESP_CTX *ctx;

    if (!(ctx = (TS_RESP_CTX *)OPENSSL_malloc(sizeof(TS_RESP_CTX)))) {
        TSerr(TS_F_TS_RESP_CTX_NEW, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    memset(ctx, 0, sizeof(TS_RESP_CTX));

    /* Setting default callbacks. */
    ctx->serial_cb = def_serial_cb;
    ctx->time_cb = def_time_cb;
    ctx->extension_cb = def_extension_cb;

    return ctx;
}

void TS_RESP_CTX_free(TS_RESP_CTX *ctx)
{
    if (!ctx)
        return;

    X509_free(ctx->signer_cert);
    EVP_PKEY_free(ctx->signer_key);
    sk_X509_pop_free(ctx->certs, X509_free);
    sk_ASN1_OBJECT_pop_free(ctx->policies, ASN1_OBJECT_free);
    ASN1_OBJECT_free(ctx->default_policy);
    sk_EVP_MD_free(ctx->mds);   /* No EVP_MD_free method exists. */
    ASN1_INTEGER_free(ctx->seconds);
    ASN1_INTEGER_free(ctx->millis);
    ASN1_INTEGER_free(ctx->micros);
    OPENSSL_free(ctx);
}

int TS_RESP_CTX_set_signer_cert(TS_RESP_CTX *ctx, X509 *signer)
{
    if (X509_check_purpose(signer, X509_PURPOSE_TIMESTAMP_SIGN, 0) != 1) {
        TSerr(TS_F_TS_RESP_CTX_SET_SIGNER_CERT,
              TS_R_INVALID_SIGNER_CERTIFICATE_PURPOSE);
        return 0;
    }
    if (ctx->signer_cert)
        X509_free(ctx->signer_cert);
    ctx->signer_cert = signer;
    CRYPTO_add(&ctx->signer_cert->references, +1, CRYPTO_LOCK_X509);
    return 1;
}

int TS_RESP_CTX_set_signer_key(TS_RESP_CTX *ctx, EVP_PKEY *key)
{
    if (ctx->signer_key)
        EVP_PKEY_free(ctx->signer_key);
    ctx->signer_key = key;
    CRYPTO_add(&ctx->signer_key->references, +1, CRYPTO_LOCK_EVP_PKEY);

    return 1;
}

int TS_RESP_CTX_set_def_policy(TS_RESP_CTX *ctx, ASN1_OBJECT *def_policy)
{
    if (ctx->default_policy)
        ASN1_OBJECT_free(ctx->default_policy);
    if (!(ctx->default_policy = OBJ_dup(def_policy)))
        goto err;
    return 1;
 err:
    TSerr(TS_F_TS_RESP_CTX_SET_DEF_POLICY, ERR_R_MALLOC_FAILURE);
    return 0;
}

int TS_RESP_CTX_set_certs(TS_RESP_CTX *ctx, STACK_OF(X509) *certs)
{

    if (ctx->certs) {
        sk_X509_pop_free(ctx->certs, X509_free);
        ctx->certs = NULL;
    }
    if (!certs)
        return 1;
    if (!(ctx->certs = X509_chain_up_ref(certs))) {
        TSerr(TS_F_TS_RESP_CTX_SET_CERTS, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    return 1;
}

int TS_RESP_CTX_add_policy(TS_RESP_CTX *ctx, ASN1_OBJECT *policy)
{
    ASN1_OBJECT *copy = NULL;

    /* Create new policy stack if necessary. */
    if (!ctx->policies && !(ctx->policies = sk_ASN1_OBJECT_new_null()))
        goto err;
    if (!(copy = OBJ_dup(policy)))
        goto err;
    if (!sk_ASN1_OBJECT_push(ctx->policies, copy))
        goto err;

    return 1;
 err:
    TSerr(TS_F_TS_RESP_CTX_ADD_POLICY, ERR_R_MALLOC_FAILURE);
    ASN1_OBJECT_free(copy);
    return 0;
}

int TS_RESP_CTX_add_md(TS_RESP_CTX *ctx, const EVP_MD *md)
{
    /* Create new md stack if necessary. */
    if (!ctx->mds && !(ctx->mds = sk_EVP_MD_new_null()))
        goto err;
    /* Add the shared md, no copy needed. */
    if (!sk_EVP_MD_push(ctx->mds, (EVP_MD *)md))
        goto err;

    return 1;
 err:
    TSerr(TS_F_TS_RESP_CTX_ADD_MD, ERR_R_MALLOC_FAILURE);
    return 0;
}

#define TS_RESP_CTX_accuracy_free(ctx)          \
        ASN1_INTEGER_free(ctx->seconds);        \
        ctx->seconds = NULL;                    \
        ASN1_INTEGER_free(ctx->millis);         \
        ctx->millis = NULL;                     \
        ASN1_INTEGER_free(ctx->micros);         \
        ctx->micros = NULL;

int TS_RESP_CTX_set_accuracy(TS_RESP_CTX *ctx,
                             int secs, int millis, int micros)
{

    TS_RESP_CTX_accuracy_free(ctx);
    if (secs && (!(ctx->seconds = ASN1_INTEGER_new())
                 || !ASN1_INTEGER_set(ctx->seconds, secs)))
        goto err;
    if (millis && (!(ctx->millis = ASN1_INTEGER_new())
                   || !ASN1_INTEGER_set(ctx->millis, millis)))
        goto err;
    if (micros && (!(ctx->micros = ASN1_INTEGER_new())
                   || !ASN1_INTEGER_set(ctx->micros, micros)))
        goto err;

    return 1;
 err:
    TS_RESP_CTX_accuracy_free(ctx);
    TSerr(TS_F_TS_RESP_CTX_SET_ACCURACY, ERR_R_MALLOC_FAILURE);
    return 0;
}

void TS_RESP_CTX_add_flags(TS_RESP_CTX *ctx, int flags)
{
    ctx->flags |= flags;
}

void TS_RESP_CTX_set_serial_cb(TS_RESP_CTX *ctx, TS_serial_cb cb, void *data)
{
    ctx->serial_cb = cb;
    ctx->serial_cb_data = data;
}

void TS_RESP_CTX_set_time_cb(TS_RESP_CTX *ctx, TS_time_cb cb, void *data)
{
    ctx->time_cb = cb;
    ctx->time_cb_data = data;
}

void TS_RESP_CTX_set_extension_cb(TS_RESP_CTX *ctx,
                                  TS_extension_cb cb, void *data)
{
    ctx->extension_cb = cb;
    ctx->extension_cb_data = data;
}

int TS_RESP_CTX_set_status_info(TS_RESP_CTX *ctx,
                                int status, const char *text)
{
    TS_STATUS_INFO *si = NULL;
    ASN1_UTF8STRING *utf8_text = NULL;
    int ret = 0;

    if (!(si = TS_STATUS_INFO_new()))
        goto err;
    if (!ASN1_INTEGER_set(si->status, status))
        goto err;
    if (text) {
        if (!(utf8_text = ASN1_UTF8STRING_new())
            || !ASN1_STRING_set(utf8_text, text, strlen(text)))
            goto err;
        if (!si->text && !(si->text = sk_ASN1_UTF8STRING_new_null()))
            goto err;
        if (!sk_ASN1_UTF8STRING_push(si->text, utf8_text))
            goto err;
        utf8_text = NULL;       /* Ownership is lost. */
    }
    if (!TS_RESP_set_status_info(ctx->response, si))
        goto err;
    ret = 1;
 err:
    if (!ret)
        TSerr(TS_F_TS_RESP_CTX_SET_STATUS_INFO, ERR_R_MALLOC_FAILURE);
    TS_STATUS_INFO_free(si);
    ASN1_UTF8STRING_free(utf8_text);
    return ret;
}

int TS_RESP_CTX_set_status_info_cond(TS_RESP_CTX *ctx,
                                     int status, const char *text)
{
    int ret = 1;
    TS_STATUS_INFO *si = TS_RESP_get_status_info(ctx->response);

    if (ASN1_INTEGER_get(si->status) == TS_STATUS_GRANTED) {
        /* Status has not been set, set it now. */
        ret = TS_RESP_CTX_set_status_info(ctx, status, text);
    }
    return ret;
}

int TS_RESP_CTX_add_failure_info(TS_RESP_CTX *ctx, int failure)
{
    TS_STATUS_INFO *si = TS_RESP_get_status_info(ctx->response);
    if (!si->failure_info && !(si->failure_info = ASN1_BIT_STRING_new()))
        goto err;
    if (!ASN1_BIT_STRING_set_bit(si->failure_info, failure, 1))
        goto err;
    return 1;
 err:
    TSerr(TS_F_TS_RESP_CTX_ADD_FAILURE_INFO, ERR_R_MALLOC_FAILURE);
    return 0;
}

TS_REQ *TS_RESP_CTX_get_request(TS_RESP_CTX *ctx)
{
    return ctx->request;
}

TS_TST_INFO *TS_RESP_CTX_get_tst_info(TS_RESP_CTX *ctx)
{
    return ctx->tst_info;
}

int TS_RESP_CTX_set_clock_precision_digits(TS_RESP_CTX *ctx,
                                           unsigned precision)
{
    if (precision > TS_MAX_CLOCK_PRECISION_DIGITS)
        return 0;
    ctx->clock_precision_digits = precision;
    return 1;
}

/* Main entry method of the response generation. */
TS_RESP *TS_RESP_create_response(TS_RESP_CTX *ctx, BIO *req_bio)
{
    ASN1_OBJECT *policy;
    TS_RESP *response;
    int result = 0;

    TS_RESP_CTX_init(ctx);

    /* Creating the response object. */
    if (!(ctx->response = TS_RESP_new())) {
        TSerr(TS_F_TS_RESP_CREATE_RESPONSE, ERR_R_MALLOC_FAILURE);
        goto end;
    }

    /* Parsing DER request. */
    if (!(ctx->request = d2i_TS_REQ_bio(req_bio, NULL))) {
        TS_RESP_CTX_set_status_info(ctx, TS_STATUS_REJECTION,
                                    "Bad request format or " "system error.");
        TS_RESP_CTX_add_failure_info(ctx, TS_INFO_BAD_DATA_FORMAT);
        goto end;
    }

    /* Setting default status info. */
    if (!TS_RESP_CTX_set_status_info(ctx, TS_STATUS_GRANTED, NULL))
        goto end;

    /* Checking the request format. */
    if (!TS_RESP_check_request(ctx))
        goto end;

    /* Checking acceptable policies. */
    if (!(policy = TS_RESP_get_policy(ctx)))
        goto end;

    /* Creating the TS_TST_INFO object. */
    if (!(ctx->tst_info = TS_RESP_create_tst_info(ctx, policy)))
        goto end;

    /* Processing extensions. */
    if (!TS_RESP_process_extensions(ctx))
        goto end;

    /* Generating the signature. */
    if (!TS_RESP_sign(ctx))
        goto end;

    /* Everything was successful. */
    result = 1;
 end:
    if (!result) {
        TSerr(TS_F_TS_RESP_CREATE_RESPONSE, TS_R_RESPONSE_SETUP_ERROR);
        if (ctx->response != NULL) {
            if (TS_RESP_CTX_set_status_info_cond(ctx,
                                                 TS_STATUS_REJECTION,
                                                 "Error during response "
                                                 "generation.") == 0) {
                TS_RESP_free(ctx->response);
                ctx->response = NULL;
            }
        }
    }
    response = ctx->response;
    ctx->response = NULL;       /* Ownership will be returned to caller. */
    TS_RESP_CTX_cleanup(ctx);
    return response;
}

/* Initializes the variable part of the context. */
static void TS_RESP_CTX_init(TS_RESP_CTX *ctx)
{
    ctx->request = NULL;
    ctx->response = NULL;
    ctx->tst_info = NULL;
}

/* Cleans up the variable part of the context. */
static void TS_RESP_CTX_cleanup(TS_RESP_CTX *ctx)
{
    TS_REQ_free(ctx->request);
    ctx->request = NULL;
    TS_RESP_free(ctx->response);
    ctx->response = NULL;
    TS_TST_INFO_free(ctx->tst_info);
    ctx->tst_info = NULL;
}

/* Checks the format and content of the request. */
static int TS_RESP_check_request(TS_RESP_CTX *ctx)
{
    TS_REQ *request = ctx->request;
    TS_MSG_IMPRINT *msg_imprint;
    X509_ALGOR *md_alg;
    int md_alg_id;
    const ASN1_OCTET_STRING *digest;
    EVP_MD *md = NULL;
    int i;

    /* Checking request version. */
    if (TS_REQ_get_version(request) != 1) {
        TS_RESP_CTX_set_status_info(ctx, TS_STATUS_REJECTION,
                                    "Bad request version.");
        TS_RESP_CTX_add_failure_info(ctx, TS_INFO_BAD_REQUEST);
        return 0;
    }

    /* Checking message digest algorithm. */
    msg_imprint = TS_REQ_get_msg_imprint(request);
    md_alg = TS_MSG_IMPRINT_get_algo(msg_imprint);
    md_alg_id = OBJ_obj2nid(md_alg->algorithm);
    for (i = 0; !md && i < sk_EVP_MD_num(ctx->mds); ++i) {
        EVP_MD *current_md = sk_EVP_MD_value(ctx->mds, i);
        if (md_alg_id == EVP_MD_type(current_md))
            md = current_md;
    }
    if (!md) {
        TS_RESP_CTX_set_status_info(ctx, TS_STATUS_REJECTION,
                                    "Message digest algorithm is "
                                    "not supported.");
        TS_RESP_CTX_add_failure_info(ctx, TS_INFO_BAD_ALG);
        return 0;
    }

    /* No message digest takes parameter. */
    if (md_alg->parameter && ASN1_TYPE_get(md_alg->parameter) != V_ASN1_NULL) {
        TS_RESP_CTX_set_status_info(ctx, TS_STATUS_REJECTION,
                                    "Superfluous message digest "
                                    "parameter.");
        TS_RESP_CTX_add_failure_info(ctx, TS_INFO_BAD_ALG);
        return 0;
    }
    /* Checking message digest size. */
    digest = TS_MSG_IMPRINT_get_msg(msg_imprint);
    if (digest->length != EVP_MD_size(md)) {
        TS_RESP_CTX_set_status_info(ctx, TS_STATUS_REJECTION,
                                    "Bad message digest.");
        TS_RESP_CTX_add_failure_info(ctx, TS_INFO_BAD_DATA_FORMAT);
        return 0;
    }

    return 1;
}

/* Returns the TSA policy based on the requested and acceptable policies. */
static ASN1_OBJECT *TS_RESP_get_policy(TS_RESP_CTX *ctx)
{
    ASN1_OBJECT *requested = TS_REQ_get_policy_id(ctx->request);
    ASN1_OBJECT *policy = NULL;
    int i;

    if (ctx->default_policy == NULL) {
        TSerr(TS_F_TS_RESP_GET_POLICY, TS_R_INVALID_NULL_POINTER);
        return NULL;
    }
    /*
     * Return the default policy if none is requested or the default is
     * requested.
     */
    if (!requested || !OBJ_cmp(requested, ctx->default_policy))
        policy = ctx->default_policy;

    /* Check if the policy is acceptable. */
    for (i = 0; !policy && i < sk_ASN1_OBJECT_num(ctx->policies); ++i) {
        ASN1_OBJECT *current = sk_ASN1_OBJECT_value(ctx->policies, i);
        if (!OBJ_cmp(requested, current))
            policy = current;
    }
    if (!policy) {
        TSerr(TS_F_TS_RESP_GET_POLICY, TS_R_UNACCEPTABLE_POLICY);
        TS_RESP_CTX_set_status_info(ctx, TS_STATUS_REJECTION,
                                    "Requested policy is not " "supported.");
        TS_RESP_CTX_add_failure_info(ctx, TS_INFO_UNACCEPTED_POLICY);
    }
    return policy;
}

/* Creates the TS_TST_INFO object based on the settings of the context. */
static TS_TST_INFO *TS_RESP_create_tst_info(TS_RESP_CTX *ctx,
                                            ASN1_OBJECT *policy)
{
    int result = 0;
    TS_TST_INFO *tst_info = NULL;
    ASN1_INTEGER *serial = NULL;
    ASN1_GENERALIZEDTIME *asn1_time = NULL;
    long sec, usec;
    TS_ACCURACY *accuracy = NULL;
    const ASN1_INTEGER *nonce;
    GENERAL_NAME *tsa_name = NULL;

    if (!(tst_info = TS_TST_INFO_new()))
        goto end;
    if (!TS_TST_INFO_set_version(tst_info, 1))
        goto end;
    if (!TS_TST_INFO_set_policy_id(tst_info, policy))
        goto end;
    if (!TS_TST_INFO_set_msg_imprint(tst_info, ctx->request->msg_imprint))
        goto end;
    if (!(serial = (*ctx->serial_cb) (ctx, ctx->serial_cb_data))
        || !TS_TST_INFO_set_serial(tst_info, serial))
        goto end;
    if (!(*ctx->time_cb) (ctx, ctx->time_cb_data, &sec, &usec)
        || !(asn1_time = TS_RESP_set_genTime_with_precision(NULL,
                                                            sec, usec,
                                                            ctx->clock_precision_digits))
        || !TS_TST_INFO_set_time(tst_info, asn1_time))
        goto end;

    /* Setting accuracy if needed. */
    if ((ctx->seconds || ctx->millis || ctx->micros)
        && !(accuracy = TS_ACCURACY_new()))
        goto end;

    if (ctx->seconds && !TS_ACCURACY_set_seconds(accuracy, ctx->seconds))
        goto end;
    if (ctx->millis && !TS_ACCURACY_set_millis(accuracy, ctx->millis))
        goto end;
    if (ctx->micros && !TS_ACCURACY_set_micros(accuracy, ctx->micros))
        goto end;
    if (accuracy && !TS_TST_INFO_set_accuracy(tst_info, accuracy))
        goto end;

    /* Setting ordering. */
    if ((ctx->flags & TS_ORDERING)
        && !TS_TST_INFO_set_ordering(tst_info, 1))
        goto end;

    /* Setting nonce if needed. */
    if ((nonce = TS_REQ_get_nonce(ctx->request)) != NULL
        && !TS_TST_INFO_set_nonce(tst_info, nonce))
        goto end;

    /* Setting TSA name to subject of signer certificate. */
    if (ctx->flags & TS_TSA_NAME) {
        if (!(tsa_name = GENERAL_NAME_new()))
            goto end;
        tsa_name->type = GEN_DIRNAME;
        tsa_name->d.dirn =
            X509_NAME_dup(ctx->signer_cert->cert_info->subject);
        if (!tsa_name->d.dirn)
            goto end;
        if (!TS_TST_INFO_set_tsa(tst_info, tsa_name))
            goto end;
    }

    result = 1;
 end:
    if (!result) {
        TS_TST_INFO_free(tst_info);
        tst_info = NULL;
        TSerr(TS_F_TS_RESP_CREATE_TST_INFO, TS_R_TST_INFO_SETUP_ERROR);
        TS_RESP_CTX_set_status_info_cond(ctx, TS_STATUS_REJECTION,
                                         "Error during TSTInfo "
                                         "generation.");
    }
    GENERAL_NAME_free(tsa_name);
    TS_ACCURACY_free(accuracy);
    ASN1_GENERALIZEDTIME_free(asn1_time);
    ASN1_INTEGER_free(serial);

    return tst_info;
}

/* Processing the extensions of the request. */
static int TS_RESP_process_extensions(TS_RESP_CTX *ctx)
{
    STACK_OF(X509_EXTENSION) *exts = TS_REQ_get_exts(ctx->request);
    int i;
    int ok = 1;

    for (i = 0; ok && i < sk_X509_EXTENSION_num(exts); ++i) {
        X509_EXTENSION *ext = sk_X509_EXTENSION_value(exts, i);
        /*
         * XXXXX The last argument was previously (void *)ctx->extension_cb,
         * but ISO C doesn't permit converting a function pointer to void *.
         * For lack of better information, I'm placing a NULL there instead.
         * The callback can pick its own address out from the ctx anyway...
         */
        ok = (*ctx->extension_cb) (ctx, ext, NULL);
    }

    return ok;
}

/* Functions for signing the TS_TST_INFO structure of the context. */
static int TS_RESP_sign(TS_RESP_CTX *ctx)
{
    int ret = 0;
    PKCS7 *p7 = NULL;
    PKCS7_SIGNER_INFO *si;
    STACK_OF(X509) *certs;      /* Certificates to include in sc. */
    ESS_SIGNING_CERT *sc = NULL;
    ASN1_OBJECT *oid;
    BIO *p7bio = NULL;
    int i;

    /* Check if signcert and pkey match. */
    if (!X509_check_private_key(ctx->signer_cert, ctx->signer_key)) {
        TSerr(TS_F_TS_RESP_SIGN, TS_R_PRIVATE_KEY_DOES_NOT_MATCH_CERTIFICATE);
        goto err;
    }

    /* Create a new PKCS7 signed object. */
    if (!(p7 = PKCS7_new())) {
        TSerr(TS_F_TS_RESP_SIGN, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    if (!PKCS7_set_type(p7, NID_pkcs7_signed))
        goto err;

    /* Force SignedData version to be 3 instead of the default 1. */
    if (!ASN1_INTEGER_set(p7->d.sign->version, 3))
        goto err;

    /* Add signer certificate and optional certificate chain. */
    if (TS_REQ_get_cert_req(ctx->request)) {
        PKCS7_add_certificate(p7, ctx->signer_cert);
        if (ctx->certs) {
            for (i = 0; i < sk_X509_num(ctx->certs); ++i) {
                X509 *cert = sk_X509_value(ctx->certs, i);
                PKCS7_add_certificate(p7, cert);
            }
        }
    }

    /* Add a new signer info. */
    if (!(si = PKCS7_add_signature(p7, ctx->signer_cert,
                                   ctx->signer_key, EVP_sha1()))) {
        TSerr(TS_F_TS_RESP_SIGN, TS_R_PKCS7_ADD_SIGNATURE_ERROR);
        goto err;
    }

    /* Add content type signed attribute to the signer info. */
    oid = OBJ_nid2obj(NID_id_smime_ct_TSTInfo);
    if (!PKCS7_add_signed_attribute(si, NID_pkcs9_contentType,
                                    V_ASN1_OBJECT, oid)) {
        TSerr(TS_F_TS_RESP_SIGN, TS_R_PKCS7_ADD_SIGNED_ATTR_ERROR);
        goto err;
    }

    /*
     * Create the ESS SigningCertificate attribute which contains the signer
     * certificate id and optionally the certificate chain.
     */
    certs = ctx->flags & TS_ESS_CERT_ID_CHAIN ? ctx->certs : NULL;
    if (!(sc = ESS_SIGNING_CERT_new_init(ctx->signer_cert, certs)))
        goto err;

    /* Add SigningCertificate signed attribute to the signer info. */
    if (!ESS_add_signing_cert(si, sc)) {
        TSerr(TS_F_TS_RESP_SIGN, TS_R_ESS_ADD_SIGNING_CERT_ERROR);
        goto err;
    }

    /* Add a new empty NID_id_smime_ct_TSTInfo encapsulated content. */
    if (!TS_TST_INFO_content_new(p7))
        goto err;

    /* Add the DER encoded tst_info to the PKCS7 structure. */
    if (!(p7bio = PKCS7_dataInit(p7, NULL))) {
        TSerr(TS_F_TS_RESP_SIGN, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    /* Convert tst_info to DER. */
    if (!i2d_TS_TST_INFO_bio(p7bio, ctx->tst_info)) {
        TSerr(TS_F_TS_RESP_SIGN, TS_R_TS_DATASIGN);
        goto err;
    }

    /* Create the signature and add it to the signer info. */
    if (!PKCS7_dataFinal(p7, p7bio)) {
        TSerr(TS_F_TS_RESP_SIGN, TS_R_TS_DATASIGN);
        goto err;
    }

    /* Set new PKCS7 and TST_INFO objects. */
    TS_RESP_set_tst_info(ctx->response, p7, ctx->tst_info);
    p7 = NULL;                  /* Ownership is lost. */
    ctx->tst_info = NULL;       /* Ownership is lost. */

    ret = 1;
 err:
    if (!ret)
        TS_RESP_CTX_set_status_info_cond(ctx, TS_STATUS_REJECTION,
                                         "Error during signature "
                                         "generation.");
    BIO_free_all(p7bio);
    ESS_SIGNING_CERT_free(sc);
    PKCS7_free(p7);
    return ret;
}

static ESS_SIGNING_CERT *ESS_SIGNING_CERT_new_init(X509 *signcert,
                                                   STACK_OF(X509) *certs)
{
    ESS_CERT_ID *cid;
    ESS_SIGNING_CERT *sc = NULL;
    int i;

    /* Creating the ESS_CERT_ID stack. */
    if (!(sc = ESS_SIGNING_CERT_new()))
        goto err;
    if (!sc->cert_ids && !(sc->cert_ids = sk_ESS_CERT_ID_new_null()))
        goto err;

    /* Adding the signing certificate id. */
    if (!(cid = ESS_CERT_ID_new_init(signcert, 0))
        || !sk_ESS_CERT_ID_push(sc->cert_ids, cid))
        goto err;
    /* Adding the certificate chain ids. */
    for (i = 0; i < sk_X509_num(certs); ++i) {
        X509 *cert = sk_X509_value(certs, i);
        if (!(cid = ESS_CERT_ID_new_init(cert, 1))
            || !sk_ESS_CERT_ID_push(sc->cert_ids, cid))
            goto err;
    }

    return sc;
 err:
    ESS_SIGNING_CERT_free(sc);
    TSerr(TS_F_ESS_SIGNING_CERT_NEW_INIT, ERR_R_MALLOC_FAILURE);
    return NULL;
}

static ESS_CERT_ID *ESS_CERT_ID_new_init(X509 *cert, int issuer_needed)
{
    ESS_CERT_ID *cid = NULL;
    GENERAL_NAME *name = NULL;

    /* Recompute SHA1 hash of certificate if necessary (side effect). */
    X509_check_purpose(cert, -1, 0);

    if (!(cid = ESS_CERT_ID_new()))
        goto err;
    if (!ASN1_OCTET_STRING_set(cid->hash, cert->sha1_hash,
                               sizeof(cert->sha1_hash)))
        goto err;

    /* Setting the issuer/serial if requested. */
    if (issuer_needed) {
        /* Creating issuer/serial structure. */
        if (!cid->issuer_serial
            && !(cid->issuer_serial = ESS_ISSUER_SERIAL_new()))
            goto err;
        /* Creating general name from the certificate issuer. */
        if (!(name = GENERAL_NAME_new()))
            goto err;
        name->type = GEN_DIRNAME;
        if (!(name->d.dirn = X509_NAME_dup(cert->cert_info->issuer)))
            goto err;
        if (!sk_GENERAL_NAME_push(cid->issuer_serial->issuer, name))
            goto err;
        name = NULL;            /* Ownership is lost. */
        /* Setting the serial number. */
        ASN1_INTEGER_free(cid->issuer_serial->serial);
        if (!(cid->issuer_serial->serial =
              ASN1_INTEGER_dup(cert->cert_info->serialNumber)))
            goto err;
    }

    return cid;
 err:
    GENERAL_NAME_free(name);
    ESS_CERT_ID_free(cid);
    TSerr(TS_F_ESS_CERT_ID_NEW_INIT, ERR_R_MALLOC_FAILURE);
    return NULL;
}

static int TS_TST_INFO_content_new(PKCS7 *p7)
{
    PKCS7 *ret = NULL;
    ASN1_OCTET_STRING *octet_string = NULL;

    /* Create new encapsulated NID_id_smime_ct_TSTInfo content. */
    if (!(ret = PKCS7_new()))
        goto err;
    if (!(ret->d.other = ASN1_TYPE_new()))
        goto err;
    ret->type = OBJ_nid2obj(NID_id_smime_ct_TSTInfo);
    if (!(octet_string = ASN1_OCTET_STRING_new()))
        goto err;
    ASN1_TYPE_set(ret->d.other, V_ASN1_OCTET_STRING, octet_string);
    octet_string = NULL;

    /* Add encapsulated content to signed PKCS7 structure. */
    if (!PKCS7_set_content(p7, ret))
        goto err;

    return 1;
 err:
    ASN1_OCTET_STRING_free(octet_string);
    PKCS7_free(ret);
    return 0;
}

static int ESS_add_signing_cert(PKCS7_SIGNER_INFO *si, ESS_SIGNING_CERT *sc)
{
    ASN1_STRING *seq = NULL;
    unsigned char *p, *pp = NULL;
    int len;

    len = i2d_ESS_SIGNING_CERT(sc, NULL);
    if (!(pp = (unsigned char *)OPENSSL_malloc(len))) {
        TSerr(TS_F_ESS_ADD_SIGNING_CERT, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    p = pp;
    i2d_ESS_SIGNING_CERT(sc, &p);
    if (!(seq = ASN1_STRING_new()) || !ASN1_STRING_set(seq, pp, len)) {
        TSerr(TS_F_ESS_ADD_SIGNING_CERT, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    OPENSSL_free(pp);
    pp = NULL;
    return PKCS7_add_signed_attribute(si,
                                      NID_id_smime_aa_signingCertificate,
                                      V_ASN1_SEQUENCE, seq);
 err:
    ASN1_STRING_free(seq);
    OPENSSL_free(pp);

    return 0;
}

static ASN1_GENERALIZEDTIME
*TS_RESP_set_genTime_with_precision(ASN1_GENERALIZEDTIME *asn1_time,
                                    long sec, long usec, unsigned precision)
{
    time_t time_sec = (time_t)sec;
    struct tm *tm = NULL;
    struct tm result = {0};
    char genTime_str[17 + TS_MAX_CLOCK_PRECISION_DIGITS];
    char *p = genTime_str;
    char *p_end = genTime_str + sizeof(genTime_str);

    if (precision > TS_MAX_CLOCK_PRECISION_DIGITS)
        goto err;

    if (!(tm = OPENSSL_gmtime(&time_sec, &result)))
        goto err;

    /*
     * Put "genTime_str" in GeneralizedTime format.  We work around the
     * restrictions imposed by rfc3280 (i.e. "GeneralizedTime values MUST
     * NOT include fractional seconds") and OpenSSL related functions to
     * meet the rfc3161 requirement: "GeneralizedTime syntax can include
     * fraction-of-second details".
     */
    p += BIO_snprintf(p, p_end - p,
                      "%04d%02d%02d%02d%02d%02d",
                      tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
                      tm->tm_hour, tm->tm_min, tm->tm_sec);
    if (precision > 0) {
        /* Add fraction of seconds (leave space for dot and null). */
        BIO_snprintf(p, 2 + precision, ".%06ld", usec);
        /*
         * We cannot use the snprintf return value, because it might have
         * been truncated.
         */
        p += strlen(p);

        /*
         * To make things a bit harder, X.690 | ISO/IEC 8825-1 provides the
         * following restrictions for a DER-encoding, which OpenSSL
         * (specifically ASN1_GENERALIZEDTIME_check() function) doesn't
         * support: "The encoding MUST terminate with a "Z" (which means
         * "Zulu" time). The decimal point element, if present, MUST be the
         * point option ".". The fractional-seconds elements, if present,
         * MUST omit all trailing 0's; if the elements correspond to 0, they
         * MUST be wholly omitted, and the decimal point element also MUST be
         * omitted."
         */
        /*
         * Remove trailing zeros. The dot guarantees the exit condition of
         * this loop even if all the digits are zero.
         */
        while (*--p == '0')
            /*
             * empty
             */ ;
        /* p points to either the dot or the last non-zero digit. */
        if (*p != '.')
            ++p;
    }
    /* Add the trailing Z and the terminating null. */
    *p++ = 'Z';
    *p++ = '\0';

    /* Now call OpenSSL to check and set our genTime value */
    if (!asn1_time && !(asn1_time = M_ASN1_GENERALIZEDTIME_new()))
        goto err;
    if (!ASN1_GENERALIZEDTIME_set_string(asn1_time, genTime_str)) {
        ASN1_GENERALIZEDTIME_free(asn1_time);
        goto err;
    }

    return asn1_time;
 err:
    TSerr(TS_F_TS_RESP_SET_GENTIME_WITH_PRECISION, TS_R_COULD_NOT_SET_TIME);
    return NULL;
}
/* crypto/ts/ts_resp_utils.c */
/*
 * Written by Zoltan Glozik (zglozik@stones.com) for the OpenSSL project
 * 2002.
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
// #include "objects.h"
// #include "ts.h"
// #include "pkcs7.h"

/* Function definitions. */

int TS_RESP_set_status_info(TS_RESP *a, TS_STATUS_INFO *status_info)
{
    TS_STATUS_INFO *new_status_info;

    if (a->status_info == status_info)
        return 1;
    new_status_info = TS_STATUS_INFO_dup(status_info);
    if (new_status_info == NULL) {
        TSerr(TS_F_TS_RESP_SET_STATUS_INFO, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    TS_STATUS_INFO_free(a->status_info);
    a->status_info = new_status_info;

    return 1;
}

TS_STATUS_INFO *TS_RESP_get_status_info(TS_RESP *a)
{
    return a->status_info;
}

/* Caller loses ownership of PKCS7 and TS_TST_INFO objects. */
void TS_RESP_set_tst_info(TS_RESP *a, PKCS7 *p7, TS_TST_INFO *tst_info)
{
    /* Set new PKCS7 and TST_INFO objects. */
    PKCS7_free(a->token);
    a->token = p7;
    TS_TST_INFO_free(a->tst_info);
    a->tst_info = tst_info;
}

PKCS7 *TS_RESP_get_token(TS_RESP *a)
{
    return a->token;
}

TS_TST_INFO *TS_RESP_get_tst_info(TS_RESP *a)
{
    return a->tst_info;
}

int TS_TST_INFO_set_version(TS_TST_INFO *a, long version)
{
    return ASN1_INTEGER_set(a->version, version);
}

long TS_TST_INFO_get_version(const TS_TST_INFO *a)
{
    return ASN1_INTEGER_get(a->version);
}

int TS_TST_INFO_set_policy_id(TS_TST_INFO *a, ASN1_OBJECT *policy)
{
    ASN1_OBJECT *new_policy;

    if (a->policy_id == policy)
        return 1;
    new_policy = OBJ_dup(policy);
    if (new_policy == NULL) {
        TSerr(TS_F_TS_TST_INFO_SET_POLICY_ID, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    ASN1_OBJECT_free(a->policy_id);
    a->policy_id = new_policy;
    return 1;
}

ASN1_OBJECT *TS_TST_INFO_get_policy_id(TS_TST_INFO *a)
{
    return a->policy_id;
}

int TS_TST_INFO_set_msg_imprint(TS_TST_INFO *a, TS_MSG_IMPRINT *msg_imprint)
{
    TS_MSG_IMPRINT *new_msg_imprint;

    if (a->msg_imprint == msg_imprint)
        return 1;
    new_msg_imprint = TS_MSG_IMPRINT_dup(msg_imprint);
    if (new_msg_imprint == NULL) {
        TSerr(TS_F_TS_TST_INFO_SET_MSG_IMPRINT, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    TS_MSG_IMPRINT_free(a->msg_imprint);
    a->msg_imprint = new_msg_imprint;
    return 1;
}

TS_MSG_IMPRINT *TS_TST_INFO_get_msg_imprint(TS_TST_INFO *a)
{
    return a->msg_imprint;
}

int TS_TST_INFO_set_serial(TS_TST_INFO *a, const ASN1_INTEGER *serial)
{
    ASN1_INTEGER *new_serial;

    if (a->serial == serial)
        return 1;
    new_serial = ASN1_INTEGER_dup(serial);
    if (new_serial == NULL) {
        TSerr(TS_F_TS_TST_INFO_SET_SERIAL, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    ASN1_INTEGER_free(a->serial);
    a->serial = new_serial;
    return 1;
}

const ASN1_INTEGER *TS_TST_INFO_get_serial(const TS_TST_INFO *a)
{
    return a->serial;
}

int TS_TST_INFO_set_time(TS_TST_INFO *a, const ASN1_GENERALIZEDTIME *gtime)
{
    ASN1_GENERALIZEDTIME *new_time;

    if (a->time == gtime)
        return 1;
    new_time = M_ASN1_GENERALIZEDTIME_dup(gtime);
    if (new_time == NULL) {
        TSerr(TS_F_TS_TST_INFO_SET_TIME, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    ASN1_GENERALIZEDTIME_free(a->time);
    a->time = new_time;
    return 1;
}

const ASN1_GENERALIZEDTIME *TS_TST_INFO_get_time(const TS_TST_INFO *a)
{
    return a->time;
}

int TS_TST_INFO_set_accuracy(TS_TST_INFO *a, TS_ACCURACY *accuracy)
{
    TS_ACCURACY *new_accuracy;

    if (a->accuracy == accuracy)
        return 1;
    new_accuracy = TS_ACCURACY_dup(accuracy);
    if (new_accuracy == NULL) {
        TSerr(TS_F_TS_TST_INFO_SET_ACCURACY, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    TS_ACCURACY_free(a->accuracy);
    a->accuracy = new_accuracy;
    return 1;
}

TS_ACCURACY *TS_TST_INFO_get_accuracy(TS_TST_INFO *a)
{
    return a->accuracy;
}

int TS_ACCURACY_set_seconds(TS_ACCURACY *a, const ASN1_INTEGER *seconds)
{
    ASN1_INTEGER *new_seconds;

    if (a->seconds == seconds)
        return 1;
    new_seconds = ASN1_INTEGER_dup(seconds);
    if (new_seconds == NULL) {
        TSerr(TS_F_TS_ACCURACY_SET_SECONDS, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    ASN1_INTEGER_free(a->seconds);
    a->seconds = new_seconds;
    return 1;
}

const ASN1_INTEGER *TS_ACCURACY_get_seconds(const TS_ACCURACY *a)
{
    return a->seconds;
}

int TS_ACCURACY_set_millis(TS_ACCURACY *a, const ASN1_INTEGER *millis)
{
    ASN1_INTEGER *new_millis = NULL;

    if (a->millis == millis)
        return 1;
    if (millis != NULL) {
        new_millis = ASN1_INTEGER_dup(millis);
        if (new_millis == NULL) {
            TSerr(TS_F_TS_ACCURACY_SET_MILLIS, ERR_R_MALLOC_FAILURE);
            return 0;
        }
    }
    ASN1_INTEGER_free(a->millis);
    a->millis = new_millis;
    return 1;
}

const ASN1_INTEGER *TS_ACCURACY_get_millis(const TS_ACCURACY *a)
{
    return a->millis;
}

int TS_ACCURACY_set_micros(TS_ACCURACY *a, const ASN1_INTEGER *micros)
{
    ASN1_INTEGER *new_micros = NULL;

    if (a->micros == micros)
        return 1;
    if (micros != NULL) {
        new_micros = ASN1_INTEGER_dup(micros);
        if (new_micros == NULL) {
            TSerr(TS_F_TS_ACCURACY_SET_MICROS, ERR_R_MALLOC_FAILURE);
            return 0;
        }
    }
    ASN1_INTEGER_free(a->micros);
    a->micros = new_micros;
    return 1;
}

const ASN1_INTEGER *TS_ACCURACY_get_micros(const TS_ACCURACY *a)
{
    return a->micros;
}

int TS_TST_INFO_set_ordering(TS_TST_INFO *a, int ordering)
{
    a->ordering = ordering ? 0xFF : 0x00;
    return 1;
}

int TS_TST_INFO_get_ordering(const TS_TST_INFO *a)
{
    return a->ordering ? 1 : 0;
}

int TS_TST_INFO_set_nonce(TS_TST_INFO *a, const ASN1_INTEGER *nonce)
{
    ASN1_INTEGER *new_nonce;

    if (a->nonce == nonce)
        return 1;
    new_nonce = ASN1_INTEGER_dup(nonce);
    if (new_nonce == NULL) {
        TSerr(TS_F_TS_TST_INFO_SET_NONCE, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    ASN1_INTEGER_free(a->nonce);
    a->nonce = new_nonce;
    return 1;
}

const ASN1_INTEGER *TS_TST_INFO_get_nonce(const TS_TST_INFO *a)
{
    return a->nonce;
}

int TS_TST_INFO_set_tsa(TS_TST_INFO *a, GENERAL_NAME *tsa)
{
    GENERAL_NAME *new_tsa;

    if (a->tsa == tsa)
        return 1;
    new_tsa = GENERAL_NAME_dup(tsa);
    if (new_tsa == NULL) {
        TSerr(TS_F_TS_TST_INFO_SET_TSA, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    GENERAL_NAME_free(a->tsa);
    a->tsa = new_tsa;
    return 1;
}

GENERAL_NAME *TS_TST_INFO_get_tsa(TS_TST_INFO *a)
{
    return a->tsa;
}

STACK_OF(X509_EXTENSION) *TS_TST_INFO_get_exts(TS_TST_INFO *a)
{
    return a->extensions;
}

void TS_TST_INFO_ext_free(TS_TST_INFO *a)
{
    if (!a)
        return;
    sk_X509_EXTENSION_pop_free(a->extensions, X509_EXTENSION_free);
    a->extensions = NULL;
}

int TS_TST_INFO_get_ext_count(TS_TST_INFO *a)
{
    return X509v3_get_ext_count(a->extensions);
}

int TS_TST_INFO_get_ext_by_NID(TS_TST_INFO *a, int nid, int lastpos)
{
    return X509v3_get_ext_by_NID(a->extensions, nid, lastpos);
}

int TS_TST_INFO_get_ext_by_OBJ(TS_TST_INFO *a, ASN1_OBJECT *obj, int lastpos)
{
    return X509v3_get_ext_by_OBJ(a->extensions, obj, lastpos);
}

int TS_TST_INFO_get_ext_by_critical(TS_TST_INFO *a, int crit, int lastpos)
{
    return X509v3_get_ext_by_critical(a->extensions, crit, lastpos);
}

X509_EXTENSION *TS_TST_INFO_get_ext(TS_TST_INFO *a, int loc)
{
    return X509v3_get_ext(a->extensions, loc);
}

X509_EXTENSION *TS_TST_INFO_delete_ext(TS_TST_INFO *a, int loc)
{
    return X509v3_delete_ext(a->extensions, loc);
}

int TS_TST_INFO_add_ext(TS_TST_INFO *a, X509_EXTENSION *ex, int loc)
{
    return X509v3_add_ext(&a->extensions, ex, loc) != NULL;
}

void *TS_TST_INFO_get_ext_d2i(TS_TST_INFO *a, int nid, int *crit, int *idx)
{
    return X509V3_get_d2i(a->extensions, nid, crit, idx);
}
/* crypto/ts/ts_resp_verify.c */
/*
 * Written by Zoltan Glozik (zglozik@stones.com) for the OpenSSL project
 * 2002.
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
// #include "objects.h"
// #include "ts.h"
// #include "pkcs7.h"

/* Private function declarations. */

static int TS_verify_cert(X509_STORE *store, STACK_OF(X509) *untrusted,
                          X509 *signer, STACK_OF(X509) **chain);
static int TS_check_signing_certs(PKCS7_SIGNER_INFO *si,
                                  STACK_OF(X509) *chain);
static ESS_SIGNING_CERT *ESS_get_signing_cert(PKCS7_SIGNER_INFO *si);
static int TS_find_cert(STACK_OF(ESS_CERT_ID) *cert_ids, X509 *cert);
static int TS_issuer_serial_cmp(ESS_ISSUER_SERIAL *is, X509_CINF *cinfo);
static int int_TS_RESP_verify_token(TS_VERIFY_CTX *ctx,
                                    PKCS7 *token, TS_TST_INFO *tst_info);
static int TS_check_status_info(TS_RESP *response);
static char *TS_get_status_text(STACK_OF(ASN1_UTF8STRING) *text);
static int TS_check_policy(ASN1_OBJECT *req_oid, TS_TST_INFO *tst_info);
static int TS_compute_imprint(BIO *data, TS_TST_INFO *tst_info,
                              X509_ALGOR **md_alg,
                              unsigned char **imprint, unsigned *imprint_len);
static int TS_check_imprints(X509_ALGOR *algor_a,
                             unsigned char *imprint_a, unsigned len_a,
                             TS_TST_INFO *tst_info);
static int TS_check_nonces(const ASN1_INTEGER *a, TS_TST_INFO *tst_info);
static int TS_check_signer_name(GENERAL_NAME *tsa_name, X509 *signer);
static int TS_find_name(STACK_OF(GENERAL_NAME) *gen_names,
                        GENERAL_NAME *name);

/*
 * Local mapping between response codes and descriptions.
 * Don't forget to change TS_STATUS_BUF_SIZE when modifying
 * the elements of this array.
 */
static const char *TS_status_text[] = { "granted",
    "grantedWithMods",
    "rejection",
    "waiting",
    "revocationWarning",
    "revocationNotification"
};

#define TS_STATUS_TEXT_SIZE     (sizeof(TS_status_text)/sizeof(*TS_status_text))

/*
 * This must be greater or equal to the sum of the strings in TS_status_text
 * plus the number of its elements.
 */
#define TS_STATUS_BUF_SIZE      256

static struct {
    int code;
    const char *text;
} TS_failure_info[] = {
    {
        TS_INFO_BAD_ALG, "badAlg"
    },
    {
        TS_INFO_BAD_REQUEST, "badRequest"
    },
    {
        TS_INFO_BAD_DATA_FORMAT, "badDataFormat"
    },
    {
        TS_INFO_TIME_NOT_AVAILABLE, "timeNotAvailable"
    },
    {
        TS_INFO_UNACCEPTED_POLICY, "unacceptedPolicy"
    },
    {
        TS_INFO_UNACCEPTED_EXTENSION, "unacceptedExtension"
    },
    {
        TS_INFO_ADD_INFO_NOT_AVAILABLE, "addInfoNotAvailable"
    },
    {
        TS_INFO_SYSTEM_FAILURE, "systemFailure"
    }
};

#define TS_FAILURE_INFO_SIZE    (sizeof(TS_failure_info) / \
                                sizeof(*TS_failure_info))

/* Functions for verifying a signed TS_TST_INFO structure. */

/*-
 * This function carries out the following tasks:
 *      - Checks if there is one and only one signer.
 *      - Search for the signing certificate in 'certs' and in the response.
 *      - Check the extended key usage and key usage fields of the signer
 *      certificate (done by the path validation).
 *      - Build and validate the certificate path.
 *      - Check if the certificate path meets the requirements of the
 *      SigningCertificate ESS signed attribute.
 *      - Verify the signature value.
 *      - Returns the signer certificate in 'signer', if 'signer' is not NULL.
 */
int TS_RESP_verify_signature(PKCS7 *token, STACK_OF(X509) *certs,
                             X509_STORE *store, X509 **signer_out)
{
    STACK_OF(PKCS7_SIGNER_INFO) *sinfos = NULL;
    PKCS7_SIGNER_INFO *si;
    STACK_OF(X509) *signers = NULL;
    X509 *signer;
    STACK_OF(X509) *chain = NULL;
    char buf[4096];
    int i, j = 0, ret = 0;
    BIO *p7bio = NULL;

    /* Some sanity checks first. */
    if (!token) {
        TSerr(TS_F_TS_RESP_VERIFY_SIGNATURE, TS_R_INVALID_NULL_POINTER);
        goto err;
    }

    /* Check for the correct content type */
    if (!PKCS7_type_is_signed(token)) {
        TSerr(TS_F_TS_RESP_VERIFY_SIGNATURE, TS_R_WRONG_CONTENT_TYPE);
        goto err;
    }

    /* Check if there is one and only one signer. */
    sinfos = PKCS7_get_signer_info(token);
    if (!sinfos || sk_PKCS7_SIGNER_INFO_num(sinfos) != 1) {
        TSerr(TS_F_TS_RESP_VERIFY_SIGNATURE, TS_R_THERE_MUST_BE_ONE_SIGNER);
        goto err;
    }
    si = sk_PKCS7_SIGNER_INFO_value(sinfos, 0);

    /* Check for no content: no data to verify signature. */
    if (PKCS7_get_detached(token)) {
        TSerr(TS_F_TS_RESP_VERIFY_SIGNATURE, TS_R_NO_CONTENT);
        goto err;
    }

    /*
     * Get hold of the signer certificate, search only internal certificates
     * if it was requested.
     */
    signers = PKCS7_get0_signers(token, certs, 0);
    if (!signers || sk_X509_num(signers) != 1)
        goto err;
    signer = sk_X509_value(signers, 0);

    /* Now verify the certificate. */
    if (!TS_verify_cert(store, certs, signer, &chain))
        goto err;

    /*
     * Check if the signer certificate is consistent with the ESS extension.
     */
    if (!TS_check_signing_certs(si, chain))
        goto err;

    /* Creating the message digest. */
    p7bio = PKCS7_dataInit(token, NULL);

    /* We now have to 'read' from p7bio to calculate digests etc. */
    while ((i = BIO_read(p7bio, buf, sizeof(buf))) > 0) ;

    /* Verifying the signature. */
    j = PKCS7_signatureVerify(p7bio, token, si, signer);
    if (j <= 0) {
        TSerr(TS_F_TS_RESP_VERIFY_SIGNATURE, TS_R_SIGNATURE_FAILURE);
        goto err;
    }

    /* Return the signer certificate if needed. */
    if (signer_out) {
        *signer_out = signer;
        CRYPTO_add(&signer->references, 1, CRYPTO_LOCK_X509);
    }

    ret = 1;

 err:
    BIO_free_all(p7bio);
    sk_X509_pop_free(chain, X509_free);
    sk_X509_free(signers);

    return ret;
}

/*
 * The certificate chain is returned in chain. Caller is responsible for
 * freeing the vector.
 */
static int TS_verify_cert(X509_STORE *store, STACK_OF(X509) *untrusted,
                          X509 *signer, STACK_OF(X509) **chain)
{
    X509_STORE_CTX cert_ctx;
    int i;
    int ret = 1;

    /* chain is an out argument. */
    *chain = NULL;
    if (!X509_STORE_CTX_init(&cert_ctx, store, signer, untrusted))
        return 0;
    X509_STORE_CTX_set_purpose(&cert_ctx, X509_PURPOSE_TIMESTAMP_SIGN);
    i = X509_verify_cert(&cert_ctx);
    if (i <= 0) {
        int j = X509_STORE_CTX_get_error(&cert_ctx);
        TSerr(TS_F_TS_VERIFY_CERT, TS_R_CERTIFICATE_VERIFY_ERROR);
        ERR_add_error_data(2, "Verify error:",
                           X509_verify_cert_error_string(j));
        ret = 0;
    } else {
        /* Get a copy of the certificate chain. */
        *chain = X509_STORE_CTX_get1_chain(&cert_ctx);
    }

    X509_STORE_CTX_cleanup(&cert_ctx);

    return ret;
}

static int TS_check_signing_certs(PKCS7_SIGNER_INFO *si,
                                  STACK_OF(X509) *chain)
{
    ESS_SIGNING_CERT *ss = ESS_get_signing_cert(si);
    STACK_OF(ESS_CERT_ID) *cert_ids = NULL;
    X509 *cert;
    int i = 0;
    int ret = 0;

    if (!ss)
        goto err;
    cert_ids = ss->cert_ids;
    /* The signer certificate must be the first in cert_ids. */
    cert = sk_X509_value(chain, 0);
    if (TS_find_cert(cert_ids, cert) != 0)
        goto err;

    /*
     * Check the other certificates of the chain if there are more than one
     * certificate ids in cert_ids.
     */
    if (sk_ESS_CERT_ID_num(cert_ids) > 1) {
        /* All the certificates of the chain must be in cert_ids. */
        for (i = 1; i < sk_X509_num(chain); ++i) {
            cert = sk_X509_value(chain, i);
            if (TS_find_cert(cert_ids, cert) < 0)
                goto err;
        }
    }
    ret = 1;
 err:
    if (!ret)
        TSerr(TS_F_TS_CHECK_SIGNING_CERTS,
              TS_R_ESS_SIGNING_CERTIFICATE_ERROR);
    ESS_SIGNING_CERT_free(ss);
    return ret;
}

static ESS_SIGNING_CERT *ESS_get_signing_cert(PKCS7_SIGNER_INFO *si)
{
    ASN1_TYPE *attr;
    const unsigned char *p;
    attr = PKCS7_get_signed_attribute(si, NID_id_smime_aa_signingCertificate);
    if (!attr)
        return NULL;
    p = attr->value.sequence->data;
    return d2i_ESS_SIGNING_CERT(NULL, &p, attr->value.sequence->length);
}

/* Returns < 0 if certificate is not found, certificate index otherwise. */
static int TS_find_cert(STACK_OF(ESS_CERT_ID) *cert_ids, X509 *cert)
{
    int i;

    if (!cert_ids || !cert)
        return -1;

    /* Recompute SHA1 hash of certificate if necessary (side effect). */
    X509_check_purpose(cert, -1, 0);

    /* Look for cert in the cert_ids vector. */
    for (i = 0; i < sk_ESS_CERT_ID_num(cert_ids); ++i) {
        ESS_CERT_ID *cid = sk_ESS_CERT_ID_value(cert_ids, i);

        /* Check the SHA-1 hash first. */
        if (cid->hash->length == sizeof(cert->sha1_hash)
            && !memcmp(cid->hash->data, cert->sha1_hash,
                       sizeof(cert->sha1_hash))) {
            /* Check the issuer/serial as well if specified. */
            ESS_ISSUER_SERIAL *is = cid->issuer_serial;
            if (!is || !TS_issuer_serial_cmp(is, cert->cert_info))
                return i;
        }
    }

    return -1;
}

static int TS_issuer_serial_cmp(ESS_ISSUER_SERIAL *is, X509_CINF *cinfo)
{
    GENERAL_NAME *issuer;

    if (!is || !cinfo || sk_GENERAL_NAME_num(is->issuer) != 1)
        return -1;

    /* Check the issuer first. It must be a directory name. */
    issuer = sk_GENERAL_NAME_value(is->issuer, 0);
    if (issuer->type != GEN_DIRNAME
        || X509_NAME_cmp(issuer->d.dirn, cinfo->issuer))
        return -1;

    /* Check the serial number, too. */
    if (ASN1_INTEGER_cmp(is->serial, cinfo->serialNumber))
        return -1;

    return 0;
}

/*-
 * Verifies whether 'response' contains a valid response with regards
 * to the settings of the context:
 *      - Gives an error message if the TS_TST_INFO is not present.
 *      - Calls _TS_RESP_verify_token to verify the token content.
 */
int TS_RESP_verify_response(TS_VERIFY_CTX *ctx, TS_RESP *response)
{
    PKCS7 *token = TS_RESP_get_token(response);
    TS_TST_INFO *tst_info = TS_RESP_get_tst_info(response);
    int ret = 0;

    /* Check if we have a successful TS_TST_INFO object in place. */
    if (!TS_check_status_info(response))
        goto err;

    /* Check the contents of the time stamp token. */
    if (!int_TS_RESP_verify_token(ctx, token, tst_info))
        goto err;

    ret = 1;
 err:
    return ret;
}

/*
 * Tries to extract a TS_TST_INFO structure from the PKCS7 token and
 * calls the internal int_TS_RESP_verify_token function for verifying it.
 */
int TS_RESP_verify_token(TS_VERIFY_CTX *ctx, PKCS7 *token)
{
    TS_TST_INFO *tst_info = PKCS7_to_TS_TST_INFO(token);
    int ret = 0;
    if (tst_info) {
        ret = int_TS_RESP_verify_token(ctx, token, tst_info);
        TS_TST_INFO_free(tst_info);
    }
    return ret;
}

/*-
 * Verifies whether the 'token' contains a valid time stamp token
 * with regards to the settings of the context. Only those checks are
 * carried out that are specified in the context:
 *      - Verifies the signature of the TS_TST_INFO.
 *      - Checks the version number of the response.
 *      - Check if the requested and returned policies math.
 *      - Check if the message imprints are the same.
 *      - Check if the nonces are the same.
 *      - Check if the TSA name matches the signer.
 *      - Check if the TSA name is the expected TSA.
 */
static int int_TS_RESP_verify_token(TS_VERIFY_CTX *ctx,
                                    PKCS7 *token, TS_TST_INFO *tst_info)
{
    X509 *signer = NULL;
    GENERAL_NAME *tsa_name = TS_TST_INFO_get_tsa(tst_info);
    X509_ALGOR *md_alg = NULL;
    unsigned char *imprint = NULL;
    unsigned imprint_len = 0;
    int ret = 0;
    int flags = ctx->flags;

    /* Some options require us to also check the signature */
    if (((flags & TS_VFY_SIGNER) && tsa_name != NULL)
            || (flags & TS_VFY_TSA_NAME)) {
        flags |= TS_VFY_SIGNATURE;
    }

    /* Verify the signature. */
    if ((flags & TS_VFY_SIGNATURE)
        && !TS_RESP_verify_signature(token, ctx->certs, ctx->store, &signer))
        goto err;

    /* Check version number of response. */
    if ((flags & TS_VFY_VERSION)
        && TS_TST_INFO_get_version(tst_info) != 1) {
        TSerr(TS_F_INT_TS_RESP_VERIFY_TOKEN, TS_R_UNSUPPORTED_VERSION);
        goto err;
    }

    /* Check policies. */
    if ((flags & TS_VFY_POLICY)
        && !TS_check_policy(ctx->policy, tst_info))
        goto err;

    /* Check message imprints. */
    if ((flags & TS_VFY_IMPRINT)
        && !TS_check_imprints(ctx->md_alg, ctx->imprint, ctx->imprint_len,
                              tst_info))
        goto err;

    /* Compute and check message imprints. */
    if ((flags & TS_VFY_DATA)
        && (!TS_compute_imprint(ctx->data, tst_info,
                                &md_alg, &imprint, &imprint_len)
            || !TS_check_imprints(md_alg, imprint, imprint_len, tst_info)))
        goto err;

    /* Check nonces. */
    if ((flags & TS_VFY_NONCE)
        && !TS_check_nonces(ctx->nonce, tst_info))
        goto err;

    /* Check whether TSA name and signer certificate match. */
    if ((flags & TS_VFY_SIGNER)
        && tsa_name && !TS_check_signer_name(tsa_name, signer)) {
        TSerr(TS_F_INT_TS_RESP_VERIFY_TOKEN, TS_R_TSA_NAME_MISMATCH);
        goto err;
    }

    /* Check whether the TSA is the expected one. */
    if ((flags & TS_VFY_TSA_NAME)
        && !TS_check_signer_name(ctx->tsa_name, signer)) {
        TSerr(TS_F_INT_TS_RESP_VERIFY_TOKEN, TS_R_TSA_UNTRUSTED);
        goto err;
    }

    ret = 1;
 err:
    X509_free(signer);
    X509_ALGOR_free(md_alg);
    OPENSSL_free(imprint);
    return ret;
}

static int TS_check_status_info(TS_RESP *response)
{
    TS_STATUS_INFO *info = TS_RESP_get_status_info(response);
    long status = ASN1_INTEGER_get(info->status);
    const char *status_text = NULL;
    char *embedded_status_text = NULL;
    char failure_text[TS_STATUS_BUF_SIZE] = "";

    /* Check if everything went fine. */
    if (status == 0 || status == 1)
        return 1;

    /* There was an error, get the description in status_text. */
    if (0 <= status && status < (long)TS_STATUS_TEXT_SIZE)
        status_text = TS_status_text[status];
    else
        status_text = "unknown code";

    /* Set the embedded_status_text to the returned description. */
    if (sk_ASN1_UTF8STRING_num(info->text) > 0
        && !(embedded_status_text = TS_get_status_text(info->text)))
        return 0;

    /* Filling in failure_text with the failure information. */
    if (info->failure_info) {
        int i;
        int first = 1;
        for (i = 0; i < (int)TS_FAILURE_INFO_SIZE; ++i) {
            if (ASN1_BIT_STRING_get_bit(info->failure_info,
                                        TS_failure_info[i].code)) {
                if (!first)
                    strcat(failure_text, ",");
                else
                    first = 0;
                strcat(failure_text, TS_failure_info[i].text);
            }
        }
    }
    if (failure_text[0] == '\0')
        strcpy(failure_text, "unspecified");

    /* Making up the error string. */
    TSerr(TS_F_TS_CHECK_STATUS_INFO, TS_R_NO_TIME_STAMP_TOKEN);
    ERR_add_error_data(6,
                       "status code: ", status_text,
                       ", status text: ", embedded_status_text ?
                       embedded_status_text : "unspecified",
                       ", failure codes: ", failure_text);
    OPENSSL_free(embedded_status_text);

    return 0;
}

static char *TS_get_status_text(STACK_OF(ASN1_UTF8STRING) *text)
{
    int i;
    int length = 0;
    char *result = NULL;
    char *p;

    /* Determine length first. */
    for (i = 0; i < sk_ASN1_UTF8STRING_num(text); ++i) {
        ASN1_UTF8STRING *current = sk_ASN1_UTF8STRING_value(text, i);
        if (ASN1_STRING_length(current) > TS_MAX_STATUS_LENGTH - length - 1)
            return NULL;
        length += ASN1_STRING_length(current);
        length += 1;            /* separator character */
    }
    /* Allocate memory (closing '\0' included). */
    if (!(result = OPENSSL_malloc(length))) {
        TSerr(TS_F_TS_GET_STATUS_TEXT, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    /* Concatenate the descriptions. */
    for (i = 0, p = result; i < sk_ASN1_UTF8STRING_num(text); ++i) {
        ASN1_UTF8STRING *current = sk_ASN1_UTF8STRING_value(text, i);
        length = ASN1_STRING_length(current);
        if (i > 0)
            *p++ = '/';
        strncpy(p, (const char *)ASN1_STRING_data(current), length);
        p += length;
    }
    /* We do have space for this, too. */
    *p = '\0';

    return result;
}

static int TS_check_policy(ASN1_OBJECT *req_oid, TS_TST_INFO *tst_info)
{
    ASN1_OBJECT *resp_oid = TS_TST_INFO_get_policy_id(tst_info);

    if (OBJ_cmp(req_oid, resp_oid) != 0) {
        TSerr(TS_F_TS_CHECK_POLICY, TS_R_POLICY_MISMATCH);
        return 0;
    }

    return 1;
}

static int TS_compute_imprint(BIO *data, TS_TST_INFO *tst_info,
                              X509_ALGOR **md_alg,
                              unsigned char **imprint, unsigned *imprint_len)
{
    TS_MSG_IMPRINT *msg_imprint = TS_TST_INFO_get_msg_imprint(tst_info);
    X509_ALGOR *md_alg_resp = TS_MSG_IMPRINT_get_algo(msg_imprint);
    const EVP_MD *md;
    EVP_MD_CTX md_ctx;
    unsigned char buffer[4096];
    int length;

    *md_alg = NULL;
    *imprint = NULL;

    /* Return the MD algorithm of the response. */
    if (!(*md_alg = X509_ALGOR_dup(md_alg_resp)))
        goto err;

    /* Getting the MD object. */
    if (!(md = EVP_get_digestbyobj((*md_alg)->algorithm))) {
        TSerr(TS_F_TS_COMPUTE_IMPRINT, TS_R_UNSUPPORTED_MD_ALGORITHM);
        goto err;
    }

    /* Compute message digest. */
    length = EVP_MD_size(md);
    if (length < 0)
        goto err;
    *imprint_len = length;
    if (!(*imprint = OPENSSL_malloc(*imprint_len))) {
        TSerr(TS_F_TS_COMPUTE_IMPRINT, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (!EVP_DigestInit(&md_ctx, md))
        goto err;
    while ((length = BIO_read(data, buffer, sizeof(buffer))) > 0) {
        if (!EVP_DigestUpdate(&md_ctx, buffer, length))
            goto err;
    }
    if (!EVP_DigestFinal(&md_ctx, *imprint, NULL))
        goto err;

    return 1;
 err:
    X509_ALGOR_free(*md_alg);
    OPENSSL_free(*imprint);
    *imprint_len = 0;
    *imprint = 0;
    return 0;
}

static int TS_check_imprints(X509_ALGOR *algor_a,
                             unsigned char *imprint_a, unsigned len_a,
                             TS_TST_INFO *tst_info)
{
    TS_MSG_IMPRINT *b = TS_TST_INFO_get_msg_imprint(tst_info);
    X509_ALGOR *algor_b = TS_MSG_IMPRINT_get_algo(b);
    int ret = 0;

    /* algor_a is optional. */
    if (algor_a) {
        /* Compare algorithm OIDs. */
        if (OBJ_cmp(algor_a->algorithm, algor_b->algorithm))
            goto err;

        /* The parameter must be NULL in both. */
        if ((algor_a->parameter
             && ASN1_TYPE_get(algor_a->parameter) != V_ASN1_NULL)
            || (algor_b->parameter
                && ASN1_TYPE_get(algor_b->parameter) != V_ASN1_NULL))
            goto err;
    }

    /* Compare octet strings. */
    ret = len_a == (unsigned)ASN1_STRING_length(b->hashed_msg) &&
        memcmp(imprint_a, ASN1_STRING_data(b->hashed_msg), len_a) == 0;
 err:
    if (!ret)
        TSerr(TS_F_TS_CHECK_IMPRINTS, TS_R_MESSAGE_IMPRINT_MISMATCH);
    return ret;
}

static int TS_check_nonces(const ASN1_INTEGER *a, TS_TST_INFO *tst_info)
{
    const ASN1_INTEGER *b = TS_TST_INFO_get_nonce(tst_info);

    /* Error if nonce is missing. */
    if (!b) {
        TSerr(TS_F_TS_CHECK_NONCES, TS_R_NONCE_NOT_RETURNED);
        return 0;
    }

    /* No error if a nonce is returned without being requested. */
    if (ASN1_INTEGER_cmp(a, b) != 0) {
        TSerr(TS_F_TS_CHECK_NONCES, TS_R_NONCE_MISMATCH);
        return 0;
    }

    return 1;
}

/*
 * Check if the specified TSA name matches either the subject or one of the
 * subject alternative names of the TSA certificate.
 */
static int TS_check_signer_name(GENERAL_NAME *tsa_name, X509 *signer)
{
    STACK_OF(GENERAL_NAME) *gen_names = NULL;
    int idx = -1;
    int found = 0;

    /* Check the subject name first. */
    if (tsa_name->type == GEN_DIRNAME
        && X509_name_cmp(tsa_name->d.dirn, signer->cert_info->subject) == 0)
        return 1;

    /* Check all the alternative names. */
    gen_names = X509_get_ext_d2i(signer, NID_subject_alt_name, NULL, &idx);
    while (gen_names != NULL
           && !(found = TS_find_name(gen_names, tsa_name) >= 0)) {
        /*
         * Get the next subject alternative name, although there should be no
         * more than one.
         */
        GENERAL_NAMES_free(gen_names);
        gen_names = X509_get_ext_d2i(signer, NID_subject_alt_name,
                                     NULL, &idx);
    }
    if (gen_names)
        GENERAL_NAMES_free(gen_names);

    return found;
}

/* Returns 1 if name is in gen_names, 0 otherwise. */
static int TS_find_name(STACK_OF(GENERAL_NAME) *gen_names, GENERAL_NAME *name)
{
    int i, found;
    for (i = 0, found = 0; !found && i < sk_GENERAL_NAME_num(gen_names); ++i) {
        GENERAL_NAME *current = sk_GENERAL_NAME_value(gen_names, i);
        found = GENERAL_NAME_cmp(current, name) == 0;
    }
    return found ? i - 1 : -1;
}
/* crypto/ts/ts_verify_ctx.c */
/*
 * Written by Zoltan Glozik (zglozik@stones.com) for the OpenSSL project
 * 2003.
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

// #include "cryptlib.h"
// #include "objects.h"
// #include "ts.h"

TS_VERIFY_CTX *TS_VERIFY_CTX_new(void)
{
    TS_VERIFY_CTX *ctx =
        (TS_VERIFY_CTX *)OPENSSL_malloc(sizeof(TS_VERIFY_CTX));
    if (ctx)
        memset(ctx, 0, sizeof(TS_VERIFY_CTX));
    else
        TSerr(TS_F_TS_VERIFY_CTX_NEW, ERR_R_MALLOC_FAILURE);
    return ctx;
}

void TS_VERIFY_CTX_init(TS_VERIFY_CTX *ctx)
{
    OPENSSL_assert(ctx != NULL);
    memset(ctx, 0, sizeof(TS_VERIFY_CTX));
}

void TS_VERIFY_CTX_free(TS_VERIFY_CTX *ctx)
{
    if (!ctx)
        return;

    TS_VERIFY_CTX_cleanup(ctx);
    OPENSSL_free(ctx);
}

void TS_VERIFY_CTX_cleanup(TS_VERIFY_CTX *ctx)
{
    if (!ctx)
        return;

    X509_STORE_free(ctx->store);
    sk_X509_pop_free(ctx->certs, X509_free);

    ASN1_OBJECT_free(ctx->policy);

    X509_ALGOR_free(ctx->md_alg);
    OPENSSL_free(ctx->imprint);

    BIO_free_all(ctx->data);

    ASN1_INTEGER_free(ctx->nonce);

    GENERAL_NAME_free(ctx->tsa_name);

    TS_VERIFY_CTX_init(ctx);
}

TS_VERIFY_CTX *TS_REQ_to_TS_VERIFY_CTX(TS_REQ *req, TS_VERIFY_CTX *ctx)
{
    TS_VERIFY_CTX *ret = ctx;
    ASN1_OBJECT *policy;
    TS_MSG_IMPRINT *imprint;
    X509_ALGOR *md_alg;
    ASN1_OCTET_STRING *msg;
    const ASN1_INTEGER *nonce;

    OPENSSL_assert(req != NULL);
    if (ret)
        TS_VERIFY_CTX_cleanup(ret);
    else if (!(ret = TS_VERIFY_CTX_new()))
        return NULL;

    /* Setting flags. */
    ret->flags = TS_VFY_ALL_IMPRINT & ~(TS_VFY_TSA_NAME | TS_VFY_SIGNATURE);

    /* Setting policy. */
    if ((policy = TS_REQ_get_policy_id(req)) != NULL) {
        if (!(ret->policy = OBJ_dup(policy)))
            goto err;
    } else
        ret->flags &= ~TS_VFY_POLICY;

    /* Setting md_alg, imprint and imprint_len. */
    imprint = TS_REQ_get_msg_imprint(req);
    md_alg = TS_MSG_IMPRINT_get_algo(imprint);
    if (!(ret->md_alg = X509_ALGOR_dup(md_alg)))
        goto err;
    msg = TS_MSG_IMPRINT_get_msg(imprint);
    ret->imprint_len = ASN1_STRING_length(msg);
    if (!(ret->imprint = OPENSSL_malloc(ret->imprint_len)))
        goto err;
    memcpy(ret->imprint, ASN1_STRING_data(msg), ret->imprint_len);

    /* Setting nonce. */
    if ((nonce = TS_REQ_get_nonce(req)) != NULL) {
        if (!(ret->nonce = ASN1_INTEGER_dup(nonce)))
            goto err;
    } else
        ret->flags &= ~TS_VFY_NONCE;

    return ret;
 err:
    if (ctx)
        TS_VERIFY_CTX_cleanup(ctx);
    else
        TS_VERIFY_CTX_free(ret);
    return NULL;
}
