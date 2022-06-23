/* pk7_asn.c */
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
#include "cryptlib.h"
#include "asn1t.h"
#include "pkcs7.h"
#include "x509.h"

/* PKCS#7 ASN1 module */

/* This is the ANY DEFINED BY table for the top level PKCS#7 structure */

ASN1_ADB_TEMPLATE(p7default) = ASN1_EXP_OPT(PKCS7, d.other, ASN1_ANY, 0);

ASN1_ADB(PKCS7) = {
        ADB_ENTRY(NID_pkcs7_data, ASN1_NDEF_EXP_OPT(PKCS7, d.data, ASN1_OCTET_STRING_NDEF, 0)),
        ADB_ENTRY(NID_pkcs7_signed, ASN1_NDEF_EXP_OPT(PKCS7, d.sign, PKCS7_SIGNED, 0)),
        ADB_ENTRY(NID_pkcs7_enveloped, ASN1_NDEF_EXP_OPT(PKCS7, d.enveloped, PKCS7_ENVELOPE, 0)),
        ADB_ENTRY(NID_pkcs7_signedAndEnveloped, ASN1_NDEF_EXP_OPT(PKCS7, d.signed_and_enveloped, PKCS7_SIGN_ENVELOPE, 0)),
        ADB_ENTRY(NID_pkcs7_digest, ASN1_NDEF_EXP_OPT(PKCS7, d.digest, PKCS7_DIGEST, 0)),
        ADB_ENTRY(NID_pkcs7_encrypted, ASN1_NDEF_EXP_OPT(PKCS7, d.encrypted, PKCS7_ENCRYPT, 0))
} ASN1_ADB_END(PKCS7, 0, type, 0, &p7default_tt, NULL);

/* PKCS#7 streaming support */
static int pk7_cb(int operation, ASN1_VALUE **pval, const ASN1_ITEM *it,
                  void *exarg)
{
    ASN1_STREAM_ARG *sarg = exarg;
    PKCS7 **pp7 = (PKCS7 **)pval;

    switch (operation) {

    case ASN1_OP_STREAM_PRE:
        if (PKCS7_stream(&sarg->boundary, *pp7) <= 0)
            return 0;
    case ASN1_OP_DETACHED_PRE:
        sarg->ndef_bio = PKCS7_dataInit(*pp7, sarg->out);
        if (!sarg->ndef_bio)
            return 0;
        break;

    case ASN1_OP_STREAM_POST:
    case ASN1_OP_DETACHED_POST:
        if (PKCS7_dataFinal(*pp7, sarg->ndef_bio) <= 0)
            return 0;
        break;

    }
    return 1;
}

ASN1_NDEF_SEQUENCE_cb(PKCS7, pk7_cb) = {
        ASN1_SIMPLE(PKCS7, type, ASN1_OBJECT),
        ASN1_ADB_OBJECT(PKCS7)
}ASN1_NDEF_SEQUENCE_END_cb(PKCS7, PKCS7)

IMPLEMENT_ASN1_FUNCTIONS(PKCS7)

IMPLEMENT_ASN1_NDEF_FUNCTION(PKCS7)

IMPLEMENT_ASN1_DUP_FUNCTION(PKCS7)

ASN1_NDEF_SEQUENCE(PKCS7_SIGNED) = {
        ASN1_SIMPLE(PKCS7_SIGNED, version, ASN1_INTEGER),
        ASN1_SET_OF(PKCS7_SIGNED, md_algs, X509_ALGOR),
        ASN1_SIMPLE(PKCS7_SIGNED, contents, PKCS7),
        ASN1_IMP_SEQUENCE_OF_OPT(PKCS7_SIGNED, cert, X509, 0),
        ASN1_IMP_SET_OF_OPT(PKCS7_SIGNED, crl, X509_CRL, 1),
        ASN1_SET_OF(PKCS7_SIGNED, signer_info, PKCS7_SIGNER_INFO)
} ASN1_NDEF_SEQUENCE_END(PKCS7_SIGNED)

IMPLEMENT_ASN1_FUNCTIONS(PKCS7_SIGNED)

/* Minor tweak to operation: free up EVP_PKEY */
static int si_cb(int operation, ASN1_VALUE **pval, const ASN1_ITEM *it,
                 void *exarg)
{
    if (operation == ASN1_OP_FREE_POST) {
        PKCS7_SIGNER_INFO *si = (PKCS7_SIGNER_INFO *)*pval;
        EVP_PKEY_free(si->pkey);
    }
    return 1;
}

ASN1_SEQUENCE_cb(PKCS7_SIGNER_INFO, si_cb) = {
        ASN1_SIMPLE(PKCS7_SIGNER_INFO, version, ASN1_INTEGER),
        ASN1_SIMPLE(PKCS7_SIGNER_INFO, issuer_and_serial, PKCS7_ISSUER_AND_SERIAL),
        ASN1_SIMPLE(PKCS7_SIGNER_INFO, digest_alg, X509_ALGOR),
        /* NB this should be a SET OF but we use a SEQUENCE OF so the
         * original order * is retained when the structure is reencoded.
         * Since the attributes are implicitly tagged this will not affect
         * the encoding.
         */
        ASN1_IMP_SEQUENCE_OF_OPT(PKCS7_SIGNER_INFO, auth_attr, X509_ATTRIBUTE, 0),
        ASN1_SIMPLE(PKCS7_SIGNER_INFO, digest_enc_alg, X509_ALGOR),
        ASN1_SIMPLE(PKCS7_SIGNER_INFO, enc_digest, ASN1_OCTET_STRING),
        ASN1_IMP_SET_OF_OPT(PKCS7_SIGNER_INFO, unauth_attr, X509_ATTRIBUTE, 1)
} ASN1_SEQUENCE_END_cb(PKCS7_SIGNER_INFO, PKCS7_SIGNER_INFO)

IMPLEMENT_ASN1_FUNCTIONS(PKCS7_SIGNER_INFO)

ASN1_SEQUENCE(PKCS7_ISSUER_AND_SERIAL) = {
        ASN1_SIMPLE(PKCS7_ISSUER_AND_SERIAL, issuer, X509_NAME),
        ASN1_SIMPLE(PKCS7_ISSUER_AND_SERIAL, serial, ASN1_INTEGER)
} ASN1_SEQUENCE_END(PKCS7_ISSUER_AND_SERIAL)

IMPLEMENT_ASN1_FUNCTIONS(PKCS7_ISSUER_AND_SERIAL)

ASN1_NDEF_SEQUENCE(PKCS7_ENVELOPE) = {
        ASN1_SIMPLE(PKCS7_ENVELOPE, version, ASN1_INTEGER),
        ASN1_SET_OF(PKCS7_ENVELOPE, recipientinfo, PKCS7_RECIP_INFO),
        ASN1_SIMPLE(PKCS7_ENVELOPE, enc_data, PKCS7_ENC_CONTENT)
} ASN1_NDEF_SEQUENCE_END(PKCS7_ENVELOPE)

IMPLEMENT_ASN1_FUNCTIONS(PKCS7_ENVELOPE)

/* Minor tweak to operation: free up X509 */
static int ri_cb(int operation, ASN1_VALUE **pval, const ASN1_ITEM *it,
                 void *exarg)
{
    if (operation == ASN1_OP_FREE_POST) {
        PKCS7_RECIP_INFO *ri = (PKCS7_RECIP_INFO *)*pval;
        X509_free(ri->cert);
    }
    return 1;
}

ASN1_SEQUENCE_cb(PKCS7_RECIP_INFO, ri_cb) = {
        ASN1_SIMPLE(PKCS7_RECIP_INFO, version, ASN1_INTEGER),
        ASN1_SIMPLE(PKCS7_RECIP_INFO, issuer_and_serial, PKCS7_ISSUER_AND_SERIAL),
        ASN1_SIMPLE(PKCS7_RECIP_INFO, key_enc_algor, X509_ALGOR),
        ASN1_SIMPLE(PKCS7_RECIP_INFO, enc_key, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END_cb(PKCS7_RECIP_INFO, PKCS7_RECIP_INFO)

IMPLEMENT_ASN1_FUNCTIONS(PKCS7_RECIP_INFO)

ASN1_NDEF_SEQUENCE(PKCS7_ENC_CONTENT) = {
        ASN1_SIMPLE(PKCS7_ENC_CONTENT, content_type, ASN1_OBJECT),
        ASN1_SIMPLE(PKCS7_ENC_CONTENT, algorithm, X509_ALGOR),
        ASN1_IMP_OPT(PKCS7_ENC_CONTENT, enc_data, ASN1_OCTET_STRING_NDEF, 0)
} ASN1_NDEF_SEQUENCE_END(PKCS7_ENC_CONTENT)

IMPLEMENT_ASN1_FUNCTIONS(PKCS7_ENC_CONTENT)

ASN1_NDEF_SEQUENCE(PKCS7_SIGN_ENVELOPE) = {
        ASN1_SIMPLE(PKCS7_SIGN_ENVELOPE, version, ASN1_INTEGER),
        ASN1_SET_OF(PKCS7_SIGN_ENVELOPE, recipientinfo, PKCS7_RECIP_INFO),
        ASN1_SET_OF(PKCS7_SIGN_ENVELOPE, md_algs, X509_ALGOR),
        ASN1_SIMPLE(PKCS7_SIGN_ENVELOPE, enc_data, PKCS7_ENC_CONTENT),
        ASN1_IMP_SET_OF_OPT(PKCS7_SIGN_ENVELOPE, cert, X509, 0),
        ASN1_IMP_SET_OF_OPT(PKCS7_SIGN_ENVELOPE, crl, X509_CRL, 1),
        ASN1_SET_OF(PKCS7_SIGN_ENVELOPE, signer_info, PKCS7_SIGNER_INFO)
} ASN1_NDEF_SEQUENCE_END(PKCS7_SIGN_ENVELOPE)

IMPLEMENT_ASN1_FUNCTIONS(PKCS7_SIGN_ENVELOPE)

ASN1_NDEF_SEQUENCE(PKCS7_ENCRYPT) = {
        ASN1_SIMPLE(PKCS7_ENCRYPT, version, ASN1_INTEGER),
        ASN1_SIMPLE(PKCS7_ENCRYPT, enc_data, PKCS7_ENC_CONTENT)
} ASN1_NDEF_SEQUENCE_END(PKCS7_ENCRYPT)

IMPLEMENT_ASN1_FUNCTIONS(PKCS7_ENCRYPT)

ASN1_NDEF_SEQUENCE(PKCS7_DIGEST) = {
        ASN1_SIMPLE(PKCS7_DIGEST, version, ASN1_INTEGER),
        ASN1_SIMPLE(PKCS7_DIGEST, md, X509_ALGOR),
        ASN1_SIMPLE(PKCS7_DIGEST, contents, PKCS7),
        ASN1_SIMPLE(PKCS7_DIGEST, digest, ASN1_OCTET_STRING)
} ASN1_NDEF_SEQUENCE_END(PKCS7_DIGEST)

IMPLEMENT_ASN1_FUNCTIONS(PKCS7_DIGEST)

/* Specials for authenticated attributes */

/*
 * When signing attributes we want to reorder them to match the sorted
 * encoding.
 */

ASN1_ITEM_TEMPLATE(PKCS7_ATTR_SIGN) =
        ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SET_ORDER, 0, PKCS7_ATTRIBUTES, X509_ATTRIBUTE)
ASN1_ITEM_TEMPLATE_END(PKCS7_ATTR_SIGN)

/*
 * When verifying attributes we need to use the received order. So we use
 * SEQUENCE OF and tag it to SET OF
 */

ASN1_ITEM_TEMPLATE(PKCS7_ATTR_VERIFY) =
        ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_IMPTAG | ASN1_TFLG_UNIVERSAL,
                                V_ASN1_SET, PKCS7_ATTRIBUTES, X509_ATTRIBUTE)
ASN1_ITEM_TEMPLATE_END(PKCS7_ATTR_VERIFY)

IMPLEMENT_ASN1_PRINT_FUNCTION(PKCS7)
/* pk7_attr.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 2001.
 */
/* ====================================================================
 * Copyright (c) 2001-2004 The OpenSSL Project.  All rights reserved.
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
#include "bio.h"
#include "asn1.h"
// #include "asn1t.h"
#include "pem.h"
// #include "pkcs7.h"
// #include "x509.h"
#include "err.h"

int PKCS7_add_attrib_smimecap(PKCS7_SIGNER_INFO *si,
                              STACK_OF(X509_ALGOR) *cap)
{
    ASN1_STRING *seq;
    if (!(seq = ASN1_STRING_new())) {
        PKCS7err(PKCS7_F_PKCS7_ADD_ATTRIB_SMIMECAP, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    seq->length = ASN1_item_i2d((ASN1_VALUE *)cap, &seq->data,
                                ASN1_ITEM_rptr(X509_ALGORS));
    return PKCS7_add_signed_attribute(si, NID_SMIMECapabilities,
                                      V_ASN1_SEQUENCE, seq);
}

STACK_OF(X509_ALGOR) *PKCS7_get_smimecap(PKCS7_SIGNER_INFO *si)
{
    ASN1_TYPE *cap;
    const unsigned char *p;

    cap = PKCS7_get_signed_attribute(si, NID_SMIMECapabilities);
    if (!cap || (cap->type != V_ASN1_SEQUENCE))
        return NULL;
    p = cap->value.sequence->data;
    return (STACK_OF(X509_ALGOR) *)
        ASN1_item_d2i(NULL, &p, cap->value.sequence->length,
                      ASN1_ITEM_rptr(X509_ALGORS));
}

/* Basic smime-capabilities OID and optional integer arg */
int PKCS7_simple_smimecap(STACK_OF(X509_ALGOR) *sk, int nid, int arg)
{
    X509_ALGOR *alg;

    if (!(alg = X509_ALGOR_new())) {
        PKCS7err(PKCS7_F_PKCS7_SIMPLE_SMIMECAP, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    ASN1_OBJECT_free(alg->algorithm);
    alg->algorithm = OBJ_nid2obj(nid);
    if (arg > 0) {
        ASN1_INTEGER *nbit;
        if (!(alg->parameter = ASN1_TYPE_new())) {
            PKCS7err(PKCS7_F_PKCS7_SIMPLE_SMIMECAP, ERR_R_MALLOC_FAILURE);
            return 0;
        }
        if (!(nbit = ASN1_INTEGER_new())) {
            PKCS7err(PKCS7_F_PKCS7_SIMPLE_SMIMECAP, ERR_R_MALLOC_FAILURE);
            return 0;
        }
        if (!ASN1_INTEGER_set(nbit, arg)) {
            PKCS7err(PKCS7_F_PKCS7_SIMPLE_SMIMECAP, ERR_R_MALLOC_FAILURE);
            return 0;
        }
        alg->parameter->value.integer = nbit;
        alg->parameter->type = V_ASN1_INTEGER;
    }
    sk_X509_ALGOR_push(sk, alg);
    return 1;
}

int PKCS7_add_attrib_content_type(PKCS7_SIGNER_INFO *si, ASN1_OBJECT *coid)
{
    if (PKCS7_get_signed_attribute(si, NID_pkcs9_contentType))
        return 0;
    if (!coid)
        coid = OBJ_nid2obj(NID_pkcs7_data);
    return PKCS7_add_signed_attribute(si, NID_pkcs9_contentType,
                                      V_ASN1_OBJECT, coid);
}

int PKCS7_add0_attrib_signing_time(PKCS7_SIGNER_INFO *si, ASN1_TIME *t)
{
    if (!t && !(t = X509_gmtime_adj(NULL, 0))) {
        PKCS7err(PKCS7_F_PKCS7_ADD0_ATTRIB_SIGNING_TIME,
                 ERR_R_MALLOC_FAILURE);
        return 0;
    }
    return PKCS7_add_signed_attribute(si, NID_pkcs9_signingTime,
                                      V_ASN1_UTCTIME, t);
}

int PKCS7_add1_attrib_digest(PKCS7_SIGNER_INFO *si,
                             const unsigned char *md, int mdlen)
{
    ASN1_OCTET_STRING *os;
    os = ASN1_OCTET_STRING_new();
    if (!os)
        return 0;
    if (!ASN1_STRING_set(os, md, mdlen)
        || !PKCS7_add_signed_attribute(si, NID_pkcs9_messageDigest,
                                       V_ASN1_OCTET_STRING, os)) {
        ASN1_OCTET_STRING_free(os);
        return 0;
    }
    return 1;
}
/* crypto/pkcs7/pk7_dgst.c */
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
#include "evp.h"
#include "rand.h"
#include "objects.h"
// #include "x509.h"
// #include "pkcs7.h"
/* crypto/pkcs7/pk7_doit.c */
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
// #include "objects.h"
// #include "x509.h"
#include "x509v3.h"
// #include "err.h"

static int add_attribute(STACK_OF(X509_ATTRIBUTE) **sk, int nid, int atrtype,
                         void *value);
static ASN1_TYPE *get_attribute(STACK_OF(X509_ATTRIBUTE) *sk, int nid);

static int PKCS7_type_is_other(PKCS7 *p7)
{
    int isOther = 1;

    int nid = OBJ_obj2nid(p7->type);

    switch (nid) {
    case NID_pkcs7_data:
    case NID_pkcs7_signed:
    case NID_pkcs7_enveloped:
    case NID_pkcs7_signedAndEnveloped:
    case NID_pkcs7_digest:
    case NID_pkcs7_encrypted:
        isOther = 0;
        break;
    default:
        isOther = 1;
    }

    return isOther;

}

static ASN1_OCTET_STRING *PKCS7_get_octet_string(PKCS7 *p7)
{
    if (PKCS7_type_is_data(p7))
        return p7->d.data;
    if (PKCS7_type_is_other(p7) && p7->d.other
        && (p7->d.other->type == V_ASN1_OCTET_STRING))
        return p7->d.other->value.octet_string;
    return NULL;
}

static int PKCS7_bio_add_digest(BIO **pbio, X509_ALGOR *alg)
{
    BIO *btmp;
    const EVP_MD *md;
    if ((btmp = BIO_new(BIO_f_md())) == NULL) {
        PKCS7err(PKCS7_F_PKCS7_BIO_ADD_DIGEST, ERR_R_BIO_LIB);
        goto err;
    }

    md = EVP_get_digestbyobj(alg->algorithm);
    if (md == NULL) {
        PKCS7err(PKCS7_F_PKCS7_BIO_ADD_DIGEST, PKCS7_R_UNKNOWN_DIGEST_TYPE);
        goto err;
    }

    BIO_set_md(btmp, md);
    if (*pbio == NULL)
        *pbio = btmp;
    else if (!BIO_push(*pbio, btmp)) {
        PKCS7err(PKCS7_F_PKCS7_BIO_ADD_DIGEST, ERR_R_BIO_LIB);
        goto err;
    }
    btmp = NULL;

    return 1;

 err:
    if (btmp)
        BIO_free(btmp);
    return 0;

}

static int pkcs7_encode_rinfo(PKCS7_RECIP_INFO *ri,
                              unsigned char *key, int keylen)
{
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkey = NULL;
    unsigned char *ek = NULL;
    int ret = 0;
    size_t eklen;

    pkey = X509_get_pubkey(ri->cert);

    if (!pkey)
        return 0;

    pctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!pctx)
        return 0;

    if (EVP_PKEY_encrypt_init(pctx) <= 0)
        goto err;

    if (EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_ENCRYPT,
                          EVP_PKEY_CTRL_PKCS7_ENCRYPT, 0, ri) <= 0) {
        PKCS7err(PKCS7_F_PKCS7_ENCODE_RINFO, PKCS7_R_CTRL_ERROR);
        goto err;
    }

    if (EVP_PKEY_encrypt(pctx, NULL, &eklen, key, keylen) <= 0)
        goto err;

    ek = OPENSSL_malloc(eklen);

    if (ek == NULL) {
        PKCS7err(PKCS7_F_PKCS7_ENCODE_RINFO, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (EVP_PKEY_encrypt(pctx, ek, &eklen, key, keylen) <= 0)
        goto err;

    ASN1_STRING_set0(ri->enc_key, ek, eklen);
    ek = NULL;

    ret = 1;

 err:
    if (pkey)
        EVP_PKEY_free(pkey);
    if (pctx)
        EVP_PKEY_CTX_free(pctx);
    if (ek)
        OPENSSL_free(ek);
    return ret;

}

static int pkcs7_decrypt_rinfo(unsigned char **pek, int *peklen,
                               PKCS7_RECIP_INFO *ri, EVP_PKEY *pkey)
{
    EVP_PKEY_CTX *pctx = NULL;
    unsigned char *ek = NULL;
    size_t eklen;

    int ret = -1;

    pctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!pctx)
        return -1;

    if (EVP_PKEY_decrypt_init(pctx) <= 0)
        goto err;

    if (EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_DECRYPT,
                          EVP_PKEY_CTRL_PKCS7_DECRYPT, 0, ri) <= 0) {
        PKCS7err(PKCS7_F_PKCS7_DECRYPT_RINFO, PKCS7_R_CTRL_ERROR);
        goto err;
    }

    if (EVP_PKEY_decrypt(pctx, NULL, &eklen,
                         ri->enc_key->data, ri->enc_key->length) <= 0)
        goto err;

    ek = OPENSSL_malloc(eklen);

    if (ek == NULL) {
        PKCS7err(PKCS7_F_PKCS7_DECRYPT_RINFO, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (EVP_PKEY_decrypt(pctx, ek, &eklen,
                         ri->enc_key->data, ri->enc_key->length) <= 0) {
        ret = 0;
        PKCS7err(PKCS7_F_PKCS7_DECRYPT_RINFO, ERR_R_EVP_LIB);
        goto err;
    }

    ret = 1;

    if (*pek) {
        OPENSSL_cleanse(*pek, *peklen);
        OPENSSL_free(*pek);
    }

    *pek = ek;
    *peklen = eklen;

 err:
    if (pctx)
        EVP_PKEY_CTX_free(pctx);
    if (!ret && ek)
        OPENSSL_free(ek);

    return ret;
}

BIO *PKCS7_dataInit(PKCS7 *p7, BIO *bio)
{
    int i;
    BIO *out = NULL, *btmp = NULL;
    X509_ALGOR *xa = NULL;
    const EVP_CIPHER *evp_cipher = NULL;
    STACK_OF(X509_ALGOR) *md_sk = NULL;
    STACK_OF(PKCS7_RECIP_INFO) *rsk = NULL;
    X509_ALGOR *xalg = NULL;
    PKCS7_RECIP_INFO *ri = NULL;
    ASN1_OCTET_STRING *os = NULL;

    if (p7 == NULL) {
        PKCS7err(PKCS7_F_PKCS7_DATAINIT, PKCS7_R_INVALID_NULL_POINTER);
        return NULL;
    }
    /*
     * The content field in the PKCS7 ContentInfo is optional, but that really
     * only applies to inner content (precisely, detached signatures).
     *
     * When reading content, missing outer content is therefore treated as an
     * error.
     *
     * When creating content, PKCS7_content_new() must be called before
     * calling this method, so a NULL p7->d is always an error.
     */
    if (p7->d.ptr == NULL) {
        PKCS7err(PKCS7_F_PKCS7_DATAINIT, PKCS7_R_NO_CONTENT);
        return NULL;
    }

    i = OBJ_obj2nid(p7->type);
    p7->state = PKCS7_S_HEADER;

    switch (i) {
    case NID_pkcs7_signed:
        md_sk = p7->d.sign->md_algs;
        os = PKCS7_get_octet_string(p7->d.sign->contents);
        break;
    case NID_pkcs7_signedAndEnveloped:
        rsk = p7->d.signed_and_enveloped->recipientinfo;
        md_sk = p7->d.signed_and_enveloped->md_algs;
        xalg = p7->d.signed_and_enveloped->enc_data->algorithm;
        evp_cipher = p7->d.signed_and_enveloped->enc_data->cipher;
        if (evp_cipher == NULL) {
            PKCS7err(PKCS7_F_PKCS7_DATAINIT, PKCS7_R_CIPHER_NOT_INITIALIZED);
            goto err;
        }
        break;
    case NID_pkcs7_enveloped:
        rsk = p7->d.enveloped->recipientinfo;
        xalg = p7->d.enveloped->enc_data->algorithm;
        evp_cipher = p7->d.enveloped->enc_data->cipher;
        if (evp_cipher == NULL) {
            PKCS7err(PKCS7_F_PKCS7_DATAINIT, PKCS7_R_CIPHER_NOT_INITIALIZED);
            goto err;
        }
        break;
    case NID_pkcs7_digest:
        xa = p7->d.digest->md;
        os = PKCS7_get_octet_string(p7->d.digest->contents);
        break;
    case NID_pkcs7_data:
        break;
    default:
        PKCS7err(PKCS7_F_PKCS7_DATAINIT, PKCS7_R_UNSUPPORTED_CONTENT_TYPE);
        goto err;
    }

    for (i = 0; i < sk_X509_ALGOR_num(md_sk); i++)
        if (!PKCS7_bio_add_digest(&out, sk_X509_ALGOR_value(md_sk, i)))
            goto err;

    if (xa && !PKCS7_bio_add_digest(&out, xa))
        goto err;

    if (evp_cipher != NULL) {
        unsigned char key[EVP_MAX_KEY_LENGTH];
        unsigned char iv[EVP_MAX_IV_LENGTH];
        int keylen, ivlen;
        EVP_CIPHER_CTX *ctx;

        if ((btmp = BIO_new(BIO_f_cipher())) == NULL) {
            PKCS7err(PKCS7_F_PKCS7_DATAINIT, ERR_R_BIO_LIB);
            goto err;
        }
        BIO_get_cipher_ctx(btmp, &ctx);
        keylen = EVP_CIPHER_key_length(evp_cipher);
        ivlen = EVP_CIPHER_iv_length(evp_cipher);
        xalg->algorithm = OBJ_nid2obj(EVP_CIPHER_type(evp_cipher));
        if (ivlen > 0)
            if (RAND_bytes(iv, ivlen) <= 0)
                goto err;
        if (EVP_CipherInit_ex(ctx, evp_cipher, NULL, NULL, NULL, 1) <= 0)
            goto err;
        if (EVP_CIPHER_CTX_rand_key(ctx, key) <= 0)
            goto err;
        if (EVP_CipherInit_ex(ctx, NULL, NULL, key, iv, 1) <= 0)
            goto err;

        if (ivlen > 0) {
            if (xalg->parameter == NULL) {
                xalg->parameter = ASN1_TYPE_new();
                if (xalg->parameter == NULL)
                    goto err;
            }
            if (EVP_CIPHER_param_to_asn1(ctx, xalg->parameter) < 0)
                goto err;
        }

        /* Lets do the pub key stuff :-) */
        for (i = 0; i < sk_PKCS7_RECIP_INFO_num(rsk); i++) {
            ri = sk_PKCS7_RECIP_INFO_value(rsk, i);
            if (pkcs7_encode_rinfo(ri, key, keylen) <= 0)
                goto err;
        }
        OPENSSL_cleanse(key, keylen);

        if (out == NULL)
            out = btmp;
        else
            BIO_push(out, btmp);
        btmp = NULL;
    }

    if (bio == NULL) {
        if (PKCS7_is_detached(p7)) {
            bio = BIO_new(BIO_s_null());
        } else if (os && os->length > 0) {
            bio = BIO_new_mem_buf(os->data, os->length);
        } else {
            bio = BIO_new(BIO_s_mem());
            if (bio == NULL)
                goto err;
            BIO_set_mem_eof_return(bio, 0);
        }
        if (bio == NULL)
            goto err;
    }
    if (out)
        BIO_push(out, bio);
    else
        out = bio;
    bio = NULL;
    if (0) {
 err:
        if (out != NULL)
            BIO_free_all(out);
        if (btmp != NULL)
            BIO_free_all(btmp);
        out = NULL;
    }
    return (out);
}

static int pkcs7_cmp_ri(PKCS7_RECIP_INFO *ri, X509 *pcert)
{
    int ret;
    ret = X509_NAME_cmp(ri->issuer_and_serial->issuer,
                        pcert->cert_info->issuer);
    if (ret)
        return ret;
    return M_ASN1_INTEGER_cmp(pcert->cert_info->serialNumber,
                              ri->issuer_and_serial->serial);
}

/* int */
BIO *PKCS7_dataDecode(PKCS7 *p7, EVP_PKEY *pkey, BIO *in_bio, X509 *pcert)
{
    int i, j;
    BIO *out = NULL, *btmp = NULL, *etmp = NULL, *bio = NULL;
    X509_ALGOR *xa;
    ASN1_OCTET_STRING *data_body = NULL;
    const EVP_MD *evp_md;
    const EVP_CIPHER *evp_cipher = NULL;
    EVP_CIPHER_CTX *evp_ctx = NULL;
    X509_ALGOR *enc_alg = NULL;
    STACK_OF(X509_ALGOR) *md_sk = NULL;
    STACK_OF(PKCS7_RECIP_INFO) *rsk = NULL;
    PKCS7_RECIP_INFO *ri = NULL;
    unsigned char *ek = NULL, *tkey = NULL;
    int eklen = 0, tkeylen = 0;

    if (p7 == NULL) {
        PKCS7err(PKCS7_F_PKCS7_DATADECODE, PKCS7_R_INVALID_NULL_POINTER);
        return NULL;
    }

    if (p7->d.ptr == NULL) {
        PKCS7err(PKCS7_F_PKCS7_DATADECODE, PKCS7_R_NO_CONTENT);
        return NULL;
    }

    i = OBJ_obj2nid(p7->type);
    p7->state = PKCS7_S_HEADER;

    switch (i) {
    case NID_pkcs7_signed:
        /*
         * p7->d.sign->contents is a PKCS7 structure consisting of a contentType
         * field and optional content.
         * data_body is NULL if that structure has no (=detached) content
         * or if the contentType is wrong (i.e., not "data").
         */
        data_body = PKCS7_get_octet_string(p7->d.sign->contents);
        if (!PKCS7_is_detached(p7) && data_body == NULL) {
            PKCS7err(PKCS7_F_PKCS7_DATADECODE,
                     PKCS7_R_INVALID_SIGNED_DATA_TYPE);
            goto err;
        }
        md_sk = p7->d.sign->md_algs;
        break;
    case NID_pkcs7_signedAndEnveloped:
        rsk = p7->d.signed_and_enveloped->recipientinfo;
        md_sk = p7->d.signed_and_enveloped->md_algs;
        /* data_body is NULL if the optional EncryptedContent is missing. */
        data_body = p7->d.signed_and_enveloped->enc_data->enc_data;
        enc_alg = p7->d.signed_and_enveloped->enc_data->algorithm;
        evp_cipher = EVP_get_cipherbyobj(enc_alg->algorithm);
        if (evp_cipher == NULL) {
            PKCS7err(PKCS7_F_PKCS7_DATADECODE,
                     PKCS7_R_UNSUPPORTED_CIPHER_TYPE);
            goto err;
        }
        break;
    case NID_pkcs7_enveloped:
        rsk = p7->d.enveloped->recipientinfo;
        enc_alg = p7->d.enveloped->enc_data->algorithm;
        /* data_body is NULL if the optional EncryptedContent is missing. */
        data_body = p7->d.enveloped->enc_data->enc_data;
        evp_cipher = EVP_get_cipherbyobj(enc_alg->algorithm);
        if (evp_cipher == NULL) {
            PKCS7err(PKCS7_F_PKCS7_DATADECODE,
                     PKCS7_R_UNSUPPORTED_CIPHER_TYPE);
            goto err;
        }
        break;
    default:
        PKCS7err(PKCS7_F_PKCS7_DATADECODE, PKCS7_R_UNSUPPORTED_CONTENT_TYPE);
        goto err;
    }

    /* Detached content must be supplied via in_bio instead. */
    if (data_body == NULL && in_bio == NULL) {
        PKCS7err(PKCS7_F_PKCS7_DATADECODE, PKCS7_R_NO_CONTENT);
        goto err;
    }

    /* We will be checking the signature */
    if (md_sk != NULL) {
        for (i = 0; i < sk_X509_ALGOR_num(md_sk); i++) {
            xa = sk_X509_ALGOR_value(md_sk, i);
            if ((btmp = BIO_new(BIO_f_md())) == NULL) {
                PKCS7err(PKCS7_F_PKCS7_DATADECODE, ERR_R_BIO_LIB);
                goto err;
            }

            j = OBJ_obj2nid(xa->algorithm);
            evp_md = EVP_get_digestbynid(j);
            if (evp_md == NULL) {
                PKCS7err(PKCS7_F_PKCS7_DATADECODE,
                         PKCS7_R_UNKNOWN_DIGEST_TYPE);
                goto err;
            }

            BIO_set_md(btmp, evp_md);
            if (out == NULL)
                out = btmp;
            else
                BIO_push(out, btmp);
            btmp = NULL;
        }
    }

    if (evp_cipher != NULL) {
#if 0
        unsigned char key[EVP_MAX_KEY_LENGTH];
        unsigned char iv[EVP_MAX_IV_LENGTH];
        unsigned char *p;
        int keylen, ivlen;
        int max;
        X509_OBJECT ret;
#endif

        if ((etmp = BIO_new(BIO_f_cipher())) == NULL) {
            PKCS7err(PKCS7_F_PKCS7_DATADECODE, ERR_R_BIO_LIB);
            goto err;
        }

        /*
         * It was encrypted, we need to decrypt the secret key with the
         * private key
         */

        /*
         * Find the recipientInfo which matches the passed certificate (if
         * any)
         */

        if (pcert) {
            for (i = 0; i < sk_PKCS7_RECIP_INFO_num(rsk); i++) {
                ri = sk_PKCS7_RECIP_INFO_value(rsk, i);
                if (!pkcs7_cmp_ri(ri, pcert))
                    break;
                ri = NULL;
            }
            if (ri == NULL) {
                PKCS7err(PKCS7_F_PKCS7_DATADECODE,
                         PKCS7_R_NO_RECIPIENT_MATCHES_CERTIFICATE);
                goto err;
            }
        }

        /* If we haven't got a certificate try each ri in turn */
        if (pcert == NULL) {
            /*
             * Always attempt to decrypt all rinfo even after sucess as a
             * defence against MMA timing attacks.
             */
            for (i = 0; i < sk_PKCS7_RECIP_INFO_num(rsk); i++) {
                ri = sk_PKCS7_RECIP_INFO_value(rsk, i);

                if (pkcs7_decrypt_rinfo(&ek, &eklen, ri, pkey) < 0)
                    goto err;
                ERR_clear_error();
            }
        } else {
            /* Only exit on fatal errors, not decrypt failure */
            if (pkcs7_decrypt_rinfo(&ek, &eklen, ri, pkey) < 0)
                goto err;
            ERR_clear_error();
        }

        evp_ctx = NULL;
        BIO_get_cipher_ctx(etmp, &evp_ctx);
        if (EVP_CipherInit_ex(evp_ctx, evp_cipher, NULL, NULL, NULL, 0) <= 0)
            goto err;
        if (EVP_CIPHER_asn1_to_param(evp_ctx, enc_alg->parameter) < 0)
            goto err;
        /* Generate random key as MMA defence */
        tkeylen = EVP_CIPHER_CTX_key_length(evp_ctx);
        tkey = OPENSSL_malloc(tkeylen);
        if (!tkey)
            goto err;
        if (EVP_CIPHER_CTX_rand_key(evp_ctx, tkey) <= 0)
            goto err;
        if (ek == NULL) {
            ek = tkey;
            eklen = tkeylen;
            tkey = NULL;
        }

        if (eklen != EVP_CIPHER_CTX_key_length(evp_ctx)) {
            /*
             * Some S/MIME clients don't use the same key and effective key
             * length. The key length is determined by the size of the
             * decrypted RSA key.
             */
            if (!EVP_CIPHER_CTX_set_key_length(evp_ctx, eklen)) {
                /* Use random key as MMA defence */
                OPENSSL_cleanse(ek, eklen);
                OPENSSL_free(ek);
                ek = tkey;
                eklen = tkeylen;
                tkey = NULL;
            }
        }
        /* Clear errors so we don't leak information useful in MMA */
        ERR_clear_error();
        if (EVP_CipherInit_ex(evp_ctx, NULL, NULL, ek, NULL, 0) <= 0)
            goto err;

        if (ek) {
            OPENSSL_cleanse(ek, eklen);
            OPENSSL_free(ek);
            ek = NULL;
        }
        if (tkey) {
            OPENSSL_cleanse(tkey, tkeylen);
            OPENSSL_free(tkey);
            tkey = NULL;
        }

        if (out == NULL)
            out = etmp;
        else
            BIO_push(out, etmp);
        etmp = NULL;
    }
#if 1
    if (in_bio != NULL) {
        bio = in_bio;
    } else {
# if 0
        bio = BIO_new(BIO_s_mem());
        if (bio == NULL)
            goto err;
        /*
         * We need to set this so that when we have read all the data, the
         * encrypt BIO, if present, will read EOF and encode the last few
         * bytes
         */
        BIO_set_mem_eof_return(bio, 0);

        if (data_body->length > 0)
            BIO_write(bio, (char *)data_body->data, data_body->length);
# else
        if (data_body->length > 0)
            bio = BIO_new_mem_buf(data_body->data, data_body->length);
        else {
            bio = BIO_new(BIO_s_mem());
            if (bio == NULL)
                goto err;
            BIO_set_mem_eof_return(bio, 0);
        }
        if (bio == NULL)
            goto err;
# endif
    }
    BIO_push(out, bio);
    bio = NULL;
#endif
    if (0) {
 err:
        if (ek) {
            OPENSSL_cleanse(ek, eklen);
            OPENSSL_free(ek);
        }
        if (tkey) {
            OPENSSL_cleanse(tkey, tkeylen);
            OPENSSL_free(tkey);
        }
        if (out != NULL)
            BIO_free_all(out);
        if (btmp != NULL)
            BIO_free_all(btmp);
        if (etmp != NULL)
            BIO_free_all(etmp);
        if (bio != NULL)
            BIO_free_all(bio);
        out = NULL;
    }
    return (out);
}

static BIO *PKCS7_find_digest(EVP_MD_CTX **pmd, BIO *bio, int nid)
{
    for (;;) {
        bio = BIO_find_type(bio, BIO_TYPE_MD);
        if (bio == NULL) {
            PKCS7err(PKCS7_F_PKCS7_FIND_DIGEST,
                     PKCS7_R_UNABLE_TO_FIND_MESSAGE_DIGEST);
            return NULL;
        }
        BIO_get_md_ctx(bio, pmd);
        if (*pmd == NULL) {
            PKCS7err(PKCS7_F_PKCS7_FIND_DIGEST, ERR_R_INTERNAL_ERROR);
            return NULL;
        }
        if (EVP_MD_CTX_type(*pmd) == nid)
            return bio;
        bio = BIO_next(bio);
    }
    return NULL;
}

static int do_pkcs7_signed_attrib(PKCS7_SIGNER_INFO *si, EVP_MD_CTX *mctx)
{
    unsigned char md_data[EVP_MAX_MD_SIZE];
    unsigned int md_len;

    /* Add signing time if not already present */
    if (!PKCS7_get_signed_attribute(si, NID_pkcs9_signingTime)) {
        if (!PKCS7_add0_attrib_signing_time(si, NULL)) {
            PKCS7err(PKCS7_F_DO_PKCS7_SIGNED_ATTRIB, ERR_R_MALLOC_FAILURE);
            return 0;
        }
    }

    /* Add digest */
    if (!EVP_DigestFinal_ex(mctx, md_data, &md_len)) {
        PKCS7err(PKCS7_F_DO_PKCS7_SIGNED_ATTRIB, ERR_R_EVP_LIB);
        return 0;
    }
    if (!PKCS7_add1_attrib_digest(si, md_data, md_len)) {
        PKCS7err(PKCS7_F_DO_PKCS7_SIGNED_ATTRIB, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    /* Now sign the attributes */
    if (!PKCS7_SIGNER_INFO_sign(si))
        return 0;

    return 1;
}

int PKCS7_dataFinal(PKCS7 *p7, BIO *bio)
{
    int ret = 0;
    int i, j;
    BIO *btmp;
    PKCS7_SIGNER_INFO *si;
    EVP_MD_CTX *mdc, ctx_tmp;
    STACK_OF(X509_ATTRIBUTE) *sk;
    STACK_OF(PKCS7_SIGNER_INFO) *si_sk = NULL;
    ASN1_OCTET_STRING *os = NULL;

    if (p7 == NULL) {
        PKCS7err(PKCS7_F_PKCS7_DATAFINAL, PKCS7_R_INVALID_NULL_POINTER);
        return 0;
    }

    if (p7->d.ptr == NULL) {
        PKCS7err(PKCS7_F_PKCS7_DATAFINAL, PKCS7_R_NO_CONTENT);
        return 0;
    }

    EVP_MD_CTX_init(&ctx_tmp);
    i = OBJ_obj2nid(p7->type);
    p7->state = PKCS7_S_HEADER;

    switch (i) {
    case NID_pkcs7_data:
        os = p7->d.data;
        break;
    case NID_pkcs7_signedAndEnveloped:
        /* XXXXXXXXXXXXXXXX */
        si_sk = p7->d.signed_and_enveloped->signer_info;
        os = p7->d.signed_and_enveloped->enc_data->enc_data;
        if (!os) {
            os = M_ASN1_OCTET_STRING_new();
            if (!os) {
                PKCS7err(PKCS7_F_PKCS7_DATAFINAL, ERR_R_MALLOC_FAILURE);
                goto err;
            }
            p7->d.signed_and_enveloped->enc_data->enc_data = os;
        }
        break;
    case NID_pkcs7_enveloped:
        /* XXXXXXXXXXXXXXXX */
        os = p7->d.enveloped->enc_data->enc_data;
        if (!os) {
            os = M_ASN1_OCTET_STRING_new();
            if (!os) {
                PKCS7err(PKCS7_F_PKCS7_DATAFINAL, ERR_R_MALLOC_FAILURE);
                goto err;
            }
            p7->d.enveloped->enc_data->enc_data = os;
        }
        break;
    case NID_pkcs7_signed:
        si_sk = p7->d.sign->signer_info;
        os = PKCS7_get_octet_string(p7->d.sign->contents);
        /* If detached data then the content is excluded */
        if (PKCS7_type_is_data(p7->d.sign->contents) && p7->detached) {
            M_ASN1_OCTET_STRING_free(os);
            os = NULL;
            p7->d.sign->contents->d.data = NULL;
        }
        break;

    case NID_pkcs7_digest:
        os = PKCS7_get_octet_string(p7->d.digest->contents);
        /* If detached data then the content is excluded */
        if (PKCS7_type_is_data(p7->d.digest->contents) && p7->detached) {
            M_ASN1_OCTET_STRING_free(os);
            os = NULL;
            p7->d.digest->contents->d.data = NULL;
        }
        break;

    default:
        PKCS7err(PKCS7_F_PKCS7_DATAFINAL, PKCS7_R_UNSUPPORTED_CONTENT_TYPE);
        goto err;
    }

    if (si_sk != NULL) {
        for (i = 0; i < sk_PKCS7_SIGNER_INFO_num(si_sk); i++) {
            si = sk_PKCS7_SIGNER_INFO_value(si_sk, i);
            if (si->pkey == NULL)
                continue;

            j = OBJ_obj2nid(si->digest_alg->algorithm);

            btmp = bio;

            btmp = PKCS7_find_digest(&mdc, btmp, j);

            if (btmp == NULL)
                goto err;

            /*
             * We now have the EVP_MD_CTX, lets do the signing.
             */
            if (!EVP_MD_CTX_copy_ex(&ctx_tmp, mdc))
                goto err;

            sk = si->auth_attr;

            /*
             * If there are attributes, we add the digest attribute and only
             * sign the attributes
             */
            if (sk_X509_ATTRIBUTE_num(sk) > 0) {
                if (!do_pkcs7_signed_attrib(si, &ctx_tmp))
                    goto err;
            } else {
                unsigned char *abuf = NULL;
                unsigned int abuflen;
                abuflen = EVP_PKEY_size(si->pkey);
                abuf = OPENSSL_malloc(abuflen);
                if (!abuf)
                    goto err;

                if (!EVP_SignFinal(&ctx_tmp, abuf, &abuflen, si->pkey)) {
                    PKCS7err(PKCS7_F_PKCS7_DATAFINAL, ERR_R_EVP_LIB);
                    goto err;
                }
                ASN1_STRING_set0(si->enc_digest, abuf, abuflen);
            }
        }
    } else if (i == NID_pkcs7_digest) {
        unsigned char md_data[EVP_MAX_MD_SIZE];
        unsigned int md_len;
        if (!PKCS7_find_digest(&mdc, bio,
                               OBJ_obj2nid(p7->d.digest->md->algorithm)))
            goto err;
        if (!EVP_DigestFinal_ex(mdc, md_data, &md_len))
            goto err;
        M_ASN1_OCTET_STRING_set(p7->d.digest->digest, md_data, md_len);
    }

    if (!PKCS7_is_detached(p7)) {
        /*
         * NOTE(emilia): I think we only reach os == NULL here because detached
         * digested data support is broken.
         */
        if (os == NULL)
            goto err;
        if (!(os->flags & ASN1_STRING_FLAG_NDEF)) {
            char *cont;
            long contlen;
            btmp = BIO_find_type(bio, BIO_TYPE_MEM);
            if (btmp == NULL) {
                PKCS7err(PKCS7_F_PKCS7_DATAFINAL, PKCS7_R_UNABLE_TO_FIND_MEM_BIO);
                goto err;
            }
            contlen = BIO_get_mem_data(btmp, &cont);
            /*
             * Mark the BIO read only then we can use its copy of the data
             * instead of making an extra copy.
             */
            BIO_set_flags(btmp, BIO_FLAGS_MEM_RDONLY);
            BIO_set_mem_eof_return(btmp, 0);
            ASN1_STRING_set0(os, (unsigned char *)cont, contlen);
        }
    }
    ret = 1;
 err:
    EVP_MD_CTX_cleanup(&ctx_tmp);
    return (ret);
}

int PKCS7_SIGNER_INFO_sign(PKCS7_SIGNER_INFO *si)
{
    EVP_MD_CTX mctx;
    EVP_PKEY_CTX *pctx;
    unsigned char *abuf = NULL;
    int alen;
    size_t siglen;
    const EVP_MD *md = NULL;

    md = EVP_get_digestbyobj(si->digest_alg->algorithm);
    if (md == NULL)
        return 0;

    EVP_MD_CTX_init(&mctx);
    if (EVP_DigestSignInit(&mctx, &pctx, md, NULL, si->pkey) <= 0)
        goto err;

    if (EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_SIGN,
                          EVP_PKEY_CTRL_PKCS7_SIGN, 0, si) <= 0) {
        PKCS7err(PKCS7_F_PKCS7_SIGNER_INFO_SIGN, PKCS7_R_CTRL_ERROR);
        goto err;
    }

    alen = ASN1_item_i2d((ASN1_VALUE *)si->auth_attr, &abuf,
                         ASN1_ITEM_rptr(PKCS7_ATTR_SIGN));
    if (!abuf)
        goto err;
    if (EVP_DigestSignUpdate(&mctx, abuf, alen) <= 0)
        goto err;
    OPENSSL_free(abuf);
    abuf = NULL;
    if (EVP_DigestSignFinal(&mctx, NULL, &siglen) <= 0)
        goto err;
    abuf = OPENSSL_malloc(siglen);
    if (!abuf)
        goto err;
    if (EVP_DigestSignFinal(&mctx, abuf, &siglen) <= 0)
        goto err;

    if (EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_SIGN,
                          EVP_PKEY_CTRL_PKCS7_SIGN, 1, si) <= 0) {
        PKCS7err(PKCS7_F_PKCS7_SIGNER_INFO_SIGN, PKCS7_R_CTRL_ERROR);
        goto err;
    }

    EVP_MD_CTX_cleanup(&mctx);

    ASN1_STRING_set0(si->enc_digest, abuf, siglen);

    return 1;

 err:
    if (abuf)
        OPENSSL_free(abuf);
    EVP_MD_CTX_cleanup(&mctx);
    return 0;

}

int PKCS7_dataVerify(X509_STORE *cert_store, X509_STORE_CTX *ctx, BIO *bio,
                     PKCS7 *p7, PKCS7_SIGNER_INFO *si)
{
    PKCS7_ISSUER_AND_SERIAL *ias;
    int ret = 0, i;
    STACK_OF(X509) *cert;
    X509 *x509;

    if (p7 == NULL) {
        PKCS7err(PKCS7_F_PKCS7_DATAVERIFY, PKCS7_R_INVALID_NULL_POINTER);
        return 0;
    }

    if (p7->d.ptr == NULL) {
        PKCS7err(PKCS7_F_PKCS7_DATAVERIFY, PKCS7_R_NO_CONTENT);
        return 0;
    }

    if (PKCS7_type_is_signed(p7)) {
        cert = p7->d.sign->cert;
    } else if (PKCS7_type_is_signedAndEnveloped(p7)) {
        cert = p7->d.signed_and_enveloped->cert;
    } else {
        PKCS7err(PKCS7_F_PKCS7_DATAVERIFY, PKCS7_R_WRONG_PKCS7_TYPE);
        goto err;
    }
    /* XXXXXXXXXXXXXXXXXXXXXXX */
    ias = si->issuer_and_serial;

    x509 = X509_find_by_issuer_and_serial(cert, ias->issuer, ias->serial);

    /* were we able to find the cert in passed to us */
    if (x509 == NULL) {
        PKCS7err(PKCS7_F_PKCS7_DATAVERIFY,
                 PKCS7_R_UNABLE_TO_FIND_CERTIFICATE);
        goto err;
    }

    /* Lets verify */
    if (!X509_STORE_CTX_init(ctx, cert_store, x509, cert)) {
        PKCS7err(PKCS7_F_PKCS7_DATAVERIFY, ERR_R_X509_LIB);
        goto err;
    }
    X509_STORE_CTX_set_purpose(ctx, X509_PURPOSE_SMIME_SIGN);
    i = X509_verify_cert(ctx);
    if (i <= 0) {
        PKCS7err(PKCS7_F_PKCS7_DATAVERIFY, ERR_R_X509_LIB);
        X509_STORE_CTX_cleanup(ctx);
        goto err;
    }
    X509_STORE_CTX_cleanup(ctx);

    return PKCS7_signatureVerify(bio, p7, si, x509);
 err:
    return ret;
}

int PKCS7_signatureVerify(BIO *bio, PKCS7 *p7, PKCS7_SIGNER_INFO *si,
                          X509 *x509)
{
    ASN1_OCTET_STRING *os;
    EVP_MD_CTX mdc_tmp, *mdc;
    int ret = 0, i;
    int md_type;
    STACK_OF(X509_ATTRIBUTE) *sk;
    BIO *btmp;
    EVP_PKEY *pkey;

    EVP_MD_CTX_init(&mdc_tmp);

    if (!PKCS7_type_is_signed(p7) && !PKCS7_type_is_signedAndEnveloped(p7)) {
        PKCS7err(PKCS7_F_PKCS7_SIGNATUREVERIFY, PKCS7_R_WRONG_PKCS7_TYPE);
        goto err;
    }

    md_type = OBJ_obj2nid(si->digest_alg->algorithm);

    btmp = bio;
    for (;;) {
        if ((btmp == NULL) ||
            ((btmp = BIO_find_type(btmp, BIO_TYPE_MD)) == NULL)) {
            PKCS7err(PKCS7_F_PKCS7_SIGNATUREVERIFY,
                     PKCS7_R_UNABLE_TO_FIND_MESSAGE_DIGEST);
            goto err;
        }
        BIO_get_md_ctx(btmp, &mdc);
        if (mdc == NULL) {
            PKCS7err(PKCS7_F_PKCS7_SIGNATUREVERIFY, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        if (EVP_MD_CTX_type(mdc) == md_type)
            break;
        /*
         * Workaround for some broken clients that put the signature OID
         * instead of the digest OID in digest_alg->algorithm
         */
        if (EVP_MD_pkey_type(EVP_MD_CTX_md(mdc)) == md_type)
            break;
        btmp = BIO_next(btmp);
    }

    /*
     * mdc is the digest ctx that we want, unless there are attributes, in
     * which case the digest is the signed attributes
     */
    if (!EVP_MD_CTX_copy_ex(&mdc_tmp, mdc))
        goto err;

    sk = si->auth_attr;
    if ((sk != NULL) && (sk_X509_ATTRIBUTE_num(sk) != 0)) {
        unsigned char md_dat[EVP_MAX_MD_SIZE], *abuf = NULL;
        unsigned int md_len;
        int alen;
        ASN1_OCTET_STRING *message_digest;

        if (!EVP_DigestFinal_ex(&mdc_tmp, md_dat, &md_len))
            goto err;
        message_digest = PKCS7_digest_from_attributes(sk);
        if (!message_digest) {
            PKCS7err(PKCS7_F_PKCS7_SIGNATUREVERIFY,
                     PKCS7_R_UNABLE_TO_FIND_MESSAGE_DIGEST);
            goto err;
        }
        if ((message_digest->length != (int)md_len) ||
            (memcmp(message_digest->data, md_dat, md_len))) {
#if 0
            {
                int ii;
                for (ii = 0; ii < message_digest->length; ii++)
                    printf("%02X", message_digest->data[ii]);
                printf(" sent\n");
                for (ii = 0; ii < md_len; ii++)
                    printf("%02X", md_dat[ii]);
                printf(" calc\n");
            }
#endif
            PKCS7err(PKCS7_F_PKCS7_SIGNATUREVERIFY, PKCS7_R_DIGEST_FAILURE);
            ret = -1;
            goto err;
        }

        if (!EVP_VerifyInit_ex(&mdc_tmp, EVP_get_digestbynid(md_type), NULL))
            goto err;

        alen = ASN1_item_i2d((ASN1_VALUE *)sk, &abuf,
                             ASN1_ITEM_rptr(PKCS7_ATTR_VERIFY));
        if (alen <= 0) {
            PKCS7err(PKCS7_F_PKCS7_SIGNATUREVERIFY, ERR_R_ASN1_LIB);
            ret = -1;
            goto err;
        }
        if (!EVP_VerifyUpdate(&mdc_tmp, abuf, alen))
            goto err;

        OPENSSL_free(abuf);
    }

    os = si->enc_digest;
    pkey = X509_get_pubkey(x509);
    if (!pkey) {
        ret = -1;
        goto err;
    }

    i = EVP_VerifyFinal(&mdc_tmp, os->data, os->length, pkey);
    EVP_PKEY_free(pkey);
    if (i <= 0) {
        PKCS7err(PKCS7_F_PKCS7_SIGNATUREVERIFY, PKCS7_R_SIGNATURE_FAILURE);
        ret = -1;
        goto err;
    } else
        ret = 1;
 err:
    EVP_MD_CTX_cleanup(&mdc_tmp);
    return (ret);
}

PKCS7_ISSUER_AND_SERIAL *PKCS7_get_issuer_and_serial(PKCS7 *p7, int idx)
{
    STACK_OF(PKCS7_RECIP_INFO) *rsk;
    PKCS7_RECIP_INFO *ri;
    int i;

    i = OBJ_obj2nid(p7->type);
    if (i != NID_pkcs7_signedAndEnveloped)
        return NULL;
    if (p7->d.signed_and_enveloped == NULL)
        return NULL;
    rsk = p7->d.signed_and_enveloped->recipientinfo;
    if (rsk == NULL)
        return NULL;
    if (sk_PKCS7_RECIP_INFO_num(rsk) <= idx)
        return (NULL);
    ri = sk_PKCS7_RECIP_INFO_value(rsk, idx);
    return (ri->issuer_and_serial);
}

ASN1_TYPE *PKCS7_get_signed_attribute(PKCS7_SIGNER_INFO *si, int nid)
{
    return (get_attribute(si->auth_attr, nid));
}

ASN1_TYPE *PKCS7_get_attribute(PKCS7_SIGNER_INFO *si, int nid)
{
    return (get_attribute(si->unauth_attr, nid));
}

static ASN1_TYPE *get_attribute(STACK_OF(X509_ATTRIBUTE) *sk, int nid)
{
    int i;
    X509_ATTRIBUTE *xa;
    ASN1_OBJECT *o;

    o = OBJ_nid2obj(nid);
    if (!o || !sk)
        return (NULL);
    for (i = 0; i < sk_X509_ATTRIBUTE_num(sk); i++) {
        xa = sk_X509_ATTRIBUTE_value(sk, i);
        if (OBJ_cmp(xa->object, o) == 0) {
            if (!xa->single && sk_ASN1_TYPE_num(xa->value.set))
                return (sk_ASN1_TYPE_value(xa->value.set, 0));
            else
                return (NULL);
        }
    }
    return (NULL);
}

ASN1_OCTET_STRING *PKCS7_digest_from_attributes(STACK_OF(X509_ATTRIBUTE) *sk)
{
    ASN1_TYPE *astype;
    if (!(astype = get_attribute(sk, NID_pkcs9_messageDigest)))
        return NULL;
    return astype->value.octet_string;
}

int PKCS7_set_signed_attributes(PKCS7_SIGNER_INFO *p7si,
                                STACK_OF(X509_ATTRIBUTE) *sk)
{
    int i;

    if (p7si->auth_attr != NULL)
        sk_X509_ATTRIBUTE_pop_free(p7si->auth_attr, X509_ATTRIBUTE_free);
    p7si->auth_attr = sk_X509_ATTRIBUTE_dup(sk);
    if (p7si->auth_attr == NULL)
        return 0;
    for (i = 0; i < sk_X509_ATTRIBUTE_num(sk); i++) {
        if ((sk_X509_ATTRIBUTE_set(p7si->auth_attr, i,
                                   X509_ATTRIBUTE_dup(sk_X509_ATTRIBUTE_value
                                                      (sk, i))))
            == NULL)
            return (0);
    }
    return (1);
}

int PKCS7_set_attributes(PKCS7_SIGNER_INFO *p7si,
                         STACK_OF(X509_ATTRIBUTE) *sk)
{
    int i;

    if (p7si->unauth_attr != NULL)
        sk_X509_ATTRIBUTE_pop_free(p7si->unauth_attr, X509_ATTRIBUTE_free);
    p7si->unauth_attr = sk_X509_ATTRIBUTE_dup(sk);
    if (p7si->unauth_attr == NULL)
        return 0;
    for (i = 0; i < sk_X509_ATTRIBUTE_num(sk); i++) {
        if ((sk_X509_ATTRIBUTE_set(p7si->unauth_attr, i,
                                   X509_ATTRIBUTE_dup(sk_X509_ATTRIBUTE_value
                                                      (sk, i))))
            == NULL)
            return (0);
    }
    return (1);
}

int PKCS7_add_signed_attribute(PKCS7_SIGNER_INFO *p7si, int nid, int atrtype,
                               void *value)
{
    return (add_attribute(&(p7si->auth_attr), nid, atrtype, value));
}

int PKCS7_add_attribute(PKCS7_SIGNER_INFO *p7si, int nid, int atrtype,
                        void *value)
{
    return (add_attribute(&(p7si->unauth_attr), nid, atrtype, value));
}

static int add_attribute(STACK_OF(X509_ATTRIBUTE) **sk, int nid, int atrtype,
                         void *value)
{
    X509_ATTRIBUTE *attr = NULL;

    if (*sk == NULL) {
        *sk = sk_X509_ATTRIBUTE_new_null();
        if (*sk == NULL)
            return 0;
 new_attrib:
        if (!(attr = X509_ATTRIBUTE_create(nid, atrtype, value)))
            return 0;
        if (!sk_X509_ATTRIBUTE_push(*sk, attr)) {
            X509_ATTRIBUTE_free(attr);
            return 0;
        }
    } else {
        int i;

        for (i = 0; i < sk_X509_ATTRIBUTE_num(*sk); i++) {
            attr = sk_X509_ATTRIBUTE_value(*sk, i);
            if (OBJ_obj2nid(attr->object) == nid) {
                X509_ATTRIBUTE_free(attr);
                attr = X509_ATTRIBUTE_create(nid, atrtype, value);
                if (attr == NULL)
                    return 0;
                if (!sk_X509_ATTRIBUTE_set(*sk, i, attr)) {
                    X509_ATTRIBUTE_free(attr);
                    return 0;
                }
                goto end;
            }
        }
        goto new_attrib;
    }
 end:
    return (1);
}
/* crypto/pkcs7/pk7_lib.c */
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
// #include "objects.h"
// #include "x509.h"
#include "asn1_locl.h"

long PKCS7_ctrl(PKCS7 *p7, int cmd, long larg, char *parg)
{
    int nid;
    long ret;

    nid = OBJ_obj2nid(p7->type);

    switch (cmd) {
    /* NOTE(emilia): does not support detached digested data. */
    case PKCS7_OP_SET_DETACHED_SIGNATURE:
        if (nid == NID_pkcs7_signed) {
            ret = p7->detached = (int)larg;
            if (ret && PKCS7_type_is_data(p7->d.sign->contents)) {
                ASN1_OCTET_STRING *os;
                os = p7->d.sign->contents->d.data;
                ASN1_OCTET_STRING_free(os);
                p7->d.sign->contents->d.data = NULL;
            }
        } else {
            PKCS7err(PKCS7_F_PKCS7_CTRL,
                     PKCS7_R_OPERATION_NOT_SUPPORTED_ON_THIS_TYPE);
            ret = 0;
        }
        break;
    case PKCS7_OP_GET_DETACHED_SIGNATURE:
        if (nid == NID_pkcs7_signed) {
            if (!p7->d.sign || !p7->d.sign->contents->d.ptr)
                ret = 1;
            else
                ret = 0;

            p7->detached = ret;
        } else {
            PKCS7err(PKCS7_F_PKCS7_CTRL,
                     PKCS7_R_OPERATION_NOT_SUPPORTED_ON_THIS_TYPE);
            ret = 0;
        }

        break;
    default:
        PKCS7err(PKCS7_F_PKCS7_CTRL, PKCS7_R_UNKNOWN_OPERATION);
        ret = 0;
    }
    return (ret);
}

int PKCS7_content_new(PKCS7 *p7, int type)
{
    PKCS7 *ret = NULL;

    if ((ret = PKCS7_new()) == NULL)
        goto err;
    if (!PKCS7_set_type(ret, type))
        goto err;
    if (!PKCS7_set_content(p7, ret))
        goto err;

    return (1);
 err:
    if (ret != NULL)
        PKCS7_free(ret);
    return (0);
}

int PKCS7_set_content(PKCS7 *p7, PKCS7 *p7_data)
{
    int i;

    i = OBJ_obj2nid(p7->type);
    switch (i) {
    case NID_pkcs7_signed:
        if (p7->d.sign->contents != NULL)
            PKCS7_free(p7->d.sign->contents);
        p7->d.sign->contents = p7_data;
        break;
    case NID_pkcs7_digest:
        if (p7->d.digest->contents != NULL)
            PKCS7_free(p7->d.digest->contents);
        p7->d.digest->contents = p7_data;
        break;
    case NID_pkcs7_data:
    case NID_pkcs7_enveloped:
    case NID_pkcs7_signedAndEnveloped:
    case NID_pkcs7_encrypted:
    default:
        PKCS7err(PKCS7_F_PKCS7_SET_CONTENT, PKCS7_R_UNSUPPORTED_CONTENT_TYPE);
        goto err;
    }
    return (1);
 err:
    return (0);
}

int PKCS7_set_type(PKCS7 *p7, int type)
{
    ASN1_OBJECT *obj;

    /*
     * PKCS7_content_free(p7);
     */
    obj = OBJ_nid2obj(type);    /* will not fail */

    switch (type) {
    case NID_pkcs7_signed:
        p7->type = obj;
        if ((p7->d.sign = PKCS7_SIGNED_new()) == NULL)
            goto err;
        if (!ASN1_INTEGER_set(p7->d.sign->version, 1)) {
            PKCS7_SIGNED_free(p7->d.sign);
            p7->d.sign = NULL;
            goto err;
        }
        break;
    case NID_pkcs7_data:
        p7->type = obj;
        if ((p7->d.data = M_ASN1_OCTET_STRING_new()) == NULL)
            goto err;
        break;
    case NID_pkcs7_signedAndEnveloped:
        p7->type = obj;
        if ((p7->d.signed_and_enveloped = PKCS7_SIGN_ENVELOPE_new())
            == NULL)
            goto err;
        if (!ASN1_INTEGER_set(p7->d.signed_and_enveloped->version, 1))
            goto err;
        p7->d.signed_and_enveloped->enc_data->content_type
            = OBJ_nid2obj(NID_pkcs7_data);
        break;
    case NID_pkcs7_enveloped:
        p7->type = obj;
        if ((p7->d.enveloped = PKCS7_ENVELOPE_new())
            == NULL)
            goto err;
        if (!ASN1_INTEGER_set(p7->d.enveloped->version, 0))
            goto err;
        p7->d.enveloped->enc_data->content_type = OBJ_nid2obj(NID_pkcs7_data);
        break;
    case NID_pkcs7_encrypted:
        p7->type = obj;
        if ((p7->d.encrypted = PKCS7_ENCRYPT_new())
            == NULL)
            goto err;
        if (!ASN1_INTEGER_set(p7->d.encrypted->version, 0))
            goto err;
        p7->d.encrypted->enc_data->content_type = OBJ_nid2obj(NID_pkcs7_data);
        break;

    case NID_pkcs7_digest:
        p7->type = obj;
        if ((p7->d.digest = PKCS7_DIGEST_new())
            == NULL)
            goto err;
        if (!ASN1_INTEGER_set(p7->d.digest->version, 0))
            goto err;
        break;
    default:
        PKCS7err(PKCS7_F_PKCS7_SET_TYPE, PKCS7_R_UNSUPPORTED_CONTENT_TYPE);
        goto err;
    }
    return (1);
 err:
    return (0);
}

int PKCS7_set0_type_other(PKCS7 *p7, int type, ASN1_TYPE *other)
{
    p7->type = OBJ_nid2obj(type);
    p7->d.other = other;
    return 1;
}

int PKCS7_add_signer(PKCS7 *p7, PKCS7_SIGNER_INFO *psi)
{
    int i, j, nid;
    X509_ALGOR *alg;
    STACK_OF(PKCS7_SIGNER_INFO) *signer_sk;
    STACK_OF(X509_ALGOR) *md_sk;

    i = OBJ_obj2nid(p7->type);
    switch (i) {
    case NID_pkcs7_signed:
        signer_sk = p7->d.sign->signer_info;
        md_sk = p7->d.sign->md_algs;
        break;
    case NID_pkcs7_signedAndEnveloped:
        signer_sk = p7->d.signed_and_enveloped->signer_info;
        md_sk = p7->d.signed_and_enveloped->md_algs;
        break;
    default:
        PKCS7err(PKCS7_F_PKCS7_ADD_SIGNER, PKCS7_R_WRONG_CONTENT_TYPE);
        return (0);
    }

    nid = OBJ_obj2nid(psi->digest_alg->algorithm);

    /* If the digest is not currently listed, add it */
    j = 0;
    for (i = 0; i < sk_X509_ALGOR_num(md_sk); i++) {
        alg = sk_X509_ALGOR_value(md_sk, i);
        if (OBJ_obj2nid(alg->algorithm) == nid) {
            j = 1;
            break;
        }
    }
    if (!j) {                   /* we need to add another algorithm */
        if (!(alg = X509_ALGOR_new())
            || !(alg->parameter = ASN1_TYPE_new())) {
            X509_ALGOR_free(alg);
            PKCS7err(PKCS7_F_PKCS7_ADD_SIGNER, ERR_R_MALLOC_FAILURE);
            return (0);
        }
        alg->algorithm = OBJ_nid2obj(nid);
        alg->parameter->type = V_ASN1_NULL;
        if (!sk_X509_ALGOR_push(md_sk, alg)) {
            X509_ALGOR_free(alg);
            return 0;
        }
    }

    if (!sk_PKCS7_SIGNER_INFO_push(signer_sk, psi))
        return 0;
    return (1);
}

int PKCS7_add_certificate(PKCS7 *p7, X509 *x509)
{
    int i;
    STACK_OF(X509) **sk;

    i = OBJ_obj2nid(p7->type);
    switch (i) {
    case NID_pkcs7_signed:
        sk = &(p7->d.sign->cert);
        break;
    case NID_pkcs7_signedAndEnveloped:
        sk = &(p7->d.signed_and_enveloped->cert);
        break;
    default:
        PKCS7err(PKCS7_F_PKCS7_ADD_CERTIFICATE, PKCS7_R_WRONG_CONTENT_TYPE);
        return (0);
    }

    if (*sk == NULL)
        *sk = sk_X509_new_null();
    if (*sk == NULL) {
        PKCS7err(PKCS7_F_PKCS7_ADD_CERTIFICATE, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    CRYPTO_add(&x509->references, 1, CRYPTO_LOCK_X509);
    if (!sk_X509_push(*sk, x509)) {
        X509_free(x509);
        return 0;
    }
    return (1);
}

int PKCS7_add_crl(PKCS7 *p7, X509_CRL *crl)
{
    int i;
    STACK_OF(X509_CRL) **sk;

    i = OBJ_obj2nid(p7->type);
    switch (i) {
    case NID_pkcs7_signed:
        sk = &(p7->d.sign->crl);
        break;
    case NID_pkcs7_signedAndEnveloped:
        sk = &(p7->d.signed_and_enveloped->crl);
        break;
    default:
        PKCS7err(PKCS7_F_PKCS7_ADD_CRL, PKCS7_R_WRONG_CONTENT_TYPE);
        return (0);
    }

    if (*sk == NULL)
        *sk = sk_X509_CRL_new_null();
    if (*sk == NULL) {
        PKCS7err(PKCS7_F_PKCS7_ADD_CRL, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    CRYPTO_add(&crl->references, 1, CRYPTO_LOCK_X509_CRL);
    if (!sk_X509_CRL_push(*sk, crl)) {
        X509_CRL_free(crl);
        return 0;
    }
    return (1);
}

int PKCS7_SIGNER_INFO_set(PKCS7_SIGNER_INFO *p7i, X509 *x509, EVP_PKEY *pkey,
                          const EVP_MD *dgst)
{
    int ret;

    /* We now need to add another PKCS7_SIGNER_INFO entry */
    if (!ASN1_INTEGER_set(p7i->version, 1))
        goto err;
    if (!X509_NAME_set(&p7i->issuer_and_serial->issuer,
                       X509_get_issuer_name(x509)))
        goto err;

    /*
     * because ASN1_INTEGER_set is used to set a 'long' we will do things the
     * ugly way.
     */
    M_ASN1_INTEGER_free(p7i->issuer_and_serial->serial);
    if (!(p7i->issuer_and_serial->serial =
          M_ASN1_INTEGER_dup(X509_get_serialNumber(x509))))
        goto err;

    /* lets keep the pkey around for a while */
    CRYPTO_add(&pkey->references, 1, CRYPTO_LOCK_EVP_PKEY);
    p7i->pkey = pkey;

    /* Set the algorithms */

    X509_ALGOR_set0(p7i->digest_alg, OBJ_nid2obj(EVP_MD_type(dgst)),
                    V_ASN1_NULL, NULL);

    if (pkey->ameth && pkey->ameth->pkey_ctrl) {
        ret = pkey->ameth->pkey_ctrl(pkey, ASN1_PKEY_CTRL_PKCS7_SIGN, 0, p7i);
        if (ret > 0)
            return 1;
        if (ret != -2) {
            PKCS7err(PKCS7_F_PKCS7_SIGNER_INFO_SET,
                     PKCS7_R_SIGNING_CTRL_FAILURE);
            return 0;
        }
    }
    PKCS7err(PKCS7_F_PKCS7_SIGNER_INFO_SET,
             PKCS7_R_SIGNING_NOT_SUPPORTED_FOR_THIS_KEY_TYPE);
 err:
    return 0;
}

PKCS7_SIGNER_INFO *PKCS7_add_signature(PKCS7 *p7, X509 *x509, EVP_PKEY *pkey,
                                       const EVP_MD *dgst)
{
    PKCS7_SIGNER_INFO *si = NULL;

    if (dgst == NULL) {
        int def_nid;
        if (EVP_PKEY_get_default_digest_nid(pkey, &def_nid) <= 0)
            goto err;
        dgst = EVP_get_digestbynid(def_nid);
        if (dgst == NULL) {
            PKCS7err(PKCS7_F_PKCS7_ADD_SIGNATURE, PKCS7_R_NO_DEFAULT_DIGEST);
            goto err;
        }
    }

    if ((si = PKCS7_SIGNER_INFO_new()) == NULL)
        goto err;
    if (!PKCS7_SIGNER_INFO_set(si, x509, pkey, dgst))
        goto err;
    if (!PKCS7_add_signer(p7, si))
        goto err;
    return (si);
 err:
    if (si)
        PKCS7_SIGNER_INFO_free(si);
    return (NULL);
}

int PKCS7_set_digest(PKCS7 *p7, const EVP_MD *md)
{
    if (PKCS7_type_is_digest(p7)) {
        if (!(p7->d.digest->md->parameter = ASN1_TYPE_new())) {
            PKCS7err(PKCS7_F_PKCS7_SET_DIGEST, ERR_R_MALLOC_FAILURE);
            return 0;
        }
        p7->d.digest->md->parameter->type = V_ASN1_NULL;
        p7->d.digest->md->algorithm = OBJ_nid2obj(EVP_MD_nid(md));
        return 1;
    }

    PKCS7err(PKCS7_F_PKCS7_SET_DIGEST, PKCS7_R_WRONG_CONTENT_TYPE);
    return 1;
}

STACK_OF(PKCS7_SIGNER_INFO) *PKCS7_get_signer_info(PKCS7 *p7)
{
    if (p7 == NULL || p7->d.ptr == NULL)
        return NULL;
    if (PKCS7_type_is_signed(p7)) {
        return (p7->d.sign->signer_info);
    } else if (PKCS7_type_is_signedAndEnveloped(p7)) {
        return (p7->d.signed_and_enveloped->signer_info);
    } else
        return (NULL);
}

void PKCS7_SIGNER_INFO_get0_algs(PKCS7_SIGNER_INFO *si, EVP_PKEY **pk,
                                 X509_ALGOR **pdig, X509_ALGOR **psig)
{
    if (pk)
        *pk = si->pkey;
    if (pdig)
        *pdig = si->digest_alg;
    if (psig)
        *psig = si->digest_enc_alg;
}

void PKCS7_RECIP_INFO_get0_alg(PKCS7_RECIP_INFO *ri, X509_ALGOR **penc)
{
    if (penc)
        *penc = ri->key_enc_algor;
}

PKCS7_RECIP_INFO *PKCS7_add_recipient(PKCS7 *p7, X509 *x509)
{
    PKCS7_RECIP_INFO *ri;

    if ((ri = PKCS7_RECIP_INFO_new()) == NULL)
        goto err;
    if (!PKCS7_RECIP_INFO_set(ri, x509))
        goto err;
    if (!PKCS7_add_recipient_info(p7, ri))
        goto err;
    return ri;
 err:
    if (ri)
        PKCS7_RECIP_INFO_free(ri);
    return NULL;
}

int PKCS7_add_recipient_info(PKCS7 *p7, PKCS7_RECIP_INFO *ri)
{
    int i;
    STACK_OF(PKCS7_RECIP_INFO) *sk;

    i = OBJ_obj2nid(p7->type);
    switch (i) {
    case NID_pkcs7_signedAndEnveloped:
        sk = p7->d.signed_and_enveloped->recipientinfo;
        break;
    case NID_pkcs7_enveloped:
        sk = p7->d.enveloped->recipientinfo;
        break;
    default:
        PKCS7err(PKCS7_F_PKCS7_ADD_RECIPIENT_INFO,
                 PKCS7_R_WRONG_CONTENT_TYPE);
        return (0);
    }

    if (!sk_PKCS7_RECIP_INFO_push(sk, ri))
        return 0;
    return (1);
}

int PKCS7_RECIP_INFO_set(PKCS7_RECIP_INFO *p7i, X509 *x509)
{
    int ret;
    EVP_PKEY *pkey = NULL;
    if (!ASN1_INTEGER_set(p7i->version, 0))
        return 0;
    if (!X509_NAME_set(&p7i->issuer_and_serial->issuer,
                       X509_get_issuer_name(x509)))
        return 0;

    M_ASN1_INTEGER_free(p7i->issuer_and_serial->serial);
    if (!(p7i->issuer_and_serial->serial =
          M_ASN1_INTEGER_dup(X509_get_serialNumber(x509))))
        return 0;

    pkey = X509_get_pubkey(x509);

    if (!pkey || !pkey->ameth || !pkey->ameth->pkey_ctrl) {
        PKCS7err(PKCS7_F_PKCS7_RECIP_INFO_SET,
                 PKCS7_R_ENCRYPTION_NOT_SUPPORTED_FOR_THIS_KEY_TYPE);
        goto err;
    }

    ret = pkey->ameth->pkey_ctrl(pkey, ASN1_PKEY_CTRL_PKCS7_ENCRYPT, 0, p7i);
    if (ret == -2) {
        PKCS7err(PKCS7_F_PKCS7_RECIP_INFO_SET,
                 PKCS7_R_ENCRYPTION_NOT_SUPPORTED_FOR_THIS_KEY_TYPE);
        goto err;
    }
    if (ret <= 0) {
        PKCS7err(PKCS7_F_PKCS7_RECIP_INFO_SET,
                 PKCS7_R_ENCRYPTION_CTRL_FAILURE);
        goto err;
    }

    EVP_PKEY_free(pkey);

    CRYPTO_add(&x509->references, 1, CRYPTO_LOCK_X509);
    p7i->cert = x509;

    return 1;

 err:
    if (pkey)
        EVP_PKEY_free(pkey);
    return 0;
}

X509 *PKCS7_cert_from_signer_info(PKCS7 *p7, PKCS7_SIGNER_INFO *si)
{
    if (PKCS7_type_is_signed(p7))
        return (X509_find_by_issuer_and_serial(p7->d.sign->cert,
                                               si->issuer_and_serial->issuer,
                                               si->
                                               issuer_and_serial->serial));
    else
        return (NULL);
}

int PKCS7_set_cipher(PKCS7 *p7, const EVP_CIPHER *cipher)
{
    int i;
    PKCS7_ENC_CONTENT *ec;

    i = OBJ_obj2nid(p7->type);
    switch (i) {
    case NID_pkcs7_signedAndEnveloped:
        ec = p7->d.signed_and_enveloped->enc_data;
        break;
    case NID_pkcs7_enveloped:
        ec = p7->d.enveloped->enc_data;
        break;
    default:
        PKCS7err(PKCS7_F_PKCS7_SET_CIPHER, PKCS7_R_WRONG_CONTENT_TYPE);
        return (0);
    }

    /* Check cipher OID exists and has data in it */
    i = EVP_CIPHER_type(cipher);
    if (i == NID_undef) {
        PKCS7err(PKCS7_F_PKCS7_SET_CIPHER,
                 PKCS7_R_CIPHER_HAS_NO_OBJECT_IDENTIFIER);
        return (0);
    }

    ec->cipher = cipher;
    return 1;
}

int PKCS7_stream(unsigned char ***boundary, PKCS7 *p7)
{
    ASN1_OCTET_STRING *os = NULL;

    switch (OBJ_obj2nid(p7->type)) {
    case NID_pkcs7_data:
        os = p7->d.data;
        break;

    case NID_pkcs7_signedAndEnveloped:
        os = p7->d.signed_and_enveloped->enc_data->enc_data;
        if (os == NULL) {
            os = M_ASN1_OCTET_STRING_new();
            p7->d.signed_and_enveloped->enc_data->enc_data = os;
        }
        break;

    case NID_pkcs7_enveloped:
        os = p7->d.enveloped->enc_data->enc_data;
        if (os == NULL) {
            os = M_ASN1_OCTET_STRING_new();
            p7->d.enveloped->enc_data->enc_data = os;
        }
        break;

    case NID_pkcs7_signed:
        os = p7->d.sign->contents->d.data;
        break;

    default:
        os = NULL;
        break;
    }

    if (os == NULL)
        return 0;

    os->flags |= ASN1_STRING_FLAG_NDEF;
    *boundary = &os->data;

    return 1;
}
/* pk7_mime.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project.
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
 */

#include <stdio.h>
#include <ctype.h>
// #include "cryptlib.h"
// #include "rand.h"
// #include "x509.h"
// #include "asn1.h"

/* PKCS#7 wrappers round generalised stream and MIME routines */

int i2d_PKCS7_bio_stream(BIO *out, PKCS7 *p7, BIO *in, int flags)
{
    return i2d_ASN1_bio_stream(out, (ASN1_VALUE *)p7, in, flags,
                               ASN1_ITEM_rptr(PKCS7));
}

int PEM_write_bio_PKCS7_stream(BIO *out, PKCS7 *p7, BIO *in, int flags)
{
    return PEM_write_bio_ASN1_stream(out, (ASN1_VALUE *)p7, in, flags,
                                     "PKCS7", ASN1_ITEM_rptr(PKCS7));
}

int SMIME_write_PKCS7(BIO *bio, PKCS7 *p7, BIO *data, int flags)
{
    STACK_OF(X509_ALGOR) *mdalgs;
    int ctype_nid = OBJ_obj2nid(p7->type);
    if (ctype_nid == NID_pkcs7_signed)
        mdalgs = p7->d.sign->md_algs;
    else
        mdalgs = NULL;

    flags ^= SMIME_OLDMIME;

    return SMIME_write_ASN1(bio, (ASN1_VALUE *)p7, data, flags,
                            ctype_nid, NID_undef, mdalgs,
                            ASN1_ITEM_rptr(PKCS7));
}

PKCS7 *SMIME_read_PKCS7(BIO *bio, BIO **bcont)
{
    return (PKCS7 *)SMIME_read_ASN1(bio, bcont, ASN1_ITEM_rptr(PKCS7));
}
/* pk7_smime.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project.
 */
/* ====================================================================
 * Copyright (c) 1999-2004 The OpenSSL Project.  All rights reserved.
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

/* Simple PKCS#7 processing functions */

#include <stdio.h>
// #include "cryptlib.h"
// #include "x509.h"
// #include "x509v3.h"

static int pkcs7_copy_existing_digest(PKCS7 *p7, PKCS7_SIGNER_INFO *si);

PKCS7 *PKCS7_sign(X509 *signcert, EVP_PKEY *pkey, STACK_OF(X509) *certs,
                  BIO *data, int flags)
{
    PKCS7 *p7;
    int i;

    if (!(p7 = PKCS7_new())) {
        PKCS7err(PKCS7_F_PKCS7_SIGN, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    if (!PKCS7_set_type(p7, NID_pkcs7_signed))
        goto err;

    if (!PKCS7_content_new(p7, NID_pkcs7_data))
        goto err;

    if (pkey && !PKCS7_sign_add_signer(p7, signcert, pkey, NULL, flags)) {
        PKCS7err(PKCS7_F_PKCS7_SIGN, PKCS7_R_PKCS7_ADD_SIGNER_ERROR);
        goto err;
    }

    if (!(flags & PKCS7_NOCERTS)) {
        for (i = 0; i < sk_X509_num(certs); i++) {
            if (!PKCS7_add_certificate(p7, sk_X509_value(certs, i)))
                goto err;
        }
    }

    if (flags & PKCS7_DETACHED)
        PKCS7_set_detached(p7, 1);

    if (flags & (PKCS7_STREAM | PKCS7_PARTIAL))
        return p7;

    if (PKCS7_final(p7, data, flags))
        return p7;

 err:
    PKCS7_free(p7);
    return NULL;
}

int PKCS7_final(PKCS7 *p7, BIO *data, int flags)
{
    BIO *p7bio;
    int ret = 0;
    if (!(p7bio = PKCS7_dataInit(p7, NULL))) {
        PKCS7err(PKCS7_F_PKCS7_FINAL, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    SMIME_crlf_copy(data, p7bio, flags);

    (void)BIO_flush(p7bio);

    if (!PKCS7_dataFinal(p7, p7bio)) {
        PKCS7err(PKCS7_F_PKCS7_FINAL, PKCS7_R_PKCS7_DATASIGN);
        goto err;
    }

    ret = 1;

 err:
    BIO_free_all(p7bio);

    return ret;

}

/* Check to see if a cipher exists and if so add S/MIME capabilities */

static int add_cipher_smcap(STACK_OF(X509_ALGOR) *sk, int nid, int arg)
{
    if (EVP_get_cipherbynid(nid))
        return PKCS7_simple_smimecap(sk, nid, arg);
    return 1;
}

static int add_digest_smcap(STACK_OF(X509_ALGOR) *sk, int nid, int arg)
{
    if (EVP_get_digestbynid(nid))
        return PKCS7_simple_smimecap(sk, nid, arg);
    return 1;
}

PKCS7_SIGNER_INFO *PKCS7_sign_add_signer(PKCS7 *p7, X509 *signcert,
                                         EVP_PKEY *pkey, const EVP_MD *md,
                                         int flags)
{
    PKCS7_SIGNER_INFO *si = NULL;
    STACK_OF(X509_ALGOR) *smcap = NULL;
    if (!X509_check_private_key(signcert, pkey)) {
        PKCS7err(PKCS7_F_PKCS7_SIGN_ADD_SIGNER,
                 PKCS7_R_PRIVATE_KEY_DOES_NOT_MATCH_CERTIFICATE);
        return NULL;
    }

    if (!(si = PKCS7_add_signature(p7, signcert, pkey, md))) {
        PKCS7err(PKCS7_F_PKCS7_SIGN_ADD_SIGNER,
                 PKCS7_R_PKCS7_ADD_SIGNATURE_ERROR);
        return NULL;
    }

    if (!(flags & PKCS7_NOCERTS)) {
        if (!PKCS7_add_certificate(p7, signcert))
            goto err;
    }

    if (!(flags & PKCS7_NOATTR)) {
        if (!PKCS7_add_attrib_content_type(si, NULL))
            goto err;
        /* Add SMIMECapabilities */
        if (!(flags & PKCS7_NOSMIMECAP)) {
            if (!(smcap = sk_X509_ALGOR_new_null())) {
                PKCS7err(PKCS7_F_PKCS7_SIGN_ADD_SIGNER, ERR_R_MALLOC_FAILURE);
                goto err;
            }
            if (!add_cipher_smcap(smcap, NID_aes_256_cbc, -1)
                || !add_digest_smcap(smcap, NID_id_GostR3411_94, -1)
                || !add_cipher_smcap(smcap, NID_id_Gost28147_89, -1)
                || !add_cipher_smcap(smcap, NID_aes_192_cbc, -1)
                || !add_cipher_smcap(smcap, NID_aes_128_cbc, -1)
                || !add_cipher_smcap(smcap, NID_des_ede3_cbc, -1)
                || !add_cipher_smcap(smcap, NID_rc2_cbc, 128)
                || !add_cipher_smcap(smcap, NID_rc2_cbc, 64)
                || !add_cipher_smcap(smcap, NID_des_cbc, -1)
                || !add_cipher_smcap(smcap, NID_rc2_cbc, 40)
                || !PKCS7_add_attrib_smimecap(si, smcap))
                goto err;
            sk_X509_ALGOR_pop_free(smcap, X509_ALGOR_free);
            smcap = NULL;
        }
        if (flags & PKCS7_REUSE_DIGEST) {
            if (!pkcs7_copy_existing_digest(p7, si))
                goto err;
            if (!(flags & PKCS7_PARTIAL) && !PKCS7_SIGNER_INFO_sign(si))
                goto err;
        }
    }
    return si;
 err:
    if (smcap)
        sk_X509_ALGOR_pop_free(smcap, X509_ALGOR_free);
    return NULL;
}

/*
 * Search for a digest matching SignerInfo digest type and if found copy
 * across.
 */

static int pkcs7_copy_existing_digest(PKCS7 *p7, PKCS7_SIGNER_INFO *si)
{
    int i;
    STACK_OF(PKCS7_SIGNER_INFO) *sinfos;
    PKCS7_SIGNER_INFO *sitmp;
    ASN1_OCTET_STRING *osdig = NULL;
    sinfos = PKCS7_get_signer_info(p7);
    for (i = 0; i < sk_PKCS7_SIGNER_INFO_num(sinfos); i++) {
        sitmp = sk_PKCS7_SIGNER_INFO_value(sinfos, i);
        if (si == sitmp)
            break;
        if (sk_X509_ATTRIBUTE_num(sitmp->auth_attr) <= 0)
            continue;
        if (!OBJ_cmp(si->digest_alg->algorithm, sitmp->digest_alg->algorithm)) {
            osdig = PKCS7_digest_from_attributes(sitmp->auth_attr);
            break;
        }

    }

    if (osdig)
        return PKCS7_add1_attrib_digest(si, osdig->data, osdig->length);

    PKCS7err(PKCS7_F_PKCS7_COPY_EXISTING_DIGEST,
             PKCS7_R_NO_MATCHING_DIGEST_TYPE_FOUND);
    return 0;
}

int PKCS7_verify(PKCS7 *p7, STACK_OF(X509) *certs, X509_STORE *store,
                 BIO *indata, BIO *out, int flags)
{
    STACK_OF(X509) *signers;
    X509 *signer;
    STACK_OF(PKCS7_SIGNER_INFO) *sinfos;
    PKCS7_SIGNER_INFO *si;
    X509_STORE_CTX cert_ctx;
    char buf[4096];
    int i, j = 0, k, ret = 0;
    BIO *p7bio = NULL;
    BIO *tmpin = NULL, *tmpout = NULL;

    if (!p7) {
        PKCS7err(PKCS7_F_PKCS7_VERIFY, PKCS7_R_INVALID_NULL_POINTER);
        return 0;
    }

    if (!PKCS7_type_is_signed(p7)) {
        PKCS7err(PKCS7_F_PKCS7_VERIFY, PKCS7_R_WRONG_CONTENT_TYPE);
        return 0;
    }

    /* Check for no data and no content: no data to verify signature */
    if (PKCS7_get_detached(p7) && !indata) {
        PKCS7err(PKCS7_F_PKCS7_VERIFY, PKCS7_R_NO_CONTENT);
        return 0;
    }
#if 0
    /*
     * NB: this test commented out because some versions of Netscape
     * illegally include zero length content when signing data. Also
     * Microsoft Authenticode includes a SpcIndirectDataContent data
     * structure which describes the content to be protected by the
     * signature, rather than directly embedding that content. So
     * Authenticode implementations are also expected to use
     * PKCS7_verify() with explicit external data, on non-detached
     * PKCS#7 signatures.
     *
     * In OpenSSL 1.1 a new flag PKCS7_NO_DUAL_CONTENT has been
     * introduced to disable this sanity check. For the 1.0.2 branch
     * this change is not acceptable, so the check remains completely
     * commented out (as it has been for a long time).
     */

    /* Check for data and content: two sets of data */
    if (!PKCS7_get_detached(p7) && indata) {
        PKCS7err(PKCS7_F_PKCS7_VERIFY, PKCS7_R_CONTENT_AND_DATA_PRESENT);
        return 0;
    }
#endif

    sinfos = PKCS7_get_signer_info(p7);

    if (!sinfos || !sk_PKCS7_SIGNER_INFO_num(sinfos)) {
        PKCS7err(PKCS7_F_PKCS7_VERIFY, PKCS7_R_NO_SIGNATURES_ON_DATA);
        return 0;
    }

    signers = PKCS7_get0_signers(p7, certs, flags);
    if (!signers)
        return 0;

    /* Now verify the certificates */

    if (!(flags & PKCS7_NOVERIFY))
        for (k = 0; k < sk_X509_num(signers); k++) {
            signer = sk_X509_value(signers, k);
            if (!(flags & PKCS7_NOCHAIN)) {
                if (!X509_STORE_CTX_init(&cert_ctx, store, signer,
                                         p7->d.sign->cert)) {
                    PKCS7err(PKCS7_F_PKCS7_VERIFY, ERR_R_X509_LIB);
                    goto err;
                }
                X509_STORE_CTX_set_default(&cert_ctx, "smime_sign");
            } else if (!X509_STORE_CTX_init(&cert_ctx, store, signer, NULL)) {
                PKCS7err(PKCS7_F_PKCS7_VERIFY, ERR_R_X509_LIB);
                goto err;
            }
            if (!(flags & PKCS7_NOCRL))
                X509_STORE_CTX_set0_crls(&cert_ctx, p7->d.sign->crl);
            i = X509_verify_cert(&cert_ctx);
            if (i <= 0)
                j = X509_STORE_CTX_get_error(&cert_ctx);
            X509_STORE_CTX_cleanup(&cert_ctx);
            if (i <= 0) {
                PKCS7err(PKCS7_F_PKCS7_VERIFY,
                         PKCS7_R_CERTIFICATE_VERIFY_ERROR);
                ERR_add_error_data(2, "Verify error:",
                                   X509_verify_cert_error_string(j));
                goto err;
            }
            /* Check for revocation status here */
        }

    /*
     * Performance optimization: if the content is a memory BIO then store
     * its contents in a temporary read only memory BIO. This avoids
     * potentially large numbers of slow copies of data which will occur when
     * reading from a read write memory BIO when signatures are calculated.
     */

    if (indata && (BIO_method_type(indata) == BIO_TYPE_MEM)) {
        char *ptr;
        long len;
        len = BIO_get_mem_data(indata, &ptr);
        tmpin = BIO_new_mem_buf(ptr, len);
        if (tmpin == NULL) {
            PKCS7err(PKCS7_F_PKCS7_VERIFY, ERR_R_MALLOC_FAILURE);
            goto err;
        }
    } else
        tmpin = indata;

    if (!(p7bio = PKCS7_dataInit(p7, tmpin)))
        goto err;

    if (flags & PKCS7_TEXT) {
        if (!(tmpout = BIO_new(BIO_s_mem()))) {
            PKCS7err(PKCS7_F_PKCS7_VERIFY, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        BIO_set_mem_eof_return(tmpout, 0);
    } else
        tmpout = out;

    /* We now have to 'read' from p7bio to calculate digests etc. */
    for (;;) {
        i = BIO_read(p7bio, buf, sizeof(buf));
        if (i <= 0)
            break;
        if (tmpout)
            BIO_write(tmpout, buf, i);
    }

    if (flags & PKCS7_TEXT) {
        if (!SMIME_text(tmpout, out)) {
            PKCS7err(PKCS7_F_PKCS7_VERIFY, PKCS7_R_SMIME_TEXT_ERROR);
            BIO_free(tmpout);
            goto err;
        }
        BIO_free(tmpout);
    }

    /* Now Verify All Signatures */
    if (!(flags & PKCS7_NOSIGS))
        for (i = 0; i < sk_PKCS7_SIGNER_INFO_num(sinfos); i++) {
            si = sk_PKCS7_SIGNER_INFO_value(sinfos, i);
            signer = sk_X509_value(signers, i);
            j = PKCS7_signatureVerify(p7bio, p7, si, signer);
            if (j <= 0) {
                PKCS7err(PKCS7_F_PKCS7_VERIFY, PKCS7_R_SIGNATURE_FAILURE);
                goto err;
            }
        }

    ret = 1;

 err:
    if (tmpin == indata) {
        if (indata)
            BIO_pop(p7bio);
    }
    BIO_free_all(p7bio);
    sk_X509_free(signers);
    return ret;
}

STACK_OF(X509) *PKCS7_get0_signers(PKCS7 *p7, STACK_OF(X509) *certs,
                                   int flags)
{
    STACK_OF(X509) *signers;
    STACK_OF(PKCS7_SIGNER_INFO) *sinfos;
    PKCS7_SIGNER_INFO *si;
    PKCS7_ISSUER_AND_SERIAL *ias;
    X509 *signer;
    int i;

    if (!p7) {
        PKCS7err(PKCS7_F_PKCS7_GET0_SIGNERS, PKCS7_R_INVALID_NULL_POINTER);
        return NULL;
    }

    if (!PKCS7_type_is_signed(p7)) {
        PKCS7err(PKCS7_F_PKCS7_GET0_SIGNERS, PKCS7_R_WRONG_CONTENT_TYPE);
        return NULL;
    }

    /* Collect all the signers together */

    sinfos = PKCS7_get_signer_info(p7);

    if (sk_PKCS7_SIGNER_INFO_num(sinfos) <= 0) {
        PKCS7err(PKCS7_F_PKCS7_GET0_SIGNERS, PKCS7_R_NO_SIGNERS);
        return 0;
    }

    if (!(signers = sk_X509_new_null())) {
        PKCS7err(PKCS7_F_PKCS7_GET0_SIGNERS, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    for (i = 0; i < sk_PKCS7_SIGNER_INFO_num(sinfos); i++) {
        si = sk_PKCS7_SIGNER_INFO_value(sinfos, i);
        ias = si->issuer_and_serial;
        signer = NULL;
        /* If any certificates passed they take priority */
        if (certs)
            signer = X509_find_by_issuer_and_serial(certs,
                                                    ias->issuer, ias->serial);
        if (!signer && !(flags & PKCS7_NOINTERN)
            && p7->d.sign->cert)
            signer =
                X509_find_by_issuer_and_serial(p7->d.sign->cert,
                                               ias->issuer, ias->serial);
        if (!signer) {
            PKCS7err(PKCS7_F_PKCS7_GET0_SIGNERS,
                     PKCS7_R_SIGNER_CERTIFICATE_NOT_FOUND);
            sk_X509_free(signers);
            return 0;
        }

        if (!sk_X509_push(signers, signer)) {
            sk_X509_free(signers);
            return NULL;
        }
    }
    return signers;
}

/* Build a complete PKCS#7 enveloped data */

PKCS7 *PKCS7_encrypt(STACK_OF(X509) *certs, BIO *in, const EVP_CIPHER *cipher,
                     int flags)
{
    PKCS7 *p7;
    BIO *p7bio = NULL;
    int i;
    X509 *x509;
    if (!(p7 = PKCS7_new())) {
        PKCS7err(PKCS7_F_PKCS7_ENCRYPT, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    if (!PKCS7_set_type(p7, NID_pkcs7_enveloped))
        goto err;
    if (!PKCS7_set_cipher(p7, cipher)) {
        PKCS7err(PKCS7_F_PKCS7_ENCRYPT, PKCS7_R_ERROR_SETTING_CIPHER);
        goto err;
    }

    for (i = 0; i < sk_X509_num(certs); i++) {
        x509 = sk_X509_value(certs, i);
        if (!PKCS7_add_recipient(p7, x509)) {
            PKCS7err(PKCS7_F_PKCS7_ENCRYPT, PKCS7_R_ERROR_ADDING_RECIPIENT);
            goto err;
        }
    }

    if (flags & PKCS7_STREAM)
        return p7;

    if (PKCS7_final(p7, in, flags))
        return p7;

 err:

    BIO_free_all(p7bio);
    PKCS7_free(p7);
    return NULL;

}

int PKCS7_decrypt(PKCS7 *p7, EVP_PKEY *pkey, X509 *cert, BIO *data, int flags)
{
    BIO *tmpmem;
    int ret, i;
    char buf[4096];

    if (!p7) {
        PKCS7err(PKCS7_F_PKCS7_DECRYPT, PKCS7_R_INVALID_NULL_POINTER);
        return 0;
    }

    if (!PKCS7_type_is_enveloped(p7)) {
        PKCS7err(PKCS7_F_PKCS7_DECRYPT, PKCS7_R_WRONG_CONTENT_TYPE);
        return 0;
    }

    if (cert && !X509_check_private_key(cert, pkey)) {
        PKCS7err(PKCS7_F_PKCS7_DECRYPT,
                 PKCS7_R_PRIVATE_KEY_DOES_NOT_MATCH_CERTIFICATE);
        return 0;
    }

    if (!(tmpmem = PKCS7_dataDecode(p7, pkey, NULL, cert))) {
        PKCS7err(PKCS7_F_PKCS7_DECRYPT, PKCS7_R_DECRYPT_ERROR);
        return 0;
    }

    if (flags & PKCS7_TEXT) {
        BIO *tmpbuf, *bread;
        /* Encrypt BIOs can't do BIO_gets() so add a buffer BIO */
        if (!(tmpbuf = BIO_new(BIO_f_buffer()))) {
            PKCS7err(PKCS7_F_PKCS7_DECRYPT, ERR_R_MALLOC_FAILURE);
            BIO_free_all(tmpmem);
            return 0;
        }
        if (!(bread = BIO_push(tmpbuf, tmpmem))) {
            PKCS7err(PKCS7_F_PKCS7_DECRYPT, ERR_R_MALLOC_FAILURE);
            BIO_free_all(tmpbuf);
            BIO_free_all(tmpmem);
            return 0;
        }
        ret = SMIME_text(bread, data);
        if (ret > 0 && BIO_method_type(tmpmem) == BIO_TYPE_CIPHER) {
            if (!BIO_get_cipher_status(tmpmem))
                ret = 0;
        }
        BIO_free_all(bread);
        return ret;
    } else {
        for (;;) {
            i = BIO_read(tmpmem, buf, sizeof(buf));
            if (i <= 0) {
                ret = 1;
                if (BIO_method_type(tmpmem) == BIO_TYPE_CIPHER) {
                    if (!BIO_get_cipher_status(tmpmem))
                        ret = 0;
                }

                break;
            }
            if (BIO_write(data, buf, i) != i) {
                ret = 0;
                break;
            }
        }
        BIO_free_all(tmpmem);
        return ret;
    }
}
