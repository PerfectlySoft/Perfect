/* ocsp_asn.c */
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
#include "asn1.h"
#include "asn1t.h"
#include "ocsp.h"

ASN1_SEQUENCE(OCSP_SIGNATURE) = {
        ASN1_SIMPLE(OCSP_SIGNATURE, signatureAlgorithm, X509_ALGOR),
        ASN1_SIMPLE(OCSP_SIGNATURE, signature, ASN1_BIT_STRING),
        ASN1_EXP_SEQUENCE_OF_OPT(OCSP_SIGNATURE, certs, X509, 0)
} ASN1_SEQUENCE_END(OCSP_SIGNATURE)

IMPLEMENT_ASN1_FUNCTIONS(OCSP_SIGNATURE)

ASN1_SEQUENCE(OCSP_CERTID) = {
        ASN1_SIMPLE(OCSP_CERTID, hashAlgorithm, X509_ALGOR),
        ASN1_SIMPLE(OCSP_CERTID, issuerNameHash, ASN1_OCTET_STRING),
        ASN1_SIMPLE(OCSP_CERTID, issuerKeyHash, ASN1_OCTET_STRING),
        ASN1_SIMPLE(OCSP_CERTID, serialNumber, ASN1_INTEGER)
} ASN1_SEQUENCE_END(OCSP_CERTID)

IMPLEMENT_ASN1_FUNCTIONS(OCSP_CERTID)

ASN1_SEQUENCE(OCSP_ONEREQ) = {
        ASN1_SIMPLE(OCSP_ONEREQ, reqCert, OCSP_CERTID),
        ASN1_EXP_SEQUENCE_OF_OPT(OCSP_ONEREQ, singleRequestExtensions, X509_EXTENSION, 0)
} ASN1_SEQUENCE_END(OCSP_ONEREQ)

IMPLEMENT_ASN1_FUNCTIONS(OCSP_ONEREQ)

ASN1_SEQUENCE(OCSP_REQINFO) = {
        ASN1_EXP_OPT(OCSP_REQINFO, version, ASN1_INTEGER, 0),
        ASN1_EXP_OPT(OCSP_REQINFO, requestorName, GENERAL_NAME, 1),
        ASN1_SEQUENCE_OF(OCSP_REQINFO, requestList, OCSP_ONEREQ),
        ASN1_EXP_SEQUENCE_OF_OPT(OCSP_REQINFO, requestExtensions, X509_EXTENSION, 2)
} ASN1_SEQUENCE_END(OCSP_REQINFO)

IMPLEMENT_ASN1_FUNCTIONS(OCSP_REQINFO)

ASN1_SEQUENCE(OCSP_REQUEST) = {
        ASN1_SIMPLE(OCSP_REQUEST, tbsRequest, OCSP_REQINFO),
        ASN1_EXP_OPT(OCSP_REQUEST, optionalSignature, OCSP_SIGNATURE, 0)
} ASN1_SEQUENCE_END(OCSP_REQUEST)

IMPLEMENT_ASN1_FUNCTIONS(OCSP_REQUEST)

/* OCSP_RESPONSE templates */

ASN1_SEQUENCE(OCSP_RESPBYTES) = {
            ASN1_SIMPLE(OCSP_RESPBYTES, responseType, ASN1_OBJECT),
            ASN1_SIMPLE(OCSP_RESPBYTES, response, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(OCSP_RESPBYTES)

IMPLEMENT_ASN1_FUNCTIONS(OCSP_RESPBYTES)

ASN1_SEQUENCE(OCSP_RESPONSE) = {
        ASN1_SIMPLE(OCSP_RESPONSE, responseStatus, ASN1_ENUMERATED),
        ASN1_EXP_OPT(OCSP_RESPONSE, responseBytes, OCSP_RESPBYTES, 0)
} ASN1_SEQUENCE_END(OCSP_RESPONSE)

IMPLEMENT_ASN1_FUNCTIONS(OCSP_RESPONSE)

ASN1_CHOICE(OCSP_RESPID) = {
           ASN1_EXP(OCSP_RESPID, value.byName, X509_NAME, 1),
           ASN1_EXP(OCSP_RESPID, value.byKey, ASN1_OCTET_STRING, 2)
} ASN1_CHOICE_END(OCSP_RESPID)

IMPLEMENT_ASN1_FUNCTIONS(OCSP_RESPID)

ASN1_SEQUENCE(OCSP_REVOKEDINFO) = {
        ASN1_SIMPLE(OCSP_REVOKEDINFO, revocationTime, ASN1_GENERALIZEDTIME),
        ASN1_EXP_OPT(OCSP_REVOKEDINFO, revocationReason, ASN1_ENUMERATED, 0)
} ASN1_SEQUENCE_END(OCSP_REVOKEDINFO)

IMPLEMENT_ASN1_FUNCTIONS(OCSP_REVOKEDINFO)

ASN1_CHOICE(OCSP_CERTSTATUS) = {
        ASN1_IMP(OCSP_CERTSTATUS, value.good, ASN1_NULL, 0),
        ASN1_IMP(OCSP_CERTSTATUS, value.revoked, OCSP_REVOKEDINFO, 1),
        ASN1_IMP(OCSP_CERTSTATUS, value.unknown, ASN1_NULL, 2)
} ASN1_CHOICE_END(OCSP_CERTSTATUS)

IMPLEMENT_ASN1_FUNCTIONS(OCSP_CERTSTATUS)

ASN1_SEQUENCE(OCSP_SINGLERESP) = {
           ASN1_SIMPLE(OCSP_SINGLERESP, certId, OCSP_CERTID),
           ASN1_SIMPLE(OCSP_SINGLERESP, certStatus, OCSP_CERTSTATUS),
           ASN1_SIMPLE(OCSP_SINGLERESP, thisUpdate, ASN1_GENERALIZEDTIME),
           ASN1_EXP_OPT(OCSP_SINGLERESP, nextUpdate, ASN1_GENERALIZEDTIME, 0),
           ASN1_EXP_SEQUENCE_OF_OPT(OCSP_SINGLERESP, singleExtensions, X509_EXTENSION, 1)
} ASN1_SEQUENCE_END(OCSP_SINGLERESP)

IMPLEMENT_ASN1_FUNCTIONS(OCSP_SINGLERESP)

ASN1_SEQUENCE(OCSP_RESPDATA) = {
           ASN1_EXP_OPT(OCSP_RESPDATA, version, ASN1_INTEGER, 0),
           ASN1_SIMPLE(OCSP_RESPDATA, responderId, OCSP_RESPID),
           ASN1_SIMPLE(OCSP_RESPDATA, producedAt, ASN1_GENERALIZEDTIME),
           ASN1_SEQUENCE_OF(OCSP_RESPDATA, responses, OCSP_SINGLERESP),
           ASN1_EXP_SEQUENCE_OF_OPT(OCSP_RESPDATA, responseExtensions, X509_EXTENSION, 1)
} ASN1_SEQUENCE_END(OCSP_RESPDATA)

IMPLEMENT_ASN1_FUNCTIONS(OCSP_RESPDATA)

ASN1_SEQUENCE(OCSP_BASICRESP) = {
           ASN1_SIMPLE(OCSP_BASICRESP, tbsResponseData, OCSP_RESPDATA),
           ASN1_SIMPLE(OCSP_BASICRESP, signatureAlgorithm, X509_ALGOR),
           ASN1_SIMPLE(OCSP_BASICRESP, signature, ASN1_BIT_STRING),
           ASN1_EXP_SEQUENCE_OF_OPT(OCSP_BASICRESP, certs, X509, 0)
} ASN1_SEQUENCE_END(OCSP_BASICRESP)

IMPLEMENT_ASN1_FUNCTIONS(OCSP_BASICRESP)

ASN1_SEQUENCE(OCSP_CRLID) = {
           ASN1_EXP_OPT(OCSP_CRLID, crlUrl, ASN1_IA5STRING, 0),
           ASN1_EXP_OPT(OCSP_CRLID, crlNum, ASN1_INTEGER, 1),
           ASN1_EXP_OPT(OCSP_CRLID, crlTime, ASN1_GENERALIZEDTIME, 2)
} ASN1_SEQUENCE_END(OCSP_CRLID)

IMPLEMENT_ASN1_FUNCTIONS(OCSP_CRLID)

ASN1_SEQUENCE(OCSP_SERVICELOC) = {
        ASN1_SIMPLE(OCSP_SERVICELOC, issuer, X509_NAME),
        ASN1_SEQUENCE_OF_OPT(OCSP_SERVICELOC, locator, ACCESS_DESCRIPTION)
} ASN1_SEQUENCE_END(OCSP_SERVICELOC)

IMPLEMENT_ASN1_FUNCTIONS(OCSP_SERVICELOC)
/* ocsp_cl.c */
/*
 * Written by Tom Titchener <Tom_Titchener@groove.net> for the OpenSSL
 * project.
 */

/*
 * History: This file was transfered to Richard Levitte from CertCo by Kathy
 * Weinhold in mid-spring 2000 to be included in OpenSSL or released as a
 * patch kit.
 */

/* ====================================================================
 * Copyright (c) 1998-2000 The OpenSSL Project.  All rights reserved.
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
#include <time.h>
#include "cryptlib.h"
#include "objects.h"
#include "rand.h"
#include "x509.h"
#include "pem.h"
#include "x509v3.h"
// #include "ocsp.h"

/*
 * Utility functions related to sending OCSP requests and extracting relevant
 * information from the response.
 */

/*
 * Add an OCSP_CERTID to an OCSP request. Return new OCSP_ONEREQ pointer:
 * useful if we want to add extensions.
 */

OCSP_ONEREQ *OCSP_request_add0_id(OCSP_REQUEST *req, OCSP_CERTID *cid)
{
    OCSP_ONEREQ *one = NULL;

    if (!(one = OCSP_ONEREQ_new()))
        goto err;
    if (one->reqCert)
        OCSP_CERTID_free(one->reqCert);
    one->reqCert = cid;
    if (req && !sk_OCSP_ONEREQ_push(req->tbsRequest->requestList, one)) {
        one->reqCert = NULL; /* do not free on error */
        goto err;
    }
    return one;
 err:
    OCSP_ONEREQ_free(one);
    return NULL;
}

/* Set requestorName from an X509_NAME structure */

int OCSP_request_set1_name(OCSP_REQUEST *req, X509_NAME *nm)
{
    GENERAL_NAME *gen;
    gen = GENERAL_NAME_new();
    if (gen == NULL)
        return 0;
    if (!X509_NAME_set(&gen->d.directoryName, nm)) {
        GENERAL_NAME_free(gen);
        return 0;
    }
    gen->type = GEN_DIRNAME;
    if (req->tbsRequest->requestorName)
        GENERAL_NAME_free(req->tbsRequest->requestorName);
    req->tbsRequest->requestorName = gen;
    return 1;
}

/* Add a certificate to an OCSP request */

int OCSP_request_add1_cert(OCSP_REQUEST *req, X509 *cert)
{
    OCSP_SIGNATURE *sig;
    if (!req->optionalSignature)
        req->optionalSignature = OCSP_SIGNATURE_new();
    sig = req->optionalSignature;
    if (!sig)
        return 0;
    if (!cert)
        return 1;
    if (!sig->certs && !(sig->certs = sk_X509_new_null()))
        return 0;

    if (!sk_X509_push(sig->certs, cert))
        return 0;
    CRYPTO_add(&cert->references, 1, CRYPTO_LOCK_X509);
    return 1;
}

/*
 * Sign an OCSP request set the requestorName to the subjec name of an
 * optional signers certificate and include one or more optional certificates
 * in the request. Behaves like PKCS7_sign().
 */

int OCSP_request_sign(OCSP_REQUEST *req,
                      X509 *signer,
                      EVP_PKEY *key,
                      const EVP_MD *dgst,
                      STACK_OF(X509) *certs, unsigned long flags)
{
    int i;
    OCSP_SIGNATURE *sig;
    X509 *x;

    if (!OCSP_request_set1_name(req, X509_get_subject_name(signer)))
        goto err;

    if (!(req->optionalSignature = sig = OCSP_SIGNATURE_new()))
        goto err;
    if (key) {
        if (!X509_check_private_key(signer, key)) {
            OCSPerr(OCSP_F_OCSP_REQUEST_SIGN,
                    OCSP_R_PRIVATE_KEY_DOES_NOT_MATCH_CERTIFICATE);
            goto err;
        }
        if (!OCSP_REQUEST_sign(req, key, dgst))
            goto err;
    }

    if (!(flags & OCSP_NOCERTS)) {
        if (!OCSP_request_add1_cert(req, signer))
            goto err;
        for (i = 0; i < sk_X509_num(certs); i++) {
            x = sk_X509_value(certs, i);
            if (!OCSP_request_add1_cert(req, x))
                goto err;
        }
    }

    return 1;
 err:
    OCSP_SIGNATURE_free(req->optionalSignature);
    req->optionalSignature = NULL;
    return 0;
}

/* Get response status */

int OCSP_response_status(OCSP_RESPONSE *resp)
{
    return ASN1_ENUMERATED_get(resp->responseStatus);
}

/*
 * Extract basic response from OCSP_RESPONSE or NULL if no basic response
 * present.
 */

OCSP_BASICRESP *OCSP_response_get1_basic(OCSP_RESPONSE *resp)
{
    OCSP_RESPBYTES *rb;
    rb = resp->responseBytes;
    if (!rb) {
        OCSPerr(OCSP_F_OCSP_RESPONSE_GET1_BASIC, OCSP_R_NO_RESPONSE_DATA);
        return NULL;
    }
    if (OBJ_obj2nid(rb->responseType) != NID_id_pkix_OCSP_basic) {
        OCSPerr(OCSP_F_OCSP_RESPONSE_GET1_BASIC, OCSP_R_NOT_BASIC_RESPONSE);
        return NULL;
    }

    return ASN1_item_unpack(rb->response, ASN1_ITEM_rptr(OCSP_BASICRESP));
}

/*
 * Return number of OCSP_SINGLERESP reponses present in a basic response.
 */

int OCSP_resp_count(OCSP_BASICRESP *bs)
{
    if (!bs)
        return -1;
    return sk_OCSP_SINGLERESP_num(bs->tbsResponseData->responses);
}

/* Extract an OCSP_SINGLERESP response with a given index */

OCSP_SINGLERESP *OCSP_resp_get0(OCSP_BASICRESP *bs, int idx)
{
    if (!bs)
        return NULL;
    return sk_OCSP_SINGLERESP_value(bs->tbsResponseData->responses, idx);
}

/* Look single response matching a given certificate ID */

int OCSP_resp_find(OCSP_BASICRESP *bs, OCSP_CERTID *id, int last)
{
    int i;
    STACK_OF(OCSP_SINGLERESP) *sresp;
    OCSP_SINGLERESP *single;
    if (!bs)
        return -1;
    if (last < 0)
        last = 0;
    else
        last++;
    sresp = bs->tbsResponseData->responses;
    for (i = last; i < sk_OCSP_SINGLERESP_num(sresp); i++) {
        single = sk_OCSP_SINGLERESP_value(sresp, i);
        if (!OCSP_id_cmp(id, single->certId))
            return i;
    }
    return -1;
}

/*
 * Extract status information from an OCSP_SINGLERESP structure. Note: the
 * revtime and reason values are only set if the certificate status is
 * revoked. Returns numerical value of status.
 */

int OCSP_single_get0_status(OCSP_SINGLERESP *single, int *reason,
                            ASN1_GENERALIZEDTIME **revtime,
                            ASN1_GENERALIZEDTIME **thisupd,
                            ASN1_GENERALIZEDTIME **nextupd)
{
    int ret;
    OCSP_CERTSTATUS *cst;
    if (!single)
        return -1;
    cst = single->certStatus;
    ret = cst->type;
    if (ret == V_OCSP_CERTSTATUS_REVOKED) {
        OCSP_REVOKEDINFO *rev = cst->value.revoked;
        if (revtime)
            *revtime = rev->revocationTime;
        if (reason) {
            if (rev->revocationReason)
                *reason = ASN1_ENUMERATED_get(rev->revocationReason);
            else
                *reason = -1;
        }
    }
    if (thisupd)
        *thisupd = single->thisUpdate;
    if (nextupd)
        *nextupd = single->nextUpdate;
    return ret;
}

/*
 * This function combines the previous ones: look up a certificate ID and if
 * found extract status information. Return 0 is successful.
 */

int OCSP_resp_find_status(OCSP_BASICRESP *bs, OCSP_CERTID *id, int *status,
                          int *reason,
                          ASN1_GENERALIZEDTIME **revtime,
                          ASN1_GENERALIZEDTIME **thisupd,
                          ASN1_GENERALIZEDTIME **nextupd)
{
    int i;
    OCSP_SINGLERESP *single;
    i = OCSP_resp_find(bs, id, -1);
    /* Maybe check for multiple responses and give an error? */
    if (i < 0)
        return 0;
    single = OCSP_resp_get0(bs, i);
    i = OCSP_single_get0_status(single, reason, revtime, thisupd, nextupd);
    if (status)
        *status = i;
    return 1;
}

/*
 * Check validity of thisUpdate and nextUpdate fields. It is possible that
 * the request will take a few seconds to process and/or the time wont be
 * totally accurate. Therefore to avoid rejecting otherwise valid time we
 * allow the times to be within 'nsec' of the current time. Also to avoid
 * accepting very old responses without a nextUpdate field an optional maxage
 * parameter specifies the maximum age the thisUpdate field can be.
 */

int OCSP_check_validity(ASN1_GENERALIZEDTIME *thisupd,
                        ASN1_GENERALIZEDTIME *nextupd, long nsec, long maxsec)
{
    int ret = 1;
    time_t t_now, t_tmp;
    time(&t_now);
    /* Check thisUpdate is valid and not more than nsec in the future */
    if (!ASN1_GENERALIZEDTIME_check(thisupd)) {
        OCSPerr(OCSP_F_OCSP_CHECK_VALIDITY, OCSP_R_ERROR_IN_THISUPDATE_FIELD);
        ret = 0;
    } else {
        t_tmp = t_now + nsec;
        if (X509_cmp_time(thisupd, &t_tmp) > 0) {
            OCSPerr(OCSP_F_OCSP_CHECK_VALIDITY, OCSP_R_STATUS_NOT_YET_VALID);
            ret = 0;
        }

        /*
         * If maxsec specified check thisUpdate is not more than maxsec in
         * the past
         */
        if (maxsec >= 0) {
            t_tmp = t_now - maxsec;
            if (X509_cmp_time(thisupd, &t_tmp) < 0) {
                OCSPerr(OCSP_F_OCSP_CHECK_VALIDITY, OCSP_R_STATUS_TOO_OLD);
                ret = 0;
            }
        }
    }

    if (!nextupd)
        return ret;

    /* Check nextUpdate is valid and not more than nsec in the past */
    if (!ASN1_GENERALIZEDTIME_check(nextupd)) {
        OCSPerr(OCSP_F_OCSP_CHECK_VALIDITY, OCSP_R_ERROR_IN_NEXTUPDATE_FIELD);
        ret = 0;
    } else {
        t_tmp = t_now - nsec;
        if (X509_cmp_time(nextupd, &t_tmp) < 0) {
            OCSPerr(OCSP_F_OCSP_CHECK_VALIDITY, OCSP_R_STATUS_EXPIRED);
            ret = 0;
        }
    }

    /* Also don't allow nextUpdate to precede thisUpdate */
    if (ASN1_STRING_cmp(nextupd, thisupd) < 0) {
        OCSPerr(OCSP_F_OCSP_CHECK_VALIDITY,
                OCSP_R_NEXTUPDATE_BEFORE_THISUPDATE);
        ret = 0;
    }

    return ret;
}
/* crypto/ocsp/ocsp_err.c */
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
// #include "ocsp.h"

/* BEGIN ERROR CODES */
#ifndef OPENSSL_NO_ERR

# define ERR_FUNC(func) ERR_PACK(ERR_LIB_OCSP,func,0)
# define ERR_REASON(reason) ERR_PACK(ERR_LIB_OCSP,0,reason)

static ERR_STRING_DATA OCSP_str_functs[] = {
    {ERR_FUNC(OCSP_F_ASN1_STRING_ENCODE), "ASN1_STRING_encode"},
    {ERR_FUNC(OCSP_F_D2I_OCSP_NONCE), "D2I_OCSP_NONCE"},
    {ERR_FUNC(OCSP_F_OCSP_BASIC_ADD1_STATUS), "OCSP_basic_add1_status"},
    {ERR_FUNC(OCSP_F_OCSP_BASIC_SIGN), "OCSP_basic_sign"},
    {ERR_FUNC(OCSP_F_OCSP_BASIC_VERIFY), "OCSP_basic_verify"},
    {ERR_FUNC(OCSP_F_OCSP_CERT_ID_NEW), "OCSP_cert_id_new"},
    {ERR_FUNC(OCSP_F_OCSP_CHECK_DELEGATED), "OCSP_CHECK_DELEGATED"},
    {ERR_FUNC(OCSP_F_OCSP_CHECK_IDS), "OCSP_CHECK_IDS"},
    {ERR_FUNC(OCSP_F_OCSP_CHECK_ISSUER), "OCSP_CHECK_ISSUER"},
    {ERR_FUNC(OCSP_F_OCSP_CHECK_VALIDITY), "OCSP_check_validity"},
    {ERR_FUNC(OCSP_F_OCSP_MATCH_ISSUERID), "OCSP_MATCH_ISSUERID"},
    {ERR_FUNC(OCSP_F_OCSP_PARSE_URL), "OCSP_parse_url"},
    {ERR_FUNC(OCSP_F_OCSP_REQUEST_SIGN), "OCSP_request_sign"},
    {ERR_FUNC(OCSP_F_OCSP_REQUEST_VERIFY), "OCSP_request_verify"},
    {ERR_FUNC(OCSP_F_OCSP_RESPONSE_GET1_BASIC), "OCSP_response_get1_basic"},
    {ERR_FUNC(OCSP_F_OCSP_SENDREQ_BIO), "OCSP_sendreq_bio"},
    {ERR_FUNC(OCSP_F_OCSP_SENDREQ_NBIO), "OCSP_sendreq_nbio"},
    {ERR_FUNC(OCSP_F_PARSE_HTTP_LINE1), "PARSE_HTTP_LINE1"},
    {ERR_FUNC(OCSP_F_REQUEST_VERIFY), "REQUEST_VERIFY"},
    {0, NULL}
};

static ERR_STRING_DATA OCSP_str_reasons[] = {
    {ERR_REASON(OCSP_R_BAD_DATA), "bad data"},
    {ERR_REASON(OCSP_R_CERTIFICATE_VERIFY_ERROR), "certificate verify error"},
    {ERR_REASON(OCSP_R_DIGEST_ERR), "digest err"},
    {ERR_REASON(OCSP_R_ERROR_IN_NEXTUPDATE_FIELD),
     "error in nextupdate field"},
    {ERR_REASON(OCSP_R_ERROR_IN_THISUPDATE_FIELD),
     "error in thisupdate field"},
    {ERR_REASON(OCSP_R_ERROR_PARSING_URL), "error parsing url"},
    {ERR_REASON(OCSP_R_MISSING_OCSPSIGNING_USAGE),
     "missing ocspsigning usage"},
    {ERR_REASON(OCSP_R_NEXTUPDATE_BEFORE_THISUPDATE),
     "nextupdate before thisupdate"},
    {ERR_REASON(OCSP_R_NOT_BASIC_RESPONSE), "not basic response"},
    {ERR_REASON(OCSP_R_NO_CERTIFICATES_IN_CHAIN), "no certificates in chain"},
    {ERR_REASON(OCSP_R_NO_CONTENT), "no content"},
    {ERR_REASON(OCSP_R_NO_PUBLIC_KEY), "no public key"},
    {ERR_REASON(OCSP_R_NO_RESPONSE_DATA), "no response data"},
    {ERR_REASON(OCSP_R_NO_REVOKED_TIME), "no revoked time"},
    {ERR_REASON(OCSP_R_PRIVATE_KEY_DOES_NOT_MATCH_CERTIFICATE),
     "private key does not match certificate"},
    {ERR_REASON(OCSP_R_REQUEST_NOT_SIGNED), "request not signed"},
    {ERR_REASON(OCSP_R_RESPONSE_CONTAINS_NO_REVOCATION_DATA),
     "response contains no revocation data"},
    {ERR_REASON(OCSP_R_ROOT_CA_NOT_TRUSTED), "root ca not trusted"},
    {ERR_REASON(OCSP_R_SERVER_READ_ERROR), "server read error"},
    {ERR_REASON(OCSP_R_SERVER_RESPONSE_ERROR), "server response error"},
    {ERR_REASON(OCSP_R_SERVER_RESPONSE_PARSE_ERROR),
     "server response parse error"},
    {ERR_REASON(OCSP_R_SERVER_WRITE_ERROR), "server write error"},
    {ERR_REASON(OCSP_R_SIGNATURE_FAILURE), "signature failure"},
    {ERR_REASON(OCSP_R_SIGNER_CERTIFICATE_NOT_FOUND),
     "signer certificate not found"},
    {ERR_REASON(OCSP_R_STATUS_EXPIRED), "status expired"},
    {ERR_REASON(OCSP_R_STATUS_NOT_YET_VALID), "status not yet valid"},
    {ERR_REASON(OCSP_R_STATUS_TOO_OLD), "status too old"},
    {ERR_REASON(OCSP_R_UNKNOWN_MESSAGE_DIGEST), "unknown message digest"},
    {ERR_REASON(OCSP_R_UNKNOWN_NID), "unknown nid"},
    {ERR_REASON(OCSP_R_UNSUPPORTED_REQUESTORNAME_TYPE),
     "unsupported requestorname type"},
    {0, NULL}
};

#endif

void ERR_load_OCSP_strings(void)
{
#ifndef OPENSSL_NO_ERR

    if (ERR_func_error_string(OCSP_str_functs[0].error) == NULL) {
        ERR_load_strings(0, OCSP_str_functs);
        ERR_load_strings(0, OCSP_str_reasons);
    }
#endif
}
/* ocsp_ext.c */
/*
 * Written by Tom Titchener <Tom_Titchener@groove.net> for the OpenSSL
 * project.
 */

/*
 * History: This file was transfered to Richard Levitte from CertCo by Kathy
 * Weinhold in mid-spring 2000 to be included in OpenSSL or released as a
 * patch kit.
 */

/* ====================================================================
 * Copyright (c) 1998-2000 The OpenSSL Project.  All rights reserved.
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
// #include "objects.h"
// #include "x509.h"
// #include "ocsp.h"
// #include "rand.h"
// #include "x509v3.h"

/* Standard wrapper functions for extensions */

/* OCSP request extensions */

int OCSP_REQUEST_get_ext_count(OCSP_REQUEST *x)
{
    return (X509v3_get_ext_count(x->tbsRequest->requestExtensions));
}

int OCSP_REQUEST_get_ext_by_NID(OCSP_REQUEST *x, int nid, int lastpos)
{
    return (X509v3_get_ext_by_NID
            (x->tbsRequest->requestExtensions, nid, lastpos));
}

int OCSP_REQUEST_get_ext_by_OBJ(OCSP_REQUEST *x, ASN1_OBJECT *obj,
                                int lastpos)
{
    return (X509v3_get_ext_by_OBJ
            (x->tbsRequest->requestExtensions, obj, lastpos));
}

int OCSP_REQUEST_get_ext_by_critical(OCSP_REQUEST *x, int crit, int lastpos)
{
    return (X509v3_get_ext_by_critical
            (x->tbsRequest->requestExtensions, crit, lastpos));
}

X509_EXTENSION *OCSP_REQUEST_get_ext(OCSP_REQUEST *x, int loc)
{
    return (X509v3_get_ext(x->tbsRequest->requestExtensions, loc));
}

X509_EXTENSION *OCSP_REQUEST_delete_ext(OCSP_REQUEST *x, int loc)
{
    return (X509v3_delete_ext(x->tbsRequest->requestExtensions, loc));
}

void *OCSP_REQUEST_get1_ext_d2i(OCSP_REQUEST *x, int nid, int *crit, int *idx)
{
    return X509V3_get_d2i(x->tbsRequest->requestExtensions, nid, crit, idx);
}

int OCSP_REQUEST_add1_ext_i2d(OCSP_REQUEST *x, int nid, void *value, int crit,
                              unsigned long flags)
{
    return X509V3_add1_i2d(&x->tbsRequest->requestExtensions, nid, value,
                           crit, flags);
}

int OCSP_REQUEST_add_ext(OCSP_REQUEST *x, X509_EXTENSION *ex, int loc)
{
    return (X509v3_add_ext(&(x->tbsRequest->requestExtensions), ex, loc) !=
            NULL);
}

/* Single extensions */

int OCSP_ONEREQ_get_ext_count(OCSP_ONEREQ *x)
{
    return (X509v3_get_ext_count(x->singleRequestExtensions));
}

int OCSP_ONEREQ_get_ext_by_NID(OCSP_ONEREQ *x, int nid, int lastpos)
{
    return (X509v3_get_ext_by_NID(x->singleRequestExtensions, nid, lastpos));
}

int OCSP_ONEREQ_get_ext_by_OBJ(OCSP_ONEREQ *x, ASN1_OBJECT *obj, int lastpos)
{
    return (X509v3_get_ext_by_OBJ(x->singleRequestExtensions, obj, lastpos));
}

int OCSP_ONEREQ_get_ext_by_critical(OCSP_ONEREQ *x, int crit, int lastpos)
{
    return (X509v3_get_ext_by_critical
            (x->singleRequestExtensions, crit, lastpos));
}

X509_EXTENSION *OCSP_ONEREQ_get_ext(OCSP_ONEREQ *x, int loc)
{
    return (X509v3_get_ext(x->singleRequestExtensions, loc));
}

X509_EXTENSION *OCSP_ONEREQ_delete_ext(OCSP_ONEREQ *x, int loc)
{
    return (X509v3_delete_ext(x->singleRequestExtensions, loc));
}

void *OCSP_ONEREQ_get1_ext_d2i(OCSP_ONEREQ *x, int nid, int *crit, int *idx)
{
    return X509V3_get_d2i(x->singleRequestExtensions, nid, crit, idx);
}

int OCSP_ONEREQ_add1_ext_i2d(OCSP_ONEREQ *x, int nid, void *value, int crit,
                             unsigned long flags)
{
    return X509V3_add1_i2d(&x->singleRequestExtensions, nid, value, crit,
                           flags);
}

int OCSP_ONEREQ_add_ext(OCSP_ONEREQ *x, X509_EXTENSION *ex, int loc)
{
    return (X509v3_add_ext(&(x->singleRequestExtensions), ex, loc) != NULL);
}

/* OCSP Basic response */

int OCSP_BASICRESP_get_ext_count(OCSP_BASICRESP *x)
{
    return (X509v3_get_ext_count(x->tbsResponseData->responseExtensions));
}

int OCSP_BASICRESP_get_ext_by_NID(OCSP_BASICRESP *x, int nid, int lastpos)
{
    return (X509v3_get_ext_by_NID
            (x->tbsResponseData->responseExtensions, nid, lastpos));
}

int OCSP_BASICRESP_get_ext_by_OBJ(OCSP_BASICRESP *x, ASN1_OBJECT *obj,
                                  int lastpos)
{
    return (X509v3_get_ext_by_OBJ
            (x->tbsResponseData->responseExtensions, obj, lastpos));
}

int OCSP_BASICRESP_get_ext_by_critical(OCSP_BASICRESP *x, int crit,
                                       int lastpos)
{
    return (X509v3_get_ext_by_critical
            (x->tbsResponseData->responseExtensions, crit, lastpos));
}

X509_EXTENSION *OCSP_BASICRESP_get_ext(OCSP_BASICRESP *x, int loc)
{
    return (X509v3_get_ext(x->tbsResponseData->responseExtensions, loc));
}

X509_EXTENSION *OCSP_BASICRESP_delete_ext(OCSP_BASICRESP *x, int loc)
{
    return (X509v3_delete_ext(x->tbsResponseData->responseExtensions, loc));
}

void *OCSP_BASICRESP_get1_ext_d2i(OCSP_BASICRESP *x, int nid, int *crit,
                                  int *idx)
{
    return X509V3_get_d2i(x->tbsResponseData->responseExtensions, nid, crit,
                          idx);
}

int OCSP_BASICRESP_add1_ext_i2d(OCSP_BASICRESP *x, int nid, void *value,
                                int crit, unsigned long flags)
{
    return X509V3_add1_i2d(&x->tbsResponseData->responseExtensions, nid,
                           value, crit, flags);
}

int OCSP_BASICRESP_add_ext(OCSP_BASICRESP *x, X509_EXTENSION *ex, int loc)
{
    return (X509v3_add_ext(&(x->tbsResponseData->responseExtensions), ex, loc)
            != NULL);
}

/* OCSP single response extensions */

int OCSP_SINGLERESP_get_ext_count(OCSP_SINGLERESP *x)
{
    return (X509v3_get_ext_count(x->singleExtensions));
}

int OCSP_SINGLERESP_get_ext_by_NID(OCSP_SINGLERESP *x, int nid, int lastpos)
{
    return (X509v3_get_ext_by_NID(x->singleExtensions, nid, lastpos));
}

int OCSP_SINGLERESP_get_ext_by_OBJ(OCSP_SINGLERESP *x, ASN1_OBJECT *obj,
                                   int lastpos)
{
    return (X509v3_get_ext_by_OBJ(x->singleExtensions, obj, lastpos));
}

int OCSP_SINGLERESP_get_ext_by_critical(OCSP_SINGLERESP *x, int crit,
                                        int lastpos)
{
    return (X509v3_get_ext_by_critical(x->singleExtensions, crit, lastpos));
}

X509_EXTENSION *OCSP_SINGLERESP_get_ext(OCSP_SINGLERESP *x, int loc)
{
    return (X509v3_get_ext(x->singleExtensions, loc));
}

X509_EXTENSION *OCSP_SINGLERESP_delete_ext(OCSP_SINGLERESP *x, int loc)
{
    return (X509v3_delete_ext(x->singleExtensions, loc));
}

void *OCSP_SINGLERESP_get1_ext_d2i(OCSP_SINGLERESP *x, int nid, int *crit,
                                   int *idx)
{
    return X509V3_get_d2i(x->singleExtensions, nid, crit, idx);
}

int OCSP_SINGLERESP_add1_ext_i2d(OCSP_SINGLERESP *x, int nid, void *value,
                                 int crit, unsigned long flags)
{
    return X509V3_add1_i2d(&x->singleExtensions, nid, value, crit, flags);
}

int OCSP_SINGLERESP_add_ext(OCSP_SINGLERESP *x, X509_EXTENSION *ex, int loc)
{
    return (X509v3_add_ext(&(x->singleExtensions), ex, loc) != NULL);
}

/* also CRL Entry Extensions */
#if 0
ASN1_STRING *ASN1_STRING_encode(ASN1_STRING *s, i2d_of_void *i2d,
                                void *data, STACK_OF(ASN1_OBJECT) *sk)
{
    int i;
    unsigned char *p, *b = NULL;

    if (data) {
        if ((i = i2d(data, NULL)) <= 0)
            goto err;
        if (!(b = p = OPENSSL_malloc((unsigned int)i)))
            goto err;
        if (i2d(data, &p) <= 0)
            goto err;
    } else if (sk) {
        if ((i = i2d_ASN1_SET_OF_ASN1_OBJECT(sk, NULL,
                                             (I2D_OF(ASN1_OBJECT)) i2d,
                                             V_ASN1_SEQUENCE,
                                             V_ASN1_UNIVERSAL,
                                             IS_SEQUENCE)) <= 0)
             goto err;
        if (!(b = p = OPENSSL_malloc((unsigned int)i)))
            goto err;
        if (i2d_ASN1_SET_OF_ASN1_OBJECT(sk, &p, (I2D_OF(ASN1_OBJECT)) i2d,
                                        V_ASN1_SEQUENCE,
                                        V_ASN1_UNIVERSAL, IS_SEQUENCE) <= 0)
             goto err;
    } else {
        OCSPerr(OCSP_F_ASN1_STRING_ENCODE, OCSP_R_BAD_DATA);
        goto err;
    }
    if (!s && !(s = ASN1_STRING_new()))
        goto err;
    if (!(ASN1_STRING_set(s, b, i)))
        goto err;
    OPENSSL_free(b);
    return s;
 err:
    if (b)
        OPENSSL_free(b);
    return NULL;
}
#endif

/* Nonce handling functions */

/*
 * Add a nonce to an extension stack. A nonce can be specificed or if NULL a
 * random nonce will be generated. Note: OpenSSL 0.9.7d and later create an
 * OCTET STRING containing the nonce, previous versions used the raw nonce.
 */

static int ocsp_add1_nonce(STACK_OF(X509_EXTENSION) **exts,
                           unsigned char *val, int len)
{
    unsigned char *tmpval;
    ASN1_OCTET_STRING os;
    int ret = 0;
    if (len <= 0)
        len = OCSP_DEFAULT_NONCE_LENGTH;
    /*
     * Create the OCTET STRING manually by writing out the header and
     * appending the content octets. This avoids an extra memory allocation
     * operation in some cases. Applications should *NOT* do this because it
     * relies on library internals.
     */
    os.length = ASN1_object_size(0, len, V_ASN1_OCTET_STRING);
    os.data = OPENSSL_malloc(os.length);
    if (os.data == NULL)
        goto err;
    tmpval = os.data;
    ASN1_put_object(&tmpval, 0, len, V_ASN1_OCTET_STRING, V_ASN1_UNIVERSAL);
    if (val)
        memcpy(tmpval, val, len);
    else if (RAND_bytes(tmpval, len) <= 0)
        goto err;
    if (!X509V3_add1_i2d(exts, NID_id_pkix_OCSP_Nonce,
                         &os, 0, X509V3_ADD_REPLACE))
        goto err;
    ret = 1;
 err:
    if (os.data)
        OPENSSL_free(os.data);
    return ret;
}

/* Add nonce to an OCSP request */

int OCSP_request_add1_nonce(OCSP_REQUEST *req, unsigned char *val, int len)
{
    return ocsp_add1_nonce(&req->tbsRequest->requestExtensions, val, len);
}

/* Same as above but for a response */

int OCSP_basic_add1_nonce(OCSP_BASICRESP *resp, unsigned char *val, int len)
{
    return ocsp_add1_nonce(&resp->tbsResponseData->responseExtensions, val,
                           len);
}

/*-
 * Check nonce validity in a request and response.
 * Return value reflects result:
 *  1: nonces present and equal.
 *  2: nonces both absent.
 *  3: nonce present in response only.
 *  0: nonces both present and not equal.
 * -1: nonce in request only.
 *
 *  For most responders clients can check return > 0.
 *  If responder doesn't handle nonces return != 0 may be
 *  necessary. return == 0 is always an error.
 */

int OCSP_check_nonce(OCSP_REQUEST *req, OCSP_BASICRESP *bs)
{
    /*
     * Since we are only interested in the presence or absence of
     * the nonce and comparing its value there is no need to use
     * the X509V3 routines: this way we can avoid them allocating an
     * ASN1_OCTET_STRING structure for the value which would be
     * freed immediately anyway.
     */

    int req_idx, resp_idx;
    X509_EXTENSION *req_ext, *resp_ext;
    req_idx = OCSP_REQUEST_get_ext_by_NID(req, NID_id_pkix_OCSP_Nonce, -1);
    resp_idx = OCSP_BASICRESP_get_ext_by_NID(bs, NID_id_pkix_OCSP_Nonce, -1);
    /* Check both absent */
    if ((req_idx < 0) && (resp_idx < 0))
        return 2;
    /* Check in request only */
    if ((req_idx >= 0) && (resp_idx < 0))
        return -1;
    /* Check in response but not request */
    if ((req_idx < 0) && (resp_idx >= 0))
        return 3;
    /*
     * Otherwise nonce in request and response so retrieve the extensions
     */
    req_ext = OCSP_REQUEST_get_ext(req, req_idx);
    resp_ext = OCSP_BASICRESP_get_ext(bs, resp_idx);
    if (ASN1_OCTET_STRING_cmp(req_ext->value, resp_ext->value))
        return 0;
    return 1;
}

/*
 * Copy the nonce value (if any) from an OCSP request to a response.
 */

int OCSP_copy_nonce(OCSP_BASICRESP *resp, OCSP_REQUEST *req)
{
    X509_EXTENSION *req_ext;
    int req_idx;
    /* Check for nonce in request */
    req_idx = OCSP_REQUEST_get_ext_by_NID(req, NID_id_pkix_OCSP_Nonce, -1);
    /* If no nonce that's OK */
    if (req_idx < 0)
        return 2;
    req_ext = OCSP_REQUEST_get_ext(req, req_idx);
    return OCSP_BASICRESP_add_ext(resp, req_ext, -1);
}

X509_EXTENSION *OCSP_crlID_new(char *url, long *n, char *tim)
{
    X509_EXTENSION *x = NULL;
    OCSP_CRLID *cid = NULL;

    if (!(cid = OCSP_CRLID_new()))
        goto err;
    if (url) {
        if (!(cid->crlUrl = ASN1_IA5STRING_new()))
            goto err;
        if (!(ASN1_STRING_set(cid->crlUrl, url, -1)))
            goto err;
    }
    if (n) {
        if (!(cid->crlNum = ASN1_INTEGER_new()))
            goto err;
        if (!(ASN1_INTEGER_set(cid->crlNum, *n)))
            goto err;
    }
    if (tim) {
        if (!(cid->crlTime = ASN1_GENERALIZEDTIME_new()))
            goto err;
        if (!(ASN1_GENERALIZEDTIME_set_string(cid->crlTime, tim)))
            goto err;
    }
    x = X509V3_EXT_i2d(NID_id_pkix_OCSP_CrlID, 0, cid);
 err:
    if (cid)
        OCSP_CRLID_free(cid);
    return x;
}

/*   AcceptableResponses ::= SEQUENCE OF OBJECT IDENTIFIER */
X509_EXTENSION *OCSP_accept_responses_new(char **oids)
{
    int nid;
    STACK_OF(ASN1_OBJECT) *sk = NULL;
    ASN1_OBJECT *o = NULL;
    X509_EXTENSION *x = NULL;

    if (!(sk = sk_ASN1_OBJECT_new_null()))
        goto err;
    while (oids && *oids) {
        if ((nid = OBJ_txt2nid(*oids)) != NID_undef && (o = OBJ_nid2obj(nid)))
            sk_ASN1_OBJECT_push(sk, o);
        oids++;
    }
    x = X509V3_EXT_i2d(NID_id_pkix_OCSP_acceptableResponses, 0, sk);
 err:
    if (sk)
        sk_ASN1_OBJECT_pop_free(sk, ASN1_OBJECT_free);
    return x;
}

/*  ArchiveCutoff ::= GeneralizedTime */
X509_EXTENSION *OCSP_archive_cutoff_new(char *tim)
{
    X509_EXTENSION *x = NULL;
    ASN1_GENERALIZEDTIME *gt = NULL;

    if (!(gt = ASN1_GENERALIZEDTIME_new()))
        goto err;
    if (!(ASN1_GENERALIZEDTIME_set_string(gt, tim)))
        goto err;
    x = X509V3_EXT_i2d(NID_id_pkix_OCSP_archiveCutoff, 0, gt);
 err:
    if (gt)
        ASN1_GENERALIZEDTIME_free(gt);
    return x;
}

/*
 * per ACCESS_DESCRIPTION parameter are oids, of which there are currently
 * two--NID_ad_ocsp, NID_id_ad_caIssuers--and GeneralName value.  This method
 * forces NID_ad_ocsp and uniformResourceLocator [6] IA5String.
 */
X509_EXTENSION *OCSP_url_svcloc_new(X509_NAME *issuer, char **urls)
{
    X509_EXTENSION *x = NULL;
    ASN1_IA5STRING *ia5 = NULL;
    OCSP_SERVICELOC *sloc = NULL;
    ACCESS_DESCRIPTION *ad = NULL;

    if (!(sloc = OCSP_SERVICELOC_new()))
        goto err;
    if (!(sloc->issuer = X509_NAME_dup(issuer)))
        goto err;
    if (urls && *urls && !(sloc->locator = sk_ACCESS_DESCRIPTION_new_null()))
        goto err;
    while (urls && *urls) {
        if (!(ad = ACCESS_DESCRIPTION_new()))
            goto err;
        if (!(ad->method = OBJ_nid2obj(NID_ad_OCSP)))
            goto err;
        if (!(ad->location = GENERAL_NAME_new()))
            goto err;
        if (!(ia5 = ASN1_IA5STRING_new()))
            goto err;
        if (!ASN1_STRING_set((ASN1_STRING *)ia5, *urls, -1))
            goto err;
        ad->location->type = GEN_URI;
        ad->location->d.ia5 = ia5;
        if (!sk_ACCESS_DESCRIPTION_push(sloc->locator, ad))
            goto err;
        urls++;
    }
    x = X509V3_EXT_i2d(NID_id_pkix_OCSP_serviceLocator, 0, sloc);
 err:
    if (sloc)
        OCSP_SERVICELOC_free(sloc);
    return x;
}
/* ocsp_ht.c */
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
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include "e_os.h"
// #include "asn1.h"
// #include "ocsp.h"
// #include "err.h"
#include "buffer.h"
#ifdef OPENSSL_SYS_SUNOS
# define strtoul (unsigned long)strtol
#endif                          /* OPENSSL_SYS_SUNOS */

/* Stateful OCSP request code, supporting non-blocking I/O */

/* Opaque OCSP request status structure */

struct ocsp_req_ctx_st {
    int state;                  /* Current I/O state */
    unsigned char *iobuf;       /* Line buffer */
    int iobuflen;               /* Line buffer length */
    BIO *io;                    /* BIO to perform I/O with */
    BIO *mem;                   /* Memory BIO response is built into */
    unsigned long asn1_len;     /* ASN1 length of response */
    unsigned long max_resp_len; /* Maximum length of response */
};

#define OCSP_MAX_RESP_LENGTH    (100 * 1024)
#define OCSP_MAX_LINE_LEN       4096;

/* OCSP states */

/* If set no reading should be performed */
#define OHS_NOREAD              0x1000
/* Error condition */
#define OHS_ERROR               (0 | OHS_NOREAD)
/* First line being read */
#define OHS_FIRSTLINE           1
/* MIME headers being read */
#define OHS_HEADERS             2
/* OCSP initial header (tag + length) being read */
#define OHS_ASN1_HEADER         3
/* OCSP content octets being read */
#define OHS_ASN1_CONTENT        4
/* First call: ready to start I/O */
#define OHS_ASN1_WRITE_INIT     (5 | OHS_NOREAD)
/* Request being sent */
#define OHS_ASN1_WRITE          (6 | OHS_NOREAD)
/* Request being flushed */
#define OHS_ASN1_FLUSH          (7 | OHS_NOREAD)
/* Completed */
#define OHS_DONE                (8 | OHS_NOREAD)
/* Headers set, no final \r\n included */
#define OHS_HTTP_HEADER         (9 | OHS_NOREAD)

static int parse_http_line1(char *line);

OCSP_REQ_CTX *OCSP_REQ_CTX_new(BIO *io, int maxline)
{
    OCSP_REQ_CTX *rctx;
    rctx = OPENSSL_malloc(sizeof(OCSP_REQ_CTX));
    if (!rctx)
        return NULL;
    rctx->state = OHS_ERROR;
    rctx->max_resp_len = OCSP_MAX_RESP_LENGTH;
    rctx->mem = BIO_new(BIO_s_mem());
    rctx->io = io;
    rctx->asn1_len = 0;
    if (maxline > 0)
        rctx->iobuflen = maxline;
    else
        rctx->iobuflen = OCSP_MAX_LINE_LEN;
    rctx->iobuf = OPENSSL_malloc(rctx->iobuflen);
    if (!rctx->iobuf || !rctx->mem) {
        OCSP_REQ_CTX_free(rctx);
        return NULL;
    }
    return rctx;
}

void OCSP_REQ_CTX_free(OCSP_REQ_CTX *rctx)
{
    if (rctx->mem)
        BIO_free(rctx->mem);
    if (rctx->iobuf)
        OPENSSL_free(rctx->iobuf);
    OPENSSL_free(rctx);
}

BIO *OCSP_REQ_CTX_get0_mem_bio(OCSP_REQ_CTX *rctx)
{
    return rctx->mem;
}

void OCSP_set_max_response_length(OCSP_REQ_CTX *rctx, unsigned long len)
{
    if (len == 0)
        rctx->max_resp_len = OCSP_MAX_RESP_LENGTH;
    else
        rctx->max_resp_len = len;
}

int OCSP_REQ_CTX_i2d(OCSP_REQ_CTX *rctx, const ASN1_ITEM *it, ASN1_VALUE *val)
{
    static const char req_hdr[] =
        "Content-Type: application/ocsp-request\r\n"
        "Content-Length: %d\r\n\r\n";
    int reqlen = ASN1_item_i2d(val, NULL, it);
    if (BIO_printf(rctx->mem, req_hdr, reqlen) <= 0)
        return 0;
    if (ASN1_item_i2d_bio(it, rctx->mem, val) <= 0)
        return 0;
    rctx->state = OHS_ASN1_WRITE_INIT;
    return 1;
}

int OCSP_REQ_CTX_nbio_d2i(OCSP_REQ_CTX *rctx,
                          ASN1_VALUE **pval, const ASN1_ITEM *it)
{
    int rv, len;
    const unsigned char *p;

    rv = OCSP_REQ_CTX_nbio(rctx);
    if (rv != 1)
        return rv;

    len = BIO_get_mem_data(rctx->mem, &p);
    *pval = ASN1_item_d2i(NULL, &p, len, it);
    if (*pval == NULL) {
        rctx->state = OHS_ERROR;
        return 0;
    }
    return 1;
}

int OCSP_REQ_CTX_http(OCSP_REQ_CTX *rctx, const char *op, const char *path)
{
    static const char http_hdr[] = "%s %s HTTP/1.0\r\n";

    if (!path)
        path = "/";

    if (BIO_printf(rctx->mem, http_hdr, op, path) <= 0)
        return 0;
    rctx->state = OHS_HTTP_HEADER;
    return 1;
}

int OCSP_REQ_CTX_set1_req(OCSP_REQ_CTX *rctx, OCSP_REQUEST *req)
{
    return OCSP_REQ_CTX_i2d(rctx, ASN1_ITEM_rptr(OCSP_REQUEST),
                            (ASN1_VALUE *)req);
}

int OCSP_REQ_CTX_add1_header(OCSP_REQ_CTX *rctx,
                             const char *name, const char *value)
{
    if (!name)
        return 0;
    if (BIO_puts(rctx->mem, name) <= 0)
        return 0;
    if (value) {
        if (BIO_write(rctx->mem, ": ", 2) != 2)
            return 0;
        if (BIO_puts(rctx->mem, value) <= 0)
            return 0;
    }
    if (BIO_write(rctx->mem, "\r\n", 2) != 2)
        return 0;
    rctx->state = OHS_HTTP_HEADER;
    return 1;
}

OCSP_REQ_CTX *OCSP_sendreq_new(BIO *io, const char *path, OCSP_REQUEST *req,
                               int maxline)
{

    OCSP_REQ_CTX *rctx = NULL;
    rctx = OCSP_REQ_CTX_new(io, maxline);
    if (!rctx)
        return NULL;

    if (!OCSP_REQ_CTX_http(rctx, "POST", path))
        goto err;

    if (req && !OCSP_REQ_CTX_set1_req(rctx, req))
        goto err;

    return rctx;

 err:
    OCSP_REQ_CTX_free(rctx);
    return NULL;
}

/*
 * Parse the HTTP response. This will look like this: "HTTP/1.0 200 OK". We
 * need to obtain the numeric code and (optional) informational message.
 */

static int parse_http_line1(char *line)
{
    int retcode;
    char *p, *q, *r;
    /* Skip to first white space (passed protocol info) */

    for (p = line; *p && !isspace((unsigned char)*p); p++)
        continue;
    if (!*p) {
        OCSPerr(OCSP_F_PARSE_HTTP_LINE1, OCSP_R_SERVER_RESPONSE_PARSE_ERROR);
        return 0;
    }

    /* Skip past white space to start of response code */
    while (*p && isspace((unsigned char)*p))
        p++;

    if (!*p) {
        OCSPerr(OCSP_F_PARSE_HTTP_LINE1, OCSP_R_SERVER_RESPONSE_PARSE_ERROR);
        return 0;
    }

    /* Find end of response code: first whitespace after start of code */
    for (q = p; *q && !isspace((unsigned char)*q); q++)
        continue;

    if (!*q) {
        OCSPerr(OCSP_F_PARSE_HTTP_LINE1, OCSP_R_SERVER_RESPONSE_PARSE_ERROR);
        return 0;
    }

    /* Set end of response code and start of message */
    *q++ = 0;

    /* Attempt to parse numeric code */
    retcode = strtoul(p, &r, 10);

    if (*r)
        return 0;

    /* Skip over any leading white space in message */
    while (*q && isspace((unsigned char)*q))
        q++;

    if (*q) {
        /*
         * Finally zap any trailing white space in message (include CRLF)
         */

        /* We know q has a non white space character so this is OK */
        for (r = q + strlen(q) - 1; isspace((unsigned char)*r); r--)
            *r = 0;
    }
    if (retcode != 200) {
        OCSPerr(OCSP_F_PARSE_HTTP_LINE1, OCSP_R_SERVER_RESPONSE_ERROR);
        if (!*q)
            ERR_add_error_data(2, "Code=", p);
        else
            ERR_add_error_data(4, "Code=", p, ",Reason=", q);
        return 0;
    }

    return 1;

}

int OCSP_REQ_CTX_nbio(OCSP_REQ_CTX *rctx)
{
    int i, n;
    const unsigned char *p;
 next_io:
    if (!(rctx->state & OHS_NOREAD)) {
        n = BIO_read(rctx->io, rctx->iobuf, rctx->iobuflen);

        if (n <= 0) {
            if (BIO_should_retry(rctx->io))
                return -1;
            return 0;
        }

        /* Write data to memory BIO */

        if (BIO_write(rctx->mem, rctx->iobuf, n) != n)
            return 0;
    }

    switch (rctx->state) {
    case OHS_HTTP_HEADER:
        /* Last operation was adding headers: need a final \r\n */
        if (BIO_write(rctx->mem, "\r\n", 2) != 2) {
            rctx->state = OHS_ERROR;
            return 0;
        }
        rctx->state = OHS_ASN1_WRITE_INIT;

    case OHS_ASN1_WRITE_INIT:
        rctx->asn1_len = BIO_get_mem_data(rctx->mem, NULL);
        rctx->state = OHS_ASN1_WRITE;

    case OHS_ASN1_WRITE:
        n = BIO_get_mem_data(rctx->mem, &p);

        i = BIO_write(rctx->io, p + (n - rctx->asn1_len), rctx->asn1_len);

        if (i <= 0) {
            if (BIO_should_retry(rctx->io))
                return -1;
            rctx->state = OHS_ERROR;
            return 0;
        }

        rctx->asn1_len -= i;

        if (rctx->asn1_len > 0)
            goto next_io;

        rctx->state = OHS_ASN1_FLUSH;

        (void)BIO_reset(rctx->mem);

    case OHS_ASN1_FLUSH:

        i = BIO_flush(rctx->io);

        if (i > 0) {
            rctx->state = OHS_FIRSTLINE;
            goto next_io;
        }

        if (BIO_should_retry(rctx->io))
            return -1;

        rctx->state = OHS_ERROR;
        return 0;

    case OHS_ERROR:
        return 0;

    case OHS_FIRSTLINE:
    case OHS_HEADERS:

        /* Attempt to read a line in */

 next_line:
        /*
         * Due to &%^*$" memory BIO behaviour with BIO_gets we have to check
         * there's a complete line in there before calling BIO_gets or we'll
         * just get a partial read.
         */
        n = BIO_get_mem_data(rctx->mem, &p);
        if ((n <= 0) || !memchr(p, '\n', n)) {
            if (n >= rctx->iobuflen) {
                rctx->state = OHS_ERROR;
                return 0;
            }
            goto next_io;
        }
        n = BIO_gets(rctx->mem, (char *)rctx->iobuf, rctx->iobuflen);

        if (n <= 0) {
            if (BIO_should_retry(rctx->mem))
                goto next_io;
            rctx->state = OHS_ERROR;
            return 0;
        }

        /* Don't allow excessive lines */
        if (n == rctx->iobuflen) {
            rctx->state = OHS_ERROR;
            return 0;
        }

        /* First line */
        if (rctx->state == OHS_FIRSTLINE) {
            if (parse_http_line1((char *)rctx->iobuf)) {
                rctx->state = OHS_HEADERS;
                goto next_line;
            } else {
                rctx->state = OHS_ERROR;
                return 0;
            }
        } else {
            /* Look for blank line: end of headers */
            for (p = rctx->iobuf; *p; p++) {
                if ((*p != '\r') && (*p != '\n'))
                    break;
            }
            if (*p)
                goto next_line;

            rctx->state = OHS_ASN1_HEADER;

        }

        /* Fall thru */

    case OHS_ASN1_HEADER:
        /*
         * Now reading ASN1 header: can read at least 2 bytes which is enough
         * for ASN1 SEQUENCE header and either length field or at least the
         * length of the length field.
         */
        n = BIO_get_mem_data(rctx->mem, &p);
        if (n < 2)
            goto next_io;

        /* Check it is an ASN1 SEQUENCE */
        if (*p++ != (V_ASN1_SEQUENCE | V_ASN1_CONSTRUCTED)) {
            rctx->state = OHS_ERROR;
            return 0;
        }

        /* Check out length field */
        if (*p & 0x80) {
            /*
             * If MSB set on initial length octet we can now always read 6
             * octets: make sure we have them.
             */
            if (n < 6)
                goto next_io;
            n = *p & 0x7F;
            /* Not NDEF or excessive length */
            if (!n || (n > 4)) {
                rctx->state = OHS_ERROR;
                return 0;
            }
            p++;
            rctx->asn1_len = 0;
            for (i = 0; i < n; i++) {
                rctx->asn1_len <<= 8;
                rctx->asn1_len |= *p++;
            }

            if (rctx->asn1_len > rctx->max_resp_len) {
                rctx->state = OHS_ERROR;
                return 0;
            }

            rctx->asn1_len += n + 2;
        } else
            rctx->asn1_len = *p + 2;

        rctx->state = OHS_ASN1_CONTENT;

        /* Fall thru */

    case OHS_ASN1_CONTENT:
        n = BIO_get_mem_data(rctx->mem, NULL);
        if (n < (int)rctx->asn1_len)
            goto next_io;

        rctx->state = OHS_DONE;
        return 1;

        break;

    case OHS_DONE:
        return 1;

    }

    return 0;

}

int OCSP_sendreq_nbio(OCSP_RESPONSE **presp, OCSP_REQ_CTX *rctx)
{
    return OCSP_REQ_CTX_nbio_d2i(rctx,
                                 (ASN1_VALUE **)presp,
                                 ASN1_ITEM_rptr(OCSP_RESPONSE));
}

/* Blocking OCSP request handler: now a special case of non-blocking I/O */

OCSP_RESPONSE *OCSP_sendreq_bio(BIO *b, const char *path, OCSP_REQUEST *req)
{
    OCSP_RESPONSE *resp = NULL;
    OCSP_REQ_CTX *ctx;
    int rv;

    ctx = OCSP_sendreq_new(b, path, req, -1);

    if (!ctx)
        return NULL;

    do {
        rv = OCSP_sendreq_nbio(&resp, ctx);
    } while ((rv == -1) && BIO_should_retry(b));

    OCSP_REQ_CTX_free(ctx);

    if (rv)
        return resp;

    return NULL;
}
/* ocsp_lib.c */
/*
 * Written by Tom Titchener <Tom_Titchener@groove.net> for the OpenSSL
 * project.
 */

/*
 * History: This file was transfered to Richard Levitte from CertCo by Kathy
 * Weinhold in mid-spring 2000 to be included in OpenSSL or released as a
 * patch kit.
 */

/* ====================================================================
 * Copyright (c) 1998-2000 The OpenSSL Project.  All rights reserved.
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
// #include "objects.h"
// #include "rand.h"
// #include "x509.h"
// #include "pem.h"
// #include "x509v3.h"
// #include "ocsp.h"
// #include "asn1t.h"

/* Convert a certificate and its issuer to an OCSP_CERTID */

OCSP_CERTID *OCSP_cert_to_id(const EVP_MD *dgst, X509 *subject, X509 *issuer)
{
    X509_NAME *iname;
    ASN1_INTEGER *serial;
    ASN1_BIT_STRING *ikey;
#ifndef OPENSSL_NO_SHA1
    if (!dgst)
        dgst = EVP_sha1();
#endif
    if (subject) {
        iname = X509_get_issuer_name(subject);
        serial = X509_get_serialNumber(subject);
    } else {
        iname = X509_get_subject_name(issuer);
        serial = NULL;
    }
    ikey = X509_get0_pubkey_bitstr(issuer);
    return OCSP_cert_id_new(dgst, iname, ikey, serial);
}

OCSP_CERTID *OCSP_cert_id_new(const EVP_MD *dgst,
                              X509_NAME *issuerName,
                              ASN1_BIT_STRING *issuerKey,
                              ASN1_INTEGER *serialNumber)
{
    int nid;
    unsigned int i;
    X509_ALGOR *alg;
    OCSP_CERTID *cid = NULL;
    unsigned char md[EVP_MAX_MD_SIZE];

    if (!(cid = OCSP_CERTID_new()))
        goto err;

    alg = cid->hashAlgorithm;
    if (alg->algorithm != NULL)
        ASN1_OBJECT_free(alg->algorithm);
    if ((nid = EVP_MD_type(dgst)) == NID_undef) {
        OCSPerr(OCSP_F_OCSP_CERT_ID_NEW, OCSP_R_UNKNOWN_NID);
        goto err;
    }
    if (!(alg->algorithm = OBJ_nid2obj(nid)))
        goto err;
    if ((alg->parameter = ASN1_TYPE_new()) == NULL)
        goto err;
    alg->parameter->type = V_ASN1_NULL;

    if (!X509_NAME_digest(issuerName, dgst, md, &i))
        goto digerr;
    if (!(ASN1_OCTET_STRING_set(cid->issuerNameHash, md, i)))
        goto err;

    /* Calculate the issuerKey hash, excluding tag and length */
    if (!EVP_Digest(issuerKey->data, issuerKey->length, md, &i, dgst, NULL))
        goto err;

    if (!(ASN1_OCTET_STRING_set(cid->issuerKeyHash, md, i)))
        goto err;

    if (serialNumber) {
        ASN1_INTEGER_free(cid->serialNumber);
        if (!(cid->serialNumber = ASN1_INTEGER_dup(serialNumber)))
            goto err;
    }
    return cid;
 digerr:
    OCSPerr(OCSP_F_OCSP_CERT_ID_NEW, OCSP_R_DIGEST_ERR);
 err:
    if (cid)
        OCSP_CERTID_free(cid);
    return NULL;
}

int OCSP_id_issuer_cmp(OCSP_CERTID *a, OCSP_CERTID *b)
{
    int ret;
    ret = OBJ_cmp(a->hashAlgorithm->algorithm, b->hashAlgorithm->algorithm);
    if (ret)
        return ret;
    ret = ASN1_OCTET_STRING_cmp(a->issuerNameHash, b->issuerNameHash);
    if (ret)
        return ret;
    return ASN1_OCTET_STRING_cmp(a->issuerKeyHash, b->issuerKeyHash);
}

int OCSP_id_cmp(OCSP_CERTID *a, OCSP_CERTID *b)
{
    int ret;
    ret = OCSP_id_issuer_cmp(a, b);
    if (ret)
        return ret;
    return ASN1_INTEGER_cmp(a->serialNumber, b->serialNumber);
}

/*
 * Parse a URL and split it up into host, port and path components and
 * whether it is SSL.
 */

int OCSP_parse_url(const char *url, char **phost, char **pport, char **ppath,
                   int *pssl)
{
    char *p, *buf;

    char *host, *port;

    *phost = NULL;
    *pport = NULL;
    *ppath = NULL;

    /* dup the buffer since we are going to mess with it */
    buf = BUF_strdup(url);
    if (!buf)
        goto mem_err;

    /* Check for initial colon */
    p = strchr(buf, ':');

    if (!p)
        goto parse_err;

    *(p++) = '\0';

    if (!strcmp(buf, "http")) {
        *pssl = 0;
        port = "80";
    } else if (!strcmp(buf, "https")) {
        *pssl = 1;
        port = "443";
    } else
        goto parse_err;

    /* Check for double slash */
    if ((p[0] != '/') || (p[1] != '/'))
        goto parse_err;

    p += 2;

    host = p;

    /* Check for trailing part of path */

    p = strchr(p, '/');

    if (!p)
        *ppath = BUF_strdup("/");
    else {
        *ppath = BUF_strdup(p);
        /* Set start of path to 0 so hostname is valid */
        *p = '\0';
    }

    if (!*ppath)
        goto mem_err;

    p = host;
    if (host[0] == '[') {
        /* ipv6 literal */
        host++;
        p = strchr(host, ']');
        if (!p)
            goto parse_err;
        *p = '\0';
        p++;
    }

    /* Look for optional ':' for port number */
    if ((p = strchr(p, ':'))) {
        *p = 0;
        port = p + 1;
    }

    *pport = BUF_strdup(port);
    if (!*pport)
        goto mem_err;

    *phost = BUF_strdup(host);

    if (!*phost)
        goto mem_err;

    OPENSSL_free(buf);

    return 1;

 mem_err:
    OCSPerr(OCSP_F_OCSP_PARSE_URL, ERR_R_MALLOC_FAILURE);
    goto err;

 parse_err:
    OCSPerr(OCSP_F_OCSP_PARSE_URL, OCSP_R_ERROR_PARSING_URL);

 err:
    if (buf)
        OPENSSL_free(buf);
    if (*ppath) {
        OPENSSL_free(*ppath);
        *ppath = NULL;
    }
    if (*pport) {
        OPENSSL_free(*pport);
        *pport = NULL;
    }
    if (*phost) {
        OPENSSL_free(*phost);
        *phost = NULL;
    }
    return 0;

}

IMPLEMENT_ASN1_DUP_FUNCTION(OCSP_CERTID)
/* ocsp_prn.c */
/*
 * Written by Tom Titchener <Tom_Titchener@groove.net> for the OpenSSL
 * project.
 */

/*
 * History: This file was originally part of ocsp.c and was transfered to
 * Richard Levitte from CertCo by Kathy Weinhold in mid-spring 2000 to be
 * included in OpenSSL or released as a patch kit.
 */

/* ====================================================================
 * Copyright (c) 1998-2000 The OpenSSL Project.  All rights reserved.
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

#include "bio.h"
// #include "err.h"
// #include "ocsp.h"
// #include "pem.h"

static int ocsp_certid_print(BIO *bp, OCSP_CERTID *a, int indent)
{
    BIO_printf(bp, "%*sCertificate ID:\n", indent, "");
    indent += 2;
    BIO_printf(bp, "%*sHash Algorithm: ", indent, "");
    i2a_ASN1_OBJECT(bp, a->hashAlgorithm->algorithm);
    BIO_printf(bp, "\n%*sIssuer Name Hash: ", indent, "");
    i2a_ASN1_STRING(bp, a->issuerNameHash, V_ASN1_OCTET_STRING);
    BIO_printf(bp, "\n%*sIssuer Key Hash: ", indent, "");
    i2a_ASN1_STRING(bp, a->issuerKeyHash, V_ASN1_OCTET_STRING);
    BIO_printf(bp, "\n%*sSerial Number: ", indent, "");
    i2a_ASN1_INTEGER(bp, a->serialNumber);
    BIO_printf(bp, "\n");
    return 1;
}

typedef struct {
    long t;
    const char *m;
} OCSP_TBLSTR;

static const char *table2string(long s, const OCSP_TBLSTR *ts, int len)
{
    const OCSP_TBLSTR *p;
    for (p = ts; p < ts + len; p++)
        if (p->t == s)
            return p->m;
    return "(UNKNOWN)";
}

const char *OCSP_response_status_str(long s)
{
    static const OCSP_TBLSTR rstat_tbl[] = {
        {OCSP_RESPONSE_STATUS_SUCCESSFUL, "successful"},
        {OCSP_RESPONSE_STATUS_MALFORMEDREQUEST, "malformedrequest"},
        {OCSP_RESPONSE_STATUS_INTERNALERROR, "internalerror"},
        {OCSP_RESPONSE_STATUS_TRYLATER, "trylater"},
        {OCSP_RESPONSE_STATUS_SIGREQUIRED, "sigrequired"},
        {OCSP_RESPONSE_STATUS_UNAUTHORIZED, "unauthorized"}
    };
    return table2string(s, rstat_tbl, 6);
}

const char *OCSP_cert_status_str(long s)
{
    static const OCSP_TBLSTR cstat_tbl[] = {
        {V_OCSP_CERTSTATUS_GOOD, "good"},
        {V_OCSP_CERTSTATUS_REVOKED, "revoked"},
        {V_OCSP_CERTSTATUS_UNKNOWN, "unknown"}
    };
    return table2string(s, cstat_tbl, 3);
}

const char *OCSP_crl_reason_str(long s)
{
    static const OCSP_TBLSTR reason_tbl[] = {
        {OCSP_REVOKED_STATUS_UNSPECIFIED, "unspecified"},
        {OCSP_REVOKED_STATUS_KEYCOMPROMISE, "keyCompromise"},
        {OCSP_REVOKED_STATUS_CACOMPROMISE, "cACompromise"},
        {OCSP_REVOKED_STATUS_AFFILIATIONCHANGED, "affiliationChanged"},
        {OCSP_REVOKED_STATUS_SUPERSEDED, "superseded"},
        {OCSP_REVOKED_STATUS_CESSATIONOFOPERATION, "cessationOfOperation"},
        {OCSP_REVOKED_STATUS_CERTIFICATEHOLD, "certificateHold"},
        {OCSP_REVOKED_STATUS_REMOVEFROMCRL, "removeFromCRL"}
    };
    return table2string(s, reason_tbl, 8);
}

int OCSP_REQUEST_print(BIO *bp, OCSP_REQUEST *o, unsigned long flags)
{
    int i;
    long l;
    OCSP_CERTID *cid = NULL;
    OCSP_ONEREQ *one = NULL;
    OCSP_REQINFO *inf = o->tbsRequest;
    OCSP_SIGNATURE *sig = o->optionalSignature;

    if (BIO_write(bp, "OCSP Request Data:\n", 19) <= 0)
        goto err;
    l = ASN1_INTEGER_get(inf->version);
    if (BIO_printf(bp, "    Version: %lu (0x%lx)", l + 1, l) <= 0)
        goto err;
    if (inf->requestorName != NULL) {
        if (BIO_write(bp, "\n    Requestor Name: ", 21) <= 0)
            goto err;
        GENERAL_NAME_print(bp, inf->requestorName);
    }
    if (BIO_write(bp, "\n    Requestor List:\n", 21) <= 0)
        goto err;
    for (i = 0; i < sk_OCSP_ONEREQ_num(inf->requestList); i++) {
        one = sk_OCSP_ONEREQ_value(inf->requestList, i);
        cid = one->reqCert;
        ocsp_certid_print(bp, cid, 8);
        if (!X509V3_extensions_print(bp,
                                     "Request Single Extensions",
                                     one->singleRequestExtensions, flags, 8))
            goto err;
    }
    if (!X509V3_extensions_print(bp, "Request Extensions",
                                 inf->requestExtensions, flags, 4))
        goto err;
    if (sig) {
        X509_signature_print(bp, sig->signatureAlgorithm, sig->signature);
        for (i = 0; i < sk_X509_num(sig->certs); i++) {
            X509_print(bp, sk_X509_value(sig->certs, i));
            PEM_write_bio_X509(bp, sk_X509_value(sig->certs, i));
        }
    }
    return 1;
 err:
    return 0;
}

int OCSP_RESPONSE_print(BIO *bp, OCSP_RESPONSE *o, unsigned long flags)
{
    int i, ret = 0;
    long l;
    OCSP_CERTID *cid = NULL;
    OCSP_BASICRESP *br = NULL;
    OCSP_RESPID *rid = NULL;
    OCSP_RESPDATA *rd = NULL;
    OCSP_CERTSTATUS *cst = NULL;
    OCSP_REVOKEDINFO *rev = NULL;
    OCSP_SINGLERESP *single = NULL;
    OCSP_RESPBYTES *rb = o->responseBytes;

    if (BIO_puts(bp, "OCSP Response Data:\n") <= 0)
        goto err;
    l = ASN1_ENUMERATED_get(o->responseStatus);
    if (BIO_printf(bp, "    OCSP Response Status: %s (0x%lx)\n",
                   OCSP_response_status_str(l), l) <= 0)
        goto err;
    if (rb == NULL)
        return 1;
    if (BIO_puts(bp, "    Response Type: ") <= 0)
        goto err;
    if (i2a_ASN1_OBJECT(bp, rb->responseType) <= 0)
        goto err;
    if (OBJ_obj2nid(rb->responseType) != NID_id_pkix_OCSP_basic) {
        BIO_puts(bp, " (unknown response type)\n");
        return 1;
    }

    if ((br = OCSP_response_get1_basic(o)) == NULL)
        goto err;
    rd = br->tbsResponseData;
    l = ASN1_INTEGER_get(rd->version);
    if (BIO_printf(bp, "\n    Version: %lu (0x%lx)\n", l + 1, l) <= 0)
        goto err;
    if (BIO_puts(bp, "    Responder Id: ") <= 0)
        goto err;

    rid = rd->responderId;
    switch (rid->type) {
    case V_OCSP_RESPID_NAME:
        X509_NAME_print_ex(bp, rid->value.byName, 0, XN_FLAG_ONELINE);
        break;
    case V_OCSP_RESPID_KEY:
        i2a_ASN1_STRING(bp, rid->value.byKey, V_ASN1_OCTET_STRING);
        break;
    }

    if (BIO_printf(bp, "\n    Produced At: ") <= 0)
        goto err;
    if (!ASN1_GENERALIZEDTIME_print(bp, rd->producedAt))
        goto err;
    if (BIO_printf(bp, "\n    Responses:\n") <= 0)
        goto err;
    for (i = 0; i < sk_OCSP_SINGLERESP_num(rd->responses); i++) {
        if (!sk_OCSP_SINGLERESP_value(rd->responses, i))
            continue;
        single = sk_OCSP_SINGLERESP_value(rd->responses, i);
        cid = single->certId;
        if (ocsp_certid_print(bp, cid, 4) <= 0)
            goto err;
        cst = single->certStatus;
        if (BIO_printf(bp, "    Cert Status: %s",
                       OCSP_cert_status_str(cst->type)) <= 0)
            goto err;
        if (cst->type == V_OCSP_CERTSTATUS_REVOKED) {
            rev = cst->value.revoked;
            if (BIO_printf(bp, "\n    Revocation Time: ") <= 0)
                goto err;
            if (!ASN1_GENERALIZEDTIME_print(bp, rev->revocationTime))
                goto err;
            if (rev->revocationReason) {
                l = ASN1_ENUMERATED_get(rev->revocationReason);
                if (BIO_printf(bp,
                               "\n    Revocation Reason: %s (0x%lx)",
                               OCSP_crl_reason_str(l), l) <= 0)
                    goto err;
            }
        }
        if (BIO_printf(bp, "\n    This Update: ") <= 0)
            goto err;
        if (!ASN1_GENERALIZEDTIME_print(bp, single->thisUpdate))
            goto err;
        if (single->nextUpdate) {
            if (BIO_printf(bp, "\n    Next Update: ") <= 0)
                goto err;
            if (!ASN1_GENERALIZEDTIME_print(bp, single->nextUpdate))
                goto err;
        }
        if (BIO_write(bp, "\n", 1) <= 0)
            goto err;
        if (!X509V3_extensions_print(bp,
                                     "Response Single Extensions",
                                     single->singleExtensions, flags, 8))
            goto err;
        if (BIO_write(bp, "\n", 1) <= 0)
            goto err;
    }
    if (!X509V3_extensions_print(bp, "Response Extensions",
                                 rd->responseExtensions, flags, 4))
        goto err;
    if (X509_signature_print(bp, br->signatureAlgorithm, br->signature) <= 0)
        goto err;

    for (i = 0; i < sk_X509_num(br->certs); i++) {
        X509_print(bp, sk_X509_value(br->certs, i));
        PEM_write_bio_X509(bp, sk_X509_value(br->certs, i));
    }

    ret = 1;
 err:
    OCSP_BASICRESP_free(br);
    return ret;
}
/* ocsp_srv.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 2001.
 */
/* ====================================================================
 * Copyright (c) 1998-2001 The OpenSSL Project.  All rights reserved.
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
// #include "objects.h"
// #include "rand.h"
// #include "x509.h"
// #include "pem.h"
// #include "x509v3.h"
// #include "ocsp.h"

/*
 * Utility functions related to sending OCSP responses and extracting
 * relevant information from the request.
 */

int OCSP_request_onereq_count(OCSP_REQUEST *req)
{
    return sk_OCSP_ONEREQ_num(req->tbsRequest->requestList);
}

OCSP_ONEREQ *OCSP_request_onereq_get0(OCSP_REQUEST *req, int i)
{
    return sk_OCSP_ONEREQ_value(req->tbsRequest->requestList, i);
}

OCSP_CERTID *OCSP_onereq_get0_id(OCSP_ONEREQ *one)
{
    return one->reqCert;
}

int OCSP_id_get0_info(ASN1_OCTET_STRING **piNameHash, ASN1_OBJECT **pmd,
                      ASN1_OCTET_STRING **pikeyHash,
                      ASN1_INTEGER **pserial, OCSP_CERTID *cid)
{
    if (!cid)
        return 0;
    if (pmd)
        *pmd = cid->hashAlgorithm->algorithm;
    if (piNameHash)
        *piNameHash = cid->issuerNameHash;
    if (pikeyHash)
        *pikeyHash = cid->issuerKeyHash;
    if (pserial)
        *pserial = cid->serialNumber;
    return 1;
}

int OCSP_request_is_signed(OCSP_REQUEST *req)
{
    if (req->optionalSignature)
        return 1;
    return 0;
}

/* Create an OCSP response and encode an optional basic response */
OCSP_RESPONSE *OCSP_response_create(int status, OCSP_BASICRESP *bs)
{
    OCSP_RESPONSE *rsp = NULL;

    if (!(rsp = OCSP_RESPONSE_new()))
        goto err;
    if (!(ASN1_ENUMERATED_set(rsp->responseStatus, status)))
        goto err;
    if (!bs)
        return rsp;
    if (!(rsp->responseBytes = OCSP_RESPBYTES_new()))
        goto err;
    rsp->responseBytes->responseType = OBJ_nid2obj(NID_id_pkix_OCSP_basic);
    if (!ASN1_item_pack
        (bs, ASN1_ITEM_rptr(OCSP_BASICRESP), &rsp->responseBytes->response))
         goto err;
    return rsp;
 err:
    if (rsp)
        OCSP_RESPONSE_free(rsp);
    return NULL;
}

OCSP_SINGLERESP *OCSP_basic_add1_status(OCSP_BASICRESP *rsp,
                                        OCSP_CERTID *cid,
                                        int status, int reason,
                                        ASN1_TIME *revtime,
                                        ASN1_TIME *thisupd,
                                        ASN1_TIME *nextupd)
{
    OCSP_SINGLERESP *single = NULL;
    OCSP_CERTSTATUS *cs;
    OCSP_REVOKEDINFO *ri;

    if (!rsp->tbsResponseData->responses &&
        !(rsp->tbsResponseData->responses = sk_OCSP_SINGLERESP_new_null()))
        goto err;

    if (!(single = OCSP_SINGLERESP_new()))
        goto err;

    if (!ASN1_TIME_to_generalizedtime(thisupd, &single->thisUpdate))
        goto err;
    if (nextupd &&
        !ASN1_TIME_to_generalizedtime(nextupd, &single->nextUpdate))
        goto err;

    OCSP_CERTID_free(single->certId);

    if (!(single->certId = OCSP_CERTID_dup(cid)))
        goto err;

    cs = single->certStatus;
    switch (cs->type = status) {
    case V_OCSP_CERTSTATUS_REVOKED:
        if (!revtime) {
            OCSPerr(OCSP_F_OCSP_BASIC_ADD1_STATUS, OCSP_R_NO_REVOKED_TIME);
            goto err;
        }
        if (!(cs->value.revoked = ri = OCSP_REVOKEDINFO_new()))
            goto err;
        if (!ASN1_TIME_to_generalizedtime(revtime, &ri->revocationTime))
            goto err;
        if (reason != OCSP_REVOKED_STATUS_NOSTATUS) {
            if (!(ri->revocationReason = ASN1_ENUMERATED_new()))
                goto err;
            if (!(ASN1_ENUMERATED_set(ri->revocationReason, reason)))
                goto err;
        }
        break;

    case V_OCSP_CERTSTATUS_GOOD:
        cs->value.good = ASN1_NULL_new();
        break;

    case V_OCSP_CERTSTATUS_UNKNOWN:
        cs->value.unknown = ASN1_NULL_new();
        break;

    default:
        goto err;

    }
    if (!(sk_OCSP_SINGLERESP_push(rsp->tbsResponseData->responses, single)))
        goto err;
    return single;
 err:
    OCSP_SINGLERESP_free(single);
    return NULL;
}

/* Add a certificate to an OCSP request */

int OCSP_basic_add1_cert(OCSP_BASICRESP *resp, X509 *cert)
{
    if (!resp->certs && !(resp->certs = sk_X509_new_null()))
        return 0;

    if (!sk_X509_push(resp->certs, cert))
        return 0;
    CRYPTO_add(&cert->references, 1, CRYPTO_LOCK_X509);
    return 1;
}

int OCSP_basic_sign(OCSP_BASICRESP *brsp,
                    X509 *signer, EVP_PKEY *key, const EVP_MD *dgst,
                    STACK_OF(X509) *certs, unsigned long flags)
{
    int i;
    OCSP_RESPID *rid;

    if (!X509_check_private_key(signer, key)) {
        OCSPerr(OCSP_F_OCSP_BASIC_SIGN,
                OCSP_R_PRIVATE_KEY_DOES_NOT_MATCH_CERTIFICATE);
        goto err;
    }

    if (!(flags & OCSP_NOCERTS)) {
        if (!OCSP_basic_add1_cert(brsp, signer))
            goto err;
        for (i = 0; i < sk_X509_num(certs); i++) {
            X509 *tmpcert = sk_X509_value(certs, i);
            if (!OCSP_basic_add1_cert(brsp, tmpcert))
                goto err;
        }
    }

    rid = brsp->tbsResponseData->responderId;
    if (flags & OCSP_RESPID_KEY) {
        unsigned char md[SHA_DIGEST_LENGTH];
        X509_pubkey_digest(signer, EVP_sha1(), md, NULL);
        if (!(rid->value.byKey = ASN1_OCTET_STRING_new()))
            goto err;
        if (!(ASN1_OCTET_STRING_set(rid->value.byKey, md, SHA_DIGEST_LENGTH)))
            goto err;
        rid->type = V_OCSP_RESPID_KEY;
    } else {
        if (!X509_NAME_set(&rid->value.byName, X509_get_subject_name(signer)))
            goto err;
        rid->type = V_OCSP_RESPID_NAME;
    }

    if (!(flags & OCSP_NOTIME) &&
        !X509_gmtime_adj(brsp->tbsResponseData->producedAt, 0))
        goto err;

    /*
     * Right now, I think that not doing double hashing is the right thing.
     * -- Richard Levitte
     */

    if (!OCSP_BASICRESP_sign(brsp, key, dgst, 0))
        goto err;

    return 1;
 err:
    return 0;
}
/* ocsp_vfy.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 2000.
 */
/* ====================================================================
 * Copyright (c) 2000-2004 The OpenSSL Project.  All rights reserved.
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

// #include "ocsp.h"
// #include "err.h"
#include <string.h>

static int ocsp_find_signer(X509 **psigner, OCSP_BASICRESP *bs,
                            STACK_OF(X509) *certs, X509_STORE *st,
                            unsigned long flags);
static X509 *ocsp_find_signer_sk(STACK_OF(X509) *certs, OCSP_RESPID *id);
static int ocsp_check_issuer(OCSP_BASICRESP *bs, STACK_OF(X509) *chain,
                             unsigned long flags);
static int ocsp_check_ids(STACK_OF(OCSP_SINGLERESP) *sresp,
                          OCSP_CERTID **ret);
static int ocsp_match_issuerid(X509 *cert, OCSP_CERTID *cid,
                               STACK_OF(OCSP_SINGLERESP) *sresp);
static int ocsp_check_delegated(X509 *x, int flags);
static int ocsp_req_find_signer(X509 **psigner, OCSP_REQUEST *req,
                                X509_NAME *nm, STACK_OF(X509) *certs,
                                X509_STORE *st, unsigned long flags);

/* Verify a basic response message */

int OCSP_basic_verify(OCSP_BASICRESP *bs, STACK_OF(X509) *certs,
                      X509_STORE *st, unsigned long flags)
{
    X509 *signer, *x;
    STACK_OF(X509) *chain = NULL;
    STACK_OF(X509) *untrusted = NULL;
    X509_STORE_CTX ctx;
    int i, ret = 0;
    ret = ocsp_find_signer(&signer, bs, certs, st, flags);
    if (!ret) {
        OCSPerr(OCSP_F_OCSP_BASIC_VERIFY,
                OCSP_R_SIGNER_CERTIFICATE_NOT_FOUND);
        goto end;
    }
    if ((ret == 2) && (flags & OCSP_TRUSTOTHER))
        flags |= OCSP_NOVERIFY;
    if (!(flags & OCSP_NOSIGS)) {
        EVP_PKEY *skey;
        skey = X509_get_pubkey(signer);
        if (skey) {
            ret = OCSP_BASICRESP_verify(bs, skey, 0);
            EVP_PKEY_free(skey);
        }
        if (!skey || ret <= 0) {
            OCSPerr(OCSP_F_OCSP_BASIC_VERIFY, OCSP_R_SIGNATURE_FAILURE);
            goto end;
        }
    }
    if (!(flags & OCSP_NOVERIFY)) {
        int init_res;
        if (flags & OCSP_NOCHAIN) {
            untrusted = NULL;
        } else if (bs->certs && certs) {
            untrusted = sk_X509_dup(bs->certs);
            for (i = 0; i < sk_X509_num(certs); i++) {
                if (!sk_X509_push(untrusted, sk_X509_value(certs, i))) {
                    OCSPerr(OCSP_F_OCSP_BASIC_VERIFY, ERR_R_MALLOC_FAILURE);
                    goto end;
                }
            }
        } else if (certs != NULL) {
            untrusted = certs;
        } else {
            untrusted = bs->certs;
        }
        init_res = X509_STORE_CTX_init(&ctx, st, signer, untrusted);
        if (!init_res) {
            ret = -1;
            OCSPerr(OCSP_F_OCSP_BASIC_VERIFY, ERR_R_X509_LIB);
            goto end;
        }

        X509_STORE_CTX_set_purpose(&ctx, X509_PURPOSE_OCSP_HELPER);
        ret = X509_verify_cert(&ctx);
        chain = X509_STORE_CTX_get1_chain(&ctx);
        X509_STORE_CTX_cleanup(&ctx);
        if (ret <= 0) {
            i = X509_STORE_CTX_get_error(&ctx);
            OCSPerr(OCSP_F_OCSP_BASIC_VERIFY,
                    OCSP_R_CERTIFICATE_VERIFY_ERROR);
            ERR_add_error_data(2, "Verify error:",
                               X509_verify_cert_error_string(i));
            goto end;
        }
        if (flags & OCSP_NOCHECKS) {
            ret = 1;
            goto end;
        }
        /*
         * At this point we have a valid certificate chain need to verify it
         * against the OCSP issuer criteria.
         */
        ret = ocsp_check_issuer(bs, chain, flags);

        /* If fatal error or valid match then finish */
        if (ret != 0)
            goto end;

        /*
         * Easy case: explicitly trusted. Get root CA and check for explicit
         * trust
         */
        if (flags & OCSP_NOEXPLICIT)
            goto end;

        x = sk_X509_value(chain, sk_X509_num(chain) - 1);
        if (X509_check_trust(x, NID_OCSP_sign, 0) != X509_TRUST_TRUSTED) {
            OCSPerr(OCSP_F_OCSP_BASIC_VERIFY, OCSP_R_ROOT_CA_NOT_TRUSTED);
            goto end;
        }
        ret = 1;
    }

 end:
    if (chain)
        sk_X509_pop_free(chain, X509_free);
    if (bs->certs && certs)
        sk_X509_free(untrusted);
    return ret;
}

static int ocsp_find_signer(X509 **psigner, OCSP_BASICRESP *bs,
                            STACK_OF(X509) *certs, X509_STORE *st,
                            unsigned long flags)
{
    X509 *signer;
    OCSP_RESPID *rid = bs->tbsResponseData->responderId;
    if ((signer = ocsp_find_signer_sk(certs, rid))) {
        *psigner = signer;
        return 2;
    }
    if (!(flags & OCSP_NOINTERN) &&
        (signer = ocsp_find_signer_sk(bs->certs, rid))) {
        *psigner = signer;
        return 1;
    }
    /* Maybe lookup from store if by subject name */

    *psigner = NULL;
    return 0;
}

static X509 *ocsp_find_signer_sk(STACK_OF(X509) *certs, OCSP_RESPID *id)
{
    int i;
    unsigned char tmphash[SHA_DIGEST_LENGTH], *keyhash;
    X509 *x;

    /* Easy if lookup by name */
    if (id->type == V_OCSP_RESPID_NAME)
        return X509_find_by_subject(certs, id->value.byName);

    /* Lookup by key hash */

    /* If key hash isn't SHA1 length then forget it */
    if (id->value.byKey->length != SHA_DIGEST_LENGTH)
        return NULL;
    keyhash = id->value.byKey->data;
    /* Calculate hash of each key and compare */
    for (i = 0; i < sk_X509_num(certs); i++) {
        x = sk_X509_value(certs, i);
        X509_pubkey_digest(x, EVP_sha1(), tmphash, NULL);
        if (!memcmp(keyhash, tmphash, SHA_DIGEST_LENGTH))
            return x;
    }
    return NULL;
}

static int ocsp_check_issuer(OCSP_BASICRESP *bs, STACK_OF(X509) *chain,
                             unsigned long flags)
{
    STACK_OF(OCSP_SINGLERESP) *sresp;
    X509 *signer, *sca;
    OCSP_CERTID *caid = NULL;
    int i;
    sresp = bs->tbsResponseData->responses;

    if (sk_X509_num(chain) <= 0) {
        OCSPerr(OCSP_F_OCSP_CHECK_ISSUER, OCSP_R_NO_CERTIFICATES_IN_CHAIN);
        return -1;
    }

    /* See if the issuer IDs match. */
    i = ocsp_check_ids(sresp, &caid);

    /* If ID mismatch or other error then return */
    if (i <= 0)
        return i;

    signer = sk_X509_value(chain, 0);
    /* Check to see if OCSP responder CA matches request CA */
    if (sk_X509_num(chain) > 1) {
        sca = sk_X509_value(chain, 1);
        i = ocsp_match_issuerid(sca, caid, sresp);
        if (i < 0)
            return i;
        if (i) {
            /* We have a match, if extensions OK then success */
            if (ocsp_check_delegated(signer, flags))
                return 1;
            return 0;
        }
    }

    /* Otherwise check if OCSP request signed directly by request CA */
    return ocsp_match_issuerid(signer, caid, sresp);
}

/*
 * Check the issuer certificate IDs for equality. If there is a mismatch with
 * the same algorithm then there's no point trying to match any certificates
 * against the issuer. If the issuer IDs all match then we just need to check
 * equality against one of them.
 */

static int ocsp_check_ids(STACK_OF(OCSP_SINGLERESP) *sresp, OCSP_CERTID **ret)
{
    OCSP_CERTID *tmpid, *cid;
    int i, idcount;

    idcount = sk_OCSP_SINGLERESP_num(sresp);
    if (idcount <= 0) {
        OCSPerr(OCSP_F_OCSP_CHECK_IDS,
                OCSP_R_RESPONSE_CONTAINS_NO_REVOCATION_DATA);
        return -1;
    }

    cid = sk_OCSP_SINGLERESP_value(sresp, 0)->certId;

    *ret = NULL;

    for (i = 1; i < idcount; i++) {
        tmpid = sk_OCSP_SINGLERESP_value(sresp, i)->certId;
        /* Check to see if IDs match */
        if (OCSP_id_issuer_cmp(cid, tmpid)) {
            /* If algoritm mismatch let caller deal with it */
            if (OBJ_cmp(tmpid->hashAlgorithm->algorithm,
                        cid->hashAlgorithm->algorithm))
                return 2;
            /* Else mismatch */
            return 0;
        }
    }

    /* All IDs match: only need to check one ID */
    *ret = cid;
    return 1;
}

static int ocsp_match_issuerid(X509 *cert, OCSP_CERTID *cid,
                               STACK_OF(OCSP_SINGLERESP) *sresp)
{
    /* If only one ID to match then do it */
    if (cid) {
        const EVP_MD *dgst;
        X509_NAME *iname;
        int mdlen;
        unsigned char md[EVP_MAX_MD_SIZE];
        if (!(dgst = EVP_get_digestbyobj(cid->hashAlgorithm->algorithm))) {
            OCSPerr(OCSP_F_OCSP_MATCH_ISSUERID,
                    OCSP_R_UNKNOWN_MESSAGE_DIGEST);
            return -1;
        }

        mdlen = EVP_MD_size(dgst);
        if (mdlen < 0)
            return -1;
        if ((cid->issuerNameHash->length != mdlen) ||
            (cid->issuerKeyHash->length != mdlen))
            return 0;
        iname = X509_get_subject_name(cert);
        if (!X509_NAME_digest(iname, dgst, md, NULL))
            return -1;
        if (memcmp(md, cid->issuerNameHash->data, mdlen))
            return 0;
        X509_pubkey_digest(cert, dgst, md, NULL);
        if (memcmp(md, cid->issuerKeyHash->data, mdlen))
            return 0;

        return 1;

    } else {
        /* We have to match the whole lot */
        int i, ret;
        OCSP_CERTID *tmpid;
        for (i = 0; i < sk_OCSP_SINGLERESP_num(sresp); i++) {
            tmpid = sk_OCSP_SINGLERESP_value(sresp, i)->certId;
            ret = ocsp_match_issuerid(cert, tmpid, NULL);
            if (ret <= 0)
                return ret;
        }
        return 1;
    }

}

static int ocsp_check_delegated(X509 *x, int flags)
{
    X509_check_purpose(x, -1, 0);
    if ((x->ex_flags & EXFLAG_XKUSAGE) && (x->ex_xkusage & XKU_OCSP_SIGN))
        return 1;
    OCSPerr(OCSP_F_OCSP_CHECK_DELEGATED, OCSP_R_MISSING_OCSPSIGNING_USAGE);
    return 0;
}

/*
 * Verify an OCSP request. This is fortunately much easier than OCSP response
 * verify. Just find the signers certificate and verify it against a given
 * trust value.
 */

int OCSP_request_verify(OCSP_REQUEST *req, STACK_OF(X509) *certs,
                        X509_STORE *store, unsigned long flags)
{
    X509 *signer;
    X509_NAME *nm;
    GENERAL_NAME *gen;
    int ret;
    X509_STORE_CTX ctx;
    if (!req->optionalSignature) {
        OCSPerr(OCSP_F_OCSP_REQUEST_VERIFY, OCSP_R_REQUEST_NOT_SIGNED);
        return 0;
    }
    gen = req->tbsRequest->requestorName;
    if (!gen || gen->type != GEN_DIRNAME) {
        OCSPerr(OCSP_F_OCSP_REQUEST_VERIFY,
                OCSP_R_UNSUPPORTED_REQUESTORNAME_TYPE);
        return 0;
    }
    nm = gen->d.directoryName;
    ret = ocsp_req_find_signer(&signer, req, nm, certs, store, flags);
    if (ret <= 0) {
        OCSPerr(OCSP_F_OCSP_REQUEST_VERIFY,
                OCSP_R_SIGNER_CERTIFICATE_NOT_FOUND);
        return 0;
    }
    if ((ret == 2) && (flags & OCSP_TRUSTOTHER))
        flags |= OCSP_NOVERIFY;
    if (!(flags & OCSP_NOSIGS)) {
        EVP_PKEY *skey;
        skey = X509_get_pubkey(signer);
        ret = OCSP_REQUEST_verify(req, skey);
        EVP_PKEY_free(skey);
        if (ret <= 0) {
            OCSPerr(OCSP_F_OCSP_REQUEST_VERIFY, OCSP_R_SIGNATURE_FAILURE);
            return 0;
        }
    }
    if (!(flags & OCSP_NOVERIFY)) {
        int init_res;
        if (flags & OCSP_NOCHAIN)
            init_res = X509_STORE_CTX_init(&ctx, store, signer, NULL);
        else
            init_res = X509_STORE_CTX_init(&ctx, store, signer,
                                           req->optionalSignature->certs);
        if (!init_res) {
            OCSPerr(OCSP_F_OCSP_REQUEST_VERIFY, ERR_R_X509_LIB);
            return 0;
        }

        X509_STORE_CTX_set_purpose(&ctx, X509_PURPOSE_OCSP_HELPER);
        X509_STORE_CTX_set_trust(&ctx, X509_TRUST_OCSP_REQUEST);
        ret = X509_verify_cert(&ctx);
        X509_STORE_CTX_cleanup(&ctx);
        if (ret <= 0) {
            ret = X509_STORE_CTX_get_error(&ctx);
            OCSPerr(OCSP_F_OCSP_REQUEST_VERIFY,
                    OCSP_R_CERTIFICATE_VERIFY_ERROR);
            ERR_add_error_data(2, "Verify error:",
                               X509_verify_cert_error_string(ret));
            return 0;
        }
    }
    return 1;
}

static int ocsp_req_find_signer(X509 **psigner, OCSP_REQUEST *req,
                                X509_NAME *nm, STACK_OF(X509) *certs,
                                X509_STORE *st, unsigned long flags)
{
    X509 *signer;
    if (!(flags & OCSP_NOINTERN)) {
        signer = X509_find_by_subject(req->optionalSignature->certs, nm);
        if (signer) {
            *psigner = signer;
            return 1;
        }
    }

    signer = X509_find_by_subject(certs, nm);
    if (signer) {
        *psigner = signer;
        return 2;
    }
    return 0;
}
