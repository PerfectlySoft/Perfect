/* crypto/cms/cms_asn1.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project.
 */
/* ====================================================================
 * Copyright (c) 2008 The OpenSSL Project.  All rights reserved.
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
 */

#include "asn1t.h"
#include "pem.h"
#include "x509v3.h"
#include "cms.h"
#include "cms_lcl.h"


ASN1_SEQUENCE(CMS_IssuerAndSerialNumber) = {
        ASN1_SIMPLE(CMS_IssuerAndSerialNumber, issuer, X509_NAME),
        ASN1_SIMPLE(CMS_IssuerAndSerialNumber, serialNumber, ASN1_INTEGER)
} ASN1_SEQUENCE_END(CMS_IssuerAndSerialNumber)

ASN1_SEQUENCE(CMS_OtherCertificateFormat) = {
        ASN1_SIMPLE(CMS_OtherCertificateFormat, otherCertFormat, ASN1_OBJECT),
        ASN1_OPT(CMS_OtherCertificateFormat, otherCert, ASN1_ANY)
} ASN1_SEQUENCE_END(CMS_OtherCertificateFormat)

ASN1_CHOICE(CMS_CertificateChoices) = {
        ASN1_SIMPLE(CMS_CertificateChoices, d.certificate, X509),
        ASN1_IMP(CMS_CertificateChoices, d.extendedCertificate, ASN1_SEQUENCE, 0),
        ASN1_IMP(CMS_CertificateChoices, d.v1AttrCert, ASN1_SEQUENCE, 1),
        ASN1_IMP(CMS_CertificateChoices, d.v2AttrCert, ASN1_SEQUENCE, 2),
        ASN1_IMP(CMS_CertificateChoices, d.other, CMS_OtherCertificateFormat, 3)
} ASN1_CHOICE_END(CMS_CertificateChoices)

ASN1_CHOICE(CMS_SignerIdentifier) = {
        ASN1_SIMPLE(CMS_SignerIdentifier, d.issuerAndSerialNumber, CMS_IssuerAndSerialNumber),
        ASN1_IMP(CMS_SignerIdentifier, d.subjectKeyIdentifier, ASN1_OCTET_STRING, 0)
} ASN1_CHOICE_END(CMS_SignerIdentifier)

ASN1_NDEF_SEQUENCE(CMS_EncapsulatedContentInfo) = {
        ASN1_SIMPLE(CMS_EncapsulatedContentInfo, eContentType, ASN1_OBJECT),
        ASN1_NDEF_EXP_OPT(CMS_EncapsulatedContentInfo, eContent, ASN1_OCTET_STRING_NDEF, 0)
} ASN1_NDEF_SEQUENCE_END(CMS_EncapsulatedContentInfo)

/* Minor tweak to operation: free up signer key, cert */
static int cms_si_cb(int operation, ASN1_VALUE **pval, const ASN1_ITEM *it,
                     void *exarg)
{
    if (operation == ASN1_OP_FREE_POST) {
        CMS_SignerInfo *si = (CMS_SignerInfo *)*pval;
        if (si->pkey)
            EVP_PKEY_free(si->pkey);
        if (si->signer)
            X509_free(si->signer);
        if (si->pctx)
            EVP_MD_CTX_cleanup(&si->mctx);
    }
    return 1;
}

ASN1_SEQUENCE_cb(CMS_SignerInfo, cms_si_cb) = {
        ASN1_SIMPLE(CMS_SignerInfo, version, LONG),
        ASN1_SIMPLE(CMS_SignerInfo, sid, CMS_SignerIdentifier),
        ASN1_SIMPLE(CMS_SignerInfo, digestAlgorithm, X509_ALGOR),
        ASN1_IMP_SET_OF_OPT(CMS_SignerInfo, signedAttrs, X509_ATTRIBUTE, 0),
        ASN1_SIMPLE(CMS_SignerInfo, signatureAlgorithm, X509_ALGOR),
        ASN1_SIMPLE(CMS_SignerInfo, signature, ASN1_OCTET_STRING),
        ASN1_IMP_SET_OF_OPT(CMS_SignerInfo, unsignedAttrs, X509_ATTRIBUTE, 1)
} ASN1_SEQUENCE_END_cb(CMS_SignerInfo, CMS_SignerInfo)

ASN1_SEQUENCE(CMS_OtherRevocationInfoFormat) = {
        ASN1_SIMPLE(CMS_OtherRevocationInfoFormat, otherRevInfoFormat, ASN1_OBJECT),
        ASN1_OPT(CMS_OtherRevocationInfoFormat, otherRevInfo, ASN1_ANY)
} ASN1_SEQUENCE_END(CMS_OtherRevocationInfoFormat)

ASN1_CHOICE(CMS_RevocationInfoChoice) = {
        ASN1_SIMPLE(CMS_RevocationInfoChoice, d.crl, X509_CRL),
        ASN1_IMP(CMS_RevocationInfoChoice, d.other, CMS_OtherRevocationInfoFormat, 1)
} ASN1_CHOICE_END(CMS_RevocationInfoChoice)

ASN1_NDEF_SEQUENCE(CMS_SignedData) = {
        ASN1_SIMPLE(CMS_SignedData, version, LONG),
        ASN1_SET_OF(CMS_SignedData, digestAlgorithms, X509_ALGOR),
        ASN1_SIMPLE(CMS_SignedData, encapContentInfo, CMS_EncapsulatedContentInfo),
        ASN1_IMP_SET_OF_OPT(CMS_SignedData, certificates, CMS_CertificateChoices, 0),
        ASN1_IMP_SET_OF_OPT(CMS_SignedData, crls, CMS_RevocationInfoChoice, 1),
        ASN1_SET_OF(CMS_SignedData, signerInfos, CMS_SignerInfo)
} ASN1_NDEF_SEQUENCE_END(CMS_SignedData)

ASN1_SEQUENCE(CMS_OriginatorInfo) = {
        ASN1_IMP_SET_OF_OPT(CMS_OriginatorInfo, certificates, CMS_CertificateChoices, 0),
        ASN1_IMP_SET_OF_OPT(CMS_OriginatorInfo, crls, CMS_RevocationInfoChoice, 1)
} ASN1_SEQUENCE_END(CMS_OriginatorInfo)

ASN1_NDEF_SEQUENCE(CMS_EncryptedContentInfo) = {
        ASN1_SIMPLE(CMS_EncryptedContentInfo, contentType, ASN1_OBJECT),
        ASN1_SIMPLE(CMS_EncryptedContentInfo, contentEncryptionAlgorithm, X509_ALGOR),
        ASN1_IMP_OPT(CMS_EncryptedContentInfo, encryptedContent, ASN1_OCTET_STRING_NDEF, 0)
} ASN1_NDEF_SEQUENCE_END(CMS_EncryptedContentInfo)

ASN1_SEQUENCE(CMS_KeyTransRecipientInfo) = {
        ASN1_SIMPLE(CMS_KeyTransRecipientInfo, version, LONG),
        ASN1_SIMPLE(CMS_KeyTransRecipientInfo, rid, CMS_SignerIdentifier),
        ASN1_SIMPLE(CMS_KeyTransRecipientInfo, keyEncryptionAlgorithm, X509_ALGOR),
        ASN1_SIMPLE(CMS_KeyTransRecipientInfo, encryptedKey, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(CMS_KeyTransRecipientInfo)

ASN1_SEQUENCE(CMS_OtherKeyAttribute) = {
        ASN1_SIMPLE(CMS_OtherKeyAttribute, keyAttrId, ASN1_OBJECT),
        ASN1_OPT(CMS_OtherKeyAttribute, keyAttr, ASN1_ANY)
} ASN1_SEQUENCE_END(CMS_OtherKeyAttribute)

ASN1_SEQUENCE(CMS_RecipientKeyIdentifier) = {
        ASN1_SIMPLE(CMS_RecipientKeyIdentifier, subjectKeyIdentifier, ASN1_OCTET_STRING),
        ASN1_OPT(CMS_RecipientKeyIdentifier, date, ASN1_GENERALIZEDTIME),
        ASN1_OPT(CMS_RecipientKeyIdentifier, other, CMS_OtherKeyAttribute)
} ASN1_SEQUENCE_END(CMS_RecipientKeyIdentifier)

ASN1_CHOICE(CMS_KeyAgreeRecipientIdentifier) = {
  ASN1_SIMPLE(CMS_KeyAgreeRecipientIdentifier, d.issuerAndSerialNumber, CMS_IssuerAndSerialNumber),
  ASN1_IMP(CMS_KeyAgreeRecipientIdentifier, d.rKeyId, CMS_RecipientKeyIdentifier, 0)
} ASN1_CHOICE_END(CMS_KeyAgreeRecipientIdentifier)

static int cms_rek_cb(int operation, ASN1_VALUE **pval, const ASN1_ITEM *it,
                      void *exarg)
{
    CMS_RecipientEncryptedKey *rek = (CMS_RecipientEncryptedKey *)*pval;
    if (operation == ASN1_OP_FREE_POST) {
        if (rek->pkey)
            EVP_PKEY_free(rek->pkey);
    }
    return 1;
}

ASN1_SEQUENCE_cb(CMS_RecipientEncryptedKey, cms_rek_cb) = {
        ASN1_SIMPLE(CMS_RecipientEncryptedKey, rid, CMS_KeyAgreeRecipientIdentifier),
        ASN1_SIMPLE(CMS_RecipientEncryptedKey, encryptedKey, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END_cb(CMS_RecipientEncryptedKey, CMS_RecipientEncryptedKey)

ASN1_SEQUENCE(CMS_OriginatorPublicKey) = {
  ASN1_SIMPLE(CMS_OriginatorPublicKey, algorithm, X509_ALGOR),
  ASN1_SIMPLE(CMS_OriginatorPublicKey, publicKey, ASN1_BIT_STRING)
} ASN1_SEQUENCE_END(CMS_OriginatorPublicKey)

ASN1_CHOICE(CMS_OriginatorIdentifierOrKey) = {
  ASN1_SIMPLE(CMS_OriginatorIdentifierOrKey, d.issuerAndSerialNumber, CMS_IssuerAndSerialNumber),
  ASN1_IMP(CMS_OriginatorIdentifierOrKey, d.subjectKeyIdentifier, ASN1_OCTET_STRING, 0),
  ASN1_IMP(CMS_OriginatorIdentifierOrKey, d.originatorKey, CMS_OriginatorPublicKey, 1)
} ASN1_CHOICE_END(CMS_OriginatorIdentifierOrKey)

static int cms_kari_cb(int operation, ASN1_VALUE **pval, const ASN1_ITEM *it,
                       void *exarg)
{
    CMS_KeyAgreeRecipientInfo *kari = (CMS_KeyAgreeRecipientInfo *)*pval;
    if (operation == ASN1_OP_NEW_POST) {
        EVP_CIPHER_CTX_init(&kari->ctx);
        EVP_CIPHER_CTX_set_flags(&kari->ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
        kari->pctx = NULL;
    } else if (operation == ASN1_OP_FREE_POST) {
        if (kari->pctx)
            EVP_PKEY_CTX_free(kari->pctx);
        EVP_CIPHER_CTX_cleanup(&kari->ctx);
    }
    return 1;
}

ASN1_SEQUENCE_cb(CMS_KeyAgreeRecipientInfo, cms_kari_cb) = {
        ASN1_SIMPLE(CMS_KeyAgreeRecipientInfo, version, LONG),
        ASN1_EXP(CMS_KeyAgreeRecipientInfo, originator, CMS_OriginatorIdentifierOrKey, 0),
        ASN1_EXP_OPT(CMS_KeyAgreeRecipientInfo, ukm, ASN1_OCTET_STRING, 1),
        ASN1_SIMPLE(CMS_KeyAgreeRecipientInfo, keyEncryptionAlgorithm, X509_ALGOR),
        ASN1_SEQUENCE_OF(CMS_KeyAgreeRecipientInfo, recipientEncryptedKeys, CMS_RecipientEncryptedKey)
} ASN1_SEQUENCE_END_cb(CMS_KeyAgreeRecipientInfo, CMS_KeyAgreeRecipientInfo)

ASN1_SEQUENCE(CMS_KEKIdentifier) = {
        ASN1_SIMPLE(CMS_KEKIdentifier, keyIdentifier, ASN1_OCTET_STRING),
        ASN1_OPT(CMS_KEKIdentifier, date, ASN1_GENERALIZEDTIME),
        ASN1_OPT(CMS_KEKIdentifier, other, CMS_OtherKeyAttribute)
} ASN1_SEQUENCE_END(CMS_KEKIdentifier)

ASN1_SEQUENCE(CMS_KEKRecipientInfo) = {
        ASN1_SIMPLE(CMS_KEKRecipientInfo, version, LONG),
        ASN1_SIMPLE(CMS_KEKRecipientInfo, kekid, CMS_KEKIdentifier),
        ASN1_SIMPLE(CMS_KEKRecipientInfo, keyEncryptionAlgorithm, X509_ALGOR),
        ASN1_SIMPLE(CMS_KEKRecipientInfo, encryptedKey, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(CMS_KEKRecipientInfo)

ASN1_SEQUENCE(CMS_PasswordRecipientInfo) = {
        ASN1_SIMPLE(CMS_PasswordRecipientInfo, version, LONG),
        ASN1_IMP_OPT(CMS_PasswordRecipientInfo, keyDerivationAlgorithm, X509_ALGOR, 0),
        ASN1_SIMPLE(CMS_PasswordRecipientInfo, keyEncryptionAlgorithm, X509_ALGOR),
        ASN1_SIMPLE(CMS_PasswordRecipientInfo, encryptedKey, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(CMS_PasswordRecipientInfo)

ASN1_SEQUENCE(CMS_OtherRecipientInfo) = {
  ASN1_SIMPLE(CMS_OtherRecipientInfo, oriType, ASN1_OBJECT),
  ASN1_OPT(CMS_OtherRecipientInfo, oriValue, ASN1_ANY)
} ASN1_SEQUENCE_END(CMS_OtherRecipientInfo)

/* Free up RecipientInfo additional data */
static int cms_ri_cb(int operation, ASN1_VALUE **pval, const ASN1_ITEM *it,
                     void *exarg)
{
    if (operation == ASN1_OP_FREE_PRE) {
        CMS_RecipientInfo *ri = (CMS_RecipientInfo *)*pval;
        if (ri->type == CMS_RECIPINFO_TRANS) {
            CMS_KeyTransRecipientInfo *ktri = ri->d.ktri;
            if (ktri->pkey)
                EVP_PKEY_free(ktri->pkey);
            if (ktri->recip)
                X509_free(ktri->recip);
            if (ktri->pctx)
                EVP_PKEY_CTX_free(ktri->pctx);
        } else if (ri->type == CMS_RECIPINFO_KEK) {
            CMS_KEKRecipientInfo *kekri = ri->d.kekri;
            if (kekri->key) {
                OPENSSL_cleanse(kekri->key, kekri->keylen);
                OPENSSL_free(kekri->key);
            }
        } else if (ri->type == CMS_RECIPINFO_PASS) {
            CMS_PasswordRecipientInfo *pwri = ri->d.pwri;
            if (pwri->pass) {
                OPENSSL_cleanse(pwri->pass, pwri->passlen);
                OPENSSL_free(pwri->pass);
            }
        }
    }
    return 1;
}

ASN1_CHOICE_cb(CMS_RecipientInfo, cms_ri_cb) = {
        ASN1_SIMPLE(CMS_RecipientInfo, d.ktri, CMS_KeyTransRecipientInfo),
        ASN1_IMP(CMS_RecipientInfo, d.kari, CMS_KeyAgreeRecipientInfo, 1),
        ASN1_IMP(CMS_RecipientInfo, d.kekri, CMS_KEKRecipientInfo, 2),
        ASN1_IMP(CMS_RecipientInfo, d.pwri, CMS_PasswordRecipientInfo, 3),
        ASN1_IMP(CMS_RecipientInfo, d.ori, CMS_OtherRecipientInfo, 4)
} ASN1_CHOICE_END_cb(CMS_RecipientInfo, CMS_RecipientInfo, type)

ASN1_NDEF_SEQUENCE(CMS_EnvelopedData) = {
        ASN1_SIMPLE(CMS_EnvelopedData, version, LONG),
        ASN1_IMP_OPT(CMS_EnvelopedData, originatorInfo, CMS_OriginatorInfo, 0),
        ASN1_SET_OF(CMS_EnvelopedData, recipientInfos, CMS_RecipientInfo),
        ASN1_SIMPLE(CMS_EnvelopedData, encryptedContentInfo, CMS_EncryptedContentInfo),
        ASN1_IMP_SET_OF_OPT(CMS_EnvelopedData, unprotectedAttrs, X509_ATTRIBUTE, 1)
} ASN1_NDEF_SEQUENCE_END(CMS_EnvelopedData)

ASN1_NDEF_SEQUENCE(CMS_DigestedData) = {
        ASN1_SIMPLE(CMS_DigestedData, version, LONG),
        ASN1_SIMPLE(CMS_DigestedData, digestAlgorithm, X509_ALGOR),
        ASN1_SIMPLE(CMS_DigestedData, encapContentInfo, CMS_EncapsulatedContentInfo),
        ASN1_SIMPLE(CMS_DigestedData, digest, ASN1_OCTET_STRING)
} ASN1_NDEF_SEQUENCE_END(CMS_DigestedData)

ASN1_NDEF_SEQUENCE(CMS_EncryptedData) = {
        ASN1_SIMPLE(CMS_EncryptedData, version, LONG),
        ASN1_SIMPLE(CMS_EncryptedData, encryptedContentInfo, CMS_EncryptedContentInfo),
        ASN1_IMP_SET_OF_OPT(CMS_EncryptedData, unprotectedAttrs, X509_ATTRIBUTE, 1)
} ASN1_NDEF_SEQUENCE_END(CMS_EncryptedData)

ASN1_NDEF_SEQUENCE(CMS_AuthenticatedData) = {
        ASN1_SIMPLE(CMS_AuthenticatedData, version, LONG),
        ASN1_IMP_OPT(CMS_AuthenticatedData, originatorInfo, CMS_OriginatorInfo, 0),
        ASN1_SET_OF(CMS_AuthenticatedData, recipientInfos, CMS_RecipientInfo),
        ASN1_SIMPLE(CMS_AuthenticatedData, macAlgorithm, X509_ALGOR),
        ASN1_IMP(CMS_AuthenticatedData, digestAlgorithm, X509_ALGOR, 1),
        ASN1_SIMPLE(CMS_AuthenticatedData, encapContentInfo, CMS_EncapsulatedContentInfo),
        ASN1_IMP_SET_OF_OPT(CMS_AuthenticatedData, authAttrs, X509_ALGOR, 2),
        ASN1_SIMPLE(CMS_AuthenticatedData, mac, ASN1_OCTET_STRING),
        ASN1_IMP_SET_OF_OPT(CMS_AuthenticatedData, unauthAttrs, X509_ALGOR, 3)
} ASN1_NDEF_SEQUENCE_END(CMS_AuthenticatedData)

ASN1_NDEF_SEQUENCE(CMS_CompressedData) = {
        ASN1_SIMPLE(CMS_CompressedData, version, LONG),
        ASN1_SIMPLE(CMS_CompressedData, compressionAlgorithm, X509_ALGOR),
        ASN1_SIMPLE(CMS_CompressedData, encapContentInfo, CMS_EncapsulatedContentInfo),
} ASN1_NDEF_SEQUENCE_END(CMS_CompressedData)

/* This is the ANY DEFINED BY table for the top level ContentInfo structure */

ASN1_ADB_TEMPLATE(cms_default) = ASN1_EXP(CMS_ContentInfo, d.other, ASN1_ANY, 0);

ASN1_ADB(CMS_ContentInfo) = {
        ADB_ENTRY(NID_pkcs7_data, ASN1_NDEF_EXP(CMS_ContentInfo, d.data, ASN1_OCTET_STRING_NDEF, 0)),
        ADB_ENTRY(NID_pkcs7_signed, ASN1_NDEF_EXP(CMS_ContentInfo, d.signedData, CMS_SignedData, 0)),
        ADB_ENTRY(NID_pkcs7_enveloped, ASN1_NDEF_EXP(CMS_ContentInfo, d.envelopedData, CMS_EnvelopedData, 0)),
        ADB_ENTRY(NID_pkcs7_digest, ASN1_NDEF_EXP(CMS_ContentInfo, d.digestedData, CMS_DigestedData, 0)),
        ADB_ENTRY(NID_pkcs7_encrypted, ASN1_NDEF_EXP(CMS_ContentInfo, d.encryptedData, CMS_EncryptedData, 0)),
        ADB_ENTRY(NID_id_smime_ct_authData, ASN1_NDEF_EXP(CMS_ContentInfo, d.authenticatedData, CMS_AuthenticatedData, 0)),
        ADB_ENTRY(NID_id_smime_ct_compressedData, ASN1_NDEF_EXP(CMS_ContentInfo, d.compressedData, CMS_CompressedData, 0)),
} ASN1_ADB_END(CMS_ContentInfo, 0, contentType, 0, &cms_default_tt, NULL);

/* CMS streaming support */
static int cms_cb(int operation, ASN1_VALUE **pval, const ASN1_ITEM *it,
                  void *exarg)
{
    ASN1_STREAM_ARG *sarg = exarg;
    CMS_ContentInfo *cms = NULL;
    if (pval)
        cms = (CMS_ContentInfo *)*pval;
    else
        return 1;
    switch (operation) {

    case ASN1_OP_STREAM_PRE:
        if (CMS_stream(&sarg->boundary, cms) <= 0)
            return 0;
    case ASN1_OP_DETACHED_PRE:
        sarg->ndef_bio = CMS_dataInit(cms, sarg->out);
        if (!sarg->ndef_bio)
            return 0;
        break;

    case ASN1_OP_STREAM_POST:
    case ASN1_OP_DETACHED_POST:
        if (CMS_dataFinal(cms, sarg->ndef_bio) <= 0)
            return 0;
        break;

    }
    return 1;
}

ASN1_NDEF_SEQUENCE_cb(CMS_ContentInfo, cms_cb) = {
        ASN1_SIMPLE(CMS_ContentInfo, contentType, ASN1_OBJECT),
        ASN1_ADB_OBJECT(CMS_ContentInfo)
} ASN1_NDEF_SEQUENCE_END_cb(CMS_ContentInfo, CMS_ContentInfo)

/* Specials for signed attributes */

/*
 * When signing attributes we want to reorder them to match the sorted
 * encoding.
 */

ASN1_ITEM_TEMPLATE(CMS_Attributes_Sign) =
        ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SET_ORDER, 0, CMS_ATTRIBUTES, X509_ATTRIBUTE)
ASN1_ITEM_TEMPLATE_END(CMS_Attributes_Sign)

/*
 * When verifying attributes we need to use the received order. So we use
 * SEQUENCE OF and tag it to SET OF
 */

ASN1_ITEM_TEMPLATE(CMS_Attributes_Verify) =
        ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_IMPTAG | ASN1_TFLG_UNIVERSAL,
                                V_ASN1_SET, CMS_ATTRIBUTES, X509_ATTRIBUTE)
ASN1_ITEM_TEMPLATE_END(CMS_Attributes_Verify)



ASN1_CHOICE(CMS_ReceiptsFrom) = {
  ASN1_IMP(CMS_ReceiptsFrom, d.allOrFirstTier, LONG, 0),
  ASN1_IMP_SEQUENCE_OF(CMS_ReceiptsFrom, d.receiptList, GENERAL_NAMES, 1)
} ASN1_CHOICE_END(CMS_ReceiptsFrom)

ASN1_SEQUENCE(CMS_ReceiptRequest) = {
  ASN1_SIMPLE(CMS_ReceiptRequest, signedContentIdentifier, ASN1_OCTET_STRING),
  ASN1_SIMPLE(CMS_ReceiptRequest, receiptsFrom, CMS_ReceiptsFrom),
  ASN1_SEQUENCE_OF(CMS_ReceiptRequest, receiptsTo, GENERAL_NAMES)
} ASN1_SEQUENCE_END(CMS_ReceiptRequest)

ASN1_SEQUENCE(CMS_Receipt) = {
  ASN1_SIMPLE(CMS_Receipt, version, LONG),
  ASN1_SIMPLE(CMS_Receipt, contentType, ASN1_OBJECT),
  ASN1_SIMPLE(CMS_Receipt, signedContentIdentifier, ASN1_OCTET_STRING),
  ASN1_SIMPLE(CMS_Receipt, originatorSignatureValue, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(CMS_Receipt)

/*
 * Utilities to encode the CMS_SharedInfo structure used during key
 * derivation.
 */

typedef struct {
    X509_ALGOR *keyInfo;
    ASN1_OCTET_STRING *entityUInfo;
    ASN1_OCTET_STRING *suppPubInfo;
} CMS_SharedInfo;

ASN1_SEQUENCE(CMS_SharedInfo) = {
  ASN1_SIMPLE(CMS_SharedInfo, keyInfo, X509_ALGOR),
  ASN1_EXP_OPT(CMS_SharedInfo, entityUInfo, ASN1_OCTET_STRING, 0),
  ASN1_EXP_OPT(CMS_SharedInfo, suppPubInfo, ASN1_OCTET_STRING, 2),
} ASN1_SEQUENCE_END(CMS_SharedInfo)

int CMS_SharedInfo_encode(unsigned char **pder, X509_ALGOR *kekalg,
                          ASN1_OCTET_STRING *ukm, int keylen)
{
    union {
        CMS_SharedInfo *pecsi;
        ASN1_VALUE *a;
    } intsi = {
        NULL
    };

    ASN1_OCTET_STRING oklen;
    unsigned char kl[4];
    CMS_SharedInfo ecsi;

    keylen <<= 3;
    kl[0] = (keylen >> 24) & 0xff;
    kl[1] = (keylen >> 16) & 0xff;
    kl[2] = (keylen >> 8) & 0xff;
    kl[3] = keylen & 0xff;
    oklen.length = 4;
    oklen.data = kl;
    oklen.type = V_ASN1_OCTET_STRING;
    oklen.flags = 0;
    ecsi.keyInfo = kekalg;
    ecsi.entityUInfo = ukm;
    ecsi.suppPubInfo = &oklen;
    intsi.pecsi = &ecsi;
    return ASN1_item_i2d(intsi.a, pder, ASN1_ITEM_rptr(CMS_SharedInfo));
}
/* crypto/cms/cms_att.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project.
 */
/* ====================================================================
 * Copyright (c) 2008 The OpenSSL Project.  All rights reserved.
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
 */

// #include "asn1t.h"
// #include "pem.h"
// #include "x509v3.h"
#include "err.h"
// #include "cms.h"
// #include "cms_lcl.h"

/* CMS SignedData Attribute utilities */

int CMS_signed_get_attr_count(const CMS_SignerInfo *si)
{
    return X509at_get_attr_count(si->signedAttrs);
}

int CMS_signed_get_attr_by_NID(const CMS_SignerInfo *si, int nid, int lastpos)
{
    return X509at_get_attr_by_NID(si->signedAttrs, nid, lastpos);
}

int CMS_signed_get_attr_by_OBJ(const CMS_SignerInfo *si, ASN1_OBJECT *obj,
                               int lastpos)
{
    return X509at_get_attr_by_OBJ(si->signedAttrs, obj, lastpos);
}

X509_ATTRIBUTE *CMS_signed_get_attr(const CMS_SignerInfo *si, int loc)
{
    return X509at_get_attr(si->signedAttrs, loc);
}

X509_ATTRIBUTE *CMS_signed_delete_attr(CMS_SignerInfo *si, int loc)
{
    return X509at_delete_attr(si->signedAttrs, loc);
}

int CMS_signed_add1_attr(CMS_SignerInfo *si, X509_ATTRIBUTE *attr)
{
    if (X509at_add1_attr(&si->signedAttrs, attr))
        return 1;
    return 0;
}

int CMS_signed_add1_attr_by_OBJ(CMS_SignerInfo *si,
                                const ASN1_OBJECT *obj, int type,
                                const void *bytes, int len)
{
    if (X509at_add1_attr_by_OBJ(&si->signedAttrs, obj, type, bytes, len))
        return 1;
    return 0;
}

int CMS_signed_add1_attr_by_NID(CMS_SignerInfo *si,
                                int nid, int type, const void *bytes, int len)
{
    if (X509at_add1_attr_by_NID(&si->signedAttrs, nid, type, bytes, len))
        return 1;
    return 0;
}

int CMS_signed_add1_attr_by_txt(CMS_SignerInfo *si,
                                const char *attrname, int type,
                                const void *bytes, int len)
{
    if (X509at_add1_attr_by_txt(&si->signedAttrs, attrname, type, bytes, len))
        return 1;
    return 0;
}

void *CMS_signed_get0_data_by_OBJ(CMS_SignerInfo *si, ASN1_OBJECT *oid,
                                  int lastpos, int type)
{
    return X509at_get0_data_by_OBJ(si->signedAttrs, oid, lastpos, type);
}

int CMS_unsigned_get_attr_count(const CMS_SignerInfo *si)
{
    return X509at_get_attr_count(si->unsignedAttrs);
}

int CMS_unsigned_get_attr_by_NID(const CMS_SignerInfo *si, int nid,
                                 int lastpos)
{
    return X509at_get_attr_by_NID(si->unsignedAttrs, nid, lastpos);
}

int CMS_unsigned_get_attr_by_OBJ(const CMS_SignerInfo *si, ASN1_OBJECT *obj,
                                 int lastpos)
{
    return X509at_get_attr_by_OBJ(si->unsignedAttrs, obj, lastpos);
}

X509_ATTRIBUTE *CMS_unsigned_get_attr(const CMS_SignerInfo *si, int loc)
{
    return X509at_get_attr(si->unsignedAttrs, loc);
}

X509_ATTRIBUTE *CMS_unsigned_delete_attr(CMS_SignerInfo *si, int loc)
{
    return X509at_delete_attr(si->unsignedAttrs, loc);
}

int CMS_unsigned_add1_attr(CMS_SignerInfo *si, X509_ATTRIBUTE *attr)
{
    if (X509at_add1_attr(&si->unsignedAttrs, attr))
        return 1;
    return 0;
}

int CMS_unsigned_add1_attr_by_OBJ(CMS_SignerInfo *si,
                                  const ASN1_OBJECT *obj, int type,
                                  const void *bytes, int len)
{
    if (X509at_add1_attr_by_OBJ(&si->unsignedAttrs, obj, type, bytes, len))
        return 1;
    return 0;
}

int CMS_unsigned_add1_attr_by_NID(CMS_SignerInfo *si,
                                  int nid, int type,
                                  const void *bytes, int len)
{
    if (X509at_add1_attr_by_NID(&si->unsignedAttrs, nid, type, bytes, len))
        return 1;
    return 0;
}

int CMS_unsigned_add1_attr_by_txt(CMS_SignerInfo *si,
                                  const char *attrname, int type,
                                  const void *bytes, int len)
{
    if (X509at_add1_attr_by_txt(&si->unsignedAttrs, attrname,
                                type, bytes, len))
        return 1;
    return 0;
}

void *CMS_unsigned_get0_data_by_OBJ(CMS_SignerInfo *si, ASN1_OBJECT *oid,
                                    int lastpos, int type)
{
    return X509at_get0_data_by_OBJ(si->unsignedAttrs, oid, lastpos, type);
}

/* Specific attribute cases */
/* crypto/cms/cms_cd.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project.
 */
/* ====================================================================
 * Copyright (c) 2008 The OpenSSL Project.  All rights reserved.
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
 */

#include "cryptlib.h"
// #include "asn1t.h"
// #include "pem.h"
// #include "x509v3.h"
// #include "err.h"
// #include "cms.h"
#include "bio.h"
#ifndef OPENSSL_NO_COMP
# include "comp.h"
#endif
// #include "cms_lcl.h"

DECLARE_ASN1_ITEM(CMS_CompressedData)

#ifdef ZLIB

/* CMS CompressedData Utilities */

CMS_ContentInfo *cms_CompressedData_create(int comp_nid)
{
    CMS_ContentInfo *cms;
    CMS_CompressedData *cd;
    /*
     * Will need something cleverer if there is ever more than one
     * compression algorithm or parameters have some meaning...
     */
    if (comp_nid != NID_zlib_compression) {
        CMSerr(CMS_F_CMS_COMPRESSEDDATA_CREATE,
               CMS_R_UNSUPPORTED_COMPRESSION_ALGORITHM);
        return NULL;
    }
    cms = CMS_ContentInfo_new();
    if (!cms)
        return NULL;

    cd = M_ASN1_new_of(CMS_CompressedData);

    if (!cd)
        goto err;

    cms->contentType = OBJ_nid2obj(NID_id_smime_ct_compressedData);
    cms->d.compressedData = cd;

    cd->version = 0;

    X509_ALGOR_set0(cd->compressionAlgorithm,
                    OBJ_nid2obj(NID_zlib_compression), V_ASN1_UNDEF, NULL);

    cd->encapContentInfo->eContentType = OBJ_nid2obj(NID_pkcs7_data);

    return cms;

 err:

    if (cms)
        CMS_ContentInfo_free(cms);

    return NULL;
}

BIO *cms_CompressedData_init_bio(CMS_ContentInfo *cms)
{
    CMS_CompressedData *cd;
    ASN1_OBJECT *compoid;
    if (OBJ_obj2nid(cms->contentType) != NID_id_smime_ct_compressedData) {
        CMSerr(CMS_F_CMS_COMPRESSEDDATA_INIT_BIO,
               CMS_R_CONTENT_TYPE_NOT_COMPRESSED_DATA);
        return NULL;
    }
    cd = cms->d.compressedData;
    X509_ALGOR_get0(&compoid, NULL, NULL, cd->compressionAlgorithm);
    if (OBJ_obj2nid(compoid) != NID_zlib_compression) {
        CMSerr(CMS_F_CMS_COMPRESSEDDATA_INIT_BIO,
               CMS_R_UNSUPPORTED_COMPRESSION_ALGORITHM);
        return NULL;
    }
    return BIO_new(BIO_f_zlib());
}

#endif
/* crypto/cms/cms_dd.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project.
 */
/* ====================================================================
 * Copyright (c) 2008 The OpenSSL Project.  All rights reserved.
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
 */

// #include "cryptlib.h"
// #include "asn1t.h"
// #include "pem.h"
// #include "x509v3.h"
// #include "err.h"
// #include "cms.h"
// #include "cms_lcl.h"

DECLARE_ASN1_ITEM(CMS_DigestedData)

/* CMS DigestedData Utilities */

CMS_ContentInfo *cms_DigestedData_create(const EVP_MD *md)
{
    CMS_ContentInfo *cms;
    CMS_DigestedData *dd;
    cms = CMS_ContentInfo_new();
    if (!cms)
        return NULL;

    dd = M_ASN1_new_of(CMS_DigestedData);

    if (!dd)
        goto err;

    cms->contentType = OBJ_nid2obj(NID_pkcs7_digest);
    cms->d.digestedData = dd;

    dd->version = 0;
    dd->encapContentInfo->eContentType = OBJ_nid2obj(NID_pkcs7_data);

    cms_DigestAlgorithm_set(dd->digestAlgorithm, md);

    return cms;

 err:

    if (cms)
        CMS_ContentInfo_free(cms);

    return NULL;
}

BIO *cms_DigestedData_init_bio(CMS_ContentInfo *cms)
{
    CMS_DigestedData *dd;
    dd = cms->d.digestedData;
    return cms_DigestAlgorithm_init_bio(dd->digestAlgorithm);
}

int cms_DigestedData_do_final(CMS_ContentInfo *cms, BIO *chain, int verify)
{
    EVP_MD_CTX mctx;
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int mdlen;
    int r = 0;
    CMS_DigestedData *dd;
    EVP_MD_CTX_init(&mctx);

    dd = cms->d.digestedData;

    if (!cms_DigestAlgorithm_find_ctx(&mctx, chain, dd->digestAlgorithm))
        goto err;

    if (EVP_DigestFinal_ex(&mctx, md, &mdlen) <= 0)
        goto err;

    if (verify) {
        if (mdlen != (unsigned int)dd->digest->length) {
            CMSerr(CMS_F_CMS_DIGESTEDDATA_DO_FINAL,
                   CMS_R_MESSAGEDIGEST_WRONG_LENGTH);
            goto err;
        }

        if (memcmp(md, dd->digest->data, mdlen))
            CMSerr(CMS_F_CMS_DIGESTEDDATA_DO_FINAL,
                   CMS_R_VERIFICATION_FAILURE);
        else
            r = 1;
    } else {
        if (!ASN1_STRING_set(dd->digest, md, mdlen))
            goto err;
        r = 1;
    }

 err:
    EVP_MD_CTX_cleanup(&mctx);

    return r;

}
/* crypto/cms/cms_enc.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project.
 */
/* ====================================================================
 * Copyright (c) 2008 The OpenSSL Project.  All rights reserved.
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
 */

// #include "cryptlib.h"
// #include "asn1t.h"
// #include "pem.h"
// #include "x509v3.h"
// #include "err.h"
// #include "cms.h"
#include "rand.h"
// #include "cms_lcl.h"

/* CMS EncryptedData Utilities */

DECLARE_ASN1_ITEM(CMS_EncryptedData)

/* Return BIO based on EncryptedContentInfo and key */

BIO *cms_EncryptedContent_init_bio(CMS_EncryptedContentInfo *ec)
{
    BIO *b;
    EVP_CIPHER_CTX *ctx;
    const EVP_CIPHER *ciph;
    X509_ALGOR *calg = ec->contentEncryptionAlgorithm;
    unsigned char iv[EVP_MAX_IV_LENGTH], *piv = NULL;
    unsigned char *tkey = NULL;
    size_t tkeylen = 0;

    int ok = 0;

    int enc, keep_key = 0;

    enc = ec->cipher ? 1 : 0;

    b = BIO_new(BIO_f_cipher());
    if (!b) {
        CMSerr(CMS_F_CMS_ENCRYPTEDCONTENT_INIT_BIO, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    BIO_get_cipher_ctx(b, &ctx);

    if (enc) {
        ciph = ec->cipher;
        /*
         * If not keeping key set cipher to NULL so subsequent calls decrypt.
         */
        if (ec->key)
            ec->cipher = NULL;
    } else {
        ciph = EVP_get_cipherbyobj(calg->algorithm);

        if (!ciph) {
            CMSerr(CMS_F_CMS_ENCRYPTEDCONTENT_INIT_BIO, CMS_R_UNKNOWN_CIPHER);
            goto err;
        }
    }

    if (EVP_CipherInit_ex(ctx, ciph, NULL, NULL, NULL, enc) <= 0) {
        CMSerr(CMS_F_CMS_ENCRYPTEDCONTENT_INIT_BIO,
               CMS_R_CIPHER_INITIALISATION_ERROR);
        goto err;
    }

    if (enc) {
        int ivlen;
        calg->algorithm = OBJ_nid2obj(EVP_CIPHER_CTX_type(ctx));
        /* Generate a random IV if we need one */
        ivlen = EVP_CIPHER_CTX_iv_length(ctx);
        if (ivlen > 0) {
            if (RAND_bytes(iv, ivlen) <= 0)
                goto err;
            piv = iv;
        }
    } else if (EVP_CIPHER_asn1_to_param(ctx, calg->parameter) <= 0) {
        CMSerr(CMS_F_CMS_ENCRYPTEDCONTENT_INIT_BIO,
               CMS_R_CIPHER_PARAMETER_INITIALISATION_ERROR);
        goto err;
    }
    tkeylen = EVP_CIPHER_CTX_key_length(ctx);
    /* Generate random session key */
    if (!enc || !ec->key) {
        tkey = OPENSSL_malloc(tkeylen);
        if (!tkey) {
            CMSerr(CMS_F_CMS_ENCRYPTEDCONTENT_INIT_BIO, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        if (EVP_CIPHER_CTX_rand_key(ctx, tkey) <= 0)
            goto err;
    }

    if (!ec->key) {
        ec->key = tkey;
        ec->keylen = tkeylen;
        tkey = NULL;
        if (enc)
            keep_key = 1;
        else
            ERR_clear_error();

    }

    if (ec->keylen != tkeylen) {
        /* If necessary set key length */
        if (EVP_CIPHER_CTX_set_key_length(ctx, ec->keylen) <= 0) {
            /*
             * Only reveal failure if debugging so we don't leak information
             * which may be useful in MMA.
             */
            if (enc || ec->debug) {
                CMSerr(CMS_F_CMS_ENCRYPTEDCONTENT_INIT_BIO,
                       CMS_R_INVALID_KEY_LENGTH);
                goto err;
            } else {
                /* Use random key */
                OPENSSL_cleanse(ec->key, ec->keylen);
                OPENSSL_free(ec->key);
                ec->key = tkey;
                ec->keylen = tkeylen;
                tkey = NULL;
                ERR_clear_error();
            }
        }
    }

    if (EVP_CipherInit_ex(ctx, NULL, NULL, ec->key, piv, enc) <= 0) {
        CMSerr(CMS_F_CMS_ENCRYPTEDCONTENT_INIT_BIO,
               CMS_R_CIPHER_INITIALISATION_ERROR);
        goto err;
    }
    if (enc) {
        calg->parameter = ASN1_TYPE_new();
        if (calg->parameter == NULL) {
            CMSerr(CMS_F_CMS_ENCRYPTEDCONTENT_INIT_BIO, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        if (EVP_CIPHER_param_to_asn1(ctx, calg->parameter) <= 0) {
            CMSerr(CMS_F_CMS_ENCRYPTEDCONTENT_INIT_BIO,
                   CMS_R_CIPHER_PARAMETER_INITIALISATION_ERROR);
            goto err;
        }
        /* If parameter type not set omit parameter */
        if (calg->parameter->type == V_ASN1_UNDEF) {
            ASN1_TYPE_free(calg->parameter);
            calg->parameter = NULL;
        }
    }
    ok = 1;

 err:
    if (ec->key && (!keep_key || !ok)) {
        OPENSSL_cleanse(ec->key, ec->keylen);
        OPENSSL_free(ec->key);
        ec->key = NULL;
    }
    if (tkey) {
        OPENSSL_cleanse(tkey, tkeylen);
        OPENSSL_free(tkey);
    }
    if (ok)
        return b;
    BIO_free(b);
    return NULL;
}

int cms_EncryptedContent_init(CMS_EncryptedContentInfo *ec,
                              const EVP_CIPHER *cipher,
                              const unsigned char *key, size_t keylen)
{
    ec->cipher = cipher;
    if (key) {
        ec->key = OPENSSL_malloc(keylen);
        if (!ec->key)
            return 0;
        memcpy(ec->key, key, keylen);
    }
    ec->keylen = keylen;
    if (cipher)
        ec->contentType = OBJ_nid2obj(NID_pkcs7_data);
    return 1;
}

int CMS_EncryptedData_set1_key(CMS_ContentInfo *cms, const EVP_CIPHER *ciph,
                               const unsigned char *key, size_t keylen)
{
    CMS_EncryptedContentInfo *ec;
    if (!key || !keylen) {
        CMSerr(CMS_F_CMS_ENCRYPTEDDATA_SET1_KEY, CMS_R_NO_KEY);
        return 0;
    }
    if (ciph) {
        cms->d.encryptedData = M_ASN1_new_of(CMS_EncryptedData);
        if (!cms->d.encryptedData) {
            CMSerr(CMS_F_CMS_ENCRYPTEDDATA_SET1_KEY, ERR_R_MALLOC_FAILURE);
            return 0;
        }
        cms->contentType = OBJ_nid2obj(NID_pkcs7_encrypted);
        cms->d.encryptedData->version = 0;
    } else if (OBJ_obj2nid(cms->contentType) != NID_pkcs7_encrypted) {
        CMSerr(CMS_F_CMS_ENCRYPTEDDATA_SET1_KEY, CMS_R_NOT_ENCRYPTED_DATA);
        return 0;
    }
    ec = cms->d.encryptedData->encryptedContentInfo;
    return cms_EncryptedContent_init(ec, ciph, key, keylen);
}

BIO *cms_EncryptedData_init_bio(CMS_ContentInfo *cms)
{
    CMS_EncryptedData *enc = cms->d.encryptedData;
    if (enc->encryptedContentInfo->cipher && enc->unprotectedAttrs)
        enc->version = 2;
    return cms_EncryptedContent_init_bio(enc->encryptedContentInfo);
}
/* crypto/cms/cms_env.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project.
 */
/* ====================================================================
 * Copyright (c) 2008 The OpenSSL Project.  All rights reserved.
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
 */

// #include "cryptlib.h"
// #include "asn1t.h"
// #include "pem.h"
// #include "x509v3.h"
// #include "err.h"
// #include "cms.h"
// #include "rand.h"
#include "aes.h"
// #include "cms_lcl.h"
#include "asn1_locl.h"

/* CMS EnvelopedData Utilities */

DECLARE_ASN1_ITEM(CMS_EnvelopedData)
DECLARE_ASN1_ITEM(CMS_KeyTransRecipientInfo)
DECLARE_ASN1_ITEM(CMS_KEKRecipientInfo)
DECLARE_ASN1_ITEM(CMS_OtherKeyAttribute)

DECLARE_STACK_OF(CMS_RecipientInfo)

CMS_EnvelopedData *cms_get0_enveloped(CMS_ContentInfo *cms)
{
    if (OBJ_obj2nid(cms->contentType) != NID_pkcs7_enveloped) {
        CMSerr(CMS_F_CMS_GET0_ENVELOPED,
               CMS_R_CONTENT_TYPE_NOT_ENVELOPED_DATA);
        return NULL;
    }
    return cms->d.envelopedData;
}

static CMS_EnvelopedData *cms_enveloped_data_init(CMS_ContentInfo *cms)
{
    if (cms->d.other == NULL) {
        cms->d.envelopedData = M_ASN1_new_of(CMS_EnvelopedData);
        if (!cms->d.envelopedData) {
            CMSerr(CMS_F_CMS_ENVELOPED_DATA_INIT, ERR_R_MALLOC_FAILURE);
            return NULL;
        }
        cms->d.envelopedData->version = 0;
        cms->d.envelopedData->encryptedContentInfo->contentType =
            OBJ_nid2obj(NID_pkcs7_data);
        ASN1_OBJECT_free(cms->contentType);
        cms->contentType = OBJ_nid2obj(NID_pkcs7_enveloped);
        return cms->d.envelopedData;
    }
    return cms_get0_enveloped(cms);
}

int cms_env_asn1_ctrl(CMS_RecipientInfo *ri, int cmd)
{
    EVP_PKEY *pkey;
    int i;
    if (ri->type == CMS_RECIPINFO_TRANS)
        pkey = ri->d.ktri->pkey;
    else if (ri->type == CMS_RECIPINFO_AGREE) {
        EVP_PKEY_CTX *pctx = ri->d.kari->pctx;
        if (!pctx)
            return 0;
        pkey = EVP_PKEY_CTX_get0_pkey(pctx);
        if (!pkey)
            return 0;
    } else
        return 0;
    if (!pkey->ameth || !pkey->ameth->pkey_ctrl)
        return 1;
    i = pkey->ameth->pkey_ctrl(pkey, ASN1_PKEY_CTRL_CMS_ENVELOPE, cmd, ri);
    if (i == -2) {
        CMSerr(CMS_F_CMS_ENV_ASN1_CTRL,
               CMS_R_NOT_SUPPORTED_FOR_THIS_KEY_TYPE);
        return 0;
    }
    if (i <= 0) {
        CMSerr(CMS_F_CMS_ENV_ASN1_CTRL, CMS_R_CTRL_FAILURE);
        return 0;
    }
    return 1;
}

STACK_OF(CMS_RecipientInfo) *CMS_get0_RecipientInfos(CMS_ContentInfo *cms)
{
    CMS_EnvelopedData *env;
    env = cms_get0_enveloped(cms);
    if (!env)
        return NULL;
    return env->recipientInfos;
}

int CMS_RecipientInfo_type(CMS_RecipientInfo *ri)
{
    return ri->type;
}

EVP_PKEY_CTX *CMS_RecipientInfo_get0_pkey_ctx(CMS_RecipientInfo *ri)
{
    if (ri->type == CMS_RECIPINFO_TRANS)
        return ri->d.ktri->pctx;
    else if (ri->type == CMS_RECIPINFO_AGREE)
        return ri->d.kari->pctx;
    return NULL;
}

CMS_ContentInfo *CMS_EnvelopedData_create(const EVP_CIPHER *cipher)
{
    CMS_ContentInfo *cms;
    CMS_EnvelopedData *env;
    cms = CMS_ContentInfo_new();
    if (!cms)
        goto merr;
    env = cms_enveloped_data_init(cms);
    if (!env)
        goto merr;
    if (!cms_EncryptedContent_init(env->encryptedContentInfo,
                                   cipher, NULL, 0))
        goto merr;
    return cms;
 merr:
    if (cms)
        CMS_ContentInfo_free(cms);
    CMSerr(CMS_F_CMS_ENVELOPEDDATA_CREATE, ERR_R_MALLOC_FAILURE);
    return NULL;
}

/* Key Transport Recipient Info (KTRI) routines */

/* Initialise a ktri based on passed certificate and key */

static int cms_RecipientInfo_ktri_init(CMS_RecipientInfo *ri, X509 *recip,
                                       EVP_PKEY *pk, unsigned int flags)
{
    CMS_KeyTransRecipientInfo *ktri;
    int idtype;

    ri->d.ktri = M_ASN1_new_of(CMS_KeyTransRecipientInfo);
    if (!ri->d.ktri)
        return 0;
    ri->type = CMS_RECIPINFO_TRANS;

    ktri = ri->d.ktri;

    if (flags & CMS_USE_KEYID) {
        ktri->version = 2;
        idtype = CMS_RECIPINFO_KEYIDENTIFIER;
    } else {
        ktri->version = 0;
        idtype = CMS_RECIPINFO_ISSUER_SERIAL;
    }

    /*
     * Not a typo: RecipientIdentifier and SignerIdentifier are the same
     * structure.
     */

    if (!cms_set1_SignerIdentifier(ktri->rid, recip, idtype))
        return 0;

    CRYPTO_add(&recip->references, 1, CRYPTO_LOCK_X509);
    CRYPTO_add(&pk->references, 1, CRYPTO_LOCK_EVP_PKEY);
    ktri->pkey = pk;
    ktri->recip = recip;

    if (flags & CMS_KEY_PARAM) {
        ktri->pctx = EVP_PKEY_CTX_new(ktri->pkey, NULL);
        if (!ktri->pctx)
            return 0;
        if (EVP_PKEY_encrypt_init(ktri->pctx) <= 0)
            return 0;
    } else if (!cms_env_asn1_ctrl(ri, 0))
        return 0;
    return 1;
}

/*
 * Add a recipient certificate using appropriate type of RecipientInfo
 */

CMS_RecipientInfo *CMS_add1_recipient_cert(CMS_ContentInfo *cms,
                                           X509 *recip, unsigned int flags)
{
    CMS_RecipientInfo *ri = NULL;
    CMS_EnvelopedData *env;
    EVP_PKEY *pk = NULL;
    env = cms_get0_enveloped(cms);
    if (!env)
        goto err;

    /* Initialize recipient info */
    ri = M_ASN1_new_of(CMS_RecipientInfo);
    if (!ri)
        goto merr;

    pk = X509_get_pubkey(recip);
    if (!pk) {
        CMSerr(CMS_F_CMS_ADD1_RECIPIENT_CERT, CMS_R_ERROR_GETTING_PUBLIC_KEY);
        goto err;
    }

    switch (cms_pkey_get_ri_type(pk)) {

    case CMS_RECIPINFO_TRANS:
        if (!cms_RecipientInfo_ktri_init(ri, recip, pk, flags))
            goto err;
        break;

    case CMS_RECIPINFO_AGREE:
        if (!cms_RecipientInfo_kari_init(ri, recip, pk, flags))
            goto err;
        break;

    default:
        CMSerr(CMS_F_CMS_ADD1_RECIPIENT_CERT,
               CMS_R_NOT_SUPPORTED_FOR_THIS_KEY_TYPE);
        goto err;

    }

    if (!sk_CMS_RecipientInfo_push(env->recipientInfos, ri))
        goto merr;

    EVP_PKEY_free(pk);

    return ri;

 merr:
    CMSerr(CMS_F_CMS_ADD1_RECIPIENT_CERT, ERR_R_MALLOC_FAILURE);
 err:
    if (ri)
        M_ASN1_free_of(ri, CMS_RecipientInfo);
    if (pk)
        EVP_PKEY_free(pk);
    return NULL;

}

int CMS_RecipientInfo_ktri_get0_algs(CMS_RecipientInfo *ri,
                                     EVP_PKEY **pk, X509 **recip,
                                     X509_ALGOR **palg)
{
    CMS_KeyTransRecipientInfo *ktri;
    if (ri->type != CMS_RECIPINFO_TRANS) {
        CMSerr(CMS_F_CMS_RECIPIENTINFO_KTRI_GET0_ALGS,
               CMS_R_NOT_KEY_TRANSPORT);
        return 0;
    }

    ktri = ri->d.ktri;

    if (pk)
        *pk = ktri->pkey;
    if (recip)
        *recip = ktri->recip;
    if (palg)
        *palg = ktri->keyEncryptionAlgorithm;
    return 1;
}

int CMS_RecipientInfo_ktri_get0_signer_id(CMS_RecipientInfo *ri,
                                          ASN1_OCTET_STRING **keyid,
                                          X509_NAME **issuer,
                                          ASN1_INTEGER **sno)
{
    CMS_KeyTransRecipientInfo *ktri;
    if (ri->type != CMS_RECIPINFO_TRANS) {
        CMSerr(CMS_F_CMS_RECIPIENTINFO_KTRI_GET0_SIGNER_ID,
               CMS_R_NOT_KEY_TRANSPORT);
        return 0;
    }
    ktri = ri->d.ktri;

    return cms_SignerIdentifier_get0_signer_id(ktri->rid, keyid, issuer, sno);
}

int CMS_RecipientInfo_ktri_cert_cmp(CMS_RecipientInfo *ri, X509 *cert)
{
    if (ri->type != CMS_RECIPINFO_TRANS) {
        CMSerr(CMS_F_CMS_RECIPIENTINFO_KTRI_CERT_CMP,
               CMS_R_NOT_KEY_TRANSPORT);
        return -2;
    }
    return cms_SignerIdentifier_cert_cmp(ri->d.ktri->rid, cert);
}

int CMS_RecipientInfo_set0_pkey(CMS_RecipientInfo *ri, EVP_PKEY *pkey)
{
    if (ri->type != CMS_RECIPINFO_TRANS) {
        CMSerr(CMS_F_CMS_RECIPIENTINFO_SET0_PKEY, CMS_R_NOT_KEY_TRANSPORT);
        return 0;
    }
    ri->d.ktri->pkey = pkey;
    return 1;
}

/* Encrypt content key in key transport recipient info */

static int cms_RecipientInfo_ktri_encrypt(CMS_ContentInfo *cms,
                                          CMS_RecipientInfo *ri)
{
    CMS_KeyTransRecipientInfo *ktri;
    CMS_EncryptedContentInfo *ec;
    EVP_PKEY_CTX *pctx;
    unsigned char *ek = NULL;
    size_t eklen;

    int ret = 0;

    if (ri->type != CMS_RECIPINFO_TRANS) {
        CMSerr(CMS_F_CMS_RECIPIENTINFO_KTRI_ENCRYPT, CMS_R_NOT_KEY_TRANSPORT);
        return 0;
    }
    ktri = ri->d.ktri;
    ec = cms->d.envelopedData->encryptedContentInfo;

    pctx = ktri->pctx;

    if (pctx) {
        if (!cms_env_asn1_ctrl(ri, 0))
            goto err;
    } else {
        pctx = EVP_PKEY_CTX_new(ktri->pkey, NULL);
        if (!pctx)
            return 0;

        if (EVP_PKEY_encrypt_init(pctx) <= 0)
            goto err;
    }

    if (EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_ENCRYPT,
                          EVP_PKEY_CTRL_CMS_ENCRYPT, 0, ri) <= 0) {
        CMSerr(CMS_F_CMS_RECIPIENTINFO_KTRI_ENCRYPT, CMS_R_CTRL_ERROR);
        goto err;
    }

    if (EVP_PKEY_encrypt(pctx, NULL, &eklen, ec->key, ec->keylen) <= 0)
        goto err;

    ek = OPENSSL_malloc(eklen);

    if (ek == NULL) {
        CMSerr(CMS_F_CMS_RECIPIENTINFO_KTRI_ENCRYPT, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (EVP_PKEY_encrypt(pctx, ek, &eklen, ec->key, ec->keylen) <= 0)
        goto err;

    ASN1_STRING_set0(ktri->encryptedKey, ek, eklen);
    ek = NULL;

    ret = 1;

 err:
    if (pctx) {
        EVP_PKEY_CTX_free(pctx);
        ktri->pctx = NULL;
    }
    if (ek)
        OPENSSL_free(ek);
    return ret;

}

/* Decrypt content key from KTRI */

static int cms_RecipientInfo_ktri_decrypt(CMS_ContentInfo *cms,
                                          CMS_RecipientInfo *ri)
{
    CMS_KeyTransRecipientInfo *ktri = ri->d.ktri;
    EVP_PKEY *pkey = ktri->pkey;
    unsigned char *ek = NULL;
    size_t eklen;
    int ret = 0;
    CMS_EncryptedContentInfo *ec;
    ec = cms->d.envelopedData->encryptedContentInfo;

    if (ktri->pkey == NULL) {
        CMSerr(CMS_F_CMS_RECIPIENTINFO_KTRI_DECRYPT, CMS_R_NO_PRIVATE_KEY);
        return 0;
    }

    ktri->pctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ktri->pctx)
        return 0;

    if (EVP_PKEY_decrypt_init(ktri->pctx) <= 0)
        goto err;

    if (!cms_env_asn1_ctrl(ri, 1))
        goto err;

    if (EVP_PKEY_CTX_ctrl(ktri->pctx, -1, EVP_PKEY_OP_DECRYPT,
                          EVP_PKEY_CTRL_CMS_DECRYPT, 0, ri) <= 0) {
        CMSerr(CMS_F_CMS_RECIPIENTINFO_KTRI_DECRYPT, CMS_R_CTRL_ERROR);
        goto err;
    }

    if (EVP_PKEY_decrypt(ktri->pctx, NULL, &eklen,
                         ktri->encryptedKey->data,
                         ktri->encryptedKey->length) <= 0)
        goto err;

    ek = OPENSSL_malloc(eklen);

    if (ek == NULL) {
        CMSerr(CMS_F_CMS_RECIPIENTINFO_KTRI_DECRYPT, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (EVP_PKEY_decrypt(ktri->pctx, ek, &eklen,
                         ktri->encryptedKey->data,
                         ktri->encryptedKey->length) <= 0) {
        CMSerr(CMS_F_CMS_RECIPIENTINFO_KTRI_DECRYPT, CMS_R_CMS_LIB);
        goto err;
    }

    ret = 1;

    if (ec->key) {
        OPENSSL_cleanse(ec->key, ec->keylen);
        OPENSSL_free(ec->key);
    }

    ec->key = ek;
    ec->keylen = eklen;

 err:
    if (ktri->pctx) {
        EVP_PKEY_CTX_free(ktri->pctx);
        ktri->pctx = NULL;
    }
    if (!ret && ek)
        OPENSSL_free(ek);

    return ret;
}

/* Key Encrypted Key (KEK) RecipientInfo routines */

int CMS_RecipientInfo_kekri_id_cmp(CMS_RecipientInfo *ri,
                                   const unsigned char *id, size_t idlen)
{
    ASN1_OCTET_STRING tmp_os;
    CMS_KEKRecipientInfo *kekri;
    if (ri->type != CMS_RECIPINFO_KEK) {
        CMSerr(CMS_F_CMS_RECIPIENTINFO_KEKRI_ID_CMP, CMS_R_NOT_KEK);
        return -2;
    }
    kekri = ri->d.kekri;
    tmp_os.type = V_ASN1_OCTET_STRING;
    tmp_os.flags = 0;
    tmp_os.data = (unsigned char *)id;
    tmp_os.length = (int)idlen;
    return ASN1_OCTET_STRING_cmp(&tmp_os, kekri->kekid->keyIdentifier);
}

/* For now hard code AES key wrap info */

static size_t aes_wrap_keylen(int nid)
{
    switch (nid) {
    case NID_id_aes128_wrap:
        return 16;

    case NID_id_aes192_wrap:
        return 24;

    case NID_id_aes256_wrap:
        return 32;

    default:
        return 0;
    }
}

CMS_RecipientInfo *CMS_add0_recipient_key(CMS_ContentInfo *cms, int nid,
                                          unsigned char *key, size_t keylen,
                                          unsigned char *id, size_t idlen,
                                          ASN1_GENERALIZEDTIME *date,
                                          ASN1_OBJECT *otherTypeId,
                                          ASN1_TYPE *otherType)
{
    CMS_RecipientInfo *ri = NULL;
    CMS_EnvelopedData *env;
    CMS_KEKRecipientInfo *kekri;
    env = cms_get0_enveloped(cms);
    if (!env)
        goto err;

    if (nid == NID_undef) {
        switch (keylen) {
        case 16:
            nid = NID_id_aes128_wrap;
            break;

        case 24:
            nid = NID_id_aes192_wrap;
            break;

        case 32:
            nid = NID_id_aes256_wrap;
            break;

        default:
            CMSerr(CMS_F_CMS_ADD0_RECIPIENT_KEY, CMS_R_INVALID_KEY_LENGTH);
            goto err;
        }

    } else {

        size_t exp_keylen = aes_wrap_keylen(nid);

        if (!exp_keylen) {
            CMSerr(CMS_F_CMS_ADD0_RECIPIENT_KEY,
                   CMS_R_UNSUPPORTED_KEK_ALGORITHM);
            goto err;
        }

        if (keylen != exp_keylen) {
            CMSerr(CMS_F_CMS_ADD0_RECIPIENT_KEY, CMS_R_INVALID_KEY_LENGTH);
            goto err;
        }

    }

    /* Initialize recipient info */
    ri = M_ASN1_new_of(CMS_RecipientInfo);
    if (!ri)
        goto merr;

    ri->d.kekri = M_ASN1_new_of(CMS_KEKRecipientInfo);
    if (!ri->d.kekri)
        goto merr;
    ri->type = CMS_RECIPINFO_KEK;

    kekri = ri->d.kekri;

    if (otherTypeId) {
        kekri->kekid->other = M_ASN1_new_of(CMS_OtherKeyAttribute);
        if (kekri->kekid->other == NULL)
            goto merr;
    }

    if (!sk_CMS_RecipientInfo_push(env->recipientInfos, ri))
        goto merr;

    /* After this point no calls can fail */

    kekri->version = 4;

    kekri->key = key;
    kekri->keylen = keylen;

    ASN1_STRING_set0(kekri->kekid->keyIdentifier, id, idlen);

    kekri->kekid->date = date;

    if (kekri->kekid->other) {
        kekri->kekid->other->keyAttrId = otherTypeId;
        kekri->kekid->other->keyAttr = otherType;
    }

    X509_ALGOR_set0(kekri->keyEncryptionAlgorithm,
                    OBJ_nid2obj(nid), V_ASN1_UNDEF, NULL);

    return ri;

 merr:
    CMSerr(CMS_F_CMS_ADD0_RECIPIENT_KEY, ERR_R_MALLOC_FAILURE);
 err:
    if (ri)
        M_ASN1_free_of(ri, CMS_RecipientInfo);
    return NULL;

}

int CMS_RecipientInfo_kekri_get0_id(CMS_RecipientInfo *ri,
                                    X509_ALGOR **palg,
                                    ASN1_OCTET_STRING **pid,
                                    ASN1_GENERALIZEDTIME **pdate,
                                    ASN1_OBJECT **potherid,
                                    ASN1_TYPE **pothertype)
{
    CMS_KEKIdentifier *rkid;
    if (ri->type != CMS_RECIPINFO_KEK) {
        CMSerr(CMS_F_CMS_RECIPIENTINFO_KEKRI_GET0_ID, CMS_R_NOT_KEK);
        return 0;
    }
    rkid = ri->d.kekri->kekid;
    if (palg)
        *palg = ri->d.kekri->keyEncryptionAlgorithm;
    if (pid)
        *pid = rkid->keyIdentifier;
    if (pdate)
        *pdate = rkid->date;
    if (potherid) {
        if (rkid->other)
            *potherid = rkid->other->keyAttrId;
        else
            *potherid = NULL;
    }
    if (pothertype) {
        if (rkid->other)
            *pothertype = rkid->other->keyAttr;
        else
            *pothertype = NULL;
    }
    return 1;
}

int CMS_RecipientInfo_set0_key(CMS_RecipientInfo *ri,
                               unsigned char *key, size_t keylen)
{
    CMS_KEKRecipientInfo *kekri;
    if (ri->type != CMS_RECIPINFO_KEK) {
        CMSerr(CMS_F_CMS_RECIPIENTINFO_SET0_KEY, CMS_R_NOT_KEK);
        return 0;
    }

    kekri = ri->d.kekri;
    kekri->key = key;
    kekri->keylen = keylen;
    return 1;
}

/* Encrypt content key in KEK recipient info */

static int cms_RecipientInfo_kekri_encrypt(CMS_ContentInfo *cms,
                                           CMS_RecipientInfo *ri)
{
    CMS_EncryptedContentInfo *ec;
    CMS_KEKRecipientInfo *kekri;
    AES_KEY actx;
    unsigned char *wkey = NULL;
    int wkeylen;
    int r = 0;

    ec = cms->d.envelopedData->encryptedContentInfo;

    kekri = ri->d.kekri;

    if (!kekri->key) {
        CMSerr(CMS_F_CMS_RECIPIENTINFO_KEKRI_ENCRYPT, CMS_R_NO_KEY);
        return 0;
    }

    if (AES_set_encrypt_key(kekri->key, kekri->keylen << 3, &actx)) {
        CMSerr(CMS_F_CMS_RECIPIENTINFO_KEKRI_ENCRYPT,
               CMS_R_ERROR_SETTING_KEY);
        goto err;
    }

    wkey = OPENSSL_malloc(ec->keylen + 8);

    if (!wkey) {
        CMSerr(CMS_F_CMS_RECIPIENTINFO_KEKRI_ENCRYPT, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    wkeylen = AES_wrap_key(&actx, NULL, wkey, ec->key, ec->keylen);

    if (wkeylen <= 0) {
        CMSerr(CMS_F_CMS_RECIPIENTINFO_KEKRI_ENCRYPT, CMS_R_WRAP_ERROR);
        goto err;
    }

    ASN1_STRING_set0(kekri->encryptedKey, wkey, wkeylen);

    r = 1;

 err:

    if (!r && wkey)
        OPENSSL_free(wkey);
    OPENSSL_cleanse(&actx, sizeof(actx));

    return r;

}

/* Decrypt content key in KEK recipient info */

static int cms_RecipientInfo_kekri_decrypt(CMS_ContentInfo *cms,
                                           CMS_RecipientInfo *ri)
{
    CMS_EncryptedContentInfo *ec;
    CMS_KEKRecipientInfo *kekri;
    AES_KEY actx;
    unsigned char *ukey = NULL;
    int ukeylen;
    int r = 0, wrap_nid;

    ec = cms->d.envelopedData->encryptedContentInfo;

    kekri = ri->d.kekri;

    if (!kekri->key) {
        CMSerr(CMS_F_CMS_RECIPIENTINFO_KEKRI_DECRYPT, CMS_R_NO_KEY);
        return 0;
    }

    wrap_nid = OBJ_obj2nid(kekri->keyEncryptionAlgorithm->algorithm);
    if (aes_wrap_keylen(wrap_nid) != kekri->keylen) {
        CMSerr(CMS_F_CMS_RECIPIENTINFO_KEKRI_DECRYPT,
               CMS_R_INVALID_KEY_LENGTH);
        return 0;
    }

    /* If encrypted key length is invalid don't bother */

    if (kekri->encryptedKey->length < 16) {
        CMSerr(CMS_F_CMS_RECIPIENTINFO_KEKRI_DECRYPT,
               CMS_R_INVALID_ENCRYPTED_KEY_LENGTH);
        goto err;
    }

    if (AES_set_decrypt_key(kekri->key, kekri->keylen << 3, &actx)) {
        CMSerr(CMS_F_CMS_RECIPIENTINFO_KEKRI_DECRYPT,
               CMS_R_ERROR_SETTING_KEY);
        goto err;
    }

    ukey = OPENSSL_malloc(kekri->encryptedKey->length - 8);

    if (!ukey) {
        CMSerr(CMS_F_CMS_RECIPIENTINFO_KEKRI_DECRYPT, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    ukeylen = AES_unwrap_key(&actx, NULL, ukey,
                             kekri->encryptedKey->data,
                             kekri->encryptedKey->length);

    if (ukeylen <= 0) {
        CMSerr(CMS_F_CMS_RECIPIENTINFO_KEKRI_DECRYPT, CMS_R_UNWRAP_ERROR);
        goto err;
    }

    ec->key = ukey;
    ec->keylen = ukeylen;

    r = 1;

 err:

    if (!r && ukey)
        OPENSSL_free(ukey);
    OPENSSL_cleanse(&actx, sizeof(actx));

    return r;

}

int CMS_RecipientInfo_decrypt(CMS_ContentInfo *cms, CMS_RecipientInfo *ri)
{
    switch (ri->type) {
    case CMS_RECIPINFO_TRANS:
        return cms_RecipientInfo_ktri_decrypt(cms, ri);

    case CMS_RECIPINFO_KEK:
        return cms_RecipientInfo_kekri_decrypt(cms, ri);

    case CMS_RECIPINFO_PASS:
        return cms_RecipientInfo_pwri_crypt(cms, ri, 0);

    default:
        CMSerr(CMS_F_CMS_RECIPIENTINFO_DECRYPT,
               CMS_R_UNSUPPORTED_RECPIENTINFO_TYPE);
        return 0;
    }
}

int CMS_RecipientInfo_encrypt(CMS_ContentInfo *cms, CMS_RecipientInfo *ri)
{
    switch (ri->type) {
    case CMS_RECIPINFO_TRANS:
        return cms_RecipientInfo_ktri_encrypt(cms, ri);

    case CMS_RECIPINFO_AGREE:
        return cms_RecipientInfo_kari_encrypt(cms, ri);

    case CMS_RECIPINFO_KEK:
        return cms_RecipientInfo_kekri_encrypt(cms, ri);
        break;

    case CMS_RECIPINFO_PASS:
        return cms_RecipientInfo_pwri_crypt(cms, ri, 1);
        break;

    default:
        CMSerr(CMS_F_CMS_RECIPIENTINFO_ENCRYPT,
               CMS_R_UNSUPPORTED_RECIPIENT_TYPE);
        return 0;
    }
}

/* Check structures and fixup version numbers (if necessary) */

static void cms_env_set_originfo_version(CMS_EnvelopedData *env)
{
    CMS_OriginatorInfo *org = env->originatorInfo;
    int i;
    if (org == NULL)
        return;
    for (i = 0; i < sk_CMS_CertificateChoices_num(org->certificates); i++) {
        CMS_CertificateChoices *cch;
        cch = sk_CMS_CertificateChoices_value(org->certificates, i);
        if (cch->type == CMS_CERTCHOICE_OTHER) {
            env->version = 4;
            return;
        } else if (cch->type == CMS_CERTCHOICE_V2ACERT) {
            if (env->version < 3)
                env->version = 3;
        }
    }

    for (i = 0; i < sk_CMS_RevocationInfoChoice_num(org->crls); i++) {
        CMS_RevocationInfoChoice *rch;
        rch = sk_CMS_RevocationInfoChoice_value(org->crls, i);
        if (rch->type == CMS_REVCHOICE_OTHER) {
            env->version = 4;
            return;
        }
    }
}

static void cms_env_set_version(CMS_EnvelopedData *env)
{
    int i;
    CMS_RecipientInfo *ri;

    /*
     * Can't set version higher than 4 so if 4 or more already nothing to do.
     */
    if (env->version >= 4)
        return;

    cms_env_set_originfo_version(env);

    if (env->version >= 3)
        return;

    for (i = 0; i < sk_CMS_RecipientInfo_num(env->recipientInfos); i++) {
        ri = sk_CMS_RecipientInfo_value(env->recipientInfos, i);
        if (ri->type == CMS_RECIPINFO_PASS || ri->type == CMS_RECIPINFO_OTHER) {
            env->version = 3;
            return;
        } else if (ri->type != CMS_RECIPINFO_TRANS
                   || ri->d.ktri->version != 0) {
            env->version = 2;
        }
    }
    if (env->version == 2)
        return;
    if (env->originatorInfo || env->unprotectedAttrs)
        env->version = 2;
    env->version = 0;
}

BIO *cms_EnvelopedData_init_bio(CMS_ContentInfo *cms)
{
    CMS_EncryptedContentInfo *ec;
    STACK_OF(CMS_RecipientInfo) *rinfos;
    CMS_RecipientInfo *ri;
    int i, ok = 0;
    BIO *ret;

    /* Get BIO first to set up key */

    ec = cms->d.envelopedData->encryptedContentInfo;
    ret = cms_EncryptedContent_init_bio(ec);

    /* If error or no cipher end of processing */

    if (!ret || !ec->cipher)
        return ret;

    /* Now encrypt content key according to each RecipientInfo type */

    rinfos = cms->d.envelopedData->recipientInfos;

    for (i = 0; i < sk_CMS_RecipientInfo_num(rinfos); i++) {
        ri = sk_CMS_RecipientInfo_value(rinfos, i);
        if (CMS_RecipientInfo_encrypt(cms, ri) <= 0) {
            CMSerr(CMS_F_CMS_ENVELOPEDDATA_INIT_BIO,
                   CMS_R_ERROR_SETTING_RECIPIENTINFO);
            goto err;
        }
    }
    cms_env_set_version(cms->d.envelopedData);

    ok = 1;

 err:
    ec->cipher = NULL;
    if (ec->key) {
        OPENSSL_cleanse(ec->key, ec->keylen);
        OPENSSL_free(ec->key);
        ec->key = NULL;
        ec->keylen = 0;
    }
    if (ok)
        return ret;
    BIO_free(ret);
    return NULL;

}

/*
 * Get RecipientInfo type (if any) supported by a key (public or private). To
 * retain compatibility with previous behaviour if the ctrl value isn't
 * supported we assume key transport.
 */
int cms_pkey_get_ri_type(EVP_PKEY *pk)
{
    if (pk->ameth && pk->ameth->pkey_ctrl) {
        int i, r;
        i = pk->ameth->pkey_ctrl(pk, ASN1_PKEY_CTRL_CMS_RI_TYPE, 0, &r);
        if (i > 0)
            return r;
    }
    return CMS_RECIPINFO_TRANS;
}
/* crypto/cms/cms_err.c */
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
// #include "err.h"
// #include "cms.h"

/* BEGIN ERROR CODES */
#ifndef OPENSSL_NO_ERR

# define ERR_FUNC(func) ERR_PACK(ERR_LIB_CMS,func,0)
# define ERR_REASON(reason) ERR_PACK(ERR_LIB_CMS,0,reason)

static ERR_STRING_DATA CMS_str_functs[] = {
    {ERR_FUNC(CMS_F_CHECK_CONTENT), "CHECK_CONTENT"},
    {ERR_FUNC(CMS_F_CMS_ADD0_CERT), "CMS_add0_cert"},
    {ERR_FUNC(CMS_F_CMS_ADD0_RECIPIENT_KEY), "CMS_add0_recipient_key"},
    {ERR_FUNC(CMS_F_CMS_ADD0_RECIPIENT_PASSWORD),
     "CMS_add0_recipient_password"},
    {ERR_FUNC(CMS_F_CMS_ADD1_RECEIPTREQUEST), "CMS_add1_ReceiptRequest"},
    {ERR_FUNC(CMS_F_CMS_ADD1_RECIPIENT_CERT), "CMS_add1_recipient_cert"},
    {ERR_FUNC(CMS_F_CMS_ADD1_SIGNER), "CMS_add1_signer"},
    {ERR_FUNC(CMS_F_CMS_ADD1_SIGNINGTIME), "CMS_ADD1_SIGNINGTIME"},
    {ERR_FUNC(CMS_F_CMS_COMPRESS), "CMS_compress"},
    {ERR_FUNC(CMS_F_CMS_COMPRESSEDDATA_CREATE), "cms_CompressedData_create"},
    {ERR_FUNC(CMS_F_CMS_COMPRESSEDDATA_INIT_BIO),
     "cms_CompressedData_init_bio"},
    {ERR_FUNC(CMS_F_CMS_COPY_CONTENT), "CMS_COPY_CONTENT"},
    {ERR_FUNC(CMS_F_CMS_COPY_MESSAGEDIGEST), "CMS_COPY_MESSAGEDIGEST"},
    {ERR_FUNC(CMS_F_CMS_DATA), "CMS_data"},
    {ERR_FUNC(CMS_F_CMS_DATAFINAL), "CMS_dataFinal"},
    {ERR_FUNC(CMS_F_CMS_DATAINIT), "CMS_dataInit"},
    {ERR_FUNC(CMS_F_CMS_DECRYPT), "CMS_decrypt"},
    {ERR_FUNC(CMS_F_CMS_DECRYPT_SET1_KEY), "CMS_decrypt_set1_key"},
    {ERR_FUNC(CMS_F_CMS_DECRYPT_SET1_PASSWORD), "CMS_decrypt_set1_password"},
    {ERR_FUNC(CMS_F_CMS_DECRYPT_SET1_PKEY), "CMS_decrypt_set1_pkey"},
    {ERR_FUNC(CMS_F_CMS_DIGESTALGORITHM_FIND_CTX),
     "cms_DigestAlgorithm_find_ctx"},
    {ERR_FUNC(CMS_F_CMS_DIGESTALGORITHM_INIT_BIO),
     "cms_DigestAlgorithm_init_bio"},
    {ERR_FUNC(CMS_F_CMS_DIGESTEDDATA_DO_FINAL), "cms_DigestedData_do_final"},
    {ERR_FUNC(CMS_F_CMS_DIGEST_VERIFY), "CMS_digest_verify"},
    {ERR_FUNC(CMS_F_CMS_ENCODE_RECEIPT), "cms_encode_Receipt"},
    {ERR_FUNC(CMS_F_CMS_ENCRYPT), "CMS_encrypt"},
    {ERR_FUNC(CMS_F_CMS_ENCRYPTEDCONTENT_INIT_BIO),
     "cms_EncryptedContent_init_bio"},
    {ERR_FUNC(CMS_F_CMS_ENCRYPTEDDATA_DECRYPT), "CMS_EncryptedData_decrypt"},
    {ERR_FUNC(CMS_F_CMS_ENCRYPTEDDATA_ENCRYPT), "CMS_EncryptedData_encrypt"},
    {ERR_FUNC(CMS_F_CMS_ENCRYPTEDDATA_SET1_KEY),
     "CMS_EncryptedData_set1_key"},
    {ERR_FUNC(CMS_F_CMS_ENVELOPEDDATA_CREATE), "CMS_EnvelopedData_create"},
    {ERR_FUNC(CMS_F_CMS_ENVELOPEDDATA_INIT_BIO),
     "cms_EnvelopedData_init_bio"},
    {ERR_FUNC(CMS_F_CMS_ENVELOPED_DATA_INIT), "CMS_ENVELOPED_DATA_INIT"},
    {ERR_FUNC(CMS_F_CMS_ENV_ASN1_CTRL), "cms_env_asn1_ctrl"},
    {ERR_FUNC(CMS_F_CMS_FINAL), "CMS_final"},
    {ERR_FUNC(CMS_F_CMS_GET0_CERTIFICATE_CHOICES),
     "CMS_GET0_CERTIFICATE_CHOICES"},
    {ERR_FUNC(CMS_F_CMS_GET0_CONTENT), "CMS_get0_content"},
    {ERR_FUNC(CMS_F_CMS_GET0_ECONTENT_TYPE), "CMS_GET0_ECONTENT_TYPE"},
    {ERR_FUNC(CMS_F_CMS_GET0_ENVELOPED), "cms_get0_enveloped"},
    {ERR_FUNC(CMS_F_CMS_GET0_REVOCATION_CHOICES),
     "CMS_GET0_REVOCATION_CHOICES"},
    {ERR_FUNC(CMS_F_CMS_GET0_SIGNED), "CMS_GET0_SIGNED"},
    {ERR_FUNC(CMS_F_CMS_MSGSIGDIGEST_ADD1), "cms_msgSigDigest_add1"},
    {ERR_FUNC(CMS_F_CMS_RECEIPTREQUEST_CREATE0),
     "CMS_ReceiptRequest_create0"},
    {ERR_FUNC(CMS_F_CMS_RECEIPT_VERIFY), "cms_Receipt_verify"},
    {ERR_FUNC(CMS_F_CMS_RECIPIENTINFO_DECRYPT), "CMS_RecipientInfo_decrypt"},
    {ERR_FUNC(CMS_F_CMS_RECIPIENTINFO_ENCRYPT), "CMS_RecipientInfo_encrypt"},
    {ERR_FUNC(CMS_F_CMS_RECIPIENTINFO_KARI_ENCRYPT),
     "cms_RecipientInfo_kari_encrypt"},
    {ERR_FUNC(CMS_F_CMS_RECIPIENTINFO_KARI_GET0_ALG),
     "CMS_RecipientInfo_kari_get0_alg"},
    {ERR_FUNC(CMS_F_CMS_RECIPIENTINFO_KARI_GET0_ORIG_ID),
     "CMS_RecipientInfo_kari_get0_orig_id"},
    {ERR_FUNC(CMS_F_CMS_RECIPIENTINFO_KARI_GET0_REKS),
     "CMS_RecipientInfo_kari_get0_reks"},
    {ERR_FUNC(CMS_F_CMS_RECIPIENTINFO_KARI_ORIG_ID_CMP),
     "CMS_RecipientInfo_kari_orig_id_cmp"},
    {ERR_FUNC(CMS_F_CMS_RECIPIENTINFO_KEKRI_DECRYPT),
     "CMS_RECIPIENTINFO_KEKRI_DECRYPT"},
    {ERR_FUNC(CMS_F_CMS_RECIPIENTINFO_KEKRI_ENCRYPT),
     "CMS_RECIPIENTINFO_KEKRI_ENCRYPT"},
    {ERR_FUNC(CMS_F_CMS_RECIPIENTINFO_KEKRI_GET0_ID),
     "CMS_RecipientInfo_kekri_get0_id"},
    {ERR_FUNC(CMS_F_CMS_RECIPIENTINFO_KEKRI_ID_CMP),
     "CMS_RecipientInfo_kekri_id_cmp"},
    {ERR_FUNC(CMS_F_CMS_RECIPIENTINFO_KTRI_CERT_CMP),
     "CMS_RecipientInfo_ktri_cert_cmp"},
    {ERR_FUNC(CMS_F_CMS_RECIPIENTINFO_KTRI_DECRYPT),
     "CMS_RECIPIENTINFO_KTRI_DECRYPT"},
    {ERR_FUNC(CMS_F_CMS_RECIPIENTINFO_KTRI_ENCRYPT),
     "CMS_RECIPIENTINFO_KTRI_ENCRYPT"},
    {ERR_FUNC(CMS_F_CMS_RECIPIENTINFO_KTRI_GET0_ALGS),
     "CMS_RecipientInfo_ktri_get0_algs"},
    {ERR_FUNC(CMS_F_CMS_RECIPIENTINFO_KTRI_GET0_SIGNER_ID),
     "CMS_RecipientInfo_ktri_get0_signer_id"},
    {ERR_FUNC(CMS_F_CMS_RECIPIENTINFO_PWRI_CRYPT),
     "cms_RecipientInfo_pwri_crypt"},
    {ERR_FUNC(CMS_F_CMS_RECIPIENTINFO_SET0_KEY),
     "CMS_RecipientInfo_set0_key"},
    {ERR_FUNC(CMS_F_CMS_RECIPIENTINFO_SET0_PASSWORD),
     "CMS_RecipientInfo_set0_password"},
    {ERR_FUNC(CMS_F_CMS_RECIPIENTINFO_SET0_PKEY),
     "CMS_RecipientInfo_set0_pkey"},
    {ERR_FUNC(CMS_F_CMS_SD_ASN1_CTRL), "CMS_SD_ASN1_CTRL"},
    {ERR_FUNC(CMS_F_CMS_SET1_IAS), "cms_set1_ias"},
    {ERR_FUNC(CMS_F_CMS_SET1_KEYID), "cms_set1_keyid"},
    {ERR_FUNC(CMS_F_CMS_SET1_SIGNERIDENTIFIER), "cms_set1_SignerIdentifier"},
    {ERR_FUNC(CMS_F_CMS_SET_DETACHED), "CMS_set_detached"},
    {ERR_FUNC(CMS_F_CMS_SIGN), "CMS_sign"},
    {ERR_FUNC(CMS_F_CMS_SIGNED_DATA_INIT), "CMS_SIGNED_DATA_INIT"},
    {ERR_FUNC(CMS_F_CMS_SIGNERINFO_CONTENT_SIGN),
     "CMS_SIGNERINFO_CONTENT_SIGN"},
    {ERR_FUNC(CMS_F_CMS_SIGNERINFO_SIGN), "CMS_SignerInfo_sign"},
    {ERR_FUNC(CMS_F_CMS_SIGNERINFO_VERIFY), "CMS_SignerInfo_verify"},
    {ERR_FUNC(CMS_F_CMS_SIGNERINFO_VERIFY_CERT),
     "CMS_SIGNERINFO_VERIFY_CERT"},
    {ERR_FUNC(CMS_F_CMS_SIGNERINFO_VERIFY_CONTENT),
     "CMS_SignerInfo_verify_content"},
    {ERR_FUNC(CMS_F_CMS_SIGN_RECEIPT), "CMS_sign_receipt"},
    {ERR_FUNC(CMS_F_CMS_STREAM), "CMS_stream"},
    {ERR_FUNC(CMS_F_CMS_UNCOMPRESS), "CMS_uncompress"},
    {ERR_FUNC(CMS_F_CMS_VERIFY), "CMS_verify"},
    {0, NULL}
};

static ERR_STRING_DATA CMS_str_reasons[] = {
    {ERR_REASON(CMS_R_ADD_SIGNER_ERROR), "add signer error"},
    {ERR_REASON(CMS_R_CERTIFICATE_ALREADY_PRESENT),
     "certificate already present"},
    {ERR_REASON(CMS_R_CERTIFICATE_HAS_NO_KEYID), "certificate has no keyid"},
    {ERR_REASON(CMS_R_CERTIFICATE_VERIFY_ERROR), "certificate verify error"},
    {ERR_REASON(CMS_R_CIPHER_INITIALISATION_ERROR),
     "cipher initialisation error"},
    {ERR_REASON(CMS_R_CIPHER_PARAMETER_INITIALISATION_ERROR),
     "cipher parameter initialisation error"},
    {ERR_REASON(CMS_R_CMS_DATAFINAL_ERROR), "cms datafinal error"},
    {ERR_REASON(CMS_R_CMS_LIB), "cms lib"},
    {ERR_REASON(CMS_R_CONTENTIDENTIFIER_MISMATCH),
     "contentidentifier mismatch"},
    {ERR_REASON(CMS_R_CONTENT_NOT_FOUND), "content not found"},
    {ERR_REASON(CMS_R_CONTENT_TYPE_MISMATCH), "content type mismatch"},
    {ERR_REASON(CMS_R_CONTENT_TYPE_NOT_COMPRESSED_DATA),
     "content type not compressed data"},
    {ERR_REASON(CMS_R_CONTENT_TYPE_NOT_ENVELOPED_DATA),
     "content type not enveloped data"},
    {ERR_REASON(CMS_R_CONTENT_TYPE_NOT_SIGNED_DATA),
     "content type not signed data"},
    {ERR_REASON(CMS_R_CONTENT_VERIFY_ERROR), "content verify error"},
    {ERR_REASON(CMS_R_CTRL_ERROR), "ctrl error"},
    {ERR_REASON(CMS_R_CTRL_FAILURE), "ctrl failure"},
    {ERR_REASON(CMS_R_DECRYPT_ERROR), "decrypt error"},
    {ERR_REASON(CMS_R_DIGEST_ERROR), "digest error"},
    {ERR_REASON(CMS_R_ERROR_GETTING_PUBLIC_KEY), "error getting public key"},
    {ERR_REASON(CMS_R_ERROR_READING_MESSAGEDIGEST_ATTRIBUTE),
     "error reading messagedigest attribute"},
    {ERR_REASON(CMS_R_ERROR_SETTING_KEY), "error setting key"},
    {ERR_REASON(CMS_R_ERROR_SETTING_RECIPIENTINFO),
     "error setting recipientinfo"},
    {ERR_REASON(CMS_R_INVALID_ENCRYPTED_KEY_LENGTH),
     "invalid encrypted key length"},
    {ERR_REASON(CMS_R_INVALID_KEY_ENCRYPTION_PARAMETER),
     "invalid key encryption parameter"},
    {ERR_REASON(CMS_R_INVALID_KEY_LENGTH), "invalid key length"},
    {ERR_REASON(CMS_R_MD_BIO_INIT_ERROR), "md bio init error"},
    {ERR_REASON(CMS_R_MESSAGEDIGEST_ATTRIBUTE_WRONG_LENGTH),
     "messagedigest attribute wrong length"},
    {ERR_REASON(CMS_R_MESSAGEDIGEST_WRONG_LENGTH),
     "messagedigest wrong length"},
    {ERR_REASON(CMS_R_MSGSIGDIGEST_ERROR), "msgsigdigest error"},
    {ERR_REASON(CMS_R_MSGSIGDIGEST_VERIFICATION_FAILURE),
     "msgsigdigest verification failure"},
    {ERR_REASON(CMS_R_MSGSIGDIGEST_WRONG_LENGTH),
     "msgsigdigest wrong length"},
    {ERR_REASON(CMS_R_NEED_ONE_SIGNER), "need one signer"},
    {ERR_REASON(CMS_R_NOT_A_SIGNED_RECEIPT), "not a signed receipt"},
    {ERR_REASON(CMS_R_NOT_ENCRYPTED_DATA), "not encrypted data"},
    {ERR_REASON(CMS_R_NOT_KEK), "not kek"},
    {ERR_REASON(CMS_R_NOT_KEY_AGREEMENT), "not key agreement"},
    {ERR_REASON(CMS_R_NOT_KEY_TRANSPORT), "not key transport"},
    {ERR_REASON(CMS_R_NOT_PWRI), "not pwri"},
    {ERR_REASON(CMS_R_NOT_SUPPORTED_FOR_THIS_KEY_TYPE),
     "not supported for this key type"},
    {ERR_REASON(CMS_R_NO_CIPHER), "no cipher"},
    {ERR_REASON(CMS_R_NO_CONTENT), "no content"},
    {ERR_REASON(CMS_R_NO_CONTENT_TYPE), "no content type"},
    {ERR_REASON(CMS_R_NO_DEFAULT_DIGEST), "no default digest"},
    {ERR_REASON(CMS_R_NO_DIGEST_SET), "no digest set"},
    {ERR_REASON(CMS_R_NO_KEY), "no key"},
    {ERR_REASON(CMS_R_NO_KEY_OR_CERT), "no key or cert"},
    {ERR_REASON(CMS_R_NO_MATCHING_DIGEST), "no matching digest"},
    {ERR_REASON(CMS_R_NO_MATCHING_RECIPIENT), "no matching recipient"},
    {ERR_REASON(CMS_R_NO_MATCHING_SIGNATURE), "no matching signature"},
    {ERR_REASON(CMS_R_NO_MSGSIGDIGEST), "no msgsigdigest"},
    {ERR_REASON(CMS_R_NO_PASSWORD), "no password"},
    {ERR_REASON(CMS_R_NO_PRIVATE_KEY), "no private key"},
    {ERR_REASON(CMS_R_NO_PUBLIC_KEY), "no public key"},
    {ERR_REASON(CMS_R_NO_RECEIPT_REQUEST), "no receipt request"},
    {ERR_REASON(CMS_R_NO_SIGNERS), "no signers"},
    {ERR_REASON(CMS_R_PRIVATE_KEY_DOES_NOT_MATCH_CERTIFICATE),
     "private key does not match certificate"},
    {ERR_REASON(CMS_R_RECEIPT_DECODE_ERROR), "receipt decode error"},
    {ERR_REASON(CMS_R_RECIPIENT_ERROR), "recipient error"},
    {ERR_REASON(CMS_R_SIGNER_CERTIFICATE_NOT_FOUND),
     "signer certificate not found"},
    {ERR_REASON(CMS_R_SIGNFINAL_ERROR), "signfinal error"},
    {ERR_REASON(CMS_R_SMIME_TEXT_ERROR), "smime text error"},
    {ERR_REASON(CMS_R_STORE_INIT_ERROR), "store init error"},
    {ERR_REASON(CMS_R_TYPE_NOT_COMPRESSED_DATA), "type not compressed data"},
    {ERR_REASON(CMS_R_TYPE_NOT_DATA), "type not data"},
    {ERR_REASON(CMS_R_TYPE_NOT_DIGESTED_DATA), "type not digested data"},
    {ERR_REASON(CMS_R_TYPE_NOT_ENCRYPTED_DATA), "type not encrypted data"},
    {ERR_REASON(CMS_R_TYPE_NOT_ENVELOPED_DATA), "type not enveloped data"},
    {ERR_REASON(CMS_R_UNABLE_TO_FINALIZE_CONTEXT),
     "unable to finalize context"},
    {ERR_REASON(CMS_R_UNKNOWN_CIPHER), "unknown cipher"},
    {ERR_REASON(CMS_R_UNKNOWN_DIGEST_ALGORIHM), "unknown digest algorihm"},
    {ERR_REASON(CMS_R_UNKNOWN_ID), "unknown id"},
    {ERR_REASON(CMS_R_UNSUPPORTED_COMPRESSION_ALGORITHM),
     "unsupported compression algorithm"},
    {ERR_REASON(CMS_R_UNSUPPORTED_CONTENT_TYPE), "unsupported content type"},
    {ERR_REASON(CMS_R_UNSUPPORTED_KEK_ALGORITHM),
     "unsupported kek algorithm"},
    {ERR_REASON(CMS_R_UNSUPPORTED_KEY_ENCRYPTION_ALGORITHM),
     "unsupported key encryption algorithm"},
    {ERR_REASON(CMS_R_UNSUPPORTED_RECIPIENT_TYPE),
     "unsupported recipient type"},
    {ERR_REASON(CMS_R_UNSUPPORTED_RECPIENTINFO_TYPE),
     "unsupported recpientinfo type"},
    {ERR_REASON(CMS_R_UNSUPPORTED_TYPE), "unsupported type"},
    {ERR_REASON(CMS_R_UNWRAP_ERROR), "unwrap error"},
    {ERR_REASON(CMS_R_UNWRAP_FAILURE), "unwrap failure"},
    {ERR_REASON(CMS_R_VERIFICATION_FAILURE), "verification failure"},
    {ERR_REASON(CMS_R_WRAP_ERROR), "wrap error"},
    {0, NULL}
};

#endif

void ERR_load_CMS_strings(void)
{
#ifndef OPENSSL_NO_ERR

    if (ERR_func_error_string(CMS_str_functs[0].error) == NULL) {
        ERR_load_strings(0, CMS_str_functs);
        ERR_load_strings(0, CMS_str_reasons);
    }
#endif
}
/* crypto/cms/cms_ess.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project.
 */
/* ====================================================================
 * Copyright (c) 2008 The OpenSSL Project.  All rights reserved.
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
 */

// #include "cryptlib.h"
// #include "asn1t.h"
// #include "pem.h"
// #include "rand.h"
// #include "x509v3.h"
// #include "err.h"
// #include "cms.h"
// #include "cms_lcl.h"

DECLARE_ASN1_ITEM(CMS_ReceiptRequest)
DECLARE_ASN1_ITEM(CMS_Receipt)

IMPLEMENT_ASN1_FUNCTIONS(CMS_ReceiptRequest)

/* ESS services: for now just Signed Receipt related */

int CMS_get1_ReceiptRequest(CMS_SignerInfo *si, CMS_ReceiptRequest **prr)
{
    ASN1_STRING *str;
    CMS_ReceiptRequest *rr = NULL;
    if (prr)
        *prr = NULL;
    str = CMS_signed_get0_data_by_OBJ(si,
                                      OBJ_nid2obj
                                      (NID_id_smime_aa_receiptRequest), -3,
                                      V_ASN1_SEQUENCE);
    if (!str)
        return 0;

    rr = ASN1_item_unpack(str, ASN1_ITEM_rptr(CMS_ReceiptRequest));
    if (!rr)
        return -1;
    if (prr)
        *prr = rr;
    else
        CMS_ReceiptRequest_free(rr);
    return 1;
}

CMS_ReceiptRequest *CMS_ReceiptRequest_create0(unsigned char *id, int idlen,
                                               int allorfirst,
                                               STACK_OF(GENERAL_NAMES)
                                               *receiptList, STACK_OF(GENERAL_NAMES)
                                               *receiptsTo)
{
    CMS_ReceiptRequest *rr = NULL;

    rr = CMS_ReceiptRequest_new();
    if (!rr)
        goto merr;
    if (id)
        ASN1_STRING_set0(rr->signedContentIdentifier, id, idlen);
    else {
        if (!ASN1_STRING_set(rr->signedContentIdentifier, NULL, 32))
            goto merr;
        if (RAND_bytes(rr->signedContentIdentifier->data, 32) <= 0)
            goto err;
    }

    sk_GENERAL_NAMES_pop_free(rr->receiptsTo, GENERAL_NAMES_free);
    rr->receiptsTo = receiptsTo;

    if (receiptList) {
        rr->receiptsFrom->type = 1;
        rr->receiptsFrom->d.receiptList = receiptList;
    } else {
        rr->receiptsFrom->type = 0;
        rr->receiptsFrom->d.allOrFirstTier = allorfirst;
    }

    return rr;

 merr:
    CMSerr(CMS_F_CMS_RECEIPTREQUEST_CREATE0, ERR_R_MALLOC_FAILURE);

 err:
    if (rr)
        CMS_ReceiptRequest_free(rr);

    return NULL;

}

int CMS_add1_ReceiptRequest(CMS_SignerInfo *si, CMS_ReceiptRequest *rr)
{
    unsigned char *rrder = NULL;
    int rrderlen, r = 0;

    rrderlen = i2d_CMS_ReceiptRequest(rr, &rrder);
    if (rrderlen < 0)
        goto merr;

    if (!CMS_signed_add1_attr_by_NID(si, NID_id_smime_aa_receiptRequest,
                                     V_ASN1_SEQUENCE, rrder, rrderlen))
        goto merr;

    r = 1;

 merr:
    if (!r)
        CMSerr(CMS_F_CMS_ADD1_RECEIPTREQUEST, ERR_R_MALLOC_FAILURE);

    if (rrder)
        OPENSSL_free(rrder);

    return r;

}

void CMS_ReceiptRequest_get0_values(CMS_ReceiptRequest *rr,
                                    ASN1_STRING **pcid,
                                    int *pallorfirst,
                                    STACK_OF(GENERAL_NAMES) **plist,
                                    STACK_OF(GENERAL_NAMES) **prto)
{
    if (pcid)
        *pcid = rr->signedContentIdentifier;
    if (rr->receiptsFrom->type == 0) {
        if (pallorfirst)
            *pallorfirst = (int)rr->receiptsFrom->d.allOrFirstTier;
        if (plist)
            *plist = NULL;
    } else {
        if (pallorfirst)
            *pallorfirst = -1;
        if (plist)
            *plist = rr->receiptsFrom->d.receiptList;
    }
    if (prto)
        *prto = rr->receiptsTo;
}

/* Digest a SignerInfo structure for msgSigDigest attribute processing */

static int cms_msgSigDigest(CMS_SignerInfo *si,
                            unsigned char *dig, unsigned int *diglen)
{
    const EVP_MD *md;
    md = EVP_get_digestbyobj(si->digestAlgorithm->algorithm);
    if (md == NULL)
        return 0;
    if (!ASN1_item_digest(ASN1_ITEM_rptr(CMS_Attributes_Verify), md,
                          si->signedAttrs, dig, diglen))
        return 0;
    return 1;
}

/* Add a msgSigDigest attribute to a SignerInfo */

int cms_msgSigDigest_add1(CMS_SignerInfo *dest, CMS_SignerInfo *src)
{
    unsigned char dig[EVP_MAX_MD_SIZE];
    unsigned int diglen;
    if (!cms_msgSigDigest(src, dig, &diglen)) {
        CMSerr(CMS_F_CMS_MSGSIGDIGEST_ADD1, CMS_R_MSGSIGDIGEST_ERROR);
        return 0;
    }
    if (!CMS_signed_add1_attr_by_NID(dest, NID_id_smime_aa_msgSigDigest,
                                     V_ASN1_OCTET_STRING, dig, diglen)) {
        CMSerr(CMS_F_CMS_MSGSIGDIGEST_ADD1, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    return 1;
}

/* Verify signed receipt after it has already passed normal CMS verify */

int cms_Receipt_verify(CMS_ContentInfo *cms, CMS_ContentInfo *req_cms)
{
    int r = 0, i;
    CMS_ReceiptRequest *rr = NULL;
    CMS_Receipt *rct = NULL;
    STACK_OF(CMS_SignerInfo) *sis, *osis;
    CMS_SignerInfo *si, *osi = NULL;
    ASN1_OCTET_STRING *msig, **pcont;
    ASN1_OBJECT *octype;
    unsigned char dig[EVP_MAX_MD_SIZE];
    unsigned int diglen;

    /* Get SignerInfos, also checks SignedData content type */
    osis = CMS_get0_SignerInfos(req_cms);
    sis = CMS_get0_SignerInfos(cms);
    if (!osis || !sis)
        goto err;

    if (sk_CMS_SignerInfo_num(sis) != 1) {
        CMSerr(CMS_F_CMS_RECEIPT_VERIFY, CMS_R_NEED_ONE_SIGNER);
        goto err;
    }

    /* Check receipt content type */
    if (OBJ_obj2nid(CMS_get0_eContentType(cms)) != NID_id_smime_ct_receipt) {
        CMSerr(CMS_F_CMS_RECEIPT_VERIFY, CMS_R_NOT_A_SIGNED_RECEIPT);
        goto err;
    }

    /* Extract and decode receipt content */
    pcont = CMS_get0_content(cms);
    if (!pcont || !*pcont) {
        CMSerr(CMS_F_CMS_RECEIPT_VERIFY, CMS_R_NO_CONTENT);
        goto err;
    }

    rct = ASN1_item_unpack(*pcont, ASN1_ITEM_rptr(CMS_Receipt));

    if (!rct) {
        CMSerr(CMS_F_CMS_RECEIPT_VERIFY, CMS_R_RECEIPT_DECODE_ERROR);
        goto err;
    }

    /* Locate original request */

    for (i = 0; i < sk_CMS_SignerInfo_num(osis); i++) {
        osi = sk_CMS_SignerInfo_value(osis, i);
        if (!ASN1_STRING_cmp(osi->signature, rct->originatorSignatureValue))
            break;
    }

    if (i == sk_CMS_SignerInfo_num(osis)) {
        CMSerr(CMS_F_CMS_RECEIPT_VERIFY, CMS_R_NO_MATCHING_SIGNATURE);
        goto err;
    }

    si = sk_CMS_SignerInfo_value(sis, 0);

    /* Get msgSigDigest value and compare */

    msig = CMS_signed_get0_data_by_OBJ(si,
                                       OBJ_nid2obj
                                       (NID_id_smime_aa_msgSigDigest), -3,
                                       V_ASN1_OCTET_STRING);

    if (!msig) {
        CMSerr(CMS_F_CMS_RECEIPT_VERIFY, CMS_R_NO_MSGSIGDIGEST);
        goto err;
    }

    if (!cms_msgSigDigest(osi, dig, &diglen)) {
        CMSerr(CMS_F_CMS_RECEIPT_VERIFY, CMS_R_MSGSIGDIGEST_ERROR);
        goto err;
    }

    if (diglen != (unsigned int)msig->length) {
        CMSerr(CMS_F_CMS_RECEIPT_VERIFY, CMS_R_MSGSIGDIGEST_WRONG_LENGTH);
        goto err;
    }

    if (memcmp(dig, msig->data, diglen)) {
        CMSerr(CMS_F_CMS_RECEIPT_VERIFY,
               CMS_R_MSGSIGDIGEST_VERIFICATION_FAILURE);
        goto err;
    }

    /* Compare content types */

    octype = CMS_signed_get0_data_by_OBJ(osi,
                                         OBJ_nid2obj(NID_pkcs9_contentType),
                                         -3, V_ASN1_OBJECT);
    if (!octype) {
        CMSerr(CMS_F_CMS_RECEIPT_VERIFY, CMS_R_NO_CONTENT_TYPE);
        goto err;
    }

    /* Compare details in receipt request */

    if (OBJ_cmp(octype, rct->contentType)) {
        CMSerr(CMS_F_CMS_RECEIPT_VERIFY, CMS_R_CONTENT_TYPE_MISMATCH);
        goto err;
    }

    /* Get original receipt request details */

    if (CMS_get1_ReceiptRequest(osi, &rr) <= 0) {
        CMSerr(CMS_F_CMS_RECEIPT_VERIFY, CMS_R_NO_RECEIPT_REQUEST);
        goto err;
    }

    if (ASN1_STRING_cmp(rr->signedContentIdentifier,
                        rct->signedContentIdentifier)) {
        CMSerr(CMS_F_CMS_RECEIPT_VERIFY, CMS_R_CONTENTIDENTIFIER_MISMATCH);
        goto err;
    }

    r = 1;

 err:
    if (rr)
        CMS_ReceiptRequest_free(rr);
    if (rct)
        M_ASN1_free_of(rct, CMS_Receipt);

    return r;

}

/*
 * Encode a Receipt into an OCTET STRING read for including into content of a
 * SignedData ContentInfo.
 */

ASN1_OCTET_STRING *cms_encode_Receipt(CMS_SignerInfo *si)
{
    CMS_Receipt rct;
    CMS_ReceiptRequest *rr = NULL;
    ASN1_OBJECT *ctype;
    ASN1_OCTET_STRING *os = NULL;

    /* Get original receipt request */

    /* Get original receipt request details */

    if (CMS_get1_ReceiptRequest(si, &rr) <= 0) {
        CMSerr(CMS_F_CMS_ENCODE_RECEIPT, CMS_R_NO_RECEIPT_REQUEST);
        goto err;
    }

    /* Get original content type */

    ctype = CMS_signed_get0_data_by_OBJ(si,
                                        OBJ_nid2obj(NID_pkcs9_contentType),
                                        -3, V_ASN1_OBJECT);
    if (!ctype) {
        CMSerr(CMS_F_CMS_ENCODE_RECEIPT, CMS_R_NO_CONTENT_TYPE);
        goto err;
    }

    rct.version = 1;
    rct.contentType = ctype;
    rct.signedContentIdentifier = rr->signedContentIdentifier;
    rct.originatorSignatureValue = si->signature;

    os = ASN1_item_pack(&rct, ASN1_ITEM_rptr(CMS_Receipt), NULL);

 err:
    if (rr)
        CMS_ReceiptRequest_free(rr);

    return os;

}
/* crypto/cms/cms_io.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project.
 */
/* ====================================================================
 * Copyright (c) 2008 The OpenSSL Project.  All rights reserved.
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
 */

// #include "asn1t.h"
#include "x509.h"
// #include "err.h"
// #include "pem.h"
// #include "cms.h"
// #include "cms_lcl.h"

int CMS_stream(unsigned char ***boundary, CMS_ContentInfo *cms)
{
    ASN1_OCTET_STRING **pos;
    pos = CMS_get0_content(cms);
    if (!pos)
        return 0;
    if (!*pos)
        *pos = ASN1_OCTET_STRING_new();
    if (*pos) {
        (*pos)->flags |= ASN1_STRING_FLAG_NDEF;
        (*pos)->flags &= ~ASN1_STRING_FLAG_CONT;
        *boundary = &(*pos)->data;
        return 1;
    }
    CMSerr(CMS_F_CMS_STREAM, ERR_R_MALLOC_FAILURE);
    return 0;
}

CMS_ContentInfo *d2i_CMS_bio(BIO *bp, CMS_ContentInfo **cms)
{
    return ASN1_item_d2i_bio(ASN1_ITEM_rptr(CMS_ContentInfo), bp, cms);
}

int i2d_CMS_bio(BIO *bp, CMS_ContentInfo *cms)
{
    return ASN1_item_i2d_bio(ASN1_ITEM_rptr(CMS_ContentInfo), bp, cms);
}

IMPLEMENT_PEM_rw_const(CMS, CMS_ContentInfo, PEM_STRING_CMS, CMS_ContentInfo)

BIO *BIO_new_CMS(BIO *out, CMS_ContentInfo *cms)
{
    return BIO_new_NDEF(out, (ASN1_VALUE *)cms,
                        ASN1_ITEM_rptr(CMS_ContentInfo));
}

/* CMS wrappers round generalised stream and MIME routines */

int i2d_CMS_bio_stream(BIO *out, CMS_ContentInfo *cms, BIO *in, int flags)
{
    return i2d_ASN1_bio_stream(out, (ASN1_VALUE *)cms, in, flags,
                               ASN1_ITEM_rptr(CMS_ContentInfo));
}

int PEM_write_bio_CMS_stream(BIO *out, CMS_ContentInfo *cms, BIO *in,
                             int flags)
{
    return PEM_write_bio_ASN1_stream(out, (ASN1_VALUE *)cms, in, flags,
                                     "CMS", ASN1_ITEM_rptr(CMS_ContentInfo));
}

int SMIME_write_CMS(BIO *bio, CMS_ContentInfo *cms, BIO *data, int flags)
{
    STACK_OF(X509_ALGOR) *mdalgs;
    int ctype_nid = OBJ_obj2nid(cms->contentType);
    int econt_nid = OBJ_obj2nid(CMS_get0_eContentType(cms));
    if (ctype_nid == NID_pkcs7_signed)
        mdalgs = cms->d.signedData->digestAlgorithms;
    else
        mdalgs = NULL;

    return SMIME_write_ASN1(bio, (ASN1_VALUE *)cms, data, flags,
                            ctype_nid, econt_nid, mdalgs,
                            ASN1_ITEM_rptr(CMS_ContentInfo));
}

CMS_ContentInfo *SMIME_read_CMS(BIO *bio, BIO **bcont)
{
    return (CMS_ContentInfo *)SMIME_read_ASN1(bio, bcont,
                                              ASN1_ITEM_rptr
                                              (CMS_ContentInfo));
}
/* crypto/cms/cms_kari.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project.
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
 */

// #include "cryptlib.h"
// #include "asn1t.h"
// #include "pem.h"
// #include "x509v3.h"
// #include "err.h"
// #include "cms.h"
// #include "rand.h"
// #include "aes.h"
// #include "cms_lcl.h"
// #include "asn1_locl.h"

DECLARE_ASN1_ITEM(CMS_KeyAgreeRecipientInfo)
DECLARE_ASN1_ITEM(CMS_RecipientEncryptedKey)
DECLARE_ASN1_ITEM(CMS_OriginatorPublicKey)
DECLARE_ASN1_ITEM(CMS_RecipientKeyIdentifier)

/* Key Agreement Recipient Info (KARI) routines */

int CMS_RecipientInfo_kari_get0_alg(CMS_RecipientInfo *ri,
                                    X509_ALGOR **palg,
                                    ASN1_OCTET_STRING **pukm)
{
    if (ri->type != CMS_RECIPINFO_AGREE) {
        CMSerr(CMS_F_CMS_RECIPIENTINFO_KARI_GET0_ALG,
               CMS_R_NOT_KEY_AGREEMENT);
        return 0;
    }
    if (palg)
        *palg = ri->d.kari->keyEncryptionAlgorithm;
    if (pukm)
        *pukm = ri->d.kari->ukm;
    return 1;
}

/* Retrieve recipient encrypted keys from a kari */

STACK_OF(CMS_RecipientEncryptedKey)
*CMS_RecipientInfo_kari_get0_reks(CMS_RecipientInfo *ri)
{
    if (ri->type != CMS_RECIPINFO_AGREE) {
        CMSerr(CMS_F_CMS_RECIPIENTINFO_KARI_GET0_REKS,
               CMS_R_NOT_KEY_AGREEMENT);
        return NULL;
    }
    return ri->d.kari->recipientEncryptedKeys;
}

int CMS_RecipientInfo_kari_get0_orig_id(CMS_RecipientInfo *ri,
                                        X509_ALGOR **pubalg,
                                        ASN1_BIT_STRING **pubkey,
                                        ASN1_OCTET_STRING **keyid,
                                        X509_NAME **issuer,
                                        ASN1_INTEGER **sno)
{
    CMS_OriginatorIdentifierOrKey *oik;
    if (ri->type != CMS_RECIPINFO_AGREE) {
        CMSerr(CMS_F_CMS_RECIPIENTINFO_KARI_GET0_ORIG_ID,
               CMS_R_NOT_KEY_AGREEMENT);
        return 0;
    }
    oik = ri->d.kari->originator;
    if (issuer)
        *issuer = NULL;
    if (sno)
        *sno = NULL;
    if (keyid)
        *keyid = NULL;
    if (pubalg)
        *pubalg = NULL;
    if (pubkey)
        *pubkey = NULL;
    if (oik->type == CMS_OIK_ISSUER_SERIAL) {
        if (issuer)
            *issuer = oik->d.issuerAndSerialNumber->issuer;
        if (sno)
            *sno = oik->d.issuerAndSerialNumber->serialNumber;
    } else if (oik->type == CMS_OIK_KEYIDENTIFIER) {
        if (keyid)
            *keyid = oik->d.subjectKeyIdentifier;
    } else if (oik->type == CMS_OIK_PUBKEY) {
        if (pubalg)
            *pubalg = oik->d.originatorKey->algorithm;
        if (pubkey)
            *pubkey = oik->d.originatorKey->publicKey;
    } else
        return 0;
    return 1;
}

int CMS_RecipientInfo_kari_orig_id_cmp(CMS_RecipientInfo *ri, X509 *cert)
{
    CMS_OriginatorIdentifierOrKey *oik;
    if (ri->type != CMS_RECIPINFO_AGREE) {
        CMSerr(CMS_F_CMS_RECIPIENTINFO_KARI_ORIG_ID_CMP,
               CMS_R_NOT_KEY_AGREEMENT);
        return -2;
    }
    oik = ri->d.kari->originator;
    if (oik->type == CMS_OIK_ISSUER_SERIAL)
        return cms_ias_cert_cmp(oik->d.issuerAndSerialNumber, cert);
    else if (oik->type == CMS_OIK_KEYIDENTIFIER)
        return cms_keyid_cert_cmp(oik->d.subjectKeyIdentifier, cert);
    return -1;
}

int CMS_RecipientEncryptedKey_get0_id(CMS_RecipientEncryptedKey *rek,
                                      ASN1_OCTET_STRING **keyid,
                                      ASN1_GENERALIZEDTIME **tm,
                                      CMS_OtherKeyAttribute **other,
                                      X509_NAME **issuer, ASN1_INTEGER **sno)
{
    CMS_KeyAgreeRecipientIdentifier *rid = rek->rid;
    if (rid->type == CMS_REK_ISSUER_SERIAL) {
        if (issuer)
            *issuer = rid->d.issuerAndSerialNumber->issuer;
        if (sno)
            *sno = rid->d.issuerAndSerialNumber->serialNumber;
        if (keyid)
            *keyid = NULL;
        if (tm)
            *tm = NULL;
        if (other)
            *other = NULL;
    } else if (rid->type == CMS_REK_KEYIDENTIFIER) {
        if (keyid)
            *keyid = rid->d.rKeyId->subjectKeyIdentifier;
        if (tm)
            *tm = rid->d.rKeyId->date;
        if (other)
            *other = rid->d.rKeyId->other;
        if (issuer)
            *issuer = NULL;
        if (sno)
            *sno = NULL;
    } else
        return 0;
    return 1;
}

int CMS_RecipientEncryptedKey_cert_cmp(CMS_RecipientEncryptedKey *rek,
                                       X509 *cert)
{
    CMS_KeyAgreeRecipientIdentifier *rid = rek->rid;
    if (rid->type == CMS_REK_ISSUER_SERIAL)
        return cms_ias_cert_cmp(rid->d.issuerAndSerialNumber, cert);
    else if (rid->type == CMS_REK_KEYIDENTIFIER)
        return cms_keyid_cert_cmp(rid->d.rKeyId->subjectKeyIdentifier, cert);
    else
        return -1;
}

int CMS_RecipientInfo_kari_set0_pkey(CMS_RecipientInfo *ri, EVP_PKEY *pk)
{
    EVP_PKEY_CTX *pctx;
    CMS_KeyAgreeRecipientInfo *kari = ri->d.kari;
    if (kari->pctx) {
        EVP_PKEY_CTX_free(kari->pctx);
        kari->pctx = NULL;
    }
    if (!pk)
        return 1;
    pctx = EVP_PKEY_CTX_new(pk, NULL);
    if (!pctx || !EVP_PKEY_derive_init(pctx))
        goto err;
    kari->pctx = pctx;
    return 1;
 err:
    if (pctx)
        EVP_PKEY_CTX_free(pctx);
    return 0;
}

EVP_CIPHER_CTX *CMS_RecipientInfo_kari_get0_ctx(CMS_RecipientInfo *ri)
{
    if (ri->type == CMS_RECIPINFO_AGREE)
        return &ri->d.kari->ctx;
    return NULL;
}

/*
 * Derive KEK and decrypt/encrypt with it to produce either the original CEK
 * or the encrypted CEK.
 */

static int cms_kek_cipher(unsigned char **pout, size_t *poutlen,
                          const unsigned char *in, size_t inlen,
                          CMS_KeyAgreeRecipientInfo *kari, int enc)
{
    /* Key encryption key */
    unsigned char kek[EVP_MAX_KEY_LENGTH];
    size_t keklen;
    int rv = 0;
    unsigned char *out = NULL;
    int outlen;
    keklen = EVP_CIPHER_CTX_key_length(&kari->ctx);
    if (keklen > EVP_MAX_KEY_LENGTH)
        return 0;
    /* Derive KEK */
    if (EVP_PKEY_derive(kari->pctx, kek, &keklen) <= 0)
        goto err;
    /* Set KEK in context */
    if (!EVP_CipherInit_ex(&kari->ctx, NULL, NULL, kek, NULL, enc))
        goto err;
    /* obtain output length of ciphered key */
    if (!EVP_CipherUpdate(&kari->ctx, NULL, &outlen, in, inlen))
        goto err;
    out = OPENSSL_malloc(outlen);
    if (!out)
        goto err;
    if (!EVP_CipherUpdate(&kari->ctx, out, &outlen, in, inlen))
        goto err;
    *pout = out;
    *poutlen = (size_t)outlen;
    rv = 1;

 err:
    OPENSSL_cleanse(kek, keklen);
    if (!rv && out)
        OPENSSL_free(out);
    EVP_CIPHER_CTX_cleanup(&kari->ctx);
    EVP_PKEY_CTX_free(kari->pctx);
    kari->pctx = NULL;
    return rv;
}

int CMS_RecipientInfo_kari_decrypt(CMS_ContentInfo *cms,
                                   CMS_RecipientInfo *ri,
                                   CMS_RecipientEncryptedKey *rek)
{
    int rv = 0;
    unsigned char *enckey = NULL, *cek = NULL;
    size_t enckeylen;
    size_t ceklen;
    CMS_EncryptedContentInfo *ec;
    enckeylen = rek->encryptedKey->length;
    enckey = rek->encryptedKey->data;
    /* Setup all parameters to derive KEK */
    if (!cms_env_asn1_ctrl(ri, 1))
        goto err;
    /* Attempt to decrypt CEK */
    if (!cms_kek_cipher(&cek, &ceklen, enckey, enckeylen, ri->d.kari, 0))
        goto err;
    ec = cms->d.envelopedData->encryptedContentInfo;
    if (ec->key) {
        OPENSSL_cleanse(ec->key, ec->keylen);
        OPENSSL_free(ec->key);
    }
    ec->key = cek;
    ec->keylen = ceklen;
    cek = NULL;
    rv = 1;
 err:
    if (cek)
        OPENSSL_free(cek);
    return rv;
}

/* Create ephemeral key and initialise context based on it */
static int cms_kari_create_ephemeral_key(CMS_KeyAgreeRecipientInfo *kari,
                                         EVP_PKEY *pk)
{
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *ekey = NULL;
    int rv = 0;
    pctx = EVP_PKEY_CTX_new(pk, NULL);
    if (!pctx)
        goto err;
    if (EVP_PKEY_keygen_init(pctx) <= 0)
        goto err;
    if (EVP_PKEY_keygen(pctx, &ekey) <= 0)
        goto err;
    EVP_PKEY_CTX_free(pctx);
    pctx = EVP_PKEY_CTX_new(ekey, NULL);
    if (!pctx)
        goto err;
    if (EVP_PKEY_derive_init(pctx) <= 0)
        goto err;
    kari->pctx = pctx;
    rv = 1;
 err:
    if (!rv && pctx)
        EVP_PKEY_CTX_free(pctx);
    if (ekey)
        EVP_PKEY_free(ekey);
    return rv;
}

/* Initialise a ktri based on passed certificate and key */

int cms_RecipientInfo_kari_init(CMS_RecipientInfo *ri, X509 *recip,
                                EVP_PKEY *pk, unsigned int flags)
{
    CMS_KeyAgreeRecipientInfo *kari;
    CMS_RecipientEncryptedKey *rek = NULL;

    ri->d.kari = M_ASN1_new_of(CMS_KeyAgreeRecipientInfo);
    if (!ri->d.kari)
        return 0;
    ri->type = CMS_RECIPINFO_AGREE;

    kari = ri->d.kari;
    kari->version = 3;

    rek = M_ASN1_new_of(CMS_RecipientEncryptedKey);
    if (!sk_CMS_RecipientEncryptedKey_push(kari->recipientEncryptedKeys, rek)) {
        M_ASN1_free_of(rek, CMS_RecipientEncryptedKey);
        return 0;
    }

    if (flags & CMS_USE_KEYID) {
        rek->rid->type = CMS_REK_KEYIDENTIFIER;
        rek->rid->d.rKeyId = M_ASN1_new_of(CMS_RecipientKeyIdentifier);
        if (rek->rid->d.rKeyId == NULL)
            return 0;
        if (!cms_set1_keyid(&rek->rid->d.rKeyId->subjectKeyIdentifier, recip))
            return 0;
    } else {
        rek->rid->type = CMS_REK_ISSUER_SERIAL;
        if (!cms_set1_ias(&rek->rid->d.issuerAndSerialNumber, recip))
            return 0;
    }

    /* Create ephemeral key */
    if (!cms_kari_create_ephemeral_key(kari, pk))
        return 0;

    CRYPTO_add(&pk->references, 1, CRYPTO_LOCK_EVP_PKEY);
    rek->pkey = pk;
    return 1;
}

static int cms_wrap_init(CMS_KeyAgreeRecipientInfo *kari,
                         const EVP_CIPHER *cipher)
{
    EVP_CIPHER_CTX *ctx = &kari->ctx;
    const EVP_CIPHER *kekcipher;
    int keylen = EVP_CIPHER_key_length(cipher);
    /* If a suitable wrap algorithm is already set nothing to do */
    kekcipher = EVP_CIPHER_CTX_cipher(ctx);

    if (kekcipher) {
        if (EVP_CIPHER_CTX_mode(ctx) != EVP_CIPH_WRAP_MODE)
            return 0;
        return 1;
    }
    /*
     * Pick a cipher based on content encryption cipher. If it is DES3 use
     * DES3 wrap otherwise use AES wrap similar to key size.
     */
#ifndef OPENSSL_NO_DES
    if (EVP_CIPHER_type(cipher) == NID_des_ede3_cbc)
        kekcipher = EVP_des_ede3_wrap();
    else
#endif
    if (keylen <= 16)
        kekcipher = EVP_aes_128_wrap();
    else if (keylen <= 24)
        kekcipher = EVP_aes_192_wrap();
    else
        kekcipher = EVP_aes_256_wrap();
    return EVP_EncryptInit_ex(ctx, kekcipher, NULL, NULL, NULL);
}

/* Encrypt content key in key agreement recipient info */

int cms_RecipientInfo_kari_encrypt(CMS_ContentInfo *cms,
                                   CMS_RecipientInfo *ri)
{
    CMS_KeyAgreeRecipientInfo *kari;
    CMS_EncryptedContentInfo *ec;
    CMS_RecipientEncryptedKey *rek;
    STACK_OF(CMS_RecipientEncryptedKey) *reks;
    int i;

    if (ri->type != CMS_RECIPINFO_AGREE) {
        CMSerr(CMS_F_CMS_RECIPIENTINFO_KARI_ENCRYPT, CMS_R_NOT_KEY_AGREEMENT);
        return 0;
    }
    kari = ri->d.kari;
    reks = kari->recipientEncryptedKeys;
    ec = cms->d.envelopedData->encryptedContentInfo;
    /* Initialise wrap algorithm parameters */
    if (!cms_wrap_init(kari, ec->cipher))
        return 0;
    /*
     * If no orignator key set up initialise for ephemeral key the public key
     * ASN1 structure will set the actual public key value.
     */
    if (kari->originator->type == -1) {
        CMS_OriginatorIdentifierOrKey *oik = kari->originator;
        oik->type = CMS_OIK_PUBKEY;
        oik->d.originatorKey = M_ASN1_new_of(CMS_OriginatorPublicKey);
        if (!oik->d.originatorKey)
            return 0;
    }
    /* Initialise KDF algorithm */
    if (!cms_env_asn1_ctrl(ri, 0))
        return 0;
    /* For each rek, derive KEK, encrypt CEK */
    for (i = 0; i < sk_CMS_RecipientEncryptedKey_num(reks); i++) {
        unsigned char *enckey;
        size_t enckeylen;
        rek = sk_CMS_RecipientEncryptedKey_value(reks, i);
        if (EVP_PKEY_derive_set_peer(kari->pctx, rek->pkey) <= 0)
            return 0;
        if (!cms_kek_cipher(&enckey, &enckeylen, ec->key, ec->keylen,
                            kari, 1))
            return 0;
        ASN1_STRING_set0(rek->encryptedKey, enckey, enckeylen);
    }

    return 1;

}
/* crypto/cms/cms_lib.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project.
 */
/* ====================================================================
 * Copyright (c) 2008 The OpenSSL Project.  All rights reserved.
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
 */

// #include "asn1t.h"
// #include "x509v3.h"
// #include "err.h"
// #include "pem.h"
// #include "bio.h"
#include "asn1.h"
// #include "cms.h"
// #include "cms_lcl.h"

IMPLEMENT_ASN1_FUNCTIONS(CMS_ContentInfo)
IMPLEMENT_ASN1_PRINT_FUNCTION(CMS_ContentInfo)

DECLARE_ASN1_ITEM(CMS_CertificateChoices)
DECLARE_ASN1_ITEM(CMS_RevocationInfoChoice)
DECLARE_STACK_OF(CMS_CertificateChoices)
DECLARE_STACK_OF(CMS_RevocationInfoChoice)

const ASN1_OBJECT *CMS_get0_type(CMS_ContentInfo *cms)
{
    return cms->contentType;
}

CMS_ContentInfo *cms_Data_create(void)
{
    CMS_ContentInfo *cms;
    cms = CMS_ContentInfo_new();
    if (cms) {
        cms->contentType = OBJ_nid2obj(NID_pkcs7_data);
        /* Never detached */
        CMS_set_detached(cms, 0);
    }
    return cms;
}

BIO *cms_content_bio(CMS_ContentInfo *cms)
{
    ASN1_OCTET_STRING **pos = CMS_get0_content(cms);
    if (!pos)
        return NULL;
    /* If content detached data goes nowhere: create NULL BIO */
    if (!*pos)
        return BIO_new(BIO_s_null());
    /*
     * If content not detached and created return memory BIO
     */
    if (!*pos || ((*pos)->flags == ASN1_STRING_FLAG_CONT))
        return BIO_new(BIO_s_mem());
    /* Else content was read in: return read only BIO for it */
    return BIO_new_mem_buf((*pos)->data, (*pos)->length);
}

BIO *CMS_dataInit(CMS_ContentInfo *cms, BIO *icont)
{
    BIO *cmsbio, *cont;
    if (icont)
        cont = icont;
    else
        cont = cms_content_bio(cms);
    if (!cont) {
        CMSerr(CMS_F_CMS_DATAINIT, CMS_R_NO_CONTENT);
        return NULL;
    }
    switch (OBJ_obj2nid(cms->contentType)) {

    case NID_pkcs7_data:
        return cont;

    case NID_pkcs7_signed:
        cmsbio = cms_SignedData_init_bio(cms);
        break;

    case NID_pkcs7_digest:
        cmsbio = cms_DigestedData_init_bio(cms);
        break;
#ifdef ZLIB
    case NID_id_smime_ct_compressedData:
        cmsbio = cms_CompressedData_init_bio(cms);
        break;
#endif

    case NID_pkcs7_encrypted:
        cmsbio = cms_EncryptedData_init_bio(cms);
        break;

    case NID_pkcs7_enveloped:
        cmsbio = cms_EnvelopedData_init_bio(cms);
        break;

    default:
        CMSerr(CMS_F_CMS_DATAINIT, CMS_R_UNSUPPORTED_TYPE);
        return NULL;
    }

    if (cmsbio)
        return BIO_push(cmsbio, cont);

    if (!icont)
        BIO_free(cont);
    return NULL;

}

int CMS_dataFinal(CMS_ContentInfo *cms, BIO *cmsbio)
{
    ASN1_OCTET_STRING **pos = CMS_get0_content(cms);
    if (!pos)
        return 0;
    /* If ebmedded content find memory BIO and set content */
    if (*pos && ((*pos)->flags & ASN1_STRING_FLAG_CONT)) {
        BIO *mbio;
        unsigned char *cont;
        long contlen;
        mbio = BIO_find_type(cmsbio, BIO_TYPE_MEM);
        if (!mbio) {
            CMSerr(CMS_F_CMS_DATAFINAL, CMS_R_CONTENT_NOT_FOUND);
            return 0;
        }
        contlen = BIO_get_mem_data(mbio, &cont);
        /* Set bio as read only so its content can't be clobbered */
        BIO_set_flags(mbio, BIO_FLAGS_MEM_RDONLY);
        BIO_set_mem_eof_return(mbio, 0);
        ASN1_STRING_set0(*pos, cont, contlen);
        (*pos)->flags &= ~ASN1_STRING_FLAG_CONT;
    }

    switch (OBJ_obj2nid(cms->contentType)) {

    case NID_pkcs7_data:
    case NID_pkcs7_enveloped:
    case NID_pkcs7_encrypted:
    case NID_id_smime_ct_compressedData:
        /* Nothing to do */
        return 1;

    case NID_pkcs7_signed:
        return cms_SignedData_final(cms, cmsbio);

    case NID_pkcs7_digest:
        return cms_DigestedData_do_final(cms, cmsbio, 0);

    default:
        CMSerr(CMS_F_CMS_DATAFINAL, CMS_R_UNSUPPORTED_TYPE);
        return 0;
    }
}

/*
 * Return an OCTET STRING pointer to content. This allows it to be accessed
 * or set later.
 */

ASN1_OCTET_STRING **CMS_get0_content(CMS_ContentInfo *cms)
{
    switch (OBJ_obj2nid(cms->contentType)) {

    case NID_pkcs7_data:
        return &cms->d.data;

    case NID_pkcs7_signed:
        return &cms->d.signedData->encapContentInfo->eContent;

    case NID_pkcs7_enveloped:
        return &cms->d.envelopedData->encryptedContentInfo->encryptedContent;

    case NID_pkcs7_digest:
        return &cms->d.digestedData->encapContentInfo->eContent;

    case NID_pkcs7_encrypted:
        return &cms->d.encryptedData->encryptedContentInfo->encryptedContent;

    case NID_id_smime_ct_authData:
        return &cms->d.authenticatedData->encapContentInfo->eContent;

    case NID_id_smime_ct_compressedData:
        return &cms->d.compressedData->encapContentInfo->eContent;

    default:
        if (cms->d.other->type == V_ASN1_OCTET_STRING)
            return &cms->d.other->value.octet_string;
        CMSerr(CMS_F_CMS_GET0_CONTENT, CMS_R_UNSUPPORTED_CONTENT_TYPE);
        return NULL;

    }
}

/*
 * Return an ASN1_OBJECT pointer to content type. This allows it to be
 * accessed or set later.
 */

static ASN1_OBJECT **cms_get0_econtent_type(CMS_ContentInfo *cms)
{
    switch (OBJ_obj2nid(cms->contentType)) {

    case NID_pkcs7_signed:
        return &cms->d.signedData->encapContentInfo->eContentType;

    case NID_pkcs7_enveloped:
        return &cms->d.envelopedData->encryptedContentInfo->contentType;

    case NID_pkcs7_digest:
        return &cms->d.digestedData->encapContentInfo->eContentType;

    case NID_pkcs7_encrypted:
        return &cms->d.encryptedData->encryptedContentInfo->contentType;

    case NID_id_smime_ct_authData:
        return &cms->d.authenticatedData->encapContentInfo->eContentType;

    case NID_id_smime_ct_compressedData:
        return &cms->d.compressedData->encapContentInfo->eContentType;

    default:
        CMSerr(CMS_F_CMS_GET0_ECONTENT_TYPE, CMS_R_UNSUPPORTED_CONTENT_TYPE);
        return NULL;

    }
}

const ASN1_OBJECT *CMS_get0_eContentType(CMS_ContentInfo *cms)
{
    ASN1_OBJECT **petype;
    petype = cms_get0_econtent_type(cms);
    if (petype)
        return *petype;
    return NULL;
}

int CMS_set1_eContentType(CMS_ContentInfo *cms, const ASN1_OBJECT *oid)
{
    ASN1_OBJECT **petype, *etype;
    petype = cms_get0_econtent_type(cms);
    if (!petype)
        return 0;
    if (!oid)
        return 1;
    etype = OBJ_dup(oid);
    if (!etype)
        return 0;
    ASN1_OBJECT_free(*petype);
    *petype = etype;
    return 1;
}

int CMS_is_detached(CMS_ContentInfo *cms)
{
    ASN1_OCTET_STRING **pos;
    pos = CMS_get0_content(cms);
    if (!pos)
        return -1;
    if (*pos)
        return 0;
    return 1;
}

int CMS_set_detached(CMS_ContentInfo *cms, int detached)
{
    ASN1_OCTET_STRING **pos;
    pos = CMS_get0_content(cms);
    if (!pos)
        return 0;
    if (detached) {
        if (*pos) {
            ASN1_OCTET_STRING_free(*pos);
            *pos = NULL;
        }
        return 1;
    }
    if (!*pos)
        *pos = ASN1_OCTET_STRING_new();
    if (*pos) {
        /*
         * NB: special flag to show content is created and not read in.
         */
        (*pos)->flags |= ASN1_STRING_FLAG_CONT;
        return 1;
    }
    CMSerr(CMS_F_CMS_SET_DETACHED, ERR_R_MALLOC_FAILURE);
    return 0;
}

/* Set up an X509_ALGOR DigestAlgorithmIdentifier from an EVP_MD */

void cms_DigestAlgorithm_set(X509_ALGOR *alg, const EVP_MD *md)
{
    int param_type;

    if (md->flags & EVP_MD_FLAG_DIGALGID_ABSENT)
        param_type = V_ASN1_UNDEF;
    else
        param_type = V_ASN1_NULL;

    X509_ALGOR_set0(alg, OBJ_nid2obj(EVP_MD_type(md)), param_type, NULL);

}

/* Create a digest BIO from an X509_ALGOR structure */

BIO *cms_DigestAlgorithm_init_bio(X509_ALGOR *digestAlgorithm)
{
    BIO *mdbio = NULL;
    ASN1_OBJECT *digestoid;
    const EVP_MD *digest;
    X509_ALGOR_get0(&digestoid, NULL, NULL, digestAlgorithm);
    digest = EVP_get_digestbyobj(digestoid);
    if (!digest) {
        CMSerr(CMS_F_CMS_DIGESTALGORITHM_INIT_BIO,
               CMS_R_UNKNOWN_DIGEST_ALGORIHM);
        goto err;
    }
    mdbio = BIO_new(BIO_f_md());
    if (!mdbio || !BIO_set_md(mdbio, digest)) {
        CMSerr(CMS_F_CMS_DIGESTALGORITHM_INIT_BIO, CMS_R_MD_BIO_INIT_ERROR);
        goto err;
    }
    return mdbio;
 err:
    if (mdbio)
        BIO_free(mdbio);
    return NULL;
}

/* Locate a message digest content from a BIO chain based on SignerInfo */

int cms_DigestAlgorithm_find_ctx(EVP_MD_CTX *mctx, BIO *chain,
                                 X509_ALGOR *mdalg)
{
    int nid;
    ASN1_OBJECT *mdoid;
    X509_ALGOR_get0(&mdoid, NULL, NULL, mdalg);
    nid = OBJ_obj2nid(mdoid);
    /* Look for digest type to match signature */
    for (;;) {
        EVP_MD_CTX *mtmp;
        chain = BIO_find_type(chain, BIO_TYPE_MD);
        if (chain == NULL) {
            CMSerr(CMS_F_CMS_DIGESTALGORITHM_FIND_CTX,
                   CMS_R_NO_MATCHING_DIGEST);
            return 0;
        }
        BIO_get_md_ctx(chain, &mtmp);
        if (EVP_MD_CTX_type(mtmp) == nid
            /*
             * Workaround for broken implementations that use signature
             * algorithm OID instead of digest.
             */
            || EVP_MD_pkey_type(EVP_MD_CTX_md(mtmp)) == nid)
            return EVP_MD_CTX_copy_ex(mctx, mtmp);
        chain = BIO_next(chain);
    }
}

static STACK_OF(CMS_CertificateChoices)
**cms_get0_certificate_choices(CMS_ContentInfo *cms)
{
    switch (OBJ_obj2nid(cms->contentType)) {

    case NID_pkcs7_signed:
        return &cms->d.signedData->certificates;

    case NID_pkcs7_enveloped:
        if (cms->d.envelopedData->originatorInfo == NULL)
            return NULL;
        return &cms->d.envelopedData->originatorInfo->certificates;

    default:
        CMSerr(CMS_F_CMS_GET0_CERTIFICATE_CHOICES,
               CMS_R_UNSUPPORTED_CONTENT_TYPE);
        return NULL;

    }
}

CMS_CertificateChoices *CMS_add0_CertificateChoices(CMS_ContentInfo *cms)
{
    STACK_OF(CMS_CertificateChoices) **pcerts;
    CMS_CertificateChoices *cch;
    pcerts = cms_get0_certificate_choices(cms);
    if (!pcerts)
        return NULL;
    if (!*pcerts)
        *pcerts = sk_CMS_CertificateChoices_new_null();
    if (!*pcerts)
        return NULL;
    cch = M_ASN1_new_of(CMS_CertificateChoices);
    if (!cch)
        return NULL;
    if (!sk_CMS_CertificateChoices_push(*pcerts, cch)) {
        M_ASN1_free_of(cch, CMS_CertificateChoices);
        return NULL;
    }
    return cch;
}

int CMS_add0_cert(CMS_ContentInfo *cms, X509 *cert)
{
    CMS_CertificateChoices *cch;
    STACK_OF(CMS_CertificateChoices) **pcerts;
    int i;
    pcerts = cms_get0_certificate_choices(cms);
    if (!pcerts)
        return 0;
    for (i = 0; i < sk_CMS_CertificateChoices_num(*pcerts); i++) {
        cch = sk_CMS_CertificateChoices_value(*pcerts, i);
        if (cch->type == CMS_CERTCHOICE_CERT) {
            if (!X509_cmp(cch->d.certificate, cert)) {
                CMSerr(CMS_F_CMS_ADD0_CERT,
                       CMS_R_CERTIFICATE_ALREADY_PRESENT);
                return 0;
            }
        }
    }
    cch = CMS_add0_CertificateChoices(cms);
    if (!cch)
        return 0;
    cch->type = CMS_CERTCHOICE_CERT;
    cch->d.certificate = cert;
    return 1;
}

int CMS_add1_cert(CMS_ContentInfo *cms, X509 *cert)
{
    int r;
    r = CMS_add0_cert(cms, cert);
    if (r > 0)
        CRYPTO_add(&cert->references, 1, CRYPTO_LOCK_X509);
    return r;
}

static STACK_OF(CMS_RevocationInfoChoice)
**cms_get0_revocation_choices(CMS_ContentInfo *cms)
{
    switch (OBJ_obj2nid(cms->contentType)) {

    case NID_pkcs7_signed:
        return &cms->d.signedData->crls;

    case NID_pkcs7_enveloped:
        if (cms->d.envelopedData->originatorInfo == NULL)
            return NULL;
        return &cms->d.envelopedData->originatorInfo->crls;

    default:
        CMSerr(CMS_F_CMS_GET0_REVOCATION_CHOICES,
               CMS_R_UNSUPPORTED_CONTENT_TYPE);
        return NULL;

    }
}

CMS_RevocationInfoChoice *CMS_add0_RevocationInfoChoice(CMS_ContentInfo *cms)
{
    STACK_OF(CMS_RevocationInfoChoice) **pcrls;
    CMS_RevocationInfoChoice *rch;
    pcrls = cms_get0_revocation_choices(cms);
    if (!pcrls)
        return NULL;
    if (!*pcrls)
        *pcrls = sk_CMS_RevocationInfoChoice_new_null();
    if (!*pcrls)
        return NULL;
    rch = M_ASN1_new_of(CMS_RevocationInfoChoice);
    if (!rch)
        return NULL;
    if (!sk_CMS_RevocationInfoChoice_push(*pcrls, rch)) {
        M_ASN1_free_of(rch, CMS_RevocationInfoChoice);
        return NULL;
    }
    return rch;
}

int CMS_add0_crl(CMS_ContentInfo *cms, X509_CRL *crl)
{
    CMS_RevocationInfoChoice *rch;
    rch = CMS_add0_RevocationInfoChoice(cms);
    if (!rch)
        return 0;
    rch->type = CMS_REVCHOICE_CRL;
    rch->d.crl = crl;
    return 1;
}

int CMS_add1_crl(CMS_ContentInfo *cms, X509_CRL *crl)
{
    int r;
    r = CMS_add0_crl(cms, crl);
    if (r > 0)
        CRYPTO_add(&crl->references, 1, CRYPTO_LOCK_X509_CRL);
    return r;
}

STACK_OF(X509) *CMS_get1_certs(CMS_ContentInfo *cms)
{
    STACK_OF(X509) *certs = NULL;
    CMS_CertificateChoices *cch;
    STACK_OF(CMS_CertificateChoices) **pcerts;
    int i;
    pcerts = cms_get0_certificate_choices(cms);
    if (!pcerts)
        return NULL;
    for (i = 0; i < sk_CMS_CertificateChoices_num(*pcerts); i++) {
        cch = sk_CMS_CertificateChoices_value(*pcerts, i);
        if (cch->type == 0) {
            if (!certs) {
                certs = sk_X509_new_null();
                if (!certs)
                    return NULL;
            }
            if (!sk_X509_push(certs, cch->d.certificate)) {
                sk_X509_pop_free(certs, X509_free);
                return NULL;
            }
            CRYPTO_add(&cch->d.certificate->references, 1, CRYPTO_LOCK_X509);
        }
    }
    return certs;

}

STACK_OF(X509_CRL) *CMS_get1_crls(CMS_ContentInfo *cms)
{
    STACK_OF(X509_CRL) *crls = NULL;
    STACK_OF(CMS_RevocationInfoChoice) **pcrls;
    CMS_RevocationInfoChoice *rch;
    int i;
    pcrls = cms_get0_revocation_choices(cms);
    if (!pcrls)
        return NULL;
    for (i = 0; i < sk_CMS_RevocationInfoChoice_num(*pcrls); i++) {
        rch = sk_CMS_RevocationInfoChoice_value(*pcrls, i);
        if (rch->type == 0) {
            if (!crls) {
                crls = sk_X509_CRL_new_null();
                if (!crls)
                    return NULL;
            }
            if (!sk_X509_CRL_push(crls, rch->d.crl)) {
                sk_X509_CRL_pop_free(crls, X509_CRL_free);
                return NULL;
            }
            CRYPTO_add(&rch->d.crl->references, 1, CRYPTO_LOCK_X509_CRL);
        }
    }
    return crls;
}

int cms_ias_cert_cmp(CMS_IssuerAndSerialNumber *ias, X509 *cert)
{
    int ret;
    ret = X509_NAME_cmp(ias->issuer, X509_get_issuer_name(cert));
    if (ret)
        return ret;
    return ASN1_INTEGER_cmp(ias->serialNumber, X509_get_serialNumber(cert));
}

int cms_keyid_cert_cmp(ASN1_OCTET_STRING *keyid, X509 *cert)
{
    X509_check_purpose(cert, -1, -1);
    if (!cert->skid)
        return -1;
    return ASN1_OCTET_STRING_cmp(keyid, cert->skid);
}

int cms_set1_ias(CMS_IssuerAndSerialNumber **pias, X509 *cert)
{
    CMS_IssuerAndSerialNumber *ias;
    ias = M_ASN1_new_of(CMS_IssuerAndSerialNumber);
    if (!ias)
        goto err;
    if (!X509_NAME_set(&ias->issuer, X509_get_issuer_name(cert)))
        goto err;
    if (!ASN1_STRING_copy(ias->serialNumber, X509_get_serialNumber(cert)))
        goto err;
    if (*pias)
        M_ASN1_free_of(*pias, CMS_IssuerAndSerialNumber);
    *pias = ias;
    return 1;
 err:
    if (ias)
        M_ASN1_free_of(ias, CMS_IssuerAndSerialNumber);
    CMSerr(CMS_F_CMS_SET1_IAS, ERR_R_MALLOC_FAILURE);
    return 0;
}

int cms_set1_keyid(ASN1_OCTET_STRING **pkeyid, X509 *cert)
{
    ASN1_OCTET_STRING *keyid = NULL;
    X509_check_purpose(cert, -1, -1);
    if (!cert->skid) {
        CMSerr(CMS_F_CMS_SET1_KEYID, CMS_R_CERTIFICATE_HAS_NO_KEYID);
        return 0;
    }
    keyid = ASN1_STRING_dup(cert->skid);
    if (!keyid) {
        CMSerr(CMS_F_CMS_SET1_KEYID, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    if (*pkeyid)
        ASN1_OCTET_STRING_free(*pkeyid);
    *pkeyid = keyid;
    return 1;
}
/* crypto/cms/cms_pwri.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project.
 */
/* ====================================================================
 * Copyright (c) 2009 The OpenSSL Project.  All rights reserved.
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
 */

// #include "cryptlib.h"
// #include "asn1t.h"
// #include "pem.h"
// #include "x509v3.h"
// #include "err.h"
// #include "cms.h"
// #include "rand.h"
// #include "aes.h"
// #include "cms_lcl.h"
// #include "asn1_locl.h"

int CMS_RecipientInfo_set0_password(CMS_RecipientInfo *ri,
                                    unsigned char *pass, ossl_ssize_t passlen)
{
    CMS_PasswordRecipientInfo *pwri;
    if (ri->type != CMS_RECIPINFO_PASS) {
        CMSerr(CMS_F_CMS_RECIPIENTINFO_SET0_PASSWORD, CMS_R_NOT_PWRI);
        return 0;
    }

    pwri = ri->d.pwri;
    pwri->pass = pass;
    if (pass && passlen < 0)
        passlen = strlen((char *)pass);
    pwri->passlen = passlen;
    return 1;
}

CMS_RecipientInfo *CMS_add0_recipient_password(CMS_ContentInfo *cms,
                                               int iter, int wrap_nid,
                                               int pbe_nid,
                                               unsigned char *pass,
                                               ossl_ssize_t passlen,
                                               const EVP_CIPHER *kekciph)
{
    CMS_RecipientInfo *ri = NULL;
    CMS_EnvelopedData *env;
    CMS_PasswordRecipientInfo *pwri;
    EVP_CIPHER_CTX ctx;
    X509_ALGOR *encalg = NULL;
    unsigned char iv[EVP_MAX_IV_LENGTH];
    int ivlen;

    env = cms_get0_enveloped(cms);
    if (!env)
        return NULL;

    if (wrap_nid <= 0)
        wrap_nid = NID_id_alg_PWRI_KEK;

    if (pbe_nid <= 0)
        pbe_nid = NID_id_pbkdf2;

    /* Get from enveloped data */
    if (kekciph == NULL)
        kekciph = env->encryptedContentInfo->cipher;

    if (kekciph == NULL) {
        CMSerr(CMS_F_CMS_ADD0_RECIPIENT_PASSWORD, CMS_R_NO_CIPHER);
        return NULL;
    }
    if (wrap_nid != NID_id_alg_PWRI_KEK) {
        CMSerr(CMS_F_CMS_ADD0_RECIPIENT_PASSWORD,
               CMS_R_UNSUPPORTED_KEY_ENCRYPTION_ALGORITHM);
        return NULL;
    }

    /* Setup algorithm identifier for cipher */
    encalg = X509_ALGOR_new();
    if (encalg == NULL) {
        goto merr;
    }
    EVP_CIPHER_CTX_init(&ctx);

    if (EVP_EncryptInit_ex(&ctx, kekciph, NULL, NULL, NULL) <= 0) {
        CMSerr(CMS_F_CMS_ADD0_RECIPIENT_PASSWORD, ERR_R_EVP_LIB);
        goto err;
    }

    ivlen = EVP_CIPHER_CTX_iv_length(&ctx);

    if (ivlen > 0) {
        if (RAND_bytes(iv, ivlen) <= 0)
            goto err;
        if (EVP_EncryptInit_ex(&ctx, NULL, NULL, NULL, iv) <= 0) {
            CMSerr(CMS_F_CMS_ADD0_RECIPIENT_PASSWORD, ERR_R_EVP_LIB);
            goto err;
        }
        encalg->parameter = ASN1_TYPE_new();
        if (!encalg->parameter) {
            CMSerr(CMS_F_CMS_ADD0_RECIPIENT_PASSWORD, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        if (EVP_CIPHER_param_to_asn1(&ctx, encalg->parameter) <= 0) {
            CMSerr(CMS_F_CMS_ADD0_RECIPIENT_PASSWORD,
                   CMS_R_CIPHER_PARAMETER_INITIALISATION_ERROR);
            goto err;
        }
    }

    encalg->algorithm = OBJ_nid2obj(EVP_CIPHER_CTX_type(&ctx));

    EVP_CIPHER_CTX_cleanup(&ctx);

    /* Initialize recipient info */
    ri = M_ASN1_new_of(CMS_RecipientInfo);
    if (!ri)
        goto merr;

    ri->d.pwri = M_ASN1_new_of(CMS_PasswordRecipientInfo);
    if (!ri->d.pwri)
        goto merr;
    ri->type = CMS_RECIPINFO_PASS;

    pwri = ri->d.pwri;
    /* Since this is overwritten, free up empty structure already there */
    X509_ALGOR_free(pwri->keyEncryptionAlgorithm);
    pwri->keyEncryptionAlgorithm = X509_ALGOR_new();
    if (!pwri->keyEncryptionAlgorithm)
        goto merr;
    pwri->keyEncryptionAlgorithm->algorithm = OBJ_nid2obj(wrap_nid);
    pwri->keyEncryptionAlgorithm->parameter = ASN1_TYPE_new();
    if (!pwri->keyEncryptionAlgorithm->parameter)
        goto merr;

    if (!ASN1_item_pack(encalg, ASN1_ITEM_rptr(X509_ALGOR),
                        &pwri->keyEncryptionAlgorithm->parameter->
                        value.sequence))
         goto merr;
    pwri->keyEncryptionAlgorithm->parameter->type = V_ASN1_SEQUENCE;

    X509_ALGOR_free(encalg);
    encalg = NULL;

    /* Setup PBE algorithm */

    pwri->keyDerivationAlgorithm = PKCS5_pbkdf2_set(iter, NULL, 0, -1, -1);

    if (!pwri->keyDerivationAlgorithm)
        goto err;

    CMS_RecipientInfo_set0_password(ri, pass, passlen);
    pwri->version = 0;

    if (!sk_CMS_RecipientInfo_push(env->recipientInfos, ri))
        goto merr;

    return ri;

 merr:
    CMSerr(CMS_F_CMS_ADD0_RECIPIENT_PASSWORD, ERR_R_MALLOC_FAILURE);
 err:
    EVP_CIPHER_CTX_cleanup(&ctx);
    if (ri)
        M_ASN1_free_of(ri, CMS_RecipientInfo);
    if (encalg)
        X509_ALGOR_free(encalg);
    return NULL;

}

/*
 * This is an implementation of the key wrapping mechanism in RFC3211, at
 * some point this should go into EVP.
 */

static int kek_unwrap_key(unsigned char *out, size_t *outlen,
                          const unsigned char *in, size_t inlen,
                          EVP_CIPHER_CTX *ctx)
{
    size_t blocklen = EVP_CIPHER_CTX_block_size(ctx);
    unsigned char *tmp;
    int outl, rv = 0;
    if (inlen < 2 * blocklen) {
        /* too small */
        return 0;
    }
    if (inlen % blocklen) {
        /* Invalid size */
        return 0;
    }
    tmp = OPENSSL_malloc(inlen);
    if (!tmp)
        return 0;
    /* setup IV by decrypting last two blocks */
    EVP_DecryptUpdate(ctx, tmp + inlen - 2 * blocklen, &outl,
                      in + inlen - 2 * blocklen, blocklen * 2);
    /*
     * Do a decrypt of last decrypted block to set IV to correct value output
     * it to start of buffer so we don't corrupt decrypted block this works
     * because buffer is at least two block lengths long.
     */
    EVP_DecryptUpdate(ctx, tmp, &outl, tmp + inlen - blocklen, blocklen);
    /* Can now decrypt first n - 1 blocks */
    EVP_DecryptUpdate(ctx, tmp, &outl, in, inlen - blocklen);

    /* Reset IV to original value */
    EVP_DecryptInit_ex(ctx, NULL, NULL, NULL, NULL);
    /* Decrypt again */
    EVP_DecryptUpdate(ctx, tmp, &outl, tmp, inlen);
    /* Check check bytes */
    if (((tmp[1] ^ tmp[4]) & (tmp[2] ^ tmp[5]) & (tmp[3] ^ tmp[6])) != 0xff) {
        /* Check byte failure */
        goto err;
    }
    if (inlen < (size_t)(tmp[0] - 4)) {
        /* Invalid length value */
        goto err;
    }
    *outlen = (size_t)tmp[0];
    memcpy(out, tmp + 4, *outlen);
    rv = 1;
 err:
    OPENSSL_cleanse(tmp, inlen);
    OPENSSL_free(tmp);
    return rv;

}

static int kek_wrap_key(unsigned char *out, size_t *outlen,
                        const unsigned char *in, size_t inlen,
                        EVP_CIPHER_CTX *ctx)
{
    size_t blocklen = EVP_CIPHER_CTX_block_size(ctx);
    size_t olen;
    int dummy;
    /*
     * First decide length of output buffer: need header and round up to
     * multiple of block length.
     */
    olen = (inlen + 4 + blocklen - 1) / blocklen;
    olen *= blocklen;
    if (olen < 2 * blocklen) {
        /* Key too small */
        return 0;
    }
    if (inlen > 0xFF) {
        /* Key too large */
        return 0;
    }
    if (out) {
        /* Set header */
        out[0] = (unsigned char)inlen;
        out[1] = in[0] ^ 0xFF;
        out[2] = in[1] ^ 0xFF;
        out[3] = in[2] ^ 0xFF;
        memcpy(out + 4, in, inlen);
        /* Add random padding to end */
        if (olen > inlen + 4
            && RAND_bytes(out + 4 + inlen, olen - 4 - inlen) <= 0)
            return 0;
        /* Encrypt twice */
        EVP_EncryptUpdate(ctx, out, &dummy, out, olen);
        EVP_EncryptUpdate(ctx, out, &dummy, out, olen);
    }

    *outlen = olen;

    return 1;
}

/* Encrypt/Decrypt content key in PWRI recipient info */

int cms_RecipientInfo_pwri_crypt(CMS_ContentInfo *cms, CMS_RecipientInfo *ri,
                                 int en_de)
{
    CMS_EncryptedContentInfo *ec;
    CMS_PasswordRecipientInfo *pwri;
    const unsigned char *p = NULL;
    int plen;
    int r = 0;
    X509_ALGOR *algtmp, *kekalg = NULL;
    EVP_CIPHER_CTX kekctx;
    const EVP_CIPHER *kekcipher;
    unsigned char *key = NULL;
    size_t keylen;

    ec = cms->d.envelopedData->encryptedContentInfo;

    pwri = ri->d.pwri;
    EVP_CIPHER_CTX_init(&kekctx);

    if (!pwri->pass) {
        CMSerr(CMS_F_CMS_RECIPIENTINFO_PWRI_CRYPT, CMS_R_NO_PASSWORD);
        return 0;
    }
    algtmp = pwri->keyEncryptionAlgorithm;

    if (!algtmp || OBJ_obj2nid(algtmp->algorithm) != NID_id_alg_PWRI_KEK) {
        CMSerr(CMS_F_CMS_RECIPIENTINFO_PWRI_CRYPT,
               CMS_R_UNSUPPORTED_KEY_ENCRYPTION_ALGORITHM);
        return 0;
    }

    if (algtmp->parameter->type == V_ASN1_SEQUENCE) {
        p = algtmp->parameter->value.sequence->data;
        plen = algtmp->parameter->value.sequence->length;
        kekalg = d2i_X509_ALGOR(NULL, &p, plen);
    }
    if (kekalg == NULL) {
        CMSerr(CMS_F_CMS_RECIPIENTINFO_PWRI_CRYPT,
               CMS_R_INVALID_KEY_ENCRYPTION_PARAMETER);
        return 0;
    }

    kekcipher = EVP_get_cipherbyobj(kekalg->algorithm);

    if (!kekcipher) {
        CMSerr(CMS_F_CMS_RECIPIENTINFO_PWRI_CRYPT, CMS_R_UNKNOWN_CIPHER);
        goto err;
    }

    /* Fixup cipher based on AlgorithmIdentifier to set IV etc */
    if (!EVP_CipherInit_ex(&kekctx, kekcipher, NULL, NULL, NULL, en_de))
        goto err;
    EVP_CIPHER_CTX_set_padding(&kekctx, 0);
    if (EVP_CIPHER_asn1_to_param(&kekctx, kekalg->parameter) < 0) {
        CMSerr(CMS_F_CMS_RECIPIENTINFO_PWRI_CRYPT,
               CMS_R_CIPHER_PARAMETER_INITIALISATION_ERROR);
        goto err;
    }

    algtmp = pwri->keyDerivationAlgorithm;

    /* Finish password based key derivation to setup key in "ctx" */

    if (EVP_PBE_CipherInit(algtmp->algorithm,
                           (char *)pwri->pass, pwri->passlen,
                           algtmp->parameter, &kekctx, en_de) < 0) {
        CMSerr(CMS_F_CMS_RECIPIENTINFO_PWRI_CRYPT, ERR_R_EVP_LIB);
        goto err;
    }

    /* Finally wrap/unwrap the key */

    if (en_de) {

        if (!kek_wrap_key(NULL, &keylen, ec->key, ec->keylen, &kekctx))
            goto err;

        key = OPENSSL_malloc(keylen);

        if (!key)
            goto err;

        if (!kek_wrap_key(key, &keylen, ec->key, ec->keylen, &kekctx))
            goto err;
        pwri->encryptedKey->data = key;
        pwri->encryptedKey->length = keylen;
    } else {
        key = OPENSSL_malloc(pwri->encryptedKey->length);

        if (!key) {
            CMSerr(CMS_F_CMS_RECIPIENTINFO_PWRI_CRYPT, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        if (!kek_unwrap_key(key, &keylen,
                            pwri->encryptedKey->data,
                            pwri->encryptedKey->length, &kekctx)) {
            CMSerr(CMS_F_CMS_RECIPIENTINFO_PWRI_CRYPT, CMS_R_UNWRAP_FAILURE);
            goto err;
        }

        ec->key = key;
        ec->keylen = keylen;

    }

    r = 1;

 err:

    EVP_CIPHER_CTX_cleanup(&kekctx);

    if (!r && key)
        OPENSSL_free(key);
    X509_ALGOR_free(kekalg);

    return r;

}
/* crypto/cms/cms_sd.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project.
 */
/* ====================================================================
 * Copyright (c) 2008 The OpenSSL Project.  All rights reserved.
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
 */

// #include "cryptlib.h"
// #include "asn1t.h"
// #include "pem.h"
// #include "x509.h"
// #include "x509v3.h"
// #include "err.h"
// #include "cms.h"
// #include "cms_lcl.h"
// #include "asn1_locl.h"

/* CMS SignedData Utilities */

DECLARE_ASN1_ITEM(CMS_SignedData)

static CMS_SignedData *cms_get0_signed(CMS_ContentInfo *cms)
{
    if (OBJ_obj2nid(cms->contentType) != NID_pkcs7_signed) {
        CMSerr(CMS_F_CMS_GET0_SIGNED, CMS_R_CONTENT_TYPE_NOT_SIGNED_DATA);
        return NULL;
    }
    return cms->d.signedData;
}

static CMS_SignedData *cms_signed_data_init(CMS_ContentInfo *cms)
{
    if (cms->d.other == NULL) {
        cms->d.signedData = M_ASN1_new_of(CMS_SignedData);
        if (!cms->d.signedData) {
            CMSerr(CMS_F_CMS_SIGNED_DATA_INIT, ERR_R_MALLOC_FAILURE);
            return NULL;
        }
        cms->d.signedData->version = 1;
        cms->d.signedData->encapContentInfo->eContentType =
            OBJ_nid2obj(NID_pkcs7_data);
        cms->d.signedData->encapContentInfo->partial = 1;
        ASN1_OBJECT_free(cms->contentType);
        cms->contentType = OBJ_nid2obj(NID_pkcs7_signed);
        return cms->d.signedData;
    }
    return cms_get0_signed(cms);
}

/* Just initialize SignedData e.g. for certs only structure */

int CMS_SignedData_init(CMS_ContentInfo *cms)
{
    if (cms_signed_data_init(cms))
        return 1;
    else
        return 0;
}

/* Check structures and fixup version numbers (if necessary) */

static void cms_sd_set_version(CMS_SignedData *sd)
{
    int i;
    CMS_CertificateChoices *cch;
    CMS_RevocationInfoChoice *rch;
    CMS_SignerInfo *si;

    for (i = 0; i < sk_CMS_CertificateChoices_num(sd->certificates); i++) {
        cch = sk_CMS_CertificateChoices_value(sd->certificates, i);
        if (cch->type == CMS_CERTCHOICE_OTHER) {
            if (sd->version < 5)
                sd->version = 5;
        } else if (cch->type == CMS_CERTCHOICE_V2ACERT) {
            if (sd->version < 4)
                sd->version = 4;
        } else if (cch->type == CMS_CERTCHOICE_V1ACERT) {
            if (sd->version < 3)
                sd->version = 3;
        }
    }

    for (i = 0; i < sk_CMS_RevocationInfoChoice_num(sd->crls); i++) {
        rch = sk_CMS_RevocationInfoChoice_value(sd->crls, i);
        if (rch->type == CMS_REVCHOICE_OTHER) {
            if (sd->version < 5)
                sd->version = 5;
        }
    }

    if ((OBJ_obj2nid(sd->encapContentInfo->eContentType) != NID_pkcs7_data)
        && (sd->version < 3))
        sd->version = 3;

    for (i = 0; i < sk_CMS_SignerInfo_num(sd->signerInfos); i++) {
        si = sk_CMS_SignerInfo_value(sd->signerInfos, i);
        if (si->sid->type == CMS_SIGNERINFO_KEYIDENTIFIER) {
            if (si->version < 3)
                si->version = 3;
            if (sd->version < 3)
                sd->version = 3;
        } else if (si->version < 1)
            si->version = 1;
    }

    if (sd->version < 1)
        sd->version = 1;

}

/* Copy an existing messageDigest value */

static int cms_copy_messageDigest(CMS_ContentInfo *cms, CMS_SignerInfo *si)
{
    STACK_OF(CMS_SignerInfo) *sinfos;
    CMS_SignerInfo *sitmp;
    int i;
    sinfos = CMS_get0_SignerInfos(cms);
    for (i = 0; i < sk_CMS_SignerInfo_num(sinfos); i++) {
        ASN1_OCTET_STRING *messageDigest;
        sitmp = sk_CMS_SignerInfo_value(sinfos, i);
        if (sitmp == si)
            continue;
        if (CMS_signed_get_attr_count(sitmp) < 0)
            continue;
        if (OBJ_cmp(si->digestAlgorithm->algorithm,
                    sitmp->digestAlgorithm->algorithm))
            continue;
        messageDigest = CMS_signed_get0_data_by_OBJ(sitmp,
                                                    OBJ_nid2obj
                                                    (NID_pkcs9_messageDigest),
                                                    -3, V_ASN1_OCTET_STRING);
        if (!messageDigest) {
            CMSerr(CMS_F_CMS_COPY_MESSAGEDIGEST,
                   CMS_R_ERROR_READING_MESSAGEDIGEST_ATTRIBUTE);
            return 0;
        }

        if (CMS_signed_add1_attr_by_NID(si, NID_pkcs9_messageDigest,
                                        V_ASN1_OCTET_STRING,
                                        messageDigest, -1))
            return 1;
        else
            return 0;
    }
    CMSerr(CMS_F_CMS_COPY_MESSAGEDIGEST, CMS_R_NO_MATCHING_DIGEST);
    return 0;
}

int cms_set1_SignerIdentifier(CMS_SignerIdentifier *sid, X509 *cert, int type)
{
    switch (type) {
    case CMS_SIGNERINFO_ISSUER_SERIAL:
        if (!cms_set1_ias(&sid->d.issuerAndSerialNumber, cert))
            return 0;
        break;

    case CMS_SIGNERINFO_KEYIDENTIFIER:
        if (!cms_set1_keyid(&sid->d.subjectKeyIdentifier, cert))
            return 0;
        break;

    default:
        CMSerr(CMS_F_CMS_SET1_SIGNERIDENTIFIER, CMS_R_UNKNOWN_ID);
        return 0;
    }

    sid->type = type;

    return 1;
}

int cms_SignerIdentifier_get0_signer_id(CMS_SignerIdentifier *sid,
                                        ASN1_OCTET_STRING **keyid,
                                        X509_NAME **issuer,
                                        ASN1_INTEGER **sno)
{
    if (sid->type == CMS_SIGNERINFO_ISSUER_SERIAL) {
        if (issuer)
            *issuer = sid->d.issuerAndSerialNumber->issuer;
        if (sno)
            *sno = sid->d.issuerAndSerialNumber->serialNumber;
    } else if (sid->type == CMS_SIGNERINFO_KEYIDENTIFIER) {
        if (keyid)
            *keyid = sid->d.subjectKeyIdentifier;
    } else
        return 0;
    return 1;
}

int cms_SignerIdentifier_cert_cmp(CMS_SignerIdentifier *sid, X509 *cert)
{
    if (sid->type == CMS_SIGNERINFO_ISSUER_SERIAL)
        return cms_ias_cert_cmp(sid->d.issuerAndSerialNumber, cert);
    else if (sid->type == CMS_SIGNERINFO_KEYIDENTIFIER)
        return cms_keyid_cert_cmp(sid->d.subjectKeyIdentifier, cert);
    else
        return -1;
}

static int cms_sd_asn1_ctrl(CMS_SignerInfo *si, int cmd)
{
    EVP_PKEY *pkey = si->pkey;
    int i;
    if (!pkey->ameth || !pkey->ameth->pkey_ctrl)
        return 1;
    i = pkey->ameth->pkey_ctrl(pkey, ASN1_PKEY_CTRL_CMS_SIGN, cmd, si);
    if (i == -2) {
        CMSerr(CMS_F_CMS_SD_ASN1_CTRL, CMS_R_NOT_SUPPORTED_FOR_THIS_KEY_TYPE);
        return 0;
    }
    if (i <= 0) {
        CMSerr(CMS_F_CMS_SD_ASN1_CTRL, CMS_R_CTRL_FAILURE);
        return 0;
    }
    return 1;
}

CMS_SignerInfo *CMS_add1_signer(CMS_ContentInfo *cms,
                                X509 *signer, EVP_PKEY *pk, const EVP_MD *md,
                                unsigned int flags)
{
    CMS_SignedData *sd;
    CMS_SignerInfo *si = NULL;
    X509_ALGOR *alg;
    int i, type;
    if (!X509_check_private_key(signer, pk)) {
        CMSerr(CMS_F_CMS_ADD1_SIGNER,
               CMS_R_PRIVATE_KEY_DOES_NOT_MATCH_CERTIFICATE);
        return NULL;
    }
    sd = cms_signed_data_init(cms);
    if (!sd)
        goto err;
    si = M_ASN1_new_of(CMS_SignerInfo);
    if (!si)
        goto merr;
    X509_check_purpose(signer, -1, -1);

    CRYPTO_add(&pk->references, 1, CRYPTO_LOCK_EVP_PKEY);
    CRYPTO_add(&signer->references, 1, CRYPTO_LOCK_X509);

    si->pkey = pk;
    si->signer = signer;
    EVP_MD_CTX_init(&si->mctx);
    si->pctx = NULL;

    if (flags & CMS_USE_KEYID) {
        si->version = 3;
        if (sd->version < 3)
            sd->version = 3;
        type = CMS_SIGNERINFO_KEYIDENTIFIER;
    } else {
        type = CMS_SIGNERINFO_ISSUER_SERIAL;
        si->version = 1;
    }

    if (!cms_set1_SignerIdentifier(si->sid, signer, type))
        goto err;

    if (md == NULL) {
        int def_nid;
        if (EVP_PKEY_get_default_digest_nid(pk, &def_nid) <= 0)
            goto err;
        md = EVP_get_digestbynid(def_nid);
        if (md == NULL) {
            CMSerr(CMS_F_CMS_ADD1_SIGNER, CMS_R_NO_DEFAULT_DIGEST);
            goto err;
        }
    }

    if (!md) {
        CMSerr(CMS_F_CMS_ADD1_SIGNER, CMS_R_NO_DIGEST_SET);
        goto err;
    }

    cms_DigestAlgorithm_set(si->digestAlgorithm, md);

    /* See if digest is present in digestAlgorithms */
    for (i = 0; i < sk_X509_ALGOR_num(sd->digestAlgorithms); i++) {
        ASN1_OBJECT *aoid;
        alg = sk_X509_ALGOR_value(sd->digestAlgorithms, i);
        X509_ALGOR_get0(&aoid, NULL, NULL, alg);
        if (OBJ_obj2nid(aoid) == EVP_MD_type(md))
            break;
    }

    if (i == sk_X509_ALGOR_num(sd->digestAlgorithms)) {
        alg = X509_ALGOR_new();
        if (!alg)
            goto merr;
        cms_DigestAlgorithm_set(alg, md);
        if (!sk_X509_ALGOR_push(sd->digestAlgorithms, alg)) {
            X509_ALGOR_free(alg);
            goto merr;
        }
    }

    if (!(flags & CMS_KEY_PARAM) && !cms_sd_asn1_ctrl(si, 0))
        goto err;
    if (!(flags & CMS_NOATTR)) {
        /*
         * Initialialize signed attributes strutucture so other attributes
         * such as signing time etc are added later even if we add none here.
         */
        if (!si->signedAttrs) {
            si->signedAttrs = sk_X509_ATTRIBUTE_new_null();
            if (!si->signedAttrs)
                goto merr;
        }

        if (!(flags & CMS_NOSMIMECAP)) {
            STACK_OF(X509_ALGOR) *smcap = NULL;
            i = CMS_add_standard_smimecap(&smcap);
            if (i)
                i = CMS_add_smimecap(si, smcap);
            sk_X509_ALGOR_pop_free(smcap, X509_ALGOR_free);
            if (!i)
                goto merr;
        }
        if (flags & CMS_REUSE_DIGEST) {
            if (!cms_copy_messageDigest(cms, si))
                goto err;
            if (!(flags & (CMS_PARTIAL | CMS_KEY_PARAM)) &&
                !CMS_SignerInfo_sign(si))
                goto err;
        }
    }

    if (!(flags & CMS_NOCERTS)) {
        /* NB ignore -1 return for duplicate cert */
        if (!CMS_add1_cert(cms, signer))
            goto merr;
    }

    if (flags & CMS_KEY_PARAM) {
        if (flags & CMS_NOATTR) {
            si->pctx = EVP_PKEY_CTX_new(si->pkey, NULL);
            if (!si->pctx)
                goto err;
            if (EVP_PKEY_sign_init(si->pctx) <= 0)
                goto err;
            if (EVP_PKEY_CTX_set_signature_md(si->pctx, md) <= 0)
                goto err;
        } else if (EVP_DigestSignInit(&si->mctx, &si->pctx, md, NULL, pk) <=
                   0)
            goto err;
    }

    if (!sd->signerInfos)
        sd->signerInfos = sk_CMS_SignerInfo_new_null();
    if (!sd->signerInfos || !sk_CMS_SignerInfo_push(sd->signerInfos, si))
        goto merr;

    return si;

 merr:
    CMSerr(CMS_F_CMS_ADD1_SIGNER, ERR_R_MALLOC_FAILURE);
 err:
    if (si)
        M_ASN1_free_of(si, CMS_SignerInfo);
    return NULL;

}

static int cms_add1_signingTime(CMS_SignerInfo *si, ASN1_TIME *t)
{
    ASN1_TIME *tt;
    int r = 0;
    if (t)
        tt = t;
    else
        tt = X509_gmtime_adj(NULL, 0);

    if (!tt)
        goto merr;

    if (CMS_signed_add1_attr_by_NID(si, NID_pkcs9_signingTime,
                                    tt->type, tt, -1) <= 0)
        goto merr;

    r = 1;

 merr:

    if (!t)
        ASN1_TIME_free(tt);

    if (!r)
        CMSerr(CMS_F_CMS_ADD1_SIGNINGTIME, ERR_R_MALLOC_FAILURE);

    return r;

}

EVP_PKEY_CTX *CMS_SignerInfo_get0_pkey_ctx(CMS_SignerInfo *si)
{
    return si->pctx;
}

EVP_MD_CTX *CMS_SignerInfo_get0_md_ctx(CMS_SignerInfo *si)
{
    return &si->mctx;
}

STACK_OF(CMS_SignerInfo) *CMS_get0_SignerInfos(CMS_ContentInfo *cms)
{
    CMS_SignedData *sd;
    sd = cms_get0_signed(cms);
    if (!sd)
        return NULL;
    return sd->signerInfos;
}

STACK_OF(X509) *CMS_get0_signers(CMS_ContentInfo *cms)
{
    STACK_OF(X509) *signers = NULL;
    STACK_OF(CMS_SignerInfo) *sinfos;
    CMS_SignerInfo *si;
    int i;
    sinfos = CMS_get0_SignerInfos(cms);
    for (i = 0; i < sk_CMS_SignerInfo_num(sinfos); i++) {
        si = sk_CMS_SignerInfo_value(sinfos, i);
        if (si->signer) {
            if (!signers) {
                signers = sk_X509_new_null();
                if (!signers)
                    return NULL;
            }
            if (!sk_X509_push(signers, si->signer)) {
                sk_X509_free(signers);
                return NULL;
            }
        }
    }
    return signers;
}

void CMS_SignerInfo_set1_signer_cert(CMS_SignerInfo *si, X509 *signer)
{
    if (signer) {
        CRYPTO_add(&signer->references, 1, CRYPTO_LOCK_X509);
        if (si->pkey)
            EVP_PKEY_free(si->pkey);
        si->pkey = X509_get_pubkey(signer);
    }
    if (si->signer)
        X509_free(si->signer);
    si->signer = signer;
}

int CMS_SignerInfo_get0_signer_id(CMS_SignerInfo *si,
                                  ASN1_OCTET_STRING **keyid,
                                  X509_NAME **issuer, ASN1_INTEGER **sno)
{
    return cms_SignerIdentifier_get0_signer_id(si->sid, keyid, issuer, sno);
}

int CMS_SignerInfo_cert_cmp(CMS_SignerInfo *si, X509 *cert)
{
    return cms_SignerIdentifier_cert_cmp(si->sid, cert);
}

int CMS_set1_signers_certs(CMS_ContentInfo *cms, STACK_OF(X509) *scerts,
                           unsigned int flags)
{
    CMS_SignedData *sd;
    CMS_SignerInfo *si;
    CMS_CertificateChoices *cch;
    STACK_OF(CMS_CertificateChoices) *certs;
    X509 *x;
    int i, j;
    int ret = 0;
    sd = cms_get0_signed(cms);
    if (!sd)
        return -1;
    certs = sd->certificates;
    for (i = 0; i < sk_CMS_SignerInfo_num(sd->signerInfos); i++) {
        si = sk_CMS_SignerInfo_value(sd->signerInfos, i);
        if (si->signer)
            continue;

        for (j = 0; j < sk_X509_num(scerts); j++) {
            x = sk_X509_value(scerts, j);
            if (CMS_SignerInfo_cert_cmp(si, x) == 0) {
                CMS_SignerInfo_set1_signer_cert(si, x);
                ret++;
                break;
            }
        }

        if (si->signer || (flags & CMS_NOINTERN))
            continue;

        for (j = 0; j < sk_CMS_CertificateChoices_num(certs); j++) {
            cch = sk_CMS_CertificateChoices_value(certs, j);
            if (cch->type != 0)
                continue;
            x = cch->d.certificate;
            if (CMS_SignerInfo_cert_cmp(si, x) == 0) {
                CMS_SignerInfo_set1_signer_cert(si, x);
                ret++;
                break;
            }
        }
    }
    return ret;
}

void CMS_SignerInfo_get0_algs(CMS_SignerInfo *si, EVP_PKEY **pk,
                              X509 **signer, X509_ALGOR **pdig,
                              X509_ALGOR **psig)
{
    if (pk)
        *pk = si->pkey;
    if (signer)
        *signer = si->signer;
    if (pdig)
        *pdig = si->digestAlgorithm;
    if (psig)
        *psig = si->signatureAlgorithm;
}

ASN1_OCTET_STRING *CMS_SignerInfo_get0_signature(CMS_SignerInfo *si)
{
    return si->signature;
}

static int cms_SignerInfo_content_sign(CMS_ContentInfo *cms,
                                       CMS_SignerInfo *si, BIO *chain)
{
    EVP_MD_CTX mctx;
    int r = 0;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_MD_CTX_init(&mctx);

    if (!si->pkey) {
        CMSerr(CMS_F_CMS_SIGNERINFO_CONTENT_SIGN, CMS_R_NO_PRIVATE_KEY);
        return 0;
    }

    if (!cms_DigestAlgorithm_find_ctx(&mctx, chain, si->digestAlgorithm))
        goto err;
    /* Set SignerInfo algortihm details if we used custom parametsr */
    if (si->pctx && !cms_sd_asn1_ctrl(si, 0))
        goto err;

    /*
     * If any signed attributes calculate and add messageDigest attribute
     */

    if (CMS_signed_get_attr_count(si) >= 0) {
        ASN1_OBJECT *ctype =
            cms->d.signedData->encapContentInfo->eContentType;
        unsigned char md[EVP_MAX_MD_SIZE];
        unsigned int mdlen;
        if (!EVP_DigestFinal_ex(&mctx, md, &mdlen))
            goto err;
        if (!CMS_signed_add1_attr_by_NID(si, NID_pkcs9_messageDigest,
                                         V_ASN1_OCTET_STRING, md, mdlen))
            goto err;
        /* Copy content type across */
        if (CMS_signed_add1_attr_by_NID(si, NID_pkcs9_contentType,
                                        V_ASN1_OBJECT, ctype, -1) <= 0)
            goto err;
        if (!CMS_SignerInfo_sign(si))
            goto err;
    } else if (si->pctx) {
        unsigned char *sig;
        size_t siglen;
        unsigned char md[EVP_MAX_MD_SIZE];
        unsigned int mdlen;
        pctx = si->pctx;
        if (!EVP_DigestFinal_ex(&mctx, md, &mdlen))
            goto err;
        siglen = EVP_PKEY_size(si->pkey);
        sig = OPENSSL_malloc(siglen);
        if (!sig) {
            CMSerr(CMS_F_CMS_SIGNERINFO_CONTENT_SIGN, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        if (EVP_PKEY_sign(pctx, sig, &siglen, md, mdlen) <= 0)
            goto err;
        ASN1_STRING_set0(si->signature, sig, siglen);
    } else {
        unsigned char *sig;
        unsigned int siglen;
        sig = OPENSSL_malloc(EVP_PKEY_size(si->pkey));
        if (!sig) {
            CMSerr(CMS_F_CMS_SIGNERINFO_CONTENT_SIGN, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        if (!EVP_SignFinal(&mctx, sig, &siglen, si->pkey)) {
            CMSerr(CMS_F_CMS_SIGNERINFO_CONTENT_SIGN, CMS_R_SIGNFINAL_ERROR);
            OPENSSL_free(sig);
            goto err;
        }
        ASN1_STRING_set0(si->signature, sig, siglen);
    }

    r = 1;

 err:
    EVP_MD_CTX_cleanup(&mctx);
    if (pctx)
        EVP_PKEY_CTX_free(pctx);
    return r;

}

int cms_SignedData_final(CMS_ContentInfo *cms, BIO *chain)
{
    STACK_OF(CMS_SignerInfo) *sinfos;
    CMS_SignerInfo *si;
    int i;
    sinfos = CMS_get0_SignerInfos(cms);
    for (i = 0; i < sk_CMS_SignerInfo_num(sinfos); i++) {
        si = sk_CMS_SignerInfo_value(sinfos, i);
        if (!cms_SignerInfo_content_sign(cms, si, chain))
            return 0;
    }
    cms->d.signedData->encapContentInfo->partial = 0;
    return 1;
}

int CMS_SignerInfo_sign(CMS_SignerInfo *si)
{
    EVP_MD_CTX *mctx = &si->mctx;
    EVP_PKEY_CTX *pctx;
    unsigned char *abuf = NULL;
    int alen;
    size_t siglen;
    const EVP_MD *md = NULL;

    md = EVP_get_digestbyobj(si->digestAlgorithm->algorithm);
    if (md == NULL)
        return 0;

    if (CMS_signed_get_attr_by_NID(si, NID_pkcs9_signingTime, -1) < 0) {
        if (!cms_add1_signingTime(si, NULL))
            goto err;
    }

    if (si->pctx)
        pctx = si->pctx;
    else {
        EVP_MD_CTX_init(mctx);
        if (EVP_DigestSignInit(mctx, &pctx, md, NULL, si->pkey) <= 0)
            goto err;
    }

    if (EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_SIGN,
                          EVP_PKEY_CTRL_CMS_SIGN, 0, si) <= 0) {
        CMSerr(CMS_F_CMS_SIGNERINFO_SIGN, CMS_R_CTRL_ERROR);
        goto err;
    }

    alen = ASN1_item_i2d((ASN1_VALUE *)si->signedAttrs, &abuf,
                         ASN1_ITEM_rptr(CMS_Attributes_Sign));
    if (!abuf)
        goto err;
    if (EVP_DigestSignUpdate(mctx, abuf, alen) <= 0)
        goto err;
    if (EVP_DigestSignFinal(mctx, NULL, &siglen) <= 0)
        goto err;
    OPENSSL_free(abuf);
    abuf = OPENSSL_malloc(siglen);
    if (!abuf)
        goto err;
    if (EVP_DigestSignFinal(mctx, abuf, &siglen) <= 0)
        goto err;

    if (EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_SIGN,
                          EVP_PKEY_CTRL_CMS_SIGN, 1, si) <= 0) {
        CMSerr(CMS_F_CMS_SIGNERINFO_SIGN, CMS_R_CTRL_ERROR);
        goto err;
    }

    EVP_MD_CTX_cleanup(mctx);

    ASN1_STRING_set0(si->signature, abuf, siglen);

    return 1;

 err:
    if (abuf)
        OPENSSL_free(abuf);
    EVP_MD_CTX_cleanup(mctx);
    return 0;

}

int CMS_SignerInfo_verify(CMS_SignerInfo *si)
{
    EVP_MD_CTX *mctx = &si->mctx;
    unsigned char *abuf = NULL;
    int alen, r = -1;
    const EVP_MD *md = NULL;

    if (!si->pkey) {
        CMSerr(CMS_F_CMS_SIGNERINFO_VERIFY, CMS_R_NO_PUBLIC_KEY);
        return -1;
    }

    md = EVP_get_digestbyobj(si->digestAlgorithm->algorithm);
    if (md == NULL)
        return -1;
    EVP_MD_CTX_init(mctx);
    if (EVP_DigestVerifyInit(mctx, &si->pctx, md, NULL, si->pkey) <= 0)
        goto err;

    if (!cms_sd_asn1_ctrl(si, 1))
        goto err;

    alen = ASN1_item_i2d((ASN1_VALUE *)si->signedAttrs, &abuf,
                         ASN1_ITEM_rptr(CMS_Attributes_Verify));
    if (!abuf)
        goto err;
    r = EVP_DigestVerifyUpdate(mctx, abuf, alen);
    OPENSSL_free(abuf);
    if (r <= 0) {
        r = -1;
        goto err;
    }
    r = EVP_DigestVerifyFinal(mctx,
                              si->signature->data, si->signature->length);
    if (r <= 0)
        CMSerr(CMS_F_CMS_SIGNERINFO_VERIFY, CMS_R_VERIFICATION_FAILURE);
 err:
    EVP_MD_CTX_cleanup(mctx);
    return r;
}

/* Create a chain of digest BIOs from a CMS ContentInfo */

BIO *cms_SignedData_init_bio(CMS_ContentInfo *cms)
{
    int i;
    CMS_SignedData *sd;
    BIO *chain = NULL;
    sd = cms_get0_signed(cms);
    if (!sd)
        return NULL;
    if (cms->d.signedData->encapContentInfo->partial)
        cms_sd_set_version(sd);
    for (i = 0; i < sk_X509_ALGOR_num(sd->digestAlgorithms); i++) {
        X509_ALGOR *digestAlgorithm;
        BIO *mdbio;
        digestAlgorithm = sk_X509_ALGOR_value(sd->digestAlgorithms, i);
        mdbio = cms_DigestAlgorithm_init_bio(digestAlgorithm);
        if (!mdbio)
            goto err;
        if (chain)
            BIO_push(chain, mdbio);
        else
            chain = mdbio;
    }
    return chain;
 err:
    if (chain)
        BIO_free_all(chain);
    return NULL;
}

int CMS_SignerInfo_verify_content(CMS_SignerInfo *si, BIO *chain)
{
    ASN1_OCTET_STRING *os = NULL;
    EVP_MD_CTX mctx;
    EVP_PKEY_CTX *pkctx = NULL;
    int r = -1;
    unsigned char mval[EVP_MAX_MD_SIZE];
    unsigned int mlen;
    EVP_MD_CTX_init(&mctx);
    /* If we have any signed attributes look for messageDigest value */
    if (CMS_signed_get_attr_count(si) >= 0) {
        os = CMS_signed_get0_data_by_OBJ(si,
                                         OBJ_nid2obj(NID_pkcs9_messageDigest),
                                         -3, V_ASN1_OCTET_STRING);
        if (!os) {
            CMSerr(CMS_F_CMS_SIGNERINFO_VERIFY_CONTENT,
                   CMS_R_ERROR_READING_MESSAGEDIGEST_ATTRIBUTE);
            goto err;
        }
    }

    if (!cms_DigestAlgorithm_find_ctx(&mctx, chain, si->digestAlgorithm))
        goto err;

    if (EVP_DigestFinal_ex(&mctx, mval, &mlen) <= 0) {
        CMSerr(CMS_F_CMS_SIGNERINFO_VERIFY_CONTENT,
               CMS_R_UNABLE_TO_FINALIZE_CONTEXT);
        goto err;
    }

    /* If messageDigest found compare it */

    if (os) {
        if (mlen != (unsigned int)os->length) {
            CMSerr(CMS_F_CMS_SIGNERINFO_VERIFY_CONTENT,
                   CMS_R_MESSAGEDIGEST_ATTRIBUTE_WRONG_LENGTH);
            goto err;
        }

        if (memcmp(mval, os->data, mlen)) {
            CMSerr(CMS_F_CMS_SIGNERINFO_VERIFY_CONTENT,
                   CMS_R_VERIFICATION_FAILURE);
            r = 0;
        } else
            r = 1;
    } else {
        const EVP_MD *md = EVP_MD_CTX_md(&mctx);
        pkctx = EVP_PKEY_CTX_new(si->pkey, NULL);
        if (pkctx == NULL)
            goto err;
        if (EVP_PKEY_verify_init(pkctx) <= 0)
            goto err;
        if (EVP_PKEY_CTX_set_signature_md(pkctx, md) <= 0)
            goto err;
        si->pctx = pkctx;
        if (!cms_sd_asn1_ctrl(si, 1))
            goto err;
        r = EVP_PKEY_verify(pkctx, si->signature->data,
                            si->signature->length, mval, mlen);
        if (r <= 0) {
            CMSerr(CMS_F_CMS_SIGNERINFO_VERIFY_CONTENT,
                   CMS_R_VERIFICATION_FAILURE);
            r = 0;
        }
    }

 err:
    if (pkctx)
        EVP_PKEY_CTX_free(pkctx);
    EVP_MD_CTX_cleanup(&mctx);
    return r;

}

int CMS_add_smimecap(CMS_SignerInfo *si, STACK_OF(X509_ALGOR) *algs)
{
    unsigned char *smder = NULL;
    int smderlen, r;
    smderlen = i2d_X509_ALGORS(algs, &smder);
    if (smderlen <= 0)
        return 0;
    r = CMS_signed_add1_attr_by_NID(si, NID_SMIMECapabilities,
                                    V_ASN1_SEQUENCE, smder, smderlen);
    OPENSSL_free(smder);
    return r;
}

int CMS_add_simple_smimecap(STACK_OF(X509_ALGOR) **algs,
                            int algnid, int keysize)
{
    X509_ALGOR *alg;
    ASN1_INTEGER *key = NULL;
    if (keysize > 0) {
        key = ASN1_INTEGER_new();
        if (!key || !ASN1_INTEGER_set(key, keysize))
            return 0;
    }
    alg = X509_ALGOR_new();
    if (!alg) {
        if (key)
            ASN1_INTEGER_free(key);
        return 0;
    }

    X509_ALGOR_set0(alg, OBJ_nid2obj(algnid),
                    key ? V_ASN1_INTEGER : V_ASN1_UNDEF, key);
    if (!*algs)
        *algs = sk_X509_ALGOR_new_null();
    if (!*algs || !sk_X509_ALGOR_push(*algs, alg)) {
        X509_ALGOR_free(alg);
        return 0;
    }
    return 1;
}

/* Check to see if a cipher exists and if so add S/MIME capabilities */

static int cms_add_cipher_smcap(STACK_OF(X509_ALGOR) **sk, int nid, int arg)
{
    if (EVP_get_cipherbynid(nid))
        return CMS_add_simple_smimecap(sk, nid, arg);
    return 1;
}

static int cms_add_digest_smcap(STACK_OF(X509_ALGOR) **sk, int nid, int arg)
{
    if (EVP_get_digestbynid(nid))
        return CMS_add_simple_smimecap(sk, nid, arg);
    return 1;
}

int CMS_add_standard_smimecap(STACK_OF(X509_ALGOR) **smcap)
{
    if (!cms_add_cipher_smcap(smcap, NID_aes_256_cbc, -1)
        || !cms_add_digest_smcap(smcap, NID_id_GostR3411_94, -1)
        || !cms_add_cipher_smcap(smcap, NID_id_Gost28147_89, -1)
        || !cms_add_cipher_smcap(smcap, NID_aes_192_cbc, -1)
        || !cms_add_cipher_smcap(smcap, NID_aes_128_cbc, -1)
        || !cms_add_cipher_smcap(smcap, NID_des_ede3_cbc, -1)
        || !cms_add_cipher_smcap(smcap, NID_rc2_cbc, 128)
        || !cms_add_cipher_smcap(smcap, NID_rc2_cbc, 64)
        || !cms_add_cipher_smcap(smcap, NID_des_cbc, -1)
        || !cms_add_cipher_smcap(smcap, NID_rc2_cbc, 40))
        return 0;
    return 1;
}
/* crypto/cms/cms_smime.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project.
 */
/* ====================================================================
 * Copyright (c) 2008 The OpenSSL Project.  All rights reserved.
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
 */

// #include "cryptlib.h"
// #include "asn1t.h"
// #include "x509.h"
// #include "x509v3.h"
// #include "err.h"
// #include "cms.h"
// #include "cms_lcl.h"
// #include "asn1_locl.h"

static int cms_copy_content(BIO *out, BIO *in, unsigned int flags)
{
    unsigned char buf[4096];
    int r = 0, i;
    BIO *tmpout = NULL;

    if (out == NULL)
        tmpout = BIO_new(BIO_s_null());
    else if (flags & CMS_TEXT) {
        tmpout = BIO_new(BIO_s_mem());
        BIO_set_mem_eof_return(tmpout, 0);
    } else
        tmpout = out;

    if (!tmpout) {
        CMSerr(CMS_F_CMS_COPY_CONTENT, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    /* Read all content through chain to process digest, decrypt etc */
    for (;;) {
        i = BIO_read(in, buf, sizeof(buf));
        if (i <= 0) {
            if (BIO_method_type(in) == BIO_TYPE_CIPHER) {
                if (!BIO_get_cipher_status(in))
                    goto err;
            }
            if (i < 0)
                goto err;
            break;
        }

        if (tmpout && (BIO_write(tmpout, buf, i) != i))
            goto err;
    }

    if (flags & CMS_TEXT) {
        if (!SMIME_text(tmpout, out)) {
            CMSerr(CMS_F_CMS_COPY_CONTENT, CMS_R_SMIME_TEXT_ERROR);
            goto err;
        }
    }

    r = 1;

 err:
    if (tmpout && (tmpout != out))
        BIO_free(tmpout);
    return r;

}

static int check_content(CMS_ContentInfo *cms)
{
    ASN1_OCTET_STRING **pos = CMS_get0_content(cms);
    if (!pos || !*pos) {
        CMSerr(CMS_F_CHECK_CONTENT, CMS_R_NO_CONTENT);
        return 0;
    }
    return 1;
}

static void do_free_upto(BIO *f, BIO *upto)
{
    if (upto) {
        BIO *tbio;
        do {
            tbio = BIO_pop(f);
            BIO_free(f);
            f = tbio;
        }
        while (f && f != upto);
    } else
        BIO_free_all(f);
}

int CMS_data(CMS_ContentInfo *cms, BIO *out, unsigned int flags)
{
    BIO *cont;
    int r;
    if (OBJ_obj2nid(CMS_get0_type(cms)) != NID_pkcs7_data) {
        CMSerr(CMS_F_CMS_DATA, CMS_R_TYPE_NOT_DATA);
        return 0;
    }
    cont = CMS_dataInit(cms, NULL);
    if (!cont)
        return 0;
    r = cms_copy_content(out, cont, flags);
    BIO_free_all(cont);
    return r;
}

CMS_ContentInfo *CMS_data_create(BIO *in, unsigned int flags)
{
    CMS_ContentInfo *cms;
    cms = cms_Data_create();
    if (!cms)
        return NULL;

    if ((flags & CMS_STREAM) || CMS_final(cms, in, NULL, flags))
        return cms;

    CMS_ContentInfo_free(cms);

    return NULL;
}

int CMS_digest_verify(CMS_ContentInfo *cms, BIO *dcont, BIO *out,
                      unsigned int flags)
{
    BIO *cont;
    int r;
    if (OBJ_obj2nid(CMS_get0_type(cms)) != NID_pkcs7_digest) {
        CMSerr(CMS_F_CMS_DIGEST_VERIFY, CMS_R_TYPE_NOT_DIGESTED_DATA);
        return 0;
    }

    if (!dcont && !check_content(cms))
        return 0;

    cont = CMS_dataInit(cms, dcont);
    if (!cont)
        return 0;
    r = cms_copy_content(out, cont, flags);
    if (r)
        r = cms_DigestedData_do_final(cms, cont, 1);
    do_free_upto(cont, dcont);
    return r;
}

CMS_ContentInfo *CMS_digest_create(BIO *in, const EVP_MD *md,
                                   unsigned int flags)
{
    CMS_ContentInfo *cms;
    if (!md)
        md = EVP_sha1();
    cms = cms_DigestedData_create(md);
    if (!cms)
        return NULL;

    if (!(flags & CMS_DETACHED))
        CMS_set_detached(cms, 0);

    if ((flags & CMS_STREAM) || CMS_final(cms, in, NULL, flags))
        return cms;

    CMS_ContentInfo_free(cms);
    return NULL;
}

int CMS_EncryptedData_decrypt(CMS_ContentInfo *cms,
                              const unsigned char *key, size_t keylen,
                              BIO *dcont, BIO *out, unsigned int flags)
{
    BIO *cont;
    int r;
    if (OBJ_obj2nid(CMS_get0_type(cms)) != NID_pkcs7_encrypted) {
        CMSerr(CMS_F_CMS_ENCRYPTEDDATA_DECRYPT,
               CMS_R_TYPE_NOT_ENCRYPTED_DATA);
        return 0;
    }

    if (!dcont && !check_content(cms))
        return 0;

    if (CMS_EncryptedData_set1_key(cms, NULL, key, keylen) <= 0)
        return 0;
    cont = CMS_dataInit(cms, dcont);
    if (!cont)
        return 0;
    r = cms_copy_content(out, cont, flags);
    do_free_upto(cont, dcont);
    return r;
}

CMS_ContentInfo *CMS_EncryptedData_encrypt(BIO *in, const EVP_CIPHER *cipher,
                                           const unsigned char *key,
                                           size_t keylen, unsigned int flags)
{
    CMS_ContentInfo *cms;
    if (!cipher) {
        CMSerr(CMS_F_CMS_ENCRYPTEDDATA_ENCRYPT, CMS_R_NO_CIPHER);
        return NULL;
    }
    cms = CMS_ContentInfo_new();
    if (!cms)
        return NULL;
    if (!CMS_EncryptedData_set1_key(cms, cipher, key, keylen))
        return NULL;

    if (!(flags & CMS_DETACHED))
        CMS_set_detached(cms, 0);

    if ((flags & (CMS_STREAM | CMS_PARTIAL))
        || CMS_final(cms, in, NULL, flags))
        return cms;

    CMS_ContentInfo_free(cms);
    return NULL;
}

static int cms_signerinfo_verify_cert(CMS_SignerInfo *si,
                                      X509_STORE *store,
                                      STACK_OF(X509) *certs,
                                      STACK_OF(X509_CRL) *crls,
                                      unsigned int flags)
{
    X509_STORE_CTX ctx;
    X509 *signer;
    int i, j, r = 0;
    CMS_SignerInfo_get0_algs(si, NULL, &signer, NULL, NULL);
    if (!X509_STORE_CTX_init(&ctx, store, signer, certs)) {
        CMSerr(CMS_F_CMS_SIGNERINFO_VERIFY_CERT, CMS_R_STORE_INIT_ERROR);
        goto err;
    }
    X509_STORE_CTX_set_default(&ctx, "smime_sign");
    if (crls)
        X509_STORE_CTX_set0_crls(&ctx, crls);

    i = X509_verify_cert(&ctx);
    if (i <= 0) {
        j = X509_STORE_CTX_get_error(&ctx);
        CMSerr(CMS_F_CMS_SIGNERINFO_VERIFY_CERT,
               CMS_R_CERTIFICATE_VERIFY_ERROR);
        ERR_add_error_data(2, "Verify error:",
                           X509_verify_cert_error_string(j));
        goto err;
    }
    r = 1;
 err:
    X509_STORE_CTX_cleanup(&ctx);
    return r;

}

int CMS_verify(CMS_ContentInfo *cms, STACK_OF(X509) *certs,
               X509_STORE *store, BIO *dcont, BIO *out, unsigned int flags)
{
    CMS_SignerInfo *si;
    STACK_OF(CMS_SignerInfo) *sinfos;
    STACK_OF(X509) *cms_certs = NULL;
    STACK_OF(X509_CRL) *crls = NULL;
    X509 *signer;
    int i, scount = 0, ret = 0;
    BIO *cmsbio = NULL, *tmpin = NULL;

    if (!dcont && !check_content(cms))
        return 0;

    /* Attempt to find all signer certificates */

    sinfos = CMS_get0_SignerInfos(cms);

    if (sk_CMS_SignerInfo_num(sinfos) <= 0) {
        CMSerr(CMS_F_CMS_VERIFY, CMS_R_NO_SIGNERS);
        goto err;
    }

    for (i = 0; i < sk_CMS_SignerInfo_num(sinfos); i++) {
        si = sk_CMS_SignerInfo_value(sinfos, i);
        CMS_SignerInfo_get0_algs(si, NULL, &signer, NULL, NULL);
        if (signer)
            scount++;
    }

    if (scount != sk_CMS_SignerInfo_num(sinfos))
        scount += CMS_set1_signers_certs(cms, certs, flags);

    if (scount != sk_CMS_SignerInfo_num(sinfos)) {
        CMSerr(CMS_F_CMS_VERIFY, CMS_R_SIGNER_CERTIFICATE_NOT_FOUND);
        goto err;
    }

    /* Attempt to verify all signers certs */

    if (!(flags & CMS_NO_SIGNER_CERT_VERIFY)) {
        cms_certs = CMS_get1_certs(cms);
        if (!(flags & CMS_NOCRL))
            crls = CMS_get1_crls(cms);
        for (i = 0; i < sk_CMS_SignerInfo_num(sinfos); i++) {
            si = sk_CMS_SignerInfo_value(sinfos, i);
            if (!cms_signerinfo_verify_cert(si, store,
                                            cms_certs, crls, flags))
                goto err;
        }
    }

    /* Attempt to verify all SignerInfo signed attribute signatures */

    if (!(flags & CMS_NO_ATTR_VERIFY)) {
        for (i = 0; i < sk_CMS_SignerInfo_num(sinfos); i++) {
            si = sk_CMS_SignerInfo_value(sinfos, i);
            if (CMS_signed_get_attr_count(si) < 0)
                continue;
            if (CMS_SignerInfo_verify(si) <= 0)
                goto err;
        }
    }

    /*
     * Performance optimization: if the content is a memory BIO then store
     * its contents in a temporary read only memory BIO. This avoids
     * potentially large numbers of slow copies of data which will occur when
     * reading from a read write memory BIO when signatures are calculated.
     */

    if (dcont && (BIO_method_type(dcont) == BIO_TYPE_MEM)) {
        char *ptr;
        long len;
        len = BIO_get_mem_data(dcont, &ptr);
        tmpin = BIO_new_mem_buf(ptr, len);
        if (tmpin == NULL) {
            CMSerr(CMS_F_CMS_VERIFY, ERR_R_MALLOC_FAILURE);
            goto err2;
        }
    } else
        tmpin = dcont;

    cmsbio = CMS_dataInit(cms, tmpin);
    if (!cmsbio)
        goto err;

    if (!cms_copy_content(out, cmsbio, flags))
        goto err;

    if (!(flags & CMS_NO_CONTENT_VERIFY)) {
        for (i = 0; i < sk_CMS_SignerInfo_num(sinfos); i++) {
            si = sk_CMS_SignerInfo_value(sinfos, i);
            if (CMS_SignerInfo_verify_content(si, cmsbio) <= 0) {
                CMSerr(CMS_F_CMS_VERIFY, CMS_R_CONTENT_VERIFY_ERROR);
                goto err;
            }
        }
    }

    ret = 1;

 err:

    if (dcont && (tmpin == dcont))
        do_free_upto(cmsbio, dcont);
    else
        BIO_free_all(cmsbio);

 err2:
    if (cms_certs)
        sk_X509_pop_free(cms_certs, X509_free);
    if (crls)
        sk_X509_CRL_pop_free(crls, X509_CRL_free);

    return ret;
}

int CMS_verify_receipt(CMS_ContentInfo *rcms, CMS_ContentInfo *ocms,
                       STACK_OF(X509) *certs,
                       X509_STORE *store, unsigned int flags)
{
    int r;
    flags &= ~(CMS_DETACHED | CMS_TEXT);
    r = CMS_verify(rcms, certs, store, NULL, NULL, flags);
    if (r <= 0)
        return r;
    return cms_Receipt_verify(rcms, ocms);
}

CMS_ContentInfo *CMS_sign(X509 *signcert, EVP_PKEY *pkey,
                          STACK_OF(X509) *certs, BIO *data,
                          unsigned int flags)
{
    CMS_ContentInfo *cms;
    int i;

    cms = CMS_ContentInfo_new();
    if (!cms || !CMS_SignedData_init(cms))
        goto merr;

    if (pkey && !CMS_add1_signer(cms, signcert, pkey, NULL, flags)) {
        CMSerr(CMS_F_CMS_SIGN, CMS_R_ADD_SIGNER_ERROR);
        goto err;
    }

    for (i = 0; i < sk_X509_num(certs); i++) {
        X509 *x = sk_X509_value(certs, i);
        if (!CMS_add1_cert(cms, x))
            goto merr;
    }

    if (!(flags & CMS_DETACHED))
        CMS_set_detached(cms, 0);

    if ((flags & (CMS_STREAM | CMS_PARTIAL))
        || CMS_final(cms, data, NULL, flags))
        return cms;
    else
        goto err;

 merr:
    CMSerr(CMS_F_CMS_SIGN, ERR_R_MALLOC_FAILURE);

 err:
    if (cms)
        CMS_ContentInfo_free(cms);
    return NULL;
}

CMS_ContentInfo *CMS_sign_receipt(CMS_SignerInfo *si,
                                  X509 *signcert, EVP_PKEY *pkey,
                                  STACK_OF(X509) *certs, unsigned int flags)
{
    CMS_SignerInfo *rct_si;
    CMS_ContentInfo *cms = NULL;
    ASN1_OCTET_STRING **pos, *os;
    BIO *rct_cont = NULL;
    int r = 0;

    flags &= ~(CMS_STREAM | CMS_TEXT);
    /* Not really detached but avoids content being allocated */
    flags |= CMS_PARTIAL | CMS_BINARY | CMS_DETACHED;
    if (!pkey || !signcert) {
        CMSerr(CMS_F_CMS_SIGN_RECEIPT, CMS_R_NO_KEY_OR_CERT);
        return NULL;
    }

    /* Initialize signed data */

    cms = CMS_sign(NULL, NULL, certs, NULL, flags);
    if (!cms)
        goto err;

    /* Set inner content type to signed receipt */
    if (!CMS_set1_eContentType(cms, OBJ_nid2obj(NID_id_smime_ct_receipt)))
        goto err;

    rct_si = CMS_add1_signer(cms, signcert, pkey, NULL, flags);
    if (!rct_si) {
        CMSerr(CMS_F_CMS_SIGN_RECEIPT, CMS_R_ADD_SIGNER_ERROR);
        goto err;
    }

    os = cms_encode_Receipt(si);

    if (!os)
        goto err;

    /* Set content to digest */
    rct_cont = BIO_new_mem_buf(os->data, os->length);
    if (!rct_cont)
        goto err;

    /* Add msgSigDigest attribute */

    if (!cms_msgSigDigest_add1(rct_si, si))
        goto err;

    /* Finalize structure */
    if (!CMS_final(cms, rct_cont, NULL, flags))
        goto err;

    /* Set embedded content */
    pos = CMS_get0_content(cms);
    *pos = os;

    r = 1;

 err:
    if (rct_cont)
        BIO_free(rct_cont);
    if (r)
        return cms;
    CMS_ContentInfo_free(cms);
    return NULL;

}

CMS_ContentInfo *CMS_encrypt(STACK_OF(X509) *certs, BIO *data,
                             const EVP_CIPHER *cipher, unsigned int flags)
{
    CMS_ContentInfo *cms;
    int i;
    X509 *recip;
    cms = CMS_EnvelopedData_create(cipher);
    if (!cms)
        goto merr;
    for (i = 0; i < sk_X509_num(certs); i++) {
        recip = sk_X509_value(certs, i);
        if (!CMS_add1_recipient_cert(cms, recip, flags)) {
            CMSerr(CMS_F_CMS_ENCRYPT, CMS_R_RECIPIENT_ERROR);
            goto err;
        }
    }

    if (!(flags & CMS_DETACHED))
        CMS_set_detached(cms, 0);

    if ((flags & (CMS_STREAM | CMS_PARTIAL))
        || CMS_final(cms, data, NULL, flags))
        return cms;
    else
        goto err;

 merr:
    CMSerr(CMS_F_CMS_ENCRYPT, ERR_R_MALLOC_FAILURE);
 err:
    if (cms)
        CMS_ContentInfo_free(cms);
    return NULL;
}

static int cms_kari_set1_pkey(CMS_ContentInfo *cms, CMS_RecipientInfo *ri,
                              EVP_PKEY *pk, X509 *cert)
{
    int i;
    STACK_OF(CMS_RecipientEncryptedKey) *reks;
    CMS_RecipientEncryptedKey *rek;
    reks = CMS_RecipientInfo_kari_get0_reks(ri);
    if (!cert)
        return 0;
    for (i = 0; i < sk_CMS_RecipientEncryptedKey_num(reks); i++) {
        int rv;
        rek = sk_CMS_RecipientEncryptedKey_value(reks, i);
        if (CMS_RecipientEncryptedKey_cert_cmp(rek, cert))
            continue;
        CMS_RecipientInfo_kari_set0_pkey(ri, pk);
        rv = CMS_RecipientInfo_kari_decrypt(cms, ri, rek);
        CMS_RecipientInfo_kari_set0_pkey(ri, NULL);
        if (rv > 0)
            return 1;
        return -1;
    }
    return 0;
}

int CMS_decrypt_set1_pkey(CMS_ContentInfo *cms, EVP_PKEY *pk, X509 *cert)
{
    STACK_OF(CMS_RecipientInfo) *ris;
    CMS_RecipientInfo *ri;
    int i, r, ri_type;
    int debug = 0, match_ri = 0;
    ris = CMS_get0_RecipientInfos(cms);
    if (ris)
        debug = cms->d.envelopedData->encryptedContentInfo->debug;
    ri_type = cms_pkey_get_ri_type(pk);
    if (ri_type == CMS_RECIPINFO_NONE) {
        CMSerr(CMS_F_CMS_DECRYPT_SET1_PKEY,
               CMS_R_NOT_SUPPORTED_FOR_THIS_KEY_TYPE);
        return 0;
    }

    for (i = 0; i < sk_CMS_RecipientInfo_num(ris); i++) {
        ri = sk_CMS_RecipientInfo_value(ris, i);
        if (CMS_RecipientInfo_type(ri) != ri_type)
            continue;
        match_ri = 1;
        if (ri_type == CMS_RECIPINFO_AGREE) {
            r = cms_kari_set1_pkey(cms, ri, pk, cert);
            if (r > 0)
                return 1;
            if (r < 0)
                return 0;
        }
        /*
         * If we have a cert try matching RecipientInfo otherwise try them
         * all.
         */
        else if (!cert || !CMS_RecipientInfo_ktri_cert_cmp(ri, cert)) {
            CMS_RecipientInfo_set0_pkey(ri, pk);
            r = CMS_RecipientInfo_decrypt(cms, ri);
            CMS_RecipientInfo_set0_pkey(ri, NULL);
            if (cert) {
                /*
                 * If not debugging clear any error and return success to
                 * avoid leaking of information useful to MMA
                 */
                if (!debug) {
                    ERR_clear_error();
                    return 1;
                }
                if (r > 0)
                    return 1;
                CMSerr(CMS_F_CMS_DECRYPT_SET1_PKEY, CMS_R_DECRYPT_ERROR);
                return 0;
            }
            /*
             * If no cert and not debugging don't leave loop after first
             * successful decrypt. Always attempt to decrypt all recipients
             * to avoid leaking timing of a successful decrypt.
             */
            else if (r > 0 && debug)
                return 1;
        }
    }
    /* If no cert and not debugging always return success */
    if (match_ri && !cert && !debug) {
        ERR_clear_error();
        return 1;
    }

    CMSerr(CMS_F_CMS_DECRYPT_SET1_PKEY, CMS_R_NO_MATCHING_RECIPIENT);
    return 0;

}

int CMS_decrypt_set1_key(CMS_ContentInfo *cms,
                         unsigned char *key, size_t keylen,
                         unsigned char *id, size_t idlen)
{
    STACK_OF(CMS_RecipientInfo) *ris;
    CMS_RecipientInfo *ri;
    int i, r;
    ris = CMS_get0_RecipientInfos(cms);
    for (i = 0; i < sk_CMS_RecipientInfo_num(ris); i++) {
        ri = sk_CMS_RecipientInfo_value(ris, i);
        if (CMS_RecipientInfo_type(ri) != CMS_RECIPINFO_KEK)
            continue;

        /*
         * If we have an id try matching RecipientInfo otherwise try them
         * all.
         */
        if (!id || (CMS_RecipientInfo_kekri_id_cmp(ri, id, idlen) == 0)) {
            CMS_RecipientInfo_set0_key(ri, key, keylen);
            r = CMS_RecipientInfo_decrypt(cms, ri);
            CMS_RecipientInfo_set0_key(ri, NULL, 0);
            if (r > 0)
                return 1;
            if (id) {
                CMSerr(CMS_F_CMS_DECRYPT_SET1_KEY, CMS_R_DECRYPT_ERROR);
                return 0;
            }
            ERR_clear_error();
        }
    }

    CMSerr(CMS_F_CMS_DECRYPT_SET1_KEY, CMS_R_NO_MATCHING_RECIPIENT);
    return 0;

}

int CMS_decrypt_set1_password(CMS_ContentInfo *cms,
                              unsigned char *pass, ossl_ssize_t passlen)
{
    STACK_OF(CMS_RecipientInfo) *ris;
    CMS_RecipientInfo *ri;
    int i, r;
    ris = CMS_get0_RecipientInfos(cms);
    for (i = 0; i < sk_CMS_RecipientInfo_num(ris); i++) {
        ri = sk_CMS_RecipientInfo_value(ris, i);
        if (CMS_RecipientInfo_type(ri) != CMS_RECIPINFO_PASS)
            continue;
        CMS_RecipientInfo_set0_password(ri, pass, passlen);
        r = CMS_RecipientInfo_decrypt(cms, ri);
        CMS_RecipientInfo_set0_password(ri, NULL, 0);
        if (r > 0)
            return 1;
    }

    CMSerr(CMS_F_CMS_DECRYPT_SET1_PASSWORD, CMS_R_NO_MATCHING_RECIPIENT);
    return 0;

}

int CMS_decrypt(CMS_ContentInfo *cms, EVP_PKEY *pk, X509 *cert,
                BIO *dcont, BIO *out, unsigned int flags)
{
    int r;
    BIO *cont;
    if (OBJ_obj2nid(CMS_get0_type(cms)) != NID_pkcs7_enveloped) {
        CMSerr(CMS_F_CMS_DECRYPT, CMS_R_TYPE_NOT_ENVELOPED_DATA);
        return 0;
    }
    if (!dcont && !check_content(cms))
        return 0;
    if (flags & CMS_DEBUG_DECRYPT)
        cms->d.envelopedData->encryptedContentInfo->debug = 1;
    else
        cms->d.envelopedData->encryptedContentInfo->debug = 0;
    if (!pk && !cert && !dcont && !out)
        return 1;
    if (pk && !CMS_decrypt_set1_pkey(cms, pk, cert))
        return 0;
    cont = CMS_dataInit(cms, dcont);
    if (!cont)
        return 0;
    r = cms_copy_content(out, cont, flags);
    do_free_upto(cont, dcont);
    return r;
}

int CMS_final(CMS_ContentInfo *cms, BIO *data, BIO *dcont, unsigned int flags)
{
    BIO *cmsbio;
    int ret = 0;
    if (!(cmsbio = CMS_dataInit(cms, dcont))) {
        CMSerr(CMS_F_CMS_FINAL, CMS_R_CMS_LIB);
        return 0;
    }

    SMIME_crlf_copy(data, cmsbio, flags);

    (void)BIO_flush(cmsbio);

    if (!CMS_dataFinal(cms, cmsbio)) {
        CMSerr(CMS_F_CMS_FINAL, CMS_R_CMS_DATAFINAL_ERROR);
        goto err;
    }

    ret = 1;

 err:
    do_free_upto(cmsbio, dcont);

    return ret;

}

#ifdef ZLIB

int CMS_uncompress(CMS_ContentInfo *cms, BIO *dcont, BIO *out,
                   unsigned int flags)
{
    BIO *cont;
    int r;
    if (OBJ_obj2nid(CMS_get0_type(cms)) != NID_id_smime_ct_compressedData) {
        CMSerr(CMS_F_CMS_UNCOMPRESS, CMS_R_TYPE_NOT_COMPRESSED_DATA);
        return 0;
    }

    if (!dcont && !check_content(cms))
        return 0;

    cont = CMS_dataInit(cms, dcont);
    if (!cont)
        return 0;
    r = cms_copy_content(out, cont, flags);
    do_free_upto(cont, dcont);
    return r;
}

CMS_ContentInfo *CMS_compress(BIO *in, int comp_nid, unsigned int flags)
{
    CMS_ContentInfo *cms;
    if (comp_nid <= 0)
        comp_nid = NID_zlib_compression;
    cms = cms_CompressedData_create(comp_nid);
    if (!cms)
        return NULL;

    if (!(flags & CMS_DETACHED))
        CMS_set_detached(cms, 0);

    if ((flags & CMS_STREAM) || CMS_final(cms, in, NULL, flags))
        return cms;

    CMS_ContentInfo_free(cms);
    return NULL;
}

#else

int CMS_uncompress(CMS_ContentInfo *cms, BIO *dcont, BIO *out,
                   unsigned int flags)
{
    CMSerr(CMS_F_CMS_UNCOMPRESS, CMS_R_UNSUPPORTED_COMPRESSION_ALGORITHM);
    return 0;
}

CMS_ContentInfo *CMS_compress(BIO *in, int comp_nid, unsigned int flags)
{
    CMSerr(CMS_F_CMS_COMPRESS, CMS_R_UNSUPPORTED_COMPRESSION_ALGORITHM);
    return NULL;
}

#endif
