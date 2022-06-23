/* p12_add.c */
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
#include "cryptlib.h"
#include "pkcs12.h"

/* Pack an object into an OCTET STRING and turn into a safebag */

PKCS12_SAFEBAG *PKCS12_item_pack_safebag(void *obj, const ASN1_ITEM *it,
                                         int nid1, int nid2)
{
    PKCS12_BAGS *bag;
    PKCS12_SAFEBAG *safebag;
    if (!(bag = PKCS12_BAGS_new())) {
        PKCS12err(PKCS12_F_PKCS12_ITEM_PACK_SAFEBAG, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    bag->type = OBJ_nid2obj(nid1);
    if (!ASN1_item_pack(obj, it, &bag->value.octet)) {
        PKCS12err(PKCS12_F_PKCS12_ITEM_PACK_SAFEBAG, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    if (!(safebag = PKCS12_SAFEBAG_new())) {
        PKCS12err(PKCS12_F_PKCS12_ITEM_PACK_SAFEBAG, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    safebag->value.bag = bag;
    safebag->type = OBJ_nid2obj(nid2);
    return safebag;

 err:
    PKCS12_BAGS_free(bag);
    return NULL;
}

/* Turn PKCS8 object into a keybag */

PKCS12_SAFEBAG *PKCS12_MAKE_KEYBAG(PKCS8_PRIV_KEY_INFO *p8)
{
    PKCS12_SAFEBAG *bag;
    if (!(bag = PKCS12_SAFEBAG_new())) {
        PKCS12err(PKCS12_F_PKCS12_MAKE_KEYBAG, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    bag->type = OBJ_nid2obj(NID_keyBag);
    bag->value.keybag = p8;
    return bag;
}

/* Turn PKCS8 object into a shrouded keybag */

PKCS12_SAFEBAG *PKCS12_MAKE_SHKEYBAG(int pbe_nid, const char *pass,
                                     int passlen, unsigned char *salt,
                                     int saltlen, int iter,
                                     PKCS8_PRIV_KEY_INFO *p8)
{
    PKCS12_SAFEBAG *bag;
    const EVP_CIPHER *pbe_ciph;

    /* Set up the safe bag */
    if (!(bag = PKCS12_SAFEBAG_new())) {
        PKCS12err(PKCS12_F_PKCS12_MAKE_SHKEYBAG, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    bag->type = OBJ_nid2obj(NID_pkcs8ShroudedKeyBag);

    pbe_ciph = EVP_get_cipherbynid(pbe_nid);

    if (pbe_ciph)
        pbe_nid = -1;

    if (!(bag->value.shkeybag =
          PKCS8_encrypt(pbe_nid, pbe_ciph, pass, passlen, salt, saltlen, iter,
                        p8))) {
        PKCS12err(PKCS12_F_PKCS12_MAKE_SHKEYBAG, ERR_R_MALLOC_FAILURE);
        PKCS12_SAFEBAG_free(bag);
        return NULL;
    }

    return bag;
}

/* Turn a stack of SAFEBAGS into a PKCS#7 data Contentinfo */
PKCS7 *PKCS12_pack_p7data(STACK_OF(PKCS12_SAFEBAG) *sk)
{
    PKCS7 *p7;
    if (!(p7 = PKCS7_new())) {
        PKCS12err(PKCS12_F_PKCS12_PACK_P7DATA, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    p7->type = OBJ_nid2obj(NID_pkcs7_data);
    if (!(p7->d.data = M_ASN1_OCTET_STRING_new())) {
        PKCS12err(PKCS12_F_PKCS12_PACK_P7DATA, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (!ASN1_item_pack(sk, ASN1_ITEM_rptr(PKCS12_SAFEBAGS), &p7->d.data)) {
        PKCS12err(PKCS12_F_PKCS12_PACK_P7DATA, PKCS12_R_CANT_PACK_STRUCTURE);
        goto err;
    }
    return p7;

 err:
    PKCS7_free(p7);
    return NULL;
}

/* Unpack SAFEBAGS from PKCS#7 data ContentInfo */
STACK_OF(PKCS12_SAFEBAG) *PKCS12_unpack_p7data(PKCS7 *p7)
{
    if (!PKCS7_type_is_data(p7)) {
        PKCS12err(PKCS12_F_PKCS12_UNPACK_P7DATA,
                  PKCS12_R_CONTENT_TYPE_NOT_DATA);
        return NULL;
    }
    return ASN1_item_unpack(p7->d.data, ASN1_ITEM_rptr(PKCS12_SAFEBAGS));
}

/* Turn a stack of SAFEBAGS into a PKCS#7 encrypted data ContentInfo */

PKCS7 *PKCS12_pack_p7encdata(int pbe_nid, const char *pass, int passlen,
                             unsigned char *salt, int saltlen, int iter,
                             STACK_OF(PKCS12_SAFEBAG) *bags)
{
    PKCS7 *p7;
    X509_ALGOR *pbe;
    const EVP_CIPHER *pbe_ciph;
    if (!(p7 = PKCS7_new())) {
        PKCS12err(PKCS12_F_PKCS12_PACK_P7ENCDATA, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    if (!PKCS7_set_type(p7, NID_pkcs7_encrypted)) {
        PKCS12err(PKCS12_F_PKCS12_PACK_P7ENCDATA,
                  PKCS12_R_ERROR_SETTING_ENCRYPTED_DATA_TYPE);
        goto err;
    }

    pbe_ciph = EVP_get_cipherbynid(pbe_nid);

    if (pbe_ciph)
        pbe = PKCS5_pbe2_set(pbe_ciph, iter, salt, saltlen);
    else
        pbe = PKCS5_pbe_set(pbe_nid, iter, salt, saltlen);

    if (!pbe) {
        PKCS12err(PKCS12_F_PKCS12_PACK_P7ENCDATA, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    X509_ALGOR_free(p7->d.encrypted->enc_data->algorithm);
    p7->d.encrypted->enc_data->algorithm = pbe;
    M_ASN1_OCTET_STRING_free(p7->d.encrypted->enc_data->enc_data);
    if (!(p7->d.encrypted->enc_data->enc_data =
          PKCS12_item_i2d_encrypt(pbe, ASN1_ITEM_rptr(PKCS12_SAFEBAGS), pass,
                                  passlen, bags, 1))) {
        PKCS12err(PKCS12_F_PKCS12_PACK_P7ENCDATA, PKCS12_R_ENCRYPT_ERROR);
        goto err;
    }

    return p7;

 err:
    PKCS7_free(p7);
    return NULL;
}

STACK_OF(PKCS12_SAFEBAG) *PKCS12_unpack_p7encdata(PKCS7 *p7, const char *pass,
                                                  int passlen)
{
    if (!PKCS7_type_is_encrypted(p7))
        return NULL;
    return PKCS12_item_decrypt_d2i(p7->d.encrypted->enc_data->algorithm,
                                   ASN1_ITEM_rptr(PKCS12_SAFEBAGS),
                                   pass, passlen,
                                   p7->d.encrypted->enc_data->enc_data, 1);
}

PKCS8_PRIV_KEY_INFO *PKCS12_decrypt_skey(PKCS12_SAFEBAG *bag,
                                         const char *pass, int passlen)
{
    return PKCS8_decrypt(bag->value.shkeybag, pass, passlen);
}

int PKCS12_pack_authsafes(PKCS12 *p12, STACK_OF(PKCS7) *safes)
{
    if (ASN1_item_pack(safes, ASN1_ITEM_rptr(PKCS12_AUTHSAFES),
                       &p12->authsafes->d.data))
        return 1;
    return 0;
}

STACK_OF(PKCS7) *PKCS12_unpack_authsafes(PKCS12 *p12)
{
    if (!PKCS7_type_is_data(p12->authsafes)) {
        PKCS12err(PKCS12_F_PKCS12_UNPACK_AUTHSAFES,
                  PKCS12_R_CONTENT_TYPE_NOT_DATA);
        return NULL;
    }
    return ASN1_item_unpack(p12->authsafes->d.data,
                            ASN1_ITEM_rptr(PKCS12_AUTHSAFES));
}
/* p12_asn.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 1999.
 */
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
#include "asn1t.h"
// #include "pkcs12.h"

/* PKCS#12 ASN1 module */

ASN1_SEQUENCE(PKCS12) = {
        ASN1_SIMPLE(PKCS12, version, ASN1_INTEGER),
        ASN1_SIMPLE(PKCS12, authsafes, PKCS7),
        ASN1_OPT(PKCS12, mac, PKCS12_MAC_DATA)
} ASN1_SEQUENCE_END(PKCS12)

IMPLEMENT_ASN1_FUNCTIONS(PKCS12)

ASN1_SEQUENCE(PKCS12_MAC_DATA) = {
        ASN1_SIMPLE(PKCS12_MAC_DATA, dinfo, X509_SIG),
        ASN1_SIMPLE(PKCS12_MAC_DATA, salt, ASN1_OCTET_STRING),
        ASN1_OPT(PKCS12_MAC_DATA, iter, ASN1_INTEGER)
} ASN1_SEQUENCE_END(PKCS12_MAC_DATA)

IMPLEMENT_ASN1_FUNCTIONS(PKCS12_MAC_DATA)

ASN1_ADB_TEMPLATE(bag_default) = ASN1_EXP(PKCS12_BAGS, value.other, ASN1_ANY, 0);

ASN1_ADB(PKCS12_BAGS) = {
        ADB_ENTRY(NID_x509Certificate, ASN1_EXP(PKCS12_BAGS, value.x509cert, ASN1_OCTET_STRING, 0)),
        ADB_ENTRY(NID_x509Crl, ASN1_EXP(PKCS12_BAGS, value.x509crl, ASN1_OCTET_STRING, 0)),
        ADB_ENTRY(NID_sdsiCertificate, ASN1_EXP(PKCS12_BAGS, value.sdsicert, ASN1_IA5STRING, 0)),
} ASN1_ADB_END(PKCS12_BAGS, 0, type, 0, &bag_default_tt, NULL);

ASN1_SEQUENCE(PKCS12_BAGS) = {
        ASN1_SIMPLE(PKCS12_BAGS, type, ASN1_OBJECT),
        ASN1_ADB_OBJECT(PKCS12_BAGS),
} ASN1_SEQUENCE_END(PKCS12_BAGS)

IMPLEMENT_ASN1_FUNCTIONS(PKCS12_BAGS)

ASN1_ADB_TEMPLATE(safebag_default) = ASN1_EXP(PKCS12_SAFEBAG, value.other, ASN1_ANY, 0);

ASN1_ADB(PKCS12_SAFEBAG) = {
        ADB_ENTRY(NID_keyBag, ASN1_EXP(PKCS12_SAFEBAG, value.keybag, PKCS8_PRIV_KEY_INFO, 0)),
        ADB_ENTRY(NID_pkcs8ShroudedKeyBag, ASN1_EXP(PKCS12_SAFEBAG, value.shkeybag, X509_SIG, 0)),
        ADB_ENTRY(NID_safeContentsBag, ASN1_EXP_SEQUENCE_OF(PKCS12_SAFEBAG, value.safes, PKCS12_SAFEBAG, 0)),
        ADB_ENTRY(NID_certBag, ASN1_EXP(PKCS12_SAFEBAG, value.bag, PKCS12_BAGS, 0)),
        ADB_ENTRY(NID_crlBag, ASN1_EXP(PKCS12_SAFEBAG, value.bag, PKCS12_BAGS, 0)),
        ADB_ENTRY(NID_secretBag, ASN1_EXP(PKCS12_SAFEBAG, value.bag, PKCS12_BAGS, 0))
} ASN1_ADB_END(PKCS12_SAFEBAG, 0, type, 0, &safebag_default_tt, NULL);

ASN1_SEQUENCE(PKCS12_SAFEBAG) = {
        ASN1_SIMPLE(PKCS12_SAFEBAG, type, ASN1_OBJECT),
        ASN1_ADB_OBJECT(PKCS12_SAFEBAG),
        ASN1_SET_OF_OPT(PKCS12_SAFEBAG, attrib, X509_ATTRIBUTE)
} ASN1_SEQUENCE_END(PKCS12_SAFEBAG)

IMPLEMENT_ASN1_FUNCTIONS(PKCS12_SAFEBAG)

/* SEQUENCE OF SafeBag */
ASN1_ITEM_TEMPLATE(PKCS12_SAFEBAGS) =
        ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SEQUENCE_OF, 0, PKCS12_SAFEBAGS, PKCS12_SAFEBAG)
ASN1_ITEM_TEMPLATE_END(PKCS12_SAFEBAGS)

/* Authsafes: SEQUENCE OF PKCS7 */
ASN1_ITEM_TEMPLATE(PKCS12_AUTHSAFES) =
        ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SEQUENCE_OF, 0, PKCS12_AUTHSAFES, PKCS7)
ASN1_ITEM_TEMPLATE_END(PKCS12_AUTHSAFES)
/* p12_attr.c */
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
// #include "pkcs12.h"

/* Add a local keyid to a safebag */

int PKCS12_add_localkeyid(PKCS12_SAFEBAG *bag, unsigned char *name,
                          int namelen)
{
    if (X509at_add1_attr_by_NID(&bag->attrib, NID_localKeyID,
                                V_ASN1_OCTET_STRING, name, namelen))
        return 1;
    else
        return 0;
}

/* Add key usage to PKCS#8 structure */

int PKCS8_add_keyusage(PKCS8_PRIV_KEY_INFO *p8, int usage)
{
    unsigned char us_val;
    us_val = (unsigned char)usage;
    if (X509at_add1_attr_by_NID(&p8->attributes, NID_key_usage,
                                V_ASN1_BIT_STRING, &us_val, 1))
        return 1;
    else
        return 0;
}

/* Add a friendlyname to a safebag */

int PKCS12_add_friendlyname_asc(PKCS12_SAFEBAG *bag, const char *name,
                                int namelen)
{
    if (X509at_add1_attr_by_NID(&bag->attrib, NID_friendlyName,
                                MBSTRING_ASC, (unsigned char *)name, namelen))
        return 1;
    else
        return 0;
}

int PKCS12_add_friendlyname_uni(PKCS12_SAFEBAG *bag,
                                const unsigned char *name, int namelen)
{
    if (X509at_add1_attr_by_NID(&bag->attrib, NID_friendlyName,
                                MBSTRING_BMP, name, namelen))
        return 1;
    else
        return 0;
}

int PKCS12_add_CSPName_asc(PKCS12_SAFEBAG *bag, const char *name, int namelen)
{
    if (X509at_add1_attr_by_NID(&bag->attrib, NID_ms_csp_name,
                                MBSTRING_ASC, (unsigned char *)name, namelen))
        return 1;
    else
        return 0;
}

ASN1_TYPE *PKCS12_get_attr_gen(STACK_OF(X509_ATTRIBUTE) *attrs, int attr_nid)
{
    X509_ATTRIBUTE *attrib;
    int i;
    if (!attrs)
        return NULL;
    for (i = 0; i < sk_X509_ATTRIBUTE_num(attrs); i++) {
        attrib = sk_X509_ATTRIBUTE_value(attrs, i);
        if (OBJ_obj2nid(attrib->object) == attr_nid) {
            if (sk_ASN1_TYPE_num(attrib->value.set))
                return sk_ASN1_TYPE_value(attrib->value.set, 0);
            else
                return NULL;
        }
    }
    return NULL;
}

char *PKCS12_get_friendlyname(PKCS12_SAFEBAG *bag)
{
    ASN1_TYPE *atype;
    if (!(atype = PKCS12_get_attr(bag, NID_friendlyName)))
        return NULL;
    if (atype->type != V_ASN1_BMPSTRING)
        return NULL;
    return OPENSSL_uni2asc(atype->value.bmpstring->data,
                           atype->value.bmpstring->length);
}
/* p12_crpt.c */
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
// #include "pkcs12.h"

/* PKCS#12 PBE algorithms now in static table */

void PKCS12_PBE_add(void)
{
}

int PKCS12_PBE_keyivgen(EVP_CIPHER_CTX *ctx, const char *pass, int passlen,
                        ASN1_TYPE *param, const EVP_CIPHER *cipher,
                        const EVP_MD *md, int en_de)
{
    PBEPARAM *pbe;
    int saltlen, iter, ret;
    unsigned char *salt;
    const unsigned char *pbuf;
    unsigned char key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];

    if (cipher == NULL)
        return 0;

    /* Extract useful info from parameter */
    if (param == NULL || param->type != V_ASN1_SEQUENCE ||
        param->value.sequence == NULL) {
        PKCS12err(PKCS12_F_PKCS12_PBE_KEYIVGEN, PKCS12_R_DECODE_ERROR);
        return 0;
    }

    pbuf = param->value.sequence->data;
    if (!(pbe = d2i_PBEPARAM(NULL, &pbuf, param->value.sequence->length))) {
        PKCS12err(PKCS12_F_PKCS12_PBE_KEYIVGEN, PKCS12_R_DECODE_ERROR);
        return 0;
    }

    if (!pbe->iter)
        iter = 1;
    else
        iter = ASN1_INTEGER_get(pbe->iter);
    salt = pbe->salt->data;
    saltlen = pbe->salt->length;
    if (!PKCS12_key_gen(pass, passlen, salt, saltlen, PKCS12_KEY_ID,
                        iter, EVP_CIPHER_key_length(cipher), key, md)) {
        PKCS12err(PKCS12_F_PKCS12_PBE_KEYIVGEN, PKCS12_R_KEY_GEN_ERROR);
        PBEPARAM_free(pbe);
        return 0;
    }
    if (!PKCS12_key_gen(pass, passlen, salt, saltlen, PKCS12_IV_ID,
                        iter, EVP_CIPHER_iv_length(cipher), iv, md)) {
        PKCS12err(PKCS12_F_PKCS12_PBE_KEYIVGEN, PKCS12_R_IV_GEN_ERROR);
        PBEPARAM_free(pbe);
        return 0;
    }
    PBEPARAM_free(pbe);
    ret = EVP_CipherInit_ex(ctx, cipher, NULL, key, iv, en_de);
    OPENSSL_cleanse(key, EVP_MAX_KEY_LENGTH);
    OPENSSL_cleanse(iv, EVP_MAX_IV_LENGTH);
    return ret;
}
/* p12_crt.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project.
 */
/* ====================================================================
 * Copyright (c) 1999-2002 The OpenSSL Project.  All rights reserved.
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
// #include "pkcs12.h"

static int pkcs12_add_bag(STACK_OF(PKCS12_SAFEBAG) **pbags,
                          PKCS12_SAFEBAG *bag);

static int copy_bag_attr(PKCS12_SAFEBAG *bag, EVP_PKEY *pkey, int nid)
{
    int idx;
    X509_ATTRIBUTE *attr;
    idx = EVP_PKEY_get_attr_by_NID(pkey, nid, -1);
    if (idx < 0)
        return 1;
    attr = EVP_PKEY_get_attr(pkey, idx);
    if (!X509at_add1_attr(&bag->attrib, attr))
        return 0;
    return 1;
}

PKCS12 *PKCS12_create(char *pass, char *name, EVP_PKEY *pkey, X509 *cert,
                      STACK_OF(X509) *ca, int nid_key, int nid_cert, int iter,
                      int mac_iter, int keytype)
{
    PKCS12 *p12 = NULL;
    STACK_OF(PKCS7) *safes = NULL;
    STACK_OF(PKCS12_SAFEBAG) *bags = NULL;
    PKCS12_SAFEBAG *bag = NULL;
    int i;
    unsigned char keyid[EVP_MAX_MD_SIZE];
    unsigned int keyidlen = 0;

    /* Set defaults */
    if (!nid_cert) {
#ifdef OPENSSL_FIPS
        if (FIPS_mode())
            nid_cert = NID_pbe_WithSHA1And3_Key_TripleDES_CBC;
        else
#endif
#ifdef OPENSSL_NO_RC2
            nid_cert = NID_pbe_WithSHA1And3_Key_TripleDES_CBC;
#else
            nid_cert = NID_pbe_WithSHA1And40BitRC2_CBC;
#endif
    }
    if (!nid_key)
        nid_key = NID_pbe_WithSHA1And3_Key_TripleDES_CBC;
    if (!iter)
        iter = PKCS12_DEFAULT_ITER;
    if (!mac_iter)
        mac_iter = 1;

    if (!pkey && !cert && !ca) {
        PKCS12err(PKCS12_F_PKCS12_CREATE, PKCS12_R_INVALID_NULL_ARGUMENT);
        return NULL;
    }

    if (pkey && cert) {
        if (!X509_check_private_key(cert, pkey))
            return NULL;
        X509_digest(cert, EVP_sha1(), keyid, &keyidlen);
    }

    if (cert) {
        bag = PKCS12_add_cert(&bags, cert);
        if (name && !PKCS12_add_friendlyname(bag, name, -1))
            goto err;
        if (keyidlen && !PKCS12_add_localkeyid(bag, keyid, keyidlen))
            goto err;
    }

    /* Add all other certificates */
    for (i = 0; i < sk_X509_num(ca); i++) {
        if (!PKCS12_add_cert(&bags, sk_X509_value(ca, i)))
            goto err;
    }

    if (bags && !PKCS12_add_safe(&safes, bags, nid_cert, iter, pass))
        goto err;

    sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
    bags = NULL;

    if (pkey) {
        bag = PKCS12_add_key(&bags, pkey, keytype, iter, nid_key, pass);

        if (!bag)
            goto err;

        if (!copy_bag_attr(bag, pkey, NID_ms_csp_name))
            goto err;
        if (!copy_bag_attr(bag, pkey, NID_LocalKeySet))
            goto err;

        if (name && !PKCS12_add_friendlyname(bag, name, -1))
            goto err;
        if (keyidlen && !PKCS12_add_localkeyid(bag, keyid, keyidlen))
            goto err;
    }

    if (bags && !PKCS12_add_safe(&safes, bags, -1, 0, NULL))
        goto err;

    sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
    bags = NULL;

    p12 = PKCS12_add_safes(safes, 0);

    if (!p12)
        goto err;

    sk_PKCS7_pop_free(safes, PKCS7_free);

    safes = NULL;

    if ((mac_iter != -1) &&
        !PKCS12_set_mac(p12, pass, -1, NULL, 0, mac_iter, NULL))
        goto err;

    return p12;

 err:

    if (p12)
        PKCS12_free(p12);
    if (safes)
        sk_PKCS7_pop_free(safes, PKCS7_free);
    if (bags)
        sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
    return NULL;

}

PKCS12_SAFEBAG *PKCS12_add_cert(STACK_OF(PKCS12_SAFEBAG) **pbags, X509 *cert)
{
    PKCS12_SAFEBAG *bag = NULL;
    char *name;
    int namelen = -1;
    unsigned char *keyid;
    int keyidlen = -1;

    /* Add user certificate */
    if (!(bag = PKCS12_x5092certbag(cert)))
        goto err;

    /*
     * Use friendlyName and localKeyID in certificate. (if present)
     */

    name = (char *)X509_alias_get0(cert, &namelen);

    if (name && !PKCS12_add_friendlyname(bag, name, namelen))
        goto err;

    keyid = X509_keyid_get0(cert, &keyidlen);

    if (keyid && !PKCS12_add_localkeyid(bag, keyid, keyidlen))
        goto err;

    if (!pkcs12_add_bag(pbags, bag))
        goto err;

    return bag;

 err:

    if (bag)
        PKCS12_SAFEBAG_free(bag);

    return NULL;

}

PKCS12_SAFEBAG *PKCS12_add_key(STACK_OF(PKCS12_SAFEBAG) **pbags,
                               EVP_PKEY *key, int key_usage, int iter,
                               int nid_key, char *pass)
{

    PKCS12_SAFEBAG *bag = NULL;
    PKCS8_PRIV_KEY_INFO *p8 = NULL;

    /* Make a PKCS#8 structure */
    if (!(p8 = EVP_PKEY2PKCS8(key)))
        goto err;
    if (key_usage && !PKCS8_add_keyusage(p8, key_usage))
        goto err;
    if (nid_key != -1) {
        bag = PKCS12_MAKE_SHKEYBAG(nid_key, pass, -1, NULL, 0, iter, p8);
        PKCS8_PRIV_KEY_INFO_free(p8);
    } else
        bag = PKCS12_MAKE_KEYBAG(p8);

    if (!bag)
        goto err;

    if (!pkcs12_add_bag(pbags, bag))
        goto err;

    return bag;

 err:

    if (bag)
        PKCS12_SAFEBAG_free(bag);

    return NULL;

}

int PKCS12_add_safe(STACK_OF(PKCS7) **psafes, STACK_OF(PKCS12_SAFEBAG) *bags,
                    int nid_safe, int iter, char *pass)
{
    PKCS7 *p7 = NULL;
    int free_safes = 0;

    if (!*psafes) {
        *psafes = sk_PKCS7_new_null();
        if (!*psafes)
            return 0;
        free_safes = 1;
    } else
        free_safes = 0;

    if (nid_safe == 0)
#ifdef OPENSSL_NO_RC2
        nid_safe = NID_pbe_WithSHA1And3_Key_TripleDES_CBC;
#else
        nid_safe = NID_pbe_WithSHA1And40BitRC2_CBC;
#endif

    if (nid_safe == -1)
        p7 = PKCS12_pack_p7data(bags);
    else
        p7 = PKCS12_pack_p7encdata(nid_safe, pass, -1, NULL, 0, iter, bags);
    if (!p7)
        goto err;

    if (!sk_PKCS7_push(*psafes, p7))
        goto err;

    return 1;

 err:
    if (free_safes) {
        sk_PKCS7_free(*psafes);
        *psafes = NULL;
    }

    if (p7)
        PKCS7_free(p7);

    return 0;

}

static int pkcs12_add_bag(STACK_OF(PKCS12_SAFEBAG) **pbags,
                          PKCS12_SAFEBAG *bag)
{
    int free_bags;
    if (!pbags)
        return 1;
    if (!*pbags) {
        *pbags = sk_PKCS12_SAFEBAG_new_null();
        if (!*pbags)
            return 0;
        free_bags = 1;
    } else
        free_bags = 0;

    if (!sk_PKCS12_SAFEBAG_push(*pbags, bag)) {
        if (free_bags) {
            sk_PKCS12_SAFEBAG_free(*pbags);
            *pbags = NULL;
        }
        return 0;
    }

    return 1;

}

PKCS12 *PKCS12_add_safes(STACK_OF(PKCS7) *safes, int nid_p7)
{
    PKCS12 *p12;
    if (nid_p7 <= 0)
        nid_p7 = NID_pkcs7_data;
    p12 = PKCS12_init(nid_p7);

    if (!p12)
        return NULL;

    if (!PKCS12_pack_authsafes(p12, safes)) {
        PKCS12_free(p12);
        return NULL;
    }

    return p12;

}
/* p12_decr.c */
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
// #include "pkcs12.h"

/* Define this to dump decrypted output to files called DERnnn */
/*
 * #define DEBUG_DECRYPT
 */

/*
 * Encrypt/Decrypt a buffer based on password and algor, result in a
 * OPENSSL_malloc'ed buffer
 */

unsigned char *PKCS12_pbe_crypt(X509_ALGOR *algor, const char *pass,
                                int passlen, unsigned char *in, int inlen,
                                unsigned char **data, int *datalen, int en_de)
{
    unsigned char *out;
    int outlen, i;
    EVP_CIPHER_CTX ctx;

    EVP_CIPHER_CTX_init(&ctx);
    /* Decrypt data */
    if (!EVP_PBE_CipherInit(algor->algorithm, pass, passlen,
                            algor->parameter, &ctx, en_de)) {
        PKCS12err(PKCS12_F_PKCS12_PBE_CRYPT,
                  PKCS12_R_PKCS12_ALGOR_CIPHERINIT_ERROR);
        return NULL;
    }

    if (!(out = OPENSSL_malloc(inlen + EVP_CIPHER_CTX_block_size(&ctx)))) {
        PKCS12err(PKCS12_F_PKCS12_PBE_CRYPT, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (!EVP_CipherUpdate(&ctx, out, &i, in, inlen)) {
        OPENSSL_free(out);
        out = NULL;
        PKCS12err(PKCS12_F_PKCS12_PBE_CRYPT, ERR_R_EVP_LIB);
        goto err;
    }

    outlen = i;
    if (!EVP_CipherFinal_ex(&ctx, out + i, &i)) {
        OPENSSL_free(out);
        out = NULL;
        PKCS12err(PKCS12_F_PKCS12_PBE_CRYPT,
                  PKCS12_R_PKCS12_CIPHERFINAL_ERROR);
        goto err;
    }
    outlen += i;
    if (datalen)
        *datalen = outlen;
    if (data)
        *data = out;
 err:
    EVP_CIPHER_CTX_cleanup(&ctx);
    return out;

}

/*
 * Decrypt an OCTET STRING and decode ASN1 structure if zbuf set zero buffer
 * after use.
 */

void *PKCS12_item_decrypt_d2i(X509_ALGOR *algor, const ASN1_ITEM *it,
                              const char *pass, int passlen,
                              ASN1_OCTET_STRING *oct, int zbuf)
{
    unsigned char *out;
    const unsigned char *p;
    void *ret;
    int outlen;

    if (!PKCS12_pbe_crypt(algor, pass, passlen, oct->data, oct->length,
                          &out, &outlen, 0)) {
        PKCS12err(PKCS12_F_PKCS12_ITEM_DECRYPT_D2I,
                  PKCS12_R_PKCS12_PBE_CRYPT_ERROR);
        return NULL;
    }
    p = out;
#ifdef DEBUG_DECRYPT
    {
        FILE *op;

        char fname[30];
        static int fnm = 1;
        sprintf(fname, "DER%d", fnm++);
        op = fopen(fname, "wb");
        fwrite(p, 1, outlen, op);
        fclose(op);
    }
#endif
    ret = ASN1_item_d2i(NULL, &p, outlen, it);
    if (zbuf)
        OPENSSL_cleanse(out, outlen);
    if (!ret)
        PKCS12err(PKCS12_F_PKCS12_ITEM_DECRYPT_D2I, PKCS12_R_DECODE_ERROR);
    OPENSSL_free(out);
    return ret;
}

/*
 * Encode ASN1 structure and encrypt, return OCTET STRING if zbuf set zero
 * encoding.
 */

ASN1_OCTET_STRING *PKCS12_item_i2d_encrypt(X509_ALGOR *algor,
                                           const ASN1_ITEM *it,
                                           const char *pass, int passlen,
                                           void *obj, int zbuf)
{
    ASN1_OCTET_STRING *oct = NULL;
    unsigned char *in = NULL;
    int inlen;
    if (!(oct = M_ASN1_OCTET_STRING_new())) {
        PKCS12err(PKCS12_F_PKCS12_ITEM_I2D_ENCRYPT, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    inlen = ASN1_item_i2d(obj, &in, it);
    if (!in) {
        PKCS12err(PKCS12_F_PKCS12_ITEM_I2D_ENCRYPT, PKCS12_R_ENCODE_ERROR);
        goto err;
    }
    if (!PKCS12_pbe_crypt(algor, pass, passlen, in, inlen, &oct->data,
                          &oct->length, 1)) {
        PKCS12err(PKCS12_F_PKCS12_ITEM_I2D_ENCRYPT, PKCS12_R_ENCRYPT_ERROR);
        OPENSSL_free(in);
        goto err;
    }
    if (zbuf)
        OPENSSL_cleanse(in, inlen);
    OPENSSL_free(in);
    return oct;
 err:
    if (oct)
        ASN1_OCTET_STRING_free(oct);
    return NULL;
}

IMPLEMENT_PKCS12_STACK_OF(PKCS7)
/* p12_init.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 1999.
 */
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
// #include "pkcs12.h"

/* Initialise a PKCS12 structure to take data */

PKCS12 *PKCS12_init(int mode)
{
    PKCS12 *pkcs12;
    if (!(pkcs12 = PKCS12_new())) {
        PKCS12err(PKCS12_F_PKCS12_INIT, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    if (!ASN1_INTEGER_set(pkcs12->version, 3))
        goto err;
    pkcs12->authsafes->type = OBJ_nid2obj(mode);
    switch (mode) {
    case NID_pkcs7_data:
        if (!(pkcs12->authsafes->d.data = M_ASN1_OCTET_STRING_new())) {
            PKCS12err(PKCS12_F_PKCS12_INIT, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        break;
    default:
        PKCS12err(PKCS12_F_PKCS12_INIT, PKCS12_R_UNSUPPORTED_PKCS12_MODE);
        goto err;
    }

    return pkcs12;
 err:
    if (pkcs12 != NULL)
        PKCS12_free(pkcs12);
    return NULL;
}
/* p12_key.c */
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
// #include "pkcs12.h"
#include "bn.h"

/* Uncomment out this line to get debugging info about key generation */
/*
 * #define DEBUG_KEYGEN
 */
#ifdef DEBUG_KEYGEN
# include "bio.h"
extern BIO *bio_err;
void h__dump(unsigned char *p, int len);
#endif

/* PKCS12 compatible key/IV generation */
#ifndef min
# define min(a,b) ((a) < (b) ? (a) : (b))
#endif

int PKCS12_key_gen_asc(const char *pass, int passlen, unsigned char *salt,
                       int saltlen, int id, int iter, int n,
                       unsigned char *out, const EVP_MD *md_type)
{
    int ret;
    unsigned char *unipass;
    int uniplen;

    if (!pass) {
        unipass = NULL;
        uniplen = 0;
    } else if (!OPENSSL_asc2uni(pass, passlen, &unipass, &uniplen)) {
        PKCS12err(PKCS12_F_PKCS12_KEY_GEN_ASC, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    ret = PKCS12_key_gen_uni(unipass, uniplen, salt, saltlen,
                             id, iter, n, out, md_type);
    if (ret <= 0)
        return 0;
    if (unipass) {
        OPENSSL_cleanse(unipass, uniplen); /* Clear password from memory */
        OPENSSL_free(unipass);
    }
    return ret;
}

int PKCS12_key_gen_uni(unsigned char *pass, int passlen, unsigned char *salt,
                       int saltlen, int id, int iter, int n,
                       unsigned char *out, const EVP_MD *md_type)
{
    unsigned char *B, *D, *I, *p, *Ai;
    int Slen, Plen, Ilen, Ijlen;
    int i, j, u, v;
    int ret = 0;
    BIGNUM *Ij, *Bpl1;          /* These hold Ij and B + 1 */
    EVP_MD_CTX ctx;
#ifdef  DEBUG_KEYGEN
    unsigned char *tmpout = out;
    int tmpn = n;
#endif

#if 0
    if (!pass) {
        PKCS12err(PKCS12_F_PKCS12_KEY_GEN_UNI, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
#endif

    EVP_MD_CTX_init(&ctx);
#ifdef  DEBUG_KEYGEN
    fprintf(stderr, "KEYGEN DEBUG\n");
    fprintf(stderr, "ID %d, ITER %d\n", id, iter);
    fprintf(stderr, "Password (length %d):\n", passlen);
    h__dump(pass, passlen);
    fprintf(stderr, "Salt (length %d):\n", saltlen);
    h__dump(salt, saltlen);
#endif
    v = EVP_MD_block_size(md_type);
    u = EVP_MD_size(md_type);
    if (u < 0)
        return 0;
    D = OPENSSL_malloc(v);
    Ai = OPENSSL_malloc(u);
    B = OPENSSL_malloc(v + 1);
    Slen = v * ((saltlen + v - 1) / v);
    if (passlen)
        Plen = v * ((passlen + v - 1) / v);
    else
        Plen = 0;
    Ilen = Slen + Plen;
    I = OPENSSL_malloc(Ilen);
    Ij = BN_new();
    Bpl1 = BN_new();
    if (!D || !Ai || !B || !I || !Ij || !Bpl1)
        goto err;
    for (i = 0; i < v; i++)
        D[i] = id;
    p = I;
    for (i = 0; i < Slen; i++)
        *p++ = salt[i % saltlen];
    for (i = 0; i < Plen; i++)
        *p++ = pass[i % passlen];
    for (;;) {
        if (!EVP_DigestInit_ex(&ctx, md_type, NULL)
            || !EVP_DigestUpdate(&ctx, D, v)
            || !EVP_DigestUpdate(&ctx, I, Ilen)
            || !EVP_DigestFinal_ex(&ctx, Ai, NULL))
            goto err;
        for (j = 1; j < iter; j++) {
            if (!EVP_DigestInit_ex(&ctx, md_type, NULL)
                || !EVP_DigestUpdate(&ctx, Ai, u)
                || !EVP_DigestFinal_ex(&ctx, Ai, NULL))
                goto err;
        }
        memcpy(out, Ai, min(n, u));
        if (u >= n) {
#ifdef DEBUG_KEYGEN
            fprintf(stderr, "Output KEY (length %d)\n", tmpn);
            h__dump(tmpout, tmpn);
#endif
            ret = 1;
            goto end;
        }
        n -= u;
        out += u;
        for (j = 0; j < v; j++)
            B[j] = Ai[j % u];
        /* Work out B + 1 first then can use B as tmp space */
        if (!BN_bin2bn(B, v, Bpl1))
            goto err;
        if (!BN_add_word(Bpl1, 1))
            goto err;
        for (j = 0; j < Ilen; j += v) {
            if (!BN_bin2bn(I + j, v, Ij))
                goto err;
            if (!BN_add(Ij, Ij, Bpl1))
                goto err;
            if (!BN_bn2bin(Ij, B))
                goto err;
            Ijlen = BN_num_bytes(Ij);
            /* If more than 2^(v*8) - 1 cut off MSB */
            if (Ijlen > v) {
                if (!BN_bn2bin(Ij, B))
                    goto err;
                memcpy(I + j, B + 1, v);
#ifndef PKCS12_BROKEN_KEYGEN
                /* If less than v bytes pad with zeroes */
            } else if (Ijlen < v) {
                memset(I + j, 0, v - Ijlen);
                if (!BN_bn2bin(Ij, I + j + v - Ijlen))
                    goto err;
#endif
            } else if (!BN_bn2bin(Ij, I + j))
                goto err;
        }
    }

 err:
    PKCS12err(PKCS12_F_PKCS12_KEY_GEN_UNI, ERR_R_MALLOC_FAILURE);

 end:
    OPENSSL_free(Ai);
    OPENSSL_free(B);
    OPENSSL_free(D);
    OPENSSL_free(I);
    BN_free(Ij);
    BN_free(Bpl1);
    EVP_MD_CTX_cleanup(&ctx);
    return ret;
}

#ifdef DEBUG_KEYGEN
void h__dump(unsigned char *p, int len)
{
    for (; len--; p++)
        fprintf(stderr, "%02X", *p);
    fprintf(stderr, "\n");
}
#endif
/* p12_kiss.c */
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
// #include "pkcs12.h"

/* Simplified PKCS#12 routines */

static int parse_pk12(PKCS12 *p12, const char *pass, int passlen,
                      EVP_PKEY **pkey, STACK_OF(X509) *ocerts);

static int parse_bags(STACK_OF(PKCS12_SAFEBAG) *bags, const char *pass,
                      int passlen, EVP_PKEY **pkey, STACK_OF(X509) *ocerts);

static int parse_bag(PKCS12_SAFEBAG *bag, const char *pass, int passlen,
                     EVP_PKEY **pkey, STACK_OF(X509) *ocerts);

/*
 * Parse and decrypt a PKCS#12 structure returning user key, user cert and
 * other (CA) certs. Note either ca should be NULL, *ca should be NULL, or it
 * should point to a valid STACK structure. pkey and cert can be passed
 * unitialised.
 */

int PKCS12_parse(PKCS12 *p12, const char *pass, EVP_PKEY **pkey, X509 **cert,
                 STACK_OF(X509) **ca)
{
    STACK_OF(X509) *ocerts = NULL;
    X509 *x = NULL;

    if (pkey)
        *pkey = NULL;
    if (cert)
        *cert = NULL;

    /* Check for NULL PKCS12 structure */

    if (!p12) {
        PKCS12err(PKCS12_F_PKCS12_PARSE,
                  PKCS12_R_INVALID_NULL_PKCS12_POINTER);
        return 0;
    }

    /* Check the mac */

    /*
     * If password is zero length or NULL then try verifying both cases to
     * determine which password is correct. The reason for this is that under
     * PKCS#12 password based encryption no password and a zero length
     * password are two different things...
     */

    if (!pass || !*pass) {
        if (PKCS12_verify_mac(p12, NULL, 0))
            pass = NULL;
        else if (PKCS12_verify_mac(p12, "", 0))
            pass = "";
        else {
            PKCS12err(PKCS12_F_PKCS12_PARSE, PKCS12_R_MAC_VERIFY_FAILURE);
            goto err;
        }
    } else if (!PKCS12_verify_mac(p12, pass, -1)) {
        PKCS12err(PKCS12_F_PKCS12_PARSE, PKCS12_R_MAC_VERIFY_FAILURE);
        goto err;
    }

    /* Allocate stack for other certificates */
    ocerts = sk_X509_new_null();

    if (!ocerts) {
        PKCS12err(PKCS12_F_PKCS12_PARSE, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (!parse_pk12(p12, pass, -1, pkey, ocerts)) {
        PKCS12err(PKCS12_F_PKCS12_PARSE, PKCS12_R_PARSE_ERROR);
        goto err;
    }

    while ((x = sk_X509_pop(ocerts))) {
        if (pkey && *pkey && cert && !*cert) {
            ERR_set_mark();
            if (X509_check_private_key(x, *pkey)) {
                *cert = x;
                x = NULL;
            }
            ERR_pop_to_mark();
        }

        if (ca && x) {
            if (!*ca)
                *ca = sk_X509_new_null();
            if (!*ca)
                goto err;
            if (!sk_X509_push(*ca, x))
                goto err;
            x = NULL;
        }
        if (x)
            X509_free(x);
    }

    if (ocerts)
        sk_X509_pop_free(ocerts, X509_free);

    return 1;

 err:

    if (pkey) {
        EVP_PKEY_free(*pkey);
        *pkey = NULL;
    }
    if (cert) {
        X509_free(*cert);
        *cert = NULL;
    }
    if (x)
        X509_free(x);
    if (ocerts)
        sk_X509_pop_free(ocerts, X509_free);
    return 0;

}

/* Parse the outer PKCS#12 structure */

static int parse_pk12(PKCS12 *p12, const char *pass, int passlen,
                      EVP_PKEY **pkey, STACK_OF(X509) *ocerts)
{
    STACK_OF(PKCS7) *asafes;
    STACK_OF(PKCS12_SAFEBAG) *bags;
    int i, bagnid;
    PKCS7 *p7;

    if (!(asafes = PKCS12_unpack_authsafes(p12)))
        return 0;
    for (i = 0; i < sk_PKCS7_num(asafes); i++) {
        p7 = sk_PKCS7_value(asafes, i);
        bagnid = OBJ_obj2nid(p7->type);
        if (bagnid == NID_pkcs7_data) {
            bags = PKCS12_unpack_p7data(p7);
        } else if (bagnid == NID_pkcs7_encrypted) {
            bags = PKCS12_unpack_p7encdata(p7, pass, passlen);
        } else
            continue;
        if (!bags) {
            sk_PKCS7_pop_free(asafes, PKCS7_free);
            return 0;
        }
        if (!parse_bags(bags, pass, passlen, pkey, ocerts)) {
            sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
            sk_PKCS7_pop_free(asafes, PKCS7_free);
            return 0;
        }
        sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
    }
    sk_PKCS7_pop_free(asafes, PKCS7_free);
    return 1;
}

static int parse_bags(STACK_OF(PKCS12_SAFEBAG) *bags, const char *pass,
                      int passlen, EVP_PKEY **pkey, STACK_OF(X509) *ocerts)
{
    int i;
    for (i = 0; i < sk_PKCS12_SAFEBAG_num(bags); i++) {
        if (!parse_bag(sk_PKCS12_SAFEBAG_value(bags, i),
                       pass, passlen, pkey, ocerts))
            return 0;
    }
    return 1;
}

static int parse_bag(PKCS12_SAFEBAG *bag, const char *pass, int passlen,
                     EVP_PKEY **pkey, STACK_OF(X509) *ocerts)
{
    PKCS8_PRIV_KEY_INFO *p8;
    X509 *x509;
    ASN1_TYPE *attrib;
    ASN1_BMPSTRING *fname = NULL;
    ASN1_OCTET_STRING *lkid = NULL;

    if ((attrib = PKCS12_get_attr(bag, NID_friendlyName)))
        fname = attrib->value.bmpstring;

    if ((attrib = PKCS12_get_attr(bag, NID_localKeyID)))
        lkid = attrib->value.octet_string;

    switch (M_PKCS12_bag_type(bag)) {
    case NID_keyBag:
        if (!pkey || *pkey)
            return 1;
        if (!(*pkey = EVP_PKCS82PKEY(bag->value.keybag)))
            return 0;
        break;

    case NID_pkcs8ShroudedKeyBag:
        if (!pkey || *pkey)
            return 1;
        if (!(p8 = PKCS12_decrypt_skey(bag, pass, passlen)))
            return 0;
        *pkey = EVP_PKCS82PKEY(p8);
        PKCS8_PRIV_KEY_INFO_free(p8);
        if (!(*pkey))
            return 0;
        break;

    case NID_certBag:
        if (M_PKCS12_cert_bag_type(bag) != NID_x509Certificate)
            return 1;
        if (!(x509 = PKCS12_certbag2x509(bag)))
            return 0;
        if (lkid && !X509_keyid_set1(x509, lkid->data, lkid->length)) {
            X509_free(x509);
            return 0;
        }
        if (fname) {
            int len, r;
            unsigned char *data;
            len = ASN1_STRING_to_UTF8(&data, fname);
            if (len >= 0) {
                r = X509_alias_set1(x509, data, len);
                OPENSSL_free(data);
                if (!r) {
                    X509_free(x509);
                    return 0;
                }
            }
        }

        if (!sk_X509_push(ocerts, x509)) {
            X509_free(x509);
            return 0;
        }

        break;

    case NID_safeContentsBag:
        return parse_bags(bag->value.safes, pass, passlen, pkey, ocerts);
        break;

    default:
        return 1;
        break;
    }
    return 1;
}
/* p12_mutl.c */
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

#ifndef OPENSSL_NO_HMAC
# include <stdio.h>
# include "cryptlib.h"
# include "crypto.h"
# include "hmac.h"
# include "rand.h"
# include "pkcs12.h"

/* Generate a MAC */
int PKCS12_gen_mac(PKCS12 *p12, const char *pass, int passlen,
                   unsigned char *mac, unsigned int *maclen)
{
    const EVP_MD *md_type;
    HMAC_CTX hmac;
    unsigned char key[EVP_MAX_MD_SIZE], *salt;
    int saltlen, iter;
    int md_size;

    if (!PKCS7_type_is_data(p12->authsafes)) {
        PKCS12err(PKCS12_F_PKCS12_GEN_MAC, PKCS12_R_CONTENT_TYPE_NOT_DATA);
        return 0;
    }

    salt = p12->mac->salt->data;
    saltlen = p12->mac->salt->length;
    if (!p12->mac->iter)
        iter = 1;
    else
        iter = ASN1_INTEGER_get(p12->mac->iter);
    if (!(md_type = EVP_get_digestbyobj(p12->mac->dinfo->algor->algorithm))) {
        PKCS12err(PKCS12_F_PKCS12_GEN_MAC, PKCS12_R_UNKNOWN_DIGEST_ALGORITHM);
        return 0;
    }
    md_size = EVP_MD_size(md_type);
    if (md_size < 0)
        return 0;
    if (!PKCS12_key_gen(pass, passlen, salt, saltlen, PKCS12_MAC_ID, iter,
                        md_size, key, md_type)) {
        PKCS12err(PKCS12_F_PKCS12_GEN_MAC, PKCS12_R_KEY_GEN_ERROR);
        return 0;
    }
    HMAC_CTX_init(&hmac);
    if (!HMAC_Init_ex(&hmac, key, md_size, md_type, NULL)
        || !HMAC_Update(&hmac, p12->authsafes->d.data->data,
                        p12->authsafes->d.data->length)
        || !HMAC_Final(&hmac, mac, maclen)) {
        HMAC_CTX_cleanup(&hmac);
        return 0;
    }
    HMAC_CTX_cleanup(&hmac);
    return 1;
}

/* Verify the mac */
int PKCS12_verify_mac(PKCS12 *p12, const char *pass, int passlen)
{
    unsigned char mac[EVP_MAX_MD_SIZE];
    unsigned int maclen;
    if (p12->mac == NULL) {
        PKCS12err(PKCS12_F_PKCS12_VERIFY_MAC, PKCS12_R_MAC_ABSENT);
        return 0;
    }
    if (!PKCS12_gen_mac(p12, pass, passlen, mac, &maclen)) {
        PKCS12err(PKCS12_F_PKCS12_VERIFY_MAC, PKCS12_R_MAC_GENERATION_ERROR);
        return 0;
    }
    if ((maclen != (unsigned int)p12->mac->dinfo->digest->length)
        || CRYPTO_memcmp(mac, p12->mac->dinfo->digest->data, maclen))
        return 0;
    return 1;
}

/* Set a mac */

int PKCS12_set_mac(PKCS12 *p12, const char *pass, int passlen,
                   unsigned char *salt, int saltlen, int iter,
                   const EVP_MD *md_type)
{
    unsigned char mac[EVP_MAX_MD_SIZE];
    unsigned int maclen;

    if (!md_type)
        md_type = EVP_sha1();
    if (PKCS12_setup_mac(p12, iter, salt, saltlen, md_type) == PKCS12_ERROR) {
        PKCS12err(PKCS12_F_PKCS12_SET_MAC, PKCS12_R_MAC_SETUP_ERROR);
        return 0;
    }
    if (!PKCS12_gen_mac(p12, pass, passlen, mac, &maclen)) {
        PKCS12err(PKCS12_F_PKCS12_SET_MAC, PKCS12_R_MAC_GENERATION_ERROR);
        return 0;
    }
    if (!(M_ASN1_OCTET_STRING_set(p12->mac->dinfo->digest, mac, maclen))) {
        PKCS12err(PKCS12_F_PKCS12_SET_MAC, PKCS12_R_MAC_STRING_SET_ERROR);
        return 0;
    }
    return 1;
}

/* Set up a mac structure */
int PKCS12_setup_mac(PKCS12 *p12, int iter, unsigned char *salt, int saltlen,
                     const EVP_MD *md_type)
{
    PKCS12_MAC_DATA_free(p12->mac);
    p12->mac = NULL;

    if ((p12->mac = PKCS12_MAC_DATA_new()) == NULL)
        return PKCS12_ERROR;
    if (iter > 1) {
        if (!(p12->mac->iter = M_ASN1_INTEGER_new())) {
            PKCS12err(PKCS12_F_PKCS12_SETUP_MAC, ERR_R_MALLOC_FAILURE);
            return 0;
        }
        if (!ASN1_INTEGER_set(p12->mac->iter, iter)) {
            PKCS12err(PKCS12_F_PKCS12_SETUP_MAC, ERR_R_MALLOC_FAILURE);
            return 0;
        }
    }
    if (!saltlen)
        saltlen = PKCS12_SALT_LEN;
    if ((p12->mac->salt->data = OPENSSL_malloc(saltlen)) == NULL) {
        PKCS12err(PKCS12_F_PKCS12_SETUP_MAC, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    p12->mac->salt->length = saltlen;
    if (!salt) {
        if (RAND_bytes(p12->mac->salt->data, saltlen) <= 0)
            return 0;
    } else
        memcpy(p12->mac->salt->data, salt, saltlen);
    p12->mac->dinfo->algor->algorithm = OBJ_nid2obj(EVP_MD_type(md_type));
    if (!(p12->mac->dinfo->algor->parameter = ASN1_TYPE_new())) {
        PKCS12err(PKCS12_F_PKCS12_SETUP_MAC, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    p12->mac->dinfo->algor->parameter->type = V_ASN1_NULL;

    return 1;
}
#endif
/* p12_npas.c */
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
#include <stdlib.h>
#include <string.h>
#include "pem.h"
#include "err.h"
// #include "pkcs12.h"

/* PKCS#12 password change routine */

static int newpass_p12(PKCS12 *p12, const char *oldpass, const char *newpass);
static int newpass_bags(STACK_OF(PKCS12_SAFEBAG) *bags, const char *oldpass,
                        const char *newpass);
static int newpass_bag(PKCS12_SAFEBAG *bag, const char *oldpass,
                        const char *newpass);
static int alg_get(X509_ALGOR *alg, int *pnid, int *piter, int *psaltlen);

/*
 * Change the password on a PKCS#12 structure.
 */

int PKCS12_newpass(PKCS12 *p12, const char *oldpass, const char *newpass)
{
    /* Check for NULL PKCS12 structure */

    if (!p12) {
        PKCS12err(PKCS12_F_PKCS12_NEWPASS,
                  PKCS12_R_INVALID_NULL_PKCS12_POINTER);
        return 0;
    }

    /* Check the mac */

    if (!PKCS12_verify_mac(p12, oldpass, -1)) {
        PKCS12err(PKCS12_F_PKCS12_NEWPASS, PKCS12_R_MAC_VERIFY_FAILURE);
        return 0;
    }

    if (!newpass_p12(p12, oldpass, newpass)) {
        PKCS12err(PKCS12_F_PKCS12_NEWPASS, PKCS12_R_PARSE_ERROR);
        return 0;
    }

    return 1;
}

/* Parse the outer PKCS#12 structure */

static int newpass_p12(PKCS12 *p12, const char *oldpass, const char *newpass)
{
    STACK_OF(PKCS7) *asafes = NULL, *newsafes = NULL;
    STACK_OF(PKCS12_SAFEBAG) *bags = NULL;
    int i, bagnid, pbe_nid = 0, pbe_iter = 0, pbe_saltlen = 0;
    PKCS7 *p7, *p7new;
    ASN1_OCTET_STRING *p12_data_tmp = NULL;
    unsigned char mac[EVP_MAX_MD_SIZE];
    unsigned int maclen;
    int rv = 0;

    if ((asafes = PKCS12_unpack_authsafes(p12)) == NULL)
        goto err;
    if ((newsafes = sk_PKCS7_new_null()) == NULL)
        goto err;
    for (i = 0; i < sk_PKCS7_num(asafes); i++) {
        p7 = sk_PKCS7_value(asafes, i);
        bagnid = OBJ_obj2nid(p7->type);
        if (bagnid == NID_pkcs7_data) {
            bags = PKCS12_unpack_p7data(p7);
        } else if (bagnid == NID_pkcs7_encrypted) {
            bags = PKCS12_unpack_p7encdata(p7, oldpass, -1);
            if (!alg_get(p7->d.encrypted->enc_data->algorithm,
                         &pbe_nid, &pbe_iter, &pbe_saltlen))
                goto err;
        } else {
            continue;
        }
        if (bags == NULL)
            goto err;
        if (!newpass_bags(bags, oldpass, newpass))
            goto err;
        /* Repack bag in same form with new password */
        if (bagnid == NID_pkcs7_data)
            p7new = PKCS12_pack_p7data(bags);
        else
            p7new = PKCS12_pack_p7encdata(pbe_nid, newpass, -1, NULL,
                                          pbe_saltlen, pbe_iter, bags);
        if (!p7new || !sk_PKCS7_push(newsafes, p7new))
            goto err;
        sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
        bags = NULL;
    }

    /* Repack safe: save old safe in case of error */

    p12_data_tmp = p12->authsafes->d.data;
    if ((p12->authsafes->d.data = ASN1_OCTET_STRING_new()) == NULL)
        goto err;
    if (!PKCS12_pack_authsafes(p12, newsafes))
        goto err;
    if (!PKCS12_gen_mac(p12, newpass, -1, mac, &maclen))
        goto err;
    if (!ASN1_OCTET_STRING_set(p12->mac->dinfo->digest, mac, maclen))
        goto err;

    rv = 1;

err:
    /* Restore old safe if necessary */
    if (rv == 1) {
        ASN1_OCTET_STRING_free(p12_data_tmp);
    } else if (p12_data_tmp != NULL) {
        ASN1_OCTET_STRING_free(p12->authsafes->d.data);
        p12->authsafes->d.data = p12_data_tmp;
    }
    sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
    sk_PKCS7_pop_free(asafes, PKCS7_free);
    sk_PKCS7_pop_free(newsafes, PKCS7_free);
    return rv;
}

static int newpass_bags(STACK_OF(PKCS12_SAFEBAG) *bags, const char *oldpass,
                        const char *newpass)
{
    int i;
    for (i = 0; i < sk_PKCS12_SAFEBAG_num(bags); i++) {
        if (!newpass_bag(sk_PKCS12_SAFEBAG_value(bags, i), oldpass, newpass))
            return 0;
    }
    return 1;
}

/* Change password of safebag: only needs handle shrouded keybags */

static int newpass_bag(PKCS12_SAFEBAG *bag, const char *oldpass,
                       const char *newpass)
{
    PKCS8_PRIV_KEY_INFO *p8;
    X509_SIG *p8new;
    int p8_nid, p8_saltlen, p8_iter;

    if (M_PKCS12_bag_type(bag) != NID_pkcs8ShroudedKeyBag)
        return 1;

    if (!(p8 = PKCS8_decrypt(bag->value.shkeybag, oldpass, -1)))
        return 0;
    if (!alg_get(bag->value.shkeybag->algor, &p8_nid, &p8_iter, &p8_saltlen))
        return 0;
    p8new = PKCS8_encrypt(p8_nid, NULL, newpass, -1, NULL, p8_saltlen,
                          p8_iter, p8);
    PKCS8_PRIV_KEY_INFO_free(p8);
    if (p8new == NULL)
        return 0;
    X509_SIG_free(bag->value.shkeybag);
    bag->value.shkeybag = p8new;
    return 1;
}

static int alg_get(X509_ALGOR *alg, int *pnid, int *piter, int *psaltlen)
{
    PBEPARAM *pbe;
    const unsigned char *p;

    p = alg->parameter->value.sequence->data;
    pbe = d2i_PBEPARAM(NULL, &p, alg->parameter->value.sequence->length);
    if (!pbe)
        return 0;
    *pnid = OBJ_obj2nid(alg->algorithm);
    *piter = ASN1_INTEGER_get(pbe->iter);
    *psaltlen = pbe->salt->length;
    PBEPARAM_free(pbe);
    return 1;
}
/* p12_p8d.c */
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
// #include "pkcs12.h"

PKCS8_PRIV_KEY_INFO *PKCS8_decrypt(X509_SIG *p8, const char *pass,
                                   int passlen)
{
    return PKCS12_item_decrypt_d2i(p8->algor,
                                   ASN1_ITEM_rptr(PKCS8_PRIV_KEY_INFO), pass,
                                   passlen, p8->digest, 1);
}
/* p12_p8e.c */
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
// #include "pkcs12.h"

X509_SIG *PKCS8_encrypt(int pbe_nid, const EVP_CIPHER *cipher,
                        const char *pass, int passlen,
                        unsigned char *salt, int saltlen, int iter,
                        PKCS8_PRIV_KEY_INFO *p8inf)
{
    X509_SIG *p8 = NULL;
    X509_ALGOR *pbe;

    if (!(p8 = X509_SIG_new())) {
        PKCS12err(PKCS12_F_PKCS8_ENCRYPT, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (pbe_nid == -1)
        pbe = PKCS5_pbe2_set(cipher, iter, salt, saltlen);
    else if (EVP_PBE_find(EVP_PBE_TYPE_PRF, pbe_nid, NULL, NULL, 0))
        pbe = PKCS5_pbe2_set_iv(cipher, iter, salt, saltlen, NULL, pbe_nid);
    else {
        ERR_clear_error();
        pbe = PKCS5_pbe_set(pbe_nid, iter, salt, saltlen);
    }
    if (!pbe) {
        PKCS12err(PKCS12_F_PKCS8_ENCRYPT, ERR_R_ASN1_LIB);
        goto err;
    }
    X509_ALGOR_free(p8->algor);
    p8->algor = pbe;
    M_ASN1_OCTET_STRING_free(p8->digest);
    p8->digest =
        PKCS12_item_i2d_encrypt(pbe, ASN1_ITEM_rptr(PKCS8_PRIV_KEY_INFO),
                                pass, passlen, p8inf, 1);
    if (!p8->digest) {
        PKCS12err(PKCS12_F_PKCS8_ENCRYPT, PKCS12_R_ENCRYPT_ERROR);
        goto err;
    }

    return p8;

 err:
    X509_SIG_free(p8);
    return NULL;
}
/* p12_utl.c */
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
// #include "pkcs12.h"

/* Cheap and nasty Unicode stuff */

unsigned char *OPENSSL_asc2uni(const char *asc, int asclen,
                               unsigned char **uni, int *unilen)
{
    int ulen, i;
    unsigned char *unitmp;
    if (asclen == -1)
        asclen = strlen(asc);
    ulen = asclen * 2 + 2;
    if (!(unitmp = OPENSSL_malloc(ulen)))
        return NULL;
    for (i = 0; i < ulen - 2; i += 2) {
        unitmp[i] = 0;
        unitmp[i + 1] = asc[i >> 1];
    }
    /* Make result double null terminated */
    unitmp[ulen - 2] = 0;
    unitmp[ulen - 1] = 0;
    if (unilen)
        *unilen = ulen;
    if (uni)
        *uni = unitmp;
    return unitmp;
}

char *OPENSSL_uni2asc(unsigned char *uni, int unilen)
{
    int asclen, i;
    char *asctmp;

    /* string must contain an even number of bytes */
    if (unilen & 1)
        return NULL;
    asclen = unilen / 2;
    /* If no terminating zero allow for one */
    if (!unilen || uni[unilen - 1])
        asclen++;
    uni++;
    if (!(asctmp = OPENSSL_malloc(asclen)))
        return NULL;
    for (i = 0; i < unilen; i += 2)
        asctmp[i >> 1] = uni[i];
    asctmp[asclen - 1] = 0;
    return asctmp;
}

int i2d_PKCS12_bio(BIO *bp, PKCS12 *p12)
{
    return ASN1_item_i2d_bio(ASN1_ITEM_rptr(PKCS12), bp, p12);
}

#ifndef OPENSSL_NO_FP_API
int i2d_PKCS12_fp(FILE *fp, PKCS12 *p12)
{
    return ASN1_item_i2d_fp(ASN1_ITEM_rptr(PKCS12), fp, p12);
}
#endif

PKCS12 *d2i_PKCS12_bio(BIO *bp, PKCS12 **p12)
{
    return ASN1_item_d2i_bio(ASN1_ITEM_rptr(PKCS12), bp, p12);
}

#ifndef OPENSSL_NO_FP_API
PKCS12 *d2i_PKCS12_fp(FILE *fp, PKCS12 **p12)
{
    return ASN1_item_d2i_fp(ASN1_ITEM_rptr(PKCS12), fp, p12);
}
#endif

PKCS12_SAFEBAG *PKCS12_x5092certbag(X509 *x509)
{
    return PKCS12_item_pack_safebag(x509, ASN1_ITEM_rptr(X509),
                                    NID_x509Certificate, NID_certBag);
}

PKCS12_SAFEBAG *PKCS12_x509crl2certbag(X509_CRL *crl)
{
    return PKCS12_item_pack_safebag(crl, ASN1_ITEM_rptr(X509_CRL),
                                    NID_x509Crl, NID_crlBag);
}

X509 *PKCS12_certbag2x509(PKCS12_SAFEBAG *bag)
{
    if (M_PKCS12_bag_type(bag) != NID_certBag)
        return NULL;
    if (M_PKCS12_cert_bag_type(bag) != NID_x509Certificate)
        return NULL;
    return ASN1_item_unpack(bag->value.bag->value.octet,
                            ASN1_ITEM_rptr(X509));
}

X509_CRL *PKCS12_certbag2x509crl(PKCS12_SAFEBAG *bag)
{
    if (M_PKCS12_bag_type(bag) != NID_crlBag)
        return NULL;
    if (M_PKCS12_cert_bag_type(bag) != NID_x509Crl)
        return NULL;
    return ASN1_item_unpack(bag->value.bag->value.octet,
                            ASN1_ITEM_rptr(X509_CRL));
}
