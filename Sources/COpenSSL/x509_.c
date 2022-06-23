/* crypto/x509/x509_att.c */
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
#include "stack.h"
#include "cryptlib.h"
#include "asn1.h"
#include "objects.h"
#include "evp.h"
#include "x509.h"
#include "x509v3.h"

int X509at_get_attr_count(const STACK_OF(X509_ATTRIBUTE) *x)
{
    return sk_X509_ATTRIBUTE_num(x);
}

int X509at_get_attr_by_NID(const STACK_OF(X509_ATTRIBUTE) *x, int nid,
                           int lastpos)
{
    ASN1_OBJECT *obj;

    obj = OBJ_nid2obj(nid);
    if (obj == NULL)
        return (-2);
    return (X509at_get_attr_by_OBJ(x, obj, lastpos));
}

int X509at_get_attr_by_OBJ(const STACK_OF(X509_ATTRIBUTE) *sk,
                           ASN1_OBJECT *obj, int lastpos)
{
    int n;
    X509_ATTRIBUTE *ex;

    if (sk == NULL)
        return (-1);
    lastpos++;
    if (lastpos < 0)
        lastpos = 0;
    n = sk_X509_ATTRIBUTE_num(sk);
    for (; lastpos < n; lastpos++) {
        ex = sk_X509_ATTRIBUTE_value(sk, lastpos);
        if (OBJ_cmp(ex->object, obj) == 0)
            return (lastpos);
    }
    return (-1);
}

X509_ATTRIBUTE *X509at_get_attr(const STACK_OF(X509_ATTRIBUTE) *x, int loc)
{
    if (x == NULL || sk_X509_ATTRIBUTE_num(x) <= loc || loc < 0)
        return NULL;
    else
        return sk_X509_ATTRIBUTE_value(x, loc);
}

X509_ATTRIBUTE *X509at_delete_attr(STACK_OF(X509_ATTRIBUTE) *x, int loc)
{
    X509_ATTRIBUTE *ret;

    if (x == NULL || sk_X509_ATTRIBUTE_num(x) <= loc || loc < 0)
        return (NULL);
    ret = sk_X509_ATTRIBUTE_delete(x, loc);
    return (ret);
}

STACK_OF(X509_ATTRIBUTE) *X509at_add1_attr(STACK_OF(X509_ATTRIBUTE) **x,
                                           X509_ATTRIBUTE *attr)
{
    X509_ATTRIBUTE *new_attr = NULL;
    STACK_OF(X509_ATTRIBUTE) *sk = NULL;

    if (x == NULL) {
        X509err(X509_F_X509AT_ADD1_ATTR, ERR_R_PASSED_NULL_PARAMETER);
        goto err2;
    }

    if (*x == NULL) {
        if ((sk = sk_X509_ATTRIBUTE_new_null()) == NULL)
            goto err;
    } else
        sk = *x;

    if ((new_attr = X509_ATTRIBUTE_dup(attr)) == NULL)
        goto err2;
    if (!sk_X509_ATTRIBUTE_push(sk, new_attr))
        goto err;
    if (*x == NULL)
        *x = sk;
    return (sk);
 err:
    X509err(X509_F_X509AT_ADD1_ATTR, ERR_R_MALLOC_FAILURE);
 err2:
    if (new_attr != NULL)
        X509_ATTRIBUTE_free(new_attr);
    if (sk != NULL)
        sk_X509_ATTRIBUTE_free(sk);
    return (NULL);
}

STACK_OF(X509_ATTRIBUTE) *X509at_add1_attr_by_OBJ(STACK_OF(X509_ATTRIBUTE)
                                                  **x, const ASN1_OBJECT *obj,
                                                  int type,
                                                  const unsigned char *bytes,
                                                  int len)
{
    X509_ATTRIBUTE *attr;
    STACK_OF(X509_ATTRIBUTE) *ret;
    attr = X509_ATTRIBUTE_create_by_OBJ(NULL, obj, type, bytes, len);
    if (!attr)
        return 0;
    ret = X509at_add1_attr(x, attr);
    X509_ATTRIBUTE_free(attr);
    return ret;
}

STACK_OF(X509_ATTRIBUTE) *X509at_add1_attr_by_NID(STACK_OF(X509_ATTRIBUTE)
                                                  **x, int nid, int type,
                                                  const unsigned char *bytes,
                                                  int len)
{
    X509_ATTRIBUTE *attr;
    STACK_OF(X509_ATTRIBUTE) *ret;
    attr = X509_ATTRIBUTE_create_by_NID(NULL, nid, type, bytes, len);
    if (!attr)
        return 0;
    ret = X509at_add1_attr(x, attr);
    X509_ATTRIBUTE_free(attr);
    return ret;
}

STACK_OF(X509_ATTRIBUTE) *X509at_add1_attr_by_txt(STACK_OF(X509_ATTRIBUTE)
                                                  **x, const char *attrname,
                                                  int type,
                                                  const unsigned char *bytes,
                                                  int len)
{
    X509_ATTRIBUTE *attr;
    STACK_OF(X509_ATTRIBUTE) *ret;
    attr = X509_ATTRIBUTE_create_by_txt(NULL, attrname, type, bytes, len);
    if (!attr)
        return 0;
    ret = X509at_add1_attr(x, attr);
    X509_ATTRIBUTE_free(attr);
    return ret;
}

void *X509at_get0_data_by_OBJ(STACK_OF(X509_ATTRIBUTE) *x,
                              ASN1_OBJECT *obj, int lastpos, int type)
{
    int i;
    X509_ATTRIBUTE *at;
    i = X509at_get_attr_by_OBJ(x, obj, lastpos);
    if (i == -1)
        return NULL;
    if ((lastpos <= -2) && (X509at_get_attr_by_OBJ(x, obj, i) != -1))
        return NULL;
    at = X509at_get_attr(x, i);
    if (lastpos <= -3 && (X509_ATTRIBUTE_count(at) != 1))
        return NULL;
    return X509_ATTRIBUTE_get0_data(at, 0, type, NULL);
}

X509_ATTRIBUTE *X509_ATTRIBUTE_create_by_NID(X509_ATTRIBUTE **attr, int nid,
                                             int atrtype, const void *data,
                                             int len)
{
    ASN1_OBJECT *obj;
    X509_ATTRIBUTE *ret;

    obj = OBJ_nid2obj(nid);
    if (obj == NULL) {
        X509err(X509_F_X509_ATTRIBUTE_CREATE_BY_NID, X509_R_UNKNOWN_NID);
        return (NULL);
    }
    ret = X509_ATTRIBUTE_create_by_OBJ(attr, obj, atrtype, data, len);
    if (ret == NULL)
        ASN1_OBJECT_free(obj);
    return (ret);
}

X509_ATTRIBUTE *X509_ATTRIBUTE_create_by_OBJ(X509_ATTRIBUTE **attr,
                                             const ASN1_OBJECT *obj,
                                             int atrtype, const void *data,
                                             int len)
{
    X509_ATTRIBUTE *ret;

    if ((attr == NULL) || (*attr == NULL)) {
        if ((ret = X509_ATTRIBUTE_new()) == NULL) {
            X509err(X509_F_X509_ATTRIBUTE_CREATE_BY_OBJ,
                    ERR_R_MALLOC_FAILURE);
            return (NULL);
        }
    } else
        ret = *attr;

    if (!X509_ATTRIBUTE_set1_object(ret, obj))
        goto err;
    if (!X509_ATTRIBUTE_set1_data(ret, atrtype, data, len))
        goto err;

    if ((attr != NULL) && (*attr == NULL))
        *attr = ret;
    return (ret);
 err:
    if ((attr == NULL) || (ret != *attr))
        X509_ATTRIBUTE_free(ret);
    return (NULL);
}

X509_ATTRIBUTE *X509_ATTRIBUTE_create_by_txt(X509_ATTRIBUTE **attr,
                                             const char *atrname, int type,
                                             const unsigned char *bytes,
                                             int len)
{
    ASN1_OBJECT *obj;
    X509_ATTRIBUTE *nattr;

    obj = OBJ_txt2obj(atrname, 0);
    if (obj == NULL) {
        X509err(X509_F_X509_ATTRIBUTE_CREATE_BY_TXT,
                X509_R_INVALID_FIELD_NAME);
        ERR_add_error_data(2, "name=", atrname);
        return (NULL);
    }
    nattr = X509_ATTRIBUTE_create_by_OBJ(attr, obj, type, bytes, len);
    ASN1_OBJECT_free(obj);
    return nattr;
}

int X509_ATTRIBUTE_set1_object(X509_ATTRIBUTE *attr, const ASN1_OBJECT *obj)
{
    if ((attr == NULL) || (obj == NULL))
        return (0);
    ASN1_OBJECT_free(attr->object);
    attr->object = OBJ_dup(obj);
    return (1);
}

int X509_ATTRIBUTE_set1_data(X509_ATTRIBUTE *attr, int attrtype,
                             const void *data, int len)
{
    ASN1_TYPE *ttmp = NULL;
    ASN1_STRING *stmp = NULL;
    int atype = 0;
    if (!attr)
        return 0;
    if (attrtype & MBSTRING_FLAG) {
        stmp = ASN1_STRING_set_by_NID(NULL, data, len, attrtype,
                                      OBJ_obj2nid(attr->object));
        if (!stmp) {
            X509err(X509_F_X509_ATTRIBUTE_SET1_DATA, ERR_R_ASN1_LIB);
            return 0;
        }
        atype = stmp->type;
    } else if (len != -1) {
        if (!(stmp = ASN1_STRING_type_new(attrtype)))
            goto err;
        if (!ASN1_STRING_set(stmp, data, len))
            goto err;
        atype = attrtype;
    }
    if (!(attr->value.set = sk_ASN1_TYPE_new_null()))
        goto err;
    attr->single = 0;
    /*
     * This is a bit naughty because the attribute should really have at
     * least one value but some types use and zero length SET and require
     * this.
     */
    if (attrtype == 0) {
        ASN1_STRING_free(stmp);
        return 1;
    }
    if (!(ttmp = ASN1_TYPE_new()))
        goto err;
    if ((len == -1) && !(attrtype & MBSTRING_FLAG)) {
        if (!ASN1_TYPE_set1(ttmp, attrtype, data))
            goto err;
    } else {
        ASN1_TYPE_set(ttmp, atype, stmp);
        stmp = NULL;
    }
    if (!sk_ASN1_TYPE_push(attr->value.set, ttmp))
        goto err;
    return 1;
 err:
    X509err(X509_F_X509_ATTRIBUTE_SET1_DATA, ERR_R_MALLOC_FAILURE);
    ASN1_TYPE_free(ttmp);
    ASN1_STRING_free(stmp);
    return 0;
}

int X509_ATTRIBUTE_count(X509_ATTRIBUTE *attr)
{
    if (!attr->single)
        return sk_ASN1_TYPE_num(attr->value.set);
    if (attr->value.single)
        return 1;
    return 0;
}

ASN1_OBJECT *X509_ATTRIBUTE_get0_object(X509_ATTRIBUTE *attr)
{
    if (attr == NULL)
        return (NULL);
    return (attr->object);
}

void *X509_ATTRIBUTE_get0_data(X509_ATTRIBUTE *attr, int idx,
                               int atrtype, void *data)
{
    ASN1_TYPE *ttmp;
    ttmp = X509_ATTRIBUTE_get0_type(attr, idx);
    if (!ttmp)
        return NULL;
    if (atrtype != ASN1_TYPE_get(ttmp)) {
        X509err(X509_F_X509_ATTRIBUTE_GET0_DATA, X509_R_WRONG_TYPE);
        return NULL;
    }
    return ttmp->value.ptr;
}

ASN1_TYPE *X509_ATTRIBUTE_get0_type(X509_ATTRIBUTE *attr, int idx)
{
    if (attr == NULL)
        return (NULL);
    if (idx >= X509_ATTRIBUTE_count(attr))
        return NULL;
    if (!attr->single)
        return sk_ASN1_TYPE_value(attr->value.set, idx);
    else
        return attr->value.single;
}
/* crypto/x509/x509_cmp.c */
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
#include <ctype.h>
// #include "cryptlib.h"
// #include "asn1.h"
// #include "objects.h"
// #include "x509.h"
// #include "x509v3.h"

int X509_issuer_and_serial_cmp(const X509 *a, const X509 *b)
{
    int i;
    X509_CINF *ai, *bi;

    ai = a->cert_info;
    bi = b->cert_info;
    i = M_ASN1_INTEGER_cmp(ai->serialNumber, bi->serialNumber);
    if (i)
        return (i);
    return (X509_NAME_cmp(ai->issuer, bi->issuer));
}

#ifndef OPENSSL_NO_MD5
unsigned long X509_issuer_and_serial_hash(X509 *a)
{
    unsigned long ret = 0;
    EVP_MD_CTX ctx;
    unsigned char md[16];
    char *f;

    EVP_MD_CTX_init(&ctx);
    f = X509_NAME_oneline(a->cert_info->issuer, NULL, 0);
    if (!EVP_DigestInit_ex(&ctx, EVP_md5(), NULL))
        goto err;
    if (!EVP_DigestUpdate(&ctx, (unsigned char *)f, strlen(f)))
        goto err;
    OPENSSL_free(f);
    if (!EVP_DigestUpdate
        (&ctx, (unsigned char *)a->cert_info->serialNumber->data,
         (unsigned long)a->cert_info->serialNumber->length))
        goto err;
    if (!EVP_DigestFinal_ex(&ctx, &(md[0]), NULL))
        goto err;
    ret = (((unsigned long)md[0]) | ((unsigned long)md[1] << 8L) |
           ((unsigned long)md[2] << 16L) | ((unsigned long)md[3] << 24L)
        ) & 0xffffffffL;
 err:
    EVP_MD_CTX_cleanup(&ctx);
    return (ret);
}
#endif

int X509_issuer_name_cmp(const X509 *a, const X509 *b)
{
    return (X509_NAME_cmp(a->cert_info->issuer, b->cert_info->issuer));
}

int X509_subject_name_cmp(const X509 *a, const X509 *b)
{
    return (X509_NAME_cmp(a->cert_info->subject, b->cert_info->subject));
}

int X509_CRL_cmp(const X509_CRL *a, const X509_CRL *b)
{
    return (X509_NAME_cmp(a->crl->issuer, b->crl->issuer));
}

#ifndef OPENSSL_NO_SHA
int X509_CRL_match(const X509_CRL *a, const X509_CRL *b)
{
    return memcmp(a->sha1_hash, b->sha1_hash, 20);
}
#endif

X509_NAME *X509_get_issuer_name(X509 *a)
{
    return (a->cert_info->issuer);
}

unsigned long X509_issuer_name_hash(X509 *x)
{
    return (X509_NAME_hash(x->cert_info->issuer));
}

#ifndef OPENSSL_NO_MD5
unsigned long X509_issuer_name_hash_old(X509 *x)
{
    return (X509_NAME_hash_old(x->cert_info->issuer));
}
#endif

X509_NAME *X509_get_subject_name(X509 *a)
{
    return (a->cert_info->subject);
}

ASN1_INTEGER *X509_get_serialNumber(X509 *a)
{
    return (a->cert_info->serialNumber);
}

unsigned long X509_subject_name_hash(X509 *x)
{
    return (X509_NAME_hash(x->cert_info->subject));
}

#ifndef OPENSSL_NO_MD5
unsigned long X509_subject_name_hash_old(X509 *x)
{
    return (X509_NAME_hash_old(x->cert_info->subject));
}
#endif

#ifndef OPENSSL_NO_SHA
/*
 * Compare two certificates: they must be identical for this to work. NB:
 * Although "cmp" operations are generally prototyped to take "const"
 * arguments (eg. for use in STACKs), the way X509 handling is - these
 * operations may involve ensuring the hashes are up-to-date and ensuring
 * certain cert information is cached. So this is the point where the
 * "depth-first" constification tree has to halt with an evil cast.
 */
int X509_cmp(const X509 *a, const X509 *b)
{
    int rv;
    /* ensure hash is valid */
    X509_check_purpose((X509 *)a, -1, 0);
    X509_check_purpose((X509 *)b, -1, 0);

    rv = memcmp(a->sha1_hash, b->sha1_hash, SHA_DIGEST_LENGTH);
    if (rv)
        return rv;
    /* Check for match against stored encoding too */
    if (!a->cert_info->enc.modified && !b->cert_info->enc.modified) {
        rv = (int)(a->cert_info->enc.len - b->cert_info->enc.len);
        if (rv)
            return rv;
        return memcmp(a->cert_info->enc.enc, b->cert_info->enc.enc,
                      a->cert_info->enc.len);
    }
    return rv;
}
#endif

int X509_NAME_cmp(const X509_NAME *a, const X509_NAME *b)
{
    int ret;

    /* Ensure canonical encoding is present and up to date */

    if (!a->canon_enc || a->modified) {
        ret = i2d_X509_NAME((X509_NAME *)a, NULL);
        if (ret < 0)
            return -2;
    }

    if (!b->canon_enc || b->modified) {
        ret = i2d_X509_NAME((X509_NAME *)b, NULL);
        if (ret < 0)
            return -2;
    }

    ret = a->canon_enclen - b->canon_enclen;

    if (ret != 0 || a->canon_enclen == 0)
        return ret;

    return memcmp(a->canon_enc, b->canon_enc, a->canon_enclen);

}

unsigned long X509_NAME_hash(X509_NAME *x)
{
    unsigned long ret = 0;
    unsigned char md[SHA_DIGEST_LENGTH];

    /* Make sure X509_NAME structure contains valid cached encoding */
    i2d_X509_NAME(x, NULL);
    if (!EVP_Digest(x->canon_enc, x->canon_enclen, md, NULL, EVP_sha1(),
                    NULL))
        return 0;

    ret = (((unsigned long)md[0]) | ((unsigned long)md[1] << 8L) |
           ((unsigned long)md[2] << 16L) | ((unsigned long)md[3] << 24L)
        ) & 0xffffffffL;
    return (ret);
}

#ifndef OPENSSL_NO_MD5
/*
 * I now DER encode the name and hash it.  Since I cache the DER encoding,
 * this is reasonably efficient.
 */

unsigned long X509_NAME_hash_old(X509_NAME *x)
{
    EVP_MD_CTX md_ctx;
    unsigned long ret = 0;
    unsigned char md[16];

    /* Make sure X509_NAME structure contains valid cached encoding */
    i2d_X509_NAME(x, NULL);
    EVP_MD_CTX_init(&md_ctx);
    EVP_MD_CTX_set_flags(&md_ctx, EVP_MD_CTX_FLAG_NON_FIPS_ALLOW);
    if (EVP_DigestInit_ex(&md_ctx, EVP_md5(), NULL)
        && EVP_DigestUpdate(&md_ctx, x->bytes->data, x->bytes->length)
        && EVP_DigestFinal_ex(&md_ctx, md, NULL))
        ret = (((unsigned long)md[0]) | ((unsigned long)md[1] << 8L) |
               ((unsigned long)md[2] << 16L) | ((unsigned long)md[3] << 24L)
            ) & 0xffffffffL;
    EVP_MD_CTX_cleanup(&md_ctx);

    return (ret);
}
#endif

/* Search a stack of X509 for a match */
X509 *X509_find_by_issuer_and_serial(STACK_OF(X509) *sk, X509_NAME *name,
                                     ASN1_INTEGER *serial)
{
    int i;
    X509_CINF cinf;
    X509 x, *x509 = NULL;

    if (!sk)
        return NULL;

    x.cert_info = &cinf;
    cinf.serialNumber = serial;
    cinf.issuer = name;

    for (i = 0; i < sk_X509_num(sk); i++) {
        x509 = sk_X509_value(sk, i);
        if (X509_issuer_and_serial_cmp(x509, &x) == 0)
            return (x509);
    }
    return (NULL);
}

X509 *X509_find_by_subject(STACK_OF(X509) *sk, X509_NAME *name)
{
    X509 *x509;
    int i;

    for (i = 0; i < sk_X509_num(sk); i++) {
        x509 = sk_X509_value(sk, i);
        if (X509_NAME_cmp(X509_get_subject_name(x509), name) == 0)
            return (x509);
    }
    return (NULL);
}

EVP_PKEY *X509_get_pubkey(X509 *x)
{
    if ((x == NULL) || (x->cert_info == NULL))
        return (NULL);
    return (X509_PUBKEY_get(x->cert_info->key));
}

ASN1_BIT_STRING *X509_get0_pubkey_bitstr(const X509 *x)
{
    if (!x)
        return NULL;
    return x->cert_info->key->public_key;
}

int X509_check_private_key(X509 *x, EVP_PKEY *k)
{
    EVP_PKEY *xk;
    int ret;

    xk = X509_get_pubkey(x);

    if (xk)
        ret = EVP_PKEY_cmp(xk, k);
    else
        ret = -2;

    switch (ret) {
    case 1:
        break;
    case 0:
        X509err(X509_F_X509_CHECK_PRIVATE_KEY, X509_R_KEY_VALUES_MISMATCH);
        break;
    case -1:
        X509err(X509_F_X509_CHECK_PRIVATE_KEY, X509_R_KEY_TYPE_MISMATCH);
        break;
    case -2:
        X509err(X509_F_X509_CHECK_PRIVATE_KEY, X509_R_UNKNOWN_KEY_TYPE);
    }
    if (xk)
        EVP_PKEY_free(xk);
    if (ret > 0)
        return 1;
    return 0;
}

/*
 * Check a suite B algorithm is permitted: pass in a public key and the NID
 * of its signature (or 0 if no signature). The pflags is a pointer to a
 * flags field which must contain the suite B verification flags.
 */

#ifndef OPENSSL_NO_EC

static int check_suite_b(EVP_PKEY *pkey, int sign_nid, unsigned long *pflags)
{
    const EC_GROUP *grp = NULL;
    int curve_nid;
    if (pkey && pkey->type == EVP_PKEY_EC)
        grp = EC_KEY_get0_group(pkey->pkey.ec);
    if (!grp)
        return X509_V_ERR_SUITE_B_INVALID_ALGORITHM;
    curve_nid = EC_GROUP_get_curve_name(grp);
    /* Check curve is consistent with LOS */
    if (curve_nid == NID_secp384r1) { /* P-384 */
        /*
         * Check signature algorithm is consistent with curve.
         */
        if (sign_nid != -1 && sign_nid != NID_ecdsa_with_SHA384)
            return X509_V_ERR_SUITE_B_INVALID_SIGNATURE_ALGORITHM;
        if (!(*pflags & X509_V_FLAG_SUITEB_192_LOS))
            return X509_V_ERR_SUITE_B_LOS_NOT_ALLOWED;
        /* If we encounter P-384 we cannot use P-256 later */
        *pflags &= ~X509_V_FLAG_SUITEB_128_LOS_ONLY;
    } else if (curve_nid == NID_X9_62_prime256v1) { /* P-256 */
        if (sign_nid != -1 && sign_nid != NID_ecdsa_with_SHA256)
            return X509_V_ERR_SUITE_B_INVALID_SIGNATURE_ALGORITHM;
        if (!(*pflags & X509_V_FLAG_SUITEB_128_LOS_ONLY))
            return X509_V_ERR_SUITE_B_LOS_NOT_ALLOWED;
    } else
        return X509_V_ERR_SUITE_B_INVALID_CURVE;

    return X509_V_OK;
}

int X509_chain_check_suiteb(int *perror_depth, X509 *x, STACK_OF(X509) *chain,
                            unsigned long flags)
{
    int rv, i, sign_nid;
    EVP_PKEY *pk = NULL;
    unsigned long tflags;
    if (!(flags & X509_V_FLAG_SUITEB_128_LOS))
        return X509_V_OK;
    tflags = flags;
    /* If no EE certificate passed in must be first in chain */
    if (x == NULL) {
        x = sk_X509_value(chain, 0);
        i = 1;
    } else
        i = 0;

    if (X509_get_version(x) != 2) {
        rv = X509_V_ERR_SUITE_B_INVALID_VERSION;
        /* Correct error depth */
        i = 0;
        goto end;
    }

    pk = X509_get_pubkey(x);
    /* Check EE key only */
    rv = check_suite_b(pk, -1, &tflags);
    if (rv != X509_V_OK) {
        /* Correct error depth */
        i = 0;
        goto end;
    }
    for (; i < sk_X509_num(chain); i++) {
        sign_nid = X509_get_signature_nid(x);
        x = sk_X509_value(chain, i);
        if (X509_get_version(x) != 2) {
            rv = X509_V_ERR_SUITE_B_INVALID_VERSION;
            goto end;
        }
        EVP_PKEY_free(pk);
        pk = X509_get_pubkey(x);
        rv = check_suite_b(pk, sign_nid, &tflags);
        if (rv != X509_V_OK)
            goto end;
    }

    /* Final check: root CA signature */
    rv = check_suite_b(pk, X509_get_signature_nid(x), &tflags);
 end:
    if (pk)
        EVP_PKEY_free(pk);
    if (rv != X509_V_OK) {
        /* Invalid signature or LOS errors are for previous cert */
        if ((rv == X509_V_ERR_SUITE_B_INVALID_SIGNATURE_ALGORITHM
             || rv == X509_V_ERR_SUITE_B_LOS_NOT_ALLOWED) && i)
            i--;
        /*
         * If we have LOS error and flags changed then we are signing P-384
         * with P-256. Use more meaninggul error.
         */
        if (rv == X509_V_ERR_SUITE_B_LOS_NOT_ALLOWED && flags != tflags)
            rv = X509_V_ERR_SUITE_B_CANNOT_SIGN_P_384_WITH_P_256;
        if (perror_depth)
            *perror_depth = i;
    }
    return rv;
}

int X509_CRL_check_suiteb(X509_CRL *crl, EVP_PKEY *pk, unsigned long flags)
{
    int sign_nid;
    if (!(flags & X509_V_FLAG_SUITEB_128_LOS))
        return X509_V_OK;
    sign_nid = OBJ_obj2nid(crl->crl->sig_alg->algorithm);
    return check_suite_b(pk, sign_nid, &flags);
}

#else
int X509_chain_check_suiteb(int *perror_depth, X509 *x, STACK_OF(X509) *chain,
                            unsigned long flags)
{
    return 0;
}

int X509_CRL_check_suiteb(X509_CRL *crl, EVP_PKEY *pk, unsigned long flags)
{
    return 0;
}

#endif
/*
 * Not strictly speaking an "up_ref" as a STACK doesn't have a reference
 * count but it has the same effect by duping the STACK and upping the ref of
 * each X509 structure.
 */
STACK_OF(X509) *X509_chain_up_ref(STACK_OF(X509) *chain)
{
    STACK_OF(X509) *ret;
    int i;
    ret = sk_X509_dup(chain);
    for (i = 0; i < sk_X509_num(ret); i++) {
        X509 *x = sk_X509_value(ret, i);
        CRYPTO_add(&x->references, 1, CRYPTO_LOCK_X509);
    }
    return ret;
}
/* crypto/x509/x509_d2.c */
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
#include "crypto.h"
// #include "x509.h"

#ifndef OPENSSL_NO_STDIO
int X509_STORE_set_default_paths(X509_STORE *ctx)
{
    X509_LOOKUP *lookup;

    lookup = X509_STORE_add_lookup(ctx, X509_LOOKUP_file());
    if (lookup == NULL)
        return (0);
    X509_LOOKUP_load_file(lookup, NULL, X509_FILETYPE_DEFAULT);

    lookup = X509_STORE_add_lookup(ctx, X509_LOOKUP_hash_dir());
    if (lookup == NULL)
        return (0);
    X509_LOOKUP_add_dir(lookup, NULL, X509_FILETYPE_DEFAULT);

    /* clear any errors */
    ERR_clear_error();

    return (1);
}

int X509_STORE_load_locations(X509_STORE *ctx, const char *file,
                              const char *path)
{
    X509_LOOKUP *lookup;

    if (file != NULL) {
        lookup = X509_STORE_add_lookup(ctx, X509_LOOKUP_file());
        if (lookup == NULL)
            return (0);
        if (X509_LOOKUP_load_file(lookup, file, X509_FILETYPE_PEM) != 1)
            return (0);
    }
    if (path != NULL) {
        lookup = X509_STORE_add_lookup(ctx, X509_LOOKUP_hash_dir());
        if (lookup == NULL)
            return (0);
        if (X509_LOOKUP_add_dir(lookup, path, X509_FILETYPE_PEM) != 1)
            return (0);
    }
    if ((path == NULL) && (file == NULL))
        return (0);
    return (1);
}

#endif
/* crypto/x509/x509_def.c */
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
// #include "crypto.h"
// #include "x509.h"

const char *X509_get_default_private_dir(void)
{
    return (X509_PRIVATE_DIR);
}

const char *X509_get_default_cert_area(void)
{
    return (X509_CERT_AREA);
}

const char *X509_get_default_cert_dir(void)
{
    return (X509_CERT_DIR);
}

const char *X509_get_default_cert_file(void)
{
    return (X509_CERT_FILE);
}

const char *X509_get_default_cert_dir_env(void)
{
    return (X509_CERT_DIR_EVP);
}

const char *X509_get_default_cert_file_env(void)
{
    return (X509_CERT_FILE_EVP);
}
/* crypto/x509/x509_err.c */
/* ====================================================================
 * Copyright (c) 1999-2016 The OpenSSL Project.  All rights reserved.
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
// #include "x509.h"

/* BEGIN ERROR CODES */
#ifndef OPENSSL_NO_ERR

# define ERR_FUNC(func) ERR_PACK(ERR_LIB_X509,func,0)
# define ERR_REASON(reason) ERR_PACK(ERR_LIB_X509,0,reason)

static ERR_STRING_DATA X509_str_functs[] = {
    {ERR_FUNC(X509_F_ADD_CERT_DIR), "ADD_CERT_DIR"},
    {ERR_FUNC(X509_F_BY_FILE_CTRL), "BY_FILE_CTRL"},
    {ERR_FUNC(X509_F_CHECK_NAME_CONSTRAINTS), "CHECK_NAME_CONSTRAINTS"},
    {ERR_FUNC(X509_F_CHECK_POLICY), "CHECK_POLICY"},
    {ERR_FUNC(X509_F_DIR_CTRL), "DIR_CTRL"},
    {ERR_FUNC(X509_F_GET_CERT_BY_SUBJECT), "GET_CERT_BY_SUBJECT"},
    {ERR_FUNC(X509_F_NETSCAPE_SPKI_B64_DECODE), "NETSCAPE_SPKI_b64_decode"},
    {ERR_FUNC(X509_F_NETSCAPE_SPKI_B64_ENCODE), "NETSCAPE_SPKI_b64_encode"},
    {ERR_FUNC(X509_F_X509AT_ADD1_ATTR), "X509at_add1_attr"},
    {ERR_FUNC(X509_F_X509V3_ADD_EXT), "X509v3_add_ext"},
    {ERR_FUNC(X509_F_X509_ATTRIBUTE_CREATE_BY_NID),
     "X509_ATTRIBUTE_create_by_NID"},
    {ERR_FUNC(X509_F_X509_ATTRIBUTE_CREATE_BY_OBJ),
     "X509_ATTRIBUTE_create_by_OBJ"},
    {ERR_FUNC(X509_F_X509_ATTRIBUTE_CREATE_BY_TXT),
     "X509_ATTRIBUTE_create_by_txt"},
    {ERR_FUNC(X509_F_X509_ATTRIBUTE_GET0_DATA), "X509_ATTRIBUTE_get0_data"},
    {ERR_FUNC(X509_F_X509_ATTRIBUTE_SET1_DATA), "X509_ATTRIBUTE_set1_data"},
    {ERR_FUNC(X509_F_X509_CHECK_PRIVATE_KEY), "X509_check_private_key"},
    {ERR_FUNC(X509_F_X509_CRL_DIFF), "X509_CRL_diff"},
    {ERR_FUNC(X509_F_X509_CRL_PRINT_FP), "X509_CRL_print_fp"},
    {ERR_FUNC(X509_F_X509_EXTENSION_CREATE_BY_NID),
     "X509_EXTENSION_create_by_NID"},
    {ERR_FUNC(X509_F_X509_EXTENSION_CREATE_BY_OBJ),
     "X509_EXTENSION_create_by_OBJ"},
    {ERR_FUNC(X509_F_X509_GET_PUBKEY_PARAMETERS),
     "X509_get_pubkey_parameters"},
    {ERR_FUNC(X509_F_X509_LOAD_CERT_CRL_FILE), "X509_load_cert_crl_file"},
    {ERR_FUNC(X509_F_X509_LOAD_CERT_FILE), "X509_load_cert_file"},
    {ERR_FUNC(X509_F_X509_LOAD_CRL_FILE), "X509_load_crl_file"},
    {ERR_FUNC(X509_F_X509_NAME_ADD_ENTRY), "X509_NAME_add_entry"},
    {ERR_FUNC(X509_F_X509_NAME_ENTRY_CREATE_BY_NID),
     "X509_NAME_ENTRY_create_by_NID"},
    {ERR_FUNC(X509_F_X509_NAME_ENTRY_CREATE_BY_TXT),
     "X509_NAME_ENTRY_create_by_txt"},
    {ERR_FUNC(X509_F_X509_NAME_ENTRY_SET_OBJECT),
     "X509_NAME_ENTRY_set_object"},
    {ERR_FUNC(X509_F_X509_NAME_ONELINE), "X509_NAME_oneline"},
    {ERR_FUNC(X509_F_X509_NAME_PRINT), "X509_NAME_print"},
    {ERR_FUNC(X509_F_X509_PRINT_EX_FP), "X509_print_ex_fp"},
    {ERR_FUNC(X509_F_X509_PUBKEY_GET), "X509_PUBKEY_get"},
    {ERR_FUNC(X509_F_X509_PUBKEY_SET), "X509_PUBKEY_set"},
    {ERR_FUNC(X509_F_X509_REQ_CHECK_PRIVATE_KEY),
     "X509_REQ_check_private_key"},
    {ERR_FUNC(X509_F_X509_REQ_PRINT_EX), "X509_REQ_print_ex"},
    {ERR_FUNC(X509_F_X509_REQ_PRINT_FP), "X509_REQ_print_fp"},
    {ERR_FUNC(X509_F_X509_REQ_TO_X509), "X509_REQ_to_X509"},
    {ERR_FUNC(X509_F_X509_STORE_ADD_CERT), "X509_STORE_add_cert"},
    {ERR_FUNC(X509_F_X509_STORE_ADD_CRL), "X509_STORE_add_crl"},
    {ERR_FUNC(X509_F_X509_STORE_CTX_GET1_ISSUER),
     "X509_STORE_CTX_get1_issuer"},
    {ERR_FUNC(X509_F_X509_STORE_CTX_INIT), "X509_STORE_CTX_init"},
    {ERR_FUNC(X509_F_X509_STORE_CTX_NEW), "X509_STORE_CTX_new"},
    {ERR_FUNC(X509_F_X509_STORE_CTX_PURPOSE_INHERIT),
     "X509_STORE_CTX_purpose_inherit"},
    {ERR_FUNC(X509_F_X509_TO_X509_REQ), "X509_to_X509_REQ"},
    {ERR_FUNC(X509_F_X509_TRUST_ADD), "X509_TRUST_add"},
    {ERR_FUNC(X509_F_X509_TRUST_SET), "X509_TRUST_set"},
    {ERR_FUNC(X509_F_X509_VERIFY_CERT), "X509_verify_cert"},
    {0, NULL}
};

static ERR_STRING_DATA X509_str_reasons[] = {
    {ERR_REASON(X509_R_AKID_MISMATCH), "akid mismatch"},
    {ERR_REASON(X509_R_BAD_X509_FILETYPE), "bad x509 filetype"},
    {ERR_REASON(X509_R_BASE64_DECODE_ERROR), "base64 decode error"},
    {ERR_REASON(X509_R_CANT_CHECK_DH_KEY), "cant check dh key"},
    {ERR_REASON(X509_R_CERT_ALREADY_IN_HASH_TABLE),
     "cert already in hash table"},
    {ERR_REASON(X509_R_CRL_ALREADY_DELTA), "crl already delta"},
    {ERR_REASON(X509_R_CRL_VERIFY_FAILURE), "crl verify failure"},
    {ERR_REASON(X509_R_ERR_ASN1_LIB), "err asn1 lib"},
    {ERR_REASON(X509_R_IDP_MISMATCH), "idp mismatch"},
    {ERR_REASON(X509_R_INVALID_DIRECTORY), "invalid directory"},
    {ERR_REASON(X509_R_INVALID_FIELD_NAME), "invalid field name"},
    {ERR_REASON(X509_R_INVALID_TRUST), "invalid trust"},
    {ERR_REASON(X509_R_ISSUER_MISMATCH), "issuer mismatch"},
    {ERR_REASON(X509_R_KEY_TYPE_MISMATCH), "key type mismatch"},
    {ERR_REASON(X509_R_KEY_VALUES_MISMATCH), "key values mismatch"},
    {ERR_REASON(X509_R_LOADING_CERT_DIR), "loading cert dir"},
    {ERR_REASON(X509_R_LOADING_DEFAULTS), "loading defaults"},
    {ERR_REASON(X509_R_METHOD_NOT_SUPPORTED), "method not supported"},
    {ERR_REASON(X509_R_NAME_TOO_LONG), "name too long"},
    {ERR_REASON(X509_R_NEWER_CRL_NOT_NEWER), "newer crl not newer"},
    {ERR_REASON(X509_R_NO_CERT_SET_FOR_US_TO_VERIFY),
     "no cert set for us to verify"},
    {ERR_REASON(X509_R_NO_CRL_NUMBER), "no crl number"},
    {ERR_REASON(X509_R_PUBLIC_KEY_DECODE_ERROR), "public key decode error"},
    {ERR_REASON(X509_R_PUBLIC_KEY_ENCODE_ERROR), "public key encode error"},
    {ERR_REASON(X509_R_SHOULD_RETRY), "should retry"},
    {ERR_REASON(X509_R_UNABLE_TO_FIND_PARAMETERS_IN_CHAIN),
     "unable to find parameters in chain"},
    {ERR_REASON(X509_R_UNABLE_TO_GET_CERTS_PUBLIC_KEY),
     "unable to get certs public key"},
    {ERR_REASON(X509_R_UNKNOWN_KEY_TYPE), "unknown key type"},
    {ERR_REASON(X509_R_UNKNOWN_NID), "unknown nid"},
    {ERR_REASON(X509_R_UNKNOWN_PURPOSE_ID), "unknown purpose id"},
    {ERR_REASON(X509_R_UNKNOWN_TRUST_ID), "unknown trust id"},
    {ERR_REASON(X509_R_UNSUPPORTED_ALGORITHM), "unsupported algorithm"},
    {ERR_REASON(X509_R_WRONG_LOOKUP_TYPE), "wrong lookup type"},
    {ERR_REASON(X509_R_WRONG_TYPE), "wrong type"},
    {0, NULL}
};

#endif

void ERR_load_X509_strings(void)
{
#ifndef OPENSSL_NO_ERR

    if (ERR_func_error_string(X509_str_functs[0].error) == NULL) {
        ERR_load_strings(0, X509_str_functs);
        ERR_load_strings(0, X509_str_reasons);
    }
#endif
}
/* crypto/x509/x509_ext.c */
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
// #include "stack.h"
// #include "cryptlib.h"
// #include "asn1.h"
// #include "objects.h"
// #include "evp.h"
// #include "x509.h"
// #include "x509v3.h"

int X509_CRL_get_ext_count(X509_CRL *x)
{
    return (X509v3_get_ext_count(x->crl->extensions));
}

int X509_CRL_get_ext_by_NID(X509_CRL *x, int nid, int lastpos)
{
    return (X509v3_get_ext_by_NID(x->crl->extensions, nid, lastpos));
}

int X509_CRL_get_ext_by_OBJ(X509_CRL *x, ASN1_OBJECT *obj, int lastpos)
{
    return (X509v3_get_ext_by_OBJ(x->crl->extensions, obj, lastpos));
}

int X509_CRL_get_ext_by_critical(X509_CRL *x, int crit, int lastpos)
{
    return (X509v3_get_ext_by_critical(x->crl->extensions, crit, lastpos));
}

X509_EXTENSION *X509_CRL_get_ext(X509_CRL *x, int loc)
{
    return (X509v3_get_ext(x->crl->extensions, loc));
}

X509_EXTENSION *X509_CRL_delete_ext(X509_CRL *x, int loc)
{
    return (X509v3_delete_ext(x->crl->extensions, loc));
}

void *X509_CRL_get_ext_d2i(X509_CRL *x, int nid, int *crit, int *idx)
{
    return X509V3_get_d2i(x->crl->extensions, nid, crit, idx);
}

int X509_CRL_add1_ext_i2d(X509_CRL *x, int nid, void *value, int crit,
                          unsigned long flags)
{
    return X509V3_add1_i2d(&x->crl->extensions, nid, value, crit, flags);
}

int X509_CRL_add_ext(X509_CRL *x, X509_EXTENSION *ex, int loc)
{
    return (X509v3_add_ext(&(x->crl->extensions), ex, loc) != NULL);
}

int X509_get_ext_count(X509 *x)
{
    return (X509v3_get_ext_count(x->cert_info->extensions));
}

int X509_get_ext_by_NID(X509 *x, int nid, int lastpos)
{
    return (X509v3_get_ext_by_NID(x->cert_info->extensions, nid, lastpos));
}

int X509_get_ext_by_OBJ(X509 *x, ASN1_OBJECT *obj, int lastpos)
{
    return (X509v3_get_ext_by_OBJ(x->cert_info->extensions, obj, lastpos));
}

int X509_get_ext_by_critical(X509 *x, int crit, int lastpos)
{
    return (X509v3_get_ext_by_critical
            (x->cert_info->extensions, crit, lastpos));
}

X509_EXTENSION *X509_get_ext(X509 *x, int loc)
{
    return (X509v3_get_ext(x->cert_info->extensions, loc));
}

X509_EXTENSION *X509_delete_ext(X509 *x, int loc)
{
    return (X509v3_delete_ext(x->cert_info->extensions, loc));
}

int X509_add_ext(X509 *x, X509_EXTENSION *ex, int loc)
{
    return (X509v3_add_ext(&(x->cert_info->extensions), ex, loc) != NULL);
}

void *X509_get_ext_d2i(X509 *x, int nid, int *crit, int *idx)
{
    return X509V3_get_d2i(x->cert_info->extensions, nid, crit, idx);
}

int X509_add1_ext_i2d(X509 *x, int nid, void *value, int crit,
                      unsigned long flags)
{
    return X509V3_add1_i2d(&x->cert_info->extensions, nid, value, crit,
                           flags);
}

int X509_REVOKED_get_ext_count(X509_REVOKED *x)
{
    return (X509v3_get_ext_count(x->extensions));
}

int X509_REVOKED_get_ext_by_NID(X509_REVOKED *x, int nid, int lastpos)
{
    return (X509v3_get_ext_by_NID(x->extensions, nid, lastpos));
}

int X509_REVOKED_get_ext_by_OBJ(X509_REVOKED *x, ASN1_OBJECT *obj,
                                int lastpos)
{
    return (X509v3_get_ext_by_OBJ(x->extensions, obj, lastpos));
}

int X509_REVOKED_get_ext_by_critical(X509_REVOKED *x, int crit, int lastpos)
{
    return (X509v3_get_ext_by_critical(x->extensions, crit, lastpos));
}

X509_EXTENSION *X509_REVOKED_get_ext(X509_REVOKED *x, int loc)
{
    return (X509v3_get_ext(x->extensions, loc));
}

X509_EXTENSION *X509_REVOKED_delete_ext(X509_REVOKED *x, int loc)
{
    return (X509v3_delete_ext(x->extensions, loc));
}

int X509_REVOKED_add_ext(X509_REVOKED *x, X509_EXTENSION *ex, int loc)
{
    return (X509v3_add_ext(&(x->extensions), ex, loc) != NULL);
}

void *X509_REVOKED_get_ext_d2i(X509_REVOKED *x, int nid, int *crit, int *idx)
{
    return X509V3_get_d2i(x->extensions, nid, crit, idx);
}

int X509_REVOKED_add1_ext_i2d(X509_REVOKED *x, int nid, void *value, int crit,
                              unsigned long flags)
{
    return X509V3_add1_i2d(&x->extensions, nid, value, crit, flags);
}

IMPLEMENT_STACK_OF(X509_EXTENSION)

IMPLEMENT_ASN1_SET_OF(X509_EXTENSION)
/* crypto/x509/x509_lu.c */
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
#include "lhash.h"
// #include "x509.h"
// #include "x509v3.h"

X509_LOOKUP *X509_LOOKUP_new(X509_LOOKUP_METHOD *method)
{
    X509_LOOKUP *ret;

    ret = (X509_LOOKUP *)OPENSSL_malloc(sizeof(X509_LOOKUP));
    if (ret == NULL)
        return NULL;

    ret->init = 0;
    ret->skip = 0;
    ret->method = method;
    ret->method_data = NULL;
    ret->store_ctx = NULL;
    if ((method->new_item != NULL) && !method->new_item(ret)) {
        OPENSSL_free(ret);
        return NULL;
    }
    return ret;
}

void X509_LOOKUP_free(X509_LOOKUP *ctx)
{
    if (ctx == NULL)
        return;
    if ((ctx->method != NULL) && (ctx->method->free != NULL))
        (*ctx->method->free) (ctx);
    OPENSSL_free(ctx);
}

int X509_LOOKUP_init(X509_LOOKUP *ctx)
{
    if (ctx->method == NULL)
        return 0;
    if (ctx->method->init != NULL)
        return ctx->method->init(ctx);
    else
        return 1;
}

int X509_LOOKUP_shutdown(X509_LOOKUP *ctx)
{
    if (ctx->method == NULL)
        return 0;
    if (ctx->method->shutdown != NULL)
        return ctx->method->shutdown(ctx);
    else
        return 1;
}

int X509_LOOKUP_ctrl(X509_LOOKUP *ctx, int cmd, const char *argc, long argl,
                     char **ret)
{
    if (ctx->method == NULL)
        return -1;
    if (ctx->method->ctrl != NULL)
        return ctx->method->ctrl(ctx, cmd, argc, argl, ret);
    else
        return 1;
}

int X509_LOOKUP_by_subject(X509_LOOKUP *ctx, int type, X509_NAME *name,
                           X509_OBJECT *ret)
{
    if ((ctx->method == NULL) || (ctx->method->get_by_subject == NULL))
        return X509_LU_FAIL;
    if (ctx->skip)
        return 0;
    return ctx->method->get_by_subject(ctx, type, name, ret);
}

int X509_LOOKUP_by_issuer_serial(X509_LOOKUP *ctx, int type, X509_NAME *name,
                                 ASN1_INTEGER *serial, X509_OBJECT *ret)
{
    if ((ctx->method == NULL) || (ctx->method->get_by_issuer_serial == NULL))
        return X509_LU_FAIL;
    return ctx->method->get_by_issuer_serial(ctx, type, name, serial, ret);
}

int X509_LOOKUP_by_fingerprint(X509_LOOKUP *ctx, int type,
                               unsigned char *bytes, int len,
                               X509_OBJECT *ret)
{
    if ((ctx->method == NULL) || (ctx->method->get_by_fingerprint == NULL))
        return X509_LU_FAIL;
    return ctx->method->get_by_fingerprint(ctx, type, bytes, len, ret);
}

int X509_LOOKUP_by_alias(X509_LOOKUP *ctx, int type, char *str, int len,
                         X509_OBJECT *ret)
{
    if ((ctx->method == NULL) || (ctx->method->get_by_alias == NULL))
        return X509_LU_FAIL;
    return ctx->method->get_by_alias(ctx, type, str, len, ret);
}

static int x509_object_cmp(const X509_OBJECT *const *a,
                           const X509_OBJECT *const *b)
{
    int ret;

    ret = ((*a)->type - (*b)->type);
    if (ret)
        return ret;
    switch ((*a)->type) {
    case X509_LU_X509:
        ret = X509_subject_name_cmp((*a)->data.x509, (*b)->data.x509);
        break;
    case X509_LU_CRL:
        ret = X509_CRL_cmp((*a)->data.crl, (*b)->data.crl);
        break;
    default:
        /* abort(); */
        return 0;
    }
    return ret;
}

X509_STORE *X509_STORE_new(void)
{
    X509_STORE *ret;

    if ((ret = (X509_STORE *)OPENSSL_malloc(sizeof(X509_STORE))) == NULL)
        return NULL;
    if ((ret->objs = sk_X509_OBJECT_new(x509_object_cmp)) == NULL)
        goto err0;
    ret->cache = 1;
    if ((ret->get_cert_methods = sk_X509_LOOKUP_new_null()) == NULL)
        goto err1;
    ret->verify = 0;
    ret->verify_cb = 0;

    if ((ret->param = X509_VERIFY_PARAM_new()) == NULL)
        goto err2;

    ret->get_issuer = 0;
    ret->check_issued = 0;
    ret->check_revocation = 0;
    ret->get_crl = 0;
    ret->check_crl = 0;
    ret->cert_crl = 0;
    ret->lookup_certs = 0;
    ret->lookup_crls = 0;
    ret->cleanup = 0;

    if (!CRYPTO_new_ex_data(CRYPTO_EX_INDEX_X509_STORE, ret, &ret->ex_data))
       goto err3;

    ret->references = 1;
    return ret;

 err3:
    X509_VERIFY_PARAM_free(ret->param);
 err2:
    sk_X509_LOOKUP_free(ret->get_cert_methods);
 err1:
    sk_X509_OBJECT_free(ret->objs);
 err0:
    OPENSSL_free(ret);
    return NULL;
}

static void cleanup(X509_OBJECT *a)
{
    if (!a)
        return;
    if (a->type == X509_LU_X509) {
        X509_free(a->data.x509);
    } else if (a->type == X509_LU_CRL) {
        X509_CRL_free(a->data.crl);
    } else {
        /* abort(); */
    }

    OPENSSL_free(a);
}

void X509_STORE_free(X509_STORE *vfy)
{
    int i;
    STACK_OF(X509_LOOKUP) *sk;
    X509_LOOKUP *lu;

    if (vfy == NULL)
        return;

    i = CRYPTO_add(&vfy->references, -1, CRYPTO_LOCK_X509_STORE);
#ifdef REF_PRINT
    REF_PRINT("X509_STORE", vfy);
#endif
    if (i > 0)
        return;
#ifdef REF_CHECK
    if (i < 0) {
        fprintf(stderr, "X509_STORE_free, bad reference count\n");
        abort();                /* ok */
    }
#endif

    sk = vfy->get_cert_methods;
    for (i = 0; i < sk_X509_LOOKUP_num(sk); i++) {
        lu = sk_X509_LOOKUP_value(sk, i);
        X509_LOOKUP_shutdown(lu);
        X509_LOOKUP_free(lu);
    }
    sk_X509_LOOKUP_free(sk);
    sk_X509_OBJECT_pop_free(vfy->objs, cleanup);

    CRYPTO_free_ex_data(CRYPTO_EX_INDEX_X509_STORE, vfy, &vfy->ex_data);
    if (vfy->param)
        X509_VERIFY_PARAM_free(vfy->param);
    OPENSSL_free(vfy);
}

X509_LOOKUP *X509_STORE_add_lookup(X509_STORE *v, X509_LOOKUP_METHOD *m)
{
    int i;
    STACK_OF(X509_LOOKUP) *sk;
    X509_LOOKUP *lu;

    sk = v->get_cert_methods;
    for (i = 0; i < sk_X509_LOOKUP_num(sk); i++) {
        lu = sk_X509_LOOKUP_value(sk, i);
        if (m == lu->method) {
            return lu;
        }
    }
    /* a new one */
    lu = X509_LOOKUP_new(m);
    if (lu == NULL)
        return NULL;
    else {
        lu->store_ctx = v;
        if (sk_X509_LOOKUP_push(v->get_cert_methods, lu))
            return lu;
        else {
            X509_LOOKUP_free(lu);
            return NULL;
        }
    }
}

int X509_STORE_get_by_subject(X509_STORE_CTX *vs, int type, X509_NAME *name,
                              X509_OBJECT *ret)
{
    X509_STORE *ctx = vs->ctx;
    X509_LOOKUP *lu;
    X509_OBJECT stmp, *tmp;
    int i, j;

    if (ctx == NULL)
        return 0;

    CRYPTO_w_lock(CRYPTO_LOCK_X509_STORE);

    tmp = X509_OBJECT_retrieve_by_subject(ctx->objs, type, name);
    CRYPTO_w_unlock(CRYPTO_LOCK_X509_STORE);

    if (tmp == NULL || type == X509_LU_CRL) {
        for (i = vs->current_method;
             i < sk_X509_LOOKUP_num(ctx->get_cert_methods); i++) {
            lu = sk_X509_LOOKUP_value(ctx->get_cert_methods, i);
            j = X509_LOOKUP_by_subject(lu, type, name, &stmp);
            if (j < 0) {
                vs->current_method = j;
                return j;
            } else if (j) {
                tmp = &stmp;
                break;
            }
        }
        vs->current_method = 0;
        if (tmp == NULL)
            return 0;
    }

/*- if (ret->data.ptr != NULL)
            X509_OBJECT_free_contents(ret); */

    ret->type = tmp->type;
    ret->data.ptr = tmp->data.ptr;

    X509_OBJECT_up_ref_count(ret);

    return 1;
}

int X509_STORE_add_cert(X509_STORE *ctx, X509 *x)
{
    X509_OBJECT *obj;
    int ret = 1;

    if (x == NULL)
        return 0;
    obj = (X509_OBJECT *)OPENSSL_malloc(sizeof(X509_OBJECT));
    if (obj == NULL) {
        X509err(X509_F_X509_STORE_ADD_CERT, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    obj->type = X509_LU_X509;
    obj->data.x509 = x;

    CRYPTO_w_lock(CRYPTO_LOCK_X509_STORE);

    X509_OBJECT_up_ref_count(obj);

    if (X509_OBJECT_retrieve_match(ctx->objs, obj)) {
        X509_OBJECT_free_contents(obj);
        OPENSSL_free(obj);
        X509err(X509_F_X509_STORE_ADD_CERT,
                X509_R_CERT_ALREADY_IN_HASH_TABLE);
        ret = 0;
    } else if (!sk_X509_OBJECT_push(ctx->objs, obj)) {
        X509_OBJECT_free_contents(obj);
        OPENSSL_free(obj);
        X509err(X509_F_X509_STORE_ADD_CERT, ERR_R_MALLOC_FAILURE);
        ret = 0;
    }

    CRYPTO_w_unlock(CRYPTO_LOCK_X509_STORE);

    return ret;
}

int X509_STORE_add_crl(X509_STORE *ctx, X509_CRL *x)
{
    X509_OBJECT *obj;
    int ret = 1;

    if (x == NULL)
        return 0;
    obj = (X509_OBJECT *)OPENSSL_malloc(sizeof(X509_OBJECT));
    if (obj == NULL) {
        X509err(X509_F_X509_STORE_ADD_CRL, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    obj->type = X509_LU_CRL;
    obj->data.crl = x;

    CRYPTO_w_lock(CRYPTO_LOCK_X509_STORE);

    X509_OBJECT_up_ref_count(obj);

    if (X509_OBJECT_retrieve_match(ctx->objs, obj)) {
        X509_OBJECT_free_contents(obj);
        OPENSSL_free(obj);
        X509err(X509_F_X509_STORE_ADD_CRL, X509_R_CERT_ALREADY_IN_HASH_TABLE);
        ret = 0;
    } else if (!sk_X509_OBJECT_push(ctx->objs, obj)) {
        X509_OBJECT_free_contents(obj);
        OPENSSL_free(obj);
        X509err(X509_F_X509_STORE_ADD_CRL, ERR_R_MALLOC_FAILURE);
        ret = 0;
    }

    CRYPTO_w_unlock(CRYPTO_LOCK_X509_STORE);

    return ret;
}

void X509_OBJECT_up_ref_count(X509_OBJECT *a)
{
    switch (a->type) {
    case X509_LU_X509:
        CRYPTO_add(&a->data.x509->references, 1, CRYPTO_LOCK_X509);
        break;
    case X509_LU_CRL:
        CRYPTO_add(&a->data.crl->references, 1, CRYPTO_LOCK_X509_CRL);
        break;
    }
}

void X509_OBJECT_free_contents(X509_OBJECT *a)
{
    switch (a->type) {
    case X509_LU_X509:
        X509_free(a->data.x509);
        break;
    case X509_LU_CRL:
        X509_CRL_free(a->data.crl);
        break;
    }
}

static int x509_object_idx_cnt(STACK_OF(X509_OBJECT) *h, int type,
                               X509_NAME *name, int *pnmatch)
{
    X509_OBJECT stmp;
    X509 x509_s;
    X509_CINF cinf_s;
    X509_CRL crl_s;
    X509_CRL_INFO crl_info_s;
    int idx;

    stmp.type = type;
    switch (type) {
    case X509_LU_X509:
        stmp.data.x509 = &x509_s;
        x509_s.cert_info = &cinf_s;
        cinf_s.subject = name;
        break;
    case X509_LU_CRL:
        stmp.data.crl = &crl_s;
        crl_s.crl = &crl_info_s;
        crl_info_s.issuer = name;
        break;
    default:
        /* abort(); */
        return -1;
    }

    idx = sk_X509_OBJECT_find(h, &stmp);
    if (idx >= 0 && pnmatch) {
        int tidx;
        const X509_OBJECT *tobj, *pstmp;
        *pnmatch = 1;
        pstmp = &stmp;
        for (tidx = idx + 1; tidx < sk_X509_OBJECT_num(h); tidx++) {
            tobj = sk_X509_OBJECT_value(h, tidx);
            if (x509_object_cmp(&tobj, &pstmp))
                break;
            (*pnmatch)++;
        }
    }
    return idx;
}

int X509_OBJECT_idx_by_subject(STACK_OF(X509_OBJECT) *h, int type,
                               X509_NAME *name)
{
    return x509_object_idx_cnt(h, type, name, NULL);
}

X509_OBJECT *X509_OBJECT_retrieve_by_subject(STACK_OF(X509_OBJECT) *h,
                                             int type, X509_NAME *name)
{
    int idx;
    idx = X509_OBJECT_idx_by_subject(h, type, name);
    if (idx == -1)
        return NULL;
    return sk_X509_OBJECT_value(h, idx);
}

STACK_OF(X509) *X509_STORE_get1_certs(X509_STORE_CTX *ctx, X509_NAME *nm)
{
    int i, idx, cnt;
    STACK_OF(X509) *sk;
    X509 *x;
    X509_OBJECT *obj;

    if (ctx->ctx == NULL)
        return NULL;

    sk = sk_X509_new_null();
    CRYPTO_w_lock(CRYPTO_LOCK_X509_STORE);
    idx = x509_object_idx_cnt(ctx->ctx->objs, X509_LU_X509, nm, &cnt);
    if (idx < 0) {
        /*
         * Nothing found in cache: do lookup to possibly add new objects to
         * cache
         */
        X509_OBJECT xobj;
        CRYPTO_w_unlock(CRYPTO_LOCK_X509_STORE);
        if (!X509_STORE_get_by_subject(ctx, X509_LU_X509, nm, &xobj)) {
            sk_X509_free(sk);
            return NULL;
        }
        X509_OBJECT_free_contents(&xobj);
        CRYPTO_w_lock(CRYPTO_LOCK_X509_STORE);
        idx = x509_object_idx_cnt(ctx->ctx->objs, X509_LU_X509, nm, &cnt);
        if (idx < 0) {
            CRYPTO_w_unlock(CRYPTO_LOCK_X509_STORE);
            sk_X509_free(sk);
            return NULL;
        }
    }
    for (i = 0; i < cnt; i++, idx++) {
        obj = sk_X509_OBJECT_value(ctx->ctx->objs, idx);
        x = obj->data.x509;
        CRYPTO_add(&x->references, 1, CRYPTO_LOCK_X509);
        if (!sk_X509_push(sk, x)) {
            CRYPTO_w_unlock(CRYPTO_LOCK_X509_STORE);
            X509_free(x);
            sk_X509_pop_free(sk, X509_free);
            return NULL;
        }
    }
    CRYPTO_w_unlock(CRYPTO_LOCK_X509_STORE);
    return sk;

}

STACK_OF(X509_CRL) *X509_STORE_get1_crls(X509_STORE_CTX *ctx, X509_NAME *nm)
{
    int i, idx, cnt;
    STACK_OF(X509_CRL) *sk;
    X509_CRL *x;
    X509_OBJECT *obj, xobj;


    if (ctx->ctx == NULL)
        return NULL;

    sk = sk_X509_CRL_new_null();
    CRYPTO_w_lock(CRYPTO_LOCK_X509_STORE);

    /*
     * Always do lookup to possibly add new CRLs to cache
     */
    CRYPTO_w_unlock(CRYPTO_LOCK_X509_STORE);
    if (!X509_STORE_get_by_subject(ctx, X509_LU_CRL, nm, &xobj)) {
        sk_X509_CRL_free(sk);
        return NULL;
    }
    X509_OBJECT_free_contents(&xobj);
    CRYPTO_w_lock(CRYPTO_LOCK_X509_STORE);
    idx = x509_object_idx_cnt(ctx->ctx->objs, X509_LU_CRL, nm, &cnt);
    if (idx < 0) {
        CRYPTO_w_unlock(CRYPTO_LOCK_X509_STORE);
        sk_X509_CRL_free(sk);
        return NULL;
    }

    for (i = 0; i < cnt; i++, idx++) {
        obj = sk_X509_OBJECT_value(ctx->ctx->objs, idx);
        x = obj->data.crl;
        CRYPTO_add(&x->references, 1, CRYPTO_LOCK_X509_CRL);
        if (!sk_X509_CRL_push(sk, x)) {
            CRYPTO_w_unlock(CRYPTO_LOCK_X509_STORE);
            X509_CRL_free(x);
            sk_X509_CRL_pop_free(sk, X509_CRL_free);
            return NULL;
        }
    }
    CRYPTO_w_unlock(CRYPTO_LOCK_X509_STORE);
    return sk;
}

X509_OBJECT *X509_OBJECT_retrieve_match(STACK_OF(X509_OBJECT) *h,
                                        X509_OBJECT *x)
{
    int idx, i;
    X509_OBJECT *obj;
    idx = sk_X509_OBJECT_find(h, x);
    if (idx == -1)
        return NULL;
    if ((x->type != X509_LU_X509) && (x->type != X509_LU_CRL))
        return sk_X509_OBJECT_value(h, idx);
    for (i = idx; i < sk_X509_OBJECT_num(h); i++) {
        obj = sk_X509_OBJECT_value(h, i);
        if (x509_object_cmp
            ((const X509_OBJECT **)&obj, (const X509_OBJECT **)&x))
            return NULL;
        if (x->type == X509_LU_X509) {
            if (!X509_cmp(obj->data.x509, x->data.x509))
                return obj;
        } else if (x->type == X509_LU_CRL) {
            if (!X509_CRL_match(obj->data.crl, x->data.crl))
                return obj;
        } else
            return obj;
    }
    return NULL;
}

/*-
 * Try to get issuer certificate from store. Due to limitations
 * of the API this can only retrieve a single certificate matching
 * a given subject name. However it will fill the cache with all
 * matching certificates, so we can examine the cache for all
 * matches.
 *
 * Return values are:
 *  1 lookup successful.
 *  0 certificate not found.
 * -1 some other error.
 */
int X509_STORE_CTX_get1_issuer(X509 **issuer, X509_STORE_CTX *ctx, X509 *x)
{
    X509_NAME *xn;
    X509_OBJECT obj, *pobj;
    int i, ok, idx, ret;
    xn = X509_get_issuer_name(x);
    ok = X509_STORE_get_by_subject(ctx, X509_LU_X509, xn, &obj);
    if (ok != X509_LU_X509) {
        if (ok == X509_LU_RETRY) {
            X509_OBJECT_free_contents(&obj);
            X509err(X509_F_X509_STORE_CTX_GET1_ISSUER, X509_R_SHOULD_RETRY);
            return -1;
        } else if (ok != X509_LU_FAIL) {
            X509_OBJECT_free_contents(&obj);
            /* not good :-(, break anyway */
            return -1;
        }
        return 0;
    }
    /* If certificate matches all OK */
    if (ctx->check_issued(ctx, x, obj.data.x509)) {
        *issuer = obj.data.x509;
        return 1;
    }
    X509_OBJECT_free_contents(&obj);

    if (ctx->ctx == NULL)
        return 0;

    /* Else find index of first cert accepted by 'check_issued' */
    ret = 0;
    CRYPTO_w_lock(CRYPTO_LOCK_X509_STORE);
    idx = X509_OBJECT_idx_by_subject(ctx->ctx->objs, X509_LU_X509, xn);
    if (idx != -1) {            /* should be true as we've had at least one
                                 * match */
        /* Look through all matching certs for suitable issuer */
        for (i = idx; i < sk_X509_OBJECT_num(ctx->ctx->objs); i++) {
            pobj = sk_X509_OBJECT_value(ctx->ctx->objs, i);
            /* See if we've run past the matches */
            if (pobj->type != X509_LU_X509)
                break;
            if (X509_NAME_cmp(xn, X509_get_subject_name(pobj->data.x509)))
                break;
            if (ctx->check_issued(ctx, x, pobj->data.x509)) {
                *issuer = pobj->data.x509;
                X509_OBJECT_up_ref_count(pobj);
                ret = 1;
                break;
            }
        }
    }
    CRYPTO_w_unlock(CRYPTO_LOCK_X509_STORE);
    return ret;
}

int X509_STORE_set_flags(X509_STORE *ctx, unsigned long flags)
{
    return X509_VERIFY_PARAM_set_flags(ctx->param, flags);
}

int X509_STORE_set_depth(X509_STORE *ctx, int depth)
{
    X509_VERIFY_PARAM_set_depth(ctx->param, depth);
    return 1;
}

int X509_STORE_set_purpose(X509_STORE *ctx, int purpose)
{
    return X509_VERIFY_PARAM_set_purpose(ctx->param, purpose);
}

int X509_STORE_set_trust(X509_STORE *ctx, int trust)
{
    return X509_VERIFY_PARAM_set_trust(ctx->param, trust);
}

int X509_STORE_set1_param(X509_STORE *ctx, X509_VERIFY_PARAM *param)
{
    return X509_VERIFY_PARAM_set1(ctx->param, param);
}

void X509_STORE_set_verify_cb(X509_STORE *ctx,
                              int (*verify_cb) (int, X509_STORE_CTX *))
{
    ctx->verify_cb = verify_cb;
}

void X509_STORE_set_lookup_crls_cb(X509_STORE *ctx,
                                   STACK_OF(X509_CRL) *(*cb) (X509_STORE_CTX
                                                              *ctx,
                                                              X509_NAME *nm))
{
    ctx->lookup_crls = cb;
}

X509_STORE *X509_STORE_CTX_get0_store(X509_STORE_CTX *ctx)
{
    return ctx->ctx;
}

IMPLEMENT_STACK_OF(X509_LOOKUP)

IMPLEMENT_STACK_OF(X509_OBJECT)
/* crypto/x509/x509_obj.c */
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
// #include "lhash.h"
// #include "objects.h"
// #include "x509.h"
#include "buffer.h"

/*
 * Limit to ensure we don't overflow: much greater than
 * anything enountered in practice.
 */

#define NAME_ONELINE_MAX    (1024 * 1024)

char *X509_NAME_oneline(X509_NAME *a, char *buf, int len)
{
    X509_NAME_ENTRY *ne;
    int i;
    int n, lold, l, l1, l2, num, j, type;
    const char *s;
    char *p;
    unsigned char *q;
    BUF_MEM *b = NULL;
    static const char hex[17] = "0123456789ABCDEF";
    int gs_doit[4];
    char tmp_buf[80];
#ifdef CHARSET_EBCDIC
    char ebcdic_buf[1024];
#endif

    if (buf == NULL) {
        if ((b = BUF_MEM_new()) == NULL)
            goto err;
        if (!BUF_MEM_grow(b, 200))
            goto err;
        b->data[0] = '\0';
        len = 200;
    } else if (len == 0) {
        return NULL;
    }
    if (a == NULL) {
        if (b) {
            buf = b->data;
            OPENSSL_free(b);
        }
        strncpy(buf, "NO X509_NAME", len);
        buf[len - 1] = '\0';
        return buf;
    }

    len--;                      /* space for '\0' */
    l = 0;
    for (i = 0; i < sk_X509_NAME_ENTRY_num(a->entries); i++) {
        ne = sk_X509_NAME_ENTRY_value(a->entries, i);
        n = OBJ_obj2nid(ne->object);
        if ((n == NID_undef) || ((s = OBJ_nid2sn(n)) == NULL)) {
            i2t_ASN1_OBJECT(tmp_buf, sizeof(tmp_buf), ne->object);
            s = tmp_buf;
        }
        l1 = strlen(s);

        type = ne->value->type;
        num = ne->value->length;
        if (num > NAME_ONELINE_MAX) {
            X509err(X509_F_X509_NAME_ONELINE, X509_R_NAME_TOO_LONG);
            goto end;
        }
        q = ne->value->data;
#ifdef CHARSET_EBCDIC
        if (type == V_ASN1_GENERALSTRING ||
            type == V_ASN1_VISIBLESTRING ||
            type == V_ASN1_PRINTABLESTRING ||
            type == V_ASN1_TELETEXSTRING ||
            type == V_ASN1_IA5STRING) {
            if (num > (int)sizeof(ebcdic_buf))
                num = sizeof(ebcdic_buf);
            ascii2ebcdic(ebcdic_buf, q, num);
            q = ebcdic_buf;
        }
#endif

        if ((type == V_ASN1_GENERALSTRING) && ((num % 4) == 0)) {
            gs_doit[0] = gs_doit[1] = gs_doit[2] = gs_doit[3] = 0;
            for (j = 0; j < num; j++)
                if (q[j] != 0)
                    gs_doit[j & 3] = 1;

            if (gs_doit[0] | gs_doit[1] | gs_doit[2])
                gs_doit[0] = gs_doit[1] = gs_doit[2] = gs_doit[3] = 1;
            else {
                gs_doit[0] = gs_doit[1] = gs_doit[2] = 0;
                gs_doit[3] = 1;
            }
        } else
            gs_doit[0] = gs_doit[1] = gs_doit[2] = gs_doit[3] = 1;

        for (l2 = j = 0; j < num; j++) {
            if (!gs_doit[j & 3])
                continue;
            l2++;
#ifndef CHARSET_EBCDIC
            if ((q[j] < ' ') || (q[j] > '~'))
                l2 += 3;
#else
            if ((os_toascii[q[j]] < os_toascii[' ']) ||
                (os_toascii[q[j]] > os_toascii['~']))
                l2 += 3;
#endif
        }

        lold = l;
        l += 1 + l1 + 1 + l2;
        if (l > NAME_ONELINE_MAX) {
            X509err(X509_F_X509_NAME_ONELINE, X509_R_NAME_TOO_LONG);
            goto end;
        }
        if (b != NULL) {
            if (!BUF_MEM_grow(b, l + 1))
                goto err;
            p = &(b->data[lold]);
        } else if (l > len) {
            break;
        } else
            p = &(buf[lold]);
        *(p++) = '/';
        memcpy(p, s, (unsigned int)l1);
        p += l1;
        *(p++) = '=';

#ifndef CHARSET_EBCDIC          /* q was assigned above already. */
        q = ne->value->data;
#endif

        for (j = 0; j < num; j++) {
            if (!gs_doit[j & 3])
                continue;
#ifndef CHARSET_EBCDIC
            n = q[j];
            if ((n < ' ') || (n > '~')) {
                *(p++) = '\\';
                *(p++) = 'x';
                *(p++) = hex[(n >> 4) & 0x0f];
                *(p++) = hex[n & 0x0f];
            } else
                *(p++) = n;
#else
            n = os_toascii[q[j]];
            if ((n < os_toascii[' ']) || (n > os_toascii['~'])) {
                *(p++) = '\\';
                *(p++) = 'x';
                *(p++) = hex[(n >> 4) & 0x0f];
                *(p++) = hex[n & 0x0f];
            } else
                *(p++) = q[j];
#endif
        }
        *p = '\0';
    }
    if (b != NULL) {
        p = b->data;
        OPENSSL_free(b);
    } else
        p = buf;
    if (i == 0)
        *p = '\0';
    return (p);
 err:
    X509err(X509_F_X509_NAME_ONELINE, ERR_R_MALLOC_FAILURE);
 end:
    BUF_MEM_free(b);
    return (NULL);
}
/* crypto/x509/x509_r2x.c */
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
#include "bn.h"
// #include "evp.h"
// #include "asn1.h"
// #include "x509.h"
// #include "objects.h"
// #include "buffer.h"

X509 *X509_REQ_to_X509(X509_REQ *r, int days, EVP_PKEY *pkey)
{
    X509 *ret = NULL;
    X509_CINF *xi = NULL;
    X509_NAME *xn;
    EVP_PKEY *pubkey = NULL;
    int res;

    if ((ret = X509_new()) == NULL) {
        X509err(X509_F_X509_REQ_TO_X509, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    /* duplicate the request */
    xi = ret->cert_info;

    if (sk_X509_ATTRIBUTE_num(r->req_info->attributes) != 0) {
        if ((xi->version = M_ASN1_INTEGER_new()) == NULL)
            goto err;
        if (!ASN1_INTEGER_set(xi->version, 2))
            goto err;
/*-     xi->extensions=ri->attributes; <- bad, should not ever be done
        ri->attributes=NULL; */
    }

    xn = X509_REQ_get_subject_name(r);
    if (X509_set_subject_name(ret, xn) == 0)
        goto err;
    if (X509_set_issuer_name(ret, xn) == 0)
        goto err;

    if (X509_gmtime_adj(xi->validity->notBefore, 0) == NULL)
        goto err;
    if (X509_gmtime_adj(xi->validity->notAfter, (long)60 * 60 * 24 * days) ==
        NULL)
        goto err;

    pubkey = X509_REQ_get_pubkey(r);
    res = X509_set_pubkey(ret, pubkey);
    EVP_PKEY_free(pubkey);

    if (!res || !X509_sign(ret, pkey, EVP_md5()))
        goto err;
    if (0) {
 err:
        X509_free(ret);
        ret = NULL;
    }
    return (ret);
}
/* crypto/x509/x509_req.c */
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
// #include "evp.h"
// #include "asn1.h"
#include "asn1t.h"
// #include "x509.h"
// #include "objects.h"
// #include "buffer.h"
#include "pem.h"

X509_REQ *X509_to_X509_REQ(X509 *x, EVP_PKEY *pkey, const EVP_MD *md)
{
    X509_REQ *ret;
    X509_REQ_INFO *ri;
    int i;
    EVP_PKEY *pktmp;

    ret = X509_REQ_new();
    if (ret == NULL) {
        X509err(X509_F_X509_TO_X509_REQ, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    ri = ret->req_info;

    ri->version->length = 1;
    ri->version->data = (unsigned char *)OPENSSL_malloc(1);
    if (ri->version->data == NULL)
        goto err;
    ri->version->data[0] = 0;   /* version == 0 */

    if (!X509_REQ_set_subject_name(ret, X509_get_subject_name(x)))
        goto err;

    pktmp = X509_get_pubkey(x);
    if (pktmp == NULL)
        goto err;
    i = X509_REQ_set_pubkey(ret, pktmp);
    EVP_PKEY_free(pktmp);
    if (!i)
        goto err;

    if (pkey != NULL) {
        if (!X509_REQ_sign(ret, pkey, md))
            goto err;
    }
    return (ret);
 err:
    X509_REQ_free(ret);
    return (NULL);
}

EVP_PKEY *X509_REQ_get_pubkey(X509_REQ *req)
{
    if ((req == NULL) || (req->req_info == NULL))
        return (NULL);
    return (X509_PUBKEY_get(req->req_info->pubkey));
}

int X509_REQ_check_private_key(X509_REQ *x, EVP_PKEY *k)
{
    EVP_PKEY *xk = NULL;
    int ok = 0;

    xk = X509_REQ_get_pubkey(x);
    switch (EVP_PKEY_cmp(xk, k)) {
    case 1:
        ok = 1;
        break;
    case 0:
        X509err(X509_F_X509_REQ_CHECK_PRIVATE_KEY,
                X509_R_KEY_VALUES_MISMATCH);
        break;
    case -1:
        X509err(X509_F_X509_REQ_CHECK_PRIVATE_KEY, X509_R_KEY_TYPE_MISMATCH);
        break;
    case -2:
#ifndef OPENSSL_NO_EC
        if (k->type == EVP_PKEY_EC) {
            X509err(X509_F_X509_REQ_CHECK_PRIVATE_KEY, ERR_R_EC_LIB);
            break;
        }
#endif
#ifndef OPENSSL_NO_DH
        if (k->type == EVP_PKEY_DH) {
            /* No idea */
            X509err(X509_F_X509_REQ_CHECK_PRIVATE_KEY,
                    X509_R_CANT_CHECK_DH_KEY);
            break;
        }
#endif
        X509err(X509_F_X509_REQ_CHECK_PRIVATE_KEY, X509_R_UNKNOWN_KEY_TYPE);
    }

    EVP_PKEY_free(xk);
    return (ok);
}

/*
 * It seems several organisations had the same idea of including a list of
 * extensions in a certificate request. There are at least two OIDs that are
 * used and there may be more: so the list is configurable.
 */

static int ext_nid_list[] = { NID_ext_req, NID_ms_ext_req, NID_undef };

static int *ext_nids = ext_nid_list;

int X509_REQ_extension_nid(int req_nid)
{
    int i, nid;
    for (i = 0;; i++) {
        nid = ext_nids[i];
        if (nid == NID_undef)
            return 0;
        else if (req_nid == nid)
            return 1;
    }
}

int *X509_REQ_get_extension_nids(void)
{
    return ext_nids;
}

void X509_REQ_set_extension_nids(int *nids)
{
    ext_nids = nids;
}

STACK_OF(X509_EXTENSION) *X509_REQ_get_extensions(X509_REQ *req)
{
    X509_ATTRIBUTE *attr;
    ASN1_TYPE *ext = NULL;
    int idx, *pnid;
    const unsigned char *p;

    if ((req == NULL) || (req->req_info == NULL) || !ext_nids)
        return (NULL);
    for (pnid = ext_nids; *pnid != NID_undef; pnid++) {
        idx = X509_REQ_get_attr_by_NID(req, *pnid, -1);
        if (idx == -1)
            continue;
        attr = X509_REQ_get_attr(req, idx);
        if (attr->single)
            ext = attr->value.single;
        else if (sk_ASN1_TYPE_num(attr->value.set))
            ext = sk_ASN1_TYPE_value(attr->value.set, 0);
        break;
    }
    if (!ext || (ext->type != V_ASN1_SEQUENCE))
        return NULL;
    p = ext->value.sequence->data;
    return (STACK_OF(X509_EXTENSION) *)
        ASN1_item_d2i(NULL, &p, ext->value.sequence->length,
                      ASN1_ITEM_rptr(X509_EXTENSIONS));
}

/*
 * Add a STACK_OF extensions to a certificate request: allow alternative OIDs
 * in case we want to create a non standard one.
 */

int X509_REQ_add_extensions_nid(X509_REQ *req, STACK_OF(X509_EXTENSION) *exts,
                                int nid)
{
    ASN1_TYPE *at = NULL;
    X509_ATTRIBUTE *attr = NULL;
    if (!(at = ASN1_TYPE_new()) || !(at->value.sequence = ASN1_STRING_new()))
        goto err;

    at->type = V_ASN1_SEQUENCE;
    /* Generate encoding of extensions */
    at->value.sequence->length =
        ASN1_item_i2d((ASN1_VALUE *)exts,
                      &at->value.sequence->data,
                      ASN1_ITEM_rptr(X509_EXTENSIONS));
    if (!(attr = X509_ATTRIBUTE_new()))
        goto err;
    if (!(attr->value.set = sk_ASN1_TYPE_new_null()))
        goto err;
    if (!sk_ASN1_TYPE_push(attr->value.set, at))
        goto err;
    at = NULL;
    attr->single = 0;
    attr->object = OBJ_nid2obj(nid);
    if (!req->req_info->attributes) {
        if (!(req->req_info->attributes = sk_X509_ATTRIBUTE_new_null()))
            goto err;
    }
    if (!sk_X509_ATTRIBUTE_push(req->req_info->attributes, attr))
        goto err;
    return 1;
 err:
    X509_ATTRIBUTE_free(attr);
    ASN1_TYPE_free(at);
    return 0;
}

/* This is the normal usage: use the "official" OID */
int X509_REQ_add_extensions(X509_REQ *req, STACK_OF(X509_EXTENSION) *exts)
{
    return X509_REQ_add_extensions_nid(req, exts, NID_ext_req);
}

/* Request attribute functions */

int X509_REQ_get_attr_count(const X509_REQ *req)
{
    return X509at_get_attr_count(req->req_info->attributes);
}

int X509_REQ_get_attr_by_NID(const X509_REQ *req, int nid, int lastpos)
{
    return X509at_get_attr_by_NID(req->req_info->attributes, nid, lastpos);
}

int X509_REQ_get_attr_by_OBJ(const X509_REQ *req, ASN1_OBJECT *obj,
                             int lastpos)
{
    return X509at_get_attr_by_OBJ(req->req_info->attributes, obj, lastpos);
}

X509_ATTRIBUTE *X509_REQ_get_attr(const X509_REQ *req, int loc)
{
    return X509at_get_attr(req->req_info->attributes, loc);
}

X509_ATTRIBUTE *X509_REQ_delete_attr(X509_REQ *req, int loc)
{
    return X509at_delete_attr(req->req_info->attributes, loc);
}

int X509_REQ_add1_attr(X509_REQ *req, X509_ATTRIBUTE *attr)
{
    if (X509at_add1_attr(&req->req_info->attributes, attr))
        return 1;
    return 0;
}

int X509_REQ_add1_attr_by_OBJ(X509_REQ *req,
                              const ASN1_OBJECT *obj, int type,
                              const unsigned char *bytes, int len)
{
    if (X509at_add1_attr_by_OBJ(&req->req_info->attributes, obj,
                                type, bytes, len))
        return 1;
    return 0;
}

int X509_REQ_add1_attr_by_NID(X509_REQ *req,
                              int nid, int type,
                              const unsigned char *bytes, int len)
{
    if (X509at_add1_attr_by_NID(&req->req_info->attributes, nid,
                                type, bytes, len))
        return 1;
    return 0;
}

int X509_REQ_add1_attr_by_txt(X509_REQ *req,
                              const char *attrname, int type,
                              const unsigned char *bytes, int len)
{
    if (X509at_add1_attr_by_txt(&req->req_info->attributes, attrname,
                                type, bytes, len))
        return 1;
    return 0;
}
/* crypto/x509/x509_set.c */
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
// #include "asn1.h"
// #include "objects.h"
// #include "evp.h"
// #include "x509.h"

int X509_set_version(X509 *x, long version)
{
    if (x == NULL)
        return (0);
    if (version == 0) {
        M_ASN1_INTEGER_free(x->cert_info->version);
        x->cert_info->version = NULL;
        return (1);
    }
    if (x->cert_info->version == NULL) {
        if ((x->cert_info->version = M_ASN1_INTEGER_new()) == NULL)
            return (0);
    }
    return (ASN1_INTEGER_set(x->cert_info->version, version));
}

int X509_set_serialNumber(X509 *x, ASN1_INTEGER *serial)
{
    ASN1_INTEGER *in;

    if (x == NULL)
        return (0);
    in = x->cert_info->serialNumber;
    if (in != serial) {
        in = M_ASN1_INTEGER_dup(serial);
        if (in != NULL) {
            M_ASN1_INTEGER_free(x->cert_info->serialNumber);
            x->cert_info->serialNumber = in;
        }
    }
    return (in != NULL);
}

int X509_set_issuer_name(X509 *x, X509_NAME *name)
{
    if ((x == NULL) || (x->cert_info == NULL))
        return (0);
    return (X509_NAME_set(&x->cert_info->issuer, name));
}

int X509_set_subject_name(X509 *x, X509_NAME *name)
{
    if ((x == NULL) || (x->cert_info == NULL))
        return (0);
    return (X509_NAME_set(&x->cert_info->subject, name));
}

int X509_set_notBefore(X509 *x, const ASN1_TIME *tm)
{
    ASN1_TIME *in;

    if ((x == NULL) || (x->cert_info->validity == NULL))
        return (0);
    in = x->cert_info->validity->notBefore;
    if (in != tm) {
        in = M_ASN1_TIME_dup(tm);
        if (in != NULL) {
            M_ASN1_TIME_free(x->cert_info->validity->notBefore);
            x->cert_info->validity->notBefore = in;
        }
    }
    return (in != NULL);
}

int X509_set_notAfter(X509 *x, const ASN1_TIME *tm)
{
    ASN1_TIME *in;

    if ((x == NULL) || (x->cert_info->validity == NULL))
        return (0);
    in = x->cert_info->validity->notAfter;
    if (in != tm) {
        in = M_ASN1_TIME_dup(tm);
        if (in != NULL) {
            M_ASN1_TIME_free(x->cert_info->validity->notAfter);
            x->cert_info->validity->notAfter = in;
        }
    }
    return (in != NULL);
}

int X509_set_pubkey(X509 *x, EVP_PKEY *pkey)
{
    if ((x == NULL) || (x->cert_info == NULL))
        return (0);
    return (X509_PUBKEY_set(&(x->cert_info->key), pkey));
}
/* x509_trs.c */
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
// #include "x509v3.h"

static int tr_cmp(const X509_TRUST *const *a, const X509_TRUST *const *b);
static void trtable_free(X509_TRUST *p);

static int trust_1oidany(X509_TRUST *trust, X509 *x, int flags);
static int trust_1oid(X509_TRUST *trust, X509 *x, int flags);
static int trust_compat(X509_TRUST *trust, X509 *x, int flags);

static int obj_trust(int id, X509 *x, int flags);
static int (*default_trust) (int id, X509 *x, int flags) = obj_trust;

/*
 * WARNING: the following table should be kept in order of trust and without
 * any gaps so we can just subtract the minimum trust value to get an index
 * into the table
 */

static X509_TRUST trstandard[] = {
    {X509_TRUST_COMPAT, 0, trust_compat, "compatible", 0, NULL},
    {X509_TRUST_SSL_CLIENT, 0, trust_1oidany, "SSL Client", NID_client_auth,
     NULL},
    {X509_TRUST_SSL_SERVER, 0, trust_1oidany, "SSL Server", NID_server_auth,
     NULL},
    {X509_TRUST_EMAIL, 0, trust_1oidany, "S/MIME email", NID_email_protect,
     NULL},
    {X509_TRUST_OBJECT_SIGN, 0, trust_1oidany, "Object Signer", NID_code_sign,
     NULL},
    {X509_TRUST_OCSP_SIGN, 0, trust_1oid, "OCSP responder", NID_OCSP_sign,
     NULL},
    {X509_TRUST_OCSP_REQUEST, 0, trust_1oid, "OCSP request", NID_ad_OCSP,
     NULL},
    {X509_TRUST_TSA, 0, trust_1oidany, "TSA server", NID_time_stamp, NULL}
};

#define X509_TRUST_COUNT        (sizeof(trstandard)/sizeof(X509_TRUST))

IMPLEMENT_STACK_OF(X509_TRUST)

static STACK_OF(X509_TRUST) *trtable = NULL;

static int tr_cmp(const X509_TRUST *const *a, const X509_TRUST *const *b)
{
    return (*a)->trust - (*b)->trust;
}

int (*X509_TRUST_set_default(int (*trust) (int, X509 *, int))) (int, X509 *,
                                                                int) {
    int (*oldtrust) (int, X509 *, int);
    oldtrust = default_trust;
    default_trust = trust;
    return oldtrust;
}

int X509_check_trust(X509 *x, int id, int flags)
{
    X509_TRUST *pt;
    int idx;
    if (id == -1)
        return 1;
    /* We get this as a default value */
    if (id == 0) {
        int rv;
        rv = obj_trust(NID_anyExtendedKeyUsage, x, 0);
        if (rv != X509_TRUST_UNTRUSTED)
            return rv;
        return trust_compat(NULL, x, 0);
    }
    idx = X509_TRUST_get_by_id(id);
    if (idx == -1)
        return default_trust(id, x, flags);
    pt = X509_TRUST_get0(idx);
    return pt->check_trust(pt, x, flags);
}

int X509_TRUST_get_count(void)
{
    if (!trtable)
        return X509_TRUST_COUNT;
    return sk_X509_TRUST_num(trtable) + X509_TRUST_COUNT;
}

X509_TRUST *X509_TRUST_get0(int idx)
{
    if (idx < 0)
        return NULL;
    if (idx < (int)X509_TRUST_COUNT)
        return trstandard + idx;
    return sk_X509_TRUST_value(trtable, idx - X509_TRUST_COUNT);
}

int X509_TRUST_get_by_id(int id)
{
    X509_TRUST tmp;
    int idx;
    if ((id >= X509_TRUST_MIN) && (id <= X509_TRUST_MAX))
        return id - X509_TRUST_MIN;
    tmp.trust = id;
    if (!trtable)
        return -1;
    idx = sk_X509_TRUST_find(trtable, &tmp);
    if (idx == -1)
        return -1;
    return idx + X509_TRUST_COUNT;
}

int X509_TRUST_set(int *t, int trust)
{
    if (X509_TRUST_get_by_id(trust) == -1) {
        X509err(X509_F_X509_TRUST_SET, X509_R_INVALID_TRUST);
        return 0;
    }
    *t = trust;
    return 1;
}

int X509_TRUST_add(int id, int flags, int (*ck) (X509_TRUST *, X509 *, int),
                   char *name, int arg1, void *arg2)
{
    int idx;
    X509_TRUST *trtmp;
    /*
     * This is set according to what we change: application can't set it
     */
    flags &= ~X509_TRUST_DYNAMIC;
    /* This will always be set for application modified trust entries */
    flags |= X509_TRUST_DYNAMIC_NAME;
    /* Get existing entry if any */
    idx = X509_TRUST_get_by_id(id);
    /* Need a new entry */
    if (idx == -1) {
        if (!(trtmp = OPENSSL_malloc(sizeof(X509_TRUST)))) {
            X509err(X509_F_X509_TRUST_ADD, ERR_R_MALLOC_FAILURE);
            return 0;
        }
        trtmp->flags = X509_TRUST_DYNAMIC;
    } else
        trtmp = X509_TRUST_get0(idx);

    /* OPENSSL_free existing name if dynamic */
    if (trtmp->flags & X509_TRUST_DYNAMIC_NAME)
        OPENSSL_free(trtmp->name);
    /* dup supplied name */
    if (!(trtmp->name = BUF_strdup(name))) {
        X509err(X509_F_X509_TRUST_ADD, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    /* Keep the dynamic flag of existing entry */
    trtmp->flags &= X509_TRUST_DYNAMIC;
    /* Set all other flags */
    trtmp->flags |= flags;

    trtmp->trust = id;
    trtmp->check_trust = ck;
    trtmp->arg1 = arg1;
    trtmp->arg2 = arg2;

    /* If its a new entry manage the dynamic table */
    if (idx == -1) {
        if (!trtable && !(trtable = sk_X509_TRUST_new(tr_cmp))) {
            X509err(X509_F_X509_TRUST_ADD, ERR_R_MALLOC_FAILURE);
            return 0;
        }
        if (!sk_X509_TRUST_push(trtable, trtmp)) {
            X509err(X509_F_X509_TRUST_ADD, ERR_R_MALLOC_FAILURE);
            return 0;
        }
    }
    return 1;
}

static void trtable_free(X509_TRUST *p)
{
    if (!p)
        return;
    if (p->flags & X509_TRUST_DYNAMIC) {
        if (p->flags & X509_TRUST_DYNAMIC_NAME)
            OPENSSL_free(p->name);
        OPENSSL_free(p);
    }
}

void X509_TRUST_cleanup(void)
{
    unsigned int i;
    for (i = 0; i < X509_TRUST_COUNT; i++)
        trtable_free(trstandard + i);
    sk_X509_TRUST_pop_free(trtable, trtable_free);
    trtable = NULL;
}

int X509_TRUST_get_flags(X509_TRUST *xp)
{
    return xp->flags;
}

char *X509_TRUST_get0_name(X509_TRUST *xp)
{
    return xp->name;
}

int X509_TRUST_get_trust(X509_TRUST *xp)
{
    return xp->trust;
}

static int trust_1oidany(X509_TRUST *trust, X509 *x, int flags)
{
    if (x->aux && (x->aux->trust || x->aux->reject))
        return obj_trust(trust->arg1, x, flags);
    /*
     * we don't have any trust settings: for compatibility we return trusted
     * if it is self signed
     */
    return trust_compat(trust, x, flags);
}

static int trust_1oid(X509_TRUST *trust, X509 *x, int flags)
{
    if (x->aux)
        return obj_trust(trust->arg1, x, flags);
    return X509_TRUST_UNTRUSTED;
}

static int trust_compat(X509_TRUST *trust, X509 *x, int flags)
{
    X509_check_purpose(x, -1, 0);
    if (x->ex_flags & EXFLAG_SS)
        return X509_TRUST_TRUSTED;
    else
        return X509_TRUST_UNTRUSTED;
}

static int obj_trust(int id, X509 *x, int flags)
{
    ASN1_OBJECT *obj;
    int i;
    X509_CERT_AUX *ax;
    ax = x->aux;
    if (!ax)
        return X509_TRUST_UNTRUSTED;
    if (ax->reject) {
        for (i = 0; i < sk_ASN1_OBJECT_num(ax->reject); i++) {
            obj = sk_ASN1_OBJECT_value(ax->reject, i);
            if (OBJ_obj2nid(obj) == id)
                return X509_TRUST_REJECTED;
        }
    }
    if (ax->trust) {
        for (i = 0; i < sk_ASN1_OBJECT_num(ax->trust); i++) {
            obj = sk_ASN1_OBJECT_value(ax->trust, i);
            if (OBJ_obj2nid(obj) == id)
                return X509_TRUST_TRUSTED;
        }
    }
    return X509_TRUST_UNTRUSTED;
}
/* crypto/x509/x509_txt.c */
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
#include <errno.h>

// #include "cryptlib.h"
// #include "lhash.h"
// #include "buffer.h"
// #include "evp.h"
// #include "asn1.h"
// #include "x509.h"
// #include "objects.h"

const char *X509_verify_cert_error_string(long n)
{
    static char buf[100];

    switch ((int)n) {
    case X509_V_OK:
        return ("ok");
    case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
        return ("unable to get issuer certificate");
    case X509_V_ERR_UNABLE_TO_GET_CRL:
        return ("unable to get certificate CRL");
    case X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE:
        return ("unable to decrypt certificate's signature");
    case X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE:
        return ("unable to decrypt CRL's signature");
    case X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY:
        return ("unable to decode issuer public key");
    case X509_V_ERR_CERT_SIGNATURE_FAILURE:
        return ("certificate signature failure");
    case X509_V_ERR_CRL_SIGNATURE_FAILURE:
        return ("CRL signature failure");
    case X509_V_ERR_CERT_NOT_YET_VALID:
        return ("certificate is not yet valid");
    case X509_V_ERR_CRL_NOT_YET_VALID:
        return ("CRL is not yet valid");
    case X509_V_ERR_CERT_HAS_EXPIRED:
        return ("certificate has expired");
    case X509_V_ERR_CRL_HAS_EXPIRED:
        return ("CRL has expired");
    case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
        return ("format error in certificate's notBefore field");
    case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
        return ("format error in certificate's notAfter field");
    case X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD:
        return ("format error in CRL's lastUpdate field");
    case X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD:
        return ("format error in CRL's nextUpdate field");
    case X509_V_ERR_OUT_OF_MEM:
        return ("out of memory");
    case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
        return ("self signed certificate");
    case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
        return ("self signed certificate in certificate chain");
    case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
        return ("unable to get local issuer certificate");
    case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
        return ("unable to verify the first certificate");
    case X509_V_ERR_CERT_CHAIN_TOO_LONG:
        return ("certificate chain too long");
    case X509_V_ERR_CERT_REVOKED:
        return ("certificate revoked");
    case X509_V_ERR_INVALID_CA:
        return ("invalid CA certificate");
    case X509_V_ERR_INVALID_NON_CA:
        return ("invalid non-CA certificate (has CA markings)");
    case X509_V_ERR_PATH_LENGTH_EXCEEDED:
        return ("path length constraint exceeded");
    case X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED:
        return ("proxy path length constraint exceeded");
    case X509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED:
        return
            ("proxy certificates not allowed, please set the appropriate flag");
    case X509_V_ERR_INVALID_PURPOSE:
        return ("unsupported certificate purpose");
    case X509_V_ERR_CERT_UNTRUSTED:
        return ("certificate not trusted");
    case X509_V_ERR_CERT_REJECTED:
        return ("certificate rejected");
    case X509_V_ERR_APPLICATION_VERIFICATION:
        return ("application verification failure");
    case X509_V_ERR_SUBJECT_ISSUER_MISMATCH:
        return ("subject issuer mismatch");
    case X509_V_ERR_AKID_SKID_MISMATCH:
        return ("authority and subject key identifier mismatch");
    case X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH:
        return ("authority and issuer serial number mismatch");
    case X509_V_ERR_KEYUSAGE_NO_CERTSIGN:
        return ("key usage does not include certificate signing");
    case X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER:
        return ("unable to get CRL issuer certificate");
    case X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION:
        return ("unhandled critical extension");
    case X509_V_ERR_KEYUSAGE_NO_CRL_SIGN:
        return ("key usage does not include CRL signing");
    case X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE:
        return ("key usage does not include digital signature");
    case X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION:
        return ("unhandled critical CRL extension");
    case X509_V_ERR_INVALID_EXTENSION:
        return ("invalid or inconsistent certificate extension");
    case X509_V_ERR_INVALID_POLICY_EXTENSION:
        return ("invalid or inconsistent certificate policy extension");
    case X509_V_ERR_NO_EXPLICIT_POLICY:
        return ("no explicit policy");
    case X509_V_ERR_DIFFERENT_CRL_SCOPE:
        return ("Different CRL scope");
    case X509_V_ERR_UNSUPPORTED_EXTENSION_FEATURE:
        return ("Unsupported extension feature");
    case X509_V_ERR_UNNESTED_RESOURCE:
        return ("RFC 3779 resource not subset of parent's resources");

    case X509_V_ERR_PERMITTED_VIOLATION:
        return ("permitted subtree violation");
    case X509_V_ERR_EXCLUDED_VIOLATION:
        return ("excluded subtree violation");
    case X509_V_ERR_SUBTREE_MINMAX:
        return ("name constraints minimum and maximum not supported");
    case X509_V_ERR_UNSUPPORTED_CONSTRAINT_TYPE:
        return ("unsupported name constraint type");
    case X509_V_ERR_UNSUPPORTED_CONSTRAINT_SYNTAX:
        return ("unsupported or invalid name constraint syntax");
    case X509_V_ERR_UNSUPPORTED_NAME_SYNTAX:
        return ("unsupported or invalid name syntax");
    case X509_V_ERR_CRL_PATH_VALIDATION_ERROR:
        return ("CRL path validation error");

    case X509_V_ERR_SUITE_B_INVALID_VERSION:
        return ("Suite B: certificate version invalid");
    case X509_V_ERR_SUITE_B_INVALID_ALGORITHM:
        return ("Suite B: invalid public key algorithm");
    case X509_V_ERR_SUITE_B_INVALID_CURVE:
        return ("Suite B: invalid ECC curve");
    case X509_V_ERR_SUITE_B_INVALID_SIGNATURE_ALGORITHM:
        return ("Suite B: invalid signature algorithm");
    case X509_V_ERR_SUITE_B_LOS_NOT_ALLOWED:
        return ("Suite B: curve not allowed for this LOS");
    case X509_V_ERR_SUITE_B_CANNOT_SIGN_P_384_WITH_P_256:
        return ("Suite B: cannot sign P-384 with P-256");

    case X509_V_ERR_HOSTNAME_MISMATCH:
        return ("Hostname mismatch");
    case X509_V_ERR_EMAIL_MISMATCH:
        return ("Email address mismatch");
    case X509_V_ERR_IP_ADDRESS_MISMATCH:
        return ("IP address mismatch");

    case X509_V_ERR_INVALID_CALL:
        return ("Invalid certificate verification context");
    case X509_V_ERR_STORE_LOOKUP:
        return ("Issuer certificate lookup error");
    case X509_V_ERR_PROXY_SUBJECT_NAME_VIOLATION:
        return ("proxy subject name violation");

    default:
        BIO_snprintf(buf, sizeof(buf), "error number %ld", n);
        return (buf);
    }
}
/* crypto/x509/x509_v3.c */
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
// #include "stack.h"
// #include "cryptlib.h"
// #include "asn1.h"
// #include "objects.h"
// #include "evp.h"
// #include "x509.h"
// #include "x509v3.h"

int X509v3_get_ext_count(const STACK_OF(X509_EXTENSION) *x)
{
    if (x == NULL)
        return (0);
    return (sk_X509_EXTENSION_num(x));
}

int X509v3_get_ext_by_NID(const STACK_OF(X509_EXTENSION) *x, int nid,
                          int lastpos)
{
    ASN1_OBJECT *obj;

    obj = OBJ_nid2obj(nid);
    if (obj == NULL)
        return (-2);
    return (X509v3_get_ext_by_OBJ(x, obj, lastpos));
}

int X509v3_get_ext_by_OBJ(const STACK_OF(X509_EXTENSION) *sk,
                          ASN1_OBJECT *obj, int lastpos)
{
    int n;
    X509_EXTENSION *ex;

    if (sk == NULL)
        return (-1);
    lastpos++;
    if (lastpos < 0)
        lastpos = 0;
    n = sk_X509_EXTENSION_num(sk);
    for (; lastpos < n; lastpos++) {
        ex = sk_X509_EXTENSION_value(sk, lastpos);
        if (OBJ_cmp(ex->object, obj) == 0)
            return (lastpos);
    }
    return (-1);
}

int X509v3_get_ext_by_critical(const STACK_OF(X509_EXTENSION) *sk, int crit,
                               int lastpos)
{
    int n;
    X509_EXTENSION *ex;

    if (sk == NULL)
        return (-1);
    lastpos++;
    if (lastpos < 0)
        lastpos = 0;
    n = sk_X509_EXTENSION_num(sk);
    for (; lastpos < n; lastpos++) {
        ex = sk_X509_EXTENSION_value(sk, lastpos);
        if (((ex->critical > 0) && crit) || ((ex->critical <= 0) && !crit))
            return (lastpos);
    }
    return (-1);
}

X509_EXTENSION *X509v3_get_ext(const STACK_OF(X509_EXTENSION) *x, int loc)
{
    if (x == NULL || sk_X509_EXTENSION_num(x) <= loc || loc < 0)
        return NULL;
    else
        return sk_X509_EXTENSION_value(x, loc);
}

X509_EXTENSION *X509v3_delete_ext(STACK_OF(X509_EXTENSION) *x, int loc)
{
    X509_EXTENSION *ret;

    if (x == NULL || sk_X509_EXTENSION_num(x) <= loc || loc < 0)
        return (NULL);
    ret = sk_X509_EXTENSION_delete(x, loc);
    return (ret);
}

STACK_OF(X509_EXTENSION) *X509v3_add_ext(STACK_OF(X509_EXTENSION) **x,
                                         X509_EXTENSION *ex, int loc)
{
    X509_EXTENSION *new_ex = NULL;
    int n;
    STACK_OF(X509_EXTENSION) *sk = NULL;

    if (x == NULL) {
        X509err(X509_F_X509V3_ADD_EXT, ERR_R_PASSED_NULL_PARAMETER);
        goto err2;
    }

    if (*x == NULL) {
        if ((sk = sk_X509_EXTENSION_new_null()) == NULL)
            goto err;
    } else
        sk = *x;

    n = sk_X509_EXTENSION_num(sk);
    if (loc > n)
        loc = n;
    else if (loc < 0)
        loc = n;

    if ((new_ex = X509_EXTENSION_dup(ex)) == NULL)
        goto err2;
    if (!sk_X509_EXTENSION_insert(sk, new_ex, loc))
        goto err;
    if (*x == NULL)
        *x = sk;
    return (sk);
 err:
    X509err(X509_F_X509V3_ADD_EXT, ERR_R_MALLOC_FAILURE);
 err2:
    if (new_ex != NULL)
        X509_EXTENSION_free(new_ex);
    if (x != NULL && *x == NULL && sk != NULL)
        sk_X509_EXTENSION_free(sk);
    return (NULL);
}

X509_EXTENSION *X509_EXTENSION_create_by_NID(X509_EXTENSION **ex, int nid,
                                             int crit,
                                             ASN1_OCTET_STRING *data)
{
    ASN1_OBJECT *obj;
    X509_EXTENSION *ret;

    obj = OBJ_nid2obj(nid);
    if (obj == NULL) {
        X509err(X509_F_X509_EXTENSION_CREATE_BY_NID, X509_R_UNKNOWN_NID);
        return (NULL);
    }
    ret = X509_EXTENSION_create_by_OBJ(ex, obj, crit, data);
    if (ret == NULL)
        ASN1_OBJECT_free(obj);
    return (ret);
}

X509_EXTENSION *X509_EXTENSION_create_by_OBJ(X509_EXTENSION **ex,
                                             ASN1_OBJECT *obj, int crit,
                                             ASN1_OCTET_STRING *data)
{
    X509_EXTENSION *ret;

    if ((ex == NULL) || (*ex == NULL)) {
        if ((ret = X509_EXTENSION_new()) == NULL) {
            X509err(X509_F_X509_EXTENSION_CREATE_BY_OBJ,
                    ERR_R_MALLOC_FAILURE);
            return (NULL);
        }
    } else
        ret = *ex;

    if (!X509_EXTENSION_set_object(ret, obj))
        goto err;
    if (!X509_EXTENSION_set_critical(ret, crit))
        goto err;
    if (!X509_EXTENSION_set_data(ret, data))
        goto err;

    if ((ex != NULL) && (*ex == NULL))
        *ex = ret;
    return (ret);
 err:
    if ((ex == NULL) || (ret != *ex))
        X509_EXTENSION_free(ret);
    return (NULL);
}

int X509_EXTENSION_set_object(X509_EXTENSION *ex, ASN1_OBJECT *obj)
{
    if ((ex == NULL) || (obj == NULL))
        return (0);
    ASN1_OBJECT_free(ex->object);
    ex->object = OBJ_dup(obj);
    return (1);
}

int X509_EXTENSION_set_critical(X509_EXTENSION *ex, int crit)
{
    if (ex == NULL)
        return (0);
    ex->critical = (crit) ? 0xFF : -1;
    return (1);
}

int X509_EXTENSION_set_data(X509_EXTENSION *ex, ASN1_OCTET_STRING *data)
{
    int i;

    if (ex == NULL)
        return (0);
    i = M_ASN1_OCTET_STRING_set(ex->value, data->data, data->length);
    if (!i)
        return (0);
    return (1);
}

ASN1_OBJECT *X509_EXTENSION_get_object(X509_EXTENSION *ex)
{
    if (ex == NULL)
        return (NULL);
    return (ex->object);
}

ASN1_OCTET_STRING *X509_EXTENSION_get_data(X509_EXTENSION *ex)
{
    if (ex == NULL)
        return (NULL);
    return (ex->value);
}

int X509_EXTENSION_get_critical(X509_EXTENSION *ex)
{
    if (ex == NULL)
        return (0);
    if (ex->critical > 0)
        return 1;
    return 0;
}
/* crypto/x509/x509_vfy.c */
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

#include <ctype.h>
#include <stdio.h>
#include <time.h>
#include <errno.h>

// #include "cryptlib.h"
// #include "crypto.h"
// #include "lhash.h"
// #include "buffer.h"
// #include "evp.h"
// #include "asn1.h"
// #include "x509.h"
// #include "x509v3.h"
// #include "objects.h"
#include "vpm_int.h"

/* CRL score values */

/* No unhandled critical extensions */

#define CRL_SCORE_NOCRITICAL    0x100

/* certificate is within CRL scope */

#define CRL_SCORE_SCOPE         0x080

/* CRL times valid */

#define CRL_SCORE_TIME          0x040

/* Issuer name matches certificate */

#define CRL_SCORE_ISSUER_NAME   0x020

/* If this score or above CRL is probably valid */

#define CRL_SCORE_VALID (CRL_SCORE_NOCRITICAL|CRL_SCORE_TIME|CRL_SCORE_SCOPE)

/* CRL issuer is certificate issuer */

#define CRL_SCORE_ISSUER_CERT   0x018

/* CRL issuer is on certificate path */

#define CRL_SCORE_SAME_PATH     0x008

/* CRL issuer matches CRL AKID */

#define CRL_SCORE_AKID          0x004

/* Have a delta CRL with valid times */

#define CRL_SCORE_TIME_DELTA    0x002

static int null_callback(int ok, X509_STORE_CTX *e);
static int check_issued(X509_STORE_CTX *ctx, X509 *x, X509 *issuer);
static X509 *find_issuer(X509_STORE_CTX *ctx, STACK_OF(X509) *sk, X509 *x);
static int check_chain_extensions(X509_STORE_CTX *ctx);
static int check_name_constraints(X509_STORE_CTX *ctx);
static int check_id(X509_STORE_CTX *ctx);
static int check_trust(X509_STORE_CTX *ctx);
static int check_revocation(X509_STORE_CTX *ctx);
static int check_cert(X509_STORE_CTX *ctx);
static int check_policy(X509_STORE_CTX *ctx);

static int get_crl_score(X509_STORE_CTX *ctx, X509 **pissuer,
                         unsigned int *preasons, X509_CRL *crl, X509 *x);
static int get_crl_delta(X509_STORE_CTX *ctx,
                         X509_CRL **pcrl, X509_CRL **pdcrl, X509 *x);
static void get_delta_sk(X509_STORE_CTX *ctx, X509_CRL **dcrl,
                         int *pcrl_score, X509_CRL *base,
                         STACK_OF(X509_CRL) *crls);
static void crl_akid_check(X509_STORE_CTX *ctx, X509_CRL *crl, X509 **pissuer,
                           int *pcrl_score);
static int crl_crldp_check(X509 *x, X509_CRL *crl, int crl_score,
                           unsigned int *preasons);
static int check_crl_path(X509_STORE_CTX *ctx, X509 *x);
static int check_crl_chain(X509_STORE_CTX *ctx,
                           STACK_OF(X509) *cert_path,
                           STACK_OF(X509) *crl_path);

static int internal_verify(X509_STORE_CTX *ctx);
const char X509_version[] = "X.509" OPENSSL_VERSION_PTEXT;

static int null_callback(int ok, X509_STORE_CTX *e)
{
    return ok;
}

#if 0
static int x509_subject_cmp(X509 **a, X509 **b)
{
    return X509_subject_name_cmp(*a, *b);
}
#endif
/* Return 1 is a certificate is self signed */
static int cert_self_signed(X509 *x)
{
    X509_check_purpose(x, -1, 0);
    if (x->ex_flags & EXFLAG_SS)
        return 1;
    else
        return 0;
}

/* Given a certificate try and find an exact match in the store */

static X509 *lookup_cert_match(X509_STORE_CTX *ctx, X509 *x)
{
    STACK_OF(X509) *certs;
    X509 *xtmp = NULL;
    int i;
    /* Lookup all certs with matching subject name */
    certs = ctx->lookup_certs(ctx, X509_get_subject_name(x));
    if (certs == NULL)
        return NULL;
    /* Look for exact match */
    for (i = 0; i < sk_X509_num(certs); i++) {
        xtmp = sk_X509_value(certs, i);
        if (!X509_cmp(xtmp, x))
            break;
    }
    if (i < sk_X509_num(certs))
        CRYPTO_add(&xtmp->references, 1, CRYPTO_LOCK_X509);
    else
        xtmp = NULL;
    sk_X509_pop_free(certs, X509_free);
    return xtmp;
}

int X509_verify_cert(X509_STORE_CTX *ctx)
{
    X509 *x, *xtmp, *xtmp2, *chain_ss = NULL;
    int bad_chain = 0;
    X509_VERIFY_PARAM *param = ctx->param;
    int depth, i, ok = 0;
    int num, j, retry;
    int (*cb) (int xok, X509_STORE_CTX *xctx);
    STACK_OF(X509) *sktmp = NULL;
    int trust = X509_TRUST_UNTRUSTED;
    int err;

    if (ctx->cert == NULL) {
        X509err(X509_F_X509_VERIFY_CERT, X509_R_NO_CERT_SET_FOR_US_TO_VERIFY);
        ctx->error = X509_V_ERR_INVALID_CALL;
        return -1;
    }
    if (ctx->chain != NULL) {
        /*
         * This X509_STORE_CTX has already been used to verify a cert. We
         * cannot do another one.
         */
        X509err(X509_F_X509_VERIFY_CERT, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        ctx->error = X509_V_ERR_INVALID_CALL;
        return -1;
    }

    cb = ctx->verify_cb;

    /*
     * first we make sure the chain we are going to build is present and that
     * the first entry is in place
     */
    if (((ctx->chain = sk_X509_new_null()) == NULL) ||
        (!sk_X509_push(ctx->chain, ctx->cert))) {
        X509err(X509_F_X509_VERIFY_CERT, ERR_R_MALLOC_FAILURE);
        ctx->error = X509_V_ERR_OUT_OF_MEM;
        ok = -1;
        goto err;
    }
    CRYPTO_add(&ctx->cert->references, 1, CRYPTO_LOCK_X509);
    ctx->last_untrusted = 1;

    /* We use a temporary STACK so we can chop and hack at it */
    if (ctx->untrusted != NULL
        && (sktmp = sk_X509_dup(ctx->untrusted)) == NULL) {
        X509err(X509_F_X509_VERIFY_CERT, ERR_R_MALLOC_FAILURE);
        ctx->error = X509_V_ERR_OUT_OF_MEM;
        ok = -1;
        goto err;
    }

    num = sk_X509_num(ctx->chain);
    x = sk_X509_value(ctx->chain, num - 1);
    depth = param->depth;

    for (;;) {
        /* If we have enough, we break */
        if (depth < num)
            break;              /* FIXME: If this happens, we should take
                                 * note of it and, if appropriate, use the
                                 * X509_V_ERR_CERT_CHAIN_TOO_LONG error code
                                 * later. */

        /* If we are self signed, we break */
        if (cert_self_signed(x))
            break;
        /*
         * If asked see if we can find issuer in trusted store first
         */
        if (ctx->param->flags & X509_V_FLAG_TRUSTED_FIRST) {
            ok = ctx->get_issuer(&xtmp, ctx, x);
            if (ok < 0) {
                ctx->error = X509_V_ERR_STORE_LOOKUP;
                goto err;
            }
            /*
             * If successful for now free up cert so it will be picked up
             * again later.
             */
            if (ok > 0) {
                X509_free(xtmp);
                break;
            }
        }

        /* If we were passed a cert chain, use it first */
        if (ctx->untrusted != NULL) {
            xtmp = find_issuer(ctx, sktmp, x);
            if (xtmp != NULL) {
                if (!sk_X509_push(ctx->chain, xtmp)) {
                    X509err(X509_F_X509_VERIFY_CERT, ERR_R_MALLOC_FAILURE);
                    ctx->error = X509_V_ERR_OUT_OF_MEM;
                    ok = -1;
                    goto err;
                }
                CRYPTO_add(&xtmp->references, 1, CRYPTO_LOCK_X509);
                (void)sk_X509_delete_ptr(sktmp, xtmp);
                ctx->last_untrusted++;
                x = xtmp;
                num++;
                /*
                 * reparse the full chain for the next one
                 */
                continue;
            }
        }
        break;
    }

    /* Remember how many untrusted certs we have */
    j = num;
    /*
     * at this point, chain should contain a list of untrusted certificates.
     * We now need to add at least one trusted one, if possible, otherwise we
     * complain.
     */

    do {
        /*
         * Examine last certificate in chain and see if it is self signed.
         */
        i = sk_X509_num(ctx->chain);
        x = sk_X509_value(ctx->chain, i - 1);
        if (cert_self_signed(x)) {
            /* we have a self signed certificate */
            if (sk_X509_num(ctx->chain) == 1) {
                /*
                 * We have a single self signed certificate: see if we can
                 * find it in the store. We must have an exact match to avoid
                 * possible impersonation.
                 */
                ok = ctx->get_issuer(&xtmp, ctx, x);
                if ((ok <= 0) || X509_cmp(x, xtmp)) {
                    ctx->error = X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT;
                    ctx->current_cert = x;
                    ctx->error_depth = i - 1;
                    if (ok == 1)
                        X509_free(xtmp);
                    bad_chain = 1;
                    ok = cb(0, ctx);
                    if (!ok)
                        goto err;
                } else {
                    /*
                     * We have a match: replace certificate with store
                     * version so we get any trust settings.
                     */
                    X509_free(x);
                    x = xtmp;
                    (void)sk_X509_set(ctx->chain, i - 1, x);
                    ctx->last_untrusted = 0;
                }
            } else {
                /*
                 * extract and save self signed certificate for later use
                 */
                chain_ss = sk_X509_pop(ctx->chain);
                ctx->last_untrusted--;
                num--;
                j--;
                x = sk_X509_value(ctx->chain, num - 1);
            }
        }
        /* We now lookup certs from the certificate store */
        for (;;) {
            /* If we have enough, we break */
            if (depth < num)
                break;
            /* If we are self signed, we break */
            if (cert_self_signed(x))
                break;
            ok = ctx->get_issuer(&xtmp, ctx, x);

            if (ok < 0) {
                ctx->error = X509_V_ERR_STORE_LOOKUP;
                goto err;
            }
            if (ok == 0)
                break;
            x = xtmp;
            if (!sk_X509_push(ctx->chain, x)) {
                X509_free(xtmp);
                X509err(X509_F_X509_VERIFY_CERT, ERR_R_MALLOC_FAILURE);
                ctx->error = X509_V_ERR_OUT_OF_MEM;
                ok = -1;
                goto err;
            }
            num++;
        }

        /* we now have our chain, lets check it... */
        if ((trust = check_trust(ctx)) == X509_TRUST_REJECTED) {
            /* Callback already issued */
            ok = 0;
            goto err;
        }

        /*
         * If it's not explicitly trusted then check if there is an alternative
         * chain that could be used. We only do this if we haven't already
         * checked via TRUSTED_FIRST and the user hasn't switched off alternate
         * chain checking
         */
        retry = 0;
        if (trust != X509_TRUST_TRUSTED
            && !(ctx->param->flags & X509_V_FLAG_TRUSTED_FIRST)
            && !(ctx->param->flags & X509_V_FLAG_NO_ALT_CHAINS)) {
            while (j-- > 1) {
                xtmp2 = sk_X509_value(ctx->chain, j - 1);
                ok = ctx->get_issuer(&xtmp, ctx, xtmp2);
                if (ok < 0) {
                    ctx->error = X509_V_ERR_STORE_LOOKUP;
                    goto err;
                }
                /* Check if we found an alternate chain */
                if (ok > 0) {
                    /*
                     * Free up the found cert we'll add it again later
                     */
                    X509_free(xtmp);

                    /*
                     * Dump all the certs above this point - we've found an
                     * alternate chain
                     */
                    while (num > j) {
                        xtmp = sk_X509_pop(ctx->chain);
                        X509_free(xtmp);
                        num--;
                    }
                    ctx->last_untrusted = sk_X509_num(ctx->chain);
                    retry = 1;
                    break;
                }
            }
        }
    } while (retry);

    /*
     * If not explicitly trusted then indicate error unless it's a single
     * self signed certificate in which case we've indicated an error already
     * and set bad_chain == 1
     */
    if (trust != X509_TRUST_TRUSTED && !bad_chain) {
        if ((chain_ss == NULL) || !ctx->check_issued(ctx, x, chain_ss)) {
            if (ctx->last_untrusted >= num)
                ctx->error = X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY;
            else
                ctx->error = X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT;
            ctx->current_cert = x;
        } else {

            sk_X509_push(ctx->chain, chain_ss);
            num++;
            ctx->last_untrusted = num;
            ctx->current_cert = chain_ss;
            ctx->error = X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN;
            chain_ss = NULL;
        }

        ctx->error_depth = num - 1;
        bad_chain = 1;
        ok = cb(0, ctx);
        if (!ok)
            goto err;
    }

    /* We have the chain complete: now we need to check its purpose */
    ok = check_chain_extensions(ctx);

    if (!ok)
        goto err;

    /* Check name constraints */

    ok = check_name_constraints(ctx);

    if (!ok)
        goto err;

    ok = check_id(ctx);

    if (!ok)
        goto err;

    /* We may as well copy down any DSA parameters that are required */
    X509_get_pubkey_parameters(NULL, ctx->chain);

    /*
     * Check revocation status: we do this after copying parameters because
     * they may be needed for CRL signature verification.
     */

    ok = ctx->check_revocation(ctx);
    if (!ok)
        goto err;

    err = X509_chain_check_suiteb(&ctx->error_depth, NULL, ctx->chain,
                                  ctx->param->flags);
    if (err != X509_V_OK) {
        ctx->error = err;
        ctx->current_cert = sk_X509_value(ctx->chain, ctx->error_depth);
        ok = cb(0, ctx);
        if (!ok)
            goto err;
    }

    /* At this point, we have a chain and need to verify it */
    if (ctx->verify != NULL)
        ok = ctx->verify(ctx);
    else
        ok = internal_verify(ctx);
    if (!ok)
        goto err;

#ifndef OPENSSL_NO_RFC3779
    /* RFC 3779 path validation, now that CRL check has been done */
    ok = v3_asid_validate_path(ctx);
    if (!ok)
        goto err;
    ok = v3_addr_validate_path(ctx);
    if (!ok)
        goto err;
#endif

    /* If we get this far evaluate policies */
    if (!bad_chain && (ctx->param->flags & X509_V_FLAG_POLICY_CHECK))
        ok = ctx->check_policy(ctx);
    if (!ok)
        goto err;
    if (0) {
 err:
        /* Ensure we return an error */
        if (ok > 0)
            ok = 0;
        X509_get_pubkey_parameters(NULL, ctx->chain);
    }
    if (sktmp != NULL)
        sk_X509_free(sktmp);
    if (chain_ss != NULL)
        X509_free(chain_ss);

    /* Safety net, error returns must set ctx->error */
    if (ok <= 0 && ctx->error == X509_V_OK)
        ctx->error = X509_V_ERR_UNSPECIFIED;
    return ok;
}

/*
 * Given a STACK_OF(X509) find the issuer of cert (if any)
 */

static X509 *find_issuer(X509_STORE_CTX *ctx, STACK_OF(X509) *sk, X509 *x)
{
    int i;
    X509 *issuer;
    for (i = 0; i < sk_X509_num(sk); i++) {
        issuer = sk_X509_value(sk, i);
        if (ctx->check_issued(ctx, x, issuer))
            return issuer;
    }
    return NULL;
}

/* Given a possible certificate and issuer check them */

static int check_issued(X509_STORE_CTX *ctx, X509 *x, X509 *issuer)
{
    int ret;
    ret = X509_check_issued(issuer, x);
    if (ret == X509_V_OK)
        return 1;
    /* If we haven't asked for issuer errors don't set ctx */
    if (!(ctx->param->flags & X509_V_FLAG_CB_ISSUER_CHECK))
        return 0;

    ctx->error = ret;
    ctx->current_cert = x;
    ctx->current_issuer = issuer;
    return ctx->verify_cb(0, ctx);
}

/* Alternative lookup method: look from a STACK stored in other_ctx */

static int get_issuer_sk(X509 **issuer, X509_STORE_CTX *ctx, X509 *x)
{
    *issuer = find_issuer(ctx, ctx->other_ctx, x);
    if (*issuer) {
        CRYPTO_add(&(*issuer)->references, 1, CRYPTO_LOCK_X509);
        return 1;
    } else
        return 0;
}

/*
 * Check a certificate chains extensions for consistency with the supplied
 * purpose
 */

static int check_chain_extensions(X509_STORE_CTX *ctx)
{
#ifdef OPENSSL_NO_CHAIN_VERIFY
    return 1;
#else
    int i, ok = 0, must_be_ca, plen = 0;
    X509 *x;
    int (*cb) (int xok, X509_STORE_CTX *xctx);
    int proxy_path_length = 0;
    int purpose;
    int allow_proxy_certs;
    cb = ctx->verify_cb;

    /*-
     *  must_be_ca can have 1 of 3 values:
     * -1: we accept both CA and non-CA certificates, to allow direct
     *     use of self-signed certificates (which are marked as CA).
     * 0:  we only accept non-CA certificates.  This is currently not
     *     used, but the possibility is present for future extensions.
     * 1:  we only accept CA certificates.  This is currently used for
     *     all certificates in the chain except the leaf certificate.
     */
    must_be_ca = -1;

    /* CRL path validation */
    if (ctx->parent) {
        allow_proxy_certs = 0;
        purpose = X509_PURPOSE_CRL_SIGN;
    } else {
        allow_proxy_certs =
            ! !(ctx->param->flags & X509_V_FLAG_ALLOW_PROXY_CERTS);
        /*
         * A hack to keep people who don't want to modify their software
         * happy
         */
        if (ossl_safe_getenv("OPENSSL_ALLOW_PROXY_CERTS"))
            allow_proxy_certs = 1;
        purpose = ctx->param->purpose;
    }

    /* Check all untrusted certificates */
    for (i = 0; i < ctx->last_untrusted; i++) {
        int ret;
        x = sk_X509_value(ctx->chain, i);
        if (!(ctx->param->flags & X509_V_FLAG_IGNORE_CRITICAL)
            && (x->ex_flags & EXFLAG_CRITICAL)) {
            ctx->error = X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION;
            ctx->error_depth = i;
            ctx->current_cert = x;
            ok = cb(0, ctx);
            if (!ok)
                goto end;
        }
        if (!allow_proxy_certs && (x->ex_flags & EXFLAG_PROXY)) {
            ctx->error = X509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED;
            ctx->error_depth = i;
            ctx->current_cert = x;
            ok = cb(0, ctx);
            if (!ok)
                goto end;
        }
        ret = X509_check_ca(x);
        switch (must_be_ca) {
        case -1:
            if ((ctx->param->flags & X509_V_FLAG_X509_STRICT)
                && (ret != 1) && (ret != 0)) {
                ret = 0;
                ctx->error = X509_V_ERR_INVALID_CA;
            } else
                ret = 1;
            break;
        case 0:
            if (ret != 0) {
                ret = 0;
                ctx->error = X509_V_ERR_INVALID_NON_CA;
            } else
                ret = 1;
            break;
        default:
            if ((ret == 0)
                || ((ctx->param->flags & X509_V_FLAG_X509_STRICT)
                    && (ret != 1))) {
                ret = 0;
                ctx->error = X509_V_ERR_INVALID_CA;
            } else
                ret = 1;
            break;
        }
        if (ret == 0) {
            ctx->error_depth = i;
            ctx->current_cert = x;
            ok = cb(0, ctx);
            if (!ok)
                goto end;
        }
        if (ctx->param->purpose > 0) {
            ret = X509_check_purpose(x, purpose, must_be_ca > 0);
            if ((ret == 0)
                || ((ctx->param->flags & X509_V_FLAG_X509_STRICT)
                    && (ret != 1))) {
                ctx->error = X509_V_ERR_INVALID_PURPOSE;
                ctx->error_depth = i;
                ctx->current_cert = x;
                ok = cb(0, ctx);
                if (!ok)
                    goto end;
            }
        }
        /* Check pathlen */
        if ((i > 1) && (x->ex_pathlen != -1)
            && (plen > (x->ex_pathlen + proxy_path_length))) {
            ctx->error = X509_V_ERR_PATH_LENGTH_EXCEEDED;
            ctx->error_depth = i;
            ctx->current_cert = x;
            ok = cb(0, ctx);
            if (!ok)
                goto end;
        }
        /* Increment path length if not a self issued intermediate CA */
        if (i > 0 && (x->ex_flags & EXFLAG_SI) == 0)
            plen++;
        /*
         * If this certificate is a proxy certificate, the next certificate
         * must be another proxy certificate or a EE certificate.  If not,
         * the next certificate must be a CA certificate.
         */
        if (x->ex_flags & EXFLAG_PROXY) {
            /*
             * RFC3820, 4.1.3 (b)(1) stipulates that if pCPathLengthConstraint
             * is less than max_path_length, the former should be copied to
             * the latter, and 4.1.4 (a) stipulates that max_path_length
             * should be verified to be larger than zero and decrement it.
             *
             * Because we're checking the certs in the reverse order, we start
             * with verifying that proxy_path_length isn't larger than pcPLC,
             * and copy the latter to the former if it is, and finally,
             * increment proxy_path_length.
             */
            if (x->ex_pcpathlen != -1) {
                if (proxy_path_length > x->ex_pcpathlen) {
                    ctx->error = X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED;
                    ctx->error_depth = i;
                    ctx->current_cert = x;
                    ok = cb(0, ctx);
                    if (!ok)
                        goto end;
                }
                proxy_path_length = x->ex_pcpathlen;
            }
            proxy_path_length++;
            must_be_ca = 0;
        } else
            must_be_ca = 1;
    }
    ok = 1;
 end:
    return ok;
#endif
}

static int check_name_constraints(X509_STORE_CTX *ctx)
{
    X509 *x;
    int i, j, rv;
    /* Check name constraints for all certificates */
    for (i = sk_X509_num(ctx->chain) - 1; i >= 0; i--) {
        x = sk_X509_value(ctx->chain, i);
        /* Ignore self issued certs unless last in chain */
        if (i && (x->ex_flags & EXFLAG_SI))
            continue;

        /*
         * Proxy certificates policy has an extra constraint, where the
         * certificate subject MUST be the issuer with a single CN entry
         * added.
         * (RFC 3820: 3.4, 4.1.3 (a)(4))
         */
        if (x->ex_flags & EXFLAG_PROXY) {
            X509_NAME *tmpsubject = X509_get_subject_name(x);
            X509_NAME *tmpissuer = X509_get_issuer_name(x);
            X509_NAME_ENTRY *tmpentry = NULL;
            int last_object_nid = 0;
            int err = X509_V_OK;
            int last_object_loc = X509_NAME_entry_count(tmpsubject) - 1;

            /* Check that there are at least two RDNs */
            if (last_object_loc < 1) {
                err = X509_V_ERR_PROXY_SUBJECT_NAME_VIOLATION;
                goto proxy_name_done;
            }

            /*
             * Check that there is exactly one more RDN in subject as
             * there is in issuer.
             */
            if (X509_NAME_entry_count(tmpsubject)
                != X509_NAME_entry_count(tmpissuer) + 1) {
                err = X509_V_ERR_PROXY_SUBJECT_NAME_VIOLATION;
                goto proxy_name_done;
            }

            /*
             * Check that the last subject component isn't part of a
             * multivalued RDN
             */
            if (X509_NAME_get_entry(tmpsubject, last_object_loc)->set
                == X509_NAME_get_entry(tmpsubject, last_object_loc - 1)->set) {
                err = X509_V_ERR_PROXY_SUBJECT_NAME_VIOLATION;
                goto proxy_name_done;
            }

            /*
             * Check that the last subject RDN is a commonName, and that
             * all the previous RDNs match the issuer exactly
             */
            tmpsubject = X509_NAME_dup(tmpsubject);
            if (tmpsubject == NULL) {
                X509err(X509_F_CHECK_NAME_CONSTRAINTS, ERR_R_MALLOC_FAILURE);
                ctx->error = X509_V_ERR_OUT_OF_MEM;
                return 0;
            }

            tmpentry =
                X509_NAME_delete_entry(tmpsubject, last_object_loc);
            last_object_nid =
                OBJ_obj2nid(X509_NAME_ENTRY_get_object(tmpentry));

            if (last_object_nid != NID_commonName
                || X509_NAME_cmp(tmpsubject, tmpissuer) != 0) {
                err = X509_V_ERR_PROXY_SUBJECT_NAME_VIOLATION;
            }

            X509_NAME_ENTRY_free(tmpentry);
            X509_NAME_free(tmpsubject);

         proxy_name_done:
            if (err != X509_V_OK) {
                ctx->error = err;
                ctx->error_depth = i;
                ctx->current_cert = x;
                if (!ctx->verify_cb(0, ctx))
                    return 0;
            }
        }

        /*
         * Check against constraints for all certificates higher in chain
         * including trust anchor. Trust anchor not strictly speaking needed
         * but if it includes constraints it is to be assumed it expects them
         * to be obeyed.
         */
        for (j = sk_X509_num(ctx->chain) - 1; j > i; j--) {
            NAME_CONSTRAINTS *nc = sk_X509_value(ctx->chain, j)->nc;
            if (nc) {
                rv = NAME_CONSTRAINTS_check(x, nc);
                switch (rv) {
                case X509_V_OK:
                    continue;
                case X509_V_ERR_OUT_OF_MEM:
                    ctx->error = rv;
                    return 0;
                default:
                    ctx->error = rv;
                    ctx->error_depth = i;
                    ctx->current_cert = x;
                    if (!ctx->verify_cb(0, ctx))
                        return 0;
                    break;
                }
            }
        }
    }
    return 1;
}

static int check_id_error(X509_STORE_CTX *ctx, int errcode)
{
    ctx->error = errcode;
    ctx->current_cert = ctx->cert;
    ctx->error_depth = 0;
    return ctx->verify_cb(0, ctx);
}

static int check_hosts(X509 *x, X509_VERIFY_PARAM_ID *id)
{
    int i;
    int n = sk_OPENSSL_STRING_num(id->hosts);
    char *name;

    if (id->peername != NULL) {
        OPENSSL_free(id->peername);
        id->peername = NULL;
    }
    for (i = 0; i < n; ++i) {
        name = sk_OPENSSL_STRING_value(id->hosts, i);
        if (X509_check_host(x, name, 0, id->hostflags, &id->peername) > 0)
            return 1;
    }
    return n == 0;
}

static int check_id(X509_STORE_CTX *ctx)
{
    X509_VERIFY_PARAM *vpm = ctx->param;
    X509_VERIFY_PARAM_ID *id = vpm->id;
    X509 *x = ctx->cert;
    if (id->hosts && check_hosts(x, id) <= 0) {
        if (!check_id_error(ctx, X509_V_ERR_HOSTNAME_MISMATCH))
            return 0;
    }
    if (id->email && X509_check_email(x, id->email, id->emaillen, 0) <= 0) {
        if (!check_id_error(ctx, X509_V_ERR_EMAIL_MISMATCH))
            return 0;
    }
    if (id->ip && X509_check_ip(x, id->ip, id->iplen, 0) <= 0) {
        if (!check_id_error(ctx, X509_V_ERR_IP_ADDRESS_MISMATCH))
            return 0;
    }
    return 1;
}

static int check_trust(X509_STORE_CTX *ctx)
{
    int i, ok;
    X509 *x = NULL;
    int (*cb) (int xok, X509_STORE_CTX *xctx);
    cb = ctx->verify_cb;
    /* Check all trusted certificates in chain */
    for (i = ctx->last_untrusted; i < sk_X509_num(ctx->chain); i++) {
        x = sk_X509_value(ctx->chain, i);
        ok = X509_check_trust(x, ctx->param->trust, 0);
        /* If explicitly trusted return trusted */
        if (ok == X509_TRUST_TRUSTED)
            return X509_TRUST_TRUSTED;
        /*
         * If explicitly rejected notify callback and reject if not
         * overridden.
         */
        if (ok == X509_TRUST_REJECTED) {
            ctx->error_depth = i;
            ctx->current_cert = x;
            ctx->error = X509_V_ERR_CERT_REJECTED;
            ok = cb(0, ctx);
            if (!ok)
                return X509_TRUST_REJECTED;
        }
    }
    /*
     * If we accept partial chains and have at least one trusted certificate
     * return success.
     */
    if (ctx->param->flags & X509_V_FLAG_PARTIAL_CHAIN) {
        X509 *mx;
        if (ctx->last_untrusted < sk_X509_num(ctx->chain))
            return X509_TRUST_TRUSTED;
        x = sk_X509_value(ctx->chain, 0);
        mx = lookup_cert_match(ctx, x);
        if (mx) {
            (void)sk_X509_set(ctx->chain, 0, mx);
            X509_free(x);
            ctx->last_untrusted = 0;
            return X509_TRUST_TRUSTED;
        }
    }

    /*
     * If no trusted certs in chain at all return untrusted and allow
     * standard (no issuer cert) etc errors to be indicated.
     */
    return X509_TRUST_UNTRUSTED;
}

static int check_revocation(X509_STORE_CTX *ctx)
{
    int i, last, ok;
    if (!(ctx->param->flags & X509_V_FLAG_CRL_CHECK))
        return 1;
    if (ctx->param->flags & X509_V_FLAG_CRL_CHECK_ALL)
        last = sk_X509_num(ctx->chain) - 1;
    else {
        /* If checking CRL paths this isn't the EE certificate */
        if (ctx->parent)
            return 1;
        last = 0;
    }
    for (i = 0; i <= last; i++) {
        ctx->error_depth = i;
        ok = check_cert(ctx);
        if (!ok)
            return ok;
    }
    return 1;
}

static int check_cert(X509_STORE_CTX *ctx)
{
    X509_CRL *crl = NULL, *dcrl = NULL;
    X509 *x;
    int ok, cnum;
    unsigned int last_reasons;
    cnum = ctx->error_depth;
    x = sk_X509_value(ctx->chain, cnum);
    ctx->current_cert = x;
    ctx->current_issuer = NULL;
    ctx->current_crl_score = 0;
    ctx->current_reasons = 0;
    if (x->ex_flags & EXFLAG_PROXY)
        return 1;
    while (ctx->current_reasons != CRLDP_ALL_REASONS) {
        last_reasons = ctx->current_reasons;
        /* Try to retrieve relevant CRL */
        if (ctx->get_crl)
            ok = ctx->get_crl(ctx, &crl, x);
        else
            ok = get_crl_delta(ctx, &crl, &dcrl, x);
        /*
         * If error looking up CRL, nothing we can do except notify callback
         */
        if (!ok) {
            ctx->error = X509_V_ERR_UNABLE_TO_GET_CRL;
            ok = ctx->verify_cb(0, ctx);
            goto err;
        }
        ctx->current_crl = crl;
        ok = ctx->check_crl(ctx, crl);
        if (!ok)
            goto err;

        if (dcrl) {
            ok = ctx->check_crl(ctx, dcrl);
            if (!ok)
                goto err;
            ok = ctx->cert_crl(ctx, dcrl, x);
            if (!ok)
                goto err;
        } else
            ok = 1;

        /* Don't look in full CRL if delta reason is removefromCRL */
        if (ok != 2) {
            ok = ctx->cert_crl(ctx, crl, x);
            if (!ok)
                goto err;
        }

        X509_CRL_free(crl);
        X509_CRL_free(dcrl);
        crl = NULL;
        dcrl = NULL;
        /*
         * If reasons not updated we wont get anywhere by another iteration,
         * so exit loop.
         */
        if (last_reasons == ctx->current_reasons) {
            ctx->error = X509_V_ERR_UNABLE_TO_GET_CRL;
            ok = ctx->verify_cb(0, ctx);
            goto err;
        }
    }
 err:
    X509_CRL_free(crl);
    X509_CRL_free(dcrl);

    ctx->current_crl = NULL;
    return ok;

}

/* Check CRL times against values in X509_STORE_CTX */

static int check_crl_time(X509_STORE_CTX *ctx, X509_CRL *crl, int notify)
{
    time_t *ptime;
    int i;
    if (notify)
        ctx->current_crl = crl;
    if (ctx->param->flags & X509_V_FLAG_USE_CHECK_TIME)
        ptime = &ctx->param->check_time;
    else
        ptime = NULL;

    i = X509_cmp_time(X509_CRL_get_lastUpdate(crl), ptime);
    if (i == 0) {
        if (!notify)
            return 0;
        ctx->error = X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD;
        if (!ctx->verify_cb(0, ctx))
            return 0;
    }

    if (i > 0) {
        if (!notify)
            return 0;
        ctx->error = X509_V_ERR_CRL_NOT_YET_VALID;
        if (!ctx->verify_cb(0, ctx))
            return 0;
    }

    if (X509_CRL_get_nextUpdate(crl)) {
        i = X509_cmp_time(X509_CRL_get_nextUpdate(crl), ptime);

        if (i == 0) {
            if (!notify)
                return 0;
            ctx->error = X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD;
            if (!ctx->verify_cb(0, ctx))
                return 0;
        }
        /* Ignore expiry of base CRL is delta is valid */
        if ((i < 0) && !(ctx->current_crl_score & CRL_SCORE_TIME_DELTA)) {
            if (!notify)
                return 0;
            ctx->error = X509_V_ERR_CRL_HAS_EXPIRED;
            if (!ctx->verify_cb(0, ctx))
                return 0;
        }
    }

    if (notify)
        ctx->current_crl = NULL;

    return 1;
}

static int get_crl_sk(X509_STORE_CTX *ctx, X509_CRL **pcrl, X509_CRL **pdcrl,
                      X509 **pissuer, int *pscore, unsigned int *preasons,
                      STACK_OF(X509_CRL) *crls)
{
    int i, crl_score, best_score = *pscore;
    unsigned int reasons, best_reasons = 0;
    X509 *x = ctx->current_cert;
    X509_CRL *crl, *best_crl = NULL;
    X509 *crl_issuer = NULL, *best_crl_issuer = NULL;

    for (i = 0; i < sk_X509_CRL_num(crls); i++) {
        crl = sk_X509_CRL_value(crls, i);
        reasons = *preasons;
        crl_score = get_crl_score(ctx, &crl_issuer, &reasons, crl, x);
        if (crl_score < best_score || crl_score == 0)
            continue;
        /* If current CRL is equivalent use it if it is newer */
        if (crl_score == best_score && best_crl != NULL) {
            int day, sec;
            if (ASN1_TIME_diff(&day, &sec, X509_CRL_get_lastUpdate(best_crl),
                               X509_CRL_get_lastUpdate(crl)) == 0)
                continue;
            /*
             * ASN1_TIME_diff never returns inconsistent signs for |day|
             * and |sec|.
             */
            if (day <= 0 && sec <= 0)
                continue;
        }
        best_crl = crl;
        best_crl_issuer = crl_issuer;
        best_score = crl_score;
        best_reasons = reasons;
    }

    if (best_crl) {
        if (*pcrl)
            X509_CRL_free(*pcrl);
        *pcrl = best_crl;
        *pissuer = best_crl_issuer;
        *pscore = best_score;
        *preasons = best_reasons;
        CRYPTO_add(&best_crl->references, 1, CRYPTO_LOCK_X509_CRL);
        if (*pdcrl) {
            X509_CRL_free(*pdcrl);
            *pdcrl = NULL;
        }
        get_delta_sk(ctx, pdcrl, pscore, best_crl, crls);
    }

    if (best_score >= CRL_SCORE_VALID)
        return 1;

    return 0;
}

/*
 * Compare two CRL extensions for delta checking purposes. They should be
 * both present or both absent. If both present all fields must be identical.
 */

static int crl_extension_match(X509_CRL *a, X509_CRL *b, int nid)
{
    ASN1_OCTET_STRING *exta, *extb;
    int i;
    i = X509_CRL_get_ext_by_NID(a, nid, -1);
    if (i >= 0) {
        /* Can't have multiple occurrences */
        if (X509_CRL_get_ext_by_NID(a, nid, i) != -1)
            return 0;
        exta = X509_EXTENSION_get_data(X509_CRL_get_ext(a, i));
    } else
        exta = NULL;

    i = X509_CRL_get_ext_by_NID(b, nid, -1);

    if (i >= 0) {

        if (X509_CRL_get_ext_by_NID(b, nid, i) != -1)
            return 0;
        extb = X509_EXTENSION_get_data(X509_CRL_get_ext(b, i));
    } else
        extb = NULL;

    if (!exta && !extb)
        return 1;

    if (!exta || !extb)
        return 0;

    if (ASN1_OCTET_STRING_cmp(exta, extb))
        return 0;

    return 1;
}

/* See if a base and delta are compatible */

static int check_delta_base(X509_CRL *delta, X509_CRL *base)
{
    /* Delta CRL must be a delta */
    if (!delta->base_crl_number)
        return 0;
    /* Base must have a CRL number */
    if (!base->crl_number)
        return 0;
    /* Issuer names must match */
    if (X509_NAME_cmp(X509_CRL_get_issuer(base), X509_CRL_get_issuer(delta)))
        return 0;
    /* AKID and IDP must match */
    if (!crl_extension_match(delta, base, NID_authority_key_identifier))
        return 0;
    if (!crl_extension_match(delta, base, NID_issuing_distribution_point))
        return 0;
    /* Delta CRL base number must not exceed Full CRL number. */
    if (ASN1_INTEGER_cmp(delta->base_crl_number, base->crl_number) > 0)
        return 0;
    /* Delta CRL number must exceed full CRL number */
    if (ASN1_INTEGER_cmp(delta->crl_number, base->crl_number) > 0)
        return 1;
    return 0;
}

/*
 * For a given base CRL find a delta... maybe extend to delta scoring or
 * retrieve a chain of deltas...
 */

static void get_delta_sk(X509_STORE_CTX *ctx, X509_CRL **dcrl, int *pscore,
                         X509_CRL *base, STACK_OF(X509_CRL) *crls)
{
    X509_CRL *delta;
    int i;
    if (!(ctx->param->flags & X509_V_FLAG_USE_DELTAS))
        return;
    if (!((ctx->current_cert->ex_flags | base->flags) & EXFLAG_FRESHEST))
        return;
    for (i = 0; i < sk_X509_CRL_num(crls); i++) {
        delta = sk_X509_CRL_value(crls, i);
        if (check_delta_base(delta, base)) {
            if (check_crl_time(ctx, delta, 0))
                *pscore |= CRL_SCORE_TIME_DELTA;
            CRYPTO_add(&delta->references, 1, CRYPTO_LOCK_X509_CRL);
            *dcrl = delta;
            return;
        }
    }
    *dcrl = NULL;
}

/*
 * For a given CRL return how suitable it is for the supplied certificate
 * 'x'. The return value is a mask of several criteria. If the issuer is not
 * the certificate issuer this is returned in *pissuer. The reasons mask is
 * also used to determine if the CRL is suitable: if no new reasons the CRL
 * is rejected, otherwise reasons is updated.
 */

static int get_crl_score(X509_STORE_CTX *ctx, X509 **pissuer,
                         unsigned int *preasons, X509_CRL *crl, X509 *x)
{

    int crl_score = 0;
    unsigned int tmp_reasons = *preasons, crl_reasons;

    /* First see if we can reject CRL straight away */

    /* Invalid IDP cannot be processed */
    if (crl->idp_flags & IDP_INVALID)
        return 0;
    /* Reason codes or indirect CRLs need extended CRL support */
    if (!(ctx->param->flags & X509_V_FLAG_EXTENDED_CRL_SUPPORT)) {
        if (crl->idp_flags & (IDP_INDIRECT | IDP_REASONS))
            return 0;
    } else if (crl->idp_flags & IDP_REASONS) {
        /* If no new reasons reject */
        if (!(crl->idp_reasons & ~tmp_reasons))
            return 0;
    }
    /* Don't process deltas at this stage */
    else if (crl->base_crl_number)
        return 0;
    /* If issuer name doesn't match certificate need indirect CRL */
    if (X509_NAME_cmp(X509_get_issuer_name(x), X509_CRL_get_issuer(crl))) {
        if (!(crl->idp_flags & IDP_INDIRECT))
            return 0;
    } else
        crl_score |= CRL_SCORE_ISSUER_NAME;

    if (!(crl->flags & EXFLAG_CRITICAL))
        crl_score |= CRL_SCORE_NOCRITICAL;

    /* Check expiry */
    if (check_crl_time(ctx, crl, 0))
        crl_score |= CRL_SCORE_TIME;

    /* Check authority key ID and locate certificate issuer */
    crl_akid_check(ctx, crl, pissuer, &crl_score);

    /* If we can't locate certificate issuer at this point forget it */

    if (!(crl_score & CRL_SCORE_AKID))
        return 0;

    /* Check cert for matching CRL distribution points */

    if (crl_crldp_check(x, crl, crl_score, &crl_reasons)) {
        /* If no new reasons reject */
        if (!(crl_reasons & ~tmp_reasons))
            return 0;
        tmp_reasons |= crl_reasons;
        crl_score |= CRL_SCORE_SCOPE;
    }

    *preasons = tmp_reasons;

    return crl_score;

}

static void crl_akid_check(X509_STORE_CTX *ctx, X509_CRL *crl,
                           X509 **pissuer, int *pcrl_score)
{
    X509 *crl_issuer = NULL;
    X509_NAME *cnm = X509_CRL_get_issuer(crl);
    int cidx = ctx->error_depth;
    int i;

    if (cidx != sk_X509_num(ctx->chain) - 1)
        cidx++;

    crl_issuer = sk_X509_value(ctx->chain, cidx);

    if (X509_check_akid(crl_issuer, crl->akid) == X509_V_OK) {
        if (*pcrl_score & CRL_SCORE_ISSUER_NAME) {
            *pcrl_score |= CRL_SCORE_AKID | CRL_SCORE_ISSUER_CERT;
            *pissuer = crl_issuer;
            return;
        }
    }

    for (cidx++; cidx < sk_X509_num(ctx->chain); cidx++) {
        crl_issuer = sk_X509_value(ctx->chain, cidx);
        if (X509_NAME_cmp(X509_get_subject_name(crl_issuer), cnm))
            continue;
        if (X509_check_akid(crl_issuer, crl->akid) == X509_V_OK) {
            *pcrl_score |= CRL_SCORE_AKID | CRL_SCORE_SAME_PATH;
            *pissuer = crl_issuer;
            return;
        }
    }

    /* Anything else needs extended CRL support */

    if (!(ctx->param->flags & X509_V_FLAG_EXTENDED_CRL_SUPPORT))
        return;

    /*
     * Otherwise the CRL issuer is not on the path. Look for it in the set of
     * untrusted certificates.
     */
    for (i = 0; i < sk_X509_num(ctx->untrusted); i++) {
        crl_issuer = sk_X509_value(ctx->untrusted, i);
        if (X509_NAME_cmp(X509_get_subject_name(crl_issuer), cnm))
            continue;
        if (X509_check_akid(crl_issuer, crl->akid) == X509_V_OK) {
            *pissuer = crl_issuer;
            *pcrl_score |= CRL_SCORE_AKID;
            return;
        }
    }
}

/*
 * Check the path of a CRL issuer certificate. This creates a new
 * X509_STORE_CTX and populates it with most of the parameters from the
 * parent. This could be optimised somewhat since a lot of path checking will
 * be duplicated by the parent, but this will rarely be used in practice.
 */

static int check_crl_path(X509_STORE_CTX *ctx, X509 *x)
{
    X509_STORE_CTX crl_ctx;
    int ret;
    /* Don't allow recursive CRL path validation */
    if (ctx->parent)
        return 0;
    if (!X509_STORE_CTX_init(&crl_ctx, ctx->ctx, x, ctx->untrusted))
        return -1;

    crl_ctx.crls = ctx->crls;
    /* Copy verify params across */
    X509_STORE_CTX_set0_param(&crl_ctx, ctx->param);

    crl_ctx.parent = ctx;
    crl_ctx.verify_cb = ctx->verify_cb;

    /* Verify CRL issuer */
    ret = X509_verify_cert(&crl_ctx);

    if (ret <= 0)
        goto err;

    /* Check chain is acceptable */

    ret = check_crl_chain(ctx, ctx->chain, crl_ctx.chain);
 err:
    X509_STORE_CTX_cleanup(&crl_ctx);
    return ret;
}

/*
 * RFC3280 says nothing about the relationship between CRL path and
 * certificate path, which could lead to situations where a certificate could
 * be revoked or validated by a CA not authorised to do so. RFC5280 is more
 * strict and states that the two paths must end in the same trust anchor,
 * though some discussions remain... until this is resolved we use the
 * RFC5280 version
 */

static int check_crl_chain(X509_STORE_CTX *ctx,
                           STACK_OF(X509) *cert_path,
                           STACK_OF(X509) *crl_path)
{
    X509 *cert_ta, *crl_ta;
    cert_ta = sk_X509_value(cert_path, sk_X509_num(cert_path) - 1);
    crl_ta = sk_X509_value(crl_path, sk_X509_num(crl_path) - 1);
    if (!X509_cmp(cert_ta, crl_ta))
        return 1;
    return 0;
}

/*-
 * Check for match between two dist point names: three separate cases.
 * 1. Both are relative names and compare X509_NAME types.
 * 2. One full, one relative. Compare X509_NAME to GENERAL_NAMES.
 * 3. Both are full names and compare two GENERAL_NAMES.
 * 4. One is NULL: automatic match.
 */

static int idp_check_dp(DIST_POINT_NAME *a, DIST_POINT_NAME *b)
{
    X509_NAME *nm = NULL;
    GENERAL_NAMES *gens = NULL;
    GENERAL_NAME *gena, *genb;
    int i, j;
    if (!a || !b)
        return 1;
    if (a->type == 1) {
        if (!a->dpname)
            return 0;
        /* Case 1: two X509_NAME */
        if (b->type == 1) {
            if (!b->dpname)
                return 0;
            if (!X509_NAME_cmp(a->dpname, b->dpname))
                return 1;
            else
                return 0;
        }
        /* Case 2: set name and GENERAL_NAMES appropriately */
        nm = a->dpname;
        gens = b->name.fullname;
    } else if (b->type == 1) {
        if (!b->dpname)
            return 0;
        /* Case 2: set name and GENERAL_NAMES appropriately */
        gens = a->name.fullname;
        nm = b->dpname;
    }

    /* Handle case 2 with one GENERAL_NAMES and one X509_NAME */
    if (nm) {
        for (i = 0; i < sk_GENERAL_NAME_num(gens); i++) {
            gena = sk_GENERAL_NAME_value(gens, i);
            if (gena->type != GEN_DIRNAME)
                continue;
            if (!X509_NAME_cmp(nm, gena->d.directoryName))
                return 1;
        }
        return 0;
    }

    /* Else case 3: two GENERAL_NAMES */

    for (i = 0; i < sk_GENERAL_NAME_num(a->name.fullname); i++) {
        gena = sk_GENERAL_NAME_value(a->name.fullname, i);
        for (j = 0; j < sk_GENERAL_NAME_num(b->name.fullname); j++) {
            genb = sk_GENERAL_NAME_value(b->name.fullname, j);
            if (!GENERAL_NAME_cmp(gena, genb))
                return 1;
        }
    }

    return 0;

}

static int crldp_check_crlissuer(DIST_POINT *dp, X509_CRL *crl, int crl_score)
{
    int i;
    X509_NAME *nm = X509_CRL_get_issuer(crl);
    /* If no CRLissuer return is successful iff don't need a match */
    if (!dp->CRLissuer)
        return ! !(crl_score & CRL_SCORE_ISSUER_NAME);
    for (i = 0; i < sk_GENERAL_NAME_num(dp->CRLissuer); i++) {
        GENERAL_NAME *gen = sk_GENERAL_NAME_value(dp->CRLissuer, i);
        if (gen->type != GEN_DIRNAME)
            continue;
        if (!X509_NAME_cmp(gen->d.directoryName, nm))
            return 1;
    }
    return 0;
}

/* Check CRLDP and IDP */

static int crl_crldp_check(X509 *x, X509_CRL *crl, int crl_score,
                           unsigned int *preasons)
{
    int i;
    if (crl->idp_flags & IDP_ONLYATTR)
        return 0;
    if (x->ex_flags & EXFLAG_CA) {
        if (crl->idp_flags & IDP_ONLYUSER)
            return 0;
    } else {
        if (crl->idp_flags & IDP_ONLYCA)
            return 0;
    }
    *preasons = crl->idp_reasons;
    for (i = 0; i < sk_DIST_POINT_num(x->crldp); i++) {
        DIST_POINT *dp = sk_DIST_POINT_value(x->crldp, i);
        if (crldp_check_crlissuer(dp, crl, crl_score)) {
            if (!crl->idp || idp_check_dp(dp->distpoint, crl->idp->distpoint)) {
                *preasons &= dp->dp_reasons;
                return 1;
            }
        }
    }
    if ((!crl->idp || !crl->idp->distpoint)
        && (crl_score & CRL_SCORE_ISSUER_NAME))
        return 1;
    return 0;
}

/*
 * Retrieve CRL corresponding to current certificate. If deltas enabled try
 * to find a delta CRL too
 */

static int get_crl_delta(X509_STORE_CTX *ctx,
                         X509_CRL **pcrl, X509_CRL **pdcrl, X509 *x)
{
    int ok;
    X509 *issuer = NULL;
    int crl_score = 0;
    unsigned int reasons;
    X509_CRL *crl = NULL, *dcrl = NULL;
    STACK_OF(X509_CRL) *skcrl;
    X509_NAME *nm = X509_get_issuer_name(x);
    reasons = ctx->current_reasons;
    ok = get_crl_sk(ctx, &crl, &dcrl,
                    &issuer, &crl_score, &reasons, ctx->crls);

    if (ok)
        goto done;

    /* Lookup CRLs from store */

    skcrl = ctx->lookup_crls(ctx, nm);

    /* If no CRLs found and a near match from get_crl_sk use that */
    if (!skcrl && crl)
        goto done;

    get_crl_sk(ctx, &crl, &dcrl, &issuer, &crl_score, &reasons, skcrl);

    sk_X509_CRL_pop_free(skcrl, X509_CRL_free);

 done:

    /* If we got any kind of CRL use it and return success */
    if (crl) {
        ctx->current_issuer = issuer;
        ctx->current_crl_score = crl_score;
        ctx->current_reasons = reasons;
        *pcrl = crl;
        *pdcrl = dcrl;
        return 1;
    }

    return 0;
}

/* Check CRL validity */
static int check_crl(X509_STORE_CTX *ctx, X509_CRL *crl)
{
    X509 *issuer = NULL;
    EVP_PKEY *ikey = NULL;
    int ok = 0, chnum, cnum;
    cnum = ctx->error_depth;
    chnum = sk_X509_num(ctx->chain) - 1;
    /* if we have an alternative CRL issuer cert use that */
    if (ctx->current_issuer)
        issuer = ctx->current_issuer;

    /*
     * Else find CRL issuer: if not last certificate then issuer is next
     * certificate in chain.
     */
    else if (cnum < chnum)
        issuer = sk_X509_value(ctx->chain, cnum + 1);
    else {
        issuer = sk_X509_value(ctx->chain, chnum);
        /* If not self signed, can't check signature */
        if (!ctx->check_issued(ctx, issuer, issuer)) {
            ctx->error = X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER;
            ok = ctx->verify_cb(0, ctx);
            if (!ok)
                goto err;
        }
    }

    if (issuer) {
        /*
         * Skip most tests for deltas because they have already been done
         */
        if (!crl->base_crl_number) {
            /* Check for cRLSign bit if keyUsage present */
            if ((issuer->ex_flags & EXFLAG_KUSAGE) &&
                !(issuer->ex_kusage & KU_CRL_SIGN)) {
                ctx->error = X509_V_ERR_KEYUSAGE_NO_CRL_SIGN;
                ok = ctx->verify_cb(0, ctx);
                if (!ok)
                    goto err;
            }

            if (!(ctx->current_crl_score & CRL_SCORE_SCOPE)) {
                ctx->error = X509_V_ERR_DIFFERENT_CRL_SCOPE;
                ok = ctx->verify_cb(0, ctx);
                if (!ok)
                    goto err;
            }

            if (!(ctx->current_crl_score & CRL_SCORE_SAME_PATH)) {
                if (check_crl_path(ctx, ctx->current_issuer) <= 0) {
                    ctx->error = X509_V_ERR_CRL_PATH_VALIDATION_ERROR;
                    ok = ctx->verify_cb(0, ctx);
                    if (!ok)
                        goto err;
                }
            }

            if (crl->idp_flags & IDP_INVALID) {
                ctx->error = X509_V_ERR_INVALID_EXTENSION;
                ok = ctx->verify_cb(0, ctx);
                if (!ok)
                    goto err;
            }

        }

        if (!(ctx->current_crl_score & CRL_SCORE_TIME)) {
            ok = check_crl_time(ctx, crl, 1);
            if (!ok)
                goto err;
        }

        /* Attempt to get issuer certificate public key */
        ikey = X509_get_pubkey(issuer);

        if (!ikey) {
            ctx->error = X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY;
            ok = ctx->verify_cb(0, ctx);
            if (!ok)
                goto err;
        } else {
            int rv;
            rv = X509_CRL_check_suiteb(crl, ikey, ctx->param->flags);
            if (rv != X509_V_OK) {
                ctx->error = rv;
                ok = ctx->verify_cb(0, ctx);
                if (!ok)
                    goto err;
            }
            /* Verify CRL signature */
            if (X509_CRL_verify(crl, ikey) <= 0) {
                ctx->error = X509_V_ERR_CRL_SIGNATURE_FAILURE;
                ok = ctx->verify_cb(0, ctx);
                if (!ok)
                    goto err;
            }
        }
    }

    ok = 1;

 err:
    EVP_PKEY_free(ikey);
    return ok;
}

/* Check certificate against CRL */
static int cert_crl(X509_STORE_CTX *ctx, X509_CRL *crl, X509 *x)
{
    int ok;
    X509_REVOKED *rev;
    /*
     * The rules changed for this... previously if a CRL contained unhandled
     * critical extensions it could still be used to indicate a certificate
     * was revoked. This has since been changed since critical extension can
     * change the meaning of CRL entries.
     */
    if (!(ctx->param->flags & X509_V_FLAG_IGNORE_CRITICAL)
        && (crl->flags & EXFLAG_CRITICAL)) {
        ctx->error = X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION;
        ok = ctx->verify_cb(0, ctx);
        if (!ok)
            return 0;
    }
    /*
     * Look for serial number of certificate in CRL If found make sure reason
     * is not removeFromCRL.
     */
    if (X509_CRL_get0_by_cert(crl, &rev, x)) {
        if (rev->reason == CRL_REASON_REMOVE_FROM_CRL)
            return 2;
        ctx->error = X509_V_ERR_CERT_REVOKED;
        ok = ctx->verify_cb(0, ctx);
        if (!ok)
            return 0;
    }

    return 1;
}

static int check_policy(X509_STORE_CTX *ctx)
{
    int ret;
    if (ctx->parent)
        return 1;
    ret = X509_policy_check(&ctx->tree, &ctx->explicit_policy, ctx->chain,
                            ctx->param->policies, ctx->param->flags);
    if (ret == 0) {
        X509err(X509_F_CHECK_POLICY, ERR_R_MALLOC_FAILURE);
        ctx->error = X509_V_ERR_OUT_OF_MEM;
        return 0;
    }
    /* Invalid or inconsistent extensions */
    if (ret == -1) {
        /*
         * Locate certificates with bad extensions and notify callback.
         */
        X509 *x;
        int i;
        for (i = 1; i < sk_X509_num(ctx->chain); i++) {
            x = sk_X509_value(ctx->chain, i);
            if (!(x->ex_flags & EXFLAG_INVALID_POLICY))
                continue;
            ctx->current_cert = x;
            ctx->error = X509_V_ERR_INVALID_POLICY_EXTENSION;
            if (!ctx->verify_cb(0, ctx))
                return 0;
        }
        return 1;
    }
    if (ret == -2) {
        ctx->current_cert = NULL;
        ctx->error = X509_V_ERR_NO_EXPLICIT_POLICY;
        return ctx->verify_cb(0, ctx);
    }

    if (ctx->param->flags & X509_V_FLAG_NOTIFY_POLICY) {
        ctx->current_cert = NULL;
        /*
         * Verification errors need to be "sticky", a callback may have allowed
         * an SSL handshake to continue despite an error, and we must then
         * remain in an error state.  Therefore, we MUST NOT clear earlier
         * verification errors by setting the error to X509_V_OK.
         */
        if (!ctx->verify_cb(2, ctx))
            return 0;
    }

    return 1;
}

static int check_cert_time(X509_STORE_CTX *ctx, X509 *x)
{
    time_t *ptime;
    int i;

    if (ctx->param->flags & X509_V_FLAG_USE_CHECK_TIME)
        ptime = &ctx->param->check_time;
    else
        ptime = NULL;

    i = X509_cmp_time(X509_get_notBefore(x), ptime);
    if (i == 0) {
        ctx->error = X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD;
        ctx->current_cert = x;
        if (!ctx->verify_cb(0, ctx))
            return 0;
    }

    if (i > 0) {
        ctx->error = X509_V_ERR_CERT_NOT_YET_VALID;
        ctx->current_cert = x;
        if (!ctx->verify_cb(0, ctx))
            return 0;
    }

    i = X509_cmp_time(X509_get_notAfter(x), ptime);
    if (i == 0) {
        ctx->error = X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD;
        ctx->current_cert = x;
        if (!ctx->verify_cb(0, ctx))
            return 0;
    }

    if (i < 0) {
        ctx->error = X509_V_ERR_CERT_HAS_EXPIRED;
        ctx->current_cert = x;
        if (!ctx->verify_cb(0, ctx))
            return 0;
    }

    return 1;
}

static int internal_verify(X509_STORE_CTX *ctx)
{
    int ok = 0, n;
    X509 *xs, *xi;
    EVP_PKEY *pkey = NULL;
    int (*cb) (int xok, X509_STORE_CTX *xctx);

    cb = ctx->verify_cb;

    n = sk_X509_num(ctx->chain);
    ctx->error_depth = n - 1;
    n--;
    xi = sk_X509_value(ctx->chain, n);

    if (ctx->check_issued(ctx, xi, xi))
        xs = xi;
    else {
        if (ctx->param->flags & X509_V_FLAG_PARTIAL_CHAIN) {
            xs = xi;
            goto check_cert;
        }
        if (n <= 0) {
            ctx->error = X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE;
            ctx->current_cert = xi;
            ok = cb(0, ctx);
            goto end;
        } else {
            n--;
            ctx->error_depth = n;
            xs = sk_X509_value(ctx->chain, n);
        }
    }

/*      ctx->error=0;  not needed */
    while (n >= 0) {
        ctx->error_depth = n;

        /*
         * Skip signature check for self signed certificates unless
         * explicitly asked for. It doesn't add any security and just wastes
         * time.
         */
        if (!xs->valid
            && (xs != xi
                || (ctx->param->flags & X509_V_FLAG_CHECK_SS_SIGNATURE))) {
            if ((pkey = X509_get_pubkey(xi)) == NULL) {
                ctx->error = X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY;
                ctx->current_cert = xi;
                ok = (*cb) (0, ctx);
                if (!ok)
                    goto end;
            } else if (X509_verify(xs, pkey) <= 0) {
                ctx->error = X509_V_ERR_CERT_SIGNATURE_FAILURE;
                ctx->current_cert = xs;
                ok = (*cb) (0, ctx);
                if (!ok) {
                    EVP_PKEY_free(pkey);
                    goto end;
                }
            }
            EVP_PKEY_free(pkey);
            pkey = NULL;
        }

        xs->valid = 1;

 check_cert:
        ok = check_cert_time(ctx, xs);
        if (!ok)
            goto end;

        /* The last error (if any) is still in the error value */
        ctx->current_issuer = xi;
        ctx->current_cert = xs;
        ok = (*cb) (1, ctx);
        if (!ok)
            goto end;

        n--;
        if (n >= 0) {
            xi = xs;
            xs = sk_X509_value(ctx->chain, n);
        }
    }
    ok = 1;
 end:
    return ok;
}

int X509_cmp_current_time(const ASN1_TIME *ctm)
{
    return X509_cmp_time(ctm, NULL);
}

int X509_cmp_time(const ASN1_TIME *ctm, time_t *cmp_time)
{
    static const size_t utctime_length = sizeof("YYMMDDHHMMSSZ") - 1;
    static const size_t generalizedtime_length = sizeof("YYYYMMDDHHMMSSZ") - 1;
    ASN1_TIME *asn1_cmp_time = NULL;
    int i, day, sec, ret = 0;

    /*
     * Note that ASN.1 allows much more slack in the time format than RFC5280.
     * In RFC5280, the representation is fixed:
     * UTCTime: YYMMDDHHMMSSZ
     * GeneralizedTime: YYYYMMDDHHMMSSZ
     *
     * We do NOT currently enforce the following RFC 5280 requirement:
     * "CAs conforming to this profile MUST always encode certificate
     *  validity dates through the year 2049 as UTCTime; certificate validity
     *  dates in 2050 or later MUST be encoded as GeneralizedTime."
     */
    switch (ctm->type) {
    case V_ASN1_UTCTIME:
        if (ctm->length != (int)(utctime_length))
            return 0;
        break;
    case V_ASN1_GENERALIZEDTIME:
        if (ctm->length != (int)(generalizedtime_length))
            return 0;
        break;
    default:
        return 0;
    }

    /**
     * Verify the format: the ASN.1 functions we use below allow a more
     * flexible format than what's mandated by RFC 5280.
     * Digit and date ranges will be verified in the conversion methods.
     */
    for (i = 0; i < ctm->length - 1; i++) {
        if (!isdigit(ctm->data[i]))
            return 0;
    }
    if (ctm->data[ctm->length - 1] != 'Z')
        return 0;

    /*
     * There is ASN1_UTCTIME_cmp_time_t but no
     * ASN1_GENERALIZEDTIME_cmp_time_t or ASN1_TIME_cmp_time_t,
     * so we go through ASN.1
     */
    asn1_cmp_time = X509_time_adj(NULL, 0, cmp_time);
    if (asn1_cmp_time == NULL)
        goto err;
    if (!ASN1_TIME_diff(&day, &sec, ctm, asn1_cmp_time))
        goto err;

    /*
     * X509_cmp_time comparison is <=.
     * The return value 0 is reserved for errors.
     */
    ret = (day >= 0 && sec >= 0) ? -1 : 1;

 err:
    ASN1_TIME_free(asn1_cmp_time);
    return ret;
}

ASN1_TIME *X509_gmtime_adj(ASN1_TIME *s, long adj)
{
    return X509_time_adj(s, adj, NULL);
}

ASN1_TIME *X509_time_adj(ASN1_TIME *s, long offset_sec, time_t *in_tm)
{
    return X509_time_adj_ex(s, 0, offset_sec, in_tm);
}

ASN1_TIME *X509_time_adj_ex(ASN1_TIME *s,
                            int offset_day, long offset_sec, time_t *in_tm)
{
    time_t t;

    if (in_tm)
        t = *in_tm;
    else
        time(&t);

    if (s && !(s->flags & ASN1_STRING_FLAG_MSTRING)) {
        if (s->type == V_ASN1_UTCTIME)
            return ASN1_UTCTIME_adj(s, t, offset_day, offset_sec);
        if (s->type == V_ASN1_GENERALIZEDTIME)
            return ASN1_GENERALIZEDTIME_adj(s, t, offset_day, offset_sec);
    }
    return ASN1_TIME_adj(s, t, offset_day, offset_sec);
}

int X509_get_pubkey_parameters(EVP_PKEY *pkey, STACK_OF(X509) *chain)
{
    EVP_PKEY *ktmp = NULL, *ktmp2;
    int i, j;

    if ((pkey != NULL) && !EVP_PKEY_missing_parameters(pkey))
        return 1;

    for (i = 0; i < sk_X509_num(chain); i++) {
        ktmp = X509_get_pubkey(sk_X509_value(chain, i));
        if (ktmp == NULL) {
            X509err(X509_F_X509_GET_PUBKEY_PARAMETERS,
                    X509_R_UNABLE_TO_GET_CERTS_PUBLIC_KEY);
            return 0;
        }
        if (!EVP_PKEY_missing_parameters(ktmp))
            break;
        else {
            EVP_PKEY_free(ktmp);
            ktmp = NULL;
        }
    }
    if (ktmp == NULL) {
        X509err(X509_F_X509_GET_PUBKEY_PARAMETERS,
                X509_R_UNABLE_TO_FIND_PARAMETERS_IN_CHAIN);
        return 0;
    }

    /* first, populate the other certs */
    for (j = i - 1; j >= 0; j--) {
        ktmp2 = X509_get_pubkey(sk_X509_value(chain, j));
        EVP_PKEY_copy_parameters(ktmp2, ktmp);
        EVP_PKEY_free(ktmp2);
    }

    if (pkey != NULL)
        EVP_PKEY_copy_parameters(pkey, ktmp);
    EVP_PKEY_free(ktmp);
    return 1;
}

/* Make a delta CRL as the diff between two full CRLs */

X509_CRL *X509_CRL_diff(X509_CRL *base, X509_CRL *newer,
                        EVP_PKEY *skey, const EVP_MD *md, unsigned int flags)
{
    X509_CRL *crl = NULL;
    int i;
    STACK_OF(X509_REVOKED) *revs = NULL;
    /* CRLs can't be delta already */
    if (base->base_crl_number || newer->base_crl_number) {
        X509err(X509_F_X509_CRL_DIFF, X509_R_CRL_ALREADY_DELTA);
        return NULL;
    }
    /* Base and new CRL must have a CRL number */
    if (!base->crl_number || !newer->crl_number) {
        X509err(X509_F_X509_CRL_DIFF, X509_R_NO_CRL_NUMBER);
        return NULL;
    }
    /* Issuer names must match */
    if (X509_NAME_cmp(X509_CRL_get_issuer(base), X509_CRL_get_issuer(newer))) {
        X509err(X509_F_X509_CRL_DIFF, X509_R_ISSUER_MISMATCH);
        return NULL;
    }
    /* AKID and IDP must match */
    if (!crl_extension_match(base, newer, NID_authority_key_identifier)) {
        X509err(X509_F_X509_CRL_DIFF, X509_R_AKID_MISMATCH);
        return NULL;
    }
    if (!crl_extension_match(base, newer, NID_issuing_distribution_point)) {
        X509err(X509_F_X509_CRL_DIFF, X509_R_IDP_MISMATCH);
        return NULL;
    }
    /* Newer CRL number must exceed full CRL number */
    if (ASN1_INTEGER_cmp(newer->crl_number, base->crl_number) <= 0) {
        X509err(X509_F_X509_CRL_DIFF, X509_R_NEWER_CRL_NOT_NEWER);
        return NULL;
    }
    /* CRLs must verify */
    if (skey && (X509_CRL_verify(base, skey) <= 0 ||
                 X509_CRL_verify(newer, skey) <= 0)) {
        X509err(X509_F_X509_CRL_DIFF, X509_R_CRL_VERIFY_FAILURE);
        return NULL;
    }
    /* Create new CRL */
    crl = X509_CRL_new();
    if (!crl || !X509_CRL_set_version(crl, 1))
        goto memerr;
    /* Set issuer name */
    if (!X509_CRL_set_issuer_name(crl, X509_CRL_get_issuer(newer)))
        goto memerr;

    if (!X509_CRL_set_lastUpdate(crl, X509_CRL_get_lastUpdate(newer)))
        goto memerr;
    if (!X509_CRL_set_nextUpdate(crl, X509_CRL_get_nextUpdate(newer)))
        goto memerr;

    /* Set base CRL number: must be critical */

    if (!X509_CRL_add1_ext_i2d(crl, NID_delta_crl, base->crl_number, 1, 0))
        goto memerr;

    /*
     * Copy extensions across from newest CRL to delta: this will set CRL
     * number to correct value too.
     */

    for (i = 0; i < X509_CRL_get_ext_count(newer); i++) {
        X509_EXTENSION *ext;
        ext = X509_CRL_get_ext(newer, i);
        if (!X509_CRL_add_ext(crl, ext, -1))
            goto memerr;
    }

    /* Go through revoked entries, copying as needed */

    revs = X509_CRL_get_REVOKED(newer);

    for (i = 0; i < sk_X509_REVOKED_num(revs); i++) {
        X509_REVOKED *rvn, *rvtmp;
        rvn = sk_X509_REVOKED_value(revs, i);
        /*
         * Add only if not also in base. TODO: need something cleverer here
         * for some more complex CRLs covering multiple CAs.
         */
        if (!X509_CRL_get0_by_serial(base, &rvtmp, rvn->serialNumber)) {
            rvtmp = X509_REVOKED_dup(rvn);
            if (!rvtmp)
                goto memerr;
            if (!X509_CRL_add0_revoked(crl, rvtmp)) {
                X509_REVOKED_free(rvtmp);
                goto memerr;
            }
        }
    }
    /* TODO: optionally prune deleted entries */

    if (skey && md && !X509_CRL_sign(crl, skey, md))
        goto memerr;

    return crl;

 memerr:
    X509err(X509_F_X509_CRL_DIFF, ERR_R_MALLOC_FAILURE);
    if (crl)
        X509_CRL_free(crl);
    return NULL;
}

int X509_STORE_CTX_get_ex_new_index(long argl, void *argp,
                                    CRYPTO_EX_new *new_func,
                                    CRYPTO_EX_dup *dup_func,
                                    CRYPTO_EX_free *free_func)
{
    /*
     * This function is (usually) called only once, by
     * SSL_get_ex_data_X509_STORE_CTX_idx (ssl/ssl_cert.c).
     */
    return CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_X509_STORE_CTX, argl, argp,
                                   new_func, dup_func, free_func);
}

int X509_STORE_CTX_set_ex_data(X509_STORE_CTX *ctx, int idx, void *data)
{
    return CRYPTO_set_ex_data(&ctx->ex_data, idx, data);
}

void *X509_STORE_CTX_get_ex_data(X509_STORE_CTX *ctx, int idx)
{
    return CRYPTO_get_ex_data(&ctx->ex_data, idx);
}

int X509_STORE_CTX_get_error(X509_STORE_CTX *ctx)
{
    return ctx->error;
}

void X509_STORE_CTX_set_error(X509_STORE_CTX *ctx, int err)
{
    ctx->error = err;
}

int X509_STORE_CTX_get_error_depth(X509_STORE_CTX *ctx)
{
    return ctx->error_depth;
}

X509 *X509_STORE_CTX_get_current_cert(X509_STORE_CTX *ctx)
{
    return ctx->current_cert;
}

STACK_OF(X509) *X509_STORE_CTX_get_chain(X509_STORE_CTX *ctx)
{
    return ctx->chain;
}

STACK_OF(X509) *X509_STORE_CTX_get1_chain(X509_STORE_CTX *ctx)
{
    if (!ctx->chain)
        return NULL;
    return X509_chain_up_ref(ctx->chain);
}

X509 *X509_STORE_CTX_get0_current_issuer(X509_STORE_CTX *ctx)
{
    return ctx->current_issuer;
}

X509_CRL *X509_STORE_CTX_get0_current_crl(X509_STORE_CTX *ctx)
{
    return ctx->current_crl;
}

X509_STORE_CTX *X509_STORE_CTX_get0_parent_ctx(X509_STORE_CTX *ctx)
{
    return ctx->parent;
}

void X509_STORE_CTX_set_cert(X509_STORE_CTX *ctx, X509 *x)
{
    ctx->cert = x;
}

void X509_STORE_CTX_set_chain(X509_STORE_CTX *ctx, STACK_OF(X509) *sk)
{
    ctx->untrusted = sk;
}

void X509_STORE_CTX_set0_crls(X509_STORE_CTX *ctx, STACK_OF(X509_CRL) *sk)
{
    ctx->crls = sk;
}

int X509_STORE_CTX_set_purpose(X509_STORE_CTX *ctx, int purpose)
{
    return X509_STORE_CTX_purpose_inherit(ctx, 0, purpose, 0);
}

int X509_STORE_CTX_set_trust(X509_STORE_CTX *ctx, int trust)
{
    return X509_STORE_CTX_purpose_inherit(ctx, 0, 0, trust);
}

/*
 * This function is used to set the X509_STORE_CTX purpose and trust values.
 * This is intended to be used when another structure has its own trust and
 * purpose values which (if set) will be inherited by the ctx. If they aren't
 * set then we will usually have a default purpose in mind which should then
 * be used to set the trust value. An example of this is SSL use: an SSL
 * structure will have its own purpose and trust settings which the
 * application can set: if they aren't set then we use the default of SSL
 * client/server.
 */

int X509_STORE_CTX_purpose_inherit(X509_STORE_CTX *ctx, int def_purpose,
                                   int purpose, int trust)
{
    int idx;
    /* If purpose not set use default */
    if (!purpose)
        purpose = def_purpose;
    /* If we have a purpose then check it is valid */
    if (purpose) {
        X509_PURPOSE *ptmp;
        idx = X509_PURPOSE_get_by_id(purpose);
        if (idx == -1) {
            X509err(X509_F_X509_STORE_CTX_PURPOSE_INHERIT,
                    X509_R_UNKNOWN_PURPOSE_ID);
            return 0;
        }
        ptmp = X509_PURPOSE_get0(idx);
        if (ptmp->trust == X509_TRUST_DEFAULT) {
            idx = X509_PURPOSE_get_by_id(def_purpose);
            if (idx == -1) {
                X509err(X509_F_X509_STORE_CTX_PURPOSE_INHERIT,
                        X509_R_UNKNOWN_PURPOSE_ID);
                return 0;
            }
            ptmp = X509_PURPOSE_get0(idx);
        }
        /* If trust not set then get from purpose default */
        if (!trust)
            trust = ptmp->trust;
    }
    if (trust) {
        idx = X509_TRUST_get_by_id(trust);
        if (idx == -1) {
            X509err(X509_F_X509_STORE_CTX_PURPOSE_INHERIT,
                    X509_R_UNKNOWN_TRUST_ID);
            return 0;
        }
    }

    if (purpose && !ctx->param->purpose)
        ctx->param->purpose = purpose;
    if (trust && !ctx->param->trust)
        ctx->param->trust = trust;
    return 1;
}

X509_STORE_CTX *X509_STORE_CTX_new(void)
{
    X509_STORE_CTX *ctx;
    ctx = (X509_STORE_CTX *)OPENSSL_malloc(sizeof(X509_STORE_CTX));
    if (!ctx) {
        X509err(X509_F_X509_STORE_CTX_NEW, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    memset(ctx, 0, sizeof(X509_STORE_CTX));
    return ctx;
}

void X509_STORE_CTX_free(X509_STORE_CTX *ctx)
{
    if (!ctx)
        return;
    X509_STORE_CTX_cleanup(ctx);
    OPENSSL_free(ctx);
}

int X509_STORE_CTX_init(X509_STORE_CTX *ctx, X509_STORE *store, X509 *x509,
                        STACK_OF(X509) *chain)
{
    int ret = 1;
    ctx->ctx = store;
    ctx->current_method = 0;
    ctx->cert = x509;
    ctx->untrusted = chain;
    ctx->crls = NULL;
    ctx->last_untrusted = 0;
    ctx->other_ctx = NULL;
    ctx->valid = 0;
    ctx->chain = NULL;
    ctx->error = 0;
    ctx->explicit_policy = 0;
    ctx->error_depth = 0;
    ctx->current_cert = NULL;
    ctx->current_issuer = NULL;
    ctx->current_crl = NULL;
    ctx->current_crl_score = 0;
    ctx->current_reasons = 0;
    ctx->tree = NULL;
    ctx->parent = NULL;
    /* Zero ex_data to make sure we're cleanup-safe */
    memset(&ctx->ex_data, 0, sizeof(ctx->ex_data));

    ctx->param = X509_VERIFY_PARAM_new();
    if (!ctx->param) {
        X509err(X509_F_X509_STORE_CTX_INIT, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    /*
     * Inherit callbacks and flags from X509_STORE if not set use defaults.
     */
    if (store)
        ret = X509_VERIFY_PARAM_inherit(ctx->param, store->param);
    else
        ctx->param->inh_flags |= X509_VP_FLAG_DEFAULT | X509_VP_FLAG_ONCE;

    if (store) {
        ctx->verify_cb = store->verify_cb;
        /* Seems to always be 0 in OpenSSL, else must be idempotent */
        ctx->cleanup = store->cleanup;
    } else
        ctx->cleanup = 0;

    if (ret)
        ret = X509_VERIFY_PARAM_inherit(ctx->param,
                                        X509_VERIFY_PARAM_lookup("default"));

    if (ret == 0) {
        X509err(X509_F_X509_STORE_CTX_INIT, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (store && store->check_issued)
        ctx->check_issued = store->check_issued;
    else
        ctx->check_issued = check_issued;

    if (store && store->get_issuer)
        ctx->get_issuer = store->get_issuer;
    else
        ctx->get_issuer = X509_STORE_CTX_get1_issuer;

    if (store && store->verify_cb)
        ctx->verify_cb = store->verify_cb;
    else
        ctx->verify_cb = null_callback;

    if (store && store->verify)
        ctx->verify = store->verify;
    else
        ctx->verify = internal_verify;

    if (store && store->check_revocation)
        ctx->check_revocation = store->check_revocation;
    else
        ctx->check_revocation = check_revocation;

    if (store && store->get_crl)
        ctx->get_crl = store->get_crl;
    else
        ctx->get_crl = NULL;

    if (store && store->check_crl)
        ctx->check_crl = store->check_crl;
    else
        ctx->check_crl = check_crl;

    if (store && store->cert_crl)
        ctx->cert_crl = store->cert_crl;
    else
        ctx->cert_crl = cert_crl;

    if (store && store->lookup_certs)
        ctx->lookup_certs = store->lookup_certs;
    else
        ctx->lookup_certs = X509_STORE_get1_certs;

    if (store && store->lookup_crls)
        ctx->lookup_crls = store->lookup_crls;
    else
        ctx->lookup_crls = X509_STORE_get1_crls;

    ctx->check_policy = check_policy;

    if (CRYPTO_new_ex_data(CRYPTO_EX_INDEX_X509_STORE_CTX, ctx,
                           &ctx->ex_data))
        return 1;
    X509err(X509_F_X509_STORE_CTX_INIT, ERR_R_MALLOC_FAILURE);

 err:
    /*
     * On error clean up allocated storage, if the store context was not
     * allocated with X509_STORE_CTX_new() this is our last chance to do so.
     */
    X509_STORE_CTX_cleanup(ctx);
    return 0;
}

/*
 * Set alternative lookup method: just a STACK of trusted certificates. This
 * avoids X509_STORE nastiness where it isn't needed.
 */

void X509_STORE_CTX_trusted_stack(X509_STORE_CTX *ctx, STACK_OF(X509) *sk)
{
    ctx->other_ctx = sk;
    ctx->get_issuer = get_issuer_sk;
}

void X509_STORE_CTX_cleanup(X509_STORE_CTX *ctx)
{
    /*
     * We need to be idempotent because, unfortunately, free() also calls
     * cleanup(), so the natural call sequence new(), init(), cleanup(), free()
     * calls cleanup() for the same object twice!  Thus we must zero the
     * pointers below after they're freed!
     */
    /* Seems to always be 0 in OpenSSL, do this at most once. */
    if (ctx->cleanup != NULL) {
        ctx->cleanup(ctx);
        ctx->cleanup = NULL;
    }
    if (ctx->param != NULL) {
        if (ctx->parent == NULL)
            X509_VERIFY_PARAM_free(ctx->param);
        ctx->param = NULL;
    }
    if (ctx->tree != NULL) {
        X509_policy_tree_free(ctx->tree);
        ctx->tree = NULL;
    }
    if (ctx->chain != NULL) {
        sk_X509_pop_free(ctx->chain, X509_free);
        ctx->chain = NULL;
    }
    CRYPTO_free_ex_data(CRYPTO_EX_INDEX_X509_STORE_CTX, ctx, &(ctx->ex_data));
    memset(&ctx->ex_data, 0, sizeof(CRYPTO_EX_DATA));
}

void X509_STORE_CTX_set_depth(X509_STORE_CTX *ctx, int depth)
{
    X509_VERIFY_PARAM_set_depth(ctx->param, depth);
}

void X509_STORE_CTX_set_flags(X509_STORE_CTX *ctx, unsigned long flags)
{
    X509_VERIFY_PARAM_set_flags(ctx->param, flags);
}

void X509_STORE_CTX_set_time(X509_STORE_CTX *ctx, unsigned long flags,
                             time_t t)
{
    X509_VERIFY_PARAM_set_time(ctx->param, t);
}

void X509_STORE_CTX_set_verify_cb(X509_STORE_CTX *ctx,
                                  int (*verify_cb) (int, X509_STORE_CTX *))
{
    ctx->verify_cb = verify_cb;
}

X509_POLICY_TREE *X509_STORE_CTX_get0_policy_tree(X509_STORE_CTX *ctx)
{
    return ctx->tree;
}

int X509_STORE_CTX_get_explicit_policy(X509_STORE_CTX *ctx)
{
    return ctx->explicit_policy;
}

int X509_STORE_CTX_set_default(X509_STORE_CTX *ctx, const char *name)
{
    const X509_VERIFY_PARAM *param;
    param = X509_VERIFY_PARAM_lookup(name);
    if (!param)
        return 0;
    return X509_VERIFY_PARAM_inherit(ctx->param, param);
}

X509_VERIFY_PARAM *X509_STORE_CTX_get0_param(X509_STORE_CTX *ctx)
{
    return ctx->param;
}

void X509_STORE_CTX_set0_param(X509_STORE_CTX *ctx, X509_VERIFY_PARAM *param)
{
    if (ctx->param)
        X509_VERIFY_PARAM_free(ctx->param);
    ctx->param = param;
}

IMPLEMENT_STACK_OF(X509)

IMPLEMENT_ASN1_SET_OF(X509)

IMPLEMENT_STACK_OF(X509_NAME)

IMPLEMENT_STACK_OF(X509_ATTRIBUTE)

IMPLEMENT_ASN1_SET_OF(X509_ATTRIBUTE)
/* x509_vpm.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 2004.
 */
/* ====================================================================
 * Copyright (c) 2004 The OpenSSL Project.  All rights reserved.
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
// #include "crypto.h"
// #include "lhash.h"
// #include "buffer.h"
// #include "x509.h"
// #include "x509v3.h"

// #include "vpm_int.h"

/* X509_VERIFY_PARAM functions */

#define SET_HOST 0
#define ADD_HOST 1

static char *str_copy(const char *s)
{
    return OPENSSL_strdup(s);
}

static void str_free(char *s)
{
    OPENSSL_free(s);
}

#define string_stack_free(sk) sk_OPENSSL_STRING_pop_free(sk, str_free)

static int int_x509_param_set_hosts(X509_VERIFY_PARAM_ID *id, int mode,
                                    const char *name, size_t namelen)
{
    char *copy;

    /*
     * Refuse names with embedded NUL bytes, except perhaps as final byte.
     * XXX: Do we need to push an error onto the error stack?
     */
    if (namelen == 0 || name == NULL)
        namelen = name ? strlen(name) : 0;
    else if (name && memchr(name, '\0', namelen > 1 ? namelen - 1 : namelen))
        return 0;
    if (namelen > 0 && name[namelen - 1] == '\0')
        --namelen;

    if (mode == SET_HOST && id->hosts) {
        string_stack_free(id->hosts);
        id->hosts = NULL;
    }
    if (name == NULL || namelen == 0)
        return 1;

    copy = BUF_strndup(name, namelen);
    if (copy == NULL)
        return 0;

    if (id->hosts == NULL &&
        (id->hosts = sk_OPENSSL_STRING_new_null()) == NULL) {
        OPENSSL_free(copy);
        return 0;
    }

    if (!sk_OPENSSL_STRING_push(id->hosts, copy)) {
        OPENSSL_free(copy);
        if (sk_OPENSSL_STRING_num(id->hosts) == 0) {
            sk_OPENSSL_STRING_free(id->hosts);
            id->hosts = NULL;
        }
        return 0;
    }

    return 1;
}

static void x509_verify_param_zero(X509_VERIFY_PARAM *param)
{
    X509_VERIFY_PARAM_ID *paramid;
    if (!param)
        return;
    param->name = NULL;
    param->purpose = 0;
    param->trust = 0;
    /*
     * param->inh_flags = X509_VP_FLAG_DEFAULT;
     */
    param->inh_flags = 0;
    param->flags = 0;
    param->depth = -1;
    if (param->policies) {
        sk_ASN1_OBJECT_pop_free(param->policies, ASN1_OBJECT_free);
        param->policies = NULL;
    }
    paramid = param->id;
    if (paramid->hosts) {
        string_stack_free(paramid->hosts);
        paramid->hosts = NULL;
    }
    if (paramid->peername)
        OPENSSL_free(paramid->peername);
    paramid->peername = NULL;
    if (paramid->email) {
        OPENSSL_free(paramid->email);
        paramid->email = NULL;
        paramid->emaillen = 0;
    }
    if (paramid->ip) {
        OPENSSL_free(paramid->ip);
        paramid->ip = NULL;
        paramid->iplen = 0;
    }
}

X509_VERIFY_PARAM *X509_VERIFY_PARAM_new(void)
{
    X509_VERIFY_PARAM *param;
    X509_VERIFY_PARAM_ID *paramid;

    param = OPENSSL_malloc(sizeof(*param));
    if (!param)
        return NULL;
    memset(param, 0, sizeof(*param));

    paramid = OPENSSL_malloc(sizeof(*paramid));
    if (!paramid) {
        OPENSSL_free(param);
        return NULL;
    }
    memset(paramid, 0, sizeof(*paramid));
    /* Exotic platforms may have non-zero bit representation of NULL */
    paramid->hosts = NULL;
    paramid->peername = NULL;
    paramid->email = NULL;
    paramid->ip = NULL;

    param->id = paramid;
    x509_verify_param_zero(param);
    return param;
}

void X509_VERIFY_PARAM_free(X509_VERIFY_PARAM *param)
{
    if (param == NULL)
        return;
    x509_verify_param_zero(param);
    OPENSSL_free(param->id);
    OPENSSL_free(param);
}

/*-
 * This function determines how parameters are "inherited" from one structure
 * to another. There are several different ways this can happen.
 *
 * 1. If a child structure needs to have its values initialized from a parent
 *    they are simply copied across. For example SSL_CTX copied to SSL.
 * 2. If the structure should take on values only if they are currently unset.
 *    For example the values in an SSL structure will take appropriate value
 *    for SSL servers or clients but only if the application has not set new
 *    ones.
 *
 * The "inh_flags" field determines how this function behaves.
 *
 * Normally any values which are set in the default are not copied from the
 * destination and verify flags are ORed together.
 *
 * If X509_VP_FLAG_DEFAULT is set then anything set in the source is copied
 * to the destination. Effectively the values in "to" become default values
 * which will be used only if nothing new is set in "from".
 *
 * If X509_VP_FLAG_OVERWRITE is set then all value are copied across whether
 * they are set or not. Flags is still Ored though.
 *
 * If X509_VP_FLAG_RESET_FLAGS is set then the flags value is copied instead
 * of ORed.
 *
 * If X509_VP_FLAG_LOCKED is set then no values are copied.
 *
 * If X509_VP_FLAG_ONCE is set then the current inh_flags setting is zeroed
 * after the next call.
 */

/* Macro to test if a field should be copied from src to dest */

#define test_x509_verify_param_copy(field, def) \
        (to_overwrite || \
                ((src->field != def) && (to_default || (dest->field == def))))

/* As above but for ID fields */

#define test_x509_verify_param_copy_id(idf, def) \
        test_x509_verify_param_copy(id->idf, def)

/* Macro to test and copy a field if necessary */

#define x509_verify_param_copy(field, def) \
        if (test_x509_verify_param_copy(field, def)) \
                dest->field = src->field

int X509_VERIFY_PARAM_inherit(X509_VERIFY_PARAM *dest,
                              const X509_VERIFY_PARAM *src)
{
    unsigned long inh_flags;
    int to_default, to_overwrite;
    X509_VERIFY_PARAM_ID *id;
    if (!src)
        return 1;
    id = src->id;
    inh_flags = dest->inh_flags | src->inh_flags;

    if (inh_flags & X509_VP_FLAG_ONCE)
        dest->inh_flags = 0;

    if (inh_flags & X509_VP_FLAG_LOCKED)
        return 1;

    if (inh_flags & X509_VP_FLAG_DEFAULT)
        to_default = 1;
    else
        to_default = 0;

    if (inh_flags & X509_VP_FLAG_OVERWRITE)
        to_overwrite = 1;
    else
        to_overwrite = 0;

    x509_verify_param_copy(purpose, 0);
    x509_verify_param_copy(trust, 0);
    x509_verify_param_copy(depth, -1);

    /* If overwrite or check time not set, copy across */

    if (to_overwrite || !(dest->flags & X509_V_FLAG_USE_CHECK_TIME)) {
        dest->check_time = src->check_time;
        dest->flags &= ~X509_V_FLAG_USE_CHECK_TIME;
        /* Don't need to copy flag: that is done below */
    }

    if (inh_flags & X509_VP_FLAG_RESET_FLAGS)
        dest->flags = 0;

    dest->flags |= src->flags;

    if (test_x509_verify_param_copy(policies, NULL)) {
        if (!X509_VERIFY_PARAM_set1_policies(dest, src->policies))
            return 0;
    }

    /* Copy the host flags if and only if we're copying the host list */
    if (test_x509_verify_param_copy_id(hosts, NULL)) {
        if (dest->id->hosts) {
            string_stack_free(dest->id->hosts);
            dest->id->hosts = NULL;
        }
        if (id->hosts) {
            dest->id->hosts =
                sk_OPENSSL_STRING_deep_copy(id->hosts, str_copy, str_free);
            if (dest->id->hosts == NULL)
                return 0;
            dest->id->hostflags = id->hostflags;
        }
    }

    if (test_x509_verify_param_copy_id(email, NULL)) {
        if (!X509_VERIFY_PARAM_set1_email(dest, id->email, id->emaillen))
            return 0;
    }

    if (test_x509_verify_param_copy_id(ip, NULL)) {
        if (!X509_VERIFY_PARAM_set1_ip(dest, id->ip, id->iplen))
            return 0;
    }

    return 1;
}

int X509_VERIFY_PARAM_set1(X509_VERIFY_PARAM *to,
                           const X509_VERIFY_PARAM *from)
{
    unsigned long save_flags = to->inh_flags;
    int ret;
    to->inh_flags |= X509_VP_FLAG_DEFAULT;
    ret = X509_VERIFY_PARAM_inherit(to, from);
    to->inh_flags = save_flags;
    return ret;
}

static int int_x509_param_set1(char **pdest, size_t *pdestlen,
                               const char *src, size_t srclen)
{
    void *tmp;
    if (src) {
        if (srclen == 0) {
            tmp = BUF_strdup(src);
            srclen = strlen(src);
        } else
            tmp = BUF_memdup(src, srclen);
        if (!tmp)
            return 0;
    } else {
        tmp = NULL;
        srclen = 0;
    }
    if (*pdest)
        OPENSSL_free(*pdest);
    *pdest = tmp;
    if (pdestlen)
        *pdestlen = srclen;
    return 1;
}

int X509_VERIFY_PARAM_set1_name(X509_VERIFY_PARAM *param, const char *name)
{
    if (param->name)
        OPENSSL_free(param->name);
    param->name = BUF_strdup(name);
    if (param->name)
        return 1;
    return 0;
}

int X509_VERIFY_PARAM_set_flags(X509_VERIFY_PARAM *param, unsigned long flags)
{
    param->flags |= flags;
    if (flags & X509_V_FLAG_POLICY_MASK)
        param->flags |= X509_V_FLAG_POLICY_CHECK;
    return 1;
}

int X509_VERIFY_PARAM_clear_flags(X509_VERIFY_PARAM *param,
                                  unsigned long flags)
{
    param->flags &= ~flags;
    return 1;
}

unsigned long X509_VERIFY_PARAM_get_flags(X509_VERIFY_PARAM *param)
{
    return param->flags;
}

int X509_VERIFY_PARAM_set_purpose(X509_VERIFY_PARAM *param, int purpose)
{
    return X509_PURPOSE_set(&param->purpose, purpose);
}

int X509_VERIFY_PARAM_set_trust(X509_VERIFY_PARAM *param, int trust)
{
    return X509_TRUST_set(&param->trust, trust);
}

void X509_VERIFY_PARAM_set_depth(X509_VERIFY_PARAM *param, int depth)
{
    param->depth = depth;
}

void X509_VERIFY_PARAM_set_time(X509_VERIFY_PARAM *param, time_t t)
{
    param->check_time = t;
    param->flags |= X509_V_FLAG_USE_CHECK_TIME;
}

int X509_VERIFY_PARAM_add0_policy(X509_VERIFY_PARAM *param,
                                  ASN1_OBJECT *policy)
{
    if (!param->policies) {
        param->policies = sk_ASN1_OBJECT_new_null();
        if (!param->policies)
            return 0;
    }
    if (!sk_ASN1_OBJECT_push(param->policies, policy))
        return 0;
    return 1;
}

int X509_VERIFY_PARAM_set1_policies(X509_VERIFY_PARAM *param,
                                    STACK_OF(ASN1_OBJECT) *policies)
{
    int i;
    ASN1_OBJECT *oid, *doid;
    if (!param)
        return 0;
    if (param->policies)
        sk_ASN1_OBJECT_pop_free(param->policies, ASN1_OBJECT_free);

    if (!policies) {
        param->policies = NULL;
        return 1;
    }

    param->policies = sk_ASN1_OBJECT_new_null();
    if (!param->policies)
        return 0;

    for (i = 0; i < sk_ASN1_OBJECT_num(policies); i++) {
        oid = sk_ASN1_OBJECT_value(policies, i);
        doid = OBJ_dup(oid);
        if (!doid)
            return 0;
        if (!sk_ASN1_OBJECT_push(param->policies, doid)) {
            ASN1_OBJECT_free(doid);
            return 0;
        }
    }
    param->flags |= X509_V_FLAG_POLICY_CHECK;
    return 1;
}

int X509_VERIFY_PARAM_set1_host(X509_VERIFY_PARAM *param,
                                const char *name, size_t namelen)
{
    return int_x509_param_set_hosts(param->id, SET_HOST, name, namelen);
}

int X509_VERIFY_PARAM_add1_host(X509_VERIFY_PARAM *param,
                                const char *name, size_t namelen)
{
    return int_x509_param_set_hosts(param->id, ADD_HOST, name, namelen);
}

void X509_VERIFY_PARAM_set_hostflags(X509_VERIFY_PARAM *param,
                                     unsigned int flags)
{
    param->id->hostflags = flags;
}

char *X509_VERIFY_PARAM_get0_peername(X509_VERIFY_PARAM *param)
{
    return param->id->peername;
}

int X509_VERIFY_PARAM_set1_email(X509_VERIFY_PARAM *param,
                                 const char *email, size_t emaillen)
{
    return int_x509_param_set1(&param->id->email, &param->id->emaillen,
                               email, emaillen);
}

int X509_VERIFY_PARAM_set1_ip(X509_VERIFY_PARAM *param,
                              const unsigned char *ip, size_t iplen)
{
    if (iplen != 0 && iplen != 4 && iplen != 16)
        return 0;
    return int_x509_param_set1((char **)&param->id->ip, &param->id->iplen,
                               (char *)ip, iplen);
}

int X509_VERIFY_PARAM_set1_ip_asc(X509_VERIFY_PARAM *param, const char *ipasc)
{
    unsigned char ipout[16];
    size_t iplen;

    iplen = (size_t)a2i_ipadd(ipout, ipasc);
    if (iplen == 0)
        return 0;
    return X509_VERIFY_PARAM_set1_ip(param, ipout, iplen);
}

int X509_VERIFY_PARAM_get_depth(const X509_VERIFY_PARAM *param)
{
    return param->depth;
}

const char *X509_VERIFY_PARAM_get0_name(const X509_VERIFY_PARAM *param)
{
    return param->name;
}

static X509_VERIFY_PARAM_ID _empty_id = { NULL, 0U, NULL, NULL, 0, NULL, 0 };

#define vpm_empty_id (X509_VERIFY_PARAM_ID *)&_empty_id

/*
 * Default verify parameters: these are used for various applications and can
 * be overridden by the user specified table. NB: the 'name' field *must* be
 * in alphabetical order because it will be searched using OBJ_search.
 */

static const X509_VERIFY_PARAM default_table[] = {
    {
     "default",                 /* X509 default parameters */
     0,                         /* Check time */
     0,                         /* internal flags */
     0,                         /* flags */
     0,                         /* purpose */
     0,                         /* trust */
     100,                       /* depth */
     NULL,                      /* policies */
     vpm_empty_id},
    {
     "pkcs7",                   /* S/MIME sign parameters */
     0,                         /* Check time */
     0,                         /* internal flags */
     0,                         /* flags */
     X509_PURPOSE_SMIME_SIGN,   /* purpose */
     X509_TRUST_EMAIL,          /* trust */
     -1,                        /* depth */
     NULL,                      /* policies */
     vpm_empty_id},
    {
     "smime_sign",              /* S/MIME sign parameters */
     0,                         /* Check time */
     0,                         /* internal flags */
     0,                         /* flags */
     X509_PURPOSE_SMIME_SIGN,   /* purpose */
     X509_TRUST_EMAIL,          /* trust */
     -1,                        /* depth */
     NULL,                      /* policies */
     vpm_empty_id},
    {
     "ssl_client",              /* SSL/TLS client parameters */
     0,                         /* Check time */
     0,                         /* internal flags */
     0,                         /* flags */
     X509_PURPOSE_SSL_CLIENT,   /* purpose */
     X509_TRUST_SSL_CLIENT,     /* trust */
     -1,                        /* depth */
     NULL,                      /* policies */
     vpm_empty_id},
    {
     "ssl_server",              /* SSL/TLS server parameters */
     0,                         /* Check time */
     0,                         /* internal flags */
     0,                         /* flags */
     X509_PURPOSE_SSL_SERVER,   /* purpose */
     X509_TRUST_SSL_SERVER,     /* trust */
     -1,                        /* depth */
     NULL,                      /* policies */
     vpm_empty_id}
};

static STACK_OF(X509_VERIFY_PARAM) *param_table = NULL;

static int table_cmp(const X509_VERIFY_PARAM *a, const X509_VERIFY_PARAM *b)
{
    return strcmp(a->name, b->name);
}

DECLARE_OBJ_BSEARCH_CMP_FN(X509_VERIFY_PARAM, X509_VERIFY_PARAM, table);
IMPLEMENT_OBJ_BSEARCH_CMP_FN(X509_VERIFY_PARAM, X509_VERIFY_PARAM, table);

static int param_cmp(const X509_VERIFY_PARAM *const *a,
                     const X509_VERIFY_PARAM *const *b)
{
    return strcmp((*a)->name, (*b)->name);
}

int X509_VERIFY_PARAM_add0_table(X509_VERIFY_PARAM *param)
{
    int idx;
    X509_VERIFY_PARAM *ptmp;
    if (!param_table) {
        param_table = sk_X509_VERIFY_PARAM_new(param_cmp);
        if (!param_table)
            return 0;
    } else {
        idx = sk_X509_VERIFY_PARAM_find(param_table, param);
        if (idx != -1) {
            ptmp = sk_X509_VERIFY_PARAM_value(param_table, idx);
            X509_VERIFY_PARAM_free(ptmp);
            (void)sk_X509_VERIFY_PARAM_delete(param_table, idx);
        }
    }
    if (!sk_X509_VERIFY_PARAM_push(param_table, param))
        return 0;
    return 1;
}

int X509_VERIFY_PARAM_get_count(void)
{
    int num = sizeof(default_table) / sizeof(X509_VERIFY_PARAM);
    if (param_table)
        num += sk_X509_VERIFY_PARAM_num(param_table);
    return num;
}

const X509_VERIFY_PARAM *X509_VERIFY_PARAM_get0(int id)
{
    int num = sizeof(default_table) / sizeof(X509_VERIFY_PARAM);
    if (id < num)
        return default_table + id;
    return sk_X509_VERIFY_PARAM_value(param_table, id - num);
}

const X509_VERIFY_PARAM *X509_VERIFY_PARAM_lookup(const char *name)
{
    int idx;
    X509_VERIFY_PARAM pm;

    pm.name = (char *)name;
    if (param_table) {
        idx = sk_X509_VERIFY_PARAM_find(param_table, &pm);
        if (idx != -1)
            return sk_X509_VERIFY_PARAM_value(param_table, idx);
    }
    return OBJ_bsearch_table(&pm, default_table,
                             sizeof(default_table) /
                             sizeof(X509_VERIFY_PARAM));
}

void X509_VERIFY_PARAM_table_cleanup(void)
{
    if (param_table)
        sk_X509_VERIFY_PARAM_pop_free(param_table, X509_VERIFY_PARAM_free);
    param_table = NULL;
}
