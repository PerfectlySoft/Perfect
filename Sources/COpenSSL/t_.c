/* t_bitst.c */
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
#include "conf.h"
#include "x509v3.h"

int ASN1_BIT_STRING_name_print(BIO *out, ASN1_BIT_STRING *bs,
                               BIT_STRING_BITNAME *tbl, int indent)
{
    BIT_STRING_BITNAME *bnam;
    char first = 1;
    BIO_printf(out, "%*s", indent, "");
    for (bnam = tbl; bnam->lname; bnam++) {
        if (ASN1_BIT_STRING_get_bit(bs, bnam->bitnum)) {
            if (!first)
                BIO_puts(out, ", ");
            BIO_puts(out, bnam->lname);
            first = 0;
        }
    }
    BIO_puts(out, "\n");
    return 1;
}

int ASN1_BIT_STRING_set_asc(ASN1_BIT_STRING *bs, char *name, int value,
                            BIT_STRING_BITNAME *tbl)
{
    int bitnum;
    bitnum = ASN1_BIT_STRING_num_asc(name, tbl);
    if (bitnum < 0)
        return 0;
    if (bs) {
        if (!ASN1_BIT_STRING_set_bit(bs, bitnum, value))
            return 0;
    }
    return 1;
}

int ASN1_BIT_STRING_num_asc(char *name, BIT_STRING_BITNAME *tbl)
{
    BIT_STRING_BITNAME *bnam;
    for (bnam = tbl; bnam->lname; bnam++) {
        if (!strcmp(bnam->sname, name) || !strcmp(bnam->lname, name))
            return bnam->bitnum;
    }
    return -1;
}
/* t_crl.c */
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
#include "buffer.h"
#include "bn.h"
#include "objects.h"
#include "x509.h"
// #include "x509v3.h"

#ifndef OPENSSL_NO_FP_API
int X509_CRL_print_fp(FILE *fp, X509_CRL *x)
{
    BIO *b;
    int ret;

    if ((b = BIO_new(BIO_s_file())) == NULL) {
        X509err(X509_F_X509_CRL_PRINT_FP, ERR_R_BUF_LIB);
        return (0);
    }
    BIO_set_fp(b, fp, BIO_NOCLOSE);
    ret = X509_CRL_print(b, x);
    BIO_free(b);
    return (ret);
}
#endif

int X509_CRL_print(BIO *out, X509_CRL *x)
{
    STACK_OF(X509_REVOKED) *rev;
    X509_REVOKED *r;
    long l;
    int i;
    char *p;

    BIO_printf(out, "Certificate Revocation List (CRL):\n");
    l = X509_CRL_get_version(x);
    BIO_printf(out, "%8sVersion %lu (0x%lx)\n", "", l + 1, l);
    i = OBJ_obj2nid(x->sig_alg->algorithm);
    X509_signature_print(out, x->sig_alg, NULL);
    p = X509_NAME_oneline(X509_CRL_get_issuer(x), NULL, 0);
    BIO_printf(out, "%8sIssuer: %s\n", "", p);
    OPENSSL_free(p);
    BIO_printf(out, "%8sLast Update: ", "");
    ASN1_TIME_print(out, X509_CRL_get_lastUpdate(x));
    BIO_printf(out, "\n%8sNext Update: ", "");
    if (X509_CRL_get_nextUpdate(x))
        ASN1_TIME_print(out, X509_CRL_get_nextUpdate(x));
    else
        BIO_printf(out, "NONE");
    BIO_printf(out, "\n");

    X509V3_extensions_print(out, "CRL extensions", x->crl->extensions, 0, 8);

    rev = X509_CRL_get_REVOKED(x);

    if (sk_X509_REVOKED_num(rev) > 0)
        BIO_printf(out, "Revoked Certificates:\n");
    else
        BIO_printf(out, "No Revoked Certificates.\n");

    for (i = 0; i < sk_X509_REVOKED_num(rev); i++) {
        r = sk_X509_REVOKED_value(rev, i);
        BIO_printf(out, "    Serial Number: ");
        i2a_ASN1_INTEGER(out, r->serialNumber);
        BIO_printf(out, "\n        Revocation Date: ");
        ASN1_TIME_print(out, r->revocationDate);
        BIO_printf(out, "\n");
        X509V3_extensions_print(out, "CRL entry extensions",
                                r->extensions, 0, 8);
    }
    X509_signature_print(out, x->sig_alg, x->signature);

    return 1;

}
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
// #include "objects.h"
// #include "buffer.h"
// #include "bn.h"

int ASN1_bn_print(BIO *bp, const char *number, const BIGNUM *num,
                  unsigned char *buf, int off)
{
    int n, i;
    const char *neg;

    if (num == NULL)
        return (1);
    neg = (BN_is_negative(num)) ? "-" : "";
    if (!BIO_indent(bp, off, 128))
        return 0;
    if (BN_is_zero(num)) {
        if (BIO_printf(bp, "%s 0\n", number) <= 0)
            return 0;
        return 1;
    }

    if (BN_num_bytes(num) <= BN_BYTES) {
        if (BIO_printf(bp, "%s %s%lu (%s0x%lx)\n", number, neg,
                       (unsigned long)num->d[0], neg,
                       (unsigned long)num->d[0])
            <= 0)
            return (0);
    } else {
        buf[0] = 0;
        if (BIO_printf(bp, "%s%s", number,
                       (neg[0] == '-') ? " (Negative)" : "") <= 0)
            return (0);
        n = BN_bn2bin(num, &buf[1]);

        if (buf[1] & 0x80)
            n++;
        else
            buf++;

        for (i = 0; i < n; i++) {
            if ((i % 15) == 0) {
                if (BIO_puts(bp, "\n") <= 0 || !BIO_indent(bp, off + 4, 128))
                    return 0;
            }
            if (BIO_printf(bp, "%02x%s", buf[i], ((i + 1) == n) ? "" : ":")
                <= 0)
                return (0);
        }
        if (BIO_write(bp, "\n", 1) <= 0)
            return (0);
    }
    return (1);
}
/* crypto/asn1/t_req.c */
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
// #include "buffer.h"
// #include "bn.h"
// #include "objects.h"
// #include "x509.h"
// #include "x509v3.h"
#ifndef OPENSSL_NO_RSA
# include "rsa.h"
#endif
#ifndef OPENSSL_NO_DSA
# include "dsa.h"
#endif

#ifndef OPENSSL_NO_FP_API
int X509_REQ_print_fp(FILE *fp, X509_REQ *x)
{
    BIO *b;
    int ret;

    if ((b = BIO_new(BIO_s_file())) == NULL) {
        X509err(X509_F_X509_REQ_PRINT_FP, ERR_R_BUF_LIB);
        return (0);
    }
    BIO_set_fp(b, fp, BIO_NOCLOSE);
    ret = X509_REQ_print(b, x);
    BIO_free(b);
    return (ret);
}
#endif

int X509_REQ_print_ex(BIO *bp, X509_REQ *x, unsigned long nmflags,
                      unsigned long cflag)
{
    unsigned long l;
    int i;
    const char *neg;
    X509_REQ_INFO *ri;
    EVP_PKEY *pkey;
    STACK_OF(X509_ATTRIBUTE) *sk;
    STACK_OF(X509_EXTENSION) *exts;
    char mlch = ' ';
    int nmindent = 0;

    if ((nmflags & XN_FLAG_SEP_MASK) == XN_FLAG_SEP_MULTILINE) {
        mlch = '\n';
        nmindent = 12;
    }

    if (nmflags == X509_FLAG_COMPAT)
        nmindent = 16;

    ri = x->req_info;
    if (!(cflag & X509_FLAG_NO_HEADER)) {
        if (BIO_write(bp, "Certificate Request:\n", 21) <= 0)
            goto err;
        if (BIO_write(bp, "    Data:\n", 10) <= 0)
            goto err;
    }
    if (!(cflag & X509_FLAG_NO_VERSION)) {
        neg = (ri->version->type == V_ASN1_NEG_INTEGER) ? "-" : "";
        l = 0;
        for (i = 0; i < ri->version->length; i++) {
            l <<= 8;
            l += ri->version->data[i];
        }
        if (BIO_printf(bp, "%8sVersion: %s%lu (%s0x%lx)\n", "", neg, l, neg,
                       l) <= 0)
            goto err;
    }
    if (!(cflag & X509_FLAG_NO_SUBJECT)) {
        if (BIO_printf(bp, "        Subject:%c", mlch) <= 0)
            goto err;
        if (X509_NAME_print_ex(bp, ri->subject, nmindent, nmflags) < 0)
            goto err;
        if (BIO_write(bp, "\n", 1) <= 0)
            goto err;
    }
    if (!(cflag & X509_FLAG_NO_PUBKEY)) {
        if (BIO_write(bp, "        Subject Public Key Info:\n", 33) <= 0)
            goto err;
        if (BIO_printf(bp, "%12sPublic Key Algorithm: ", "") <= 0)
            goto err;
        if (i2a_ASN1_OBJECT(bp, ri->pubkey->algor->algorithm) <= 0)
            goto err;
        if (BIO_puts(bp, "\n") <= 0)
            goto err;

        pkey = X509_REQ_get_pubkey(x);
        if (pkey == NULL) {
            BIO_printf(bp, "%12sUnable to load Public Key\n", "");
            ERR_print_errors(bp);
        } else {
            EVP_PKEY_print_public(bp, pkey, 16, NULL);
            EVP_PKEY_free(pkey);
        }
    }

    if (!(cflag & X509_FLAG_NO_ATTRIBUTES)) {
        /* may not be */
        if (BIO_printf(bp, "%8sAttributes:\n", "") <= 0)
            goto err;

        sk = x->req_info->attributes;
        if (sk_X509_ATTRIBUTE_num(sk) == 0) {
            if (BIO_printf(bp, "%12sa0:00\n", "") <= 0)
                goto err;
        } else {
            for (i = 0; i < sk_X509_ATTRIBUTE_num(sk); i++) {
                ASN1_TYPE *at;
                X509_ATTRIBUTE *a;
                ASN1_BIT_STRING *bs = NULL;
                ASN1_TYPE *t;
                int j, type = 0, count = 1, ii = 0;

                a = sk_X509_ATTRIBUTE_value(sk, i);
                if (X509_REQ_extension_nid(OBJ_obj2nid(a->object)))
                    continue;
                if (BIO_printf(bp, "%12s", "") <= 0)
                    goto err;
                if ((j = i2a_ASN1_OBJECT(bp, a->object)) > 0) {
                    if (a->single) {
                        t = a->value.single;
                        type = t->type;
                        bs = t->value.bit_string;
                    } else {
                        ii = 0;
                        count = sk_ASN1_TYPE_num(a->value.set);
 get_next:
                        at = sk_ASN1_TYPE_value(a->value.set, ii);
                        type = at->type;
                        bs = at->value.asn1_string;
                    }
                }
                for (j = 25 - j; j > 0; j--)
                    if (BIO_write(bp, " ", 1) != 1)
                        goto err;
                if (BIO_puts(bp, ":") <= 0)
                    goto err;
                if ((type == V_ASN1_PRINTABLESTRING) ||
                    (type == V_ASN1_UTF8STRING) ||
                    (type == V_ASN1_T61STRING) ||
                    (type == V_ASN1_IA5STRING)) {
                    if (BIO_write(bp, (char *)bs->data, bs->length)
                        != bs->length)
                        goto err;
                    BIO_puts(bp, "\n");
                } else {
                    BIO_puts(bp, "unable to print attribute\n");
                }
                if (++ii < count)
                    goto get_next;
            }
        }
    }
    if (!(cflag & X509_FLAG_NO_EXTENSIONS)) {
        exts = X509_REQ_get_extensions(x);
        if (exts) {
            BIO_printf(bp, "%8sRequested Extensions:\n", "");
            for (i = 0; i < sk_X509_EXTENSION_num(exts); i++) {
                ASN1_OBJECT *obj;
                X509_EXTENSION *ex;
                int j;
                ex = sk_X509_EXTENSION_value(exts, i);
                if (BIO_printf(bp, "%12s", "") <= 0)
                    goto err;
                obj = X509_EXTENSION_get_object(ex);
                i2a_ASN1_OBJECT(bp, obj);
                j = X509_EXTENSION_get_critical(ex);
                if (BIO_printf(bp, ": %s\n", j ? "critical" : "") <= 0)
                    goto err;
                if (!X509V3_EXT_print(bp, ex, cflag, 16)) {
                    BIO_printf(bp, "%16s", "");
                    M_ASN1_OCTET_STRING_print(bp, ex->value);
                }
                if (BIO_write(bp, "\n", 1) <= 0)
                    goto err;
            }
            sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
        }
    }

    if (!(cflag & X509_FLAG_NO_SIGDUMP)) {
        if (!X509_signature_print(bp, x->sig_alg, x->signature))
            goto err;
    }

    return (1);
 err:
    X509err(X509_F_X509_REQ_PRINT_EX, ERR_R_BUF_LIB);
    return (0);
}

int X509_REQ_print(BIO *bp, X509_REQ *x)
{
    return X509_REQ_print_ex(bp, x, XN_FLAG_COMPAT, X509_FLAG_COMPAT);
}
/* t_spki.c */
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
// #include "x509.h"
#include "asn1.h"
#ifndef OPENSSL_NO_RSA
# include "rsa.h"
#endif
#ifndef OPENSSL_NO_DSA
# include "dsa.h"
#endif
// #include "bn.h"

/* Print out an SPKI */

int NETSCAPE_SPKI_print(BIO *out, NETSCAPE_SPKI *spki)
{
    EVP_PKEY *pkey;
    ASN1_IA5STRING *chal;
    int i, n;
    char *s;
    BIO_printf(out, "Netscape SPKI:\n");
    i = OBJ_obj2nid(spki->spkac->pubkey->algor->algorithm);
    BIO_printf(out, "  Public Key Algorithm: %s\n",
               (i == NID_undef) ? "UNKNOWN" : OBJ_nid2ln(i));
    pkey = X509_PUBKEY_get(spki->spkac->pubkey);
    if (!pkey)
        BIO_printf(out, "  Unable to load public key\n");
    else {
        EVP_PKEY_print_public(out, pkey, 4, NULL);
        EVP_PKEY_free(pkey);
    }
    chal = spki->spkac->challenge;
    if (chal->length)
        BIO_printf(out, "  Challenge String: %s\n", chal->data);
    i = OBJ_obj2nid(spki->sig_algor->algorithm);
    BIO_printf(out, "  Signature Algorithm: %s",
               (i == NID_undef) ? "UNKNOWN" : OBJ_nid2ln(i));

    n = spki->signature->length;
    s = (char *)spki->signature->data;
    for (i = 0; i < n; i++) {
        if ((i % 18) == 0)
            BIO_write(out, "\n      ", 7);
        BIO_printf(out, "%02x%s", (unsigned char)s[i],
                   ((i + 1) == n) ? "" : ":");
    }
    BIO_write(out, "\n", 1);
    return 1;
}
/* crypto/asn1/t_x509.c */
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
// #include "buffer.h"
// #include "bn.h"
#ifndef OPENSSL_NO_RSA
# include "rsa.h"
#endif
#ifndef OPENSSL_NO_DSA
# include "dsa.h"
#endif
#ifndef OPENSSL_NO_EC
# include "ec.h"
#endif
// #include "objects.h"
// #include "x509.h"
// #include "x509v3.h"
#include "asn1_locl.h"

#ifndef OPENSSL_NO_FP_API
int X509_print_fp(FILE *fp, X509 *x)
{
    return X509_print_ex_fp(fp, x, XN_FLAG_COMPAT, X509_FLAG_COMPAT);
}

int X509_print_ex_fp(FILE *fp, X509 *x, unsigned long nmflag,
                     unsigned long cflag)
{
    BIO *b;
    int ret;

    if ((b = BIO_new(BIO_s_file())) == NULL) {
        X509err(X509_F_X509_PRINT_EX_FP, ERR_R_BUF_LIB);
        return (0);
    }
    BIO_set_fp(b, fp, BIO_NOCLOSE);
    ret = X509_print_ex(b, x, nmflag, cflag);
    BIO_free(b);
    return (ret);
}
#endif

int X509_print(BIO *bp, X509 *x)
{
    return X509_print_ex(bp, x, XN_FLAG_COMPAT, X509_FLAG_COMPAT);
}

int X509_print_ex(BIO *bp, X509 *x, unsigned long nmflags,
                  unsigned long cflag)
{
    long l;
    int ret = 0, i;
    char *m = NULL, mlch = ' ';
    int nmindent = 0;
    X509_CINF *ci;
    ASN1_INTEGER *bs;
    EVP_PKEY *pkey = NULL;
    const char *neg;

    if ((nmflags & XN_FLAG_SEP_MASK) == XN_FLAG_SEP_MULTILINE) {
        mlch = '\n';
        nmindent = 12;
    }

    if (nmflags == X509_FLAG_COMPAT)
        nmindent = 16;

    ci = x->cert_info;
    if (!(cflag & X509_FLAG_NO_HEADER)) {
        if (BIO_write(bp, "Certificate:\n", 13) <= 0)
            goto err;
        if (BIO_write(bp, "    Data:\n", 10) <= 0)
            goto err;
    }
    if (!(cflag & X509_FLAG_NO_VERSION)) {
        l = X509_get_version(x);
        if (BIO_printf(bp, "%8sVersion: %lu (0x%lx)\n", "", l + 1, l) <= 0)
            goto err;
    }
    if (!(cflag & X509_FLAG_NO_SERIAL)) {

        if (BIO_write(bp, "        Serial Number:", 22) <= 0)
            goto err;

        bs = X509_get_serialNumber(x);
        if (bs->length < (int)sizeof(long)
            || (bs->length == sizeof(long) && (bs->data[0] & 0x80) == 0)) {
            l = ASN1_INTEGER_get(bs);
            if (bs->type == V_ASN1_NEG_INTEGER) {
                l = -l;
                neg = "-";
            } else
                neg = "";
            if (BIO_printf(bp, " %s%lu (%s0x%lx)\n", neg, l, neg, l) <= 0)
                goto err;
        } else {
            neg = (bs->type == V_ASN1_NEG_INTEGER) ? " (Negative)" : "";
            if (BIO_printf(bp, "\n%12s%s", "", neg) <= 0)
                goto err;

            for (i = 0; i < bs->length; i++) {
                if (BIO_printf(bp, "%02x%c", bs->data[i],
                               ((i + 1 == bs->length) ? '\n' : ':')) <= 0)
                    goto err;
            }
        }

    }

    if (!(cflag & X509_FLAG_NO_SIGNAME)) {
        if (X509_signature_print(bp, ci->signature, NULL) <= 0)
            goto err;
#if 0
        if (BIO_printf(bp, "%8sSignature Algorithm: ", "") <= 0)
            goto err;
        if (i2a_ASN1_OBJECT(bp, ci->signature->algorithm) <= 0)
            goto err;
        if (BIO_puts(bp, "\n") <= 0)
            goto err;
#endif
    }

    if (!(cflag & X509_FLAG_NO_ISSUER)) {
        if (BIO_printf(bp, "        Issuer:%c", mlch) <= 0)
            goto err;
        if (X509_NAME_print_ex(bp, X509_get_issuer_name(x), nmindent, nmflags)
            < 0)
            goto err;
        if (BIO_write(bp, "\n", 1) <= 0)
            goto err;
    }
    if (!(cflag & X509_FLAG_NO_VALIDITY)) {
        if (BIO_write(bp, "        Validity\n", 17) <= 0)
            goto err;
        if (BIO_write(bp, "            Not Before: ", 24) <= 0)
            goto err;
        if (!ASN1_TIME_print(bp, X509_get_notBefore(x)))
            goto err;
        if (BIO_write(bp, "\n            Not After : ", 25) <= 0)
            goto err;
        if (!ASN1_TIME_print(bp, X509_get_notAfter(x)))
            goto err;
        if (BIO_write(bp, "\n", 1) <= 0)
            goto err;
    }
    if (!(cflag & X509_FLAG_NO_SUBJECT)) {
        if (BIO_printf(bp, "        Subject:%c", mlch) <= 0)
            goto err;
        if (X509_NAME_print_ex
            (bp, X509_get_subject_name(x), nmindent, nmflags) < 0)
            goto err;
        if (BIO_write(bp, "\n", 1) <= 0)
            goto err;
    }
    if (!(cflag & X509_FLAG_NO_PUBKEY)) {
        if (BIO_write(bp, "        Subject Public Key Info:\n", 33) <= 0)
            goto err;
        if (BIO_printf(bp, "%12sPublic Key Algorithm: ", "") <= 0)
            goto err;
        if (i2a_ASN1_OBJECT(bp, ci->key->algor->algorithm) <= 0)
            goto err;
        if (BIO_puts(bp, "\n") <= 0)
            goto err;

        pkey = X509_get_pubkey(x);
        if (pkey == NULL) {
            BIO_printf(bp, "%12sUnable to load Public Key\n", "");
            ERR_print_errors(bp);
        } else {
            EVP_PKEY_print_public(bp, pkey, 16, NULL);
            EVP_PKEY_free(pkey);
        }
    }

    if (!(cflag & X509_FLAG_NO_IDS)) {
        if (ci->issuerUID) {
            if (BIO_printf(bp, "%8sIssuer Unique ID: ", "") <= 0)
                goto err;
            if (!X509_signature_dump(bp, ci->issuerUID, 12))
                goto err;
        }
        if (ci->subjectUID) {
            if (BIO_printf(bp, "%8sSubject Unique ID: ", "") <= 0)
                goto err;
            if (!X509_signature_dump(bp, ci->subjectUID, 12))
                goto err;
        }
    }

    if (!(cflag & X509_FLAG_NO_EXTENSIONS))
        X509V3_extensions_print(bp, "X509v3 extensions",
                                ci->extensions, cflag, 8);

    if (!(cflag & X509_FLAG_NO_SIGDUMP)) {
        if (X509_signature_print(bp, x->sig_alg, x->signature) <= 0)
            goto err;
    }
    if (!(cflag & X509_FLAG_NO_AUX)) {
        if (!X509_CERT_AUX_print(bp, x->aux, 0))
            goto err;
    }
    ret = 1;
 err:
    if (m != NULL)
        OPENSSL_free(m);
    return (ret);
}

int X509_ocspid_print(BIO *bp, X509 *x)
{
    unsigned char *der = NULL;
    unsigned char *dertmp;
    int derlen;
    int i;
    unsigned char SHA1md[SHA_DIGEST_LENGTH];

    /*
     * display the hash of the subject as it would appear in OCSP requests
     */
    if (BIO_printf(bp, "        Subject OCSP hash: ") <= 0)
        goto err;
    derlen = i2d_X509_NAME(x->cert_info->subject, NULL);
    if ((der = dertmp = (unsigned char *)OPENSSL_malloc(derlen)) == NULL)
        goto err;
    i2d_X509_NAME(x->cert_info->subject, &dertmp);

    if (!EVP_Digest(der, derlen, SHA1md, NULL, EVP_sha1(), NULL))
        goto err;
    for (i = 0; i < SHA_DIGEST_LENGTH; i++) {
        if (BIO_printf(bp, "%02X", SHA1md[i]) <= 0)
            goto err;
    }
    OPENSSL_free(der);
    der = NULL;

    /*
     * display the hash of the public key as it would appear in OCSP requests
     */
    if (BIO_printf(bp, "\n        Public key OCSP hash: ") <= 0)
        goto err;

    if (!EVP_Digest(x->cert_info->key->public_key->data,
                    x->cert_info->key->public_key->length,
                    SHA1md, NULL, EVP_sha1(), NULL))
        goto err;
    for (i = 0; i < SHA_DIGEST_LENGTH; i++) {
        if (BIO_printf(bp, "%02X", SHA1md[i]) <= 0)
            goto err;
    }
    BIO_printf(bp, "\n");

    return (1);
 err:
    if (der != NULL)
        OPENSSL_free(der);
    return (0);
}

int X509_signature_dump(BIO *bp, const ASN1_STRING *sig, int indent)
{
    const unsigned char *s;
    int i, n;

    n = sig->length;
    s = sig->data;
    for (i = 0; i < n; i++) {
        if ((i % 18) == 0) {
            if (BIO_write(bp, "\n", 1) <= 0)
                return 0;
            if (BIO_indent(bp, indent, indent) <= 0)
                return 0;
        }
        if (BIO_printf(bp, "%02x%s", s[i], ((i + 1) == n) ? "" : ":") <= 0)
            return 0;
    }
    if (BIO_write(bp, "\n", 1) != 1)
        return 0;

    return 1;
}

int X509_signature_print(BIO *bp, X509_ALGOR *sigalg, ASN1_STRING *sig)
{
    int sig_nid;
    if (BIO_puts(bp, "    Signature Algorithm: ") <= 0)
        return 0;
    if (i2a_ASN1_OBJECT(bp, sigalg->algorithm) <= 0)
        return 0;

    sig_nid = OBJ_obj2nid(sigalg->algorithm);
    if (sig_nid != NID_undef) {
        int pkey_nid, dig_nid;
        const EVP_PKEY_ASN1_METHOD *ameth;
        if (OBJ_find_sigid_algs(sig_nid, &dig_nid, &pkey_nid)) {
            ameth = EVP_PKEY_asn1_find(NULL, pkey_nid);
            if (ameth && ameth->sig_print)
                return ameth->sig_print(bp, sigalg, sig, 9, 0);
        }
    }
    if (sig)
        return X509_signature_dump(bp, sig, 9);
    else if (BIO_puts(bp, "\n") <= 0)
        return 0;
    return 1;
}

int ASN1_STRING_print(BIO *bp, const ASN1_STRING *v)
{
    int i, n;
    char buf[80];
    const char *p;

    if (v == NULL)
        return (0);
    n = 0;
    p = (const char *)v->data;
    for (i = 0; i < v->length; i++) {
        if ((p[i] > '~') || ((p[i] < ' ') &&
                             (p[i] != '\n') && (p[i] != '\r')))
            buf[n] = '.';
        else
            buf[n] = p[i];
        n++;
        if (n >= 80) {
            if (BIO_write(bp, buf, n) <= 0)
                return (0);
            n = 0;
        }
    }
    if (n > 0)
        if (BIO_write(bp, buf, n) <= 0)
            return (0);
    return (1);
}

int ASN1_TIME_print(BIO *bp, const ASN1_TIME *tm)
{
    if (tm->type == V_ASN1_UTCTIME)
        return ASN1_UTCTIME_print(bp, tm);
    if (tm->type == V_ASN1_GENERALIZEDTIME)
        return ASN1_GENERALIZEDTIME_print(bp, tm);
    BIO_write(bp, "Bad time value", 14);
    return (0);
}

static const char *mon[12] = {
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
};

int ASN1_GENERALIZEDTIME_print(BIO *bp, const ASN1_GENERALIZEDTIME *tm)
{
    char *v;
    int gmt = 0;
    int i;
    int y = 0, M = 0, d = 0, h = 0, m = 0, s = 0;
    char *f = NULL;
    int f_len = 0;

    i = tm->length;
    v = (char *)tm->data;

    if (i < 12)
        goto err;
    if (v[i - 1] == 'Z')
        gmt = 1;
    for (i = 0; i < 12; i++)
        if ((v[i] > '9') || (v[i] < '0'))
            goto err;
    y = (v[0] - '0') * 1000 + (v[1] - '0') * 100
        + (v[2] - '0') * 10 + (v[3] - '0');
    M = (v[4] - '0') * 10 + (v[5] - '0');
    if ((M > 12) || (M < 1))
        goto err;
    d = (v[6] - '0') * 10 + (v[7] - '0');
    h = (v[8] - '0') * 10 + (v[9] - '0');
    m = (v[10] - '0') * 10 + (v[11] - '0');
    if (tm->length >= 14 &&
        (v[12] >= '0') && (v[12] <= '9') &&
        (v[13] >= '0') && (v[13] <= '9')) {
        s = (v[12] - '0') * 10 + (v[13] - '0');
        /* Check for fractions of seconds. */
        if (tm->length >= 15 && v[14] == '.') {
            int l = tm->length;
            f = &v[14];         /* The decimal point. */
            f_len = 1;
            while (14 + f_len < l && f[f_len] >= '0' && f[f_len] <= '9')
                ++f_len;
        }
    }

    if (BIO_printf(bp, "%s %2d %02d:%02d:%02d%.*s %d%s",
                   mon[M - 1], d, h, m, s, f_len, f, y,
                   (gmt) ? " GMT" : "") <= 0)
        return (0);
    else
        return (1);
 err:
    BIO_write(bp, "Bad time value", 14);
    return (0);
}

int ASN1_UTCTIME_print(BIO *bp, const ASN1_UTCTIME *tm)
{
    const char *v;
    int gmt = 0;
    int i;
    int y = 0, M = 0, d = 0, h = 0, m = 0, s = 0;

    i = tm->length;
    v = (const char *)tm->data;

    if (i < 10)
        goto err;
    if (v[i - 1] == 'Z')
        gmt = 1;
    for (i = 0; i < 10; i++)
        if ((v[i] > '9') || (v[i] < '0'))
            goto err;
    y = (v[0] - '0') * 10 + (v[1] - '0');
    if (y < 50)
        y += 100;
    M = (v[2] - '0') * 10 + (v[3] - '0');
    if ((M > 12) || (M < 1))
        goto err;
    d = (v[4] - '0') * 10 + (v[5] - '0');
    h = (v[6] - '0') * 10 + (v[7] - '0');
    m = (v[8] - '0') * 10 + (v[9] - '0');
    if (tm->length >= 12 &&
        (v[10] >= '0') && (v[10] <= '9') && (v[11] >= '0') && (v[11] <= '9'))
        s = (v[10] - '0') * 10 + (v[11] - '0');

    if (BIO_printf(bp, "%s %2d %02d:%02d:%02d %d%s",
                   mon[M - 1], d, h, m, s, y + 1900,
                   (gmt) ? " GMT" : "") <= 0)
        return (0);
    else
        return (1);
 err:
    BIO_write(bp, "Bad time value", 14);
    return (0);
}

int X509_NAME_print(BIO *bp, X509_NAME *name, int obase)
{
    char *s, *c, *b;
    int ret = 0, l, i;

    l = 80 - 2 - obase;

    b = X509_NAME_oneline(name, NULL, 0);
    if (!b)
        return 0;
    if (!*b) {
        OPENSSL_free(b);
        return 1;
    }
    s = b + 1;                  /* skip the first slash */

    c = s;
    for (;;) {
#ifndef CHARSET_EBCDIC
        if (((*s == '/') &&
             ((s[1] >= 'A') && (s[1] <= 'Z') && ((s[2] == '=') ||
                                                 ((s[2] >= 'A')
                                                  && (s[2] <= 'Z')
                                                  && (s[3] == '='))
              ))) || (*s == '\0'))
#else
        if (((*s == '/') &&
             (isupper(s[1]) && ((s[2] == '=') ||
                                (isupper(s[2]) && (s[3] == '='))
              ))) || (*s == '\0'))
#endif
        {
            i = s - c;
            if (BIO_write(bp, c, i) != i)
                goto err;
            c = s + 1;          /* skip following slash */
            if (*s != '\0') {
                if (BIO_write(bp, ", ", 2) != 2)
                    goto err;
            }
            l--;
        }
        if (*s == '\0')
            break;
        s++;
        l--;
    }

    ret = 1;
    if (0) {
 err:
        X509err(X509_F_X509_NAME_PRINT, ERR_R_BUF_LIB);
    }
    OPENSSL_free(b);
    return (ret);
}
/* t_x509a.c */
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
#include "evp.h"
// #include "asn1.h"
// #include "x509.h"

/*
 * X509_CERT_AUX and string set routines
 */

int X509_CERT_AUX_print(BIO *out, X509_CERT_AUX *aux, int indent)
{
    char oidstr[80], first;
    int i;
    if (!aux)
        return 1;
    if (aux->trust) {
        first = 1;
        BIO_printf(out, "%*sTrusted Uses:\n%*s", indent, "", indent + 2, "");
        for (i = 0; i < sk_ASN1_OBJECT_num(aux->trust); i++) {
            if (!first)
                BIO_puts(out, ", ");
            else
                first = 0;
            OBJ_obj2txt(oidstr, sizeof(oidstr),
                        sk_ASN1_OBJECT_value(aux->trust, i), 0);
            BIO_puts(out, oidstr);
        }
        BIO_puts(out, "\n");
    } else
        BIO_printf(out, "%*sNo Trusted Uses.\n", indent, "");
    if (aux->reject) {
        first = 1;
        BIO_printf(out, "%*sRejected Uses:\n%*s", indent, "", indent + 2, "");
        for (i = 0; i < sk_ASN1_OBJECT_num(aux->reject); i++) {
            if (!first)
                BIO_puts(out, ", ");
            else
                first = 0;
            OBJ_obj2txt(oidstr, sizeof(oidstr),
                        sk_ASN1_OBJECT_value(aux->reject, i), 0);
            BIO_puts(out, oidstr);
        }
        BIO_puts(out, "\n");
    } else
        BIO_printf(out, "%*sNo Rejected Uses.\n", indent, "");
    if (aux->alias)
        BIO_printf(out, "%*sAlias: %s\n", indent, "", aux->alias->data);
    if (aux->keyid) {
        BIO_printf(out, "%*sKey Id: ", indent, "");
        for (i = 0; i < aux->keyid->length; i++)
            BIO_printf(out, "%s%02X", i ? ":" : "", aux->keyid->data[i]);
        BIO_write(out, "\n", 1);
    }
    return 1;
}
