/* crypto/asn1/a_bitstr.c */
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

#include <limits.h>
#include <stdio.h>
#include "cryptlib.h"
#include "asn1.h"

int ASN1_BIT_STRING_set(ASN1_BIT_STRING *x, unsigned char *d, int len)
{
    return M_ASN1_BIT_STRING_set(x, d, len);
}

int i2c_ASN1_BIT_STRING(ASN1_BIT_STRING *a, unsigned char **pp)
{
    int ret, j, bits, len;
    unsigned char *p, *d;

    if (a == NULL)
        return (0);

    len = a->length;

    if (len > 0) {
        if (a->flags & ASN1_STRING_FLAG_BITS_LEFT) {
            bits = (int)a->flags & 0x07;
        } else {
            for (; len > 0; len--) {
                if (a->data[len - 1])
                    break;
            }
            j = a->data[len - 1];
            if (j & 0x01)
                bits = 0;
            else if (j & 0x02)
                bits = 1;
            else if (j & 0x04)
                bits = 2;
            else if (j & 0x08)
                bits = 3;
            else if (j & 0x10)
                bits = 4;
            else if (j & 0x20)
                bits = 5;
            else if (j & 0x40)
                bits = 6;
            else if (j & 0x80)
                bits = 7;
            else
                bits = 0;       /* should not happen */
        }
    } else
        bits = 0;

    ret = 1 + len;
    if (pp == NULL)
        return (ret);

    p = *pp;

    *(p++) = (unsigned char)bits;
    d = a->data;
    if (len > 0) {
        memcpy(p, d, len);
        p += len;
        p[-1] &= (0xff << bits);
    }
    *pp = p;
    return (ret);
}

ASN1_BIT_STRING *c2i_ASN1_BIT_STRING(ASN1_BIT_STRING **a,
                                     const unsigned char **pp, long len)
{
    ASN1_BIT_STRING *ret = NULL;
    const unsigned char *p;
    unsigned char *s;
    int i;

    if (len < 1) {
        i = ASN1_R_STRING_TOO_SHORT;
        goto err;
    }

    if (len > INT_MAX) {
        i = ASN1_R_STRING_TOO_LONG;
        goto err;
    }

    if ((a == NULL) || ((*a) == NULL)) {
        if ((ret = M_ASN1_BIT_STRING_new()) == NULL)
            return (NULL);
    } else
        ret = (*a);

    p = *pp;
    i = *(p++);
    if (i > 7) {
        i = ASN1_R_INVALID_BIT_STRING_BITS_LEFT;
        goto err;
    }
    /*
     * We do this to preserve the settings.  If we modify the settings, via
     * the _set_bit function, we will recalculate on output
     */
    ret->flags &= ~(ASN1_STRING_FLAG_BITS_LEFT | 0x07); /* clear */
    ret->flags |= (ASN1_STRING_FLAG_BITS_LEFT | i); /* set */

    if (len-- > 1) {            /* using one because of the bits left byte */
        s = (unsigned char *)OPENSSL_malloc((int)len);
        if (s == NULL) {
            i = ERR_R_MALLOC_FAILURE;
            goto err;
        }
        memcpy(s, p, (int)len);
        s[len - 1] &= (0xff << i);
        p += len;
    } else
        s = NULL;

    ret->length = (int)len;
    if (ret->data != NULL)
        OPENSSL_free(ret->data);
    ret->data = s;
    ret->type = V_ASN1_BIT_STRING;
    if (a != NULL)
        (*a) = ret;
    *pp = p;
    return (ret);
 err:
    ASN1err(ASN1_F_C2I_ASN1_BIT_STRING, i);
    if ((ret != NULL) && ((a == NULL) || (*a != ret)))
        M_ASN1_BIT_STRING_free(ret);
    return (NULL);
}

/*
 * These next 2 functions from Goetz Babin-Ebell <babinebell@trustcenter.de>
 */
int ASN1_BIT_STRING_set_bit(ASN1_BIT_STRING *a, int n, int value)
{
    int w, v, iv;
    unsigned char *c;

    w = n / 8;
    v = 1 << (7 - (n & 0x07));
    iv = ~v;
    if (!value)
        v = 0;

    if (a == NULL)
        return 0;

    a->flags &= ~(ASN1_STRING_FLAG_BITS_LEFT | 0x07); /* clear, set on write */

    if ((a->length < (w + 1)) || (a->data == NULL)) {
        if (!value)
            return (1);         /* Don't need to set */
        if (a->data == NULL)
            c = (unsigned char *)OPENSSL_malloc(w + 1);
        else
            c = (unsigned char *)OPENSSL_realloc_clean(a->data,
                                                       a->length, w + 1);
        if (c == NULL) {
            ASN1err(ASN1_F_ASN1_BIT_STRING_SET_BIT, ERR_R_MALLOC_FAILURE);
            return 0;
        }
        if (w + 1 - a->length > 0)
            memset(c + a->length, 0, w + 1 - a->length);
        a->data = c;
        a->length = w + 1;
    }
    a->data[w] = ((a->data[w]) & iv) | v;
    while ((a->length > 0) && (a->data[a->length - 1] == 0))
        a->length--;
    return (1);
}

int ASN1_BIT_STRING_get_bit(ASN1_BIT_STRING *a, int n)
{
    int w, v;

    w = n / 8;
    v = 1 << (7 - (n & 0x07));
    if ((a == NULL) || (a->length < (w + 1)) || (a->data == NULL))
        return (0);
    return ((a->data[w] & v) != 0);
}

/*
 * Checks if the given bit string contains only bits specified by
 * the flags vector. Returns 0 if there is at least one bit set in 'a'
 * which is not specified in 'flags', 1 otherwise.
 * 'len' is the length of 'flags'.
 */
int ASN1_BIT_STRING_check(ASN1_BIT_STRING *a,
                          unsigned char *flags, int flags_len)
{
    int i, ok;
    /* Check if there is one bit set at all. */
    if (!a || !a->data)
        return 1;

    /*
     * Check each byte of the internal representation of the bit string.
     */
    ok = 1;
    for (i = 0; i < a->length && ok; ++i) {
        unsigned char mask = i < flags_len ? ~flags[i] : 0xff;
        /* We are done if there is an unneeded bit set. */
        ok = (a->data[i] & mask) == 0;
    }
    return ok;
}
/* crypto/asn1/a_bool.c */
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
#include "asn1t.h"

int i2d_ASN1_BOOLEAN(int a, unsigned char **pp)
{
    int r;
    unsigned char *p, *allocated = NULL;

    r = ASN1_object_size(0, 1, V_ASN1_BOOLEAN);
    if (pp == NULL)
        return (r);

    if (*pp == NULL) {
        if ((p = allocated = OPENSSL_malloc(r)) == NULL) {
            ASN1err(ASN1_F_I2D_ASN1_BOOLEAN, ERR_R_MALLOC_FAILURE);
            return 0;
        }
    } else {
        p = *pp;
    }

    ASN1_put_object(&p, 0, 1, V_ASN1_BOOLEAN, V_ASN1_UNIVERSAL);
    *p = (unsigned char)a;


    /*
     * If a new buffer was allocated, just return it back.
     * If not, return the incremented buffer pointer.
     */
    *pp = allocated != NULL ? allocated : p + 1;
    return r;
}

int d2i_ASN1_BOOLEAN(int *a, const unsigned char **pp, long length)
{
    int ret = -1;
    const unsigned char *p;
    long len;
    int inf, tag, xclass;
    int i = 0;

    p = *pp;
    inf = ASN1_get_object(&p, &len, &tag, &xclass, length);
    if (inf & 0x80) {
        i = ASN1_R_BAD_OBJECT_HEADER;
        goto err;
    }

    if (tag != V_ASN1_BOOLEAN) {
        i = ASN1_R_EXPECTING_A_BOOLEAN;
        goto err;
    }

    if (len != 1) {
        i = ASN1_R_BOOLEAN_IS_WRONG_LENGTH;
        goto err;
    }
    ret = (int)*(p++);
    if (a != NULL)
        (*a) = ret;
    *pp = p;
    return (ret);
 err:
    ASN1err(ASN1_F_D2I_ASN1_BOOLEAN, i);
    return (ret);
}
/* crypto/asn1/a_bytes.c */
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

static int asn1_collate_primitive(ASN1_STRING *a, ASN1_const_CTX *c,
                                  int depth);
static ASN1_STRING *int_d2i_ASN1_bytes(ASN1_STRING **a,
                                       const unsigned char **pp, long length,
                                       int Ptag, int Pclass, int depth,
                                       int *perr);
/*
 * type is a 'bitmap' of acceptable string types.
 */
ASN1_STRING *d2i_ASN1_type_bytes(ASN1_STRING **a, const unsigned char **pp,
                                 long length, int type)
{
    ASN1_STRING *ret = NULL;
    const unsigned char *p;
    unsigned char *s;
    long len;
    int inf, tag, xclass;
    int i = 0;

    p = *pp;
    inf = ASN1_get_object(&p, &len, &tag, &xclass, length);
    if (inf & 0x80)
        goto err;

    if (tag >= 32) {
        i = ASN1_R_TAG_VALUE_TOO_HIGH;
        goto err;
    }
    if (!(ASN1_tag2bit(tag) & type)) {
        i = ASN1_R_WRONG_TYPE;
        goto err;
    }

    /* If a bit-string, exit early */
    if (tag == V_ASN1_BIT_STRING)
        return (d2i_ASN1_BIT_STRING(a, pp, length));

    if ((a == NULL) || ((*a) == NULL)) {
        if ((ret = ASN1_STRING_new()) == NULL)
            return (NULL);
    } else
        ret = (*a);

    if (len != 0) {
        s = OPENSSL_malloc((int)len + 1);
        if (s == NULL) {
            i = ERR_R_MALLOC_FAILURE;
            goto err;
        }
        memcpy(s, p, (int)len);
        s[len] = '\0';
        p += len;
    } else
        s = NULL;

    if (ret->data != NULL)
        OPENSSL_free(ret->data);
    ret->length = (int)len;
    ret->data = s;
    ret->type = tag;
    if (a != NULL)
        (*a) = ret;
    *pp = p;
    return (ret);
 err:
    ASN1err(ASN1_F_D2I_ASN1_TYPE_BYTES, i);
    if ((ret != NULL) && ((a == NULL) || (*a != ret)))
        ASN1_STRING_free(ret);
    return (NULL);
}

int i2d_ASN1_bytes(ASN1_STRING *a, unsigned char **pp, int tag, int xclass)
{
    int ret, r, constructed;
    unsigned char *p;

    if (a == NULL)
        return (0);

    if (tag == V_ASN1_BIT_STRING)
        return (i2d_ASN1_BIT_STRING(a, pp));

    ret = a->length;
    r = ASN1_object_size(0, ret, tag);
    if (pp == NULL)
        return (r);
    p = *pp;

    if ((tag == V_ASN1_SEQUENCE) || (tag == V_ASN1_SET))
        constructed = 1;
    else
        constructed = 0;
    ASN1_put_object(&p, constructed, ret, tag, xclass);
    memcpy(p, a->data, a->length);
    p += a->length;
    *pp = p;
    return (r);
}

/*
 * Maximum recursion depth of d2i_ASN1_bytes(): much more than should be
 * encountered in pratice.
 */

#define ASN1_BYTES_MAXDEPTH 20

ASN1_STRING *d2i_ASN1_bytes(ASN1_STRING **a, const unsigned char **pp,
                            long length, int Ptag, int Pclass)
{
    int err = 0;
    ASN1_STRING *s = int_d2i_ASN1_bytes(a, pp, length, Ptag, Pclass, 0, &err);
    if (err != 0)
        ASN1err(ASN1_F_D2I_ASN1_BYTES, err);
    return s;
}

static ASN1_STRING *int_d2i_ASN1_bytes(ASN1_STRING **a,
                                       const unsigned char **pp, long length,
                                       int Ptag, int Pclass,
                                       int depth, int *perr)
{
    ASN1_STRING *ret = NULL;
    const unsigned char *p;
    unsigned char *s;
    long len;
    int inf, tag, xclass;

    if (depth > ASN1_BYTES_MAXDEPTH) {
        *perr = ASN1_R_NESTED_ASN1_STRING;
        return NULL;
    }

    if ((a == NULL) || ((*a) == NULL)) {
        if ((ret = ASN1_STRING_new()) == NULL)
            return (NULL);
    } else
        ret = (*a);

    p = *pp;
    inf = ASN1_get_object(&p, &len, &tag, &xclass, length);
    if (inf & 0x80) {
        *perr = ASN1_R_BAD_OBJECT_HEADER;
        goto err;
    }

    if (tag != Ptag) {
        *perr = ASN1_R_WRONG_TAG;
        goto err;
    }

    if (inf & V_ASN1_CONSTRUCTED) {
        ASN1_const_CTX c;

        c.error = 0;
        c.pp = pp;
        c.p = p;
        c.inf = inf;
        c.slen = len;
        c.tag = Ptag;
        c.xclass = Pclass;
        c.max = (length == 0) ? 0 : (p + length);
        if (!asn1_collate_primitive(ret, &c, depth)) {
            *perr = c.error;
            goto err;
        } else {
            p = c.p;
        }
    } else {
        if (len != 0) {
            if ((ret->length < len) || (ret->data == NULL)) {
                s = OPENSSL_malloc((int)len + 1);
                if (s == NULL) {
                    *perr = ERR_R_MALLOC_FAILURE;
                    goto err;
                }
                if (ret->data != NULL)
                    OPENSSL_free(ret->data);
            } else
                s = ret->data;
            memcpy(s, p, (int)len);
            s[len] = '\0';
            p += len;
        } else {
            s = NULL;
            if (ret->data != NULL)
                OPENSSL_free(ret->data);
        }

        ret->length = (int)len;
        ret->data = s;
        ret->type = Ptag;
    }

    if (a != NULL)
        (*a) = ret;
    *pp = p;
    return (ret);
 err:
    if ((ret != NULL) && ((a == NULL) || (*a != ret)))
        ASN1_STRING_free(ret);
    return (NULL);
}

/*
 * We are about to parse 0..n d2i_ASN1_bytes objects, we are to collapse them
 * into the one structure that is then returned
 */
/*
 * There have been a few bug fixes for this function from Paul Keogh
 * <paul.keogh@sse.ie>, many thanks to him
 */
static int asn1_collate_primitive(ASN1_STRING *a, ASN1_const_CTX *c,
                                  int depth)
{
    ASN1_STRING *os = NULL;
    BUF_MEM b;
    int num;

    b.length = 0;
    b.max = 0;
    b.data = NULL;

    if (a == NULL) {
        c->error = ERR_R_PASSED_NULL_PARAMETER;
        goto err;
    }

    num = 0;
    for (;;) {
        if (c->inf & 1) {
            c->eos = ASN1_const_check_infinite_end(&c->p,
                                                   (long)(c->max - c->p));
            if (c->eos)
                break;
        } else {
            if (c->slen <= 0)
                break;
        }

        c->q = c->p;
        if (int_d2i_ASN1_bytes(&os, &c->p, c->max - c->p, c->tag, c->xclass,
                               depth + 1, &c->error) == NULL) {
            goto err;
        }

        if (!BUF_MEM_grow_clean(&b, num + os->length)) {
            c->error = ERR_R_BUF_LIB;
            goto err;
        }
        memcpy(&(b.data[num]), os->data, os->length);
        if (!(c->inf & 1))
            c->slen -= (c->p - c->q);
        num += os->length;
    }

    if (!asn1_const_Finish(c))
        goto err;

    a->length = num;
    if (a->data != NULL)
        OPENSSL_free(a->data);
    a->data = (unsigned char *)b.data;
    if (os != NULL)
        ASN1_STRING_free(os);
    return (1);
 err:
    if (os != NULL)
        ASN1_STRING_free(os);
    if (b.data != NULL)
        OPENSSL_free(b.data);
    return (0);
}
/* crypto/asn1/a_d2i_fp.c */
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
#include <limits.h>
// #include "cryptlib.h"
#include "buffer.h"
#include "asn1_mac.h"

static int asn1_d2i_read_bio(BIO *in, BUF_MEM **pb);

#ifndef NO_OLD_ASN1
# ifndef OPENSSL_NO_FP_API

void *ASN1_d2i_fp(void *(*xnew) (void), d2i_of_void *d2i, FILE *in, void **x)
{
    BIO *b;
    void *ret;

    if ((b = BIO_new(BIO_s_file())) == NULL) {
        ASN1err(ASN1_F_ASN1_D2I_FP, ERR_R_BUF_LIB);
        return (NULL);
    }
    BIO_set_fp(b, in, BIO_NOCLOSE);
    ret = ASN1_d2i_bio(xnew, d2i, b, x);
    BIO_free(b);
    return (ret);
}
# endif

void *ASN1_d2i_bio(void *(*xnew) (void), d2i_of_void *d2i, BIO *in, void **x)
{
    BUF_MEM *b = NULL;
    const unsigned char *p;
    void *ret = NULL;
    int len;

    len = asn1_d2i_read_bio(in, &b);
    if (len < 0)
        goto err;

    p = (unsigned char *)b->data;
    ret = d2i(x, &p, len);
 err:
    if (b != NULL)
        BUF_MEM_free(b);
    return (ret);
}

#endif

void *ASN1_item_d2i_bio(const ASN1_ITEM *it, BIO *in, void *x)
{
    BUF_MEM *b = NULL;
    const unsigned char *p;
    void *ret = NULL;
    int len;

    len = asn1_d2i_read_bio(in, &b);
    if (len < 0)
        goto err;

    p = (const unsigned char *)b->data;
    ret = ASN1_item_d2i(x, &p, len, it);
 err:
    if (b != NULL)
        BUF_MEM_free(b);
    return (ret);
}

#ifndef OPENSSL_NO_FP_API
void *ASN1_item_d2i_fp(const ASN1_ITEM *it, FILE *in, void *x)
{
    BIO *b;
    char *ret;

    if ((b = BIO_new(BIO_s_file())) == NULL) {
        ASN1err(ASN1_F_ASN1_ITEM_D2I_FP, ERR_R_BUF_LIB);
        return (NULL);
    }
    BIO_set_fp(b, in, BIO_NOCLOSE);
    ret = ASN1_item_d2i_bio(it, b, x);
    BIO_free(b);
    return (ret);
}
#endif

#define HEADER_SIZE   8
#define ASN1_CHUNK_INITIAL_SIZE (16 * 1024)
static int asn1_d2i_read_bio(BIO *in, BUF_MEM **pb)
{
    BUF_MEM *b;
    unsigned char *p;
    int i;
    ASN1_const_CTX c;
    size_t want = HEADER_SIZE;
    int eos = 0;
    size_t off = 0;
    size_t len = 0;

    b = BUF_MEM_new();
    if (b == NULL) {
        ASN1err(ASN1_F_ASN1_D2I_READ_BIO, ERR_R_MALLOC_FAILURE);
        return -1;
    }

    ERR_clear_error();
    for (;;) {
        if (want >= (len - off)) {
            want -= (len - off);

            if (len + want < len || !BUF_MEM_grow_clean(b, len + want)) {
                ASN1err(ASN1_F_ASN1_D2I_READ_BIO, ERR_R_MALLOC_FAILURE);
                goto err;
            }
            i = BIO_read(in, &(b->data[len]), want);
            if ((i < 0) && ((len - off) == 0)) {
                ASN1err(ASN1_F_ASN1_D2I_READ_BIO, ASN1_R_NOT_ENOUGH_DATA);
                goto err;
            }
            if (i > 0) {
                if (len + i < len) {
                    ASN1err(ASN1_F_ASN1_D2I_READ_BIO, ASN1_R_TOO_LONG);
                    goto err;
                }
                len += i;
            }
        }
        /* else data already loaded */

        p = (unsigned char *)&(b->data[off]);
        c.p = p;
        c.inf = ASN1_get_object(&(c.p), &(c.slen), &(c.tag), &(c.xclass),
                                len - off);
        if (c.inf & 0x80) {
            unsigned long e;

            e = ERR_GET_REASON(ERR_peek_error());
            if (e != ASN1_R_TOO_LONG)
                goto err;
            else
                ERR_clear_error(); /* clear error */
        }
        i = c.p - p;            /* header length */
        off += i;               /* end of data */

        if (c.inf & 1) {
            /* no data body so go round again */
            eos++;
            if (eos < 0) {
                ASN1err(ASN1_F_ASN1_D2I_READ_BIO, ASN1_R_HEADER_TOO_LONG);
                goto err;
            }
            want = HEADER_SIZE;
        } else if (eos && (c.slen == 0) && (c.tag == V_ASN1_EOC)) {
            /* eos value, so go back and read another header */
            eos--;
            if (eos <= 0)
                break;
            else
                want = HEADER_SIZE;
        } else {
            /* suck in c.slen bytes of data */
            want = c.slen;
            if (want > (len - off)) {
                size_t chunk_max = ASN1_CHUNK_INITIAL_SIZE;

                want -= (len - off);
                if (want > INT_MAX /* BIO_read takes an int length */  ||
                    len + want < len) {
                    ASN1err(ASN1_F_ASN1_D2I_READ_BIO, ASN1_R_TOO_LONG);
                    goto err;
                }
                while (want > 0) {
                    /*
                     * Read content in chunks of increasing size
                     * so we can return an error for EOF without
                     * having to allocate the entire content length
                     * in one go.
                     */
                    size_t chunk = want > chunk_max ? chunk_max : want;

                    if (!BUF_MEM_grow_clean(b, len + chunk)) {
                        ASN1err(ASN1_F_ASN1_D2I_READ_BIO, ERR_R_MALLOC_FAILURE);
                        goto err;
                    }
                    want -= chunk;
                    while (chunk > 0) {
                        i = BIO_read(in, &(b->data[len]), chunk);
                        if (i <= 0) {
                            ASN1err(ASN1_F_ASN1_D2I_READ_BIO,
                                    ASN1_R_NOT_ENOUGH_DATA);
                            goto err;
                        }
                    /*
                     * This can't overflow because |len+want| didn't
                     * overflow.
                     */
                        len += i;
                        chunk -= i;
                    }
                    if (chunk_max < INT_MAX/2)
                        chunk_max *= 2;
                }
            }
            if (off + c.slen < off) {
                ASN1err(ASN1_F_ASN1_D2I_READ_BIO, ASN1_R_TOO_LONG);
                goto err;
            }
            off += c.slen;
            if (eos <= 0) {
                break;
            } else
                want = HEADER_SIZE;
        }
    }

    if (off > INT_MAX) {
        ASN1err(ASN1_F_ASN1_D2I_READ_BIO, ASN1_R_TOO_LONG);
        goto err;
    }

    *pb = b;
    return off;
 err:
    if (b != NULL)
        BUF_MEM_free(b);
    return -1;
}
/* crypto/asn1/a_digest.c */
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

// #include "cryptlib.h"

#ifndef NO_SYS_TYPES_H
# include <sys/types.h>
#endif

#include "err.h"
#include "evp.h"
// #include "buffer.h"
#include "x509.h"

#ifndef NO_ASN1_OLD

int ASN1_digest(i2d_of_void *i2d, const EVP_MD *type, char *data,
                unsigned char *md, unsigned int *len)
{
    int i;
    unsigned char *str, *p;

    i = i2d(data, NULL);
    if ((str = (unsigned char *)OPENSSL_malloc(i)) == NULL) {
        ASN1err(ASN1_F_ASN1_DIGEST, ERR_R_MALLOC_FAILURE);
        return (0);
    }
    p = str;
    i2d(data, &p);

    if (!EVP_Digest(str, i, md, len, type, NULL)) {
        OPENSSL_free(str);
        return 0;
    }
    OPENSSL_free(str);
    return (1);
}

#endif

int ASN1_item_digest(const ASN1_ITEM *it, const EVP_MD *type, void *asn,
                     unsigned char *md, unsigned int *len)
{
    int i;
    unsigned char *str = NULL;

    i = ASN1_item_i2d(asn, &str, it);
    if (!str)
        return (0);

    if (!EVP_Digest(str, i, md, len, type, NULL)) {
        OPENSSL_free(str);
        return 0;
    }
    OPENSSL_free(str);
    return (1);
}
/* crypto/asn1/a_dup.c */
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

#ifndef NO_OLD_ASN1

void *ASN1_dup(i2d_of_void *i2d, d2i_of_void *d2i, void *x)
{
    unsigned char *b, *p;
    const unsigned char *p2;
    int i;
    char *ret;

    if (x == NULL)
        return (NULL);

    i = i2d(x, NULL);
    b = OPENSSL_malloc(i + 10);
    if (b == NULL) {
        ASN1err(ASN1_F_ASN1_DUP, ERR_R_MALLOC_FAILURE);
        return (NULL);
    }
    p = b;
    i = i2d(x, &p);
    p2 = b;
    ret = d2i(NULL, &p2, i);
    OPENSSL_free(b);
    return (ret);
}

#endif

/*
 * ASN1_ITEM version of dup: this follows the model above except we don't
 * need to allocate the buffer. At some point this could be rewritten to
 * directly dup the underlying structure instead of doing and encode and
 * decode.
 */

void *ASN1_item_dup(const ASN1_ITEM *it, void *x)
{
    unsigned char *b = NULL;
    const unsigned char *p;
    long i;
    void *ret;

    if (x == NULL)
        return (NULL);

    i = ASN1_item_i2d(x, &b, it);
    if (b == NULL) {
        ASN1err(ASN1_F_ASN1_ITEM_DUP, ERR_R_MALLOC_FAILURE);
        return (NULL);
    }
    p = b;
    ret = ASN1_item_d2i(NULL, &p, i, it);
    OPENSSL_free(b);
    return (ret);
}
/* crypto/asn1/a_enum.c */
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
#include "bn.h"

/*
 * Code for ENUMERATED type: identical to INTEGER apart from a different tag.
 * for comments on encoding see a_int.c
 */

int ASN1_ENUMERATED_set(ASN1_ENUMERATED *a, long v)
{
    int j, k;
    unsigned int i;
    unsigned char buf[sizeof(long) + 1];
    long d;

    a->type = V_ASN1_ENUMERATED;
    if (a->length < (int)(sizeof(long) + 1)) {
        if (a->data != NULL)
            OPENSSL_free(a->data);
        if ((a->data =
             (unsigned char *)OPENSSL_malloc(sizeof(long) + 1)) != NULL)
            memset((char *)a->data, 0, sizeof(long) + 1);
    }
    if (a->data == NULL) {
        ASN1err(ASN1_F_ASN1_ENUMERATED_SET, ERR_R_MALLOC_FAILURE);
        return (0);
    }
    d = v;
    if (d < 0) {
        d = -d;
        a->type = V_ASN1_NEG_ENUMERATED;
    }

    for (i = 0; i < sizeof(long); i++) {
        if (d == 0)
            break;
        buf[i] = (int)d & 0xff;
        d >>= 8;
    }
    j = 0;
    for (k = i - 1; k >= 0; k--)
        a->data[j++] = buf[k];
    a->length = j;
    return (1);
}

long ASN1_ENUMERATED_get(ASN1_ENUMERATED *a)
{
    int neg = 0, i;
    long r = 0;

    if (a == NULL)
        return (0L);
    i = a->type;
    if (i == V_ASN1_NEG_ENUMERATED)
        neg = 1;
    else if (i != V_ASN1_ENUMERATED)
        return -1;

    if (a->length > (int)sizeof(long)) {
        /* hmm... a bit ugly */
        return (0xffffffffL);
    }
    if (a->data == NULL)
        return 0;

    for (i = 0; i < a->length; i++) {
        r <<= 8;
        r |= (unsigned char)a->data[i];
    }
    if (neg)
        r = -r;
    return (r);
}

ASN1_ENUMERATED *BN_to_ASN1_ENUMERATED(BIGNUM *bn, ASN1_ENUMERATED *ai)
{
    ASN1_ENUMERATED *ret;
    int len, j;

    if (ai == NULL)
        ret = M_ASN1_ENUMERATED_new();
    else
        ret = ai;
    if (ret == NULL) {
        ASN1err(ASN1_F_BN_TO_ASN1_ENUMERATED, ERR_R_NESTED_ASN1_ERROR);
        goto err;
    }
    if (BN_is_negative(bn))
        ret->type = V_ASN1_NEG_ENUMERATED;
    else
        ret->type = V_ASN1_ENUMERATED;
    j = BN_num_bits(bn);
    len = ((j == 0) ? 0 : ((j / 8) + 1));
    if (ret->length < len + 4) {
        unsigned char *new_data = OPENSSL_realloc(ret->data, len + 4);
        if (!new_data) {
            ASN1err(ASN1_F_BN_TO_ASN1_ENUMERATED, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        ret->data = new_data;
    }

    ret->length = BN_bn2bin(bn, ret->data);
    return (ret);
 err:
    if (ret != ai)
        M_ASN1_ENUMERATED_free(ret);
    return (NULL);
}

BIGNUM *ASN1_ENUMERATED_to_BN(ASN1_ENUMERATED *ai, BIGNUM *bn)
{
    BIGNUM *ret;

    if ((ret = BN_bin2bn(ai->data, ai->length, bn)) == NULL)
        ASN1err(ASN1_F_ASN1_ENUMERATED_TO_BN, ASN1_R_BN_LIB);
    else if (ai->type == V_ASN1_NEG_ENUMERATED)
        BN_set_negative(ret, 1);
    return (ret);
}
/* crypto/asn1/a_gentm.c */
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
 * GENERALIZEDTIME implementation, written by Steve Henson. Based on UTCTIME
 */

#include <stdio.h>
#include <time.h>
// #include "cryptlib.h"
#include "o_time.h"
// #include "asn1.h"
#include "asn1_locl.h"

#if 0

int i2d_ASN1_GENERALIZEDTIME(ASN1_GENERALIZEDTIME *a, unsigned char **pp)
{
# ifdef CHARSET_EBCDIC
    /* KLUDGE! We convert to ascii before writing DER */
    int len;
    char tmp[24];
    ASN1_STRING tmpstr = *(ASN1_STRING *)a;

    len = tmpstr.length;
    ebcdic2ascii(tmp, tmpstr.data, (len >= sizeof(tmp)) ? sizeof(tmp) : len);
    tmpstr.data = tmp;

    a = (ASN1_GENERALIZEDTIME *)&tmpstr;
# endif
    return (i2d_ASN1_bytes((ASN1_STRING *)a, pp,
                           V_ASN1_GENERALIZEDTIME, V_ASN1_UNIVERSAL));
}

ASN1_GENERALIZEDTIME *d2i_ASN1_GENERALIZEDTIME(ASN1_GENERALIZEDTIME **a,
                                               unsigned char **pp,
                                               long length)
{
    ASN1_GENERALIZEDTIME *ret = NULL;

    ret =
        (ASN1_GENERALIZEDTIME *)d2i_ASN1_bytes((ASN1_STRING **)a, pp, length,
                                               V_ASN1_GENERALIZEDTIME,
                                               V_ASN1_UNIVERSAL);
    if (ret == NULL) {
        ASN1err(ASN1_F_D2I_ASN1_GENERALIZEDTIME, ERR_R_NESTED_ASN1_ERROR);
        return (NULL);
    }
# ifdef CHARSET_EBCDIC
    ascii2ebcdic(ret->data, ret->data, ret->length);
# endif
    if (!ASN1_GENERALIZEDTIME_check(ret)) {
        ASN1err(ASN1_F_D2I_ASN1_GENERALIZEDTIME, ASN1_R_INVALID_TIME_FORMAT);
        goto err;
    }

    return (ret);
 err:
    if ((ret != NULL) && ((a == NULL) || (*a != ret)))
        M_ASN1_GENERALIZEDTIME_free(ret);
    return (NULL);
}

#endif

int asn1_generalizedtime_to_tm(struct tm *tm, const ASN1_GENERALIZEDTIME *d)
{
    static const int min[9] = { 0, 0, 1, 1, 0, 0, 0, 0, 0 };
    static const int max[9] = { 99, 99, 12, 31, 23, 59, 59, 12, 59 };
    char *a;
    int n, i, l, o;

    if (d->type != V_ASN1_GENERALIZEDTIME)
        return (0);
    l = d->length;
    a = (char *)d->data;
    o = 0;
    /*
     * GENERALIZEDTIME is similar to UTCTIME except the year is represented
     * as YYYY. This stuff treats everything as a two digit field so make
     * first two fields 00 to 99
     */
    if (l < 13)
        goto err;
    for (i = 0; i < 7; i++) {
        if ((i == 6) && ((a[o] == 'Z') || (a[o] == '+') || (a[o] == '-'))) {
            i++;
            if (tm)
                tm->tm_sec = 0;
            break;
        }
        if ((a[o] < '0') || (a[o] > '9'))
            goto err;
        n = a[o] - '0';
        if (++o > l)
            goto err;

        if ((a[o] < '0') || (a[o] > '9'))
            goto err;
        n = (n * 10) + a[o] - '0';
        if (++o > l)
            goto err;

        if ((n < min[i]) || (n > max[i]))
            goto err;
        if (tm) {
            switch (i) {
            case 0:
                tm->tm_year = n * 100 - 1900;
                break;
            case 1:
                tm->tm_year += n;
                break;
            case 2:
                tm->tm_mon = n - 1;
                break;
            case 3:
                tm->tm_mday = n;
                break;
            case 4:
                tm->tm_hour = n;
                break;
            case 5:
                tm->tm_min = n;
                break;
            case 6:
                tm->tm_sec = n;
                break;
            }
        }
    }
    /*
     * Optional fractional seconds: decimal point followed by one or more
     * digits.
     */
    if (a[o] == '.') {
        if (++o > l)
            goto err;
        i = o;
        while ((a[o] >= '0') && (a[o] <= '9') && (o <= l))
            o++;
        /* Must have at least one digit after decimal point */
        if (i == o)
            goto err;
    }

    if (a[o] == 'Z')
        o++;
    else if ((a[o] == '+') || (a[o] == '-')) {
        int offsign = a[o] == '-' ? 1 : -1, offset = 0;
        o++;
        if (o + 4 > l)
            goto err;
        for (i = 7; i < 9; i++) {
            if ((a[o] < '0') || (a[o] > '9'))
                goto err;
            n = a[o] - '0';
            o++;
            if ((a[o] < '0') || (a[o] > '9'))
                goto err;
            n = (n * 10) + a[o] - '0';
            if ((n < min[i]) || (n > max[i]))
                goto err;
            if (tm) {
                if (i == 7)
                    offset = n * 3600;
                else if (i == 8)
                    offset += n * 60;
            }
            o++;
        }
        if (offset && !OPENSSL_gmtime_adj(tm, 0, offset * offsign))
            return 0;
    } else if (a[o]) {
        /* Missing time zone information. */
        goto err;
    }
    return (o == l);
 err:
    return (0);
}

int ASN1_GENERALIZEDTIME_check(const ASN1_GENERALIZEDTIME *d)
{
    return asn1_generalizedtime_to_tm(NULL, d);
}

int ASN1_GENERALIZEDTIME_set_string(ASN1_GENERALIZEDTIME *s, const char *str)
{
    ASN1_GENERALIZEDTIME t;

    t.type = V_ASN1_GENERALIZEDTIME;
    t.length = strlen(str);
    t.data = (unsigned char *)str;
    if (ASN1_GENERALIZEDTIME_check(&t)) {
        if (s != NULL) {
            if (!ASN1_STRING_set((ASN1_STRING *)s,
                                 (unsigned char *)str, t.length))
                return 0;
            s->type = V_ASN1_GENERALIZEDTIME;
        }
        return (1);
    } else
        return (0);
}

ASN1_GENERALIZEDTIME *ASN1_GENERALIZEDTIME_set(ASN1_GENERALIZEDTIME *s,
                                               time_t t)
{
    return ASN1_GENERALIZEDTIME_adj(s, t, 0, 0);
}

ASN1_GENERALIZEDTIME *ASN1_GENERALIZEDTIME_adj(ASN1_GENERALIZEDTIME *s,
                                               time_t t, int offset_day,
                                               long offset_sec)
{
    char *p;
    struct tm *ts;
    struct tm data;
    size_t len = 20;

    if (s == NULL)
        s = M_ASN1_GENERALIZEDTIME_new();
    if (s == NULL)
        return (NULL);

    ts = OPENSSL_gmtime(&t, &data);
    if (ts == NULL)
        return (NULL);

    if (offset_day || offset_sec) {
        if (!OPENSSL_gmtime_adj(ts, offset_day, offset_sec))
            return NULL;
    }

    p = (char *)s->data;
    if ((p == NULL) || ((size_t)s->length < len)) {
        p = OPENSSL_malloc(len);
        if (p == NULL) {
            ASN1err(ASN1_F_ASN1_GENERALIZEDTIME_ADJ, ERR_R_MALLOC_FAILURE);
            return (NULL);
        }
        if (s->data != NULL)
            OPENSSL_free(s->data);
        s->data = (unsigned char *)p;
    }

    BIO_snprintf(p, len, "%04d%02d%02d%02d%02d%02dZ", ts->tm_year + 1900,
                 ts->tm_mon + 1, ts->tm_mday, ts->tm_hour, ts->tm_min,
                 ts->tm_sec);
    s->length = strlen(p);
    s->type = V_ASN1_GENERALIZEDTIME;
#ifdef CHARSET_EBCDIC_not
    ebcdic2ascii(s->data, s->data, s->length);
#endif
    return (s);
}
/* crypto/asn1/a_i2d_fp.c */
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
// #include "asn1.h"

#ifndef NO_OLD_ASN1

# ifndef OPENSSL_NO_FP_API
int ASN1_i2d_fp(i2d_of_void *i2d, FILE *out, void *x)
{
    BIO *b;
    int ret;

    if ((b = BIO_new(BIO_s_file())) == NULL) {
        ASN1err(ASN1_F_ASN1_I2D_FP, ERR_R_BUF_LIB);
        return (0);
    }
    BIO_set_fp(b, out, BIO_NOCLOSE);
    ret = ASN1_i2d_bio(i2d, b, x);
    BIO_free(b);
    return (ret);
}
# endif

int ASN1_i2d_bio(i2d_of_void *i2d, BIO *out, unsigned char *x)
{
    char *b;
    unsigned char *p;
    int i, j = 0, n, ret = 1;

    n = i2d(x, NULL);
    if (n <= 0)
        return 0;

    b = (char *)OPENSSL_malloc(n);
    if (b == NULL) {
        ASN1err(ASN1_F_ASN1_I2D_BIO, ERR_R_MALLOC_FAILURE);
        return (0);
    }

    p = (unsigned char *)b;
    i2d(x, &p);

    for (;;) {
        i = BIO_write(out, &(b[j]), n);
        if (i == n)
            break;
        if (i <= 0) {
            ret = 0;
            break;
        }
        j += i;
        n -= i;
    }
    OPENSSL_free(b);
    return (ret);
}

#endif

#ifndef OPENSSL_NO_FP_API
int ASN1_item_i2d_fp(const ASN1_ITEM *it, FILE *out, void *x)
{
    BIO *b;
    int ret;

    if ((b = BIO_new(BIO_s_file())) == NULL) {
        ASN1err(ASN1_F_ASN1_ITEM_I2D_FP, ERR_R_BUF_LIB);
        return (0);
    }
    BIO_set_fp(b, out, BIO_NOCLOSE);
    ret = ASN1_item_i2d_bio(it, b, x);
    BIO_free(b);
    return (ret);
}
#endif

int ASN1_item_i2d_bio(const ASN1_ITEM *it, BIO *out, void *x)
{
    unsigned char *b = NULL;
    int i, j = 0, n, ret = 1;

    n = ASN1_item_i2d(x, &b, it);
    if (b == NULL) {
        ASN1err(ASN1_F_ASN1_ITEM_I2D_BIO, ERR_R_MALLOC_FAILURE);
        return (0);
    }

    for (;;) {
        i = BIO_write(out, &(b[j]), n);
        if (i == n)
            break;
        if (i <= 0) {
            ret = 0;
            break;
        }
        j += i;
        n -= i;
    }
    OPENSSL_free(b);
    return (ret);
}
/* crypto/asn1/a_int.c */
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
// #include "bn.h"

ASN1_INTEGER *ASN1_INTEGER_dup(const ASN1_INTEGER *x)
{
    return M_ASN1_INTEGER_dup(x);
}

int ASN1_INTEGER_cmp(const ASN1_INTEGER *x, const ASN1_INTEGER *y)
{
    int neg, ret;
    /* Compare signs */
    neg = x->type & V_ASN1_NEG;
    if (neg != (y->type & V_ASN1_NEG)) {
        if (neg)
            return -1;
        else
            return 1;
    }

    ret = ASN1_STRING_cmp(x, y);

    if (neg)
        return -ret;
    else
        return ret;
}

/*-
 * This converts an ASN1 INTEGER into its content encoding.
 * The internal representation is an ASN1_STRING whose data is a big endian
 * representation of the value, ignoring the sign. The sign is determined by
 * the type: V_ASN1_INTEGER for positive and V_ASN1_NEG_INTEGER for negative.
 *
 * Positive integers are no problem: they are almost the same as the DER
 * encoding, except if the first byte is >= 0x80 we need to add a zero pad.
 *
 * Negative integers are a bit trickier...
 * The DER representation of negative integers is in 2s complement form.
 * The internal form is converted by complementing each octet and finally
 * adding one to the result. This can be done less messily with a little trick.
 * If the internal form has trailing zeroes then they will become FF by the
 * complement and 0 by the add one (due to carry) so just copy as many trailing
 * zeros to the destination as there are in the source. The carry will add one
 * to the last none zero octet: so complement this octet and add one and finally
 * complement any left over until you get to the start of the string.
 *
 * Padding is a little trickier too. If the first bytes is > 0x80 then we pad
 * with 0xff. However if the first byte is 0x80 and one of the following bytes
 * is non-zero we pad with 0xff. The reason for this distinction is that 0x80
 * followed by optional zeros isn't padded.
 */

int i2c_ASN1_INTEGER(ASN1_INTEGER *a, unsigned char **pp)
{
    int pad = 0, ret, i, neg;
    unsigned char *p, *n, pb = 0;

    if (a == NULL)
        return (0);
    neg = a->type & V_ASN1_NEG;
    if (a->length == 0)
        ret = 1;
    else {
        ret = a->length;
        i = a->data[0];
        if (ret == 1 && i == 0)
            neg = 0;
        if (!neg && (i > 127)) {
            pad = 1;
            pb = 0;
        } else if (neg) {
            if (i > 128) {
                pad = 1;
                pb = 0xFF;
            } else if (i == 128) {
                /*
                 * Special case: if any other bytes non zero we pad:
                 * otherwise we don't.
                 */
                for (i = 1; i < a->length; i++)
                    if (a->data[i]) {
                        pad = 1;
                        pb = 0xFF;
                        break;
                    }
            }
        }
        ret += pad;
    }
    if (pp == NULL)
        return (ret);
    p = *pp;

    if (pad)
        *(p++) = pb;
    if (a->length == 0)
        *(p++) = 0;
    else if (!neg)
        memcpy(p, a->data, (unsigned int)a->length);
    else {
        /* Begin at the end of the encoding */
        n = a->data + a->length - 1;
        p += a->length - 1;
        i = a->length;
        /* Copy zeros to destination as long as source is zero */
        while (!*n && i > 1) {
            *(p--) = 0;
            n--;
            i--;
        }
        /* Complement and increment next octet */
        *(p--) = ((*(n--)) ^ 0xff) + 1;
        i--;
        /* Complement any octets left */
        for (; i > 0; i--)
            *(p--) = *(n--) ^ 0xff;
    }

    *pp += ret;
    return (ret);
}

/* Convert just ASN1 INTEGER content octets to ASN1_INTEGER structure */

ASN1_INTEGER *c2i_ASN1_INTEGER(ASN1_INTEGER **a, const unsigned char **pp,
                               long len)
{
    ASN1_INTEGER *ret = NULL;
    const unsigned char *p, *pend;
    unsigned char *to, *s;
    int i;

    if ((a == NULL) || ((*a) == NULL)) {
        if ((ret = M_ASN1_INTEGER_new()) == NULL)
            return (NULL);
        ret->type = V_ASN1_INTEGER;
    } else
        ret = (*a);

    p = *pp;
    pend = p + len;

    /*
     * We must OPENSSL_malloc stuff, even for 0 bytes otherwise it signifies
     * a missing NULL parameter.
     */
    s = (unsigned char *)OPENSSL_malloc((int)len + 1);
    if (s == NULL) {
        i = ERR_R_MALLOC_FAILURE;
        goto err;
    }
    to = s;
    if (!len) {
        /*
         * Strictly speaking this is an illegal INTEGER but we tolerate it.
         */
        ret->type = V_ASN1_INTEGER;
    } else if (*p & 0x80) {     /* a negative number */
        ret->type = V_ASN1_NEG_INTEGER;
        if ((*p == 0xff) && (len != 1)) {
            p++;
            len--;
        }
        i = len;
        p += i - 1;
        to += i - 1;
        while ((!*p) && i) {
            *(to--) = 0;
            i--;
            p--;
        }
        /*
         * Special case: if all zeros then the number will be of the form FF
         * followed by n zero bytes: this corresponds to 1 followed by n zero
         * bytes. We've already written n zeros so we just append an extra
         * one and set the first byte to a 1. This is treated separately
         * because it is the only case where the number of bytes is larger
         * than len.
         */
        if (!i) {
            *s = 1;
            s[len] = 0;
            len++;
        } else {
            *(to--) = (*(p--) ^ 0xff) + 1;
            i--;
            for (; i > 0; i--)
                *(to--) = *(p--) ^ 0xff;
        }
    } else {
        ret->type = V_ASN1_INTEGER;
        if ((*p == 0) && (len != 1)) {
            p++;
            len--;
        }
        memcpy(s, p, (int)len);
    }

    if (ret->data != NULL)
        OPENSSL_free(ret->data);
    ret->data = s;
    ret->length = (int)len;
    if (a != NULL)
        (*a) = ret;
    *pp = pend;
    return (ret);
 err:
    ASN1err(ASN1_F_C2I_ASN1_INTEGER, i);
    if ((ret != NULL) && ((a == NULL) || (*a != ret)))
        M_ASN1_INTEGER_free(ret);
    return (NULL);
}

/*
 * This is a version of d2i_ASN1_INTEGER that ignores the sign bit of ASN1
 * integers: some broken software can encode a positive INTEGER with its MSB
 * set as negative (it doesn't add a padding zero).
 */

ASN1_INTEGER *d2i_ASN1_UINTEGER(ASN1_INTEGER **a, const unsigned char **pp,
                                long length)
{
    ASN1_INTEGER *ret = NULL;
    const unsigned char *p;
    unsigned char *s;
    long len;
    int inf, tag, xclass;
    int i;

    if ((a == NULL) || ((*a) == NULL)) {
        if ((ret = M_ASN1_INTEGER_new()) == NULL)
            return (NULL);
        ret->type = V_ASN1_INTEGER;
    } else
        ret = (*a);

    p = *pp;
    inf = ASN1_get_object(&p, &len, &tag, &xclass, length);
    if (inf & 0x80) {
        i = ASN1_R_BAD_OBJECT_HEADER;
        goto err;
    }

    if (tag != V_ASN1_INTEGER) {
        i = ASN1_R_EXPECTING_AN_INTEGER;
        goto err;
    }

    /*
     * We must OPENSSL_malloc stuff, even for 0 bytes otherwise it signifies
     * a missing NULL parameter.
     */
    s = (unsigned char *)OPENSSL_malloc((int)len + 1);
    if (s == NULL) {
        i = ERR_R_MALLOC_FAILURE;
        goto err;
    }
    ret->type = V_ASN1_INTEGER;
    if (len) {
        if ((*p == 0) && (len != 1)) {
            p++;
            len--;
        }
        memcpy(s, p, (int)len);
        p += len;
    }

    if (ret->data != NULL)
        OPENSSL_free(ret->data);
    ret->data = s;
    ret->length = (int)len;
    if (a != NULL)
        (*a) = ret;
    *pp = p;
    return (ret);
 err:
    ASN1err(ASN1_F_D2I_ASN1_UINTEGER, i);
    if ((ret != NULL) && ((a == NULL) || (*a != ret)))
        M_ASN1_INTEGER_free(ret);
    return (NULL);
}

int ASN1_INTEGER_set(ASN1_INTEGER *a, long v)
{
    int j, k;
    unsigned int i;
    unsigned char buf[sizeof(long) + 1];
    long d;

    a->type = V_ASN1_INTEGER;
    if (a->length < (int)(sizeof(long) + 1)) {
        if (a->data != NULL)
            OPENSSL_free(a->data);
        if ((a->data =
             (unsigned char *)OPENSSL_malloc(sizeof(long) + 1)) != NULL)
            memset((char *)a->data, 0, sizeof(long) + 1);
    }
    if (a->data == NULL) {
        ASN1err(ASN1_F_ASN1_INTEGER_SET, ERR_R_MALLOC_FAILURE);
        return (0);
    }
    d = v;
    if (d < 0) {
        d = -d;
        a->type = V_ASN1_NEG_INTEGER;
    }

    for (i = 0; i < sizeof(long); i++) {
        if (d == 0)
            break;
        buf[i] = (int)d & 0xff;
        d >>= 8;
    }
    j = 0;
    for (k = i - 1; k >= 0; k--)
        a->data[j++] = buf[k];
    a->length = j;
    return (1);
}

long ASN1_INTEGER_get(const ASN1_INTEGER *a)
{
    int neg = 0, i;
    long r = 0;

    if (a == NULL)
        return (0L);
    i = a->type;
    if (i == V_ASN1_NEG_INTEGER)
        neg = 1;
    else if (i != V_ASN1_INTEGER)
        return -1;

    if (a->length > (int)sizeof(long)) {
        /* hmm... a bit ugly, return all ones */
        return -1;
    }
    if (a->data == NULL)
        return 0;

    for (i = 0; i < a->length; i++) {
        r <<= 8;
        r |= (unsigned char)a->data[i];
    }
    if (neg)
        r = -r;
    return (r);
}

ASN1_INTEGER *BN_to_ASN1_INTEGER(const BIGNUM *bn, ASN1_INTEGER *ai)
{
    ASN1_INTEGER *ret;
    int len, j;

    if (ai == NULL)
        ret = M_ASN1_INTEGER_new();
    else
        ret = ai;
    if (ret == NULL) {
        ASN1err(ASN1_F_BN_TO_ASN1_INTEGER, ERR_R_NESTED_ASN1_ERROR);
        goto err;
    }
    if (BN_is_negative(bn) && !BN_is_zero(bn))
        ret->type = V_ASN1_NEG_INTEGER;
    else
        ret->type = V_ASN1_INTEGER;
    j = BN_num_bits(bn);
    len = ((j == 0) ? 0 : ((j / 8) + 1));
    if (ret->length < len + 4) {
        unsigned char *new_data = OPENSSL_realloc(ret->data, len + 4);
        if (!new_data) {
            ASN1err(ASN1_F_BN_TO_ASN1_INTEGER, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        ret->data = new_data;
    }
    ret->length = BN_bn2bin(bn, ret->data);
    /* Correct zero case */
    if (!ret->length) {
        ret->data[0] = 0;
        ret->length = 1;
    }
    return (ret);
 err:
    if (ret != ai)
        M_ASN1_INTEGER_free(ret);
    return (NULL);
}

BIGNUM *ASN1_INTEGER_to_BN(const ASN1_INTEGER *ai, BIGNUM *bn)
{
    BIGNUM *ret;

    if ((ret = BN_bin2bn(ai->data, ai->length, bn)) == NULL)
        ASN1err(ASN1_F_ASN1_INTEGER_TO_BN, ASN1_R_BN_LIB);
    else if (ai->type == V_ASN1_NEG_INTEGER)
        BN_set_negative(ret, 1);
    return (ret);
}

IMPLEMENT_STACK_OF(ASN1_INTEGER)

IMPLEMENT_ASN1_SET_OF(ASN1_INTEGER)
/* a_mbstr.c */
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
#include <ctype.h>
// #include "cryptlib.h"
// #include "asn1.h"

static int traverse_string(const unsigned char *p, int len, int inform,
                           int (*rfunc) (unsigned long value, void *in),
                           void *arg);
static int in_utf8(unsigned long value, void *arg);
static int out_utf8(unsigned long value, void *arg);
static int type_str(unsigned long value, void *arg);
static int cpy_asc(unsigned long value, void *arg);
static int cpy_bmp(unsigned long value, void *arg);
static int cpy_univ(unsigned long value, void *arg);
static int cpy_utf8(unsigned long value, void *arg);
static int is_printable(unsigned long value);

/*
 * These functions take a string in UTF8, ASCII or multibyte form and a mask
 * of permissible ASN1 string types. It then works out the minimal type
 * (using the order Printable < IA5 < T61 < BMP < Universal < UTF8) and
 * creates a string of the correct type with the supplied data. Yes this is
 * horrible: it has to be :-( The 'ncopy' form checks minimum and maximum
 * size limits too.
 */

int ASN1_mbstring_copy(ASN1_STRING **out, const unsigned char *in, int len,
                       int inform, unsigned long mask)
{
    return ASN1_mbstring_ncopy(out, in, len, inform, mask, 0, 0);
}

int ASN1_mbstring_ncopy(ASN1_STRING **out, const unsigned char *in, int len,
                        int inform, unsigned long mask,
                        long minsize, long maxsize)
{
    int str_type;
    int ret;
    char free_out;
    int outform, outlen = 0;
    ASN1_STRING *dest;
    unsigned char *p;
    int nchar;
    char strbuf[32];
    int (*cpyfunc) (unsigned long, void *) = NULL;
    if (len == -1)
        len = strlen((const char *)in);
    if (!mask)
        mask = DIRSTRING_TYPE;

    /* First do a string check and work out the number of characters */
    switch (inform) {

    case MBSTRING_BMP:
        if (len & 1) {
            ASN1err(ASN1_F_ASN1_MBSTRING_NCOPY,
                    ASN1_R_INVALID_BMPSTRING_LENGTH);
            return -1;
        }
        nchar = len >> 1;
        break;

    case MBSTRING_UNIV:
        if (len & 3) {
            ASN1err(ASN1_F_ASN1_MBSTRING_NCOPY,
                    ASN1_R_INVALID_UNIVERSALSTRING_LENGTH);
            return -1;
        }
        nchar = len >> 2;
        break;

    case MBSTRING_UTF8:
        nchar = 0;
        /* This counts the characters and does utf8 syntax checking */
        ret = traverse_string(in, len, MBSTRING_UTF8, in_utf8, &nchar);
        if (ret < 0) {
            ASN1err(ASN1_F_ASN1_MBSTRING_NCOPY, ASN1_R_INVALID_UTF8STRING);
            return -1;
        }
        break;

    case MBSTRING_ASC:
        nchar = len;
        break;

    default:
        ASN1err(ASN1_F_ASN1_MBSTRING_NCOPY, ASN1_R_UNKNOWN_FORMAT);
        return -1;
    }

    if ((minsize > 0) && (nchar < minsize)) {
        ASN1err(ASN1_F_ASN1_MBSTRING_NCOPY, ASN1_R_STRING_TOO_SHORT);
        BIO_snprintf(strbuf, sizeof(strbuf), "%ld", minsize);
        ERR_add_error_data(2, "minsize=", strbuf);
        return -1;
    }

    if ((maxsize > 0) && (nchar > maxsize)) {
        ASN1err(ASN1_F_ASN1_MBSTRING_NCOPY, ASN1_R_STRING_TOO_LONG);
        BIO_snprintf(strbuf, sizeof(strbuf), "%ld", maxsize);
        ERR_add_error_data(2, "maxsize=", strbuf);
        return -1;
    }

    /* Now work out minimal type (if any) */
    if (traverse_string(in, len, inform, type_str, &mask) < 0) {
        ASN1err(ASN1_F_ASN1_MBSTRING_NCOPY, ASN1_R_ILLEGAL_CHARACTERS);
        return -1;
    }

    /* Now work out output format and string type */
    outform = MBSTRING_ASC;
    if (mask & B_ASN1_PRINTABLESTRING)
        str_type = V_ASN1_PRINTABLESTRING;
    else if (mask & B_ASN1_IA5STRING)
        str_type = V_ASN1_IA5STRING;
    else if (mask & B_ASN1_T61STRING)
        str_type = V_ASN1_T61STRING;
    else if (mask & B_ASN1_BMPSTRING) {
        str_type = V_ASN1_BMPSTRING;
        outform = MBSTRING_BMP;
    } else if (mask & B_ASN1_UNIVERSALSTRING) {
        str_type = V_ASN1_UNIVERSALSTRING;
        outform = MBSTRING_UNIV;
    } else {
        str_type = V_ASN1_UTF8STRING;
        outform = MBSTRING_UTF8;
    }
    if (!out)
        return str_type;
    if (*out) {
        free_out = 0;
        dest = *out;
        if (dest->data) {
            dest->length = 0;
            OPENSSL_free(dest->data);
            dest->data = NULL;
        }
        dest->type = str_type;
    } else {
        free_out = 1;
        dest = ASN1_STRING_type_new(str_type);
        if (!dest) {
            ASN1err(ASN1_F_ASN1_MBSTRING_NCOPY, ERR_R_MALLOC_FAILURE);
            return -1;
        }
        *out = dest;
    }
    /* If both the same type just copy across */
    if (inform == outform) {
        if (!ASN1_STRING_set(dest, in, len)) {
            ASN1err(ASN1_F_ASN1_MBSTRING_NCOPY, ERR_R_MALLOC_FAILURE);
            return -1;
        }
        return str_type;
    }

    /* Work out how much space the destination will need */
    switch (outform) {
    case MBSTRING_ASC:
        outlen = nchar;
        cpyfunc = cpy_asc;
        break;

    case MBSTRING_BMP:
        outlen = nchar << 1;
        cpyfunc = cpy_bmp;
        break;

    case MBSTRING_UNIV:
        outlen = nchar << 2;
        cpyfunc = cpy_univ;
        break;

    case MBSTRING_UTF8:
        outlen = 0;
        traverse_string(in, len, inform, out_utf8, &outlen);
        cpyfunc = cpy_utf8;
        break;
    }
    if (!(p = OPENSSL_malloc(outlen + 1))) {
        if (free_out)
            ASN1_STRING_free(dest);
        ASN1err(ASN1_F_ASN1_MBSTRING_NCOPY, ERR_R_MALLOC_FAILURE);
        return -1;
    }
    dest->length = outlen;
    dest->data = p;
    p[outlen] = 0;
    traverse_string(in, len, inform, cpyfunc, &p);
    return str_type;
}

/*
 * This function traverses a string and passes the value of each character to
 * an optional function along with a void * argument.
 */

static int traverse_string(const unsigned char *p, int len, int inform,
                           int (*rfunc) (unsigned long value, void *in),
                           void *arg)
{
    unsigned long value;
    int ret;
    while (len) {
        if (inform == MBSTRING_ASC) {
            value = *p++;
            len--;
        } else if (inform == MBSTRING_BMP) {
            value = *p++ << 8;
            value |= *p++;
            len -= 2;
        } else if (inform == MBSTRING_UNIV) {
            value = ((unsigned long)*p++) << 24;
            value |= ((unsigned long)*p++) << 16;
            value |= *p++ << 8;
            value |= *p++;
            len -= 4;
        } else {
            ret = UTF8_getc(p, len, &value);
            if (ret < 0)
                return -1;
            len -= ret;
            p += ret;
        }
        if (rfunc) {
            ret = rfunc(value, arg);
            if (ret <= 0)
                return ret;
        }
    }
    return 1;
}

/* Various utility functions for traverse_string */

/* Just count number of characters */

static int in_utf8(unsigned long value, void *arg)
{
    int *nchar;
    nchar = arg;
    (*nchar)++;
    return 1;
}

/* Determine size of output as a UTF8 String */

static int out_utf8(unsigned long value, void *arg)
{
    int *outlen;
    outlen = arg;
    *outlen += UTF8_putc(NULL, -1, value);
    return 1;
}

/*
 * Determine the "type" of a string: check each character against a supplied
 * "mask".
 */

static int type_str(unsigned long value, void *arg)
{
    unsigned long types;
    types = *((unsigned long *)arg);
    if ((types & B_ASN1_PRINTABLESTRING) && !is_printable(value))
        types &= ~B_ASN1_PRINTABLESTRING;
    if ((types & B_ASN1_IA5STRING) && (value > 127))
        types &= ~B_ASN1_IA5STRING;
    if ((types & B_ASN1_T61STRING) && (value > 0xff))
        types &= ~B_ASN1_T61STRING;
    if ((types & B_ASN1_BMPSTRING) && (value > 0xffff))
        types &= ~B_ASN1_BMPSTRING;
    if (!types)
        return -1;
    *((unsigned long *)arg) = types;
    return 1;
}

/* Copy one byte per character ASCII like strings */

static int cpy_asc(unsigned long value, void *arg)
{
    unsigned char **p, *q;
    p = arg;
    q = *p;
    *q = (unsigned char)value;
    (*p)++;
    return 1;
}

/* Copy two byte per character BMPStrings */

static int cpy_bmp(unsigned long value, void *arg)
{
    unsigned char **p, *q;
    p = arg;
    q = *p;
    *q++ = (unsigned char)((value >> 8) & 0xff);
    *q = (unsigned char)(value & 0xff);
    *p += 2;
    return 1;
}

/* Copy four byte per character UniversalStrings */

static int cpy_univ(unsigned long value, void *arg)
{
    unsigned char **p, *q;
    p = arg;
    q = *p;
    *q++ = (unsigned char)((value >> 24) & 0xff);
    *q++ = (unsigned char)((value >> 16) & 0xff);
    *q++ = (unsigned char)((value >> 8) & 0xff);
    *q = (unsigned char)(value & 0xff);
    *p += 4;
    return 1;
}

/* Copy to a UTF8String */

static int cpy_utf8(unsigned long value, void *arg)
{
    unsigned char **p;
    int ret;
    p = arg;
    /* We already know there is enough room so pass 0xff as the length */
    ret = UTF8_putc(*p, 0xff, value);
    *p += ret;
    return 1;
}

/* Return 1 if the character is permitted in a PrintableString */
static int is_printable(unsigned long value)
{
    int ch;
    if (value > 0x7f)
        return 0;
    ch = (int)value;
    /*
     * Note: we can't use 'isalnum' because certain accented characters may
     * count as alphanumeric in some environments.
     */
#ifndef CHARSET_EBCDIC
    if ((ch >= 'a') && (ch <= 'z'))
        return 1;
    if ((ch >= 'A') && (ch <= 'Z'))
        return 1;
    if ((ch >= '0') && (ch <= '9'))
        return 1;
    if ((ch == ' ') || strchr("'()+,-./:=?", ch))
        return 1;
#else                           /* CHARSET_EBCDIC */
    if ((ch >= os_toascii['a']) && (ch <= os_toascii['z']))
        return 1;
    if ((ch >= os_toascii['A']) && (ch <= os_toascii['Z']))
        return 1;
    if ((ch >= os_toascii['0']) && (ch <= os_toascii['9']))
        return 1;
    if ((ch == os_toascii[' ']) || strchr("'()+,-./:=?", os_toebcdic[ch]))
        return 1;
#endif                          /* CHARSET_EBCDIC */
    return 0;
}
/* crypto/asn1/a_object.c */
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
#include <limits.h>
// #include "cryptlib.h"
// #include "buffer.h"
// #include "asn1.h"
#include "objects.h"
// #include "bn.h"

int i2d_ASN1_OBJECT(ASN1_OBJECT *a, unsigned char **pp)
{
    unsigned char *p, *allocated = NULL;
    int objsize;

    if ((a == NULL) || (a->data == NULL))
        return (0);

    objsize = ASN1_object_size(0, a->length, V_ASN1_OBJECT);
    if (pp == NULL || objsize == -1)
        return objsize;

    if (*pp == NULL) {
        if ((p = allocated = OPENSSL_malloc(objsize)) == NULL) {
            ASN1err(ASN1_F_I2D_ASN1_OBJECT, ERR_R_MALLOC_FAILURE);
            return 0;
        }
    } else {
        p = *pp;
    }

    ASN1_put_object(&p, 0, a->length, V_ASN1_OBJECT, V_ASN1_UNIVERSAL);
    memcpy(p, a->data, a->length);

    /*
     * If a new buffer was allocated, just return it back.
     * If not, return the incremented buffer pointer.
     */
    *pp = allocated != NULL ? allocated : p + a->length;
    return objsize;
}

int a2d_ASN1_OBJECT(unsigned char *out, int olen, const char *buf, int num)
{
    int i, first, len = 0, c, use_bn;
    char ftmp[24], *tmp = ftmp;
    int tmpsize = sizeof(ftmp);
    const char *p;
    unsigned long l;
    BIGNUM *bl = NULL;

    if (num == 0)
        return (0);
    else if (num == -1)
        num = strlen(buf);

    p = buf;
    c = *(p++);
    num--;
    if ((c >= '0') && (c <= '2')) {
        first = c - '0';
    } else {
        ASN1err(ASN1_F_A2D_ASN1_OBJECT, ASN1_R_FIRST_NUM_TOO_LARGE);
        goto err;
    }

    if (num <= 0) {
        ASN1err(ASN1_F_A2D_ASN1_OBJECT, ASN1_R_MISSING_SECOND_NUMBER);
        goto err;
    }
    c = *(p++);
    num--;
    for (;;) {
        if (num <= 0)
            break;
        if ((c != '.') && (c != ' ')) {
            ASN1err(ASN1_F_A2D_ASN1_OBJECT, ASN1_R_INVALID_SEPARATOR);
            goto err;
        }
        l = 0;
        use_bn = 0;
        for (;;) {
            if (num <= 0)
                break;
            num--;
            c = *(p++);
            if ((c == ' ') || (c == '.'))
                break;
            if ((c < '0') || (c > '9')) {
                ASN1err(ASN1_F_A2D_ASN1_OBJECT, ASN1_R_INVALID_DIGIT);
                goto err;
            }
            if (!use_bn && l >= ((ULONG_MAX - 80) / 10L)) {
                use_bn = 1;
                if (!bl)
                    bl = BN_new();
                if (!bl || !BN_set_word(bl, l))
                    goto err;
            }
            if (use_bn) {
                if (!BN_mul_word(bl, 10L)
                    || !BN_add_word(bl, c - '0'))
                    goto err;
            } else
                l = l * 10L + (long)(c - '0');
        }
        if (len == 0) {
            if ((first < 2) && (l >= 40)) {
                ASN1err(ASN1_F_A2D_ASN1_OBJECT,
                        ASN1_R_SECOND_NUMBER_TOO_LARGE);
                goto err;
            }
            if (use_bn) {
                if (!BN_add_word(bl, first * 40))
                    goto err;
            } else
                l += (long)first *40;
        }
        i = 0;
        if (use_bn) {
            int blsize;
            blsize = BN_num_bits(bl);
            blsize = (blsize + 6) / 7;
            if (blsize > tmpsize) {
                if (tmp != ftmp)
                    OPENSSL_free(tmp);
                tmpsize = blsize + 32;
                tmp = OPENSSL_malloc(tmpsize);
                if (!tmp)
                    goto err;
            }
            while (blsize--) {
                BN_ULONG t = BN_div_word(bl, 0x80L);
                if (t == (BN_ULONG)-1)
                    goto err;
                tmp[i++] = (unsigned char)t;
            }
        } else {

            for (;;) {
                tmp[i++] = (unsigned char)l & 0x7f;
                l >>= 7L;
                if (l == 0L)
                    break;
            }

        }
        if (out != NULL) {
            if (len + i > olen) {
                ASN1err(ASN1_F_A2D_ASN1_OBJECT, ASN1_R_BUFFER_TOO_SMALL);
                goto err;
            }
            while (--i > 0)
                out[len++] = tmp[i] | 0x80;
            out[len++] = tmp[0];
        } else
            len += i;
    }
    if (tmp != ftmp)
        OPENSSL_free(tmp);
    if (bl)
        BN_free(bl);
    return (len);
 err:
    if (tmp != ftmp)
        OPENSSL_free(tmp);
    if (bl)
        BN_free(bl);
    return (0);
}

int i2t_ASN1_OBJECT(char *buf, int buf_len, ASN1_OBJECT *a)
{
    return OBJ_obj2txt(buf, buf_len, a, 0);
}

int i2a_ASN1_OBJECT(BIO *bp, ASN1_OBJECT *a)
{
    char buf[80], *p = buf;
    int i;

    if ((a == NULL) || (a->data == NULL))
        return (BIO_write(bp, "NULL", 4));
    i = i2t_ASN1_OBJECT(buf, sizeof(buf), a);
    if (i > (int)(sizeof(buf) - 1)) {
        p = OPENSSL_malloc(i + 1);
        if (!p)
            return -1;
        i2t_ASN1_OBJECT(p, i + 1, a);
    }
    if (i <= 0)
        return BIO_write(bp, "<INVALID>", 9);
    BIO_write(bp, p, i);
    if (p != buf)
        OPENSSL_free(p);
    return (i);
}

ASN1_OBJECT *d2i_ASN1_OBJECT(ASN1_OBJECT **a, const unsigned char **pp,
                             long length)
{
    const unsigned char *p;
    long len;
    int tag, xclass;
    int inf, i;
    ASN1_OBJECT *ret = NULL;
    p = *pp;
    inf = ASN1_get_object(&p, &len, &tag, &xclass, length);
    if (inf & 0x80) {
        i = ASN1_R_BAD_OBJECT_HEADER;
        goto err;
    }

    if (tag != V_ASN1_OBJECT) {
        i = ASN1_R_EXPECTING_AN_OBJECT;
        goto err;
    }
    ret = c2i_ASN1_OBJECT(a, &p, len);
    if (ret)
        *pp = p;
    return ret;
 err:
    ASN1err(ASN1_F_D2I_ASN1_OBJECT, i);
    return (NULL);
}

ASN1_OBJECT *c2i_ASN1_OBJECT(ASN1_OBJECT **a, const unsigned char **pp,
                             long len)
{
    ASN1_OBJECT *ret = NULL;
    const unsigned char *p;
    unsigned char *data;
    int i, length;

    /*
     * Sanity check OID encoding. Need at least one content octet. MSB must
     * be clear in the last octet. can't have leading 0x80 in subidentifiers,
     * see: X.690 8.19.2
     */
    if (len <= 0 || len > INT_MAX || pp == NULL || (p = *pp) == NULL ||
        p[len - 1] & 0x80) {
        ASN1err(ASN1_F_C2I_ASN1_OBJECT, ASN1_R_INVALID_OBJECT_ENCODING);
        return NULL;
    }
    /* Now 0 < len <= INT_MAX, so the cast is safe. */
    length = (int)len;
    for (i = 0; i < length; i++, p++) {
        if (*p == 0x80 && (!i || !(p[-1] & 0x80))) {
            ASN1err(ASN1_F_C2I_ASN1_OBJECT, ASN1_R_INVALID_OBJECT_ENCODING);
            return NULL;
        }
    }

    /*
     * only the ASN1_OBJECTs from the 'table' will have values for ->sn or
     * ->ln
     */
    if ((a == NULL) || ((*a) == NULL) ||
        !((*a)->flags & ASN1_OBJECT_FLAG_DYNAMIC)) {
        if ((ret = ASN1_OBJECT_new()) == NULL)
            return (NULL);
    } else
        ret = (*a);

    p = *pp;
    /* detach data from object */
    data = (unsigned char *)ret->data;
    ret->data = NULL;
    /* once detached we can change it */
    if ((data == NULL) || (ret->length < length)) {
        ret->length = 0;
        if (data != NULL)
            OPENSSL_free(data);
        data = (unsigned char *)OPENSSL_malloc(length);
        if (data == NULL) {
            i = ERR_R_MALLOC_FAILURE;
            goto err;
        }
        ret->flags |= ASN1_OBJECT_FLAG_DYNAMIC_DATA;
    }
    memcpy(data, p, length);
    /* reattach data to object, after which it remains const */
    ret->data = data;
    ret->length = length;
    ret->sn = NULL;
    ret->ln = NULL;
    /* ret->flags=ASN1_OBJECT_FLAG_DYNAMIC; we know it is dynamic */
    p += length;

    if (a != NULL)
        (*a) = ret;
    *pp = p;
    return (ret);
 err:
    ASN1err(ASN1_F_C2I_ASN1_OBJECT, i);
    if ((ret != NULL) && ((a == NULL) || (*a != ret)))
        ASN1_OBJECT_free(ret);
    return (NULL);
}

ASN1_OBJECT *ASN1_OBJECT_new(void)
{
    ASN1_OBJECT *ret;

    ret = (ASN1_OBJECT *)OPENSSL_malloc(sizeof(ASN1_OBJECT));
    if (ret == NULL) {
        ASN1err(ASN1_F_ASN1_OBJECT_NEW, ERR_R_MALLOC_FAILURE);
        return (NULL);
    }
    ret->length = 0;
    ret->data = NULL;
    ret->nid = 0;
    ret->sn = NULL;
    ret->ln = NULL;
    ret->flags = ASN1_OBJECT_FLAG_DYNAMIC;
    return (ret);
}

void ASN1_OBJECT_free(ASN1_OBJECT *a)
{
    if (a == NULL)
        return;
    if (a->flags & ASN1_OBJECT_FLAG_DYNAMIC_STRINGS) {
#ifndef CONST_STRICT            /* disable purely for compile-time strict
                                 * const checking. Doing this on a "real"
                                 * compile will cause memory leaks */
        if (a->sn != NULL)
            OPENSSL_free((void *)a->sn);
        if (a->ln != NULL)
            OPENSSL_free((void *)a->ln);
#endif
        a->sn = a->ln = NULL;
    }
    if (a->flags & ASN1_OBJECT_FLAG_DYNAMIC_DATA) {
        if (a->data != NULL)
            OPENSSL_free((void *)a->data);
        a->data = NULL;
        a->length = 0;
    }
    if (a->flags & ASN1_OBJECT_FLAG_DYNAMIC)
        OPENSSL_free(a);
}

ASN1_OBJECT *ASN1_OBJECT_create(int nid, unsigned char *data, int len,
                                const char *sn, const char *ln)
{
    ASN1_OBJECT o;

    o.sn = sn;
    o.ln = ln;
    o.data = data;
    o.nid = nid;
    o.length = len;
    o.flags = ASN1_OBJECT_FLAG_DYNAMIC | ASN1_OBJECT_FLAG_DYNAMIC_STRINGS |
        ASN1_OBJECT_FLAG_DYNAMIC_DATA;
    return (OBJ_dup(&o));
}

IMPLEMENT_STACK_OF(ASN1_OBJECT)

IMPLEMENT_ASN1_SET_OF(ASN1_OBJECT)
/* crypto/asn1/a_octet.c */
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

ASN1_OCTET_STRING *ASN1_OCTET_STRING_dup(const ASN1_OCTET_STRING *x)
{
    return M_ASN1_OCTET_STRING_dup(x);
}

int ASN1_OCTET_STRING_cmp(const ASN1_OCTET_STRING *a,
                          const ASN1_OCTET_STRING *b)
{
    return M_ASN1_OCTET_STRING_cmp(a, b);
}

int ASN1_OCTET_STRING_set(ASN1_OCTET_STRING *x, const unsigned char *d,
                          int len)
{
    return M_ASN1_OCTET_STRING_set(x, d, len);
}
/* crypto/asn1/a_print.c */
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

int ASN1_PRINTABLE_type(const unsigned char *s, int len)
{
    int c;
    int ia5 = 0;
    int t61 = 0;

    if (len <= 0)
        len = -1;
    if (s == NULL)
        return (V_ASN1_PRINTABLESTRING);

    while ((*s) && (len-- != 0)) {
        c = *(s++);
#ifndef CHARSET_EBCDIC
        if (!(((c >= 'a') && (c <= 'z')) ||
              ((c >= 'A') && (c <= 'Z')) ||
              (c == ' ') ||
              ((c >= '0') && (c <= '9')) ||
              (c == ' ') || (c == '\'') ||
              (c == '(') || (c == ')') ||
              (c == '+') || (c == ',') ||
              (c == '-') || (c == '.') ||
              (c == '/') || (c == ':') || (c == '=') || (c == '?')))
            ia5 = 1;
        if (c & 0x80)
            t61 = 1;
#else
        if (!isalnum(c) && (c != ' ') && strchr("'()+,-./:=?", c) == NULL)
            ia5 = 1;
        if (os_toascii[c] & 0x80)
            t61 = 1;
#endif
    }
    if (t61)
        return (V_ASN1_T61STRING);
    if (ia5)
        return (V_ASN1_IA5STRING);
    return (V_ASN1_PRINTABLESTRING);
}

int ASN1_UNIVERSALSTRING_to_string(ASN1_UNIVERSALSTRING *s)
{
    int i;
    unsigned char *p;

    if (s->type != V_ASN1_UNIVERSALSTRING)
        return (0);
    if ((s->length % 4) != 0)
        return (0);
    p = s->data;
    for (i = 0; i < s->length; i += 4) {
        if ((p[0] != '\0') || (p[1] != '\0') || (p[2] != '\0'))
            break;
        else
            p += 4;
    }
    if (i < s->length)
        return (0);
    p = s->data;
    for (i = 3; i < s->length; i += 4) {
        *(p++) = s->data[i];
    }
    *(p) = '\0';
    s->length /= 4;
    s->type = ASN1_PRINTABLE_type(s->data, s->length);
    return (1);
}
/* crypto/asn1/a_set.c */
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
#include <limits.h>
// #include "cryptlib.h"
// #include "asn1_mac.h"

#ifndef NO_ASN1_OLD

typedef struct {
    unsigned char *pbData;
    int cbData;
} MYBLOB;

/*
 * SetBlobCmp This function compares two elements of SET_OF block
 */
static int SetBlobCmp(const void *elem1, const void *elem2)
{
    const MYBLOB *b1 = (const MYBLOB *)elem1;
    const MYBLOB *b2 = (const MYBLOB *)elem2;
    int r;

    r = memcmp(b1->pbData, b2->pbData,
               b1->cbData < b2->cbData ? b1->cbData : b2->cbData);
    if (r != 0)
        return r;
    return b1->cbData - b2->cbData;
}

/*
 * int is_set: if TRUE, then sort the contents (i.e. it isn't a SEQUENCE)
 */
int i2d_ASN1_SET(STACK_OF(OPENSSL_BLOCK) *a, unsigned char **pp,
                 i2d_of_void *i2d, int ex_tag, int ex_class, int is_set)
{
    int ret = 0, r;
    int i;
    unsigned char *p;
    unsigned char *pStart, *pTempMem;
    MYBLOB *rgSetBlob;
    int totSize;

    if (a == NULL)
        return (0);
    for (i = sk_OPENSSL_BLOCK_num(a) - 1; i >= 0; i--) {
        int tmplen = i2d(sk_OPENSSL_BLOCK_value(a, i), NULL);
        if (tmplen > INT_MAX - ret)
            return -1;
        ret += i2d(sk_OPENSSL_BLOCK_value(a, i), NULL);
    }
    r = ASN1_object_size(1, ret, ex_tag);
    if (pp == NULL || r == -1)
        return (r);

    p = *pp;
    ASN1_put_object(&p, 1, ret, ex_tag, ex_class);

/* Modified by gp@nsj.co.jp */
    /* And then again by Ben */
    /* And again by Steve */

    if (!is_set || (sk_OPENSSL_BLOCK_num(a) < 2)) {
        for (i = 0; i < sk_OPENSSL_BLOCK_num(a); i++)
            i2d(sk_OPENSSL_BLOCK_value(a, i), &p);

        *pp = p;
        return (r);
    }

    pStart = p;                 /* Catch the beg of Setblobs */
    /* In this array we will store the SET blobs */
    rgSetBlob = OPENSSL_malloc(sk_OPENSSL_BLOCK_num(a) * sizeof(MYBLOB));
    if (rgSetBlob == NULL) {
        ASN1err(ASN1_F_I2D_ASN1_SET, ERR_R_MALLOC_FAILURE);
        return (0);
    }

    for (i = 0; i < sk_OPENSSL_BLOCK_num(a); i++) {
        rgSetBlob[i].pbData = p; /* catch each set encode blob */
        i2d(sk_OPENSSL_BLOCK_value(a, i), &p);
        rgSetBlob[i].cbData = p - rgSetBlob[i].pbData; /* Length of this
                                                        * SetBlob */
    }
    *pp = p;
    totSize = p - pStart;       /* This is the total size of all set blobs */

    /*
     * Now we have to sort the blobs. I am using a simple algo. *Sort ptrs
     * *Copy to temp-mem *Copy from temp-mem to user-mem
     */
    qsort(rgSetBlob, sk_OPENSSL_BLOCK_num(a), sizeof(MYBLOB), SetBlobCmp);
    if (!(pTempMem = OPENSSL_malloc(totSize))) {
        ASN1err(ASN1_F_I2D_ASN1_SET, ERR_R_MALLOC_FAILURE);
        return (0);
    }

/* Copy to temp mem */
    p = pTempMem;
    for (i = 0; i < sk_OPENSSL_BLOCK_num(a); ++i) {
        memcpy(p, rgSetBlob[i].pbData, rgSetBlob[i].cbData);
        p += rgSetBlob[i].cbData;
    }

/* Copy back to user mem*/
    memcpy(pStart, pTempMem, totSize);
    OPENSSL_free(pTempMem);
    OPENSSL_free(rgSetBlob);

    return (r);
}

STACK_OF(OPENSSL_BLOCK) *d2i_ASN1_SET(STACK_OF(OPENSSL_BLOCK) **a,
                                      const unsigned char **pp,
                                      long length, d2i_of_void *d2i,
                                      void (*free_func) (OPENSSL_BLOCK),
                                      int ex_tag, int ex_class)
{
    ASN1_const_CTX c;
    STACK_OF(OPENSSL_BLOCK) *ret = NULL;

    if ((a == NULL) || ((*a) == NULL)) {
        if ((ret = sk_OPENSSL_BLOCK_new_null()) == NULL) {
            ASN1err(ASN1_F_D2I_ASN1_SET, ERR_R_MALLOC_FAILURE);
            goto err;
        }
    } else
        ret = (*a);

    c.p = *pp;
    c.max = (length == 0) ? 0 : (c.p + length);

    c.inf = ASN1_get_object(&c.p, &c.slen, &c.tag, &c.xclass, c.max - c.p);
    if (c.inf & 0x80)
        goto err;
    if (ex_class != c.xclass) {
        ASN1err(ASN1_F_D2I_ASN1_SET, ASN1_R_BAD_CLASS);
        goto err;
    }
    if (ex_tag != c.tag) {
        ASN1err(ASN1_F_D2I_ASN1_SET, ASN1_R_BAD_TAG);
        goto err;
    }
    if ((c.slen + c.p) > c.max) {
        ASN1err(ASN1_F_D2I_ASN1_SET, ASN1_R_LENGTH_ERROR);
        goto err;
    }
    /*
     * check for infinite constructed - it can be as long as the amount of
     * data passed to us
     */
    if (c.inf == (V_ASN1_CONSTRUCTED + 1))
        c.slen = length + *pp - c.p;
    c.max = c.p + c.slen;

    while (c.p < c.max) {
        char *s;

        if (M_ASN1_D2I_end_sequence())
            break;
        /*
         * XXX: This was called with 4 arguments, incorrectly, it seems if
         * ((s=func(NULL,&c.p,c.slen,c.max-c.p)) == NULL)
         */
        if ((s = d2i(NULL, &c.p, c.slen)) == NULL) {
            ASN1err(ASN1_F_D2I_ASN1_SET, ASN1_R_ERROR_PARSING_SET_ELEMENT);
            asn1_add_error(*pp, (int)(c.p - *pp));
            goto err;
        }
        if (!sk_OPENSSL_BLOCK_push(ret, s))
            goto err;
    }
    if (a != NULL)
        (*a) = ret;
    *pp = c.p;
    return (ret);
 err:
    if ((ret != NULL) && ((a == NULL) || (*a != ret))) {
        if (free_func != NULL)
            sk_OPENSSL_BLOCK_pop_free(ret, free_func);
        else
            sk_OPENSSL_BLOCK_free(ret);
    }
    return (NULL);
}

#endif
/* crypto/asn1/a_sign.c */
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

#include <stdio.h>
#include <time.h>

// #include "cryptlib.h"

#ifndef NO_SYS_TYPES_H
# include <sys/types.h>
#endif

// #include "bn.h"
// #include "evp.h"
// #include "x509.h"
// #include "objects.h"
// #include "buffer.h"
// #include "asn1_locl.h"

#ifndef NO_ASN1_OLD

int ASN1_sign(i2d_of_void *i2d, X509_ALGOR *algor1, X509_ALGOR *algor2,
              ASN1_BIT_STRING *signature, char *data, EVP_PKEY *pkey,
              const EVP_MD *type)
{
    EVP_MD_CTX ctx;
    unsigned char *p, *buf_in = NULL, *buf_out = NULL;
    int i, inl = 0, outl = 0, outll = 0;
    X509_ALGOR *a;

    EVP_MD_CTX_init(&ctx);
    for (i = 0; i < 2; i++) {
        if (i == 0)
            a = algor1;
        else
            a = algor2;
        if (a == NULL)
            continue;
        if (type->pkey_type == NID_dsaWithSHA1) {
            /*
             * special case: RFC 2459 tells us to omit 'parameters' with
             * id-dsa-with-sha1
             */
            ASN1_TYPE_free(a->parameter);
            a->parameter = NULL;
        } else if ((a->parameter == NULL) ||
                   (a->parameter->type != V_ASN1_NULL)) {
            ASN1_TYPE_free(a->parameter);
            if ((a->parameter = ASN1_TYPE_new()) == NULL)
                goto err;
            a->parameter->type = V_ASN1_NULL;
        }
        ASN1_OBJECT_free(a->algorithm);
        a->algorithm = OBJ_nid2obj(type->pkey_type);
        if (a->algorithm == NULL) {
            ASN1err(ASN1_F_ASN1_SIGN, ASN1_R_UNKNOWN_OBJECT_TYPE);
            goto err;
        }
        if (a->algorithm->length == 0) {
            ASN1err(ASN1_F_ASN1_SIGN,
                    ASN1_R_THE_ASN1_OBJECT_IDENTIFIER_IS_NOT_KNOWN_FOR_THIS_MD);
            goto err;
        }
    }
    inl = i2d(data, NULL);
    buf_in = (unsigned char *)OPENSSL_malloc((unsigned int)inl);
    outll = outl = EVP_PKEY_size(pkey);
    buf_out = (unsigned char *)OPENSSL_malloc((unsigned int)outl);
    if ((buf_in == NULL) || (buf_out == NULL)) {
        outl = 0;
        ASN1err(ASN1_F_ASN1_SIGN, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    p = buf_in;

    i2d(data, &p);
    if (!EVP_SignInit_ex(&ctx, type, NULL)
        || !EVP_SignUpdate(&ctx, (unsigned char *)buf_in, inl)
        || !EVP_SignFinal(&ctx, (unsigned char *)buf_out,
                          (unsigned int *)&outl, pkey)) {
        outl = 0;
        ASN1err(ASN1_F_ASN1_SIGN, ERR_R_EVP_LIB);
        goto err;
    }
    if (signature->data != NULL)
        OPENSSL_free(signature->data);
    signature->data = buf_out;
    buf_out = NULL;
    signature->length = outl;
    /*
     * In the interests of compatibility, I'll make sure that the bit string
     * has a 'not-used bits' value of 0
     */
    signature->flags &= ~(ASN1_STRING_FLAG_BITS_LEFT | 0x07);
    signature->flags |= ASN1_STRING_FLAG_BITS_LEFT;
 err:
    EVP_MD_CTX_cleanup(&ctx);
    if (buf_in != NULL) {
        OPENSSL_cleanse((char *)buf_in, (unsigned int)inl);
        OPENSSL_free(buf_in);
    }
    if (buf_out != NULL) {
        OPENSSL_cleanse((char *)buf_out, outll);
        OPENSSL_free(buf_out);
    }
    return (outl);
}

#endif

int ASN1_item_sign(const ASN1_ITEM *it, X509_ALGOR *algor1,
                   X509_ALGOR *algor2, ASN1_BIT_STRING *signature, void *asn,
                   EVP_PKEY *pkey, const EVP_MD *type)
{
    EVP_MD_CTX ctx;
    EVP_MD_CTX_init(&ctx);
    if (!EVP_DigestSignInit(&ctx, NULL, type, NULL, pkey)) {
        EVP_MD_CTX_cleanup(&ctx);
        return 0;
    }
    return ASN1_item_sign_ctx(it, algor1, algor2, signature, asn, &ctx);
}

int ASN1_item_sign_ctx(const ASN1_ITEM *it,
                       X509_ALGOR *algor1, X509_ALGOR *algor2,
                       ASN1_BIT_STRING *signature, void *asn, EVP_MD_CTX *ctx)
{
    const EVP_MD *type;
    EVP_PKEY *pkey;
    unsigned char *buf_in = NULL, *buf_out = NULL;
    size_t inl = 0, outl = 0, outll = 0;
    int signid, paramtype;
    int rv;

    type = EVP_MD_CTX_md(ctx);
    pkey = EVP_PKEY_CTX_get0_pkey(ctx->pctx);

    if (!type || !pkey) {
        ASN1err(ASN1_F_ASN1_ITEM_SIGN_CTX, ASN1_R_CONTEXT_NOT_INITIALISED);
        return 0;
    }

    if (pkey->ameth->item_sign) {
        rv = pkey->ameth->item_sign(ctx, it, asn, algor1, algor2, signature);
        if (rv == 1)
            outl = signature->length;
        /*-
         * Return value meanings:
         * <=0: error.
         *   1: method does everything.
         *   2: carry on as normal.
         *   3: ASN1 method sets algorithm identifiers: just sign.
         */
        if (rv <= 0)
            ASN1err(ASN1_F_ASN1_ITEM_SIGN_CTX, ERR_R_EVP_LIB);
        if (rv <= 1)
            goto err;
    } else
        rv = 2;

    if (rv == 2) {
        if (type->flags & EVP_MD_FLAG_PKEY_METHOD_SIGNATURE) {
            if (!pkey->ameth ||
                !OBJ_find_sigid_by_algs(&signid,
                                        EVP_MD_nid(type),
                                        pkey->ameth->pkey_id)) {
                ASN1err(ASN1_F_ASN1_ITEM_SIGN_CTX,
                        ASN1_R_DIGEST_AND_KEY_TYPE_NOT_SUPPORTED);
                return 0;
            }
        } else
            signid = type->pkey_type;

        if (pkey->ameth->pkey_flags & ASN1_PKEY_SIGPARAM_NULL)
            paramtype = V_ASN1_NULL;
        else
            paramtype = V_ASN1_UNDEF;

        if (algor1)
            X509_ALGOR_set0(algor1, OBJ_nid2obj(signid), paramtype, NULL);
        if (algor2)
            X509_ALGOR_set0(algor2, OBJ_nid2obj(signid), paramtype, NULL);

    }

    inl = ASN1_item_i2d(asn, &buf_in, it);
    outll = outl = EVP_PKEY_size(pkey);
    buf_out = OPENSSL_malloc((unsigned int)outl);
    if ((buf_in == NULL) || (buf_out == NULL)) {
        outl = 0;
        ASN1err(ASN1_F_ASN1_ITEM_SIGN_CTX, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (!EVP_DigestSignUpdate(ctx, buf_in, inl)
        || !EVP_DigestSignFinal(ctx, buf_out, &outl)) {
        outl = 0;
        ASN1err(ASN1_F_ASN1_ITEM_SIGN_CTX, ERR_R_EVP_LIB);
        goto err;
    }
    if (signature->data != NULL)
        OPENSSL_free(signature->data);
    signature->data = buf_out;
    buf_out = NULL;
    signature->length = outl;
    /*
     * In the interests of compatibility, I'll make sure that the bit string
     * has a 'not-used bits' value of 0
     */
    signature->flags &= ~(ASN1_STRING_FLAG_BITS_LEFT | 0x07);
    signature->flags |= ASN1_STRING_FLAG_BITS_LEFT;
 err:
    EVP_MD_CTX_cleanup(ctx);
    if (buf_in != NULL) {
        OPENSSL_cleanse((char *)buf_in, (unsigned int)inl);
        OPENSSL_free(buf_in);
    }
    if (buf_out != NULL) {
        OPENSSL_cleanse((char *)buf_out, outll);
        OPENSSL_free(buf_out);
    }
    return (outl);
}
/* a_strex.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 2000.
 */
/* ====================================================================
 * Copyright (c) 2000-2018 The OpenSSL Project.  All rights reserved.
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
#include <string.h>
// #include "cryptlib.h"
#include "crypto.h"
// #include "x509.h"
// #include "asn1.h"

#include "charmap.h"

/*
 * ASN1_STRING_print_ex() and X509_NAME_print_ex(). Enhanced string and name
 * printing routines handling multibyte characters, RFC2253 and a host of
 * other options.
 */

#define CHARTYPE_BS_ESC         (ASN1_STRFLGS_ESC_2253 | CHARTYPE_FIRST_ESC_2253 | CHARTYPE_LAST_ESC_2253)

#define ESC_FLAGS (ASN1_STRFLGS_ESC_2253 | \
                  ASN1_STRFLGS_ESC_QUOTE | \
                  ASN1_STRFLGS_ESC_CTRL | \
                  ASN1_STRFLGS_ESC_MSB)

/*
 * Three IO functions for sending data to memory, a BIO and and a FILE
 * pointer.
 */
#if 0                           /* never used */
static int send_mem_chars(void *arg, const void *buf, int len)
{
    unsigned char **out = arg;
    if (!out)
        return 1;
    memcpy(*out, buf, len);
    *out += len;
    return 1;
}
#endif

static int send_bio_chars(void *arg, const void *buf, int len)
{
    if (!arg)
        return 1;
    if (BIO_write(arg, buf, len) != len)
        return 0;
    return 1;
}

static int send_fp_chars(void *arg, const void *buf, int len)
{
    if (!arg)
        return 1;
    if (fwrite(buf, 1, len, arg) != (unsigned int)len)
        return 0;
    return 1;
}

typedef int char_io (void *arg, const void *buf, int len);

/*
 * This function handles display of strings, one character at a time. It is
 * passed an unsigned long for each character because it could come from 2 or
 * even 4 byte forms.
 */

static int do_esc_char(unsigned long c, unsigned char flags, char *do_quotes,
                       char_io *io_ch, void *arg)
{
    unsigned char chflgs, chtmp;
    char tmphex[HEX_SIZE(long) + 3];

    if (c > 0xffffffffL)
        return -1;
    if (c > 0xffff) {
        BIO_snprintf(tmphex, sizeof(tmphex), "\\W%08lX", c);
        if (!io_ch(arg, tmphex, 10))
            return -1;
        return 10;
    }
    if (c > 0xff) {
        BIO_snprintf(tmphex, sizeof(tmphex), "\\U%04lX", c);
        if (!io_ch(arg, tmphex, 6))
            return -1;
        return 6;
    }
    chtmp = (unsigned char)c;
    if (chtmp > 0x7f)
        chflgs = flags & ASN1_STRFLGS_ESC_MSB;
    else
        chflgs = char_type[chtmp] & flags;
    if (chflgs & CHARTYPE_BS_ESC) {
        /* If we don't escape with quotes, signal we need quotes */
        if (chflgs & ASN1_STRFLGS_ESC_QUOTE) {
            if (do_quotes)
                *do_quotes = 1;
            if (!io_ch(arg, &chtmp, 1))
                return -1;
            return 1;
        }
        if (!io_ch(arg, "\\", 1))
            return -1;
        if (!io_ch(arg, &chtmp, 1))
            return -1;
        return 2;
    }
    if (chflgs & (ASN1_STRFLGS_ESC_CTRL | ASN1_STRFLGS_ESC_MSB)) {
        BIO_snprintf(tmphex, 11, "\\%02X", chtmp);
        if (!io_ch(arg, tmphex, 3))
            return -1;
        return 3;
    }
    /*
     * If we get this far and do any escaping at all must escape the escape
     * character itself: backslash.
     */
    if (chtmp == '\\' && flags & ESC_FLAGS) {
        if (!io_ch(arg, "\\\\", 2))
            return -1;
        return 2;
    }
    if (!io_ch(arg, &chtmp, 1))
        return -1;
    return 1;
}

#define BUF_TYPE_WIDTH_MASK     0x7
#define BUF_TYPE_CONVUTF8       0x8

/*
 * This function sends each character in a buffer to do_esc_char(). It
 * interprets the content formats and converts to or from UTF8 as
 * appropriate.
 */

static int do_buf(unsigned char *buf, int buflen,
                  int type, unsigned char flags, char *quotes, char_io *io_ch,
                  void *arg)
{
    int i, outlen, len, charwidth;
    unsigned char orflags, *p, *q;
    unsigned long c;
    p = buf;
    q = buf + buflen;
    outlen = 0;
    charwidth = type & BUF_TYPE_WIDTH_MASK;

    switch (charwidth) {
    case 4:
        if (buflen & 3) {
            ASN1err(ASN1_F_DO_BUF, ASN1_R_INVALID_UNIVERSALSTRING_LENGTH);
            return -1;
        }
        break;
    case 2:
        if (buflen & 1) {
            ASN1err(ASN1_F_DO_BUF, ASN1_R_INVALID_BMPSTRING_LENGTH);
            return -1;
        }
        break;
    default:
        break;
    }

    while (p != q) {
        if (p == buf && flags & ASN1_STRFLGS_ESC_2253)
            orflags = CHARTYPE_FIRST_ESC_2253;
        else
            orflags = 0;

        switch (charwidth) {
        case 4:
            c = ((unsigned long)*p++) << 24;
            c |= ((unsigned long)*p++) << 16;
            c |= ((unsigned long)*p++) << 8;
            c |= *p++;
            break;

        case 2:
            c = ((unsigned long)*p++) << 8;
            c |= *p++;
            break;

        case 1:
            c = *p++;
            break;

        case 0:
            i = UTF8_getc(p, buflen, &c);
            if (i < 0)
                return -1;      /* Invalid UTF8String */
            buflen -= i;
            p += i;
            break;
        default:
            return -1;          /* invalid width */
        }
        if (p == q && flags & ASN1_STRFLGS_ESC_2253)
            orflags = CHARTYPE_LAST_ESC_2253;
        if (type & BUF_TYPE_CONVUTF8) {
            unsigned char utfbuf[6];
            int utflen;
            utflen = UTF8_putc(utfbuf, sizeof(utfbuf), c);
            for (i = 0; i < utflen; i++) {
                /*
                 * We don't need to worry about setting orflags correctly
                 * because if utflen==1 its value will be correct anyway
                 * otherwise each character will be > 0x7f and so the
                 * character will never be escaped on first and last.
                 */
                len =
                    do_esc_char(utfbuf[i], (unsigned char)(flags | orflags),
                                quotes, io_ch, arg);
                if (len < 0)
                    return -1;
                outlen += len;
            }
        } else {
            len =
                do_esc_char(c, (unsigned char)(flags | orflags), quotes,
                            io_ch, arg);
            if (len < 0)
                return -1;
            outlen += len;
        }
    }
    return outlen;
}

/* This function hex dumps a buffer of characters */

static int do_hex_dump(char_io *io_ch, void *arg, unsigned char *buf,
                       int buflen)
{
    static const char hexdig[] = "0123456789ABCDEF";
    unsigned char *p, *q;
    char hextmp[2];
    if (arg) {
        p = buf;
        q = buf + buflen;
        while (p != q) {
            hextmp[0] = hexdig[*p >> 4];
            hextmp[1] = hexdig[*p & 0xf];
            if (!io_ch(arg, hextmp, 2))
                return -1;
            p++;
        }
    }
    return buflen << 1;
}

/*
 * "dump" a string. This is done when the type is unknown, or the flags
 * request it. We can either dump the content octets or the entire DER
 * encoding. This uses the RFC2253 #01234 format.
 */

static int do_dump(unsigned long lflags, char_io *io_ch, void *arg,
                   ASN1_STRING *str)
{
    /*
     * Placing the ASN1_STRING in a temp ASN1_TYPE allows the DER encoding to
     * readily obtained
     */
    ASN1_TYPE t;
    unsigned char *der_buf, *p;
    int outlen, der_len;

    if (!io_ch(arg, "#", 1))
        return -1;
    /* If we don't dump DER encoding just dump content octets */
    if (!(lflags & ASN1_STRFLGS_DUMP_DER)) {
        outlen = do_hex_dump(io_ch, arg, str->data, str->length);
        if (outlen < 0)
            return -1;
        return outlen + 1;
    }
    t.type = str->type;
    t.value.ptr = (char *)str;
    der_len = i2d_ASN1_TYPE(&t, NULL);
    der_buf = OPENSSL_malloc(der_len);
    if (!der_buf)
        return -1;
    p = der_buf;
    i2d_ASN1_TYPE(&t, &p);
    outlen = do_hex_dump(io_ch, arg, der_buf, der_len);
    OPENSSL_free(der_buf);
    if (outlen < 0)
        return -1;
    return outlen + 1;
}

/*
 * Lookup table to convert tags to character widths, 0 = UTF8 encoded, -1 is
 * used for non string types otherwise it is the number of bytes per
 * character
 */

static const signed char tag2nbyte[] = {
    -1, -1, -1, -1, -1,         /* 0-4 */
    -1, -1, -1, -1, -1,         /* 5-9 */
    -1, -1, 0, -1,              /* 10-13 */
    -1, -1, -1, -1,             /* 15-17 */
    1, 1, 1,                    /* 18-20 */
    -1, 1, 1, 1,                /* 21-24 */
    -1, 1, -1,                  /* 25-27 */
    4, -1, 2                    /* 28-30 */
};

/*
 * This is the main function, print out an ASN1_STRING taking note of various
 * escape and display options. Returns number of characters written or -1 if
 * an error occurred.
 */

static int do_print_ex(char_io *io_ch, void *arg, unsigned long lflags,
                       ASN1_STRING *str)
{
    int outlen, len;
    int type;
    char quotes;
    unsigned char flags;
    quotes = 0;
    /* Keep a copy of escape flags */
    flags = (unsigned char)(lflags & ESC_FLAGS);

    type = str->type;

    outlen = 0;

    if (lflags & ASN1_STRFLGS_SHOW_TYPE) {
        const char *tagname;
        tagname = ASN1_tag2str(type);
        outlen += strlen(tagname);
        if (!io_ch(arg, tagname, outlen) || !io_ch(arg, ":", 1))
            return -1;
        outlen++;
    }

    /* Decide what to do with type, either dump content or display it */

    /* Dump everything */
    if (lflags & ASN1_STRFLGS_DUMP_ALL)
        type = -1;
    /* Ignore the string type */
    else if (lflags & ASN1_STRFLGS_IGNORE_TYPE)
        type = 1;
    else {
        /* Else determine width based on type */
        if ((type > 0) && (type < 31))
            type = tag2nbyte[type];
        else
            type = -1;
        if ((type == -1) && !(lflags & ASN1_STRFLGS_DUMP_UNKNOWN))
            type = 1;
    }

    if (type == -1) {
        len = do_dump(lflags, io_ch, arg, str);
        if (len < 0)
            return -1;
        outlen += len;
        return outlen;
    }

    if (lflags & ASN1_STRFLGS_UTF8_CONVERT) {
        /*
         * Note: if string is UTF8 and we want to convert to UTF8 then we
         * just interpret it as 1 byte per character to avoid converting
         * twice.
         */
        if (!type)
            type = 1;
        else
            type |= BUF_TYPE_CONVUTF8;
    }

    len = do_buf(str->data, str->length, type, flags, &quotes, io_ch, NULL);
    if (len < 0)
        return -1;
    outlen += len;
    if (quotes)
        outlen += 2;
    if (!arg)
        return outlen;
    if (quotes && !io_ch(arg, "\"", 1))
        return -1;
    if (do_buf(str->data, str->length, type, flags, NULL, io_ch, arg) < 0)
        return -1;
    if (quotes && !io_ch(arg, "\"", 1))
        return -1;
    return outlen;
}

/* Used for line indenting: print 'indent' spaces */

static int do_indent(char_io *io_ch, void *arg, int indent)
{
    int i;
    for (i = 0; i < indent; i++)
        if (!io_ch(arg, " ", 1))
            return 0;
    return 1;
}

#define FN_WIDTH_LN     25
#define FN_WIDTH_SN     10

static int do_name_ex(char_io *io_ch, void *arg, X509_NAME *n,
                      int indent, unsigned long flags)
{
    int i, prev = -1, orflags, cnt;
    int fn_opt, fn_nid;
    ASN1_OBJECT *fn;
    ASN1_STRING *val;
    X509_NAME_ENTRY *ent;
    char objtmp[80];
    const char *objbuf;
    int outlen, len;
    char *sep_dn, *sep_mv, *sep_eq;
    int sep_dn_len, sep_mv_len, sep_eq_len;
    if (indent < 0)
        indent = 0;
    outlen = indent;
    if (!do_indent(io_ch, arg, indent))
        return -1;
    switch (flags & XN_FLAG_SEP_MASK) {
    case XN_FLAG_SEP_MULTILINE:
        sep_dn = "\n";
        sep_dn_len = 1;
        sep_mv = " + ";
        sep_mv_len = 3;
        break;

    case XN_FLAG_SEP_COMMA_PLUS:
        sep_dn = ",";
        sep_dn_len = 1;
        sep_mv = "+";
        sep_mv_len = 1;
        indent = 0;
        break;

    case XN_FLAG_SEP_CPLUS_SPC:
        sep_dn = ", ";
        sep_dn_len = 2;
        sep_mv = " + ";
        sep_mv_len = 3;
        indent = 0;
        break;

    case XN_FLAG_SEP_SPLUS_SPC:
        sep_dn = "; ";
        sep_dn_len = 2;
        sep_mv = " + ";
        sep_mv_len = 3;
        indent = 0;
        break;

    default:
        return -1;
    }

    if (flags & XN_FLAG_SPC_EQ) {
        sep_eq = " = ";
        sep_eq_len = 3;
    } else {
        sep_eq = "=";
        sep_eq_len = 1;
    }

    fn_opt = flags & XN_FLAG_FN_MASK;

    cnt = X509_NAME_entry_count(n);
    for (i = 0; i < cnt; i++) {
        if (flags & XN_FLAG_DN_REV)
            ent = X509_NAME_get_entry(n, cnt - i - 1);
        else
            ent = X509_NAME_get_entry(n, i);
        if (prev != -1) {
            if (prev == ent->set) {
                if (!io_ch(arg, sep_mv, sep_mv_len))
                    return -1;
                outlen += sep_mv_len;
            } else {
                if (!io_ch(arg, sep_dn, sep_dn_len))
                    return -1;
                outlen += sep_dn_len;
                if (!do_indent(io_ch, arg, indent))
                    return -1;
                outlen += indent;
            }
        }
        prev = ent->set;
        fn = X509_NAME_ENTRY_get_object(ent);
        val = X509_NAME_ENTRY_get_data(ent);
        fn_nid = OBJ_obj2nid(fn);
        if (fn_opt != XN_FLAG_FN_NONE) {
            int objlen, fld_len;
            if ((fn_opt == XN_FLAG_FN_OID) || (fn_nid == NID_undef)) {
                OBJ_obj2txt(objtmp, sizeof(objtmp), fn, 1);
                fld_len = 0;    /* XXX: what should this be? */
                objbuf = objtmp;
            } else {
                if (fn_opt == XN_FLAG_FN_SN) {
                    fld_len = FN_WIDTH_SN;
                    objbuf = OBJ_nid2sn(fn_nid);
                } else if (fn_opt == XN_FLAG_FN_LN) {
                    fld_len = FN_WIDTH_LN;
                    objbuf = OBJ_nid2ln(fn_nid);
                } else {
                    fld_len = 0; /* XXX: what should this be? */
                    objbuf = "";
                }
            }
            objlen = strlen(objbuf);
            if (!io_ch(arg, objbuf, objlen))
                return -1;
            if ((objlen < fld_len) && (flags & XN_FLAG_FN_ALIGN)) {
                if (!do_indent(io_ch, arg, fld_len - objlen))
                    return -1;
                outlen += fld_len - objlen;
            }
            if (!io_ch(arg, sep_eq, sep_eq_len))
                return -1;
            outlen += objlen + sep_eq_len;
        }
        /*
         * If the field name is unknown then fix up the DER dump flag. We
         * might want to limit this further so it will DER dump on anything
         * other than a few 'standard' fields.
         */
        if ((fn_nid == NID_undef) && (flags & XN_FLAG_DUMP_UNKNOWN_FIELDS))
            orflags = ASN1_STRFLGS_DUMP_ALL;
        else
            orflags = 0;

        len = do_print_ex(io_ch, arg, flags | orflags, val);
        if (len < 0)
            return -1;
        outlen += len;
    }
    return outlen;
}

/* Wrappers round the main functions */

int X509_NAME_print_ex(BIO *out, X509_NAME *nm, int indent,
                       unsigned long flags)
{
    if (flags == XN_FLAG_COMPAT)
        return X509_NAME_print(out, nm, indent);
    return do_name_ex(send_bio_chars, out, nm, indent, flags);
}

#ifndef OPENSSL_NO_FP_API
int X509_NAME_print_ex_fp(FILE *fp, X509_NAME *nm, int indent,
                          unsigned long flags)
{
    if (flags == XN_FLAG_COMPAT) {
        BIO *btmp;
        int ret;
        btmp = BIO_new_fp(fp, BIO_NOCLOSE);
        if (!btmp)
            return -1;
        ret = X509_NAME_print(btmp, nm, indent);
        BIO_free(btmp);
        return ret;
    }
    return do_name_ex(send_fp_chars, fp, nm, indent, flags);
}
#endif

int ASN1_STRING_print_ex(BIO *out, ASN1_STRING *str, unsigned long flags)
{
    return do_print_ex(send_bio_chars, out, flags, str);
}

#ifndef OPENSSL_NO_FP_API
int ASN1_STRING_print_ex_fp(FILE *fp, ASN1_STRING *str, unsigned long flags)
{
    return do_print_ex(send_fp_chars, fp, flags, str);
}
#endif

/*
 * Utility function: convert any string type to UTF8, returns number of bytes
 * in output string or a negative error code
 */

int ASN1_STRING_to_UTF8(unsigned char **out, ASN1_STRING *in)
{
    ASN1_STRING stmp, *str = &stmp;
    int mbflag, type, ret;
    if (!in)
        return -1;
    type = in->type;
    if ((type < 0) || (type > 30))
        return -1;
    mbflag = tag2nbyte[type];
    if (mbflag == -1)
        return -1;
    mbflag |= MBSTRING_FLAG;
    stmp.data = NULL;
    stmp.length = 0;
    stmp.flags = 0;
    ret =
        ASN1_mbstring_copy(&str, in->data, in->length, mbflag,
                           B_ASN1_UTF8STRING);
    if (ret < 0)
        return ret;
    *out = stmp.data;
    return stmp.length;
}
/* a_strnid.c */
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
#include <ctype.h>
// #include "cryptlib.h"
// #include "asn1.h"
// #include "objects.h"

static STACK_OF(ASN1_STRING_TABLE) *stable = NULL;
static void st_free(ASN1_STRING_TABLE *tbl);
static int sk_table_cmp(const ASN1_STRING_TABLE *const *a,
                        const ASN1_STRING_TABLE *const *b);

/*
 * This is the global mask for the mbstring functions: this is use to mask
 * out certain types (such as BMPString and UTF8String) because certain
 * software (e.g. Netscape) has problems with them.
 */

static unsigned long global_mask = B_ASN1_UTF8STRING;

void ASN1_STRING_set_default_mask(unsigned long mask)
{
    global_mask = mask;
}

unsigned long ASN1_STRING_get_default_mask(void)
{
    return global_mask;
}

/*-
 * This function sets the default to various "flavours" of configuration.
 * based on an ASCII string. Currently this is:
 * MASK:XXXX : a numerical mask value.
 * nobmp : Don't use BMPStrings (just Printable, T61).
 * pkix : PKIX recommendation in RFC2459.
 * utf8only : only use UTF8Strings (RFC2459 recommendation for 2004).
 * default:   the default value, Printable, T61, BMP.
 */

int ASN1_STRING_set_default_mask_asc(const char *p)
{
    unsigned long mask;
    char *end;
    if (!strncmp(p, "MASK:", 5)) {
        if (!p[5])
            return 0;
        mask = strtoul(p + 5, &end, 0);
        if (*end)
            return 0;
    } else if (!strcmp(p, "nombstr"))
        mask = ~((unsigned long)(B_ASN1_BMPSTRING | B_ASN1_UTF8STRING));
    else if (!strcmp(p, "pkix"))
        mask = ~((unsigned long)B_ASN1_T61STRING);
    else if (!strcmp(p, "utf8only"))
        mask = B_ASN1_UTF8STRING;
    else if (!strcmp(p, "default"))
        mask = 0xFFFFFFFFL;
    else
        return 0;
    ASN1_STRING_set_default_mask(mask);
    return 1;
}

/*
 * The following function generates an ASN1_STRING based on limits in a
 * table. Frequently the types and length of an ASN1_STRING are restricted by
 * a corresponding OID. For example certificates and certificate requests.
 */

ASN1_STRING *ASN1_STRING_set_by_NID(ASN1_STRING **out,
                                    const unsigned char *in, int inlen,
                                    int inform, int nid)
{
    ASN1_STRING_TABLE *tbl;
    ASN1_STRING *str = NULL;
    unsigned long mask;
    int ret;
    if (!out)
        out = &str;
    tbl = ASN1_STRING_TABLE_get(nid);
    if (tbl) {
        mask = tbl->mask;
        if (!(tbl->flags & STABLE_NO_MASK))
            mask &= global_mask;
        ret = ASN1_mbstring_ncopy(out, in, inlen, inform, mask,
                                  tbl->minsize, tbl->maxsize);
    } else
        ret =
            ASN1_mbstring_copy(out, in, inlen, inform,
                               DIRSTRING_TYPE & global_mask);
    if (ret <= 0)
        return NULL;
    return *out;
}

/*
 * Now the tables and helper functions for the string table:
 */

/* size limits: this stuff is taken straight from RFC3280 */

#define ub_name                         32768
#define ub_common_name                  64
#define ub_locality_name                128
#define ub_state_name                   128
#define ub_organization_name            64
#define ub_organization_unit_name       64
#define ub_title                        64
#define ub_email_address                128
#define ub_serial_number                64

/* This table must be kept in NID order */

static const ASN1_STRING_TABLE tbl_standard[] = {
    {NID_commonName, 1, ub_common_name, DIRSTRING_TYPE, 0},
    {NID_countryName, 2, 2, B_ASN1_PRINTABLESTRING, STABLE_NO_MASK},
    {NID_localityName, 1, ub_locality_name, DIRSTRING_TYPE, 0},
    {NID_stateOrProvinceName, 1, ub_state_name, DIRSTRING_TYPE, 0},
    {NID_organizationName, 1, ub_organization_name, DIRSTRING_TYPE, 0},
    {NID_organizationalUnitName, 1, ub_organization_unit_name, DIRSTRING_TYPE,
     0},
    {NID_pkcs9_emailAddress, 1, ub_email_address, B_ASN1_IA5STRING,
     STABLE_NO_MASK},
    {NID_pkcs9_unstructuredName, 1, -1, PKCS9STRING_TYPE, 0},
    {NID_pkcs9_challengePassword, 1, -1, PKCS9STRING_TYPE, 0},
    {NID_pkcs9_unstructuredAddress, 1, -1, DIRSTRING_TYPE, 0},
    {NID_givenName, 1, ub_name, DIRSTRING_TYPE, 0},
    {NID_surname, 1, ub_name, DIRSTRING_TYPE, 0},
    {NID_initials, 1, ub_name, DIRSTRING_TYPE, 0},
    {NID_serialNumber, 1, ub_serial_number, B_ASN1_PRINTABLESTRING,
     STABLE_NO_MASK},
    {NID_friendlyName, -1, -1, B_ASN1_BMPSTRING, STABLE_NO_MASK},
    {NID_name, 1, ub_name, DIRSTRING_TYPE, 0},
    {NID_dnQualifier, -1, -1, B_ASN1_PRINTABLESTRING, STABLE_NO_MASK},
    {NID_domainComponent, 1, -1, B_ASN1_IA5STRING, STABLE_NO_MASK},
    {NID_ms_csp_name, -1, -1, B_ASN1_BMPSTRING, STABLE_NO_MASK},
    {NID_jurisdictionCountryName, 2, 2, B_ASN1_PRINTABLESTRING, STABLE_NO_MASK}
};

static int sk_table_cmp(const ASN1_STRING_TABLE *const *a,
                        const ASN1_STRING_TABLE *const *b)
{
    return (*a)->nid - (*b)->nid;
}

DECLARE_OBJ_BSEARCH_CMP_FN(ASN1_STRING_TABLE, ASN1_STRING_TABLE, table);

static int table_cmp(const ASN1_STRING_TABLE *a, const ASN1_STRING_TABLE *b)
{
    return a->nid - b->nid;
}

IMPLEMENT_OBJ_BSEARCH_CMP_FN(ASN1_STRING_TABLE, ASN1_STRING_TABLE, table);

ASN1_STRING_TABLE *ASN1_STRING_TABLE_get(int nid)
{
    int idx;
    ASN1_STRING_TABLE *ttmp;
    ASN1_STRING_TABLE fnd;
    fnd.nid = nid;
    ttmp = OBJ_bsearch_table(&fnd, tbl_standard,
                             sizeof(tbl_standard) /
                             sizeof(ASN1_STRING_TABLE));
    if (ttmp)
        return ttmp;
    if (!stable)
        return NULL;
    idx = sk_ASN1_STRING_TABLE_find(stable, &fnd);
    if (idx < 0)
        return NULL;
    return sk_ASN1_STRING_TABLE_value(stable, idx);
}

int ASN1_STRING_TABLE_add(int nid,
                          long minsize, long maxsize, unsigned long mask,
                          unsigned long flags)
{
    ASN1_STRING_TABLE *tmp;
    char new_nid = 0;
    flags &= ~STABLE_FLAGS_MALLOC;
    if (!stable)
        stable = sk_ASN1_STRING_TABLE_new(sk_table_cmp);
    if (!stable) {
        ASN1err(ASN1_F_ASN1_STRING_TABLE_ADD, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    if (!(tmp = ASN1_STRING_TABLE_get(nid))) {
        tmp = OPENSSL_malloc(sizeof(ASN1_STRING_TABLE));
        if (!tmp) {
            ASN1err(ASN1_F_ASN1_STRING_TABLE_ADD, ERR_R_MALLOC_FAILURE);
            return 0;
        }
        tmp->flags = flags | STABLE_FLAGS_MALLOC;
        tmp->nid = nid;
        tmp->minsize = tmp->maxsize = -1;
        new_nid = 1;
    } else
        tmp->flags = (tmp->flags & STABLE_FLAGS_MALLOC) | flags;
    if (minsize != -1)
        tmp->minsize = minsize;
    if (maxsize != -1)
        tmp->maxsize = maxsize;
    tmp->mask = mask;
    if (new_nid)
        sk_ASN1_STRING_TABLE_push(stable, tmp);
    return 1;
}

void ASN1_STRING_TABLE_cleanup(void)
{
    STACK_OF(ASN1_STRING_TABLE) *tmp;
    tmp = stable;
    if (!tmp)
        return;
    stable = NULL;
    sk_ASN1_STRING_TABLE_pop_free(tmp, st_free);
}

static void st_free(ASN1_STRING_TABLE *tbl)
{
    if (tbl->flags & STABLE_FLAGS_MALLOC)
        OPENSSL_free(tbl);
}


IMPLEMENT_STACK_OF(ASN1_STRING_TABLE)

#ifdef STRING_TABLE_TEST

main()
{
    ASN1_STRING_TABLE *tmp;
    int i, last_nid = -1;

    for (tmp = tbl_standard, i = 0;
         i < sizeof(tbl_standard) / sizeof(ASN1_STRING_TABLE); i++, tmp++) {
        if (tmp->nid < last_nid) {
            last_nid = 0;
            break;
        }
        last_nid = tmp->nid;
    }

    if (last_nid != 0) {
        printf("Table order OK\n");
        exit(0);
    }

    for (tmp = tbl_standard, i = 0;
         i < sizeof(tbl_standard) / sizeof(ASN1_STRING_TABLE); i++, tmp++)
        printf("Index %d, NID %d, Name=%s\n", i, tmp->nid,
               OBJ_nid2ln(tmp->nid));

}

#endif
/* crypto/asn1/a_time.c */
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

/*-
 * This is an implementation of the ASN1 Time structure which is:
 *    Time ::= CHOICE {
 *      utcTime        UTCTime,
 *      generalTime    GeneralizedTime }
 * written by Steve Henson.
 */

#include <stdio.h>
#include <time.h>
// #include "cryptlib.h"
// #include "o_time.h"
// #include "asn1t.h"
// #include "asn1_locl.h"

IMPLEMENT_ASN1_MSTRING(ASN1_TIME, B_ASN1_TIME)

IMPLEMENT_ASN1_FUNCTIONS(ASN1_TIME)

#if 0
int i2d_ASN1_TIME(ASN1_TIME *a, unsigned char **pp)
{
# ifdef CHARSET_EBCDIC
    /* KLUDGE! We convert to ascii before writing DER */
    char tmp[24];
    ASN1_STRING tmpstr;

    if (a->type == V_ASN1_UTCTIME || a->type == V_ASN1_GENERALIZEDTIME) {
        int len;

        tmpstr = *(ASN1_STRING *)a;
        len = tmpstr.length;
        ebcdic2ascii(tmp, tmpstr.data,
                     (len >= sizeof(tmp)) ? sizeof(tmp) : len);
        tmpstr.data = tmp;
        a = (ASN1_GENERALIZEDTIME *)&tmpstr;
    }
# endif
    if (a->type == V_ASN1_UTCTIME || a->type == V_ASN1_GENERALIZEDTIME)
        return (i2d_ASN1_bytes((ASN1_STRING *)a, pp,
                               a->type, V_ASN1_UNIVERSAL));
    ASN1err(ASN1_F_I2D_ASN1_TIME, ASN1_R_EXPECTING_A_TIME);
    return -1;
}
#endif

ASN1_TIME *ASN1_TIME_set(ASN1_TIME *s, time_t t)
{
    return ASN1_TIME_adj(s, t, 0, 0);
}

ASN1_TIME *ASN1_TIME_adj(ASN1_TIME *s, time_t t,
                         int offset_day, long offset_sec)
{
    struct tm *ts;
    struct tm data;

    ts = OPENSSL_gmtime(&t, &data);
    if (ts == NULL) {
        ASN1err(ASN1_F_ASN1_TIME_ADJ, ASN1_R_ERROR_GETTING_TIME);
        return NULL;
    }
    if (offset_day || offset_sec) {
        if (!OPENSSL_gmtime_adj(ts, offset_day, offset_sec))
            return NULL;
    }
    if ((ts->tm_year >= 50) && (ts->tm_year < 150))
        return ASN1_UTCTIME_adj(s, t, offset_day, offset_sec);
    return ASN1_GENERALIZEDTIME_adj(s, t, offset_day, offset_sec);
}

int ASN1_TIME_check(ASN1_TIME *t)
{
    if (t->type == V_ASN1_GENERALIZEDTIME)
        return ASN1_GENERALIZEDTIME_check(t);
    else if (t->type == V_ASN1_UTCTIME)
        return ASN1_UTCTIME_check(t);
    return 0;
}

/* Convert an ASN1_TIME structure to GeneralizedTime */
ASN1_GENERALIZEDTIME *ASN1_TIME_to_generalizedtime(ASN1_TIME *t,
                                                   ASN1_GENERALIZEDTIME **out)
{
    ASN1_GENERALIZEDTIME *ret = NULL;
    char *str;
    int newlen;

    if (!ASN1_TIME_check(t))
        return NULL;

    if (!out || !*out) {
        if (!(ret = ASN1_GENERALIZEDTIME_new()))
            goto err;
    } else {
        ret = *out;
    }

    /* If already GeneralizedTime just copy across */
    if (t->type == V_ASN1_GENERALIZEDTIME) {
        if (!ASN1_STRING_set(ret, t->data, t->length))
            goto err;
        goto done;
    }

    /* grow the string */
    if (!ASN1_STRING_set(ret, NULL, t->length + 2))
        goto err;
    /* ASN1_STRING_set() allocated 'len + 1' bytes. */
    newlen = t->length + 2 + 1;
    str = (char *)ret->data;
    /* Work out the century and prepend */
    if (t->data[0] >= '5')
        BUF_strlcpy(str, "19", newlen);
    else
        BUF_strlcpy(str, "20", newlen);

    BUF_strlcat(str, (char *)t->data, newlen);

 done:
   if (out != NULL && *out == NULL)
       *out = ret;
   return ret;

 err:
    if (out == NULL || *out != ret)
        ASN1_GENERALIZEDTIME_free(ret);
    return NULL;
}


int ASN1_TIME_set_string(ASN1_TIME *s, const char *str)
{
    ASN1_TIME t;

    t.length = strlen(str);
    t.data = (unsigned char *)str;
    t.flags = 0;

    t.type = V_ASN1_UTCTIME;

    if (!ASN1_TIME_check(&t)) {
        t.type = V_ASN1_GENERALIZEDTIME;
        if (!ASN1_TIME_check(&t))
            return 0;
    }

    if (s && !ASN1_STRING_copy((ASN1_STRING *)s, (ASN1_STRING *)&t))
        return 0;

    return 1;
}

static int asn1_time_to_tm(struct tm *tm, const ASN1_TIME *t)
{
    if (t == NULL) {
        time_t now_t;
        time(&now_t);
        if (OPENSSL_gmtime(&now_t, tm))
            return 1;
        return 0;
    }

    if (t->type == V_ASN1_UTCTIME)
        return asn1_utctime_to_tm(tm, t);
    else if (t->type == V_ASN1_GENERALIZEDTIME)
        return asn1_generalizedtime_to_tm(tm, t);

    return 0;
}

int ASN1_TIME_diff(int *pday, int *psec,
                   const ASN1_TIME *from, const ASN1_TIME *to)
{
    struct tm tm_from, tm_to;
    if (!asn1_time_to_tm(&tm_from, from))
        return 0;
    if (!asn1_time_to_tm(&tm_to, to))
        return 0;
    return OPENSSL_gmtime_diff(pday, psec, &tm_from, &tm_to);
}
/* crypto/asn1/a_type.c */
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
// #include "asn1t.h"
// #include "objects.h"

int ASN1_TYPE_get(ASN1_TYPE *a)
{
    if ((a->value.ptr != NULL) || (a->type == V_ASN1_NULL))
        return (a->type);
    else
        return (0);
}

void ASN1_TYPE_set(ASN1_TYPE *a, int type, void *value)
{
    if (a->value.ptr != NULL) {
        ASN1_TYPE **tmp_a = &a;
        ASN1_primitive_free((ASN1_VALUE **)tmp_a, NULL);
    }
    a->type = type;
    if (type == V_ASN1_BOOLEAN)
        a->value.boolean = value ? 0xff : 0;
    else
        a->value.ptr = value;
}

int ASN1_TYPE_set1(ASN1_TYPE *a, int type, const void *value)
{
    if (!value || (type == V_ASN1_BOOLEAN)) {
        void *p = (void *)value;
        ASN1_TYPE_set(a, type, p);
    } else if (type == V_ASN1_OBJECT) {
        ASN1_OBJECT *odup;
        odup = OBJ_dup(value);
        if (!odup)
            return 0;
        ASN1_TYPE_set(a, type, odup);
    } else {
        ASN1_STRING *sdup;
        sdup = ASN1_STRING_dup(value);
        if (!sdup)
            return 0;
        ASN1_TYPE_set(a, type, sdup);
    }
    return 1;
}

IMPLEMENT_STACK_OF(ASN1_TYPE)

IMPLEMENT_ASN1_SET_OF(ASN1_TYPE)

/* Returns 0 if they are equal, != 0 otherwise. */
int ASN1_TYPE_cmp(const ASN1_TYPE *a, const ASN1_TYPE *b)
{
    int result = -1;

    if (!a || !b || a->type != b->type)
        return -1;

    switch (a->type) {
    case V_ASN1_OBJECT:
        result = OBJ_cmp(a->value.object, b->value.object);
        break;
    case V_ASN1_BOOLEAN:
        result = a->value.boolean - b->value.boolean;
        break;
    case V_ASN1_NULL:
        result = 0;             /* They do not have content. */
        break;
    case V_ASN1_INTEGER:
    case V_ASN1_ENUMERATED:
    case V_ASN1_BIT_STRING:
    case V_ASN1_OCTET_STRING:
    case V_ASN1_SEQUENCE:
    case V_ASN1_SET:
    case V_ASN1_NUMERICSTRING:
    case V_ASN1_PRINTABLESTRING:
    case V_ASN1_T61STRING:
    case V_ASN1_VIDEOTEXSTRING:
    case V_ASN1_IA5STRING:
    case V_ASN1_UTCTIME:
    case V_ASN1_GENERALIZEDTIME:
    case V_ASN1_GRAPHICSTRING:
    case V_ASN1_VISIBLESTRING:
    case V_ASN1_GENERALSTRING:
    case V_ASN1_UNIVERSALSTRING:
    case V_ASN1_BMPSTRING:
    case V_ASN1_UTF8STRING:
    case V_ASN1_OTHER:
    default:
        result = ASN1_STRING_cmp((ASN1_STRING *)a->value.ptr,
                                 (ASN1_STRING *)b->value.ptr);
        break;
    }

    return result;
}
/* crypto/asn1/a_utctm.c */
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
// #include "cryptlib.h"
// #include "o_time.h"
// #include "asn1.h"
// #include "asn1_locl.h"

#if 0
int i2d_ASN1_UTCTIME(ASN1_UTCTIME *a, unsigned char **pp)
{
# ifndef CHARSET_EBCDIC
    return (i2d_ASN1_bytes((ASN1_STRING *)a, pp,
                           V_ASN1_UTCTIME, V_ASN1_UNIVERSAL));
# else
    /* KLUDGE! We convert to ascii before writing DER */
    int len;
    char tmp[24];
    ASN1_STRING x = *(ASN1_STRING *)a;

    len = x.length;
    ebcdic2ascii(tmp, x.data, (len >= sizeof(tmp)) ? sizeof(tmp) : len);
    x.data = tmp;
    return i2d_ASN1_bytes(&x, pp, V_ASN1_UTCTIME, V_ASN1_UNIVERSAL);
# endif
}

ASN1_UTCTIME *d2i_ASN1_UTCTIME(ASN1_UTCTIME **a, unsigned char **pp,
                               long length)
{
    ASN1_UTCTIME *ret = NULL;

    ret = (ASN1_UTCTIME *)d2i_ASN1_bytes((ASN1_STRING **)a, pp, length,
                                         V_ASN1_UTCTIME, V_ASN1_UNIVERSAL);
    if (ret == NULL) {
        ASN1err(ASN1_F_D2I_ASN1_UTCTIME, ERR_R_NESTED_ASN1_ERROR);
        return (NULL);
    }
# ifdef CHARSET_EBCDIC
    ascii2ebcdic(ret->data, ret->data, ret->length);
# endif
    if (!ASN1_UTCTIME_check(ret)) {
        ASN1err(ASN1_F_D2I_ASN1_UTCTIME, ASN1_R_INVALID_TIME_FORMAT);
        goto err;
    }

    return (ret);
 err:
    if ((ret != NULL) && ((a == NULL) || (*a != ret)))
        M_ASN1_UTCTIME_free(ret);
    return (NULL);
}

#endif

int asn1_utctime_to_tm(struct tm *tm, const ASN1_UTCTIME *d)
{
    static const int min[8] = { 0, 1, 1, 0, 0, 0, 0, 0 };
    static const int max[8] = { 99, 12, 31, 23, 59, 59, 12, 59 };
    char *a;
    int n, i, l, o;

    if (d->type != V_ASN1_UTCTIME)
        return (0);
    l = d->length;
    a = (char *)d->data;
    o = 0;

    if (l < 11)
        goto err;
    for (i = 0; i < 6; i++) {
        if ((i == 5) && ((a[o] == 'Z') || (a[o] == '+') || (a[o] == '-'))) {
            i++;
            if (tm)
                tm->tm_sec = 0;
            break;
        }
        if ((a[o] < '0') || (a[o] > '9'))
            goto err;
        n = a[o] - '0';
        if (++o > l)
            goto err;

        if ((a[o] < '0') || (a[o] > '9'))
            goto err;
        n = (n * 10) + a[o] - '0';
        if (++o > l)
            goto err;

        if ((n < min[i]) || (n > max[i]))
            goto err;
        if (tm) {
            switch (i) {
            case 0:
                tm->tm_year = n < 50 ? n + 100 : n;
                break;
            case 1:
                tm->tm_mon = n - 1;
                break;
            case 2:
                tm->tm_mday = n;
                break;
            case 3:
                tm->tm_hour = n;
                break;
            case 4:
                tm->tm_min = n;
                break;
            case 5:
                tm->tm_sec = n;
                break;
            }
        }
    }
    if (a[o] == 'Z')
        o++;
    else if ((a[o] == '+') || (a[o] == '-')) {
        int offsign = a[o] == '-' ? 1 : -1, offset = 0;
        o++;
        if (o + 4 > l)
            goto err;
        for (i = 6; i < 8; i++) {
            if ((a[o] < '0') || (a[o] > '9'))
                goto err;
            n = a[o] - '0';
            o++;
            if ((a[o] < '0') || (a[o] > '9'))
                goto err;
            n = (n * 10) + a[o] - '0';
            if ((n < min[i]) || (n > max[i]))
                goto err;
            if (tm) {
                if (i == 6)
                    offset = n * 3600;
                else if (i == 7)
                    offset += n * 60;
            }
            o++;
        }
        if (offset && !OPENSSL_gmtime_adj(tm, 0, offset * offsign))
            return 0;
    }
    return o == l;
 err:
    return 0;
}

int ASN1_UTCTIME_check(const ASN1_UTCTIME *d)
{
    return asn1_utctime_to_tm(NULL, d);
}

int ASN1_UTCTIME_set_string(ASN1_UTCTIME *s, const char *str)
{
    ASN1_UTCTIME t;

    t.type = V_ASN1_UTCTIME;
    t.length = strlen(str);
    t.data = (unsigned char *)str;
    if (ASN1_UTCTIME_check(&t)) {
        if (s != NULL) {
            if (!ASN1_STRING_set((ASN1_STRING *)s,
                                 (unsigned char *)str, t.length))
                return 0;
            s->type = V_ASN1_UTCTIME;
        }
        return (1);
    } else
        return (0);
}

ASN1_UTCTIME *ASN1_UTCTIME_set(ASN1_UTCTIME *s, time_t t)
{
    return ASN1_UTCTIME_adj(s, t, 0, 0);
}

ASN1_UTCTIME *ASN1_UTCTIME_adj(ASN1_UTCTIME *s, time_t t,
                               int offset_day, long offset_sec)
{
    char *p;
    struct tm *ts;
    struct tm data;
    size_t len = 20;
    int free_s = 0;

    if (s == NULL) {
        free_s = 1;
        s = M_ASN1_UTCTIME_new();
    }
    if (s == NULL)
        goto err;

    ts = OPENSSL_gmtime(&t, &data);
    if (ts == NULL)
        goto err;

    if (offset_day || offset_sec) {
        if (!OPENSSL_gmtime_adj(ts, offset_day, offset_sec))
            goto err;
    }

    if ((ts->tm_year < 50) || (ts->tm_year >= 150))
        goto err;

    p = (char *)s->data;
    if ((p == NULL) || ((size_t)s->length < len)) {
        p = OPENSSL_malloc(len);
        if (p == NULL) {
            ASN1err(ASN1_F_ASN1_UTCTIME_ADJ, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        if (s->data != NULL)
            OPENSSL_free(s->data);
        s->data = (unsigned char *)p;
    }

    BIO_snprintf(p, len, "%02d%02d%02d%02d%02d%02dZ", ts->tm_year % 100,
                 ts->tm_mon + 1, ts->tm_mday, ts->tm_hour, ts->tm_min,
                 ts->tm_sec);
    s->length = strlen(p);
    s->type = V_ASN1_UTCTIME;
#ifdef CHARSET_EBCDIC_not
    ebcdic2ascii(s->data, s->data, s->length);
#endif
    return (s);
 err:
    if (free_s && s)
        M_ASN1_UTCTIME_free(s);
    return NULL;
}

int ASN1_UTCTIME_cmp_time_t(const ASN1_UTCTIME *s, time_t t)
{
    struct tm stm, ttm;
    int day, sec;

    if (!asn1_utctime_to_tm(&stm, s))
        return -2;

    if (!OPENSSL_gmtime(&t, &ttm))
        return -2;

    if (!OPENSSL_gmtime_diff(&day, &sec, &ttm, &stm))
        return -2;

    if (day > 0)
        return 1;
    if (day < 0)
        return -1;
    if (sec > 0)
        return 1;
    if (sec < 0)
        return -1;
    return 0;
}

#if 0
time_t ASN1_UTCTIME_get(const ASN1_UTCTIME *s)
{
    struct tm tm;
    int offset;

    memset(&tm, '\0', sizeof(tm));

# define g2(p) (((p)[0]-'0')*10+(p)[1]-'0')
    tm.tm_year = g2(s->data);
    if (tm.tm_year < 50)
        tm.tm_year += 100;
    tm.tm_mon = g2(s->data + 2) - 1;
    tm.tm_mday = g2(s->data + 4);
    tm.tm_hour = g2(s->data + 6);
    tm.tm_min = g2(s->data + 8);
    tm.tm_sec = g2(s->data + 10);
    if (s->data[12] == 'Z')
        offset = 0;
    else {
        offset = g2(s->data + 13) * 60 + g2(s->data + 15);
        if (s->data[12] == '-')
            offset = -offset;
    }
# undef g2

    /*
     * FIXME: mktime assumes the current timezone
     * instead of UTC, and unless we rewrite OpenSSL
     * in Lisp we cannot locally change the timezone
     * without possibly interfering with other parts
     * of the program. timegm, which uses UTC, is
     * non-standard.
     * Also time_t is inappropriate for general
     * UTC times because it may a 32 bit type.
     */
    return mktime(&tm) - offset * 60;
}
#endif
/* crypto/asn1/a_utf8.c */
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

/* UTF8 utilities */

/*-
 * This parses a UTF8 string one character at a time. It is passed a pointer
 * to the string and the length of the string. It sets 'value' to the value of
 * the current character. It returns the number of characters read or a
 * negative error code:
 * -1 = string too short
 * -2 = illegal character
 * -3 = subsequent characters not of the form 10xxxxxx
 * -4 = character encoded incorrectly (not minimal length).
 */

int UTF8_getc(const unsigned char *str, int len, unsigned long *val)
{
    const unsigned char *p;
    unsigned long value;
    int ret;
    if (len <= 0)
        return 0;
    p = str;

    /* Check syntax and work out the encoded value (if correct) */
    if ((*p & 0x80) == 0) {
        value = *p++ & 0x7f;
        ret = 1;
    } else if ((*p & 0xe0) == 0xc0) {
        if (len < 2)
            return -1;
        if ((p[1] & 0xc0) != 0x80)
            return -3;
        value = (*p++ & 0x1f) << 6;
        value |= *p++ & 0x3f;
        if (value < 0x80)
            return -4;
        ret = 2;
    } else if ((*p & 0xf0) == 0xe0) {
        if (len < 3)
            return -1;
        if (((p[1] & 0xc0) != 0x80)
            || ((p[2] & 0xc0) != 0x80))
            return -3;
        value = (*p++ & 0xf) << 12;
        value |= (*p++ & 0x3f) << 6;
        value |= *p++ & 0x3f;
        if (value < 0x800)
            return -4;
        ret = 3;
    } else if ((*p & 0xf8) == 0xf0) {
        if (len < 4)
            return -1;
        if (((p[1] & 0xc0) != 0x80)
            || ((p[2] & 0xc0) != 0x80)
            || ((p[3] & 0xc0) != 0x80))
            return -3;
        value = ((unsigned long)(*p++ & 0x7)) << 18;
        value |= (*p++ & 0x3f) << 12;
        value |= (*p++ & 0x3f) << 6;
        value |= *p++ & 0x3f;
        if (value < 0x10000)
            return -4;
        ret = 4;
    } else if ((*p & 0xfc) == 0xf8) {
        if (len < 5)
            return -1;
        if (((p[1] & 0xc0) != 0x80)
            || ((p[2] & 0xc0) != 0x80)
            || ((p[3] & 0xc0) != 0x80)
            || ((p[4] & 0xc0) != 0x80))
            return -3;
        value = ((unsigned long)(*p++ & 0x3)) << 24;
        value |= ((unsigned long)(*p++ & 0x3f)) << 18;
        value |= ((unsigned long)(*p++ & 0x3f)) << 12;
        value |= (*p++ & 0x3f) << 6;
        value |= *p++ & 0x3f;
        if (value < 0x200000)
            return -4;
        ret = 5;
    } else if ((*p & 0xfe) == 0xfc) {
        if (len < 6)
            return -1;
        if (((p[1] & 0xc0) != 0x80)
            || ((p[2] & 0xc0) != 0x80)
            || ((p[3] & 0xc0) != 0x80)
            || ((p[4] & 0xc0) != 0x80)
            || ((p[5] & 0xc0) != 0x80))
            return -3;
        value = ((unsigned long)(*p++ & 0x1)) << 30;
        value |= ((unsigned long)(*p++ & 0x3f)) << 24;
        value |= ((unsigned long)(*p++ & 0x3f)) << 18;
        value |= ((unsigned long)(*p++ & 0x3f)) << 12;
        value |= (*p++ & 0x3f) << 6;
        value |= *p++ & 0x3f;
        if (value < 0x4000000)
            return -4;
        ret = 6;
    } else
        return -2;
    *val = value;
    return ret;
}

/*
 * This takes a character 'value' and writes the UTF8 encoded value in 'str'
 * where 'str' is a buffer containing 'len' characters. Returns the number of
 * characters written or -1 if 'len' is too small. 'str' can be set to NULL
 * in which case it just returns the number of characters. It will need at
 * most 6 characters.
 */

int UTF8_putc(unsigned char *str, int len, unsigned long value)
{
    if (!str)
        len = 6;                /* Maximum we will need */
    else if (len <= 0)
        return -1;
    if (value < 0x80) {
        if (str)
            *str = (unsigned char)value;
        return 1;
    }
    if (value < 0x800) {
        if (len < 2)
            return -1;
        if (str) {
            *str++ = (unsigned char)(((value >> 6) & 0x1f) | 0xc0);
            *str = (unsigned char)((value & 0x3f) | 0x80);
        }
        return 2;
    }
    if (value < 0x10000) {
        if (len < 3)
            return -1;
        if (str) {
            *str++ = (unsigned char)(((value >> 12) & 0xf) | 0xe0);
            *str++ = (unsigned char)(((value >> 6) & 0x3f) | 0x80);
            *str = (unsigned char)((value & 0x3f) | 0x80);
        }
        return 3;
    }
    if (value < 0x200000) {
        if (len < 4)
            return -1;
        if (str) {
            *str++ = (unsigned char)(((value >> 18) & 0x7) | 0xf0);
            *str++ = (unsigned char)(((value >> 12) & 0x3f) | 0x80);
            *str++ = (unsigned char)(((value >> 6) & 0x3f) | 0x80);
            *str = (unsigned char)((value & 0x3f) | 0x80);
        }
        return 4;
    }
    if (value < 0x4000000) {
        if (len < 5)
            return -1;
        if (str) {
            *str++ = (unsigned char)(((value >> 24) & 0x3) | 0xf8);
            *str++ = (unsigned char)(((value >> 18) & 0x3f) | 0x80);
            *str++ = (unsigned char)(((value >> 12) & 0x3f) | 0x80);
            *str++ = (unsigned char)(((value >> 6) & 0x3f) | 0x80);
            *str = (unsigned char)((value & 0x3f) | 0x80);
        }
        return 5;
    }
    if (len < 6)
        return -1;
    if (str) {
        *str++ = (unsigned char)(((value >> 30) & 0x1) | 0xfc);
        *str++ = (unsigned char)(((value >> 24) & 0x3f) | 0x80);
        *str++ = (unsigned char)(((value >> 18) & 0x3f) | 0x80);
        *str++ = (unsigned char)(((value >> 12) & 0x3f) | 0x80);
        *str++ = (unsigned char)(((value >> 6) & 0x3f) | 0x80);
        *str = (unsigned char)((value & 0x3f) | 0x80);
    }
    return 6;
}
/* crypto/asn1/a_verify.c */
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

// #include "cryptlib.h"
// #include "asn1_locl.h"

#ifndef NO_SYS_TYPES_H
# include <sys/types.h>
#endif

// #include "bn.h"
// #include "x509.h"
// #include "objects.h"
// #include "buffer.h"
// #include "evp.h"

#ifndef NO_ASN1_OLD

int ASN1_verify(i2d_of_void *i2d, X509_ALGOR *a, ASN1_BIT_STRING *signature,
                char *data, EVP_PKEY *pkey)
{
    EVP_MD_CTX ctx;
    const EVP_MD *type;
    unsigned char *p, *buf_in = NULL;
    int ret = -1, i, inl;

    EVP_MD_CTX_init(&ctx);
    i = OBJ_obj2nid(a->algorithm);
    type = EVP_get_digestbyname(OBJ_nid2sn(i));
    if (type == NULL) {
        ASN1err(ASN1_F_ASN1_VERIFY, ASN1_R_UNKNOWN_MESSAGE_DIGEST_ALGORITHM);
        goto err;
    }

    if (signature->type == V_ASN1_BIT_STRING && signature->flags & 0x7) {
        ASN1err(ASN1_F_ASN1_VERIFY, ASN1_R_INVALID_BIT_STRING_BITS_LEFT);
        goto err;
    }

    inl = i2d(data, NULL);
    buf_in = OPENSSL_malloc((unsigned int)inl);
    if (buf_in == NULL) {
        ASN1err(ASN1_F_ASN1_VERIFY, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    p = buf_in;

    i2d(data, &p);
    if (!EVP_VerifyInit_ex(&ctx, type, NULL)
        || !EVP_VerifyUpdate(&ctx, (unsigned char *)buf_in, inl)) {
        ASN1err(ASN1_F_ASN1_VERIFY, ERR_R_EVP_LIB);
        ret = 0;
        goto err;
    }

    OPENSSL_cleanse(buf_in, (unsigned int)inl);
    OPENSSL_free(buf_in);

    if (EVP_VerifyFinal(&ctx, (unsigned char *)signature->data,
                        (unsigned int)signature->length, pkey) <= 0) {
        ASN1err(ASN1_F_ASN1_VERIFY, ERR_R_EVP_LIB);
        ret = 0;
        goto err;
    }
    /*
     * we don't need to zero the 'ctx' because we just checked public
     * information
     */
    /* memset(&ctx,0,sizeof(ctx)); */
    ret = 1;
 err:
    EVP_MD_CTX_cleanup(&ctx);
    return (ret);
}

#endif

int ASN1_item_verify(const ASN1_ITEM *it, X509_ALGOR *a,
                     ASN1_BIT_STRING *signature, void *asn, EVP_PKEY *pkey)
{
    EVP_MD_CTX ctx;
    unsigned char *buf_in = NULL;
    int ret = -1, inl;

    int mdnid, pknid;

    if (!pkey) {
        ASN1err(ASN1_F_ASN1_ITEM_VERIFY, ERR_R_PASSED_NULL_PARAMETER);
        return -1;
    }

    if (signature->type == V_ASN1_BIT_STRING && signature->flags & 0x7) {
        ASN1err(ASN1_F_ASN1_ITEM_VERIFY, ASN1_R_INVALID_BIT_STRING_BITS_LEFT);
        return -1;
    }

    EVP_MD_CTX_init(&ctx);

    /* Convert signature OID into digest and public key OIDs */
    if (!OBJ_find_sigid_algs(OBJ_obj2nid(a->algorithm), &mdnid, &pknid)) {
        ASN1err(ASN1_F_ASN1_ITEM_VERIFY, ASN1_R_UNKNOWN_SIGNATURE_ALGORITHM);
        goto err;
    }
    if (mdnid == NID_undef) {
        if (!pkey->ameth || !pkey->ameth->item_verify) {
            ASN1err(ASN1_F_ASN1_ITEM_VERIFY,
                    ASN1_R_UNKNOWN_SIGNATURE_ALGORITHM);
            goto err;
        }
        ret = pkey->ameth->item_verify(&ctx, it, asn, a, signature, pkey);
        /*
         * Return value of 2 means carry on, anything else means we exit
         * straight away: either a fatal error of the underlying verification
         * routine handles all verification.
         */
        if (ret != 2)
            goto err;
        ret = -1;
    } else {
        const EVP_MD *type;
        type = EVP_get_digestbynid(mdnid);
        if (type == NULL) {
            ASN1err(ASN1_F_ASN1_ITEM_VERIFY,
                    ASN1_R_UNKNOWN_MESSAGE_DIGEST_ALGORITHM);
            goto err;
        }

        /* Check public key OID matches public key type */
        if (EVP_PKEY_type(pknid) != pkey->ameth->pkey_id) {
            ASN1err(ASN1_F_ASN1_ITEM_VERIFY, ASN1_R_WRONG_PUBLIC_KEY_TYPE);
            goto err;
        }

        if (!EVP_DigestVerifyInit(&ctx, NULL, type, NULL, pkey)) {
            ASN1err(ASN1_F_ASN1_ITEM_VERIFY, ERR_R_EVP_LIB);
            ret = 0;
            goto err;
        }

    }

    inl = ASN1_item_i2d(asn, &buf_in, it);

    if (buf_in == NULL) {
        ASN1err(ASN1_F_ASN1_ITEM_VERIFY, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (!EVP_DigestVerifyUpdate(&ctx, buf_in, inl)) {
        ASN1err(ASN1_F_ASN1_ITEM_VERIFY, ERR_R_EVP_LIB);
        ret = 0;
        goto err;
    }

    OPENSSL_cleanse(buf_in, (unsigned int)inl);
    OPENSSL_free(buf_in);

    if (EVP_DigestVerifyFinal(&ctx, signature->data,
                              (size_t)signature->length) <= 0) {
        ASN1err(ASN1_F_ASN1_ITEM_VERIFY, ERR_R_EVP_LIB);
        ret = 0;
        goto err;
    }
    /*
     * we don't need to zero the 'ctx' because we just checked public
     * information
     */
    /* memset(&ctx,0,sizeof(ctx)); */
    ret = 1;
 err:
    EVP_MD_CTX_cleanup(&ctx);
    return (ret);
}
