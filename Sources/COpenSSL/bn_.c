/* crypto/bn/bn_add.c */
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
#include "cryptlib.h"
#include "bn_lcl.h"

/* r can == a or b */
int BN_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b)
{
    const BIGNUM *tmp;
    int a_neg = a->neg, ret;

    bn_check_top(a);
    bn_check_top(b);

    /*-
     *  a +  b      a+b
     *  a + -b      a-b
     * -a +  b      b-a
     * -a + -b      -(a+b)
     */
    if (a_neg ^ b->neg) {
        /* only one is negative */
        if (a_neg) {
            tmp = a;
            a = b;
            b = tmp;
        }

        /* we are now a - b */

        if (BN_ucmp(a, b) < 0) {
            if (!BN_usub(r, b, a))
                return (0);
            r->neg = 1;
        } else {
            if (!BN_usub(r, a, b))
                return (0);
            r->neg = 0;
        }
        return (1);
    }

    ret = BN_uadd(r, a, b);
    r->neg = a_neg;
    bn_check_top(r);
    return ret;
}

/* unsigned add of b to a */
int BN_uadd(BIGNUM *r, const BIGNUM *a, const BIGNUM *b)
{
    int max, min, dif;
    BN_ULONG *ap, *bp, *rp, carry, t1, t2;
    const BIGNUM *tmp;

    bn_check_top(a);
    bn_check_top(b);

    if (a->top < b->top) {
        tmp = a;
        a = b;
        b = tmp;
    }
    max = a->top;
    min = b->top;
    dif = max - min;

    if (bn_wexpand(r, max + 1) == NULL)
        return 0;

    r->top = max;

    ap = a->d;
    bp = b->d;
    rp = r->d;

    carry = bn_add_words(rp, ap, bp, min);
    rp += min;
    ap += min;
    bp += min;

    if (carry) {
        while (dif) {
            dif--;
            t1 = *(ap++);
            t2 = (t1 + 1) & BN_MASK2;
            *(rp++) = t2;
            if (t2) {
                carry = 0;
                break;
            }
        }
        if (carry) {
            /* carry != 0 => dif == 0 */
            *rp = 1;
            r->top++;
        }
    }
    if (dif && rp != ap)
        while (dif--)
            /* copy remaining words if ap != rp */
            *(rp++) = *(ap++);
    r->neg = 0;
    bn_check_top(r);
    return 1;
}

/* unsigned subtraction of b from a, a must be larger than b. */
int BN_usub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b)
{
    int max, min, dif;
    register BN_ULONG t1, t2, *ap, *bp, *rp;
    int i, carry;
#if defined(IRIX_CC_BUG) && !defined(LINT)
    int dummy;
#endif

    bn_check_top(a);
    bn_check_top(b);

    max = a->top;
    min = b->top;
    dif = max - min;

    if (dif < 0) {              /* hmm... should not be happening */
        BNerr(BN_F_BN_USUB, BN_R_ARG2_LT_ARG3);
        return (0);
    }

    if (bn_wexpand(r, max) == NULL)
        return (0);

    ap = a->d;
    bp = b->d;
    rp = r->d;

#if 1
    carry = 0;
    for (i = min; i != 0; i--) {
        t1 = *(ap++);
        t2 = *(bp++);
        if (carry) {
            carry = (t1 <= t2);
            t1 = (t1 - t2 - 1) & BN_MASK2;
        } else {
            carry = (t1 < t2);
            t1 = (t1 - t2) & BN_MASK2;
        }
# if defined(IRIX_CC_BUG) && !defined(LINT)
        dummy = t1;
# endif
        *(rp++) = t1 & BN_MASK2;
    }
#else
    carry = bn_sub_words(rp, ap, bp, min);
    ap += min;
    bp += min;
    rp += min;
#endif
    if (carry) {                /* subtracted */
        if (!dif)
            /* error: a < b */
            return 0;
        while (dif) {
            dif--;
            t1 = *(ap++);
            t2 = (t1 - 1) & BN_MASK2;
            *(rp++) = t2;
            if (t1)
                break;
        }
    }
#if 0
    memcpy(rp, ap, sizeof(*rp) * (max - i));
#else
    if (rp != ap) {
        for (;;) {
            if (!dif--)
                break;
            rp[0] = ap[0];
            if (!dif--)
                break;
            rp[1] = ap[1];
            if (!dif--)
                break;
            rp[2] = ap[2];
            if (!dif--)
                break;
            rp[3] = ap[3];
            rp += 4;
            ap += 4;
        }
    }
#endif

    r->top = max;
    r->neg = 0;
    bn_correct_top(r);
    return (1);
}

int BN_sub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b)
{
    int max;
    int add = 0, neg = 0;
    const BIGNUM *tmp;

    bn_check_top(a);
    bn_check_top(b);

    /*-
     *  a -  b      a-b
     *  a - -b      a+b
     * -a -  b      -(a+b)
     * -a - -b      b-a
     */
    if (a->neg) {
        if (b->neg) {
            tmp = a;
            a = b;
            b = tmp;
        } else {
            add = 1;
            neg = 1;
        }
    } else {
        if (b->neg) {
            add = 1;
            neg = 0;
        }
    }

    if (add) {
        if (!BN_uadd(r, a, b))
            return (0);
        r->neg = neg;
        return (1);
    }

    /* We are actually doing a - b :-) */

    max = (a->top > b->top) ? a->top : b->top;
    if (bn_wexpand(r, max) == NULL)
        return (0);
    if (BN_ucmp(a, b) < 0) {
        if (!BN_usub(r, b, a))
            return (0);
        r->neg = 1;
    } else {
        if (!BN_usub(r, a, b))
            return (0);
        r->neg = 0;
    }
    bn_check_top(r);
    return (1);
}
/* crypto/bn/bn_asm.c */
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

#ifndef BN_DEBUG
# undef NDEBUG                  /* avoid conflicting definitions */
# define NDEBUG
#endif

#include <stdio.h>
#include <assert.h>
// #include "cryptlib.h"
// #include "bn_lcl.h"

#if defined(BN_LLONG) || defined(BN_UMULT_HIGH)

BN_ULONG bn_mul_add_words(BN_ULONG *rp, const BN_ULONG *ap, int num,
                          BN_ULONG w)
{
    BN_ULONG c1 = 0;

    assert(num >= 0);
    if (num <= 0)
        return (c1);

# ifndef OPENSSL_SMALL_FOOTPRINT
    while (num & ~3) {
        mul_add(rp[0], ap[0], w, c1);
        mul_add(rp[1], ap[1], w, c1);
        mul_add(rp[2], ap[2], w, c1);
        mul_add(rp[3], ap[3], w, c1);
        ap += 4;
        rp += 4;
        num -= 4;
    }
# endif
    while (num) {
        mul_add(rp[0], ap[0], w, c1);
        ap++;
        rp++;
        num--;
    }

    return (c1);
}

BN_ULONG bn_mul_words(BN_ULONG *rp, const BN_ULONG *ap, int num, BN_ULONG w)
{
    BN_ULONG c1 = 0;

    assert(num >= 0);
    if (num <= 0)
        return (c1);

# ifndef OPENSSL_SMALL_FOOTPRINT
    while (num & ~3) {
        mul(rp[0], ap[0], w, c1);
        mul(rp[1], ap[1], w, c1);
        mul(rp[2], ap[2], w, c1);
        mul(rp[3], ap[3], w, c1);
        ap += 4;
        rp += 4;
        num -= 4;
    }
# endif
    while (num) {
        mul(rp[0], ap[0], w, c1);
        ap++;
        rp++;
        num--;
    }
    return (c1);
}

void bn_sqr_words(BN_ULONG *r, const BN_ULONG *a, int n)
{
    assert(n >= 0);
    if (n <= 0)
        return;

# ifndef OPENSSL_SMALL_FOOTPRINT
    while (n & ~3) {
        sqr(r[0], r[1], a[0]);
        sqr(r[2], r[3], a[1]);
        sqr(r[4], r[5], a[2]);
        sqr(r[6], r[7], a[3]);
        a += 4;
        r += 8;
        n -= 4;
    }
# endif
    while (n) {
        sqr(r[0], r[1], a[0]);
        a++;
        r += 2;
        n--;
    }
}

#else                           /* !(defined(BN_LLONG) ||
                                 * defined(BN_UMULT_HIGH)) */

BN_ULONG bn_mul_add_words(BN_ULONG *rp, const BN_ULONG *ap, int num,
                          BN_ULONG w)
{
    BN_ULONG c = 0;
    BN_ULONG bl, bh;

    assert(num >= 0);
    if (num <= 0)
        return ((BN_ULONG)0);

    bl = LBITS(w);
    bh = HBITS(w);

# ifndef OPENSSL_SMALL_FOOTPRINT
    while (num & ~3) {
        mul_add(rp[0], ap[0], bl, bh, c);
        mul_add(rp[1], ap[1], bl, bh, c);
        mul_add(rp[2], ap[2], bl, bh, c);
        mul_add(rp[3], ap[3], bl, bh, c);
        ap += 4;
        rp += 4;
        num -= 4;
    }
# endif
    while (num) {
        mul_add(rp[0], ap[0], bl, bh, c);
        ap++;
        rp++;
        num--;
    }
    return (c);
}

BN_ULONG bn_mul_words(BN_ULONG *rp, const BN_ULONG *ap, int num, BN_ULONG w)
{
    BN_ULONG carry = 0;
    BN_ULONG bl, bh;

    assert(num >= 0);
    if (num <= 0)
        return ((BN_ULONG)0);

    bl = LBITS(w);
    bh = HBITS(w);

# ifndef OPENSSL_SMALL_FOOTPRINT
    while (num & ~3) {
        mul(rp[0], ap[0], bl, bh, carry);
        mul(rp[1], ap[1], bl, bh, carry);
        mul(rp[2], ap[2], bl, bh, carry);
        mul(rp[3], ap[3], bl, bh, carry);
        ap += 4;
        rp += 4;
        num -= 4;
    }
# endif
    while (num) {
        mul(rp[0], ap[0], bl, bh, carry);
        ap++;
        rp++;
        num--;
    }
    return (carry);
}

void bn_sqr_words(BN_ULONG *r, const BN_ULONG *a, int n)
{
    assert(n >= 0);
    if (n <= 0)
        return;

# ifndef OPENSSL_SMALL_FOOTPRINT
    while (n & ~3) {
        sqr64(r[0], r[1], a[0]);
        sqr64(r[2], r[3], a[1]);
        sqr64(r[4], r[5], a[2]);
        sqr64(r[6], r[7], a[3]);
        a += 4;
        r += 8;
        n -= 4;
    }
# endif
    while (n) {
        sqr64(r[0], r[1], a[0]);
        a++;
        r += 2;
        n--;
    }
}

#endif                          /* !(defined(BN_LLONG) ||
                                 * defined(BN_UMULT_HIGH)) */

#if defined(BN_LLONG) && defined(BN_DIV2W)

BN_ULONG bn_div_words(BN_ULONG h, BN_ULONG l, BN_ULONG d)
{
    return ((BN_ULONG)(((((BN_ULLONG) h) << BN_BITS2) | l) / (BN_ULLONG) d));
}

#else

/* Divide h,l by d and return the result. */
/* I need to test this some more :-( */
BN_ULONG bn_div_words(BN_ULONG h, BN_ULONG l, BN_ULONG d)
{
    BN_ULONG dh, dl, q, ret = 0, th, tl, t;
    int i, count = 2;

    if (d == 0)
        return (BN_MASK2);

    i = BN_num_bits_word(d);
    assert((i == BN_BITS2) || (h <= (BN_ULONG)1 << i));

    i = BN_BITS2 - i;
    if (h >= d)
        h -= d;

    if (i) {
        d <<= i;
        h = (h << i) | (l >> (BN_BITS2 - i));
        l <<= i;
    }
    dh = (d & BN_MASK2h) >> BN_BITS4;
    dl = (d & BN_MASK2l);
    for (;;) {
        if ((h >> BN_BITS4) == dh)
            q = BN_MASK2l;
        else
            q = h / dh;

        th = q * dh;
        tl = dl * q;
        for (;;) {
            t = h - th;
            if ((t & BN_MASK2h) ||
                ((tl) <= ((t << BN_BITS4) | ((l & BN_MASK2h) >> BN_BITS4))))
                break;
            q--;
            th -= dh;
            tl -= dl;
        }
        t = (tl >> BN_BITS4);
        tl = (tl << BN_BITS4) & BN_MASK2h;
        th += t;

        if (l < tl)
            th++;
        l -= tl;
        if (h < th) {
            h += d;
            q--;
        }
        h -= th;

        if (--count == 0)
            break;

        ret = q << BN_BITS4;
        h = ((h << BN_BITS4) | (l >> BN_BITS4)) & BN_MASK2;
        l = (l & BN_MASK2l) << BN_BITS4;
    }
    ret |= q;
    return (ret);
}
#endif                          /* !defined(BN_LLONG) && defined(BN_DIV2W) */

#ifdef BN_LLONG
BN_ULONG bn_add_words(BN_ULONG *r, const BN_ULONG *a, const BN_ULONG *b,
                      int n)
{
    BN_ULLONG ll = 0;

    assert(n >= 0);
    if (n <= 0)
        return ((BN_ULONG)0);

# ifndef OPENSSL_SMALL_FOOTPRINT
    while (n & ~3) {
        ll += (BN_ULLONG) a[0] + b[0];
        r[0] = (BN_ULONG)ll & BN_MASK2;
        ll >>= BN_BITS2;
        ll += (BN_ULLONG) a[1] + b[1];
        r[1] = (BN_ULONG)ll & BN_MASK2;
        ll >>= BN_BITS2;
        ll += (BN_ULLONG) a[2] + b[2];
        r[2] = (BN_ULONG)ll & BN_MASK2;
        ll >>= BN_BITS2;
        ll += (BN_ULLONG) a[3] + b[3];
        r[3] = (BN_ULONG)ll & BN_MASK2;
        ll >>= BN_BITS2;
        a += 4;
        b += 4;
        r += 4;
        n -= 4;
    }
# endif
    while (n) {
        ll += (BN_ULLONG) a[0] + b[0];
        r[0] = (BN_ULONG)ll & BN_MASK2;
        ll >>= BN_BITS2;
        a++;
        b++;
        r++;
        n--;
    }
    return ((BN_ULONG)ll);
}
#else                           /* !BN_LLONG */
BN_ULONG bn_add_words(BN_ULONG *r, const BN_ULONG *a, const BN_ULONG *b,
                      int n)
{
    BN_ULONG c, l, t;

    assert(n >= 0);
    if (n <= 0)
        return ((BN_ULONG)0);

    c = 0;
# ifndef OPENSSL_SMALL_FOOTPRINT
    while (n & ~3) {
        t = a[0];
        t = (t + c) & BN_MASK2;
        c = (t < c);
        l = (t + b[0]) & BN_MASK2;
        c += (l < t);
        r[0] = l;
        t = a[1];
        t = (t + c) & BN_MASK2;
        c = (t < c);
        l = (t + b[1]) & BN_MASK2;
        c += (l < t);
        r[1] = l;
        t = a[2];
        t = (t + c) & BN_MASK2;
        c = (t < c);
        l = (t + b[2]) & BN_MASK2;
        c += (l < t);
        r[2] = l;
        t = a[3];
        t = (t + c) & BN_MASK2;
        c = (t < c);
        l = (t + b[3]) & BN_MASK2;
        c += (l < t);
        r[3] = l;
        a += 4;
        b += 4;
        r += 4;
        n -= 4;
    }
# endif
    while (n) {
        t = a[0];
        t = (t + c) & BN_MASK2;
        c = (t < c);
        l = (t + b[0]) & BN_MASK2;
        c += (l < t);
        r[0] = l;
        a++;
        b++;
        r++;
        n--;
    }
    return ((BN_ULONG)c);
}
#endif                          /* !BN_LLONG */

BN_ULONG bn_sub_words(BN_ULONG *r, const BN_ULONG *a, const BN_ULONG *b,
                      int n)
{
    BN_ULONG t1, t2;
    int c = 0;

    assert(n >= 0);
    if (n <= 0)
        return ((BN_ULONG)0);

#ifndef OPENSSL_SMALL_FOOTPRINT
    while (n & ~3) {
        t1 = a[0];
        t2 = b[0];
        r[0] = (t1 - t2 - c) & BN_MASK2;
        if (t1 != t2)
            c = (t1 < t2);
        t1 = a[1];
        t2 = b[1];
        r[1] = (t1 - t2 - c) & BN_MASK2;
        if (t1 != t2)
            c = (t1 < t2);
        t1 = a[2];
        t2 = b[2];
        r[2] = (t1 - t2 - c) & BN_MASK2;
        if (t1 != t2)
            c = (t1 < t2);
        t1 = a[3];
        t2 = b[3];
        r[3] = (t1 - t2 - c) & BN_MASK2;
        if (t1 != t2)
            c = (t1 < t2);
        a += 4;
        b += 4;
        r += 4;
        n -= 4;
    }
#endif
    while (n) {
        t1 = a[0];
        t2 = b[0];
        r[0] = (t1 - t2 - c) & BN_MASK2;
        if (t1 != t2)
            c = (t1 < t2);
        a++;
        b++;
        r++;
        n--;
    }
    return (c);
}

#if defined(BN_MUL_COMBA) && !defined(OPENSSL_SMALL_FOOTPRINT)

# undef bn_mul_comba8
# undef bn_mul_comba4
# undef bn_sqr_comba8
# undef bn_sqr_comba4

/* mul_add_c(a,b,c0,c1,c2)  -- c+=a*b for three word number c=(c2,c1,c0) */
/* mul_add_c2(a,b,c0,c1,c2) -- c+=2*a*b for three word number c=(c2,c1,c0) */
/* sqr_add_c(a,i,c0,c1,c2)  -- c+=a[i]^2 for three word number c=(c2,c1,c0) */
/*
 * sqr_add_c2(a,i,c0,c1,c2) -- c+=2*a[i]*a[j] for three word number
 * c=(c2,c1,c0)
 */

# ifdef BN_LLONG
/*
 * Keep in mind that additions to multiplication result can not
 * overflow, because its high half cannot be all-ones.
 */
#  define mul_add_c(a,b,c0,c1,c2)       do {    \
        BN_ULONG hi;                            \
        BN_ULLONG t = (BN_ULLONG)(a)*(b);       \
        t += c0;                /* no carry */  \
        c0 = (BN_ULONG)Lw(t);                   \
        hi = (BN_ULONG)Hw(t);                   \
        c1 = (c1+hi)&BN_MASK2; if (c1<hi) c2++; \
        } while(0)

#  define mul_add_c2(a,b,c0,c1,c2)      do {    \
        BN_ULONG hi;                            \
        BN_ULLONG t = (BN_ULLONG)(a)*(b);       \
        BN_ULLONG tt = t+c0;    /* no carry */  \
        c0 = (BN_ULONG)Lw(tt);                  \
        hi = (BN_ULONG)Hw(tt);                  \
        c1 = (c1+hi)&BN_MASK2; if (c1<hi) c2++; \
        t += c0;                /* no carry */  \
        c0 = (BN_ULONG)Lw(t);                   \
        hi = (BN_ULONG)Hw(t);                   \
        c1 = (c1+hi)&BN_MASK2; if (c1<hi) c2++; \
        } while(0)

#  define sqr_add_c(a,i,c0,c1,c2)       do {    \
        BN_ULONG hi;                            \
        BN_ULLONG t = (BN_ULLONG)a[i]*a[i];     \
        t += c0;                /* no carry */  \
        c0 = (BN_ULONG)Lw(t);                   \
        hi = (BN_ULONG)Hw(t);                   \
        c1 = (c1+hi)&BN_MASK2; if (c1<hi) c2++; \
        } while(0)

#  define sqr_add_c2(a,i,j,c0,c1,c2) \
        mul_add_c2((a)[i],(a)[j],c0,c1,c2)

# elif defined(BN_UMULT_LOHI)
/*
 * Keep in mind that additions to hi can not overflow, because
 * the high word of a multiplication result cannot be all-ones.
 */
#  define mul_add_c(a,b,c0,c1,c2)       do {    \
        BN_ULONG ta = (a), tb = (b);            \
        BN_ULONG lo, hi;                        \
        BN_UMULT_LOHI(lo,hi,ta,tb);             \
        c0 += lo; hi += (c0<lo)?1:0;            \
        c1 += hi; c2 += (c1<hi)?1:0;            \
        } while(0)

#  define mul_add_c2(a,b,c0,c1,c2)      do {    \
        BN_ULONG ta = (a), tb = (b);            \
        BN_ULONG lo, hi, tt;                    \
        BN_UMULT_LOHI(lo,hi,ta,tb);             \
        c0 += lo; tt = hi+((c0<lo)?1:0);        \
        c1 += tt; c2 += (c1<tt)?1:0;            \
        c0 += lo; hi += (c0<lo)?1:0;            \
        c1 += hi; c2 += (c1<hi)?1:0;            \
        } while(0)

#  define sqr_add_c(a,i,c0,c1,c2)       do {    \
        BN_ULONG ta = (a)[i];                   \
        BN_ULONG lo, hi;                        \
        BN_UMULT_LOHI(lo,hi,ta,ta);             \
        c0 += lo; hi += (c0<lo)?1:0;            \
        c1 += hi; c2 += (c1<hi)?1:0;            \
        } while(0)

#  define sqr_add_c2(a,i,j,c0,c1,c2)    \
        mul_add_c2((a)[i],(a)[j],c0,c1,c2)

# elif defined(BN_UMULT_HIGH)
/*
 * Keep in mind that additions to hi can not overflow, because
 * the high word of a multiplication result cannot be all-ones.
 */
#  define mul_add_c(a,b,c0,c1,c2)       do {    \
        BN_ULONG ta = (a), tb = (b);            \
        BN_ULONG lo = ta * tb;                  \
        BN_ULONG hi = BN_UMULT_HIGH(ta,tb);     \
        c0 += lo; hi += (c0<lo)?1:0;            \
        c1 += hi; c2 += (c1<hi)?1:0;            \
        } while(0)

#  define mul_add_c2(a,b,c0,c1,c2)      do {    \
        BN_ULONG ta = (a), tb = (b), tt;        \
        BN_ULONG lo = ta * tb;                  \
        BN_ULONG hi = BN_UMULT_HIGH(ta,tb);     \
        c0 += lo; tt = hi + ((c0<lo)?1:0);      \
        c1 += tt; c2 += (c1<tt)?1:0;            \
        c0 += lo; hi += (c0<lo)?1:0;            \
        c1 += hi; c2 += (c1<hi)?1:0;            \
        } while(0)

#  define sqr_add_c(a,i,c0,c1,c2)       do {    \
        BN_ULONG ta = (a)[i];                   \
        BN_ULONG lo = ta * ta;                  \
        BN_ULONG hi = BN_UMULT_HIGH(ta,ta);     \
        c0 += lo; hi += (c0<lo)?1:0;            \
        c1 += hi; c2 += (c1<hi)?1:0;            \
        } while(0)

#  define sqr_add_c2(a,i,j,c0,c1,c2)      \
        mul_add_c2((a)[i],(a)[j],c0,c1,c2)

# else                          /* !BN_LLONG */
/*
 * Keep in mind that additions to hi can not overflow, because
 * the high word of a multiplication result cannot be all-ones.
 */
#  define mul_add_c(a,b,c0,c1,c2)       do {    \
        BN_ULONG lo = LBITS(a), hi = HBITS(a);  \
        BN_ULONG bl = LBITS(b), bh = HBITS(b);  \
        mul64(lo,hi,bl,bh);                     \
        c0 = (c0+lo)&BN_MASK2; if (c0<lo) hi++; \
        c1 = (c1+hi)&BN_MASK2; if (c1<hi) c2++; \
        } while(0)

#  define mul_add_c2(a,b,c0,c1,c2)      do {    \
        BN_ULONG tt;                            \
        BN_ULONG lo = LBITS(a), hi = HBITS(a);  \
        BN_ULONG bl = LBITS(b), bh = HBITS(b);  \
        mul64(lo,hi,bl,bh);                     \
        tt = hi;                                \
        c0 = (c0+lo)&BN_MASK2; if (c0<lo) tt++; \
        c1 = (c1+tt)&BN_MASK2; if (c1<tt) c2++; \
        c0 = (c0+lo)&BN_MASK2; if (c0<lo) hi++; \
        c1 = (c1+hi)&BN_MASK2; if (c1<hi) c2++; \
        } while(0)

#  define sqr_add_c(a,i,c0,c1,c2)       do {    \
        BN_ULONG lo, hi;                        \
        sqr64(lo,hi,(a)[i]);                    \
        c0 = (c0+lo)&BN_MASK2; if (c0<lo) hi++; \
        c1 = (c1+hi)&BN_MASK2; if (c1<hi) c2++; \
        } while(0)

#  define sqr_add_c2(a,i,j,c0,c1,c2) \
        mul_add_c2((a)[i],(a)[j],c0,c1,c2)
# endif                         /* !BN_LLONG */

void bn_mul_comba8(BN_ULONG *r, BN_ULONG *a, BN_ULONG *b)
{
    BN_ULONG c1, c2, c3;

    c1 = 0;
    c2 = 0;
    c3 = 0;
    mul_add_c(a[0], b[0], c1, c2, c3);
    r[0] = c1;
    c1 = 0;
    mul_add_c(a[0], b[1], c2, c3, c1);
    mul_add_c(a[1], b[0], c2, c3, c1);
    r[1] = c2;
    c2 = 0;
    mul_add_c(a[2], b[0], c3, c1, c2);
    mul_add_c(a[1], b[1], c3, c1, c2);
    mul_add_c(a[0], b[2], c3, c1, c2);
    r[2] = c3;
    c3 = 0;
    mul_add_c(a[0], b[3], c1, c2, c3);
    mul_add_c(a[1], b[2], c1, c2, c3);
    mul_add_c(a[2], b[1], c1, c2, c3);
    mul_add_c(a[3], b[0], c1, c2, c3);
    r[3] = c1;
    c1 = 0;
    mul_add_c(a[4], b[0], c2, c3, c1);
    mul_add_c(a[3], b[1], c2, c3, c1);
    mul_add_c(a[2], b[2], c2, c3, c1);
    mul_add_c(a[1], b[3], c2, c3, c1);
    mul_add_c(a[0], b[4], c2, c3, c1);
    r[4] = c2;
    c2 = 0;
    mul_add_c(a[0], b[5], c3, c1, c2);
    mul_add_c(a[1], b[4], c3, c1, c2);
    mul_add_c(a[2], b[3], c3, c1, c2);
    mul_add_c(a[3], b[2], c3, c1, c2);
    mul_add_c(a[4], b[1], c3, c1, c2);
    mul_add_c(a[5], b[0], c3, c1, c2);
    r[5] = c3;
    c3 = 0;
    mul_add_c(a[6], b[0], c1, c2, c3);
    mul_add_c(a[5], b[1], c1, c2, c3);
    mul_add_c(a[4], b[2], c1, c2, c3);
    mul_add_c(a[3], b[3], c1, c2, c3);
    mul_add_c(a[2], b[4], c1, c2, c3);
    mul_add_c(a[1], b[5], c1, c2, c3);
    mul_add_c(a[0], b[6], c1, c2, c3);
    r[6] = c1;
    c1 = 0;
    mul_add_c(a[0], b[7], c2, c3, c1);
    mul_add_c(a[1], b[6], c2, c3, c1);
    mul_add_c(a[2], b[5], c2, c3, c1);
    mul_add_c(a[3], b[4], c2, c3, c1);
    mul_add_c(a[4], b[3], c2, c3, c1);
    mul_add_c(a[5], b[2], c2, c3, c1);
    mul_add_c(a[6], b[1], c2, c3, c1);
    mul_add_c(a[7], b[0], c2, c3, c1);
    r[7] = c2;
    c2 = 0;
    mul_add_c(a[7], b[1], c3, c1, c2);
    mul_add_c(a[6], b[2], c3, c1, c2);
    mul_add_c(a[5], b[3], c3, c1, c2);
    mul_add_c(a[4], b[4], c3, c1, c2);
    mul_add_c(a[3], b[5], c3, c1, c2);
    mul_add_c(a[2], b[6], c3, c1, c2);
    mul_add_c(a[1], b[7], c3, c1, c2);
    r[8] = c3;
    c3 = 0;
    mul_add_c(a[2], b[7], c1, c2, c3);
    mul_add_c(a[3], b[6], c1, c2, c3);
    mul_add_c(a[4], b[5], c1, c2, c3);
    mul_add_c(a[5], b[4], c1, c2, c3);
    mul_add_c(a[6], b[3], c1, c2, c3);
    mul_add_c(a[7], b[2], c1, c2, c3);
    r[9] = c1;
    c1 = 0;
    mul_add_c(a[7], b[3], c2, c3, c1);
    mul_add_c(a[6], b[4], c2, c3, c1);
    mul_add_c(a[5], b[5], c2, c3, c1);
    mul_add_c(a[4], b[6], c2, c3, c1);
    mul_add_c(a[3], b[7], c2, c3, c1);
    r[10] = c2;
    c2 = 0;
    mul_add_c(a[4], b[7], c3, c1, c2);
    mul_add_c(a[5], b[6], c3, c1, c2);
    mul_add_c(a[6], b[5], c3, c1, c2);
    mul_add_c(a[7], b[4], c3, c1, c2);
    r[11] = c3;
    c3 = 0;
    mul_add_c(a[7], b[5], c1, c2, c3);
    mul_add_c(a[6], b[6], c1, c2, c3);
    mul_add_c(a[5], b[7], c1, c2, c3);
    r[12] = c1;
    c1 = 0;
    mul_add_c(a[6], b[7], c2, c3, c1);
    mul_add_c(a[7], b[6], c2, c3, c1);
    r[13] = c2;
    c2 = 0;
    mul_add_c(a[7], b[7], c3, c1, c2);
    r[14] = c3;
    r[15] = c1;
}

void bn_mul_comba4(BN_ULONG *r, BN_ULONG *a, BN_ULONG *b)
{
    BN_ULONG c1, c2, c3;

    c1 = 0;
    c2 = 0;
    c3 = 0;
    mul_add_c(a[0], b[0], c1, c2, c3);
    r[0] = c1;
    c1 = 0;
    mul_add_c(a[0], b[1], c2, c3, c1);
    mul_add_c(a[1], b[0], c2, c3, c1);
    r[1] = c2;
    c2 = 0;
    mul_add_c(a[2], b[0], c3, c1, c2);
    mul_add_c(a[1], b[1], c3, c1, c2);
    mul_add_c(a[0], b[2], c3, c1, c2);
    r[2] = c3;
    c3 = 0;
    mul_add_c(a[0], b[3], c1, c2, c3);
    mul_add_c(a[1], b[2], c1, c2, c3);
    mul_add_c(a[2], b[1], c1, c2, c3);
    mul_add_c(a[3], b[0], c1, c2, c3);
    r[3] = c1;
    c1 = 0;
    mul_add_c(a[3], b[1], c2, c3, c1);
    mul_add_c(a[2], b[2], c2, c3, c1);
    mul_add_c(a[1], b[3], c2, c3, c1);
    r[4] = c2;
    c2 = 0;
    mul_add_c(a[2], b[3], c3, c1, c2);
    mul_add_c(a[3], b[2], c3, c1, c2);
    r[5] = c3;
    c3 = 0;
    mul_add_c(a[3], b[3], c1, c2, c3);
    r[6] = c1;
    r[7] = c2;
}

void bn_sqr_comba8(BN_ULONG *r, const BN_ULONG *a)
{
    BN_ULONG c1, c2, c3;

    c1 = 0;
    c2 = 0;
    c3 = 0;
    sqr_add_c(a, 0, c1, c2, c3);
    r[0] = c1;
    c1 = 0;
    sqr_add_c2(a, 1, 0, c2, c3, c1);
    r[1] = c2;
    c2 = 0;
    sqr_add_c(a, 1, c3, c1, c2);
    sqr_add_c2(a, 2, 0, c3, c1, c2);
    r[2] = c3;
    c3 = 0;
    sqr_add_c2(a, 3, 0, c1, c2, c3);
    sqr_add_c2(a, 2, 1, c1, c2, c3);
    r[3] = c1;
    c1 = 0;
    sqr_add_c(a, 2, c2, c3, c1);
    sqr_add_c2(a, 3, 1, c2, c3, c1);
    sqr_add_c2(a, 4, 0, c2, c3, c1);
    r[4] = c2;
    c2 = 0;
    sqr_add_c2(a, 5, 0, c3, c1, c2);
    sqr_add_c2(a, 4, 1, c3, c1, c2);
    sqr_add_c2(a, 3, 2, c3, c1, c2);
    r[5] = c3;
    c3 = 0;
    sqr_add_c(a, 3, c1, c2, c3);
    sqr_add_c2(a, 4, 2, c1, c2, c3);
    sqr_add_c2(a, 5, 1, c1, c2, c3);
    sqr_add_c2(a, 6, 0, c1, c2, c3);
    r[6] = c1;
    c1 = 0;
    sqr_add_c2(a, 7, 0, c2, c3, c1);
    sqr_add_c2(a, 6, 1, c2, c3, c1);
    sqr_add_c2(a, 5, 2, c2, c3, c1);
    sqr_add_c2(a, 4, 3, c2, c3, c1);
    r[7] = c2;
    c2 = 0;
    sqr_add_c(a, 4, c3, c1, c2);
    sqr_add_c2(a, 5, 3, c3, c1, c2);
    sqr_add_c2(a, 6, 2, c3, c1, c2);
    sqr_add_c2(a, 7, 1, c3, c1, c2);
    r[8] = c3;
    c3 = 0;
    sqr_add_c2(a, 7, 2, c1, c2, c3);
    sqr_add_c2(a, 6, 3, c1, c2, c3);
    sqr_add_c2(a, 5, 4, c1, c2, c3);
    r[9] = c1;
    c1 = 0;
    sqr_add_c(a, 5, c2, c3, c1);
    sqr_add_c2(a, 6, 4, c2, c3, c1);
    sqr_add_c2(a, 7, 3, c2, c3, c1);
    r[10] = c2;
    c2 = 0;
    sqr_add_c2(a, 7, 4, c3, c1, c2);
    sqr_add_c2(a, 6, 5, c3, c1, c2);
    r[11] = c3;
    c3 = 0;
    sqr_add_c(a, 6, c1, c2, c3);
    sqr_add_c2(a, 7, 5, c1, c2, c3);
    r[12] = c1;
    c1 = 0;
    sqr_add_c2(a, 7, 6, c2, c3, c1);
    r[13] = c2;
    c2 = 0;
    sqr_add_c(a, 7, c3, c1, c2);
    r[14] = c3;
    r[15] = c1;
}

void bn_sqr_comba4(BN_ULONG *r, const BN_ULONG *a)
{
    BN_ULONG c1, c2, c3;

    c1 = 0;
    c2 = 0;
    c3 = 0;
    sqr_add_c(a, 0, c1, c2, c3);
    r[0] = c1;
    c1 = 0;
    sqr_add_c2(a, 1, 0, c2, c3, c1);
    r[1] = c2;
    c2 = 0;
    sqr_add_c(a, 1, c3, c1, c2);
    sqr_add_c2(a, 2, 0, c3, c1, c2);
    r[2] = c3;
    c3 = 0;
    sqr_add_c2(a, 3, 0, c1, c2, c3);
    sqr_add_c2(a, 2, 1, c1, c2, c3);
    r[3] = c1;
    c1 = 0;
    sqr_add_c(a, 2, c2, c3, c1);
    sqr_add_c2(a, 3, 1, c2, c3, c1);
    r[4] = c2;
    c2 = 0;
    sqr_add_c2(a, 3, 2, c3, c1, c2);
    r[5] = c3;
    c3 = 0;
    sqr_add_c(a, 3, c1, c2, c3);
    r[6] = c1;
    r[7] = c2;
}

# ifdef OPENSSL_NO_ASM
#  ifdef OPENSSL_BN_ASM_MONT
#   include <alloca.h>
/*
 * This is essentially reference implementation, which may or may not
 * result in performance improvement. E.g. on IA-32 this routine was
 * observed to give 40% faster rsa1024 private key operations and 10%
 * faster rsa4096 ones, while on AMD64 it improves rsa1024 sign only
 * by 10% and *worsens* rsa4096 sign by 15%. Once again, it's a
 * reference implementation, one to be used as starting point for
 * platform-specific assembler. Mentioned numbers apply to compiler
 * generated code compiled with and without -DOPENSSL_BN_ASM_MONT and
 * can vary not only from platform to platform, but even for compiler
 * versions. Assembler vs. assembler improvement coefficients can
 * [and are known to] differ and are to be documented elsewhere.
 */
int bn_mul_mont(BN_ULONG *rp, const BN_ULONG *ap, const BN_ULONG *bp,
                const BN_ULONG *np, const BN_ULONG *n0p, int num)
{
    BN_ULONG c0, c1, ml, *tp, n0;
#   ifdef mul64
    BN_ULONG mh;
#   endif
    volatile BN_ULONG *vp;
    int i = 0, j;

#   if 0                        /* template for platform-specific
                                 * implementation */
    if (ap == bp)
        return bn_sqr_mont(rp, ap, np, n0p, num);
#   endif
    vp = tp = alloca((num + 2) * sizeof(BN_ULONG));

    n0 = *n0p;

    c0 = 0;
    ml = bp[0];
#   ifdef mul64
    mh = HBITS(ml);
    ml = LBITS(ml);
    for (j = 0; j < num; ++j)
        mul(tp[j], ap[j], ml, mh, c0);
#   else
    for (j = 0; j < num; ++j)
        mul(tp[j], ap[j], ml, c0);
#   endif

    tp[num] = c0;
    tp[num + 1] = 0;
    goto enter;

    for (i = 0; i < num; i++) {
        c0 = 0;
        ml = bp[i];
#   ifdef mul64
        mh = HBITS(ml);
        ml = LBITS(ml);
        for (j = 0; j < num; ++j)
            mul_add(tp[j], ap[j], ml, mh, c0);
#   else
        for (j = 0; j < num; ++j)
            mul_add(tp[j], ap[j], ml, c0);
#   endif
        c1 = (tp[num] + c0) & BN_MASK2;
        tp[num] = c1;
        tp[num + 1] = (c1 < c0 ? 1 : 0);
 enter:
        c1 = tp[0];
        ml = (c1 * n0) & BN_MASK2;
        c0 = 0;
#   ifdef mul64
        mh = HBITS(ml);
        ml = LBITS(ml);
        mul_add(c1, np[0], ml, mh, c0);
#   else
        mul_add(c1, ml, np[0], c0);
#   endif
        for (j = 1; j < num; j++) {
            c1 = tp[j];
#   ifdef mul64
            mul_add(c1, np[j], ml, mh, c0);
#   else
            mul_add(c1, ml, np[j], c0);
#   endif
            tp[j - 1] = c1 & BN_MASK2;
        }
        c1 = (tp[num] + c0) & BN_MASK2;
        tp[num - 1] = c1;
        tp[num] = tp[num + 1] + (c1 < c0 ? 1 : 0);
    }

    if (tp[num] != 0 || tp[num - 1] >= np[num - 1]) {
        c0 = bn_sub_words(rp, tp, np, num);
        if (tp[num] != 0 || c0 == 0) {
            for (i = 0; i < num + 2; i++)
                vp[i] = 0;
            return 1;
        }
    }
    for (i = 0; i < num; i++)
        rp[i] = tp[i], vp[i] = 0;
    vp[num] = 0;
    vp[num + 1] = 0;
    return 1;
}
#  else
/*
 * Return value of 0 indicates that multiplication/convolution was not
 * performed to signal the caller to fall down to alternative/original
 * code-path.
 */
int bn_mul_mont(BN_ULONG *rp, const BN_ULONG *ap, const BN_ULONG *bp,
                const BN_ULONG *np, const BN_ULONG *n0, int num)
{
    return 0;
}
#  endif                        /* OPENSSL_BN_ASM_MONT */
# endif

#else                           /* !BN_MUL_COMBA */

/* hmm... is it faster just to do a multiply? */
# undef bn_sqr_comba4
void bn_sqr_comba4(BN_ULONG *r, const BN_ULONG *a)
{
    BN_ULONG t[8];
    bn_sqr_normal(r, a, 4, t);
}

# undef bn_sqr_comba8
void bn_sqr_comba8(BN_ULONG *r, const BN_ULONG *a)
{
    BN_ULONG t[16];
    bn_sqr_normal(r, a, 8, t);
}

void bn_mul_comba4(BN_ULONG *r, BN_ULONG *a, BN_ULONG *b)
{
    r[4] = bn_mul_words(&(r[0]), a, 4, b[0]);
    r[5] = bn_mul_add_words(&(r[1]), a, 4, b[1]);
    r[6] = bn_mul_add_words(&(r[2]), a, 4, b[2]);
    r[7] = bn_mul_add_words(&(r[3]), a, 4, b[3]);
}

void bn_mul_comba8(BN_ULONG *r, BN_ULONG *a, BN_ULONG *b)
{
    r[8] = bn_mul_words(&(r[0]), a, 8, b[0]);
    r[9] = bn_mul_add_words(&(r[1]), a, 8, b[1]);
    r[10] = bn_mul_add_words(&(r[2]), a, 8, b[2]);
    r[11] = bn_mul_add_words(&(r[3]), a, 8, b[3]);
    r[12] = bn_mul_add_words(&(r[4]), a, 8, b[4]);
    r[13] = bn_mul_add_words(&(r[5]), a, 8, b[5]);
    r[14] = bn_mul_add_words(&(r[6]), a, 8, b[6]);
    r[15] = bn_mul_add_words(&(r[7]), a, 8, b[7]);
}

# ifdef OPENSSL_NO_ASM
#  ifdef OPENSSL_BN_ASM_MONT
#   include <alloca.h>
int bn_mul_mont(BN_ULONG *rp, const BN_ULONG *ap, const BN_ULONG *bp,
                const BN_ULONG *np, const BN_ULONG *n0p, int num)
{
    BN_ULONG c0, c1, *tp, n0 = *n0p;
    volatile BN_ULONG *vp;
    int i = 0, j;

    vp = tp = alloca((num + 2) * sizeof(BN_ULONG));

    for (i = 0; i <= num; i++)
        tp[i] = 0;

    for (i = 0; i < num; i++) {
        c0 = bn_mul_add_words(tp, ap, num, bp[i]);
        c1 = (tp[num] + c0) & BN_MASK2;
        tp[num] = c1;
        tp[num + 1] = (c1 < c0 ? 1 : 0);

        c0 = bn_mul_add_words(tp, np, num, tp[0] * n0);
        c1 = (tp[num] + c0) & BN_MASK2;
        tp[num] = c1;
        tp[num + 1] += (c1 < c0 ? 1 : 0);
        for (j = 0; j <= num; j++)
            tp[j] = tp[j + 1];
    }

    if (tp[num] != 0 || tp[num - 1] >= np[num - 1]) {
        c0 = bn_sub_words(rp, tp, np, num);
        if (tp[num] != 0 || c0 == 0) {
            for (i = 0; i < num + 2; i++)
                vp[i] = 0;
            return 1;
        }
    }
    for (i = 0; i < num; i++)
        rp[i] = tp[i], vp[i] = 0;
    vp[num] = 0;
    vp[num + 1] = 0;
    return 1;
}
#  else
int bn_mul_mont(BN_ULONG *rp, const BN_ULONG *ap, const BN_ULONG *bp,
                const BN_ULONG *np, const BN_ULONG *n0, int num)
{
    return 0;
}
#  endif                        /* OPENSSL_BN_ASM_MONT */
# endif

#endif                          /* !BN_MUL_COMBA */
/* crypto/bn/bn_blind.c */
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
// #include "bn_lcl.h"

#define BN_BLINDING_COUNTER     32

struct bn_blinding_st {
    BIGNUM *A;
    BIGNUM *Ai;
    BIGNUM *e;
    BIGNUM *mod;                /* just a reference */
#ifndef OPENSSL_NO_DEPRECATED
    unsigned long thread_id;    /* added in OpenSSL 0.9.6j and 0.9.7b; used
                                 * only by crypto/rsa/rsa_eay.c, rsa_lib.c */
#endif
    CRYPTO_THREADID tid;
    int counter;
    unsigned long flags;
    BN_MONT_CTX *m_ctx;
    int (*bn_mod_exp) (BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
                       const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx);
};

BN_BLINDING *BN_BLINDING_new(const BIGNUM *A, const BIGNUM *Ai, BIGNUM *mod)
{
    BN_BLINDING *ret = NULL;

    bn_check_top(mod);

    if ((ret = (BN_BLINDING *)OPENSSL_malloc(sizeof(BN_BLINDING))) == NULL) {
        BNerr(BN_F_BN_BLINDING_NEW, ERR_R_MALLOC_FAILURE);
        return (NULL);
    }
    memset(ret, 0, sizeof(BN_BLINDING));
    if (A != NULL) {
        if ((ret->A = BN_dup(A)) == NULL)
            goto err;
    }
    if (Ai != NULL) {
        if ((ret->Ai = BN_dup(Ai)) == NULL)
            goto err;
    }

    /* save a copy of mod in the BN_BLINDING structure */
    if ((ret->mod = BN_dup(mod)) == NULL)
        goto err;
    if (BN_get_flags(mod, BN_FLG_CONSTTIME) != 0)
        BN_set_flags(ret->mod, BN_FLG_CONSTTIME);

    /*
     * Set the counter to the special value -1 to indicate that this is
     * never-used fresh blinding that does not need updating before first
     * use.
     */
    ret->counter = -1;
    CRYPTO_THREADID_current(&ret->tid);
    return (ret);
 err:
    if (ret != NULL)
        BN_BLINDING_free(ret);
    return (NULL);
}

void BN_BLINDING_free(BN_BLINDING *r)
{
    if (r == NULL)
        return;

    if (r->A != NULL)
        BN_free(r->A);
    if (r->Ai != NULL)
        BN_free(r->Ai);
    if (r->e != NULL)
        BN_free(r->e);
    if (r->mod != NULL)
        BN_free(r->mod);
    OPENSSL_free(r);
}

int BN_BLINDING_update(BN_BLINDING *b, BN_CTX *ctx)
{
    int ret = 0;

    if ((b->A == NULL) || (b->Ai == NULL)) {
        BNerr(BN_F_BN_BLINDING_UPDATE, BN_R_NOT_INITIALIZED);
        goto err;
    }

    if (b->counter == -1)
        b->counter = 0;

    if (++b->counter == BN_BLINDING_COUNTER && b->e != NULL &&
        !(b->flags & BN_BLINDING_NO_RECREATE)) {
        /* re-create blinding parameters */
        if (!BN_BLINDING_create_param(b, NULL, NULL, ctx, NULL, NULL))
            goto err;
    } else if (!(b->flags & BN_BLINDING_NO_UPDATE)) {
        if (b->m_ctx != NULL) {
            if (!bn_mul_mont_fixed_top(b->Ai, b->Ai, b->Ai, b->m_ctx, ctx)
                || !bn_mul_mont_fixed_top(b->A, b->A, b->A, b->m_ctx, ctx))
                goto err;
        } else {
            if (!BN_mod_mul(b->Ai, b->Ai, b->Ai, b->mod, ctx)
                || !BN_mod_mul(b->A, b->A, b->A, b->mod, ctx))
                goto err;
        }
    }

    ret = 1;
 err:
    if (b->counter == BN_BLINDING_COUNTER)
        b->counter = 0;
    return (ret);
}

int BN_BLINDING_convert(BIGNUM *n, BN_BLINDING *b, BN_CTX *ctx)
{
    return BN_BLINDING_convert_ex(n, NULL, b, ctx);
}

int BN_BLINDING_convert_ex(BIGNUM *n, BIGNUM *r, BN_BLINDING *b, BN_CTX *ctx)
{
    int ret = 1;

    bn_check_top(n);

    if ((b->A == NULL) || (b->Ai == NULL)) {
        BNerr(BN_F_BN_BLINDING_CONVERT_EX, BN_R_NOT_INITIALIZED);
        return (0);
    }

    if (b->counter == -1)
        /* Fresh blinding, doesn't need updating. */
        b->counter = 0;
    else if (!BN_BLINDING_update(b, ctx))
        return (0);

    if (r != NULL && (BN_copy(r, b->Ai) == NULL))
        return 0;

    if (b->m_ctx != NULL)
        ret = BN_mod_mul_montgomery(n, n, b->A, b->m_ctx, ctx);
    else
        ret = BN_mod_mul(n, n, b->A, b->mod, ctx);

    return ret;
}

int BN_BLINDING_invert(BIGNUM *n, BN_BLINDING *b, BN_CTX *ctx)
{
    return BN_BLINDING_invert_ex(n, NULL, b, ctx);
}

int BN_BLINDING_invert_ex(BIGNUM *n, const BIGNUM *r, BN_BLINDING *b,
                          BN_CTX *ctx)
{
    int ret;

    bn_check_top(n);

    if (r == NULL && (r = b->Ai) == NULL) {
        BNerr(BN_F_BN_BLINDING_INVERT_EX, BN_R_NOT_INITIALIZED);
        return 0;
    }

    if (b->m_ctx != NULL) {
        /* ensure that BN_mod_mul_montgomery takes pre-defined path */
        if (n->dmax >= r->top) {
            size_t i, rtop = r->top, ntop = n->top;
            BN_ULONG mask;

            for (i = 0; i < rtop; i++) {
                mask = (BN_ULONG)0 - ((i - ntop) >> (8 * sizeof(i) - 1));
                n->d[i] &= mask;
            }
            mask = (BN_ULONG)0 - ((rtop - ntop) >> (8 * sizeof(ntop) - 1));
            /* always true, if (rtop >= ntop) n->top = r->top; */
            n->top = (int)(rtop & ~mask) | (ntop & mask);
            n->flags |= (BN_FLG_FIXED_TOP & ~mask);
        }
        ret = BN_mod_mul_montgomery(n, n, r, b->m_ctx, ctx);
    } else {
        ret = BN_mod_mul(n, n, r, b->mod, ctx);
    }

    bn_check_top(n);
    return (ret);
}

#ifndef OPENSSL_NO_DEPRECATED
unsigned long BN_BLINDING_get_thread_id(const BN_BLINDING *b)
{
    return b->thread_id;
}

void BN_BLINDING_set_thread_id(BN_BLINDING *b, unsigned long n)
{
    b->thread_id = n;
}
#endif

CRYPTO_THREADID *BN_BLINDING_thread_id(BN_BLINDING *b)
{
    return &b->tid;
}

unsigned long BN_BLINDING_get_flags(const BN_BLINDING *b)
{
    return b->flags;
}

void BN_BLINDING_set_flags(BN_BLINDING *b, unsigned long flags)
{
    b->flags = flags;
}

BN_BLINDING *BN_BLINDING_create_param(BN_BLINDING *b,
                                      const BIGNUM *e, BIGNUM *m, BN_CTX *ctx,
                                      int (*bn_mod_exp) (BIGNUM *r,
                                                         const BIGNUM *a,
                                                         const BIGNUM *p,
                                                         const BIGNUM *m,
                                                         BN_CTX *ctx,
                                                         BN_MONT_CTX *m_ctx),
                                      BN_MONT_CTX *m_ctx)
{
    int retry_counter = 32;
    BN_BLINDING *ret = NULL;

    if (b == NULL)
        ret = BN_BLINDING_new(NULL, NULL, m);
    else
        ret = b;

    if (ret == NULL)
        goto err;

    if (ret->A == NULL && (ret->A = BN_new()) == NULL)
        goto err;
    if (ret->Ai == NULL && (ret->Ai = BN_new()) == NULL)
        goto err;

    if (e != NULL) {
        if (ret->e != NULL)
            BN_free(ret->e);
        ret->e = BN_dup(e);
    }
    if (ret->e == NULL)
        goto err;

    if (bn_mod_exp != NULL)
        ret->bn_mod_exp = bn_mod_exp;
    if (m_ctx != NULL)
        ret->m_ctx = m_ctx;

    do {
        if (!BN_rand_range(ret->A, ret->mod))
            goto err;
        if (BN_mod_inverse(ret->Ai, ret->A, ret->mod, ctx) == NULL) {
            /*
             * this should almost never happen for good RSA keys
             */
            unsigned long error = ERR_peek_last_error();
            if (ERR_GET_REASON(error) == BN_R_NO_INVERSE) {
                if (retry_counter-- == 0) {
                    BNerr(BN_F_BN_BLINDING_CREATE_PARAM,
                          BN_R_TOO_MANY_ITERATIONS);
                    goto err;
                }
                ERR_clear_error();
            } else
                goto err;
        } else
            break;
    } while (1);

    if (ret->bn_mod_exp != NULL && ret->m_ctx != NULL) {
        if (!ret->bn_mod_exp(ret->A, ret->A, ret->e, ret->mod, ctx, ret->m_ctx))
            goto err;
    } else {
        if (!BN_mod_exp(ret->A, ret->A, ret->e, ret->mod, ctx))
            goto err;
    }

    if (ret->m_ctx != NULL) {
        if (!bn_to_mont_fixed_top(ret->Ai, ret->Ai, ret->m_ctx, ctx)
            || !bn_to_mont_fixed_top(ret->A, ret->A, ret->m_ctx, ctx))
            goto err;
    }

    return ret;
 err:
    if (b == NULL && ret != NULL) {
        BN_BLINDING_free(ret);
        ret = NULL;
    }

    return ret;
}
/* crypto/bn/knownprimes.c */
/* Insert boilerplate */

#include "bn.h"

/*-
 * "First Oakley Default Group" from RFC2409, section 6.1.
 *
 * The prime is: 2^768 - 2 ^704 - 1 + 2^64 * { [2^638 pi] + 149686 }
 *
 * RFC2409 specifies a generator of 2.
 * RFC2412 specifies a generator of of 22.
 */

BIGNUM *get_rfc2409_prime_768(BIGNUM *bn)
{
    static const unsigned char RFC2409_PRIME_768[] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
        0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
        0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
        0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22,
        0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
        0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B,
        0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
        0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
        0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
        0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x3A, 0x36, 0x20,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    };
    return BN_bin2bn(RFC2409_PRIME_768, sizeof(RFC2409_PRIME_768), bn);
}

/*-
 * "Second Oakley Default Group" from RFC2409, section 6.2.
 *
 * The prime is: 2^1024 - 2^960 - 1 + 2^64 * { [2^894 pi] + 129093 }.
 *
 * RFC2409 specifies a generator of 2.
 * RFC2412 specifies a generator of 22.
 */

BIGNUM *get_rfc2409_prime_1024(BIGNUM *bn)
{
    static const unsigned char RFC2409_PRIME_1024[] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
        0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
        0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
        0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22,
        0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
        0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B,
        0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
        0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
        0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
        0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B,
        0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
        0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5,
        0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
        0x49, 0x28, 0x66, 0x51, 0xEC, 0xE6, 0x53, 0x81,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    };
    return BN_bin2bn(RFC2409_PRIME_1024, sizeof(RFC2409_PRIME_1024), bn);
}

/*-
 * "1536-bit MODP Group" from RFC3526, Section 2.
 *
 * The prime is: 2^1536 - 2^1472 - 1 + 2^64 * { [2^1406 pi] + 741804 }
 *
 * RFC3526 specifies a generator of 2.
 * RFC2312 specifies a generator of 22.
 */

BIGNUM *get_rfc3526_prime_1536(BIGNUM *bn)
{
    static const unsigned char RFC3526_PRIME_1536[] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
        0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
        0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
        0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22,
        0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
        0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B,
        0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
        0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
        0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
        0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B,
        0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
        0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5,
        0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
        0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
        0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05,
        0x98, 0xDA, 0x48, 0x36, 0x1C, 0x55, 0xD3, 0x9A,
        0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
        0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96,
        0x1C, 0x62, 0xF3, 0x56, 0x20, 0x85, 0x52, 0xBB,
        0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D,
        0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04,
        0xF1, 0x74, 0x6C, 0x08, 0xCA, 0x23, 0x73, 0x27,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    };
    return BN_bin2bn(RFC3526_PRIME_1536, sizeof(RFC3526_PRIME_1536), bn);
}

/*-
 * "2048-bit MODP Group" from RFC3526, Section 3.
 *
 * The prime is: 2^2048 - 2^1984 - 1 + 2^64 * { [2^1918 pi] + 124476 }
 *
 * RFC3526 specifies a generator of 2.
 */

BIGNUM *get_rfc3526_prime_2048(BIGNUM *bn)
{
    static const unsigned char RFC3526_PRIME_2048[] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
        0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
        0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
        0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22,
        0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
        0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B,
        0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
        0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
        0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
        0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B,
        0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
        0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5,
        0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
        0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
        0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05,
        0x98, 0xDA, 0x48, 0x36, 0x1C, 0x55, 0xD3, 0x9A,
        0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
        0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96,
        0x1C, 0x62, 0xF3, 0x56, 0x20, 0x85, 0x52, 0xBB,
        0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D,
        0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04,
        0xF1, 0x74, 0x6C, 0x08, 0xCA, 0x18, 0x21, 0x7C,
        0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B,
        0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03,
        0x9B, 0x27, 0x83, 0xA2, 0xEC, 0x07, 0xA2, 0x8F,
        0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9,
        0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18,
        0x39, 0x95, 0x49, 0x7C, 0xEA, 0x95, 0x6A, 0xE5,
        0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10,
        0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAC, 0xAA, 0x68,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    };
    return BN_bin2bn(RFC3526_PRIME_2048, sizeof(RFC3526_PRIME_2048), bn);
}

/*-
 * "3072-bit MODP Group" from RFC3526, Section 4.
 *
 * The prime is: 2^3072 - 2^3008 - 1 + 2^64 * { [2^2942 pi] + 1690314 }
 *
 * RFC3526 specifies a generator of 2.
 */

BIGNUM *get_rfc3526_prime_3072(BIGNUM *bn)
{
    static const unsigned char RFC3526_PRIME_3072[] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
        0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
        0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
        0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22,
        0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
        0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B,
        0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
        0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
        0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
        0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B,
        0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
        0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5,
        0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
        0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
        0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05,
        0x98, 0xDA, 0x48, 0x36, 0x1C, 0x55, 0xD3, 0x9A,
        0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
        0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96,
        0x1C, 0x62, 0xF3, 0x56, 0x20, 0x85, 0x52, 0xBB,
        0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D,
        0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04,
        0xF1, 0x74, 0x6C, 0x08, 0xCA, 0x18, 0x21, 0x7C,
        0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B,
        0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03,
        0x9B, 0x27, 0x83, 0xA2, 0xEC, 0x07, 0xA2, 0x8F,
        0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9,
        0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18,
        0x39, 0x95, 0x49, 0x7C, 0xEA, 0x95, 0x6A, 0xE5,
        0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10,
        0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAA, 0xC4, 0x2D,
        0xAD, 0x33, 0x17, 0x0D, 0x04, 0x50, 0x7A, 0x33,
        0xA8, 0x55, 0x21, 0xAB, 0xDF, 0x1C, 0xBA, 0x64,
        0xEC, 0xFB, 0x85, 0x04, 0x58, 0xDB, 0xEF, 0x0A,
        0x8A, 0xEA, 0x71, 0x57, 0x5D, 0x06, 0x0C, 0x7D,
        0xB3, 0x97, 0x0F, 0x85, 0xA6, 0xE1, 0xE4, 0xC7,
        0xAB, 0xF5, 0xAE, 0x8C, 0xDB, 0x09, 0x33, 0xD7,
        0x1E, 0x8C, 0x94, 0xE0, 0x4A, 0x25, 0x61, 0x9D,
        0xCE, 0xE3, 0xD2, 0x26, 0x1A, 0xD2, 0xEE, 0x6B,
        0xF1, 0x2F, 0xFA, 0x06, 0xD9, 0x8A, 0x08, 0x64,
        0xD8, 0x76, 0x02, 0x73, 0x3E, 0xC8, 0x6A, 0x64,
        0x52, 0x1F, 0x2B, 0x18, 0x17, 0x7B, 0x20, 0x0C,
        0xBB, 0xE1, 0x17, 0x57, 0x7A, 0x61, 0x5D, 0x6C,
        0x77, 0x09, 0x88, 0xC0, 0xBA, 0xD9, 0x46, 0xE2,
        0x08, 0xE2, 0x4F, 0xA0, 0x74, 0xE5, 0xAB, 0x31,
        0x43, 0xDB, 0x5B, 0xFC, 0xE0, 0xFD, 0x10, 0x8E,
        0x4B, 0x82, 0xD1, 0x20, 0xA9, 0x3A, 0xD2, 0xCA,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    };
    return BN_bin2bn(RFC3526_PRIME_3072, sizeof(RFC3526_PRIME_3072), bn);
}

/*-
 * "4096-bit MODP Group" from RFC3526, Section 5.
 *
 * The prime is: 2^4096 - 2^4032 - 1 + 2^64 * { [2^3966 pi] + 240904 }
 *
 * RFC3526 specifies a generator of 2.
 */

BIGNUM *get_rfc3526_prime_4096(BIGNUM *bn)
{
    static const unsigned char RFC3526_PRIME_4096[] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
        0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
        0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
        0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22,
        0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
        0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B,
        0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
        0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
        0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
        0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B,
        0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
        0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5,
        0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
        0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
        0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05,
        0x98, 0xDA, 0x48, 0x36, 0x1C, 0x55, 0xD3, 0x9A,
        0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
        0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96,
        0x1C, 0x62, 0xF3, 0x56, 0x20, 0x85, 0x52, 0xBB,
        0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D,
        0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04,
        0xF1, 0x74, 0x6C, 0x08, 0xCA, 0x18, 0x21, 0x7C,
        0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B,
        0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03,
        0x9B, 0x27, 0x83, 0xA2, 0xEC, 0x07, 0xA2, 0x8F,
        0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9,
        0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18,
        0x39, 0x95, 0x49, 0x7C, 0xEA, 0x95, 0x6A, 0xE5,
        0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10,
        0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAA, 0xC4, 0x2D,
        0xAD, 0x33, 0x17, 0x0D, 0x04, 0x50, 0x7A, 0x33,
        0xA8, 0x55, 0x21, 0xAB, 0xDF, 0x1C, 0xBA, 0x64,
        0xEC, 0xFB, 0x85, 0x04, 0x58, 0xDB, 0xEF, 0x0A,
        0x8A, 0xEA, 0x71, 0x57, 0x5D, 0x06, 0x0C, 0x7D,
        0xB3, 0x97, 0x0F, 0x85, 0xA6, 0xE1, 0xE4, 0xC7,
        0xAB, 0xF5, 0xAE, 0x8C, 0xDB, 0x09, 0x33, 0xD7,
        0x1E, 0x8C, 0x94, 0xE0, 0x4A, 0x25, 0x61, 0x9D,
        0xCE, 0xE3, 0xD2, 0x26, 0x1A, 0xD2, 0xEE, 0x6B,
        0xF1, 0x2F, 0xFA, 0x06, 0xD9, 0x8A, 0x08, 0x64,
        0xD8, 0x76, 0x02, 0x73, 0x3E, 0xC8, 0x6A, 0x64,
        0x52, 0x1F, 0x2B, 0x18, 0x17, 0x7B, 0x20, 0x0C,
        0xBB, 0xE1, 0x17, 0x57, 0x7A, 0x61, 0x5D, 0x6C,
        0x77, 0x09, 0x88, 0xC0, 0xBA, 0xD9, 0x46, 0xE2,
        0x08, 0xE2, 0x4F, 0xA0, 0x74, 0xE5, 0xAB, 0x31,
        0x43, 0xDB, 0x5B, 0xFC, 0xE0, 0xFD, 0x10, 0x8E,
        0x4B, 0x82, 0xD1, 0x20, 0xA9, 0x21, 0x08, 0x01,
        0x1A, 0x72, 0x3C, 0x12, 0xA7, 0x87, 0xE6, 0xD7,
        0x88, 0x71, 0x9A, 0x10, 0xBD, 0xBA, 0x5B, 0x26,
        0x99, 0xC3, 0x27, 0x18, 0x6A, 0xF4, 0xE2, 0x3C,
        0x1A, 0x94, 0x68, 0x34, 0xB6, 0x15, 0x0B, 0xDA,
        0x25, 0x83, 0xE9, 0xCA, 0x2A, 0xD4, 0x4C, 0xE8,
        0xDB, 0xBB, 0xC2, 0xDB, 0x04, 0xDE, 0x8E, 0xF9,
        0x2E, 0x8E, 0xFC, 0x14, 0x1F, 0xBE, 0xCA, 0xA6,
        0x28, 0x7C, 0x59, 0x47, 0x4E, 0x6B, 0xC0, 0x5D,
        0x99, 0xB2, 0x96, 0x4F, 0xA0, 0x90, 0xC3, 0xA2,
        0x23, 0x3B, 0xA1, 0x86, 0x51, 0x5B, 0xE7, 0xED,
        0x1F, 0x61, 0x29, 0x70, 0xCE, 0xE2, 0xD7, 0xAF,
        0xB8, 0x1B, 0xDD, 0x76, 0x21, 0x70, 0x48, 0x1C,
        0xD0, 0x06, 0x91, 0x27, 0xD5, 0xB0, 0x5A, 0xA9,
        0x93, 0xB4, 0xEA, 0x98, 0x8D, 0x8F, 0xDD, 0xC1,
        0x86, 0xFF, 0xB7, 0xDC, 0x90, 0xA6, 0xC0, 0x8F,
        0x4D, 0xF4, 0x35, 0xC9, 0x34, 0x06, 0x31, 0x99,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    };
    return BN_bin2bn(RFC3526_PRIME_4096, sizeof(RFC3526_PRIME_4096), bn);
}

/*-
 * "6144-bit MODP Group" from RFC3526, Section 6.
 *
 * The prime is: 2^6144 - 2^6080 - 1 + 2^64 * { [2^6014 pi] + 929484 }
 *
 * RFC3526 specifies a generator of 2.
 */

BIGNUM *get_rfc3526_prime_6144(BIGNUM *bn)
{
    static const unsigned char RFC3526_PRIME_6144[] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
        0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
        0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
        0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22,
        0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
        0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B,
        0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
        0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
        0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
        0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B,
        0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
        0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5,
        0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
        0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
        0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05,
        0x98, 0xDA, 0x48, 0x36, 0x1C, 0x55, 0xD3, 0x9A,
        0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
        0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96,
        0x1C, 0x62, 0xF3, 0x56, 0x20, 0x85, 0x52, 0xBB,
        0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D,
        0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04,
        0xF1, 0x74, 0x6C, 0x08, 0xCA, 0x18, 0x21, 0x7C,
        0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B,
        0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03,
        0x9B, 0x27, 0x83, 0xA2, 0xEC, 0x07, 0xA2, 0x8F,
        0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9,
        0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18,
        0x39, 0x95, 0x49, 0x7C, 0xEA, 0x95, 0x6A, 0xE5,
        0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10,
        0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAA, 0xC4, 0x2D,
        0xAD, 0x33, 0x17, 0x0D, 0x04, 0x50, 0x7A, 0x33,
        0xA8, 0x55, 0x21, 0xAB, 0xDF, 0x1C, 0xBA, 0x64,
        0xEC, 0xFB, 0x85, 0x04, 0x58, 0xDB, 0xEF, 0x0A,
        0x8A, 0xEA, 0x71, 0x57, 0x5D, 0x06, 0x0C, 0x7D,
        0xB3, 0x97, 0x0F, 0x85, 0xA6, 0xE1, 0xE4, 0xC7,
        0xAB, 0xF5, 0xAE, 0x8C, 0xDB, 0x09, 0x33, 0xD7,
        0x1E, 0x8C, 0x94, 0xE0, 0x4A, 0x25, 0x61, 0x9D,
        0xCE, 0xE3, 0xD2, 0x26, 0x1A, 0xD2, 0xEE, 0x6B,
        0xF1, 0x2F, 0xFA, 0x06, 0xD9, 0x8A, 0x08, 0x64,
        0xD8, 0x76, 0x02, 0x73, 0x3E, 0xC8, 0x6A, 0x64,
        0x52, 0x1F, 0x2B, 0x18, 0x17, 0x7B, 0x20, 0x0C,
        0xBB, 0xE1, 0x17, 0x57, 0x7A, 0x61, 0x5D, 0x6C,
        0x77, 0x09, 0x88, 0xC0, 0xBA, 0xD9, 0x46, 0xE2,
        0x08, 0xE2, 0x4F, 0xA0, 0x74, 0xE5, 0xAB, 0x31,
        0x43, 0xDB, 0x5B, 0xFC, 0xE0, 0xFD, 0x10, 0x8E,
        0x4B, 0x82, 0xD1, 0x20, 0xA9, 0x21, 0x08, 0x01,
        0x1A, 0x72, 0x3C, 0x12, 0xA7, 0x87, 0xE6, 0xD7,
        0x88, 0x71, 0x9A, 0x10, 0xBD, 0xBA, 0x5B, 0x26,
        0x99, 0xC3, 0x27, 0x18, 0x6A, 0xF4, 0xE2, 0x3C,
        0x1A, 0x94, 0x68, 0x34, 0xB6, 0x15, 0x0B, 0xDA,
        0x25, 0x83, 0xE9, 0xCA, 0x2A, 0xD4, 0x4C, 0xE8,
        0xDB, 0xBB, 0xC2, 0xDB, 0x04, 0xDE, 0x8E, 0xF9,
        0x2E, 0x8E, 0xFC, 0x14, 0x1F, 0xBE, 0xCA, 0xA6,
        0x28, 0x7C, 0x59, 0x47, 0x4E, 0x6B, 0xC0, 0x5D,
        0x99, 0xB2, 0x96, 0x4F, 0xA0, 0x90, 0xC3, 0xA2,
        0x23, 0x3B, 0xA1, 0x86, 0x51, 0x5B, 0xE7, 0xED,
        0x1F, 0x61, 0x29, 0x70, 0xCE, 0xE2, 0xD7, 0xAF,
        0xB8, 0x1B, 0xDD, 0x76, 0x21, 0x70, 0x48, 0x1C,
        0xD0, 0x06, 0x91, 0x27, 0xD5, 0xB0, 0x5A, 0xA9,
        0x93, 0xB4, 0xEA, 0x98, 0x8D, 0x8F, 0xDD, 0xC1,
        0x86, 0xFF, 0xB7, 0xDC, 0x90, 0xA6, 0xC0, 0x8F,
        0x4D, 0xF4, 0x35, 0xC9, 0x34, 0x02, 0x84, 0x92,
        0x36, 0xC3, 0xFA, 0xB4, 0xD2, 0x7C, 0x70, 0x26,
        0xC1, 0xD4, 0xDC, 0xB2, 0x60, 0x26, 0x46, 0xDE,
        0xC9, 0x75, 0x1E, 0x76, 0x3D, 0xBA, 0x37, 0xBD,
        0xF8, 0xFF, 0x94, 0x06, 0xAD, 0x9E, 0x53, 0x0E,
        0xE5, 0xDB, 0x38, 0x2F, 0x41, 0x30, 0x01, 0xAE,
        0xB0, 0x6A, 0x53, 0xED, 0x90, 0x27, 0xD8, 0x31,
        0x17, 0x97, 0x27, 0xB0, 0x86, 0x5A, 0x89, 0x18,
        0xDA, 0x3E, 0xDB, 0xEB, 0xCF, 0x9B, 0x14, 0xED,
        0x44, 0xCE, 0x6C, 0xBA, 0xCE, 0xD4, 0xBB, 0x1B,
        0xDB, 0x7F, 0x14, 0x47, 0xE6, 0xCC, 0x25, 0x4B,
        0x33, 0x20, 0x51, 0x51, 0x2B, 0xD7, 0xAF, 0x42,
        0x6F, 0xB8, 0xF4, 0x01, 0x37, 0x8C, 0xD2, 0xBF,
        0x59, 0x83, 0xCA, 0x01, 0xC6, 0x4B, 0x92, 0xEC,
        0xF0, 0x32, 0xEA, 0x15, 0xD1, 0x72, 0x1D, 0x03,
        0xF4, 0x82, 0xD7, 0xCE, 0x6E, 0x74, 0xFE, 0xF6,
        0xD5, 0x5E, 0x70, 0x2F, 0x46, 0x98, 0x0C, 0x82,
        0xB5, 0xA8, 0x40, 0x31, 0x90, 0x0B, 0x1C, 0x9E,
        0x59, 0xE7, 0xC9, 0x7F, 0xBE, 0xC7, 0xE8, 0xF3,
        0x23, 0xA9, 0x7A, 0x7E, 0x36, 0xCC, 0x88, 0xBE,
        0x0F, 0x1D, 0x45, 0xB7, 0xFF, 0x58, 0x5A, 0xC5,
        0x4B, 0xD4, 0x07, 0xB2, 0x2B, 0x41, 0x54, 0xAA,
        0xCC, 0x8F, 0x6D, 0x7E, 0xBF, 0x48, 0xE1, 0xD8,
        0x14, 0xCC, 0x5E, 0xD2, 0x0F, 0x80, 0x37, 0xE0,
        0xA7, 0x97, 0x15, 0xEE, 0xF2, 0x9B, 0xE3, 0x28,
        0x06, 0xA1, 0xD5, 0x8B, 0xB7, 0xC5, 0xDA, 0x76,
        0xF5, 0x50, 0xAA, 0x3D, 0x8A, 0x1F, 0xBF, 0xF0,
        0xEB, 0x19, 0xCC, 0xB1, 0xA3, 0x13, 0xD5, 0x5C,
        0xDA, 0x56, 0xC9, 0xEC, 0x2E, 0xF2, 0x96, 0x32,
        0x38, 0x7F, 0xE8, 0xD7, 0x6E, 0x3C, 0x04, 0x68,
        0x04, 0x3E, 0x8F, 0x66, 0x3F, 0x48, 0x60, 0xEE,
        0x12, 0xBF, 0x2D, 0x5B, 0x0B, 0x74, 0x74, 0xD6,
        0xE6, 0x94, 0xF9, 0x1E, 0x6D, 0xCC, 0x40, 0x24,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    };
    return BN_bin2bn(RFC3526_PRIME_6144, sizeof(RFC3526_PRIME_6144), bn);
}

/*-
 * "8192-bit MODP Group" from RFC3526, Section 7.
 *
 * The prime is: 2^8192 - 2^8128 - 1 + 2^64 * { [2^8062 pi] + 4743158 }
 *
 * RFC3526 specifies a generator of 2.
 */

BIGNUM *get_rfc3526_prime_8192(BIGNUM *bn)
{
    static const unsigned char RFC3526_PRIME_8192[] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
        0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
        0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
        0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22,
        0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
        0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B,
        0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
        0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
        0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
        0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B,
        0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
        0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5,
        0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
        0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
        0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05,
        0x98, 0xDA, 0x48, 0x36, 0x1C, 0x55, 0xD3, 0x9A,
        0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
        0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96,
        0x1C, 0x62, 0xF3, 0x56, 0x20, 0x85, 0x52, 0xBB,
        0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D,
        0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04,
        0xF1, 0x74, 0x6C, 0x08, 0xCA, 0x18, 0x21, 0x7C,
        0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B,
        0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03,
        0x9B, 0x27, 0x83, 0xA2, 0xEC, 0x07, 0xA2, 0x8F,
        0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9,
        0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18,
        0x39, 0x95, 0x49, 0x7C, 0xEA, 0x95, 0x6A, 0xE5,
        0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10,
        0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAA, 0xC4, 0x2D,
        0xAD, 0x33, 0x17, 0x0D, 0x04, 0x50, 0x7A, 0x33,
        0xA8, 0x55, 0x21, 0xAB, 0xDF, 0x1C, 0xBA, 0x64,
        0xEC, 0xFB, 0x85, 0x04, 0x58, 0xDB, 0xEF, 0x0A,
        0x8A, 0xEA, 0x71, 0x57, 0x5D, 0x06, 0x0C, 0x7D,
        0xB3, 0x97, 0x0F, 0x85, 0xA6, 0xE1, 0xE4, 0xC7,
        0xAB, 0xF5, 0xAE, 0x8C, 0xDB, 0x09, 0x33, 0xD7,
        0x1E, 0x8C, 0x94, 0xE0, 0x4A, 0x25, 0x61, 0x9D,
        0xCE, 0xE3, 0xD2, 0x26, 0x1A, 0xD2, 0xEE, 0x6B,
        0xF1, 0x2F, 0xFA, 0x06, 0xD9, 0x8A, 0x08, 0x64,
        0xD8, 0x76, 0x02, 0x73, 0x3E, 0xC8, 0x6A, 0x64,
        0x52, 0x1F, 0x2B, 0x18, 0x17, 0x7B, 0x20, 0x0C,
        0xBB, 0xE1, 0x17, 0x57, 0x7A, 0x61, 0x5D, 0x6C,
        0x77, 0x09, 0x88, 0xC0, 0xBA, 0xD9, 0x46, 0xE2,
        0x08, 0xE2, 0x4F, 0xA0, 0x74, 0xE5, 0xAB, 0x31,
        0x43, 0xDB, 0x5B, 0xFC, 0xE0, 0xFD, 0x10, 0x8E,
        0x4B, 0x82, 0xD1, 0x20, 0xA9, 0x21, 0x08, 0x01,
        0x1A, 0x72, 0x3C, 0x12, 0xA7, 0x87, 0xE6, 0xD7,
        0x88, 0x71, 0x9A, 0x10, 0xBD, 0xBA, 0x5B, 0x26,
        0x99, 0xC3, 0x27, 0x18, 0x6A, 0xF4, 0xE2, 0x3C,
        0x1A, 0x94, 0x68, 0x34, 0xB6, 0x15, 0x0B, 0xDA,
        0x25, 0x83, 0xE9, 0xCA, 0x2A, 0xD4, 0x4C, 0xE8,
        0xDB, 0xBB, 0xC2, 0xDB, 0x04, 0xDE, 0x8E, 0xF9,
        0x2E, 0x8E, 0xFC, 0x14, 0x1F, 0xBE, 0xCA, 0xA6,
        0x28, 0x7C, 0x59, 0x47, 0x4E, 0x6B, 0xC0, 0x5D,
        0x99, 0xB2, 0x96, 0x4F, 0xA0, 0x90, 0xC3, 0xA2,
        0x23, 0x3B, 0xA1, 0x86, 0x51, 0x5B, 0xE7, 0xED,
        0x1F, 0x61, 0x29, 0x70, 0xCE, 0xE2, 0xD7, 0xAF,
        0xB8, 0x1B, 0xDD, 0x76, 0x21, 0x70, 0x48, 0x1C,
        0xD0, 0x06, 0x91, 0x27, 0xD5, 0xB0, 0x5A, 0xA9,
        0x93, 0xB4, 0xEA, 0x98, 0x8D, 0x8F, 0xDD, 0xC1,
        0x86, 0xFF, 0xB7, 0xDC, 0x90, 0xA6, 0xC0, 0x8F,
        0x4D, 0xF4, 0x35, 0xC9, 0x34, 0x02, 0x84, 0x92,
        0x36, 0xC3, 0xFA, 0xB4, 0xD2, 0x7C, 0x70, 0x26,
        0xC1, 0xD4, 0xDC, 0xB2, 0x60, 0x26, 0x46, 0xDE,
        0xC9, 0x75, 0x1E, 0x76, 0x3D, 0xBA, 0x37, 0xBD,
        0xF8, 0xFF, 0x94, 0x06, 0xAD, 0x9E, 0x53, 0x0E,
        0xE5, 0xDB, 0x38, 0x2F, 0x41, 0x30, 0x01, 0xAE,
        0xB0, 0x6A, 0x53, 0xED, 0x90, 0x27, 0xD8, 0x31,
        0x17, 0x97, 0x27, 0xB0, 0x86, 0x5A, 0x89, 0x18,
        0xDA, 0x3E, 0xDB, 0xEB, 0xCF, 0x9B, 0x14, 0xED,
        0x44, 0xCE, 0x6C, 0xBA, 0xCE, 0xD4, 0xBB, 0x1B,
        0xDB, 0x7F, 0x14, 0x47, 0xE6, 0xCC, 0x25, 0x4B,
        0x33, 0x20, 0x51, 0x51, 0x2B, 0xD7, 0xAF, 0x42,
        0x6F, 0xB8, 0xF4, 0x01, 0x37, 0x8C, 0xD2, 0xBF,
        0x59, 0x83, 0xCA, 0x01, 0xC6, 0x4B, 0x92, 0xEC,
        0xF0, 0x32, 0xEA, 0x15, 0xD1, 0x72, 0x1D, 0x03,
        0xF4, 0x82, 0xD7, 0xCE, 0x6E, 0x74, 0xFE, 0xF6,
        0xD5, 0x5E, 0x70, 0x2F, 0x46, 0x98, 0x0C, 0x82,
        0xB5, 0xA8, 0x40, 0x31, 0x90, 0x0B, 0x1C, 0x9E,
        0x59, 0xE7, 0xC9, 0x7F, 0xBE, 0xC7, 0xE8, 0xF3,
        0x23, 0xA9, 0x7A, 0x7E, 0x36, 0xCC, 0x88, 0xBE,
        0x0F, 0x1D, 0x45, 0xB7, 0xFF, 0x58, 0x5A, 0xC5,
        0x4B, 0xD4, 0x07, 0xB2, 0x2B, 0x41, 0x54, 0xAA,
        0xCC, 0x8F, 0x6D, 0x7E, 0xBF, 0x48, 0xE1, 0xD8,
        0x14, 0xCC, 0x5E, 0xD2, 0x0F, 0x80, 0x37, 0xE0,
        0xA7, 0x97, 0x15, 0xEE, 0xF2, 0x9B, 0xE3, 0x28,
        0x06, 0xA1, 0xD5, 0x8B, 0xB7, 0xC5, 0xDA, 0x76,
        0xF5, 0x50, 0xAA, 0x3D, 0x8A, 0x1F, 0xBF, 0xF0,
        0xEB, 0x19, 0xCC, 0xB1, 0xA3, 0x13, 0xD5, 0x5C,
        0xDA, 0x56, 0xC9, 0xEC, 0x2E, 0xF2, 0x96, 0x32,
        0x38, 0x7F, 0xE8, 0xD7, 0x6E, 0x3C, 0x04, 0x68,
        0x04, 0x3E, 0x8F, 0x66, 0x3F, 0x48, 0x60, 0xEE,
        0x12, 0xBF, 0x2D, 0x5B, 0x0B, 0x74, 0x74, 0xD6,
        0xE6, 0x94, 0xF9, 0x1E, 0x6D, 0xBE, 0x11, 0x59,
        0x74, 0xA3, 0x92, 0x6F, 0x12, 0xFE, 0xE5, 0xE4,
        0x38, 0x77, 0x7C, 0xB6, 0xA9, 0x32, 0xDF, 0x8C,
        0xD8, 0xBE, 0xC4, 0xD0, 0x73, 0xB9, 0x31, 0xBA,
        0x3B, 0xC8, 0x32, 0xB6, 0x8D, 0x9D, 0xD3, 0x00,
        0x74, 0x1F, 0xA7, 0xBF, 0x8A, 0xFC, 0x47, 0xED,
        0x25, 0x76, 0xF6, 0x93, 0x6B, 0xA4, 0x24, 0x66,
        0x3A, 0xAB, 0x63, 0x9C, 0x5A, 0xE4, 0xF5, 0x68,
        0x34, 0x23, 0xB4, 0x74, 0x2B, 0xF1, 0xC9, 0x78,
        0x23, 0x8F, 0x16, 0xCB, 0xE3, 0x9D, 0x65, 0x2D,
        0xE3, 0xFD, 0xB8, 0xBE, 0xFC, 0x84, 0x8A, 0xD9,
        0x22, 0x22, 0x2E, 0x04, 0xA4, 0x03, 0x7C, 0x07,
        0x13, 0xEB, 0x57, 0xA8, 0x1A, 0x23, 0xF0, 0xC7,
        0x34, 0x73, 0xFC, 0x64, 0x6C, 0xEA, 0x30, 0x6B,
        0x4B, 0xCB, 0xC8, 0x86, 0x2F, 0x83, 0x85, 0xDD,
        0xFA, 0x9D, 0x4B, 0x7F, 0xA2, 0xC0, 0x87, 0xE8,
        0x79, 0x68, 0x33, 0x03, 0xED, 0x5B, 0xDD, 0x3A,
        0x06, 0x2B, 0x3C, 0xF5, 0xB3, 0xA2, 0x78, 0xA6,
        0x6D, 0x2A, 0x13, 0xF8, 0x3F, 0x44, 0xF8, 0x2D,
        0xDF, 0x31, 0x0E, 0xE0, 0x74, 0xAB, 0x6A, 0x36,
        0x45, 0x97, 0xE8, 0x99, 0xA0, 0x25, 0x5D, 0xC1,
        0x64, 0xF3, 0x1C, 0xC5, 0x08, 0x46, 0x85, 0x1D,
        0xF9, 0xAB, 0x48, 0x19, 0x5D, 0xED, 0x7E, 0xA1,
        0xB1, 0xD5, 0x10, 0xBD, 0x7E, 0xE7, 0x4D, 0x73,
        0xFA, 0xF3, 0x6B, 0xC3, 0x1E, 0xCF, 0xA2, 0x68,
        0x35, 0x90, 0x46, 0xF4, 0xEB, 0x87, 0x9F, 0x92,
        0x40, 0x09, 0x43, 0x8B, 0x48, 0x1C, 0x6C, 0xD7,
        0x88, 0x9A, 0x00, 0x2E, 0xD5, 0xEE, 0x38, 0x2B,
        0xC9, 0x19, 0x0D, 0xA6, 0xFC, 0x02, 0x6E, 0x47,
        0x95, 0x58, 0xE4, 0x47, 0x56, 0x77, 0xE9, 0xAA,
        0x9E, 0x30, 0x50, 0xE2, 0x76, 0x56, 0x94, 0xDF,
        0xC8, 0x1F, 0x56, 0xE8, 0x80, 0xB9, 0x6E, 0x71,
        0x60, 0xC9, 0x80, 0xDD, 0x98, 0xED, 0xD3, 0xDF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    };
    return BN_bin2bn(RFC3526_PRIME_8192, sizeof(RFC3526_PRIME_8192), bn);
}
/* crypto/bn/bn_ctx.c */
/* Written by Ulf Moeller for the OpenSSL project. */
/* ====================================================================
 * Copyright (c) 1998-2004 The OpenSSL Project.  All rights reserved.
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

#if !defined(BN_CTX_DEBUG) && !defined(BN_DEBUG)
# ifndef NDEBUG
#  define NDEBUG
# endif
#endif

#include <stdio.h>
#include <assert.h>

// #include "cryptlib.h"
// #include "bn_lcl.h"

/*-
 * TODO list
 *
 * 1. Check a bunch of "(words+1)" type hacks in various bignum functions and
 * check they can be safely removed.
 *  - Check +1 and other ugliness in BN_from_montgomery()
 *
 * 2. Consider allowing a BN_new_ex() that, at least, lets you specify an
 * appropriate 'block' size that will be honoured by bn_expand_internal() to
 * prevent piddly little reallocations. OTOH, profiling bignum expansions in
 * BN_CTX doesn't show this to be a big issue.
 */

/* How many bignums are in each "pool item"; */
#define BN_CTX_POOL_SIZE        16
/* The stack frame info is resizing, set a first-time expansion size; */
#define BN_CTX_START_FRAMES     32

/***********/
/* BN_POOL */
/***********/

/* A bundle of bignums that can be linked with other bundles */
typedef struct bignum_pool_item {
    /* The bignum values */
    BIGNUM vals[BN_CTX_POOL_SIZE];
    /* Linked-list admin */
    struct bignum_pool_item *prev, *next;
} BN_POOL_ITEM;
/* A linked-list of bignums grouped in bundles */
typedef struct bignum_pool {
    /* Linked-list admin */
    BN_POOL_ITEM *head, *current, *tail;
    /* Stack depth and allocation size */
    unsigned used, size;
} BN_POOL;
static void BN_POOL_init(BN_POOL *);
static void BN_POOL_finish(BN_POOL *);
#ifndef OPENSSL_NO_DEPRECATED
static void BN_POOL_reset(BN_POOL *);
#endif
static BIGNUM *BN_POOL_get(BN_POOL *);
static void BN_POOL_release(BN_POOL *, unsigned int);

/************/
/* BN_STACK */
/************/

/* A wrapper to manage the "stack frames" */
typedef struct bignum_ctx_stack {
    /* Array of indexes into the bignum stack */
    unsigned int *indexes;
    /* Number of stack frames, and the size of the allocated array */
    unsigned int depth, size;
} BN_STACK;
static void BN_STACK_init(BN_STACK *);
static void BN_STACK_finish(BN_STACK *);
#ifndef OPENSSL_NO_DEPRECATED
static void BN_STACK_reset(BN_STACK *);
#endif
static int BN_STACK_push(BN_STACK *, unsigned int);
static unsigned int BN_STACK_pop(BN_STACK *);

/**********/
/* BN_CTX */
/**********/

/* The opaque BN_CTX type */
struct bignum_ctx {
    /* The bignum bundles */
    BN_POOL pool;
    /* The "stack frames", if you will */
    BN_STACK stack;
    /* The number of bignums currently assigned */
    unsigned int used;
    /* Depth of stack overflow */
    int err_stack;
    /* Block "gets" until an "end" (compatibility behaviour) */
    int too_many;
};

/* Enable this to find BN_CTX bugs */
#ifdef BN_CTX_DEBUG
static const char *ctxdbg_cur = NULL;
static void ctxdbg(BN_CTX *ctx)
{
    unsigned int bnidx = 0, fpidx = 0;
    BN_POOL_ITEM *item = ctx->pool.head;
    BN_STACK *stack = &ctx->stack;
    fprintf(stderr, "(%16p): ", ctx);
    while (bnidx < ctx->used) {
        fprintf(stderr, "%03x ", item->vals[bnidx++ % BN_CTX_POOL_SIZE].dmax);
        if (!(bnidx % BN_CTX_POOL_SIZE))
            item = item->next;
    }
    fprintf(stderr, "\n");
    bnidx = 0;
    fprintf(stderr, "          : ");
    while (fpidx < stack->depth) {
        while (bnidx++ < stack->indexes[fpidx])
            fprintf(stderr, "    ");
        fprintf(stderr, "^^^ ");
        bnidx++;
        fpidx++;
    }
    fprintf(stderr, "\n");
}

# define CTXDBG_ENTRY(str, ctx)  do { \
                                ctxdbg_cur = (str); \
                                fprintf(stderr,"Starting %s\n", ctxdbg_cur); \
                                ctxdbg(ctx); \
                                } while(0)
# define CTXDBG_EXIT(ctx)        do { \
                                fprintf(stderr,"Ending %s\n", ctxdbg_cur); \
                                ctxdbg(ctx); \
                                } while(0)
# define CTXDBG_RET(ctx,ret)
#else
# define CTXDBG_ENTRY(str, ctx)
# define CTXDBG_EXIT(ctx)
# define CTXDBG_RET(ctx,ret)
#endif

/*
 * This function is an evil legacy and should not be used. This
 * implementation is WYSIWYG, though I've done my best.
 */
#ifndef OPENSSL_NO_DEPRECATED
void BN_CTX_init(BN_CTX *ctx)
{
    /*
     * Assume the caller obtained the context via BN_CTX_new() and so is
     * trying to reset it for use. Nothing else makes sense, least of all
     * binary compatibility from a time when they could declare a static
     * variable.
     */
    BN_POOL_reset(&ctx->pool);
    BN_STACK_reset(&ctx->stack);
    ctx->used = 0;
    ctx->err_stack = 0;
    ctx->too_many = 0;
}
#endif

BN_CTX *BN_CTX_new(void)
{
    BN_CTX *ret = OPENSSL_malloc(sizeof(BN_CTX));
    if (!ret) {
        BNerr(BN_F_BN_CTX_NEW, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    /* Initialise the structure */
    BN_POOL_init(&ret->pool);
    BN_STACK_init(&ret->stack);
    ret->used = 0;
    ret->err_stack = 0;
    ret->too_many = 0;
    return ret;
}

void BN_CTX_free(BN_CTX *ctx)
{
    if (ctx == NULL)
        return;
#ifdef BN_CTX_DEBUG
    {
        BN_POOL_ITEM *pool = ctx->pool.head;
        fprintf(stderr, "BN_CTX_free, stack-size=%d, pool-bignums=%d\n",
                ctx->stack.size, ctx->pool.size);
        fprintf(stderr, "dmaxs: ");
        while (pool) {
            unsigned loop = 0;
            while (loop < BN_CTX_POOL_SIZE)
                fprintf(stderr, "%02x ", pool->vals[loop++].dmax);
            pool = pool->next;
        }
        fprintf(stderr, "\n");
    }
#endif
    BN_STACK_finish(&ctx->stack);
    BN_POOL_finish(&ctx->pool);
    OPENSSL_free(ctx);
}

void BN_CTX_start(BN_CTX *ctx)
{
    CTXDBG_ENTRY("BN_CTX_start", ctx);
    /* If we're already overflowing ... */
    if (ctx->err_stack || ctx->too_many)
        ctx->err_stack++;
    /* (Try to) get a new frame pointer */
    else if (!BN_STACK_push(&ctx->stack, ctx->used)) {
        BNerr(BN_F_BN_CTX_START, BN_R_TOO_MANY_TEMPORARY_VARIABLES);
        ctx->err_stack++;
    }
    CTXDBG_EXIT(ctx);
}

void BN_CTX_end(BN_CTX *ctx)
{
    CTXDBG_ENTRY("BN_CTX_end", ctx);
    if (ctx->err_stack)
        ctx->err_stack--;
    else {
        unsigned int fp = BN_STACK_pop(&ctx->stack);
        /* Does this stack frame have anything to release? */
        if (fp < ctx->used)
            BN_POOL_release(&ctx->pool, ctx->used - fp);
        ctx->used = fp;
        /* Unjam "too_many" in case "get" had failed */
        ctx->too_many = 0;
    }
    CTXDBG_EXIT(ctx);
}

BIGNUM *BN_CTX_get(BN_CTX *ctx)
{
    BIGNUM *ret;
    CTXDBG_ENTRY("BN_CTX_get", ctx);
    if (ctx->err_stack || ctx->too_many)
        return NULL;
    if ((ret = BN_POOL_get(&ctx->pool)) == NULL) {
        /*
         * Setting too_many prevents repeated "get" attempts from cluttering
         * the error stack.
         */
        ctx->too_many = 1;
        BNerr(BN_F_BN_CTX_GET, BN_R_TOO_MANY_TEMPORARY_VARIABLES);
        return NULL;
    }
    /* OK, make sure the returned bignum is "zero" */
    BN_zero(ret);
    ctx->used++;
    CTXDBG_RET(ctx, ret);
    return ret;
}

/************/
/* BN_STACK */
/************/

static void BN_STACK_init(BN_STACK *st)
{
    st->indexes = NULL;
    st->depth = st->size = 0;
}

static void BN_STACK_finish(BN_STACK *st)
{
    if (st->size)
        OPENSSL_free(st->indexes);
}

#ifndef OPENSSL_NO_DEPRECATED
static void BN_STACK_reset(BN_STACK *st)
{
    st->depth = 0;
}
#endif

static int BN_STACK_push(BN_STACK *st, unsigned int idx)
{
    if (st->depth == st->size)
        /* Need to expand */
    {
        unsigned int newsize = (st->size ?
                                (st->size * 3 / 2) : BN_CTX_START_FRAMES);
        unsigned int *newitems = OPENSSL_malloc(newsize *
                                                sizeof(unsigned int));
        if (!newitems)
            return 0;
        if (st->depth)
            memcpy(newitems, st->indexes, st->depth * sizeof(unsigned int));
        if (st->size)
            OPENSSL_free(st->indexes);
        st->indexes = newitems;
        st->size = newsize;
    }
    st->indexes[(st->depth)++] = idx;
    return 1;
}

static unsigned int BN_STACK_pop(BN_STACK *st)
{
    return st->indexes[--(st->depth)];
}

/***********/
/* BN_POOL */
/***********/

static void BN_POOL_init(BN_POOL *p)
{
    p->head = p->current = p->tail = NULL;
    p->used = p->size = 0;
}

static void BN_POOL_finish(BN_POOL *p)
{
    while (p->head) {
        unsigned int loop = 0;
        BIGNUM *bn = p->head->vals;
        while (loop++ < BN_CTX_POOL_SIZE) {
            if (bn->d)
                BN_clear_free(bn);
            bn++;
        }
        p->current = p->head->next;
        OPENSSL_free(p->head);
        p->head = p->current;
    }
}

#ifndef OPENSSL_NO_DEPRECATED
static void BN_POOL_reset(BN_POOL *p)
{
    BN_POOL_ITEM *item = p->head;
    while (item) {
        unsigned int loop = 0;
        BIGNUM *bn = item->vals;
        while (loop++ < BN_CTX_POOL_SIZE) {
            if (bn->d)
                BN_clear(bn);
            bn++;
        }
        item = item->next;
    }
    p->current = p->head;
    p->used = 0;
}
#endif

static BIGNUM *BN_POOL_get(BN_POOL *p)
{
    if (p->used == p->size) {
        BIGNUM *bn;
        unsigned int loop = 0;
        BN_POOL_ITEM *item = OPENSSL_malloc(sizeof(BN_POOL_ITEM));
        if (!item)
            return NULL;
        /* Initialise the structure */
        bn = item->vals;
        while (loop++ < BN_CTX_POOL_SIZE)
            BN_init(bn++);
        item->prev = p->tail;
        item->next = NULL;
        /* Link it in */
        if (!p->head)
            p->head = p->current = p->tail = item;
        else {
            p->tail->next = item;
            p->tail = item;
            p->current = item;
        }
        p->size += BN_CTX_POOL_SIZE;
        p->used++;
        /* Return the first bignum from the new pool */
        return item->vals;
    }
    if (!p->used)
        p->current = p->head;
    else if ((p->used % BN_CTX_POOL_SIZE) == 0)
        p->current = p->current->next;
    return p->current->vals + ((p->used++) % BN_CTX_POOL_SIZE);
}

static void BN_POOL_release(BN_POOL *p, unsigned int num)
{
    unsigned int offset = (p->used - 1) % BN_CTX_POOL_SIZE;
    p->used -= num;
    while (num--) {
        bn_check_top(p->current->vals + offset);
        if (!offset) {
            offset = BN_CTX_POOL_SIZE - 1;
            p->current = p->current->prev;
        } else
            offset--;
    }
}
/* crypto/bn/bn_depr.c */
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

/*
 * Support for deprecated functions goes here - static linkage will only
 * slurp this code if applications are using them directly.
 */

#include <stdio.h>
#include <time.h>
// #include "cryptlib.h"
// #include "bn_lcl.h"
#include "rand.h"

static void *dummy = &dummy;

#ifndef OPENSSL_NO_DEPRECATED
BIGNUM *BN_generate_prime(BIGNUM *ret, int bits, int safe,
                          const BIGNUM *add, const BIGNUM *rem,
                          void (*callback) (int, int, void *), void *cb_arg)
{
    BN_GENCB cb;
    BIGNUM *rnd = NULL;
    int found = 0;

    BN_GENCB_set_old(&cb, callback, cb_arg);

    if (ret == NULL) {
        if ((rnd = BN_new()) == NULL)
            goto err;
    } else
        rnd = ret;
    if (!BN_generate_prime_ex(rnd, bits, safe, add, rem, &cb))
        goto err;

    /* we have a prime :-) */
    found = 1;
 err:
    if (!found && (ret == NULL) && (rnd != NULL))
        BN_free(rnd);
    return (found ? rnd : NULL);
}

int BN_is_prime(const BIGNUM *a, int checks,
                void (*callback) (int, int, void *), BN_CTX *ctx_passed,
                void *cb_arg)
{
    BN_GENCB cb;
    BN_GENCB_set_old(&cb, callback, cb_arg);
    return BN_is_prime_ex(a, checks, ctx_passed, &cb);
}

int BN_is_prime_fasttest(const BIGNUM *a, int checks,
                         void (*callback) (int, int, void *),
                         BN_CTX *ctx_passed, void *cb_arg,
                         int do_trial_division)
{
    BN_GENCB cb;
    BN_GENCB_set_old(&cb, callback, cb_arg);
    return BN_is_prime_fasttest_ex(a, checks, ctx_passed,
                                   do_trial_division, &cb);
}
#endif
/* crypto/bn/bn_div.c */
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
// #include "bn.h"
// #include "cryptlib.h"
// #include "bn_lcl.h"

/* The old slow way */
#if 0
int BN_div(BIGNUM *dv, BIGNUM *rem, const BIGNUM *m, const BIGNUM *d,
           BN_CTX *ctx)
{
    int i, nm, nd;
    int ret = 0;
    BIGNUM *D;

    bn_check_top(m);
    bn_check_top(d);
    if (BN_is_zero(d)) {
        BNerr(BN_F_BN_DIV, BN_R_DIV_BY_ZERO);
        return (0);
    }

    if (BN_ucmp(m, d) < 0) {
        if (rem != NULL) {
            if (BN_copy(rem, m) == NULL)
                return (0);
        }
        if (dv != NULL)
            BN_zero(dv);
        return (1);
    }

    BN_CTX_start(ctx);
    D = BN_CTX_get(ctx);
    if (dv == NULL)
        dv = BN_CTX_get(ctx);
    if (rem == NULL)
        rem = BN_CTX_get(ctx);
    if (D == NULL || dv == NULL || rem == NULL)
        goto end;

    nd = BN_num_bits(d);
    nm = BN_num_bits(m);
    if (BN_copy(D, d) == NULL)
        goto end;
    if (BN_copy(rem, m) == NULL)
        goto end;

    /*
     * The next 2 are needed so we can do a dv->d[0]|=1 later since
     * BN_lshift1 will only work once there is a value :-)
     */
    BN_zero(dv);
    if (bn_wexpand(dv, 1) == NULL)
        goto end;
    dv->top = 1;

    if (!BN_lshift(D, D, nm - nd))
        goto end;
    for (i = nm - nd; i >= 0; i--) {
        if (!BN_lshift1(dv, dv))
            goto end;
        if (BN_ucmp(rem, D) >= 0) {
            dv->d[0] |= 1;
            if (!BN_usub(rem, rem, D))
                goto end;
        }
/* CAN IMPROVE (and have now :=) */
        if (!BN_rshift1(D, D))
            goto end;
    }
    rem->neg = BN_is_zero(rem) ? 0 : m->neg;
    dv->neg = m->neg ^ d->neg;
    ret = 1;
 end:
    BN_CTX_end(ctx);
    return (ret);
}

#else

# if !defined(OPENSSL_NO_ASM) && !defined(OPENSSL_NO_INLINE_ASM) \
    && !defined(PEDANTIC) && !defined(BN_DIV3W)
#  if defined(__GNUC__) && __GNUC__>=2
#   if defined(__i386) || defined (__i386__)
   /*-
    * There were two reasons for implementing this template:
    * - GNU C generates a call to a function (__udivdi3 to be exact)
    *   in reply to ((((BN_ULLONG)n0)<<BN_BITS2)|n1)/d0 (I fail to
    *   understand why...);
    * - divl doesn't only calculate quotient, but also leaves
    *   remainder in %edx which we can definitely use here:-)
    *
    *                                   <appro@fy.chalmers.se>
    */
#    undef bn_div_words
#    define bn_div_words(n0,n1,d0)                \
        ({  asm volatile (                      \
                "divl   %4"                     \
                : "=a"(q), "=d"(rem)            \
                : "a"(n1), "d"(n0), "r"(d0)     \
                : "cc");                        \
            q;                                  \
        })
#    define REMAINDER_IS_ALREADY_CALCULATED
#   elif defined(__x86_64) && defined(SIXTY_FOUR_BIT_LONG)
   /*
    * Same story here, but it's 128-bit by 64-bit division. Wow!
    *                                   <appro@fy.chalmers.se>
    */
#    undef bn_div_words
#    define bn_div_words(n0,n1,d0)                \
        ({  asm volatile (                      \
                "divq   %4"                     \
                : "=a"(q), "=d"(rem)            \
                : "a"(n1), "d"(n0), "r"(d0)     \
                : "cc");                        \
            q;                                  \
        })
#    define REMAINDER_IS_ALREADY_CALCULATED
#   endif                       /* __<cpu> */
#  endif                        /* __GNUC__ */
# endif                         /* OPENSSL_NO_ASM */

/*-
 * BN_div computes  dv := num / divisor,  rounding towards
 * zero, and sets up rm  such that  dv*divisor + rm = num  holds.
 * Thus:
 *     dv->neg == num->neg ^ divisor->neg  (unless the result is zero)
 *     rm->neg == num->neg                 (unless the remainder is zero)
 * If 'dv' or 'rm' is NULL, the respective value is not returned.
 */
int BN_div(BIGNUM *dv, BIGNUM *rm, const BIGNUM *num, const BIGNUM *divisor,
           BN_CTX *ctx)
{
    int norm_shift, i, loop;
    BIGNUM *tmp, wnum, *snum, *sdiv, *res;
    BN_ULONG *resp, *wnump;
    BN_ULONG d0, d1;
    int num_n, div_n;
    int no_branch = 0;

    /*
     * Invalid zero-padding would have particularly bad consequences so don't
     * just rely on bn_check_top() here (bn_check_top() works only for
     * BN_DEBUG builds)
     */
    if ((num->top > 0 && num->d[num->top - 1] == 0) ||
        (divisor->top > 0 && divisor->d[divisor->top - 1] == 0)) {
        BNerr(BN_F_BN_DIV, BN_R_NOT_INITIALIZED);
        return 0;
    }

    bn_check_top(num);
    bn_check_top(divisor);

    if ((BN_get_flags(num, BN_FLG_CONSTTIME) != 0)
        || (BN_get_flags(divisor, BN_FLG_CONSTTIME) != 0)) {
        no_branch = 1;
    }

    bn_check_top(dv);
    bn_check_top(rm);
    /*- bn_check_top(num); *//*
     * 'num' has been checked already
     */
    /*- bn_check_top(divisor); *//*
     * 'divisor' has been checked already
     */

    if (BN_is_zero(divisor)) {
        BNerr(BN_F_BN_DIV, BN_R_DIV_BY_ZERO);
        return (0);
    }

    if (!no_branch && BN_ucmp(num, divisor) < 0) {
        if (rm != NULL) {
            if (BN_copy(rm, num) == NULL)
                return (0);
        }
        if (dv != NULL)
            BN_zero(dv);
        return (1);
    }

    BN_CTX_start(ctx);
    tmp = BN_CTX_get(ctx);
    snum = BN_CTX_get(ctx);
    sdiv = BN_CTX_get(ctx);
    if (dv == NULL)
        res = BN_CTX_get(ctx);
    else
        res = dv;
    if (sdiv == NULL || res == NULL || tmp == NULL || snum == NULL)
        goto err;

    /* First we normalise the numbers */
    norm_shift = BN_BITS2 - ((BN_num_bits(divisor)) % BN_BITS2);
    if (!(BN_lshift(sdiv, divisor, norm_shift)))
        goto err;
    sdiv->neg = 0;
    norm_shift += BN_BITS2;
    if (!(BN_lshift(snum, num, norm_shift)))
        goto err;
    snum->neg = 0;

    if (no_branch) {
        /*
         * Since we don't know whether snum is larger than sdiv, we pad snum
         * with enough zeroes without changing its value.
         */
        if (snum->top <= sdiv->top + 1) {
            if (bn_wexpand(snum, sdiv->top + 2) == NULL)
                goto err;
            for (i = snum->top; i < sdiv->top + 2; i++)
                snum->d[i] = 0;
            snum->top = sdiv->top + 2;
        } else {
            if (bn_wexpand(snum, snum->top + 1) == NULL)
                goto err;
            snum->d[snum->top] = 0;
            snum->top++;
        }
    }

    div_n = sdiv->top;
    num_n = snum->top;
    loop = num_n - div_n;
    /*
     * Lets setup a 'window' into snum This is the part that corresponds to
     * the current 'area' being divided
     */
    wnum.neg = 0;
    wnum.d = &(snum->d[loop]);
    wnum.top = div_n;
    wnum.flags = BN_FLG_STATIC_DATA;
    /*
     * only needed when BN_ucmp messes up the values between top and max
     */
    wnum.dmax = snum->dmax - loop; /* so we don't step out of bounds */

    /* Get the top 2 words of sdiv */
    /* div_n=sdiv->top; */
    d0 = sdiv->d[div_n - 1];
    d1 = (div_n == 1) ? 0 : sdiv->d[div_n - 2];

    /* pointer to the 'top' of snum */
    wnump = &(snum->d[num_n - 1]);

    /* Setup to 'res' */
    res->neg = (num->neg ^ divisor->neg);
    if (!bn_wexpand(res, (loop + 1)))
        goto err;
    res->top = loop - no_branch;
    resp = &(res->d[loop - 1]);

    /* space for temp */
    if (!bn_wexpand(tmp, (div_n + 1)))
        goto err;

    if (!no_branch) {
        if (BN_ucmp(&wnum, sdiv) >= 0) {
            /*
             * If BN_DEBUG_RAND is defined BN_ucmp changes (via bn_pollute)
             * the const bignum arguments => clean the values between top and
             * max again
             */
            bn_clear_top2max(&wnum);
            bn_sub_words(wnum.d, wnum.d, sdiv->d, div_n);
            *resp = 1;
        } else
            res->top--;
    }

    /*
     * if res->top == 0 then clear the neg value otherwise decrease the resp
     * pointer
     */
    if (res->top == 0)
        res->neg = 0;
    else
        resp--;

    for (i = 0; i < loop - 1; i++, wnump--, resp--) {
        BN_ULONG q, l0;
        /*
         * the first part of the loop uses the top two words of snum and sdiv
         * to calculate a BN_ULONG q such that | wnum - sdiv * q | < sdiv
         */
# if defined(BN_DIV3W) && !defined(OPENSSL_NO_ASM)
        BN_ULONG bn_div_3_words(BN_ULONG *, BN_ULONG, BN_ULONG);
        q = bn_div_3_words(wnump, d1, d0);
# else
        BN_ULONG n0, n1, rem = 0;

        n0 = wnump[0];
        n1 = wnump[-1];
        if (n0 == d0)
            q = BN_MASK2;
        else {                  /* n0 < d0 */

#  ifdef BN_LLONG
            BN_ULLONG t2;

#   if defined(BN_LLONG) && defined(BN_DIV2W) && !defined(bn_div_words)
            q = (BN_ULONG)(((((BN_ULLONG) n0) << BN_BITS2) | n1) / d0);
#   else
            q = bn_div_words(n0, n1, d0);
#    ifdef BN_DEBUG_LEVITTE
            fprintf(stderr, "DEBUG: bn_div_words(0x%08X,0x%08X,0x%08\
X) -> 0x%08X\n", n0, n1, d0, q);
#    endif
#   endif

#   ifndef REMAINDER_IS_ALREADY_CALCULATED
            /*
             * rem doesn't have to be BN_ULLONG. The least we
             * know it's less that d0, isn't it?
             */
            rem = (n1 - q * d0) & BN_MASK2;
#   endif
            t2 = (BN_ULLONG) d1 *q;

            for (;;) {
                if (t2 <= ((((BN_ULLONG) rem) << BN_BITS2) | wnump[-2]))
                    break;
                q--;
                rem += d0;
                if (rem < d0)
                    break;      /* don't let rem overflow */
                t2 -= d1;
            }
#  else                         /* !BN_LLONG */
            BN_ULONG t2l, t2h;

            q = bn_div_words(n0, n1, d0);
#   ifdef BN_DEBUG_LEVITTE
            fprintf(stderr, "DEBUG: bn_div_words(0x%08X,0x%08X,0x%08\
X) -> 0x%08X\n", n0, n1, d0, q);
#   endif
#   ifndef REMAINDER_IS_ALREADY_CALCULATED
            rem = (n1 - q * d0) & BN_MASK2;
#   endif

#   if defined(BN_UMULT_LOHI)
            BN_UMULT_LOHI(t2l, t2h, d1, q);
#   elif defined(BN_UMULT_HIGH)
            t2l = d1 * q;
            t2h = BN_UMULT_HIGH(d1, q);
#   else
            {
                BN_ULONG ql, qh;
                t2l = LBITS(d1);
                t2h = HBITS(d1);
                ql = LBITS(q);
                qh = HBITS(q);
                mul64(t2l, t2h, ql, qh); /* t2=(BN_ULLONG)d1*q; */
            }
#   endif

            for (;;) {
                if ((t2h < rem) || ((t2h == rem) && (t2l <= wnump[-2])))
                    break;
                q--;
                rem += d0;
                if (rem < d0)
                    break;      /* don't let rem overflow */
                if (t2l < d1)
                    t2h--;
                t2l -= d1;
            }
#  endif                        /* !BN_LLONG */
        }
# endif                         /* !BN_DIV3W */

        l0 = bn_mul_words(tmp->d, sdiv->d, div_n, q);
        tmp->d[div_n] = l0;
        wnum.d--;
        /*
         * ingore top values of the bignums just sub the two BN_ULONG arrays
         * with bn_sub_words
         */
        if (bn_sub_words(wnum.d, wnum.d, tmp->d, div_n + 1)) {
            /*
             * Note: As we have considered only the leading two BN_ULONGs in
             * the calculation of q, sdiv * q might be greater than wnum (but
             * then (q-1) * sdiv is less or equal than wnum)
             */
            q--;
            if (bn_add_words(wnum.d, wnum.d, sdiv->d, div_n))
                /*
                 * we can't have an overflow here (assuming that q != 0, but
                 * if q == 0 then tmp is zero anyway)
                 */
                (*wnump)++;
        }
        /* store part of the result */
        *resp = q;
    }
    bn_correct_top(snum);
    if (rm != NULL) {
        /*
         * Keep a copy of the neg flag in num because if rm==num BN_rshift()
         * will overwrite it.
         */
        int neg = num->neg;
        BN_rshift(rm, snum, norm_shift);
        if (!BN_is_zero(rm))
            rm->neg = neg;
        bn_check_top(rm);
    }
    if (no_branch)
        bn_correct_top(res);
    BN_CTX_end(ctx);
    return (1);
 err:
    bn_check_top(rm);
    BN_CTX_end(ctx);
    return (0);
}
#endif
/* crypto/bn/bn_err.c */
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
#include "err.h"
// #include "bn.h"

/* BEGIN ERROR CODES */
#ifndef OPENSSL_NO_ERR

# define ERR_FUNC(func) ERR_PACK(ERR_LIB_BN,func,0)
# define ERR_REASON(reason) ERR_PACK(ERR_LIB_BN,0,reason)

static ERR_STRING_DATA BN_str_functs[] = {
    {ERR_FUNC(BN_F_BNRAND), "BNRAND"},
    {ERR_FUNC(BN_F_BN_BLINDING_CONVERT_EX), "BN_BLINDING_convert_ex"},
    {ERR_FUNC(BN_F_BN_BLINDING_CREATE_PARAM), "BN_BLINDING_create_param"},
    {ERR_FUNC(BN_F_BN_BLINDING_INVERT_EX), "BN_BLINDING_invert_ex"},
    {ERR_FUNC(BN_F_BN_BLINDING_NEW), "BN_BLINDING_new"},
    {ERR_FUNC(BN_F_BN_BLINDING_UPDATE), "BN_BLINDING_update"},
    {ERR_FUNC(BN_F_BN_BN2DEC), "BN_bn2dec"},
    {ERR_FUNC(BN_F_BN_BN2HEX), "BN_bn2hex"},
    {ERR_FUNC(BN_F_BN_CTX_GET), "BN_CTX_get"},
    {ERR_FUNC(BN_F_BN_CTX_NEW), "BN_CTX_new"},
    {ERR_FUNC(BN_F_BN_CTX_START), "BN_CTX_start"},
    {ERR_FUNC(BN_F_BN_DIV), "BN_div"},
    {ERR_FUNC(BN_F_BN_DIV_NO_BRANCH), "BN_div_no_branch"},
    {ERR_FUNC(BN_F_BN_DIV_RECP), "BN_div_recp"},
    {ERR_FUNC(BN_F_BN_EXP), "BN_exp"},
    {ERR_FUNC(BN_F_BN_EXPAND2), "bn_expand2"},
    {ERR_FUNC(BN_F_BN_EXPAND_INTERNAL), "BN_EXPAND_INTERNAL"},
    {ERR_FUNC(BN_F_BN_GF2M_MOD), "BN_GF2m_mod"},
    {ERR_FUNC(BN_F_BN_GF2M_MOD_EXP), "BN_GF2m_mod_exp"},
    {ERR_FUNC(BN_F_BN_GF2M_MOD_MUL), "BN_GF2m_mod_mul"},
    {ERR_FUNC(BN_F_BN_GF2M_MOD_SOLVE_QUAD), "BN_GF2m_mod_solve_quad"},
    {ERR_FUNC(BN_F_BN_GF2M_MOD_SOLVE_QUAD_ARR), "BN_GF2m_mod_solve_quad_arr"},
    {ERR_FUNC(BN_F_BN_GF2M_MOD_SQR), "BN_GF2m_mod_sqr"},
    {ERR_FUNC(BN_F_BN_GF2M_MOD_SQRT), "BN_GF2m_mod_sqrt"},
    {ERR_FUNC(BN_F_BN_LSHIFT), "BN_lshift"},
    {ERR_FUNC(BN_F_BN_MOD_EXP2_MONT), "BN_mod_exp2_mont"},
    {ERR_FUNC(BN_F_BN_MOD_EXP_MONT), "BN_mod_exp_mont"},
    {ERR_FUNC(BN_F_BN_MOD_EXP_MONT_CONSTTIME), "BN_mod_exp_mont_consttime"},
    {ERR_FUNC(BN_F_BN_MOD_EXP_MONT_WORD), "BN_mod_exp_mont_word"},
    {ERR_FUNC(BN_F_BN_MOD_EXP_RECP), "BN_mod_exp_recp"},
    {ERR_FUNC(BN_F_BN_MOD_EXP_SIMPLE), "BN_mod_exp_simple"},
    {ERR_FUNC(BN_F_BN_MOD_INVERSE), "BN_mod_inverse"},
    {ERR_FUNC(BN_F_BN_MOD_INVERSE_NO_BRANCH), "BN_mod_inverse_no_branch"},
    {ERR_FUNC(BN_F_BN_MOD_LSHIFT_QUICK), "BN_mod_lshift_quick"},
    {ERR_FUNC(BN_F_BN_MOD_MUL_RECIPROCAL), "BN_mod_mul_reciprocal"},
    {ERR_FUNC(BN_F_BN_MOD_SQRT), "BN_mod_sqrt"},
    {ERR_FUNC(BN_F_BN_MPI2BN), "BN_mpi2bn"},
    {ERR_FUNC(BN_F_BN_NEW), "BN_new"},
    {ERR_FUNC(BN_F_BN_RAND), "BN_rand"},
    {ERR_FUNC(BN_F_BN_RAND_RANGE), "BN_rand_range"},
    {ERR_FUNC(BN_F_BN_RSHIFT), "BN_rshift"},
    {ERR_FUNC(BN_F_BN_USUB), "BN_usub"},
    {0, NULL}
};

static ERR_STRING_DATA BN_str_reasons[] = {
    {ERR_REASON(BN_R_ARG2_LT_ARG3), "arg2 lt arg3"},
    {ERR_REASON(BN_R_BAD_RECIPROCAL), "bad reciprocal"},
    {ERR_REASON(BN_R_BIGNUM_TOO_LONG), "bignum too long"},
    {ERR_REASON(BN_R_BITS_TOO_SMALL), "bits too small"},
    {ERR_REASON(BN_R_CALLED_WITH_EVEN_MODULUS), "called with even modulus"},
    {ERR_REASON(BN_R_DIV_BY_ZERO), "div by zero"},
    {ERR_REASON(BN_R_ENCODING_ERROR), "encoding error"},
    {ERR_REASON(BN_R_EXPAND_ON_STATIC_BIGNUM_DATA),
     "expand on static bignum data"},
    {ERR_REASON(BN_R_INPUT_NOT_REDUCED), "input not reduced"},
    {ERR_REASON(BN_R_INVALID_LENGTH), "invalid length"},
    {ERR_REASON(BN_R_INVALID_RANGE), "invalid range"},
    {ERR_REASON(BN_R_INVALID_SHIFT), "invalid shift"},
    {ERR_REASON(BN_R_NOT_A_SQUARE), "not a square"},
    {ERR_REASON(BN_R_NOT_INITIALIZED), "not initialized"},
    {ERR_REASON(BN_R_NO_INVERSE), "no inverse"},
    {ERR_REASON(BN_R_NO_SOLUTION), "no solution"},
    {ERR_REASON(BN_R_P_IS_NOT_PRIME), "p is not prime"},
    {ERR_REASON(BN_R_TOO_MANY_ITERATIONS), "too many iterations"},
    {ERR_REASON(BN_R_TOO_MANY_TEMPORARY_VARIABLES),
     "too many temporary variables"},
    {0, NULL}
};

#endif

void ERR_load_BN_strings(void)
{
#ifndef OPENSSL_NO_ERR

    if (ERR_func_error_string(BN_str_functs[0].error) == NULL) {
        ERR_load_strings(0, BN_str_functs);
        ERR_load_strings(0, BN_str_reasons);
    }
#endif
}
/* crypto/bn/bn_exp.c */
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

// #include "cryptlib.h"
#include "constant_time_locl.h"
// #include "bn_lcl.h"

#include <stdlib.h>
#ifdef _WIN32
# include <malloc.h>
# ifndef alloca
#  define alloca _alloca
# endif
#elif defined(__GNUC__)
# ifndef alloca
#  define alloca(s) __builtin_alloca((s))
# endif
#elif defined(__sun)
# include <alloca.h>
#endif

#include "rsaz_exp.h"

#undef SPARC_T4_MONT
#if defined(OPENSSL_BN_ASM_MONT) && (defined(__sparc__) || defined(__sparc))
# include "sparc_arch.h"
extern unsigned int OPENSSL_sparcv9cap_P[];
# define SPARC_T4_MONT
#endif

/* maximum precomputation table size for *variable* sliding windows */
#define TABLE_SIZE      32

/* this one works - simple but works */
int BN_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx)
{
    int i, bits, ret = 0;
    BIGNUM *v, *rr;

    if (BN_get_flags(p, BN_FLG_CONSTTIME) != 0
            || BN_get_flags(a, BN_FLG_CONSTTIME) != 0) {
        /* BN_FLG_CONSTTIME only supported by BN_mod_exp_mont() */
        BNerr(BN_F_BN_EXP, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }

    BN_CTX_start(ctx);
    if ((r == a) || (r == p))
        rr = BN_CTX_get(ctx);
    else
        rr = r;
    v = BN_CTX_get(ctx);
    if (rr == NULL || v == NULL)
        goto err;

    if (BN_copy(v, a) == NULL)
        goto err;
    bits = BN_num_bits(p);

    if (BN_is_odd(p)) {
        if (BN_copy(rr, a) == NULL)
            goto err;
    } else {
        if (!BN_one(rr))
            goto err;
    }

    for (i = 1; i < bits; i++) {
        if (!BN_sqr(v, v, ctx))
            goto err;
        if (BN_is_bit_set(p, i)) {
            if (!BN_mul(rr, rr, v, ctx))
                goto err;
        }
    }
    if (r != rr && BN_copy(r, rr) == NULL)
        goto err;

    ret = 1;
 err:
    BN_CTX_end(ctx);
    bn_check_top(r);
    return (ret);
}

int BN_mod_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, const BIGNUM *m,
               BN_CTX *ctx)
{
    int ret;

    bn_check_top(a);
    bn_check_top(p);
    bn_check_top(m);

    /*-
     * For even modulus  m = 2^k*m_odd,  it might make sense to compute
     * a^p mod m_odd  and  a^p mod 2^k  separately (with Montgomery
     * exponentiation for the odd part), using appropriate exponent
     * reductions, and combine the results using the CRT.
     *
     * For now, we use Montgomery only if the modulus is odd; otherwise,
     * exponentiation using the reciprocal-based quick remaindering
     * algorithm is used.
     *
     * (Timing obtained with expspeed.c [computations  a^p mod m
     * where  a, p, m  are of the same length: 256, 512, 1024, 2048,
     * 4096, 8192 bits], compared to the running time of the
     * standard algorithm:
     *
     *   BN_mod_exp_mont   33 .. 40 %  [AMD K6-2, Linux, debug configuration]
     *                     55 .. 77 %  [UltraSparc processor, but
     *                                  debug-solaris-sparcv8-gcc conf.]
     *
     *   BN_mod_exp_recp   50 .. 70 %  [AMD K6-2, Linux, debug configuration]
     *                     62 .. 118 % [UltraSparc, debug-solaris-sparcv8-gcc]
     *
     * On the Sparc, BN_mod_exp_recp was faster than BN_mod_exp_mont
     * at 2048 and more bits, but at 512 and 1024 bits, it was
     * slower even than the standard algorithm!
     *
     * "Real" timings [linux-elf, solaris-sparcv9-gcc configurations]
     * should be obtained when the new Montgomery reduction code
     * has been integrated into OpenSSL.)
     */

#define MONT_MUL_MOD
#define MONT_EXP_WORD
#define RECP_MUL_MOD

#ifdef MONT_MUL_MOD
    /*
     * I have finally been able to take out this pre-condition of the top bit
     * being set.  It was caused by an error in BN_div with negatives.  There
     * was also another problem when for a^b%m a >= m.  eay 07-May-97
     */
    /* if ((m->d[m->top-1]&BN_TBIT) && BN_is_odd(m)) */

    if (BN_is_odd(m)) {
# ifdef MONT_EXP_WORD
        if (a->top == 1 && !a->neg
            && (BN_get_flags(p, BN_FLG_CONSTTIME) == 0)
            && (BN_get_flags(a, BN_FLG_CONSTTIME) == 0)
            && (BN_get_flags(m, BN_FLG_CONSTTIME) == 0)) {
            BN_ULONG A = a->d[0];
            ret = BN_mod_exp_mont_word(r, A, p, m, ctx, NULL);
        } else
# endif
            ret = BN_mod_exp_mont(r, a, p, m, ctx, NULL);
    } else
#endif
#ifdef RECP_MUL_MOD
    {
        ret = BN_mod_exp_recp(r, a, p, m, ctx);
    }
#else
    {
        ret = BN_mod_exp_simple(r, a, p, m, ctx);
    }
#endif

    bn_check_top(r);
    return (ret);
}

int BN_mod_exp_recp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
                    const BIGNUM *m, BN_CTX *ctx)
{
    int i, j, bits, ret = 0, wstart, wend, window, wvalue;
    int start = 1;
    BIGNUM *aa;
    /* Table of variables obtained from 'ctx' */
    BIGNUM *val[TABLE_SIZE];
    BN_RECP_CTX recp;

    if (BN_get_flags(p, BN_FLG_CONSTTIME) != 0
            || BN_get_flags(a, BN_FLG_CONSTTIME) != 0
            || BN_get_flags(m, BN_FLG_CONSTTIME) != 0) {
        /* BN_FLG_CONSTTIME only supported by BN_mod_exp_mont() */
        BNerr(BN_F_BN_MOD_EXP_RECP, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }

    bits = BN_num_bits(p);
    if (bits == 0) {
        /* x**0 mod 1, or x**0 mod -1 is still zero. */
        if (BN_abs_is_word(m, 1)) {
            ret = 1;
            BN_zero(r);
        } else {
            ret = BN_one(r);
        }
        return ret;
    }

    BN_CTX_start(ctx);
    aa = BN_CTX_get(ctx);
    val[0] = BN_CTX_get(ctx);
    if (!aa || !val[0])
        goto err;

    BN_RECP_CTX_init(&recp);
    if (m->neg) {
        /* ignore sign of 'm' */
        if (!BN_copy(aa, m))
            goto err;
        aa->neg = 0;
        if (BN_RECP_CTX_set(&recp, aa, ctx) <= 0)
            goto err;
    } else {
        if (BN_RECP_CTX_set(&recp, m, ctx) <= 0)
            goto err;
    }

    if (!BN_nnmod(val[0], a, m, ctx))
        goto err;               /* 1 */
    if (BN_is_zero(val[0])) {
        BN_zero(r);
        ret = 1;
        goto err;
    }

    window = BN_window_bits_for_exponent_size(bits);
    if (window > 1) {
        if (!BN_mod_mul_reciprocal(aa, val[0], val[0], &recp, ctx))
            goto err;           /* 2 */
        j = 1 << (window - 1);
        for (i = 1; i < j; i++) {
            if (((val[i] = BN_CTX_get(ctx)) == NULL) ||
                !BN_mod_mul_reciprocal(val[i], val[i - 1], aa, &recp, ctx))
                goto err;
        }
    }

    start = 1;                  /* This is used to avoid multiplication etc
                                 * when there is only the value '1' in the
                                 * buffer. */
    wvalue = 0;                 /* The 'value' of the window */
    wstart = bits - 1;          /* The top bit of the window */
    wend = 0;                   /* The bottom bit of the window */

    if (!BN_one(r))
        goto err;

    for (;;) {
        if (BN_is_bit_set(p, wstart) == 0) {
            if (!start)
                if (!BN_mod_mul_reciprocal(r, r, r, &recp, ctx))
                    goto err;
            if (wstart == 0)
                break;
            wstart--;
            continue;
        }
        /*
         * We now have wstart on a 'set' bit, we now need to work out how bit
         * a window to do.  To do this we need to scan forward until the last
         * set bit before the end of the window
         */
        j = wstart;
        wvalue = 1;
        wend = 0;
        for (i = 1; i < window; i++) {
            if (wstart - i < 0)
                break;
            if (BN_is_bit_set(p, wstart - i)) {
                wvalue <<= (i - wend);
                wvalue |= 1;
                wend = i;
            }
        }

        /* wend is the size of the current window */
        j = wend + 1;
        /* add the 'bytes above' */
        if (!start)
            for (i = 0; i < j; i++) {
                if (!BN_mod_mul_reciprocal(r, r, r, &recp, ctx))
                    goto err;
            }

        /* wvalue will be an odd number < 2^window */
        if (!BN_mod_mul_reciprocal(r, r, val[wvalue >> 1], &recp, ctx))
            goto err;

        /* move the 'window' down further */
        wstart -= wend + 1;
        wvalue = 0;
        start = 0;
        if (wstart < 0)
            break;
    }
    ret = 1;
 err:
    BN_CTX_end(ctx);
    BN_RECP_CTX_free(&recp);
    bn_check_top(r);
    return (ret);
}

int BN_mod_exp_mont(BIGNUM *rr, const BIGNUM *a, const BIGNUM *p,
                    const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *in_mont)
{
    int i, j, bits, ret = 0, wstart, wend, window, wvalue;
    int start = 1;
    BIGNUM *d, *r;
    const BIGNUM *aa;
    /* Table of variables obtained from 'ctx' */
    BIGNUM *val[TABLE_SIZE];
    BN_MONT_CTX *mont = NULL;

    if (BN_get_flags(p, BN_FLG_CONSTTIME) != 0
            || BN_get_flags(a, BN_FLG_CONSTTIME) != 0
            || BN_get_flags(m, BN_FLG_CONSTTIME) != 0) {
        return BN_mod_exp_mont_consttime(rr, a, p, m, ctx, in_mont);
    }

    bn_check_top(a);
    bn_check_top(p);
    bn_check_top(m);

    if (!BN_is_odd(m)) {
        BNerr(BN_F_BN_MOD_EXP_MONT, BN_R_CALLED_WITH_EVEN_MODULUS);
        return (0);
    }
    bits = BN_num_bits(p);
    if (bits == 0) {
        /* x**0 mod 1, or x**0 mod -1 is still zero. */
        if (BN_abs_is_word(m, 1)) {
            ret = 1;
            BN_zero(rr);
        } else {
            ret = BN_one(rr);
        }
        return ret;
    }

    BN_CTX_start(ctx);
    d = BN_CTX_get(ctx);
    r = BN_CTX_get(ctx);
    val[0] = BN_CTX_get(ctx);
    if (!d || !r || !val[0])
        goto err;

    /*
     * If this is not done, things will break in the montgomery part
     */

    if (in_mont != NULL)
        mont = in_mont;
    else {
        if ((mont = BN_MONT_CTX_new()) == NULL)
            goto err;
        if (!BN_MONT_CTX_set(mont, m, ctx))
            goto err;
    }

    if (a->neg || BN_ucmp(a, m) >= 0) {
        if (!BN_nnmod(val[0], a, m, ctx))
            goto err;
        aa = val[0];
    } else
        aa = a;
    if (BN_is_zero(aa)) {
        BN_zero(rr);
        ret = 1;
        goto err;
    }
    if (!bn_to_mont_fixed_top(val[0], aa, mont, ctx))
        goto err;               /* 1 */

    window = BN_window_bits_for_exponent_size(bits);
    if (window > 1) {
        if (!bn_mul_mont_fixed_top(d, val[0], val[0], mont, ctx))
            goto err;           /* 2 */
        j = 1 << (window - 1);
        for (i = 1; i < j; i++) {
            if (((val[i] = BN_CTX_get(ctx)) == NULL) ||
                !bn_mul_mont_fixed_top(val[i], val[i - 1], d, mont, ctx))
                goto err;
        }
    }

    start = 1;                  /* This is used to avoid multiplication etc
                                 * when there is only the value '1' in the
                                 * buffer. */
    wvalue = 0;                 /* The 'value' of the window */
    wstart = bits - 1;          /* The top bit of the window */
    wend = 0;                   /* The bottom bit of the window */

#if 1                           /* by Shay Gueron's suggestion */
    j = m->top;                 /* borrow j */
    if (m->d[j - 1] & (((BN_ULONG)1) << (BN_BITS2 - 1))) {
        if (bn_wexpand(r, j) == NULL)
            goto err;
        /* 2^(top*BN_BITS2) - m */
        r->d[0] = (0 - m->d[0]) & BN_MASK2;
        for (i = 1; i < j; i++)
            r->d[i] = (~m->d[i]) & BN_MASK2;
        r->top = j;
        r->flags |= BN_FLG_FIXED_TOP;
    } else
#endif
    if (!bn_to_mont_fixed_top(r, BN_value_one(), mont, ctx))
        goto err;
    for (;;) {
        if (BN_is_bit_set(p, wstart) == 0) {
            if (!start) {
                if (!bn_mul_mont_fixed_top(r, r, r, mont, ctx))
                    goto err;
            }
            if (wstart == 0)
                break;
            wstart--;
            continue;
        }
        /*
         * We now have wstart on a 'set' bit, we now need to work out how bit
         * a window to do.  To do this we need to scan forward until the last
         * set bit before the end of the window
         */
        j = wstart;
        wvalue = 1;
        wend = 0;
        for (i = 1; i < window; i++) {
            if (wstart - i < 0)
                break;
            if (BN_is_bit_set(p, wstart - i)) {
                wvalue <<= (i - wend);
                wvalue |= 1;
                wend = i;
            }
        }

        /* wend is the size of the current window */
        j = wend + 1;
        /* add the 'bytes above' */
        if (!start)
            for (i = 0; i < j; i++) {
                if (!bn_mul_mont_fixed_top(r, r, r, mont, ctx))
                    goto err;
            }

        /* wvalue will be an odd number < 2^window */
        if (!bn_mul_mont_fixed_top(r, r, val[wvalue >> 1], mont, ctx))
            goto err;

        /* move the 'window' down further */
        wstart -= wend + 1;
        wvalue = 0;
        start = 0;
        if (wstart < 0)
            break;
    }
    /*
     * Done with zero-padded intermediate BIGNUMs. Final BN_from_montgomery
     * removes padding [if any] and makes return value suitable for public
     * API consumer.
     */
#if defined(SPARC_T4_MONT)
    if (OPENSSL_sparcv9cap_P[0] & (SPARCV9_VIS3 | SPARCV9_PREFER_FPU)) {
        j = mont->N.top;        /* borrow j */
        val[0]->d[0] = 1;       /* borrow val[0] */
        for (i = 1; i < j; i++)
            val[0]->d[i] = 0;
        val[0]->top = j;
        if (!BN_mod_mul_montgomery(rr, r, val[0], mont, ctx))
            goto err;
    } else
#endif
    if (!BN_from_montgomery(rr, r, mont, ctx))
        goto err;
    ret = 1;
 err:
    if ((in_mont == NULL) && (mont != NULL))
        BN_MONT_CTX_free(mont);
    BN_CTX_end(ctx);
    bn_check_top(rr);
    return (ret);
}

#if defined(SPARC_T4_MONT)
static BN_ULONG bn_get_bits(const BIGNUM *a, int bitpos)
{
    BN_ULONG ret = 0;
    int wordpos;

    wordpos = bitpos / BN_BITS2;
    bitpos %= BN_BITS2;
    if (wordpos >= 0 && wordpos < a->top) {
        ret = a->d[wordpos] & BN_MASK2;
        if (bitpos) {
            ret >>= bitpos;
            if (++wordpos < a->top)
                ret |= a->d[wordpos] << (BN_BITS2 - bitpos);
        }
    }

    return ret & BN_MASK2;
}
#endif

/*
 * BN_mod_exp_mont_consttime() stores the precomputed powers in a specific
 * layout so that accessing any of these table values shows the same access
 * pattern as far as cache lines are concerned.  The following functions are
 * used to transfer a BIGNUM from/to that table.
 */

static int MOD_EXP_CTIME_COPY_TO_PREBUF(const BIGNUM *b, int top,
                                        unsigned char *buf, int idx,
                                        int window)
{
    int i, j;
    int width = 1 << window;
    BN_ULONG *table = (BN_ULONG *)buf;

    if (top > b->top)
        top = b->top;           /* this works because 'buf' is explicitly
                                 * zeroed */
    for (i = 0, j = idx; i < top; i++, j += width) {
        table[j] = b->d[i];
    }

    return 1;
}

static int MOD_EXP_CTIME_COPY_FROM_PREBUF(BIGNUM *b, int top,
                                          unsigned char *buf, int idx,
                                          int window)
{
    int i, j;
    int width = 1 << window;
    volatile BN_ULONG *table = (volatile BN_ULONG *)buf;

    if (bn_wexpand(b, top) == NULL)
        return 0;

    if (window <= 3) {
        for (i = 0; i < top; i++, table += width) {
            BN_ULONG acc = 0;

            for (j = 0; j < width; j++) {
                acc |= table[j] &
                       ((BN_ULONG)0 - (constant_time_eq_int(j,idx)&1));
            }

            b->d[i] = acc;
        }
    } else {
        int xstride = 1 << (window - 2);
        BN_ULONG y0, y1, y2, y3;

        i = idx >> (window - 2);        /* equivalent of idx / xstride */
        idx &= xstride - 1;             /* equivalent of idx % xstride */

        y0 = (BN_ULONG)0 - (constant_time_eq_int(i,0)&1);
        y1 = (BN_ULONG)0 - (constant_time_eq_int(i,1)&1);
        y2 = (BN_ULONG)0 - (constant_time_eq_int(i,2)&1);
        y3 = (BN_ULONG)0 - (constant_time_eq_int(i,3)&1);

        for (i = 0; i < top; i++, table += width) {
            BN_ULONG acc = 0;

            for (j = 0; j < xstride; j++) {
                acc |= ( (table[j + 0 * xstride] & y0) |
                         (table[j + 1 * xstride] & y1) |
                         (table[j + 2 * xstride] & y2) |
                         (table[j + 3 * xstride] & y3) )
                       & ((BN_ULONG)0 - (constant_time_eq_int(j,idx)&1));
            }

            b->d[i] = acc;
        }
    }

    b->top = top;
    b->flags |= BN_FLG_FIXED_TOP;
    return 1;
}

/*
 * Given a pointer value, compute the next address that is a cache line
 * multiple.
 */
#define MOD_EXP_CTIME_ALIGN(x_) \
        ((unsigned char*)(x_) + (MOD_EXP_CTIME_MIN_CACHE_LINE_WIDTH - (((size_t)(x_)) & (MOD_EXP_CTIME_MIN_CACHE_LINE_MASK))))

/*
 * This variant of BN_mod_exp_mont() uses fixed windows and the special
 * precomputation memory layout to limit data-dependency to a minimum to
 * protect secret exponents (cf. the hyper-threading timing attacks pointed
 * out by Colin Percival,
 * http://www.daemonology.net/hyperthreading-considered-harmful/)
 */
int BN_mod_exp_mont_consttime(BIGNUM *rr, const BIGNUM *a, const BIGNUM *p,
                              const BIGNUM *m, BN_CTX *ctx,
                              BN_MONT_CTX *in_mont)
{
    int i, bits, ret = 0, window, wvalue;
    int top;
    BN_MONT_CTX *mont = NULL;

    int numPowers;
    unsigned char *powerbufFree = NULL;
    int powerbufLen = 0;
    unsigned char *powerbuf = NULL;
    BIGNUM tmp, am;
#if defined(SPARC_T4_MONT)
    unsigned int t4 = 0;
#endif

    bn_check_top(a);
    bn_check_top(p);
    bn_check_top(m);

    if (!BN_is_odd(m)) {
        BNerr(BN_F_BN_MOD_EXP_MONT_CONSTTIME, BN_R_CALLED_WITH_EVEN_MODULUS);
        return (0);
    }

    top = m->top;

    /*
     * Use all bits stored in |p|, rather than |BN_num_bits|, so we do not leak
     * whether the top bits are zero.
     */
    bits = p->top * BN_BITS2;
    if (bits == 0) {
        /* x**0 mod 1, or x**0 mod -1 is still zero. */
        if (BN_abs_is_word(m, 1)) {
            ret = 1;
            BN_zero(rr);
        } else {
            ret = BN_one(rr);
        }
        return ret;
    }

    BN_CTX_start(ctx);

    /*
     * Allocate a montgomery context if it was not supplied by the caller. If
     * this is not done, things will break in the montgomery part.
     */
    if (in_mont != NULL)
        mont = in_mont;
    else {
        if ((mont = BN_MONT_CTX_new()) == NULL)
            goto err;
        if (!BN_MONT_CTX_set(mont, m, ctx))
            goto err;
    }

#ifdef RSAZ_ENABLED
    /*
     * If the size of the operands allow it, perform the optimized
     * RSAZ exponentiation. For further information see
     * crypto/bn/rsaz_exp.c and accompanying assembly modules.
     */
    if ((16 == a->top) && (16 == p->top) && (BN_num_bits(m) == 1024)
        && rsaz_avx2_eligible()) {
        if (NULL == bn_wexpand(rr, 16))
            goto err;
        RSAZ_1024_mod_exp_avx2(rr->d, a->d, p->d, m->d, mont->RR.d,
                               mont->n0[0]);
        rr->top = 16;
        rr->neg = 0;
        bn_correct_top(rr);
        ret = 1;
        goto err;
    } else if ((8 == a->top) && (8 == p->top) && (BN_num_bits(m) == 512)) {
        if (NULL == bn_wexpand(rr, 8))
            goto err;
        RSAZ_512_mod_exp(rr->d, a->d, p->d, m->d, mont->n0[0], mont->RR.d);
        rr->top = 8;
        rr->neg = 0;
        bn_correct_top(rr);
        ret = 1;
        goto err;
    }
#endif

    /* Get the window size to use with size of p. */
    window = BN_window_bits_for_ctime_exponent_size(bits);
#if defined(SPARC_T4_MONT)
    if (window >= 5 && (top & 15) == 0 && top <= 64 &&
        (OPENSSL_sparcv9cap_P[1] & (CFR_MONTMUL | CFR_MONTSQR)) ==
        (CFR_MONTMUL | CFR_MONTSQR) && (t4 = OPENSSL_sparcv9cap_P[0]))
        window = 5;
    else
#endif
#if defined(OPENSSL_BN_ASM_MONT5)
    if (window >= 5) {
        window = 5;             /* ~5% improvement for RSA2048 sign, and even
                                 * for RSA4096 */
        /* reserve space for mont->N.d[] copy */
        powerbufLen += top * sizeof(mont->N.d[0]);
    }
#endif
    (void)0;

    /*
     * Allocate a buffer large enough to hold all of the pre-computed powers
     * of am, am itself and tmp.
     */
    numPowers = 1 << window;
    powerbufLen += sizeof(m->d[0]) * (top * numPowers +
                                      ((2 * top) >
                                       numPowers ? (2 * top) : numPowers));
#ifdef alloca
    if (powerbufLen < 3072)
        powerbufFree =
            alloca(powerbufLen + MOD_EXP_CTIME_MIN_CACHE_LINE_WIDTH);
    else
#endif
        if ((powerbufFree =
             (unsigned char *)OPENSSL_malloc(powerbufLen +
                                             MOD_EXP_CTIME_MIN_CACHE_LINE_WIDTH))
            == NULL)
        goto err;

    powerbuf = MOD_EXP_CTIME_ALIGN(powerbufFree);
    memset(powerbuf, 0, powerbufLen);

#ifdef alloca
    if (powerbufLen < 3072)
        powerbufFree = NULL;
#endif

    /* lay down tmp and am right after powers table */
    tmp.d = (BN_ULONG *)(powerbuf + sizeof(m->d[0]) * top * numPowers);
    am.d = tmp.d + top;
    tmp.top = am.top = 0;
    tmp.dmax = am.dmax = top;
    tmp.neg = am.neg = 0;
    tmp.flags = am.flags = BN_FLG_STATIC_DATA;

    /* prepare a^0 in Montgomery domain */
#if 1                           /* by Shay Gueron's suggestion */
    if (m->d[top - 1] & (((BN_ULONG)1) << (BN_BITS2 - 1))) {
        /* 2^(top*BN_BITS2) - m */
        tmp.d[0] = (0 - m->d[0]) & BN_MASK2;
        for (i = 1; i < top; i++)
            tmp.d[i] = (~m->d[i]) & BN_MASK2;
        tmp.top = top;
    } else
#endif
    if (!bn_to_mont_fixed_top(&tmp, BN_value_one(), mont, ctx))
        goto err;

    /* prepare a^1 in Montgomery domain */
    if (a->neg || BN_ucmp(a, m) >= 0) {
        if (!BN_mod(&am, a, m, ctx))
            goto err;
        if (!bn_to_mont_fixed_top(&am, &am, mont, ctx))
            goto err;
    } else if (!bn_to_mont_fixed_top(&am, a, mont, ctx))
        goto err;

#if defined(SPARC_T4_MONT)
    if (t4) {
        typedef int (*bn_pwr5_mont_f) (BN_ULONG *tp, const BN_ULONG *np,
                                       const BN_ULONG *n0, const void *table,
                                       int power, int bits);
        int bn_pwr5_mont_t4_8(BN_ULONG *tp, const BN_ULONG *np,
                              const BN_ULONG *n0, const void *table,
                              int power, int bits);
        int bn_pwr5_mont_t4_16(BN_ULONG *tp, const BN_ULONG *np,
                               const BN_ULONG *n0, const void *table,
                               int power, int bits);
        int bn_pwr5_mont_t4_24(BN_ULONG *tp, const BN_ULONG *np,
                               const BN_ULONG *n0, const void *table,
                               int power, int bits);
        int bn_pwr5_mont_t4_32(BN_ULONG *tp, const BN_ULONG *np,
                               const BN_ULONG *n0, const void *table,
                               int power, int bits);
        static const bn_pwr5_mont_f pwr5_funcs[4] = {
            bn_pwr5_mont_t4_8, bn_pwr5_mont_t4_16,
            bn_pwr5_mont_t4_24, bn_pwr5_mont_t4_32
        };
        bn_pwr5_mont_f pwr5_worker = pwr5_funcs[top / 16 - 1];

        typedef int (*bn_mul_mont_f) (BN_ULONG *rp, const BN_ULONG *ap,
                                      const void *bp, const BN_ULONG *np,
                                      const BN_ULONG *n0);
        int bn_mul_mont_t4_8(BN_ULONG *rp, const BN_ULONG *ap, const void *bp,
                             const BN_ULONG *np, const BN_ULONG *n0);
        int bn_mul_mont_t4_16(BN_ULONG *rp, const BN_ULONG *ap,
                              const void *bp, const BN_ULONG *np,
                              const BN_ULONG *n0);
        int bn_mul_mont_t4_24(BN_ULONG *rp, const BN_ULONG *ap,
                              const void *bp, const BN_ULONG *np,
                              const BN_ULONG *n0);
        int bn_mul_mont_t4_32(BN_ULONG *rp, const BN_ULONG *ap,
                              const void *bp, const BN_ULONG *np,
                              const BN_ULONG *n0);
        static const bn_mul_mont_f mul_funcs[4] = {
            bn_mul_mont_t4_8, bn_mul_mont_t4_16,
            bn_mul_mont_t4_24, bn_mul_mont_t4_32
        };
        bn_mul_mont_f mul_worker = mul_funcs[top / 16 - 1];

        void bn_mul_mont_vis3(BN_ULONG *rp, const BN_ULONG *ap,
                              const void *bp, const BN_ULONG *np,
                              const BN_ULONG *n0, int num);
        void bn_mul_mont_t4(BN_ULONG *rp, const BN_ULONG *ap,
                            const void *bp, const BN_ULONG *np,
                            const BN_ULONG *n0, int num);
        void bn_mul_mont_gather5_t4(BN_ULONG *rp, const BN_ULONG *ap,
                                    const void *table, const BN_ULONG *np,
                                    const BN_ULONG *n0, int num, int power);
        void bn_flip_n_scatter5_t4(const BN_ULONG *inp, size_t num,
                                   void *table, size_t power);
        void bn_gather5_t4(BN_ULONG *out, size_t num,
                           void *table, size_t power);
        void bn_flip_t4(BN_ULONG *dst, BN_ULONG *src, size_t num);

        BN_ULONG *np = mont->N.d, *n0 = mont->n0;
        int stride = 5 * (6 - (top / 16 - 1)); /* multiple of 5, but less
                                                * than 32 */

        /*
         * BN_to_montgomery can contaminate words above .top [in
         * BN_DEBUG[_DEBUG] build]...
         */
        for (i = am.top; i < top; i++)
            am.d[i] = 0;
        for (i = tmp.top; i < top; i++)
            tmp.d[i] = 0;

        bn_flip_n_scatter5_t4(tmp.d, top, powerbuf, 0);
        bn_flip_n_scatter5_t4(am.d, top, powerbuf, 1);
        if (!(*mul_worker) (tmp.d, am.d, am.d, np, n0) &&
            !(*mul_worker) (tmp.d, am.d, am.d, np, n0))
            bn_mul_mont_vis3(tmp.d, am.d, am.d, np, n0, top);
        bn_flip_n_scatter5_t4(tmp.d, top, powerbuf, 2);

        for (i = 3; i < 32; i++) {
            /* Calculate a^i = a^(i-1) * a */
            if (!(*mul_worker) (tmp.d, tmp.d, am.d, np, n0) &&
                !(*mul_worker) (tmp.d, tmp.d, am.d, np, n0))
                bn_mul_mont_vis3(tmp.d, tmp.d, am.d, np, n0, top);
            bn_flip_n_scatter5_t4(tmp.d, top, powerbuf, i);
        }

        /* switch to 64-bit domain */
        np = alloca(top * sizeof(BN_ULONG));
        top /= 2;
        bn_flip_t4(np, mont->N.d, top);

        bits--;
        for (wvalue = 0, i = bits % 5; i >= 0; i--, bits--)
            wvalue = (wvalue << 1) + BN_is_bit_set(p, bits);
        bn_gather5_t4(tmp.d, top, powerbuf, wvalue);

        /*
         * Scan the exponent one window at a time starting from the most
         * significant bits.
         */
        while (bits >= 0) {
            if (bits < stride)
                stride = bits + 1;
            bits -= stride;
            wvalue = bn_get_bits(p, bits + 1);

            if ((*pwr5_worker) (tmp.d, np, n0, powerbuf, wvalue, stride))
                continue;
            /* retry once and fall back */
            if ((*pwr5_worker) (tmp.d, np, n0, powerbuf, wvalue, stride))
                continue;

            bits += stride - 5;
            wvalue >>= stride - 5;
            wvalue &= 31;
            bn_mul_mont_t4(tmp.d, tmp.d, tmp.d, np, n0, top);
            bn_mul_mont_t4(tmp.d, tmp.d, tmp.d, np, n0, top);
            bn_mul_mont_t4(tmp.d, tmp.d, tmp.d, np, n0, top);
            bn_mul_mont_t4(tmp.d, tmp.d, tmp.d, np, n0, top);
            bn_mul_mont_t4(tmp.d, tmp.d, tmp.d, np, n0, top);
            bn_mul_mont_gather5_t4(tmp.d, tmp.d, powerbuf, np, n0, top,
                                   wvalue);
        }

        bn_flip_t4(tmp.d, tmp.d, top);
        top *= 2;
        /* back to 32-bit domain */
        tmp.top = top;
        bn_correct_top(&tmp);
        OPENSSL_cleanse(np, top * sizeof(BN_ULONG));
    } else
#endif
#if defined(OPENSSL_BN_ASM_MONT5)
    if (window == 5 && top > 1) {
        /*
         * This optimization uses ideas from http://eprint.iacr.org/2011/239,
         * specifically optimization of cache-timing attack countermeasures
         * and pre-computation optimization.
         */

        /*
         * Dedicated window==4 case improves 512-bit RSA sign by ~15%, but as
         * 512-bit RSA is hardly relevant, we omit it to spare size...
         */
        void bn_mul_mont_gather5(BN_ULONG *rp, const BN_ULONG *ap,
                                 const void *table, const BN_ULONG *np,
                                 const BN_ULONG *n0, int num, int power);
        void bn_scatter5(const BN_ULONG *inp, size_t num,
                         void *table, size_t power);
        void bn_gather5(BN_ULONG *out, size_t num, void *table, size_t power);
        void bn_power5(BN_ULONG *rp, const BN_ULONG *ap,
                       const void *table, const BN_ULONG *np,
                       const BN_ULONG *n0, int num, int power);
        int bn_get_bits5(const BN_ULONG *ap, int off);
        int bn_from_montgomery(BN_ULONG *rp, const BN_ULONG *ap,
                               const BN_ULONG *not_used, const BN_ULONG *np,
                               const BN_ULONG *n0, int num);

        BN_ULONG *n0 = mont->n0, *np;

        /*
         * BN_to_montgomery can contaminate words above .top [in
         * BN_DEBUG[_DEBUG] build]...
         */
        for (i = am.top; i < top; i++)
            am.d[i] = 0;
        for (i = tmp.top; i < top; i++)
            tmp.d[i] = 0;

        /*
         * copy mont->N.d[] to improve cache locality
         */
        for (np = am.d + top, i = 0; i < top; i++)
            np[i] = mont->N.d[i];

        bn_scatter5(tmp.d, top, powerbuf, 0);
        bn_scatter5(am.d, am.top, powerbuf, 1);
        bn_mul_mont(tmp.d, am.d, am.d, np, n0, top);
        bn_scatter5(tmp.d, top, powerbuf, 2);

# if 0
        for (i = 3; i < 32; i++) {
            /* Calculate a^i = a^(i-1) * a */
            bn_mul_mont_gather5(tmp.d, am.d, powerbuf, np, n0, top, i - 1);
            bn_scatter5(tmp.d, top, powerbuf, i);
        }
# else
        /* same as above, but uses squaring for 1/2 of operations */
        for (i = 4; i < 32; i *= 2) {
            bn_mul_mont(tmp.d, tmp.d, tmp.d, np, n0, top);
            bn_scatter5(tmp.d, top, powerbuf, i);
        }
        for (i = 3; i < 8; i += 2) {
            int j;
            bn_mul_mont_gather5(tmp.d, am.d, powerbuf, np, n0, top, i - 1);
            bn_scatter5(tmp.d, top, powerbuf, i);
            for (j = 2 * i; j < 32; j *= 2) {
                bn_mul_mont(tmp.d, tmp.d, tmp.d, np, n0, top);
                bn_scatter5(tmp.d, top, powerbuf, j);
            }
        }
        for (; i < 16; i += 2) {
            bn_mul_mont_gather5(tmp.d, am.d, powerbuf, np, n0, top, i - 1);
            bn_scatter5(tmp.d, top, powerbuf, i);
            bn_mul_mont(tmp.d, tmp.d, tmp.d, np, n0, top);
            bn_scatter5(tmp.d, top, powerbuf, 2 * i);
        }
        for (; i < 32; i += 2) {
            bn_mul_mont_gather5(tmp.d, am.d, powerbuf, np, n0, top, i - 1);
            bn_scatter5(tmp.d, top, powerbuf, i);
        }
# endif
        bits--;
        for (wvalue = 0, i = bits % 5; i >= 0; i--, bits--)
            wvalue = (wvalue << 1) + BN_is_bit_set(p, bits);
        bn_gather5(tmp.d, top, powerbuf, wvalue);

        /*
         * Scan the exponent one window at a time starting from the most
         * significant bits.
         */
        if (top & 7)
            while (bits >= 0) {
                for (wvalue = 0, i = 0; i < 5; i++, bits--)
                    wvalue = (wvalue << 1) + BN_is_bit_set(p, bits);

                bn_mul_mont(tmp.d, tmp.d, tmp.d, np, n0, top);
                bn_mul_mont(tmp.d, tmp.d, tmp.d, np, n0, top);
                bn_mul_mont(tmp.d, tmp.d, tmp.d, np, n0, top);
                bn_mul_mont(tmp.d, tmp.d, tmp.d, np, n0, top);
                bn_mul_mont(tmp.d, tmp.d, tmp.d, np, n0, top);
                bn_mul_mont_gather5(tmp.d, tmp.d, powerbuf, np, n0, top,
                                    wvalue);
        } else {
            while (bits >= 0) {
                wvalue = bn_get_bits5(p->d, bits - 4);
                bits -= 5;
                bn_power5(tmp.d, tmp.d, powerbuf, np, n0, top, wvalue);
            }
        }

        ret = bn_from_montgomery(tmp.d, tmp.d, NULL, np, n0, top);
        tmp.top = top;
        bn_correct_top(&tmp);
        if (ret) {
            if (!BN_copy(rr, &tmp))
                ret = 0;
            goto err;           /* non-zero ret means it's not error */
        }
    } else
#endif
    {
        if (!MOD_EXP_CTIME_COPY_TO_PREBUF(&tmp, top, powerbuf, 0, window))
            goto err;
        if (!MOD_EXP_CTIME_COPY_TO_PREBUF(&am, top, powerbuf, 1, window))
            goto err;

        /*
         * If the window size is greater than 1, then calculate
         * val[i=2..2^winsize-1]. Powers are computed as a*a^(i-1) (even
         * powers could instead be computed as (a^(i/2))^2 to use the slight
         * performance advantage of sqr over mul).
         */
        if (window > 1) {
            if (!bn_mul_mont_fixed_top(&tmp, &am, &am, mont, ctx))
                goto err;
            if (!MOD_EXP_CTIME_COPY_TO_PREBUF(&tmp, top, powerbuf, 2,
                                              window))
                goto err;
            for (i = 3; i < numPowers; i++) {
                /* Calculate a^i = a^(i-1) * a */
                if (!bn_mul_mont_fixed_top(&tmp, &am, &tmp, mont, ctx))
                    goto err;
                if (!MOD_EXP_CTIME_COPY_TO_PREBUF(&tmp, top, powerbuf, i,
                                                  window))
                    goto err;
            }
        }

        bits--;
        for (wvalue = 0, i = bits % window; i >= 0; i--, bits--)
            wvalue = (wvalue << 1) + BN_is_bit_set(p, bits);
        if (!MOD_EXP_CTIME_COPY_FROM_PREBUF(&tmp, top, powerbuf, wvalue,
                                            window))
            goto err;

        /*
         * Scan the exponent one window at a time starting from the most
         * significant bits.
         */
        while (bits >= 0) {
            wvalue = 0;         /* The 'value' of the window */

            /* Scan the window, squaring the result as we go */
            for (i = 0; i < window; i++, bits--) {
                if (!bn_mul_mont_fixed_top(&tmp, &tmp, &tmp, mont, ctx))
                    goto err;
                wvalue = (wvalue << 1) + BN_is_bit_set(p, bits);
            }

            /*
             * Fetch the appropriate pre-computed value from the pre-buf
             */
            if (!MOD_EXP_CTIME_COPY_FROM_PREBUF(&am, top, powerbuf, wvalue,
                                                window))
                goto err;

            /* Multiply the result into the intermediate result */
            if (!bn_mul_mont_fixed_top(&tmp, &tmp, &am, mont, ctx))
                goto err;
        }
    }

    /*
     * Done with zero-padded intermediate BIGNUMs. Final BN_from_montgomery
     * removes padding [if any] and makes return value suitable for public
     * API consumer.
     */
#if defined(SPARC_T4_MONT)
    if (OPENSSL_sparcv9cap_P[0] & (SPARCV9_VIS3 | SPARCV9_PREFER_FPU)) {
        am.d[0] = 1;            /* borrow am */
        for (i = 1; i < top; i++)
            am.d[i] = 0;
        if (!BN_mod_mul_montgomery(rr, &tmp, &am, mont, ctx))
            goto err;
    } else
#endif
    if (!BN_from_montgomery(rr, &tmp, mont, ctx))
        goto err;
    ret = 1;
 err:
    if ((in_mont == NULL) && (mont != NULL))
        BN_MONT_CTX_free(mont);
    if (powerbuf != NULL) {
        OPENSSL_cleanse(powerbuf, powerbufLen);
        if (powerbufFree)
            OPENSSL_free(powerbufFree);
    }
    BN_CTX_end(ctx);
    return (ret);
}

int BN_mod_exp_mont_word(BIGNUM *rr, BN_ULONG a, const BIGNUM *p,
                         const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *in_mont)
{
    BN_MONT_CTX *mont = NULL;
    int b, bits, ret = 0;
    int r_is_one;
    BN_ULONG w, next_w;
    BIGNUM *d, *r, *t;
    BIGNUM *swap_tmp;
#define BN_MOD_MUL_WORD(r, w, m) \
                (BN_mul_word(r, (w)) && \
                (/* BN_ucmp(r, (m)) < 0 ? 1 :*/  \
                        (BN_mod(t, r, m, ctx) && (swap_tmp = r, r = t, t = swap_tmp, 1))))
    /*
     * BN_MOD_MUL_WORD is only used with 'w' large, so the BN_ucmp test is
     * probably more overhead than always using BN_mod (which uses BN_copy if
     * a similar test returns true).
     */
    /*
     * We can use BN_mod and do not need BN_nnmod because our accumulator is
     * never negative (the result of BN_mod does not depend on the sign of
     * the modulus).
     */
#define BN_TO_MONTGOMERY_WORD(r, w, mont) \
                (BN_set_word(r, (w)) && BN_to_montgomery(r, r, (mont), ctx))

    if (BN_get_flags(p, BN_FLG_CONSTTIME) != 0
            || BN_get_flags(m, BN_FLG_CONSTTIME) != 0) {
        /* BN_FLG_CONSTTIME only supported by BN_mod_exp_mont() */
        BNerr(BN_F_BN_MOD_EXP_MONT_WORD, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }

    bn_check_top(p);
    bn_check_top(m);

    if (!BN_is_odd(m)) {
        BNerr(BN_F_BN_MOD_EXP_MONT_WORD, BN_R_CALLED_WITH_EVEN_MODULUS);
        return (0);
    }
    if (m->top == 1)
        a %= m->d[0];           /* make sure that 'a' is reduced */

    bits = BN_num_bits(p);
    if (bits == 0) {
        /* x**0 mod 1, or x**0 mod -1 is still zero. */
        if (BN_abs_is_word(m, 1)) {
            ret = 1;
            BN_zero(rr);
        } else {
            ret = BN_one(rr);
        }
        return ret;
    }
    if (a == 0) {
        BN_zero(rr);
        ret = 1;
        return ret;
    }

    BN_CTX_start(ctx);
    d = BN_CTX_get(ctx);
    r = BN_CTX_get(ctx);
    t = BN_CTX_get(ctx);
    if (d == NULL || r == NULL || t == NULL)
        goto err;

    if (in_mont != NULL)
        mont = in_mont;
    else {
        if ((mont = BN_MONT_CTX_new()) == NULL)
            goto err;
        if (!BN_MONT_CTX_set(mont, m, ctx))
            goto err;
    }

    r_is_one = 1;               /* except for Montgomery factor */

    /* bits-1 >= 0 */

    /* The result is accumulated in the product r*w. */
    w = a;                      /* bit 'bits-1' of 'p' is always set */
    for (b = bits - 2; b >= 0; b--) {
        /* First, square r*w. */
        next_w = w * w;
        if ((next_w / w) != w) { /* overflow */
            if (r_is_one) {
                if (!BN_TO_MONTGOMERY_WORD(r, w, mont))
                    goto err;
                r_is_one = 0;
            } else {
                if (!BN_MOD_MUL_WORD(r, w, m))
                    goto err;
            }
            next_w = 1;
        }
        w = next_w;
        if (!r_is_one) {
            if (!BN_mod_mul_montgomery(r, r, r, mont, ctx))
                goto err;
        }

        /* Second, multiply r*w by 'a' if exponent bit is set. */
        if (BN_is_bit_set(p, b)) {
            next_w = w * a;
            if ((next_w / a) != w) { /* overflow */
                if (r_is_one) {
                    if (!BN_TO_MONTGOMERY_WORD(r, w, mont))
                        goto err;
                    r_is_one = 0;
                } else {
                    if (!BN_MOD_MUL_WORD(r, w, m))
                        goto err;
                }
                next_w = a;
            }
            w = next_w;
        }
    }

    /* Finally, set r:=r*w. */
    if (w != 1) {
        if (r_is_one) {
            if (!BN_TO_MONTGOMERY_WORD(r, w, mont))
                goto err;
            r_is_one = 0;
        } else {
            if (!BN_MOD_MUL_WORD(r, w, m))
                goto err;
        }
    }

    if (r_is_one) {             /* can happen only if a == 1 */
        if (!BN_one(rr))
            goto err;
    } else {
        if (!BN_from_montgomery(rr, r, mont, ctx))
            goto err;
    }
    ret = 1;
 err:
    if ((in_mont == NULL) && (mont != NULL))
        BN_MONT_CTX_free(mont);
    BN_CTX_end(ctx);
    bn_check_top(rr);
    return (ret);
}

/* The old fallback, simple version :-) */
int BN_mod_exp_simple(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
                      const BIGNUM *m, BN_CTX *ctx)
{
    int i, j, bits, ret = 0, wstart, wend, window, wvalue;
    int start = 1;
    BIGNUM *d;
    /* Table of variables obtained from 'ctx' */
    BIGNUM *val[TABLE_SIZE];

    if (BN_get_flags(p, BN_FLG_CONSTTIME) != 0
            || BN_get_flags(a, BN_FLG_CONSTTIME) != 0
            || BN_get_flags(m, BN_FLG_CONSTTIME) != 0) {
        /* BN_FLG_CONSTTIME only supported by BN_mod_exp_mont() */
        BNerr(BN_F_BN_MOD_EXP_SIMPLE, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }

    bits = BN_num_bits(p);
    if (bits == 0) {
        /* x**0 mod 1, or x**0 mod -1 is still zero. */
        if (BN_abs_is_word(m, 1)) {
            ret = 1;
            BN_zero(r);
        } else {
            ret = BN_one(r);
        }
        return ret;
    }

    BN_CTX_start(ctx);
    d = BN_CTX_get(ctx);
    val[0] = BN_CTX_get(ctx);
    if (!d || !val[0])
        goto err;

    if (!BN_nnmod(val[0], a, m, ctx))
        goto err;               /* 1 */
    if (BN_is_zero(val[0])) {
        BN_zero(r);
        ret = 1;
        goto err;
    }

    window = BN_window_bits_for_exponent_size(bits);
    if (window > 1) {
        if (!BN_mod_mul(d, val[0], val[0], m, ctx))
            goto err;           /* 2 */
        j = 1 << (window - 1);
        for (i = 1; i < j; i++) {
            if (((val[i] = BN_CTX_get(ctx)) == NULL) ||
                !BN_mod_mul(val[i], val[i - 1], d, m, ctx))
                goto err;
        }
    }

    start = 1;                  /* This is used to avoid multiplication etc
                                 * when there is only the value '1' in the
                                 * buffer. */
    wvalue = 0;                 /* The 'value' of the window */
    wstart = bits - 1;          /* The top bit of the window */
    wend = 0;                   /* The bottom bit of the window */

    if (!BN_one(r))
        goto err;

    for (;;) {
        if (BN_is_bit_set(p, wstart) == 0) {
            if (!start)
                if (!BN_mod_mul(r, r, r, m, ctx))
                    goto err;
            if (wstart == 0)
                break;
            wstart--;
            continue;
        }
        /*
         * We now have wstart on a 'set' bit, we now need to work out how bit
         * a window to do.  To do this we need to scan forward until the last
         * set bit before the end of the window
         */
        j = wstart;
        wvalue = 1;
        wend = 0;
        for (i = 1; i < window; i++) {
            if (wstart - i < 0)
                break;
            if (BN_is_bit_set(p, wstart - i)) {
                wvalue <<= (i - wend);
                wvalue |= 1;
                wend = i;
            }
        }

        /* wend is the size of the current window */
        j = wend + 1;
        /* add the 'bytes above' */
        if (!start)
            for (i = 0; i < j; i++) {
                if (!BN_mod_mul(r, r, r, m, ctx))
                    goto err;
            }

        /* wvalue will be an odd number < 2^window */
        if (!BN_mod_mul(r, r, val[wvalue >> 1], m, ctx))
            goto err;

        /* move the 'window' down further */
        wstart -= wend + 1;
        wvalue = 0;
        start = 0;
        if (wstart < 0)
            break;
    }
    ret = 1;
 err:
    BN_CTX_end(ctx);
    bn_check_top(r);
    return (ret);
}
/* crypto/bn/bn_exp2.c */
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
// #include "bn_lcl.h"

#define TABLE_SIZE      32

int BN_mod_exp2_mont(BIGNUM *rr, const BIGNUM *a1, const BIGNUM *p1,
                     const BIGNUM *a2, const BIGNUM *p2, const BIGNUM *m,
                     BN_CTX *ctx, BN_MONT_CTX *in_mont)
{
    int i, j, bits, b, bits1, bits2, ret =
        0, wpos1, wpos2, window1, window2, wvalue1, wvalue2;
    int r_is_one = 1;
    BIGNUM *d, *r;
    const BIGNUM *a_mod_m;
    /* Tables of variables obtained from 'ctx' */
    BIGNUM *val1[TABLE_SIZE], *val2[TABLE_SIZE];
    BN_MONT_CTX *mont = NULL;

    bn_check_top(a1);
    bn_check_top(p1);
    bn_check_top(a2);
    bn_check_top(p2);
    bn_check_top(m);

    if (!(m->d[0] & 1)) {
        BNerr(BN_F_BN_MOD_EXP2_MONT, BN_R_CALLED_WITH_EVEN_MODULUS);
        return (0);
    }
    bits1 = BN_num_bits(p1);
    bits2 = BN_num_bits(p2);
    if ((bits1 == 0) && (bits2 == 0)) {
        ret = BN_one(rr);
        return ret;
    }

    bits = (bits1 > bits2) ? bits1 : bits2;

    BN_CTX_start(ctx);
    d = BN_CTX_get(ctx);
    r = BN_CTX_get(ctx);
    val1[0] = BN_CTX_get(ctx);
    val2[0] = BN_CTX_get(ctx);
    if (!d || !r || !val1[0] || !val2[0])
        goto err;

    if (in_mont != NULL)
        mont = in_mont;
    else {
        if ((mont = BN_MONT_CTX_new()) == NULL)
            goto err;
        if (!BN_MONT_CTX_set(mont, m, ctx))
            goto err;
    }

    window1 = BN_window_bits_for_exponent_size(bits1);
    window2 = BN_window_bits_for_exponent_size(bits2);

    /*
     * Build table for a1:   val1[i] := a1^(2*i + 1) mod m  for i = 0 .. 2^(window1-1)
     */
    if (a1->neg || BN_ucmp(a1, m) >= 0) {
        if (!BN_mod(val1[0], a1, m, ctx))
            goto err;
        a_mod_m = val1[0];
    } else
        a_mod_m = a1;
    if (BN_is_zero(a_mod_m)) {
        BN_zero(rr);
        ret = 1;
        goto err;
    }

    if (!BN_to_montgomery(val1[0], a_mod_m, mont, ctx))
        goto err;
    if (window1 > 1) {
        if (!BN_mod_mul_montgomery(d, val1[0], val1[0], mont, ctx))
            goto err;

        j = 1 << (window1 - 1);
        for (i = 1; i < j; i++) {
            if (((val1[i] = BN_CTX_get(ctx)) == NULL) ||
                !BN_mod_mul_montgomery(val1[i], val1[i - 1], d, mont, ctx))
                goto err;
        }
    }

    /*
     * Build table for a2:   val2[i] := a2^(2*i + 1) mod m  for i = 0 .. 2^(window2-1)
     */
    if (a2->neg || BN_ucmp(a2, m) >= 0) {
        if (!BN_mod(val2[0], a2, m, ctx))
            goto err;
        a_mod_m = val2[0];
    } else
        a_mod_m = a2;
    if (BN_is_zero(a_mod_m)) {
        BN_zero(rr);
        ret = 1;
        goto err;
    }
    if (!BN_to_montgomery(val2[0], a_mod_m, mont, ctx))
        goto err;
    if (window2 > 1) {
        if (!BN_mod_mul_montgomery(d, val2[0], val2[0], mont, ctx))
            goto err;

        j = 1 << (window2 - 1);
        for (i = 1; i < j; i++) {
            if (((val2[i] = BN_CTX_get(ctx)) == NULL) ||
                !BN_mod_mul_montgomery(val2[i], val2[i - 1], d, mont, ctx))
                goto err;
        }
    }

    /* Now compute the power product, using independent windows. */
    r_is_one = 1;
    wvalue1 = 0;                /* The 'value' of the first window */
    wvalue2 = 0;                /* The 'value' of the second window */
    wpos1 = 0;                  /* If wvalue1 > 0, the bottom bit of the
                                 * first window */
    wpos2 = 0;                  /* If wvalue2 > 0, the bottom bit of the
                                 * second window */

    if (!BN_to_montgomery(r, BN_value_one(), mont, ctx))
        goto err;
    for (b = bits - 1; b >= 0; b--) {
        if (!r_is_one) {
            if (!BN_mod_mul_montgomery(r, r, r, mont, ctx))
                goto err;
        }

        if (!wvalue1)
            if (BN_is_bit_set(p1, b)) {
                /*
                 * consider bits b-window1+1 .. b for this window
                 */
                i = b - window1 + 1;
                while (!BN_is_bit_set(p1, i)) /* works for i<0 */
                    i++;
                wpos1 = i;
                wvalue1 = 1;
                for (i = b - 1; i >= wpos1; i--) {
                    wvalue1 <<= 1;
                    if (BN_is_bit_set(p1, i))
                        wvalue1++;
                }
            }

        if (!wvalue2)
            if (BN_is_bit_set(p2, b)) {
                /*
                 * consider bits b-window2+1 .. b for this window
                 */
                i = b - window2 + 1;
                while (!BN_is_bit_set(p2, i))
                    i++;
                wpos2 = i;
                wvalue2 = 1;
                for (i = b - 1; i >= wpos2; i--) {
                    wvalue2 <<= 1;
                    if (BN_is_bit_set(p2, i))
                        wvalue2++;
                }
            }

        if (wvalue1 && b == wpos1) {
            /* wvalue1 is odd and < 2^window1 */
            if (!BN_mod_mul_montgomery(r, r, val1[wvalue1 >> 1], mont, ctx))
                goto err;
            wvalue1 = 0;
            r_is_one = 0;
        }

        if (wvalue2 && b == wpos2) {
            /* wvalue2 is odd and < 2^window2 */
            if (!BN_mod_mul_montgomery(r, r, val2[wvalue2 >> 1], mont, ctx))
                goto err;
            wvalue2 = 0;
            r_is_one = 0;
        }
    }
    if (!BN_from_montgomery(rr, r, mont, ctx))
        goto err;
    ret = 1;
 err:
    if ((in_mont == NULL) && (mont != NULL))
        BN_MONT_CTX_free(mont);
    BN_CTX_end(ctx);
    bn_check_top(rr);
    return (ret);
}
/* crypto/bn/bn_gcd.c */
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

// #include "cryptlib.h"
// #include "bn_lcl.h"

static BIGNUM *euclid(BIGNUM *a, BIGNUM *b);

int BN_gcd(BIGNUM *r, const BIGNUM *in_a, const BIGNUM *in_b, BN_CTX *ctx)
{
    BIGNUM *a, *b, *t;
    int ret = 0;

    bn_check_top(in_a);
    bn_check_top(in_b);

    BN_CTX_start(ctx);
    a = BN_CTX_get(ctx);
    b = BN_CTX_get(ctx);
    if (a == NULL || b == NULL)
        goto err;

    if (BN_copy(a, in_a) == NULL)
        goto err;
    if (BN_copy(b, in_b) == NULL)
        goto err;
    a->neg = 0;
    b->neg = 0;

    if (BN_cmp(a, b) < 0) {
        t = a;
        a = b;
        b = t;
    }
    t = euclid(a, b);
    if (t == NULL)
        goto err;

    if (BN_copy(r, t) == NULL)
        goto err;
    ret = 1;
 err:
    BN_CTX_end(ctx);
    bn_check_top(r);
    return (ret);
}

static BIGNUM *euclid(BIGNUM *a, BIGNUM *b)
{
    BIGNUM *t;
    int shifts = 0;

    bn_check_top(a);
    bn_check_top(b);

    /* 0 <= b <= a */
    while (!BN_is_zero(b)) {
        /* 0 < b <= a */

        if (BN_is_odd(a)) {
            if (BN_is_odd(b)) {
                if (!BN_sub(a, a, b))
                    goto err;
                if (!BN_rshift1(a, a))
                    goto err;
                if (BN_cmp(a, b) < 0) {
                    t = a;
                    a = b;
                    b = t;
                }
            } else {            /* a odd - b even */

                if (!BN_rshift1(b, b))
                    goto err;
                if (BN_cmp(a, b) < 0) {
                    t = a;
                    a = b;
                    b = t;
                }
            }
        } else {                /* a is even */

            if (BN_is_odd(b)) {
                if (!BN_rshift1(a, a))
                    goto err;
                if (BN_cmp(a, b) < 0) {
                    t = a;
                    a = b;
                    b = t;
                }
            } else {            /* a even - b even */

                if (!BN_rshift1(a, a))
                    goto err;
                if (!BN_rshift1(b, b))
                    goto err;
                shifts++;
            }
        }
        /* 0 <= b <= a */
    }

    if (shifts) {
        if (!BN_lshift(a, a, shifts))
            goto err;
    }
    bn_check_top(a);
    return (a);
 err:
    return (NULL);
}

/* solves ax == 1 (mod n) */
static BIGNUM *BN_mod_inverse_no_branch(BIGNUM *in,
                                        const BIGNUM *a, const BIGNUM *n,
                                        BN_CTX *ctx);

BIGNUM *BN_mod_inverse(BIGNUM *in,
                       const BIGNUM *a, const BIGNUM *n, BN_CTX *ctx)
{
    BIGNUM *A, *B, *X, *Y, *M, *D, *T, *R = NULL;
    BIGNUM *ret = NULL;
    int sign;

    if ((BN_get_flags(a, BN_FLG_CONSTTIME) != 0)
        || (BN_get_flags(n, BN_FLG_CONSTTIME) != 0)) {
        return BN_mod_inverse_no_branch(in, a, n, ctx);
    }

    bn_check_top(a);
    bn_check_top(n);

    BN_CTX_start(ctx);
    A = BN_CTX_get(ctx);
    B = BN_CTX_get(ctx);
    X = BN_CTX_get(ctx);
    D = BN_CTX_get(ctx);
    M = BN_CTX_get(ctx);
    Y = BN_CTX_get(ctx);
    T = BN_CTX_get(ctx);
    if (T == NULL)
        goto err;

    if (in == NULL)
        R = BN_new();
    else
        R = in;
    if (R == NULL)
        goto err;

    BN_one(X);
    BN_zero(Y);
    if (BN_copy(B, a) == NULL)
        goto err;
    if (BN_copy(A, n) == NULL)
        goto err;
    A->neg = 0;
    if (B->neg || (BN_ucmp(B, A) >= 0)) {
        if (!BN_nnmod(B, B, A, ctx))
            goto err;
    }
    sign = -1;
    /*-
     * From  B = a mod |n|,  A = |n|  it follows that
     *
     *      0 <= B < A,
     *     -sign*X*a  ==  B   (mod |n|),
     *      sign*Y*a  ==  A   (mod |n|).
     */

    if (BN_is_odd(n) && (BN_num_bits(n) <= (BN_BITS <= 32 ? 450 : 2048))) {
        /*
         * Binary inversion algorithm; requires odd modulus. This is faster
         * than the general algorithm if the modulus is sufficiently small
         * (about 400 .. 500 bits on 32-bit sytems, but much more on 64-bit
         * systems)
         */
        int shift;

        while (!BN_is_zero(B)) {
            /*-
             *      0 < B < |n|,
             *      0 < A <= |n|,
             * (1) -sign*X*a  ==  B   (mod |n|),
             * (2)  sign*Y*a  ==  A   (mod |n|)
             */

            /*
             * Now divide B by the maximum possible power of two in the
             * integers, and divide X by the same value mod |n|. When we're
             * done, (1) still holds.
             */
            shift = 0;
            while (!BN_is_bit_set(B, shift)) { /* note that 0 < B */
                shift++;

                if (BN_is_odd(X)) {
                    if (!BN_uadd(X, X, n))
                        goto err;
                }
                /*
                 * now X is even, so we can easily divide it by two
                 */
                if (!BN_rshift1(X, X))
                    goto err;
            }
            if (shift > 0) {
                if (!BN_rshift(B, B, shift))
                    goto err;
            }

            /*
             * Same for A and Y.  Afterwards, (2) still holds.
             */
            shift = 0;
            while (!BN_is_bit_set(A, shift)) { /* note that 0 < A */
                shift++;

                if (BN_is_odd(Y)) {
                    if (!BN_uadd(Y, Y, n))
                        goto err;
                }
                /* now Y is even */
                if (!BN_rshift1(Y, Y))
                    goto err;
            }
            if (shift > 0) {
                if (!BN_rshift(A, A, shift))
                    goto err;
            }

            /*-
             * We still have (1) and (2).
             * Both  A  and  B  are odd.
             * The following computations ensure that
             *
             *     0 <= B < |n|,
             *      0 < A < |n|,
             * (1) -sign*X*a  ==  B   (mod |n|),
             * (2)  sign*Y*a  ==  A   (mod |n|),
             *
             * and that either  A  or  B  is even in the next iteration.
             */
            if (BN_ucmp(B, A) >= 0) {
                /* -sign*(X + Y)*a == B - A  (mod |n|) */
                if (!BN_uadd(X, X, Y))
                    goto err;
                /*
                 * NB: we could use BN_mod_add_quick(X, X, Y, n), but that
                 * actually makes the algorithm slower
                 */
                if (!BN_usub(B, B, A))
                    goto err;
            } else {
                /*  sign*(X + Y)*a == A - B  (mod |n|) */
                if (!BN_uadd(Y, Y, X))
                    goto err;
                /*
                 * as above, BN_mod_add_quick(Y, Y, X, n) would slow things
                 * down
                 */
                if (!BN_usub(A, A, B))
                    goto err;
            }
        }
    } else {
        /* general inversion algorithm */

        while (!BN_is_zero(B)) {
            BIGNUM *tmp;

            /*-
             *      0 < B < A,
             * (*) -sign*X*a  ==  B   (mod |n|),
             *      sign*Y*a  ==  A   (mod |n|)
             */

            /* (D, M) := (A/B, A%B) ... */
            if (BN_num_bits(A) == BN_num_bits(B)) {
                if (!BN_one(D))
                    goto err;
                if (!BN_sub(M, A, B))
                    goto err;
            } else if (BN_num_bits(A) == BN_num_bits(B) + 1) {
                /* A/B is 1, 2, or 3 */
                if (!BN_lshift1(T, B))
                    goto err;
                if (BN_ucmp(A, T) < 0) {
                    /* A < 2*B, so D=1 */
                    if (!BN_one(D))
                        goto err;
                    if (!BN_sub(M, A, B))
                        goto err;
                } else {
                    /* A >= 2*B, so D=2 or D=3 */
                    if (!BN_sub(M, A, T))
                        goto err;
                    if (!BN_add(D, T, B))
                        goto err; /* use D (:= 3*B) as temp */
                    if (BN_ucmp(A, D) < 0) {
                        /* A < 3*B, so D=2 */
                        if (!BN_set_word(D, 2))
                            goto err;
                        /*
                         * M (= A - 2*B) already has the correct value
                         */
                    } else {
                        /* only D=3 remains */
                        if (!BN_set_word(D, 3))
                            goto err;
                        /*
                         * currently M = A - 2*B, but we need M = A - 3*B
                         */
                        if (!BN_sub(M, M, B))
                            goto err;
                    }
                }
            } else {
                if (!BN_div(D, M, A, B, ctx))
                    goto err;
            }

            /*-
             * Now
             *      A = D*B + M;
             * thus we have
             * (**)  sign*Y*a  ==  D*B + M   (mod |n|).
             */

            tmp = A;            /* keep the BIGNUM object, the value does not
                                 * matter */

            /* (A, B) := (B, A mod B) ... */
            A = B;
            B = M;
            /* ... so we have  0 <= B < A  again */

            /*-
             * Since the former  M  is now  B  and the former  B  is now  A,
             * (**) translates into
             *       sign*Y*a  ==  D*A + B    (mod |n|),
             * i.e.
             *       sign*Y*a - D*A  ==  B    (mod |n|).
             * Similarly, (*) translates into
             *      -sign*X*a  ==  A          (mod |n|).
             *
             * Thus,
             *   sign*Y*a + D*sign*X*a  ==  B  (mod |n|),
             * i.e.
             *        sign*(Y + D*X)*a  ==  B  (mod |n|).
             *
             * So if we set  (X, Y, sign) := (Y + D*X, X, -sign),  we arrive back at
             *      -sign*X*a  ==  B   (mod |n|),
             *       sign*Y*a  ==  A   (mod |n|).
             * Note that  X  and  Y  stay non-negative all the time.
             */

            /*
             * most of the time D is very small, so we can optimize tmp :=
             * D*X+Y
             */
            if (BN_is_one(D)) {
                if (!BN_add(tmp, X, Y))
                    goto err;
            } else {
                if (BN_is_word(D, 2)) {
                    if (!BN_lshift1(tmp, X))
                        goto err;
                } else if (BN_is_word(D, 4)) {
                    if (!BN_lshift(tmp, X, 2))
                        goto err;
                } else if (D->top == 1) {
                    if (!BN_copy(tmp, X))
                        goto err;
                    if (!BN_mul_word(tmp, D->d[0]))
                        goto err;
                } else {
                    if (!BN_mul(tmp, D, X, ctx))
                        goto err;
                }
                if (!BN_add(tmp, tmp, Y))
                    goto err;
            }

            M = Y;              /* keep the BIGNUM object, the value does not
                                 * matter */
            Y = X;
            X = tmp;
            sign = -sign;
        }
    }

    /*-
     * The while loop (Euclid's algorithm) ends when
     *      A == gcd(a,n);
     * we have
     *       sign*Y*a  ==  A  (mod |n|),
     * where  Y  is non-negative.
     */

    if (sign < 0) {
        if (!BN_sub(Y, n, Y))
            goto err;
    }
    /* Now  Y*a  ==  A  (mod |n|).  */

    if (BN_is_one(A)) {
        /* Y*a == 1  (mod |n|) */
        if (!Y->neg && BN_ucmp(Y, n) < 0) {
            if (!BN_copy(R, Y))
                goto err;
        } else {
            if (!BN_nnmod(R, Y, n, ctx))
                goto err;
        }
    } else {
        BNerr(BN_F_BN_MOD_INVERSE, BN_R_NO_INVERSE);
        goto err;
    }
    ret = R;
 err:
    if ((ret == NULL) && (in == NULL))
        BN_free(R);
    BN_CTX_end(ctx);
    bn_check_top(ret);
    return (ret);
}

/*
 * BN_mod_inverse_no_branch is a special version of BN_mod_inverse. It does
 * not contain branches that may leak sensitive information.
 */
static BIGNUM *BN_mod_inverse_no_branch(BIGNUM *in,
                                        const BIGNUM *a, const BIGNUM *n,
                                        BN_CTX *ctx)
{
    BIGNUM *A, *B, *X, *Y, *M, *D, *T, *R = NULL;
    BIGNUM local_A, local_B;
    BIGNUM *pA, *pB;
    BIGNUM *ret = NULL;
    int sign;

    bn_check_top(a);
    bn_check_top(n);

    BN_CTX_start(ctx);
    A = BN_CTX_get(ctx);
    B = BN_CTX_get(ctx);
    X = BN_CTX_get(ctx);
    D = BN_CTX_get(ctx);
    M = BN_CTX_get(ctx);
    Y = BN_CTX_get(ctx);
    T = BN_CTX_get(ctx);
    if (T == NULL)
        goto err;

    if (in == NULL)
        R = BN_new();
    else
        R = in;
    if (R == NULL)
        goto err;

    BN_one(X);
    BN_zero(Y);
    if (BN_copy(B, a) == NULL)
        goto err;
    if (BN_copy(A, n) == NULL)
        goto err;
    A->neg = 0;

    if (B->neg || (BN_ucmp(B, A) >= 0)) {
        /*
         * Turn BN_FLG_CONSTTIME flag on, so that when BN_div is invoked,
         * BN_div_no_branch will be called eventually.
         */
        pB = &local_B;
        local_B.flags = 0;
        BN_with_flags(pB, B, BN_FLG_CONSTTIME);
        if (!BN_nnmod(B, pB, A, ctx))
            goto err;
    }
    sign = -1;
    /*-
     * From  B = a mod |n|,  A = |n|  it follows that
     *
     *      0 <= B < A,
     *     -sign*X*a  ==  B   (mod |n|),
     *      sign*Y*a  ==  A   (mod |n|).
     */

    while (!BN_is_zero(B)) {
        BIGNUM *tmp;

        /*-
         *      0 < B < A,
         * (*) -sign*X*a  ==  B   (mod |n|),
         *      sign*Y*a  ==  A   (mod |n|)
         */

        /*
         * Turn BN_FLG_CONSTTIME flag on, so that when BN_div is invoked,
         * BN_div_no_branch will be called eventually.
         */
        pA = &local_A;
        local_A.flags = 0;
        BN_with_flags(pA, A, BN_FLG_CONSTTIME);

        /* (D, M) := (A/B, A%B) ... */
        if (!BN_div(D, M, pA, B, ctx))
            goto err;

        /*-
         * Now
         *      A = D*B + M;
         * thus we have
         * (**)  sign*Y*a  ==  D*B + M   (mod |n|).
         */

        tmp = A;                /* keep the BIGNUM object, the value does not
                                 * matter */

        /* (A, B) := (B, A mod B) ... */
        A = B;
        B = M;
        /* ... so we have  0 <= B < A  again */

        /*-
         * Since the former  M  is now  B  and the former  B  is now  A,
         * (**) translates into
         *       sign*Y*a  ==  D*A + B    (mod |n|),
         * i.e.
         *       sign*Y*a - D*A  ==  B    (mod |n|).
         * Similarly, (*) translates into
         *      -sign*X*a  ==  A          (mod |n|).
         *
         * Thus,
         *   sign*Y*a + D*sign*X*a  ==  B  (mod |n|),
         * i.e.
         *        sign*(Y + D*X)*a  ==  B  (mod |n|).
         *
         * So if we set  (X, Y, sign) := (Y + D*X, X, -sign),  we arrive back at
         *      -sign*X*a  ==  B   (mod |n|),
         *       sign*Y*a  ==  A   (mod |n|).
         * Note that  X  and  Y  stay non-negative all the time.
         */

        if (!BN_mul(tmp, D, X, ctx))
            goto err;
        if (!BN_add(tmp, tmp, Y))
            goto err;

        M = Y;                  /* keep the BIGNUM object, the value does not
                                 * matter */
        Y = X;
        X = tmp;
        sign = -sign;
    }

    /*-
     * The while loop (Euclid's algorithm) ends when
     *      A == gcd(a,n);
     * we have
     *       sign*Y*a  ==  A  (mod |n|),
     * where  Y  is non-negative.
     */

    if (sign < 0) {
        if (!BN_sub(Y, n, Y))
            goto err;
    }
    /* Now  Y*a  ==  A  (mod |n|).  */

    if (BN_is_one(A)) {
        /* Y*a == 1  (mod |n|) */
        if (!Y->neg && BN_ucmp(Y, n) < 0) {
            if (!BN_copy(R, Y))
                goto err;
        } else {
            if (!BN_nnmod(R, Y, n, ctx))
                goto err;
        }
    } else {
        BNerr(BN_F_BN_MOD_INVERSE_NO_BRANCH, BN_R_NO_INVERSE);
        goto err;
    }
    ret = R;
 err:
    if ((ret == NULL) && (in == NULL))
        BN_free(R);
    BN_CTX_end(ctx);
    bn_check_top(ret);
    return (ret);
}
/* crypto/bn/bn_gf2m.c */
/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 *
 * The Elliptic Curve Public-Key Crypto Library (ECC Code) included
 * herein is developed by SUN MICROSYSTEMS, INC., and is contributed
 * to the OpenSSL project.
 *
 * The ECC Code is licensed pursuant to the OpenSSL open source
 * license provided below.
 *
 * In addition, Sun covenants to all licensees who provide a reciprocal
 * covenant with respect to their own patents if any, not to sue under
 * current and future patent claims necessarily infringed by the making,
 * using, practicing, selling, offering for sale and/or otherwise
 * disposing of the ECC Code as delivered hereunder (or portions thereof),
 * provided that such covenant shall not apply:
 *  1) for code that a licensee deletes from the ECC Code;
 *  2) separates from the ECC Code; or
 *  3) for infringements caused by:
 *       i) the modification of the ECC Code or
 *      ii) the combination of the ECC Code with other software or
 *          devices where such combination causes the infringement.
 *
 * The software is originally written by Sheueling Chang Shantz and
 * Douglas Stebila of Sun Microsystems Laboratories.
 *
 */

/*
 * NOTE: This file is licensed pursuant to the OpenSSL license below and may
 * be modified; but after modifications, the above covenant may no longer
 * apply! In such cases, the corresponding paragraph ["In addition, Sun
 * covenants ... causes the infringement."] and this note can be edited out;
 * but please keep the Sun copyright notice and attribution.
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

#include <assert.h>
#include <limits.h>
#include <stdio.h>
// #include "cryptlib.h"
// #include "bn_lcl.h"

#ifndef OPENSSL_NO_EC2M

/*
 * Maximum number of iterations before BN_GF2m_mod_solve_quad_arr should
 * fail.
 */
# define MAX_ITERATIONS 50

# define SQR_nibble(w)   ((((w) & 8) << 3) \
                       |  (((w) & 4) << 2) \
                       |  (((w) & 2) << 1) \
                       |   ((w) & 1))


/* Platform-specific macros to accelerate squaring. */
# if defined(SIXTY_FOUR_BIT) || defined(SIXTY_FOUR_BIT_LONG)
#  define SQR1(w) \
    SQR_nibble((w) >> 60) << 56 | SQR_nibble((w) >> 56) << 48 | \
    SQR_nibble((w) >> 52) << 40 | SQR_nibble((w) >> 48) << 32 | \
    SQR_nibble((w) >> 44) << 24 | SQR_nibble((w) >> 40) << 16 | \
    SQR_nibble((w) >> 36) <<  8 | SQR_nibble((w) >> 32)
#  define SQR0(w) \
    SQR_nibble((w) >> 28) << 56 | SQR_nibble((w) >> 24) << 48 | \
    SQR_nibble((w) >> 20) << 40 | SQR_nibble((w) >> 16) << 32 | \
    SQR_nibble((w) >> 12) << 24 | SQR_nibble((w) >>  8) << 16 | \
    SQR_nibble((w) >>  4) <<  8 | SQR_nibble((w)      )
# endif
# ifdef THIRTY_TWO_BIT
#  define SQR1(w) \
    SQR_nibble((w) >> 28) << 24 | SQR_nibble((w) >> 24) << 16 | \
    SQR_nibble((w) >> 20) <<  8 | SQR_nibble((w) >> 16)
#  define SQR0(w) \
    SQR_nibble((w) >> 12) << 24 | SQR_nibble((w) >>  8) << 16 | \
    SQR_nibble((w) >>  4) <<  8 | SQR_nibble((w)      )
# endif

# if !defined(OPENSSL_BN_ASM_GF2m)
/*
 * Product of two polynomials a, b each with degree < BN_BITS2 - 1, result is
 * a polynomial r with degree < 2 * BN_BITS - 1 The caller MUST ensure that
 * the variables have the right amount of space allocated.
 */
#  ifdef THIRTY_TWO_BIT
static void bn_GF2m_mul_1x1(BN_ULONG *r1, BN_ULONG *r0, const BN_ULONG a,
                            const BN_ULONG b)
{
    register BN_ULONG h, l, s;
    BN_ULONG tab[8], top2b = a >> 30;
    register BN_ULONG a1, a2, a4;

    a1 = a & (0x3FFFFFFF);
    a2 = a1 << 1;
    a4 = a2 << 1;

    tab[0] = 0;
    tab[1] = a1;
    tab[2] = a2;
    tab[3] = a1 ^ a2;
    tab[4] = a4;
    tab[5] = a1 ^ a4;
    tab[6] = a2 ^ a4;
    tab[7] = a1 ^ a2 ^ a4;

    s = tab[b & 0x7];
    l = s;
    s = tab[b >> 3 & 0x7];
    l ^= s << 3;
    h = s >> 29;
    s = tab[b >> 6 & 0x7];
    l ^= s << 6;
    h ^= s >> 26;
    s = tab[b >> 9 & 0x7];
    l ^= s << 9;
    h ^= s >> 23;
    s = tab[b >> 12 & 0x7];
    l ^= s << 12;
    h ^= s >> 20;
    s = tab[b >> 15 & 0x7];
    l ^= s << 15;
    h ^= s >> 17;
    s = tab[b >> 18 & 0x7];
    l ^= s << 18;
    h ^= s >> 14;
    s = tab[b >> 21 & 0x7];
    l ^= s << 21;
    h ^= s >> 11;
    s = tab[b >> 24 & 0x7];
    l ^= s << 24;
    h ^= s >> 8;
    s = tab[b >> 27 & 0x7];
    l ^= s << 27;
    h ^= s >> 5;
    s = tab[b >> 30];
    l ^= s << 30;
    h ^= s >> 2;

    /* compensate for the top two bits of a */

    if (top2b & 01) {
        l ^= b << 30;
        h ^= b >> 2;
    }
    if (top2b & 02) {
        l ^= b << 31;
        h ^= b >> 1;
    }

    *r1 = h;
    *r0 = l;
}
#  endif
#  if defined(SIXTY_FOUR_BIT) || defined(SIXTY_FOUR_BIT_LONG)
static void bn_GF2m_mul_1x1(BN_ULONG *r1, BN_ULONG *r0, const BN_ULONG a,
                            const BN_ULONG b)
{
    register BN_ULONG h, l, s;
    BN_ULONG tab[16], top3b = a >> 61;
    register BN_ULONG a1, a2, a4, a8;

    a1 = a & (0x1FFFFFFFFFFFFFFFULL);
    a2 = a1 << 1;
    a4 = a2 << 1;
    a8 = a4 << 1;

    tab[0] = 0;
    tab[1] = a1;
    tab[2] = a2;
    tab[3] = a1 ^ a2;
    tab[4] = a4;
    tab[5] = a1 ^ a4;
    tab[6] = a2 ^ a4;
    tab[7] = a1 ^ a2 ^ a4;
    tab[8] = a8;
    tab[9] = a1 ^ a8;
    tab[10] = a2 ^ a8;
    tab[11] = a1 ^ a2 ^ a8;
    tab[12] = a4 ^ a8;
    tab[13] = a1 ^ a4 ^ a8;
    tab[14] = a2 ^ a4 ^ a8;
    tab[15] = a1 ^ a2 ^ a4 ^ a8;

    s = tab[b & 0xF];
    l = s;
    s = tab[b >> 4 & 0xF];
    l ^= s << 4;
    h = s >> 60;
    s = tab[b >> 8 & 0xF];
    l ^= s << 8;
    h ^= s >> 56;
    s = tab[b >> 12 & 0xF];
    l ^= s << 12;
    h ^= s >> 52;
    s = tab[b >> 16 & 0xF];
    l ^= s << 16;
    h ^= s >> 48;
    s = tab[b >> 20 & 0xF];
    l ^= s << 20;
    h ^= s >> 44;
    s = tab[b >> 24 & 0xF];
    l ^= s << 24;
    h ^= s >> 40;
    s = tab[b >> 28 & 0xF];
    l ^= s << 28;
    h ^= s >> 36;
    s = tab[b >> 32 & 0xF];
    l ^= s << 32;
    h ^= s >> 32;
    s = tab[b >> 36 & 0xF];
    l ^= s << 36;
    h ^= s >> 28;
    s = tab[b >> 40 & 0xF];
    l ^= s << 40;
    h ^= s >> 24;
    s = tab[b >> 44 & 0xF];
    l ^= s << 44;
    h ^= s >> 20;
    s = tab[b >> 48 & 0xF];
    l ^= s << 48;
    h ^= s >> 16;
    s = tab[b >> 52 & 0xF];
    l ^= s << 52;
    h ^= s >> 12;
    s = tab[b >> 56 & 0xF];
    l ^= s << 56;
    h ^= s >> 8;
    s = tab[b >> 60];
    l ^= s << 60;
    h ^= s >> 4;

    /* compensate for the top three bits of a */

    if (top3b & 01) {
        l ^= b << 61;
        h ^= b >> 3;
    }
    if (top3b & 02) {
        l ^= b << 62;
        h ^= b >> 2;
    }
    if (top3b & 04) {
        l ^= b << 63;
        h ^= b >> 1;
    }

    *r1 = h;
    *r0 = l;
}
#  endif

/*
 * Product of two polynomials a, b each with degree < 2 * BN_BITS2 - 1,
 * result is a polynomial r with degree < 4 * BN_BITS2 - 1 The caller MUST
 * ensure that the variables have the right amount of space allocated.
 */
static void bn_GF2m_mul_2x2(BN_ULONG *r, const BN_ULONG a1, const BN_ULONG a0,
                            const BN_ULONG b1, const BN_ULONG b0)
{
    BN_ULONG m1, m0;
    /* r[3] = h1, r[2] = h0; r[1] = l1; r[0] = l0 */
    bn_GF2m_mul_1x1(r + 3, r + 2, a1, b1);
    bn_GF2m_mul_1x1(r + 1, r, a0, b0);
    bn_GF2m_mul_1x1(&m1, &m0, a0 ^ a1, b0 ^ b1);
    /* Correction on m1 ^= l1 ^ h1; m0 ^= l0 ^ h0; */
    r[2] ^= m1 ^ r[1] ^ r[3];   /* h0 ^= m1 ^ l1 ^ h1; */
    r[1] = r[3] ^ r[2] ^ r[0] ^ m1 ^ m0; /* l1 ^= l0 ^ h0 ^ m0; */
}
# else
void bn_GF2m_mul_2x2(BN_ULONG *r, BN_ULONG a1, BN_ULONG a0, BN_ULONG b1,
                     BN_ULONG b0);
# endif

/*
 * Add polynomials a and b and store result in r; r could be a or b, a and b
 * could be equal; r is the bitwise XOR of a and b.
 */
int BN_GF2m_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b)
{
    int i;
    const BIGNUM *at, *bt;

    bn_check_top(a);
    bn_check_top(b);

    if (a->top < b->top) {
        at = b;
        bt = a;
    } else {
        at = a;
        bt = b;
    }

    if (bn_wexpand(r, at->top) == NULL)
        return 0;

    for (i = 0; i < bt->top; i++) {
        r->d[i] = at->d[i] ^ bt->d[i];
    }
    for (; i < at->top; i++) {
        r->d[i] = at->d[i];
    }

    r->top = at->top;
    bn_correct_top(r);

    return 1;
}

/*-
 * Some functions allow for representation of the irreducible polynomials
 * as an int[], say p.  The irreducible f(t) is then of the form:
 *     t^p[0] + t^p[1] + ... + t^p[k]
 * where m = p[0] > p[1] > ... > p[k] = 0.
 */

/* Performs modular reduction of a and store result in r.  r could be a. */
int BN_GF2m_mod_arr(BIGNUM *r, const BIGNUM *a, const int p[])
{
    int j, k;
    int n, dN, d0, d1;
    BN_ULONG zz, *z;

    bn_check_top(a);

    if (!p[0]) {
        /* reduction mod 1 => return 0 */
        BN_zero(r);
        return 1;
    }

    /*
     * Since the algorithm does reduction in the r value, if a != r, copy the
     * contents of a into r so we can do reduction in r.
     */
    if (a != r) {
        if (!bn_wexpand(r, a->top))
            return 0;
        for (j = 0; j < a->top; j++) {
            r->d[j] = a->d[j];
        }
        r->top = a->top;
    }
    z = r->d;

    /* start reduction */
    dN = p[0] / BN_BITS2;
    for (j = r->top - 1; j > dN;) {
        zz = z[j];
        if (z[j] == 0) {
            j--;
            continue;
        }
        z[j] = 0;

        for (k = 1; p[k] != 0; k++) {
            /* reducing component t^p[k] */
            n = p[0] - p[k];
            d0 = n % BN_BITS2;
            d1 = BN_BITS2 - d0;
            n /= BN_BITS2;
            z[j - n] ^= (zz >> d0);
            if (d0)
                z[j - n - 1] ^= (zz << d1);
        }

        /* reducing component t^0 */
        n = dN;
        d0 = p[0] % BN_BITS2;
        d1 = BN_BITS2 - d0;
        z[j - n] ^= (zz >> d0);
        if (d0)
            z[j - n - 1] ^= (zz << d1);
    }

    /* final round of reduction */
    while (j == dN) {

        d0 = p[0] % BN_BITS2;
        zz = z[dN] >> d0;
        if (zz == 0)
            break;
        d1 = BN_BITS2 - d0;

        /* clear up the top d1 bits */
        if (d0)
            z[dN] = (z[dN] << d1) >> d1;
        else
            z[dN] = 0;
        z[0] ^= zz;             /* reduction t^0 component */

        for (k = 1; p[k] != 0; k++) {
            BN_ULONG tmp_ulong;

            /* reducing component t^p[k] */
            n = p[k] / BN_BITS2;
            d0 = p[k] % BN_BITS2;
            d1 = BN_BITS2 - d0;
            z[n] ^= (zz << d0);
            if (d0 && (tmp_ulong = zz >> d1))
                z[n + 1] ^= tmp_ulong;
        }

    }

    bn_correct_top(r);
    return 1;
}

/*
 * Performs modular reduction of a by p and store result in r.  r could be a.
 * This function calls down to the BN_GF2m_mod_arr implementation; this wrapper
 * function is only provided for convenience; for best performance, use the
 * BN_GF2m_mod_arr function.
 */
int BN_GF2m_mod(BIGNUM *r, const BIGNUM *a, const BIGNUM *p)
{
    int ret = 0;
    int arr[6];
    bn_check_top(a);
    bn_check_top(p);
    ret = BN_GF2m_poly2arr(p, arr, sizeof(arr) / sizeof(arr[0]));
    if (!ret || ret > (int)(sizeof(arr) / sizeof(arr[0]))) {
        BNerr(BN_F_BN_GF2M_MOD, BN_R_INVALID_LENGTH);
        return 0;
    }
    ret = BN_GF2m_mod_arr(r, a, arr);
    bn_check_top(r);
    return ret;
}

/*
 * Compute the product of two polynomials a and b, reduce modulo p, and store
 * the result in r.  r could be a or b; a could be b.
 */
int BN_GF2m_mod_mul_arr(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
                        const int p[], BN_CTX *ctx)
{
    int zlen, i, j, k, ret = 0;
    BIGNUM *s;
    BN_ULONG x1, x0, y1, y0, zz[4];

    bn_check_top(a);
    bn_check_top(b);

    if (a == b) {
        return BN_GF2m_mod_sqr_arr(r, a, p, ctx);
    }

    BN_CTX_start(ctx);
    if ((s = BN_CTX_get(ctx)) == NULL)
        goto err;

    zlen = a->top + b->top + 4;
    if (!bn_wexpand(s, zlen))
        goto err;
    s->top = zlen;

    for (i = 0; i < zlen; i++)
        s->d[i] = 0;

    for (j = 0; j < b->top; j += 2) {
        y0 = b->d[j];
        y1 = ((j + 1) == b->top) ? 0 : b->d[j + 1];
        for (i = 0; i < a->top; i += 2) {
            x0 = a->d[i];
            x1 = ((i + 1) == a->top) ? 0 : a->d[i + 1];
            bn_GF2m_mul_2x2(zz, x1, x0, y1, y0);
            for (k = 0; k < 4; k++)
                s->d[i + j + k] ^= zz[k];
        }
    }

    bn_correct_top(s);
    if (BN_GF2m_mod_arr(r, s, p))
        ret = 1;
    bn_check_top(r);

 err:
    BN_CTX_end(ctx);
    return ret;
}

/*
 * Compute the product of two polynomials a and b, reduce modulo p, and store
 * the result in r.  r could be a or b; a could equal b. This function calls
 * down to the BN_GF2m_mod_mul_arr implementation; this wrapper function is
 * only provided for convenience; for best performance, use the
 * BN_GF2m_mod_mul_arr function.
 */
int BN_GF2m_mod_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
                    const BIGNUM *p, BN_CTX *ctx)
{
    int ret = 0;
    const int max = BN_num_bits(p) + 1;
    int *arr = NULL;
    bn_check_top(a);
    bn_check_top(b);
    bn_check_top(p);
    if ((arr = (int *)OPENSSL_malloc(sizeof(int) * max)) == NULL)
        goto err;
    ret = BN_GF2m_poly2arr(p, arr, max);
    if (!ret || ret > max) {
        BNerr(BN_F_BN_GF2M_MOD_MUL, BN_R_INVALID_LENGTH);
        goto err;
    }
    ret = BN_GF2m_mod_mul_arr(r, a, b, arr, ctx);
    bn_check_top(r);
 err:
    if (arr)
        OPENSSL_free(arr);
    return ret;
}

/* Square a, reduce the result mod p, and store it in a.  r could be a. */
int BN_GF2m_mod_sqr_arr(BIGNUM *r, const BIGNUM *a, const int p[],
                        BN_CTX *ctx)
{
    int i, ret = 0;
    BIGNUM *s;

    bn_check_top(a);
    BN_CTX_start(ctx);
    if ((s = BN_CTX_get(ctx)) == NULL)
        goto err;
    if (!bn_wexpand(s, 2 * a->top))
        goto err;

    for (i = a->top - 1; i >= 0; i--) {
        s->d[2 * i + 1] = SQR1(a->d[i]);
        s->d[2 * i] = SQR0(a->d[i]);
    }

    s->top = 2 * a->top;
    bn_correct_top(s);
    if (!BN_GF2m_mod_arr(r, s, p))
        goto err;
    bn_check_top(r);
    ret = 1;
 err:
    BN_CTX_end(ctx);
    return ret;
}

/*
 * Square a, reduce the result mod p, and store it in a.  r could be a. This
 * function calls down to the BN_GF2m_mod_sqr_arr implementation; this
 * wrapper function is only provided for convenience; for best performance,
 * use the BN_GF2m_mod_sqr_arr function.
 */
int BN_GF2m_mod_sqr(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx)
{
    int ret = 0;
    const int max = BN_num_bits(p) + 1;
    int *arr = NULL;

    bn_check_top(a);
    bn_check_top(p);
    if ((arr = (int *)OPENSSL_malloc(sizeof(int) * max)) == NULL)
        goto err;
    ret = BN_GF2m_poly2arr(p, arr, max);
    if (!ret || ret > max) {
        BNerr(BN_F_BN_GF2M_MOD_SQR, BN_R_INVALID_LENGTH);
        goto err;
    }
    ret = BN_GF2m_mod_sqr_arr(r, a, arr, ctx);
    bn_check_top(r);
 err:
    if (arr)
        OPENSSL_free(arr);
    return ret;
}

/*
 * Invert a, reduce modulo p, and store the result in r. r could be a. Uses
 * Modified Almost Inverse Algorithm (Algorithm 10) from Hankerson, D.,
 * Hernandez, J.L., and Menezes, A.  "Software Implementation of Elliptic
 * Curve Cryptography Over Binary Fields".
 */
int BN_GF2m_mod_inv(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx)
{
    BIGNUM *b, *c = NULL, *u = NULL, *v = NULL, *tmp;
    int ret = 0;

    bn_check_top(a);
    bn_check_top(p);

    BN_CTX_start(ctx);

    if ((b = BN_CTX_get(ctx)) == NULL)
        goto err;
    if ((c = BN_CTX_get(ctx)) == NULL)
        goto err;
    if ((u = BN_CTX_get(ctx)) == NULL)
        goto err;
    if ((v = BN_CTX_get(ctx)) == NULL)
        goto err;

    if (!BN_GF2m_mod(u, a, p))
        goto err;
    if (BN_is_zero(u))
        goto err;

    if (!BN_copy(v, p))
        goto err;
# if 0
    if (!BN_one(b))
        goto err;

    while (1) {
        while (!BN_is_odd(u)) {
            if (BN_is_zero(u))
                goto err;
            if (!BN_rshift1(u, u))
                goto err;
            if (BN_is_odd(b)) {
                if (!BN_GF2m_add(b, b, p))
                    goto err;
            }
            if (!BN_rshift1(b, b))
                goto err;
        }

        if (BN_abs_is_word(u, 1))
            break;

        if (BN_num_bits(u) < BN_num_bits(v)) {
            tmp = u;
            u = v;
            v = tmp;
            tmp = b;
            b = c;
            c = tmp;
        }

        if (!BN_GF2m_add(u, u, v))
            goto err;
        if (!BN_GF2m_add(b, b, c))
            goto err;
    }
# else
    {
        int i;
        int ubits = BN_num_bits(u);
        int vbits = BN_num_bits(v); /* v is copy of p */
        int top = p->top;
        BN_ULONG *udp, *bdp, *vdp, *cdp;

        if (!bn_wexpand(u, top))
            goto err;
        udp = u->d;
        for (i = u->top; i < top; i++)
            udp[i] = 0;
        u->top = top;
        if (!bn_wexpand(b, top))
          goto err;
        bdp = b->d;
        bdp[0] = 1;
        for (i = 1; i < top; i++)
            bdp[i] = 0;
        b->top = top;
        if (!bn_wexpand(c, top))
          goto err;
        cdp = c->d;
        for (i = 0; i < top; i++)
            cdp[i] = 0;
        c->top = top;
        vdp = v->d;             /* It pays off to "cache" *->d pointers,
                                 * because it allows optimizer to be more
                                 * aggressive. But we don't have to "cache"
                                 * p->d, because *p is declared 'const'... */
        while (1) {
            while (ubits && !(udp[0] & 1)) {
                BN_ULONG u0, u1, b0, b1, mask;

                u0 = udp[0];
                b0 = bdp[0];
                mask = (BN_ULONG)0 - (b0 & 1);
                b0 ^= p->d[0] & mask;
                for (i = 0; i < top - 1; i++) {
                    u1 = udp[i + 1];
                    udp[i] = ((u0 >> 1) | (u1 << (BN_BITS2 - 1))) & BN_MASK2;
                    u0 = u1;
                    b1 = bdp[i + 1] ^ (p->d[i + 1] & mask);
                    bdp[i] = ((b0 >> 1) | (b1 << (BN_BITS2 - 1))) & BN_MASK2;
                    b0 = b1;
                }
                udp[i] = u0 >> 1;
                bdp[i] = b0 >> 1;
                ubits--;
            }

            if (ubits <= BN_BITS2) {
                if (udp[0] == 0) /* poly was reducible */
                    goto err;
                if (udp[0] == 1)
                    break;
            }

            if (ubits < vbits) {
                i = ubits;
                ubits = vbits;
                vbits = i;
                tmp = u;
                u = v;
                v = tmp;
                tmp = b;
                b = c;
                c = tmp;
                udp = vdp;
                vdp = v->d;
                bdp = cdp;
                cdp = c->d;
            }
            for (i = 0; i < top; i++) {
                udp[i] ^= vdp[i];
                bdp[i] ^= cdp[i];
            }
            if (ubits == vbits) {
                BN_ULONG ul;
                int utop = (ubits - 1) / BN_BITS2;

                while ((ul = udp[utop]) == 0 && utop)
                    utop--;
                ubits = utop * BN_BITS2 + BN_num_bits_word(ul);
            }
        }
        bn_correct_top(b);
    }
# endif

    if (!BN_copy(r, b))
        goto err;
    bn_check_top(r);
    ret = 1;

 err:
# ifdef BN_DEBUG                /* BN_CTX_end would complain about the
                                 * expanded form */
    bn_correct_top(c);
    bn_correct_top(u);
    bn_correct_top(v);
# endif
    BN_CTX_end(ctx);
    return ret;
}

/*
 * Invert xx, reduce modulo p, and store the result in r. r could be xx.
 * This function calls down to the BN_GF2m_mod_inv implementation; this
 * wrapper function is only provided for convenience; for best performance,
 * use the BN_GF2m_mod_inv function.
 */
int BN_GF2m_mod_inv_arr(BIGNUM *r, const BIGNUM *xx, const int p[],
                        BN_CTX *ctx)
{
    BIGNUM *field;
    int ret = 0;

    bn_check_top(xx);
    BN_CTX_start(ctx);
    if ((field = BN_CTX_get(ctx)) == NULL)
        goto err;
    if (!BN_GF2m_arr2poly(p, field))
        goto err;

    ret = BN_GF2m_mod_inv(r, xx, field, ctx);
    bn_check_top(r);

 err:
    BN_CTX_end(ctx);
    return ret;
}

# ifndef OPENSSL_SUN_GF2M_DIV
/*
 * Divide y by x, reduce modulo p, and store the result in r. r could be x
 * or y, x could equal y.
 */
int BN_GF2m_mod_div(BIGNUM *r, const BIGNUM *y, const BIGNUM *x,
                    const BIGNUM *p, BN_CTX *ctx)
{
    BIGNUM *xinv = NULL;
    int ret = 0;

    bn_check_top(y);
    bn_check_top(x);
    bn_check_top(p);

    BN_CTX_start(ctx);
    xinv = BN_CTX_get(ctx);
    if (xinv == NULL)
        goto err;

    if (!BN_GF2m_mod_inv(xinv, x, p, ctx))
        goto err;
    if (!BN_GF2m_mod_mul(r, y, xinv, p, ctx))
        goto err;
    bn_check_top(r);
    ret = 1;

 err:
    BN_CTX_end(ctx);
    return ret;
}
# else
/*
 * Divide y by x, reduce modulo p, and store the result in r. r could be x
 * or y, x could equal y. Uses algorithm Modular_Division_GF(2^m) from
 * Chang-Shantz, S.  "From Euclid's GCD to Montgomery Multiplication to the
 * Great Divide".
 */
int BN_GF2m_mod_div(BIGNUM *r, const BIGNUM *y, const BIGNUM *x,
                    const BIGNUM *p, BN_CTX *ctx)
{
    BIGNUM *a, *b, *u, *v;
    int ret = 0;

    bn_check_top(y);
    bn_check_top(x);
    bn_check_top(p);

    BN_CTX_start(ctx);

    a = BN_CTX_get(ctx);
    b = BN_CTX_get(ctx);
    u = BN_CTX_get(ctx);
    v = BN_CTX_get(ctx);
    if (v == NULL)
        goto err;

    /* reduce x and y mod p */
    if (!BN_GF2m_mod(u, y, p))
        goto err;
    if (!BN_GF2m_mod(a, x, p))
        goto err;
    if (!BN_copy(b, p))
        goto err;

    while (!BN_is_odd(a)) {
        if (!BN_rshift1(a, a))
            goto err;
        if (BN_is_odd(u))
            if (!BN_GF2m_add(u, u, p))
                goto err;
        if (!BN_rshift1(u, u))
            goto err;
    }

    do {
        if (BN_GF2m_cmp(b, a) > 0) {
            if (!BN_GF2m_add(b, b, a))
                goto err;
            if (!BN_GF2m_add(v, v, u))
                goto err;
            do {
                if (!BN_rshift1(b, b))
                    goto err;
                if (BN_is_odd(v))
                    if (!BN_GF2m_add(v, v, p))
                        goto err;
                if (!BN_rshift1(v, v))
                    goto err;
            } while (!BN_is_odd(b));
        } else if (BN_abs_is_word(a, 1))
            break;
        else {
            if (!BN_GF2m_add(a, a, b))
                goto err;
            if (!BN_GF2m_add(u, u, v))
                goto err;
            do {
                if (!BN_rshift1(a, a))
                    goto err;
                if (BN_is_odd(u))
                    if (!BN_GF2m_add(u, u, p))
                        goto err;
                if (!BN_rshift1(u, u))
                    goto err;
            } while (!BN_is_odd(a));
        }
    } while (1);

    if (!BN_copy(r, u))
        goto err;
    bn_check_top(r);
    ret = 1;

 err:
    BN_CTX_end(ctx);
    return ret;
}
# endif

/*
 * Divide yy by xx, reduce modulo p, and store the result in r. r could be xx
 * * or yy, xx could equal yy. This function calls down to the
 * BN_GF2m_mod_div implementation; this wrapper function is only provided for
 * convenience; for best performance, use the BN_GF2m_mod_div function.
 */
int BN_GF2m_mod_div_arr(BIGNUM *r, const BIGNUM *yy, const BIGNUM *xx,
                        const int p[], BN_CTX *ctx)
{
    BIGNUM *field;
    int ret = 0;

    bn_check_top(yy);
    bn_check_top(xx);

    BN_CTX_start(ctx);
    if ((field = BN_CTX_get(ctx)) == NULL)
        goto err;
    if (!BN_GF2m_arr2poly(p, field))
        goto err;

    ret = BN_GF2m_mod_div(r, yy, xx, field, ctx);
    bn_check_top(r);

 err:
    BN_CTX_end(ctx);
    return ret;
}

/*
 * Compute the bth power of a, reduce modulo p, and store the result in r.  r
 * could be a. Uses simple square-and-multiply algorithm A.5.1 from IEEE
 * P1363.
 */
int BN_GF2m_mod_exp_arr(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
                        const int p[], BN_CTX *ctx)
{
    int ret = 0, i, n;
    BIGNUM *u;

    bn_check_top(a);
    bn_check_top(b);

    if (BN_is_zero(b))
        return (BN_one(r));

    if (BN_abs_is_word(b, 1))
        return (BN_copy(r, a) != NULL);

    BN_CTX_start(ctx);
    if ((u = BN_CTX_get(ctx)) == NULL)
        goto err;

    if (!BN_GF2m_mod_arr(u, a, p))
        goto err;

    n = BN_num_bits(b) - 1;
    for (i = n - 1; i >= 0; i--) {
        if (!BN_GF2m_mod_sqr_arr(u, u, p, ctx))
            goto err;
        if (BN_is_bit_set(b, i)) {
            if (!BN_GF2m_mod_mul_arr(u, u, a, p, ctx))
                goto err;
        }
    }
    if (!BN_copy(r, u))
        goto err;
    bn_check_top(r);
    ret = 1;
 err:
    BN_CTX_end(ctx);
    return ret;
}

/*
 * Compute the bth power of a, reduce modulo p, and store the result in r.  r
 * could be a. This function calls down to the BN_GF2m_mod_exp_arr
 * implementation; this wrapper function is only provided for convenience;
 * for best performance, use the BN_GF2m_mod_exp_arr function.
 */
int BN_GF2m_mod_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
                    const BIGNUM *p, BN_CTX *ctx)
{
    int ret = 0;
    const int max = BN_num_bits(p) + 1;
    int *arr = NULL;
    bn_check_top(a);
    bn_check_top(b);
    bn_check_top(p);
    if ((arr = (int *)OPENSSL_malloc(sizeof(int) * max)) == NULL)
        goto err;
    ret = BN_GF2m_poly2arr(p, arr, max);
    if (!ret || ret > max) {
        BNerr(BN_F_BN_GF2M_MOD_EXP, BN_R_INVALID_LENGTH);
        goto err;
    }
    ret = BN_GF2m_mod_exp_arr(r, a, b, arr, ctx);
    bn_check_top(r);
 err:
    if (arr)
        OPENSSL_free(arr);
    return ret;
}

/*
 * Compute the square root of a, reduce modulo p, and store the result in r.
 * r could be a. Uses exponentiation as in algorithm A.4.1 from IEEE P1363.
 */
int BN_GF2m_mod_sqrt_arr(BIGNUM *r, const BIGNUM *a, const int p[],
                         BN_CTX *ctx)
{
    int ret = 0;
    BIGNUM *u;

    bn_check_top(a);

    if (!p[0]) {
        /* reduction mod 1 => return 0 */
        BN_zero(r);
        return 1;
    }

    BN_CTX_start(ctx);
    if ((u = BN_CTX_get(ctx)) == NULL)
        goto err;

    if (!BN_set_bit(u, p[0] - 1))
        goto err;
    ret = BN_GF2m_mod_exp_arr(r, a, u, p, ctx);
    bn_check_top(r);

 err:
    BN_CTX_end(ctx);
    return ret;
}

/*
 * Compute the square root of a, reduce modulo p, and store the result in r.
 * r could be a. This function calls down to the BN_GF2m_mod_sqrt_arr
 * implementation; this wrapper function is only provided for convenience;
 * for best performance, use the BN_GF2m_mod_sqrt_arr function.
 */
int BN_GF2m_mod_sqrt(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx)
{
    int ret = 0;
    const int max = BN_num_bits(p) + 1;
    int *arr = NULL;
    bn_check_top(a);
    bn_check_top(p);
    if ((arr = (int *)OPENSSL_malloc(sizeof(int) * max)) == NULL)
        goto err;
    ret = BN_GF2m_poly2arr(p, arr, max);
    if (!ret || ret > max) {
        BNerr(BN_F_BN_GF2M_MOD_SQRT, BN_R_INVALID_LENGTH);
        goto err;
    }
    ret = BN_GF2m_mod_sqrt_arr(r, a, arr, ctx);
    bn_check_top(r);
 err:
    if (arr)
        OPENSSL_free(arr);
    return ret;
}

/*
 * Find r such that r^2 + r = a mod p.  r could be a. If no r exists returns
 * 0. Uses algorithms A.4.7 and A.4.6 from IEEE P1363.
 */
int BN_GF2m_mod_solve_quad_arr(BIGNUM *r, const BIGNUM *a_, const int p[],
                               BN_CTX *ctx)
{
    int ret = 0, count = 0, j;
    BIGNUM *a, *z, *rho, *w, *w2, *tmp;

    bn_check_top(a_);

    if (!p[0]) {
        /* reduction mod 1 => return 0 */
        BN_zero(r);
        return 1;
    }

    BN_CTX_start(ctx);
    a = BN_CTX_get(ctx);
    z = BN_CTX_get(ctx);
    w = BN_CTX_get(ctx);
    if (w == NULL)
        goto err;

    if (!BN_GF2m_mod_arr(a, a_, p))
        goto err;

    if (BN_is_zero(a)) {
        BN_zero(r);
        ret = 1;
        goto err;
    }

    if (p[0] & 0x1) {           /* m is odd */
        /* compute half-trace of a */
        if (!BN_copy(z, a))
            goto err;
        for (j = 1; j <= (p[0] - 1) / 2; j++) {
            if (!BN_GF2m_mod_sqr_arr(z, z, p, ctx))
                goto err;
            if (!BN_GF2m_mod_sqr_arr(z, z, p, ctx))
                goto err;
            if (!BN_GF2m_add(z, z, a))
                goto err;
        }

    } else {                    /* m is even */

        rho = BN_CTX_get(ctx);
        w2 = BN_CTX_get(ctx);
        tmp = BN_CTX_get(ctx);
        if (tmp == NULL)
            goto err;
        do {
            if (!BN_rand(rho, p[0], 0, 0))
                goto err;
            if (!BN_GF2m_mod_arr(rho, rho, p))
                goto err;
            BN_zero(z);
            if (!BN_copy(w, rho))
                goto err;
            for (j = 1; j <= p[0] - 1; j++) {
                if (!BN_GF2m_mod_sqr_arr(z, z, p, ctx))
                    goto err;
                if (!BN_GF2m_mod_sqr_arr(w2, w, p, ctx))
                    goto err;
                if (!BN_GF2m_mod_mul_arr(tmp, w2, a, p, ctx))
                    goto err;
                if (!BN_GF2m_add(z, z, tmp))
                    goto err;
                if (!BN_GF2m_add(w, w2, rho))
                    goto err;
            }
            count++;
        } while (BN_is_zero(w) && (count < MAX_ITERATIONS));
        if (BN_is_zero(w)) {
            BNerr(BN_F_BN_GF2M_MOD_SOLVE_QUAD_ARR, BN_R_TOO_MANY_ITERATIONS);
            goto err;
        }
    }

    if (!BN_GF2m_mod_sqr_arr(w, z, p, ctx))
        goto err;
    if (!BN_GF2m_add(w, z, w))
        goto err;
    if (BN_GF2m_cmp(w, a)) {
        BNerr(BN_F_BN_GF2M_MOD_SOLVE_QUAD_ARR, BN_R_NO_SOLUTION);
        goto err;
    }

    if (!BN_copy(r, z))
        goto err;
    bn_check_top(r);

    ret = 1;

 err:
    BN_CTX_end(ctx);
    return ret;
}

/*
 * Find r such that r^2 + r = a mod p.  r could be a. If no r exists returns
 * 0. This function calls down to the BN_GF2m_mod_solve_quad_arr
 * implementation; this wrapper function is only provided for convenience;
 * for best performance, use the BN_GF2m_mod_solve_quad_arr function.
 */
int BN_GF2m_mod_solve_quad(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
                           BN_CTX *ctx)
{
    int ret = 0;
    const int max = BN_num_bits(p) + 1;
    int *arr = NULL;
    bn_check_top(a);
    bn_check_top(p);
    if ((arr = (int *)OPENSSL_malloc(sizeof(int) * max)) == NULL)
        goto err;
    ret = BN_GF2m_poly2arr(p, arr, max);
    if (!ret || ret > max) {
        BNerr(BN_F_BN_GF2M_MOD_SOLVE_QUAD, BN_R_INVALID_LENGTH);
        goto err;
    }
    ret = BN_GF2m_mod_solve_quad_arr(r, a, arr, ctx);
    bn_check_top(r);
 err:
    if (arr)
        OPENSSL_free(arr);
    return ret;
}

/*
 * Convert the bit-string representation of a polynomial ( \sum_{i=0}^n a_i *
 * x^i) into an array of integers corresponding to the bits with non-zero
 * coefficient.  Array is terminated with -1. Up to max elements of the array
 * will be filled.  Return value is total number of array elements that would
 * be filled if array was large enough.
 */
int BN_GF2m_poly2arr(const BIGNUM *a, int p[], int max)
{
    int i, j, k = 0;
    BN_ULONG mask;

    if (BN_is_zero(a))
        return 0;

    for (i = a->top - 1; i >= 0; i--) {
        if (!a->d[i])
            /* skip word if a->d[i] == 0 */
            continue;
        mask = BN_TBIT;
        for (j = BN_BITS2 - 1; j >= 0; j--) {
            if (a->d[i] & mask) {
                if (k < max)
                    p[k] = BN_BITS2 * i + j;
                k++;
            }
            mask >>= 1;
        }
    }

    if (k < max) {
        p[k] = -1;
        k++;
    }

    return k;
}

/*
 * Convert the coefficient array representation of a polynomial to a
 * bit-string.  The array must be terminated by -1.
 */
int BN_GF2m_arr2poly(const int p[], BIGNUM *a)
{
    int i;

    bn_check_top(a);
    BN_zero(a);
    for (i = 0; p[i] != -1; i++) {
        if (BN_set_bit(a, p[i]) == 0)
            return 0;
    }
    bn_check_top(a);

    return 1;
}

#endif
/* crypto/bn/bn_kron.c */
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

// #include "cryptlib.h"
// #include "bn_lcl.h"

/* least significant word */
#define BN_lsw(n) (((n)->top == 0) ? (BN_ULONG) 0 : (n)->d[0])

/* Returns -2 for errors because both -1 and 0 are valid results. */
int BN_kronecker(const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx)
{
    int i;
    int ret = -2;               /* avoid 'uninitialized' warning */
    int err = 0;
    BIGNUM *A, *B, *tmp;
    /*-
     * In 'tab', only odd-indexed entries are relevant:
     * For any odd BIGNUM n,
     *     tab[BN_lsw(n) & 7]
     * is $(-1)^{(n^2-1)/8}$ (using TeX notation).
     * Note that the sign of n does not matter.
     */
    static const int tab[8] = { 0, 1, 0, -1, 0, -1, 0, 1 };

    bn_check_top(a);
    bn_check_top(b);

    BN_CTX_start(ctx);
    A = BN_CTX_get(ctx);
    B = BN_CTX_get(ctx);
    if (B == NULL)
        goto end;

    err = !BN_copy(A, a);
    if (err)
        goto end;
    err = !BN_copy(B, b);
    if (err)
        goto end;

    /*
     * Kronecker symbol, imlemented according to Henri Cohen,
     * "A Course in Computational Algebraic Number Theory"
     * (algorithm 1.4.10).
     */

    /* Cohen's step 1: */

    if (BN_is_zero(B)) {
        ret = BN_abs_is_word(A, 1);
        goto end;
    }

    /* Cohen's step 2: */

    if (!BN_is_odd(A) && !BN_is_odd(B)) {
        ret = 0;
        goto end;
    }

    /* now  B  is non-zero */
    i = 0;
    while (!BN_is_bit_set(B, i))
        i++;
    err = !BN_rshift(B, B, i);
    if (err)
        goto end;
    if (i & 1) {
        /* i is odd */
        /* (thus  B  was even, thus  A  must be odd!)  */

        /* set 'ret' to $(-1)^{(A^2-1)/8}$ */
        ret = tab[BN_lsw(A) & 7];
    } else {
        /* i is even */
        ret = 1;
    }

    if (B->neg) {
        B->neg = 0;
        if (A->neg)
            ret = -ret;
    }

    /*
     * now B is positive and odd, so what remains to be done is to compute
     * the Jacobi symbol (A/B) and multiply it by 'ret'
     */

    while (1) {
        /* Cohen's step 3: */

        /*  B  is positive and odd */

        if (BN_is_zero(A)) {
            ret = BN_is_one(B) ? ret : 0;
            goto end;
        }

        /* now  A  is non-zero */
        i = 0;
        while (!BN_is_bit_set(A, i))
            i++;
        err = !BN_rshift(A, A, i);
        if (err)
            goto end;
        if (i & 1) {
            /* i is odd */
            /* multiply 'ret' by  $(-1)^{(B^2-1)/8}$ */
            ret = ret * tab[BN_lsw(B) & 7];
        }

        /* Cohen's step 4: */
        /* multiply 'ret' by  $(-1)^{(A-1)(B-1)/4}$ */
        if ((A->neg ? ~BN_lsw(A) : BN_lsw(A)) & BN_lsw(B) & 2)
            ret = -ret;

        /* (A, B) := (B mod |A|, |A|) */
        err = !BN_nnmod(B, B, A, ctx);
        if (err)
            goto end;
        tmp = A;
        A = B;
        B = tmp;
        tmp->neg = 0;
    }
 end:
    BN_CTX_end(ctx);
    if (err)
        return -2;
    else
        return ret;
}
/* crypto/bn/bn_lib.c */
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

#ifndef BN_DEBUG
# undef NDEBUG                  /* avoid conflicting definitions */
# define NDEBUG
#endif

#include <assert.h>
#include <limits.h>
#include <stdio.h>
// #include "cryptlib.h"
// #include "bn_lcl.h"

const char BN_version[] = "Big Number" OPENSSL_VERSION_PTEXT;

/* This stuff appears to be completely unused, so is deprecated */
#ifndef OPENSSL_NO_DEPRECATED
/*-
 * For a 32 bit machine
 * 2 -   4 ==  128
 * 3 -   8 ==  256
 * 4 -  16 ==  512
 * 5 -  32 == 1024
 * 6 -  64 == 2048
 * 7 - 128 == 4096
 * 8 - 256 == 8192
 */
static int bn_limit_bits = 0;
static int bn_limit_num = 8;    /* (1<<bn_limit_bits) */
static int bn_limit_bits_low = 0;
static int bn_limit_num_low = 8; /* (1<<bn_limit_bits_low) */
static int bn_limit_bits_high = 0;
static int bn_limit_num_high = 8; /* (1<<bn_limit_bits_high) */
static int bn_limit_bits_mont = 0;
static int bn_limit_num_mont = 8; /* (1<<bn_limit_bits_mont) */

void BN_set_params(int mult, int high, int low, int mont)
{
    if (mult >= 0) {
        if (mult > (int)(sizeof(int) * 8) - 1)
            mult = sizeof(int) * 8 - 1;
        bn_limit_bits = mult;
        bn_limit_num = 1 << mult;
    }
    if (high >= 0) {
        if (high > (int)(sizeof(int) * 8) - 1)
            high = sizeof(int) * 8 - 1;
        bn_limit_bits_high = high;
        bn_limit_num_high = 1 << high;
    }
    if (low >= 0) {
        if (low > (int)(sizeof(int) * 8) - 1)
            low = sizeof(int) * 8 - 1;
        bn_limit_bits_low = low;
        bn_limit_num_low = 1 << low;
    }
    if (mont >= 0) {
        if (mont > (int)(sizeof(int) * 8) - 1)
            mont = sizeof(int) * 8 - 1;
        bn_limit_bits_mont = mont;
        bn_limit_num_mont = 1 << mont;
    }
}

int BN_get_params(int which)
{
    if (which == 0)
        return (bn_limit_bits);
    else if (which == 1)
        return (bn_limit_bits_high);
    else if (which == 2)
        return (bn_limit_bits_low);
    else if (which == 3)
        return (bn_limit_bits_mont);
    else
        return (0);
}
#endif

const BIGNUM *BN_value_one(void)
{
    static const BN_ULONG data_one = 1L;
    static const BIGNUM const_one =
        { (BN_ULONG *)&data_one, 1, 1, 0, BN_FLG_STATIC_DATA };

    return (&const_one);
}

int BN_num_bits_word(BN_ULONG l)
{
    BN_ULONG x, mask;
    int bits = (l != 0);

#if BN_BITS2 > 32
    x = l >> 32;
    mask = (0 - x) & BN_MASK2;
    mask = (0 - (mask >> (BN_BITS2 - 1)));
    bits += 32 & mask;
    l ^= (x ^ l) & mask;
#endif

    x = l >> 16;
    mask = (0 - x) & BN_MASK2;
    mask = (0 - (mask >> (BN_BITS2 - 1)));
    bits += 16 & mask;
    l ^= (x ^ l) & mask;

    x = l >> 8;
    mask = (0 - x) & BN_MASK2;
    mask = (0 - (mask >> (BN_BITS2 - 1)));
    bits += 8 & mask;
    l ^= (x ^ l) & mask;

    x = l >> 4;
    mask = (0 - x) & BN_MASK2;
    mask = (0 - (mask >> (BN_BITS2 - 1)));
    bits += 4 & mask;
    l ^= (x ^ l) & mask;

    x = l >> 2;
    mask = (0 - x) & BN_MASK2;
    mask = (0 - (mask >> (BN_BITS2 - 1)));
    bits += 2 & mask;
    l ^= (x ^ l) & mask;

    x = l >> 1;
    mask = (0 - x) & BN_MASK2;
    mask = (0 - (mask >> (BN_BITS2 - 1)));
    bits += 1 & mask;

    return bits;
}

int BN_num_bits(const BIGNUM *a)
{
    int i = a->top - 1;
    bn_check_top(a);

    if (BN_is_zero(a))
        return 0;
    return ((i * BN_BITS2) + BN_num_bits_word(a->d[i]));
}

void BN_clear_free(BIGNUM *a)
{
    int i;

    if (a == NULL)
        return;
    bn_check_top(a);
    if (a->d != NULL) {
        OPENSSL_cleanse(a->d, a->dmax * sizeof(a->d[0]));
        if (!(BN_get_flags(a, BN_FLG_STATIC_DATA)))
            OPENSSL_free(a->d);
    }
    i = BN_get_flags(a, BN_FLG_MALLOCED);
    OPENSSL_cleanse(a, sizeof(BIGNUM));
    if (i)
        OPENSSL_free(a);
}

void BN_free(BIGNUM *a)
{
    if (a == NULL)
        return;
    bn_check_top(a);
    if ((a->d != NULL) && !(BN_get_flags(a, BN_FLG_STATIC_DATA)))
        OPENSSL_free(a->d);
    if (a->flags & BN_FLG_MALLOCED)
        OPENSSL_free(a);
    else {
#ifndef OPENSSL_NO_DEPRECATED
        a->flags |= BN_FLG_FREE;
#endif
        a->d = NULL;
    }
}

void BN_init(BIGNUM *a)
{
    memset(a, 0, sizeof(BIGNUM));
    bn_check_top(a);
}

BIGNUM *BN_new(void)
{
    BIGNUM *ret;

    if ((ret = (BIGNUM *)OPENSSL_malloc(sizeof(BIGNUM))) == NULL) {
        BNerr(BN_F_BN_NEW, ERR_R_MALLOC_FAILURE);
        return (NULL);
    }
    ret->flags = BN_FLG_MALLOCED;
    ret->top = 0;
    ret->neg = 0;
    ret->dmax = 0;
    ret->d = NULL;
    bn_check_top(ret);
    return (ret);
}

/* This is used both by bn_expand2() and bn_dup_expand() */
/* The caller MUST check that words > b->dmax before calling this */
static BN_ULONG *bn_expand_internal(const BIGNUM *b, int words)
{
    BN_ULONG *A, *a = NULL;
    const BN_ULONG *B;
    int i;

    if (words > (INT_MAX / (4 * BN_BITS2))) {
        BNerr(BN_F_BN_EXPAND_INTERNAL, BN_R_BIGNUM_TOO_LONG);
        return NULL;
    }
    if (BN_get_flags(b, BN_FLG_STATIC_DATA)) {
        BNerr(BN_F_BN_EXPAND_INTERNAL, BN_R_EXPAND_ON_STATIC_BIGNUM_DATA);
        return (NULL);
    }
    a = A = (BN_ULONG *)OPENSSL_malloc(sizeof(BN_ULONG) * words);
    if (A == NULL) {
        BNerr(BN_F_BN_EXPAND_INTERNAL, ERR_R_MALLOC_FAILURE);
        return (NULL);
    }
#ifdef PURIFY
    /*
     * Valgrind complains in BN_consttime_swap because we process the whole
     * array even if it's not initialised yet. This doesn't matter in that
     * function - what's important is constant time operation (we're not
     * actually going to use the data)
     */
    memset(a, 0, sizeof(BN_ULONG) * words);
#endif

#if 1
    B = b->d;
    /* Check if the previous number needs to be copied */
    if (B != NULL) {
        for (i = b->top >> 2; i > 0; i--, A += 4, B += 4) {
            /*
             * The fact that the loop is unrolled
             * 4-wise is a tribute to Intel. It's
             * the one that doesn't have enough
             * registers to accomodate more data.
             * I'd unroll it 8-wise otherwise:-)
             *
             *              <appro@fy.chalmers.se>
             */
            BN_ULONG a0, a1, a2, a3;
            a0 = B[0];
            a1 = B[1];
            a2 = B[2];
            a3 = B[3];
            A[0] = a0;
            A[1] = a1;
            A[2] = a2;
            A[3] = a3;
        }
        /*
         * workaround for ultrix cc: without 'case 0', the optimizer does
         * the switch table by doing a=top&3; a--; goto jump_table[a];
         * which fails for top== 0
         */
        switch (b->top & 3) {
        case 3:
            A[2] = B[2];
        case 2:
            A[1] = B[1];
        case 1:
            A[0] = B[0];
        case 0:
            ;
        }
    }
#else
    memset(A, 0, sizeof(BN_ULONG) * words);
    memcpy(A, b->d, sizeof(b->d[0]) * b->top);
#endif

    return (a);
}

/*
 * This is an internal function that can be used instead of bn_expand2() when
 * there is a need to copy BIGNUMs instead of only expanding the data part,
 * while still expanding them. Especially useful when needing to expand
 * BIGNUMs that are declared 'const' and should therefore not be changed. The
 * reason to use this instead of a BN_dup() followed by a bn_expand2() is
 * memory allocation overhead.  A BN_dup() followed by a bn_expand2() will
 * allocate new memory for the BIGNUM data twice, and free it once, while
 * bn_dup_expand() makes sure allocation is made only once.
 */

#ifndef OPENSSL_NO_DEPRECATED
BIGNUM *bn_dup_expand(const BIGNUM *b, int words)
{
    BIGNUM *r = NULL;

    bn_check_top(b);

    /*
     * This function does not work if words <= b->dmax && top < words because
     * BN_dup() does not preserve 'dmax'! (But bn_dup_expand() is not used
     * anywhere yet.)
     */

    if (words > b->dmax) {
        BN_ULONG *a = bn_expand_internal(b, words);

        if (a) {
            r = BN_new();
            if (r) {
                r->top = b->top;
                r->dmax = words;
                r->neg = b->neg;
                r->d = a;
            } else {
                /* r == NULL, BN_new failure */
                OPENSSL_free(a);
            }
        }
        /*
         * If a == NULL, there was an error in allocation in
         * bn_expand_internal(), and NULL should be returned
         */
    } else {
        r = BN_dup(b);
    }

    bn_check_top(r);
    return r;
}
#endif

/*
 * This is an internal function that should not be used in applications. It
 * ensures that 'b' has enough room for a 'words' word number and initialises
 * any unused part of b->d with leading zeros. It is mostly used by the
 * various BIGNUM routines. If there is an error, NULL is returned. If not,
 * 'b' is returned.
 */

BIGNUM *bn_expand2(BIGNUM *b, int words)
{
    if (words > b->dmax) {
        BN_ULONG *a = bn_expand_internal(b, words);
        if (!a)
            return NULL;
        if (b->d)
            OPENSSL_free(b->d);
        b->d = a;
        b->dmax = words;
    }

/* None of this should be necessary because of what b->top means! */
#if 0
    /*
     * NB: bn_wexpand() calls this only if the BIGNUM really has to grow
     */
    if (b->top < b->dmax) {
        int i;
        BN_ULONG *A = &(b->d[b->top]);
        for (i = (b->dmax - b->top) >> 3; i > 0; i--, A += 8) {
            A[0] = 0;
            A[1] = 0;
            A[2] = 0;
            A[3] = 0;
            A[4] = 0;
            A[5] = 0;
            A[6] = 0;
            A[7] = 0;
        }
        for (i = (b->dmax - b->top) & 7; i > 0; i--, A++)
            A[0] = 0;
        assert(A == &(b->d[b->dmax]));
    }
#endif
    return b;
}

BIGNUM *BN_dup(const BIGNUM *a)
{
    BIGNUM *t;

    if (a == NULL)
        return NULL;
    bn_check_top(a);

    t = BN_new();
    if (t == NULL)
        return NULL;
    if (!BN_copy(t, a)) {
        BN_free(t);
        return NULL;
    }
    bn_check_top(t);
    return t;
}

BIGNUM *BN_copy(BIGNUM *a, const BIGNUM *b)
{
    int i;
    BN_ULONG *A;
    const BN_ULONG *B;

    bn_check_top(b);

    if (a == b)
        return (a);
    if (bn_wexpand(a, b->top) == NULL)
        return (NULL);

#if 1
    A = a->d;
    B = b->d;
    for (i = b->top >> 2; i > 0; i--, A += 4, B += 4) {
        BN_ULONG a0, a1, a2, a3;
        a0 = B[0];
        a1 = B[1];
        a2 = B[2];
        a3 = B[3];
        A[0] = a0;
        A[1] = a1;
        A[2] = a2;
        A[3] = a3;
    }
    /* ultrix cc workaround, see comments in bn_expand_internal */
    switch (b->top & 3) {
    case 3:
        A[2] = B[2];
    case 2:
        A[1] = B[1];
    case 1:
        A[0] = B[0];
    case 0:;
    }
#else
    memcpy(a->d, b->d, sizeof(b->d[0]) * b->top);
#endif

    a->neg = b->neg;
    a->top = b->top;
    a->flags |= b->flags & BN_FLG_FIXED_TOP;
    bn_check_top(a);
    return (a);
}

#define FLAGS_DATA(flags) ((flags) & (BN_FLG_STATIC_DATA \
                                    | BN_FLG_CONSTTIME   \
                                    | BN_FLG_FIXED_TOP))
#define FLAGS_STRUCT(flags) ((flags) & (BN_FLG_MALLOCED))

void BN_swap(BIGNUM *a, BIGNUM *b)
{
    int flags_old_a, flags_old_b;
    BN_ULONG *tmp_d;
    int tmp_top, tmp_dmax, tmp_neg;

    bn_check_top(a);
    bn_check_top(b);

    flags_old_a = a->flags;
    flags_old_b = b->flags;

    tmp_d = a->d;
    tmp_top = a->top;
    tmp_dmax = a->dmax;
    tmp_neg = a->neg;

    a->d = b->d;
    a->top = b->top;
    a->dmax = b->dmax;
    a->neg = b->neg;

    b->d = tmp_d;
    b->top = tmp_top;
    b->dmax = tmp_dmax;
    b->neg = tmp_neg;

    a->flags = FLAGS_STRUCT(flags_old_a) | FLAGS_DATA(flags_old_b);
    b->flags = FLAGS_STRUCT(flags_old_b) | FLAGS_DATA(flags_old_a);
    bn_check_top(a);
    bn_check_top(b);
}

void BN_clear(BIGNUM *a)
{
    bn_check_top(a);
    if (a->d != NULL)
        OPENSSL_cleanse(a->d, a->dmax * sizeof(a->d[0]));
    a->top = 0;
    a->neg = 0;
    a->flags &= ~BN_FLG_FIXED_TOP;
}

BN_ULONG BN_get_word(const BIGNUM *a)
{
    if (a->top > 1)
        return BN_MASK2;
    else if (a->top == 1)
        return a->d[0];
    /* a->top == 0 */
    return 0;
}

int BN_set_word(BIGNUM *a, BN_ULONG w)
{
    bn_check_top(a);
    if (bn_expand(a, (int)sizeof(BN_ULONG) * 8) == NULL)
        return (0);
    a->neg = 0;
    a->d[0] = w;
    a->top = (w ? 1 : 0);
    a->flags &= ~BN_FLG_FIXED_TOP;
    bn_check_top(a);
    return (1);
}

BIGNUM *BN_bin2bn(const unsigned char *s, int len, BIGNUM *ret)
{
    unsigned int i, m;
    unsigned int n;
    BN_ULONG l;
    BIGNUM *bn = NULL;

    if (ret == NULL)
        ret = bn = BN_new();
    if (ret == NULL)
        return (NULL);
    bn_check_top(ret);
    l = 0;
    n = len;
    if (n == 0) {
        ret->top = 0;
        return (ret);
    }
    i = ((n - 1) / BN_BYTES) + 1;
    m = ((n - 1) % (BN_BYTES));
    if (bn_wexpand(ret, (int)i) == NULL) {
        if (bn)
            BN_free(bn);
        return NULL;
    }
    ret->top = i;
    ret->neg = 0;
    while (n--) {
        l = (l << 8L) | *(s++);
        if (m-- == 0) {
            ret->d[--i] = l;
            l = 0;
            m = BN_BYTES - 1;
        }
    }
    /*
     * need to call this due to clear byte at top if avoiding having the top
     * bit set (-ve number)
     */
    bn_correct_top(ret);
    return (ret);
}

/* ignore negative */
static int bn2binpad(const BIGNUM *a, unsigned char *to, int tolen)
{
    int n;
    size_t i, lasti, j, atop, mask;
    BN_ULONG l;

    /*
     * In case |a| is fixed-top, BN_num_bytes can return bogus length,
     * but it's assumed that fixed-top inputs ought to be "nominated"
     * even for padded output, so it works out...
     */
    n = BN_num_bytes(a);
    if (tolen == -1) {
        tolen = n;
    } else if (tolen < n) {     /* uncommon/unlike case */
        BIGNUM temp = *a;

        bn_correct_top(&temp);
        n = BN_num_bytes(&temp);
        if (tolen < n)
            return -1;
    }

    /* Swipe through whole available data and don't give away padded zero. */
    atop = a->dmax * BN_BYTES;
    if (atop == 0) {
        OPENSSL_cleanse(to, tolen);
        return tolen;
    }

    lasti = atop - 1;
    atop = a->top * BN_BYTES;
    for (i = 0, j = 0, to += tolen; j < (size_t)tolen; j++) {
        l = a->d[i / BN_BYTES];
        mask = 0 - ((j - atop) >> (8 * sizeof(i) - 1));
        *--to = (unsigned char)(l >> (8 * (i % BN_BYTES)) & mask);
        i += (i - lasti) >> (8 * sizeof(i) - 1); /* stay on last limb */
    }

    return tolen;
}

int bn_bn2binpad(const BIGNUM *a, unsigned char *to, int tolen)
{
    if (tolen < 0)
        return -1;
    return bn2binpad(a, to, tolen);
}

int BN_bn2bin(const BIGNUM *a, unsigned char *to)
{
    int n, i;
    BN_ULONG l;

    bn_check_top(a);
    n = i = BN_num_bytes(a);
    while (i--) {
        l = a->d[i / BN_BYTES];
        *(to++) = (unsigned char)(l >> (8 * (i % BN_BYTES))) & 0xff;
    }
    return (n);
}

int BN_ucmp(const BIGNUM *a, const BIGNUM *b)
{
    int i;
    BN_ULONG t1, t2, *ap, *bp;

    bn_check_top(a);
    bn_check_top(b);

    i = a->top - b->top;
    if (i != 0)
        return (i);
    ap = a->d;
    bp = b->d;
    for (i = a->top - 1; i >= 0; i--) {
        t1 = ap[i];
        t2 = bp[i];
        if (t1 != t2)
            return ((t1 > t2) ? 1 : -1);
    }
    return (0);
}

int BN_cmp(const BIGNUM *a, const BIGNUM *b)
{
    int i;
    int gt, lt;
    BN_ULONG t1, t2;

    if ((a == NULL) || (b == NULL)) {
        if (a != NULL)
            return (-1);
        else if (b != NULL)
            return (1);
        else
            return (0);
    }

    bn_check_top(a);
    bn_check_top(b);

    if (a->neg != b->neg) {
        if (a->neg)
            return (-1);
        else
            return (1);
    }
    if (a->neg == 0) {
        gt = 1;
        lt = -1;
    } else {
        gt = -1;
        lt = 1;
    }

    if (a->top > b->top)
        return (gt);
    if (a->top < b->top)
        return (lt);
    for (i = a->top - 1; i >= 0; i--) {
        t1 = a->d[i];
        t2 = b->d[i];
        if (t1 > t2)
            return (gt);
        if (t1 < t2)
            return (lt);
    }
    return (0);
}

int BN_set_bit(BIGNUM *a, int n)
{
    int i, j, k;

    if (n < 0)
        return 0;

    i = n / BN_BITS2;
    j = n % BN_BITS2;
    if (a->top <= i) {
        if (bn_wexpand(a, i + 1) == NULL)
            return (0);
        for (k = a->top; k < i + 1; k++)
            a->d[k] = 0;
        a->top = i + 1;
        a->flags &= ~BN_FLG_FIXED_TOP;
    }

    a->d[i] |= (((BN_ULONG)1) << j);
    bn_check_top(a);
    return (1);
}

int BN_clear_bit(BIGNUM *a, int n)
{
    int i, j;

    bn_check_top(a);
    if (n < 0)
        return 0;

    i = n / BN_BITS2;
    j = n % BN_BITS2;
    if (a->top <= i)
        return (0);

    a->d[i] &= (~(((BN_ULONG)1) << j));
    bn_correct_top(a);
    return (1);
}

int BN_is_bit_set(const BIGNUM *a, int n)
{
    int i, j;

    bn_check_top(a);
    if (n < 0)
        return 0;
    i = n / BN_BITS2;
    j = n % BN_BITS2;
    if (a->top <= i)
        return 0;
    return (int)(((a->d[i]) >> j) & ((BN_ULONG)1));
}

int BN_mask_bits(BIGNUM *a, int n)
{
    int b, w;

    bn_check_top(a);
    if (n < 0)
        return 0;

    w = n / BN_BITS2;
    b = n % BN_BITS2;
    if (w >= a->top)
        return 0;
    if (b == 0)
        a->top = w;
    else {
        a->top = w + 1;
        a->d[w] &= ~(BN_MASK2 << b);
    }
    bn_correct_top(a);
    return (1);
}

void BN_set_negative(BIGNUM *a, int b)
{
    if (b && !BN_is_zero(a))
        a->neg = 1;
    else
        a->neg = 0;
}

int bn_cmp_words(const BN_ULONG *a, const BN_ULONG *b, int n)
{
    int i;
    BN_ULONG aa, bb;

    aa = a[n - 1];
    bb = b[n - 1];
    if (aa != bb)
        return ((aa > bb) ? 1 : -1);
    for (i = n - 2; i >= 0; i--) {
        aa = a[i];
        bb = b[i];
        if (aa != bb)
            return ((aa > bb) ? 1 : -1);
    }
    return (0);
}

/*
 * Here follows a specialised variants of bn_cmp_words().  It has the
 * property of performing the operation on arrays of different sizes. The
 * sizes of those arrays is expressed through cl, which is the common length
 * ( basicall, min(len(a),len(b)) ), and dl, which is the delta between the
 * two lengths, calculated as len(a)-len(b). All lengths are the number of
 * BN_ULONGs...
 */

int bn_cmp_part_words(const BN_ULONG *a, const BN_ULONG *b, int cl, int dl)
{
    int n, i;
    n = cl - 1;

    if (dl < 0) {
        for (i = dl; i < 0; i++) {
            if (b[n - i] != 0)
                return -1;      /* a < b */
        }
    }
    if (dl > 0) {
        for (i = dl; i > 0; i--) {
            if (a[n + i] != 0)
                return 1;       /* a > b */
        }
    }
    return bn_cmp_words(a, b, cl);
}

/*
 * Constant-time conditional swap of a and b.
 * a and b are swapped if condition is not 0.  The code assumes that at most one bit of condition is set.
 * nwords is the number of words to swap.  The code assumes that at least nwords are allocated in both a and b,
 * and that no more than nwords are used by either a or b.
 * a and b cannot be the same number
 */
void BN_consttime_swap(BN_ULONG condition, BIGNUM *a, BIGNUM *b, int nwords)
{
    BN_ULONG t;
    int i;

    bn_wcheck_size(a, nwords);
    bn_wcheck_size(b, nwords);

    assert(a != b);
    assert((condition & (condition - 1)) == 0);
    assert(sizeof(BN_ULONG) >= sizeof(int));

    condition = ((condition - 1) >> (BN_BITS2 - 1)) - 1;

    t = (a->top ^ b->top) & condition;
    a->top ^= t;
    b->top ^= t;

    t = (a->neg ^ b->neg) & condition;
    a->neg ^= t;
    b->neg ^= t;

    /*-
     * BN_FLG_STATIC_DATA: indicates that data may not be written to. Intention
     * is actually to treat it as it's read-only data, and some (if not most)
     * of it does reside in read-only segment. In other words observation of
     * BN_FLG_STATIC_DATA in BN_consttime_swap should be treated as fatal
     * condition. It would either cause SEGV or effectively cause data
     * corruption.
     *
     * BN_FLG_MALLOCED: refers to BN structure itself, and hence must be
     * preserved.
     *
     * BN_FLG_SECURE: must be preserved, because it determines how x->d was
     * allocated and hence how to free it.
     *
     * BN_FLG_CONSTTIME: sufficient to mask and swap
     *
     * BN_FLG_FIXED_TOP: indicates that we haven't called bn_correct_top() on
     * the data, so the d array may be padded with additional 0 values (i.e.
     * top could be greater than the minimal value that it could be). We should
     * be swapping it
     */

#define BN_CONSTTIME_SWAP_FLAGS (BN_FLG_CONSTTIME | BN_FLG_FIXED_TOP)

    t = ((a->flags ^ b->flags) & BN_CONSTTIME_SWAP_FLAGS) & condition;
    a->flags ^= t;
    b->flags ^= t;

#define BN_CONSTTIME_SWAP(ind) \
        do { \
                t = (a->d[ind] ^ b->d[ind]) & condition; \
                a->d[ind] ^= t; \
                b->d[ind] ^= t; \
        } while (0)

    switch (nwords) {
    default:
        for (i = 10; i < nwords; i++)
            BN_CONSTTIME_SWAP(i);
        /* Fallthrough */
    case 10:
        BN_CONSTTIME_SWAP(9);   /* Fallthrough */
    case 9:
        BN_CONSTTIME_SWAP(8);   /* Fallthrough */
    case 8:
        BN_CONSTTIME_SWAP(7);   /* Fallthrough */
    case 7:
        BN_CONSTTIME_SWAP(6);   /* Fallthrough */
    case 6:
        BN_CONSTTIME_SWAP(5);   /* Fallthrough */
    case 5:
        BN_CONSTTIME_SWAP(4);   /* Fallthrough */
    case 4:
        BN_CONSTTIME_SWAP(3);   /* Fallthrough */
    case 3:
        BN_CONSTTIME_SWAP(2);   /* Fallthrough */
    case 2:
        BN_CONSTTIME_SWAP(1);   /* Fallthrough */
    case 1:
        BN_CONSTTIME_SWAP(0);
    }
#undef BN_CONSTTIME_SWAP
}
/* crypto/bn/bn_mod.c */
/*
 * Includes code written by Lenka Fibikova <fibikova@exp-math.uni-essen.de>
 * for the OpenSSL project.
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

// #include "cryptlib.h"
// #include "bn_lcl.h"

#if 0                           /* now just a #define */
int BN_mod(BIGNUM *rem, const BIGNUM *m, const BIGNUM *d, BN_CTX *ctx)
{
    return (BN_div(NULL, rem, m, d, ctx));
    /* note that  rem->neg == m->neg  (unless the remainder is zero) */
}
#endif

int BN_nnmod(BIGNUM *r, const BIGNUM *m, const BIGNUM *d, BN_CTX *ctx)
{
    /*
     * like BN_mod, but returns non-negative remainder (i.e., 0 <= r < |d|
     * always holds)
     */

    if (!(BN_mod(r, m, d, ctx)))
        return 0;
    if (!r->neg)
        return 1;
    /* now   -|d| < r < 0,  so we have to set  r := r + |d| */
    return (d->neg ? BN_sub : BN_add) (r, r, d);
}

int BN_mod_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m,
               BN_CTX *ctx)
{
    if (!BN_add(r, a, b))
        return 0;
    return BN_nnmod(r, r, m, ctx);
}

/*
 * BN_mod_add variant that may be used if both a and b are non-negative and
 * less than m. The original algorithm was
 *
 *    if (!BN_uadd(r, a, b))
 *       return 0;
 *    if (BN_ucmp(r, m) >= 0)
 *       return BN_usub(r, r, m);
 *
 * which is replaced with addition, subtracting modulus, and conditional
 * move depending on whether or not subtraction borrowed.
 */
int bn_mod_add_fixed_top(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
                         const BIGNUM *m)
{
    size_t i, ai, bi, mtop = m->top;
    BN_ULONG storage[1024 / BN_BITS2];
    BN_ULONG carry, temp, mask, *rp, *tp = storage;
    const BN_ULONG *ap, *bp;

    if (bn_wexpand(r, m->top) == NULL)
        return 0;

    if (mtop > sizeof(storage) / sizeof(storage[0])
        && (tp = OPENSSL_malloc(mtop * sizeof(BN_ULONG))) == NULL)
        return 0;

    ap = a->d != NULL ? a->d : tp;
    bp = b->d != NULL ? b->d : tp;

    for (i = 0, ai = 0, bi = 0, carry = 0; i < mtop;) {
        mask = (BN_ULONG)0 - ((i - a->top) >> (8 * sizeof(i) - 1));
        temp = ((ap[ai] & mask) + carry) & BN_MASK2;
        carry = (temp < carry);

        mask = (BN_ULONG)0 - ((i - b->top) >> (8 * sizeof(i) - 1));
        tp[i] = ((bp[bi] & mask) + temp) & BN_MASK2;
        carry += (tp[i] < temp);

        i++;
        ai += (i - a->dmax) >> (8 * sizeof(i) - 1);
        bi += (i - b->dmax) >> (8 * sizeof(i) - 1);
    }
    rp = r->d;
    carry -= bn_sub_words(rp, tp, m->d, mtop);
    for (i = 0; i < mtop; i++) {
        rp[i] = (carry & tp[i]) | (~carry & rp[i]);
        ((volatile BN_ULONG *)tp)[i] = 0;
    }
    r->top = mtop;
    r->flags |= BN_FLG_FIXED_TOP;
    r->neg = 0;

    if (tp != storage)
        OPENSSL_free(tp);

    return 1;
}

int BN_mod_add_quick(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
                     const BIGNUM *m)
{
    int ret = bn_mod_add_fixed_top(r, a, b, m);

    if (ret)
        bn_correct_top(r);

    return ret;
}

int BN_mod_sub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m,
               BN_CTX *ctx)
{
    if (!BN_sub(r, a, b))
        return 0;
    return BN_nnmod(r, r, m, ctx);
}

/*
 * BN_mod_sub variant that may be used if both a and b are non-negative,
 * a is less than m, while b is of same bit width as m. It's implemented
 * as subtraction followed by two conditional additions.
 *
 * 0 <= a < m
 * 0 <= b < 2^w < 2*m
 *
 * after subtraction
 *
 * -2*m < r = a - b < m
 *
 * Thus it takes up to two conditional additions to make |r| positive.
 */
int bn_mod_sub_fixed_top(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
                         const BIGNUM *m)
{
    size_t i, ai, bi, mtop = m->top;
    BN_ULONG borrow, carry, ta, tb, mask, *rp;
    const BN_ULONG *ap, *bp;

    if (bn_wexpand(r, m->top) == NULL)
        return 0;

    rp = r->d;
    ap = a->d != NULL ? a->d : rp;
    bp = b->d != NULL ? b->d : rp;

    for (i = 0, ai = 0, bi = 0, borrow = 0; i < mtop;) {
        mask = (BN_ULONG)0 - ((i - a->top) >> (8 * sizeof(i) - 1));
        ta = ap[ai] & mask;

        mask = (BN_ULONG)0 - ((i - b->top) >> (8 * sizeof(i) - 1));
        tb = bp[bi] & mask;
        rp[i] = ta - tb - borrow;
        if (ta != tb)
            borrow = (ta < tb);

        i++;
        ai += (i - a->dmax) >> (8 * sizeof(i) - 1);
        bi += (i - b->dmax) >> (8 * sizeof(i) - 1);
    }
    ap = m->d;
    for (i = 0, mask = 0 - borrow, carry = 0; i < mtop; i++) {
        ta = ((ap[i] & mask) + carry) & BN_MASK2;
        carry = (ta < carry);
        rp[i] = (rp[i] + ta) & BN_MASK2;
        carry += (rp[i] < ta);
    }
    borrow -= carry;
    for (i = 0, mask = 0 - borrow, carry = 0; i < mtop; i++) {
        ta = ((ap[i] & mask) + carry) & BN_MASK2;
        carry = (ta < carry);
        rp[i] = (rp[i] + ta) & BN_MASK2;
        carry += (rp[i] < ta);
    }

    r->top = mtop;
    r->flags |= BN_FLG_FIXED_TOP;
    r->neg = 0;

    return 1;
}

/*
 * BN_mod_sub variant that may be used if both a and b are non-negative and
 * less than m
 */
int BN_mod_sub_quick(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
                     const BIGNUM *m)
{
    if (!BN_sub(r, a, b))
        return 0;
    if (r->neg)
        return BN_add(r, r, m);
    return 1;
}

/* slow but works */
int BN_mod_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m,
               BN_CTX *ctx)
{
    BIGNUM *t;
    int ret = 0;

    bn_check_top(a);
    bn_check_top(b);
    bn_check_top(m);

    BN_CTX_start(ctx);
    if ((t = BN_CTX_get(ctx)) == NULL)
        goto err;
    if (a == b) {
        if (!BN_sqr(t, a, ctx))
            goto err;
    } else {
        if (!BN_mul(t, a, b, ctx))
            goto err;
    }
    if (!BN_nnmod(r, t, m, ctx))
        goto err;
    bn_check_top(r);
    ret = 1;
 err:
    BN_CTX_end(ctx);
    return (ret);
}

int BN_mod_sqr(BIGNUM *r, const BIGNUM *a, const BIGNUM *m, BN_CTX *ctx)
{
    if (!BN_sqr(r, a, ctx))
        return 0;
    /* r->neg == 0,  thus we don't need BN_nnmod */
    return BN_mod(r, r, m, ctx);
}

int BN_mod_lshift1(BIGNUM *r, const BIGNUM *a, const BIGNUM *m, BN_CTX *ctx)
{
    if (!BN_lshift1(r, a))
        return 0;
    bn_check_top(r);
    return BN_nnmod(r, r, m, ctx);
}

/*
 * BN_mod_lshift1 variant that may be used if a is non-negative and less than
 * m
 */
int BN_mod_lshift1_quick(BIGNUM *r, const BIGNUM *a, const BIGNUM *m)
{
    if (!BN_lshift1(r, a))
        return 0;
    bn_check_top(r);
    if (BN_cmp(r, m) >= 0)
        return BN_sub(r, r, m);
    return 1;
}

int BN_mod_lshift(BIGNUM *r, const BIGNUM *a, int n, const BIGNUM *m,
                  BN_CTX *ctx)
{
    BIGNUM *abs_m = NULL;
    int ret;

    if (!BN_nnmod(r, a, m, ctx))
        return 0;

    if (m->neg) {
        abs_m = BN_dup(m);
        if (abs_m == NULL)
            return 0;
        abs_m->neg = 0;
    }

    ret = BN_mod_lshift_quick(r, r, n, (abs_m ? abs_m : m));
    bn_check_top(r);

    if (abs_m)
        BN_free(abs_m);
    return ret;
}

/*
 * BN_mod_lshift variant that may be used if a is non-negative and less than
 * m
 */
int BN_mod_lshift_quick(BIGNUM *r, const BIGNUM *a, int n, const BIGNUM *m)
{
    if (r != a) {
        if (BN_copy(r, a) == NULL)
            return 0;
    }

    while (n > 0) {
        int max_shift;

        /* 0 < r < m */
        max_shift = BN_num_bits(m) - BN_num_bits(r);
        /* max_shift >= 0 */

        if (max_shift < 0) {
            BNerr(BN_F_BN_MOD_LSHIFT_QUICK, BN_R_INPUT_NOT_REDUCED);
            return 0;
        }

        if (max_shift > n)
            max_shift = n;

        if (max_shift) {
            if (!BN_lshift(r, r, max_shift))
                return 0;
            n -= max_shift;
        } else {
            if (!BN_lshift1(r, r))
                return 0;
            --n;
        }

        /* BN_num_bits(r) <= BN_num_bits(m) */

        if (BN_cmp(r, m) >= 0) {
            if (!BN_sub(r, r, m))
                return 0;
        }
    }
    bn_check_top(r);

    return 1;
}
/* crypto/bn/bn_mont.c */
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

/*
 * Details about Montgomery multiplication algorithms can be found at
 * http://security.ece.orst.edu/publications.html, e.g.
 * http://security.ece.orst.edu/koc/papers/j37acmon.pdf and
 * sections 3.8 and 4.2 in http://security.ece.orst.edu/koc/papers/r01rsasw.pdf
 */

#include <stdio.h>
// #include "cryptlib.h"
// #include "bn_lcl.h"

#define MONT_WORD               /* use the faster word-based algorithm */

#ifdef MONT_WORD
static int bn_from_montgomery_word(BIGNUM *ret, BIGNUM *r, BN_MONT_CTX *mont);
#endif

int BN_mod_mul_montgomery(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
                          BN_MONT_CTX *mont, BN_CTX *ctx)
{
    int ret = bn_mul_mont_fixed_top(r, a, b, mont, ctx);

    bn_correct_top(r);
    bn_check_top(r);

    return ret;
}

int bn_mul_mont_fixed_top(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
                          BN_MONT_CTX *mont, BN_CTX *ctx)
{
    BIGNUM *tmp;
    int ret = 0;
#if defined(OPENSSL_BN_ASM_MONT) && defined(MONT_WORD)
    int num = mont->N.top;

    if (num > 1 && a->top == num && b->top == num) {
        if (bn_wexpand(r, num) == NULL)
            return (0);
        if (bn_mul_mont(r->d, a->d, b->d, mont->N.d, mont->n0, num)) {
            r->neg = a->neg ^ b->neg;
            r->top = num;
            r->flags |= BN_FLG_FIXED_TOP;
            return 1;
        }
    }
#endif

    BN_CTX_start(ctx);
    tmp = BN_CTX_get(ctx);
    if (tmp == NULL)
        goto err;

    bn_check_top(tmp);
    if (a == b) {
        if (!bn_sqr_fixed_top(tmp, a, ctx))
            goto err;
    } else {
        if (!bn_mul_fixed_top(tmp, a, b, ctx))
            goto err;
    }
    /* reduce from aRR to aR */
#ifdef MONT_WORD
    if (!bn_from_montgomery_word(r, tmp, mont))
        goto err;
#else
    if (!BN_from_montgomery(r, tmp, mont, ctx))
        goto err;
#endif
    ret = 1;
 err:
    BN_CTX_end(ctx);
    return (ret);
}

#ifdef MONT_WORD
static int bn_from_montgomery_word(BIGNUM *ret, BIGNUM *r, BN_MONT_CTX *mont)
{
    BIGNUM *n;
    BN_ULONG *ap, *np, *rp, n0, v, carry;
    int nl, max, i;
    unsigned int rtop;

    n = &(mont->N);
    nl = n->top;
    if (nl == 0) {
        ret->top = 0;
        return (1);
    }

    max = (2 * nl);             /* carry is stored separately */
    if (bn_wexpand(r, max) == NULL)
        return (0);

    r->neg ^= n->neg;
    np = n->d;
    rp = r->d;

    /* clear the top words of T */
    for (rtop = r->top, i = 0; i < max; i++) {
        v = (BN_ULONG)0 - ((i - rtop) >> (8 * sizeof(rtop) - 1));
        rp[i] &= v;
    }

    r->top = max;
    r->flags |= BN_FLG_FIXED_TOP;
    n0 = mont->n0[0];

    /*
     * Add multiples of |n| to |r| until R = 2^(nl * BN_BITS2) divides it. On
     * input, we had |r| < |n| * R, so now |r| < 2 * |n| * R. Note that |r|
     * includes |carry| which is stored separately.
     */
    for (carry = 0, i = 0; i < nl; i++, rp++) {
        v = bn_mul_add_words(rp, np, nl, (rp[0] * n0) & BN_MASK2);
        v = (v + carry + rp[nl]) & BN_MASK2;
        carry |= (v != rp[nl]);
        carry &= (v <= rp[nl]);
        rp[nl] = v;
    }

    if (bn_wexpand(ret, nl) == NULL)
        return (0);
    ret->top = nl;
    ret->flags |= BN_FLG_FIXED_TOP;
    ret->neg = r->neg;

    rp = ret->d;

    /*
     * Shift |nl| words to divide by R. We have |ap| < 2 * |n|. Note that |ap|
     * includes |carry| which is stored separately.
     */
    ap = &(r->d[nl]);

    carry -= bn_sub_words(rp, ap, np, nl);
    /*
     * |carry| is -1 if |ap| - |np| underflowed or zero if it did not. Note
     * |carry| cannot be 1. That would imply the subtraction did not fit in
     * |nl| words, and we know at most one subtraction is needed.
     */
    for (i = 0; i < nl; i++) {
        rp[i] = (carry & ap[i]) | (~carry & rp[i]);
        ap[i] = 0;
    }

    return (1);
}
#endif                          /* MONT_WORD */

int BN_from_montgomery(BIGNUM *ret, const BIGNUM *a, BN_MONT_CTX *mont,
                       BN_CTX *ctx)
{
    int retn;

    retn = bn_from_mont_fixed_top(ret, a, mont, ctx);
    bn_correct_top(ret);
    bn_check_top(ret);

    return retn;
}

int bn_from_mont_fixed_top(BIGNUM *ret, const BIGNUM *a, BN_MONT_CTX *mont,
                           BN_CTX *ctx)
{
    int retn = 0;
#ifdef MONT_WORD
    BIGNUM *t;

    BN_CTX_start(ctx);
    if ((t = BN_CTX_get(ctx)) && BN_copy(t, a)) {
        retn = bn_from_montgomery_word(ret, t, mont);
    }
    BN_CTX_end(ctx);
#else                           /* !MONT_WORD */
    BIGNUM *t1, *t2;

    BN_CTX_start(ctx);
    t1 = BN_CTX_get(ctx);
    t2 = BN_CTX_get(ctx);
    if (t1 == NULL || t2 == NULL)
        goto err;

    if (!BN_copy(t1, a))
        goto err;
    BN_mask_bits(t1, mont->ri);

    if (!BN_mul(t2, t1, &mont->Ni, ctx))
        goto err;
    BN_mask_bits(t2, mont->ri);

    if (!BN_mul(t1, t2, &mont->N, ctx))
        goto err;
    if (!BN_add(t2, a, t1))
        goto err;
    if (!BN_rshift(ret, t2, mont->ri))
        goto err;

    if (BN_ucmp(ret, &(mont->N)) >= 0) {
        if (!BN_usub(ret, ret, &(mont->N)))
            goto err;
    }
    retn = 1;
    bn_check_top(ret);
 err:
    BN_CTX_end(ctx);
#endif                          /* MONT_WORD */
    return (retn);
}

int bn_to_mont_fixed_top(BIGNUM *r, const BIGNUM *a, BN_MONT_CTX *mont,
                         BN_CTX *ctx)
{
    return bn_mul_mont_fixed_top(r, a, &(mont->RR), mont, ctx);
}

BN_MONT_CTX *BN_MONT_CTX_new(void)
{
    BN_MONT_CTX *ret;

    if ((ret = (BN_MONT_CTX *)OPENSSL_malloc(sizeof(BN_MONT_CTX))) == NULL)
        return (NULL);

    BN_MONT_CTX_init(ret);
    ret->flags = BN_FLG_MALLOCED;
    return (ret);
}

void BN_MONT_CTX_init(BN_MONT_CTX *ctx)
{
    ctx->ri = 0;
    BN_init(&(ctx->RR));
    BN_init(&(ctx->N));
    BN_init(&(ctx->Ni));
    ctx->n0[0] = ctx->n0[1] = 0;
    ctx->flags = 0;
}

void BN_MONT_CTX_free(BN_MONT_CTX *mont)
{
    if (mont == NULL)
        return;

    BN_clear_free(&(mont->RR));
    BN_clear_free(&(mont->N));
    BN_clear_free(&(mont->Ni));
    if (mont->flags & BN_FLG_MALLOCED)
        OPENSSL_free(mont);
}

int BN_MONT_CTX_set(BN_MONT_CTX *mont, const BIGNUM *mod, BN_CTX *ctx)
{
    int i, ret = 0;
    BIGNUM *Ri, *R;

    if (BN_is_zero(mod))
        return 0;

    BN_CTX_start(ctx);
    if ((Ri = BN_CTX_get(ctx)) == NULL)
        goto err;
    R = &(mont->RR);            /* grab RR as a temp */
    if (!BN_copy(&(mont->N), mod))
        goto err;               /* Set N */
    if (BN_get_flags(mod, BN_FLG_CONSTTIME) != 0)
        BN_set_flags(&(mont->N), BN_FLG_CONSTTIME);
    mont->N.neg = 0;

#ifdef MONT_WORD
    {
        BIGNUM tmod;
        BN_ULONG buf[2];

        BN_init(&tmod);
        tmod.d = buf;
        tmod.dmax = 2;
        tmod.neg = 0;

        if (BN_get_flags(mod, BN_FLG_CONSTTIME) != 0)
            BN_set_flags(&tmod, BN_FLG_CONSTTIME);

        mont->ri = (BN_num_bits(mod) + (BN_BITS2 - 1)) / BN_BITS2 * BN_BITS2;

# if defined(OPENSSL_BN_ASM_MONT) && (BN_BITS2<=32)
        /*
         * Only certain BN_BITS2<=32 platforms actually make use of n0[1],
         * and we could use the #else case (with a shorter R value) for the
         * others.  However, currently only the assembler files do know which
         * is which.
         */

        BN_zero(R);
        if (!(BN_set_bit(R, 2 * BN_BITS2)))
            goto err;

        tmod.top = 0;
        if ((buf[0] = mod->d[0]))
            tmod.top = 1;
        if ((buf[1] = mod->top > 1 ? mod->d[1] : 0))
            tmod.top = 2;

        if ((BN_mod_inverse(Ri, R, &tmod, ctx)) == NULL)
            goto err;
        if (!BN_lshift(Ri, Ri, 2 * BN_BITS2))
            goto err;           /* R*Ri */
        if (!BN_is_zero(Ri)) {
            if (!BN_sub_word(Ri, 1))
                goto err;
        } else {                /* if N mod word size == 1 */

            if (bn_expand(Ri, (int)sizeof(BN_ULONG) * 2) == NULL)
                goto err;
            /* Ri-- (mod double word size) */
            Ri->neg = 0;
            Ri->d[0] = BN_MASK2;
            Ri->d[1] = BN_MASK2;
            Ri->top = 2;
        }
        if (!BN_div(Ri, NULL, Ri, &tmod, ctx))
            goto err;
        /*
         * Ni = (R*Ri-1)/N, keep only couple of least significant words:
         */
        mont->n0[0] = (Ri->top > 0) ? Ri->d[0] : 0;
        mont->n0[1] = (Ri->top > 1) ? Ri->d[1] : 0;
# else
        BN_zero(R);
        if (!(BN_set_bit(R, BN_BITS2)))
            goto err;           /* R */

        buf[0] = mod->d[0];     /* tmod = N mod word size */
        buf[1] = 0;
        tmod.top = buf[0] != 0 ? 1 : 0;
        /* Ri = R^-1 mod N */
        if ((BN_mod_inverse(Ri, R, &tmod, ctx)) == NULL)
            goto err;
        if (!BN_lshift(Ri, Ri, BN_BITS2))
            goto err;           /* R*Ri */
        if (!BN_is_zero(Ri)) {
            if (!BN_sub_word(Ri, 1))
                goto err;
        } else {                /* if N mod word size == 1 */

            if (!BN_set_word(Ri, BN_MASK2))
                goto err;       /* Ri-- (mod word size) */
        }
        if (!BN_div(Ri, NULL, Ri, &tmod, ctx))
            goto err;
        /*
         * Ni = (R*Ri-1)/N, keep only least significant word:
         */
        mont->n0[0] = (Ri->top > 0) ? Ri->d[0] : 0;
        mont->n0[1] = 0;
# endif
    }
#else                           /* !MONT_WORD */
    {                           /* bignum version */
        mont->ri = BN_num_bits(&mont->N);
        BN_zero(R);
        if (!BN_set_bit(R, mont->ri))
            goto err;           /* R = 2^ri */
        /* Ri = R^-1 mod N */
        if ((BN_mod_inverse(Ri, R, &mont->N, ctx)) == NULL)
            goto err;
        if (!BN_lshift(Ri, Ri, mont->ri))
            goto err;           /* R*Ri */
        if (!BN_sub_word(Ri, 1))
            goto err;
        /*
         * Ni = (R*Ri-1) / N
         */
        if (!BN_div(&(mont->Ni), NULL, Ri, &mont->N, ctx))
            goto err;
    }
#endif

    /* setup RR for conversions */
    BN_zero(&(mont->RR));
    if (!BN_set_bit(&(mont->RR), mont->ri * 2))
        goto err;
    if (!BN_mod(&(mont->RR), &(mont->RR), &(mont->N), ctx))
        goto err;

    for (i = mont->RR.top, ret = mont->N.top; i < ret; i++)
        mont->RR.d[i] = 0;
    mont->RR.top = ret;
    mont->RR.flags |= BN_FLG_FIXED_TOP;

    ret = 1;
 err:
    BN_CTX_end(ctx);
    return ret;
}

BN_MONT_CTX *BN_MONT_CTX_copy(BN_MONT_CTX *to, BN_MONT_CTX *from)
{
    if (to == from)
        return (to);

    if (!BN_copy(&(to->RR), &(from->RR)))
        return NULL;
    if (!BN_copy(&(to->N), &(from->N)))
        return NULL;
    if (!BN_copy(&(to->Ni), &(from->Ni)))
        return NULL;
    to->ri = from->ri;
    to->n0[0] = from->n0[0];
    to->n0[1] = from->n0[1];
    return (to);
}

BN_MONT_CTX *BN_MONT_CTX_set_locked(BN_MONT_CTX **pmont, int lock,
                                    const BIGNUM *mod, BN_CTX *ctx)
{
    BN_MONT_CTX *ret;

    CRYPTO_r_lock(lock);
    ret = *pmont;
    CRYPTO_r_unlock(lock);
    if (ret)
        return ret;

    /*
     * We don't want to serialise globally while doing our lazy-init math in
     * BN_MONT_CTX_set. That punishes threads that are doing independent
     * things. Instead, punish the case where more than one thread tries to
     * lazy-init the same 'pmont', by having each do the lazy-init math work
     * independently and only use the one from the thread that wins the race
     * (the losers throw away the work they've done).
     */
    ret = BN_MONT_CTX_new();
    if (!ret)
        return NULL;
    if (!BN_MONT_CTX_set(ret, mod, ctx)) {
        BN_MONT_CTX_free(ret);
        return NULL;
    }

    /* The locked compare-and-set, after the local work is done. */
    CRYPTO_w_lock(lock);
    if (*pmont) {
        BN_MONT_CTX_free(ret);
        ret = *pmont;
    } else
        *pmont = ret;
    CRYPTO_w_unlock(lock);
    return ret;
}
/* crypto/bn/bn_mpi.c */
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
// #include "bn_lcl.h"

int BN_bn2mpi(const BIGNUM *a, unsigned char *d)
{
    int bits;
    int num = 0;
    int ext = 0;
    long l;

    bits = BN_num_bits(a);
    num = (bits + 7) / 8;
    if (bits > 0) {
        ext = ((bits & 0x07) == 0);
    }
    if (d == NULL)
        return (num + 4 + ext);

    l = num + ext;
    d[0] = (unsigned char)(l >> 24) & 0xff;
    d[1] = (unsigned char)(l >> 16) & 0xff;
    d[2] = (unsigned char)(l >> 8) & 0xff;
    d[3] = (unsigned char)(l) & 0xff;
    if (ext)
        d[4] = 0;
    num = BN_bn2bin(a, &(d[4 + ext]));
    if (a->neg)
        d[4] |= 0x80;
    return (num + 4 + ext);
}

BIGNUM *BN_mpi2bn(const unsigned char *d, int n, BIGNUM *a)
{
    long len;
    int neg = 0;

    if (n < 4) {
        BNerr(BN_F_BN_MPI2BN, BN_R_INVALID_LENGTH);
        return (NULL);
    }
    len = ((long)d[0] << 24) | ((long)d[1] << 16) | ((int)d[2] << 8) | (int)
        d[3];
    if ((len + 4) != n) {
        BNerr(BN_F_BN_MPI2BN, BN_R_ENCODING_ERROR);
        return (NULL);
    }

    if (a == NULL)
        a = BN_new();
    if (a == NULL)
        return (NULL);

    if (len == 0) {
        a->neg = 0;
        a->top = 0;
        return (a);
    }
    d += 4;
    if ((*d) & 0x80)
        neg = 1;
    if (BN_bin2bn(d, (int)len, a) == NULL)
        return (NULL);
    a->neg = neg;
    if (neg) {
        BN_clear_bit(a, BN_num_bits(a) - 1);
    }
    bn_check_top(a);
    return (a);
}
/* crypto/bn/bn_mul.c */
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

#ifndef BN_DEBUG
# undef NDEBUG                  /* avoid conflicting definitions */
# define NDEBUG
#endif

#include <stdio.h>
#include <assert.h>
// #include "cryptlib.h"
// #include "bn_lcl.h"

#if defined(OPENSSL_NO_ASM) || !defined(OPENSSL_BN_ASM_PART_WORDS)
/*
 * Here follows specialised variants of bn_add_words() and bn_sub_words().
 * They have the property performing operations on arrays of different sizes.
 * The sizes of those arrays is expressed through cl, which is the common
 * length ( basicall, min(len(a),len(b)) ), and dl, which is the delta
 * between the two lengths, calculated as len(a)-len(b). All lengths are the
 * number of BN_ULONGs...  For the operations that require a result array as
 * parameter, it must have the length cl+abs(dl). These functions should
 * probably end up in bn_asm.c as soon as there are assembler counterparts
 * for the systems that use assembler files.
 */

BN_ULONG bn_sub_part_words(BN_ULONG *r,
                           const BN_ULONG *a, const BN_ULONG *b,
                           int cl, int dl)
{
    BN_ULONG c, t;

    assert(cl >= 0);
    c = bn_sub_words(r, a, b, cl);

    if (dl == 0)
        return c;

    r += cl;
    a += cl;
    b += cl;

    if (dl < 0) {
# ifdef BN_COUNT
        fprintf(stderr, "  bn_sub_part_words %d + %d (dl < 0, c = %d)\n", cl,
                dl, c);
# endif
        for (;;) {
            t = b[0];
            r[0] = (0 - t - c) & BN_MASK2;
            if (t != 0)
                c = 1;
            if (++dl >= 0)
                break;

            t = b[1];
            r[1] = (0 - t - c) & BN_MASK2;
            if (t != 0)
                c = 1;
            if (++dl >= 0)
                break;

            t = b[2];
            r[2] = (0 - t - c) & BN_MASK2;
            if (t != 0)
                c = 1;
            if (++dl >= 0)
                break;

            t = b[3];
            r[3] = (0 - t - c) & BN_MASK2;
            if (t != 0)
                c = 1;
            if (++dl >= 0)
                break;

            b += 4;
            r += 4;
        }
    } else {
        int save_dl = dl;
# ifdef BN_COUNT
        fprintf(stderr, "  bn_sub_part_words %d + %d (dl > 0, c = %d)\n", cl,
                dl, c);
# endif
        while (c) {
            t = a[0];
            r[0] = (t - c) & BN_MASK2;
            if (t != 0)
                c = 0;
            if (--dl <= 0)
                break;

            t = a[1];
            r[1] = (t - c) & BN_MASK2;
            if (t != 0)
                c = 0;
            if (--dl <= 0)
                break;

            t = a[2];
            r[2] = (t - c) & BN_MASK2;
            if (t != 0)
                c = 0;
            if (--dl <= 0)
                break;

            t = a[3];
            r[3] = (t - c) & BN_MASK2;
            if (t != 0)
                c = 0;
            if (--dl <= 0)
                break;

            save_dl = dl;
            a += 4;
            r += 4;
        }
        if (dl > 0) {
# ifdef BN_COUNT
            fprintf(stderr, "  bn_sub_part_words %d + %d (dl > 0, c == 0)\n",
                    cl, dl);
# endif
            if (save_dl > dl) {
                switch (save_dl - dl) {
                case 1:
                    r[1] = a[1];
                    if (--dl <= 0)
                        break;
                case 2:
                    r[2] = a[2];
                    if (--dl <= 0)
                        break;
                case 3:
                    r[3] = a[3];
                    if (--dl <= 0)
                        break;
                }
                a += 4;
                r += 4;
            }
        }
        if (dl > 0) {
# ifdef BN_COUNT
            fprintf(stderr, "  bn_sub_part_words %d + %d (dl > 0, copy)\n",
                    cl, dl);
# endif
            for (;;) {
                r[0] = a[0];
                if (--dl <= 0)
                    break;
                r[1] = a[1];
                if (--dl <= 0)
                    break;
                r[2] = a[2];
                if (--dl <= 0)
                    break;
                r[3] = a[3];
                if (--dl <= 0)
                    break;

                a += 4;
                r += 4;
            }
        }
    }
    return c;
}
#endif

BN_ULONG bn_add_part_words(BN_ULONG *r,
                           const BN_ULONG *a, const BN_ULONG *b,
                           int cl, int dl)
{
    BN_ULONG c, l, t;

    assert(cl >= 0);
    c = bn_add_words(r, a, b, cl);

    if (dl == 0)
        return c;

    r += cl;
    a += cl;
    b += cl;

    if (dl < 0) {
        int save_dl = dl;
#ifdef BN_COUNT
        fprintf(stderr, "  bn_add_part_words %d + %d (dl < 0, c = %d)\n", cl,
                dl, c);
#endif
        while (c) {
            l = (c + b[0]) & BN_MASK2;
            c = (l < c);
            r[0] = l;
            if (++dl >= 0)
                break;

            l = (c + b[1]) & BN_MASK2;
            c = (l < c);
            r[1] = l;
            if (++dl >= 0)
                break;

            l = (c + b[2]) & BN_MASK2;
            c = (l < c);
            r[2] = l;
            if (++dl >= 0)
                break;

            l = (c + b[3]) & BN_MASK2;
            c = (l < c);
            r[3] = l;
            if (++dl >= 0)
                break;

            save_dl = dl;
            b += 4;
            r += 4;
        }
        if (dl < 0) {
#ifdef BN_COUNT
            fprintf(stderr, "  bn_add_part_words %d + %d (dl < 0, c == 0)\n",
                    cl, dl);
#endif
            if (save_dl < dl) {
                switch (dl - save_dl) {
                case 1:
                    r[1] = b[1];
                    if (++dl >= 0)
                        break;
                case 2:
                    r[2] = b[2];
                    if (++dl >= 0)
                        break;
                case 3:
                    r[3] = b[3];
                    if (++dl >= 0)
                        break;
                }
                b += 4;
                r += 4;
            }
        }
        if (dl < 0) {
#ifdef BN_COUNT
            fprintf(stderr, "  bn_add_part_words %d + %d (dl < 0, copy)\n",
                    cl, dl);
#endif
            for (;;) {
                r[0] = b[0];
                if (++dl >= 0)
                    break;
                r[1] = b[1];
                if (++dl >= 0)
                    break;
                r[2] = b[2];
                if (++dl >= 0)
                    break;
                r[3] = b[3];
                if (++dl >= 0)
                    break;

                b += 4;
                r += 4;
            }
        }
    } else {
        int save_dl = dl;
#ifdef BN_COUNT
        fprintf(stderr, "  bn_add_part_words %d + %d (dl > 0)\n", cl, dl);
#endif
        while (c) {
            t = (a[0] + c) & BN_MASK2;
            c = (t < c);
            r[0] = t;
            if (--dl <= 0)
                break;

            t = (a[1] + c) & BN_MASK2;
            c = (t < c);
            r[1] = t;
            if (--dl <= 0)
                break;

            t = (a[2] + c) & BN_MASK2;
            c = (t < c);
            r[2] = t;
            if (--dl <= 0)
                break;

            t = (a[3] + c) & BN_MASK2;
            c = (t < c);
            r[3] = t;
            if (--dl <= 0)
                break;

            save_dl = dl;
            a += 4;
            r += 4;
        }
#ifdef BN_COUNT
        fprintf(stderr, "  bn_add_part_words %d + %d (dl > 0, c == 0)\n", cl,
                dl);
#endif
        if (dl > 0) {
            if (save_dl > dl) {
                switch (save_dl - dl) {
                case 1:
                    r[1] = a[1];
                    if (--dl <= 0)
                        break;
                case 2:
                    r[2] = a[2];
                    if (--dl <= 0)
                        break;
                case 3:
                    r[3] = a[3];
                    if (--dl <= 0)
                        break;
                }
                a += 4;
                r += 4;
            }
        }
        if (dl > 0) {
#ifdef BN_COUNT
            fprintf(stderr, "  bn_add_part_words %d + %d (dl > 0, copy)\n",
                    cl, dl);
#endif
            for (;;) {
                r[0] = a[0];
                if (--dl <= 0)
                    break;
                r[1] = a[1];
                if (--dl <= 0)
                    break;
                r[2] = a[2];
                if (--dl <= 0)
                    break;
                r[3] = a[3];
                if (--dl <= 0)
                    break;

                a += 4;
                r += 4;
            }
        }
    }
    return c;
}

#ifdef BN_RECURSION
/*
 * Karatsuba recursive multiplication algorithm (cf. Knuth, The Art of
 * Computer Programming, Vol. 2)
 */

/*-
 * r is 2*n2 words in size,
 * a and b are both n2 words in size.
 * n2 must be a power of 2.
 * We multiply and return the result.
 * t must be 2*n2 words in size
 * We calculate
 * a[0]*b[0]
 * a[0]*b[0]+a[1]*b[1]+(a[0]-a[1])*(b[1]-b[0])
 * a[1]*b[1]
 */
/* dnX may not be positive, but n2/2+dnX has to be */
void bn_mul_recursive(BN_ULONG *r, BN_ULONG *a, BN_ULONG *b, int n2,
                      int dna, int dnb, BN_ULONG *t)
{
    int n = n2 / 2, c1, c2;
    int tna = n + dna, tnb = n + dnb;
    unsigned int neg, zero;
    BN_ULONG ln, lo, *p;

# ifdef BN_COUNT
    fprintf(stderr, " bn_mul_recursive %d%+d * %d%+d\n", n2, dna, n2, dnb);
# endif
# ifdef BN_MUL_COMBA
#  if 0
    if (n2 == 4) {
        bn_mul_comba4(r, a, b);
        return;
    }
#  endif
    /*
     * Only call bn_mul_comba 8 if n2 == 8 and the two arrays are complete
     * [steve]
     */
    if (n2 == 8 && dna == 0 && dnb == 0) {
        bn_mul_comba8(r, a, b);
        return;
    }
# endif                         /* BN_MUL_COMBA */
    /* Else do normal multiply */
    if (n2 < BN_MUL_RECURSIVE_SIZE_NORMAL) {
        bn_mul_normal(r, a, n2 + dna, b, n2 + dnb);
        if ((dna + dnb) < 0)
            memset(&r[2 * n2 + dna + dnb], 0,
                   sizeof(BN_ULONG) * -(dna + dnb));
        return;
    }
    /* r=(a[0]-a[1])*(b[1]-b[0]) */
    c1 = bn_cmp_part_words(a, &(a[n]), tna, n - tna);
    c2 = bn_cmp_part_words(&(b[n]), b, tnb, tnb - n);
    zero = neg = 0;
    switch (c1 * 3 + c2) {
    case -4:
        bn_sub_part_words(t, &(a[n]), a, tna, tna - n); /* - */
        bn_sub_part_words(&(t[n]), b, &(b[n]), tnb, n - tnb); /* - */
        break;
    case -3:
        zero = 1;
        break;
    case -2:
        bn_sub_part_words(t, &(a[n]), a, tna, tna - n); /* - */
        bn_sub_part_words(&(t[n]), &(b[n]), b, tnb, tnb - n); /* + */
        neg = 1;
        break;
    case -1:
    case 0:
    case 1:
        zero = 1;
        break;
    case 2:
        bn_sub_part_words(t, a, &(a[n]), tna, n - tna); /* + */
        bn_sub_part_words(&(t[n]), b, &(b[n]), tnb, n - tnb); /* - */
        neg = 1;
        break;
    case 3:
        zero = 1;
        break;
    case 4:
        bn_sub_part_words(t, a, &(a[n]), tna, n - tna);
        bn_sub_part_words(&(t[n]), &(b[n]), b, tnb, tnb - n);
        break;
    }

# ifdef BN_MUL_COMBA
    if (n == 4 && dna == 0 && dnb == 0) { /* XXX: bn_mul_comba4 could take
                                           * extra args to do this well */
        if (!zero)
            bn_mul_comba4(&(t[n2]), t, &(t[n]));
        else
            memset(&(t[n2]), 0, 8 * sizeof(BN_ULONG));

        bn_mul_comba4(r, a, b);
        bn_mul_comba4(&(r[n2]), &(a[n]), &(b[n]));
    } else if (n == 8 && dna == 0 && dnb == 0) { /* XXX: bn_mul_comba8 could
                                                  * take extra args to do
                                                  * this well */
        if (!zero)
            bn_mul_comba8(&(t[n2]), t, &(t[n]));
        else
            memset(&(t[n2]), 0, 16 * sizeof(BN_ULONG));

        bn_mul_comba8(r, a, b);
        bn_mul_comba8(&(r[n2]), &(a[n]), &(b[n]));
    } else
# endif                         /* BN_MUL_COMBA */
    {
        p = &(t[n2 * 2]);
        if (!zero)
            bn_mul_recursive(&(t[n2]), t, &(t[n]), n, 0, 0, p);
        else
            memset(&(t[n2]), 0, n2 * sizeof(BN_ULONG));
        bn_mul_recursive(r, a, b, n, 0, 0, p);
        bn_mul_recursive(&(r[n2]), &(a[n]), &(b[n]), n, dna, dnb, p);
    }

    /*-
     * t[32] holds (a[0]-a[1])*(b[1]-b[0]), c1 is the sign
     * r[10] holds (a[0]*b[0])
     * r[32] holds (b[1]*b[1])
     */

    c1 = (int)(bn_add_words(t, r, &(r[n2]), n2));

    if (neg) {                  /* if t[32] is negative */
        c1 -= (int)(bn_sub_words(&(t[n2]), t, &(t[n2]), n2));
    } else {
        /* Might have a carry */
        c1 += (int)(bn_add_words(&(t[n2]), &(t[n2]), t, n2));
    }

    /*-
     * t[32] holds (a[0]-a[1])*(b[1]-b[0])+(a[0]*b[0])+(a[1]*b[1])
     * r[10] holds (a[0]*b[0])
     * r[32] holds (b[1]*b[1])
     * c1 holds the carry bits
     */
    c1 += (int)(bn_add_words(&(r[n]), &(r[n]), &(t[n2]), n2));
    if (c1) {
        p = &(r[n + n2]);
        lo = *p;
        ln = (lo + c1) & BN_MASK2;
        *p = ln;

        /*
         * The overflow will stop before we over write words we should not
         * overwrite
         */
        if (ln < (BN_ULONG)c1) {
            do {
                p++;
                lo = *p;
                ln = (lo + 1) & BN_MASK2;
                *p = ln;
            } while (ln == 0);
        }
    }
}

/*
 * n+tn is the word length t needs to be n*4 is size, as does r
 */
/* tnX may not be negative but less than n */
void bn_mul_part_recursive(BN_ULONG *r, BN_ULONG *a, BN_ULONG *b, int n,
                           int tna, int tnb, BN_ULONG *t)
{
    int i, j, n2 = n * 2;
    int c1, c2, neg;
    BN_ULONG ln, lo, *p;

# ifdef BN_COUNT
    fprintf(stderr, " bn_mul_part_recursive (%d%+d) * (%d%+d)\n",
            n, tna, n, tnb);
# endif
    if (n < 8) {
        bn_mul_normal(r, a, n + tna, b, n + tnb);
        return;
    }

    /* r=(a[0]-a[1])*(b[1]-b[0]) */
    c1 = bn_cmp_part_words(a, &(a[n]), tna, n - tna);
    c2 = bn_cmp_part_words(&(b[n]), b, tnb, tnb - n);
    neg = 0;
    switch (c1 * 3 + c2) {
    case -4:
        bn_sub_part_words(t, &(a[n]), a, tna, tna - n); /* - */
        bn_sub_part_words(&(t[n]), b, &(b[n]), tnb, n - tnb); /* - */
        break;
    case -3:
        /* break; */
    case -2:
        bn_sub_part_words(t, &(a[n]), a, tna, tna - n); /* - */
        bn_sub_part_words(&(t[n]), &(b[n]), b, tnb, tnb - n); /* + */
        neg = 1;
        break;
    case -1:
    case 0:
    case 1:
        /* break; */
    case 2:
        bn_sub_part_words(t, a, &(a[n]), tna, n - tna); /* + */
        bn_sub_part_words(&(t[n]), b, &(b[n]), tnb, n - tnb); /* - */
        neg = 1;
        break;
    case 3:
        /* break; */
    case 4:
        bn_sub_part_words(t, a, &(a[n]), tna, n - tna);
        bn_sub_part_words(&(t[n]), &(b[n]), b, tnb, tnb - n);
        break;
    }
    /*
     * The zero case isn't yet implemented here. The speedup would probably
     * be negligible.
     */
# if 0
    if (n == 4) {
        bn_mul_comba4(&(t[n2]), t, &(t[n]));
        bn_mul_comba4(r, a, b);
        bn_mul_normal(&(r[n2]), &(a[n]), tn, &(b[n]), tn);
        memset(&(r[n2 + tn * 2]), 0, sizeof(BN_ULONG) * (n2 - tn * 2));
    } else
# endif
    if (n == 8) {
        bn_mul_comba8(&(t[n2]), t, &(t[n]));
        bn_mul_comba8(r, a, b);
        bn_mul_normal(&(r[n2]), &(a[n]), tna, &(b[n]), tnb);
        memset(&(r[n2 + tna + tnb]), 0, sizeof(BN_ULONG) * (n2 - tna - tnb));
    } else {
        p = &(t[n2 * 2]);
        bn_mul_recursive(&(t[n2]), t, &(t[n]), n, 0, 0, p);
        bn_mul_recursive(r, a, b, n, 0, 0, p);
        i = n / 2;
        /*
         * If there is only a bottom half to the number, just do it
         */
        if (tna > tnb)
            j = tna - i;
        else
            j = tnb - i;
        if (j == 0) {
            bn_mul_recursive(&(r[n2]), &(a[n]), &(b[n]),
                             i, tna - i, tnb - i, p);
            memset(&(r[n2 + i * 2]), 0, sizeof(BN_ULONG) * (n2 - i * 2));
        } else if (j > 0) {     /* eg, n == 16, i == 8 and tn == 11 */
            bn_mul_part_recursive(&(r[n2]), &(a[n]), &(b[n]),
                                  i, tna - i, tnb - i, p);
            memset(&(r[n2 + tna + tnb]), 0,
                   sizeof(BN_ULONG) * (n2 - tna - tnb));
        } else {                /* (j < 0) eg, n == 16, i == 8 and tn == 5 */

            memset(&(r[n2]), 0, sizeof(BN_ULONG) * n2);
            if (tna < BN_MUL_RECURSIVE_SIZE_NORMAL
                && tnb < BN_MUL_RECURSIVE_SIZE_NORMAL) {
                bn_mul_normal(&(r[n2]), &(a[n]), tna, &(b[n]), tnb);
            } else {
                for (;;) {
                    i /= 2;
                    /*
                     * these simplified conditions work exclusively because
                     * difference between tna and tnb is 1 or 0
                     */
                    if (i < tna || i < tnb) {
                        bn_mul_part_recursive(&(r[n2]),
                                              &(a[n]), &(b[n]),
                                              i, tna - i, tnb - i, p);
                        break;
                    } else if (i == tna || i == tnb) {
                        bn_mul_recursive(&(r[n2]),
                                         &(a[n]), &(b[n]),
                                         i, tna - i, tnb - i, p);
                        break;
                    }
                }
            }
        }
    }

    /*-
     * t[32] holds (a[0]-a[1])*(b[1]-b[0]), c1 is the sign
     * r[10] holds (a[0]*b[0])
     * r[32] holds (b[1]*b[1])
     */

    c1 = (int)(bn_add_words(t, r, &(r[n2]), n2));

    if (neg) {                  /* if t[32] is negative */
        c1 -= (int)(bn_sub_words(&(t[n2]), t, &(t[n2]), n2));
    } else {
        /* Might have a carry */
        c1 += (int)(bn_add_words(&(t[n2]), &(t[n2]), t, n2));
    }

    /*-
     * t[32] holds (a[0]-a[1])*(b[1]-b[0])+(a[0]*b[0])+(a[1]*b[1])
     * r[10] holds (a[0]*b[0])
     * r[32] holds (b[1]*b[1])
     * c1 holds the carry bits
     */
    c1 += (int)(bn_add_words(&(r[n]), &(r[n]), &(t[n2]), n2));
    if (c1) {
        p = &(r[n + n2]);
        lo = *p;
        ln = (lo + c1) & BN_MASK2;
        *p = ln;

        /*
         * The overflow will stop before we over write words we should not
         * overwrite
         */
        if (ln < (BN_ULONG)c1) {
            do {
                p++;
                lo = *p;
                ln = (lo + 1) & BN_MASK2;
                *p = ln;
            } while (ln == 0);
        }
    }
}

/*-
 * a and b must be the same size, which is n2.
 * r needs to be n2 words and t needs to be n2*2
 */
void bn_mul_low_recursive(BN_ULONG *r, BN_ULONG *a, BN_ULONG *b, int n2,
                          BN_ULONG *t)
{
    int n = n2 / 2;

# ifdef BN_COUNT
    fprintf(stderr, " bn_mul_low_recursive %d * %d\n", n2, n2);
# endif

    bn_mul_recursive(r, a, b, n, 0, 0, &(t[0]));
    if (n >= BN_MUL_LOW_RECURSIVE_SIZE_NORMAL) {
        bn_mul_low_recursive(&(t[0]), &(a[0]), &(b[n]), n, &(t[n2]));
        bn_add_words(&(r[n]), &(r[n]), &(t[0]), n);
        bn_mul_low_recursive(&(t[0]), &(a[n]), &(b[0]), n, &(t[n2]));
        bn_add_words(&(r[n]), &(r[n]), &(t[0]), n);
    } else {
        bn_mul_low_normal(&(t[0]), &(a[0]), &(b[n]), n);
        bn_mul_low_normal(&(t[n]), &(a[n]), &(b[0]), n);
        bn_add_words(&(r[n]), &(r[n]), &(t[0]), n);
        bn_add_words(&(r[n]), &(r[n]), &(t[n]), n);
    }
}

/*-
 * a and b must be the same size, which is n2.
 * r needs to be n2 words and t needs to be n2*2
 * l is the low words of the output.
 * t needs to be n2*3
 */
void bn_mul_high(BN_ULONG *r, BN_ULONG *a, BN_ULONG *b, BN_ULONG *l, int n2,
                 BN_ULONG *t)
{
    int i, n;
    int c1, c2;
    int neg, oneg, zero;
    BN_ULONG ll, lc, *lp, *mp;

# ifdef BN_COUNT
    fprintf(stderr, " bn_mul_high %d * %d\n", n2, n2);
# endif
    n = n2 / 2;

    /* Calculate (al-ah)*(bh-bl) */
    neg = zero = 0;
    c1 = bn_cmp_words(&(a[0]), &(a[n]), n);
    c2 = bn_cmp_words(&(b[n]), &(b[0]), n);
    switch (c1 * 3 + c2) {
    case -4:
        bn_sub_words(&(r[0]), &(a[n]), &(a[0]), n);
        bn_sub_words(&(r[n]), &(b[0]), &(b[n]), n);
        break;
    case -3:
        zero = 1;
        break;
    case -2:
        bn_sub_words(&(r[0]), &(a[n]), &(a[0]), n);
        bn_sub_words(&(r[n]), &(b[n]), &(b[0]), n);
        neg = 1;
        break;
    case -1:
    case 0:
    case 1:
        zero = 1;
        break;
    case 2:
        bn_sub_words(&(r[0]), &(a[0]), &(a[n]), n);
        bn_sub_words(&(r[n]), &(b[0]), &(b[n]), n);
        neg = 1;
        break;
    case 3:
        zero = 1;
        break;
    case 4:
        bn_sub_words(&(r[0]), &(a[0]), &(a[n]), n);
        bn_sub_words(&(r[n]), &(b[n]), &(b[0]), n);
        break;
    }

    oneg = neg;
    /* t[10] = (a[0]-a[1])*(b[1]-b[0]) */
    /* r[10] = (a[1]*b[1]) */
# ifdef BN_MUL_COMBA
    if (n == 8) {
        bn_mul_comba8(&(t[0]), &(r[0]), &(r[n]));
        bn_mul_comba8(r, &(a[n]), &(b[n]));
    } else
# endif
    {
        bn_mul_recursive(&(t[0]), &(r[0]), &(r[n]), n, 0, 0, &(t[n2]));
        bn_mul_recursive(r, &(a[n]), &(b[n]), n, 0, 0, &(t[n2]));
    }

    /*-
     * s0 == low(al*bl)
     * s1 == low(ah*bh)+low((al-ah)*(bh-bl))+low(al*bl)+high(al*bl)
     * We know s0 and s1 so the only unknown is high(al*bl)
     * high(al*bl) == s1 - low(ah*bh+s0+(al-ah)*(bh-bl))
     * high(al*bl) == s1 - (r[0]+l[0]+t[0])
     */
    if (l != NULL) {
        lp = &(t[n2 + n]);
        c1 = (int)(bn_add_words(lp, &(r[0]), &(l[0]), n));
    } else {
        c1 = 0;
        lp = &(r[0]);
    }

    if (neg)
        neg = (int)(bn_sub_words(&(t[n2]), lp, &(t[0]), n));
    else {
        bn_add_words(&(t[n2]), lp, &(t[0]), n);
        neg = 0;
    }

    if (l != NULL) {
        bn_sub_words(&(t[n2 + n]), &(l[n]), &(t[n2]), n);
    } else {
        lp = &(t[n2 + n]);
        mp = &(t[n2]);
        for (i = 0; i < n; i++)
            lp[i] = ((~mp[i]) + 1) & BN_MASK2;
    }

    /*-
     * s[0] = low(al*bl)
     * t[3] = high(al*bl)
     * t[10] = (a[0]-a[1])*(b[1]-b[0]) neg is the sign
     * r[10] = (a[1]*b[1])
     */
    /*-
     * R[10] = al*bl
     * R[21] = al*bl + ah*bh + (a[0]-a[1])*(b[1]-b[0])
     * R[32] = ah*bh
     */
    /*-
     * R[1]=t[3]+l[0]+r[0](+-)t[0] (have carry/borrow)
     * R[2]=r[0]+t[3]+r[1](+-)t[1] (have carry/borrow)
     * R[3]=r[1]+(carry/borrow)
     */
    if (l != NULL) {
        lp = &(t[n2]);
        c1 = (int)(bn_add_words(lp, &(t[n2 + n]), &(l[0]), n));
    } else {
        lp = &(t[n2 + n]);
        c1 = 0;
    }
    c1 += (int)(bn_add_words(&(t[n2]), lp, &(r[0]), n));
    if (oneg)
        c1 -= (int)(bn_sub_words(&(t[n2]), &(t[n2]), &(t[0]), n));
    else
        c1 += (int)(bn_add_words(&(t[n2]), &(t[n2]), &(t[0]), n));

    c2 = (int)(bn_add_words(&(r[0]), &(r[0]), &(t[n2 + n]), n));
    c2 += (int)(bn_add_words(&(r[0]), &(r[0]), &(r[n]), n));
    if (oneg)
        c2 -= (int)(bn_sub_words(&(r[0]), &(r[0]), &(t[n]), n));
    else
        c2 += (int)(bn_add_words(&(r[0]), &(r[0]), &(t[n]), n));

    if (c1 != 0) {              /* Add starting at r[0], could be +ve or -ve */
        i = 0;
        if (c1 > 0) {
            lc = c1;
            do {
                ll = (r[i] + lc) & BN_MASK2;
                r[i++] = ll;
                lc = (lc > ll);
            } while (lc);
        } else {
            lc = -c1;
            do {
                ll = r[i];
                r[i++] = (ll - lc) & BN_MASK2;
                lc = (lc > ll);
            } while (lc);
        }
    }
    if (c2 != 0) {              /* Add starting at r[1] */
        i = n;
        if (c2 > 0) {
            lc = c2;
            do {
                ll = (r[i] + lc) & BN_MASK2;
                r[i++] = ll;
                lc = (lc > ll);
            } while (lc);
        } else {
            lc = -c2;
            do {
                ll = r[i];
                r[i++] = (ll - lc) & BN_MASK2;
                lc = (lc > ll);
            } while (lc);
        }
    }
}
#endif                          /* BN_RECURSION */

int BN_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx)
{
    int ret = bn_mul_fixed_top(r, a, b, ctx);

    bn_correct_top(r);
    bn_check_top(r);

    return ret;
}

int bn_mul_fixed_top(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx)
{
    int ret = 0;
    int top, al, bl;
    BIGNUM *rr;
#if defined(BN_MUL_COMBA) || defined(BN_RECURSION)
    int i;
#endif
#ifdef BN_RECURSION
    BIGNUM *t = NULL;
    int j = 0, k;
#endif

#ifdef BN_COUNT
    fprintf(stderr, "BN_mul %d * %d\n", a->top, b->top);
#endif

    bn_check_top(a);
    bn_check_top(b);
    bn_check_top(r);

    al = a->top;
    bl = b->top;

    if ((al == 0) || (bl == 0)) {
        BN_zero(r);
        return (1);
    }
    top = al + bl;

    BN_CTX_start(ctx);
    if ((r == a) || (r == b)) {
        if ((rr = BN_CTX_get(ctx)) == NULL)
            goto err;
    } else
        rr = r;
    rr->neg = a->neg ^ b->neg;

#if defined(BN_MUL_COMBA) || defined(BN_RECURSION)
    i = al - bl;
#endif
#ifdef BN_MUL_COMBA
    if (i == 0) {
# if 0
        if (al == 4) {
            if (bn_wexpand(rr, 8) == NULL)
                goto err;
            rr->top = 8;
            bn_mul_comba4(rr->d, a->d, b->d);
            goto end;
        }
# endif
        if (al == 8) {
            if (bn_wexpand(rr, 16) == NULL)
                goto err;
            rr->top = 16;
            bn_mul_comba8(rr->d, a->d, b->d);
            goto end;
        }
    }
#endif                          /* BN_MUL_COMBA */
#ifdef BN_RECURSION
    if ((al >= BN_MULL_SIZE_NORMAL) && (bl >= BN_MULL_SIZE_NORMAL)) {
        if (i >= -1 && i <= 1) {
            /*
             * Find out the power of two lower or equal to the longest of the
             * two numbers
             */
            if (i >= 0) {
                j = BN_num_bits_word((BN_ULONG)al);
            }
            if (i == -1) {
                j = BN_num_bits_word((BN_ULONG)bl);
            }
            j = 1 << (j - 1);
            assert(j <= al || j <= bl);
            k = j + j;
            t = BN_CTX_get(ctx);
            if (t == NULL)
                goto err;
            if (al > j || bl > j) {
                if (bn_wexpand(t, k * 4) == NULL)
                    goto err;
                if (bn_wexpand(rr, k * 4) == NULL)
                    goto err;
                bn_mul_part_recursive(rr->d, a->d, b->d,
                                      j, al - j, bl - j, t->d);
            } else {            /* al <= j || bl <= j */

                if (bn_wexpand(t, k * 2) == NULL)
                    goto err;
                if (bn_wexpand(rr, k * 2) == NULL)
                    goto err;
                bn_mul_recursive(rr->d, a->d, b->d, j, al - j, bl - j, t->d);
            }
            rr->top = top;
            goto end;
        }
    }
#endif                          /* BN_RECURSION */
    if (bn_wexpand(rr, top) == NULL)
        goto err;
    rr->top = top;
    bn_mul_normal(rr->d, a->d, al, b->d, bl);

#if defined(BN_MUL_COMBA) || defined(BN_RECURSION)
 end:
#endif
    rr->flags |= BN_FLG_FIXED_TOP;
    if (r != rr && BN_copy(r, rr) == NULL)
        goto err;

    ret = 1;
 err:
    bn_check_top(r);
    BN_CTX_end(ctx);
    return (ret);
}

void bn_mul_normal(BN_ULONG *r, BN_ULONG *a, int na, BN_ULONG *b, int nb)
{
    BN_ULONG *rr;

#ifdef BN_COUNT
    fprintf(stderr, " bn_mul_normal %d * %d\n", na, nb);
#endif

    if (na < nb) {
        int itmp;
        BN_ULONG *ltmp;

        itmp = na;
        na = nb;
        nb = itmp;
        ltmp = a;
        a = b;
        b = ltmp;

    }
    rr = &(r[na]);
    if (nb <= 0) {
        (void)bn_mul_words(r, a, na, 0);
        return;
    } else
        rr[0] = bn_mul_words(r, a, na, b[0]);

    for (;;) {
        if (--nb <= 0)
            return;
        rr[1] = bn_mul_add_words(&(r[1]), a, na, b[1]);
        if (--nb <= 0)
            return;
        rr[2] = bn_mul_add_words(&(r[2]), a, na, b[2]);
        if (--nb <= 0)
            return;
        rr[3] = bn_mul_add_words(&(r[3]), a, na, b[3]);
        if (--nb <= 0)
            return;
        rr[4] = bn_mul_add_words(&(r[4]), a, na, b[4]);
        rr += 4;
        r += 4;
        b += 4;
    }
}

void bn_mul_low_normal(BN_ULONG *r, BN_ULONG *a, BN_ULONG *b, int n)
{
#ifdef BN_COUNT
    fprintf(stderr, " bn_mul_low_normal %d * %d\n", n, n);
#endif
    bn_mul_words(r, a, n, b[0]);

    for (;;) {
        if (--n <= 0)
            return;
        bn_mul_add_words(&(r[1]), a, n, b[1]);
        if (--n <= 0)
            return;
        bn_mul_add_words(&(r[2]), a, n, b[2]);
        if (--n <= 0)
            return;
        bn_mul_add_words(&(r[3]), a, n, b[3]);
        if (--n <= 0)
            return;
        bn_mul_add_words(&(r[4]), a, n, b[4]);
        r += 4;
        b += 4;
    }
}
/* crypto/bn/bn_nist.c */
/*
 * Written by Nils Larsch for the OpenSSL project
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

// #include "bn_lcl.h"
// #include "cryptlib.h"

#define BN_NIST_192_TOP (192+BN_BITS2-1)/BN_BITS2
#define BN_NIST_224_TOP (224+BN_BITS2-1)/BN_BITS2
#define BN_NIST_256_TOP (256+BN_BITS2-1)/BN_BITS2
#define BN_NIST_384_TOP (384+BN_BITS2-1)/BN_BITS2
#define BN_NIST_521_TOP (521+BN_BITS2-1)/BN_BITS2

/* pre-computed tables are "carry-less" values of modulus*(i+1) */
#if BN_BITS2 == 64
static const BN_ULONG _nist_p_192[][BN_NIST_192_TOP] = {
    {0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFEULL, 0xFFFFFFFFFFFFFFFFULL},
    {0xFFFFFFFFFFFFFFFEULL, 0xFFFFFFFFFFFFFFFDULL, 0xFFFFFFFFFFFFFFFFULL},
    {0xFFFFFFFFFFFFFFFDULL, 0xFFFFFFFFFFFFFFFCULL, 0xFFFFFFFFFFFFFFFFULL}
};

static const BN_ULONG _nist_p_192_sqr[] = {
    0x0000000000000001ULL, 0x0000000000000002ULL, 0x0000000000000001ULL,
    0xFFFFFFFFFFFFFFFEULL, 0xFFFFFFFFFFFFFFFDULL, 0xFFFFFFFFFFFFFFFFULL
};

static const BN_ULONG _nist_p_224[][BN_NIST_224_TOP] = {
    {0x0000000000000001ULL, 0xFFFFFFFF00000000ULL,
     0xFFFFFFFFFFFFFFFFULL, 0x00000000FFFFFFFFULL},
    {0x0000000000000002ULL, 0xFFFFFFFE00000000ULL,
     0xFFFFFFFFFFFFFFFFULL, 0x00000001FFFFFFFFULL} /* this one is
                                                    * "carry-full" */
};

static const BN_ULONG _nist_p_224_sqr[] = {
    0x0000000000000001ULL, 0xFFFFFFFE00000000ULL,
    0xFFFFFFFFFFFFFFFFULL, 0x0000000200000000ULL,
    0x0000000000000000ULL, 0xFFFFFFFFFFFFFFFEULL,
    0xFFFFFFFFFFFFFFFFULL
};

static const BN_ULONG _nist_p_256[][BN_NIST_256_TOP] = {
    {0xFFFFFFFFFFFFFFFFULL, 0x00000000FFFFFFFFULL,
     0x0000000000000000ULL, 0xFFFFFFFF00000001ULL},
    {0xFFFFFFFFFFFFFFFEULL, 0x00000001FFFFFFFFULL,
     0x0000000000000000ULL, 0xFFFFFFFE00000002ULL},
    {0xFFFFFFFFFFFFFFFDULL, 0x00000002FFFFFFFFULL,
     0x0000000000000000ULL, 0xFFFFFFFD00000003ULL},
    {0xFFFFFFFFFFFFFFFCULL, 0x00000003FFFFFFFFULL,
     0x0000000000000000ULL, 0xFFFFFFFC00000004ULL},
    {0xFFFFFFFFFFFFFFFBULL, 0x00000004FFFFFFFFULL,
     0x0000000000000000ULL, 0xFFFFFFFB00000005ULL},
};

static const BN_ULONG _nist_p_256_sqr[] = {
    0x0000000000000001ULL, 0xFFFFFFFE00000000ULL,
    0xFFFFFFFFFFFFFFFFULL, 0x00000001FFFFFFFEULL,
    0x00000001FFFFFFFEULL, 0x00000001FFFFFFFEULL,
    0xFFFFFFFE00000001ULL, 0xFFFFFFFE00000002ULL
};

static const BN_ULONG _nist_p_384[][BN_NIST_384_TOP] = {
    {0x00000000FFFFFFFFULL, 0xFFFFFFFF00000000ULL, 0xFFFFFFFFFFFFFFFEULL,
     0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL},
    {0x00000001FFFFFFFEULL, 0xFFFFFFFE00000000ULL, 0xFFFFFFFFFFFFFFFDULL,
     0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL},
    {0x00000002FFFFFFFDULL, 0xFFFFFFFD00000000ULL, 0xFFFFFFFFFFFFFFFCULL,
     0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL},
    {0x00000003FFFFFFFCULL, 0xFFFFFFFC00000000ULL, 0xFFFFFFFFFFFFFFFBULL,
     0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL},
    {0x00000004FFFFFFFBULL, 0xFFFFFFFB00000000ULL, 0xFFFFFFFFFFFFFFFAULL,
     0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL},
};

static const BN_ULONG _nist_p_384_sqr[] = {
    0xFFFFFFFE00000001ULL, 0x0000000200000000ULL, 0xFFFFFFFE00000000ULL,
    0x0000000200000000ULL, 0x0000000000000001ULL, 0x0000000000000000ULL,
    0x00000001FFFFFFFEULL, 0xFFFFFFFE00000000ULL, 0xFFFFFFFFFFFFFFFDULL,
    0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL
};

static const BN_ULONG _nist_p_521[] =
    { 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL,
    0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL,
    0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL,
    0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL,
    0x00000000000001FFULL
};

static const BN_ULONG _nist_p_521_sqr[] = {
    0x0000000000000001ULL, 0x0000000000000000ULL, 0x0000000000000000ULL,
    0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL,
    0x0000000000000000ULL, 0x0000000000000000ULL, 0xFFFFFFFFFFFFFC00ULL,
    0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL,
    0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL,
    0xFFFFFFFFFFFFFFFFULL, 0x000000000003FFFFULL
};
#elif BN_BITS2 == 32
static const BN_ULONG _nist_p_192[][BN_NIST_192_TOP] = {
    {0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF},
    {0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFD, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF},
    {0xFFFFFFFD, 0xFFFFFFFF, 0xFFFFFFFC, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF}
};

static const BN_ULONG _nist_p_192_sqr[] = {
    0x00000001, 0x00000000, 0x00000002, 0x00000000, 0x00000001, 0x00000000,
    0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFD, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF
};

static const BN_ULONG _nist_p_224[][BN_NIST_224_TOP] = {
    {0x00000001, 0x00000000, 0x00000000, 0xFFFFFFFF,
     0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF},
    {0x00000002, 0x00000000, 0x00000000, 0xFFFFFFFE,
     0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF}
};

static const BN_ULONG _nist_p_224_sqr[] = {
    0x00000001, 0x00000000, 0x00000000, 0xFFFFFFFE,
    0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0x00000002,
    0x00000000, 0x00000000, 0xFFFFFFFE, 0xFFFFFFFF,
    0xFFFFFFFF, 0xFFFFFFFF
};

static const BN_ULONG _nist_p_256[][BN_NIST_256_TOP] = {
    {0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000,
     0x00000000, 0x00000000, 0x00000001, 0xFFFFFFFF},
    {0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000001,
     0x00000000, 0x00000000, 0x00000002, 0xFFFFFFFE},
    {0xFFFFFFFD, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000002,
     0x00000000, 0x00000000, 0x00000003, 0xFFFFFFFD},
    {0xFFFFFFFC, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000003,
     0x00000000, 0x00000000, 0x00000004, 0xFFFFFFFC},
    {0xFFFFFFFB, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000004,
     0x00000000, 0x00000000, 0x00000005, 0xFFFFFFFB},
};

static const BN_ULONG _nist_p_256_sqr[] = {
    0x00000001, 0x00000000, 0x00000000, 0xFFFFFFFE,
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFE, 0x00000001,
    0xFFFFFFFE, 0x00000001, 0xFFFFFFFE, 0x00000001,
    0x00000001, 0xFFFFFFFE, 0x00000002, 0xFFFFFFFE
};

static const BN_ULONG _nist_p_384[][BN_NIST_384_TOP] = {
    {0xFFFFFFFF, 0x00000000, 0x00000000, 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFF,
     0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF},
    {0xFFFFFFFE, 0x00000001, 0x00000000, 0xFFFFFFFE, 0xFFFFFFFD, 0xFFFFFFFF,
     0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF},
    {0xFFFFFFFD, 0x00000002, 0x00000000, 0xFFFFFFFD, 0xFFFFFFFC, 0xFFFFFFFF,
     0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF},
    {0xFFFFFFFC, 0x00000003, 0x00000000, 0xFFFFFFFC, 0xFFFFFFFB, 0xFFFFFFFF,
     0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF},
    {0xFFFFFFFB, 0x00000004, 0x00000000, 0xFFFFFFFB, 0xFFFFFFFA, 0xFFFFFFFF,
     0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF},
};

static const BN_ULONG _nist_p_384_sqr[] = {
    0x00000001, 0xFFFFFFFE, 0x00000000, 0x00000002, 0x00000000, 0xFFFFFFFE,
    0x00000000, 0x00000002, 0x00000001, 0x00000000, 0x00000000, 0x00000000,
    0xFFFFFFFE, 0x00000001, 0x00000000, 0xFFFFFFFE, 0xFFFFFFFD, 0xFFFFFFFF,
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF
};

static const BN_ULONG _nist_p_521[] = { 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
    0xFFFFFFFF, 0x000001FF
};

static const BN_ULONG _nist_p_521_sqr[] = {
    0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0xFFFFFC00, 0xFFFFFFFF,
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
    0xFFFFFFFF, 0xFFFFFFFF, 0x0003FFFF
};
#else
# error "unsupported BN_BITS2"
#endif

static const BIGNUM _bignum_nist_p_192 = {
    (BN_ULONG *)_nist_p_192[0],
    BN_NIST_192_TOP,
    BN_NIST_192_TOP,
    0,
    BN_FLG_STATIC_DATA
};

static const BIGNUM _bignum_nist_p_224 = {
    (BN_ULONG *)_nist_p_224[0],
    BN_NIST_224_TOP,
    BN_NIST_224_TOP,
    0,
    BN_FLG_STATIC_DATA
};

static const BIGNUM _bignum_nist_p_256 = {
    (BN_ULONG *)_nist_p_256[0],
    BN_NIST_256_TOP,
    BN_NIST_256_TOP,
    0,
    BN_FLG_STATIC_DATA
};

static const BIGNUM _bignum_nist_p_384 = {
    (BN_ULONG *)_nist_p_384[0],
    BN_NIST_384_TOP,
    BN_NIST_384_TOP,
    0,
    BN_FLG_STATIC_DATA
};

static const BIGNUM _bignum_nist_p_521 = {
    (BN_ULONG *)_nist_p_521,
    BN_NIST_521_TOP,
    BN_NIST_521_TOP,
    0,
    BN_FLG_STATIC_DATA
};

const BIGNUM *BN_get0_nist_prime_192(void)
{
    return &_bignum_nist_p_192;
}

const BIGNUM *BN_get0_nist_prime_224(void)
{
    return &_bignum_nist_p_224;
}

const BIGNUM *BN_get0_nist_prime_256(void)
{
    return &_bignum_nist_p_256;
}

const BIGNUM *BN_get0_nist_prime_384(void)
{
    return &_bignum_nist_p_384;
}

const BIGNUM *BN_get0_nist_prime_521(void)
{
    return &_bignum_nist_p_521;
}

static void nist_cp_bn_0(BN_ULONG *dst, const BN_ULONG *src, int top, int max)
{
    int i;

#ifdef BN_DEBUG
    OPENSSL_assert(top <= max);
#endif
    for (i = 0; i < top; i++)
        dst[i] = src[i];
    for (; i < max; i++)
        dst[i] = 0;
}

static void nist_cp_bn(BN_ULONG *dst, const BN_ULONG *src, int top)
{
    int i;

    for (i = 0; i < top; i++)
        dst[i] = src[i];
}

#if BN_BITS2 == 64
# define bn_cp_64(to, n, from, m)        (to)[n] = (m>=0)?((from)[m]):0;
# define bn_64_set_0(to, n)              (to)[n] = (BN_ULONG)0;
/*
 * two following macros are implemented under assumption that they
 * are called in a sequence with *ascending* n, i.e. as they are...
 */
# define bn_cp_32_naked(to, n, from, m)  (((n)&1)?(to[(n)/2]|=((m)&1)?(from[(m)/2]&BN_MASK2h):(from[(m)/2]<<32))\
                                                :(to[(n)/2] =((m)&1)?(from[(m)/2]>>32):(from[(m)/2]&BN_MASK2l)))
# define bn_32_set_0(to, n)              (((n)&1)?(to[(n)/2]&=BN_MASK2l):(to[(n)/2]=0));
# define bn_cp_32(to,n,from,m)           ((m)>=0)?bn_cp_32_naked(to,n,from,m):bn_32_set_0(to,n)
# if defined(L_ENDIAN)
#  if defined(__arch64__)
#   define NIST_INT64 long
#  else
#   define NIST_INT64 long long
#  endif
# endif
#else
# define bn_cp_64(to, n, from, m) \
        { \
        bn_cp_32(to, (n)*2, from, (m)*2); \
        bn_cp_32(to, (n)*2+1, from, (m)*2+1); \
        }
# define bn_64_set_0(to, n) \
        { \
        bn_32_set_0(to, (n)*2); \
        bn_32_set_0(to, (n)*2+1); \
        }
# define bn_cp_32(to, n, from, m)        (to)[n] = (m>=0)?((from)[m]):0;
# define bn_32_set_0(to, n)              (to)[n] = (BN_ULONG)0;
# if defined(_WIN32) && !defined(__GNUC__)
#  define NIST_INT64 __int64
# elif defined(BN_LLONG)
#  define NIST_INT64 long long
# endif
#endif                          /* BN_BITS2 != 64 */

#define nist_set_192(to, from, a1, a2, a3) \
        { \
        bn_cp_64(to, 0, from, (a3) - 3) \
        bn_cp_64(to, 1, from, (a2) - 3) \
        bn_cp_64(to, 2, from, (a1) - 3) \
        }

int BN_nist_mod_192(BIGNUM *r, const BIGNUM *a, const BIGNUM *field,
                    BN_CTX *ctx)
{
    int top = a->top, i;
    int carry;
    register BN_ULONG *r_d, *a_d = a->d;
    union {
        BN_ULONG bn[BN_NIST_192_TOP];
        unsigned int ui[BN_NIST_192_TOP * sizeof(BN_ULONG) /
                        sizeof(unsigned int)];
    } buf;
    BN_ULONG c_d[BN_NIST_192_TOP], *res;
    PTR_SIZE_INT mask;
    static const BIGNUM _bignum_nist_p_192_sqr = {
        (BN_ULONG *)_nist_p_192_sqr,
        sizeof(_nist_p_192_sqr) / sizeof(_nist_p_192_sqr[0]),
        sizeof(_nist_p_192_sqr) / sizeof(_nist_p_192_sqr[0]),
        0, BN_FLG_STATIC_DATA
    };

    field = &_bignum_nist_p_192; /* just to make sure */

    if (BN_is_negative(a) || BN_ucmp(a, &_bignum_nist_p_192_sqr) >= 0)
        return BN_nnmod(r, a, field, ctx);

    i = BN_ucmp(field, a);
    if (i == 0) {
        BN_zero(r);
        return 1;
    } else if (i > 0)
        return (r == a) ? 1 : (BN_copy(r, a) != NULL);

    if (r != a) {
        if (!bn_wexpand(r, BN_NIST_192_TOP))
            return 0;
        r_d = r->d;
        nist_cp_bn(r_d, a_d, BN_NIST_192_TOP);
    } else
        r_d = a_d;

    nist_cp_bn_0(buf.bn, a_d + BN_NIST_192_TOP, top - BN_NIST_192_TOP,
                 BN_NIST_192_TOP);

#if defined(NIST_INT64)
    {
        NIST_INT64 acc;         /* accumulator */
        unsigned int *rp = (unsigned int *)r_d;
        const unsigned int *bp = (const unsigned int *)buf.ui;

        acc = rp[0];
        acc += bp[3 * 2 - 6];
        acc += bp[5 * 2 - 6];
        rp[0] = (unsigned int)acc;
        acc >>= 32;

        acc += rp[1];
        acc += bp[3 * 2 - 5];
        acc += bp[5 * 2 - 5];
        rp[1] = (unsigned int)acc;
        acc >>= 32;

        acc += rp[2];
        acc += bp[3 * 2 - 6];
        acc += bp[4 * 2 - 6];
        acc += bp[5 * 2 - 6];
        rp[2] = (unsigned int)acc;
        acc >>= 32;

        acc += rp[3];
        acc += bp[3 * 2 - 5];
        acc += bp[4 * 2 - 5];
        acc += bp[5 * 2 - 5];
        rp[3] = (unsigned int)acc;
        acc >>= 32;

        acc += rp[4];
        acc += bp[4 * 2 - 6];
        acc += bp[5 * 2 - 6];
        rp[4] = (unsigned int)acc;
        acc >>= 32;

        acc += rp[5];
        acc += bp[4 * 2 - 5];
        acc += bp[5 * 2 - 5];
        rp[5] = (unsigned int)acc;

        carry = (int)(acc >> 32);
    }
#else
    {
        BN_ULONG t_d[BN_NIST_192_TOP];

        nist_set_192(t_d, buf.bn, 0, 3, 3);
        carry = (int)bn_add_words(r_d, r_d, t_d, BN_NIST_192_TOP);
        nist_set_192(t_d, buf.bn, 4, 4, 0);
        carry += (int)bn_add_words(r_d, r_d, t_d, BN_NIST_192_TOP);
        nist_set_192(t_d, buf.bn, 5, 5, 5)
            carry += (int)bn_add_words(r_d, r_d, t_d, BN_NIST_192_TOP);
    }
#endif
    if (carry > 0)
        carry =
            (int)bn_sub_words(r_d, r_d, _nist_p_192[carry - 1],
                              BN_NIST_192_TOP);
    else
        carry = 1;

    /*
     * we need 'if (carry==0 || result>=modulus) result-=modulus;'
     * as comparison implies subtraction, we can write
     * 'tmp=result-modulus; if (!carry || !borrow) result=tmp;'
     * this is what happens below, but without explicit if:-) a.
     */
    mask =
        0 - (PTR_SIZE_INT) bn_sub_words(c_d, r_d, _nist_p_192[0],
                                        BN_NIST_192_TOP);
    mask &= 0 - (PTR_SIZE_INT) carry;
    res = c_d;
    res = (BN_ULONG *)
        (((PTR_SIZE_INT) res & ~mask) | ((PTR_SIZE_INT) r_d & mask));
    nist_cp_bn(r_d, res, BN_NIST_192_TOP);
    r->top = BN_NIST_192_TOP;
    bn_correct_top(r);

    return 1;
}

typedef BN_ULONG (*bn_addsub_f) (BN_ULONG *, const BN_ULONG *,
                                 const BN_ULONG *, int);

#define nist_set_224(to, from, a1, a2, a3, a4, a5, a6, a7) \
        { \
        bn_cp_32(to, 0, from, (a7) - 7) \
        bn_cp_32(to, 1, from, (a6) - 7) \
        bn_cp_32(to, 2, from, (a5) - 7) \
        bn_cp_32(to, 3, from, (a4) - 7) \
        bn_cp_32(to, 4, from, (a3) - 7) \
        bn_cp_32(to, 5, from, (a2) - 7) \
        bn_cp_32(to, 6, from, (a1) - 7) \
        }

int BN_nist_mod_224(BIGNUM *r, const BIGNUM *a, const BIGNUM *field,
                    BN_CTX *ctx)
{
    int top = a->top, i;
    int carry;
    BN_ULONG *r_d, *a_d = a->d;
    union {
        BN_ULONG bn[BN_NIST_224_TOP];
        unsigned int ui[BN_NIST_224_TOP * sizeof(BN_ULONG) /
                        sizeof(unsigned int)];
    } buf;
    BN_ULONG c_d[BN_NIST_224_TOP], *res;
    PTR_SIZE_INT mask;
    union {
        bn_addsub_f f;
        PTR_SIZE_INT p;
    } u;
    static const BIGNUM _bignum_nist_p_224_sqr = {
        (BN_ULONG *)_nist_p_224_sqr,
        sizeof(_nist_p_224_sqr) / sizeof(_nist_p_224_sqr[0]),
        sizeof(_nist_p_224_sqr) / sizeof(_nist_p_224_sqr[0]),
        0, BN_FLG_STATIC_DATA
    };

    field = &_bignum_nist_p_224; /* just to make sure */

    if (BN_is_negative(a) || BN_ucmp(a, &_bignum_nist_p_224_sqr) >= 0)
        return BN_nnmod(r, a, field, ctx);

    i = BN_ucmp(field, a);
    if (i == 0) {
        BN_zero(r);
        return 1;
    } else if (i > 0)
        return (r == a) ? 1 : (BN_copy(r, a) != NULL);

    if (r != a) {
        if (!bn_wexpand(r, BN_NIST_224_TOP))
            return 0;
        r_d = r->d;
        nist_cp_bn(r_d, a_d, BN_NIST_224_TOP);
    } else
        r_d = a_d;

#if BN_BITS2==64
    /* copy upper 256 bits of 448 bit number ... */
    nist_cp_bn_0(c_d, a_d + (BN_NIST_224_TOP - 1),
                 top - (BN_NIST_224_TOP - 1), BN_NIST_224_TOP);
    /* ... and right shift by 32 to obtain upper 224 bits */
    nist_set_224(buf.bn, c_d, 14, 13, 12, 11, 10, 9, 8);
    /* truncate lower part to 224 bits too */
    r_d[BN_NIST_224_TOP - 1] &= BN_MASK2l;
#else
    nist_cp_bn_0(buf.bn, a_d + BN_NIST_224_TOP, top - BN_NIST_224_TOP,
                 BN_NIST_224_TOP);
#endif

#if defined(NIST_INT64) && BN_BITS2!=64
    {
        NIST_INT64 acc;         /* accumulator */
        unsigned int *rp = (unsigned int *)r_d;
        const unsigned int *bp = (const unsigned int *)buf.ui;

        acc = rp[0];
        acc -= bp[7 - 7];
        acc -= bp[11 - 7];
        rp[0] = (unsigned int)acc;
        acc >>= 32;

        acc += rp[1];
        acc -= bp[8 - 7];
        acc -= bp[12 - 7];
        rp[1] = (unsigned int)acc;
        acc >>= 32;

        acc += rp[2];
        acc -= bp[9 - 7];
        acc -= bp[13 - 7];
        rp[2] = (unsigned int)acc;
        acc >>= 32;

        acc += rp[3];
        acc += bp[7 - 7];
        acc += bp[11 - 7];
        acc -= bp[10 - 7];
        rp[3] = (unsigned int)acc;
        acc >>= 32;

        acc += rp[4];
        acc += bp[8 - 7];
        acc += bp[12 - 7];
        acc -= bp[11 - 7];
        rp[4] = (unsigned int)acc;
        acc >>= 32;

        acc += rp[5];
        acc += bp[9 - 7];
        acc += bp[13 - 7];
        acc -= bp[12 - 7];
        rp[5] = (unsigned int)acc;
        acc >>= 32;

        acc += rp[6];
        acc += bp[10 - 7];
        acc -= bp[13 - 7];
        rp[6] = (unsigned int)acc;

        carry = (int)(acc >> 32);
# if BN_BITS2==64
        rp[7] = carry;
# endif
    }
#else
    {
        BN_ULONG t_d[BN_NIST_224_TOP];

        nist_set_224(t_d, buf.bn, 10, 9, 8, 7, 0, 0, 0);
        carry = (int)bn_add_words(r_d, r_d, t_d, BN_NIST_224_TOP);
        nist_set_224(t_d, buf.bn, 0, 13, 12, 11, 0, 0, 0);
        carry += (int)bn_add_words(r_d, r_d, t_d, BN_NIST_224_TOP);
        nist_set_224(t_d, buf.bn, 13, 12, 11, 10, 9, 8, 7);
        carry -= (int)bn_sub_words(r_d, r_d, t_d, BN_NIST_224_TOP);
        nist_set_224(t_d, buf.bn, 0, 0, 0, 0, 13, 12, 11);
        carry -= (int)bn_sub_words(r_d, r_d, t_d, BN_NIST_224_TOP);

# if BN_BITS2==64
        carry = (int)(r_d[BN_NIST_224_TOP - 1] >> 32);
# endif
    }
#endif
    u.f = bn_sub_words;
    if (carry > 0) {
        carry =
            (int)bn_sub_words(r_d, r_d, _nist_p_224[carry - 1],
                              BN_NIST_224_TOP);
#if BN_BITS2==64
        carry = (int)(~(r_d[BN_NIST_224_TOP - 1] >> 32)) & 1;
#endif
    } else if (carry < 0) {
        /*
         * it's a bit more comlicated logic in this case. if bn_add_words
         * yields no carry, then result has to be adjusted by unconditionally
         * *adding* the modulus. but if it does, then result has to be
         * compared to the modulus and conditionally adjusted by
         * *subtracting* the latter.
         */
        carry =
            (int)bn_add_words(r_d, r_d, _nist_p_224[-carry - 1],
                              BN_NIST_224_TOP);
        mask = 0 - (PTR_SIZE_INT) carry;
        u.p = ((PTR_SIZE_INT) bn_sub_words & mask) |
            ((PTR_SIZE_INT) bn_add_words & ~mask);
    } else
        carry = 1;

    /* otherwise it's effectively same as in BN_nist_mod_192... */
    mask =
        0 - (PTR_SIZE_INT) (*u.f) (c_d, r_d, _nist_p_224[0], BN_NIST_224_TOP);
    mask &= 0 - (PTR_SIZE_INT) carry;
    res = c_d;
    res = (BN_ULONG *)(((PTR_SIZE_INT) res & ~mask) |
                       ((PTR_SIZE_INT) r_d & mask));
    nist_cp_bn(r_d, res, BN_NIST_224_TOP);
    r->top = BN_NIST_224_TOP;
    bn_correct_top(r);

    return 1;
}

#define nist_set_256(to, from, a1, a2, a3, a4, a5, a6, a7, a8) \
        { \
        bn_cp_32(to, 0, from, (a8) - 8) \
        bn_cp_32(to, 1, from, (a7) - 8) \
        bn_cp_32(to, 2, from, (a6) - 8) \
        bn_cp_32(to, 3, from, (a5) - 8) \
        bn_cp_32(to, 4, from, (a4) - 8) \
        bn_cp_32(to, 5, from, (a3) - 8) \
        bn_cp_32(to, 6, from, (a2) - 8) \
        bn_cp_32(to, 7, from, (a1) - 8) \
        }

int BN_nist_mod_256(BIGNUM *r, const BIGNUM *a, const BIGNUM *field,
                    BN_CTX *ctx)
{
    int i, top = a->top;
    int carry = 0;
    register BN_ULONG *a_d = a->d, *r_d;
    union {
        BN_ULONG bn[BN_NIST_256_TOP];
        unsigned int ui[BN_NIST_256_TOP * sizeof(BN_ULONG) /
                        sizeof(unsigned int)];
    } buf;
    BN_ULONG c_d[BN_NIST_256_TOP], *res;
    PTR_SIZE_INT mask;
    union {
        bn_addsub_f f;
        PTR_SIZE_INT p;
    } u;
    static const BIGNUM _bignum_nist_p_256_sqr = {
        (BN_ULONG *)_nist_p_256_sqr,
        sizeof(_nist_p_256_sqr) / sizeof(_nist_p_256_sqr[0]),
        sizeof(_nist_p_256_sqr) / sizeof(_nist_p_256_sqr[0]),
        0, BN_FLG_STATIC_DATA
    };

    field = &_bignum_nist_p_256; /* just to make sure */

    if (BN_is_negative(a) || BN_ucmp(a, &_bignum_nist_p_256_sqr) >= 0)
        return BN_nnmod(r, a, field, ctx);

    i = BN_ucmp(field, a);
    if (i == 0) {
        BN_zero(r);
        return 1;
    } else if (i > 0)
        return (r == a) ? 1 : (BN_copy(r, a) != NULL);

    if (r != a) {
        if (!bn_wexpand(r, BN_NIST_256_TOP))
            return 0;
        r_d = r->d;
        nist_cp_bn(r_d, a_d, BN_NIST_256_TOP);
    } else
        r_d = a_d;

    nist_cp_bn_0(buf.bn, a_d + BN_NIST_256_TOP, top - BN_NIST_256_TOP,
                 BN_NIST_256_TOP);

#if defined(NIST_INT64)
    {
        NIST_INT64 acc;         /* accumulator */
        unsigned int *rp = (unsigned int *)r_d;
        const unsigned int *bp = (const unsigned int *)buf.ui;

        acc = rp[0];
        acc += bp[8 - 8];
        acc += bp[9 - 8];
        acc -= bp[11 - 8];
        acc -= bp[12 - 8];
        acc -= bp[13 - 8];
        acc -= bp[14 - 8];
        rp[0] = (unsigned int)acc;
        acc >>= 32;

        acc += rp[1];
        acc += bp[9 - 8];
        acc += bp[10 - 8];
        acc -= bp[12 - 8];
        acc -= bp[13 - 8];
        acc -= bp[14 - 8];
        acc -= bp[15 - 8];
        rp[1] = (unsigned int)acc;
        acc >>= 32;

        acc += rp[2];
        acc += bp[10 - 8];
        acc += bp[11 - 8];
        acc -= bp[13 - 8];
        acc -= bp[14 - 8];
        acc -= bp[15 - 8];
        rp[2] = (unsigned int)acc;
        acc >>= 32;

        acc += rp[3];
        acc += bp[11 - 8];
        acc += bp[11 - 8];
        acc += bp[12 - 8];
        acc += bp[12 - 8];
        acc += bp[13 - 8];
        acc -= bp[15 - 8];
        acc -= bp[8 - 8];
        acc -= bp[9 - 8];
        rp[3] = (unsigned int)acc;
        acc >>= 32;

        acc += rp[4];
        acc += bp[12 - 8];
        acc += bp[12 - 8];
        acc += bp[13 - 8];
        acc += bp[13 - 8];
        acc += bp[14 - 8];
        acc -= bp[9 - 8];
        acc -= bp[10 - 8];
        rp[4] = (unsigned int)acc;
        acc >>= 32;

        acc += rp[5];
        acc += bp[13 - 8];
        acc += bp[13 - 8];
        acc += bp[14 - 8];
        acc += bp[14 - 8];
        acc += bp[15 - 8];
        acc -= bp[10 - 8];
        acc -= bp[11 - 8];
        rp[5] = (unsigned int)acc;
        acc >>= 32;

        acc += rp[6];
        acc += bp[14 - 8];
        acc += bp[14 - 8];
        acc += bp[15 - 8];
        acc += bp[15 - 8];
        acc += bp[14 - 8];
        acc += bp[13 - 8];
        acc -= bp[8 - 8];
        acc -= bp[9 - 8];
        rp[6] = (unsigned int)acc;
        acc >>= 32;

        acc += rp[7];
        acc += bp[15 - 8];
        acc += bp[15 - 8];
        acc += bp[15 - 8];
        acc += bp[8 - 8];
        acc -= bp[10 - 8];
        acc -= bp[11 - 8];
        acc -= bp[12 - 8];
        acc -= bp[13 - 8];
        rp[7] = (unsigned int)acc;

        carry = (int)(acc >> 32);
    }
#else
    {
        BN_ULONG t_d[BN_NIST_256_TOP];

        /*
         * S1
         */
        nist_set_256(t_d, buf.bn, 15, 14, 13, 12, 11, 0, 0, 0);
        /*
         * S2
         */
        nist_set_256(c_d, buf.bn, 0, 15, 14, 13, 12, 0, 0, 0);
        carry = (int)bn_add_words(t_d, t_d, c_d, BN_NIST_256_TOP);
        /* left shift */
        {
            register BN_ULONG *ap, t, c;
            ap = t_d;
            c = 0;
            for (i = BN_NIST_256_TOP; i != 0; --i) {
                t = *ap;
                *(ap++) = ((t << 1) | c) & BN_MASK2;
                c = (t & BN_TBIT) ? 1 : 0;
            }
            carry <<= 1;
            carry |= c;
        }
        carry += (int)bn_add_words(r_d, r_d, t_d, BN_NIST_256_TOP);
        /*
         * S3
         */
        nist_set_256(t_d, buf.bn, 15, 14, 0, 0, 0, 10, 9, 8);
        carry += (int)bn_add_words(r_d, r_d, t_d, BN_NIST_256_TOP);
        /*
         * S4
         */
        nist_set_256(t_d, buf.bn, 8, 13, 15, 14, 13, 11, 10, 9);
        carry += (int)bn_add_words(r_d, r_d, t_d, BN_NIST_256_TOP);
        /*
         * D1
         */
        nist_set_256(t_d, buf.bn, 10, 8, 0, 0, 0, 13, 12, 11);
        carry -= (int)bn_sub_words(r_d, r_d, t_d, BN_NIST_256_TOP);
        /*
         * D2
         */
        nist_set_256(t_d, buf.bn, 11, 9, 0, 0, 15, 14, 13, 12);
        carry -= (int)bn_sub_words(r_d, r_d, t_d, BN_NIST_256_TOP);
        /*
         * D3
         */
        nist_set_256(t_d, buf.bn, 12, 0, 10, 9, 8, 15, 14, 13);
        carry -= (int)bn_sub_words(r_d, r_d, t_d, BN_NIST_256_TOP);
        /*
         * D4
         */
        nist_set_256(t_d, buf.bn, 13, 0, 11, 10, 9, 0, 15, 14);
        carry -= (int)bn_sub_words(r_d, r_d, t_d, BN_NIST_256_TOP);

    }
#endif
    /* see BN_nist_mod_224 for explanation */
    u.f = bn_sub_words;
    if (carry > 0)
        carry =
            (int)bn_sub_words(r_d, r_d, _nist_p_256[carry - 1],
                              BN_NIST_256_TOP);
    else if (carry < 0) {
        carry =
            (int)bn_add_words(r_d, r_d, _nist_p_256[-carry - 1],
                              BN_NIST_256_TOP);
        mask = 0 - (PTR_SIZE_INT) carry;
        u.p = ((PTR_SIZE_INT) bn_sub_words & mask) |
            ((PTR_SIZE_INT) bn_add_words & ~mask);
    } else
        carry = 1;

    mask =
        0 - (PTR_SIZE_INT) (*u.f) (c_d, r_d, _nist_p_256[0], BN_NIST_256_TOP);
    mask &= 0 - (PTR_SIZE_INT) carry;
    res = c_d;
    res = (BN_ULONG *)(((PTR_SIZE_INT) res & ~mask) |
                       ((PTR_SIZE_INT) r_d & mask));
    nist_cp_bn(r_d, res, BN_NIST_256_TOP);
    r->top = BN_NIST_256_TOP;
    bn_correct_top(r);

    return 1;
}

#define nist_set_384(to,from,a1,a2,a3,a4,a5,a6,a7,a8,a9,a10,a11,a12) \
        { \
        bn_cp_32(to, 0, from,  (a12) - 12) \
        bn_cp_32(to, 1, from,  (a11) - 12) \
        bn_cp_32(to, 2, from,  (a10) - 12) \
        bn_cp_32(to, 3, from,  (a9) - 12)  \
        bn_cp_32(to, 4, from,  (a8) - 12)  \
        bn_cp_32(to, 5, from,  (a7) - 12)  \
        bn_cp_32(to, 6, from,  (a6) - 12)  \
        bn_cp_32(to, 7, from,  (a5) - 12)  \
        bn_cp_32(to, 8, from,  (a4) - 12)  \
        bn_cp_32(to, 9, from,  (a3) - 12)  \
        bn_cp_32(to, 10, from, (a2) - 12)  \
        bn_cp_32(to, 11, from, (a1) - 12)  \
        }

int BN_nist_mod_384(BIGNUM *r, const BIGNUM *a, const BIGNUM *field,
                    BN_CTX *ctx)
{
    int i, top = a->top;
    int carry = 0;
    register BN_ULONG *r_d, *a_d = a->d;
    union {
        BN_ULONG bn[BN_NIST_384_TOP];
        unsigned int ui[BN_NIST_384_TOP * sizeof(BN_ULONG) /
                        sizeof(unsigned int)];
    } buf;
    BN_ULONG c_d[BN_NIST_384_TOP], *res;
    PTR_SIZE_INT mask;
    union {
        bn_addsub_f f;
        PTR_SIZE_INT p;
    } u;
    static const BIGNUM _bignum_nist_p_384_sqr = {
        (BN_ULONG *)_nist_p_384_sqr,
        sizeof(_nist_p_384_sqr) / sizeof(_nist_p_384_sqr[0]),
        sizeof(_nist_p_384_sqr) / sizeof(_nist_p_384_sqr[0]),
        0, BN_FLG_STATIC_DATA
    };

    field = &_bignum_nist_p_384; /* just to make sure */

    if (BN_is_negative(a) || BN_ucmp(a, &_bignum_nist_p_384_sqr) >= 0)
        return BN_nnmod(r, a, field, ctx);

    i = BN_ucmp(field, a);
    if (i == 0) {
        BN_zero(r);
        return 1;
    } else if (i > 0)
        return (r == a) ? 1 : (BN_copy(r, a) != NULL);

    if (r != a) {
        if (!bn_wexpand(r, BN_NIST_384_TOP))
            return 0;
        r_d = r->d;
        nist_cp_bn(r_d, a_d, BN_NIST_384_TOP);
    } else
        r_d = a_d;

    nist_cp_bn_0(buf.bn, a_d + BN_NIST_384_TOP, top - BN_NIST_384_TOP,
                 BN_NIST_384_TOP);

#if defined(NIST_INT64)
    {
        NIST_INT64 acc;         /* accumulator */
        unsigned int *rp = (unsigned int *)r_d;
        const unsigned int *bp = (const unsigned int *)buf.ui;

        acc = rp[0];
        acc += bp[12 - 12];
        acc += bp[21 - 12];
        acc += bp[20 - 12];
        acc -= bp[23 - 12];
        rp[0] = (unsigned int)acc;
        acc >>= 32;

        acc += rp[1];
        acc += bp[13 - 12];
        acc += bp[22 - 12];
        acc += bp[23 - 12];
        acc -= bp[12 - 12];
        acc -= bp[20 - 12];
        rp[1] = (unsigned int)acc;
        acc >>= 32;

        acc += rp[2];
        acc += bp[14 - 12];
        acc += bp[23 - 12];
        acc -= bp[13 - 12];
        acc -= bp[21 - 12];
        rp[2] = (unsigned int)acc;
        acc >>= 32;

        acc += rp[3];
        acc += bp[15 - 12];
        acc += bp[12 - 12];
        acc += bp[20 - 12];
        acc += bp[21 - 12];
        acc -= bp[14 - 12];
        acc -= bp[22 - 12];
        acc -= bp[23 - 12];
        rp[3] = (unsigned int)acc;
        acc >>= 32;

        acc += rp[4];
        acc += bp[21 - 12];
        acc += bp[21 - 12];
        acc += bp[16 - 12];
        acc += bp[13 - 12];
        acc += bp[12 - 12];
        acc += bp[20 - 12];
        acc += bp[22 - 12];
        acc -= bp[15 - 12];
        acc -= bp[23 - 12];
        acc -= bp[23 - 12];
        rp[4] = (unsigned int)acc;
        acc >>= 32;

        acc += rp[5];
        acc += bp[22 - 12];
        acc += bp[22 - 12];
        acc += bp[17 - 12];
        acc += bp[14 - 12];
        acc += bp[13 - 12];
        acc += bp[21 - 12];
        acc += bp[23 - 12];
        acc -= bp[16 - 12];
        rp[5] = (unsigned int)acc;
        acc >>= 32;

        acc += rp[6];
        acc += bp[23 - 12];
        acc += bp[23 - 12];
        acc += bp[18 - 12];
        acc += bp[15 - 12];
        acc += bp[14 - 12];
        acc += bp[22 - 12];
        acc -= bp[17 - 12];
        rp[6] = (unsigned int)acc;
        acc >>= 32;

        acc += rp[7];
        acc += bp[19 - 12];
        acc += bp[16 - 12];
        acc += bp[15 - 12];
        acc += bp[23 - 12];
        acc -= bp[18 - 12];
        rp[7] = (unsigned int)acc;
        acc >>= 32;

        acc += rp[8];
        acc += bp[20 - 12];
        acc += bp[17 - 12];
        acc += bp[16 - 12];
        acc -= bp[19 - 12];
        rp[8] = (unsigned int)acc;
        acc >>= 32;

        acc += rp[9];
        acc += bp[21 - 12];
        acc += bp[18 - 12];
        acc += bp[17 - 12];
        acc -= bp[20 - 12];
        rp[9] = (unsigned int)acc;
        acc >>= 32;

        acc += rp[10];
        acc += bp[22 - 12];
        acc += bp[19 - 12];
        acc += bp[18 - 12];
        acc -= bp[21 - 12];
        rp[10] = (unsigned int)acc;
        acc >>= 32;

        acc += rp[11];
        acc += bp[23 - 12];
        acc += bp[20 - 12];
        acc += bp[19 - 12];
        acc -= bp[22 - 12];
        rp[11] = (unsigned int)acc;

        carry = (int)(acc >> 32);
    }
#else
    {
        BN_ULONG t_d[BN_NIST_384_TOP];

        /*
         * S1
         */
        nist_set_256(t_d, buf.bn, 0, 0, 0, 0, 0, 23 - 4, 22 - 4, 21 - 4);
        /* left shift */
        {
            register BN_ULONG *ap, t, c;
            ap = t_d;
            c = 0;
            for (i = 3; i != 0; --i) {
                t = *ap;
                *(ap++) = ((t << 1) | c) & BN_MASK2;
                c = (t & BN_TBIT) ? 1 : 0;
            }
            *ap = c;
        }
        carry =
            (int)bn_add_words(r_d + (128 / BN_BITS2), r_d + (128 / BN_BITS2),
                              t_d, BN_NIST_256_TOP);
        /*
         * S2
         */
        carry += (int)bn_add_words(r_d, r_d, buf.bn, BN_NIST_384_TOP);
        /*
         * S3
         */
        nist_set_384(t_d, buf.bn, 20, 19, 18, 17, 16, 15, 14, 13, 12, 23, 22,
                     21);
        carry += (int)bn_add_words(r_d, r_d, t_d, BN_NIST_384_TOP);
        /*
         * S4
         */
        nist_set_384(t_d, buf.bn, 19, 18, 17, 16, 15, 14, 13, 12, 20, 0, 23,
                     0);
        carry += (int)bn_add_words(r_d, r_d, t_d, BN_NIST_384_TOP);
        /*
         * S5
         */
        nist_set_384(t_d, buf.bn, 0, 0, 0, 0, 23, 22, 21, 20, 0, 0, 0, 0);
        carry += (int)bn_add_words(r_d, r_d, t_d, BN_NIST_384_TOP);
        /*
         * S6
         */
        nist_set_384(t_d, buf.bn, 0, 0, 0, 0, 0, 0, 23, 22, 21, 0, 0, 20);
        carry += (int)bn_add_words(r_d, r_d, t_d, BN_NIST_384_TOP);
        /*
         * D1
         */
        nist_set_384(t_d, buf.bn, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12,
                     23);
        carry -= (int)bn_sub_words(r_d, r_d, t_d, BN_NIST_384_TOP);
        /*
         * D2
         */
        nist_set_384(t_d, buf.bn, 0, 0, 0, 0, 0, 0, 0, 23, 22, 21, 20, 0);
        carry -= (int)bn_sub_words(r_d, r_d, t_d, BN_NIST_384_TOP);
        /*
         * D3
         */
        nist_set_384(t_d, buf.bn, 0, 0, 0, 0, 0, 0, 0, 23, 23, 0, 0, 0);
        carry -= (int)bn_sub_words(r_d, r_d, t_d, BN_NIST_384_TOP);

    }
#endif
    /* see BN_nist_mod_224 for explanation */
    u.f = bn_sub_words;
    if (carry > 0)
        carry =
            (int)bn_sub_words(r_d, r_d, _nist_p_384[carry - 1],
                              BN_NIST_384_TOP);
    else if (carry < 0) {
        carry =
            (int)bn_add_words(r_d, r_d, _nist_p_384[-carry - 1],
                              BN_NIST_384_TOP);
        mask = 0 - (PTR_SIZE_INT) carry;
        u.p = ((PTR_SIZE_INT) bn_sub_words & mask) |
            ((PTR_SIZE_INT) bn_add_words & ~mask);
    } else
        carry = 1;

    mask =
        0 - (PTR_SIZE_INT) (*u.f) (c_d, r_d, _nist_p_384[0], BN_NIST_384_TOP);
    mask &= 0 - (PTR_SIZE_INT) carry;
    res = c_d;
    res = (BN_ULONG *)(((PTR_SIZE_INT) res & ~mask) |
                       ((PTR_SIZE_INT) r_d & mask));
    nist_cp_bn(r_d, res, BN_NIST_384_TOP);
    r->top = BN_NIST_384_TOP;
    bn_correct_top(r);

    return 1;
}

#define BN_NIST_521_RSHIFT      (521%BN_BITS2)
#define BN_NIST_521_LSHIFT      (BN_BITS2-BN_NIST_521_RSHIFT)
#define BN_NIST_521_TOP_MASK    ((BN_ULONG)BN_MASK2>>BN_NIST_521_LSHIFT)

int BN_nist_mod_521(BIGNUM *r, const BIGNUM *a, const BIGNUM *field,
                    BN_CTX *ctx)
{
    int top = a->top, i;
    BN_ULONG *r_d, *a_d = a->d, t_d[BN_NIST_521_TOP], val, tmp, *res;
    PTR_SIZE_INT mask;
    static const BIGNUM _bignum_nist_p_521_sqr = {
        (BN_ULONG *)_nist_p_521_sqr,
        sizeof(_nist_p_521_sqr) / sizeof(_nist_p_521_sqr[0]),
        sizeof(_nist_p_521_sqr) / sizeof(_nist_p_521_sqr[0]),
        0, BN_FLG_STATIC_DATA
    };

    field = &_bignum_nist_p_521; /* just to make sure */

    if (BN_is_negative(a) || BN_ucmp(a, &_bignum_nist_p_521_sqr) >= 0)
        return BN_nnmod(r, a, field, ctx);

    i = BN_ucmp(field, a);
    if (i == 0) {
        BN_zero(r);
        return 1;
    } else if (i > 0)
        return (r == a) ? 1 : (BN_copy(r, a) != NULL);

    if (r != a) {
        if (!bn_wexpand(r, BN_NIST_521_TOP))
            return 0;
        r_d = r->d;
        nist_cp_bn(r_d, a_d, BN_NIST_521_TOP);
    } else
        r_d = a_d;

    /* upper 521 bits, copy ... */
    nist_cp_bn_0(t_d, a_d + (BN_NIST_521_TOP - 1),
                 top - (BN_NIST_521_TOP - 1), BN_NIST_521_TOP);
    /* ... and right shift */
    for (val = t_d[0], i = 0; i < BN_NIST_521_TOP - 1; i++) {
        t_d[i] = (val >> BN_NIST_521_RSHIFT |
                  (tmp = t_d[i + 1]) << BN_NIST_521_LSHIFT) & BN_MASK2;
        val = tmp;
    }
    t_d[i] = val >> BN_NIST_521_RSHIFT;
    /* lower 521 bits */
    r_d[i] &= BN_NIST_521_TOP_MASK;

    bn_add_words(r_d, r_d, t_d, BN_NIST_521_TOP);
    mask =
        0 - (PTR_SIZE_INT) bn_sub_words(t_d, r_d, _nist_p_521,
                                        BN_NIST_521_TOP);
    res = t_d;
    res = (BN_ULONG *)(((PTR_SIZE_INT) res & ~mask) |
                       ((PTR_SIZE_INT) r_d & mask));
    nist_cp_bn(r_d, res, BN_NIST_521_TOP);
    r->top = BN_NIST_521_TOP;
    bn_correct_top(r);

    return 1;
}
/* crypto/bn/bn_prime.c */
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
#include <time.h>
// #include "cryptlib.h"
// #include "bn_lcl.h"
// #include "rand.h"

/*
 * NB: these functions have been "upgraded", the deprecated versions (which
 * are compatibility wrappers using these functions) are in bn_depr.c. -
 * Geoff
 */

/*
 * The quick sieve algorithm approach to weeding out primes is Philip
 * Zimmermann's, as implemented in PGP.  I have had a read of his comments
 * and implemented my own version.
 */
#include "bn_prime.h"

static int witness(BIGNUM *w, const BIGNUM *a, const BIGNUM *a1,
                   const BIGNUM *a1_odd, int k, BN_CTX *ctx,
                   BN_MONT_CTX *mont);
static int probable_prime(BIGNUM *rnd, int bits);
static int probable_prime_dh(BIGNUM *rnd, int bits,
                             const BIGNUM *add, const BIGNUM *rem,
                             BN_CTX *ctx);
static int probable_prime_dh_safe(BIGNUM *rnd, int bits, const BIGNUM *add,
                                  const BIGNUM *rem, BN_CTX *ctx);

int BN_GENCB_call(BN_GENCB *cb, int a, int b)
{
    /* No callback means continue */
    if (!cb)
        return 1;
    switch (cb->ver) {
    case 1:
        /* Deprecated-style callbacks */
        if (!cb->cb.cb_1)
            return 1;
        cb->cb.cb_1(a, b, cb->arg);
        return 1;
    case 2:
        /* New-style callbacks */
        return cb->cb.cb_2(a, b, cb);
    default:
        break;
    }
    /* Unrecognised callback type */
    return 0;
}

int BN_generate_prime_ex(BIGNUM *ret, int bits, int safe,
                         const BIGNUM *add, const BIGNUM *rem, BN_GENCB *cb)
{
    BIGNUM *t;
    int found = 0;
    int i, j, c1 = 0;
    BN_CTX *ctx;
    int checks = BN_prime_checks_for_size(bits);

    ctx = BN_CTX_new();
    if (ctx == NULL)
        goto err;
    BN_CTX_start(ctx);
    t = BN_CTX_get(ctx);
    if (!t)
        goto err;
 loop:
    /* make a random number and set the top and bottom bits */
    if (add == NULL) {
        if (!probable_prime(ret, bits))
            goto err;
    } else {
        if (safe) {
            if (!probable_prime_dh_safe(ret, bits, add, rem, ctx))
                goto err;
        } else {
            if (!probable_prime_dh(ret, bits, add, rem, ctx))
                goto err;
        }
    }
    /* if (BN_mod_word(ret,(BN_ULONG)3) == 1) goto loop; */
    if (!BN_GENCB_call(cb, 0, c1++))
        /* aborted */
        goto err;

    if (!safe) {
        i = BN_is_prime_fasttest_ex(ret, checks, ctx, 0, cb);
        if (i == -1)
            goto err;
        if (i == 0)
            goto loop;
    } else {
        /*
         * for "safe prime" generation, check that (p-1)/2 is prime. Since a
         * prime is odd, We just need to divide by 2
         */
        if (!BN_rshift1(t, ret))
            goto err;

        for (i = 0; i < checks; i++) {
            j = BN_is_prime_fasttest_ex(ret, 1, ctx, 0, cb);
            if (j == -1)
                goto err;
            if (j == 0)
                goto loop;

            j = BN_is_prime_fasttest_ex(t, 1, ctx, 0, cb);
            if (j == -1)
                goto err;
            if (j == 0)
                goto loop;

            if (!BN_GENCB_call(cb, 2, c1 - 1))
                goto err;
            /* We have a safe prime test pass */
        }
    }
    /* we have a prime :-) */
    found = 1;
 err:
    if (ctx != NULL) {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    bn_check_top(ret);
    return found;
}

int BN_is_prime_ex(const BIGNUM *a, int checks, BN_CTX *ctx_passed,
                   BN_GENCB *cb)
{
    return BN_is_prime_fasttest_ex(a, checks, ctx_passed, 0, cb);
}

int BN_is_prime_fasttest_ex(const BIGNUM *a, int checks, BN_CTX *ctx_passed,
                            int do_trial_division, BN_GENCB *cb)
{
    int i, j, ret = -1;
    int k;
    BN_CTX *ctx = NULL;
    BIGNUM *A1, *A1_odd, *check; /* taken from ctx */
    BN_MONT_CTX *mont = NULL;

    if (BN_cmp(a, BN_value_one()) <= 0)
        return 0;

    if (checks == BN_prime_checks)
        checks = BN_prime_checks_for_size(BN_num_bits(a));

    /* first look for small factors */
    if (!BN_is_odd(a))
        /* a is even => a is prime if and only if a == 2 */
        return BN_is_word(a, 2);
    if (do_trial_division) {
        for (i = 1; i < NUMPRIMES; i++)
            if (BN_mod_word(a, primes[i]) == 0)
                return 0;
        if (!BN_GENCB_call(cb, 1, -1))
            goto err;
    }

    if (ctx_passed != NULL)
        ctx = ctx_passed;
    else if ((ctx = BN_CTX_new()) == NULL)
        goto err;
    BN_CTX_start(ctx);

    A1 = BN_CTX_get(ctx);
    A1_odd = BN_CTX_get(ctx);
    check = BN_CTX_get(ctx);
    if (check == NULL)
        goto err;

    /* compute A1 := a - 1 */
    if (!BN_copy(A1, a))
        goto err;
    if (!BN_sub_word(A1, 1))
        goto err;
    if (BN_is_zero(A1)) {
        ret = 0;
        goto err;
    }

    /* write  A1  as  A1_odd * 2^k */
    k = 1;
    while (!BN_is_bit_set(A1, k))
        k++;
    if (!BN_rshift(A1_odd, A1, k))
        goto err;

    /* Montgomery setup for computations mod a */
    mont = BN_MONT_CTX_new();
    if (mont == NULL)
        goto err;
    if (!BN_MONT_CTX_set(mont, a, ctx))
        goto err;

    for (i = 0; i < checks; i++) {
        if (!BN_pseudo_rand_range(check, A1))
            goto err;
        if (!BN_add_word(check, 1))
            goto err;
        /* now 1 <= check < a */

        j = witness(check, a, A1, A1_odd, k, ctx, mont);
        if (j == -1)
            goto err;
        if (j) {
            ret = 0;
            goto err;
        }
        if (!BN_GENCB_call(cb, 1, i))
            goto err;
    }
    ret = 1;
 err:
    if (ctx != NULL) {
        BN_CTX_end(ctx);
        if (ctx_passed == NULL)
            BN_CTX_free(ctx);
    }
    if (mont != NULL)
        BN_MONT_CTX_free(mont);

    return (ret);
}

static int witness(BIGNUM *w, const BIGNUM *a, const BIGNUM *a1,
                   const BIGNUM *a1_odd, int k, BN_CTX *ctx,
                   BN_MONT_CTX *mont)
{
    if (!BN_mod_exp_mont(w, w, a1_odd, a, ctx, mont)) /* w := w^a1_odd mod a */
        return -1;
    if (BN_is_one(w))
        return 0;               /* probably prime */
    if (BN_cmp(w, a1) == 0)
        return 0;               /* w == -1 (mod a), 'a' is probably prime */
    while (--k) {
        if (!BN_mod_mul(w, w, w, a, ctx)) /* w := w^2 mod a */
            return -1;
        if (BN_is_one(w))
            return 1;           /* 'a' is composite, otherwise a previous 'w'
                                 * would have been == -1 (mod 'a') */
        if (BN_cmp(w, a1) == 0)
            return 0;           /* w == -1 (mod a), 'a' is probably prime */
    }
    /*
     * If we get here, 'w' is the (a-1)/2-th power of the original 'w', and
     * it is neither -1 nor +1 -- so 'a' cannot be prime
     */
    bn_check_top(w);
    return 1;
}

static int probable_prime(BIGNUM *rnd, int bits)
{
    int i;
    prime_t mods[NUMPRIMES];
    BN_ULONG delta, maxdelta;

 again:
    if (!BN_rand(rnd, bits, 1, 1))
        return (0);
    /* we now have a random number 'rand' to test. */
    for (i = 1; i < NUMPRIMES; i++)
        mods[i] = (prime_t) BN_mod_word(rnd, (BN_ULONG)primes[i]);
    maxdelta = BN_MASK2 - primes[NUMPRIMES - 1];
    delta = 0;
 loop:for (i = 1; i < NUMPRIMES; i++) {
        /*
         * check that rnd is not a prime and also that gcd(rnd-1,primes) == 1
         * (except for 2)
         */
        if (((mods[i] + delta) % primes[i]) <= 1) {
            delta += 2;
            if (delta > maxdelta)
                goto again;
            goto loop;
        }
    }
    if (!BN_add_word(rnd, delta))
        return (0);
    bn_check_top(rnd);
    return (1);
}

static int probable_prime_dh(BIGNUM *rnd, int bits,
                             const BIGNUM *add, const BIGNUM *rem,
                             BN_CTX *ctx)
{
    int i, ret = 0;
    BIGNUM *t1;

    BN_CTX_start(ctx);
    if ((t1 = BN_CTX_get(ctx)) == NULL)
        goto err;

    if (!BN_rand(rnd, bits, 0, 1))
        goto err;

    /* we need ((rnd-rem) % add) == 0 */

    if (!BN_mod(t1, rnd, add, ctx))
        goto err;
    if (!BN_sub(rnd, rnd, t1))
        goto err;
    if (rem == NULL) {
        if (!BN_add_word(rnd, 1))
            goto err;
    } else {
        if (!BN_add(rnd, rnd, rem))
            goto err;
    }

    /* we now have a random number 'rand' to test. */

 loop:for (i = 1; i < NUMPRIMES; i++) {
        /* check that rnd is a prime */
        if (BN_mod_word(rnd, (BN_ULONG)primes[i]) <= 1) {
            if (!BN_add(rnd, rnd, add))
                goto err;
            goto loop;
        }
    }
    ret = 1;
 err:
    BN_CTX_end(ctx);
    bn_check_top(rnd);
    return (ret);
}

static int probable_prime_dh_safe(BIGNUM *p, int bits, const BIGNUM *padd,
                                  const BIGNUM *rem, BN_CTX *ctx)
{
    int i, ret = 0;
    BIGNUM *t1, *qadd, *q;

    bits--;
    BN_CTX_start(ctx);
    t1 = BN_CTX_get(ctx);
    q = BN_CTX_get(ctx);
    qadd = BN_CTX_get(ctx);
    if (qadd == NULL)
        goto err;

    if (!BN_rshift1(qadd, padd))
        goto err;

    if (!BN_rand(q, bits, 0, 1))
        goto err;

    /* we need ((rnd-rem) % add) == 0 */
    if (!BN_mod(t1, q, qadd, ctx))
        goto err;
    if (!BN_sub(q, q, t1))
        goto err;
    if (rem == NULL) {
        if (!BN_add_word(q, 1))
            goto err;
    } else {
        if (!BN_rshift1(t1, rem))
            goto err;
        if (!BN_add(q, q, t1))
            goto err;
    }

    /* we now have a random number 'rand' to test. */
    if (!BN_lshift1(p, q))
        goto err;
    if (!BN_add_word(p, 1))
        goto err;

 loop:for (i = 1; i < NUMPRIMES; i++) {
        /* check that p and q are prime */
        /*
         * check that for p and q gcd(p-1,primes) == 1 (except for 2)
         */
        if ((BN_mod_word(p, (BN_ULONG)primes[i]) == 0) ||
            (BN_mod_word(q, (BN_ULONG)primes[i]) == 0)) {
            if (!BN_add(p, p, padd))
                goto err;
            if (!BN_add(q, q, qadd))
                goto err;
            goto loop;
        }
    }
    ret = 1;
 err:
    BN_CTX_end(ctx);
    bn_check_top(p);
    return (ret);
}
/* crypto/bn/bn_print.c */
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
#include <limits.h>
// #include "cryptlib.h"
#include "buffer.h"
// #include "bn_lcl.h"

static const char Hex[] = "0123456789ABCDEF";

/* Must 'OPENSSL_free' the returned data */
char *BN_bn2hex(const BIGNUM *a)
{
    int i, j, v, z = 0;
    char *buf;
    char *p;

    if (BN_is_zero(a))
        return OPENSSL_strdup("0");
    buf = OPENSSL_malloc(a->top * BN_BYTES * 2 + 2);
    if (buf == NULL) {
        BNerr(BN_F_BN_BN2HEX, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    p = buf;
    if (a->neg)
        *(p++) = '-';
    for (i = a->top - 1; i >= 0; i--) {
        for (j = BN_BITS2 - 8; j >= 0; j -= 8) {
            /* strip leading zeros */
            v = ((int)(a->d[i] >> (long)j)) & 0xff;
            if (z || (v != 0)) {
                *(p++) = Hex[v >> 4];
                *(p++) = Hex[v & 0x0f];
                z = 1;
            }
        }
    }
    *p = '\0';
 err:
    return (buf);
}

/* Must 'OPENSSL_free' the returned data */
char *BN_bn2dec(const BIGNUM *a)
{
    int i = 0, num, ok = 0;
    char *buf = NULL;
    char *p;
    BIGNUM *t = NULL;
    BN_ULONG *bn_data = NULL, *lp;
    int bn_data_num;

    /*-
     * get an upper bound for the length of the decimal integer
     * num <= (BN_num_bits(a) + 1) * log(2)
     *     <= 3 * BN_num_bits(a) * 0.1001 + log(2) + 1     (rounding error)
     *     <= BN_num_bits(a)/10 + BN_num_bits/1000 + 1 + 1
     */
    i = BN_num_bits(a) * 3;
    num = (i / 10 + i / 1000 + 1) + 1;
    bn_data_num = num / BN_DEC_NUM + 1;
    bn_data = OPENSSL_malloc(bn_data_num * sizeof(BN_ULONG));
    buf = OPENSSL_malloc(num + 3);
    if ((buf == NULL) || (bn_data == NULL)) {
        BNerr(BN_F_BN_BN2DEC, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    if ((t = BN_dup(a)) == NULL)
        goto err;

#define BUF_REMAIN (num+3 - (size_t)(p - buf))
    p = buf;
    lp = bn_data;
    if (BN_is_zero(t)) {
        *(p++) = '0';
        *(p++) = '\0';
    } else {
        if (BN_is_negative(t))
            *p++ = '-';

        while (!BN_is_zero(t)) {
            if (lp - bn_data >= bn_data_num)
                goto err;
            *lp = BN_div_word(t, BN_DEC_CONV);
            if (*lp == (BN_ULONG)-1)
                goto err;
            lp++;
        }
        lp--;
        /*
         * We now have a series of blocks, BN_DEC_NUM chars in length, where
         * the last one needs truncation. The blocks need to be reversed in
         * order.
         */
        BIO_snprintf(p, BUF_REMAIN, BN_DEC_FMT1, *lp);
        while (*p)
            p++;
        while (lp != bn_data) {
            lp--;
            BIO_snprintf(p, BUF_REMAIN, BN_DEC_FMT2, *lp);
            while (*p)
                p++;
        }
    }
    ok = 1;
 err:
    if (bn_data != NULL)
        OPENSSL_free(bn_data);
    if (t != NULL)
        BN_free(t);
    if (!ok && buf) {
        OPENSSL_free(buf);
        buf = NULL;
    }

    return (buf);
}

int BN_hex2bn(BIGNUM **bn, const char *a)
{
    BIGNUM *ret = NULL;
    BN_ULONG l = 0;
    int neg = 0, h, m, i, j, k, c;
    int num;

    if ((a == NULL) || (*a == '\0'))
        return (0);

    if (*a == '-') {
        neg = 1;
        a++;
    }

    for (i = 0; i <= (INT_MAX/4) && isxdigit((unsigned char)a[i]); i++)
        continue;

    if (i > INT_MAX/4)
        goto err;

    num = i + neg;
    if (bn == NULL)
        return (num);

    /* a is the start of the hex digits, and it is 'i' long */
    if (*bn == NULL) {
        if ((ret = BN_new()) == NULL)
            return (0);
    } else {
        ret = *bn;
        BN_zero(ret);
    }

    /* i is the number of hex digits */
    if (bn_expand(ret, i * 4) == NULL)
        goto err;

    j = i;                      /* least significant 'hex' */
    m = 0;
    h = 0;
    while (j > 0) {
        m = ((BN_BYTES * 2) <= j) ? (BN_BYTES * 2) : j;
        l = 0;
        for (;;) {
            c = a[j - m];
            if ((c >= '0') && (c <= '9'))
                k = c - '0';
            else if ((c >= 'a') && (c <= 'f'))
                k = c - 'a' + 10;
            else if ((c >= 'A') && (c <= 'F'))
                k = c - 'A' + 10;
            else
                k = 0;          /* paranoia */
            l = (l << 4) | k;

            if (--m <= 0) {
                ret->d[h++] = l;
                break;
            }
        }
        j -= (BN_BYTES * 2);
    }
    ret->top = h;
    bn_correct_top(ret);

    *bn = ret;
    bn_check_top(ret);
    /* Don't set the negative flag if it's zero. */
    if (ret->top != 0)
        ret->neg = neg;
    return (num);
 err:
    if (*bn == NULL)
        BN_free(ret);
    return (0);
}

int BN_dec2bn(BIGNUM **bn, const char *a)
{
    BIGNUM *ret = NULL;
    BN_ULONG l = 0;
    int neg = 0, i, j;
    int num;

    if ((a == NULL) || (*a == '\0'))
        return (0);
    if (*a == '-') {
        neg = 1;
        a++;
    }

    for (i = 0; i <= (INT_MAX/4) && isdigit((unsigned char)a[i]); i++)
        continue;

    if (i > INT_MAX/4)
        goto err;

    num = i + neg;
    if (bn == NULL)
        return (num);

    /*
     * a is the start of the digits, and it is 'i' long. We chop it into
     * BN_DEC_NUM digits at a time
     */
    if (*bn == NULL) {
        if ((ret = BN_new()) == NULL)
            return (0);
    } else {
        ret = *bn;
        BN_zero(ret);
    }

    /* i is the number of digits, a bit of an over expand */
    if (bn_expand(ret, i * 4) == NULL)
        goto err;

    j = BN_DEC_NUM - (i % BN_DEC_NUM);
    if (j == BN_DEC_NUM)
        j = 0;
    l = 0;
    while (--i >= 0) {
        l *= 10;
        l += *a - '0';
        a++;
        if (++j == BN_DEC_NUM) {
            BN_mul_word(ret, BN_DEC_CONV);
            BN_add_word(ret, l);
            l = 0;
            j = 0;
        }
    }

    bn_correct_top(ret);
    *bn = ret;
    bn_check_top(ret);
    /* Don't set the negative flag if it's zero. */
    if (ret->top != 0)
        ret->neg = neg;
    return (num);
 err:
    if (*bn == NULL)
        BN_free(ret);
    return (0);
}

int BN_asc2bn(BIGNUM **bn, const char *a)
{
    const char *p = a;

    if (*p == '-')
        p++;

    if (p[0] == '0' && (p[1] == 'X' || p[1] == 'x')) {
        if (!BN_hex2bn(bn, p + 2))
            return 0;
    } else {
        if (!BN_dec2bn(bn, p))
            return 0;
    }
    /* Don't set the negative flag if it's zero. */
    if (*a == '-' && (*bn)->top != 0)
        (*bn)->neg = 1;
    return 1;
}

#ifndef OPENSSL_NO_BIO
# ifndef OPENSSL_NO_FP_API
int BN_print_fp(FILE *fp, const BIGNUM *a)
{
    BIO *b;
    int ret;

    if ((b = BIO_new(BIO_s_file())) == NULL)
        return (0);
    BIO_set_fp(b, fp, BIO_NOCLOSE);
    ret = BN_print(b, a);
    BIO_free(b);
    return (ret);
}
# endif

int BN_print(BIO *bp, const BIGNUM *a)
{
    int i, j, v, z = 0;
    int ret = 0;

    if ((a->neg) && (BIO_write(bp, "-", 1) != 1))
        goto end;
    if (BN_is_zero(a) && (BIO_write(bp, "0", 1) != 1))
        goto end;
    for (i = a->top - 1; i >= 0; i--) {
        for (j = BN_BITS2 - 4; j >= 0; j -= 4) {
            /* strip leading zeros */
            v = ((int)(a->d[i] >> (long)j)) & 0x0f;
            if (z || (v != 0)) {
                if (BIO_write(bp, &(Hex[v]), 1) != 1)
                    goto end;
                z = 1;
            }
        }
    }
    ret = 1;
 end:
    return (ret);
}
#endif

char *BN_options(void)
{
    static int init = 0;
    static char data[16];

    if (!init) {
        init++;
#ifdef BN_LLONG
        BIO_snprintf(data, sizeof(data), "bn(%d,%d)",
                     (int)sizeof(BN_ULLONG) * 8, (int)sizeof(BN_ULONG) * 8);
#else
        BIO_snprintf(data, sizeof(data), "bn(%d,%d)",
                     (int)sizeof(BN_ULONG) * 8, (int)sizeof(BN_ULONG) * 8);
#endif
    }
    return (data);
}
/* crypto/bn/bn_rand.c */
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
#include <time.h>
// #include "cryptlib.h"
// #include "bn_lcl.h"
// #include "rand.h"

static int bnrand(int pseudorand, BIGNUM *rnd, int bits, int top, int bottom)
{
    unsigned char *buf = NULL;
    int ret = 0, bit, bytes, mask;
    time_t tim;

    if (bits == 0) {
        if (top != -1 || bottom != 0)
            goto toosmall;
        BN_zero(rnd);
        return 1;
    }
    if (bits < 0 || (bits == 1 && top > 0))
        goto toosmall;

    bytes = (bits + 7) / 8;
    bit = (bits - 1) % 8;
    mask = 0xff << (bit + 1);

    buf = (unsigned char *)OPENSSL_malloc(bytes);
    if (buf == NULL) {
        BNerr(BN_F_BNRAND, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    /* make a random number and set the top and bottom bits */
    time(&tim);
    RAND_add(&tim, sizeof(tim), 0.0);

    /* We ignore the value of pseudorand and always call RAND_bytes */
    if (RAND_bytes(buf, bytes) <= 0)
        goto err;

#if 1
    if (pseudorand == 2) {
        /*
         * generate patterns that are more likely to trigger BN library bugs
         */
        int i;
        unsigned char c;

        for (i = 0; i < bytes; i++) {
            if (RAND_pseudo_bytes(&c, 1) < 0)
                goto err;
            if (c >= 128 && i > 0)
                buf[i] = buf[i - 1];
            else if (c < 42)
                buf[i] = 0;
            else if (c < 84)
                buf[i] = 255;
        }
    }
#endif

    if (top >= 0) {
        if (top) {
            if (bit == 0) {
                buf[0] = 1;
                buf[1] |= 0x80;
            } else {
                buf[0] |= (3 << (bit - 1));
            }
        } else {
            buf[0] |= (1 << bit);
        }
    }
    buf[0] &= ~mask;
    if (bottom)                 /* set bottom bit if requested */
        buf[bytes - 1] |= 1;
    if (!BN_bin2bn(buf, bytes, rnd))
        goto err;
    ret = 1;
 err:
    if (buf != NULL) {
        OPENSSL_cleanse(buf, bytes);
        OPENSSL_free(buf);
    }
    bn_check_top(rnd);
    return (ret);

toosmall:
    BNerr(BN_F_BNRAND, BN_R_BITS_TOO_SMALL);
    return 0;
}

int BN_rand(BIGNUM *rnd, int bits, int top, int bottom)
{
    return bnrand(0, rnd, bits, top, bottom);
}

int BN_pseudo_rand(BIGNUM *rnd, int bits, int top, int bottom)
{
    return bnrand(1, rnd, bits, top, bottom);
}

#if 1
int BN_bntest_rand(BIGNUM *rnd, int bits, int top, int bottom)
{
    return bnrand(2, rnd, bits, top, bottom);
}
#endif

/* random number r:  0 <= r < range */
static int bn_rand_range(int pseudo, BIGNUM *r, const BIGNUM *range)
{
    int (*bn_rand) (BIGNUM *, int, int, int) =
        pseudo ? BN_pseudo_rand : BN_rand;
    int n;
    int count = 100;

    if (range->neg || BN_is_zero(range)) {
        BNerr(BN_F_BN_RAND_RANGE, BN_R_INVALID_RANGE);
        return 0;
    }

    n = BN_num_bits(range);     /* n > 0 */

    /* BN_is_bit_set(range, n - 1) always holds */

    if (n == 1)
        BN_zero(r);
    else if (!BN_is_bit_set(range, n - 2) && !BN_is_bit_set(range, n - 3)) {
        /*
         * range = 100..._2, so 3*range (= 11..._2) is exactly one bit longer
         * than range
         */
        do {
            if (!bn_rand(r, n + 1, -1, 0))
                return 0;
            /*
             * If r < 3*range, use r := r MOD range (which is either r, r -
             * range, or r - 2*range). Otherwise, iterate once more. Since
             * 3*range = 11..._2, each iteration succeeds with probability >=
             * .75.
             */
            if (BN_cmp(r, range) >= 0) {
                if (!BN_sub(r, r, range))
                    return 0;
                if (BN_cmp(r, range) >= 0)
                    if (!BN_sub(r, r, range))
                        return 0;
            }

            if (!--count) {
                BNerr(BN_F_BN_RAND_RANGE, BN_R_TOO_MANY_ITERATIONS);
                return 0;
            }

        }
        while (BN_cmp(r, range) >= 0);
    } else {
        do {
            /* range = 11..._2  or  range = 101..._2 */
            if (!bn_rand(r, n, -1, 0))
                return 0;

            if (!--count) {
                BNerr(BN_F_BN_RAND_RANGE, BN_R_TOO_MANY_ITERATIONS);
                return 0;
            }
        }
        while (BN_cmp(r, range) >= 0);
    }

    bn_check_top(r);
    return 1;
}

int BN_rand_range(BIGNUM *r, const BIGNUM *range)
{
    return bn_rand_range(0, r, range);
}

int BN_pseudo_rand_range(BIGNUM *r, const BIGNUM *range)
{
    return bn_rand_range(1, r, range);
}
/* crypto/bn/bn_recp.c */
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
// #include "bn_lcl.h"

void BN_RECP_CTX_init(BN_RECP_CTX *recp)
{
    BN_init(&(recp->N));
    BN_init(&(recp->Nr));
    recp->num_bits = 0;
    recp->shift = 0;
    recp->flags = 0;
}

BN_RECP_CTX *BN_RECP_CTX_new(void)
{
    BN_RECP_CTX *ret;

    if ((ret = (BN_RECP_CTX *)OPENSSL_malloc(sizeof(BN_RECP_CTX))) == NULL)
        return (NULL);

    BN_RECP_CTX_init(ret);
    ret->flags = BN_FLG_MALLOCED;
    return (ret);
}

void BN_RECP_CTX_free(BN_RECP_CTX *recp)
{
    if (recp == NULL)
        return;

    BN_free(&(recp->N));
    BN_free(&(recp->Nr));
    if (recp->flags & BN_FLG_MALLOCED)
        OPENSSL_free(recp);
}

int BN_RECP_CTX_set(BN_RECP_CTX *recp, const BIGNUM *d, BN_CTX *ctx)
{
    if (!BN_copy(&(recp->N), d))
        return 0;
    BN_zero(&(recp->Nr));
    recp->num_bits = BN_num_bits(d);
    recp->shift = 0;
    return (1);
}

int BN_mod_mul_reciprocal(BIGNUM *r, const BIGNUM *x, const BIGNUM *y,
                          BN_RECP_CTX *recp, BN_CTX *ctx)
{
    int ret = 0;
    BIGNUM *a;
    const BIGNUM *ca;

    BN_CTX_start(ctx);
    if ((a = BN_CTX_get(ctx)) == NULL)
        goto err;
    if (y != NULL) {
        if (x == y) {
            if (!BN_sqr(a, x, ctx))
                goto err;
        } else {
            if (!BN_mul(a, x, y, ctx))
                goto err;
        }
        ca = a;
    } else
        ca = x;                 /* Just do the mod */

    ret = BN_div_recp(NULL, r, ca, recp, ctx);
 err:
    BN_CTX_end(ctx);
    bn_check_top(r);
    return (ret);
}

int BN_div_recp(BIGNUM *dv, BIGNUM *rem, const BIGNUM *m,
                BN_RECP_CTX *recp, BN_CTX *ctx)
{
    int i, j, ret = 0;
    BIGNUM *a, *b, *d, *r;

    BN_CTX_start(ctx);
    a = BN_CTX_get(ctx);
    b = BN_CTX_get(ctx);
    if (dv != NULL)
        d = dv;
    else
        d = BN_CTX_get(ctx);
    if (rem != NULL)
        r = rem;
    else
        r = BN_CTX_get(ctx);
    if (a == NULL || b == NULL || d == NULL || r == NULL)
        goto err;

    if (BN_ucmp(m, &(recp->N)) < 0) {
        BN_zero(d);
        if (!BN_copy(r, m)) {
            BN_CTX_end(ctx);
            return 0;
        }
        BN_CTX_end(ctx);
        return (1);
    }

    /*
     * We want the remainder Given input of ABCDEF / ab we need multiply
     * ABCDEF by 3 digests of the reciprocal of ab
     */

    /* i := max(BN_num_bits(m), 2*BN_num_bits(N)) */
    i = BN_num_bits(m);
    j = recp->num_bits << 1;
    if (j > i)
        i = j;

    /* Nr := round(2^i / N) */
    if (i != recp->shift)
        recp->shift = BN_reciprocal(&(recp->Nr), &(recp->N), i, ctx);
    /* BN_reciprocal could have returned -1 for an error */
    if (recp->shift == -1)
        goto err;

    /*-
     * d := |round(round(m / 2^BN_num_bits(N)) * recp->Nr / 2^(i - BN_num_bits(N)))|
     *    = |round(round(m / 2^BN_num_bits(N)) * round(2^i / N) / 2^(i - BN_num_bits(N)))|
     *   <= |(m / 2^BN_num_bits(N)) * (2^i / N) * (2^BN_num_bits(N) / 2^i)|
     *    = |m/N|
     */
    if (!BN_rshift(a, m, recp->num_bits))
        goto err;
    if (!BN_mul(b, a, &(recp->Nr), ctx))
        goto err;
    if (!BN_rshift(d, b, i - recp->num_bits))
        goto err;
    d->neg = 0;

    if (!BN_mul(b, &(recp->N), d, ctx))
        goto err;
    if (!BN_usub(r, m, b))
        goto err;
    r->neg = 0;

#if 1
    j = 0;
    while (BN_ucmp(r, &(recp->N)) >= 0) {
        if (j++ > 2) {
            BNerr(BN_F_BN_DIV_RECP, BN_R_BAD_RECIPROCAL);
            goto err;
        }
        if (!BN_usub(r, r, &(recp->N)))
            goto err;
        if (!BN_add_word(d, 1))
            goto err;
    }
#endif

    r->neg = BN_is_zero(r) ? 0 : m->neg;
    d->neg = m->neg ^ recp->N.neg;
    ret = 1;
 err:
    BN_CTX_end(ctx);
    bn_check_top(dv);
    bn_check_top(rem);
    return (ret);
}

/*
 * len is the expected size of the result We actually calculate with an extra
 * word of precision, so we can do faster division if the remainder is not
 * required.
 */
/* r := 2^len / m */
int BN_reciprocal(BIGNUM *r, const BIGNUM *m, int len, BN_CTX *ctx)
{
    int ret = -1;
    BIGNUM *t;

    BN_CTX_start(ctx);
    if ((t = BN_CTX_get(ctx)) == NULL)
        goto err;

    if (!BN_set_bit(t, len))
        goto err;

    if (!BN_div(r, NULL, t, m, ctx))
        goto err;

    ret = len;
 err:
    bn_check_top(r);
    BN_CTX_end(ctx);
    return (ret);
}
/* crypto/bn/bn_shift.c */
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
// #include "bn_lcl.h"

int BN_lshift1(BIGNUM *r, const BIGNUM *a)
{
    register BN_ULONG *ap, *rp, t, c;
    int i;

    bn_check_top(r);
    bn_check_top(a);

    if (r != a) {
        r->neg = a->neg;
        if (bn_wexpand(r, a->top + 1) == NULL)
            return (0);
        r->top = a->top;
    } else {
        if (bn_wexpand(r, a->top + 1) == NULL)
            return (0);
    }
    ap = a->d;
    rp = r->d;
    c = 0;
    for (i = 0; i < a->top; i++) {
        t = *(ap++);
        *(rp++) = ((t << 1) | c) & BN_MASK2;
        c = (t & BN_TBIT) ? 1 : 0;
    }
    if (c) {
        *rp = 1;
        r->top++;
    }
    bn_check_top(r);
    return (1);
}

int BN_rshift1(BIGNUM *r, const BIGNUM *a)
{
    BN_ULONG *ap, *rp, t, c;
    int i, j;

    bn_check_top(r);
    bn_check_top(a);

    if (BN_is_zero(a)) {
        BN_zero(r);
        return (1);
    }
    i = a->top;
    ap = a->d;
    j = i - (ap[i - 1] == 1);
    if (a != r) {
        if (bn_wexpand(r, j) == NULL)
            return (0);
        r->neg = a->neg;
    }
    rp = r->d;
    t = ap[--i];
    c = (t & 1) ? BN_TBIT : 0;
    if (t >>= 1)
        rp[i] = t;
    while (i > 0) {
        t = ap[--i];
        rp[i] = ((t >> 1) & BN_MASK2) | c;
        c = (t & 1) ? BN_TBIT : 0;
    }
    r->top = j;
    bn_check_top(r);
    return (1);
}

int BN_lshift(BIGNUM *r, const BIGNUM *a, int n)
{
    int i, nw, lb, rb;
    BN_ULONG *t, *f;
    BN_ULONG l;

    bn_check_top(r);
    bn_check_top(a);

    if (n < 0) {
        BNerr(BN_F_BN_LSHIFT, BN_R_INVALID_SHIFT);
        return 0;
    }

    r->neg = a->neg;
    nw = n / BN_BITS2;
    if (bn_wexpand(r, a->top + nw + 1) == NULL)
        return (0);
    lb = n % BN_BITS2;
    rb = BN_BITS2 - lb;
    f = a->d;
    t = r->d;
    t[a->top + nw] = 0;
    if (lb == 0)
        for (i = a->top - 1; i >= 0; i--)
            t[nw + i] = f[i];
    else
        for (i = a->top - 1; i >= 0; i--) {
            l = f[i];
            t[nw + i + 1] |= (l >> rb) & BN_MASK2;
            t[nw + i] = (l << lb) & BN_MASK2;
        }
    memset(t, 0, nw * sizeof(t[0]));
    /*
     * for (i=0; i<nw; i++) t[i]=0;
     */
    r->top = a->top + nw + 1;
    bn_correct_top(r);
    bn_check_top(r);
    return (1);
}

int BN_rshift(BIGNUM *r, const BIGNUM *a, int n)
{
    int i, j, nw, lb, rb;
    BN_ULONG *t, *f;
    BN_ULONG l, tmp;

    bn_check_top(r);
    bn_check_top(a);

    if (n < 0) {
        BNerr(BN_F_BN_RSHIFT, BN_R_INVALID_SHIFT);
        return 0;
    }

    nw = n / BN_BITS2;
    rb = n % BN_BITS2;
    lb = BN_BITS2 - rb;
    if (nw >= a->top || a->top == 0) {
        BN_zero(r);
        return (1);
    }
    i = (BN_num_bits(a) - n + (BN_BITS2 - 1)) / BN_BITS2;
    if (r != a) {
        r->neg = a->neg;
        if (bn_wexpand(r, i) == NULL)
            return (0);
    } else {
        if (n == 0)
            return 1;           /* or the copying loop will go berserk */
    }

    f = &(a->d[nw]);
    t = r->d;
    j = a->top - nw;
    r->top = i;

    if (rb == 0) {
        for (i = j; i != 0; i--)
            *(t++) = *(f++);
    } else {
        l = *(f++);
        for (i = j - 1; i != 0; i--) {
            tmp = (l >> rb) & BN_MASK2;
            l = *(f++);
            *(t++) = (tmp | (l << lb)) & BN_MASK2;
        }
        if ((l = (l >> rb) & BN_MASK2))
            *(t) = l;
    }
    bn_check_top(r);
    return (1);
}
/* crypto/bn/bn_sqr.c */
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
// #include "bn_lcl.h"

/* r must not be a */
/*
 * I've just gone over this and it is now %20 faster on x86 - eay - 27 Jun 96
 */
int BN_sqr(BIGNUM *r, const BIGNUM *a, BN_CTX *ctx)
{
    int ret = bn_sqr_fixed_top(r, a, ctx);

    bn_correct_top(r);
    bn_check_top(r);

    return ret;
}

int bn_sqr_fixed_top(BIGNUM *r, const BIGNUM *a, BN_CTX *ctx)
{
    int max, al;
    int ret = 0;
    BIGNUM *tmp, *rr;

#ifdef BN_COUNT
    fprintf(stderr, "BN_sqr %d * %d\n", a->top, a->top);
#endif
    bn_check_top(a);

    al = a->top;
    if (al <= 0) {
        r->top = 0;
        r->neg = 0;
        return 1;
    }

    BN_CTX_start(ctx);
    rr = (a != r) ? r : BN_CTX_get(ctx);
    tmp = BN_CTX_get(ctx);
    if (!rr || !tmp)
        goto err;

    max = 2 * al;               /* Non-zero (from above) */
    if (bn_wexpand(rr, max) == NULL)
        goto err;

    if (al == 4) {
#ifndef BN_SQR_COMBA
        BN_ULONG t[8];
        bn_sqr_normal(rr->d, a->d, 4, t);
#else
        bn_sqr_comba4(rr->d, a->d);
#endif
    } else if (al == 8) {
#ifndef BN_SQR_COMBA
        BN_ULONG t[16];
        bn_sqr_normal(rr->d, a->d, 8, t);
#else
        bn_sqr_comba8(rr->d, a->d);
#endif
    } else {
#if defined(BN_RECURSION)
        if (al < BN_SQR_RECURSIVE_SIZE_NORMAL) {
            BN_ULONG t[BN_SQR_RECURSIVE_SIZE_NORMAL * 2];
            bn_sqr_normal(rr->d, a->d, al, t);
        } else {
            int j, k;

            j = BN_num_bits_word((BN_ULONG)al);
            j = 1 << (j - 1);
            k = j + j;
            if (al == j) {
                if (bn_wexpand(tmp, k * 2) == NULL)
                    goto err;
                bn_sqr_recursive(rr->d, a->d, al, tmp->d);
            } else {
                if (bn_wexpand(tmp, max) == NULL)
                    goto err;
                bn_sqr_normal(rr->d, a->d, al, tmp->d);
            }
        }
#else
        if (bn_wexpand(tmp, max) == NULL)
            goto err;
        bn_sqr_normal(rr->d, a->d, al, tmp->d);
#endif
    }

    rr->neg = 0;
    rr->top = max;
    rr->flags |= BN_FLG_FIXED_TOP;
    if (r != rr && BN_copy(r, rr) == NULL)
        goto err;

    ret = 1;
 err:
    bn_check_top(rr);
    bn_check_top(tmp);
    BN_CTX_end(ctx);
    return (ret);
}

/* tmp must have 2*n words */
void bn_sqr_normal(BN_ULONG *r, const BN_ULONG *a, int n, BN_ULONG *tmp)
{
    int i, j, max;
    const BN_ULONG *ap;
    BN_ULONG *rp;

    max = n * 2;
    ap = a;
    rp = r;
    rp[0] = rp[max - 1] = 0;
    rp++;
    j = n;

    if (--j > 0) {
        ap++;
        rp[j] = bn_mul_words(rp, ap, j, ap[-1]);
        rp += 2;
    }

    for (i = n - 2; i > 0; i--) {
        j--;
        ap++;
        rp[j] = bn_mul_add_words(rp, ap, j, ap[-1]);
        rp += 2;
    }

    bn_add_words(r, r, r, max);

    /* There will not be a carry */

    bn_sqr_words(tmp, a, n);

    bn_add_words(r, r, tmp, max);
}

#ifdef BN_RECURSION
/*-
 * r is 2*n words in size,
 * a and b are both n words in size.    (There's not actually a 'b' here ...)
 * n must be a power of 2.
 * We multiply and return the result.
 * t must be 2*n words in size
 * We calculate
 * a[0]*b[0]
 * a[0]*b[0]+a[1]*b[1]+(a[0]-a[1])*(b[1]-b[0])
 * a[1]*b[1]
 */
void bn_sqr_recursive(BN_ULONG *r, const BN_ULONG *a, int n2, BN_ULONG *t)
{
    int n = n2 / 2;
    int zero, c1;
    BN_ULONG ln, lo, *p;

# ifdef BN_COUNT
    fprintf(stderr, " bn_sqr_recursive %d * %d\n", n2, n2);
# endif
    if (n2 == 4) {
# ifndef BN_SQR_COMBA
        bn_sqr_normal(r, a, 4, t);
# else
        bn_sqr_comba4(r, a);
# endif
        return;
    } else if (n2 == 8) {
# ifndef BN_SQR_COMBA
        bn_sqr_normal(r, a, 8, t);
# else
        bn_sqr_comba8(r, a);
# endif
        return;
    }
    if (n2 < BN_SQR_RECURSIVE_SIZE_NORMAL) {
        bn_sqr_normal(r, a, n2, t);
        return;
    }
    /* r=(a[0]-a[1])*(a[1]-a[0]) */
    c1 = bn_cmp_words(a, &(a[n]), n);
    zero = 0;
    if (c1 > 0)
        bn_sub_words(t, a, &(a[n]), n);
    else if (c1 < 0)
        bn_sub_words(t, &(a[n]), a, n);
    else
        zero = 1;

    /* The result will always be negative unless it is zero */
    p = &(t[n2 * 2]);

    if (!zero)
        bn_sqr_recursive(&(t[n2]), t, n, p);
    else
        memset(&(t[n2]), 0, n2 * sizeof(BN_ULONG));
    bn_sqr_recursive(r, a, n, p);
    bn_sqr_recursive(&(r[n2]), &(a[n]), n, p);

    /*-
     * t[32] holds (a[0]-a[1])*(a[1]-a[0]), it is negative or zero
     * r[10] holds (a[0]*b[0])
     * r[32] holds (b[1]*b[1])
     */

    c1 = (int)(bn_add_words(t, r, &(r[n2]), n2));

    /* t[32] is negative */
    c1 -= (int)(bn_sub_words(&(t[n2]), t, &(t[n2]), n2));

    /*-
     * t[32] holds (a[0]-a[1])*(a[1]-a[0])+(a[0]*a[0])+(a[1]*a[1])
     * r[10] holds (a[0]*a[0])
     * r[32] holds (a[1]*a[1])
     * c1 holds the carry bits
     */
    c1 += (int)(bn_add_words(&(r[n]), &(r[n]), &(t[n2]), n2));
    if (c1) {
        p = &(r[n + n2]);
        lo = *p;
        ln = (lo + c1) & BN_MASK2;
        *p = ln;

        /*
         * The overflow will stop before we over write words we should not
         * overwrite
         */
        if (ln < (BN_ULONG)c1) {
            do {
                p++;
                lo = *p;
                ln = (lo + 1) & BN_MASK2;
                *p = ln;
            } while (ln == 0);
        }
    }
}
#endif
/* crypto/bn/bn_sqrt.c */
/*
 * Written by Lenka Fibikova <fibikova@exp-math.uni-essen.de> and Bodo
 * Moeller for the OpenSSL project.
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

// #include "cryptlib.h"
// #include "bn_lcl.h"

BIGNUM *BN_mod_sqrt(BIGNUM *in, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx)
/*
 * Returns 'ret' such that ret^2 == a (mod p), using the Tonelli/Shanks
 * algorithm (cf. Henri Cohen, "A Course in Algebraic Computational Number
 * Theory", algorithm 1.5.1). 'p' must be prime!
 */
{
    BIGNUM *ret = in;
    int err = 1;
    int r;
    BIGNUM *A, *b, *q, *t, *x, *y;
    int e, i, j;

    if (!BN_is_odd(p) || BN_abs_is_word(p, 1)) {
        if (BN_abs_is_word(p, 2)) {
            if (ret == NULL)
                ret = BN_new();
            if (ret == NULL)
                goto end;
            if (!BN_set_word(ret, BN_is_bit_set(a, 0))) {
                if (ret != in)
                    BN_free(ret);
                return NULL;
            }
            bn_check_top(ret);
            return ret;
        }

        BNerr(BN_F_BN_MOD_SQRT, BN_R_P_IS_NOT_PRIME);
        return (NULL);
    }

    if (BN_is_zero(a) || BN_is_one(a)) {
        if (ret == NULL)
            ret = BN_new();
        if (ret == NULL)
            goto end;
        if (!BN_set_word(ret, BN_is_one(a))) {
            if (ret != in)
                BN_free(ret);
            return NULL;
        }
        bn_check_top(ret);
        return ret;
    }

    BN_CTX_start(ctx);
    A = BN_CTX_get(ctx);
    b = BN_CTX_get(ctx);
    q = BN_CTX_get(ctx);
    t = BN_CTX_get(ctx);
    x = BN_CTX_get(ctx);
    y = BN_CTX_get(ctx);
    if (y == NULL)
        goto end;

    if (ret == NULL)
        ret = BN_new();
    if (ret == NULL)
        goto end;

    /* A = a mod p */
    if (!BN_nnmod(A, a, p, ctx))
        goto end;

    /* now write  |p| - 1  as  2^e*q  where  q  is odd */
    e = 1;
    while (!BN_is_bit_set(p, e))
        e++;
    /* we'll set  q  later (if needed) */

    if (e == 1) {
        /*-
         * The easy case:  (|p|-1)/2  is odd, so 2 has an inverse
         * modulo  (|p|-1)/2,  and square roots can be computed
         * directly by modular exponentiation.
         * We have
         *     2 * (|p|+1)/4 == 1   (mod (|p|-1)/2),
         * so we can use exponent  (|p|+1)/4,  i.e.  (|p|-3)/4 + 1.
         */
        if (!BN_rshift(q, p, 2))
            goto end;
        q->neg = 0;
        if (!BN_add_word(q, 1))
            goto end;
        if (!BN_mod_exp(ret, A, q, p, ctx))
            goto end;
        err = 0;
        goto vrfy;
    }

    if (e == 2) {
        /*-
         * |p| == 5  (mod 8)
         *
         * In this case  2  is always a non-square since
         * Legendre(2,p) = (-1)^((p^2-1)/8)  for any odd prime.
         * So if  a  really is a square, then  2*a  is a non-square.
         * Thus for
         *      b := (2*a)^((|p|-5)/8),
         *      i := (2*a)*b^2
         * we have
         *     i^2 = (2*a)^((1 + (|p|-5)/4)*2)
         *         = (2*a)^((p-1)/2)
         *         = -1;
         * so if we set
         *      x := a*b*(i-1),
         * then
         *     x^2 = a^2 * b^2 * (i^2 - 2*i + 1)
         *         = a^2 * b^2 * (-2*i)
         *         = a*(-i)*(2*a*b^2)
         *         = a*(-i)*i
         *         = a.
         *
         * (This is due to A.O.L. Atkin,
         * <URL: http://listserv.nodak.edu/scripts/wa.exe?A2=ind9211&L=nmbrthry&O=T&P=562>,
         * November 1992.)
         */

        /* t := 2*a */
        if (!BN_mod_lshift1_quick(t, A, p))
            goto end;

        /* b := (2*a)^((|p|-5)/8) */
        if (!BN_rshift(q, p, 3))
            goto end;
        q->neg = 0;
        if (!BN_mod_exp(b, t, q, p, ctx))
            goto end;

        /* y := b^2 */
        if (!BN_mod_sqr(y, b, p, ctx))
            goto end;

        /* t := (2*a)*b^2 - 1 */
        if (!BN_mod_mul(t, t, y, p, ctx))
            goto end;
        if (!BN_sub_word(t, 1))
            goto end;

        /* x = a*b*t */
        if (!BN_mod_mul(x, A, b, p, ctx))
            goto end;
        if (!BN_mod_mul(x, x, t, p, ctx))
            goto end;

        if (!BN_copy(ret, x))
            goto end;
        err = 0;
        goto vrfy;
    }

    /*
     * e > 2, so we really have to use the Tonelli/Shanks algorithm. First,
     * find some y that is not a square.
     */
    if (!BN_copy(q, p))
        goto end;               /* use 'q' as temp */
    q->neg = 0;
    i = 2;
    do {
        /*
         * For efficiency, try small numbers first; if this fails, try random
         * numbers.
         */
        if (i < 22) {
            if (!BN_set_word(y, i))
                goto end;
        } else {
            if (!BN_pseudo_rand(y, BN_num_bits(p), 0, 0))
                goto end;
            if (BN_ucmp(y, p) >= 0) {
                if (!(p->neg ? BN_add : BN_sub) (y, y, p))
                    goto end;
            }
            /* now 0 <= y < |p| */
            if (BN_is_zero(y))
                if (!BN_set_word(y, i))
                    goto end;
        }

        r = BN_kronecker(y, q, ctx); /* here 'q' is |p| */
        if (r < -1)
            goto end;
        if (r == 0) {
            /* m divides p */
            BNerr(BN_F_BN_MOD_SQRT, BN_R_P_IS_NOT_PRIME);
            goto end;
        }
    }
    while (r == 1 && ++i < 82);

    if (r != -1) {
        /*
         * Many rounds and still no non-square -- this is more likely a bug
         * than just bad luck. Even if p is not prime, we should have found
         * some y such that r == -1.
         */
        BNerr(BN_F_BN_MOD_SQRT, BN_R_TOO_MANY_ITERATIONS);
        goto end;
    }

    /* Here's our actual 'q': */
    if (!BN_rshift(q, q, e))
        goto end;

    /*
     * Now that we have some non-square, we can find an element of order 2^e
     * by computing its q'th power.
     */
    if (!BN_mod_exp(y, y, q, p, ctx))
        goto end;
    if (BN_is_one(y)) {
        BNerr(BN_F_BN_MOD_SQRT, BN_R_P_IS_NOT_PRIME);
        goto end;
    }

    /*-
     * Now we know that (if  p  is indeed prime) there is an integer
     * k,  0 <= k < 2^e,  such that
     *
     *      a^q * y^k == 1   (mod p).
     *
     * As  a^q  is a square and  y  is not,  k  must be even.
     * q+1  is even, too, so there is an element
     *
     *     X := a^((q+1)/2) * y^(k/2),
     *
     * and it satisfies
     *
     *     X^2 = a^q * a     * y^k
     *         = a,
     *
     * so it is the square root that we are looking for.
     */

    /* t := (q-1)/2  (note that  q  is odd) */
    if (!BN_rshift1(t, q))
        goto end;

    /* x := a^((q-1)/2) */
    if (BN_is_zero(t)) {        /* special case: p = 2^e + 1 */
        if (!BN_nnmod(t, A, p, ctx))
            goto end;
        if (BN_is_zero(t)) {
            /* special case: a == 0  (mod p) */
            BN_zero(ret);
            err = 0;
            goto end;
        } else if (!BN_one(x))
            goto end;
    } else {
        if (!BN_mod_exp(x, A, t, p, ctx))
            goto end;
        if (BN_is_zero(x)) {
            /* special case: a == 0  (mod p) */
            BN_zero(ret);
            err = 0;
            goto end;
        }
    }

    /* b := a*x^2  (= a^q) */
    if (!BN_mod_sqr(b, x, p, ctx))
        goto end;
    if (!BN_mod_mul(b, b, A, p, ctx))
        goto end;

    /* x := a*x    (= a^((q+1)/2)) */
    if (!BN_mod_mul(x, x, A, p, ctx))
        goto end;

    while (1) {
        /*-
         * Now  b  is  a^q * y^k  for some even  k  (0 <= k < 2^E
         * where  E  refers to the original value of  e,  which we
         * don't keep in a variable),  and  x  is  a^((q+1)/2) * y^(k/2).
         *
         * We have  a*b = x^2,
         *    y^2^(e-1) = -1,
         *    b^2^(e-1) = 1.
         */

        if (BN_is_one(b)) {
            if (!BN_copy(ret, x))
                goto end;
            err = 0;
            goto vrfy;
        }

        /* find smallest  i  such that  b^(2^i) = 1 */
        i = 1;
        if (!BN_mod_sqr(t, b, p, ctx))
            goto end;
        while (!BN_is_one(t)) {
            i++;
            if (i == e) {
                BNerr(BN_F_BN_MOD_SQRT, BN_R_NOT_A_SQUARE);
                goto end;
            }
            if (!BN_mod_mul(t, t, t, p, ctx))
                goto end;
        }

        /* t := y^2^(e - i - 1) */
        if (!BN_copy(t, y))
            goto end;
        for (j = e - i - 1; j > 0; j--) {
            if (!BN_mod_sqr(t, t, p, ctx))
                goto end;
        }
        if (!BN_mod_mul(y, t, t, p, ctx))
            goto end;
        if (!BN_mod_mul(x, x, t, p, ctx))
            goto end;
        if (!BN_mod_mul(b, b, y, p, ctx))
            goto end;
        e = i;
    }

 vrfy:
    if (!err) {
        /*
         * verify the result -- the input might have been not a square (test
         * added in 0.9.8)
         */

        if (!BN_mod_sqr(x, ret, p, ctx))
            err = 1;

        if (!err && 0 != BN_cmp(x, A)) {
            BNerr(BN_F_BN_MOD_SQRT, BN_R_NOT_A_SQUARE);
            err = 1;
        }
    }

 end:
    if (err) {
        if (ret != NULL && ret != in) {
            BN_clear_free(ret);
        }
        ret = NULL;
    }
    BN_CTX_end(ctx);
    bn_check_top(ret);
    return ret;
}
/* crypto/bn/bn_word.c */
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
// #include "bn_lcl.h"

BN_ULONG BN_mod_word(const BIGNUM *a, BN_ULONG w)
{
#ifndef BN_LLONG
    BN_ULONG ret = 0;
#else
    BN_ULLONG ret = 0;
#endif
    int i;

    if (w == 0)
        return (BN_ULONG)-1;

#ifndef BN_LLONG
    /*
     * If |w| is too long and we don't have BN_ULLONG then we need to fall
     * back to using BN_div_word
     */
    if (w > ((BN_ULONG)1 << BN_BITS4)) {
        BIGNUM *tmp = BN_dup(a);
        if (tmp == NULL)
            return (BN_ULONG)-1;

        ret = BN_div_word(tmp, w);
        BN_free(tmp);

        return ret;
    }
#endif

    bn_check_top(a);
    w &= BN_MASK2;
    for (i = a->top - 1; i >= 0; i--) {
#ifndef BN_LLONG
        /*
         * We can assume here that | w <= ((BN_ULONG)1 << BN_BITS4) | and so
         * | ret < ((BN_ULONG)1 << BN_BITS4) | and therefore the shifts here are
         * safe and will not overflow
         */
        ret = ((ret << BN_BITS4) | ((a->d[i] >> BN_BITS4) & BN_MASK2l)) % w;
        ret = ((ret << BN_BITS4) | (a->d[i] & BN_MASK2l)) % w;
#else
        ret = (BN_ULLONG) (((ret << (BN_ULLONG) BN_BITS2) | a->d[i]) %
                           (BN_ULLONG) w);
#endif
    }
    return ((BN_ULONG)ret);
}

BN_ULONG BN_div_word(BIGNUM *a, BN_ULONG w)
{
    BN_ULONG ret = 0;
    int i, j;

    bn_check_top(a);
    w &= BN_MASK2;

    if (!w)
        /* actually this an error (division by zero) */
        return (BN_ULONG)-1;
    if (a->top == 0)
        return 0;

    /* normalize input (so bn_div_words doesn't complain) */
    j = BN_BITS2 - BN_num_bits_word(w);
    w <<= j;
    if (!BN_lshift(a, a, j))
        return (BN_ULONG)-1;

    for (i = a->top - 1; i >= 0; i--) {
        BN_ULONG l, d;

        l = a->d[i];
        d = bn_div_words(ret, l, w);
        ret = (l - ((d * w) & BN_MASK2)) & BN_MASK2;
        a->d[i] = d;
    }
    if ((a->top > 0) && (a->d[a->top - 1] == 0))
        a->top--;
    ret >>= j;
    bn_check_top(a);
    return (ret);
}

int BN_add_word(BIGNUM *a, BN_ULONG w)
{
    BN_ULONG l;
    int i;

    bn_check_top(a);
    w &= BN_MASK2;

    /* degenerate case: w is zero */
    if (!w)
        return 1;
    /* degenerate case: a is zero */
    if (BN_is_zero(a))
        return BN_set_word(a, w);
    /* handle 'a' when negative */
    if (a->neg) {
        a->neg = 0;
        i = BN_sub_word(a, w);
        if (!BN_is_zero(a))
            a->neg = !(a->neg);
        return (i);
    }
    for (i = 0; w != 0 && i < a->top; i++) {
        a->d[i] = l = (a->d[i] + w) & BN_MASK2;
        w = (w > l) ? 1 : 0;
    }
    if (w && i == a->top) {
        if (bn_wexpand(a, a->top + 1) == NULL)
            return 0;
        a->top++;
        a->d[i] = w;
    }
    bn_check_top(a);
    return (1);
}

int BN_sub_word(BIGNUM *a, BN_ULONG w)
{
    int i;

    bn_check_top(a);
    w &= BN_MASK2;

    /* degenerate case: w is zero */
    if (!w)
        return 1;
    /* degenerate case: a is zero */
    if (BN_is_zero(a)) {
        i = BN_set_word(a, w);
        if (i != 0)
            BN_set_negative(a, 1);
        return i;
    }
    /* handle 'a' when negative */
    if (a->neg) {
        a->neg = 0;
        i = BN_add_word(a, w);
        a->neg = 1;
        return (i);
    }

    if ((a->top == 1) && (a->d[0] < w)) {
        a->d[0] = w - a->d[0];
        a->neg = 1;
        return (1);
    }
    i = 0;
    for (;;) {
        if (a->d[i] >= w) {
            a->d[i] -= w;
            break;
        } else {
            a->d[i] = (a->d[i] - w) & BN_MASK2;
            i++;
            w = 1;
        }
    }
    if ((a->d[i] == 0) && (i == (a->top - 1)))
        a->top--;
    bn_check_top(a);
    return (1);
}

int BN_mul_word(BIGNUM *a, BN_ULONG w)
{
    BN_ULONG ll;

    bn_check_top(a);
    w &= BN_MASK2;
    if (a->top) {
        if (w == 0)
            BN_zero(a);
        else {
            ll = bn_mul_words(a->d, a->d, a->top, w);
            if (ll) {
                if (bn_wexpand(a, a->top + 1) == NULL)
                    return (0);
                a->d[a->top++] = ll;
            }
        }
    }
    bn_check_top(a);
    return (1);
}
/* bn_x931p.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 2005.
 */
/* ====================================================================
 * Copyright (c) 2005-2018 The OpenSSL Project.  All rights reserved.
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
// #include "bn.h"

/* X9.31 routines for prime derivation */

/*
 * X9.31 prime derivation. This is used to generate the primes pi (p1, p2,
 * q1, q2) from a parameter Xpi by checking successive odd integers.
 */

static int bn_x931_derive_pi(BIGNUM *pi, const BIGNUM *Xpi, BN_CTX *ctx,
                             BN_GENCB *cb)
{
    int i = 0;
    if (!BN_copy(pi, Xpi))
        return 0;
    if (!BN_is_odd(pi) && !BN_add_word(pi, 1))
        return 0;
    for (;;) {
        i++;
        BN_GENCB_call(cb, 0, i);
        /* NB 27 MR is specificed in X9.31 */
        if (BN_is_prime_fasttest_ex(pi, 27, ctx, 1, cb))
            break;
        if (!BN_add_word(pi, 2))
            return 0;
    }
    BN_GENCB_call(cb, 2, i);
    return 1;
}

/*
 * This is the main X9.31 prime derivation function. From parameters Xp1, Xp2
 * and Xp derive the prime p. If the parameters p1 or p2 are not NULL they
 * will be returned too: this is needed for testing.
 */

int BN_X931_derive_prime_ex(BIGNUM *p, BIGNUM *p1, BIGNUM *p2,
                            const BIGNUM *Xp, const BIGNUM *Xp1,
                            const BIGNUM *Xp2, const BIGNUM *e, BN_CTX *ctx,
                            BN_GENCB *cb)
{
    int ret = 0;

    BIGNUM *t, *p1p2, *pm1;

    /* Only even e supported */
    if (!BN_is_odd(e))
        return 0;

    BN_CTX_start(ctx);
    if (!p1)
        p1 = BN_CTX_get(ctx);

    if (!p2)
        p2 = BN_CTX_get(ctx);

    t = BN_CTX_get(ctx);

    p1p2 = BN_CTX_get(ctx);

    pm1 = BN_CTX_get(ctx);

    if (!bn_x931_derive_pi(p1, Xp1, ctx, cb))
        goto err;

    if (!bn_x931_derive_pi(p2, Xp2, ctx, cb))
        goto err;

    if (!BN_mul(p1p2, p1, p2, ctx))
        goto err;

    /* First set p to value of Rp */

    if (!BN_mod_inverse(p, p2, p1, ctx))
        goto err;

    if (!BN_mul(p, p, p2, ctx))
        goto err;

    if (!BN_mod_inverse(t, p1, p2, ctx))
        goto err;

    if (!BN_mul(t, t, p1, ctx))
        goto err;

    if (!BN_sub(p, p, t))
        goto err;

    if (p->neg && !BN_add(p, p, p1p2))
        goto err;

    /* p now equals Rp */

    if (!BN_mod_sub(p, p, Xp, p1p2, ctx))
        goto err;

    if (!BN_add(p, p, Xp))
        goto err;

    /* p now equals Yp0 */

    for (;;) {
        int i = 1;
        BN_GENCB_call(cb, 0, i++);
        if (!BN_copy(pm1, p))
            goto err;
        if (!BN_sub_word(pm1, 1))
            goto err;
        if (!BN_gcd(t, pm1, e, ctx))
            goto err;
        if (BN_is_one(t)
            /*
             * X9.31 specifies 8 MR and 1 Lucas test or any prime test
             * offering similar or better guarantees 50 MR is considerably
             * better.
             */
            && BN_is_prime_fasttest_ex(p, 50, ctx, 1, cb))
            break;
        if (!BN_add(p, p, p1p2))
            goto err;
    }

    BN_GENCB_call(cb, 3, 0);

    ret = 1;

 err:

    BN_CTX_end(ctx);

    return ret;
}

/*
 * Generate pair of paramters Xp, Xq for X9.31 prime generation. Note: nbits
 * paramter is sum of number of bits in both.
 */

int BN_X931_generate_Xpq(BIGNUM *Xp, BIGNUM *Xq, int nbits, BN_CTX *ctx)
{
    BIGNUM *t;
    int i;
    /*
     * Number of bits for each prime is of the form 512+128s for s = 0, 1,
     * ...
     */
    if ((nbits < 1024) || (nbits & 0xff))
        return 0;
    nbits >>= 1;
    /*
     * The random value Xp must be between sqrt(2) * 2^(nbits-1) and 2^nbits
     * - 1. By setting the top two bits we ensure that the lower bound is
     * exceeded.
     */
    if (!BN_rand(Xp, nbits, 1, 0))
        goto err;

    BN_CTX_start(ctx);
    t = BN_CTX_get(ctx);
    if (t == NULL)
        goto err;

    for (i = 0; i < 1000; i++) {
        if (!BN_rand(Xq, nbits, 1, 0))
            goto err;

        /* Check that |Xp - Xq| > 2^(nbits - 100) */
        if (!BN_sub(t, Xp, Xq))
            goto err;
        if (BN_num_bits(t) > (nbits - 100))
            break;
    }

    BN_CTX_end(ctx);

    if (i < 1000)
        return 1;

    return 0;

 err:
    BN_CTX_end(ctx);
    return 0;
}

/*
 * Generate primes using X9.31 algorithm. Of the values p, p1, p2, Xp1 and
 * Xp2 only 'p' needs to be non-NULL. If any of the others are not NULL the
 * relevant parameter will be stored in it. Due to the fact that |Xp - Xq| >
 * 2^(nbits - 100) must be satisfied Xp and Xq are generated using the
 * previous function and supplied as input.
 */

int BN_X931_generate_prime_ex(BIGNUM *p, BIGNUM *p1, BIGNUM *p2,
                              BIGNUM *Xp1, BIGNUM *Xp2,
                              const BIGNUM *Xp,
                              const BIGNUM *e, BN_CTX *ctx, BN_GENCB *cb)
{
    int ret = 0;

    BN_CTX_start(ctx);
    if (Xp1 == NULL)
        Xp1 = BN_CTX_get(ctx);
    if (Xp2 == NULL)
        Xp2 = BN_CTX_get(ctx);
    if (Xp1 == NULL || Xp2 == NULL)
        goto error;

    if (!BN_rand(Xp1, 101, 0, 0))
        goto error;
    if (!BN_rand(Xp2, 101, 0, 0))
        goto error;
    if (!BN_X931_derive_prime_ex(p, p1, p2, Xp, Xp1, Xp2, e, ctx, cb))
        goto error;

    ret = 1;

 error:
    BN_CTX_end(ctx);

    return ret;

}
