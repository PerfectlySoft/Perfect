/* crypto/bio/bf_buff.c */
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
#include <errno.h>
#include "cryptlib.h"
#include "bio.h"

static int buffer_write(BIO *h, const char *buf, int num);
static int buffer_read(BIO *h, char *buf, int size);
static int buffer_puts(BIO *h, const char *str);
static int buffer_gets(BIO *h, char *str, int size);
static long buffer_ctrl(BIO *h, int cmd, long arg1, void *arg2);
static int buffer_new(BIO *h);
static int buffer_free(BIO *data);
static long buffer_callback_ctrl(BIO *h, int cmd, bio_info_cb *fp);
#define DEFAULT_BUFFER_SIZE     4096

static BIO_METHOD methods_buffer = {
    BIO_TYPE_BUFFER,
    "buffer",
    buffer_write,
    buffer_read,
    buffer_puts,
    buffer_gets,
    buffer_ctrl,
    buffer_new,
    buffer_free,
    buffer_callback_ctrl,
};

BIO_METHOD *BIO_f_buffer(void)
{
    return (&methods_buffer);
}

static int buffer_new(BIO *bi)
{
    BIO_F_BUFFER_CTX *ctx;

    ctx = (BIO_F_BUFFER_CTX *)OPENSSL_malloc(sizeof(BIO_F_BUFFER_CTX));
    if (ctx == NULL)
        return (0);
    ctx->ibuf = (char *)OPENSSL_malloc(DEFAULT_BUFFER_SIZE);
    if (ctx->ibuf == NULL) {
        OPENSSL_free(ctx);
        return (0);
    }
    ctx->obuf = (char *)OPENSSL_malloc(DEFAULT_BUFFER_SIZE);
    if (ctx->obuf == NULL) {
        OPENSSL_free(ctx->ibuf);
        OPENSSL_free(ctx);
        return (0);
    }
    ctx->ibuf_size = DEFAULT_BUFFER_SIZE;
    ctx->obuf_size = DEFAULT_BUFFER_SIZE;
    ctx->ibuf_len = 0;
    ctx->ibuf_off = 0;
    ctx->obuf_len = 0;
    ctx->obuf_off = 0;

    bi->init = 1;
    bi->ptr = (char *)ctx;
    bi->flags = 0;
    return (1);
}

static int buffer_free(BIO *a)
{
    BIO_F_BUFFER_CTX *b;

    if (a == NULL)
        return (0);
    b = (BIO_F_BUFFER_CTX *)a->ptr;
    if (b->ibuf != NULL)
        OPENSSL_free(b->ibuf);
    if (b->obuf != NULL)
        OPENSSL_free(b->obuf);
    OPENSSL_free(a->ptr);
    a->ptr = NULL;
    a->init = 0;
    a->flags = 0;
    return (1);
}

static int buffer_read(BIO *b, char *out, int outl)
{
    int i, num = 0;
    BIO_F_BUFFER_CTX *ctx;

    if (out == NULL)
        return (0);
    ctx = (BIO_F_BUFFER_CTX *)b->ptr;

    if ((ctx == NULL) || (b->next_bio == NULL))
        return (0);
    num = 0;
    BIO_clear_retry_flags(b);

 start:
    i = ctx->ibuf_len;
    /* If there is stuff left over, grab it */
    if (i != 0) {
        if (i > outl)
            i = outl;
        memcpy(out, &(ctx->ibuf[ctx->ibuf_off]), i);
        ctx->ibuf_off += i;
        ctx->ibuf_len -= i;
        num += i;
        if (outl == i)
            return (num);
        outl -= i;
        out += i;
    }

    /*
     * We may have done a partial read. try to do more. We have nothing in
     * the buffer. If we get an error and have read some data, just return it
     * and let them retry to get the error again. copy direct to parent
     * address space
     */
    if (outl > ctx->ibuf_size) {
        for (;;) {
            i = BIO_read(b->next_bio, out, outl);
            if (i <= 0) {
                BIO_copy_next_retry(b);
                if (i < 0)
                    return ((num > 0) ? num : i);
                if (i == 0)
                    return (num);
            }
            num += i;
            if (outl == i)
                return (num);
            out += i;
            outl -= i;
        }
    }
    /* else */

    /* we are going to be doing some buffering */
    i = BIO_read(b->next_bio, ctx->ibuf, ctx->ibuf_size);
    if (i <= 0) {
        BIO_copy_next_retry(b);
        if (i < 0)
            return ((num > 0) ? num : i);
        if (i == 0)
            return (num);
    }
    ctx->ibuf_off = 0;
    ctx->ibuf_len = i;

    /* Lets re-read using ourselves :-) */
    goto start;
}

static int buffer_write(BIO *b, const char *in, int inl)
{
    int i, num = 0;
    BIO_F_BUFFER_CTX *ctx;

    if ((in == NULL) || (inl <= 0))
        return (0);
    ctx = (BIO_F_BUFFER_CTX *)b->ptr;
    if ((ctx == NULL) || (b->next_bio == NULL))
        return (0);

    BIO_clear_retry_flags(b);
 start:
    i = ctx->obuf_size - (ctx->obuf_len + ctx->obuf_off);
    /* add to buffer and return */
    if (i >= inl) {
        memcpy(&(ctx->obuf[ctx->obuf_off + ctx->obuf_len]), in, inl);
        ctx->obuf_len += inl;
        return (num + inl);
    }
    /* else */
    /* stuff already in buffer, so add to it first, then flush */
    if (ctx->obuf_len != 0) {
        if (i > 0) {            /* lets fill it up if we can */
            memcpy(&(ctx->obuf[ctx->obuf_off + ctx->obuf_len]), in, i);
            in += i;
            inl -= i;
            num += i;
            ctx->obuf_len += i;
        }
        /* we now have a full buffer needing flushing */
        for (;;) {
            i = BIO_write(b->next_bio, &(ctx->obuf[ctx->obuf_off]),
                          ctx->obuf_len);
            if (i <= 0) {
                BIO_copy_next_retry(b);

                if (i < 0)
                    return ((num > 0) ? num : i);
                if (i == 0)
                    return (num);
            }
            ctx->obuf_off += i;
            ctx->obuf_len -= i;
            if (ctx->obuf_len == 0)
                break;
        }
    }
    /*
     * we only get here if the buffer has been flushed and we still have
     * stuff to write
     */
    ctx->obuf_off = 0;

    /* we now have inl bytes to write */
    while (inl >= ctx->obuf_size) {
        i = BIO_write(b->next_bio, in, inl);
        if (i <= 0) {
            BIO_copy_next_retry(b);
            if (i < 0)
                return ((num > 0) ? num : i);
            if (i == 0)
                return (num);
        }
        num += i;
        in += i;
        inl -= i;
        if (inl == 0)
            return (num);
    }

    /*
     * copy the rest into the buffer since we have only a small amount left
     */
    goto start;
}

static long buffer_ctrl(BIO *b, int cmd, long num, void *ptr)
{
    BIO *dbio;
    BIO_F_BUFFER_CTX *ctx;
    long ret = 1;
    char *p1, *p2;
    int r, i, *ip;
    int ibs, obs;

    ctx = (BIO_F_BUFFER_CTX *)b->ptr;

    switch (cmd) {
    case BIO_CTRL_RESET:
        ctx->ibuf_off = 0;
        ctx->ibuf_len = 0;
        ctx->obuf_off = 0;
        ctx->obuf_len = 0;
        if (b->next_bio == NULL)
            return (0);
        ret = BIO_ctrl(b->next_bio, cmd, num, ptr);
        break;
    case BIO_CTRL_INFO:
        ret = (long)ctx->obuf_len;
        break;
    case BIO_C_GET_BUFF_NUM_LINES:
        ret = 0;
        p1 = ctx->ibuf;
        for (i = 0; i < ctx->ibuf_len; i++) {
            if (p1[ctx->ibuf_off + i] == '\n')
                ret++;
        }
        break;
    case BIO_CTRL_WPENDING:
        ret = (long)ctx->obuf_len;
        if (ret == 0) {
            if (b->next_bio == NULL)
                return (0);
            ret = BIO_ctrl(b->next_bio, cmd, num, ptr);
        }
        break;
    case BIO_CTRL_PENDING:
        ret = (long)ctx->ibuf_len;
        if (ret == 0) {
            if (b->next_bio == NULL)
                return (0);
            ret = BIO_ctrl(b->next_bio, cmd, num, ptr);
        }
        break;
    case BIO_C_SET_BUFF_READ_DATA:
        if (num > ctx->ibuf_size) {
            p1 = OPENSSL_malloc((int)num);
            if (p1 == NULL)
                goto malloc_error;
            if (ctx->ibuf != NULL)
                OPENSSL_free(ctx->ibuf);
            ctx->ibuf = p1;
        }
        ctx->ibuf_off = 0;
        ctx->ibuf_len = (int)num;
        memcpy(ctx->ibuf, ptr, (int)num);
        ret = 1;
        break;
    case BIO_C_SET_BUFF_SIZE:
        if (ptr != NULL) {
            ip = (int *)ptr;
            if (*ip == 0) {
                ibs = (int)num;
                obs = ctx->obuf_size;
            } else {            /* if (*ip == 1) */

                ibs = ctx->ibuf_size;
                obs = (int)num;
            }
        } else {
            ibs = (int)num;
            obs = (int)num;
        }
        p1 = ctx->ibuf;
        p2 = ctx->obuf;
        if ((ibs > DEFAULT_BUFFER_SIZE) && (ibs != ctx->ibuf_size)) {
            p1 = (char *)OPENSSL_malloc((int)num);
            if (p1 == NULL)
                goto malloc_error;
        }
        if ((obs > DEFAULT_BUFFER_SIZE) && (obs != ctx->obuf_size)) {
            p2 = (char *)OPENSSL_malloc((int)num);
            if (p2 == NULL) {
                if (p1 != ctx->ibuf)
                    OPENSSL_free(p1);
                goto malloc_error;
            }
        }
        if (ctx->ibuf != p1) {
            OPENSSL_free(ctx->ibuf);
            ctx->ibuf = p1;
            ctx->ibuf_off = 0;
            ctx->ibuf_len = 0;
            ctx->ibuf_size = ibs;
        }
        if (ctx->obuf != p2) {
            OPENSSL_free(ctx->obuf);
            ctx->obuf = p2;
            ctx->obuf_off = 0;
            ctx->obuf_len = 0;
            ctx->obuf_size = obs;
        }
        break;
    case BIO_C_DO_STATE_MACHINE:
        if (b->next_bio == NULL)
            return (0);
        BIO_clear_retry_flags(b);
        ret = BIO_ctrl(b->next_bio, cmd, num, ptr);
        BIO_copy_next_retry(b);
        break;

    case BIO_CTRL_FLUSH:
        if (b->next_bio == NULL)
            return (0);
        if (ctx->obuf_len <= 0) {
            ret = BIO_ctrl(b->next_bio, cmd, num, ptr);
            break;
        }

        for (;;) {
            BIO_clear_retry_flags(b);
            if (ctx->obuf_len > 0) {
                r = BIO_write(b->next_bio,
                              &(ctx->obuf[ctx->obuf_off]), ctx->obuf_len);
#if 0
                fprintf(stderr, "FLUSH [%3d] %3d -> %3d\n", ctx->obuf_off,
                        ctx->obuf_len, r);
#endif
                BIO_copy_next_retry(b);
                if (r <= 0)
                    return ((long)r);
                ctx->obuf_off += r;
                ctx->obuf_len -= r;
            } else {
                ctx->obuf_len = 0;
                ctx->obuf_off = 0;
                ret = 1;
                break;
            }
        }
        ret = BIO_ctrl(b->next_bio, cmd, num, ptr);
        break;
    case BIO_CTRL_DUP:
        dbio = (BIO *)ptr;
        if (!BIO_set_read_buffer_size(dbio, ctx->ibuf_size) ||
            !BIO_set_write_buffer_size(dbio, ctx->obuf_size))
            ret = 0;
        break;
    default:
        if (b->next_bio == NULL)
            return (0);
        ret = BIO_ctrl(b->next_bio, cmd, num, ptr);
        break;
    }
    return (ret);
 malloc_error:
    BIOerr(BIO_F_BUFFER_CTRL, ERR_R_MALLOC_FAILURE);
    return (0);
}

static long buffer_callback_ctrl(BIO *b, int cmd, bio_info_cb *fp)
{
    long ret = 1;

    if (b->next_bio == NULL)
        return (0);
    switch (cmd) {
    default:
        ret = BIO_callback_ctrl(b->next_bio, cmd, fp);
        break;
    }
    return (ret);
}

static int buffer_gets(BIO *b, char *buf, int size)
{
    BIO_F_BUFFER_CTX *ctx;
    int num = 0, i, flag;
    char *p;

    ctx = (BIO_F_BUFFER_CTX *)b->ptr;
    size--;                     /* reserve space for a '\0' */
    BIO_clear_retry_flags(b);

    for (;;) {
        if (ctx->ibuf_len > 0) {
            p = &(ctx->ibuf[ctx->ibuf_off]);
            flag = 0;
            for (i = 0; (i < ctx->ibuf_len) && (i < size); i++) {
                *(buf++) = p[i];
                if (p[i] == '\n') {
                    flag = 1;
                    i++;
                    break;
                }
            }
            num += i;
            size -= i;
            ctx->ibuf_len -= i;
            ctx->ibuf_off += i;
            if (flag || size == 0) {
                *buf = '\0';
                return (num);
            }
        } else {                /* read another chunk */

            i = BIO_read(b->next_bio, ctx->ibuf, ctx->ibuf_size);
            if (i <= 0) {
                BIO_copy_next_retry(b);
                *buf = '\0';
                if (i < 0)
                    return ((num > 0) ? num : i);
                if (i == 0)
                    return (num);
            }
            ctx->ibuf_len = i;
            ctx->ibuf_off = 0;
        }
    }
}

static int buffer_puts(BIO *b, const char *str)
{
    return (buffer_write(b, str, strlen(str)));
}
/* crypto/bf/bf_cfb64.c */
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

#include "blowfish.h"
#include "bf_locl.h"

/*
 * The input and output encrypted as though 64bit cfb mode is being used.
 * The extra state information to record how much of the 64bit block we have
 * used is contained in *num;
 */

void BF_cfb64_encrypt(const unsigned char *in, unsigned char *out,
                      long length, const BF_KEY *schedule,
                      unsigned char *ivec, int *num, int encrypt)
{
    register BF_LONG v0, v1, t;
    register int n = *num;
    register long l = length;
    BF_LONG ti[2];
    unsigned char *iv, c, cc;

    iv = (unsigned char *)ivec;
    if (encrypt) {
        while (l--) {
            if (n == 0) {
                n2l(iv, v0);
                ti[0] = v0;
                n2l(iv, v1);
                ti[1] = v1;
                BF_encrypt((BF_LONG *)ti, schedule);
                iv = (unsigned char *)ivec;
                t = ti[0];
                l2n(t, iv);
                t = ti[1];
                l2n(t, iv);
                iv = (unsigned char *)ivec;
            }
            c = *(in++) ^ iv[n];
            *(out++) = c;
            iv[n] = c;
            n = (n + 1) & 0x07;
        }
    } else {
        while (l--) {
            if (n == 0) {
                n2l(iv, v0);
                ti[0] = v0;
                n2l(iv, v1);
                ti[1] = v1;
                BF_encrypt((BF_LONG *)ti, schedule);
                iv = (unsigned char *)ivec;
                t = ti[0];
                l2n(t, iv);
                t = ti[1];
                l2n(t, iv);
                iv = (unsigned char *)ivec;
            }
            cc = *(in++);
            c = iv[n];
            iv[n] = cc;
            *(out++) = c ^ cc;
            n = (n + 1) & 0x07;
        }
    }
    v0 = v1 = ti[0] = ti[1] = t = c = cc = 0;
    *num = n;
}
/* crypto/bf/bf_ecb.c */
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

// #include "blowfish.h"
// #include "bf_locl.h"
#include "opensslv.h"

/*
 * Blowfish as implemented from 'Blowfish: Springer-Verlag paper' (From
 * LECTURE NOTES IN COMPUTER SCIENCE 809, FAST SOFTWARE ENCRYPTION, CAMBRIDGE
 * SECURITY WORKSHOP, CAMBRIDGE, U.K., DECEMBER 9-11, 1993)
 */

const char BF_version[] = "Blowfish" OPENSSL_VERSION_PTEXT;

const char *BF_options(void)
{
#ifdef BF_PTR
    return ("blowfish(ptr)");
#elif defined(BF_PTR2)
    return ("blowfish(ptr2)");
#else
    return ("blowfish(idx)");
#endif
}

void BF_ecb_encrypt(const unsigned char *in, unsigned char *out,
                    const BF_KEY *key, int encrypt)
{
    BF_LONG l, d[2];

    n2l(in, l);
    d[0] = l;
    n2l(in, l);
    d[1] = l;
    if (encrypt)
        BF_encrypt(d, key);
    else
        BF_decrypt(d, key);
    l = d[0];
    l2n(l, out);
    l = d[1];
    l2n(l, out);
    l = d[0] = d[1] = 0;
}
/* crypto/bf/bf_enc.c */
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

// #include "blowfish.h"
// #include "bf_locl.h"

/*
 * Blowfish as implemented from 'Blowfish: Springer-Verlag paper' (From
 * LECTURE NOTES IN COMPUTER SCIENCE 809, FAST SOFTWARE ENCRYPTION, CAMBRIDGE
 * SECURITY WORKSHOP, CAMBRIDGE, U.K., DECEMBER 9-11, 1993)
 */

#if (BF_ROUNDS != 16) && (BF_ROUNDS != 20)
# error If you set BF_ROUNDS to some value other than 16 or 20, you will have \
to modify the code.
#endif

void BF_encrypt(BF_LONG *data, const BF_KEY *key)
{
#ifndef BF_PTR2
    register BF_LONG l, r;
    register const BF_LONG *p, *s;

    p = key->P;
    s = &(key->S[0]);
    l = data[0];
    r = data[1];

    l ^= p[0];
    BF_ENC(r, l, s, p[1]);
    BF_ENC(l, r, s, p[2]);
    BF_ENC(r, l, s, p[3]);
    BF_ENC(l, r, s, p[4]);
    BF_ENC(r, l, s, p[5]);
    BF_ENC(l, r, s, p[6]);
    BF_ENC(r, l, s, p[7]);
    BF_ENC(l, r, s, p[8]);
    BF_ENC(r, l, s, p[9]);
    BF_ENC(l, r, s, p[10]);
    BF_ENC(r, l, s, p[11]);
    BF_ENC(l, r, s, p[12]);
    BF_ENC(r, l, s, p[13]);
    BF_ENC(l, r, s, p[14]);
    BF_ENC(r, l, s, p[15]);
    BF_ENC(l, r, s, p[16]);
# if BF_ROUNDS == 20
    BF_ENC(r, l, s, p[17]);
    BF_ENC(l, r, s, p[18]);
    BF_ENC(r, l, s, p[19]);
    BF_ENC(l, r, s, p[20]);
# endif
    r ^= p[BF_ROUNDS + 1];

    data[1] = l & 0xffffffffL;
    data[0] = r & 0xffffffffL;
#else
    register BF_LONG l, r, t, *k;

    l = data[0];
    r = data[1];
    k = (BF_LONG *)key;

    l ^= k[0];
    BF_ENC(r, l, k, 1);
    BF_ENC(l, r, k, 2);
    BF_ENC(r, l, k, 3);
    BF_ENC(l, r, k, 4);
    BF_ENC(r, l, k, 5);
    BF_ENC(l, r, k, 6);
    BF_ENC(r, l, k, 7);
    BF_ENC(l, r, k, 8);
    BF_ENC(r, l, k, 9);
    BF_ENC(l, r, k, 10);
    BF_ENC(r, l, k, 11);
    BF_ENC(l, r, k, 12);
    BF_ENC(r, l, k, 13);
    BF_ENC(l, r, k, 14);
    BF_ENC(r, l, k, 15);
    BF_ENC(l, r, k, 16);
# if BF_ROUNDS == 20
    BF_ENC(r, l, k, 17);
    BF_ENC(l, r, k, 18);
    BF_ENC(r, l, k, 19);
    BF_ENC(l, r, k, 20);
# endif
    r ^= k[BF_ROUNDS + 1];

    data[1] = l & 0xffffffffL;
    data[0] = r & 0xffffffffL;
#endif
}

#ifndef BF_DEFAULT_OPTIONS

void BF_decrypt(BF_LONG *data, const BF_KEY *key)
{
# ifndef BF_PTR2
    register BF_LONG l, r;
    register const BF_LONG *p, *s;

    p = key->P;
    s = &(key->S[0]);
    l = data[0];
    r = data[1];

    l ^= p[BF_ROUNDS + 1];
#  if BF_ROUNDS == 20
    BF_ENC(r, l, s, p[20]);
    BF_ENC(l, r, s, p[19]);
    BF_ENC(r, l, s, p[18]);
    BF_ENC(l, r, s, p[17]);
#  endif
    BF_ENC(r, l, s, p[16]);
    BF_ENC(l, r, s, p[15]);
    BF_ENC(r, l, s, p[14]);
    BF_ENC(l, r, s, p[13]);
    BF_ENC(r, l, s, p[12]);
    BF_ENC(l, r, s, p[11]);
    BF_ENC(r, l, s, p[10]);
    BF_ENC(l, r, s, p[9]);
    BF_ENC(r, l, s, p[8]);
    BF_ENC(l, r, s, p[7]);
    BF_ENC(r, l, s, p[6]);
    BF_ENC(l, r, s, p[5]);
    BF_ENC(r, l, s, p[4]);
    BF_ENC(l, r, s, p[3]);
    BF_ENC(r, l, s, p[2]);
    BF_ENC(l, r, s, p[1]);
    r ^= p[0];

    data[1] = l & 0xffffffffL;
    data[0] = r & 0xffffffffL;
# else
    register BF_LONG l, r, t, *k;

    l = data[0];
    r = data[1];
    k = (BF_LONG *)key;

    l ^= k[BF_ROUNDS + 1];
#  if BF_ROUNDS == 20
    BF_ENC(r, l, k, 20);
    BF_ENC(l, r, k, 19);
    BF_ENC(r, l, k, 18);
    BF_ENC(l, r, k, 17);
#  endif
    BF_ENC(r, l, k, 16);
    BF_ENC(l, r, k, 15);
    BF_ENC(r, l, k, 14);
    BF_ENC(l, r, k, 13);
    BF_ENC(r, l, k, 12);
    BF_ENC(l, r, k, 11);
    BF_ENC(r, l, k, 10);
    BF_ENC(l, r, k, 9);
    BF_ENC(r, l, k, 8);
    BF_ENC(l, r, k, 7);
    BF_ENC(r, l, k, 6);
    BF_ENC(l, r, k, 5);
    BF_ENC(r, l, k, 4);
    BF_ENC(l, r, k, 3);
    BF_ENC(r, l, k, 2);
    BF_ENC(l, r, k, 1);
    r ^= k[0];

    data[1] = l & 0xffffffffL;
    data[0] = r & 0xffffffffL;
# endif
}

void BF_cbc_encrypt(const unsigned char *in, unsigned char *out, long length,
                    const BF_KEY *schedule, unsigned char *ivec, int encrypt)
{
    register BF_LONG tin0, tin1;
    register BF_LONG tout0, tout1, xor0, xor1;
    register long l = length;
    BF_LONG tin[2];

    if (encrypt) {
        n2l(ivec, tout0);
        n2l(ivec, tout1);
        ivec -= 8;
        for (l -= 8; l >= 0; l -= 8) {
            n2l(in, tin0);
            n2l(in, tin1);
            tin0 ^= tout0;
            tin1 ^= tout1;
            tin[0] = tin0;
            tin[1] = tin1;
            BF_encrypt(tin, schedule);
            tout0 = tin[0];
            tout1 = tin[1];
            l2n(tout0, out);
            l2n(tout1, out);
        }
        if (l != -8) {
            n2ln(in, tin0, tin1, l + 8);
            tin0 ^= tout0;
            tin1 ^= tout1;
            tin[0] = tin0;
            tin[1] = tin1;
            BF_encrypt(tin, schedule);
            tout0 = tin[0];
            tout1 = tin[1];
            l2n(tout0, out);
            l2n(tout1, out);
        }
        l2n(tout0, ivec);
        l2n(tout1, ivec);
    } else {
        n2l(ivec, xor0);
        n2l(ivec, xor1);
        ivec -= 8;
        for (l -= 8; l >= 0; l -= 8) {
            n2l(in, tin0);
            n2l(in, tin1);
            tin[0] = tin0;
            tin[1] = tin1;
            BF_decrypt(tin, schedule);
            tout0 = tin[0] ^ xor0;
            tout1 = tin[1] ^ xor1;
            l2n(tout0, out);
            l2n(tout1, out);
            xor0 = tin0;
            xor1 = tin1;
        }
        if (l != -8) {
            n2l(in, tin0);
            n2l(in, tin1);
            tin[0] = tin0;
            tin[1] = tin1;
            BF_decrypt(tin, schedule);
            tout0 = tin[0] ^ xor0;
            tout1 = tin[1] ^ xor1;
            l2nn(tout0, tout1, out, l + 8);
            xor0 = tin0;
            xor1 = tin1;
        }
        l2n(xor0, ivec);
        l2n(xor1, ivec);
    }
    tin0 = tin1 = tout0 = tout1 = xor0 = xor1 = 0;
    tin[0] = tin[1] = 0;
}

#endif
/* crypto/bio/bf_buff.c */
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
#include <errno.h>
// #include "cryptlib.h"
// #include "bio.h"
#include "evp.h"

static int linebuffer_write(BIO *h, const char *buf, int num);
static int linebuffer_read(BIO *h, char *buf, int size);
static int linebuffer_puts(BIO *h, const char *str);
static int linebuffer_gets(BIO *h, char *str, int size);
static long linebuffer_ctrl(BIO *h, int cmd, long arg1, void *arg2);
static int linebuffer_new(BIO *h);
static int linebuffer_free(BIO *data);
static long linebuffer_callback_ctrl(BIO *h, int cmd, bio_info_cb *fp);

/* A 10k maximum should be enough for most purposes */
#define DEFAULT_LINEBUFFER_SIZE 1024*10

/* #define DEBUG */

static BIO_METHOD methods_linebuffer = {
    BIO_TYPE_LINEBUFFER,
    "linebuffer",
    linebuffer_write,
    linebuffer_read,
    linebuffer_puts,
    linebuffer_gets,
    linebuffer_ctrl,
    linebuffer_new,
    linebuffer_free,
    linebuffer_callback_ctrl,
};

BIO_METHOD *BIO_f_linebuffer(void)
{
    return (&methods_linebuffer);
}

typedef struct bio_linebuffer_ctx_struct {
    char *obuf;                 /* the output char array */
    int obuf_size;              /* how big is the output buffer */
    int obuf_len;               /* how many bytes are in it */
} BIO_LINEBUFFER_CTX;

static int linebuffer_new(BIO *bi)
{
    BIO_LINEBUFFER_CTX *ctx;

    ctx = (BIO_LINEBUFFER_CTX *)OPENSSL_malloc(sizeof(BIO_LINEBUFFER_CTX));
    if (ctx == NULL)
        return (0);
    ctx->obuf = (char *)OPENSSL_malloc(DEFAULT_LINEBUFFER_SIZE);
    if (ctx->obuf == NULL) {
        OPENSSL_free(ctx);
        return (0);
    }
    ctx->obuf_size = DEFAULT_LINEBUFFER_SIZE;
    ctx->obuf_len = 0;

    bi->init = 1;
    bi->ptr = (char *)ctx;
    bi->flags = 0;
    return (1);
}

static int linebuffer_free(BIO *a)
{
    BIO_LINEBUFFER_CTX *b;

    if (a == NULL)
        return (0);
    b = (BIO_LINEBUFFER_CTX *)a->ptr;
    if (b->obuf != NULL)
        OPENSSL_free(b->obuf);
    OPENSSL_free(a->ptr);
    a->ptr = NULL;
    a->init = 0;
    a->flags = 0;
    return (1);
}

static int linebuffer_read(BIO *b, char *out, int outl)
{
    int ret = 0;

    if (out == NULL)
        return (0);
    if (b->next_bio == NULL)
        return (0);
    ret = BIO_read(b->next_bio, out, outl);
    BIO_clear_retry_flags(b);
    BIO_copy_next_retry(b);
    return (ret);
}

static int linebuffer_write(BIO *b, const char *in, int inl)
{
    int i, num = 0, foundnl;
    BIO_LINEBUFFER_CTX *ctx;

    if ((in == NULL) || (inl <= 0))
        return (0);
    ctx = (BIO_LINEBUFFER_CTX *)b->ptr;
    if ((ctx == NULL) || (b->next_bio == NULL))
        return (0);

    BIO_clear_retry_flags(b);

    do {
        const char *p;

        for (p = in; p < in + inl && *p != '\n'; p++) ;
        if (*p == '\n') {
            p++;
            foundnl = 1;
        } else
            foundnl = 0;

        /*
         * If a NL was found and we already have text in the save buffer,
         * concatenate them and write
         */
        while ((foundnl || p - in > ctx->obuf_size - ctx->obuf_len)
               && ctx->obuf_len > 0) {
            int orig_olen = ctx->obuf_len;

            i = ctx->obuf_size - ctx->obuf_len;
            if (p - in > 0) {
                if (i >= p - in) {
                    memcpy(&(ctx->obuf[ctx->obuf_len]), in, p - in);
                    ctx->obuf_len += p - in;
                    inl -= p - in;
                    num += p - in;
                    in = p;
                } else {
                    memcpy(&(ctx->obuf[ctx->obuf_len]), in, i);
                    ctx->obuf_len += i;
                    inl -= i;
                    in += i;
                    num += i;
                }
            }
#if 0
            BIO_write(b->next_bio, "<*<", 3);
#endif
            i = BIO_write(b->next_bio, ctx->obuf, ctx->obuf_len);
            if (i <= 0) {
                ctx->obuf_len = orig_olen;
                BIO_copy_next_retry(b);

#if 0
                BIO_write(b->next_bio, ">*>", 3);
#endif
                if (i < 0)
                    return ((num > 0) ? num : i);
                if (i == 0)
                    return (num);
            }
#if 0
            BIO_write(b->next_bio, ">*>", 3);
#endif
            if (i < ctx->obuf_len)
                memmove(ctx->obuf, ctx->obuf + i, ctx->obuf_len - i);
            ctx->obuf_len -= i;
        }

        /*
         * Now that the save buffer is emptied, let's write the input buffer
         * if a NL was found and there is anything to write.
         */
        if ((foundnl || p - in > ctx->obuf_size) && p - in > 0) {
#if 0
            BIO_write(b->next_bio, "<*<", 3);
#endif
            i = BIO_write(b->next_bio, in, p - in);
            if (i <= 0) {
                BIO_copy_next_retry(b);
#if 0
                BIO_write(b->next_bio, ">*>", 3);
#endif
                if (i < 0)
                    return ((num > 0) ? num : i);
                if (i == 0)
                    return (num);
            }
#if 0
            BIO_write(b->next_bio, ">*>", 3);
#endif
            num += i;
            in += i;
            inl -= i;
        }
    }
    while (foundnl && inl > 0);
    /*
     * We've written as much as we can.  The rest of the input buffer, if
     * any, is text that doesn't and with a NL and therefore needs to be
     * saved for the next trip.
     */
    if (inl > 0) {
        memcpy(&(ctx->obuf[ctx->obuf_len]), in, inl);
        ctx->obuf_len += inl;
        num += inl;
    }
    return num;
}

static long linebuffer_ctrl(BIO *b, int cmd, long num, void *ptr)
{
    BIO *dbio;
    BIO_LINEBUFFER_CTX *ctx;
    long ret = 1;
    char *p;
    int r;
    int obs;

    ctx = (BIO_LINEBUFFER_CTX *)b->ptr;

    switch (cmd) {
    case BIO_CTRL_RESET:
        ctx->obuf_len = 0;
        if (b->next_bio == NULL)
            return (0);
        ret = BIO_ctrl(b->next_bio, cmd, num, ptr);
        break;
    case BIO_CTRL_INFO:
        ret = (long)ctx->obuf_len;
        break;
    case BIO_CTRL_WPENDING:
        ret = (long)ctx->obuf_len;
        if (ret == 0) {
            if (b->next_bio == NULL)
                return (0);
            ret = BIO_ctrl(b->next_bio, cmd, num, ptr);
        }
        break;
    case BIO_C_SET_BUFF_SIZE:
        obs = (int)num;
        p = ctx->obuf;
        if ((obs > DEFAULT_LINEBUFFER_SIZE) && (obs != ctx->obuf_size)) {
            p = (char *)OPENSSL_malloc((int)num);
            if (p == NULL)
                goto malloc_error;
        }
        if (ctx->obuf != p) {
            if (ctx->obuf_len > obs) {
                ctx->obuf_len = obs;
            }
            memcpy(p, ctx->obuf, ctx->obuf_len);
            OPENSSL_free(ctx->obuf);
            ctx->obuf = p;
            ctx->obuf_size = obs;
        }
        break;
    case BIO_C_DO_STATE_MACHINE:
        if (b->next_bio == NULL)
            return (0);
        BIO_clear_retry_flags(b);
        ret = BIO_ctrl(b->next_bio, cmd, num, ptr);
        BIO_copy_next_retry(b);
        break;

    case BIO_CTRL_FLUSH:
        if (b->next_bio == NULL)
            return (0);
        if (ctx->obuf_len <= 0) {
            ret = BIO_ctrl(b->next_bio, cmd, num, ptr);
            break;
        }

        for (;;) {
            BIO_clear_retry_flags(b);
            if (ctx->obuf_len > 0) {
                r = BIO_write(b->next_bio, ctx->obuf, ctx->obuf_len);
#if 0
                fprintf(stderr, "FLUSH %3d -> %3d\n", ctx->obuf_len, r);
#endif
                BIO_copy_next_retry(b);
                if (r <= 0)
                    return ((long)r);
                if (r < ctx->obuf_len)
                    memmove(ctx->obuf, ctx->obuf + r, ctx->obuf_len - r);
                ctx->obuf_len -= r;
            } else {
                ctx->obuf_len = 0;
                ret = 1;
                break;
            }
        }
        ret = BIO_ctrl(b->next_bio, cmd, num, ptr);
        break;
    case BIO_CTRL_DUP:
        dbio = (BIO *)ptr;
        if (!BIO_set_write_buffer_size(dbio, ctx->obuf_size))
            ret = 0;
        break;
    default:
        if (b->next_bio == NULL)
            return (0);
        ret = BIO_ctrl(b->next_bio, cmd, num, ptr);
        break;
    }
    return (ret);
 malloc_error:
    BIOerr(BIO_F_LINEBUFFER_CTRL, ERR_R_MALLOC_FAILURE);
    return (0);
}

static long linebuffer_callback_ctrl(BIO *b, int cmd, bio_info_cb *fp)
{
    long ret = 1;

    if (b->next_bio == NULL)
        return (0);
    switch (cmd) {
    default:
        ret = BIO_callback_ctrl(b->next_bio, cmd, fp);
        break;
    }
    return (ret);
}

static int linebuffer_gets(BIO *b, char *buf, int size)
{
    if (b->next_bio == NULL)
        return (0);
    return (BIO_gets(b->next_bio, buf, size));
}

static int linebuffer_puts(BIO *b, const char *str)
{
    return (linebuffer_write(b, str, strlen(str)));
}
/* crypto/bio/bf_nbio.c */
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
#include <errno.h>
// #include "cryptlib.h"
#include "rand.h"
// #include "bio.h"

/*
 * BIO_put and BIO_get both add to the digest, BIO_gets returns the digest
 */

static int nbiof_write(BIO *h, const char *buf, int num);
static int nbiof_read(BIO *h, char *buf, int size);
static int nbiof_puts(BIO *h, const char *str);
static int nbiof_gets(BIO *h, char *str, int size);
static long nbiof_ctrl(BIO *h, int cmd, long arg1, void *arg2);
static int nbiof_new(BIO *h);
static int nbiof_free(BIO *data);
static long nbiof_callback_ctrl(BIO *h, int cmd, bio_info_cb *fp);
typedef struct nbio_test_st {
    /* only set if we sent a 'should retry' error */
    int lrn;
    int lwn;
} NBIO_TEST;

static BIO_METHOD methods_nbiof = {
    BIO_TYPE_NBIO_TEST,
    "non-blocking IO test filter",
    nbiof_write,
    nbiof_read,
    nbiof_puts,
    nbiof_gets,
    nbiof_ctrl,
    nbiof_new,
    nbiof_free,
    nbiof_callback_ctrl,
};

BIO_METHOD *BIO_f_nbio_test(void)
{
    return (&methods_nbiof);
}

static int nbiof_new(BIO *bi)
{
    NBIO_TEST *nt;

    if (!(nt = (NBIO_TEST *)OPENSSL_malloc(sizeof(NBIO_TEST))))
        return (0);
    nt->lrn = -1;
    nt->lwn = -1;
    bi->ptr = (char *)nt;
    bi->init = 1;
    bi->flags = 0;
    return (1);
}

static int nbiof_free(BIO *a)
{
    if (a == NULL)
        return (0);
    if (a->ptr != NULL)
        OPENSSL_free(a->ptr);
    a->ptr = NULL;
    a->init = 0;
    a->flags = 0;
    return (1);
}

static int nbiof_read(BIO *b, char *out, int outl)
{
    int ret = 0;
#if 1
    int num;
    unsigned char n;
#endif

    if (out == NULL)
        return (0);
    if (b->next_bio == NULL)
        return (0);

    BIO_clear_retry_flags(b);
#if 1
    if (RAND_bytes(&n, 1) <= 0)
        return -1;
    num = (n & 0x07);

    if (outl > num)
        outl = num;

    if (num == 0) {
        ret = -1;
        BIO_set_retry_read(b);
    } else
#endif
    {
        ret = BIO_read(b->next_bio, out, outl);
        if (ret < 0)
            BIO_copy_next_retry(b);
    }
    return (ret);
}

static int nbiof_write(BIO *b, const char *in, int inl)
{
    NBIO_TEST *nt;
    int ret = 0;
    int num;
    unsigned char n;

    if ((in == NULL) || (inl <= 0))
        return (0);
    if (b->next_bio == NULL)
        return (0);
    nt = (NBIO_TEST *)b->ptr;

    BIO_clear_retry_flags(b);

#if 1
    if (nt->lwn > 0) {
        num = nt->lwn;
        nt->lwn = 0;
    } else {
        if (RAND_bytes(&n, 1) <= 0)
            return -1;
        num = (n & 7);
    }

    if (inl > num)
        inl = num;

    if (num == 0) {
        ret = -1;
        BIO_set_retry_write(b);
    } else
#endif
    {
        ret = BIO_write(b->next_bio, in, inl);
        if (ret < 0) {
            BIO_copy_next_retry(b);
            nt->lwn = inl;
        }
    }
    return (ret);
}

static long nbiof_ctrl(BIO *b, int cmd, long num, void *ptr)
{
    long ret;

    if (b->next_bio == NULL)
        return (0);
    switch (cmd) {
    case BIO_C_DO_STATE_MACHINE:
        BIO_clear_retry_flags(b);
        ret = BIO_ctrl(b->next_bio, cmd, num, ptr);
        BIO_copy_next_retry(b);
        break;
    case BIO_CTRL_DUP:
        ret = 0L;
        break;
    default:
        ret = BIO_ctrl(b->next_bio, cmd, num, ptr);
        break;
    }
    return (ret);
}

static long nbiof_callback_ctrl(BIO *b, int cmd, bio_info_cb *fp)
{
    long ret = 1;

    if (b->next_bio == NULL)
        return (0);
    switch (cmd) {
    default:
        ret = BIO_callback_ctrl(b->next_bio, cmd, fp);
        break;
    }
    return (ret);
}

static int nbiof_gets(BIO *bp, char *buf, int size)
{
    if (bp->next_bio == NULL)
        return (0);
    return (BIO_gets(bp->next_bio, buf, size));
}

static int nbiof_puts(BIO *bp, const char *str)
{
    if (bp->next_bio == NULL)
        return (0);
    return (BIO_puts(bp->next_bio, str));
}
/* crypto/bio/bf_null.c */
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
#include <errno.h>
// #include "cryptlib.h"
// #include "bio.h"

/*
 * BIO_put and BIO_get both add to the digest, BIO_gets returns the digest
 */

static int nullf_write(BIO *h, const char *buf, int num);
static int nullf_read(BIO *h, char *buf, int size);
static int nullf_puts(BIO *h, const char *str);
static int nullf_gets(BIO *h, char *str, int size);
static long nullf_ctrl(BIO *h, int cmd, long arg1, void *arg2);
static int nullf_new(BIO *h);
static int nullf_free(BIO *data);
static long nullf_callback_ctrl(BIO *h, int cmd, bio_info_cb *fp);
static BIO_METHOD methods_nullf = {
    BIO_TYPE_NULL_FILTER,
    "NULL filter",
    nullf_write,
    nullf_read,
    nullf_puts,
    nullf_gets,
    nullf_ctrl,
    nullf_new,
    nullf_free,
    nullf_callback_ctrl,
};

BIO_METHOD *BIO_f_null(void)
{
    return (&methods_nullf);
}

static int nullf_new(BIO *bi)
{
    bi->init = 1;
    bi->ptr = NULL;
    bi->flags = 0;
    return (1);
}

static int nullf_free(BIO *a)
{
    if (a == NULL)
        return (0);
    /*-
    a->ptr=NULL;
    a->init=0;
    a->flags=0;
    */
    return (1);
}

static int nullf_read(BIO *b, char *out, int outl)
{
    int ret = 0;

    if (out == NULL)
        return (0);
    if (b->next_bio == NULL)
        return (0);
    ret = BIO_read(b->next_bio, out, outl);
    BIO_clear_retry_flags(b);
    BIO_copy_next_retry(b);
    return (ret);
}

static int nullf_write(BIO *b, const char *in, int inl)
{
    int ret = 0;

    if ((in == NULL) || (inl <= 0))
        return (0);
    if (b->next_bio == NULL)
        return (0);
    ret = BIO_write(b->next_bio, in, inl);
    BIO_clear_retry_flags(b);
    BIO_copy_next_retry(b);
    return (ret);
}

static long nullf_ctrl(BIO *b, int cmd, long num, void *ptr)
{
    long ret;

    if (b->next_bio == NULL)
        return (0);
    switch (cmd) {
    case BIO_C_DO_STATE_MACHINE:
        BIO_clear_retry_flags(b);
        ret = BIO_ctrl(b->next_bio, cmd, num, ptr);
        BIO_copy_next_retry(b);
        break;
    case BIO_CTRL_DUP:
        ret = 0L;
        break;
    default:
        ret = BIO_ctrl(b->next_bio, cmd, num, ptr);
    }
    return (ret);
}

static long nullf_callback_ctrl(BIO *b, int cmd, bio_info_cb *fp)
{
    long ret = 1;

    if (b->next_bio == NULL)
        return (0);
    switch (cmd) {
    default:
        ret = BIO_callback_ctrl(b->next_bio, cmd, fp);
        break;
    }
    return (ret);
}

static int nullf_gets(BIO *bp, char *buf, int size)
{
    if (bp->next_bio == NULL)
        return (0);
    return (BIO_gets(bp->next_bio, buf, size));
}

static int nullf_puts(BIO *bp, const char *str)
{
    if (bp->next_bio == NULL)
        return (0);
    return (BIO_puts(bp->next_bio, str));
}
/* crypto/bf/bf_ofb64.c */
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

// #include "blowfish.h"
// #include "bf_locl.h"

/*
 * The input and output encrypted as though 64bit ofb mode is being used.
 * The extra state information to record how much of the 64bit block we have
 * used is contained in *num;
 */
void BF_ofb64_encrypt(const unsigned char *in, unsigned char *out,
                      long length, const BF_KEY *schedule,
                      unsigned char *ivec, int *num)
{
    register BF_LONG v0, v1, t;
    register int n = *num;
    register long l = length;
    unsigned char d[8];
    register char *dp;
    BF_LONG ti[2];
    unsigned char *iv;
    int save = 0;

    iv = (unsigned char *)ivec;
    n2l(iv, v0);
    n2l(iv, v1);
    ti[0] = v0;
    ti[1] = v1;
    dp = (char *)d;
    l2n(v0, dp);
    l2n(v1, dp);
    while (l--) {
        if (n == 0) {
            BF_encrypt((BF_LONG *)ti, schedule);
            dp = (char *)d;
            t = ti[0];
            l2n(t, dp);
            t = ti[1];
            l2n(t, dp);
            save++;
        }
        *(out++) = *(in++) ^ d[n];
        n = (n + 1) & 0x07;
    }
    if (save) {
        v0 = ti[0];
        v1 = ti[1];
        iv = (unsigned char *)ivec;
        l2n(v0, iv);
        l2n(v1, iv);
    }
    t = v0 = v1 = ti[0] = ti[1] = 0;
    *num = n;
}
/* crypto/bf/bf_skey.c */
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
#include <string.h>
#include "crypto.h"
// #include "blowfish.h"
// #include "bf_locl.h"
#include "bf_pi.h"

void BF_set_key(BF_KEY *key, int len, const unsigned char *data)
#ifdef OPENSSL_FIPS
{
    fips_cipher_abort(BLOWFISH);
    private_BF_set_key(key, len, data);
}

void private_BF_set_key(BF_KEY *key, int len, const unsigned char *data)
#endif
{
    int i;
    BF_LONG *p, ri, in[2];
    const unsigned char *d, *end;

    memcpy(key, &bf_init, sizeof(BF_KEY));
    p = key->P;

    if (len > ((BF_ROUNDS + 2) * 4))
        len = (BF_ROUNDS + 2) * 4;

    d = data;
    end = &(data[len]);
    for (i = 0; i < (BF_ROUNDS + 2); i++) {
        ri = *(d++);
        if (d >= end)
            d = data;

        ri <<= 8;
        ri |= *(d++);
        if (d >= end)
            d = data;

        ri <<= 8;
        ri |= *(d++);
        if (d >= end)
            d = data;

        ri <<= 8;
        ri |= *(d++);
        if (d >= end)
            d = data;

        p[i] ^= ri;
    }

    in[0] = 0L;
    in[1] = 0L;
    for (i = 0; i < (BF_ROUNDS + 2); i += 2) {
        BF_encrypt(in, key);
        p[i] = in[0];
        p[i + 1] = in[1];
    }

    p = key->S;
    for (i = 0; i < 4 * 256; i += 2) {
        BF_encrypt(in, key);
        p[i] = in[0];
        p[i + 1] = in[1];
    }
}
