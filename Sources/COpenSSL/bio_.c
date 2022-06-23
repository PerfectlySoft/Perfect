/* bio_asn1.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project.
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

/*
 * Experimental ASN1 BIO. When written through the data is converted to an
 * ASN1 string type: default is OCTET STRING. Additional functions can be
 * provided to add prefix and suffix data.
 */

#include <string.h>
#include "bio.h"
#include "asn1.h"

/* Must be large enough for biggest tag+length */
#define DEFAULT_ASN1_BUF_SIZE 20

typedef enum {
    ASN1_STATE_START,
    ASN1_STATE_PRE_COPY,
    ASN1_STATE_HEADER,
    ASN1_STATE_HEADER_COPY,
    ASN1_STATE_DATA_COPY,
    ASN1_STATE_POST_COPY,
    ASN1_STATE_DONE
} asn1_bio_state_t;

typedef struct BIO_ASN1_EX_FUNCS_st {
    asn1_ps_func *ex_func;
    asn1_ps_func *ex_free_func;
} BIO_ASN1_EX_FUNCS;

typedef struct BIO_ASN1_BUF_CTX_t {
    /* Internal state */
    asn1_bio_state_t state;
    /* Internal buffer */
    unsigned char *buf;
    /* Size of buffer */
    int bufsize;
    /* Current position in buffer */
    int bufpos;
    /* Current buffer length */
    int buflen;
    /* Amount of data to copy */
    int copylen;
    /* Class and tag to use */
    int asn1_class, asn1_tag;
    asn1_ps_func *prefix, *prefix_free, *suffix, *suffix_free;
    /* Extra buffer for prefix and suffix data */
    unsigned char *ex_buf;
    int ex_len;
    int ex_pos;
    void *ex_arg;
} BIO_ASN1_BUF_CTX;

static int asn1_bio_write(BIO *h, const char *buf, int num);
static int asn1_bio_read(BIO *h, char *buf, int size);
static int asn1_bio_puts(BIO *h, const char *str);
static int asn1_bio_gets(BIO *h, char *str, int size);
static long asn1_bio_ctrl(BIO *h, int cmd, long arg1, void *arg2);
static int asn1_bio_new(BIO *h);
static int asn1_bio_free(BIO *data);
static long asn1_bio_callback_ctrl(BIO *h, int cmd, bio_info_cb *fp);

static int asn1_bio_init(BIO_ASN1_BUF_CTX *ctx, int size);
static int asn1_bio_flush_ex(BIO *b, BIO_ASN1_BUF_CTX *ctx,
                             asn1_ps_func *cleanup, asn1_bio_state_t next);
static int asn1_bio_setup_ex(BIO *b, BIO_ASN1_BUF_CTX *ctx,
                             asn1_ps_func *setup,
                             asn1_bio_state_t ex_state,
                             asn1_bio_state_t other_state);

static BIO_METHOD methods_asn1 = {
    BIO_TYPE_ASN1,
    "asn1",
    asn1_bio_write,
    asn1_bio_read,
    asn1_bio_puts,
    asn1_bio_gets,
    asn1_bio_ctrl,
    asn1_bio_new,
    asn1_bio_free,
    asn1_bio_callback_ctrl,
};

BIO_METHOD *BIO_f_asn1(void)
{
    return (&methods_asn1);
}

static int asn1_bio_new(BIO *b)
{
    BIO_ASN1_BUF_CTX *ctx;
    ctx = OPENSSL_malloc(sizeof(BIO_ASN1_BUF_CTX));
    if (!ctx)
        return 0;
    if (!asn1_bio_init(ctx, DEFAULT_ASN1_BUF_SIZE)) {
        OPENSSL_free(ctx);
        return 0;
    }
    b->init = 1;
    b->ptr = (char *)ctx;
    b->flags = 0;
    return 1;
}

static int asn1_bio_init(BIO_ASN1_BUF_CTX *ctx, int size)
{
    ctx->buf = OPENSSL_malloc(size);
    if (!ctx->buf)
        return 0;
    ctx->bufsize = size;
    ctx->bufpos = 0;
    ctx->buflen = 0;
    ctx->copylen = 0;
    ctx->asn1_class = V_ASN1_UNIVERSAL;
    ctx->asn1_tag = V_ASN1_OCTET_STRING;
    ctx->ex_buf = NULL;
    ctx->ex_len = 0;
    ctx->ex_pos = 0;
    ctx->state = ASN1_STATE_START;
    ctx->prefix = ctx->prefix_free = ctx->suffix = ctx->suffix_free = NULL;
    ctx->ex_arg = NULL;
    return 1;
}

static int asn1_bio_free(BIO *b)
{
    BIO_ASN1_BUF_CTX *ctx;
    ctx = (BIO_ASN1_BUF_CTX *)b->ptr;
    if (ctx == NULL)
        return 0;
    if (ctx->buf)
        OPENSSL_free(ctx->buf);
    OPENSSL_free(ctx);
    b->init = 0;
    b->ptr = NULL;
    b->flags = 0;
    return 1;
}

static int asn1_bio_write(BIO *b, const char *in, int inl)
{
    BIO_ASN1_BUF_CTX *ctx;
    int wrmax, wrlen, ret;
    unsigned char *p;
    if (!in || (inl < 0) || (b->next_bio == NULL))
        return 0;
    ctx = (BIO_ASN1_BUF_CTX *)b->ptr;
    if (ctx == NULL)
        return 0;

    wrlen = 0;
    ret = -1;

    for (;;) {
        switch (ctx->state) {

            /* Setup prefix data, call it */
        case ASN1_STATE_START:
            if (!asn1_bio_setup_ex(b, ctx, ctx->prefix,
                                   ASN1_STATE_PRE_COPY, ASN1_STATE_HEADER))
                return 0;
            break;

            /* Copy any pre data first */
        case ASN1_STATE_PRE_COPY:

            ret = asn1_bio_flush_ex(b, ctx, ctx->prefix_free,
                                    ASN1_STATE_HEADER);

            if (ret <= 0)
                goto done;

            break;

        case ASN1_STATE_HEADER:
            ctx->buflen = ASN1_object_size(0, inl, ctx->asn1_tag) - inl;
            OPENSSL_assert(ctx->buflen <= ctx->bufsize);
            p = ctx->buf;
            ASN1_put_object(&p, 0, inl, ctx->asn1_tag, ctx->asn1_class);
            ctx->copylen = inl;
            ctx->state = ASN1_STATE_HEADER_COPY;

            break;

        case ASN1_STATE_HEADER_COPY:
            ret = BIO_write(b->next_bio, ctx->buf + ctx->bufpos, ctx->buflen);
            if (ret <= 0)
                goto done;

            ctx->buflen -= ret;
            if (ctx->buflen)
                ctx->bufpos += ret;
            else {
                ctx->bufpos = 0;
                ctx->state = ASN1_STATE_DATA_COPY;
            }

            break;

        case ASN1_STATE_DATA_COPY:

            if (inl > ctx->copylen)
                wrmax = ctx->copylen;
            else
                wrmax = inl;
            ret = BIO_write(b->next_bio, in, wrmax);
            if (ret <= 0)
                break;
            wrlen += ret;
            ctx->copylen -= ret;
            in += ret;
            inl -= ret;

            if (ctx->copylen == 0)
                ctx->state = ASN1_STATE_HEADER;

            if (inl == 0)
                goto done;

            break;

        default:
            BIO_clear_retry_flags(b);
            return 0;

        }

    }

 done:
    BIO_clear_retry_flags(b);
    BIO_copy_next_retry(b);

    return (wrlen > 0) ? wrlen : ret;

}

static int asn1_bio_flush_ex(BIO *b, BIO_ASN1_BUF_CTX *ctx,
                             asn1_ps_func *cleanup, asn1_bio_state_t next)
{
    int ret;
    if (ctx->ex_len <= 0)
        return 1;
    for (;;) {
        ret = BIO_write(b->next_bio, ctx->ex_buf + ctx->ex_pos, ctx->ex_len);
        if (ret <= 0)
            break;
        ctx->ex_len -= ret;
        if (ctx->ex_len > 0)
            ctx->ex_pos += ret;
        else {
            if (cleanup)
                cleanup(b, &ctx->ex_buf, &ctx->ex_len, &ctx->ex_arg);
            ctx->state = next;
            ctx->ex_pos = 0;
            break;
        }
    }
    return ret;
}

static int asn1_bio_setup_ex(BIO *b, BIO_ASN1_BUF_CTX *ctx,
                             asn1_ps_func *setup,
                             asn1_bio_state_t ex_state,
                             asn1_bio_state_t other_state)
{
    if (setup && !setup(b, &ctx->ex_buf, &ctx->ex_len, &ctx->ex_arg)) {
        BIO_clear_retry_flags(b);
        return 0;
    }
    if (ctx->ex_len > 0)
        ctx->state = ex_state;
    else
        ctx->state = other_state;
    return 1;
}

static int asn1_bio_read(BIO *b, char *in, int inl)
{
    if (!b->next_bio)
        return 0;
    return BIO_read(b->next_bio, in, inl);
}

static int asn1_bio_puts(BIO *b, const char *str)
{
    return asn1_bio_write(b, str, strlen(str));
}

static int asn1_bio_gets(BIO *b, char *str, int size)
{
    if (!b->next_bio)
        return 0;
    return BIO_gets(b->next_bio, str, size);
}

static long asn1_bio_callback_ctrl(BIO *b, int cmd, bio_info_cb *fp)
{
    if (b->next_bio == NULL)
        return (0);
    return BIO_callback_ctrl(b->next_bio, cmd, fp);
}

static long asn1_bio_ctrl(BIO *b, int cmd, long arg1, void *arg2)
{
    BIO_ASN1_BUF_CTX *ctx;
    BIO_ASN1_EX_FUNCS *ex_func;
    long ret = 1;
    ctx = (BIO_ASN1_BUF_CTX *)b->ptr;
    if (ctx == NULL)
        return 0;
    switch (cmd) {

    case BIO_C_SET_PREFIX:
        ex_func = arg2;
        ctx->prefix = ex_func->ex_func;
        ctx->prefix_free = ex_func->ex_free_func;
        break;

    case BIO_C_GET_PREFIX:
        ex_func = arg2;
        ex_func->ex_func = ctx->prefix;
        ex_func->ex_free_func = ctx->prefix_free;
        break;

    case BIO_C_SET_SUFFIX:
        ex_func = arg2;
        ctx->suffix = ex_func->ex_func;
        ctx->suffix_free = ex_func->ex_free_func;
        break;

    case BIO_C_GET_SUFFIX:
        ex_func = arg2;
        ex_func->ex_func = ctx->suffix;
        ex_func->ex_free_func = ctx->suffix_free;
        break;

    case BIO_C_SET_EX_ARG:
        ctx->ex_arg = arg2;
        break;

    case BIO_C_GET_EX_ARG:
        *(void **)arg2 = ctx->ex_arg;
        break;

    case BIO_CTRL_FLUSH:
        if (!b->next_bio)
            return 0;

        /* Call post function if possible */
        if (ctx->state == ASN1_STATE_HEADER) {
            if (!asn1_bio_setup_ex(b, ctx, ctx->suffix,
                                   ASN1_STATE_POST_COPY, ASN1_STATE_DONE))
                return 0;
        }

        if (ctx->state == ASN1_STATE_POST_COPY) {
            ret = asn1_bio_flush_ex(b, ctx, ctx->suffix_free,
                                    ASN1_STATE_DONE);
            if (ret <= 0)
                return ret;
        }

        if (ctx->state == ASN1_STATE_DONE)
            return BIO_ctrl(b->next_bio, cmd, arg1, arg2);
        else {
            BIO_clear_retry_flags(b);
            return 0;
        }
        break;

    default:
        if (!b->next_bio)
            return 0;
        return BIO_ctrl(b->next_bio, cmd, arg1, arg2);

    }

    return ret;
}

static int asn1_bio_set_ex(BIO *b, int cmd,
                           asn1_ps_func *ex_func, asn1_ps_func *ex_free_func)
{
    BIO_ASN1_EX_FUNCS extmp;
    extmp.ex_func = ex_func;
    extmp.ex_free_func = ex_free_func;
    return BIO_ctrl(b, cmd, 0, &extmp);
}

static int asn1_bio_get_ex(BIO *b, int cmd,
                           asn1_ps_func **ex_func,
                           asn1_ps_func **ex_free_func)
{
    BIO_ASN1_EX_FUNCS extmp;
    int ret;
    ret = BIO_ctrl(b, cmd, 0, &extmp);
    if (ret > 0) {
        *ex_func = extmp.ex_func;
        *ex_free_func = extmp.ex_free_func;
    }
    return ret;
}

int BIO_asn1_set_prefix(BIO *b, asn1_ps_func *prefix,
                        asn1_ps_func *prefix_free)
{
    return asn1_bio_set_ex(b, BIO_C_SET_PREFIX, prefix, prefix_free);
}

int BIO_asn1_get_prefix(BIO *b, asn1_ps_func **pprefix,
                        asn1_ps_func **pprefix_free)
{
    return asn1_bio_get_ex(b, BIO_C_GET_PREFIX, pprefix, pprefix_free);
}

int BIO_asn1_set_suffix(BIO *b, asn1_ps_func *suffix,
                        asn1_ps_func *suffix_free)
{
    return asn1_bio_set_ex(b, BIO_C_SET_SUFFIX, suffix, suffix_free);
}

int BIO_asn1_get_suffix(BIO *b, asn1_ps_func **psuffix,
                        asn1_ps_func **psuffix_free)
{
    return asn1_bio_get_ex(b, BIO_C_GET_SUFFIX, psuffix, psuffix_free);
}
/* crypto/evp/bio_b64.c */
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
#include "buffer.h"
#include "evp.h"

static int b64_write(BIO *h, const char *buf, int num);
static int b64_read(BIO *h, char *buf, int size);
static int b64_puts(BIO *h, const char *str);
/*
 * static int b64_gets(BIO *h, char *str, int size);
 */
static long b64_ctrl(BIO *h, int cmd, long arg1, void *arg2);
static int b64_new(BIO *h);
static int b64_free(BIO *data);
static long b64_callback_ctrl(BIO *h, int cmd, bio_info_cb *fp);
#define B64_BLOCK_SIZE  1024
#define B64_BLOCK_SIZE2 768
#define B64_NONE        0
#define B64_ENCODE      1
#define B64_DECODE      2

typedef struct b64_struct {
    /*
     * BIO *bio; moved to the BIO structure
     */
    int buf_len;
    int buf_off;
    int tmp_len;                /* used to find the start when decoding */
    int tmp_nl;                 /* If true, scan until '\n' */
    int encode;
    int start;                  /* have we started decoding yet? */
    int cont;                   /* <= 0 when finished */
    EVP_ENCODE_CTX base64;
    char buf[EVP_ENCODE_LENGTH(B64_BLOCK_SIZE) + 10];
    char tmp[B64_BLOCK_SIZE];
} BIO_B64_CTX;

static BIO_METHOD methods_b64 = {
    BIO_TYPE_BASE64, "base64 encoding",
    b64_write,
    b64_read,
    b64_puts,
    NULL,                       /* b64_gets, */
    b64_ctrl,
    b64_new,
    b64_free,
    b64_callback_ctrl,
};

BIO_METHOD *BIO_f_base64(void)
{
    return (&methods_b64);
}

static int b64_new(BIO *bi)
{
    BIO_B64_CTX *ctx;

    ctx = (BIO_B64_CTX *)OPENSSL_malloc(sizeof(BIO_B64_CTX));
    if (ctx == NULL)
        return (0);

    ctx->buf_len = 0;
    ctx->tmp_len = 0;
    ctx->tmp_nl = 0;
    ctx->buf_off = 0;
    ctx->cont = 1;
    ctx->start = 1;
    ctx->encode = 0;

    bi->init = 1;
    bi->ptr = (char *)ctx;
    bi->flags = 0;
    bi->num = 0;
    return (1);
}

static int b64_free(BIO *a)
{
    if (a == NULL)
        return (0);
    OPENSSL_free(a->ptr);
    a->ptr = NULL;
    a->init = 0;
    a->flags = 0;
    return (1);
}

static int b64_read(BIO *b, char *out, int outl)
{
    int ret = 0, i, ii, j, k, x, n, num, ret_code = 0;
    BIO_B64_CTX *ctx;
    unsigned char *p, *q;

    if (out == NULL)
        return (0);
    ctx = (BIO_B64_CTX *)b->ptr;

    if ((ctx == NULL) || (b->next_bio == NULL))
        return (0);

    BIO_clear_retry_flags(b);

    if (ctx->encode != B64_DECODE) {
        ctx->encode = B64_DECODE;
        ctx->buf_len = 0;
        ctx->buf_off = 0;
        ctx->tmp_len = 0;
        EVP_DecodeInit(&(ctx->base64));
    }

    /* First check if there are bytes decoded/encoded */
    if (ctx->buf_len > 0) {
        OPENSSL_assert(ctx->buf_len >= ctx->buf_off);
        i = ctx->buf_len - ctx->buf_off;
        if (i > outl)
            i = outl;
        OPENSSL_assert(ctx->buf_off + i < (int)sizeof(ctx->buf));
        memcpy(out, &(ctx->buf[ctx->buf_off]), i);
        ret = i;
        out += i;
        outl -= i;
        ctx->buf_off += i;
        if (ctx->buf_len == ctx->buf_off) {
            ctx->buf_len = 0;
            ctx->buf_off = 0;
        }
    }

    /*
     * At this point, we have room of outl bytes and an empty buffer, so we
     * should read in some more.
     */

    ret_code = 0;
    while (outl > 0) {
        if (ctx->cont <= 0)
            break;

        i = BIO_read(b->next_bio, &(ctx->tmp[ctx->tmp_len]),
                     B64_BLOCK_SIZE - ctx->tmp_len);

        if (i <= 0) {
            ret_code = i;

            /* Should we continue next time we are called? */
            if (!BIO_should_retry(b->next_bio)) {
                ctx->cont = i;
                /* If buffer empty break */
                if (ctx->tmp_len == 0)
                    break;
                /* Fall through and process what we have */
                else
                    i = 0;
            }
            /* else we retry and add more data to buffer */
            else
                break;
        }
        i += ctx->tmp_len;
        ctx->tmp_len = i;

        /*
         * We need to scan, a line at a time until we have a valid line if we
         * are starting.
         */
        if (ctx->start && (BIO_get_flags(b) & BIO_FLAGS_BASE64_NO_NL)) {
            /* ctx->start=1; */
            ctx->tmp_len = 0;
        } else if (ctx->start) {
            q = p = (unsigned char *)ctx->tmp;
            num = 0;
            for (j = 0; j < i; j++) {
                if (*(q++) != '\n')
                    continue;

                /*
                 * due to a previous very long line, we need to keep on
                 * scanning for a '\n' before we even start looking for
                 * base64 encoded stuff.
                 */
                if (ctx->tmp_nl) {
                    p = q;
                    ctx->tmp_nl = 0;
                    continue;
                }

                k = EVP_DecodeUpdate(&(ctx->base64),
                                     (unsigned char *)ctx->buf,
                                     &num, p, q - p);
                if ((k <= 0) && (num == 0) && (ctx->start))
                    EVP_DecodeInit(&ctx->base64);
                else {
                    if (p != (unsigned char *)
                        &(ctx->tmp[0])) {
                        i -= (p - (unsigned char *)
                              &(ctx->tmp[0]));
                        for (x = 0; x < i; x++)
                            ctx->tmp[x] = p[x];
                    }
                    EVP_DecodeInit(&ctx->base64);
                    ctx->start = 0;
                    break;
                }
                p = q;
            }

            /* we fell off the end without starting */
            if ((j == i) && (num == 0)) {
                /*
                 * Is this is one long chunk?, if so, keep on reading until a
                 * new line.
                 */
                if (p == (unsigned char *)&(ctx->tmp[0])) {
                    /* Check buffer full */
                    if (i == B64_BLOCK_SIZE) {
                        ctx->tmp_nl = 1;
                        ctx->tmp_len = 0;
                    }
                } else if (p != q) { /* finished on a '\n' */
                    n = q - p;
                    for (ii = 0; ii < n; ii++)
                        ctx->tmp[ii] = p[ii];
                    ctx->tmp_len = n;
                }
                /* else finished on a '\n' */
                continue;
            } else {
                ctx->tmp_len = 0;
            }
        } else if ((i < B64_BLOCK_SIZE) && (ctx->cont > 0)) {
            /*
             * If buffer isn't full and we can retry then restart to read in
             * more data.
             */
            continue;
        }

        if (BIO_get_flags(b) & BIO_FLAGS_BASE64_NO_NL) {
            int z, jj;

#if 0
            jj = (i >> 2) << 2;
#else
            jj = i & ~3;        /* process per 4 */
#endif
            z = EVP_DecodeBlock((unsigned char *)ctx->buf,
                                (unsigned char *)ctx->tmp, jj);
            if (jj > 2) {
                if (ctx->tmp[jj - 1] == '=') {
                    z--;
                    if (ctx->tmp[jj - 2] == '=')
                        z--;
                }
            }
            /*
             * z is now number of output bytes and jj is the number consumed
             */
            if (jj != i) {
                memmove(ctx->tmp, &ctx->tmp[jj], i - jj);
                ctx->tmp_len = i - jj;
            }
            ctx->buf_len = 0;
            if (z > 0) {
                ctx->buf_len = z;
            }
            i = z;
        } else {
            i = EVP_DecodeUpdate(&(ctx->base64),
                                 (unsigned char *)ctx->buf, &ctx->buf_len,
                                 (unsigned char *)ctx->tmp, i);
            ctx->tmp_len = 0;
        }
        /*
         * If eof or an error was signalled, then the condition
         * 'ctx->cont <= 0' will prevent b64_read() from reading
         * more data on subsequent calls. This assignment was
         * deleted accidentally in commit 5562cfaca4f3.
         */
        ctx->cont = i;

        ctx->buf_off = 0;
        if (i < 0) {
            ret_code = 0;
            ctx->buf_len = 0;
            break;
        }

        if (ctx->buf_len <= outl)
            i = ctx->buf_len;
        else
            i = outl;

        memcpy(out, ctx->buf, i);
        ret += i;
        ctx->buf_off = i;
        if (ctx->buf_off == ctx->buf_len) {
            ctx->buf_len = 0;
            ctx->buf_off = 0;
        }
        outl -= i;
        out += i;
    }
    /* BIO_clear_retry_flags(b); */
    BIO_copy_next_retry(b);
    return ((ret == 0) ? ret_code : ret);
}

static int b64_write(BIO *b, const char *in, int inl)
{
    int ret = 0;
    int n;
    int i;
    BIO_B64_CTX *ctx;

    ctx = (BIO_B64_CTX *)b->ptr;
    BIO_clear_retry_flags(b);

    if (ctx->encode != B64_ENCODE) {
        ctx->encode = B64_ENCODE;
        ctx->buf_len = 0;
        ctx->buf_off = 0;
        ctx->tmp_len = 0;
        EVP_EncodeInit(&(ctx->base64));
    }

    OPENSSL_assert(ctx->buf_off < (int)sizeof(ctx->buf));
    OPENSSL_assert(ctx->buf_len <= (int)sizeof(ctx->buf));
    OPENSSL_assert(ctx->buf_len >= ctx->buf_off);
    n = ctx->buf_len - ctx->buf_off;
    while (n > 0) {
        i = BIO_write(b->next_bio, &(ctx->buf[ctx->buf_off]), n);
        if (i <= 0) {
            BIO_copy_next_retry(b);
            return (i);
        }
        OPENSSL_assert(i <= n);
        ctx->buf_off += i;
        OPENSSL_assert(ctx->buf_off <= (int)sizeof(ctx->buf));
        OPENSSL_assert(ctx->buf_len >= ctx->buf_off);
        n -= i;
    }
    /* at this point all pending data has been written */
    ctx->buf_off = 0;
    ctx->buf_len = 0;

    if ((in == NULL) || (inl <= 0))
        return (0);

    while (inl > 0) {
        n = (inl > B64_BLOCK_SIZE) ? B64_BLOCK_SIZE : inl;

        if (BIO_get_flags(b) & BIO_FLAGS_BASE64_NO_NL) {
            if (ctx->tmp_len > 0) {
                OPENSSL_assert(ctx->tmp_len <= 3);
                n = 3 - ctx->tmp_len;
                /*
                 * There's a theoretical possibility for this
                 */
                if (n > inl)
                    n = inl;
                memcpy(&(ctx->tmp[ctx->tmp_len]), in, n);
                ctx->tmp_len += n;
                ret += n;
                if (ctx->tmp_len < 3)
                    break;
                ctx->buf_len =
                    EVP_EncodeBlock((unsigned char *)ctx->buf,
                                    (unsigned char *)ctx->tmp, ctx->tmp_len);
                OPENSSL_assert(ctx->buf_len <= (int)sizeof(ctx->buf));
                OPENSSL_assert(ctx->buf_len >= ctx->buf_off);
                /*
                 * Since we're now done using the temporary buffer, the
                 * length should be 0'd
                 */
                ctx->tmp_len = 0;
            } else {
                if (n < 3) {
                    memcpy(ctx->tmp, in, n);
                    ctx->tmp_len = n;
                    ret += n;
                    break;
                }
                n -= n % 3;
                ctx->buf_len =
                    EVP_EncodeBlock((unsigned char *)ctx->buf,
                                    (const unsigned char *)in, n);
                OPENSSL_assert(ctx->buf_len <= (int)sizeof(ctx->buf));
                OPENSSL_assert(ctx->buf_len >= ctx->buf_off);
                ret += n;
            }
        } else {
            EVP_EncodeUpdate(&(ctx->base64),
                             (unsigned char *)ctx->buf, &ctx->buf_len,
                             (unsigned char *)in, n);
            OPENSSL_assert(ctx->buf_len <= (int)sizeof(ctx->buf));
            OPENSSL_assert(ctx->buf_len >= ctx->buf_off);
            ret += n;
        }
        inl -= n;
        in += n;

        ctx->buf_off = 0;
        n = ctx->buf_len;
        while (n > 0) {
            i = BIO_write(b->next_bio, &(ctx->buf[ctx->buf_off]), n);
            if (i <= 0) {
                BIO_copy_next_retry(b);
                return ((ret == 0) ? i : ret);
            }
            OPENSSL_assert(i <= n);
            n -= i;
            ctx->buf_off += i;
            OPENSSL_assert(ctx->buf_off <= (int)sizeof(ctx->buf));
            OPENSSL_assert(ctx->buf_len >= ctx->buf_off);
        }
        ctx->buf_len = 0;
        ctx->buf_off = 0;
    }
    return (ret);
}

static long b64_ctrl(BIO *b, int cmd, long num, void *ptr)
{
    BIO_B64_CTX *ctx;
    long ret = 1;
    int i;

    ctx = (BIO_B64_CTX *)b->ptr;

    switch (cmd) {
    case BIO_CTRL_RESET:
        ctx->cont = 1;
        ctx->start = 1;
        ctx->encode = B64_NONE;
        ret = BIO_ctrl(b->next_bio, cmd, num, ptr);
        break;
    case BIO_CTRL_EOF:         /* More to read */
        if (ctx->cont <= 0)
            ret = 1;
        else
            ret = BIO_ctrl(b->next_bio, cmd, num, ptr);
        break;
    case BIO_CTRL_WPENDING:    /* More to write in buffer */
        OPENSSL_assert(ctx->buf_len >= ctx->buf_off);
        ret = ctx->buf_len - ctx->buf_off;
        if ((ret == 0) && (ctx->encode != B64_NONE)
            && (ctx->base64.num != 0))
            ret = 1;
        else if (ret <= 0)
            ret = BIO_ctrl(b->next_bio, cmd, num, ptr);
        break;
    case BIO_CTRL_PENDING:     /* More to read in buffer */
        OPENSSL_assert(ctx->buf_len >= ctx->buf_off);
        ret = ctx->buf_len - ctx->buf_off;
        if (ret <= 0)
            ret = BIO_ctrl(b->next_bio, cmd, num, ptr);
        break;
    case BIO_CTRL_FLUSH:
        /* do a final write */
 again:
        while (ctx->buf_len != ctx->buf_off) {
            i = b64_write(b, NULL, 0);
            if (i < 0)
                return i;
        }
        if (BIO_get_flags(b) & BIO_FLAGS_BASE64_NO_NL) {
            if (ctx->tmp_len != 0) {
                ctx->buf_len = EVP_EncodeBlock((unsigned char *)ctx->buf,
                                               (unsigned char *)ctx->tmp,
                                               ctx->tmp_len);
                ctx->buf_off = 0;
                ctx->tmp_len = 0;
                goto again;
            }
        } else if (ctx->encode != B64_NONE && ctx->base64.num != 0) {
            ctx->buf_off = 0;
            EVP_EncodeFinal(&(ctx->base64),
                            (unsigned char *)ctx->buf, &(ctx->buf_len));
            /* push out the bytes */
            goto again;
        }
        /* Finally flush the underlying BIO */
        ret = BIO_ctrl(b->next_bio, cmd, num, ptr);
        break;

    case BIO_C_DO_STATE_MACHINE:
        BIO_clear_retry_flags(b);
        ret = BIO_ctrl(b->next_bio, cmd, num, ptr);
        BIO_copy_next_retry(b);
        break;

    case BIO_CTRL_DUP:
        break;
    case BIO_CTRL_INFO:
    case BIO_CTRL_GET:
    case BIO_CTRL_SET:
    default:
        ret = BIO_ctrl(b->next_bio, cmd, num, ptr);
        break;
    }
    return (ret);
}

static long b64_callback_ctrl(BIO *b, int cmd, bio_info_cb *fp)
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

static int b64_puts(BIO *b, const char *str)
{
    return b64_write(b, str, strlen(str));
}
/* crypto/bio/bio_cb.c */
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
#include <stdlib.h>
// #include "cryptlib.h"
// #include "bio.h"
#include "err.h"

long MS_CALLBACK BIO_debug_callback(BIO *bio, int cmd, const char *argp,
                                    int argi, long argl, long ret)
{
    BIO *b;
    MS_STATIC char buf[256];
    char *p;
    long r = 1;
    int len;
    size_t p_maxlen;

    if (BIO_CB_RETURN & cmd)
        r = ret;

    len = BIO_snprintf(buf,sizeof(buf),"BIO[%p]: ",(void *)bio);

    /* Ignore errors and continue printing the other information. */
    if (len < 0)
        len = 0;
    p = buf + len;
    p_maxlen = sizeof(buf) - len;

    switch (cmd) {
    case BIO_CB_FREE:
        BIO_snprintf(p, p_maxlen, "Free - %s\n", bio->method->name);
        break;
    case BIO_CB_READ:
        if (bio->method->type & BIO_TYPE_DESCRIPTOR)
            BIO_snprintf(p, p_maxlen, "read(%d,%lu) - %s fd=%d\n",
                         bio->num, (unsigned long)argi,
                         bio->method->name, bio->num);
        else
            BIO_snprintf(p, p_maxlen, "read(%d,%lu) - %s\n",
                         bio->num, (unsigned long)argi, bio->method->name);
        break;
    case BIO_CB_WRITE:
        if (bio->method->type & BIO_TYPE_DESCRIPTOR)
            BIO_snprintf(p, p_maxlen, "write(%d,%lu) - %s fd=%d\n",
                         bio->num, (unsigned long)argi,
                         bio->method->name, bio->num);
        else
            BIO_snprintf(p, p_maxlen, "write(%d,%lu) - %s\n",
                         bio->num, (unsigned long)argi, bio->method->name);
        break;
    case BIO_CB_PUTS:
        BIO_snprintf(p, p_maxlen, "puts() - %s\n", bio->method->name);
        break;
    case BIO_CB_GETS:
        BIO_snprintf(p, p_maxlen, "gets(%lu) - %s\n", (unsigned long)argi,
                     bio->method->name);
        break;
    case BIO_CB_CTRL:
        BIO_snprintf(p, p_maxlen, "ctrl(%lu) - %s\n", (unsigned long)argi,
                     bio->method->name);
        break;
    case BIO_CB_RETURN | BIO_CB_READ:
        BIO_snprintf(p, p_maxlen, "read return %ld\n", ret);
        break;
    case BIO_CB_RETURN | BIO_CB_WRITE:
        BIO_snprintf(p, p_maxlen, "write return %ld\n", ret);
        break;
    case BIO_CB_RETURN | BIO_CB_GETS:
        BIO_snprintf(p, p_maxlen, "gets return %ld\n", ret);
        break;
    case BIO_CB_RETURN | BIO_CB_PUTS:
        BIO_snprintf(p, p_maxlen, "puts return %ld\n", ret);
        break;
    case BIO_CB_RETURN | BIO_CB_CTRL:
        BIO_snprintf(p, p_maxlen, "ctrl return %ld\n", ret);
        break;
    default:
        BIO_snprintf(p, p_maxlen, "bio callback - unknown type (%d)\n", cmd);
        break;
    }

    b = (BIO *)bio->cb_arg;
    if (b != NULL)
        BIO_write(b, buf, strlen(buf));
#if !defined(OPENSSL_NO_STDIO) && !defined(OPENSSL_SYS_WIN16)
    else
        fputs(buf, stderr);
#endif
    return (r);
}
/* crypto/evp/bio_enc.c */
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
// #include "buffer.h"
// #include "evp.h"

static int enc_write(BIO *h, const char *buf, int num);
static int enc_read(BIO *h, char *buf, int size);
/*
 * static int enc_puts(BIO *h, const char *str);
 */
/*
 * static int enc_gets(BIO *h, char *str, int size);
 */
static long enc_ctrl(BIO *h, int cmd, long arg1, void *arg2);
static int enc_new(BIO *h);
static int enc_free(BIO *data);
static long enc_callback_ctrl(BIO *h, int cmd, bio_info_cb *fps);
#define ENC_BLOCK_SIZE  (1024*4)
#define BUF_OFFSET      (EVP_MAX_BLOCK_LENGTH*2)

typedef struct enc_struct {
    int buf_len;
    int buf_off;
    int cont;                   /* <= 0 when finished */
    int finished;
    int ok;                     /* bad decrypt */
    EVP_CIPHER_CTX cipher;
    /*
     * buf is larger than ENC_BLOCK_SIZE because EVP_DecryptUpdate can return
     * up to a block more data than is presented to it
     */
    char buf[ENC_BLOCK_SIZE + BUF_OFFSET + 2];
} BIO_ENC_CTX;

static BIO_METHOD methods_enc = {
    BIO_TYPE_CIPHER, "cipher",
    enc_write,
    enc_read,
    NULL,                       /* enc_puts, */
    NULL,                       /* enc_gets, */
    enc_ctrl,
    enc_new,
    enc_free,
    enc_callback_ctrl,
};

BIO_METHOD *BIO_f_cipher(void)
{
    return (&methods_enc);
}

static int enc_new(BIO *bi)
{
    BIO_ENC_CTX *ctx;

    ctx = (BIO_ENC_CTX *)OPENSSL_malloc(sizeof(BIO_ENC_CTX));
    if (ctx == NULL)
        return (0);
    EVP_CIPHER_CTX_init(&ctx->cipher);

    ctx->buf_len = 0;
    ctx->buf_off = 0;
    ctx->cont = 1;
    ctx->finished = 0;
    ctx->ok = 1;

    bi->init = 0;
    bi->ptr = (char *)ctx;
    bi->flags = 0;
    return (1);
}

static int enc_free(BIO *a)
{
    BIO_ENC_CTX *b;

    if (a == NULL)
        return (0);
    b = (BIO_ENC_CTX *)a->ptr;
    EVP_CIPHER_CTX_cleanup(&(b->cipher));
    OPENSSL_cleanse(a->ptr, sizeof(BIO_ENC_CTX));
    OPENSSL_free(a->ptr);
    a->ptr = NULL;
    a->init = 0;
    a->flags = 0;
    return (1);
}

static int enc_read(BIO *b, char *out, int outl)
{
    int ret = 0, i;
    BIO_ENC_CTX *ctx;

    if (out == NULL)
        return (0);
    ctx = (BIO_ENC_CTX *)b->ptr;

    if ((ctx == NULL) || (b->next_bio == NULL))
        return (0);

    /* First check if there are bytes decoded/encoded */
    if (ctx->buf_len > 0) {
        i = ctx->buf_len - ctx->buf_off;
        if (i > outl)
            i = outl;
        memcpy(out, &(ctx->buf[ctx->buf_off]), i);
        ret = i;
        out += i;
        outl -= i;
        ctx->buf_off += i;
        if (ctx->buf_len == ctx->buf_off) {
            ctx->buf_len = 0;
            ctx->buf_off = 0;
        }
    }

    /*
     * At this point, we have room of outl bytes and an empty buffer, so we
     * should read in some more.
     */

    while (outl > 0) {
        if (ctx->cont <= 0)
            break;

        /*
         * read in at IV offset, read the EVP_Cipher documentation about why
         */
        i = BIO_read(b->next_bio, &(ctx->buf[BUF_OFFSET]), ENC_BLOCK_SIZE);

        if (i <= 0) {
            /* Should be continue next time we are called? */
            if (!BIO_should_retry(b->next_bio)) {
                ctx->cont = i;
                i = EVP_CipherFinal_ex(&(ctx->cipher),
                                       (unsigned char *)ctx->buf,
                                       &(ctx->buf_len));
                ctx->ok = i;
                ctx->buf_off = 0;
            } else {
                ret = (ret == 0) ? i : ret;
                break;
            }
        } else {
            if (!EVP_CipherUpdate(&ctx->cipher,
                                  (unsigned char *)ctx->buf, &ctx->buf_len,
                                  (unsigned char *)&(ctx->buf[BUF_OFFSET]),
                                  i)) {
                BIO_clear_retry_flags(b);
                ctx->ok = 0;
                return 0;
            }
            ctx->cont = 1;
            /*
             * Note: it is possible for EVP_CipherUpdate to decrypt zero
             * bytes because this is or looks like the final block: if this
             * happens we should retry and either read more data or decrypt
             * the final block
             */
            if (ctx->buf_len == 0)
                continue;
        }

        if (ctx->buf_len <= outl)
            i = ctx->buf_len;
        else
            i = outl;
        if (i <= 0)
            break;
        memcpy(out, ctx->buf, i);
        ret += i;
        ctx->buf_off = i;
        outl -= i;
        out += i;
    }

    BIO_clear_retry_flags(b);
    BIO_copy_next_retry(b);
    return ((ret == 0) ? ctx->cont : ret);
}

static int enc_write(BIO *b, const char *in, int inl)
{
    int ret = 0, n, i;
    BIO_ENC_CTX *ctx;

    ctx = (BIO_ENC_CTX *)b->ptr;
    ret = inl;

    BIO_clear_retry_flags(b);
    n = ctx->buf_len - ctx->buf_off;
    while (n > 0) {
        i = BIO_write(b->next_bio, &(ctx->buf[ctx->buf_off]), n);
        if (i <= 0) {
            BIO_copy_next_retry(b);
            return (i);
        }
        ctx->buf_off += i;
        n -= i;
    }
    /* at this point all pending data has been written */

    if ((in == NULL) || (inl <= 0))
        return (0);

    ctx->buf_off = 0;
    while (inl > 0) {
        n = (inl > ENC_BLOCK_SIZE) ? ENC_BLOCK_SIZE : inl;
        if (!EVP_CipherUpdate(&ctx->cipher,
                              (unsigned char *)ctx->buf, &ctx->buf_len,
                              (unsigned char *)in, n)) {
            BIO_clear_retry_flags(b);
            ctx->ok = 0;
            return 0;
        }
        inl -= n;
        in += n;

        ctx->buf_off = 0;
        n = ctx->buf_len;
        while (n > 0) {
            i = BIO_write(b->next_bio, &(ctx->buf[ctx->buf_off]), n);
            if (i <= 0) {
                BIO_copy_next_retry(b);
                return (ret == inl) ? i : ret - inl;
            }
            n -= i;
            ctx->buf_off += i;
        }
        ctx->buf_len = 0;
        ctx->buf_off = 0;
    }
    BIO_copy_next_retry(b);
    return (ret);
}

static long enc_ctrl(BIO *b, int cmd, long num, void *ptr)
{
    BIO *dbio;
    BIO_ENC_CTX *ctx, *dctx;
    long ret = 1;
    int i;
    EVP_CIPHER_CTX **c_ctx;

    ctx = (BIO_ENC_CTX *)b->ptr;

    switch (cmd) {
    case BIO_CTRL_RESET:
        ctx->ok = 1;
        ctx->finished = 0;
        EVP_CipherInit_ex(&(ctx->cipher), NULL, NULL, NULL, NULL,
                          ctx->cipher.encrypt);
        ret = BIO_ctrl(b->next_bio, cmd, num, ptr);
        break;
    case BIO_CTRL_EOF:         /* More to read */
        if (ctx->cont <= 0)
            ret = 1;
        else
            ret = BIO_ctrl(b->next_bio, cmd, num, ptr);
        break;
    case BIO_CTRL_WPENDING:
        ret = ctx->buf_len - ctx->buf_off;
        if (ret <= 0)
            ret = BIO_ctrl(b->next_bio, cmd, num, ptr);
        break;
    case BIO_CTRL_PENDING:     /* More to read in buffer */
        ret = ctx->buf_len - ctx->buf_off;
        if (ret <= 0)
            ret = BIO_ctrl(b->next_bio, cmd, num, ptr);
        break;
    case BIO_CTRL_FLUSH:
        /* do a final write */
 again:
        while (ctx->buf_len != ctx->buf_off) {
            i = enc_write(b, NULL, 0);
            if (i < 0)
                return i;
        }

        if (!ctx->finished) {
            ctx->finished = 1;
            ctx->buf_off = 0;
            ret = EVP_CipherFinal_ex(&(ctx->cipher),
                                     (unsigned char *)ctx->buf,
                                     &(ctx->buf_len));
            ctx->ok = (int)ret;
            if (ret <= 0)
                break;

            /* push out the bytes */
            goto again;
        }

        /* Finally flush the underlying BIO */
        ret = BIO_ctrl(b->next_bio, cmd, num, ptr);
        break;
    case BIO_C_GET_CIPHER_STATUS:
        ret = (long)ctx->ok;
        break;
    case BIO_C_DO_STATE_MACHINE:
        BIO_clear_retry_flags(b);
        ret = BIO_ctrl(b->next_bio, cmd, num, ptr);
        BIO_copy_next_retry(b);
        break;
    case BIO_C_GET_CIPHER_CTX:
        c_ctx = (EVP_CIPHER_CTX **)ptr;
        (*c_ctx) = &(ctx->cipher);
        b->init = 1;
        break;
    case BIO_CTRL_DUP:
        dbio = (BIO *)ptr;
        dctx = (BIO_ENC_CTX *)dbio->ptr;
        EVP_CIPHER_CTX_init(&dctx->cipher);
        ret = EVP_CIPHER_CTX_copy(&dctx->cipher, &ctx->cipher);
        if (ret)
            dbio->init = 1;
        break;
    default:
        ret = BIO_ctrl(b->next_bio, cmd, num, ptr);
        break;
    }
    return (ret);
}

static long enc_callback_ctrl(BIO *b, int cmd, bio_info_cb *fp)
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

/*-
void BIO_set_cipher_ctx(b,c)
BIO *b;
EVP_CIPHER_ctx *c;
        {
        if (b == NULL) return;

        if ((b->callback != NULL) &&
                (b->callback(b,BIO_CB_CTRL,(char *)c,BIO_CTRL_SET,e,0L) <= 0))
                return;

        b->init=1;
        ctx=(BIO_ENC_CTX *)b->ptr;
        memcpy(ctx->cipher,c,sizeof(EVP_CIPHER_CTX));

        if (b->callback != NULL)
                b->callback(b,BIO_CB_CTRL,(char *)c,BIO_CTRL_SET,e,1L);
        }
*/

void BIO_set_cipher(BIO *b, const EVP_CIPHER *c, const unsigned char *k,
                    const unsigned char *i, int e)
{
    BIO_ENC_CTX *ctx;

    if (b == NULL)
        return;

    if ((b->callback != NULL) &&
        (b->callback(b, BIO_CB_CTRL, (const char *)c, BIO_CTRL_SET, e, 0L) <=
         0))
        return;

    b->init = 1;
    ctx = (BIO_ENC_CTX *)b->ptr;
    EVP_CipherInit_ex(&(ctx->cipher), c, NULL, k, i, e);

    if (b->callback != NULL)
        b->callback(b, BIO_CB_CTRL, (const char *)c, BIO_CTRL_SET, e, 1L);
}
/* crypto/bio/bio_err.c */
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
// #include "err.h"
// #include "bio.h"

/* BEGIN ERROR CODES */
#ifndef OPENSSL_NO_ERR

# define ERR_FUNC(func) ERR_PACK(ERR_LIB_BIO,func,0)
# define ERR_REASON(reason) ERR_PACK(ERR_LIB_BIO,0,reason)

static ERR_STRING_DATA BIO_str_functs[] = {
    {ERR_FUNC(BIO_F_ACPT_STATE), "ACPT_STATE"},
    {ERR_FUNC(BIO_F_BIO_ACCEPT), "BIO_accept"},
    {ERR_FUNC(BIO_F_BIO_BER_GET_HEADER), "BIO_BER_GET_HEADER"},
    {ERR_FUNC(BIO_F_BIO_CALLBACK_CTRL), "BIO_callback_ctrl"},
    {ERR_FUNC(BIO_F_BIO_CTRL), "BIO_ctrl"},
    {ERR_FUNC(BIO_F_BIO_GETHOSTBYNAME), "BIO_gethostbyname"},
    {ERR_FUNC(BIO_F_BIO_GETS), "BIO_gets"},
    {ERR_FUNC(BIO_F_BIO_GET_ACCEPT_SOCKET), "BIO_get_accept_socket"},
    {ERR_FUNC(BIO_F_BIO_GET_HOST_IP), "BIO_get_host_ip"},
    {ERR_FUNC(BIO_F_BIO_GET_PORT), "BIO_get_port"},
    {ERR_FUNC(BIO_F_BIO_MAKE_PAIR), "BIO_MAKE_PAIR"},
    {ERR_FUNC(BIO_F_BIO_NEW), "BIO_new"},
    {ERR_FUNC(BIO_F_BIO_NEW_FILE), "BIO_new_file"},
    {ERR_FUNC(BIO_F_BIO_NEW_MEM_BUF), "BIO_new_mem_buf"},
    {ERR_FUNC(BIO_F_BIO_NREAD), "BIO_nread"},
    {ERR_FUNC(BIO_F_BIO_NREAD0), "BIO_nread0"},
    {ERR_FUNC(BIO_F_BIO_NWRITE), "BIO_nwrite"},
    {ERR_FUNC(BIO_F_BIO_NWRITE0), "BIO_nwrite0"},
    {ERR_FUNC(BIO_F_BIO_PUTS), "BIO_puts"},
    {ERR_FUNC(BIO_F_BIO_READ), "BIO_read"},
    {ERR_FUNC(BIO_F_BIO_SOCK_INIT), "BIO_sock_init"},
    {ERR_FUNC(BIO_F_BIO_WRITE), "BIO_write"},
    {ERR_FUNC(BIO_F_BUFFER_CTRL), "BUFFER_CTRL"},
    {ERR_FUNC(BIO_F_CONN_CTRL), "CONN_CTRL"},
    {ERR_FUNC(BIO_F_CONN_STATE), "CONN_STATE"},
    {ERR_FUNC(BIO_F_DGRAM_SCTP_READ), "DGRAM_SCTP_READ"},
    {ERR_FUNC(BIO_F_DGRAM_SCTP_WRITE), "DGRAM_SCTP_WRITE"},
    {ERR_FUNC(BIO_F_FILE_CTRL), "FILE_CTRL"},
    {ERR_FUNC(BIO_F_FILE_READ), "FILE_READ"},
    {ERR_FUNC(BIO_F_LINEBUFFER_CTRL), "LINEBUFFER_CTRL"},
    {ERR_FUNC(BIO_F_MEM_READ), "MEM_READ"},
    {ERR_FUNC(BIO_F_MEM_WRITE), "MEM_WRITE"},
    {ERR_FUNC(BIO_F_SSL_NEW), "SSL_new"},
    {ERR_FUNC(BIO_F_WSASTARTUP), "WSASTARTUP"},
    {0, NULL}
};

static ERR_STRING_DATA BIO_str_reasons[] = {
    {ERR_REASON(BIO_R_ACCEPT_ERROR), "accept error"},
    {ERR_REASON(BIO_R_BAD_FOPEN_MODE), "bad fopen mode"},
    {ERR_REASON(BIO_R_BAD_HOSTNAME_LOOKUP), "bad hostname lookup"},
    {ERR_REASON(BIO_R_BROKEN_PIPE), "broken pipe"},
    {ERR_REASON(BIO_R_CONNECT_ERROR), "connect error"},
    {ERR_REASON(BIO_R_EOF_ON_MEMORY_BIO), "EOF on memory BIO"},
    {ERR_REASON(BIO_R_ERROR_SETTING_NBIO), "error setting nbio"},
    {ERR_REASON(BIO_R_ERROR_SETTING_NBIO_ON_ACCEPTED_SOCKET),
     "error setting nbio on accepted socket"},
    {ERR_REASON(BIO_R_ERROR_SETTING_NBIO_ON_ACCEPT_SOCKET),
     "error setting nbio on accept socket"},
    {ERR_REASON(BIO_R_GETHOSTBYNAME_ADDR_IS_NOT_AF_INET),
     "gethostbyname addr is not af inet"},
    {ERR_REASON(BIO_R_INVALID_ARGUMENT), "invalid argument"},
    {ERR_REASON(BIO_R_INVALID_IP_ADDRESS), "invalid ip address"},
    {ERR_REASON(BIO_R_IN_USE), "in use"},
    {ERR_REASON(BIO_R_KEEPALIVE), "keepalive"},
    {ERR_REASON(BIO_R_NBIO_CONNECT_ERROR), "nbio connect error"},
    {ERR_REASON(BIO_R_NO_ACCEPT_PORT_SPECIFIED), "no accept port specified"},
    {ERR_REASON(BIO_R_NO_HOSTNAME_SPECIFIED), "no hostname specified"},
    {ERR_REASON(BIO_R_NO_PORT_DEFINED), "no port defined"},
    {ERR_REASON(BIO_R_NO_PORT_SPECIFIED), "no port specified"},
    {ERR_REASON(BIO_R_NO_SUCH_FILE), "no such file"},
    {ERR_REASON(BIO_R_NULL_PARAMETER), "null parameter"},
    {ERR_REASON(BIO_R_TAG_MISMATCH), "tag mismatch"},
    {ERR_REASON(BIO_R_UNABLE_TO_BIND_SOCKET), "unable to bind socket"},
    {ERR_REASON(BIO_R_UNABLE_TO_CREATE_SOCKET), "unable to create socket"},
    {ERR_REASON(BIO_R_UNABLE_TO_LISTEN_SOCKET), "unable to listen socket"},
    {ERR_REASON(BIO_R_UNINITIALIZED), "uninitialized"},
    {ERR_REASON(BIO_R_UNSUPPORTED_METHOD), "unsupported method"},
    {ERR_REASON(BIO_R_WRITE_TO_READ_ONLY_BIO), "write to read only BIO"},
    {ERR_REASON(BIO_R_WSASTARTUP), "WSAStartup"},
    {0, NULL}
};

#endif

void ERR_load_BIO_strings(void)
{
#ifndef OPENSSL_NO_ERR

    if (ERR_func_error_string(BIO_str_functs[0].error) == NULL) {
        ERR_load_strings(0, BIO_str_functs);
        ERR_load_strings(0, BIO_str_reasons);
    }
#endif
}
/* crypto/bio/bio_lib.c */
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
#include "crypto.h"
// #include "cryptlib.h"
// #include "bio.h"
#include "stack.h"

BIO *BIO_new(BIO_METHOD *method)
{
    BIO *ret = NULL;

    ret = (BIO *)OPENSSL_malloc(sizeof(BIO));
    if (ret == NULL) {
        BIOerr(BIO_F_BIO_NEW, ERR_R_MALLOC_FAILURE);
        return (NULL);
    }
    if (!BIO_set(ret, method)) {
        OPENSSL_free(ret);
        ret = NULL;
    }
    return (ret);
}

int BIO_set(BIO *bio, BIO_METHOD *method)
{
    bio->method = method;
    bio->callback = NULL;
    bio->cb_arg = NULL;
    bio->init = 0;
    bio->shutdown = 1;
    bio->flags = 0;
    bio->retry_reason = 0;
    bio->num = 0;
    bio->ptr = NULL;
    bio->prev_bio = NULL;
    bio->next_bio = NULL;
    bio->references = 1;
    bio->num_read = 0L;
    bio->num_write = 0L;
    CRYPTO_new_ex_data(CRYPTO_EX_INDEX_BIO, bio, &bio->ex_data);
    if (method->create != NULL)
        if (!method->create(bio)) {
            CRYPTO_free_ex_data(CRYPTO_EX_INDEX_BIO, bio, &bio->ex_data);
            return (0);
        }
    return (1);
}

int BIO_free(BIO *a)
{
    int i;

    if (a == NULL)
        return (0);

    i = CRYPTO_add(&a->references, -1, CRYPTO_LOCK_BIO);
#ifdef REF_PRINT
    REF_PRINT("BIO", a);
#endif
    if (i > 0)
        return (1);
#ifdef REF_CHECK
    if (i < 0) {
        fprintf(stderr, "BIO_free, bad reference count\n");
        abort();
    }
#endif
    if ((a->callback != NULL) &&
        ((i = (int)a->callback(a, BIO_CB_FREE, NULL, 0, 0L, 1L)) <= 0))
        return (i);

    CRYPTO_free_ex_data(CRYPTO_EX_INDEX_BIO, a, &a->ex_data);

    if ((a->method != NULL) && (a->method->destroy != NULL))
        a->method->destroy(a);
    OPENSSL_free(a);
    return (1);
}

void BIO_vfree(BIO *a)
{
    BIO_free(a);
}

void BIO_clear_flags(BIO *b, int flags)
{
    b->flags &= ~flags;
}

int BIO_test_flags(const BIO *b, int flags)
{
    return (b->flags & flags);
}

void BIO_set_flags(BIO *b, int flags)
{
    b->flags |= flags;
}

long (*BIO_get_callback(const BIO *b)) (struct bio_st *, int, const char *,
                                        int, long, long) {
    return b->callback;
}

void BIO_set_callback(BIO *b,
                      long (*cb) (struct bio_st *, int, const char *, int,
                                  long, long))
{
    b->callback = cb;
}

void BIO_set_callback_arg(BIO *b, char *arg)
{
    b->cb_arg = arg;
}

char *BIO_get_callback_arg(const BIO *b)
{
    return b->cb_arg;
}

const char *BIO_method_name(const BIO *b)
{
    return b->method->name;
}

int BIO_method_type(const BIO *b)
{
    return b->method->type;
}

int BIO_read(BIO *b, void *out, int outl)
{
    int i;
    long (*cb) (BIO *, int, const char *, int, long, long);

    if ((b == NULL) || (b->method == NULL) || (b->method->bread == NULL)) {
        BIOerr(BIO_F_BIO_READ, BIO_R_UNSUPPORTED_METHOD);
        return (-2);
    }

    cb = b->callback;
    if ((cb != NULL) &&
        ((i = (int)cb(b, BIO_CB_READ, out, outl, 0L, 1L)) <= 0))
        return (i);

    if (!b->init) {
        BIOerr(BIO_F_BIO_READ, BIO_R_UNINITIALIZED);
        return (-2);
    }

    i = b->method->bread(b, out, outl);

    if (i > 0)
        b->num_read += (unsigned long)i;

    if (cb != NULL)
        i = (int)cb(b, BIO_CB_READ | BIO_CB_RETURN, out, outl, 0L, (long)i);
    return (i);
}

int BIO_write(BIO *b, const void *in, int inl)
{
    int i;
    long (*cb) (BIO *, int, const char *, int, long, long);

    if (b == NULL)
        return (0);

    cb = b->callback;
    if ((b->method == NULL) || (b->method->bwrite == NULL)) {
        BIOerr(BIO_F_BIO_WRITE, BIO_R_UNSUPPORTED_METHOD);
        return (-2);
    }

    if ((cb != NULL) &&
        ((i = (int)cb(b, BIO_CB_WRITE, in, inl, 0L, 1L)) <= 0))
        return (i);

    if (!b->init) {
        BIOerr(BIO_F_BIO_WRITE, BIO_R_UNINITIALIZED);
        return (-2);
    }

    i = b->method->bwrite(b, in, inl);

    if (i > 0)
        b->num_write += (unsigned long)i;

    if (cb != NULL)
        i = (int)cb(b, BIO_CB_WRITE | BIO_CB_RETURN, in, inl, 0L, (long)i);
    return (i);
}

int BIO_puts(BIO *b, const char *in)
{
    int i;
    long (*cb) (BIO *, int, const char *, int, long, long);

    if ((b == NULL) || (b->method == NULL) || (b->method->bputs == NULL)) {
        BIOerr(BIO_F_BIO_PUTS, BIO_R_UNSUPPORTED_METHOD);
        return (-2);
    }

    cb = b->callback;

    if ((cb != NULL) && ((i = (int)cb(b, BIO_CB_PUTS, in, 0, 0L, 1L)) <= 0))
        return (i);

    if (!b->init) {
        BIOerr(BIO_F_BIO_PUTS, BIO_R_UNINITIALIZED);
        return (-2);
    }

    i = b->method->bputs(b, in);

    if (i > 0)
        b->num_write += (unsigned long)i;

    if (cb != NULL)
        i = (int)cb(b, BIO_CB_PUTS | BIO_CB_RETURN, in, 0, 0L, (long)i);
    return (i);
}

int BIO_gets(BIO *b, char *in, int inl)
{
    int i;
    long (*cb) (BIO *, int, const char *, int, long, long);

    if ((b == NULL) || (b->method == NULL) || (b->method->bgets == NULL)) {
        BIOerr(BIO_F_BIO_GETS, BIO_R_UNSUPPORTED_METHOD);
        return (-2);
    }

    cb = b->callback;

    if ((cb != NULL) && ((i = (int)cb(b, BIO_CB_GETS, in, inl, 0L, 1L)) <= 0))
        return (i);

    if (!b->init) {
        BIOerr(BIO_F_BIO_GETS, BIO_R_UNINITIALIZED);
        return (-2);
    }

    i = b->method->bgets(b, in, inl);

    if (cb != NULL)
        i = (int)cb(b, BIO_CB_GETS | BIO_CB_RETURN, in, inl, 0L, (long)i);
    return (i);
}

int BIO_indent(BIO *b, int indent, int max)
{
    if (indent < 0)
        indent = 0;
    if (indent > max)
        indent = max;
    while (indent--)
        if (BIO_puts(b, " ") != 1)
            return 0;
    return 1;
}

long BIO_int_ctrl(BIO *b, int cmd, long larg, int iarg)
{
    int i;

    i = iarg;
    return (BIO_ctrl(b, cmd, larg, (char *)&i));
}

char *BIO_ptr_ctrl(BIO *b, int cmd, long larg)
{
    char *p = NULL;

    if (BIO_ctrl(b, cmd, larg, (char *)&p) <= 0)
        return (NULL);
    else
        return (p);
}

long BIO_ctrl(BIO *b, int cmd, long larg, void *parg)
{
    long ret;
    long (*cb) (BIO *, int, const char *, int, long, long);

    if (b == NULL)
        return (0);

    if ((b->method == NULL) || (b->method->ctrl == NULL)) {
        BIOerr(BIO_F_BIO_CTRL, BIO_R_UNSUPPORTED_METHOD);
        return (-2);
    }

    cb = b->callback;

    if ((cb != NULL) &&
        ((ret = cb(b, BIO_CB_CTRL, parg, cmd, larg, 1L)) <= 0))
        return (ret);

    ret = b->method->ctrl(b, cmd, larg, parg);

    if (cb != NULL)
        ret = cb(b, BIO_CB_CTRL | BIO_CB_RETURN, parg, cmd, larg, ret);
    return (ret);
}

long BIO_callback_ctrl(BIO *b, int cmd,
                       void (*fp) (struct bio_st *, int, const char *, int,
                                   long, long))
{
    long ret;
    long (*cb) (BIO *, int, const char *, int, long, long);

    if (b == NULL)
        return (0);

    if ((b->method == NULL) || (b->method->callback_ctrl == NULL)) {
        BIOerr(BIO_F_BIO_CALLBACK_CTRL, BIO_R_UNSUPPORTED_METHOD);
        return (-2);
    }

    cb = b->callback;

    if ((cb != NULL) &&
        ((ret = cb(b, BIO_CB_CTRL, (void *)&fp, cmd, 0, 1L)) <= 0))
        return (ret);

    ret = b->method->callback_ctrl(b, cmd, fp);

    if (cb != NULL)
        ret = cb(b, BIO_CB_CTRL | BIO_CB_RETURN, (void *)&fp, cmd, 0, ret);
    return (ret);
}

/*
 * It is unfortunate to duplicate in functions what the BIO_(w)pending macros
 * do; but those macros have inappropriate return type, and for interfacing
 * from other programming languages, C macros aren't much of a help anyway.
 */
size_t BIO_ctrl_pending(BIO *bio)
{
    return BIO_ctrl(bio, BIO_CTRL_PENDING, 0, NULL);
}

size_t BIO_ctrl_wpending(BIO *bio)
{
    return BIO_ctrl(bio, BIO_CTRL_WPENDING, 0, NULL);
}

/* put the 'bio' on the end of b's list of operators */
BIO *BIO_push(BIO *b, BIO *bio)
{
    BIO *lb;

    if (b == NULL)
        return (bio);
    lb = b;
    while (lb->next_bio != NULL)
        lb = lb->next_bio;
    lb->next_bio = bio;
    if (bio != NULL)
        bio->prev_bio = lb;
    /* called to do internal processing */
    BIO_ctrl(b, BIO_CTRL_PUSH, 0, lb);
    return (b);
}

/* Remove the first and return the rest */
BIO *BIO_pop(BIO *b)
{
    BIO *ret;

    if (b == NULL)
        return (NULL);
    ret = b->next_bio;

    BIO_ctrl(b, BIO_CTRL_POP, 0, b);

    if (b->prev_bio != NULL)
        b->prev_bio->next_bio = b->next_bio;
    if (b->next_bio != NULL)
        b->next_bio->prev_bio = b->prev_bio;

    b->next_bio = NULL;
    b->prev_bio = NULL;
    return (ret);
}

BIO *BIO_get_retry_BIO(BIO *bio, int *reason)
{
    BIO *b, *last;

    b = last = bio;
    for (;;) {
        if (!BIO_should_retry(b))
            break;
        last = b;
        b = b->next_bio;
        if (b == NULL)
            break;
    }
    if (reason != NULL)
        *reason = last->retry_reason;
    return (last);
}

int BIO_get_retry_reason(BIO *bio)
{
    return (bio->retry_reason);
}

BIO *BIO_find_type(BIO *bio, int type)
{
    int mt, mask;

    if (!bio)
        return NULL;
    mask = type & 0xff;
    do {
        if (bio->method != NULL) {
            mt = bio->method->type;

            if (!mask) {
                if (mt & type)
                    return (bio);
            } else if (mt == type)
                return (bio);
        }
        bio = bio->next_bio;
    } while (bio != NULL);
    return (NULL);
}

BIO *BIO_next(BIO *b)
{
    if (!b)
        return NULL;
    return b->next_bio;
}

void BIO_free_all(BIO *bio)
{
    BIO *b;
    int ref;

    while (bio != NULL) {
        b = bio;
        ref = b->references;
        bio = bio->next_bio;
        BIO_free(b);
        /* Since ref count > 1, don't free anyone else. */
        if (ref > 1)
            break;
    }
}

BIO *BIO_dup_chain(BIO *in)
{
    BIO *ret = NULL, *eoc = NULL, *bio, *new_bio;

    for (bio = in; bio != NULL; bio = bio->next_bio) {
        if ((new_bio = BIO_new(bio->method)) == NULL)
            goto err;
        new_bio->callback = bio->callback;
        new_bio->cb_arg = bio->cb_arg;
        new_bio->init = bio->init;
        new_bio->shutdown = bio->shutdown;
        new_bio->flags = bio->flags;

        /* This will let SSL_s_sock() work with stdin/stdout */
        new_bio->num = bio->num;

        if (!BIO_dup_state(bio, (char *)new_bio)) {
            BIO_free(new_bio);
            goto err;
        }

        /* copy app data */
        if (!CRYPTO_dup_ex_data(CRYPTO_EX_INDEX_BIO, &new_bio->ex_data,
                                &bio->ex_data)) {
            BIO_free(new_bio);
            goto err;
        }

        if (ret == NULL) {
            eoc = new_bio;
            ret = eoc;
        } else {
            BIO_push(eoc, new_bio);
            eoc = new_bio;
        }
    }
    return (ret);
 err:
    BIO_free_all(ret);

    return (NULL);
}

void BIO_copy_next_retry(BIO *b)
{
    BIO_set_flags(b, BIO_get_retry_flags(b->next_bio));
    b->retry_reason = b->next_bio->retry_reason;
}

int BIO_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func,
                         CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func)
{
    return CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_BIO, argl, argp,
                                   new_func, dup_func, free_func);
}

int BIO_set_ex_data(BIO *bio, int idx, void *data)
{
    return (CRYPTO_set_ex_data(&(bio->ex_data), idx, data));
}

void *BIO_get_ex_data(BIO *bio, int idx)
{
    return (CRYPTO_get_ex_data(&(bio->ex_data), idx));
}

unsigned long BIO_number_read(BIO *bio)
{
    if (bio)
        return bio->num_read;
    return 0;
}

unsigned long BIO_number_written(BIO *bio)
{
    if (bio)
        return bio->num_write;
    return 0;
}

IMPLEMENT_STACK_OF(BIO)
/* crypto/evp/bio_md.c */
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
// #include "buffer.h"
// #include "evp.h"

/*
 * BIO_put and BIO_get both add to the digest, BIO_gets returns the digest
 */

static int md_write(BIO *h, char const *buf, int num);
static int md_read(BIO *h, char *buf, int size);
/*
 * static int md_puts(BIO *h, const char *str);
 */
static int md_gets(BIO *h, char *str, int size);
static long md_ctrl(BIO *h, int cmd, long arg1, void *arg2);
static int md_new(BIO *h);
static int md_free(BIO *data);
static long md_callback_ctrl(BIO *h, int cmd, bio_info_cb *fp);

static BIO_METHOD methods_md = {
    BIO_TYPE_MD, "message digest",
    md_write,
    md_read,
    NULL,                       /* md_puts, */
    md_gets,
    md_ctrl,
    md_new,
    md_free,
    md_callback_ctrl,
};

BIO_METHOD *BIO_f_md(void)
{
    return (&methods_md);
}

static int md_new(BIO *bi)
{
    EVP_MD_CTX *ctx;

    ctx = EVP_MD_CTX_create();
    if (ctx == NULL)
        return (0);

    bi->init = 0;
    bi->ptr = (char *)ctx;
    bi->flags = 0;
    return (1);
}

static int md_free(BIO *a)
{
    if (a == NULL)
        return (0);
    EVP_MD_CTX_destroy(a->ptr);
    a->ptr = NULL;
    a->init = 0;
    a->flags = 0;
    return (1);
}

static int md_read(BIO *b, char *out, int outl)
{
    int ret = 0;
    EVP_MD_CTX *ctx;

    if (out == NULL)
        return (0);
    ctx = b->ptr;

    if ((ctx == NULL) || (b->next_bio == NULL))
        return (0);

    ret = BIO_read(b->next_bio, out, outl);
    if (b->init) {
        if (ret > 0) {
            if (EVP_DigestUpdate(ctx, (unsigned char *)out,
                                 (unsigned int)ret) <= 0)
                return (-1);
        }
    }
    BIO_clear_retry_flags(b);
    BIO_copy_next_retry(b);
    return (ret);
}

static int md_write(BIO *b, const char *in, int inl)
{
    int ret = 0;
    EVP_MD_CTX *ctx;

    if ((in == NULL) || (inl <= 0))
        return (0);
    ctx = b->ptr;

    if ((ctx != NULL) && (b->next_bio != NULL))
        ret = BIO_write(b->next_bio, in, inl);
    if (b->init) {
        if (ret > 0) {
            if (!EVP_DigestUpdate(ctx, (const unsigned char *)in,
                                  (unsigned int)ret)) {
                BIO_clear_retry_flags(b);
                return 0;
            }
        }
    }
    if (b->next_bio != NULL) {
        BIO_clear_retry_flags(b);
        BIO_copy_next_retry(b);
    }
    return (ret);
}

static long md_ctrl(BIO *b, int cmd, long num, void *ptr)
{
    EVP_MD_CTX *ctx, *dctx, **pctx;
    const EVP_MD **ppmd;
    EVP_MD *md;
    long ret = 1;
    BIO *dbio;

    ctx = b->ptr;

    switch (cmd) {
    case BIO_CTRL_RESET:
        if (b->init)
            ret = EVP_DigestInit_ex(ctx, ctx->digest, NULL);
        else
            ret = 0;
        if (ret > 0)
            ret = BIO_ctrl(b->next_bio, cmd, num, ptr);
        break;
    case BIO_C_GET_MD:
        if (b->init) {
            ppmd = ptr;
            *ppmd = ctx->digest;
        } else
            ret = 0;
        break;
    case BIO_C_GET_MD_CTX:
        pctx = ptr;
        *pctx = ctx;
        b->init = 1;
        break;
    case BIO_C_SET_MD_CTX:
        if (b->init)
            b->ptr = ptr;
        else
            ret = 0;
        break;
    case BIO_C_DO_STATE_MACHINE:
        BIO_clear_retry_flags(b);
        ret = BIO_ctrl(b->next_bio, cmd, num, ptr);
        BIO_copy_next_retry(b);
        break;

    case BIO_C_SET_MD:
        md = ptr;
        ret = EVP_DigestInit_ex(ctx, md, NULL);
        if (ret > 0)
            b->init = 1;
        break;
    case BIO_CTRL_DUP:
        dbio = ptr;
        dctx = dbio->ptr;
        if (!EVP_MD_CTX_copy_ex(dctx, ctx))
            return 0;
        b->init = 1;
        break;
    default:
        ret = BIO_ctrl(b->next_bio, cmd, num, ptr);
        break;
    }
    return (ret);
}

static long md_callback_ctrl(BIO *b, int cmd, bio_info_cb *fp)
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

static int md_gets(BIO *bp, char *buf, int size)
{
    EVP_MD_CTX *ctx;
    unsigned int ret;

    ctx = bp->ptr;
    if (size < ctx->digest->md_size)
        return (0);
    if (EVP_DigestFinal_ex(ctx, (unsigned char *)buf, &ret) <= 0)
        return -1;

    return ((int)ret);
}

/*-
static int md_puts(bp,str)
BIO *bp;
char *str;
        {
        return(-1);
        }
*/
/* bio_ndef.c */
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
 *
 */

// #include "asn1.h"
#include "asn1t.h"
// #include "bio.h"
// #include "err.h"

#include <stdio.h>

/* Experimental NDEF ASN1 BIO support routines */

/*
 * The usage is quite simple, initialize an ASN1 structure, get a BIO from it
 * then any data written through the BIO will end up translated to
 * approptiate format on the fly. The data is streamed out and does *not*
 * need to be all held in memory at once. When the BIO is flushed the output
 * is finalized and any signatures etc written out. The BIO is a 'proper'
 * BIO and can handle non blocking I/O correctly. The usage is simple. The
 * implementation is *not*...
 */

/* BIO support data stored in the ASN1 BIO ex_arg */

typedef struct ndef_aux_st {
    /* ASN1 structure this BIO refers to */
    ASN1_VALUE *val;
    const ASN1_ITEM *it;
    /* Top of the BIO chain */
    BIO *ndef_bio;
    /* Output BIO */
    BIO *out;
    /* Boundary where content is inserted */
    unsigned char **boundary;
    /* DER buffer start */
    unsigned char *derbuf;
} NDEF_SUPPORT;

static int ndef_prefix(BIO *b, unsigned char **pbuf, int *plen, void *parg);
static int ndef_prefix_free(BIO *b, unsigned char **pbuf, int *plen,
                            void *parg);
static int ndef_suffix(BIO *b, unsigned char **pbuf, int *plen, void *parg);
static int ndef_suffix_free(BIO *b, unsigned char **pbuf, int *plen,
                            void *parg);

BIO *BIO_new_NDEF(BIO *out, ASN1_VALUE *val, const ASN1_ITEM *it)
{
    NDEF_SUPPORT *ndef_aux = NULL;
    BIO *asn_bio = NULL;
    const ASN1_AUX *aux = it->funcs;
    ASN1_STREAM_ARG sarg;

    if (!aux || !aux->asn1_cb) {
        ASN1err(ASN1_F_BIO_NEW_NDEF, ASN1_R_STREAMING_NOT_SUPPORTED);
        return NULL;
    }
    ndef_aux = OPENSSL_malloc(sizeof(NDEF_SUPPORT));
    asn_bio = BIO_new(BIO_f_asn1());

    /* ASN1 bio needs to be next to output BIO */

    out = BIO_push(asn_bio, out);

    if (!ndef_aux || !asn_bio || !out)
        goto err;

    BIO_asn1_set_prefix(asn_bio, ndef_prefix, ndef_prefix_free);
    BIO_asn1_set_suffix(asn_bio, ndef_suffix, ndef_suffix_free);

    /*
     * Now let callback prepend any digest, cipher etc BIOs ASN1 structure
     * needs.
     */

    sarg.out = out;
    sarg.ndef_bio = NULL;
    sarg.boundary = NULL;

    if (aux->asn1_cb(ASN1_OP_STREAM_PRE, &val, it, &sarg) <= 0)
        goto err;

    ndef_aux->val = val;
    ndef_aux->it = it;
    ndef_aux->ndef_bio = sarg.ndef_bio;
    ndef_aux->boundary = sarg.boundary;
    ndef_aux->out = out;
    ndef_aux->derbuf = NULL;

    BIO_ctrl(asn_bio, BIO_C_SET_EX_ARG, 0, ndef_aux);

    return sarg.ndef_bio;

 err:
    if (asn_bio)
        BIO_free(asn_bio);
    if (ndef_aux)
        OPENSSL_free(ndef_aux);
    return NULL;
}

static int ndef_prefix(BIO *b, unsigned char **pbuf, int *plen, void *parg)
{
    NDEF_SUPPORT *ndef_aux;
    unsigned char *p;
    int derlen;

    if (!parg)
        return 0;

    ndef_aux = *(NDEF_SUPPORT **)parg;

    derlen = ASN1_item_ndef_i2d(ndef_aux->val, NULL, ndef_aux->it);
    p = OPENSSL_malloc(derlen);
    if (!p)
        return 0;

    ndef_aux->derbuf = p;
    *pbuf = p;
    derlen = ASN1_item_ndef_i2d(ndef_aux->val, &p, ndef_aux->it);

    if (!*ndef_aux->boundary)
        return 0;

    *plen = *ndef_aux->boundary - *pbuf;

    return 1;
}

static int ndef_prefix_free(BIO *b, unsigned char **pbuf, int *plen,
                            void *parg)
{
    NDEF_SUPPORT *ndef_aux;

    if (!parg)
        return 0;

    ndef_aux = *(NDEF_SUPPORT **)parg;

    if (ndef_aux->derbuf)
        OPENSSL_free(ndef_aux->derbuf);

    ndef_aux->derbuf = NULL;
    *pbuf = NULL;
    *plen = 0;
    return 1;
}

static int ndef_suffix_free(BIO *b, unsigned char **pbuf, int *plen,
                            void *parg)
{
    NDEF_SUPPORT **pndef_aux = (NDEF_SUPPORT **)parg;
    if (!ndef_prefix_free(b, pbuf, plen, parg))
        return 0;
    OPENSSL_free(*pndef_aux);
    *pndef_aux = NULL;
    return 1;
}

static int ndef_suffix(BIO *b, unsigned char **pbuf, int *plen, void *parg)
{
    NDEF_SUPPORT *ndef_aux;
    unsigned char *p;
    int derlen;
    const ASN1_AUX *aux;
    ASN1_STREAM_ARG sarg;

    if (!parg)
        return 0;

    ndef_aux = *(NDEF_SUPPORT **)parg;

    aux = ndef_aux->it->funcs;

    /* Finalize structures */
    sarg.ndef_bio = ndef_aux->ndef_bio;
    sarg.out = ndef_aux->out;
    sarg.boundary = ndef_aux->boundary;
    if (aux->asn1_cb(ASN1_OP_STREAM_POST,
                     &ndef_aux->val, ndef_aux->it, &sarg) <= 0)
        return 0;

    derlen = ASN1_item_ndef_i2d(ndef_aux->val, NULL, ndef_aux->it);
    p = OPENSSL_malloc(derlen);
    if (!p)
        return 0;

    ndef_aux->derbuf = p;
    *pbuf = p;
    derlen = ASN1_item_ndef_i2d(ndef_aux->val, &p, ndef_aux->it);

    if (!*ndef_aux->boundary)
        return 0;
    *pbuf = *ndef_aux->boundary;
    *plen = derlen - (*ndef_aux->boundary - ndef_aux->derbuf);

    return 1;
}
/* crypto/evp/bio_ok.c */
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

/*-
        From: Arne Ansper <arne@cyber.ee>

        Why BIO_f_reliable?

        I wrote function which took BIO* as argument, read data from it
        and processed it. Then I wanted to store the input file in
        encrypted form. OK I pushed BIO_f_cipher to the BIO stack
        and everything was OK. BUT if user types wrong password
        BIO_f_cipher outputs only garbage and my function crashes. Yes
        I can and I should fix my function, but BIO_f_cipher is
        easy way to add encryption support to many existing applications
        and it's hard to debug and fix them all.

        So I wanted another BIO which would catch the incorrect passwords and
        file damages which cause garbage on BIO_f_cipher's output.

        The easy way is to push the BIO_f_md and save the checksum at
        the end of the file. However there are several problems with this
        approach:

        1) you must somehow separate checksum from actual data.
        2) you need lot's of memory when reading the file, because you
        must read to the end of the file and verify the checksum before
        letting the application to read the data.

        BIO_f_reliable tries to solve both problems, so that you can
        read and write arbitrary long streams using only fixed amount
        of memory.

        BIO_f_reliable splits data stream into blocks. Each block is prefixed
        with it's length and suffixed with it's digest. So you need only
        several Kbytes of memory to buffer single block before verifying
        it's digest.

        BIO_f_reliable goes further and adds several important capabilities:

        1) the digest of the block is computed over the whole stream
        -- so nobody can rearrange the blocks or remove or replace them.

        2) to detect invalid passwords right at the start BIO_f_reliable
        adds special prefix to the stream. In order to avoid known plain-text
        attacks this prefix is generated as follows:

                *) digest is initialized with random seed instead of
                standardized one.
                *) same seed is written to output
                *) well-known text is then hashed and the output
                of the digest is also written to output.

        reader can now read the seed from stream, hash the same string
        and then compare the digest output.

        Bad things: BIO_f_reliable knows what's going on in EVP_Digest. I
        initially wrote and tested this code on x86 machine and wrote the
        digests out in machine-dependent order :( There are people using
        this code and I cannot change this easily without making existing
        data files unreadable.

*/

#include <stdio.h>
#include <errno.h>
#include <assert.h>
// #include "cryptlib.h"
// #include "buffer.h"
// #include "bio.h"
// #include "evp.h"
#include "rand.h"

static int ok_write(BIO *h, const char *buf, int num);
static int ok_read(BIO *h, char *buf, int size);
static long ok_ctrl(BIO *h, int cmd, long arg1, void *arg2);
static int ok_new(BIO *h);
static int ok_free(BIO *data);
static long ok_callback_ctrl(BIO *h, int cmd, bio_info_cb *fp);

static int sig_out(BIO *b);
static int sig_in(BIO *b);
static int block_out(BIO *b);
static int block_in(BIO *b);
#define OK_BLOCK_SIZE   (1024*4)
#define OK_BLOCK_BLOCK  4
#define IOBS            (OK_BLOCK_SIZE+ OK_BLOCK_BLOCK+ 3*EVP_MAX_MD_SIZE)
#define WELLKNOWN "The quick brown fox jumped over the lazy dog's back."

typedef struct ok_struct {
    size_t buf_len;
    size_t buf_off;
    size_t buf_len_save;
    size_t buf_off_save;
    int cont;                   /* <= 0 when finished */
    int finished;
    EVP_MD_CTX md;
    int blockout;               /* output block is ready */
    int sigio;                  /* must process signature */
    unsigned char buf[IOBS];
} BIO_OK_CTX;

static BIO_METHOD methods_ok = {
    BIO_TYPE_CIPHER, "reliable",
    ok_write,
    ok_read,
    NULL,                       /* ok_puts, */
    NULL,                       /* ok_gets, */
    ok_ctrl,
    ok_new,
    ok_free,
    ok_callback_ctrl,
};

BIO_METHOD *BIO_f_reliable(void)
{
    return (&methods_ok);
}

static int ok_new(BIO *bi)
{
    BIO_OK_CTX *ctx;

    ctx = (BIO_OK_CTX *)OPENSSL_malloc(sizeof(BIO_OK_CTX));
    if (ctx == NULL)
        return (0);

    ctx->buf_len = 0;
    ctx->buf_off = 0;
    ctx->buf_len_save = 0;
    ctx->buf_off_save = 0;
    ctx->cont = 1;
    ctx->finished = 0;
    ctx->blockout = 0;
    ctx->sigio = 1;

    EVP_MD_CTX_init(&ctx->md);

    bi->init = 0;
    bi->ptr = (char *)ctx;
    bi->flags = 0;
    return (1);
}

static int ok_free(BIO *a)
{
    if (a == NULL)
        return (0);
    EVP_MD_CTX_cleanup(&((BIO_OK_CTX *)a->ptr)->md);
    OPENSSL_cleanse(a->ptr, sizeof(BIO_OK_CTX));
    OPENSSL_free(a->ptr);
    a->ptr = NULL;
    a->init = 0;
    a->flags = 0;
    return (1);
}

static int ok_read(BIO *b, char *out, int outl)
{
    int ret = 0, i, n;
    BIO_OK_CTX *ctx;

    if (out == NULL)
        return (0);
    ctx = (BIO_OK_CTX *)b->ptr;

    if ((ctx == NULL) || (b->next_bio == NULL) || (b->init == 0))
        return (0);

    while (outl > 0) {

        /* copy clean bytes to output buffer */
        if (ctx->blockout) {
            i = ctx->buf_len - ctx->buf_off;
            if (i > outl)
                i = outl;
            memcpy(out, &(ctx->buf[ctx->buf_off]), i);
            ret += i;
            out += i;
            outl -= i;
            ctx->buf_off += i;

            /* all clean bytes are out */
            if (ctx->buf_len == ctx->buf_off) {
                ctx->buf_off = 0;

                /*
                 * copy start of the next block into proper place
                 */
                if (ctx->buf_len_save - ctx->buf_off_save > 0) {
                    ctx->buf_len = ctx->buf_len_save - ctx->buf_off_save;
                    memmove(ctx->buf, &(ctx->buf[ctx->buf_off_save]),
                            ctx->buf_len);
                } else {
                    ctx->buf_len = 0;
                }
                ctx->blockout = 0;
            }
        }

        /* output buffer full -- cancel */
        if (outl == 0)
            break;

        /* no clean bytes in buffer -- fill it */
        n = IOBS - ctx->buf_len;
        i = BIO_read(b->next_bio, &(ctx->buf[ctx->buf_len]), n);

        if (i <= 0)
            break;              /* nothing new */

        ctx->buf_len += i;

        /* no signature yet -- check if we got one */
        if (ctx->sigio == 1) {
            if (!sig_in(b)) {
                BIO_clear_retry_flags(b);
                return 0;
            }
        }

        /* signature ok -- check if we got block */
        if (ctx->sigio == 0) {
            if (!block_in(b)) {
                BIO_clear_retry_flags(b);
                return 0;
            }
        }

        /* invalid block -- cancel */
        if (ctx->cont <= 0)
            break;

    }

    BIO_clear_retry_flags(b);
    BIO_copy_next_retry(b);
    return (ret);
}

static int ok_write(BIO *b, const char *in, int inl)
{
    int ret = 0, n, i;
    BIO_OK_CTX *ctx;

    if (inl <= 0)
        return inl;

    ctx = (BIO_OK_CTX *)b->ptr;
    ret = inl;

    if ((ctx == NULL) || (b->next_bio == NULL) || (b->init == 0))
        return (0);

    if (ctx->sigio && !sig_out(b))
        return 0;

    do {
        BIO_clear_retry_flags(b);
        n = ctx->buf_len - ctx->buf_off;
        while (ctx->blockout && n > 0) {
            i = BIO_write(b->next_bio, &(ctx->buf[ctx->buf_off]), n);
            if (i <= 0) {
                BIO_copy_next_retry(b);
                if (!BIO_should_retry(b))
                    ctx->cont = 0;
                return (i);
            }
            ctx->buf_off += i;
            n -= i;
        }

        /* at this point all pending data has been written */
        ctx->blockout = 0;
        if (ctx->buf_len == ctx->buf_off) {
            ctx->buf_len = OK_BLOCK_BLOCK;
            ctx->buf_off = 0;
        }

        if ((in == NULL) || (inl <= 0))
            return (0);

        n = (inl + ctx->buf_len > OK_BLOCK_SIZE + OK_BLOCK_BLOCK) ?
            (int)(OK_BLOCK_SIZE + OK_BLOCK_BLOCK - ctx->buf_len) : inl;

        memcpy((unsigned char *)(&(ctx->buf[ctx->buf_len])),
               (unsigned char *)in, n);
        ctx->buf_len += n;
        inl -= n;
        in += n;

        if (ctx->buf_len >= OK_BLOCK_SIZE + OK_BLOCK_BLOCK) {
            if (!block_out(b)) {
                BIO_clear_retry_flags(b);
                return 0;
            }
        }
    } while (inl > 0);

    BIO_clear_retry_flags(b);
    BIO_copy_next_retry(b);
    return (ret);
}

static long ok_ctrl(BIO *b, int cmd, long num, void *ptr)
{
    BIO_OK_CTX *ctx;
    EVP_MD *md;
    const EVP_MD **ppmd;
    long ret = 1;
    int i;

    ctx = b->ptr;

    switch (cmd) {
    case BIO_CTRL_RESET:
        ctx->buf_len = 0;
        ctx->buf_off = 0;
        ctx->buf_len_save = 0;
        ctx->buf_off_save = 0;
        ctx->cont = 1;
        ctx->finished = 0;
        ctx->blockout = 0;
        ctx->sigio = 1;
        ret = BIO_ctrl(b->next_bio, cmd, num, ptr);
        break;
    case BIO_CTRL_EOF:         /* More to read */
        if (ctx->cont <= 0)
            ret = 1;
        else
            ret = BIO_ctrl(b->next_bio, cmd, num, ptr);
        break;
    case BIO_CTRL_PENDING:     /* More to read in buffer */
    case BIO_CTRL_WPENDING:    /* More to read in buffer */
        ret = ctx->blockout ? ctx->buf_len - ctx->buf_off : 0;
        if (ret <= 0)
            ret = BIO_ctrl(b->next_bio, cmd, num, ptr);
        break;
    case BIO_CTRL_FLUSH:
        /* do a final write */
        if (ctx->blockout == 0)
            if (!block_out(b))
                return 0;

        while (ctx->blockout) {
            i = ok_write(b, NULL, 0);
            if (i < 0) {
                ret = i;
                break;
            }
        }

        ctx->finished = 1;
        ctx->buf_off = ctx->buf_len = 0;
        ctx->cont = (int)ret;

        /* Finally flush the underlying BIO */
        ret = BIO_ctrl(b->next_bio, cmd, num, ptr);
        break;
    case BIO_C_DO_STATE_MACHINE:
        BIO_clear_retry_flags(b);
        ret = BIO_ctrl(b->next_bio, cmd, num, ptr);
        BIO_copy_next_retry(b);
        break;
    case BIO_CTRL_INFO:
        ret = (long)ctx->cont;
        break;
    case BIO_C_SET_MD:
        md = ptr;
        if (!EVP_DigestInit_ex(&ctx->md, md, NULL))
            return 0;
        b->init = 1;
        break;
    case BIO_C_GET_MD:
        if (b->init) {
            ppmd = ptr;
            *ppmd = ctx->md.digest;
        } else
            ret = 0;
        break;
    default:
        ret = BIO_ctrl(b->next_bio, cmd, num, ptr);
        break;
    }
    return (ret);
}

static long ok_callback_ctrl(BIO *b, int cmd, bio_info_cb *fp)
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

static void longswap(void *_ptr, size_t len)
{
    const union {
        long one;
        char little;
    } is_endian = {
        1
    };

    if (is_endian.little) {
        size_t i;
        unsigned char *p = _ptr, c;

        for (i = 0; i < len; i += 4) {
            c = p[0], p[0] = p[3], p[3] = c;
            c = p[1], p[1] = p[2], p[2] = c;
        }
    }
}

static int sig_out(BIO *b)
{
    BIO_OK_CTX *ctx;
    EVP_MD_CTX *md;

    ctx = b->ptr;
    md = &ctx->md;

    if (ctx->buf_len + 2 * md->digest->md_size > OK_BLOCK_SIZE)
        return 1;

    if (!EVP_DigestInit_ex(md, md->digest, NULL))
        goto berr;
    /*
     * FIXME: there's absolutely no guarantee this makes any sense at all,
     * particularly now EVP_MD_CTX has been restructured.
     */
    if (RAND_bytes(md->md_data, md->digest->md_size) <= 0)
        goto berr;
    memcpy(&(ctx->buf[ctx->buf_len]), md->md_data, md->digest->md_size);
    longswap(&(ctx->buf[ctx->buf_len]), md->digest->md_size);
    ctx->buf_len += md->digest->md_size;

    if (!EVP_DigestUpdate(md, WELLKNOWN, strlen(WELLKNOWN)))
        goto berr;
    if (!EVP_DigestFinal_ex(md, &(ctx->buf[ctx->buf_len]), NULL))
        goto berr;
    ctx->buf_len += md->digest->md_size;
    ctx->blockout = 1;
    ctx->sigio = 0;
    return 1;
 berr:
    BIO_clear_retry_flags(b);
    return 0;
}

static int sig_in(BIO *b)
{
    BIO_OK_CTX *ctx;
    EVP_MD_CTX *md;
    unsigned char tmp[EVP_MAX_MD_SIZE];
    int ret = 0;

    ctx = b->ptr;
    md = &ctx->md;

    if ((int)(ctx->buf_len - ctx->buf_off) < 2 * md->digest->md_size)
        return 1;

    if (!EVP_DigestInit_ex(md, md->digest, NULL))
        goto berr;
    memcpy(md->md_data, &(ctx->buf[ctx->buf_off]), md->digest->md_size);
    longswap(md->md_data, md->digest->md_size);
    ctx->buf_off += md->digest->md_size;

    if (!EVP_DigestUpdate(md, WELLKNOWN, strlen(WELLKNOWN)))
        goto berr;
    if (!EVP_DigestFinal_ex(md, tmp, NULL))
        goto berr;
    ret = memcmp(&(ctx->buf[ctx->buf_off]), tmp, md->digest->md_size) == 0;
    ctx->buf_off += md->digest->md_size;
    if (ret == 1) {
        ctx->sigio = 0;
        if (ctx->buf_len != ctx->buf_off) {
            memmove(ctx->buf, &(ctx->buf[ctx->buf_off]),
                    ctx->buf_len - ctx->buf_off);
        }
        ctx->buf_len -= ctx->buf_off;
        ctx->buf_off = 0;
    } else {
        ctx->cont = 0;
    }
    return 1;
 berr:
    BIO_clear_retry_flags(b);
    return 0;
}

static int block_out(BIO *b)
{
    BIO_OK_CTX *ctx;
    EVP_MD_CTX *md;
    unsigned long tl;

    ctx = b->ptr;
    md = &ctx->md;

    tl = ctx->buf_len - OK_BLOCK_BLOCK;
    ctx->buf[0] = (unsigned char)(tl >> 24);
    ctx->buf[1] = (unsigned char)(tl >> 16);
    ctx->buf[2] = (unsigned char)(tl >> 8);
    ctx->buf[3] = (unsigned char)(tl);
    if (!EVP_DigestUpdate(md,
                          (unsigned char *)&(ctx->buf[OK_BLOCK_BLOCK]), tl))
        goto berr;
    if (!EVP_DigestFinal_ex(md, &(ctx->buf[ctx->buf_len]), NULL))
        goto berr;
    ctx->buf_len += md->digest->md_size;
    ctx->blockout = 1;
    return 1;
 berr:
    BIO_clear_retry_flags(b);
    return 0;
}

static int block_in(BIO *b)
{
    BIO_OK_CTX *ctx;
    EVP_MD_CTX *md;
    unsigned long tl = 0;
    unsigned char tmp[EVP_MAX_MD_SIZE];

    ctx = b->ptr;
    md = &ctx->md;

    assert(sizeof(tl) >= OK_BLOCK_BLOCK); /* always true */
    tl = ctx->buf[0];
    tl <<= 8;
    tl |= ctx->buf[1];
    tl <<= 8;
    tl |= ctx->buf[2];
    tl <<= 8;
    tl |= ctx->buf[3];

    if (ctx->buf_len < tl + OK_BLOCK_BLOCK + md->digest->md_size)
        return 1;

    if (!EVP_DigestUpdate(md,
                          (unsigned char *)&(ctx->buf[OK_BLOCK_BLOCK]), tl))
        goto berr;
    if (!EVP_DigestFinal_ex(md, tmp, NULL))
        goto berr;
    if (memcmp(&(ctx->buf[tl + OK_BLOCK_BLOCK]), tmp, md->digest->md_size) ==
        0) {
        /* there might be parts from next block lurking around ! */
        ctx->buf_off_save = tl + OK_BLOCK_BLOCK + md->digest->md_size;
        ctx->buf_len_save = ctx->buf_len;
        ctx->buf_off = OK_BLOCK_BLOCK;
        ctx->buf_len = tl + OK_BLOCK_BLOCK;
        ctx->blockout = 1;
    } else {
        ctx->cont = 0;
    }
    return 1;
 berr:
    BIO_clear_retry_flags(b);
    return 0;
}
/* bio_pk7.c */
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
 *
 */

// #include "asn1.h"
#include "pkcs7.h"
// #include "bio.h"

#if !defined(OPENSSL_SYSNAME_NETWARE) && !defined(OPENSSL_SYSNAME_VXWORKS)
# include <memory.h>
#endif
#include <stdio.h>

/* Streaming encode support for PKCS#7 */

BIO *BIO_new_PKCS7(BIO *out, PKCS7 *p7)
{
    return BIO_new_NDEF(out, (ASN1_VALUE *)p7, ASN1_ITEM_rptr(PKCS7));
}
/* ssl/bio_ssl.c */
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
#include <stdlib.h>
#include <string.h>
#include <errno.h>
// #include "crypto.h"
// #include "bio.h"
// #include "err.h"
#include "ssl.h"

static int ssl_write(BIO *h, const char *buf, int num);
static int ssl_read(BIO *h, char *buf, int size);
static int ssl_puts(BIO *h, const char *str);
static long ssl_ctrl(BIO *h, int cmd, long arg1, void *arg2);
static int ssl_new(BIO *h);
static int ssl_free(BIO *data);
static long ssl_callback_ctrl(BIO *h, int cmd, bio_info_cb *fp);
typedef struct bio_ssl_st {
    SSL *ssl;                   /* The ssl handle :-) */
    /* re-negotiate every time the total number of bytes is this size */
    int num_renegotiates;
    unsigned long renegotiate_count;
    unsigned long byte_count;
    unsigned long renegotiate_timeout;
    unsigned long last_time;
} BIO_SSL;

static BIO_METHOD methods_sslp = {
    BIO_TYPE_SSL, "ssl",
    ssl_write,
    ssl_read,
    ssl_puts,
    NULL,                       /* ssl_gets, */
    ssl_ctrl,
    ssl_new,
    ssl_free,
    ssl_callback_ctrl,
};

BIO_METHOD *BIO_f_ssl(void)
{
    return (&methods_sslp);
}

static int ssl_new(BIO *bi)
{
    BIO_SSL *bs;

    bs = (BIO_SSL *)OPENSSL_malloc(sizeof(BIO_SSL));
    if (bs == NULL) {
        BIOerr(BIO_F_SSL_NEW, ERR_R_MALLOC_FAILURE);
        return (0);
    }
    memset(bs, 0, sizeof(BIO_SSL));
    bi->init = 0;
    bi->ptr = (char *)bs;
    bi->flags = 0;
    return (1);
}

static int ssl_free(BIO *a)
{
    BIO_SSL *bs;

    if (a == NULL)
        return (0);
    bs = (BIO_SSL *)a->ptr;
    if (bs->ssl != NULL)
        SSL_shutdown(bs->ssl);
    if (a->shutdown) {
        if (a->init && (bs->ssl != NULL))
            SSL_free(bs->ssl);
        a->init = 0;
        a->flags = 0;
    }
    if (a->ptr != NULL)
        OPENSSL_free(a->ptr);
    return (1);
}

static int ssl_read(BIO *b, char *out, int outl)
{
    int ret = 1;
    BIO_SSL *sb;
    SSL *ssl;
    int retry_reason = 0;
    int r = 0;

    if (out == NULL)
        return (0);
    sb = (BIO_SSL *)b->ptr;
    ssl = sb->ssl;

    BIO_clear_retry_flags(b);

#if 0
    if (!SSL_is_init_finished(ssl)) {
/*              ret=SSL_do_handshake(ssl); */
        if (ret > 0) {

            outflags = (BIO_FLAGS_READ | BIO_FLAGS_SHOULD_RETRY);
            ret = -1;
            goto end;
        }
    }
#endif
/*      if (ret > 0) */
    ret = SSL_read(ssl, out, outl);

    switch (SSL_get_error(ssl, ret)) {
    case SSL_ERROR_NONE:
        if (ret <= 0)
            break;
        if (sb->renegotiate_count > 0) {
            sb->byte_count += ret;
            if (sb->byte_count > sb->renegotiate_count) {
                sb->byte_count = 0;
                sb->num_renegotiates++;
                SSL_renegotiate(ssl);
                r = 1;
            }
        }
        if ((sb->renegotiate_timeout > 0) && (!r)) {
            unsigned long tm;

            tm = (unsigned long)time(NULL);
            if (tm > sb->last_time + sb->renegotiate_timeout) {
                sb->last_time = tm;
                sb->num_renegotiates++;
                SSL_renegotiate(ssl);
            }
        }

        break;
    case SSL_ERROR_WANT_READ:
        BIO_set_retry_read(b);
        break;
    case SSL_ERROR_WANT_WRITE:
        BIO_set_retry_write(b);
        break;
    case SSL_ERROR_WANT_X509_LOOKUP:
        BIO_set_retry_special(b);
        retry_reason = BIO_RR_SSL_X509_LOOKUP;
        break;
    case SSL_ERROR_WANT_ACCEPT:
        BIO_set_retry_special(b);
        retry_reason = BIO_RR_ACCEPT;
        break;
    case SSL_ERROR_WANT_CONNECT:
        BIO_set_retry_special(b);
        retry_reason = BIO_RR_CONNECT;
        break;
    case SSL_ERROR_SYSCALL:
    case SSL_ERROR_SSL:
    case SSL_ERROR_ZERO_RETURN:
    default:
        break;
    }

    b->retry_reason = retry_reason;
    return (ret);
}

static int ssl_write(BIO *b, const char *out, int outl)
{
    int ret, r = 0;
    int retry_reason = 0;
    SSL *ssl;
    BIO_SSL *bs;

    if (out == NULL)
        return (0);
    bs = (BIO_SSL *)b->ptr;
    ssl = bs->ssl;

    BIO_clear_retry_flags(b);

    /*
     * ret=SSL_do_handshake(ssl); if (ret > 0)
     */
    ret = SSL_write(ssl, out, outl);

    switch (SSL_get_error(ssl, ret)) {
    case SSL_ERROR_NONE:
        if (ret <= 0)
            break;
        if (bs->renegotiate_count > 0) {
            bs->byte_count += ret;
            if (bs->byte_count > bs->renegotiate_count) {
                bs->byte_count = 0;
                bs->num_renegotiates++;
                SSL_renegotiate(ssl);
                r = 1;
            }
        }
        if ((bs->renegotiate_timeout > 0) && (!r)) {
            unsigned long tm;

            tm = (unsigned long)time(NULL);
            if (tm > bs->last_time + bs->renegotiate_timeout) {
                bs->last_time = tm;
                bs->num_renegotiates++;
                SSL_renegotiate(ssl);
            }
        }
        break;
    case SSL_ERROR_WANT_WRITE:
        BIO_set_retry_write(b);
        break;
    case SSL_ERROR_WANT_READ:
        BIO_set_retry_read(b);
        break;
    case SSL_ERROR_WANT_X509_LOOKUP:
        BIO_set_retry_special(b);
        retry_reason = BIO_RR_SSL_X509_LOOKUP;
        break;
    case SSL_ERROR_WANT_CONNECT:
        BIO_set_retry_special(b);
        retry_reason = BIO_RR_CONNECT;
    case SSL_ERROR_SYSCALL:
    case SSL_ERROR_SSL:
    default:
        break;
    }

    b->retry_reason = retry_reason;
    return (ret);
}

static long ssl_ctrl(BIO *b, int cmd, long num, void *ptr)
{
    SSL **sslp, *ssl;
    BIO_SSL *bs;
    BIO *dbio, *bio;
    long ret = 1;

    bs = (BIO_SSL *)b->ptr;
    ssl = bs->ssl;
    if ((ssl == NULL) && (cmd != BIO_C_SET_SSL))
        return (0);
    switch (cmd) {
    case BIO_CTRL_RESET:
        SSL_shutdown(ssl);

        if (ssl->handshake_func == ssl->method->ssl_connect)
            SSL_set_connect_state(ssl);
        else if (ssl->handshake_func == ssl->method->ssl_accept)
            SSL_set_accept_state(ssl);

        SSL_clear(ssl);

        if (b->next_bio != NULL)
            ret = BIO_ctrl(b->next_bio, cmd, num, ptr);
        else if (ssl->rbio != NULL)
            ret = BIO_ctrl(ssl->rbio, cmd, num, ptr);
        else
            ret = 1;
        break;
    case BIO_CTRL_INFO:
        ret = 0;
        break;
    case BIO_C_SSL_MODE:
        if (num)                /* client mode */
            SSL_set_connect_state(ssl);
        else
            SSL_set_accept_state(ssl);
        break;
    case BIO_C_SET_SSL_RENEGOTIATE_TIMEOUT:
        ret = bs->renegotiate_timeout;
        if (num < 60)
            num = 5;
        bs->renegotiate_timeout = (unsigned long)num;
        bs->last_time = (unsigned long)time(NULL);
        break;
    case BIO_C_SET_SSL_RENEGOTIATE_BYTES:
        ret = bs->renegotiate_count;
        if ((long)num >= 512)
            bs->renegotiate_count = (unsigned long)num;
        break;
    case BIO_C_GET_SSL_NUM_RENEGOTIATES:
        ret = bs->num_renegotiates;
        break;
    case BIO_C_SET_SSL:
        if (ssl != NULL) {
            ssl_free(b);
            if (!ssl_new(b))
                return 0;
        }
        b->shutdown = (int)num;
        ssl = (SSL *)ptr;
        ((BIO_SSL *)b->ptr)->ssl = ssl;
        bio = SSL_get_rbio(ssl);
        if (bio != NULL) {
            if (b->next_bio != NULL)
                BIO_push(bio, b->next_bio);
            b->next_bio = bio;
            CRYPTO_add(&bio->references, 1, CRYPTO_LOCK_BIO);
        }
        b->init = 1;
        break;
    case BIO_C_GET_SSL:
        if (ptr != NULL) {
            sslp = (SSL **)ptr;
            *sslp = ssl;
        } else
            ret = 0;
        break;
    case BIO_CTRL_GET_CLOSE:
        ret = b->shutdown;
        break;
    case BIO_CTRL_SET_CLOSE:
        b->shutdown = (int)num;
        break;
    case BIO_CTRL_WPENDING:
        ret = BIO_ctrl(ssl->wbio, cmd, num, ptr);
        break;
    case BIO_CTRL_PENDING:
        ret = SSL_pending(ssl);
        if (ret == 0)
            ret = BIO_pending(ssl->rbio);
        break;
    case BIO_CTRL_FLUSH:
        BIO_clear_retry_flags(b);
        ret = BIO_ctrl(ssl->wbio, cmd, num, ptr);
        BIO_copy_next_retry(b);
        break;
    case BIO_CTRL_PUSH:
        if ((b->next_bio != NULL) && (b->next_bio != ssl->rbio)) {
            SSL_set_bio(ssl, b->next_bio, b->next_bio);
            CRYPTO_add(&b->next_bio->references, 1, CRYPTO_LOCK_BIO);
        }
        break;
    case BIO_CTRL_POP:
        /* Only detach if we are the BIO explicitly being popped */
        if (b == ptr) {
            /*
             * Shouldn't happen in practice because the rbio and wbio are the
             * same when pushed.
             */
            if (ssl->rbio != ssl->wbio)
                BIO_free_all(ssl->wbio);
            if (b->next_bio != NULL)
                CRYPTO_add(&b->next_bio->references, -1, CRYPTO_LOCK_BIO);
            ssl->wbio = NULL;
            ssl->rbio = NULL;
        }
        break;
    case BIO_C_DO_STATE_MACHINE:
        BIO_clear_retry_flags(b);

        b->retry_reason = 0;
        ret = (int)SSL_do_handshake(ssl);

        switch (SSL_get_error(ssl, (int)ret)) {
        case SSL_ERROR_WANT_READ:
            BIO_set_flags(b, BIO_FLAGS_READ | BIO_FLAGS_SHOULD_RETRY);
            break;
        case SSL_ERROR_WANT_WRITE:
            BIO_set_flags(b, BIO_FLAGS_WRITE | BIO_FLAGS_SHOULD_RETRY);
            break;
        case SSL_ERROR_WANT_CONNECT:
            BIO_set_flags(b, BIO_FLAGS_IO_SPECIAL | BIO_FLAGS_SHOULD_RETRY);
            b->retry_reason = b->next_bio->retry_reason;
            break;
        case SSL_ERROR_WANT_X509_LOOKUP:
            BIO_set_retry_special(b);
            b->retry_reason = BIO_RR_SSL_X509_LOOKUP;
            break;
        default:
            break;
        }
        break;
    case BIO_CTRL_DUP:
        dbio = (BIO *)ptr;
        if (((BIO_SSL *)dbio->ptr)->ssl != NULL)
            SSL_free(((BIO_SSL *)dbio->ptr)->ssl);
        ((BIO_SSL *)dbio->ptr)->ssl = SSL_dup(ssl);
        ((BIO_SSL *)dbio->ptr)->renegotiate_count =
            ((BIO_SSL *)b->ptr)->renegotiate_count;
        ((BIO_SSL *)dbio->ptr)->byte_count = ((BIO_SSL *)b->ptr)->byte_count;
        ((BIO_SSL *)dbio->ptr)->renegotiate_timeout =
            ((BIO_SSL *)b->ptr)->renegotiate_timeout;
        ((BIO_SSL *)dbio->ptr)->last_time = ((BIO_SSL *)b->ptr)->last_time;
        ret = (((BIO_SSL *)dbio->ptr)->ssl != NULL);
        break;
    case BIO_C_GET_FD:
        ret = BIO_ctrl(ssl->rbio, cmd, num, ptr);
        break;
    case BIO_CTRL_SET_CALLBACK:
        {
#if 0                           /* FIXME: Should this be used? -- Richard
                                 * Levitte */
            SSLerr(SSL_F_SSL_CTRL, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
            ret = -1;
#else
            ret = 0;
#endif
        }
        break;
    case BIO_CTRL_GET_CALLBACK:
        {
            void (**fptr) (const SSL *xssl, int type, int val);

            fptr = (void (**)(const SSL *xssl, int type, int val))ptr;
            *fptr = SSL_get_info_callback(ssl);
        }
        break;
    default:
        ret = BIO_ctrl(ssl->rbio, cmd, num, ptr);
        break;
    }
    return (ret);
}

static long ssl_callback_ctrl(BIO *b, int cmd, bio_info_cb *fp)
{
    SSL *ssl;
    BIO_SSL *bs;
    long ret = 1;

    bs = (BIO_SSL *)b->ptr;
    ssl = bs->ssl;
    switch (cmd) {
    case BIO_CTRL_SET_CALLBACK:
        {
            /*
             * FIXME: setting this via a completely different prototype seems
             * like a crap idea
             */
            SSL_set_info_callback(ssl, (void (*)(const SSL *, int, int))fp);
        }
        break;
    default:
        ret = BIO_callback_ctrl(ssl->rbio, cmd, fp);
        break;
    }
    return (ret);
}

static int ssl_puts(BIO *bp, const char *str)
{
    int n, ret;

    n = strlen(str);
    ret = BIO_write(bp, str, n);
    return (ret);
}

BIO *BIO_new_buffer_ssl_connect(SSL_CTX *ctx)
{
#ifndef OPENSSL_NO_SOCK
    BIO *ret = NULL, *buf = NULL, *ssl = NULL;

    if ((buf = BIO_new(BIO_f_buffer())) == NULL)
        return (NULL);
    if ((ssl = BIO_new_ssl_connect(ctx)) == NULL)
        goto err;
    if ((ret = BIO_push(buf, ssl)) == NULL)
        goto err;
    return (ret);
 err:
    if (buf != NULL)
        BIO_free(buf);
    if (ssl != NULL)
        BIO_free(ssl);
#endif
    return (NULL);
}

BIO *BIO_new_ssl_connect(SSL_CTX *ctx)
{
#ifndef OPENSSL_NO_SOCK
    BIO *ret = NULL, *con = NULL, *ssl = NULL;

    if ((con = BIO_new(BIO_s_connect())) == NULL)
        return (NULL);
    if ((ssl = BIO_new_ssl(ctx, 1)) == NULL)
        goto err;
    if ((ret = BIO_push(ssl, con)) == NULL)
        goto err;
    return (ret);
 err:
    if (con != NULL)
        BIO_free(con);
#endif
    return (NULL);
}

BIO *BIO_new_ssl(SSL_CTX *ctx, int client)
{
    BIO *ret;
    SSL *ssl;

    if ((ret = BIO_new(BIO_f_ssl())) == NULL)
        return (NULL);
    if ((ssl = SSL_new(ctx)) == NULL) {
        BIO_free(ret);
        return (NULL);
    }
    if (client)
        SSL_set_connect_state(ssl);
    else
        SSL_set_accept_state(ssl);

    BIO_set_ssl(ret, ssl, BIO_CLOSE);
    return (ret);
}

int BIO_ssl_copy_session_id(BIO *t, BIO *f)
{
    t = BIO_find_type(t, BIO_TYPE_SSL);
    f = BIO_find_type(f, BIO_TYPE_SSL);
    if ((t == NULL) || (f == NULL))
        return (0);
    if ((((BIO_SSL *)t->ptr)->ssl == NULL) ||
        (((BIO_SSL *)f->ptr)->ssl == NULL))
        return (0);
    SSL_copy_session_id(((BIO_SSL *)t->ptr)->ssl, ((BIO_SSL *)f->ptr)->ssl);
    return (1);
}

void BIO_ssl_shutdown(BIO *b)
{
    SSL *s;

    while (b != NULL) {
        if (b->method->type == BIO_TYPE_SSL) {
            s = ((BIO_SSL *)b->ptr)->ssl;
            SSL_shutdown(s);
            break;
        }
        b = b->next_bio;
    }
}
