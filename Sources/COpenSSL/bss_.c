/* crypto/bio/bss_acpt.c */
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
#define USE_SOCKETS
#include "cryptlib.h"
#include "bio.h"

#ifndef OPENSSL_NO_SOCK

# ifdef OPENSSL_SYS_WIN16
#  define SOCKET_PROTOCOL 0     /* more microsoft stupidity */
# else
#  define SOCKET_PROTOCOL IPPROTO_TCP
# endif

# if (defined(OPENSSL_SYS_VMS) && __VMS_VER < 70000000)
/* FIONBIO used as a switch to enable ioctl, and that isn't in VMS < 7.0 */
#  undef FIONBIO
# endif

typedef struct bio_accept_st {
    int state;
    char *param_addr;
    int accept_sock;
    int accept_nbio;
    char *addr;
    int nbio;
    /*
     * If 0, it means normal, if 1, do a connect on bind failure, and if
     * there is no-one listening, bind with SO_REUSEADDR. If 2, always use
     * SO_REUSEADDR.
     */
    int bind_mode;
    BIO *bio_chain;
} BIO_ACCEPT;

static int acpt_write(BIO *h, const char *buf, int num);
static int acpt_read(BIO *h, char *buf, int size);
static int acpt_puts(BIO *h, const char *str);
static long acpt_ctrl(BIO *h, int cmd, long arg1, void *arg2);
static int acpt_new(BIO *h);
static int acpt_free(BIO *data);
static int acpt_state(BIO *b, BIO_ACCEPT *c);
static void acpt_close_socket(BIO *data);
static BIO_ACCEPT *BIO_ACCEPT_new(void);
static void BIO_ACCEPT_free(BIO_ACCEPT *a);

# define ACPT_S_BEFORE                   1
# define ACPT_S_GET_ACCEPT_SOCKET        2
# define ACPT_S_OK                       3

static BIO_METHOD methods_acceptp = {
    BIO_TYPE_ACCEPT,
    "socket accept",
    acpt_write,
    acpt_read,
    acpt_puts,
    NULL,                       /* connect_gets, */
    acpt_ctrl,
    acpt_new,
    acpt_free,
    NULL,
};

BIO_METHOD *BIO_s_accept(void)
{
    return (&methods_acceptp);
}

static int acpt_new(BIO *bi)
{
    BIO_ACCEPT *ba;

    bi->init = 0;
    bi->num = INVALID_SOCKET;
    bi->flags = 0;
    if ((ba = BIO_ACCEPT_new()) == NULL)
        return (0);
    bi->ptr = (char *)ba;
    ba->state = ACPT_S_BEFORE;
    bi->shutdown = 1;
    return (1);
}

static BIO_ACCEPT *BIO_ACCEPT_new(void)
{
    BIO_ACCEPT *ret;

    if ((ret = (BIO_ACCEPT *)OPENSSL_malloc(sizeof(BIO_ACCEPT))) == NULL)
        return (NULL);

    memset(ret, 0, sizeof(BIO_ACCEPT));
    ret->accept_sock = INVALID_SOCKET;
    ret->bind_mode = BIO_BIND_NORMAL;
    return (ret);
}

static void BIO_ACCEPT_free(BIO_ACCEPT *a)
{
    if (a == NULL)
        return;

    if (a->param_addr != NULL)
        OPENSSL_free(a->param_addr);
    if (a->addr != NULL)
        OPENSSL_free(a->addr);
    if (a->bio_chain != NULL)
        BIO_free(a->bio_chain);
    OPENSSL_free(a);
}

static void acpt_close_socket(BIO *bio)
{
    BIO_ACCEPT *c;

    c = (BIO_ACCEPT *)bio->ptr;
    if (c->accept_sock != INVALID_SOCKET) {
        shutdown(c->accept_sock, 2);
        closesocket(c->accept_sock);
        c->accept_sock = INVALID_SOCKET;
        bio->num = INVALID_SOCKET;
    }
}

static int acpt_free(BIO *a)
{
    BIO_ACCEPT *data;

    if (a == NULL)
        return (0);
    data = (BIO_ACCEPT *)a->ptr;

    if (a->shutdown) {
        acpt_close_socket(a);
        BIO_ACCEPT_free(data);
        a->ptr = NULL;
        a->flags = 0;
        a->init = 0;
    }
    return (1);
}

static int acpt_state(BIO *b, BIO_ACCEPT *c)
{
    BIO *bio = NULL, *dbio;
    int s = -1;
    int i;

 again:
    switch (c->state) {
    case ACPT_S_BEFORE:
        if (c->param_addr == NULL) {
            BIOerr(BIO_F_ACPT_STATE, BIO_R_NO_ACCEPT_PORT_SPECIFIED);
            return (-1);
        }
        s = BIO_get_accept_socket(c->param_addr, c->bind_mode);
        if (s == INVALID_SOCKET)
            return (-1);

        if (c->accept_nbio) {
            if (!BIO_socket_nbio(s, 1)) {
                closesocket(s);
                BIOerr(BIO_F_ACPT_STATE,
                       BIO_R_ERROR_SETTING_NBIO_ON_ACCEPT_SOCKET);
                return (-1);
            }
        }
        c->accept_sock = s;
        b->num = s;
        c->state = ACPT_S_GET_ACCEPT_SOCKET;
        return (1);
        /* break; */
    case ACPT_S_GET_ACCEPT_SOCKET:
        if (b->next_bio != NULL) {
            c->state = ACPT_S_OK;
            goto again;
        }
        BIO_clear_retry_flags(b);
        b->retry_reason = 0;
        i = BIO_accept(c->accept_sock, &(c->addr));

        /* -2 return means we should retry */
        if (i == -2) {
            BIO_set_retry_special(b);
            b->retry_reason = BIO_RR_ACCEPT;
            return -1;
        }

        if (i < 0)
            return (i);

        bio = BIO_new_socket(i, BIO_CLOSE);
        if (bio == NULL)
            goto err;

        BIO_set_callback(bio, BIO_get_callback(b));
        BIO_set_callback_arg(bio, BIO_get_callback_arg(b));

        if (c->nbio) {
            if (!BIO_socket_nbio(i, 1)) {
                BIOerr(BIO_F_ACPT_STATE,
                       BIO_R_ERROR_SETTING_NBIO_ON_ACCEPTED_SOCKET);
                goto err;
            }
        }

        /*
         * If the accept BIO has an bio_chain, we dup it and put the new
         * socket at the end.
         */
        if (c->bio_chain != NULL) {
            if ((dbio = BIO_dup_chain(c->bio_chain)) == NULL)
                goto err;
            if (!BIO_push(dbio, bio))
                goto err;
            bio = dbio;
        }
        if (BIO_push(b, bio) == NULL)
            goto err;

        c->state = ACPT_S_OK;
        return (1);
 err:
        if (bio != NULL)
            BIO_free(bio);
        else if (s >= 0)
            closesocket(s);
        return (0);
        /* break; */
    case ACPT_S_OK:
        if (b->next_bio == NULL) {
            c->state = ACPT_S_GET_ACCEPT_SOCKET;
            goto again;
        }
        return (1);
        /* break; */
    default:
        return (0);
        /* break; */
    }

}

static int acpt_read(BIO *b, char *out, int outl)
{
    int ret = 0;
    BIO_ACCEPT *data;

    BIO_clear_retry_flags(b);
    data = (BIO_ACCEPT *)b->ptr;

    while (b->next_bio == NULL) {
        ret = acpt_state(b, data);
        if (ret <= 0)
            return (ret);
    }

    ret = BIO_read(b->next_bio, out, outl);
    BIO_copy_next_retry(b);
    return (ret);
}

static int acpt_write(BIO *b, const char *in, int inl)
{
    int ret;
    BIO_ACCEPT *data;

    BIO_clear_retry_flags(b);
    data = (BIO_ACCEPT *)b->ptr;

    while (b->next_bio == NULL) {
        ret = acpt_state(b, data);
        if (ret <= 0)
            return (ret);
    }

    ret = BIO_write(b->next_bio, in, inl);
    BIO_copy_next_retry(b);
    return (ret);
}

static long acpt_ctrl(BIO *b, int cmd, long num, void *ptr)
{
    int *ip;
    long ret = 1;
    BIO_ACCEPT *data;
    char **pp;

    data = (BIO_ACCEPT *)b->ptr;

    switch (cmd) {
    case BIO_CTRL_RESET:
        ret = 0;
        data->state = ACPT_S_BEFORE;
        acpt_close_socket(b);
        b->flags = 0;
        break;
    case BIO_C_DO_STATE_MACHINE:
        /* use this one to start the connection */
        ret = (long)acpt_state(b, data);
        break;
    case BIO_C_SET_ACCEPT:
        if (ptr != NULL) {
            if (num == 0) {
                b->init = 1;
                if (data->param_addr != NULL)
                    OPENSSL_free(data->param_addr);
                data->param_addr = BUF_strdup(ptr);
            } else if (num == 1) {
                data->accept_nbio = (ptr != NULL);
            } else if (num == 2) {
                if (data->bio_chain != NULL)
                    BIO_free(data->bio_chain);
                data->bio_chain = (BIO *)ptr;
            }
        }
        break;
    case BIO_C_SET_NBIO:
        data->nbio = (int)num;
        break;
    case BIO_C_SET_FD:
        b->init = 1;
        b->num = *((int *)ptr);
        data->accept_sock = b->num;
        data->state = ACPT_S_GET_ACCEPT_SOCKET;
        b->shutdown = (int)num;
        b->init = 1;
        break;
    case BIO_C_GET_FD:
        if (b->init) {
            ip = (int *)ptr;
            if (ip != NULL)
                *ip = data->accept_sock;
            ret = data->accept_sock;
        } else
            ret = -1;
        break;
    case BIO_C_GET_ACCEPT:
        if (b->init) {
            if (ptr != NULL) {
                pp = (char **)ptr;
                *pp = data->param_addr;
            } else
                ret = -1;
        } else
            ret = -1;
        break;
    case BIO_CTRL_GET_CLOSE:
        ret = b->shutdown;
        break;
    case BIO_CTRL_SET_CLOSE:
        b->shutdown = (int)num;
        break;
    case BIO_CTRL_PENDING:
    case BIO_CTRL_WPENDING:
        ret = 0;
        break;
    case BIO_CTRL_FLUSH:
        break;
    case BIO_C_SET_BIND_MODE:
        data->bind_mode = (int)num;
        break;
    case BIO_C_GET_BIND_MODE:
        ret = (long)data->bind_mode;
        break;
    case BIO_CTRL_DUP:
/*-     dbio=(BIO *)ptr;
        if (data->param_port) EAY EAY
                BIO_set_port(dbio,data->param_port);
        if (data->param_hostname)
                BIO_set_hostname(dbio,data->param_hostname);
        BIO_set_nbio(dbio,data->nbio); */
        break;

    default:
        ret = 0;
        break;
    }
    return (ret);
}

static int acpt_puts(BIO *bp, const char *str)
{
    int n, ret;

    n = strlen(str);
    ret = acpt_write(bp, str, n);
    return (ret);
}

BIO *BIO_new_accept(const char *str)
{
    BIO *ret;

    ret = BIO_new(BIO_s_accept());
    if (ret == NULL)
        return (NULL);
    if (BIO_set_accept_port(ret, str))
        return (ret);
    else {
        BIO_free(ret);
        return (NULL);
    }
}

#endif
/* crypto/bio/bss_bio.c  */
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

/*
 * Special method for a BIO where the other endpoint is also a BIO of this
 * kind, handled by the same thread (i.e. the "peer" is actually ourselves,
 * wearing a different hat). Such "BIO pairs" are mainly for using the SSL
 * library with I/O interfaces for which no specific BIO method is available.
 * See ssl/ssltest.c for some hints on how this can be used.
 */

/* BIO_DEBUG implies BIO_PAIR_DEBUG */
#ifdef BIO_DEBUG
# ifndef BIO_PAIR_DEBUG
#  define BIO_PAIR_DEBUG
# endif
#endif

/* disable assert() unless BIO_PAIR_DEBUG has been defined */
#ifndef BIO_PAIR_DEBUG
# ifndef NDEBUG
#  define NDEBUG
# endif
#endif

#include <assert.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

// #include "bio.h"
#include "err.h"
#include "crypto.h"

#include "e_os.h"

/* VxWorks defines SSIZE_MAX with an empty value causing compile errors */
#if defined(OPENSSL_SYS_VXWORKS)
# undef SSIZE_MAX
#endif
#ifndef SSIZE_MAX
# define SSIZE_MAX INT_MAX
#endif

static int bio_new(BIO *bio);
static int bio_free(BIO *bio);
static int bio_read(BIO *bio, char *buf, int size);
static int bio_write(BIO *bio, const char *buf, int num);
static long bio_ctrl(BIO *bio, int cmd, long num, void *ptr);
static int bio_puts(BIO *bio, const char *str);

static int bio_make_pair(BIO *bio1, BIO *bio2);
static void bio_destroy_pair(BIO *bio);

static BIO_METHOD methods_biop = {
    BIO_TYPE_BIO,
    "BIO pair",
    bio_write,
    bio_read,
    bio_puts,
    NULL /* no bio_gets */ ,
    bio_ctrl,
    bio_new,
    bio_free,
    NULL                        /* no bio_callback_ctrl */
};

BIO_METHOD *BIO_s_bio(void)
{
    return &methods_biop;
}

struct bio_bio_st {
    BIO *peer;                  /* NULL if buf == NULL. If peer != NULL, then
                                 * peer->ptr is also a bio_bio_st, and its
                                 * "peer" member points back to us. peer !=
                                 * NULL iff init != 0 in the BIO. */
    /* This is for what we write (i.e. reading uses peer's struct): */
    int closed;                 /* valid iff peer != NULL */
    size_t len;                 /* valid iff buf != NULL; 0 if peer == NULL */
    size_t offset;              /* valid iff buf != NULL; 0 if len == 0 */
    size_t size;
    char *buf;                  /* "size" elements (if != NULL) */
    size_t request;             /* valid iff peer != NULL; 0 if len != 0,
                                 * otherwise set by peer to number of bytes
                                 * it (unsuccessfully) tried to read, never
                                 * more than buffer space (size-len)
                                 * warrants. */
};

static int bio_new(BIO *bio)
{
    struct bio_bio_st *b;

    b = OPENSSL_malloc(sizeof(*b));
    if (b == NULL)
        return 0;

    b->peer = NULL;
    b->closed = 0;
    b->len = 0;
    b->offset = 0;
    /* enough for one TLS record (just a default) */
    b->size = 17 * 1024;
    b->buf = NULL;
    b->request = 0;

    bio->ptr = b;
    return 1;
}

static int bio_free(BIO *bio)
{
    struct bio_bio_st *b;

    if (bio == NULL)
        return 0;
    b = bio->ptr;

    assert(b != NULL);

    if (b->peer)
        bio_destroy_pair(bio);

    if (b->buf != NULL) {
        OPENSSL_free(b->buf);
    }

    OPENSSL_free(b);

    return 1;
}

static int bio_read(BIO *bio, char *buf, int size_)
{
    size_t size = size_;
    size_t rest;
    struct bio_bio_st *b, *peer_b;

    BIO_clear_retry_flags(bio);

    if (!bio->init)
        return 0;

    b = bio->ptr;
    assert(b != NULL);
    assert(b->peer != NULL);
    peer_b = b->peer->ptr;
    assert(peer_b != NULL);
    assert(peer_b->buf != NULL);

    peer_b->request = 0;        /* will be set in "retry_read" situation */

    if (buf == NULL || size == 0)
        return 0;

    if (peer_b->len == 0) {
        if (peer_b->closed)
            return 0;           /* writer has closed, and no data is left */
        else {
            BIO_set_retry_read(bio); /* buffer is empty */
            if (size <= peer_b->size)
                peer_b->request = size;
            else
                /*
                 * don't ask for more than the peer can deliver in one write
                 */
                peer_b->request = peer_b->size;
            return -1;
        }
    }

    /* we can read */
    if (peer_b->len < size)
        size = peer_b->len;

    /* now read "size" bytes */

    rest = size;

    assert(rest > 0);
    do {                        /* one or two iterations */
        size_t chunk;

        assert(rest <= peer_b->len);
        if (peer_b->offset + rest <= peer_b->size)
            chunk = rest;
        else
            /* wrap around ring buffer */
            chunk = peer_b->size - peer_b->offset;
        assert(peer_b->offset + chunk <= peer_b->size);

        memcpy(buf, peer_b->buf + peer_b->offset, chunk);

        peer_b->len -= chunk;
        if (peer_b->len) {
            peer_b->offset += chunk;
            assert(peer_b->offset <= peer_b->size);
            if (peer_b->offset == peer_b->size)
                peer_b->offset = 0;
            buf += chunk;
        } else {
            /* buffer now empty, no need to advance "buf" */
            assert(chunk == rest);
            peer_b->offset = 0;
        }
        rest -= chunk;
    }
    while (rest);

    return size;
}

/*-
 * non-copying interface: provide pointer to available data in buffer
 *    bio_nread0:  return number of available bytes
 *    bio_nread:   also advance index
 * (example usage:  bio_nread0(), read from buffer, bio_nread()
 *  or just         bio_nread(), read from buffer)
 */
/*
 * WARNING: The non-copying interface is largely untested as of yet and may
 * contain bugs.
 */
static ossl_ssize_t bio_nread0(BIO *bio, char **buf)
{
    struct bio_bio_st *b, *peer_b;
    ossl_ssize_t num;

    BIO_clear_retry_flags(bio);

    if (!bio->init)
        return 0;

    b = bio->ptr;
    assert(b != NULL);
    assert(b->peer != NULL);
    peer_b = b->peer->ptr;
    assert(peer_b != NULL);
    assert(peer_b->buf != NULL);

    peer_b->request = 0;

    if (peer_b->len == 0) {
        char dummy;

        /* avoid code duplication -- nothing available for reading */
        return bio_read(bio, &dummy, 1); /* returns 0 or -1 */
    }

    num = peer_b->len;
    if (peer_b->size < peer_b->offset + num)
        /* no ring buffer wrap-around for non-copying interface */
        num = peer_b->size - peer_b->offset;
    assert(num > 0);

    if (buf != NULL)
        *buf = peer_b->buf + peer_b->offset;
    return num;
}

static ossl_ssize_t bio_nread(BIO *bio, char **buf, size_t num_)
{
    struct bio_bio_st *b, *peer_b;
    ossl_ssize_t num, available;

    if (num_ > SSIZE_MAX)
        num = SSIZE_MAX;
    else
        num = (ossl_ssize_t) num_;

    available = bio_nread0(bio, buf);
    if (num > available)
        num = available;
    if (num <= 0)
        return num;

    b = bio->ptr;
    peer_b = b->peer->ptr;

    peer_b->len -= num;
    if (peer_b->len) {
        peer_b->offset += num;
        assert(peer_b->offset <= peer_b->size);
        if (peer_b->offset == peer_b->size)
            peer_b->offset = 0;
    } else
        peer_b->offset = 0;

    return num;
}

static int bio_write(BIO *bio, const char *buf, int num_)
{
    size_t num = num_;
    size_t rest;
    struct bio_bio_st *b;

    BIO_clear_retry_flags(bio);

    if (!bio->init || buf == NULL || num == 0)
        return 0;

    b = bio->ptr;
    assert(b != NULL);
    assert(b->peer != NULL);
    assert(b->buf != NULL);

    b->request = 0;
    if (b->closed) {
        /* we already closed */
        BIOerr(BIO_F_BIO_WRITE, BIO_R_BROKEN_PIPE);
        return -1;
    }

    assert(b->len <= b->size);

    if (b->len == b->size) {
        BIO_set_retry_write(bio); /* buffer is full */
        return -1;
    }

    /* we can write */
    if (num > b->size - b->len)
        num = b->size - b->len;

    /* now write "num" bytes */

    rest = num;

    assert(rest > 0);
    do {                        /* one or two iterations */
        size_t write_offset;
        size_t chunk;

        assert(b->len + rest <= b->size);

        write_offset = b->offset + b->len;
        if (write_offset >= b->size)
            write_offset -= b->size;
        /* b->buf[write_offset] is the first byte we can write to. */

        if (write_offset + rest <= b->size)
            chunk = rest;
        else
            /* wrap around ring buffer */
            chunk = b->size - write_offset;

        memcpy(b->buf + write_offset, buf, chunk);

        b->len += chunk;

        assert(b->len <= b->size);

        rest -= chunk;
        buf += chunk;
    }
    while (rest);

    return num;
}

/*-
 * non-copying interface: provide pointer to region to write to
 *   bio_nwrite0:  check how much space is available
 *   bio_nwrite:   also increase length
 * (example usage:  bio_nwrite0(), write to buffer, bio_nwrite()
 *  or just         bio_nwrite(), write to buffer)
 */
static ossl_ssize_t bio_nwrite0(BIO *bio, char **buf)
{
    struct bio_bio_st *b;
    size_t num;
    size_t write_offset;

    BIO_clear_retry_flags(bio);

    if (!bio->init)
        return 0;

    b = bio->ptr;
    assert(b != NULL);
    assert(b->peer != NULL);
    assert(b->buf != NULL);

    b->request = 0;
    if (b->closed) {
        BIOerr(BIO_F_BIO_NWRITE0, BIO_R_BROKEN_PIPE);
        return -1;
    }

    assert(b->len <= b->size);

    if (b->len == b->size) {
        BIO_set_retry_write(bio);
        return -1;
    }

    num = b->size - b->len;
    write_offset = b->offset + b->len;
    if (write_offset >= b->size)
        write_offset -= b->size;
    if (write_offset + num > b->size)
        /*
         * no ring buffer wrap-around for non-copying interface (to fulfil
         * the promise by BIO_ctrl_get_write_guarantee, BIO_nwrite may have
         * to be called twice)
         */
        num = b->size - write_offset;

    if (buf != NULL)
        *buf = b->buf + write_offset;
    assert(write_offset + num <= b->size);

    return num;
}

static ossl_ssize_t bio_nwrite(BIO *bio, char **buf, size_t num_)
{
    struct bio_bio_st *b;
    ossl_ssize_t num, space;

    if (num_ > SSIZE_MAX)
        num = SSIZE_MAX;
    else
        num = (ossl_ssize_t) num_;

    space = bio_nwrite0(bio, buf);
    if (num > space)
        num = space;
    if (num <= 0)
        return num;
    b = bio->ptr;
    assert(b != NULL);
    b->len += num;
    assert(b->len <= b->size);

    return num;
}

static long bio_ctrl(BIO *bio, int cmd, long num, void *ptr)
{
    long ret;
    struct bio_bio_st *b = bio->ptr;

    assert(b != NULL);

    switch (cmd) {
        /* specific CTRL codes */

    case BIO_C_SET_WRITE_BUF_SIZE:
        if (b->peer) {
            BIOerr(BIO_F_BIO_CTRL, BIO_R_IN_USE);
            ret = 0;
        } else if (num == 0) {
            BIOerr(BIO_F_BIO_CTRL, BIO_R_INVALID_ARGUMENT);
            ret = 0;
        } else {
            size_t new_size = num;

            if (b->size != new_size) {
                if (b->buf) {
                    OPENSSL_free(b->buf);
                    b->buf = NULL;
                }
                b->size = new_size;
            }
            ret = 1;
        }
        break;

    case BIO_C_GET_WRITE_BUF_SIZE:
        ret = (long)b->size;
        break;

    case BIO_C_MAKE_BIO_PAIR:
        {
            BIO *other_bio = ptr;

            if (bio_make_pair(bio, other_bio))
                ret = 1;
            else
                ret = 0;
        }
        break;

    case BIO_C_DESTROY_BIO_PAIR:
        /*
         * Affects both BIOs in the pair -- call just once! Or let
         * BIO_free(bio1); BIO_free(bio2); do the job.
         */
        bio_destroy_pair(bio);
        ret = 1;
        break;

    case BIO_C_GET_WRITE_GUARANTEE:
        /*
         * How many bytes can the caller feed to the next write without
         * having to keep any?
         */
        if (b->peer == NULL || b->closed)
            ret = 0;
        else
            ret = (long)b->size - b->len;
        break;

    case BIO_C_GET_READ_REQUEST:
        /*
         * If the peer unsuccessfully tried to read, how many bytes were
         * requested? (As with BIO_CTRL_PENDING, that number can usually be
         * treated as boolean.)
         */
        ret = (long)b->request;
        break;

    case BIO_C_RESET_READ_REQUEST:
        /*
         * Reset request.  (Can be useful after read attempts at the other
         * side that are meant to be non-blocking, e.g. when probing SSL_read
         * to see if any data is available.)
         */
        b->request = 0;
        ret = 1;
        break;

    case BIO_C_SHUTDOWN_WR:
        /* similar to shutdown(..., SHUT_WR) */
        b->closed = 1;
        ret = 1;
        break;

    case BIO_C_NREAD0:
        /* prepare for non-copying read */
        ret = (long)bio_nread0(bio, ptr);
        break;

    case BIO_C_NREAD:
        /* non-copying read */
        ret = (long)bio_nread(bio, ptr, (size_t)num);
        break;

    case BIO_C_NWRITE0:
        /* prepare for non-copying write */
        ret = (long)bio_nwrite0(bio, ptr);
        break;

    case BIO_C_NWRITE:
        /* non-copying write */
        ret = (long)bio_nwrite(bio, ptr, (size_t)num);
        break;

        /* standard CTRL codes follow */

    case BIO_CTRL_RESET:
        if (b->buf != NULL) {
            b->len = 0;
            b->offset = 0;
        }
        ret = 0;
        break;

    case BIO_CTRL_GET_CLOSE:
        ret = bio->shutdown;
        break;

    case BIO_CTRL_SET_CLOSE:
        bio->shutdown = (int)num;
        ret = 1;
        break;

    case BIO_CTRL_PENDING:
        if (b->peer != NULL) {
            struct bio_bio_st *peer_b = b->peer->ptr;

            ret = (long)peer_b->len;
        } else
            ret = 0;
        break;

    case BIO_CTRL_WPENDING:
        if (b->buf != NULL)
            ret = (long)b->len;
        else
            ret = 0;
        break;

    case BIO_CTRL_DUP:
        /* See BIO_dup_chain for circumstances we have to expect. */
        {
            BIO *other_bio = ptr;
            struct bio_bio_st *other_b;

            assert(other_bio != NULL);
            other_b = other_bio->ptr;
            assert(other_b != NULL);

            assert(other_b->buf == NULL); /* other_bio is always fresh */

            other_b->size = b->size;
        }

        ret = 1;
        break;

    case BIO_CTRL_FLUSH:
        ret = 1;
        break;

    case BIO_CTRL_EOF:
        if (b->peer != NULL) {
            struct bio_bio_st *peer_b = b->peer->ptr;

            if (peer_b->len == 0 && peer_b->closed)
                ret = 1;
            else
                ret = 0;
        } else {
            ret = 1;
        }
        break;

    default:
        ret = 0;
    }
    return ret;
}

static int bio_puts(BIO *bio, const char *str)
{
    return bio_write(bio, str, strlen(str));
}

static int bio_make_pair(BIO *bio1, BIO *bio2)
{
    struct bio_bio_st *b1, *b2;

    assert(bio1 != NULL);
    assert(bio2 != NULL);

    b1 = bio1->ptr;
    b2 = bio2->ptr;

    if (b1->peer != NULL || b2->peer != NULL) {
        BIOerr(BIO_F_BIO_MAKE_PAIR, BIO_R_IN_USE);
        return 0;
    }

    if (b1->buf == NULL) {
        b1->buf = OPENSSL_malloc(b1->size);
        if (b1->buf == NULL) {
            BIOerr(BIO_F_BIO_MAKE_PAIR, ERR_R_MALLOC_FAILURE);
            return 0;
        }
        b1->len = 0;
        b1->offset = 0;
    }

    if (b2->buf == NULL) {
        b2->buf = OPENSSL_malloc(b2->size);
        if (b2->buf == NULL) {
            BIOerr(BIO_F_BIO_MAKE_PAIR, ERR_R_MALLOC_FAILURE);
            return 0;
        }
        b2->len = 0;
        b2->offset = 0;
    }

    b1->peer = bio2;
    b1->closed = 0;
    b1->request = 0;
    b2->peer = bio1;
    b2->closed = 0;
    b2->request = 0;

    bio1->init = 1;
    bio2->init = 1;

    return 1;
}

static void bio_destroy_pair(BIO *bio)
{
    struct bio_bio_st *b = bio->ptr;

    if (b != NULL) {
        BIO *peer_bio = b->peer;

        if (peer_bio != NULL) {
            struct bio_bio_st *peer_b = peer_bio->ptr;

            assert(peer_b != NULL);
            assert(peer_b->peer == bio);

            peer_b->peer = NULL;
            peer_bio->init = 0;
            assert(peer_b->buf != NULL);
            peer_b->len = 0;
            peer_b->offset = 0;

            b->peer = NULL;
            bio->init = 0;
            assert(b->buf != NULL);
            b->len = 0;
            b->offset = 0;
        }
    }
}

/* Exported convenience functions */
int BIO_new_bio_pair(BIO **bio1_p, size_t writebuf1,
                     BIO **bio2_p, size_t writebuf2)
{
    BIO *bio1 = NULL, *bio2 = NULL;
    long r;
    int ret = 0;

    bio1 = BIO_new(BIO_s_bio());
    if (bio1 == NULL)
        goto err;
    bio2 = BIO_new(BIO_s_bio());
    if (bio2 == NULL)
        goto err;

    if (writebuf1) {
        r = BIO_set_write_buf_size(bio1, writebuf1);
        if (!r)
            goto err;
    }
    if (writebuf2) {
        r = BIO_set_write_buf_size(bio2, writebuf2);
        if (!r)
            goto err;
    }

    r = BIO_make_bio_pair(bio1, bio2);
    if (!r)
        goto err;
    ret = 1;

 err:
    if (ret == 0) {
        if (bio1) {
            BIO_free(bio1);
            bio1 = NULL;
        }
        if (bio2) {
            BIO_free(bio2);
            bio2 = NULL;
        }
    }

    *bio1_p = bio1;
    *bio2_p = bio2;
    return ret;
}

size_t BIO_ctrl_get_write_guarantee(BIO *bio)
{
    return BIO_ctrl(bio, BIO_C_GET_WRITE_GUARANTEE, 0, NULL);
}

size_t BIO_ctrl_get_read_request(BIO *bio)
{
    return BIO_ctrl(bio, BIO_C_GET_READ_REQUEST, 0, NULL);
}

int BIO_ctrl_reset_read_request(BIO *bio)
{
    return (BIO_ctrl(bio, BIO_C_RESET_READ_REQUEST, 0, NULL) != 0);
}

/*
 * BIO_nread0/nread/nwrite0/nwrite are available only for BIO pairs for now
 * (conceivably some other BIOs could allow non-copying reads and writes
 * too.)
 */
int BIO_nread0(BIO *bio, char **buf)
{
    long ret;

    if (!bio->init) {
        BIOerr(BIO_F_BIO_NREAD0, BIO_R_UNINITIALIZED);
        return -2;
    }

    ret = BIO_ctrl(bio, BIO_C_NREAD0, 0, buf);
    if (ret > INT_MAX)
        return INT_MAX;
    else
        return (int)ret;
}

int BIO_nread(BIO *bio, char **buf, int num)
{
    int ret;

    if (!bio->init) {
        BIOerr(BIO_F_BIO_NREAD, BIO_R_UNINITIALIZED);
        return -2;
    }

    ret = (int)BIO_ctrl(bio, BIO_C_NREAD, num, buf);
    if (ret > 0)
        bio->num_read += ret;
    return ret;
}

int BIO_nwrite0(BIO *bio, char **buf)
{
    long ret;

    if (!bio->init) {
        BIOerr(BIO_F_BIO_NWRITE0, BIO_R_UNINITIALIZED);
        return -2;
    }

    ret = BIO_ctrl(bio, BIO_C_NWRITE0, 0, buf);
    if (ret > INT_MAX)
        return INT_MAX;
    else
        return (int)ret;
}

int BIO_nwrite(BIO *bio, char **buf, int num)
{
    int ret;

    if (!bio->init) {
        BIOerr(BIO_F_BIO_NWRITE, BIO_R_UNINITIALIZED);
        return -2;
    }

    ret = BIO_ctrl(bio, BIO_C_NWRITE, num, buf);
    if (ret > 0)
        bio->num_write += ret;
    return ret;
}
/* crypto/bio/bss_conn.c */
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
#define USE_SOCKETS
// #include "cryptlib.h"
// #include "bio.h"

#ifndef OPENSSL_NO_SOCK

# ifdef OPENSSL_SYS_WIN16
#  define SOCKET_PROTOCOL 0     /* more microsoft stupidity */
# else
#  define SOCKET_PROTOCOL IPPROTO_TCP
# endif

# if (defined(OPENSSL_SYS_VMS) && __VMS_VER < 70000000)
/* FIONBIO used as a switch to enable ioctl, and that isn't in VMS < 7.0 */
#  undef FIONBIO
# endif

typedef struct bio_connect_st {
    int state;
    char *param_hostname;
    char *param_port;
    int nbio;
    unsigned char ip[4];
    unsigned short port;
    struct sockaddr_in them;
    /*
     * int socket; this will be kept in bio->num so that it is compatible
     * with the bss_sock bio
     */
    /*
     * called when the connection is initially made callback(BIO,state,ret);
     * The callback should return 'ret'.  state is for compatibility with the
     * ssl info_callback
     */
    int (*info_callback) (const BIO *bio, int state, int ret);
} BIO_CONNECT;

static int conn_write(BIO *h, const char *buf, int num);
static int conn_read(BIO *h, char *buf, int size);
static int conn_puts(BIO *h, const char *str);
static long conn_ctrl(BIO *h, int cmd, long arg1, void *arg2);
static int conn_new(BIO *h);
static int conn_free(BIO *data);
static long conn_callback_ctrl(BIO *h, int cmd, bio_info_cb *);

static int conn_state(BIO *b, BIO_CONNECT *c);
static void conn_close_socket(BIO *data);
BIO_CONNECT *BIO_CONNECT_new(void);
void BIO_CONNECT_free(BIO_CONNECT *a);

static BIO_METHOD methods_connectp = {
    BIO_TYPE_CONNECT,
    "socket connect",
    conn_write,
    conn_read,
    conn_puts,
    NULL,                       /* connect_gets, */
    conn_ctrl,
    conn_new,
    conn_free,
    conn_callback_ctrl,
};

static int conn_state(BIO *b, BIO_CONNECT *c)
{
    int ret = -1, i;
    unsigned long l;
    char *p, *q;
    int (*cb) (const BIO *, int, int) = NULL;

    if (c->info_callback != NULL)
        cb = c->info_callback;

    for (;;) {
        switch (c->state) {
        case BIO_CONN_S_BEFORE:
            p = c->param_hostname;
            if (p == NULL) {
                BIOerr(BIO_F_CONN_STATE, BIO_R_NO_HOSTNAME_SPECIFIED);
                goto exit_loop;
            }
            for (; *p != '\0'; p++) {
                if ((*p == ':') || (*p == '/'))
                    break;
            }

            i = *p;
            if ((i == ':') || (i == '/')) {

                *(p++) = '\0';
                if (i == ':') {
                    for (q = p; *q; q++)
                        if (*q == '/') {
                            *q = '\0';
                            break;
                        }
                    if (c->param_port != NULL)
                        OPENSSL_free(c->param_port);
                    c->param_port = BUF_strdup(p);
                }
            }

            if (c->param_port == NULL) {
                BIOerr(BIO_F_CONN_STATE, BIO_R_NO_PORT_SPECIFIED);
                ERR_add_error_data(2, "host=", c->param_hostname);
                goto exit_loop;
            }
            c->state = BIO_CONN_S_GET_IP;
            break;

        case BIO_CONN_S_GET_IP:
            if (BIO_get_host_ip(c->param_hostname, &(c->ip[0])) <= 0)
                goto exit_loop;
            c->state = BIO_CONN_S_GET_PORT;
            break;

        case BIO_CONN_S_GET_PORT:
            if (c->param_port == NULL) {
                /* abort(); */
                goto exit_loop;
            } else if (BIO_get_port(c->param_port, &c->port) <= 0)
                goto exit_loop;
            c->state = BIO_CONN_S_CREATE_SOCKET;
            break;

        case BIO_CONN_S_CREATE_SOCKET:
            /* now setup address */
            memset((char *)&c->them, 0, sizeof(c->them));
            c->them.sin_family = AF_INET;
            c->them.sin_port = htons((unsigned short)c->port);
            l = (unsigned long)
                ((unsigned long)c->ip[0] << 24L) |
                ((unsigned long)c->ip[1] << 16L) |
                ((unsigned long)c->ip[2] << 8L) | ((unsigned long)c->ip[3]);
            c->them.sin_addr.s_addr = htonl(l);
            c->state = BIO_CONN_S_CREATE_SOCKET;

            ret = socket(AF_INET, SOCK_STREAM, SOCKET_PROTOCOL);
            if (ret == INVALID_SOCKET) {
                SYSerr(SYS_F_SOCKET, get_last_socket_error());
                ERR_add_error_data(4, "host=", c->param_hostname,
                                   ":", c->param_port);
                BIOerr(BIO_F_CONN_STATE, BIO_R_UNABLE_TO_CREATE_SOCKET);
                goto exit_loop;
            }
            b->num = ret;
            c->state = BIO_CONN_S_NBIO;
            break;

        case BIO_CONN_S_NBIO:
            if (c->nbio) {
                if (!BIO_socket_nbio(b->num, 1)) {
                    BIOerr(BIO_F_CONN_STATE, BIO_R_ERROR_SETTING_NBIO);
                    ERR_add_error_data(4, "host=",
                                       c->param_hostname, ":", c->param_port);
                    goto exit_loop;
                }
            }
            c->state = BIO_CONN_S_CONNECT;

# if defined(SO_KEEPALIVE) && !defined(OPENSSL_SYS_MPE)
            i = 1;
            i = setsockopt(b->num, SOL_SOCKET, SO_KEEPALIVE, (char *)&i,
                           sizeof(i));
            if (i < 0) {
                SYSerr(SYS_F_SOCKET, get_last_socket_error());
                ERR_add_error_data(4, "host=", c->param_hostname,
                                   ":", c->param_port);
                BIOerr(BIO_F_CONN_STATE, BIO_R_KEEPALIVE);
                goto exit_loop;
            }
# endif
            break;

        case BIO_CONN_S_CONNECT:
            BIO_clear_retry_flags(b);
            ret = connect(b->num,
                          (struct sockaddr *)&c->them, sizeof(c->them));
            b->retry_reason = 0;
            if (ret < 0) {
                if (BIO_sock_should_retry(ret)) {
                    BIO_set_retry_special(b);
                    c->state = BIO_CONN_S_BLOCKED_CONNECT;
                    b->retry_reason = BIO_RR_CONNECT;
                } else {
                    SYSerr(SYS_F_CONNECT, get_last_socket_error());
                    ERR_add_error_data(4, "host=",
                                       c->param_hostname, ":", c->param_port);
                    BIOerr(BIO_F_CONN_STATE, BIO_R_CONNECT_ERROR);
                }
                goto exit_loop;
            } else
                c->state = BIO_CONN_S_OK;
            break;

        case BIO_CONN_S_BLOCKED_CONNECT:
            i = BIO_sock_error(b->num);
            if (i) {
                BIO_clear_retry_flags(b);
                SYSerr(SYS_F_CONNECT, i);
                ERR_add_error_data(4, "host=",
                                   c->param_hostname, ":", c->param_port);
                BIOerr(BIO_F_CONN_STATE, BIO_R_NBIO_CONNECT_ERROR);
                ret = 0;
                goto exit_loop;
            } else
                c->state = BIO_CONN_S_OK;
            break;

        case BIO_CONN_S_OK:
            ret = 1;
            goto exit_loop;
        default:
            /* abort(); */
            goto exit_loop;
        }

        if (cb != NULL) {
            if (!(ret = cb((BIO *)b, c->state, ret)))
                goto end;
        }
    }

    /* Loop does not exit */
 exit_loop:
    if (cb != NULL)
        ret = cb((BIO *)b, c->state, ret);
 end:
    return (ret);
}

BIO_CONNECT *BIO_CONNECT_new(void)
{
    BIO_CONNECT *ret;

    if ((ret = (BIO_CONNECT *)OPENSSL_malloc(sizeof(BIO_CONNECT))) == NULL)
        return (NULL);
    ret->state = BIO_CONN_S_BEFORE;
    ret->param_hostname = NULL;
    ret->param_port = NULL;
    ret->info_callback = NULL;
    ret->nbio = 0;
    ret->ip[0] = 0;
    ret->ip[1] = 0;
    ret->ip[2] = 0;
    ret->ip[3] = 0;
    ret->port = 0;
    memset((char *)&ret->them, 0, sizeof(ret->them));
    return (ret);
}

void BIO_CONNECT_free(BIO_CONNECT *a)
{
    if (a == NULL)
        return;

    if (a->param_hostname != NULL)
        OPENSSL_free(a->param_hostname);
    if (a->param_port != NULL)
        OPENSSL_free(a->param_port);
    OPENSSL_free(a);
}

BIO_METHOD *BIO_s_connect(void)
{
    return (&methods_connectp);
}

static int conn_new(BIO *bi)
{
    bi->init = 0;
    bi->num = INVALID_SOCKET;
    bi->flags = 0;
    if ((bi->ptr = (char *)BIO_CONNECT_new()) == NULL)
        return (0);
    else
        return (1);
}

static void conn_close_socket(BIO *bio)
{
    BIO_CONNECT *c;

    c = (BIO_CONNECT *)bio->ptr;
    if (bio->num != INVALID_SOCKET) {
        /* Only do a shutdown if things were established */
        if (c->state == BIO_CONN_S_OK)
            shutdown(bio->num, 2);
        closesocket(bio->num);
        bio->num = INVALID_SOCKET;
    }
}

static int conn_free(BIO *a)
{
    BIO_CONNECT *data;

    if (a == NULL)
        return (0);
    data = (BIO_CONNECT *)a->ptr;

    if (a->shutdown) {
        conn_close_socket(a);
        BIO_CONNECT_free(data);
        a->ptr = NULL;
        a->flags = 0;
        a->init = 0;
    }
    return (1);
}

static int conn_read(BIO *b, char *out, int outl)
{
    int ret = 0;
    BIO_CONNECT *data;

    data = (BIO_CONNECT *)b->ptr;
    if (data->state != BIO_CONN_S_OK) {
        ret = conn_state(b, data);
        if (ret <= 0)
            return (ret);
    }

    if (out != NULL) {
        clear_socket_error();
        ret = readsocket(b->num, out, outl);
        BIO_clear_retry_flags(b);
        if (ret <= 0) {
            if (BIO_sock_should_retry(ret))
                BIO_set_retry_read(b);
        }
    }
    return (ret);
}

static int conn_write(BIO *b, const char *in, int inl)
{
    int ret;
    BIO_CONNECT *data;

    data = (BIO_CONNECT *)b->ptr;
    if (data->state != BIO_CONN_S_OK) {
        ret = conn_state(b, data);
        if (ret <= 0)
            return (ret);
    }

    clear_socket_error();
    ret = writesocket(b->num, in, inl);
    BIO_clear_retry_flags(b);
    if (ret <= 0) {
        if (BIO_sock_should_retry(ret))
            BIO_set_retry_write(b);
    }
    return (ret);
}

static long conn_ctrl(BIO *b, int cmd, long num, void *ptr)
{
    BIO *dbio;
    int *ip;
    const char **pptr = NULL;
    long ret = 1;
    BIO_CONNECT *data;

    data = (BIO_CONNECT *)b->ptr;

    switch (cmd) {
    case BIO_CTRL_RESET:
        ret = 0;
        data->state = BIO_CONN_S_BEFORE;
        conn_close_socket(b);
        b->flags = 0;
        break;
    case BIO_C_DO_STATE_MACHINE:
        /* use this one to start the connection */
        if (data->state != BIO_CONN_S_OK)
            ret = (long)conn_state(b, data);
        else
            ret = 1;
        break;
    case BIO_C_GET_CONNECT:
        if (ptr != NULL) {
            pptr = (const char **)ptr;
        }

        if (b->init) {
            if (pptr != NULL) {
                ret = 1;
                if (num == 0) {
                    *pptr = data->param_hostname;
                } else if (num == 1) {
                    *pptr = data->param_port;
                } else if (num == 2) {
                    *pptr = (char *)&(data->ip[0]);
                } else {
                    ret = 0;
                }
            }
            if (num == 3) {
                ret = data->port;
            }
        } else {
            if (pptr != NULL)
                *pptr = "not initialized";
            ret = 0;
        }
        break;
    case BIO_C_SET_CONNECT:
        if (ptr != NULL) {
            b->init = 1;
            if (num == 0) {
                if (data->param_hostname != NULL)
                    OPENSSL_free(data->param_hostname);
                data->param_hostname = BUF_strdup(ptr);
            } else if (num == 1) {
                if (data->param_port != NULL)
                    OPENSSL_free(data->param_port);
                data->param_port = BUF_strdup(ptr);
            } else if (num == 2) {
                char buf[16];
                unsigned char *p = ptr;

                BIO_snprintf(buf, sizeof(buf), "%d.%d.%d.%d",
                             p[0], p[1], p[2], p[3]);
                if (data->param_hostname != NULL)
                    OPENSSL_free(data->param_hostname);
                data->param_hostname = BUF_strdup(buf);
                memcpy(&(data->ip[0]), ptr, 4);
            } else if (num == 3) {
                char buf[DECIMAL_SIZE(int) + 1];

                BIO_snprintf(buf, sizeof(buf), "%d", *(int *)ptr);
                if (data->param_port != NULL)
                    OPENSSL_free(data->param_port);
                data->param_port = BUF_strdup(buf);
                data->port = *(int *)ptr;
            }
        }
        break;
    case BIO_C_SET_NBIO:
        data->nbio = (int)num;
        break;
    case BIO_C_GET_FD:
        if (b->init) {
            ip = (int *)ptr;
            if (ip != NULL)
                *ip = b->num;
            ret = b->num;
        } else
            ret = -1;
        break;
    case BIO_CTRL_GET_CLOSE:
        ret = b->shutdown;
        break;
    case BIO_CTRL_SET_CLOSE:
        b->shutdown = (int)num;
        break;
    case BIO_CTRL_PENDING:
    case BIO_CTRL_WPENDING:
        ret = 0;
        break;
    case BIO_CTRL_FLUSH:
        break;
    case BIO_CTRL_DUP:
        {
            dbio = (BIO *)ptr;
            if (data->param_port)
                BIO_set_conn_port(dbio, data->param_port);
            if (data->param_hostname)
                BIO_set_conn_hostname(dbio, data->param_hostname);
            BIO_set_nbio(dbio, data->nbio);
            /*
             * FIXME: the cast of the function seems unlikely to be a good
             * idea
             */
            (void)BIO_set_info_callback(dbio,
                                        (bio_info_cb *)data->info_callback);
        }
        break;
    case BIO_CTRL_SET_CALLBACK:
        {
# if 0                          /* FIXME: Should this be used? -- Richard
                                 * Levitte */
            BIOerr(BIO_F_CONN_CTRL, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
            ret = -1;
# else
            ret = 0;
# endif
        }
        break;
    case BIO_CTRL_GET_CALLBACK:
        {
            int (**fptr) (const BIO *bio, int state, int xret);

            fptr = (int (**)(const BIO *bio, int state, int xret))ptr;
            *fptr = data->info_callback;
        }
        break;
    default:
        ret = 0;
        break;
    }
    return (ret);
}

static long conn_callback_ctrl(BIO *b, int cmd, bio_info_cb *fp)
{
    long ret = 1;
    BIO_CONNECT *data;

    data = (BIO_CONNECT *)b->ptr;

    switch (cmd) {
    case BIO_CTRL_SET_CALLBACK:
        {
            data->info_callback =
                (int (*)(const struct bio_st *, int, int))fp;
        }
        break;
    default:
        ret = 0;
        break;
    }
    return (ret);
}

static int conn_puts(BIO *bp, const char *str)
{
    int n, ret;

    n = strlen(str);
    ret = conn_write(bp, str, n);
    return (ret);
}

BIO *BIO_new_connect(const char *str)
{
    BIO *ret;

    ret = BIO_new(BIO_s_connect());
    if (ret == NULL)
        return (NULL);
    if (BIO_set_conn_hostname(ret, str))
        return (ret);
    else {
        BIO_free(ret);
        return (NULL);
    }
}

#endif
/* crypto/bio/bio_dgram.c */
/*
 * DTLS implementation written by Nagendra Modadugu
 * (nagendra@cs.stanford.edu) for the OpenSSL project 2005.
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

#include <stdio.h>
#include <errno.h>
#define USE_SOCKETS
// #include "cryptlib.h"

// #include "bio.h"
#ifndef OPENSSL_NO_DGRAM

# if defined(OPENSSL_SYS_VMS)
#  include <sys/timeb.h>
# endif

# ifndef OPENSSL_NO_SCTP
#  include <netinet/sctp.h>
#  include <fcntl.h>
#  define OPENSSL_SCTP_DATA_CHUNK_TYPE            0x00
#  define OPENSSL_SCTP_FORWARD_CUM_TSN_CHUNK_TYPE 0xc0
# endif

# if defined(OPENSSL_SYS_LINUX) && !defined(IP_MTU)
#  define IP_MTU      14        /* linux is lame */
# endif

# if OPENSSL_USE_IPV6 && !defined(IPPROTO_IPV6)
#  define IPPROTO_IPV6 41       /* windows is lame */
# endif

# if defined(__FreeBSD__) && defined(IN6_IS_ADDR_V4MAPPED)
/* Standard definition causes type-punning problems. */
#  undef IN6_IS_ADDR_V4MAPPED
#  define s6_addr32 __u6_addr.__u6_addr32
#  define IN6_IS_ADDR_V4MAPPED(a)               \
        (((a)->s6_addr32[0] == 0) &&          \
         ((a)->s6_addr32[1] == 0) &&          \
         ((a)->s6_addr32[2] == htonl(0x0000ffff)))
# endif

# ifdef WATT32
#  define sock_write SockWrite  /* Watt-32 uses same names */
#  define sock_read  SockRead
#  define sock_puts  SockPuts
# endif

static int dgram_write(BIO *h, const char *buf, int num);
static int dgram_read(BIO *h, char *buf, int size);
static int dgram_puts(BIO *h, const char *str);
static long dgram_ctrl(BIO *h, int cmd, long arg1, void *arg2);
static int dgram_new(BIO *h);
static int dgram_free(BIO *data);
static int dgram_clear(BIO *bio);

# ifndef OPENSSL_NO_SCTP
static int dgram_sctp_write(BIO *h, const char *buf, int num);
static int dgram_sctp_read(BIO *h, char *buf, int size);
static int dgram_sctp_puts(BIO *h, const char *str);
static long dgram_sctp_ctrl(BIO *h, int cmd, long arg1, void *arg2);
static int dgram_sctp_new(BIO *h);
static int dgram_sctp_free(BIO *data);
#  ifdef SCTP_AUTHENTICATION_EVENT
static void dgram_sctp_handle_auth_free_key_event(BIO *b, union sctp_notification
                                                  *snp);
#  endif
# endif

static int BIO_dgram_should_retry(int s);

static void get_current_time(struct timeval *t);

static BIO_METHOD methods_dgramp = {
    BIO_TYPE_DGRAM,
    "datagram socket",
    dgram_write,
    dgram_read,
    dgram_puts,
    NULL,                       /* dgram_gets, */
    dgram_ctrl,
    dgram_new,
    dgram_free,
    NULL,
};

# ifndef OPENSSL_NO_SCTP
static BIO_METHOD methods_dgramp_sctp = {
    BIO_TYPE_DGRAM_SCTP,
    "datagram sctp socket",
    dgram_sctp_write,
    dgram_sctp_read,
    dgram_sctp_puts,
    NULL,                       /* dgram_gets, */
    dgram_sctp_ctrl,
    dgram_sctp_new,
    dgram_sctp_free,
    NULL,
};
# endif

typedef struct bio_dgram_data_st {
    union {
        struct sockaddr sa;
        struct sockaddr_in sa_in;
# if OPENSSL_USE_IPV6
        struct sockaddr_in6 sa_in6;
# endif
    } peer;
    unsigned int connected;
    unsigned int _errno;
    unsigned int mtu;
    struct timeval next_timeout;
    struct timeval socket_timeout;
} bio_dgram_data;

# ifndef OPENSSL_NO_SCTP
typedef struct bio_dgram_sctp_save_message_st {
    BIO *bio;
    char *data;
    int length;
} bio_dgram_sctp_save_message;

typedef struct bio_dgram_sctp_data_st {
    union {
        struct sockaddr sa;
        struct sockaddr_in sa_in;
#  if OPENSSL_USE_IPV6
        struct sockaddr_in6 sa_in6;
#  endif
    } peer;
    unsigned int connected;
    unsigned int _errno;
    unsigned int mtu;
    struct bio_dgram_sctp_sndinfo sndinfo;
    struct bio_dgram_sctp_rcvinfo rcvinfo;
    struct bio_dgram_sctp_prinfo prinfo;
    void (*handle_notifications) (BIO *bio, void *context, void *buf);
    void *notification_context;
    int in_handshake;
    int ccs_rcvd;
    int ccs_sent;
    int save_shutdown;
    int peer_auth_tested;
    bio_dgram_sctp_save_message saved_message;
} bio_dgram_sctp_data;
# endif

BIO_METHOD *BIO_s_datagram(void)
{
    return (&methods_dgramp);
}

BIO *BIO_new_dgram(int fd, int close_flag)
{
    BIO *ret;

    ret = BIO_new(BIO_s_datagram());
    if (ret == NULL)
        return (NULL);
    BIO_set_fd(ret, fd, close_flag);
    return (ret);
}

static int dgram_new(BIO *bi)
{
    bio_dgram_data *data = NULL;

    bi->init = 0;
    bi->num = 0;
    data = OPENSSL_malloc(sizeof(bio_dgram_data));
    if (data == NULL)
        return 0;
    memset(data, 0x00, sizeof(bio_dgram_data));
    bi->ptr = data;

    bi->flags = 0;
    return (1);
}

static int dgram_free(BIO *a)
{
    bio_dgram_data *data;

    if (a == NULL)
        return (0);
    if (!dgram_clear(a))
        return 0;

    data = (bio_dgram_data *)a->ptr;
    if (data != NULL)
        OPENSSL_free(data);

    return (1);
}

static int dgram_clear(BIO *a)
{
    if (a == NULL)
        return (0);
    if (a->shutdown) {
        if (a->init) {
            SHUTDOWN2(a->num);
        }
        a->init = 0;
        a->flags = 0;
    }
    return (1);
}

static void dgram_adjust_rcv_timeout(BIO *b)
{
# if defined(SO_RCVTIMEO)
    bio_dgram_data *data = (bio_dgram_data *)b->ptr;
    union {
        size_t s;
        int i;
    } sz = {
        0
    };

    /* Is a timer active? */
    if (data->next_timeout.tv_sec > 0 || data->next_timeout.tv_usec > 0) {
        struct timeval timenow, timeleft;

        /* Read current socket timeout */
#  ifdef OPENSSL_SYS_WINDOWS
        int timeout;

        sz.i = sizeof(timeout);
        if (getsockopt(b->num, SOL_SOCKET, SO_RCVTIMEO,
                       (void *)&timeout, &sz.i) < 0) {
            perror("getsockopt");
        } else {
            data->socket_timeout.tv_sec = timeout / 1000;
            data->socket_timeout.tv_usec = (timeout % 1000) * 1000;
        }
#  else
        sz.i = sizeof(data->socket_timeout);
        if (getsockopt(b->num, SOL_SOCKET, SO_RCVTIMEO,
                       &(data->socket_timeout), (void *)&sz) < 0) {
            perror("getsockopt");
        } else if (sizeof(sz.s) != sizeof(sz.i) && sz.i == 0)
            OPENSSL_assert(sz.s <= sizeof(data->socket_timeout));
#  endif

        /* Get current time */
        get_current_time(&timenow);

        /* Calculate time left until timer expires */
        memcpy(&timeleft, &(data->next_timeout), sizeof(struct timeval));
        if (timeleft.tv_usec < timenow.tv_usec) {
            timeleft.tv_usec = 1000000 - timenow.tv_usec + timeleft.tv_usec;
            timeleft.tv_sec--;
        } else {
            timeleft.tv_usec -= timenow.tv_usec;
        }
        if (timeleft.tv_sec < timenow.tv_sec) {
            timeleft.tv_sec = 0;
            timeleft.tv_usec = 1;
        } else {
            timeleft.tv_sec -= timenow.tv_sec;
        }

        /*
         * Adjust socket timeout if next handhake message timer will expire
         * earlier.
         */
        if ((data->socket_timeout.tv_sec == 0
             && data->socket_timeout.tv_usec == 0)
            || (data->socket_timeout.tv_sec > timeleft.tv_sec)
            || (data->socket_timeout.tv_sec == timeleft.tv_sec
                && data->socket_timeout.tv_usec >= timeleft.tv_usec)) {
#  ifdef OPENSSL_SYS_WINDOWS
            timeout = timeleft.tv_sec * 1000 + timeleft.tv_usec / 1000;
            if (setsockopt(b->num, SOL_SOCKET, SO_RCVTIMEO,
                           (void *)&timeout, sizeof(timeout)) < 0) {
                perror("setsockopt");
            }
#  else
            if (setsockopt(b->num, SOL_SOCKET, SO_RCVTIMEO, &timeleft,
                           sizeof(struct timeval)) < 0) {
                perror("setsockopt");
            }
#  endif
        }
    }
# endif
}

static void dgram_reset_rcv_timeout(BIO *b)
{
# if defined(SO_RCVTIMEO)
    bio_dgram_data *data = (bio_dgram_data *)b->ptr;

    /* Is a timer active? */
    if (data->next_timeout.tv_sec > 0 || data->next_timeout.tv_usec > 0) {
#  ifdef OPENSSL_SYS_WINDOWS
        int timeout = data->socket_timeout.tv_sec * 1000 +
            data->socket_timeout.tv_usec / 1000;
        if (setsockopt(b->num, SOL_SOCKET, SO_RCVTIMEO,
                       (void *)&timeout, sizeof(timeout)) < 0) {
            perror("setsockopt");
        }
#  else
        if (setsockopt
            (b->num, SOL_SOCKET, SO_RCVTIMEO, &(data->socket_timeout),
             sizeof(struct timeval)) < 0) {
            perror("setsockopt");
        }
#  endif
    }
# endif
}

static int dgram_read(BIO *b, char *out, int outl)
{
    int ret = 0;
    bio_dgram_data *data = (bio_dgram_data *)b->ptr;

    struct {
        /*
         * See commentary in b_sock.c. <appro>
         */
        union {
            size_t s;
            int i;
        } len;
        union {
            struct sockaddr sa;
            struct sockaddr_in sa_in;
# if OPENSSL_USE_IPV6
            struct sockaddr_in6 sa_in6;
# endif
        } peer;
    } sa;

    sa.len.s = 0;
    sa.len.i = sizeof(sa.peer);

    if (out != NULL) {
        clear_socket_error();
        memset(&sa.peer, 0x00, sizeof(sa.peer));
        dgram_adjust_rcv_timeout(b);
        ret = recvfrom(b->num, out, outl, 0, &sa.peer.sa, (void *)&sa.len);
        if (sizeof(sa.len.i) != sizeof(sa.len.s) && sa.len.i == 0) {
            OPENSSL_assert(sa.len.s <= sizeof(sa.peer));
            sa.len.i = (int)sa.len.s;
        }

        if (!data->connected && ret >= 0)
            BIO_ctrl(b, BIO_CTRL_DGRAM_SET_PEER, 0, &sa.peer);

        BIO_clear_retry_flags(b);
        if (ret < 0) {
            if (BIO_dgram_should_retry(ret)) {
                BIO_set_retry_read(b);
                data->_errno = get_last_socket_error();
            }
        }

        dgram_reset_rcv_timeout(b);
    }
    return (ret);
}

static int dgram_write(BIO *b, const char *in, int inl)
{
    int ret;
    bio_dgram_data *data = (bio_dgram_data *)b->ptr;
    clear_socket_error();

    if (data->connected)
        ret = writesocket(b->num, in, inl);
    else {
        int peerlen = sizeof(data->peer);

        if (data->peer.sa.sa_family == AF_INET)
            peerlen = sizeof(data->peer.sa_in);
# if OPENSSL_USE_IPV6
        else if (data->peer.sa.sa_family == AF_INET6)
            peerlen = sizeof(data->peer.sa_in6);
# endif
# if defined(NETWARE_CLIB) && defined(NETWARE_BSDSOCK)
        ret = sendto(b->num, (char *)in, inl, 0, &data->peer.sa, peerlen);
# else
        ret = sendto(b->num, in, inl, 0, &data->peer.sa, peerlen);
# endif
    }

    BIO_clear_retry_flags(b);
    if (ret <= 0) {
        if (BIO_dgram_should_retry(ret)) {
            BIO_set_retry_write(b);
            data->_errno = get_last_socket_error();

# if 0                          /* higher layers are responsible for querying
                                 * MTU, if necessary */
            if (data->_errno == EMSGSIZE)
                /* retrieve the new MTU */
                BIO_ctrl(b, BIO_CTRL_DGRAM_QUERY_MTU, 0, NULL);
# endif
        }
    }
    return (ret);
}

static long dgram_get_mtu_overhead(bio_dgram_data *data)
{
    long ret;

    switch (data->peer.sa.sa_family) {
    case AF_INET:
        /*
         * Assume this is UDP - 20 bytes for IP, 8 bytes for UDP
         */
        ret = 28;
        break;
# if OPENSSL_USE_IPV6
    case AF_INET6:
#  ifdef IN6_IS_ADDR_V4MAPPED
        if (IN6_IS_ADDR_V4MAPPED(&data->peer.sa_in6.sin6_addr))
            /*
             * Assume this is UDP - 20 bytes for IP, 8 bytes for UDP
             */
            ret = 28;
        else
#  endif
            /*
             * Assume this is UDP - 40 bytes for IP, 8 bytes for UDP
             */
            ret = 48;
        break;
# endif
    default:
        /* We don't know. Go with the historical default */
        ret = 28;
        break;
    }
    return ret;
}

static long dgram_ctrl(BIO *b, int cmd, long num, void *ptr)
{
    long ret = 1;
    int *ip;
    struct sockaddr *to = NULL;
    bio_dgram_data *data = NULL;
    int sockopt_val = 0;
# if defined(OPENSSL_SYS_LINUX) && (defined(IP_MTU_DISCOVER) || defined(IP_MTU))
    socklen_t sockopt_len;      /* assume that system supporting IP_MTU is
                                 * modern enough to define socklen_t */
    socklen_t addr_len;
    union {
        struct sockaddr sa;
        struct sockaddr_in s4;
#  if OPENSSL_USE_IPV6
        struct sockaddr_in6 s6;
#  endif
    } addr;
# endif

    data = (bio_dgram_data *)b->ptr;

    switch (cmd) {
    case BIO_CTRL_RESET:
        num = 0;
        ret = 0;
        break;
    case BIO_CTRL_INFO:
        ret = 0;
        break;
    case BIO_C_SET_FD:
        dgram_clear(b);
        b->num = *((int *)ptr);
        b->shutdown = (int)num;
        b->init = 1;
        break;
    case BIO_C_GET_FD:
        if (b->init) {
            ip = (int *)ptr;
            if (ip != NULL)
                *ip = b->num;
            ret = b->num;
        } else
            ret = -1;
        break;
    case BIO_CTRL_GET_CLOSE:
        ret = b->shutdown;
        break;
    case BIO_CTRL_SET_CLOSE:
        b->shutdown = (int)num;
        break;
    case BIO_CTRL_PENDING:
    case BIO_CTRL_WPENDING:
        ret = 0;
        break;
    case BIO_CTRL_DUP:
    case BIO_CTRL_FLUSH:
        ret = 1;
        break;
    case BIO_CTRL_DGRAM_CONNECT:
        to = (struct sockaddr *)ptr;
# if 0
        if (connect(b->num, to, sizeof(struct sockaddr)) < 0) {
            perror("connect");
            ret = 0;
        } else {
# endif
            switch (to->sa_family) {
            case AF_INET:
                memcpy(&data->peer, to, sizeof(data->peer.sa_in));
                break;
# if OPENSSL_USE_IPV6
            case AF_INET6:
                memcpy(&data->peer, to, sizeof(data->peer.sa_in6));
                break;
# endif
            default:
                memcpy(&data->peer, to, sizeof(data->peer.sa));
                break;
            }
# if 0
        }
# endif
        break;
        /* (Linux)kernel sets DF bit on outgoing IP packets */
    case BIO_CTRL_DGRAM_MTU_DISCOVER:
# if defined(OPENSSL_SYS_LINUX) && defined(IP_MTU_DISCOVER) && defined(IP_PMTUDISC_DO)
        addr_len = (socklen_t) sizeof(addr);
        memset((void *)&addr, 0, sizeof(addr));
        if (getsockname(b->num, &addr.sa, &addr_len) < 0) {
            ret = 0;
            break;
        }
        switch (addr.sa.sa_family) {
        case AF_INET:
            sockopt_val = IP_PMTUDISC_DO;
            if ((ret = setsockopt(b->num, IPPROTO_IP, IP_MTU_DISCOVER,
                                  &sockopt_val, sizeof(sockopt_val))) < 0)
                perror("setsockopt");
            break;
#  if OPENSSL_USE_IPV6 && defined(IPV6_MTU_DISCOVER) && defined(IPV6_PMTUDISC_DO)
        case AF_INET6:
            sockopt_val = IPV6_PMTUDISC_DO;
            if ((ret = setsockopt(b->num, IPPROTO_IPV6, IPV6_MTU_DISCOVER,
                                  &sockopt_val, sizeof(sockopt_val))) < 0)
                perror("setsockopt");
            break;
#  endif
        default:
            ret = -1;
            break;
        }
        ret = -1;
# else
        break;
# endif
    case BIO_CTRL_DGRAM_QUERY_MTU:
# if defined(OPENSSL_SYS_LINUX) && defined(IP_MTU)
        addr_len = (socklen_t) sizeof(addr);
        memset((void *)&addr, 0, sizeof(addr));
        if (getsockname(b->num, &addr.sa, &addr_len) < 0) {
            ret = 0;
            break;
        }
        sockopt_len = sizeof(sockopt_val);
        switch (addr.sa.sa_family) {
        case AF_INET:
            if ((ret =
                 getsockopt(b->num, IPPROTO_IP, IP_MTU, (void *)&sockopt_val,
                            &sockopt_len)) < 0 || sockopt_val < 0) {
                ret = 0;
            } else {
                /*
                 * we assume that the transport protocol is UDP and no IP
                 * options are used.
                 */
                data->mtu = sockopt_val - 8 - 20;
                ret = data->mtu;
            }
            break;
#  if OPENSSL_USE_IPV6 && defined(IPV6_MTU)
        case AF_INET6:
            if ((ret =
                 getsockopt(b->num, IPPROTO_IPV6, IPV6_MTU,
                            (void *)&sockopt_val, &sockopt_len)) < 0
                || sockopt_val < 0) {
                ret = 0;
            } else {
                /*
                 * we assume that the transport protocol is UDP and no IPV6
                 * options are used.
                 */
                data->mtu = sockopt_val - 8 - 40;
                ret = data->mtu;
            }
            break;
#  endif
        default:
            ret = 0;
            break;
        }
# else
        ret = 0;
# endif
        break;
    case BIO_CTRL_DGRAM_GET_FALLBACK_MTU:
        ret = -dgram_get_mtu_overhead(data);
        switch (data->peer.sa.sa_family) {
        case AF_INET:
            ret += 576;
            break;
# if OPENSSL_USE_IPV6
        case AF_INET6:
#  ifdef IN6_IS_ADDR_V4MAPPED
            if (IN6_IS_ADDR_V4MAPPED(&data->peer.sa_in6.sin6_addr))
                ret += 576;
            else
#  endif
                ret += 1280;
            break;
# endif
        default:
            ret += 576;
            break;
        }
        break;
    case BIO_CTRL_DGRAM_GET_MTU:
        return data->mtu;
        break;
    case BIO_CTRL_DGRAM_SET_MTU:
        data->mtu = num;
        ret = num;
        break;
    case BIO_CTRL_DGRAM_SET_CONNECTED:
        to = (struct sockaddr *)ptr;

        if (to != NULL) {
            data->connected = 1;
            switch (to->sa_family) {
            case AF_INET:
                memcpy(&data->peer, to, sizeof(data->peer.sa_in));
                break;
# if OPENSSL_USE_IPV6
            case AF_INET6:
                memcpy(&data->peer, to, sizeof(data->peer.sa_in6));
                break;
# endif
            default:
                memcpy(&data->peer, to, sizeof(data->peer.sa));
                break;
            }
        } else {
            data->connected = 0;
            memset(&(data->peer), 0x00, sizeof(data->peer));
        }
        break;
    case BIO_CTRL_DGRAM_GET_PEER:
        switch (data->peer.sa.sa_family) {
        case AF_INET:
            ret = sizeof(data->peer.sa_in);
            break;
# if OPENSSL_USE_IPV6
        case AF_INET6:
            ret = sizeof(data->peer.sa_in6);
            break;
# endif
        default:
            ret = sizeof(data->peer.sa);
            break;
        }
        if (num == 0 || num > ret)
            num = ret;
        memcpy(ptr, &data->peer, (ret = num));
        break;
    case BIO_CTRL_DGRAM_SET_PEER:
        to = (struct sockaddr *)ptr;
        switch (to->sa_family) {
        case AF_INET:
            memcpy(&data->peer, to, sizeof(data->peer.sa_in));
            break;
# if OPENSSL_USE_IPV6
        case AF_INET6:
            memcpy(&data->peer, to, sizeof(data->peer.sa_in6));
            break;
# endif
        default:
            memcpy(&data->peer, to, sizeof(data->peer.sa));
            break;
        }
        break;
    case BIO_CTRL_DGRAM_SET_NEXT_TIMEOUT:
        memcpy(&(data->next_timeout), ptr, sizeof(struct timeval));
        break;
# if defined(SO_RCVTIMEO)
    case BIO_CTRL_DGRAM_SET_RECV_TIMEOUT:
#  ifdef OPENSSL_SYS_WINDOWS
        {
            struct timeval *tv = (struct timeval *)ptr;
            int timeout = tv->tv_sec * 1000 + tv->tv_usec / 1000;
            if (setsockopt(b->num, SOL_SOCKET, SO_RCVTIMEO,
                           (void *)&timeout, sizeof(timeout)) < 0) {
                perror("setsockopt");
                ret = -1;
            }
        }
#  else
        if (setsockopt(b->num, SOL_SOCKET, SO_RCVTIMEO, ptr,
                       sizeof(struct timeval)) < 0) {
            perror("setsockopt");
            ret = -1;
        }
#  endif
        break;
    case BIO_CTRL_DGRAM_GET_RECV_TIMEOUT:
        {
            union {
                size_t s;
                int i;
            } sz = {
                0
            };
#  ifdef OPENSSL_SYS_WINDOWS
            int timeout;
            struct timeval *tv = (struct timeval *)ptr;

            sz.i = sizeof(timeout);
            if (getsockopt(b->num, SOL_SOCKET, SO_RCVTIMEO,
                           (void *)&timeout, &sz.i) < 0) {
                perror("getsockopt");
                ret = -1;
            } else {
                tv->tv_sec = timeout / 1000;
                tv->tv_usec = (timeout % 1000) * 1000;
                ret = sizeof(*tv);
            }
#  else
            sz.i = sizeof(struct timeval);
            if (getsockopt(b->num, SOL_SOCKET, SO_RCVTIMEO,
                           ptr, (void *)&sz) < 0) {
                perror("getsockopt");
                ret = -1;
            } else if (sizeof(sz.s) != sizeof(sz.i) && sz.i == 0) {
                OPENSSL_assert(sz.s <= sizeof(struct timeval));
                ret = (int)sz.s;
            } else
                ret = sz.i;
#  endif
        }
        break;
# endif
# if defined(SO_SNDTIMEO)
    case BIO_CTRL_DGRAM_SET_SEND_TIMEOUT:
#  ifdef OPENSSL_SYS_WINDOWS
        {
            struct timeval *tv = (struct timeval *)ptr;
            int timeout = tv->tv_sec * 1000 + tv->tv_usec / 1000;
            if (setsockopt(b->num, SOL_SOCKET, SO_SNDTIMEO,
                           (void *)&timeout, sizeof(timeout)) < 0) {
                perror("setsockopt");
                ret = -1;
            }
        }
#  else
        if (setsockopt(b->num, SOL_SOCKET, SO_SNDTIMEO, ptr,
                       sizeof(struct timeval)) < 0) {
            perror("setsockopt");
            ret = -1;
        }
#  endif
        break;
    case BIO_CTRL_DGRAM_GET_SEND_TIMEOUT:
        {
            union {
                size_t s;
                int i;
            } sz = {
                0
            };
#  ifdef OPENSSL_SYS_WINDOWS
            int timeout;
            struct timeval *tv = (struct timeval *)ptr;

            sz.i = sizeof(timeout);
            if (getsockopt(b->num, SOL_SOCKET, SO_SNDTIMEO,
                           (void *)&timeout, &sz.i) < 0) {
                perror("getsockopt");
                ret = -1;
            } else {
                tv->tv_sec = timeout / 1000;
                tv->tv_usec = (timeout % 1000) * 1000;
                ret = sizeof(*tv);
            }
#  else
            sz.i = sizeof(struct timeval);
            if (getsockopt(b->num, SOL_SOCKET, SO_SNDTIMEO,
                           ptr, (void *)&sz) < 0) {
                perror("getsockopt");
                ret = -1;
            } else if (sizeof(sz.s) != sizeof(sz.i) && sz.i == 0) {
                OPENSSL_assert(sz.s <= sizeof(struct timeval));
                ret = (int)sz.s;
            } else
                ret = sz.i;
#  endif
        }
        break;
# endif
    case BIO_CTRL_DGRAM_GET_SEND_TIMER_EXP:
        /* fall-through */
    case BIO_CTRL_DGRAM_GET_RECV_TIMER_EXP:
# ifdef OPENSSL_SYS_WINDOWS
        if (data->_errno == WSAETIMEDOUT)
# else
        if (data->_errno == EAGAIN)
# endif
        {
            ret = 1;
            data->_errno = 0;
        } else
            ret = 0;
        break;
# ifdef EMSGSIZE
    case BIO_CTRL_DGRAM_MTU_EXCEEDED:
        if (data->_errno == EMSGSIZE) {
            ret = 1;
            data->_errno = 0;
        } else
            ret = 0;
        break;
# endif
    case BIO_CTRL_DGRAM_SET_DONT_FRAG:
        sockopt_val = num ? 1 : 0;

        switch (data->peer.sa.sa_family) {
        case AF_INET:
# if defined(IP_DONTFRAG)
            if ((ret = setsockopt(b->num, IPPROTO_IP, IP_DONTFRAG,
                                  &sockopt_val, sizeof(sockopt_val))) < 0) {
                perror("setsockopt");
                ret = -1;
            }
# elif defined(OPENSSL_SYS_LINUX) && defined(IP_MTU_DISCOVER) && defined (IP_PMTUDISC_PROBE)
            if ((sockopt_val = num ? IP_PMTUDISC_PROBE : IP_PMTUDISC_DONT),
                (ret = setsockopt(b->num, IPPROTO_IP, IP_MTU_DISCOVER,
                                  &sockopt_val, sizeof(sockopt_val))) < 0) {
                perror("setsockopt");
                ret = -1;
            }
# elif defined(OPENSSL_SYS_WINDOWS) && defined(IP_DONTFRAGMENT)
            if ((ret = setsockopt(b->num, IPPROTO_IP, IP_DONTFRAGMENT,
                                  (const char *)&sockopt_val,
                                  sizeof(sockopt_val))) < 0) {
                perror("setsockopt");
                ret = -1;
            }
# else
            ret = -1;
# endif
            break;
# if OPENSSL_USE_IPV6
        case AF_INET6:
#  if defined(IPV6_DONTFRAG)
            if ((ret = setsockopt(b->num, IPPROTO_IPV6, IPV6_DONTFRAG,
                                  (const void *)&sockopt_val,
                                  sizeof(sockopt_val))) < 0) {
                perror("setsockopt");
                ret = -1;
            }
#  elif defined(OPENSSL_SYS_LINUX) && defined(IPV6_MTUDISCOVER)
            if ((sockopt_val = num ? IP_PMTUDISC_PROBE : IP_PMTUDISC_DONT),
                (ret = setsockopt(b->num, IPPROTO_IPV6, IPV6_MTU_DISCOVER,
                                  &sockopt_val, sizeof(sockopt_val))) < 0) {
                perror("setsockopt");
                ret = -1;
            }
#  else
            ret = -1;
#  endif
            break;
# endif
        default:
            ret = -1;
            break;
        }
        break;
    case BIO_CTRL_DGRAM_GET_MTU_OVERHEAD:
        ret = dgram_get_mtu_overhead(data);
        break;
    default:
        ret = 0;
        break;
    }
    return (ret);
}

static int dgram_puts(BIO *bp, const char *str)
{
    int n, ret;

    n = strlen(str);
    ret = dgram_write(bp, str, n);
    return (ret);
}

# ifndef OPENSSL_NO_SCTP
BIO_METHOD *BIO_s_datagram_sctp(void)
{
    return (&methods_dgramp_sctp);
}

BIO *BIO_new_dgram_sctp(int fd, int close_flag)
{
    BIO *bio;
    int ret, optval = 20000;
    int auth_data = 0, auth_forward = 0;
    unsigned char *p;
    struct sctp_authchunk auth;
    struct sctp_authchunks *authchunks;
    socklen_t sockopt_len;
#  ifdef SCTP_AUTHENTICATION_EVENT
#   ifdef SCTP_EVENT
    struct sctp_event event;
#   else
    struct sctp_event_subscribe event;
#   endif
#  endif

    bio = BIO_new(BIO_s_datagram_sctp());
    if (bio == NULL)
        return (NULL);
    BIO_set_fd(bio, fd, close_flag);

    /* Activate SCTP-AUTH for DATA and FORWARD-TSN chunks */
    auth.sauth_chunk = OPENSSL_SCTP_DATA_CHUNK_TYPE;
    ret =
        setsockopt(fd, IPPROTO_SCTP, SCTP_AUTH_CHUNK, &auth,
                   sizeof(struct sctp_authchunk));
    if (ret < 0) {
        BIO_vfree(bio);
        return (NULL);
    }
    auth.sauth_chunk = OPENSSL_SCTP_FORWARD_CUM_TSN_CHUNK_TYPE;
    ret =
        setsockopt(fd, IPPROTO_SCTP, SCTP_AUTH_CHUNK, &auth,
                   sizeof(struct sctp_authchunk));
    if (ret < 0) {
        BIO_vfree(bio);
        return (NULL);
    }

    /*
     * Test if activation was successful. When using accept(), SCTP-AUTH has
     * to be activated for the listening socket already, otherwise the
     * connected socket won't use it.
     */
    sockopt_len = (socklen_t) (sizeof(sctp_assoc_t) + 256 * sizeof(uint8_t));
    authchunks = OPENSSL_malloc(sockopt_len);
    if (!authchunks) {
        BIO_vfree(bio);
        return (NULL);
    }
    memset(authchunks, 0, sizeof(sockopt_len));
    ret =
        getsockopt(fd, IPPROTO_SCTP, SCTP_LOCAL_AUTH_CHUNKS, authchunks,
                   &sockopt_len);

    if (ret < 0) {
        OPENSSL_free(authchunks);
        BIO_vfree(bio);
        return (NULL);
    }

    for (p = (unsigned char *)authchunks->gauth_chunks;
         p < (unsigned char *)authchunks + sockopt_len;
         p += sizeof(uint8_t)) {
        if (*p == OPENSSL_SCTP_DATA_CHUNK_TYPE)
            auth_data = 1;
        if (*p == OPENSSL_SCTP_FORWARD_CUM_TSN_CHUNK_TYPE)
            auth_forward = 1;
    }

    OPENSSL_free(authchunks);

    OPENSSL_assert(auth_data);
    OPENSSL_assert(auth_forward);

#  ifdef SCTP_AUTHENTICATION_EVENT
#   ifdef SCTP_EVENT
    memset(&event, 0, sizeof(struct sctp_event));
    event.se_assoc_id = 0;
    event.se_type = SCTP_AUTHENTICATION_EVENT;
    event.se_on = 1;
    ret =
        setsockopt(fd, IPPROTO_SCTP, SCTP_EVENT, &event,
                   sizeof(struct sctp_event));
    if (ret < 0) {
        BIO_vfree(bio);
        return (NULL);
    }
#   else
    sockopt_len = (socklen_t) sizeof(struct sctp_event_subscribe);
    ret = getsockopt(fd, IPPROTO_SCTP, SCTP_EVENTS, &event, &sockopt_len);
    if (ret < 0) {
        BIO_vfree(bio);
        return (NULL);
    }

    event.sctp_authentication_event = 1;

    ret =
        setsockopt(fd, IPPROTO_SCTP, SCTP_EVENTS, &event,
                   sizeof(struct sctp_event_subscribe));
    if (ret < 0) {
        BIO_vfree(bio);
        return (NULL);
    }
#   endif
#  endif

    /*
     * Disable partial delivery by setting the min size larger than the max
     * record size of 2^14 + 2048 + 13
     */
    ret =
        setsockopt(fd, IPPROTO_SCTP, SCTP_PARTIAL_DELIVERY_POINT, &optval,
                   sizeof(optval));
    if (ret < 0) {
        BIO_vfree(bio);
        return (NULL);
    }

    return (bio);
}

int BIO_dgram_is_sctp(BIO *bio)
{
    return (BIO_method_type(bio) == BIO_TYPE_DGRAM_SCTP);
}

static int dgram_sctp_new(BIO *bi)
{
    bio_dgram_sctp_data *data = NULL;

    bi->init = 0;
    bi->num = 0;
    data = OPENSSL_malloc(sizeof(bio_dgram_sctp_data));
    if (data == NULL)
        return 0;
    memset(data, 0x00, sizeof(bio_dgram_sctp_data));
#  ifdef SCTP_PR_SCTP_NONE
    data->prinfo.pr_policy = SCTP_PR_SCTP_NONE;
#  endif
    bi->ptr = data;

    bi->flags = 0;
    return (1);
}

static int dgram_sctp_free(BIO *a)
{
    bio_dgram_sctp_data *data;

    if (a == NULL)
        return (0);
    if (!dgram_clear(a))
        return 0;

    data = (bio_dgram_sctp_data *) a->ptr;
    if (data != NULL) {
        if (data->saved_message.data != NULL)
            OPENSSL_free(data->saved_message.data);
        OPENSSL_free(data);
    }

    return (1);
}

#  ifdef SCTP_AUTHENTICATION_EVENT
void dgram_sctp_handle_auth_free_key_event(BIO *b,
                                           union sctp_notification *snp)
{
    int ret;
    struct sctp_authkey_event *authkeyevent = &snp->sn_auth_event;

    if (authkeyevent->auth_indication == SCTP_AUTH_FREE_KEY) {
        struct sctp_authkeyid authkeyid;

        /* delete key */
        authkeyid.scact_keynumber = authkeyevent->auth_keynumber;
        ret = setsockopt(b->num, IPPROTO_SCTP, SCTP_AUTH_DELETE_KEY,
                         &authkeyid, sizeof(struct sctp_authkeyid));
    }
}
#  endif

static int dgram_sctp_read(BIO *b, char *out, int outl)
{
    int ret = 0, n = 0, i, optval;
    socklen_t optlen;
    bio_dgram_sctp_data *data = (bio_dgram_sctp_data *) b->ptr;
    union sctp_notification *snp;
    struct msghdr msg;
    struct iovec iov;
    struct cmsghdr *cmsg;
    char cmsgbuf[512];

    if (out != NULL) {
        clear_socket_error();

        do {
            memset(&data->rcvinfo, 0x00,
                   sizeof(struct bio_dgram_sctp_rcvinfo));
            iov.iov_base = out;
            iov.iov_len = outl;
            msg.msg_name = NULL;
            msg.msg_namelen = 0;
            msg.msg_iov = &iov;
            msg.msg_iovlen = 1;
            msg.msg_control = cmsgbuf;
            msg.msg_controllen = 512;
            msg.msg_flags = 0;
            n = recvmsg(b->num, &msg, 0);

            if (n <= 0) {
                if (n < 0)
                    ret = n;
                break;
            }

            if (msg.msg_controllen > 0) {
                for (cmsg = CMSG_FIRSTHDR(&msg); cmsg;
                     cmsg = CMSG_NXTHDR(&msg, cmsg)) {
                    if (cmsg->cmsg_level != IPPROTO_SCTP)
                        continue;
#  ifdef SCTP_RCVINFO
                    if (cmsg->cmsg_type == SCTP_RCVINFO) {
                        struct sctp_rcvinfo *rcvinfo;

                        rcvinfo = (struct sctp_rcvinfo *)CMSG_DATA(cmsg);
                        data->rcvinfo.rcv_sid = rcvinfo->rcv_sid;
                        data->rcvinfo.rcv_ssn = rcvinfo->rcv_ssn;
                        data->rcvinfo.rcv_flags = rcvinfo->rcv_flags;
                        data->rcvinfo.rcv_ppid = rcvinfo->rcv_ppid;
                        data->rcvinfo.rcv_tsn = rcvinfo->rcv_tsn;
                        data->rcvinfo.rcv_cumtsn = rcvinfo->rcv_cumtsn;
                        data->rcvinfo.rcv_context = rcvinfo->rcv_context;
                    }
#  endif
#  ifdef SCTP_SNDRCV
                    if (cmsg->cmsg_type == SCTP_SNDRCV) {
                        struct sctp_sndrcvinfo *sndrcvinfo;

                        sndrcvinfo =
                            (struct sctp_sndrcvinfo *)CMSG_DATA(cmsg);
                        data->rcvinfo.rcv_sid = sndrcvinfo->sinfo_stream;
                        data->rcvinfo.rcv_ssn = sndrcvinfo->sinfo_ssn;
                        data->rcvinfo.rcv_flags = sndrcvinfo->sinfo_flags;
                        data->rcvinfo.rcv_ppid = sndrcvinfo->sinfo_ppid;
                        data->rcvinfo.rcv_tsn = sndrcvinfo->sinfo_tsn;
                        data->rcvinfo.rcv_cumtsn = sndrcvinfo->sinfo_cumtsn;
                        data->rcvinfo.rcv_context = sndrcvinfo->sinfo_context;
                    }
#  endif
                }
            }

            if (msg.msg_flags & MSG_NOTIFICATION) {
                snp = (union sctp_notification *)out;
                if (snp->sn_header.sn_type == SCTP_SENDER_DRY_EVENT) {
#  ifdef SCTP_EVENT
                    struct sctp_event event;
#  else
                    struct sctp_event_subscribe event;
                    socklen_t eventsize;
#  endif
                    /*
                     * If a message has been delayed until the socket is dry,
                     * it can be sent now.
                     */
                    if (data->saved_message.length > 0) {
                        dgram_sctp_write(data->saved_message.bio,
                                         data->saved_message.data,
                                         data->saved_message.length);
                        OPENSSL_free(data->saved_message.data);
                        data->saved_message.data = NULL;
                        data->saved_message.length = 0;
                    }

                    /* disable sender dry event */
#  ifdef SCTP_EVENT
                    memset(&event, 0, sizeof(struct sctp_event));
                    event.se_assoc_id = 0;
                    event.se_type = SCTP_SENDER_DRY_EVENT;
                    event.se_on = 0;
                    i = setsockopt(b->num, IPPROTO_SCTP, SCTP_EVENT, &event,
                                   sizeof(struct sctp_event));
                    if (i < 0) {
                        ret = i;
                        break;
                    }
#  else
                    eventsize = sizeof(struct sctp_event_subscribe);
                    i = getsockopt(b->num, IPPROTO_SCTP, SCTP_EVENTS, &event,
                                   &eventsize);
                    if (i < 0) {
                        ret = i;
                        break;
                    }

                    event.sctp_sender_dry_event = 0;

                    i = setsockopt(b->num, IPPROTO_SCTP, SCTP_EVENTS, &event,
                                   sizeof(struct sctp_event_subscribe));
                    if (i < 0) {
                        ret = i;
                        break;
                    }
#  endif
                }
#  ifdef SCTP_AUTHENTICATION_EVENT
                if (snp->sn_header.sn_type == SCTP_AUTHENTICATION_EVENT)
                    dgram_sctp_handle_auth_free_key_event(b, snp);
#  endif

                if (data->handle_notifications != NULL)
                    data->handle_notifications(b, data->notification_context,
                                               (void *)out);

                memset(out, 0, outl);
            } else
                ret += n;
        }
        while ((msg.msg_flags & MSG_NOTIFICATION) && (msg.msg_flags & MSG_EOR)
               && (ret < outl));

        if (ret > 0 && !(msg.msg_flags & MSG_EOR)) {
            /* Partial message read, this should never happen! */

            /*
             * The buffer was too small, this means the peer sent a message
             * that was larger than allowed.
             */
            if (ret == outl)
                return -1;

            /*
             * Test if socket buffer can handle max record size (2^14 + 2048
             * + 13)
             */
            optlen = (socklen_t) sizeof(int);
            ret = getsockopt(b->num, SOL_SOCKET, SO_RCVBUF, &optval, &optlen);
            if (ret >= 0)
                OPENSSL_assert(optval >= 18445);

            /*
             * Test if SCTP doesn't partially deliver below max record size
             * (2^14 + 2048 + 13)
             */
            optlen = (socklen_t) sizeof(int);
            ret =
                getsockopt(b->num, IPPROTO_SCTP, SCTP_PARTIAL_DELIVERY_POINT,
                           &optval, &optlen);
            if (ret >= 0)
                OPENSSL_assert(optval >= 18445);

            /*
             * Partially delivered notification??? Probably a bug....
             */
            OPENSSL_assert(!(msg.msg_flags & MSG_NOTIFICATION));

            /*
             * Everything seems ok till now, so it's most likely a message
             * dropped by PR-SCTP.
             */
            memset(out, 0, outl);
            BIO_set_retry_read(b);
            return -1;
        }

        BIO_clear_retry_flags(b);
        if (ret < 0) {
            if (BIO_dgram_should_retry(ret)) {
                BIO_set_retry_read(b);
                data->_errno = get_last_socket_error();
            }
        }

        /* Test if peer uses SCTP-AUTH before continuing */
        if (!data->peer_auth_tested) {
            int ii, auth_data = 0, auth_forward = 0;
            unsigned char *p;
            struct sctp_authchunks *authchunks;

            optlen =
                (socklen_t) (sizeof(sctp_assoc_t) + 256 * sizeof(uint8_t));
            authchunks = OPENSSL_malloc(optlen);
            if (!authchunks) {
                BIOerr(BIO_F_DGRAM_SCTP_READ, ERR_R_MALLOC_FAILURE);
                return -1;
            }
            memset(authchunks, 0, sizeof(optlen));
            ii = getsockopt(b->num, IPPROTO_SCTP, SCTP_PEER_AUTH_CHUNKS,
                            authchunks, &optlen);

            if (ii >= 0)
                for (p = (unsigned char *)authchunks->gauth_chunks;
                     p < (unsigned char *)authchunks + optlen;
                     p += sizeof(uint8_t)) {
                    if (*p == OPENSSL_SCTP_DATA_CHUNK_TYPE)
                        auth_data = 1;
                    if (*p == OPENSSL_SCTP_FORWARD_CUM_TSN_CHUNK_TYPE)
                        auth_forward = 1;
                }

            OPENSSL_free(authchunks);

            if (!auth_data || !auth_forward) {
                BIOerr(BIO_F_DGRAM_SCTP_READ, BIO_R_CONNECT_ERROR);
                return -1;
            }

            data->peer_auth_tested = 1;
        }
    }
    return (ret);
}

static int dgram_sctp_write(BIO *b, const char *in, int inl)
{
    int ret;
    bio_dgram_sctp_data *data = (bio_dgram_sctp_data *) b->ptr;
    struct bio_dgram_sctp_sndinfo *sinfo = &(data->sndinfo);
    struct bio_dgram_sctp_prinfo *pinfo = &(data->prinfo);
    struct bio_dgram_sctp_sndinfo handshake_sinfo;
    struct iovec iov[1];
    struct msghdr msg;
    struct cmsghdr *cmsg;
#  if defined(SCTP_SNDINFO) && defined(SCTP_PRINFO)
    char cmsgbuf[CMSG_SPACE(sizeof(struct sctp_sndinfo)) +
                 CMSG_SPACE(sizeof(struct sctp_prinfo))];
    struct sctp_sndinfo *sndinfo;
    struct sctp_prinfo *prinfo;
#  else
    char cmsgbuf[CMSG_SPACE(sizeof(struct sctp_sndrcvinfo))];
    struct sctp_sndrcvinfo *sndrcvinfo;
#  endif

    clear_socket_error();

    /*
     * If we're send anything else than application data, disable all user
     * parameters and flags.
     */
    if (in[0] != 23) {
        memset(&handshake_sinfo, 0x00, sizeof(struct bio_dgram_sctp_sndinfo));
#  ifdef SCTP_SACK_IMMEDIATELY
        handshake_sinfo.snd_flags = SCTP_SACK_IMMEDIATELY;
#  endif
        sinfo = &handshake_sinfo;
    }

    /*
     * If we have to send a shutdown alert message and the socket is not dry
     * yet, we have to save it and send it as soon as the socket gets dry.
     */
    if (data->save_shutdown && !BIO_dgram_sctp_wait_for_dry(b)) {
        char *tmp;
        data->saved_message.bio = b;
        if (!(tmp = OPENSSL_malloc(inl))) {
            BIOerr(BIO_F_DGRAM_SCTP_WRITE, ERR_R_MALLOC_FAILURE);
            return -1;
        }
        if (data->saved_message.data)
            OPENSSL_free(data->saved_message.data);
        data->saved_message.data = tmp;
        memcpy(data->saved_message.data, in, inl);
        data->saved_message.length = inl;
        return inl;
    }

    iov[0].iov_base = (char *)in;
    iov[0].iov_len = inl;
    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;
    msg.msg_control = (caddr_t) cmsgbuf;
    msg.msg_controllen = 0;
    msg.msg_flags = 0;
#  if defined(SCTP_SNDINFO) && defined(SCTP_PRINFO)
    cmsg = (struct cmsghdr *)cmsgbuf;
    cmsg->cmsg_level = IPPROTO_SCTP;
    cmsg->cmsg_type = SCTP_SNDINFO;
    cmsg->cmsg_len = CMSG_LEN(sizeof(struct sctp_sndinfo));
    sndinfo = (struct sctp_sndinfo *)CMSG_DATA(cmsg);
    memset(sndinfo, 0, sizeof(struct sctp_sndinfo));
    sndinfo->snd_sid = sinfo->snd_sid;
    sndinfo->snd_flags = sinfo->snd_flags;
    sndinfo->snd_ppid = sinfo->snd_ppid;
    sndinfo->snd_context = sinfo->snd_context;
    msg.msg_controllen += CMSG_SPACE(sizeof(struct sctp_sndinfo));

    cmsg =
        (struct cmsghdr *)&cmsgbuf[CMSG_SPACE(sizeof(struct sctp_sndinfo))];
    cmsg->cmsg_level = IPPROTO_SCTP;
    cmsg->cmsg_type = SCTP_PRINFO;
    cmsg->cmsg_len = CMSG_LEN(sizeof(struct sctp_prinfo));
    prinfo = (struct sctp_prinfo *)CMSG_DATA(cmsg);
    memset(prinfo, 0, sizeof(struct sctp_prinfo));
    prinfo->pr_policy = pinfo->pr_policy;
    prinfo->pr_value = pinfo->pr_value;
    msg.msg_controllen += CMSG_SPACE(sizeof(struct sctp_prinfo));
#  else
    cmsg = (struct cmsghdr *)cmsgbuf;
    cmsg->cmsg_level = IPPROTO_SCTP;
    cmsg->cmsg_type = SCTP_SNDRCV;
    cmsg->cmsg_len = CMSG_LEN(sizeof(struct sctp_sndrcvinfo));
    sndrcvinfo = (struct sctp_sndrcvinfo *)CMSG_DATA(cmsg);
    memset(sndrcvinfo, 0, sizeof(struct sctp_sndrcvinfo));
    sndrcvinfo->sinfo_stream = sinfo->snd_sid;
    sndrcvinfo->sinfo_flags = sinfo->snd_flags;
#   ifdef __FreeBSD__
    sndrcvinfo->sinfo_flags |= pinfo->pr_policy;
#   endif
    sndrcvinfo->sinfo_ppid = sinfo->snd_ppid;
    sndrcvinfo->sinfo_context = sinfo->snd_context;
    sndrcvinfo->sinfo_timetolive = pinfo->pr_value;
    msg.msg_controllen += CMSG_SPACE(sizeof(struct sctp_sndrcvinfo));
#  endif

    ret = sendmsg(b->num, &msg, 0);

    BIO_clear_retry_flags(b);
    if (ret <= 0) {
        if (BIO_dgram_should_retry(ret)) {
            BIO_set_retry_write(b);
            data->_errno = get_last_socket_error();
        }
    }
    return (ret);
}

static long dgram_sctp_ctrl(BIO *b, int cmd, long num, void *ptr)
{
    long ret = 1;
    bio_dgram_sctp_data *data = NULL;
    socklen_t sockopt_len = 0;
    struct sctp_authkeyid authkeyid;
    struct sctp_authkey *authkey = NULL;

    data = (bio_dgram_sctp_data *) b->ptr;

    switch (cmd) {
    case BIO_CTRL_DGRAM_QUERY_MTU:
        /*
         * Set to maximum (2^14) and ignore user input to enable transport
         * protocol fragmentation. Returns always 2^14.
         */
        data->mtu = 16384;
        ret = data->mtu;
        break;
    case BIO_CTRL_DGRAM_SET_MTU:
        /*
         * Set to maximum (2^14) and ignore input to enable transport
         * protocol fragmentation. Returns always 2^14.
         */
        data->mtu = 16384;
        ret = data->mtu;
        break;
    case BIO_CTRL_DGRAM_SET_CONNECTED:
    case BIO_CTRL_DGRAM_CONNECT:
        /* Returns always -1. */
        ret = -1;
        break;
    case BIO_CTRL_DGRAM_SET_NEXT_TIMEOUT:
        /*
         * SCTP doesn't need the DTLS timer Returns always 1.
         */
        break;
    case BIO_CTRL_DGRAM_GET_MTU_OVERHEAD:
        /*
         * We allow transport protocol fragmentation so this is irrelevant
         */
        ret = 0;
        break;
    case BIO_CTRL_DGRAM_SCTP_SET_IN_HANDSHAKE:
        if (num > 0)
            data->in_handshake = 1;
        else
            data->in_handshake = 0;

        ret =
            setsockopt(b->num, IPPROTO_SCTP, SCTP_NODELAY,
                       &data->in_handshake, sizeof(int));
        break;
    case BIO_CTRL_DGRAM_SCTP_ADD_AUTH_KEY:
        /*
         * New shared key for SCTP AUTH. Returns 0 on success, -1 otherwise.
         */

        /* Get active key */
        sockopt_len = sizeof(struct sctp_authkeyid);
        ret =
            getsockopt(b->num, IPPROTO_SCTP, SCTP_AUTH_ACTIVE_KEY, &authkeyid,
                       &sockopt_len);
        if (ret < 0)
            break;

        /* Add new key */
        sockopt_len = sizeof(struct sctp_authkey) + 64 * sizeof(uint8_t);
        authkey = OPENSSL_malloc(sockopt_len);
        if (authkey == NULL) {
            ret = -1;
            break;
        }
        memset(authkey, 0x00, sockopt_len);
        authkey->sca_keynumber = authkeyid.scact_keynumber + 1;
#  ifndef __FreeBSD__
        /*
         * This field is missing in FreeBSD 8.2 and earlier, and FreeBSD 8.3
         * and higher work without it.
         */
        authkey->sca_keylength = 64;
#  endif
        memcpy(&authkey->sca_key[0], ptr, 64 * sizeof(uint8_t));

        ret =
            setsockopt(b->num, IPPROTO_SCTP, SCTP_AUTH_KEY, authkey,
                       sockopt_len);
        OPENSSL_free(authkey);
        authkey = NULL;
        if (ret < 0)
            break;

        /* Reset active key */
        ret = setsockopt(b->num, IPPROTO_SCTP, SCTP_AUTH_ACTIVE_KEY,
                         &authkeyid, sizeof(struct sctp_authkeyid));
        if (ret < 0)
            break;

        break;
    case BIO_CTRL_DGRAM_SCTP_NEXT_AUTH_KEY:
        /* Returns 0 on success, -1 otherwise. */

        /* Get active key */
        sockopt_len = sizeof(struct sctp_authkeyid);
        ret =
            getsockopt(b->num, IPPROTO_SCTP, SCTP_AUTH_ACTIVE_KEY, &authkeyid,
                       &sockopt_len);
        if (ret < 0)
            break;

        /* Set active key */
        authkeyid.scact_keynumber = authkeyid.scact_keynumber + 1;
        ret = setsockopt(b->num, IPPROTO_SCTP, SCTP_AUTH_ACTIVE_KEY,
                         &authkeyid, sizeof(struct sctp_authkeyid));
        if (ret < 0)
            break;

        /*
         * CCS has been sent, so remember that and fall through to check if
         * we need to deactivate an old key
         */
        data->ccs_sent = 1;

    case BIO_CTRL_DGRAM_SCTP_AUTH_CCS_RCVD:
        /* Returns 0 on success, -1 otherwise. */

        /*
         * Has this command really been called or is this just a
         * fall-through?
         */
        if (cmd == BIO_CTRL_DGRAM_SCTP_AUTH_CCS_RCVD)
            data->ccs_rcvd = 1;

        /*
         * CSS has been both, received and sent, so deactivate an old key
         */
        if (data->ccs_rcvd == 1 && data->ccs_sent == 1) {
            /* Get active key */
            sockopt_len = sizeof(struct sctp_authkeyid);
            ret =
                getsockopt(b->num, IPPROTO_SCTP, SCTP_AUTH_ACTIVE_KEY,
                           &authkeyid, &sockopt_len);
            if (ret < 0)
                break;

            /*
             * Deactivate key or delete second last key if
             * SCTP_AUTHENTICATION_EVENT is not available.
             */
            authkeyid.scact_keynumber = authkeyid.scact_keynumber - 1;
#  ifdef SCTP_AUTH_DEACTIVATE_KEY
            sockopt_len = sizeof(struct sctp_authkeyid);
            ret = setsockopt(b->num, IPPROTO_SCTP, SCTP_AUTH_DEACTIVATE_KEY,
                             &authkeyid, sockopt_len);
            if (ret < 0)
                break;
#  endif
#  ifndef SCTP_AUTHENTICATION_EVENT
            if (authkeyid.scact_keynumber > 0) {
                authkeyid.scact_keynumber = authkeyid.scact_keynumber - 1;
                ret = setsockopt(b->num, IPPROTO_SCTP, SCTP_AUTH_DELETE_KEY,
                                 &authkeyid, sizeof(struct sctp_authkeyid));
                if (ret < 0)
                    break;
            }
#  endif

            data->ccs_rcvd = 0;
            data->ccs_sent = 0;
        }
        break;
    case BIO_CTRL_DGRAM_SCTP_GET_SNDINFO:
        /* Returns the size of the copied struct. */
        if (num > (long)sizeof(struct bio_dgram_sctp_sndinfo))
            num = sizeof(struct bio_dgram_sctp_sndinfo);

        memcpy(ptr, &(data->sndinfo), num);
        ret = num;
        break;
    case BIO_CTRL_DGRAM_SCTP_SET_SNDINFO:
        /* Returns the size of the copied struct. */
        if (num > (long)sizeof(struct bio_dgram_sctp_sndinfo))
            num = sizeof(struct bio_dgram_sctp_sndinfo);

        memcpy(&(data->sndinfo), ptr, num);
        break;
    case BIO_CTRL_DGRAM_SCTP_GET_RCVINFO:
        /* Returns the size of the copied struct. */
        if (num > (long)sizeof(struct bio_dgram_sctp_rcvinfo))
            num = sizeof(struct bio_dgram_sctp_rcvinfo);

        memcpy(ptr, &data->rcvinfo, num);

        ret = num;
        break;
    case BIO_CTRL_DGRAM_SCTP_SET_RCVINFO:
        /* Returns the size of the copied struct. */
        if (num > (long)sizeof(struct bio_dgram_sctp_rcvinfo))
            num = sizeof(struct bio_dgram_sctp_rcvinfo);

        memcpy(&(data->rcvinfo), ptr, num);
        break;
    case BIO_CTRL_DGRAM_SCTP_GET_PRINFO:
        /* Returns the size of the copied struct. */
        if (num > (long)sizeof(struct bio_dgram_sctp_prinfo))
            num = sizeof(struct bio_dgram_sctp_prinfo);

        memcpy(ptr, &(data->prinfo), num);
        ret = num;
        break;
    case BIO_CTRL_DGRAM_SCTP_SET_PRINFO:
        /* Returns the size of the copied struct. */
        if (num > (long)sizeof(struct bio_dgram_sctp_prinfo))
            num = sizeof(struct bio_dgram_sctp_prinfo);

        memcpy(&(data->prinfo), ptr, num);
        break;
    case BIO_CTRL_DGRAM_SCTP_SAVE_SHUTDOWN:
        /* Returns always 1. */
        if (num > 0)
            data->save_shutdown = 1;
        else
            data->save_shutdown = 0;
        break;

    default:
        /*
         * Pass to default ctrl function to process SCTP unspecific commands
         */
        ret = dgram_ctrl(b, cmd, num, ptr);
        break;
    }
    return (ret);
}

int BIO_dgram_sctp_notification_cb(BIO *b,
                                   void (*handle_notifications) (BIO *bio,
                                                                 void
                                                                 *context,
                                                                 void *buf),
                                   void *context)
{
    bio_dgram_sctp_data *data = (bio_dgram_sctp_data *) b->ptr;

    if (handle_notifications != NULL) {
        data->handle_notifications = handle_notifications;
        data->notification_context = context;
    } else
        return -1;

    return 0;
}

int BIO_dgram_sctp_wait_for_dry(BIO *b)
{
    int is_dry = 0;
    int n, sockflags, ret;
    union sctp_notification snp;
    struct msghdr msg;
    struct iovec iov;
#  ifdef SCTP_EVENT
    struct sctp_event event;
#  else
    struct sctp_event_subscribe event;
    socklen_t eventsize;
#  endif
    bio_dgram_sctp_data *data = (bio_dgram_sctp_data *) b->ptr;

    /* set sender dry event */
#  ifdef SCTP_EVENT
    memset(&event, 0, sizeof(struct sctp_event));
    event.se_assoc_id = 0;
    event.se_type = SCTP_SENDER_DRY_EVENT;
    event.se_on = 1;
    ret =
        setsockopt(b->num, IPPROTO_SCTP, SCTP_EVENT, &event,
                   sizeof(struct sctp_event));
#  else
    eventsize = sizeof(struct sctp_event_subscribe);
    ret = getsockopt(b->num, IPPROTO_SCTP, SCTP_EVENTS, &event, &eventsize);
    if (ret < 0)
        return -1;

    event.sctp_sender_dry_event = 1;

    ret =
        setsockopt(b->num, IPPROTO_SCTP, SCTP_EVENTS, &event,
                   sizeof(struct sctp_event_subscribe));
#  endif
    if (ret < 0)
        return -1;

    /* peek for notification */
    memset(&snp, 0x00, sizeof(union sctp_notification));
    iov.iov_base = (char *)&snp;
    iov.iov_len = sizeof(union sctp_notification);
    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
    msg.msg_flags = 0;

    n = recvmsg(b->num, &msg, MSG_PEEK);
    if (n <= 0) {
        if ((n < 0) && (get_last_socket_error() != EAGAIN)
            && (get_last_socket_error() != EWOULDBLOCK))
            return -1;
        else
            return 0;
    }

    /* if we find a notification, process it and try again if necessary */
    while (msg.msg_flags & MSG_NOTIFICATION) {
        memset(&snp, 0x00, sizeof(union sctp_notification));
        iov.iov_base = (char *)&snp;
        iov.iov_len = sizeof(union sctp_notification);
        msg.msg_name = NULL;
        msg.msg_namelen = 0;
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = NULL;
        msg.msg_controllen = 0;
        msg.msg_flags = 0;

        n = recvmsg(b->num, &msg, 0);
        if (n <= 0) {
            if ((n < 0) && (get_last_socket_error() != EAGAIN)
                && (get_last_socket_error() != EWOULDBLOCK))
                return -1;
            else
                return is_dry;
        }

        if (snp.sn_header.sn_type == SCTP_SENDER_DRY_EVENT) {
            is_dry = 1;

            /* disable sender dry event */
#  ifdef SCTP_EVENT
            memset(&event, 0, sizeof(struct sctp_event));
            event.se_assoc_id = 0;
            event.se_type = SCTP_SENDER_DRY_EVENT;
            event.se_on = 0;
            ret =
                setsockopt(b->num, IPPROTO_SCTP, SCTP_EVENT, &event,
                           sizeof(struct sctp_event));
#  else
            eventsize = (socklen_t) sizeof(struct sctp_event_subscribe);
            ret =
                getsockopt(b->num, IPPROTO_SCTP, SCTP_EVENTS, &event,
                           &eventsize);
            if (ret < 0)
                return -1;

            event.sctp_sender_dry_event = 0;

            ret =
                setsockopt(b->num, IPPROTO_SCTP, SCTP_EVENTS, &event,
                           sizeof(struct sctp_event_subscribe));
#  endif
            if (ret < 0)
                return -1;
        }
#  ifdef SCTP_AUTHENTICATION_EVENT
        if (snp.sn_header.sn_type == SCTP_AUTHENTICATION_EVENT)
            dgram_sctp_handle_auth_free_key_event(b, &snp);
#  endif

        if (data->handle_notifications != NULL)
            data->handle_notifications(b, data->notification_context,
                                       (void *)&snp);

        /* found notification, peek again */
        memset(&snp, 0x00, sizeof(union sctp_notification));
        iov.iov_base = (char *)&snp;
        iov.iov_len = sizeof(union sctp_notification);
        msg.msg_name = NULL;
        msg.msg_namelen = 0;
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = NULL;
        msg.msg_controllen = 0;
        msg.msg_flags = 0;

        /* if we have seen the dry already, don't wait */
        if (is_dry) {
            sockflags = fcntl(b->num, F_GETFL, 0);
            fcntl(b->num, F_SETFL, O_NONBLOCK);
        }

        n = recvmsg(b->num, &msg, MSG_PEEK);

        if (is_dry) {
            fcntl(b->num, F_SETFL, sockflags);
        }

        if (n <= 0) {
            if ((n < 0) && (get_last_socket_error() != EAGAIN)
                && (get_last_socket_error() != EWOULDBLOCK))
                return -1;
            else
                return is_dry;
        }
    }

    /* read anything else */
    return is_dry;
}

int BIO_dgram_sctp_msg_waiting(BIO *b)
{
    int n, sockflags;
    union sctp_notification snp;
    struct msghdr msg;
    struct iovec iov;
    bio_dgram_sctp_data *data = (bio_dgram_sctp_data *) b->ptr;

    /* Check if there are any messages waiting to be read */
    do {
        memset(&snp, 0x00, sizeof(union sctp_notification));
        iov.iov_base = (char *)&snp;
        iov.iov_len = sizeof(union sctp_notification);
        msg.msg_name = NULL;
        msg.msg_namelen = 0;
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = NULL;
        msg.msg_controllen = 0;
        msg.msg_flags = 0;

        sockflags = fcntl(b->num, F_GETFL, 0);
        fcntl(b->num, F_SETFL, O_NONBLOCK);
        n = recvmsg(b->num, &msg, MSG_PEEK);
        fcntl(b->num, F_SETFL, sockflags);

        /* if notification, process and try again */
        if (n > 0 && (msg.msg_flags & MSG_NOTIFICATION)) {
#  ifdef SCTP_AUTHENTICATION_EVENT
            if (snp.sn_header.sn_type == SCTP_AUTHENTICATION_EVENT)
                dgram_sctp_handle_auth_free_key_event(b, &snp);
#  endif

            memset(&snp, 0x00, sizeof(union sctp_notification));
            iov.iov_base = (char *)&snp;
            iov.iov_len = sizeof(union sctp_notification);
            msg.msg_name = NULL;
            msg.msg_namelen = 0;
            msg.msg_iov = &iov;
            msg.msg_iovlen = 1;
            msg.msg_control = NULL;
            msg.msg_controllen = 0;
            msg.msg_flags = 0;
            n = recvmsg(b->num, &msg, 0);

            if (data->handle_notifications != NULL)
                data->handle_notifications(b, data->notification_context,
                                           (void *)&snp);
        }

    } while (n > 0 && (msg.msg_flags & MSG_NOTIFICATION));

    /* Return 1 if there is a message to be read, return 0 otherwise. */
    if (n > 0)
        return 1;
    else
        return 0;
}

static int dgram_sctp_puts(BIO *bp, const char *str)
{
    int n, ret;

    n = strlen(str);
    ret = dgram_sctp_write(bp, str, n);
    return (ret);
}
# endif

static int BIO_dgram_should_retry(int i)
{
    int err;

    if ((i == 0) || (i == -1)) {
        err = get_last_socket_error();

# if defined(OPENSSL_SYS_WINDOWS)
        /*
         * If the socket return value (i) is -1 and err is unexpectedly 0 at
         * this point, the error code was overwritten by another system call
         * before this error handling is called.
         */
# endif

        return (BIO_dgram_non_fatal_error(err));
    }
    return (0);
}

int BIO_dgram_non_fatal_error(int err)
{
    switch (err) {
# if defined(OPENSSL_SYS_WINDOWS)
#  if defined(WSAEWOULDBLOCK)
    case WSAEWOULDBLOCK:
#  endif

#  if 0                         /* This appears to always be an error */
#   if defined(WSAENOTCONN)
    case WSAENOTCONN:
#   endif
#  endif
# endif

# ifdef EWOULDBLOCK
#  ifdef WSAEWOULDBLOCK
#   if WSAEWOULDBLOCK != EWOULDBLOCK
    case EWOULDBLOCK:
#   endif
#  else
    case EWOULDBLOCK:
#  endif
# endif

# ifdef EINTR
    case EINTR:
# endif

# ifdef EAGAIN
#  if EWOULDBLOCK != EAGAIN
    case EAGAIN:
#  endif
# endif

# ifdef EPROTO
    case EPROTO:
# endif

# ifdef EINPROGRESS
    case EINPROGRESS:
# endif

# ifdef EALREADY
    case EALREADY:
# endif

        return (1);
        /* break; */
    default:
        break;
    }
    return (0);
}

static void get_current_time(struct timeval *t)
{
# if defined(_WIN32)
    SYSTEMTIME st;
    union {
        unsigned __int64 ul;
        FILETIME ft;
    } now;

    GetSystemTime(&st);
    SystemTimeToFileTime(&st, &now.ft);
#  ifdef  __MINGW32__
    now.ul -= 116444736000000000ULL;
#  else
    now.ul -= 116444736000000000UI64; /* re-bias to 1/1/1970 */
#  endif
    t->tv_sec = (long)(now.ul / 10000000);
    t->tv_usec = ((int)(now.ul % 10000000)) / 10;
# elif defined(OPENSSL_SYS_VMS)
    struct timeb tb;
    ftime(&tb);
    t->tv_sec = (long)tb.time;
    t->tv_usec = (long)tb.millitm * 1000;
# else
    gettimeofday(t, NULL);
# endif
}

#endif
/* crypto/bio/bss_fd.c */
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
#define USE_SOCKETS
// #include "cryptlib.h"

#if defined(OPENSSL_NO_POSIX_IO)
/*
 * Dummy placeholder for BIO_s_fd...
 */
BIO *BIO_new_fd(int fd, int close_flag)
{
    return NULL;
}

int BIO_fd_non_fatal_error(int err)
{
    return 0;
}

int BIO_fd_should_retry(int i)
{
    return 0;
}

BIO_METHOD *BIO_s_fd(void)
{
    return NULL;
}
#else
/*
 * As for unconditional usage of "UPLINK" interface in this module.
 * Trouble is that unlike Unix file descriptors [which are indexes
 * in kernel-side per-process table], corresponding descriptors on
 * platforms which require "UPLINK" interface seem to be indexes
 * in a user-land, non-global table. Well, in fact they are indexes
 * in stdio _iob[], and recall that _iob[] was the very reason why
 * "UPLINK" interface was introduced in first place. But one way on
 * another. Neither libcrypto or libssl use this BIO meaning that
 * file descriptors can only be provided by application. Therefore
 * "UPLINK" calls are due...
 */
# include "bio_lcl.h"

static int fd_write(BIO *h, const char *buf, int num);
static int fd_read(BIO *h, char *buf, int size);
static int fd_puts(BIO *h, const char *str);
static int fd_gets(BIO *h, char *buf, int size);
static long fd_ctrl(BIO *h, int cmd, long arg1, void *arg2);
static int fd_new(BIO *h);
static int fd_free(BIO *data);
int BIO_fd_should_retry(int s);

static BIO_METHOD methods_fdp = {
    BIO_TYPE_FD, "file descriptor",
    fd_write,
    fd_read,
    fd_puts,
    fd_gets,
    fd_ctrl,
    fd_new,
    fd_free,
    NULL,
};

BIO_METHOD *BIO_s_fd(void)
{
    return (&methods_fdp);
}

BIO *BIO_new_fd(int fd, int close_flag)
{
    BIO *ret;
    ret = BIO_new(BIO_s_fd());
    if (ret == NULL)
        return (NULL);
    BIO_set_fd(ret, fd, close_flag);
    return (ret);
}

static int fd_new(BIO *bi)
{
    bi->init = 0;
    bi->num = -1;
    bi->ptr = NULL;
    bi->flags = BIO_FLAGS_UPLINK; /* essentially redundant */
    return (1);
}

static int fd_free(BIO *a)
{
    if (a == NULL)
        return (0);
    if (a->shutdown) {
        if (a->init) {
            UP_close(a->num);
        }
        a->init = 0;
        a->flags = BIO_FLAGS_UPLINK;
    }
    return (1);
}

static int fd_read(BIO *b, char *out, int outl)
{
    int ret = 0;

    if (out != NULL) {
        clear_sys_error();
        ret = UP_read(b->num, out, outl);
        BIO_clear_retry_flags(b);
        if (ret <= 0) {
            if (BIO_fd_should_retry(ret))
                BIO_set_retry_read(b);
        }
    }
    return (ret);
}

static int fd_write(BIO *b, const char *in, int inl)
{
    int ret;
    clear_sys_error();
    ret = UP_write(b->num, in, inl);
    BIO_clear_retry_flags(b);
    if (ret <= 0) {
        if (BIO_fd_should_retry(ret))
            BIO_set_retry_write(b);
    }
    return (ret);
}

static long fd_ctrl(BIO *b, int cmd, long num, void *ptr)
{
    long ret = 1;
    int *ip;

    switch (cmd) {
    case BIO_CTRL_RESET:
        num = 0;
    case BIO_C_FILE_SEEK:
        ret = (long)UP_lseek(b->num, num, 0);
        break;
    case BIO_C_FILE_TELL:
    case BIO_CTRL_INFO:
        ret = (long)UP_lseek(b->num, 0, 1);
        break;
    case BIO_C_SET_FD:
        fd_free(b);
        b->num = *((int *)ptr);
        b->shutdown = (int)num;
        b->init = 1;
        break;
    case BIO_C_GET_FD:
        if (b->init) {
            ip = (int *)ptr;
            if (ip != NULL)
                *ip = b->num;
            ret = b->num;
        } else
            ret = -1;
        break;
    case BIO_CTRL_GET_CLOSE:
        ret = b->shutdown;
        break;
    case BIO_CTRL_SET_CLOSE:
        b->shutdown = (int)num;
        break;
    case BIO_CTRL_PENDING:
    case BIO_CTRL_WPENDING:
        ret = 0;
        break;
    case BIO_CTRL_DUP:
    case BIO_CTRL_FLUSH:
        ret = 1;
        break;
    default:
        ret = 0;
        break;
    }
    return (ret);
}

static int fd_puts(BIO *bp, const char *str)
{
    int n, ret;

    n = strlen(str);
    ret = fd_write(bp, str, n);
    return (ret);
}

static int fd_gets(BIO *bp, char *buf, int size)
{
    int ret = 0;
    char *ptr = buf;
    char *end = buf + size - 1;

    while ((ptr < end) && (fd_read(bp, ptr, 1) > 0) && (ptr[0] != '\n'))
        ptr++;

    ptr[0] = '\0';

    if (buf[0] != '\0')
        ret = strlen(buf);
    return (ret);
}

int BIO_fd_should_retry(int i)
{
    int err;

    if ((i == 0) || (i == -1)) {
        err = get_last_sys_error();

# if defined(OPENSSL_SYS_WINDOWS) && 0/* more microsoft stupidity? perhaps
                                       * not? Ben 4/1/99 */
        if ((i == -1) && (err == 0))
            return (1);
# endif

        return (BIO_fd_non_fatal_error(err));
    }
    return (0);
}

int BIO_fd_non_fatal_error(int err)
{
    switch (err) {

# ifdef EWOULDBLOCK
#  ifdef WSAEWOULDBLOCK
#   if WSAEWOULDBLOCK != EWOULDBLOCK
    case EWOULDBLOCK:
#   endif
#  else
    case EWOULDBLOCK:
#  endif
# endif

# if defined(ENOTCONN)
    case ENOTCONN:
# endif

# ifdef EINTR
    case EINTR:
# endif

# ifdef EAGAIN
#  if EWOULDBLOCK != EAGAIN
    case EAGAIN:
#  endif
# endif

# ifdef EPROTO
    case EPROTO:
# endif

# ifdef EINPROGRESS
    case EINPROGRESS:
# endif

# ifdef EALREADY
    case EALREADY:
# endif
        return (1);
        /* break; */
    default:
        break;
    }
    return (0);
}
#endif
/* crypto/bio/bss_file.c */
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
 * 03-Dec-1997  rdenny@dc3.com  Fix bug preventing use of stdin/stdout
 *              with binary data (e.g. asn1parse -inform DER < xxx) under
 *              Windows
 */

#ifndef HEADER_BSS_FILE_C
# define HEADER_BSS_FILE_C

# if defined(__linux) || defined(__sun) || defined(__hpux)
/*
 * Following definition aliases fopen to fopen64 on above mentioned
 * platforms. This makes it possible to open and sequentially access files
 * larger than 2GB from 32-bit application. It does not allow to traverse
 * them beyond 2GB with fseek/ftell, but on the other hand *no* 32-bit
 * platform permits that, not with fseek/ftell. Not to mention that breaking
 * 2GB limit for seeking would require surgery to *our* API. But sequential
 * access suffices for practical cases when you can run into large files,
 * such as fingerprinting, so we can let API alone. For reference, the list
 * of 32-bit platforms which allow for sequential access of large files
 * without extra "magic" comprise *BSD, Darwin, IRIX...
 */
#  ifndef _FILE_OFFSET_BITS
#   define _FILE_OFFSET_BITS 64
#  endif
# endif

# include <stdio.h>
# include <errno.h>
# include "cryptlib.h"
# include "bio_lcl.h"
# include "err.h"

# if defined(OPENSSL_SYS_NETWARE) && defined(NETWARE_CLIB)
#  include <nwfileio.h>
# endif

# if !defined(OPENSSL_NO_STDIO)

static int MS_CALLBACK file_write(BIO *h, const char *buf, int num);
static int MS_CALLBACK file_read(BIO *h, char *buf, int size);
static int MS_CALLBACK file_puts(BIO *h, const char *str);
static int MS_CALLBACK file_gets(BIO *h, char *str, int size);
static long MS_CALLBACK file_ctrl(BIO *h, int cmd, long arg1, void *arg2);
static int MS_CALLBACK file_new(BIO *h);
static int MS_CALLBACK file_free(BIO *data);
static BIO_METHOD methods_filep = {
    BIO_TYPE_FILE,
    "FILE pointer",
    file_write,
    file_read,
    file_puts,
    file_gets,
    file_ctrl,
    file_new,
    file_free,
    NULL,
};

static FILE *file_fopen(const char *filename, const char *mode)
{
    FILE *file = NULL;

#  if defined(_WIN32) && defined(CP_UTF8)
    int sz, len_0 = (int)strlen(filename) + 1;
    DWORD flags;

    /*
     * Basically there are three cases to cover: a) filename is
     * pure ASCII string; b) actual UTF-8 encoded string and
     * c) locale-ized string, i.e. one containing 8-bit
     * characters that are meaningful in current system locale.
     * If filename is pure ASCII or real UTF-8 encoded string,
     * MultiByteToWideChar succeeds and _wfopen works. If
     * filename is locale-ized string, chances are that
     * MultiByteToWideChar fails reporting
     * ERROR_NO_UNICODE_TRANSLATION, in which case we fall
     * back to fopen...
     */
    if ((sz = MultiByteToWideChar(CP_UTF8, (flags = MB_ERR_INVALID_CHARS),
                                  filename, len_0, NULL, 0)) > 0 ||
        (GetLastError() == ERROR_INVALID_FLAGS &&
         (sz = MultiByteToWideChar(CP_UTF8, (flags = 0),
                                   filename, len_0, NULL, 0)) > 0)
        ) {
        WCHAR wmode[8];
        WCHAR *wfilename = _alloca(sz * sizeof(WCHAR));

        if (MultiByteToWideChar(CP_UTF8, flags,
                                filename, len_0, wfilename, sz) &&
            MultiByteToWideChar(CP_UTF8, 0, mode, strlen(mode) + 1,
                                wmode, sizeof(wmode) / sizeof(wmode[0])) &&
            (file = _wfopen(wfilename, wmode)) == NULL &&
            (errno == ENOENT || errno == EBADF)
            ) {
            /*
             * UTF-8 decode succeeded, but no file, filename
             * could still have been locale-ized...
             */
            file = fopen(filename, mode);
        }
    } else if (GetLastError() == ERROR_NO_UNICODE_TRANSLATION) {
        file = fopen(filename, mode);
    }
#  else
    file = fopen(filename, mode);
#  endif
    return (file);
}

BIO *BIO_new_file(const char *filename, const char *mode)
{
    BIO  *ret;
    FILE *file = file_fopen(filename, mode);

    if (file == NULL) {
        SYSerr(SYS_F_FOPEN, get_last_sys_error());
        ERR_add_error_data(5, "fopen('", filename, "','", mode, "')");
        if (errno == ENOENT
# ifdef ENXIO
            || errno == ENXIO
# endif
            )
            BIOerr(BIO_F_BIO_NEW_FILE, BIO_R_NO_SUCH_FILE);
        else
            BIOerr(BIO_F_BIO_NEW_FILE, ERR_R_SYS_LIB);
        return (NULL);
    }
    if ((ret = BIO_new(BIO_s_file())) == NULL) {
        fclose(file);
        return (NULL);
    }

    BIO_clear_flags(ret, BIO_FLAGS_UPLINK); /* we did fopen -> we disengage
                                             * UPLINK */
    BIO_set_fp(ret, file, BIO_CLOSE);
    return (ret);
}

BIO *BIO_new_fp(FILE *stream, int close_flag)
{
    BIO *ret;

    if ((ret = BIO_new(BIO_s_file())) == NULL)
        return (NULL);

    BIO_set_flags(ret, BIO_FLAGS_UPLINK); /* redundant, left for
                                           * documentation puposes */
    BIO_set_fp(ret, stream, close_flag);
    return (ret);
}

BIO_METHOD *BIO_s_file(void)
{
    return (&methods_filep);
}

static int MS_CALLBACK file_new(BIO *bi)
{
    bi->init = 0;
    bi->num = 0;
    bi->ptr = NULL;
    bi->flags = BIO_FLAGS_UPLINK; /* default to UPLINK */
    return (1);
}

static int MS_CALLBACK file_free(BIO *a)
{
    if (a == NULL)
        return (0);
    if (a->shutdown) {
        if ((a->init) && (a->ptr != NULL)) {
            if (a->flags & BIO_FLAGS_UPLINK)
                UP_fclose(a->ptr);
            else
                fclose(a->ptr);
            a->ptr = NULL;
            a->flags = BIO_FLAGS_UPLINK;
        }
        a->init = 0;
    }
    return (1);
}

static int MS_CALLBACK file_read(BIO *b, char *out, int outl)
{
    int ret = 0;

    if (b->init && (out != NULL)) {
        if (b->flags & BIO_FLAGS_UPLINK)
            ret = UP_fread(out, 1, (int)outl, b->ptr);
        else
            ret = fread(out, 1, (int)outl, (FILE *)b->ptr);
        if (ret == 0
            && (b->flags & BIO_FLAGS_UPLINK) ? UP_ferror((FILE *)b->ptr) :
                                               ferror((FILE *)b->ptr)) {
            SYSerr(SYS_F_FREAD, get_last_sys_error());
            BIOerr(BIO_F_FILE_READ, ERR_R_SYS_LIB);
            ret = -1;
        }
    }
    return (ret);
}

static int MS_CALLBACK file_write(BIO *b, const char *in, int inl)
{
    int ret = 0;

    if (b->init && (in != NULL)) {
        if (b->flags & BIO_FLAGS_UPLINK)
            ret = UP_fwrite(in, (int)inl, 1, b->ptr);
        else
            ret = fwrite(in, (int)inl, 1, (FILE *)b->ptr);
        if (ret)
            ret = inl;
        /* ret=fwrite(in,1,(int)inl,(FILE *)b->ptr); */
        /*
         * according to Tim Hudson <tjh@cryptsoft.com>, the commented out
         * version above can cause 'inl' write calls under some stupid stdio
         * implementations (VMS)
         */
    }
    return (ret);
}

static long MS_CALLBACK file_ctrl(BIO *b, int cmd, long num, void *ptr)
{
    long ret = 1;
    FILE *fp = (FILE *)b->ptr;
    FILE **fpp;
    char p[4];
    int st;

    switch (cmd) {
    case BIO_C_FILE_SEEK:
    case BIO_CTRL_RESET:
        if (b->flags & BIO_FLAGS_UPLINK)
            ret = (long)UP_fseek(b->ptr, num, 0);
        else
            ret = (long)fseek(fp, num, 0);
        break;
    case BIO_CTRL_EOF:
        if (b->flags & BIO_FLAGS_UPLINK)
            ret = (long)UP_feof(fp);
        else
            ret = (long)feof(fp);
        break;
    case BIO_C_FILE_TELL:
    case BIO_CTRL_INFO:
        if (b->flags & BIO_FLAGS_UPLINK)
            ret = UP_ftell(b->ptr);
        else
            ret = ftell(fp);
        break;
    case BIO_C_SET_FILE_PTR:
        file_free(b);
        b->shutdown = (int)num & BIO_CLOSE;
        b->ptr = ptr;
        b->init = 1;
#  if BIO_FLAGS_UPLINK!=0
#   if defined(__MINGW32__) && defined(__MSVCRT__) && !defined(_IOB_ENTRIES)
#    define _IOB_ENTRIES 20
#   endif
        /* Safety net to catch purely internal BIO_set_fp calls */
#   if defined(_MSC_VER) && _MSC_VER>=1900
        if (ptr == stdin || ptr == stdout || ptr == stderr)
            BIO_clear_flags(b, BIO_FLAGS_UPLINK);
#   elif defined(_IOB_ENTRIES)
        if ((size_t)ptr >= (size_t)stdin &&
            (size_t)ptr < (size_t)(stdin + _IOB_ENTRIES))
            BIO_clear_flags(b, BIO_FLAGS_UPLINK);
#   endif
#  endif
#  ifdef UP_fsetmod
        if (b->flags & BIO_FLAGS_UPLINK)
            UP_fsetmod(b->ptr, (char)((num & BIO_FP_TEXT) ? 't' : 'b'));
        else
#  endif
        {
#  if defined(OPENSSL_SYS_WINDOWS)
            int fd = _fileno((FILE *)ptr);
            if (num & BIO_FP_TEXT)
                _setmode(fd, _O_TEXT);
            else
                _setmode(fd, _O_BINARY);
#  elif defined(OPENSSL_SYS_NETWARE) && defined(NETWARE_CLIB)
            int fd = fileno((FILE *)ptr);
            /* Under CLib there are differences in file modes */
            if (num & BIO_FP_TEXT)
                setmode(fd, O_TEXT);
            else
                setmode(fd, O_BINARY);
#  elif defined(OPENSSL_SYS_MSDOS)
            int fd = fileno((FILE *)ptr);
            /* Set correct text/binary mode */
            if (num & BIO_FP_TEXT)
                _setmode(fd, _O_TEXT);
            /* Dangerous to set stdin/stdout to raw (unless redirected) */
            else {
                if (fd == STDIN_FILENO || fd == STDOUT_FILENO) {
                    if (isatty(fd) <= 0)
                        _setmode(fd, _O_BINARY);
                } else
                    _setmode(fd, _O_BINARY);
            }
#  elif defined(OPENSSL_SYS_OS2) || defined(OPENSSL_SYS_WIN32_CYGWIN)
            int fd = fileno((FILE *)ptr);
            if (num & BIO_FP_TEXT)
                setmode(fd, O_TEXT);
            else
                setmode(fd, O_BINARY);
#  endif
        }
        break;
    case BIO_C_SET_FILENAME:
        file_free(b);
        b->shutdown = (int)num & BIO_CLOSE;
        if (num & BIO_FP_APPEND) {
            if (num & BIO_FP_READ)
                BUF_strlcpy(p, "a+", sizeof(p));
            else
                BUF_strlcpy(p, "a", sizeof(p));
        } else if ((num & BIO_FP_READ) && (num & BIO_FP_WRITE))
            BUF_strlcpy(p, "r+", sizeof(p));
        else if (num & BIO_FP_WRITE)
            BUF_strlcpy(p, "w", sizeof(p));
        else if (num & BIO_FP_READ)
            BUF_strlcpy(p, "r", sizeof(p));
        else {
            BIOerr(BIO_F_FILE_CTRL, BIO_R_BAD_FOPEN_MODE);
            ret = 0;
            break;
        }
#  if defined(OPENSSL_SYS_MSDOS) || defined(OPENSSL_SYS_WINDOWS) || defined(OPENSSL_SYS_OS2) || defined(OPENSSL_SYS_WIN32_CYGWIN)
        if (!(num & BIO_FP_TEXT))
            strcat(p, "b");
        else
            strcat(p, "t");
#  endif
#  if defined(OPENSSL_SYS_NETWARE)
        if (!(num & BIO_FP_TEXT))
            strcat(p, "b");
        else
            strcat(p, "t");
#  endif
        fp = file_fopen(ptr, p);
        if (fp == NULL) {
            SYSerr(SYS_F_FOPEN, get_last_sys_error());
            ERR_add_error_data(5, "fopen('", ptr, "','", p, "')");
            BIOerr(BIO_F_FILE_CTRL, ERR_R_SYS_LIB);
            ret = 0;
            break;
        }
        b->ptr = fp;
        b->init = 1;
        BIO_clear_flags(b, BIO_FLAGS_UPLINK); /* we did fopen -> we disengage
                                               * UPLINK */
        break;
    case BIO_C_GET_FILE_PTR:
        /* the ptr parameter is actually a FILE ** in this case. */
        if (ptr != NULL) {
            fpp = (FILE **)ptr;
            *fpp = (FILE *)b->ptr;
        }
        break;
    case BIO_CTRL_GET_CLOSE:
        ret = (long)b->shutdown;
        break;
    case BIO_CTRL_SET_CLOSE:
        b->shutdown = (int)num;
        break;
    case BIO_CTRL_FLUSH:
        st = b->flags & BIO_FLAGS_UPLINK
                ? UP_fflush(b->ptr) : fflush((FILE *)b->ptr);
        if (st == EOF) {
            SYSerr(SYS_F_FFLUSH, get_last_sys_error());
            ERR_add_error_data(1, "fflush()");
            BIOerr(BIO_F_FILE_CTRL, ERR_R_SYS_LIB);
            ret = 0;
        }
        break;
    case BIO_CTRL_DUP:
        ret = 1;
        break;

    case BIO_CTRL_WPENDING:
    case BIO_CTRL_PENDING:
    case BIO_CTRL_PUSH:
    case BIO_CTRL_POP:
    default:
        ret = 0;
        break;
    }
    return (ret);
}

static int MS_CALLBACK file_gets(BIO *bp, char *buf, int size)
{
    int ret = 0;

    buf[0] = '\0';
    if (bp->flags & BIO_FLAGS_UPLINK) {
        if (!UP_fgets(buf, size, bp->ptr))
            goto err;
    } else {
        if (!fgets(buf, size, (FILE *)bp->ptr))
            goto err;
    }
    if (buf[0] != '\0')
        ret = strlen(buf);
 err:
    return (ret);
}

static int MS_CALLBACK file_puts(BIO *bp, const char *str)
{
    int n, ret;

    n = strlen(str);
    ret = file_write(bp, str, n);
    return (ret);
}

# endif                         /* OPENSSL_NO_STDIO */

#endif                          /* HEADER_BSS_FILE_C */
/* crypto/bio/bss_log.c */
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

/*
 * Why BIO_s_log?
 *
 * BIO_s_log is useful for system daemons (or services under NT). It is
 * one-way BIO, it sends all stuff to syslogd (on system that commonly use
 * that), or event log (on NT), or OPCOM (on OpenVMS).
 *
 */

#include <stdio.h>
#include <errno.h>

// #include "cryptlib.h"

#if defined(OPENSSL_SYS_WINCE)
#elif defined(OPENSSL_SYS_WIN32)
#elif defined(OPENSSL_SYS_VMS)
# include <opcdef.h>
# include <descrip.h>
# include <lib$routines.h>
# include <starlet.h>
/* Some compiler options may mask the declaration of "_malloc32". */
# if __INITIAL_POINTER_SIZE && defined _ANSI_C_SOURCE
#  if __INITIAL_POINTER_SIZE == 64
#   pragma pointer_size save
#   pragma pointer_size 32
void *_malloc32(__size_t);
#   pragma pointer_size restore
#  endif                        /* __INITIAL_POINTER_SIZE == 64 */
# endif                         /* __INITIAL_POINTER_SIZE && defined
                                 * _ANSI_C_SOURCE */
#elif defined(__ultrix)
# include <sys/syslog.h>
#elif defined(OPENSSL_SYS_NETWARE)
# define NO_SYSLOG
#elif (!defined(MSDOS) || defined(WATT32)) && !defined(OPENSSL_SYS_VXWORKS) && !defined(NO_SYSLOG)
# include <syslog.h>
#endif

#include "buffer.h"
// #include "err.h"

#ifndef NO_SYSLOG

# if defined(OPENSSL_SYS_WIN32)
#  define LOG_EMERG       0
#  define LOG_ALERT       1
#  define LOG_CRIT        2
#  define LOG_ERR         3
#  define LOG_WARNING     4
#  define LOG_NOTICE      5
#  define LOG_INFO        6
#  define LOG_DEBUG       7

#  define LOG_DAEMON      (3<<3)
# elif defined(OPENSSL_SYS_VMS)
/* On VMS, we don't really care about these, but we need them to compile */
#  define LOG_EMERG       0
#  define LOG_ALERT       1
#  define LOG_CRIT        2
#  define LOG_ERR         3
#  define LOG_WARNING     4
#  define LOG_NOTICE      5
#  define LOG_INFO        6
#  define LOG_DEBUG       7

#  define LOG_DAEMON      OPC$M_NM_NTWORK
# endif

static int MS_CALLBACK slg_write(BIO *h, const char *buf, int num);
static int MS_CALLBACK slg_puts(BIO *h, const char *str);
static long MS_CALLBACK slg_ctrl(BIO *h, int cmd, long arg1, void *arg2);
static int MS_CALLBACK slg_new(BIO *h);
static int MS_CALLBACK slg_free(BIO *data);
static void xopenlog(BIO *bp, char *name, int level);
static void xsyslog(BIO *bp, int priority, const char *string);
static void xcloselog(BIO *bp);

static BIO_METHOD methods_slg = {
    BIO_TYPE_MEM, "syslog",
    slg_write,
    NULL,
    slg_puts,
    NULL,
    slg_ctrl,
    slg_new,
    slg_free,
    NULL,
};

BIO_METHOD *BIO_s_log(void)
{
    return (&methods_slg);
}

static int MS_CALLBACK slg_new(BIO *bi)
{
    bi->init = 1;
    bi->num = 0;
    bi->ptr = NULL;
    xopenlog(bi, "application", LOG_DAEMON);
    return (1);
}

static int MS_CALLBACK slg_free(BIO *a)
{
    if (a == NULL)
        return (0);
    xcloselog(a);
    return (1);
}

static int MS_CALLBACK slg_write(BIO *b, const char *in, int inl)
{
    int ret = inl;
    char *buf;
    char *pp;
    int priority, i;
    static const struct {
        int strl;
        char str[10];
        int log_level;
    } mapping[] = {
        {
            6, "PANIC ", LOG_EMERG
        },
        {
            6, "EMERG ", LOG_EMERG
        },
        {
            4, "EMR ", LOG_EMERG
        },
        {
            6, "ALERT ", LOG_ALERT
        },
        {
            4, "ALR ", LOG_ALERT
        },
        {
            5, "CRIT ", LOG_CRIT
        },
        {
            4, "CRI ", LOG_CRIT
        },
        {
            6, "ERROR ", LOG_ERR
        },
        {
            4, "ERR ", LOG_ERR
        },
        {
            8, "WARNING ", LOG_WARNING
        },
        {
            5, "WARN ", LOG_WARNING
        },
        {
            4, "WAR ", LOG_WARNING
        },
        {
            7, "NOTICE ", LOG_NOTICE
        },
        {
            5, "NOTE ", LOG_NOTICE
        },
        {
            4, "NOT ", LOG_NOTICE
        },
        {
            5, "INFO ", LOG_INFO
        },
        {
            4, "INF ", LOG_INFO
        },
        {
            6, "DEBUG ", LOG_DEBUG
        },
        {
            4, "DBG ", LOG_DEBUG
        },
        {
            0, "", LOG_ERR
        }
        /* The default */
    };

    if ((buf = (char *)OPENSSL_malloc(inl + 1)) == NULL) {
        return (0);
    }
    memcpy(buf, in, inl);
    buf[inl] = '\0';

    i = 0;
    while (strncmp(buf, mapping[i].str, mapping[i].strl) != 0)
        i++;
    priority = mapping[i].log_level;
    pp = buf + mapping[i].strl;

    xsyslog(b, priority, pp);

    OPENSSL_free(buf);
    return (ret);
}

static long MS_CALLBACK slg_ctrl(BIO *b, int cmd, long num, void *ptr)
{
    switch (cmd) {
    case BIO_CTRL_SET:
        xcloselog(b);
        xopenlog(b, ptr, num);
        break;
    default:
        break;
    }
    return (0);
}

static int MS_CALLBACK slg_puts(BIO *bp, const char *str)
{
    int n, ret;

    n = strlen(str);
    ret = slg_write(bp, str, n);
    return (ret);
}

# if defined(OPENSSL_SYS_WIN32)

static void xopenlog(BIO *bp, char *name, int level)
{
    if (check_winnt())
        bp->ptr = RegisterEventSourceA(NULL, name);
    else
        bp->ptr = NULL;
}

static void xsyslog(BIO *bp, int priority, const char *string)
{
    LPCSTR lpszStrings[2];
    WORD evtype = EVENTLOG_ERROR_TYPE;
    char pidbuf[DECIMAL_SIZE(DWORD) + 4];

    if (bp->ptr == NULL)
        return;

    switch (priority) {
    case LOG_EMERG:
    case LOG_ALERT:
    case LOG_CRIT:
    case LOG_ERR:
        evtype = EVENTLOG_ERROR_TYPE;
        break;
    case LOG_WARNING:
        evtype = EVENTLOG_WARNING_TYPE;
        break;
    case LOG_NOTICE:
    case LOG_INFO:
    case LOG_DEBUG:
        evtype = EVENTLOG_INFORMATION_TYPE;
        break;
    default:
        /*
         * Should never happen, but set it
         * as error anyway.
         */
        evtype = EVENTLOG_ERROR_TYPE;
        break;
    }

    sprintf(pidbuf, "[%u] ", GetCurrentProcessId());
    lpszStrings[0] = pidbuf;
    lpszStrings[1] = string;

    ReportEventA(bp->ptr, evtype, 0, 1024, NULL, 2, 0, lpszStrings, NULL);
}

static void xcloselog(BIO *bp)
{
    if (bp->ptr)
        DeregisterEventSource((HANDLE) (bp->ptr));
    bp->ptr = NULL;
}

# elif defined(OPENSSL_SYS_VMS)

static int VMS_OPC_target = LOG_DAEMON;

static void xopenlog(BIO *bp, char *name, int level)
{
    VMS_OPC_target = level;
}

static void xsyslog(BIO *bp, int priority, const char *string)
{
    struct dsc$descriptor_s opc_dsc;

/* Arrange 32-bit pointer to opcdef buffer and malloc(), if needed. */
#  if __INITIAL_POINTER_SIZE == 64
#   pragma pointer_size save
#   pragma pointer_size 32
#   define OPCDEF_TYPE __char_ptr32
#   define OPCDEF_MALLOC _malloc32
#  else                         /* __INITIAL_POINTER_SIZE == 64 */
#   define OPCDEF_TYPE char *
#   define OPCDEF_MALLOC OPENSSL_malloc
#  endif                        /* __INITIAL_POINTER_SIZE == 64 [else] */

    struct opcdef *opcdef_p;

#  if __INITIAL_POINTER_SIZE == 64
#   pragma pointer_size restore
#  endif                        /* __INITIAL_POINTER_SIZE == 64 */

    char buf[10240];
    unsigned int len;
    struct dsc$descriptor_s buf_dsc;
    $DESCRIPTOR(fao_cmd, "!AZ: !AZ");
    char *priority_tag;

    switch (priority) {
    case LOG_EMERG:
        priority_tag = "Emergency";
        break;
    case LOG_ALERT:
        priority_tag = "Alert";
        break;
    case LOG_CRIT:
        priority_tag = "Critical";
        break;
    case LOG_ERR:
        priority_tag = "Error";
        break;
    case LOG_WARNING:
        priority_tag = "Warning";
        break;
    case LOG_NOTICE:
        priority_tag = "Notice";
        break;
    case LOG_INFO:
        priority_tag = "Info";
        break;
    case LOG_DEBUG:
        priority_tag = "DEBUG";
        break;
    }

    buf_dsc.dsc$b_dtype = DSC$K_DTYPE_T;
    buf_dsc.dsc$b_class = DSC$K_CLASS_S;
    buf_dsc.dsc$a_pointer = buf;
    buf_dsc.dsc$w_length = sizeof(buf) - 1;

    lib$sys_fao(&fao_cmd, &len, &buf_dsc, priority_tag, string);

    /* We know there's an 8-byte header.  That's documented. */
    opcdef_p = OPCDEF_MALLOC(8 + len);
    opcdef_p->opc$b_ms_type = OPC$_RQ_RQST;
    memcpy(opcdef_p->opc$z_ms_target_classes, &VMS_OPC_target, 3);
    opcdef_p->opc$l_ms_rqstid = 0;
    memcpy(&opcdef_p->opc$l_ms_text, buf, len);

    opc_dsc.dsc$b_dtype = DSC$K_DTYPE_T;
    opc_dsc.dsc$b_class = DSC$K_CLASS_S;
    opc_dsc.dsc$a_pointer = (OPCDEF_TYPE) opcdef_p;
    opc_dsc.dsc$w_length = len + 8;

    sys$sndopr(opc_dsc, 0);

    OPENSSL_free(opcdef_p);
}

static void xcloselog(BIO *bp)
{
}

# else                          /* Unix/Watt32 */

static void xopenlog(BIO *bp, char *name, int level)
{
#  ifdef WATT32                 /* djgpp/DOS */
    openlog(name, LOG_PID | LOG_CONS | LOG_NDELAY, level);
#  else
    openlog(name, LOG_PID | LOG_CONS, level);
#  endif
}

static void xsyslog(BIO *bp, int priority, const char *string)
{
    syslog(priority, "%s", string);
}

static void xcloselog(BIO *bp)
{
    closelog();
}

# endif                         /* Unix */

#endif                          /* NO_SYSLOG */
/* crypto/bio/bss_mem.c */
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

static int mem_write(BIO *h, const char *buf, int num);
static int mem_read(BIO *h, char *buf, int size);
static int mem_puts(BIO *h, const char *str);
static int mem_gets(BIO *h, char *str, int size);
static long mem_ctrl(BIO *h, int cmd, long arg1, void *arg2);
static int mem_new(BIO *h);
static int mem_free(BIO *data);
static BIO_METHOD mem_method = {
    BIO_TYPE_MEM,
    "memory buffer",
    mem_write,
    mem_read,
    mem_puts,
    mem_gets,
    mem_ctrl,
    mem_new,
    mem_free,
    NULL,
};

/*
 * bio->num is used to hold the value to return on 'empty', if it is 0,
 * should_retry is not set
 */

BIO_METHOD *BIO_s_mem(void)
{
    return (&mem_method);
}


BIO *BIO_new_mem_buf(const void *buf, int len)
{
    BIO *ret;
    BUF_MEM *b;
    size_t sz;

    if (!buf) {
        BIOerr(BIO_F_BIO_NEW_MEM_BUF, BIO_R_NULL_PARAMETER);
        return NULL;
    }
    sz = (len < 0) ? strlen(buf) : (size_t)len;
    if (!(ret = BIO_new(BIO_s_mem())))
        return NULL;
    b = (BUF_MEM *)ret->ptr;
    /* Cast away const and trust in the MEM_RDONLY flag. */
    b->data = (void *)buf;
    b->length = sz;
    b->max = sz;
    ret->flags |= BIO_FLAGS_MEM_RDONLY;
    /* Since this is static data retrying wont help */
    ret->num = 0;
    return ret;
}

static int mem_new(BIO *bi)
{
    BUF_MEM *b;

    if ((b = BUF_MEM_new()) == NULL)
        return (0);
    bi->shutdown = 1;
    bi->init = 1;
    bi->num = -1;
    bi->ptr = (char *)b;
    return (1);
}

static int mem_free(BIO *a)
{
    if (a == NULL)
        return (0);
    if (a->shutdown) {
        if ((a->init) && (a->ptr != NULL)) {
            BUF_MEM *b;
            b = (BUF_MEM *)a->ptr;
            if (a->flags & BIO_FLAGS_MEM_RDONLY)
                b->data = NULL;
            BUF_MEM_free(b);
            a->ptr = NULL;
        }
    }
    return (1);
}

static int mem_read(BIO *b, char *out, int outl)
{
    int ret = -1;
    BUF_MEM *bm;

    bm = (BUF_MEM *)b->ptr;
    BIO_clear_retry_flags(b);
    ret = (outl >= 0 && (size_t)outl > bm->length) ? (int)bm->length : outl;
    if ((out != NULL) && (ret > 0)) {
        memcpy(out, bm->data, ret);
        bm->length -= ret;
        if (b->flags & BIO_FLAGS_MEM_RDONLY)
            bm->data += ret;
        else {
            memmove(&(bm->data[0]), &(bm->data[ret]), bm->length);
        }
    } else if (bm->length == 0) {
        ret = b->num;
        if (ret != 0)
            BIO_set_retry_read(b);
    }
    return (ret);
}

static int mem_write(BIO *b, const char *in, int inl)
{
    int ret = -1;
    int blen;
    BUF_MEM *bm;

    bm = (BUF_MEM *)b->ptr;
    if (in == NULL) {
        BIOerr(BIO_F_MEM_WRITE, BIO_R_NULL_PARAMETER);
        goto end;
    }

    if (b->flags & BIO_FLAGS_MEM_RDONLY) {
        BIOerr(BIO_F_MEM_WRITE, BIO_R_WRITE_TO_READ_ONLY_BIO);
        goto end;
    }

    BIO_clear_retry_flags(b);
    if (inl == 0)
        return 0;
    blen = bm->length;
    if (BUF_MEM_grow_clean(bm, blen + inl) != (blen + inl))
        goto end;
    memcpy(&(bm->data[blen]), in, inl);
    ret = inl;
 end:
    return (ret);
}

static long mem_ctrl(BIO *b, int cmd, long num, void *ptr)
{
    long ret = 1;
    char **pptr;

    BUF_MEM *bm = (BUF_MEM *)b->ptr;

    switch (cmd) {
    case BIO_CTRL_RESET:
        if (bm->data != NULL) {
            /* For read only case reset to the start again */
            if (b->flags & BIO_FLAGS_MEM_RDONLY) {
                bm->data -= bm->max - bm->length;
                bm->length = bm->max;
            } else {
                memset(bm->data, 0, bm->max);
                bm->length = 0;
            }
        }
        break;
    case BIO_CTRL_EOF:
        ret = (long)(bm->length == 0);
        break;
    case BIO_C_SET_BUF_MEM_EOF_RETURN:
        b->num = (int)num;
        break;
    case BIO_CTRL_INFO:
        ret = (long)bm->length;
        if (ptr != NULL) {
            pptr = (char **)ptr;
            *pptr = (char *)&(bm->data[0]);
        }
        break;
    case BIO_C_SET_BUF_MEM:
        mem_free(b);
        b->shutdown = (int)num;
        b->ptr = ptr;
        break;
    case BIO_C_GET_BUF_MEM_PTR:
        if (ptr != NULL) {
            pptr = (char **)ptr;
            *pptr = (char *)bm;
        }
        break;
    case BIO_CTRL_GET_CLOSE:
        ret = (long)b->shutdown;
        break;
    case BIO_CTRL_SET_CLOSE:
        b->shutdown = (int)num;
        break;

    case BIO_CTRL_WPENDING:
        ret = 0L;
        break;
    case BIO_CTRL_PENDING:
        ret = (long)bm->length;
        break;
    case BIO_CTRL_DUP:
    case BIO_CTRL_FLUSH:
        ret = 1;
        break;
    case BIO_CTRL_PUSH:
    case BIO_CTRL_POP:
    default:
        ret = 0;
        break;
    }
    return (ret);
}

static int mem_gets(BIO *bp, char *buf, int size)
{
    int i, j;
    int ret = -1;
    char *p;
    BUF_MEM *bm = (BUF_MEM *)bp->ptr;

    BIO_clear_retry_flags(bp);
    j = bm->length;
    if ((size - 1) < j)
        j = size - 1;
    if (j <= 0) {
        *buf = '\0';
        return 0;
    }
    p = bm->data;
    for (i = 0; i < j; i++) {
        if (p[i] == '\n') {
            i++;
            break;
        }
    }

    /*
     * i is now the max num of bytes to copy, either j or up to
     * and including the first newline
     */

    i = mem_read(bp, buf, i);
    if (i > 0)
        buf[i] = '\0';
    ret = i;
    return (ret);
}

static int mem_puts(BIO *bp, const char *str)
{
    int n, ret;

    n = strlen(str);
    ret = mem_write(bp, str, n);
    /* memory semantics is that it will always work */
    return (ret);
}
/* crypto/bio/bss_null.c */
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

static int null_write(BIO *h, const char *buf, int num);
static int null_read(BIO *h, char *buf, int size);
static int null_puts(BIO *h, const char *str);
static int null_gets(BIO *h, char *str, int size);
static long null_ctrl(BIO *h, int cmd, long arg1, void *arg2);
static int null_new(BIO *h);
static int null_free(BIO *data);
static BIO_METHOD null_method = {
    BIO_TYPE_NULL,
    "NULL",
    null_write,
    null_read,
    null_puts,
    null_gets,
    null_ctrl,
    null_new,
    null_free,
    NULL,
};

BIO_METHOD *BIO_s_null(void)
{
    return (&null_method);
}

static int null_new(BIO *bi)
{
    bi->init = 1;
    bi->num = 0;
    bi->ptr = (NULL);
    return (1);
}

static int null_free(BIO *a)
{
    if (a == NULL)
        return (0);
    return (1);
}

static int null_read(BIO *b, char *out, int outl)
{
    return (0);
}

static int null_write(BIO *b, const char *in, int inl)
{
    return (inl);
}

static long null_ctrl(BIO *b, int cmd, long num, void *ptr)
{
    long ret = 1;

    switch (cmd) {
    case BIO_CTRL_RESET:
    case BIO_CTRL_EOF:
    case BIO_CTRL_SET:
    case BIO_CTRL_SET_CLOSE:
    case BIO_CTRL_FLUSH:
    case BIO_CTRL_DUP:
        ret = 1;
        break;
    case BIO_CTRL_GET_CLOSE:
    case BIO_CTRL_INFO:
    case BIO_CTRL_GET:
    case BIO_CTRL_PENDING:
    case BIO_CTRL_WPENDING:
    default:
        ret = 0;
        break;
    }
    return (ret);
}

static int null_gets(BIO *bp, char *buf, int size)
{
    return (0);
}

static int null_puts(BIO *bp, const char *str)
{
    if (str == NULL)
        return (0);
    return (strlen(str));
}
/* crypto/bio/bss_sock.c */
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
#define USE_SOCKETS
// #include "cryptlib.h"

#ifndef OPENSSL_NO_SOCK

# include "bio.h"

# ifdef WATT32
#  define sock_write SockWrite  /* Watt-32 uses same names */
#  define sock_read  SockRead
#  define sock_puts  SockPuts
# endif

static int sock_write(BIO *h, const char *buf, int num);
static int sock_read(BIO *h, char *buf, int size);
static int sock_puts(BIO *h, const char *str);
static long sock_ctrl(BIO *h, int cmd, long arg1, void *arg2);
static int sock_new(BIO *h);
static int sock_free(BIO *data);
int BIO_sock_should_retry(int s);

static BIO_METHOD methods_sockp = {
    BIO_TYPE_SOCKET,
    "socket",
    sock_write,
    sock_read,
    sock_puts,
    NULL,                       /* sock_gets, */
    sock_ctrl,
    sock_new,
    sock_free,
    NULL,
};

BIO_METHOD *BIO_s_socket(void)
{
    return (&methods_sockp);
}

BIO *BIO_new_socket(int fd, int close_flag)
{
    BIO *ret;

    ret = BIO_new(BIO_s_socket());
    if (ret == NULL)
        return (NULL);
    BIO_set_fd(ret, fd, close_flag);
    return (ret);
}

static int sock_new(BIO *bi)
{
    bi->init = 0;
    bi->num = 0;
    bi->ptr = NULL;
    bi->flags = 0;
    return (1);
}

static int sock_free(BIO *a)
{
    if (a == NULL)
        return (0);
    if (a->shutdown) {
        if (a->init) {
            SHUTDOWN2(a->num);
        }
        a->init = 0;
        a->flags = 0;
    }
    return (1);
}

static int sock_read(BIO *b, char *out, int outl)
{
    int ret = 0;

    if (out != NULL) {
        clear_socket_error();
        ret = readsocket(b->num, out, outl);
        BIO_clear_retry_flags(b);
        if (ret <= 0) {
            if (BIO_sock_should_retry(ret))
                BIO_set_retry_read(b);
        }
    }
    return (ret);
}

static int sock_write(BIO *b, const char *in, int inl)
{
    int ret;

    clear_socket_error();
    ret = writesocket(b->num, in, inl);
    BIO_clear_retry_flags(b);
    if (ret <= 0) {
        if (BIO_sock_should_retry(ret))
            BIO_set_retry_write(b);
    }
    return (ret);
}

static long sock_ctrl(BIO *b, int cmd, long num, void *ptr)
{
    long ret = 1;
    int *ip;

    switch (cmd) {
    case BIO_C_SET_FD:
        sock_free(b);
        b->num = *((int *)ptr);
        b->shutdown = (int)num;
        b->init = 1;
        break;
    case BIO_C_GET_FD:
        if (b->init) {
            ip = (int *)ptr;
            if (ip != NULL)
                *ip = b->num;
            ret = b->num;
        } else
            ret = -1;
        break;
    case BIO_CTRL_GET_CLOSE:
        ret = b->shutdown;
        break;
    case BIO_CTRL_SET_CLOSE:
        b->shutdown = (int)num;
        break;
    case BIO_CTRL_DUP:
    case BIO_CTRL_FLUSH:
        ret = 1;
        break;
    default:
        ret = 0;
        break;
    }
    return (ret);
}

static int sock_puts(BIO *bp, const char *str)
{
    int n, ret;

    n = strlen(str);
    ret = sock_write(bp, str, n);
    return (ret);
}

int BIO_sock_should_retry(int i)
{
    int err;

    if ((i == 0) || (i == -1)) {
        err = get_last_socket_error();

# if defined(OPENSSL_SYS_WINDOWS) && 0/* more microsoft stupidity? perhaps
                                       * not? Ben 4/1/99 */
        if ((i == -1) && (err == 0))
            return (1);
# endif

        return (BIO_sock_non_fatal_error(err));
    }
    return (0);
}

int BIO_sock_non_fatal_error(int err)
{
    switch (err) {
# if defined(OPENSSL_SYS_WINDOWS) || defined(OPENSSL_SYS_NETWARE)
#  if defined(WSAEWOULDBLOCK)
    case WSAEWOULDBLOCK:
#  endif

#  if 0                         /* This appears to always be an error */
#   if defined(WSAENOTCONN)
    case WSAENOTCONN:
#   endif
#  endif
# endif

# ifdef EWOULDBLOCK
#  ifdef WSAEWOULDBLOCK
#   if WSAEWOULDBLOCK != EWOULDBLOCK
    case EWOULDBLOCK:
#   endif
#  else
    case EWOULDBLOCK:
#  endif
# endif

# if defined(ENOTCONN)
    case ENOTCONN:
# endif

# ifdef EINTR
    case EINTR:
# endif

# ifdef EAGAIN
#  if EWOULDBLOCK != EAGAIN
    case EAGAIN:
#  endif
# endif

# ifdef EPROTO
    case EPROTO:
# endif

# ifdef EINPROGRESS
    case EINPROGRESS:
# endif

# ifdef EALREADY
    case EALREADY:
# endif
        return (1);
        /* break; */
    default:
        break;
    }
    return (0);
}

#endif                          /* #ifndef OPENSSL_NO_SOCK */
