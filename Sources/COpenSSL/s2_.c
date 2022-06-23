/* ssl/s2_clnt.c */
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

#include "ssl_locl.h"
#ifndef OPENSSL_NO_SSL2
# include <stdio.h>
# include "rand.h"
# include "buffer.h"
# include "objects.h"
# include "evp.h"

static const SSL_METHOD *ssl2_get_client_method(int ver);
static int get_server_finished(SSL *s);
static int get_server_verify(SSL *s);
static int get_server_hello(SSL *s);
static int client_hello(SSL *s);
static int client_master_key(SSL *s);
static int client_finished(SSL *s);
static int client_certificate(SSL *s);
static int ssl_rsa_public_encrypt(SESS_CERT *sc, int len, unsigned char *from,
                                  unsigned char *to, int padding);
# define BREAK   break

static const SSL_METHOD *ssl2_get_client_method(int ver)
{
    if (ver == SSL2_VERSION)
        return (SSLv2_client_method());
    else
        return (NULL);
}

IMPLEMENT_ssl2_meth_func(SSLv2_client_method,
                         ssl_undefined_function,
                         ssl2_connect, ssl2_get_client_method)

int ssl2_connect(SSL *s)
{
    unsigned long l = (unsigned long)time(NULL);
    BUF_MEM *buf = NULL;
    int ret = -1;
    void (*cb) (const SSL *ssl, int type, int val) = NULL;
    int new_state, state;

    RAND_add(&l, sizeof(l), 0);
    ERR_clear_error();
    clear_sys_error();

    if (s->info_callback != NULL)
        cb = s->info_callback;
    else if (s->ctx->info_callback != NULL)
        cb = s->ctx->info_callback;

    /* init things to blank */
    s->in_handshake++;
    if (!SSL_in_init(s) || SSL_in_before(s))
        SSL_clear(s);

    for (;;) {
        state = s->state;

        switch (s->state) {
        case SSL_ST_BEFORE:
        case SSL_ST_CONNECT:
        case SSL_ST_BEFORE | SSL_ST_CONNECT:
        case SSL_ST_OK | SSL_ST_CONNECT:

            s->server = 0;
            if (cb != NULL)
                cb(s, SSL_CB_HANDSHAKE_START, 1);

            s->version = SSL2_VERSION;
            s->type = SSL_ST_CONNECT;

            buf = s->init_buf;
            if ((buf == NULL) && ((buf = BUF_MEM_new()) == NULL)) {
                ret = -1;
                goto end;
            }
            if (!BUF_MEM_grow(buf, SSL2_MAX_RECORD_LENGTH_3_BYTE_HEADER)) {
                if (buf == s->init_buf)
                    buf = NULL;
                ret = -1;
                goto end;
            }
            s->init_buf = buf;
            buf = NULL;
            s->init_num = 0;
            s->state = SSL2_ST_SEND_CLIENT_HELLO_A;
            s->ctx->stats.sess_connect++;
            s->handshake_func = ssl2_connect;
            BREAK;

        case SSL2_ST_SEND_CLIENT_HELLO_A:
        case SSL2_ST_SEND_CLIENT_HELLO_B:
            s->shutdown = 0;
            ret = client_hello(s);
            if (ret <= 0)
                goto end;
            s->init_num = 0;
            s->state = SSL2_ST_GET_SERVER_HELLO_A;
            BREAK;

        case SSL2_ST_GET_SERVER_HELLO_A:
        case SSL2_ST_GET_SERVER_HELLO_B:
            ret = get_server_hello(s);
            if (ret <= 0)
                goto end;
            s->init_num = 0;
            if (!s->hit) {      /* new session */
                s->state = SSL2_ST_SEND_CLIENT_MASTER_KEY_A;
                BREAK;
            } else {
                s->state = SSL2_ST_CLIENT_START_ENCRYPTION;
                break;
            }

        case SSL2_ST_SEND_CLIENT_MASTER_KEY_A:
        case SSL2_ST_SEND_CLIENT_MASTER_KEY_B:
            ret = client_master_key(s);
            if (ret <= 0)
                goto end;
            s->init_num = 0;
            s->state = SSL2_ST_CLIENT_START_ENCRYPTION;
            break;

        case SSL2_ST_CLIENT_START_ENCRYPTION:
            /*
             * Ok, we now have all the stuff needed to start encrypting, so
             * lets fire it up :-)
             */
            if (!ssl2_enc_init(s, 1)) {
                ret = -1;
                goto end;
            }
            s->s2->clear_text = 0;
            s->state = SSL2_ST_SEND_CLIENT_FINISHED_A;
            break;

        case SSL2_ST_SEND_CLIENT_FINISHED_A:
        case SSL2_ST_SEND_CLIENT_FINISHED_B:
            ret = client_finished(s);
            if (ret <= 0)
                goto end;
            s->init_num = 0;
            s->state = SSL2_ST_GET_SERVER_VERIFY_A;
            break;

        case SSL2_ST_GET_SERVER_VERIFY_A:
        case SSL2_ST_GET_SERVER_VERIFY_B:
            ret = get_server_verify(s);
            if (ret <= 0)
                goto end;
            s->init_num = 0;
            s->state = SSL2_ST_GET_SERVER_FINISHED_A;
            break;

        case SSL2_ST_GET_SERVER_FINISHED_A:
        case SSL2_ST_GET_SERVER_FINISHED_B:
            ret = get_server_finished(s);
            if (ret <= 0)
                goto end;
            break;

        case SSL2_ST_SEND_CLIENT_CERTIFICATE_A:
        case SSL2_ST_SEND_CLIENT_CERTIFICATE_B:
        case SSL2_ST_SEND_CLIENT_CERTIFICATE_C:
        case SSL2_ST_SEND_CLIENT_CERTIFICATE_D:
        case SSL2_ST_X509_GET_CLIENT_CERTIFICATE:
            ret = client_certificate(s);
            if (ret <= 0)
                goto end;
            s->init_num = 0;
            s->state = SSL2_ST_GET_SERVER_FINISHED_A;
            break;

        case SSL_ST_OK:
            if (s->init_buf != NULL) {
                BUF_MEM_free(s->init_buf);
                s->init_buf = NULL;
            }
            s->init_num = 0;
            /*      ERR_clear_error(); */

            /*
             * If we want to cache session-ids in the client and we
             * successfully add the session-id to the cache, and there is a
             * callback, then pass it out. 26/11/96 - eay - only add if not a
             * re-used session.
             */

            ssl_update_cache(s, SSL_SESS_CACHE_CLIENT);
            if (s->hit)
                s->ctx->stats.sess_hit++;

            ret = 1;
            /* s->server=0; */
            s->ctx->stats.sess_connect_good++;

            if (cb != NULL)
                cb(s, SSL_CB_HANDSHAKE_DONE, 1);

            goto end;
            /* break; */
        default:
            SSLerr(SSL_F_SSL2_CONNECT, SSL_R_UNKNOWN_STATE);
            return (-1);
            /* break; */
        }

        if ((cb != NULL) && (s->state != state)) {
            new_state = s->state;
            s->state = state;
            cb(s, SSL_CB_CONNECT_LOOP, 1);
            s->state = new_state;
        }
    }
 end:
    s->in_handshake--;
    if (buf != NULL)
        BUF_MEM_free(buf);
    if (cb != NULL)
        cb(s, SSL_CB_CONNECT_EXIT, ret);
    return (ret);
}

static int get_server_hello(SSL *s)
{
    unsigned char *buf;
    unsigned char *p;
    int i, j;
    unsigned long len;
    STACK_OF(SSL_CIPHER) *sk = NULL, *cl, *prio, *allow;

    buf = (unsigned char *)s->init_buf->data;
    p = buf;
    if (s->state == SSL2_ST_GET_SERVER_HELLO_A) {
        i = ssl2_read(s, (char *)&(buf[s->init_num]), 11 - s->init_num);
        if (i < (11 - s->init_num))
            return (ssl2_part_read(s, SSL_F_GET_SERVER_HELLO, i));
        s->init_num = 11;

        if (*(p++) != SSL2_MT_SERVER_HELLO) {
            if (p[-1] != SSL2_MT_ERROR) {
                ssl2_return_error(s, SSL2_PE_UNDEFINED_ERROR);
                SSLerr(SSL_F_GET_SERVER_HELLO, SSL_R_READ_WRONG_PACKET_TYPE);
            } else
                SSLerr(SSL_F_GET_SERVER_HELLO, SSL_R_PEER_ERROR);
            return (-1);
        }
# if 0
        s->hit = (*(p++)) ? 1 : 0;
        /*
         * Some [PPC?] compilers fail to increment p in above statement, e.g.
         * one provided with Rhapsody 5.5, but most recent example XL C 11.1
         * for AIX, even without optimization flag...
         */
# else
        s->hit = (*p) ? 1 : 0;
        p++;
# endif
        s->s2->tmp.cert_type = *(p++);
        n2s(p, i);
        if (i < s->version)
            s->version = i;
        n2s(p, i);
        s->s2->tmp.cert_length = i;
        n2s(p, i);
        s->s2->tmp.csl = i;
        n2s(p, i);
        s->s2->tmp.conn_id_length = i;
        s->state = SSL2_ST_GET_SERVER_HELLO_B;
    }

    /* SSL2_ST_GET_SERVER_HELLO_B */
    len =
        11 + (unsigned long)s->s2->tmp.cert_length +
        (unsigned long)s->s2->tmp.csl +
        (unsigned long)s->s2->tmp.conn_id_length;
    if (len > SSL2_MAX_RECORD_LENGTH_3_BYTE_HEADER) {
        SSLerr(SSL_F_GET_SERVER_HELLO, SSL_R_MESSAGE_TOO_LONG);
        return -1;
    }
    j = (int)len - s->init_num;
    i = ssl2_read(s, (char *)&(buf[s->init_num]), j);
    if (i != j)
        return (ssl2_part_read(s, SSL_F_GET_SERVER_HELLO, i));
    if (s->msg_callback) {
        /* SERVER-HELLO */
        s->msg_callback(0, s->version, 0, buf, (size_t)len, s,
                        s->msg_callback_arg);
    }

    /* things are looking good */

    p = buf + 11;
    if (s->hit) {
        if (s->s2->tmp.cert_length != 0) {
            SSLerr(SSL_F_GET_SERVER_HELLO, SSL_R_REUSE_CERT_LENGTH_NOT_ZERO);
            return (-1);
        }
        if (s->s2->tmp.cert_type != 0) {
            if (!(s->options & SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG)) {
                SSLerr(SSL_F_GET_SERVER_HELLO,
                       SSL_R_REUSE_CERT_TYPE_NOT_ZERO);
                return (-1);
            }
        }
        if (s->s2->tmp.csl != 0) {
            SSLerr(SSL_F_GET_SERVER_HELLO, SSL_R_REUSE_CIPHER_LIST_NOT_ZERO);
            return (-1);
        }
    } else {
# if 0
        /* very bad */
        memset(s->session->session_id, 0,
               SSL_MAX_SSL_SESSION_ID_LENGTH_IN_BYTES);
        s->session->session_id_length = 0;
# endif

        /*
         * we need to do this in case we were trying to reuse a client
         * session but others are already reusing it. If this was a new
         * 'blank' session ID, the session-id length will still be 0
         */
        if (s->session->session_id_length > 0) {
            if (!ssl_get_new_session(s, 0)) {
                ssl2_return_error(s, SSL2_PE_UNDEFINED_ERROR);
                return (-1);
            }
        }

        if (ssl2_set_certificate(s, s->s2->tmp.cert_type,
                                 s->s2->tmp.cert_length, p) <= 0) {
            ssl2_return_error(s, SSL2_PE_BAD_CERTIFICATE);
            return (-1);
        }
        p += s->s2->tmp.cert_length;

        if (s->s2->tmp.csl == 0) {
            ssl2_return_error(s, SSL2_PE_NO_CIPHER);
            SSLerr(SSL_F_GET_SERVER_HELLO, SSL_R_NO_CIPHER_LIST);
            return (-1);
        }

        /*
         * We have just received a list of ciphers back from the server.  We
         * need to get the ones that match, then select the one we want the
         * most :-).
         */

        /* load the ciphers */
        sk = ssl_bytes_to_cipher_list(s, p, s->s2->tmp.csl,
                                      &s->session->ciphers);
        p += s->s2->tmp.csl;
        if (sk == NULL) {
            ssl2_return_error(s, SSL2_PE_UNDEFINED_ERROR);
            SSLerr(SSL_F_GET_SERVER_HELLO, ERR_R_MALLOC_FAILURE);
            return (-1);
        }

        (void)sk_SSL_CIPHER_set_cmp_func(sk, ssl_cipher_ptr_id_cmp);

        /* get the array of ciphers we will accept */
        cl = SSL_get_ciphers(s);
        (void)sk_SSL_CIPHER_set_cmp_func(cl, ssl_cipher_ptr_id_cmp);

        /*
         * If server preference flag set, choose the first
         * (highest priority) cipher the server sends, otherwise
         * client preference has priority.
         */
        if (s->options & SSL_OP_CIPHER_SERVER_PREFERENCE) {
            prio = sk;
            allow = cl;
        } else {
            prio = cl;
            allow = sk;
        }
        /*
         * In theory we could have ciphers sent back that we don't want to
         * use but that does not matter since we will check against the list
         * we originally sent and for performance reasons we should not
         * bother to match the two lists up just to check.
         */
        for (i = 0; i < sk_SSL_CIPHER_num(prio); i++) {
            if (sk_SSL_CIPHER_find(allow, sk_SSL_CIPHER_value(prio, i)) >= 0)
                break;
        }

        if (i >= sk_SSL_CIPHER_num(prio)) {
            ssl2_return_error(s, SSL2_PE_NO_CIPHER);
            SSLerr(SSL_F_GET_SERVER_HELLO, SSL_R_NO_CIPHER_MATCH);
            return (-1);
        }
        s->session->cipher = sk_SSL_CIPHER_value(prio, i);

        if (s->session->peer != NULL) { /* can't happen */
            ssl2_return_error(s, SSL2_PE_UNDEFINED_ERROR);
            SSLerr(SSL_F_GET_SERVER_HELLO, ERR_R_INTERNAL_ERROR);
            return (-1);
        }

        s->session->peer = s->session->sess_cert->peer_key->x509;
        /* peer_key->x509 has been set by ssl2_set_certificate. */
        CRYPTO_add(&s->session->peer->references, 1, CRYPTO_LOCK_X509);
    }

    if (s->session->sess_cert == NULL
        || s->session->peer != s->session->sess_cert->peer_key->x509)
        /* can't happen */
    {
        ssl2_return_error(s, SSL2_PE_UNDEFINED_ERROR);
        SSLerr(SSL_F_GET_SERVER_HELLO, ERR_R_INTERNAL_ERROR);
        return (-1);
    }

    s->s2->conn_id_length = s->s2->tmp.conn_id_length;
    if (s->s2->conn_id_length > sizeof(s->s2->conn_id)) {
        ssl2_return_error(s, SSL2_PE_UNDEFINED_ERROR);
        SSLerr(SSL_F_GET_SERVER_HELLO, SSL_R_SSL2_CONNECTION_ID_TOO_LONG);
        return -1;
    }
    memcpy(s->s2->conn_id, p, s->s2->tmp.conn_id_length);
    return (1);
}

static int client_hello(SSL *s)
{
    unsigned char *buf;
    unsigned char *p, *d;
/*      CIPHER **cipher;*/
    int i, n, j;

    buf = (unsigned char *)s->init_buf->data;
    if (s->state == SSL2_ST_SEND_CLIENT_HELLO_A) {
        if ((s->session == NULL) || (s->session->ssl_version != s->version)) {
            if (!ssl_get_new_session(s, 0)) {
                ssl2_return_error(s, SSL2_PE_UNDEFINED_ERROR);
                return (-1);
            }
        }
        /* else use the pre-loaded session */

        p = buf;                /* header */
        d = p + 9;              /* data section */
        *(p++) = SSL2_MT_CLIENT_HELLO; /* type */
        s2n(SSL2_VERSION, p);   /* version */
        n = j = 0;

        n = ssl_cipher_list_to_bytes(s, SSL_get_ciphers(s), d, 0);
        d += n;

        if (n == 0) {
            SSLerr(SSL_F_CLIENT_HELLO, SSL_R_NO_CIPHERS_AVAILABLE);
            return (-1);
        }

        s2n(n, p);              /* cipher spec num bytes */

        if ((s->session->session_id_length > 0) &&
            (s->session->session_id_length <=
             SSL2_MAX_SSL_SESSION_ID_LENGTH)) {
            i = s->session->session_id_length;
            s2n(i, p);          /* session id length */
            memcpy(d, s->session->session_id, (unsigned int)i);
            d += i;
        } else {
            s2n(0, p);
        }

        s->s2->challenge_length = SSL2_CHALLENGE_LENGTH;
        s2n(SSL2_CHALLENGE_LENGTH, p); /* challenge length */
        /*
         * challenge id data
         */
        if (RAND_bytes(s->s2->challenge, SSL2_CHALLENGE_LENGTH) <= 0)
            return -1;
        memcpy(d, s->s2->challenge, SSL2_CHALLENGE_LENGTH);
        d += SSL2_CHALLENGE_LENGTH;

        s->state = SSL2_ST_SEND_CLIENT_HELLO_B;
        s->init_num = d - buf;
        s->init_off = 0;
    }
    /* SSL2_ST_SEND_CLIENT_HELLO_B */
    return (ssl2_do_write(s));
}

static int client_master_key(SSL *s)
{
    unsigned char *buf;
    unsigned char *p, *d;
    int clear, enc, karg, i;
    SSL_SESSION *sess;
    const EVP_CIPHER *c;
    const EVP_MD *md;

    buf = (unsigned char *)s->init_buf->data;
    if (s->state == SSL2_ST_SEND_CLIENT_MASTER_KEY_A) {

        if (!ssl_cipher_get_evp(s->session, &c, &md, NULL, NULL, NULL)) {
            ssl2_return_error(s, SSL2_PE_NO_CIPHER);
            SSLerr(SSL_F_CLIENT_MASTER_KEY,
                   SSL_R_PROBLEMS_MAPPING_CIPHER_FUNCTIONS);
            return (-1);
        }
        sess = s->session;
        p = buf;
        d = p + 10;
        *(p++) = SSL2_MT_CLIENT_MASTER_KEY; /* type */

        i = ssl_put_cipher_by_char(s, sess->cipher, p);
        p += i;

        /* make key_arg data */
        i = EVP_CIPHER_iv_length(c);
        sess->key_arg_length = i;
        if (i > SSL_MAX_KEY_ARG_LENGTH) {
            ssl2_return_error(s, SSL2_PE_UNDEFINED_ERROR);
            SSLerr(SSL_F_CLIENT_MASTER_KEY, ERR_R_INTERNAL_ERROR);
            return -1;
        }
        if (i > 0)
            if (RAND_bytes(sess->key_arg, i) <= 0)
                return -1;

        /* make a master key */
        i = EVP_CIPHER_key_length(c);
        sess->master_key_length = i;
        if (i > 0) {
            if (i > (int)sizeof(sess->master_key)) {
                ssl2_return_error(s, SSL2_PE_UNDEFINED_ERROR);
                SSLerr(SSL_F_CLIENT_MASTER_KEY, ERR_R_INTERNAL_ERROR);
                return -1;
            }
            if (RAND_bytes(sess->master_key, i) <= 0) {
                ssl2_return_error(s, SSL2_PE_UNDEFINED_ERROR);
                return (-1);
            }
        }

        if (sess->cipher->algorithm2 & SSL2_CF_8_BYTE_ENC)
            enc = 8;
        else if (SSL_C_IS_EXPORT(sess->cipher))
            enc = 5;
        else
            enc = i;

        if ((int)i < enc) {
            ssl2_return_error(s, SSL2_PE_UNDEFINED_ERROR);
            SSLerr(SSL_F_CLIENT_MASTER_KEY, SSL_R_CIPHER_TABLE_SRC_ERROR);
            return (-1);
        }
        clear = i - enc;
        s2n(clear, p);
        memcpy(d, sess->master_key, (unsigned int)clear);
        d += clear;

        enc = ssl_rsa_public_encrypt(sess->sess_cert, enc,
                                     &(sess->master_key[clear]), d,
                                     (s->
                                      s2->ssl2_rollback) ? RSA_SSLV23_PADDING
                                     : RSA_PKCS1_PADDING);
        if (enc <= 0) {
            ssl2_return_error(s, SSL2_PE_UNDEFINED_ERROR);
            SSLerr(SSL_F_CLIENT_MASTER_KEY, SSL_R_PUBLIC_KEY_ENCRYPT_ERROR);
            return (-1);
        }
# ifdef PKCS1_CHECK
        if (s->options & SSL_OP_PKCS1_CHECK_1)
            d[1]++;
        if (s->options & SSL_OP_PKCS1_CHECK_2)
            sess->master_key[clear]++;
# endif
        s2n(enc, p);
        d += enc;
        karg = sess->key_arg_length;
        s2n(karg, p);           /* key arg size */
        if (karg > (int)sizeof(sess->key_arg)) {
            ssl2_return_error(s, SSL2_PE_UNDEFINED_ERROR);
            SSLerr(SSL_F_CLIENT_MASTER_KEY, ERR_R_INTERNAL_ERROR);
            return -1;
        }
        memcpy(d, sess->key_arg, (unsigned int)karg);
        d += karg;

        s->state = SSL2_ST_SEND_CLIENT_MASTER_KEY_B;
        s->init_num = d - buf;
        s->init_off = 0;
    }

    /* SSL2_ST_SEND_CLIENT_MASTER_KEY_B */
    return (ssl2_do_write(s));
}

static int client_finished(SSL *s)
{
    unsigned char *p;

    if (s->state == SSL2_ST_SEND_CLIENT_FINISHED_A) {
        p = (unsigned char *)s->init_buf->data;
        *(p++) = SSL2_MT_CLIENT_FINISHED;
        if (s->s2->conn_id_length > sizeof(s->s2->conn_id)) {
            SSLerr(SSL_F_CLIENT_FINISHED, ERR_R_INTERNAL_ERROR);
            return -1;
        }
        memcpy(p, s->s2->conn_id, (unsigned int)s->s2->conn_id_length);

        s->state = SSL2_ST_SEND_CLIENT_FINISHED_B;
        s->init_num = s->s2->conn_id_length + 1;
        s->init_off = 0;
    }
    return (ssl2_do_write(s));
}

/* read the data and then respond */
static int client_certificate(SSL *s)
{
    unsigned char *buf;
    unsigned char *p, *d;
    int i;
    unsigned int n;
    int cert_ch_len;
    unsigned char *cert_ch;

    buf = (unsigned char *)s->init_buf->data;

    /*
     * We have a cert associated with the SSL, so attach it to the session if
     * it does not have one
     */

    if (s->state == SSL2_ST_SEND_CLIENT_CERTIFICATE_A) {
        i = ssl2_read(s, (char *)&(buf[s->init_num]),
                      SSL2_MAX_CERT_CHALLENGE_LENGTH + 2 - s->init_num);
        if (i < (SSL2_MIN_CERT_CHALLENGE_LENGTH + 2 - s->init_num))
            return (ssl2_part_read(s, SSL_F_CLIENT_CERTIFICATE, i));
        s->init_num += i;
        if (s->msg_callback) {
            /* REQUEST-CERTIFICATE */
            s->msg_callback(0, s->version, 0, buf, (size_t)s->init_num, s,
                            s->msg_callback_arg);
        }

        /* type=buf[0]; */
        /* type eq x509 */
        if (buf[1] != SSL2_AT_MD5_WITH_RSA_ENCRYPTION) {
            ssl2_return_error(s, SSL2_PE_UNSUPPORTED_CERTIFICATE_TYPE);
            SSLerr(SSL_F_CLIENT_CERTIFICATE, SSL_R_BAD_AUTHENTICATION_TYPE);
            return (-1);
        }

        if ((s->cert == NULL) ||
            (s->cert->key->x509 == NULL) ||
            (s->cert->key->privatekey == NULL)) {
            s->state = SSL2_ST_X509_GET_CLIENT_CERTIFICATE;
        } else
            s->state = SSL2_ST_SEND_CLIENT_CERTIFICATE_C;
    }

    cert_ch = buf + 2;
    cert_ch_len = s->init_num - 2;

    if (s->state == SSL2_ST_X509_GET_CLIENT_CERTIFICATE) {
        X509 *x509 = NULL;
        EVP_PKEY *pkey = NULL;

        /*
         * If we get an error we need to ssl->rwstate=SSL_X509_LOOKUP;
         * return(error); We should then be retried when things are ok and we
         * can get a cert or not
         */

        i = 0;
        if (s->ctx->client_cert_cb != NULL) {
            i = s->ctx->client_cert_cb(s, &(x509), &(pkey));
        }

        if (i < 0) {
            s->rwstate = SSL_X509_LOOKUP;
            return (-1);
        }
        s->rwstate = SSL_NOTHING;

        if ((i == 1) && (pkey != NULL) && (x509 != NULL)) {
            s->state = SSL2_ST_SEND_CLIENT_CERTIFICATE_C;
            if (!SSL_use_certificate(s, x509) || !SSL_use_PrivateKey(s, pkey)) {
                i = 0;
            }
            X509_free(x509);
            EVP_PKEY_free(pkey);
        } else if (i == 1) {
            if (x509 != NULL)
                X509_free(x509);
            if (pkey != NULL)
                EVP_PKEY_free(pkey);
            SSLerr(SSL_F_CLIENT_CERTIFICATE,
                   SSL_R_BAD_DATA_RETURNED_BY_CALLBACK);
            i = 0;
        }

        if (i == 0) {
            /*
             * We have no client certificate to respond with so send the
             * correct error message back
             */
            s->state = SSL2_ST_SEND_CLIENT_CERTIFICATE_B;
            p = buf;
            *(p++) = SSL2_MT_ERROR;
            s2n(SSL2_PE_NO_CERTIFICATE, p);
            s->init_off = 0;
            s->init_num = 3;
            /* Write is done at the end */
        }
    }

    if (s->state == SSL2_ST_SEND_CLIENT_CERTIFICATE_B) {
        return (ssl2_do_write(s));
    }

    if (s->state == SSL2_ST_SEND_CLIENT_CERTIFICATE_C) {
        EVP_MD_CTX ctx;

        /*
         * ok, now we calculate the checksum do it first so we can reuse buf
         * :-)
         */
        p = buf;
        EVP_MD_CTX_init(&ctx);
        EVP_SignInit_ex(&ctx, s->ctx->rsa_md5, NULL);
        EVP_SignUpdate(&ctx, s->s2->key_material, s->s2->key_material_length);
        EVP_SignUpdate(&ctx, cert_ch, (unsigned int)cert_ch_len);
        i = i2d_X509(s->session->sess_cert->peer_key->x509, &p);
        /*
         * Don't update the signature if it fails - FIXME: probably should
         * handle this better
         */
        if (i > 0)
            EVP_SignUpdate(&ctx, buf, (unsigned int)i);

        p = buf;
        d = p + 6;
        *(p++) = SSL2_MT_CLIENT_CERTIFICATE;
        *(p++) = SSL2_CT_X509_CERTIFICATE;
        n = i2d_X509(s->cert->key->x509, &d);
        s2n(n, p);

        if (!EVP_SignFinal(&ctx, d, &n, s->cert->key->privatekey)) {
            /*
             * this is not good.  If things have failed it means there so
             * something wrong with the key. We will continue with a 0 length
             * signature
             */
        }
        EVP_MD_CTX_cleanup(&ctx);
        s2n(n, p);
        d += n;

        s->state = SSL2_ST_SEND_CLIENT_CERTIFICATE_D;
        s->init_num = d - buf;
        s->init_off = 0;
    }
    /* if (s->state == SSL2_ST_SEND_CLIENT_CERTIFICATE_D) */
    return (ssl2_do_write(s));
}

static int get_server_verify(SSL *s)
{
    unsigned char *p;
    int i, n, len;

    p = (unsigned char *)s->init_buf->data;
    if (s->state == SSL2_ST_GET_SERVER_VERIFY_A) {
        i = ssl2_read(s, (char *)&(p[s->init_num]), 1 - s->init_num);
        if (i < (1 - s->init_num))
            return (ssl2_part_read(s, SSL_F_GET_SERVER_VERIFY, i));
        s->init_num += i;

        s->state = SSL2_ST_GET_SERVER_VERIFY_B;
        if (*p != SSL2_MT_SERVER_VERIFY) {
            if (p[0] != SSL2_MT_ERROR) {
                ssl2_return_error(s, SSL2_PE_UNDEFINED_ERROR);
                SSLerr(SSL_F_GET_SERVER_VERIFY, SSL_R_READ_WRONG_PACKET_TYPE);
            } else {
                SSLerr(SSL_F_GET_SERVER_VERIFY, SSL_R_PEER_ERROR);
                /* try to read the error message */
                i = ssl2_read(s, (char *)&(p[s->init_num]), 3 - s->init_num);
                return ssl2_part_read(s, SSL_F_GET_SERVER_VERIFY, i);
            }
            return (-1);
        }
    }

    p = (unsigned char *)s->init_buf->data;
    len = 1 + s->s2->challenge_length;
    n = len - s->init_num;
    i = ssl2_read(s, (char *)&(p[s->init_num]), n);
    if (i < n)
        return (ssl2_part_read(s, SSL_F_GET_SERVER_VERIFY, i));
    if (s->msg_callback) {
        /* SERVER-VERIFY */
        s->msg_callback(0, s->version, 0, p, len, s, s->msg_callback_arg);
    }
    p += 1;

    if (CRYPTO_memcmp(p, s->s2->challenge, s->s2->challenge_length) != 0) {
        ssl2_return_error(s, SSL2_PE_UNDEFINED_ERROR);
        SSLerr(SSL_F_GET_SERVER_VERIFY, SSL_R_CHALLENGE_IS_DIFFERENT);
        return (-1);
    }
    return (1);
}

static int get_server_finished(SSL *s)
{
    unsigned char *buf;
    unsigned char *p;
    int i, n, len;

    buf = (unsigned char *)s->init_buf->data;
    p = buf;
    if (s->state == SSL2_ST_GET_SERVER_FINISHED_A) {
        i = ssl2_read(s, (char *)&(buf[s->init_num]), 1 - s->init_num);
        if (i < (1 - s->init_num))
            return (ssl2_part_read(s, SSL_F_GET_SERVER_FINISHED, i));
        s->init_num += i;

        if (*p == SSL2_MT_REQUEST_CERTIFICATE) {
            s->state = SSL2_ST_SEND_CLIENT_CERTIFICATE_A;
            return (1);
        } else if (*p != SSL2_MT_SERVER_FINISHED) {
            if (p[0] != SSL2_MT_ERROR) {
                ssl2_return_error(s, SSL2_PE_UNDEFINED_ERROR);
                SSLerr(SSL_F_GET_SERVER_FINISHED,
                       SSL_R_READ_WRONG_PACKET_TYPE);
            } else {
                SSLerr(SSL_F_GET_SERVER_FINISHED, SSL_R_PEER_ERROR);
                /* try to read the error message */
                i = ssl2_read(s, (char *)&(p[s->init_num]), 3 - s->init_num);
                return ssl2_part_read(s, SSL_F_GET_SERVER_VERIFY, i);
            }
            return (-1);
        }
        s->state = SSL2_ST_GET_SERVER_FINISHED_B;
    }

    len = 1 + SSL2_SSL_SESSION_ID_LENGTH;
    n = len - s->init_num;
    i = ssl2_read(s, (char *)&(buf[s->init_num]), n);
    if (i < n) {
        /*
         * XXX could be shorter than SSL2_SSL_SESSION_ID_LENGTH,
         * that's the maximum
         */
        return (ssl2_part_read(s, SSL_F_GET_SERVER_FINISHED, i));
    }
    s->init_num += i;
    if (s->msg_callback) {
        /* SERVER-FINISHED */
        s->msg_callback(0, s->version, 0, buf, (size_t)s->init_num, s,
                        s->msg_callback_arg);
    }

    if (!s->hit) {              /* new session */
        /* new session-id */
        /*
         * Make sure we were not trying to re-use an old SSL_SESSION or bad
         * things can happen
         */
        /* ZZZZZZZZZZZZZ */
        s->session->session_id_length = SSL2_SSL_SESSION_ID_LENGTH;
        memcpy(s->session->session_id, p + 1, SSL2_SSL_SESSION_ID_LENGTH);
    } else {
        if (!(s->options & SSL_OP_MICROSOFT_SESS_ID_BUG)) {
            if ((s->session->session_id_length >
                 sizeof(s->session->session_id))
                || (0 !=
                    memcmp(buf + 1, s->session->session_id,
                           (unsigned int)s->session->session_id_length))) {
                ssl2_return_error(s, SSL2_PE_UNDEFINED_ERROR);
                SSLerr(SSL_F_GET_SERVER_FINISHED,
                       SSL_R_SSL_SESSION_ID_IS_DIFFERENT);
                return (-1);
            }
        }
    }
    s->state = SSL_ST_OK;
    return (1);
}

/* loads in the certificate from the server */
int ssl2_set_certificate(SSL *s, int type, int len, const unsigned char *data)
{
    STACK_OF(X509) *sk = NULL;
    EVP_PKEY *pkey = NULL;
    SESS_CERT *sc = NULL;
    int i;
    X509 *x509 = NULL;
    int ret = 0;

    x509 = d2i_X509(NULL, &data, (long)len);
    if (x509 == NULL) {
        SSLerr(SSL_F_SSL2_SET_CERTIFICATE, ERR_R_X509_LIB);
        goto err;
    }

    if ((sk = sk_X509_new_null()) == NULL || !sk_X509_push(sk, x509)) {
        SSLerr(SSL_F_SSL2_SET_CERTIFICATE, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    i = ssl_verify_cert_chain(s, sk);

    if ((s->verify_mode != SSL_VERIFY_NONE) && (i <= 0)) {
        SSLerr(SSL_F_SSL2_SET_CERTIFICATE, SSL_R_CERTIFICATE_VERIFY_FAILED);
        goto err;
    }
    ERR_clear_error();          /* but we keep s->verify_result */
    s->session->verify_result = s->verify_result;

    /* server's cert for this session */
    sc = ssl_sess_cert_new();
    if (sc == NULL) {
        ret = -1;
        goto err;
    }
    if (s->session->sess_cert)
        ssl_sess_cert_free(s->session->sess_cert);
    s->session->sess_cert = sc;

    sc->peer_pkeys[SSL_PKEY_RSA_ENC].x509 = x509;
    sc->peer_key = &(sc->peer_pkeys[SSL_PKEY_RSA_ENC]);

    pkey = X509_get_pubkey(x509);
    x509 = NULL;
    if (pkey == NULL) {
        SSLerr(SSL_F_SSL2_SET_CERTIFICATE,
               SSL_R_UNABLE_TO_EXTRACT_PUBLIC_KEY);
        goto err;
    }
    if (pkey->type != EVP_PKEY_RSA) {
        SSLerr(SSL_F_SSL2_SET_CERTIFICATE, SSL_R_PUBLIC_KEY_NOT_RSA);
        goto err;
    }

    if (!ssl_set_peer_cert_type(sc, SSL2_CT_X509_CERTIFICATE))
        goto err;
    ret = 1;
 err:
    sk_X509_free(sk);
    X509_free(x509);
    EVP_PKEY_free(pkey);
    return (ret);
}

static int ssl_rsa_public_encrypt(SESS_CERT *sc, int len, unsigned char *from,
                                  unsigned char *to, int padding)
{
    EVP_PKEY *pkey = NULL;
    int i = -1;

    if ((sc == NULL) || (sc->peer_key->x509 == NULL) ||
        ((pkey = X509_get_pubkey(sc->peer_key->x509)) == NULL)) {
        SSLerr(SSL_F_SSL_RSA_PUBLIC_ENCRYPT, SSL_R_NO_PUBLICKEY);
        return (-1);
    }
    if (pkey->type != EVP_PKEY_RSA) {
        SSLerr(SSL_F_SSL_RSA_PUBLIC_ENCRYPT, SSL_R_PUBLIC_KEY_IS_NOT_RSA);
        goto end;
    }

    /* we have the public key */
    i = RSA_public_encrypt(len, from, to, pkey->pkey.rsa, padding);
    if (i < 0)
        SSLerr(SSL_F_SSL_RSA_PUBLIC_ENCRYPT, ERR_R_RSA_LIB);
 end:
    EVP_PKEY_free(pkey);
    return (i);
}
#else                           /* !OPENSSL_NO_SSL2 */

# if PEDANTIC
static void *dummy = &dummy;
# endif

#endif
/* ssl/s2_enc.c */
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

// #include "ssl_locl.h"
#ifndef OPENSSL_NO_SSL2
# include <stdio.h>

int ssl2_enc_init(SSL *s, int client)
{
    /* Max number of bytes needed */
    EVP_CIPHER_CTX *rs, *ws;
    const EVP_CIPHER *c;
    const EVP_MD *md;
    int num;

    if (!ssl_cipher_get_evp(s->session, &c, &md, NULL, NULL, NULL)) {
        ssl2_return_error(s, SSL2_PE_NO_CIPHER);
        SSLerr(SSL_F_SSL2_ENC_INIT, SSL_R_PROBLEMS_MAPPING_CIPHER_FUNCTIONS);
        return (0);
    }
    ssl_replace_hash(&s->read_hash, md);
    ssl_replace_hash(&s->write_hash, md);

    if ((s->enc_read_ctx == NULL) && ((s->enc_read_ctx = (EVP_CIPHER_CTX *)
                                       OPENSSL_malloc(sizeof(EVP_CIPHER_CTX)))
                                      == NULL))
        goto err;

    /*
     * make sure it's intialized in case the malloc for enc_write_ctx fails
     * and we exit with an error
     */
    rs = s->enc_read_ctx;
    EVP_CIPHER_CTX_init(rs);

    if ((s->enc_write_ctx == NULL) && ((s->enc_write_ctx = (EVP_CIPHER_CTX *)
                                        OPENSSL_malloc(sizeof
                                                       (EVP_CIPHER_CTX))) ==
                                       NULL))
        goto err;

    ws = s->enc_write_ctx;
    EVP_CIPHER_CTX_init(ws);

    num = c->key_len;
    s->s2->key_material_length = num * 2;
    OPENSSL_assert(s->s2->key_material_length <= sizeof(s->s2->key_material));

    if (ssl2_generate_key_material(s) <= 0)
        return 0;

    OPENSSL_assert(c->iv_len <= (int)sizeof(s->session->key_arg));
    EVP_EncryptInit_ex(ws, c, NULL,
                       &(s->s2->key_material[(client) ? num : 0]),
                       s->session->key_arg);
    EVP_DecryptInit_ex(rs, c, NULL,
                       &(s->s2->key_material[(client) ? 0 : num]),
                       s->session->key_arg);
    s->s2->read_key = &(s->s2->key_material[(client) ? 0 : num]);
    s->s2->write_key = &(s->s2->key_material[(client) ? num : 0]);
    return (1);
 err:
    SSLerr(SSL_F_SSL2_ENC_INIT, ERR_R_MALLOC_FAILURE);
    return (0);
}

/*
 * read/writes from s->s2->mac_data using length for encrypt and decrypt.
 * It sets s->s2->padding and s->[rw]length if we are encrypting Returns 0 on
 * error and 1 on success
 */
int ssl2_enc(SSL *s, int send)
{
    EVP_CIPHER_CTX *ds;
    unsigned long l;
    int bs;

    if (send) {
        ds = s->enc_write_ctx;
        l = s->s2->wlength;
    } else {
        ds = s->enc_read_ctx;
        l = s->s2->rlength;
    }

    /* check for NULL cipher */
    if (ds == NULL)
        return 1;

    bs = ds->cipher->block_size;
    /*
     * This should be using (bs-1) and bs instead of 7 and 8, but what the
     * hell.
     */
    if (bs == 8)
        l = (l + 7) / 8 * 8;

    if (EVP_Cipher(ds, s->s2->mac_data, s->s2->mac_data, l) < 1)
        return 0;

    return 1;
}

void ssl2_mac(SSL *s, unsigned char *md, int send)
{
    EVP_MD_CTX c;
    unsigned char sequence[4], *p, *sec, *act;
    unsigned long seq;
    unsigned int len;

    if (send) {
        seq = s->s2->write_sequence;
        sec = s->s2->write_key;
        len = s->s2->wact_data_length;
        act = s->s2->wact_data;
    } else {
        seq = s->s2->read_sequence;
        sec = s->s2->read_key;
        len = s->s2->ract_data_length;
        act = s->s2->ract_data;
    }

    p = &(sequence[0]);
    l2n(seq, p);

    /* There has to be a MAC algorithm. */
    EVP_MD_CTX_init(&c);
    EVP_MD_CTX_copy(&c, s->read_hash);
    EVP_DigestUpdate(&c, sec, EVP_CIPHER_CTX_key_length(s->enc_read_ctx));
    EVP_DigestUpdate(&c, act, len);
    /* the above line also does the pad data */
    EVP_DigestUpdate(&c, sequence, 4);
    EVP_DigestFinal_ex(&c, md, NULL);
    EVP_MD_CTX_cleanup(&c);
}
#else                           /* !OPENSSL_NO_SSL2 */

# if PEDANTIC
static void *dummy = &dummy;
# endif

#endif
/* ssl/s2_lib.c */
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
 * Copyright (c) 1998-2007 The OpenSSL Project.  All rights reserved.
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

// #include "ssl_locl.h"
#ifndef OPENSSL_NO_SSL2
# include <stdio.h>
# include "objects.h"
# include "evp.h"
# include "md5.h"

const char ssl2_version_str[] = "SSLv2" OPENSSL_VERSION_PTEXT;

# define SSL2_NUM_CIPHERS (sizeof(ssl2_ciphers)/sizeof(SSL_CIPHER))

/* list of available SSLv2 ciphers (sorted by id) */
OPENSSL_GLOBAL const SSL_CIPHER ssl2_ciphers[] = {
# if 0
/* NULL_WITH_MD5 v3 */
    {
     1,
     SSL2_TXT_NULL_WITH_MD5,
     SSL2_CK_NULL_WITH_MD5,
     SSL_kRSA,
     SSL_aRSA,
     SSL_eNULL,
     SSL_MD5,
     SSL_SSLV2,
     SSL_EXPORT | SSL_EXP40 | SSL_STRONG_NONE,
     0,
     0,
     0,
     },
# endif

/* RC4_128_WITH_MD5 */
    {
     1,
     SSL2_TXT_RC4_128_WITH_MD5,
     SSL2_CK_RC4_128_WITH_MD5,
     SSL_kRSA,
     SSL_aRSA,
     SSL_RC4,
     SSL_MD5,
     SSL_SSLV2,
     SSL_NOT_DEFAULT | SSL_NOT_EXP | SSL_MEDIUM,
     0,
     128,
     128,
     },

# if 0
/* RC4_128_EXPORT40_WITH_MD5 */
    {
     1,
     SSL2_TXT_RC4_128_EXPORT40_WITH_MD5,
     SSL2_CK_RC4_128_EXPORT40_WITH_MD5,
     SSL_kRSA,
     SSL_aRSA,
     SSL_RC4,
     SSL_MD5,
     SSL_SSLV2,
     SSL_NOT_DEFAULT | SSL_EXPORT | SSL_EXP40,
     SSL2_CF_5_BYTE_ENC,
     40,
     128,
     },
# endif

/* RC2_128_CBC_WITH_MD5 */
    {
     1,
     SSL2_TXT_RC2_128_CBC_WITH_MD5,
     SSL2_CK_RC2_128_CBC_WITH_MD5,
     SSL_kRSA,
     SSL_aRSA,
     SSL_RC2,
     SSL_MD5,
     SSL_SSLV2,
     SSL_NOT_DEFAULT | SSL_NOT_EXP | SSL_MEDIUM,
     0,
     128,
     128,
     },

# if 0
/* RC2_128_CBC_EXPORT40_WITH_MD5 */
    {
     1,
     SSL2_TXT_RC2_128_CBC_EXPORT40_WITH_MD5,
     SSL2_CK_RC2_128_CBC_EXPORT40_WITH_MD5,
     SSL_kRSA,
     SSL_aRSA,
     SSL_RC2,
     SSL_MD5,
     SSL_SSLV2,
     SSL_NOT_DEFAULT | SSL_EXPORT | SSL_EXP40,
     SSL2_CF_5_BYTE_ENC,
     40,
     128,
     },
# endif

# ifndef OPENSSL_NO_IDEA
/* IDEA_128_CBC_WITH_MD5 */
    {
     1,
     SSL2_TXT_IDEA_128_CBC_WITH_MD5,
     SSL2_CK_IDEA_128_CBC_WITH_MD5,
     SSL_kRSA,
     SSL_aRSA,
     SSL_IDEA,
     SSL_MD5,
     SSL_SSLV2,
     SSL_NOT_DEFAULT | SSL_NOT_EXP | SSL_MEDIUM,
     0,
     128,
     128,
     },
# endif

# if 0
/* DES_64_CBC_WITH_MD5 */
    {
     1,
     SSL2_TXT_DES_64_CBC_WITH_MD5,
     SSL2_CK_DES_64_CBC_WITH_MD5,
     SSL_kRSA,
     SSL_aRSA,
     SSL_DES,
     SSL_MD5,
     SSL_SSLV2,
     SSL_NOT_DEFAULT | SSL_NOT_EXP | SSL_LOW,
     0,
     56,
     56,
     },
# endif

/* DES_192_EDE3_CBC_WITH_MD5 */
    {
     1,
     SSL2_TXT_DES_192_EDE3_CBC_WITH_MD5,
     SSL2_CK_DES_192_EDE3_CBC_WITH_MD5,
     SSL_kRSA,
     SSL_aRSA,
     SSL_3DES,
     SSL_MD5,
     SSL_SSLV2,
     SSL_NOT_DEFAULT | SSL_NOT_EXP | SSL_MEDIUM,
     0,
     112,
     168,
     },

# if 0
/* RC4_64_WITH_MD5 */
    {
     1,
     SSL2_TXT_RC4_64_WITH_MD5,
     SSL2_CK_RC4_64_WITH_MD5,
     SSL_kRSA,
     SSL_aRSA,
     SSL_RC4,
     SSL_MD5,
     SSL_SSLV2,
     SSL_NOT_DEFAULT | SSL_NOT_EXP | SSL_LOW,
     SSL2_CF_8_BYTE_ENC,
     64,
     64,
     },
# endif

# if 0
/* NULL SSLeay (testing) */
    {
     0,
     SSL2_TXT_NULL,
     SSL2_CK_NULL,
     0,
     0,
     0,
     0,
     SSL_SSLV2,
     SSL_STRONG_NONE,
     0,
     0,
     0,
     },
# endif

/* end of list :-) */
};

long ssl2_default_timeout(void)
{
    return (300);
}

int ssl2_num_ciphers(void)
{
    return (SSL2_NUM_CIPHERS);
}

const SSL_CIPHER *ssl2_get_cipher(unsigned int u)
{
    if (u < SSL2_NUM_CIPHERS)
        return (&(ssl2_ciphers[SSL2_NUM_CIPHERS - 1 - u]));
    else
        return (NULL);
}

int ssl2_pending(const SSL *s)
{
    return SSL_in_init(s) ? 0 : s->s2->ract_data_length;
}

int ssl2_new(SSL *s)
{
    SSL2_STATE *s2;

    if ((s2 = OPENSSL_malloc(sizeof(*s2))) == NULL)
        goto err;
    memset(s2, 0, sizeof(*s2));

# if SSL2_MAX_RECORD_LENGTH_3_BYTE_HEADER + 3 > SSL2_MAX_RECORD_LENGTH_2_BYTE_HEADER + 2
#  error "assertion failed"
# endif

    if ((s2->rbuf =
         OPENSSL_malloc(SSL2_MAX_RECORD_LENGTH_2_BYTE_HEADER + 2)) == NULL)
        goto err;
    /*
     * wbuf needs one byte more because when using two-byte headers, we leave
     * the first byte unused in do_ssl_write (s2_pkt.c)
     */
    if ((s2->wbuf =
         OPENSSL_malloc(SSL2_MAX_RECORD_LENGTH_2_BYTE_HEADER + 3)) == NULL)
        goto err;
    s->s2 = s2;

    ssl2_clear(s);
    return (1);
 err:
    if (s2 != NULL) {
        if (s2->wbuf != NULL)
            OPENSSL_free(s2->wbuf);
        if (s2->rbuf != NULL)
            OPENSSL_free(s2->rbuf);
        OPENSSL_free(s2);
    }
    return (0);
}

void ssl2_free(SSL *s)
{
    SSL2_STATE *s2;

    if (s == NULL)
        return;

    s2 = s->s2;
    if (s2->rbuf != NULL)
        OPENSSL_free(s2->rbuf);
    if (s2->wbuf != NULL)
        OPENSSL_free(s2->wbuf);
    OPENSSL_cleanse(s2, sizeof(*s2));
    OPENSSL_free(s2);
    s->s2 = NULL;
}

void ssl2_clear(SSL *s)
{
    SSL2_STATE *s2;
    unsigned char *rbuf, *wbuf;

    s2 = s->s2;

    rbuf = s2->rbuf;
    wbuf = s2->wbuf;

    memset(s2, 0, sizeof(*s2));

    s2->rbuf = rbuf;
    s2->wbuf = wbuf;
    s2->clear_text = 1;
    s->packet = s2->rbuf;
    s->version = SSL2_VERSION;
    s->packet_length = 0;
}

long ssl2_ctrl(SSL *s, int cmd, long larg, void *parg)
{
    int ret = 0;

    switch (cmd) {
    case SSL_CTRL_GET_SESSION_REUSED:
        ret = s->hit;
        break;
    case SSL_CTRL_CHECK_PROTO_VERSION:
        return ssl3_ctrl(s, SSL_CTRL_CHECK_PROTO_VERSION, larg, parg);
    default:
        break;
    }
    return (ret);
}

long ssl2_callback_ctrl(SSL *s, int cmd, void (*fp) (void))
{
    return (0);
}

long ssl2_ctx_ctrl(SSL_CTX *ctx, int cmd, long larg, void *parg)
{
    return (0);
}

long ssl2_ctx_callback_ctrl(SSL_CTX *ctx, int cmd, void (*fp) (void))
{
    return (0);
}

/*
 * This function needs to check if the ciphers required are actually
 * available
 */
const SSL_CIPHER *ssl2_get_cipher_by_char(const unsigned char *p)
{
    SSL_CIPHER c;
    const SSL_CIPHER *cp;
    unsigned long id;

    id = 0x02000000L | ((unsigned long)p[0] << 16L) |
        ((unsigned long)p[1] << 8L) | (unsigned long)p[2];
    c.id = id;
    cp = OBJ_bsearch_ssl_cipher_id(&c, ssl2_ciphers, SSL2_NUM_CIPHERS);
    return cp;
}

int ssl2_put_cipher_by_char(const SSL_CIPHER *c, unsigned char *p)
{
    long l;

    if (p != NULL) {
        l = c->id;
        if ((l & 0xff000000) != 0x02000000 && l != SSL3_CK_FALLBACK_SCSV)
            return (0);
        p[0] = ((unsigned char)(l >> 16L)) & 0xFF;
        p[1] = ((unsigned char)(l >> 8L)) & 0xFF;
        p[2] = ((unsigned char)(l)) & 0xFF;
    }
    return (3);
}

int ssl2_generate_key_material(SSL *s)
{
    unsigned int i;
    EVP_MD_CTX ctx;
    unsigned char *km;
    unsigned char c = '0';
    const EVP_MD *md5;
    int md_size;

    md5 = EVP_md5();

# ifdef CHARSET_EBCDIC
    c = os_toascii['0'];        /* Must be an ASCII '0', not EBCDIC '0', see
                                 * SSLv2 docu */
# endif
    EVP_MD_CTX_init(&ctx);
    km = s->s2->key_material;

    if (s->session->master_key_length < 0 ||
        s->session->master_key_length > (int)sizeof(s->session->master_key)) {
        SSLerr(SSL_F_SSL2_GENERATE_KEY_MATERIAL, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    md_size = EVP_MD_size(md5);
    if (md_size < 0)
        return 0;
    for (i = 0; i < s->s2->key_material_length; i += md_size) {
        if (((km - s->s2->key_material) + md_size) >
            (int)sizeof(s->s2->key_material)) {
            /*
             * EVP_DigestFinal_ex() below would write beyond buffer
             */
            SSLerr(SSL_F_SSL2_GENERATE_KEY_MATERIAL, ERR_R_INTERNAL_ERROR);
            return 0;
        }

        EVP_DigestInit_ex(&ctx, md5, NULL);

        OPENSSL_assert(s->session->master_key_length >= 0
                       && s->session->master_key_length
                       <= (int)sizeof(s->session->master_key));
        EVP_DigestUpdate(&ctx, s->session->master_key,
                         s->session->master_key_length);
        EVP_DigestUpdate(&ctx, &c, 1);
        c++;
        EVP_DigestUpdate(&ctx, s->s2->challenge, s->s2->challenge_length);
        EVP_DigestUpdate(&ctx, s->s2->conn_id, s->s2->conn_id_length);
        EVP_DigestFinal_ex(&ctx, km, NULL);
        km += md_size;
    }

    EVP_MD_CTX_cleanup(&ctx);
    return 1;
}

void ssl2_return_error(SSL *s, int err)
{
    if (!s->error) {
        s->error = 3;
        s->error_code = err;

        ssl2_write_error(s);
    }
}

void ssl2_write_error(SSL *s)
{
    unsigned char buf[3];
    int i, error;

    buf[0] = SSL2_MT_ERROR;
    buf[1] = (s->error_code >> 8) & 0xff;
    buf[2] = (s->error_code) & 0xff;

/*      state=s->rwstate;*/

    error = s->error;           /* number of bytes left to write */
    s->error = 0;
    OPENSSL_assert(error >= 0 && error <= (int)sizeof(buf));
    i = ssl2_write(s, &(buf[3 - error]), error);

/*      if (i == error) s->rwstate=state; */

    if (i < 0)
        s->error = error;
    else {
        s->error = error - i;

        if (s->error == 0)
            if (s->msg_callback) {
                /* ERROR */
                s->msg_callback(1, s->version, 0, buf, 3, s,
                                s->msg_callback_arg);
            }
    }
}

int ssl2_shutdown(SSL *s)
{
    s->shutdown = (SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
    return (1);
}
#else                           /* !OPENSSL_NO_SSL2 */

# if PEDANTIC
static void *dummy = &dummy;
# endif

#endif
/* ssl/s2_meth.c */
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

// #include "ssl_locl.h"
#ifndef OPENSSL_NO_SSL2_METHOD
# ifndef OPENSSL_NO_SSL2
# include <stdio.h>
# include "objects.h"

static const SSL_METHOD *ssl2_get_method(int ver);
static const SSL_METHOD *ssl2_get_method(int ver)
{
    if (ver == SSL2_VERSION)
        return (SSLv2_method());
    else
        return (NULL);
}

IMPLEMENT_ssl2_meth_func(SSLv2_method,
                         ssl2_accept, ssl2_connect, ssl2_get_method)

# else /* !OPENSSL_NO_SSL2 */

const SSL_METHOD *SSLv2_method(void) { return NULL; }
const SSL_METHOD *SSLv2_client_method(void) { return NULL; }
const SSL_METHOD *SSLv2_server_method(void) { return NULL; }

# endif

#else /* !OPENSSL_NO_SSL2_METHOD */

# if PEDANTIC
static void *dummy = &dummy;
# endif

#endif
/* ssl/s2_pkt.c */
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

// #include "ssl_locl.h"
#ifndef OPENSSL_NO_SSL2
# include <stdio.h>
# include <errno.h>
# define USE_SOCKETS

static int read_n(SSL *s, unsigned int n, unsigned int max,
                  unsigned int extend);
static int n_do_ssl_write(SSL *s, const unsigned char *buf, unsigned int len);
static int write_pending(SSL *s, const unsigned char *buf, unsigned int len);
static int ssl_mt_error(int n);

/*
 * SSL 2.0 imlementation for SSL_read/SSL_peek - This routine will return 0
 * to len bytes, decrypted etc if required.
 */
static int ssl2_read_internal(SSL *s, void *buf, int len, int peek)
{
    int n;
    unsigned char mac[MAX_MAC_SIZE];
    unsigned char *p;
    int i;
    int mac_size;

 ssl2_read_again:
    if (SSL_in_init(s) && !s->in_handshake) {
        n = s->handshake_func(s);
        if (n < 0)
            return (n);
        if (n == 0) {
            SSLerr(SSL_F_SSL2_READ_INTERNAL, SSL_R_SSL_HANDSHAKE_FAILURE);
            return (-1);
        }
    }

    clear_sys_error();
    s->rwstate = SSL_NOTHING;
    if (len <= 0)
        return (len);

    if (s->s2->ract_data_length != 0) { /* read from buffer */
        if (len > s->s2->ract_data_length)
            n = s->s2->ract_data_length;
        else
            n = len;

        memcpy(buf, s->s2->ract_data, (unsigned int)n);
        if (!peek) {
            s->s2->ract_data_length -= n;
            s->s2->ract_data += n;
            if (s->s2->ract_data_length == 0)
                s->rstate = SSL_ST_READ_HEADER;
        }

        return (n);
    }

    /*
     * s->s2->ract_data_length == 0 Fill the buffer, then goto
     * ssl2_read_again.
     */

    if (s->rstate == SSL_ST_READ_HEADER) {
        if (s->first_packet) {
            n = read_n(s, 5, SSL2_MAX_RECORD_LENGTH_2_BYTE_HEADER + 2, 0);
            if (n <= 0)
                return (n);     /* error or non-blocking */
            s->first_packet = 0;
            p = s->packet;
            if (!((p[0] & 0x80) && ((p[2] == SSL2_MT_CLIENT_HELLO) ||
                                    (p[2] == SSL2_MT_SERVER_HELLO)))) {
                SSLerr(SSL_F_SSL2_READ_INTERNAL,
                       SSL_R_NON_SSLV2_INITIAL_PACKET);
                return (-1);
            }
        } else {
            n = read_n(s, 2, SSL2_MAX_RECORD_LENGTH_2_BYTE_HEADER + 2, 0);
            if (n <= 0)
                return (n);     /* error or non-blocking */
        }
        /* part read stuff */

        s->rstate = SSL_ST_READ_BODY;
        p = s->packet;
        /* Do header */
        /*
         * s->s2->padding=0;
         */
        s->s2->escape = 0;
        s->s2->rlength = (((unsigned int)p[0]) << 8) | ((unsigned int)p[1]);
        if ((p[0] & TWO_BYTE_BIT)) { /* Two byte header? */
            s->s2->three_byte_header = 0;
            s->s2->rlength &= TWO_BYTE_MASK;
        } else {
            s->s2->three_byte_header = 1;
            s->s2->rlength &= THREE_BYTE_MASK;

            /* security >s2->escape */
            s->s2->escape = ((p[0] & SEC_ESC_BIT)) ? 1 : 0;
        }
    }

    if (s->rstate == SSL_ST_READ_BODY) {
        n = s->s2->rlength + 2 + s->s2->three_byte_header;
        if (n > (int)s->packet_length) {
            n -= s->packet_length;
            i = read_n(s, (unsigned int)n, (unsigned int)n, 1);
            if (i <= 0)
                return (i);     /* ERROR */
        }

        p = &(s->packet[2]);
        s->rstate = SSL_ST_READ_HEADER;
        if (s->s2->three_byte_header)
            s->s2->padding = *(p++);
        else
            s->s2->padding = 0;

        /* Data portion */
        if (s->s2->clear_text) {
            mac_size = 0;
            s->s2->mac_data = p;
            s->s2->ract_data = p;
            if (s->s2->padding) {
                SSLerr(SSL_F_SSL2_READ_INTERNAL, SSL_R_ILLEGAL_PADDING);
                return (-1);
            }
        } else {
            mac_size = EVP_MD_CTX_size(s->read_hash);
            if (mac_size < 0)
                return -1;
            OPENSSL_assert(mac_size <= MAX_MAC_SIZE);
            s->s2->mac_data = p;
            s->s2->ract_data = &p[mac_size];
            if (s->s2->padding + mac_size > s->s2->rlength) {
                SSLerr(SSL_F_SSL2_READ_INTERNAL, SSL_R_ILLEGAL_PADDING);
                return (-1);
            }
        }

        s->s2->ract_data_length = s->s2->rlength;
        /*
         * added a check for length > max_size in case encryption was not
         * turned on yet due to an error
         */
        if ((!s->s2->clear_text) &&
            (s->s2->rlength >= (unsigned int)mac_size)) {
            if (!ssl2_enc(s, 0)) {
                SSLerr(SSL_F_SSL2_READ_INTERNAL, SSL_R_DECRYPTION_FAILED);
                return (-1);
            }
            s->s2->ract_data_length -= mac_size;
            ssl2_mac(s, mac, 0);
            s->s2->ract_data_length -= s->s2->padding;
            if ((CRYPTO_memcmp(mac, s->s2->mac_data, mac_size) != 0) ||
                (s->s2->rlength %
                 EVP_CIPHER_CTX_block_size(s->enc_read_ctx) != 0)) {
                SSLerr(SSL_F_SSL2_READ_INTERNAL, SSL_R_BAD_MAC_DECODE);
                return (-1);
            }
        }
        INC32(s->s2->read_sequence); /* expect next number */
        /* s->s2->ract_data is now available for processing */

        /*
         * Possibly the packet that we just read had 0 actual data bytes.
         * (SSLeay/OpenSSL itself never sends such packets; see ssl2_write.)
         * In this case, returning 0 would be interpreted by the caller as
         * indicating EOF, so it's not a good idea.  Instead, we just
         * continue reading; thus ssl2_read_internal may have to process
         * multiple packets before it can return. [Note that using select()
         * for blocking sockets *never* guarantees that the next SSL_read
         * will not block -- the available data may contain incomplete
         * packets, and except for SSL 2, renegotiation can confuse things
         * even more.]
         */

        goto ssl2_read_again;   /* This should really be "return
                                 * ssl2_read(s,buf,len)", but that would
                                 * allow for denial-of-service attacks if a C
                                 * compiler is used that does not recognize
                                 * end-recursion. */
    } else {
        SSLerr(SSL_F_SSL2_READ_INTERNAL, SSL_R_BAD_STATE);
        return (-1);
    }
}

int ssl2_read(SSL *s, void *buf, int len)
{
    return ssl2_read_internal(s, buf, len, 0);
}

int ssl2_peek(SSL *s, void *buf, int len)
{
    return ssl2_read_internal(s, buf, len, 1);
}

/*
 * Return values are as per SSL_read()
 */
static int read_n(SSL *s, unsigned int n, unsigned int max,
                  unsigned int extend)
{
    int i, off, newb;

    /*
     * if there is stuff still in the buffer from a previous read, and there
     * is more than we want, take some.
     */
    if (s->s2->rbuf_left >= (int)n) {
        if (extend)
            s->packet_length += n;
        else {
            s->packet = &(s->s2->rbuf[s->s2->rbuf_offs]);
            s->packet_length = n;
        }
        s->s2->rbuf_left -= n;
        s->s2->rbuf_offs += n;
        return (n);
    }

    if (!s->read_ahead)
        max = n;
    if (max > (unsigned int)(SSL2_MAX_RECORD_LENGTH_2_BYTE_HEADER + 2))
        max = SSL2_MAX_RECORD_LENGTH_2_BYTE_HEADER + 2;

    /*
     * Else we want more than we have. First, if there is some left or we
     * want to extend
     */
    off = 0;
    if ((s->s2->rbuf_left != 0) || ((s->packet_length != 0) && extend)) {
        newb = s->s2->rbuf_left;
        if (extend) {
            off = s->packet_length;
            if (s->packet != s->s2->rbuf)
                memcpy(s->s2->rbuf, s->packet, (unsigned int)newb + off);
        } else if (s->s2->rbuf_offs != 0) {
            memcpy(s->s2->rbuf, &(s->s2->rbuf[s->s2->rbuf_offs]),
                   (unsigned int)newb);
            s->s2->rbuf_offs = 0;
        }
        s->s2->rbuf_left = 0;
    } else
        newb = 0;

    /*
     * off is the offset to start writing too. r->s2->rbuf_offs is the
     * 'unread data', now 0. newb is the number of new bytes so far
     */
    s->packet = s->s2->rbuf;
    while (newb < (int)n) {
        clear_sys_error();
        if (s->rbio != NULL) {
            s->rwstate = SSL_READING;
            i = BIO_read(s->rbio, (char *)&(s->s2->rbuf[off + newb]),
                         max - newb);
        } else {
            SSLerr(SSL_F_READ_N, SSL_R_READ_BIO_NOT_SET);
            i = -1;
        }
# ifdef PKT_DEBUG
        if (s->debug & 0x01)
            sleep(1);
# endif
        if (i <= 0) {
            s->s2->rbuf_left += newb;
            return i;
        }
        newb += i;
    }

    /* record unread data */
    if (newb > (int)n) {
        s->s2->rbuf_offs = n + off;
        s->s2->rbuf_left = newb - n;
    } else {
        s->s2->rbuf_offs = 0;
        s->s2->rbuf_left = 0;
    }
    if (extend)
        s->packet_length += n;
    else
        s->packet_length = n;
    s->rwstate = SSL_NOTHING;
    return (n);
}

int ssl2_write(SSL *s, const void *_buf, int len)
{
    const unsigned char *buf = _buf;
    unsigned int n, tot;
    int i;

    if (SSL_in_init(s) && !s->in_handshake) {
        i = s->handshake_func(s);
        if (i < 0)
            return (i);
        if (i == 0) {
            SSLerr(SSL_F_SSL2_WRITE, SSL_R_SSL_HANDSHAKE_FAILURE);
            return (-1);
        }
    }

    if (s->error) {
        ssl2_write_error(s);
        if (s->error)
            return (-1);
    }

    clear_sys_error();
    s->rwstate = SSL_NOTHING;
    if (len <= 0)
        return (len);

    tot = s->s2->wnum;
    s->s2->wnum = 0;

    n = (len - tot);
    for (;;) {
        i = n_do_ssl_write(s, &(buf[tot]), n);
        if (i <= 0) {
            s->s2->wnum = tot;
            return (i);
        }
        if ((i == (int)n) || (s->mode & SSL_MODE_ENABLE_PARTIAL_WRITE)) {
            return (tot + i);
        }

        n -= i;
        tot += i;
    }
}

/*
 * Return values are as per SSL_write()
 */
static int write_pending(SSL *s, const unsigned char *buf, unsigned int len)
{
    int i;

    /* s->s2->wpend_len != 0 MUST be true. */

    /*
     * check that they have given us the same buffer to write
     */
    if ((s->s2->wpend_tot > (int)len) ||
        ((s->s2->wpend_buf != buf) &&
         !(s->mode & SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER))) {
        SSLerr(SSL_F_WRITE_PENDING, SSL_R_BAD_WRITE_RETRY);
        return (-1);
    }

    for (;;) {
        clear_sys_error();
        if (s->wbio != NULL) {
            s->rwstate = SSL_WRITING;
            i = BIO_write(s->wbio,
                          (char *)&(s->s2->write_ptr[s->s2->wpend_off]),
                          (unsigned int)s->s2->wpend_len);
        } else {
            SSLerr(SSL_F_WRITE_PENDING, SSL_R_WRITE_BIO_NOT_SET);
            i = -1;
        }
# ifdef PKT_DEBUG
        if (s->debug & 0x01)
            sleep(1);
# endif
        if (i == s->s2->wpend_len) {
            s->s2->wpend_len = 0;
            s->rwstate = SSL_NOTHING;
            return (s->s2->wpend_ret);
        } else if (i <= 0)
            return i;
        s->s2->wpend_off += i;
        s->s2->wpend_len -= i;
    }
}

static int n_do_ssl_write(SSL *s, const unsigned char *buf, unsigned int len)
{
    unsigned int j, k, olen, p, bs;
    int mac_size;
    register unsigned char *pp;

    olen = len;

    /*
     * first check if there is data from an encryption waiting to be sent -
     * it must be sent because the other end is waiting. This will happen
     * with non-blocking IO.  We print it and then return.
     */
    if (s->s2->wpend_len != 0)
        return (write_pending(s, buf, len));

    /* set mac_size to mac size */
    if (s->s2->clear_text)
        mac_size = 0;
    else {
        mac_size = EVP_MD_CTX_size(s->write_hash);
        if (mac_size < 0)
            return -1;
    }

    /* lets set the pad p */
    if (s->s2->clear_text) {
        if (len > SSL2_MAX_RECORD_LENGTH_2_BYTE_HEADER)
            len = SSL2_MAX_RECORD_LENGTH_2_BYTE_HEADER;
        p = 0;
        s->s2->three_byte_header = 0;
        /* len=len; */
    } else {
        bs = EVP_CIPHER_CTX_block_size(s->enc_read_ctx);
        j = len + mac_size;
        /*
         * Two-byte headers allow for a larger record length than three-byte
         * headers, but we can't use them if we need padding or if we have to
         * set the escape bit.
         */
        if ((j > SSL2_MAX_RECORD_LENGTH_3_BYTE_HEADER) && (!s->s2->escape)) {
            if (j > SSL2_MAX_RECORD_LENGTH_2_BYTE_HEADER)
                j = SSL2_MAX_RECORD_LENGTH_2_BYTE_HEADER;
            /*
             * set k to the max number of bytes with 2 byte header
             */
            k = j - (j % bs);
            /* how many data bytes? */
            len = k - mac_size;
            s->s2->three_byte_header = 0;
            p = 0;
        } else if ((bs <= 1) && (!s->s2->escape)) {
            /*-
             * j <= SSL2_MAX_RECORD_LENGTH_3_BYTE_HEADER, thus
             * j < SSL2_MAX_RECORD_LENGTH_2_BYTE_HEADER
             */
            s->s2->three_byte_header = 0;
            p = 0;
        } else {                /* we may have to use a 3 byte header */

            /*-
             * If s->s2->escape is not set, then
             * j <= SSL2_MAX_RECORD_LENGTH_3_BYTE_HEADER, and thus
             * j < SSL2_MAX_RECORD_LENGTH_2_BYTE_HEADER.
             */
            p = (j % bs);
            p = (p == 0) ? 0 : (bs - p);
            if (s->s2->escape) {
                s->s2->three_byte_header = 1;
                if (j > SSL2_MAX_RECORD_LENGTH_3_BYTE_HEADER)
                    j = SSL2_MAX_RECORD_LENGTH_3_BYTE_HEADER;
            } else
                s->s2->three_byte_header = (p == 0) ? 0 : 1;
        }
    }

    /*-
     * Now
     *      j <= SSL2_MAX_RECORD_LENGTH_2_BYTE_HEADER
     * holds, and if s->s2->three_byte_header is set, then even
     *      j <= SSL2_MAX_RECORD_LENGTH_3_BYTE_HEADER.
     */

    /*
     * mac_size is the number of MAC bytes len is the number of data bytes we
     * are going to send p is the number of padding bytes (if it is a
     * two-byte header, then p == 0)
     */

    s->s2->wlength = len;
    s->s2->padding = p;
    s->s2->mac_data = &(s->s2->wbuf[3]);
    s->s2->wact_data = &(s->s2->wbuf[3 + mac_size]);

    /*
     * It would be clearer to write this as follows:
     *     if (mac_size + len + p > SSL2_MAX_RECORD_LENGTH_2_BYTE_HEADER)
     * However |len| is user input that could in theory be very large. We
     * know |mac_size| and |p| are small, so to avoid any possibility of
     * overflow we write it like this.
     *
     * In theory this should never fail because the logic above should have
     * modified |len| if it is too big. But we are being cautious.
     */
    if (len > (SSL2_MAX_RECORD_LENGTH_2_BYTE_HEADER - (mac_size + p))) {
        return -1;
    }
    /* we copy the data into s->s2->wbuf */
    memcpy(s->s2->wact_data, buf, len);
    if (p)
        memset(&(s->s2->wact_data[len]), 0, p); /* arbitrary padding */

    if (!s->s2->clear_text) {
        s->s2->wact_data_length = len + p;
        ssl2_mac(s, s->s2->mac_data, 1);
        s->s2->wlength += p + mac_size;
        if (ssl2_enc(s, 1) < 1)
            return -1;
    }

    /* package up the header */
    s->s2->wpend_len = s->s2->wlength;
    if (s->s2->three_byte_header) { /* 3 byte header */
        pp = s->s2->mac_data;
        pp -= 3;
        pp[0] = (s->s2->wlength >> 8) & (THREE_BYTE_MASK >> 8);
        if (s->s2->escape)
            pp[0] |= SEC_ESC_BIT;
        pp[1] = s->s2->wlength & 0xff;
        pp[2] = s->s2->padding;
        s->s2->wpend_len += 3;
    } else {
        pp = s->s2->mac_data;
        pp -= 2;
        pp[0] = ((s->s2->wlength >> 8) & (TWO_BYTE_MASK >> 8)) | TWO_BYTE_BIT;
        pp[1] = s->s2->wlength & 0xff;
        s->s2->wpend_len += 2;
    }
    s->s2->write_ptr = pp;

    INC32(s->s2->write_sequence); /* expect next number */

    /* lets try to actually write the data */
    s->s2->wpend_tot = olen;
    s->s2->wpend_buf = buf;

    s->s2->wpend_ret = len;

    s->s2->wpend_off = 0;
    return (write_pending(s, buf, olen));
}

int ssl2_part_read(SSL *s, unsigned long f, int i)
{
    unsigned char *p;
    int j;

    if (i < 0) {
        /* ssl2_return_error(s); */
        /*
         * for non-blocking io, this is not necessarily fatal
         */
        return (i);
    } else {
        s->init_num += i;

        /*
         * Check for error.  While there are recoverable errors, this
         * function is not called when those must be expected; any error
         * detected here is fatal.
         */
        if (s->init_num >= 3) {
            p = (unsigned char *)s->init_buf->data;
            if (p[0] == SSL2_MT_ERROR) {
                j = (p[1] << 8) | p[2];
                SSLerr((int)f, ssl_mt_error(j));
                s->init_num -= 3;
                if (s->init_num > 0)
                    memmove(p, p + 3, s->init_num);
            }
        }

        /*
         * If it's not an error message, we have some error anyway -- the
         * message was shorter than expected.  This too is treated as fatal
         * (at least if SSL_get_error is asked for its opinion).
         */
        return (0);
    }
}

int ssl2_do_write(SSL *s)
{
    int ret;

    ret = ssl2_write(s, &s->init_buf->data[s->init_off], s->init_num);
    if (ret == s->init_num) {
        if (s->msg_callback)
            s->msg_callback(1, s->version, 0, s->init_buf->data,
                            (size_t)(s->init_off + s->init_num), s,
                            s->msg_callback_arg);
        return (1);
    }
    if (ret < 0)
        return (-1);
    s->init_off += ret;
    s->init_num -= ret;
    return (0);
}

static int ssl_mt_error(int n)
{
    int ret;

    switch (n) {
    case SSL2_PE_NO_CIPHER:
        ret = SSL_R_PEER_ERROR_NO_CIPHER;
        break;
    case SSL2_PE_NO_CERTIFICATE:
        ret = SSL_R_PEER_ERROR_NO_CERTIFICATE;
        break;
    case SSL2_PE_BAD_CERTIFICATE:
        ret = SSL_R_PEER_ERROR_CERTIFICATE;
        break;
    case SSL2_PE_UNSUPPORTED_CERTIFICATE_TYPE:
        ret = SSL_R_PEER_ERROR_UNSUPPORTED_CERTIFICATE_TYPE;
        break;
    default:
        ret = SSL_R_UNKNOWN_REMOTE_ERROR_TYPE;
        break;
    }
    return (ret);
}
#else                           /* !OPENSSL_NO_SSL2 */

# if PEDANTIC
static void *dummy = &dummy;
# endif

#endif
/* ssl/s2_srvr.c */
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

// #include "ssl_locl.h"
#ifndef OPENSSL_NO_SSL2
#include "constant_time_locl.h"
# include <stdio.h>
# include "bio.h"
# include "rand.h"
# include "objects.h"
# include "evp.h"

static const SSL_METHOD *ssl2_get_server_method(int ver);
static int get_client_master_key(SSL *s);
static int get_client_hello(SSL *s);
static int server_hello(SSL *s);
static int get_client_finished(SSL *s);
static int server_verify(SSL *s);
static int server_finish(SSL *s);
static int request_certificate(SSL *s);
static int ssl_rsa_private_decrypt(CERT *c, int len, unsigned char *from,
                                   unsigned char *to, int padding);
# define BREAK   break

static const SSL_METHOD *ssl2_get_server_method(int ver)
{
    if (ver == SSL2_VERSION)
        return (SSLv2_server_method());
    else
        return (NULL);
}

IMPLEMENT_ssl2_meth_func(SSLv2_server_method,
                         ssl2_accept,
                         ssl_undefined_function, ssl2_get_server_method)

int ssl2_accept(SSL *s)
{
    unsigned long l = (unsigned long)time(NULL);
    BUF_MEM *buf = NULL;
    int ret = -1;
    long num1;
    void (*cb) (const SSL *ssl, int type, int val) = NULL;
    int new_state, state;

    RAND_add(&l, sizeof(l), 0);
    ERR_clear_error();
    clear_sys_error();

    if (s->info_callback != NULL)
        cb = s->info_callback;
    else if (s->ctx->info_callback != NULL)
        cb = s->ctx->info_callback;

    /* init things to blank */
    s->in_handshake++;
    if (!SSL_in_init(s) || SSL_in_before(s))
        SSL_clear(s);

    if (s->cert == NULL) {
        SSLerr(SSL_F_SSL2_ACCEPT, SSL_R_NO_CERTIFICATE_SET);
        return (-1);
    }

    clear_sys_error();
    for (;;) {
        state = s->state;

        switch (s->state) {
        case SSL_ST_BEFORE:
        case SSL_ST_ACCEPT:
        case SSL_ST_BEFORE | SSL_ST_ACCEPT:
        case SSL_ST_OK | SSL_ST_ACCEPT:

            s->server = 1;
            if (cb != NULL)
                cb(s, SSL_CB_HANDSHAKE_START, 1);

            s->version = SSL2_VERSION;
            s->type = SSL_ST_ACCEPT;

            if (s->init_buf == NULL) {
                if ((buf = BUF_MEM_new()) == NULL) {
                    ret = -1;
                    goto end;
                }
                if (!BUF_MEM_grow
                    (buf, (int)SSL2_MAX_RECORD_LENGTH_3_BYTE_HEADER)) {
                    BUF_MEM_free(buf);
                    ret = -1;
                    goto end;
                }
                s->init_buf = buf;
            }
            s->init_num = 0;
            s->ctx->stats.sess_accept++;
            s->handshake_func = ssl2_accept;
            s->state = SSL2_ST_GET_CLIENT_HELLO_A;
            BREAK;

        case SSL2_ST_GET_CLIENT_HELLO_A:
        case SSL2_ST_GET_CLIENT_HELLO_B:
        case SSL2_ST_GET_CLIENT_HELLO_C:
            s->shutdown = 0;
            ret = get_client_hello(s);
            if (ret <= 0)
                goto end;
            s->init_num = 0;
            s->state = SSL2_ST_SEND_SERVER_HELLO_A;
            BREAK;

        case SSL2_ST_SEND_SERVER_HELLO_A:
        case SSL2_ST_SEND_SERVER_HELLO_B:
            ret = server_hello(s);
            if (ret <= 0)
                goto end;
            s->init_num = 0;
            if (!s->hit) {
                s->state = SSL2_ST_GET_CLIENT_MASTER_KEY_A;
                BREAK;
            } else {
                s->state = SSL2_ST_SERVER_START_ENCRYPTION;
                BREAK;
            }
        case SSL2_ST_GET_CLIENT_MASTER_KEY_A:
        case SSL2_ST_GET_CLIENT_MASTER_KEY_B:
            ret = get_client_master_key(s);
            if (ret <= 0)
                goto end;
            s->init_num = 0;
            s->state = SSL2_ST_SERVER_START_ENCRYPTION;
            BREAK;

        case SSL2_ST_SERVER_START_ENCRYPTION:
            /*
             * Ok we how have sent all the stuff needed to start encrypting,
             * the next packet back will be encrypted.
             */
            if (!ssl2_enc_init(s, 0)) {
                ret = -1;
                goto end;
            }
            s->s2->clear_text = 0;
            s->state = SSL2_ST_SEND_SERVER_VERIFY_A;
            BREAK;

        case SSL2_ST_SEND_SERVER_VERIFY_A:
        case SSL2_ST_SEND_SERVER_VERIFY_B:
            ret = server_verify(s);
            if (ret <= 0)
                goto end;
            s->init_num = 0;
            if (s->hit) {
                /*
                 * If we are in here, we have been buffering the output, so
                 * we need to flush it and remove buffering from future
                 * traffic
                 */
                s->state = SSL2_ST_SEND_SERVER_VERIFY_C;
                BREAK;
            } else {
                s->state = SSL2_ST_GET_CLIENT_FINISHED_A;
                break;
            }

        case SSL2_ST_SEND_SERVER_VERIFY_C:
            /* get the number of bytes to write */
            num1 = BIO_ctrl(s->wbio, BIO_CTRL_INFO, 0, NULL);
            if (num1 > 0) {
                s->rwstate = SSL_WRITING;
                num1 = BIO_flush(s->wbio);
                if (num1 <= 0) {
                    ret = -1;
                    goto end;
                }
                s->rwstate = SSL_NOTHING;
            }

            /* flushed and now remove buffering */
            s->wbio = BIO_pop(s->wbio);

            s->state = SSL2_ST_GET_CLIENT_FINISHED_A;
            BREAK;

        case SSL2_ST_GET_CLIENT_FINISHED_A:
        case SSL2_ST_GET_CLIENT_FINISHED_B:
            ret = get_client_finished(s);
            if (ret <= 0)
                goto end;
            s->init_num = 0;
            s->state = SSL2_ST_SEND_REQUEST_CERTIFICATE_A;
            BREAK;

        case SSL2_ST_SEND_REQUEST_CERTIFICATE_A:
        case SSL2_ST_SEND_REQUEST_CERTIFICATE_B:
        case SSL2_ST_SEND_REQUEST_CERTIFICATE_C:
        case SSL2_ST_SEND_REQUEST_CERTIFICATE_D:
            /*
             * don't do a 'request certificate' if we don't want to, or we
             * already have one, and we only want to do it once.
             */
            if (!(s->verify_mode & SSL_VERIFY_PEER) ||
                ((s->session->peer != NULL) &&
                 (s->verify_mode & SSL_VERIFY_CLIENT_ONCE))) {
                s->state = SSL2_ST_SEND_SERVER_FINISHED_A;
                break;
            } else {
                ret = request_certificate(s);
                if (ret <= 0)
                    goto end;
                s->init_num = 0;
                s->state = SSL2_ST_SEND_SERVER_FINISHED_A;
            }
            BREAK;

        case SSL2_ST_SEND_SERVER_FINISHED_A:
        case SSL2_ST_SEND_SERVER_FINISHED_B:
            ret = server_finish(s);
            if (ret <= 0)
                goto end;
            s->init_num = 0;
            s->state = SSL_ST_OK;
            break;

        case SSL_ST_OK:
            BUF_MEM_free(s->init_buf);
            ssl_free_wbio_buffer(s);
            s->init_buf = NULL;
            s->init_num = 0;
            /*      ERR_clear_error(); */

            ssl_update_cache(s, SSL_SESS_CACHE_SERVER);

            s->ctx->stats.sess_accept_good++;
            /* s->server=1; */
            ret = 1;

            if (cb != NULL)
                cb(s, SSL_CB_HANDSHAKE_DONE, 1);

            goto end;
            /* BREAK; */

        default:
            SSLerr(SSL_F_SSL2_ACCEPT, SSL_R_UNKNOWN_STATE);
            ret = -1;
            goto end;
            /* BREAK; */
        }

        if ((cb != NULL) && (s->state != state)) {
            new_state = s->state;
            s->state = state;
            cb(s, SSL_CB_ACCEPT_LOOP, 1);
            s->state = new_state;
        }
    }
 end:
    s->in_handshake--;
    if (cb != NULL)
        cb(s, SSL_CB_ACCEPT_EXIT, ret);
    return (ret);
}

static int get_client_master_key(SSL *s)
{
    int is_export, i, n, keya;
    unsigned int num_encrypted_key_bytes, key_length;
    unsigned long len;
    unsigned char *p;
    const SSL_CIPHER *cp;
    const EVP_CIPHER *c;
    const EVP_MD *md;
    unsigned char rand_premaster_secret[SSL_MAX_MASTER_KEY_LENGTH];
    unsigned char decrypt_good;
    size_t j;

    p = (unsigned char *)s->init_buf->data;
    if (s->state == SSL2_ST_GET_CLIENT_MASTER_KEY_A) {
        i = ssl2_read(s, (char *)&(p[s->init_num]), 10 - s->init_num);

        if (i < (10 - s->init_num))
            return (ssl2_part_read(s, SSL_F_GET_CLIENT_MASTER_KEY, i));
        s->init_num = 10;

        if (*(p++) != SSL2_MT_CLIENT_MASTER_KEY) {
            if (p[-1] != SSL2_MT_ERROR) {
                ssl2_return_error(s, SSL2_PE_UNDEFINED_ERROR);
                SSLerr(SSL_F_GET_CLIENT_MASTER_KEY,
                       SSL_R_READ_WRONG_PACKET_TYPE);
            } else
                SSLerr(SSL_F_GET_CLIENT_MASTER_KEY, SSL_R_PEER_ERROR);
            return (-1);
        }

        cp = ssl2_get_cipher_by_char(p);
        if (cp == NULL || sk_SSL_CIPHER_find(s->session->ciphers, cp) < 0) {
            ssl2_return_error(s, SSL2_PE_NO_CIPHER);
            SSLerr(SSL_F_GET_CLIENT_MASTER_KEY, SSL_R_NO_CIPHER_MATCH);
            return (-1);
        }
        s->session->cipher = cp;

        p += 3;
        n2s(p, i);
        s->s2->tmp.clear = i;
        n2s(p, i);
        s->s2->tmp.enc = i;
        n2s(p, i);
        if (i > SSL_MAX_KEY_ARG_LENGTH) {
            ssl2_return_error(s, SSL2_PE_UNDEFINED_ERROR);
            SSLerr(SSL_F_GET_CLIENT_MASTER_KEY, SSL_R_KEY_ARG_TOO_LONG);
            return -1;
        }
        s->session->key_arg_length = i;
        s->state = SSL2_ST_GET_CLIENT_MASTER_KEY_B;
    }

    /* SSL2_ST_GET_CLIENT_MASTER_KEY_B */
    p = (unsigned char *)s->init_buf->data;
    if (s->init_buf->length < SSL2_MAX_RECORD_LENGTH_3_BYTE_HEADER) {
        ssl2_return_error(s, SSL2_PE_UNDEFINED_ERROR);
        SSLerr(SSL_F_GET_CLIENT_MASTER_KEY, ERR_R_INTERNAL_ERROR);
        return -1;
    }
    keya = s->session->key_arg_length;
    len =
        10 + (unsigned long)s->s2->tmp.clear + (unsigned long)s->s2->tmp.enc +
        (unsigned long)keya;
    if (len > SSL2_MAX_RECORD_LENGTH_3_BYTE_HEADER) {
        ssl2_return_error(s, SSL2_PE_UNDEFINED_ERROR);
        SSLerr(SSL_F_GET_CLIENT_MASTER_KEY, SSL_R_MESSAGE_TOO_LONG);
        return -1;
    }
    n = (int)len - s->init_num;
    i = ssl2_read(s, (char *)&(p[s->init_num]), n);
    if (i != n)
        return (ssl2_part_read(s, SSL_F_GET_CLIENT_MASTER_KEY, i));
    if (s->msg_callback) {
        /* CLIENT-MASTER-KEY */
        s->msg_callback(0, s->version, 0, p, (size_t)len, s,
                        s->msg_callback_arg);
    }
    p += 10;

    memcpy(s->session->key_arg, &(p[s->s2->tmp.clear + s->s2->tmp.enc]),
           (unsigned int)keya);

    if (s->cert->pkeys[SSL_PKEY_RSA_ENC].privatekey == NULL) {
        ssl2_return_error(s, SSL2_PE_UNDEFINED_ERROR);
        SSLerr(SSL_F_GET_CLIENT_MASTER_KEY, SSL_R_NO_PRIVATEKEY);
        return (-1);
    }

    is_export = SSL_C_IS_EXPORT(s->session->cipher);

    if (!ssl_cipher_get_evp(s->session, &c, &md, NULL, NULL, NULL)) {
        ssl2_return_error(s, SSL2_PE_NO_CIPHER);
        SSLerr(SSL_F_GET_CLIENT_MASTER_KEY,
               SSL_R_PROBLEMS_MAPPING_CIPHER_FUNCTIONS);
        return (0);
    }

    /*
     * The format of the CLIENT-MASTER-KEY message is
     * 1 byte message type
     * 3 bytes cipher
     * 2-byte clear key length (stored in s->s2->tmp.clear)
     * 2-byte encrypted key length (stored in s->s2->tmp.enc)
     * 2-byte key args length (IV etc)
     * clear key
     * encrypted key
     * key args
     *
     * If the cipher is an export cipher, then the encrypted key bytes
     * are a fixed portion of the total key (5 or 8 bytes). The size of
     * this portion is in |num_encrypted_key_bytes|. If the cipher is not an
     * export cipher, then the entire key material is encrypted (i.e., clear
     * key length must be zero).
     */
    key_length = (unsigned int)EVP_CIPHER_key_length(c);
    if (key_length > SSL_MAX_MASTER_KEY_LENGTH) {
        ssl2_return_error(s, SSL2_PE_UNDEFINED_ERROR);
        SSLerr(SSL_F_GET_CLIENT_MASTER_KEY, ERR_R_INTERNAL_ERROR);
        return -1;
    }

    if (s->session->cipher->algorithm2 & SSL2_CF_8_BYTE_ENC) {
        is_export = 1;
        num_encrypted_key_bytes = 8;
    } else if (is_export) {
        num_encrypted_key_bytes = 5;
    } else {
        num_encrypted_key_bytes = key_length;
    }

    if (s->s2->tmp.clear + num_encrypted_key_bytes != key_length) {
        ssl2_return_error(s, SSL2_PE_UNDEFINED_ERROR);
        SSLerr(SSL_F_GET_CLIENT_MASTER_KEY,SSL_R_BAD_LENGTH);
        return -1;
    }
    /*
     * The encrypted blob must decrypt to the encrypted portion of the key.
     * Decryption can't be expanding, so if we don't have enough encrypted
     * bytes to fit the key in the buffer, stop now.
     */
    if (s->s2->tmp.enc < num_encrypted_key_bytes) {
        ssl2_return_error(s,SSL2_PE_UNDEFINED_ERROR);
        SSLerr(SSL_F_GET_CLIENT_MASTER_KEY,SSL_R_LENGTH_TOO_SHORT);
        return -1;
    }

    /*
     * We must not leak whether a decryption failure occurs because of
     * Bleichenbacher's attack on PKCS #1 v1.5 RSA padding (see RFC 2246,
     * section 7.4.7.1). The code follows that advice of the TLS RFC and
     * generates a random premaster secret for the case that the decrypt
     * fails. See https://tools.ietf.org/html/rfc5246#section-7.4.7.1
     */

    if (RAND_bytes(rand_premaster_secret,
                  (int)num_encrypted_key_bytes) <= 0)
        return 0;

    i = ssl_rsa_private_decrypt(s->cert, s->s2->tmp.enc,
                                &(p[s->s2->tmp.clear]),
                                &(p[s->s2->tmp.clear]),
                                (s->s2->ssl2_rollback) ? RSA_SSLV23_PADDING :
                                RSA_PKCS1_PADDING);
    ERR_clear_error();
    /*
     * If a bad decrypt, continue with protocol but with a random master
     * secret (Bleichenbacher attack)
     */
    decrypt_good = constant_time_eq_int_8(i, (int)num_encrypted_key_bytes);
    for (j = 0; j < num_encrypted_key_bytes; j++) {
        p[s->s2->tmp.clear + j] =
                constant_time_select_8(decrypt_good, p[s->s2->tmp.clear + j],
                                       rand_premaster_secret[j]);
    }

    s->session->master_key_length = (int)key_length;
    memcpy(s->session->master_key, p, key_length);
    OPENSSL_cleanse(p, key_length);

    return 1;
}

static int get_client_hello(SSL *s)
{
    int i, n;
    unsigned long len;
    unsigned char *p;
    STACK_OF(SSL_CIPHER) *cs;   /* a stack of SSL_CIPHERS */
    STACK_OF(SSL_CIPHER) *cl;   /* the ones we want to use */
    STACK_OF(SSL_CIPHER) *prio, *allow;
    int z;

    /*
     * This is a bit of a hack to check for the correct packet type the first
     * time round.
     */
    if (s->state == SSL2_ST_GET_CLIENT_HELLO_A) {
        s->first_packet = 1;
        s->state = SSL2_ST_GET_CLIENT_HELLO_B;
    }

    p = (unsigned char *)s->init_buf->data;
    if (s->state == SSL2_ST_GET_CLIENT_HELLO_B) {
        i = ssl2_read(s, (char *)&(p[s->init_num]), 9 - s->init_num);
        if (i < (9 - s->init_num))
            return (ssl2_part_read(s, SSL_F_GET_CLIENT_HELLO, i));
        s->init_num = 9;

        if (*(p++) != SSL2_MT_CLIENT_HELLO) {
            if (p[-1] != SSL2_MT_ERROR) {
                ssl2_return_error(s, SSL2_PE_UNDEFINED_ERROR);
                SSLerr(SSL_F_GET_CLIENT_HELLO, SSL_R_READ_WRONG_PACKET_TYPE);
            } else
                SSLerr(SSL_F_GET_CLIENT_HELLO, SSL_R_PEER_ERROR);
            return (-1);
        }
        n2s(p, i);
        if (i < s->version)
            s->version = i;
        n2s(p, i);
        s->s2->tmp.cipher_spec_length = i;
        n2s(p, i);
        s->s2->tmp.session_id_length = i;
        if ((i < 0) || (i > SSL_MAX_SSL_SESSION_ID_LENGTH)) {
            ssl2_return_error(s, SSL2_PE_UNDEFINED_ERROR);
            SSLerr(SSL_F_GET_CLIENT_HELLO, SSL_R_LENGTH_MISMATCH);
            return -1;
        }
        n2s(p, i);
        s->s2->challenge_length = i;
        if ((i < SSL2_MIN_CHALLENGE_LENGTH) ||
            (i > SSL2_MAX_CHALLENGE_LENGTH)) {
            ssl2_return_error(s, SSL2_PE_UNDEFINED_ERROR);
            SSLerr(SSL_F_GET_CLIENT_HELLO, SSL_R_INVALID_CHALLENGE_LENGTH);
            return (-1);
        }
        s->state = SSL2_ST_GET_CLIENT_HELLO_C;
    }

    /* SSL2_ST_GET_CLIENT_HELLO_C */
    p = (unsigned char *)s->init_buf->data;
    len =
        9 + (unsigned long)s->s2->tmp.cipher_spec_length +
        (unsigned long)s->s2->challenge_length +
        (unsigned long)s->s2->tmp.session_id_length;
    if (len > SSL2_MAX_RECORD_LENGTH_3_BYTE_HEADER) {
        ssl2_return_error(s, SSL2_PE_UNDEFINED_ERROR);
        SSLerr(SSL_F_GET_CLIENT_HELLO, SSL_R_MESSAGE_TOO_LONG);
        return -1;
    }
    n = (int)len - s->init_num;
    i = ssl2_read(s, (char *)&(p[s->init_num]), n);
    if (i != n)
        return (ssl2_part_read(s, SSL_F_GET_CLIENT_HELLO, i));
    if (s->msg_callback) {
        /* CLIENT-HELLO */
        s->msg_callback(0, s->version, 0, p, (size_t)len, s,
                        s->msg_callback_arg);
    }
    p += 9;

    /*
     * get session-id before cipher stuff so we can get out session structure
     * if it is cached
     */
    /* session-id */
    if ((s->s2->tmp.session_id_length != 0) &&
        (s->s2->tmp.session_id_length != SSL2_SSL_SESSION_ID_LENGTH)) {
        ssl2_return_error(s, SSL2_PE_UNDEFINED_ERROR);
        SSLerr(SSL_F_GET_CLIENT_HELLO, SSL_R_BAD_SSL_SESSION_ID_LENGTH);
        return (-1);
    }

    if (s->s2->tmp.session_id_length == 0) {
        if (!ssl_get_new_session(s, 1)) {
            ssl2_return_error(s, SSL2_PE_UNDEFINED_ERROR);
            return (-1);
        }
    } else {
        i = ssl_get_prev_session(s, &(p[s->s2->tmp.cipher_spec_length]),
                                 s->s2->tmp.session_id_length, NULL);
        if (i == 1) {           /* previous session */
            s->hit = 1;
        } else if (i == -1) {
            ssl2_return_error(s, SSL2_PE_UNDEFINED_ERROR);
            return (-1);
        } else {
            if (s->cert == NULL) {
                ssl2_return_error(s, SSL2_PE_NO_CERTIFICATE);
                SSLerr(SSL_F_GET_CLIENT_HELLO, SSL_R_NO_CERTIFICATE_SET);
                return (-1);
            }

            if (!ssl_get_new_session(s, 1)) {
                ssl2_return_error(s, SSL2_PE_UNDEFINED_ERROR);
                return (-1);
            }
        }
    }

    if (!s->hit) {
        cs = ssl_bytes_to_cipher_list(s, p, s->s2->tmp.cipher_spec_length,
                                      &s->session->ciphers);
        if (cs == NULL)
            goto mem_err;

        cl = SSL_get_ciphers(s);

        if (s->options & SSL_OP_CIPHER_SERVER_PREFERENCE) {
            prio = sk_SSL_CIPHER_dup(cl);
            if (prio == NULL)
                goto mem_err;
            allow = cs;
        } else {
            prio = cs;
            allow = cl;
        }

        /* Generate list of SSLv2 ciphers shared between client and server */
        for (z = 0; z < sk_SSL_CIPHER_num(prio); z++) {
            const SSL_CIPHER *cp = sk_SSL_CIPHER_value(prio, z);
            if ((cp->algorithm_ssl & SSL_SSLV2) == 0 ||
                sk_SSL_CIPHER_find(allow, cp) < 0) {
                (void)sk_SSL_CIPHER_delete(prio, z);
                z--;
            }
        }
        if (s->options & SSL_OP_CIPHER_SERVER_PREFERENCE) {
            sk_SSL_CIPHER_free(s->session->ciphers);
            s->session->ciphers = prio;
        }

        /* Make sure we have at least one cipher in common */
        if (sk_SSL_CIPHER_num(s->session->ciphers) == 0) {
            ssl2_return_error(s, SSL2_PE_NO_CIPHER);
            SSLerr(SSL_F_GET_CLIENT_HELLO, SSL_R_NO_CIPHER_MATCH);
            return -1;
        }
        /*
         * s->session->ciphers should now have a list of ciphers that are on
         * both the client and server. This list is ordered by the order the
         * client sent the ciphers or in the order of the server's preference
         * if SSL_OP_CIPHER_SERVER_PREFERENCE was set.
         */
    }
    p += s->s2->tmp.cipher_spec_length;
    /* done cipher selection */

    /* session id extracted already */
    p += s->s2->tmp.session_id_length;

    /* challenge */
    if (s->s2->challenge_length > sizeof(s->s2->challenge)) {
        ssl2_return_error(s, SSL2_PE_UNDEFINED_ERROR);
        SSLerr(SSL_F_GET_CLIENT_HELLO, ERR_R_INTERNAL_ERROR);
        return -1;
    }
    memcpy(s->s2->challenge, p, (unsigned int)s->s2->challenge_length);
    return (1);
 mem_err:
    SSLerr(SSL_F_GET_CLIENT_HELLO, ERR_R_MALLOC_FAILURE);
    return (0);
}

static int server_hello(SSL *s)
{
    unsigned char *p, *d;
    int n, hit;

    p = (unsigned char *)s->init_buf->data;
    if (s->state == SSL2_ST_SEND_SERVER_HELLO_A) {
        d = p + 11;
        *(p++) = SSL2_MT_SERVER_HELLO; /* type */
        hit = s->hit;
        *(p++) = (unsigned char)hit;
# if 1
        if (!hit) {
            if (s->session->sess_cert != NULL)
                /*
                 * This can't really happen because get_client_hello has
                 * called ssl_get_new_session, which does not set sess_cert.
                 */
                ssl_sess_cert_free(s->session->sess_cert);
            s->session->sess_cert = ssl_sess_cert_new();
            if (s->session->sess_cert == NULL) {
                SSLerr(SSL_F_SERVER_HELLO, ERR_R_MALLOC_FAILURE);
                return (-1);
            }
        }
        /*
         * If 'hit' is set, then s->sess_cert may be non-NULL or NULL,
         * depending on whether it survived in the internal cache or was
         * retrieved from an external cache. If it is NULL, we cannot put any
         * useful data in it anyway, so we don't touch it.
         */

# else                          /* That's what used to be done when cert_st
                                 * and sess_cert_st were * the same. */
        if (!hit) {             /* else add cert to session */
            CRYPTO_add(&s->cert->references, 1, CRYPTO_LOCK_SSL_CERT);
            if (s->session->sess_cert != NULL)
                ssl_cert_free(s->session->sess_cert);
            s->session->sess_cert = s->cert;
        } else {                /* We have a session id-cache hit, if the *
                                 * session-id has no certificate listed
                                 * against * the 'cert' structure, grab the
                                 * 'old' one * listed against the SSL
                                 * connection */
            if (s->session->sess_cert == NULL) {
                CRYPTO_add(&s->cert->references, 1, CRYPTO_LOCK_SSL_CERT);
                s->session->sess_cert = s->cert;
            }
        }
# endif

        if (s->cert == NULL) {
            ssl2_return_error(s, SSL2_PE_NO_CERTIFICATE);
            SSLerr(SSL_F_SERVER_HELLO, SSL_R_NO_CERTIFICATE_SPECIFIED);
            return (-1);
        }

        if (hit) {
            *(p++) = 0;         /* no certificate type */
            s2n(s->version, p); /* version */
            s2n(0, p);          /* cert len */
            s2n(0, p);          /* ciphers len */
        } else {
            /* EAY EAY */
            /* put certificate type */
            *(p++) = SSL2_CT_X509_CERTIFICATE;
            s2n(s->version, p); /* version */
            n = i2d_X509(s->cert->pkeys[SSL_PKEY_RSA_ENC].x509, NULL);
            s2n(n, p);          /* certificate length */
            i2d_X509(s->cert->pkeys[SSL_PKEY_RSA_ENC].x509, &d);
            n = 0;

            /*
             * lets send out the ciphers we like in the prefered order
             */
            n = ssl_cipher_list_to_bytes(s, s->session->ciphers, d, 0);
            d += n;
            s2n(n, p);          /* add cipher length */
        }

        /* make and send conn_id */
        s2n(SSL2_CONNECTION_ID_LENGTH, p); /* add conn_id length */
        s->s2->conn_id_length = SSL2_CONNECTION_ID_LENGTH;
        if (RAND_bytes(s->s2->conn_id, (int)s->s2->conn_id_length) <= 0)
            return -1;
        memcpy(d, s->s2->conn_id, SSL2_CONNECTION_ID_LENGTH);
        d += SSL2_CONNECTION_ID_LENGTH;

        s->state = SSL2_ST_SEND_SERVER_HELLO_B;
        s->init_num = d - (unsigned char *)s->init_buf->data;
        s->init_off = 0;
    }
    /* SSL2_ST_SEND_SERVER_HELLO_B */
    /*
     * If we are using TCP/IP, the performance is bad if we do 2 writes
     * without a read between them.  This occurs when Session-id reuse is
     * used, so I will put in a buffering module
     */
    if (s->hit) {
        if (!ssl_init_wbio_buffer(s, 1))
            return (-1);
    }

    return (ssl2_do_write(s));
}

static int get_client_finished(SSL *s)
{
    unsigned char *p;
    int i, n;
    unsigned long len;

    p = (unsigned char *)s->init_buf->data;
    if (s->state == SSL2_ST_GET_CLIENT_FINISHED_A) {
        i = ssl2_read(s, (char *)&(p[s->init_num]), 1 - s->init_num);
        if (i < 1 - s->init_num)
            return (ssl2_part_read(s, SSL_F_GET_CLIENT_FINISHED, i));
        s->init_num += i;

        if (*p != SSL2_MT_CLIENT_FINISHED) {
            if (*p != SSL2_MT_ERROR) {
                ssl2_return_error(s, SSL2_PE_UNDEFINED_ERROR);
                SSLerr(SSL_F_GET_CLIENT_FINISHED,
                       SSL_R_READ_WRONG_PACKET_TYPE);
            } else {
                SSLerr(SSL_F_GET_CLIENT_FINISHED, SSL_R_PEER_ERROR);
                /* try to read the error message */
                i = ssl2_read(s, (char *)&(p[s->init_num]), 3 - s->init_num);
                return ssl2_part_read(s, SSL_F_GET_SERVER_VERIFY, i);
            }
            return (-1);
        }
        s->state = SSL2_ST_GET_CLIENT_FINISHED_B;
    }

    /* SSL2_ST_GET_CLIENT_FINISHED_B */
    if (s->s2->conn_id_length > sizeof(s->s2->conn_id)) {
        ssl2_return_error(s, SSL2_PE_UNDEFINED_ERROR);
        SSLerr(SSL_F_GET_CLIENT_FINISHED, ERR_R_INTERNAL_ERROR);
        return -1;
    }
    len = 1 + (unsigned long)s->s2->conn_id_length;
    n = (int)len - s->init_num;
    i = ssl2_read(s, (char *)&(p[s->init_num]), n);
    if (i < n) {
        return (ssl2_part_read(s, SSL_F_GET_CLIENT_FINISHED, i));
    }
    if (s->msg_callback) {
        /* CLIENT-FINISHED */
        s->msg_callback(0, s->version, 0, p, len, s, s->msg_callback_arg);
    }
    p += 1;
    if (memcmp(p, s->s2->conn_id, s->s2->conn_id_length) != 0) {
        ssl2_return_error(s, SSL2_PE_UNDEFINED_ERROR);
        SSLerr(SSL_F_GET_CLIENT_FINISHED, SSL_R_CONNECTION_ID_IS_DIFFERENT);
        return (-1);
    }
    return (1);
}

static int server_verify(SSL *s)
{
    unsigned char *p;

    if (s->state == SSL2_ST_SEND_SERVER_VERIFY_A) {
        p = (unsigned char *)s->init_buf->data;
        *(p++) = SSL2_MT_SERVER_VERIFY;
        if (s->s2->challenge_length > sizeof(s->s2->challenge)) {
            SSLerr(SSL_F_SERVER_VERIFY, ERR_R_INTERNAL_ERROR);
            return -1;
        }
        memcpy(p, s->s2->challenge, (unsigned int)s->s2->challenge_length);
        /* p+=s->s2->challenge_length; */

        s->state = SSL2_ST_SEND_SERVER_VERIFY_B;
        s->init_num = s->s2->challenge_length + 1;
        s->init_off = 0;
    }
    return (ssl2_do_write(s));
}

static int server_finish(SSL *s)
{
    unsigned char *p;

    if (s->state == SSL2_ST_SEND_SERVER_FINISHED_A) {
        p = (unsigned char *)s->init_buf->data;
        *(p++) = SSL2_MT_SERVER_FINISHED;

        if (s->session->session_id_length > sizeof(s->session->session_id)) {
            SSLerr(SSL_F_SERVER_FINISH, ERR_R_INTERNAL_ERROR);
            return -1;
        }
        memcpy(p, s->session->session_id,
               (unsigned int)s->session->session_id_length);
        /* p+=s->session->session_id_length; */

        s->state = SSL2_ST_SEND_SERVER_FINISHED_B;
        s->init_num = s->session->session_id_length + 1;
        s->init_off = 0;
    }

    /* SSL2_ST_SEND_SERVER_FINISHED_B */
    return (ssl2_do_write(s));
}

/* send the request and check the response */
static int request_certificate(SSL *s)
{
    const unsigned char *cp;
    unsigned char *p, *p2, *buf2;
    unsigned char *ccd;
    int i, j, ctype, ret = -1;
    unsigned long len;
    X509 *x509 = NULL;
    STACK_OF(X509) *sk = NULL;

    ccd = s->s2->tmp.ccl;
    if (s->state == SSL2_ST_SEND_REQUEST_CERTIFICATE_A) {
        p = (unsigned char *)s->init_buf->data;
        *(p++) = SSL2_MT_REQUEST_CERTIFICATE;
        *(p++) = SSL2_AT_MD5_WITH_RSA_ENCRYPTION;
        if (RAND_bytes(ccd, SSL2_MIN_CERT_CHALLENGE_LENGTH) <= 0)
            return -1;
        memcpy(p, ccd, SSL2_MIN_CERT_CHALLENGE_LENGTH);

        s->state = SSL2_ST_SEND_REQUEST_CERTIFICATE_B;
        s->init_num = SSL2_MIN_CERT_CHALLENGE_LENGTH + 2;
        s->init_off = 0;
    }

    if (s->state == SSL2_ST_SEND_REQUEST_CERTIFICATE_B) {
        i = ssl2_do_write(s);
        if (i <= 0) {
            ret = i;
            goto end;
        }

        s->init_num = 0;
        s->state = SSL2_ST_SEND_REQUEST_CERTIFICATE_C;
    }

    if (s->state == SSL2_ST_SEND_REQUEST_CERTIFICATE_C) {
        p = (unsigned char *)s->init_buf->data;
        /* try to read 6 octets ... */
        i = ssl2_read(s, (char *)&(p[s->init_num]), 6 - s->init_num);
        /*
         * ... but don't call ssl2_part_read now if we got at least 3
         * (probably NO-CERTIFICATE-ERROR)
         */
        if (i < 3 - s->init_num) {
            ret = ssl2_part_read(s, SSL_F_REQUEST_CERTIFICATE, i);
            goto end;
        }
        s->init_num += i;

        if ((s->init_num >= 3) && (p[0] == SSL2_MT_ERROR)) {
            n2s(p, i);
            if (i != SSL2_PE_NO_CERTIFICATE) {
                /*
                 * not the error message we expected -- let ssl2_part_read
                 * handle it
                 */
                s->init_num -= 3;
                ret = ssl2_part_read(s, SSL_F_REQUEST_CERTIFICATE, 3);
                goto end;
            }

            if (s->msg_callback) {
                /* ERROR */
                s->msg_callback(0, s->version, 0, p, 3, s,
                                s->msg_callback_arg);
            }

            /*
             * this is the one place where we can recover from an SSL 2.0
             * error
             */

            if (s->verify_mode & SSL_VERIFY_FAIL_IF_NO_PEER_CERT) {
                ssl2_return_error(s, SSL2_PE_BAD_CERTIFICATE);
                SSLerr(SSL_F_REQUEST_CERTIFICATE,
                       SSL_R_PEER_DID_NOT_RETURN_A_CERTIFICATE);
                goto end;
            }
            ret = 1;
            goto end;
        }
        if ((*(p++) != SSL2_MT_CLIENT_CERTIFICATE) || (s->init_num < 6)) {
            ssl2_return_error(s, SSL2_PE_UNDEFINED_ERROR);
            SSLerr(SSL_F_REQUEST_CERTIFICATE, SSL_R_SHORT_READ);
            goto end;
        }
        if (s->init_num != 6) {
            SSLerr(SSL_F_REQUEST_CERTIFICATE, ERR_R_INTERNAL_ERROR);
            goto end;
        }

        /* ok we have a response */
        /* certificate type, there is only one right now. */
        ctype = *(p++);
        if (ctype != SSL2_AT_MD5_WITH_RSA_ENCRYPTION) {
            ssl2_return_error(s, SSL2_PE_UNSUPPORTED_CERTIFICATE_TYPE);
            SSLerr(SSL_F_REQUEST_CERTIFICATE, SSL_R_BAD_RESPONSE_ARGUMENT);
            goto end;
        }
        n2s(p, i);
        s->s2->tmp.clen = i;
        n2s(p, i);
        s->s2->tmp.rlen = i;
        s->state = SSL2_ST_SEND_REQUEST_CERTIFICATE_D;
    }

    /* SSL2_ST_SEND_REQUEST_CERTIFICATE_D */
    p = (unsigned char *)s->init_buf->data;
    len = 6 + (unsigned long)s->s2->tmp.clen + (unsigned long)s->s2->tmp.rlen;
    if (len > SSL2_MAX_RECORD_LENGTH_3_BYTE_HEADER) {
        SSLerr(SSL_F_REQUEST_CERTIFICATE, SSL_R_MESSAGE_TOO_LONG);
        goto end;
    }
    j = (int)len - s->init_num;
    i = ssl2_read(s, (char *)&(p[s->init_num]), j);
    if (i < j) {
        ret = ssl2_part_read(s, SSL_F_REQUEST_CERTIFICATE, i);
        goto end;
    }
    if (s->msg_callback) {
        /* CLIENT-CERTIFICATE */
        s->msg_callback(0, s->version, 0, p, len, s, s->msg_callback_arg);
    }
    p += 6;

    cp = p;
    x509 = (X509 *)d2i_X509(NULL, &cp, (long)s->s2->tmp.clen);
    if (x509 == NULL) {
        SSLerr(SSL_F_REQUEST_CERTIFICATE, ERR_R_X509_LIB);
        goto msg_end;
    }

    if (((sk = sk_X509_new_null()) == NULL) || (!sk_X509_push(sk, x509))) {
        SSLerr(SSL_F_REQUEST_CERTIFICATE, ERR_R_MALLOC_FAILURE);
        goto msg_end;
    }

    i = ssl_verify_cert_chain(s, sk);

    if (i > 0) {                /* we like the packet, now check the chksum */
        EVP_MD_CTX ctx;
        EVP_PKEY *pkey = NULL;

        EVP_MD_CTX_init(&ctx);
        if (!EVP_VerifyInit_ex(&ctx, s->ctx->rsa_md5, NULL)
            || !EVP_VerifyUpdate(&ctx, s->s2->key_material,
                                 s->s2->key_material_length)
            || !EVP_VerifyUpdate(&ctx, ccd, SSL2_MIN_CERT_CHALLENGE_LENGTH))
            goto msg_end;

        i = i2d_X509(s->cert->pkeys[SSL_PKEY_RSA_ENC].x509, NULL);
        buf2 = OPENSSL_malloc((unsigned int)i);
        if (buf2 == NULL) {
            SSLerr(SSL_F_REQUEST_CERTIFICATE, ERR_R_MALLOC_FAILURE);
            goto msg_end;
        }
        p2 = buf2;
        i = i2d_X509(s->cert->pkeys[SSL_PKEY_RSA_ENC].x509, &p2);
        if (!EVP_VerifyUpdate(&ctx, buf2, (unsigned int)i)) {
            OPENSSL_free(buf2);
            goto msg_end;
        }
        OPENSSL_free(buf2);

        pkey = X509_get_pubkey(x509);
        if (pkey == NULL)
            goto end;
        i = EVP_VerifyFinal(&ctx, cp, s->s2->tmp.rlen, pkey);
        EVP_PKEY_free(pkey);
        EVP_MD_CTX_cleanup(&ctx);

        if (i > 0) {
            if (s->session->peer != NULL)
                X509_free(s->session->peer);
            s->session->peer = x509;
            CRYPTO_add(&x509->references, 1, CRYPTO_LOCK_X509);
            s->session->verify_result = s->verify_result;
            ret = 1;
            goto end;
        } else {
            SSLerr(SSL_F_REQUEST_CERTIFICATE, SSL_R_BAD_CHECKSUM);
            goto msg_end;
        }
    } else {
 msg_end:
        ssl2_return_error(s, SSL2_PE_BAD_CERTIFICATE);
    }
 end:
    sk_X509_free(sk);
    X509_free(x509);
    return (ret);
}

static int ssl_rsa_private_decrypt(CERT *c, int len, unsigned char *from,
                                   unsigned char *to, int padding)
{
    RSA *rsa;
    int i;

    if ((c == NULL) || (c->pkeys[SSL_PKEY_RSA_ENC].privatekey == NULL)) {
        SSLerr(SSL_F_SSL_RSA_PRIVATE_DECRYPT, SSL_R_NO_PRIVATEKEY);
        return (-1);
    }
    if (c->pkeys[SSL_PKEY_RSA_ENC].privatekey->type != EVP_PKEY_RSA) {
        SSLerr(SSL_F_SSL_RSA_PRIVATE_DECRYPT, SSL_R_PUBLIC_KEY_IS_NOT_RSA);
        return (-1);
    }
    rsa = c->pkeys[SSL_PKEY_RSA_ENC].privatekey->pkey.rsa;

    /* we have the public key */
    i = RSA_private_decrypt(len, from, to, rsa, padding);
    if (i < 0)
        SSLerr(SSL_F_SSL_RSA_PRIVATE_DECRYPT, ERR_R_RSA_LIB);
    return (i);
}
#else                           /* !OPENSSL_NO_SSL2 */

# if PEDANTIC
static void *dummy = &dummy;
# endif

#endif
