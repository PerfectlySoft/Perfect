/* ssl/s3_both.c */
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
/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 * ECC cipher suite support in OpenSSL originally developed by
 * SUN MICROSYSTEMS, INC., and contributed to the OpenSSL project.
 */

#include <limits.h>
#include <string.h>
#include <stdio.h>
#include "ssl_locl.h"
#include "buffer.h"
#include "rand.h"
#include "objects.h"
#include "evp.h"
#include "x509.h"

/*
 * send s->init_buf in records of type 'type' (SSL3_RT_HANDSHAKE or
 * SSL3_RT_CHANGE_CIPHER_SPEC)
 */
int ssl3_do_write(SSL *s, int type)
{
    int ret;

    ret = ssl3_write_bytes(s, type, &s->init_buf->data[s->init_off],
                           s->init_num);
    if (ret < 0)
        return (-1);
    if (type == SSL3_RT_HANDSHAKE)
        /*
         * should not be done for 'Hello Request's, but in that case we'll
         * ignore the result anyway
         */
        ssl3_finish_mac(s, (unsigned char *)&s->init_buf->data[s->init_off],
                        ret);

    if (ret == s->init_num) {
        if (s->msg_callback)
            s->msg_callback(1, s->version, type, s->init_buf->data,
                            (size_t)(s->init_off + s->init_num), s,
                            s->msg_callback_arg);
        return (1);
    }
    s->init_off += ret;
    s->init_num -= ret;
    return (0);
}

int ssl3_send_finished(SSL *s, int a, int b, const char *sender, int slen)
{
    unsigned char *p;
    int i;
    unsigned long l;

    if (s->state == a) {
        p = ssl_handshake_start(s);

        i = s->method->ssl3_enc->final_finish_mac(s,
                                                  sender, slen,
                                                  s->s3->tmp.finish_md);
        if (i <= 0)
            return 0;
        s->s3->tmp.finish_md_len = i;
        memcpy(p, s->s3->tmp.finish_md, i);
        l = i;

        /*
         * Copy the finished so we can use it for renegotiation checks
         */
        if (s->type == SSL_ST_CONNECT) {
            OPENSSL_assert(i <= EVP_MAX_MD_SIZE);
            memcpy(s->s3->previous_client_finished, s->s3->tmp.finish_md, i);
            s->s3->previous_client_finished_len = i;
        } else {
            OPENSSL_assert(i <= EVP_MAX_MD_SIZE);
            memcpy(s->s3->previous_server_finished, s->s3->tmp.finish_md, i);
            s->s3->previous_server_finished_len = i;
        }

#ifdef OPENSSL_SYS_WIN16
        /*
         * MSVC 1.5 does not clear the top bytes of the word unless I do
         * this.
         */
        l &= 0xffff;
#endif
        ssl_set_handshake_header(s, SSL3_MT_FINISHED, l);
        s->state = b;
    }

    /* SSL3_ST_SEND_xxxxxx_HELLO_B */
    return ssl_do_write(s);
}

#ifndef OPENSSL_NO_NEXTPROTONEG
/*
 * ssl3_take_mac calculates the Finished MAC for the handshakes messages seen
 * to far.
 */
static void ssl3_take_mac(SSL *s)
{
    const char *sender;
    int slen;
    /*
     * If no new cipher setup return immediately: other functions will set
     * the appropriate error.
     */
    if (s->s3->tmp.new_cipher == NULL)
        return;
    if (s->state & SSL_ST_CONNECT) {
        sender = s->method->ssl3_enc->server_finished_label;
        slen = s->method->ssl3_enc->server_finished_label_len;
    } else {
        sender = s->method->ssl3_enc->client_finished_label;
        slen = s->method->ssl3_enc->client_finished_label_len;
    }

    s->s3->tmp.peer_finish_md_len = s->method->ssl3_enc->final_finish_mac(s,
                                                                          sender,
                                                                          slen,
                                                                          s->s3->tmp.peer_finish_md);
}
#endif

int ssl3_get_finished(SSL *s, int a, int b)
{
    int al, i, ok;
    long n;
    unsigned char *p;

#ifdef OPENSSL_NO_NEXTPROTONEG
    /*
     * the mac has already been generated when we received the change cipher
     * spec message and is in s->s3->tmp.peer_finish_md
     */
#endif

    /* 64 argument should actually be 36+4 :-) */
    n = s->method->ssl_get_message(s, a, b, SSL3_MT_FINISHED, 64, &ok);

    if (!ok)
        return ((int)n);

    /* If this occurs, we have missed a message */
    if (!s->s3->change_cipher_spec) {
        al = SSL_AD_UNEXPECTED_MESSAGE;
        SSLerr(SSL_F_SSL3_GET_FINISHED, SSL_R_GOT_A_FIN_BEFORE_A_CCS);
        goto f_err;
    }
    s->s3->change_cipher_spec = 0;

    p = (unsigned char *)s->init_msg;
    i = s->s3->tmp.peer_finish_md_len;

    if (i != n) {
        al = SSL_AD_DECODE_ERROR;
        SSLerr(SSL_F_SSL3_GET_FINISHED, SSL_R_BAD_DIGEST_LENGTH);
        goto f_err;
    }

    if (CRYPTO_memcmp(p, s->s3->tmp.peer_finish_md, i) != 0) {
        al = SSL_AD_DECRYPT_ERROR;
        SSLerr(SSL_F_SSL3_GET_FINISHED, SSL_R_DIGEST_CHECK_FAILED);
        goto f_err;
    }

    /*
     * Copy the finished so we can use it for renegotiation checks
     */
    if (s->type == SSL_ST_ACCEPT) {
        OPENSSL_assert(i <= EVP_MAX_MD_SIZE);
        memcpy(s->s3->previous_client_finished, s->s3->tmp.peer_finish_md, i);
        s->s3->previous_client_finished_len = i;
    } else {
        OPENSSL_assert(i <= EVP_MAX_MD_SIZE);
        memcpy(s->s3->previous_server_finished, s->s3->tmp.peer_finish_md, i);
        s->s3->previous_server_finished_len = i;
    }

    return (1);
 f_err:
    ssl3_send_alert(s, SSL3_AL_FATAL, al);
    return (0);
}

/*-
 * for these 2 messages, we need to
 * ssl->enc_read_ctx                    re-init
 * ssl->s3->read_sequence               zero
 * ssl->s3->read_mac_secret             re-init
 * ssl->session->read_sym_enc           assign
 * ssl->session->read_compression       assign
 * ssl->session->read_hash              assign
 */
int ssl3_send_change_cipher_spec(SSL *s, int a, int b)
{
    unsigned char *p;

    if (s->state == a) {
        p = (unsigned char *)s->init_buf->data;
        *p = SSL3_MT_CCS;
        s->init_num = 1;
        s->init_off = 0;

        s->state = b;
    }

    /* SSL3_ST_CW_CHANGE_B */
    return (ssl3_do_write(s, SSL3_RT_CHANGE_CIPHER_SPEC));
}

unsigned long ssl3_output_cert_chain(SSL *s, CERT_PKEY *cpk)
{
    unsigned char *p;
    unsigned long l = 3 + SSL_HM_HEADER_LENGTH(s);

    if (!ssl_add_cert_chain(s, cpk, &l))
        return 0;

    l -= 3 + SSL_HM_HEADER_LENGTH(s);
    p = ssl_handshake_start(s);
    l2n3(l, p);
    l += 3;
    ssl_set_handshake_header(s, SSL3_MT_CERTIFICATE, l);
    return l + SSL_HM_HEADER_LENGTH(s);
}

/*
 * Obtain handshake message of message type 'mt' (any if mt == -1), maximum
 * acceptable body length 'max'. The first four bytes (msg_type and length)
 * are read in state 'st1', the body is read in state 'stn'.
 */
long ssl3_get_message(SSL *s, int st1, int stn, int mt, long max, int *ok)
{
    unsigned char *p;
    unsigned long l;
    long n;
    int i, al;

    if (s->s3->tmp.reuse_message) {
        s->s3->tmp.reuse_message = 0;
        if ((mt >= 0) && (s->s3->tmp.message_type != mt)) {
            al = SSL_AD_UNEXPECTED_MESSAGE;
            SSLerr(SSL_F_SSL3_GET_MESSAGE, SSL_R_UNEXPECTED_MESSAGE);
            goto f_err;
        }
        *ok = 1;
        s->state = stn;
        s->init_msg = s->init_buf->data + SSL3_HM_HEADER_LENGTH;
        s->init_num = (int)s->s3->tmp.message_size;
        return s->init_num;
    }

    p = (unsigned char *)s->init_buf->data;

    if (s->state == st1) {      /* s->init_num < SSL3_HM_HEADER_LENGTH */
        int skip_message;

        do {
            while (s->init_num < SSL3_HM_HEADER_LENGTH) {
                i = s->method->ssl_read_bytes(s, SSL3_RT_HANDSHAKE,
                                              &p[s->init_num],
                                              SSL3_HM_HEADER_LENGTH -
                                              s->init_num, 0);
                if (i <= 0) {
                    s->rwstate = SSL_READING;
                    *ok = 0;
                    return i;
                }
                s->init_num += i;
            }

            skip_message = 0;
            if (!s->server)
                if (p[0] == SSL3_MT_HELLO_REQUEST)
                    /*
                     * The server may always send 'Hello Request' messages --
                     * we are doing a handshake anyway now, so ignore them if
                     * their format is correct. Does not count for 'Finished'
                     * MAC.
                     */
                    if (p[1] == 0 && p[2] == 0 && p[3] == 0) {
                        s->init_num = 0;
                        skip_message = 1;

                        if (s->msg_callback)
                            s->msg_callback(0, s->version, SSL3_RT_HANDSHAKE,
                                            p, SSL3_HM_HEADER_LENGTH, s,
                                            s->msg_callback_arg);
                    }
        }
        while (skip_message);

        /* s->init_num == SSL3_HM_HEADER_LENGTH */

        if ((mt >= 0) && (*p != mt)) {
            al = SSL_AD_UNEXPECTED_MESSAGE;
            SSLerr(SSL_F_SSL3_GET_MESSAGE, SSL_R_UNEXPECTED_MESSAGE);
            goto f_err;
        }

        s->s3->tmp.message_type = *(p++);

        n2l3(p, l);
        if (l > (unsigned long)max) {
            al = SSL_AD_ILLEGAL_PARAMETER;
            SSLerr(SSL_F_SSL3_GET_MESSAGE, SSL_R_EXCESSIVE_MESSAGE_SIZE);
            goto f_err;
        }
        /*
         * Make buffer slightly larger than message length as a precaution
         * against small OOB reads e.g. CVE-2016-6306
         */
        if (l
            && !BUF_MEM_grow_clean(s->init_buf,
                                   (int)l + SSL3_HM_HEADER_LENGTH + 16)) {
            SSLerr(SSL_F_SSL3_GET_MESSAGE, ERR_R_BUF_LIB);
            goto err;
        }
        s->s3->tmp.message_size = l;
        s->state = stn;

        s->init_msg = s->init_buf->data + SSL3_HM_HEADER_LENGTH;
        s->init_num = 0;
    }

    /* next state (stn) */
    p = s->init_msg;
    n = s->s3->tmp.message_size - s->init_num;
    while (n > 0) {
        i = s->method->ssl_read_bytes(s, SSL3_RT_HANDSHAKE, &p[s->init_num],
                                      n, 0);
        if (i <= 0) {
            s->rwstate = SSL_READING;
            *ok = 0;
            return i;
        }
        s->init_num += i;
        n -= i;
    }

#ifndef OPENSSL_NO_NEXTPROTONEG
    /*
     * If receiving Finished, record MAC of prior handshake messages for
     * Finished verification.
     */
    if (*s->init_buf->data == SSL3_MT_FINISHED)
        ssl3_take_mac(s);
#endif

    /* Feed this message into MAC computation. */
    ssl3_finish_mac(s, (unsigned char *)s->init_buf->data,
                    s->init_num + SSL3_HM_HEADER_LENGTH);
    if (s->msg_callback)
        s->msg_callback(0, s->version, SSL3_RT_HANDSHAKE, s->init_buf->data,
                        (size_t)s->init_num + SSL3_HM_HEADER_LENGTH, s,
                        s->msg_callback_arg);
    *ok = 1;
    return s->init_num;
 f_err:
    ssl3_send_alert(s, SSL3_AL_FATAL, al);
 err:
    *ok = 0;
    return (-1);
}

int ssl_cert_type(X509 *x, EVP_PKEY *pkey)
{
    EVP_PKEY *pk;
    int ret = -1, i;

    if (pkey == NULL)
        pk = X509_get_pubkey(x);
    else
        pk = pkey;
    if (pk == NULL)
        goto err;

    i = pk->type;
    if (i == EVP_PKEY_RSA) {
        ret = SSL_PKEY_RSA_ENC;
    } else if (i == EVP_PKEY_DSA) {
        ret = SSL_PKEY_DSA_SIGN;
    }
#ifndef OPENSSL_NO_EC
    else if (i == EVP_PKEY_EC) {
        ret = SSL_PKEY_ECC;
    }
#endif
    else if (i == NID_id_GostR3410_94 || i == NID_id_GostR3410_94_cc) {
        ret = SSL_PKEY_GOST94;
    } else if (i == NID_id_GostR3410_2001 || i == NID_id_GostR3410_2001_cc) {
        ret = SSL_PKEY_GOST01;
    } else if (x && (i == EVP_PKEY_DH || i == EVP_PKEY_DHX)) {
        /*
         * For DH two cases: DH certificate signed with RSA and DH
         * certificate signed with DSA.
         */
        i = X509_certificate_type(x, pk);
        if (i & EVP_PKS_RSA)
            ret = SSL_PKEY_DH_RSA;
        else if (i & EVP_PKS_DSA)
            ret = SSL_PKEY_DH_DSA;
    }

 err:
    if (!pkey)
        EVP_PKEY_free(pk);
    return (ret);
}

int ssl_verify_alarm_type(long type)
{
    int al;

    switch (type) {
    case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
    case X509_V_ERR_UNABLE_TO_GET_CRL:
    case X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER:
        al = SSL_AD_UNKNOWN_CA;
        break;
    case X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE:
    case X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE:
    case X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY:
    case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
    case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
    case X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD:
    case X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD:
    case X509_V_ERR_CERT_NOT_YET_VALID:
    case X509_V_ERR_CRL_NOT_YET_VALID:
    case X509_V_ERR_CERT_UNTRUSTED:
    case X509_V_ERR_CERT_REJECTED:
    case X509_V_ERR_HOSTNAME_MISMATCH:
    case X509_V_ERR_EMAIL_MISMATCH:
    case X509_V_ERR_IP_ADDRESS_MISMATCH:
        al = SSL_AD_BAD_CERTIFICATE;
        break;
    case X509_V_ERR_CERT_SIGNATURE_FAILURE:
    case X509_V_ERR_CRL_SIGNATURE_FAILURE:
        al = SSL_AD_DECRYPT_ERROR;
        break;
    case X509_V_ERR_CERT_HAS_EXPIRED:
    case X509_V_ERR_CRL_HAS_EXPIRED:
        al = SSL_AD_CERTIFICATE_EXPIRED;
        break;
    case X509_V_ERR_CERT_REVOKED:
        al = SSL_AD_CERTIFICATE_REVOKED;
        break;
    case X509_V_ERR_UNSPECIFIED:
    case X509_V_ERR_OUT_OF_MEM:
    case X509_V_ERR_INVALID_CALL:
    case X509_V_ERR_STORE_LOOKUP:
        al = SSL_AD_INTERNAL_ERROR;
        break;
    case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
    case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
    case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
    case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
    case X509_V_ERR_CERT_CHAIN_TOO_LONG:
    case X509_V_ERR_PATH_LENGTH_EXCEEDED:
    case X509_V_ERR_INVALID_CA:
        al = SSL_AD_UNKNOWN_CA;
        break;
    case X509_V_ERR_APPLICATION_VERIFICATION:
        al = SSL_AD_HANDSHAKE_FAILURE;
        break;
    case X509_V_ERR_INVALID_PURPOSE:
        al = SSL_AD_UNSUPPORTED_CERTIFICATE;
        break;
    default:
        al = SSL_AD_CERTIFICATE_UNKNOWN;
        break;
    }
    return (al);
}

#ifndef OPENSSL_NO_BUF_FREELISTS
/*-
 * On some platforms, malloc() performance is bad enough that you can't just
 * free() and malloc() buffers all the time, so we need to use freelists from
 * unused buffers.  Currently, each freelist holds memory chunks of only a
 * given size (list->chunklen); other sized chunks are freed and malloced.
 * This doesn't help much if you're using many different SSL option settings
 * with a given context.  (The options affecting buffer size are
 * max_send_fragment, read buffer vs write buffer,
 * SSL_OP_MICROSOFT_BIG_WRITE_BUFFER, SSL_OP_NO_COMPRESSION, and
 * SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS.)  Using a separate freelist for every
 * possible size is not an option, since max_send_fragment can take on many
 * different values.
 *
 * If you are on a platform with a slow malloc(), and you're using SSL
 * connections with many different settings for these options, and you need to
 * use the SSL_MOD_RELEASE_BUFFERS feature, you have a few options:
 *    - Link against a faster malloc implementation.
 *    - Use a separate SSL_CTX for each option set.
 *    - Improve this code.
 */
static void *freelist_extract(SSL_CTX *ctx, int for_read, int sz)
{
    SSL3_BUF_FREELIST *list;
    SSL3_BUF_FREELIST_ENTRY *ent = NULL;
    void *result = NULL;

    CRYPTO_w_lock(CRYPTO_LOCK_SSL_CTX);
    list = for_read ? ctx->rbuf_freelist : ctx->wbuf_freelist;
    if (list != NULL && sz == (int)list->chunklen)
        ent = list->head;
    if (ent != NULL) {
        list->head = ent->next;
        result = ent;
        if (--list->len == 0)
            list->chunklen = 0;
    }
    CRYPTO_w_unlock(CRYPTO_LOCK_SSL_CTX);
    if (!result)
        result = OPENSSL_malloc(sz);
    return result;
}

static void freelist_insert(SSL_CTX *ctx, int for_read, size_t sz, void *mem)
{
    SSL3_BUF_FREELIST *list;
    SSL3_BUF_FREELIST_ENTRY *ent;

    CRYPTO_w_lock(CRYPTO_LOCK_SSL_CTX);
    list = for_read ? ctx->rbuf_freelist : ctx->wbuf_freelist;
    if (list != NULL &&
        (sz == list->chunklen || list->chunklen == 0) &&
        list->len < ctx->freelist_max_len && sz >= sizeof(*ent)) {
        list->chunklen = sz;
        ent = mem;
        ent->next = list->head;
        list->head = ent;
        ++list->len;
        mem = NULL;
    }

    CRYPTO_w_unlock(CRYPTO_LOCK_SSL_CTX);
    if (mem)
        OPENSSL_free(mem);
}
#else
# define freelist_extract(c,fr,sz) OPENSSL_malloc(sz)
# define freelist_insert(c,fr,sz,m) OPENSSL_free(m)
#endif

int ssl3_setup_read_buffer(SSL *s)
{
    unsigned char *p;
    size_t len, align = 0, headerlen;

    if (SSL_IS_DTLS(s))
        headerlen = DTLS1_RT_HEADER_LENGTH;
    else
        headerlen = SSL3_RT_HEADER_LENGTH;

#if defined(SSL3_ALIGN_PAYLOAD) && SSL3_ALIGN_PAYLOAD!=0
    align = (-SSL3_RT_HEADER_LENGTH) & (SSL3_ALIGN_PAYLOAD - 1);
#endif

    if (s->s3->rbuf.buf == NULL) {
        len = SSL3_RT_MAX_PLAIN_LENGTH
            + SSL3_RT_MAX_ENCRYPTED_OVERHEAD + headerlen + align;
        if (s->options & SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER) {
            s->s3->init_extra = 1;
            len += SSL3_RT_MAX_EXTRA;
        }
#ifndef OPENSSL_NO_COMP
        if (!(s->options & SSL_OP_NO_COMPRESSION))
            len += SSL3_RT_MAX_COMPRESSED_OVERHEAD;
#endif
        if ((p = freelist_extract(s->ctx, 1, len)) == NULL)
            goto err;
        s->s3->rbuf.buf = p;
        s->s3->rbuf.len = len;
    }

    s->packet = &(s->s3->rbuf.buf[0]);
    return 1;

 err:
    SSLerr(SSL_F_SSL3_SETUP_READ_BUFFER, ERR_R_MALLOC_FAILURE);
    return 0;
}

int ssl3_setup_write_buffer(SSL *s)
{
    unsigned char *p;
    size_t len, align = 0, headerlen;

    if (SSL_IS_DTLS(s))
        headerlen = DTLS1_RT_HEADER_LENGTH + 1;
    else
        headerlen = SSL3_RT_HEADER_LENGTH;

#if defined(SSL3_ALIGN_PAYLOAD) && SSL3_ALIGN_PAYLOAD!=0
    align = (-SSL3_RT_HEADER_LENGTH) & (SSL3_ALIGN_PAYLOAD - 1);
#endif

    if (s->s3->wbuf.buf == NULL) {
        len = s->max_send_fragment
            + SSL3_RT_SEND_MAX_ENCRYPTED_OVERHEAD + headerlen + align;
#ifndef OPENSSL_NO_COMP
        if (!(s->options & SSL_OP_NO_COMPRESSION))
            len += SSL3_RT_MAX_COMPRESSED_OVERHEAD;
#endif
        if (!(s->options & SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS))
            len += headerlen + align + SSL3_RT_SEND_MAX_ENCRYPTED_OVERHEAD;

        if ((p = freelist_extract(s->ctx, 0, len)) == NULL)
            goto err;
        s->s3->wbuf.buf = p;
        s->s3->wbuf.len = len;
    }

    return 1;

 err:
    SSLerr(SSL_F_SSL3_SETUP_WRITE_BUFFER, ERR_R_MALLOC_FAILURE);
    return 0;
}

int ssl3_setup_buffers(SSL *s)
{
    if (!ssl3_setup_read_buffer(s))
        return 0;
    if (!ssl3_setup_write_buffer(s))
        return 0;
    return 1;
}

int ssl3_release_write_buffer(SSL *s)
{
    if (s->s3->wbuf.buf != NULL) {
        freelist_insert(s->ctx, 0, s->s3->wbuf.len, s->s3->wbuf.buf);
        s->s3->wbuf.buf = NULL;
    }
    return 1;
}

int ssl3_release_read_buffer(SSL *s)
{
    if (s->s3->rbuf.buf != NULL) {
        freelist_insert(s->ctx, 1, s->s3->rbuf.len, s->s3->rbuf.buf);
        s->s3->rbuf.buf = NULL;
    }
    return 1;
}
/* ssl/s3_cbc.c */
/* ====================================================================
 * Copyright (c) 2012 The OpenSSL Project.  All rights reserved.
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

#include "constant_time_locl.h"
// #include "ssl_locl.h"

#include "md5.h"
#include "sha.h"

/*
 * MAX_HASH_BIT_COUNT_BYTES is the maximum number of bytes in the hash's
 * length field. (SHA-384/512 have 128-bit length.)
 */
#define MAX_HASH_BIT_COUNT_BYTES 16

/*
 * MAX_HASH_BLOCK_SIZE is the maximum hash block size that we'll support.
 * Currently SHA-384/512 has a 128-byte block size and that's the largest
 * supported by TLS.)
 */
#define MAX_HASH_BLOCK_SIZE 128

/*-
 * ssl3_cbc_remove_padding removes padding from the decrypted, SSLv3, CBC
 * record in |rec| by updating |rec->length| in constant time.
 *
 * block_size: the block size of the cipher used to encrypt the record.
 * returns:
 *   0: (in non-constant time) if the record is publicly invalid.
 *   1: if the padding was valid
 *  -1: otherwise.
 */
int ssl3_cbc_remove_padding(const SSL *s,
                            SSL3_RECORD *rec,
                            unsigned block_size, unsigned mac_size)
{
    unsigned padding_length, good;
    const unsigned overhead = 1 /* padding length byte */  + mac_size;

    /*
     * These lengths are all public so we can test them in non-constant time.
     */
    if (overhead > rec->length)
        return 0;

    padding_length = rec->data[rec->length - 1];
    good = constant_time_ge(rec->length, padding_length + overhead);
    /* SSLv3 requires that the padding is minimal. */
    good &= constant_time_ge(block_size, padding_length + 1);
    padding_length = good & (padding_length + 1);
    rec->length -= padding_length;
    rec->type |= padding_length << 8; /* kludge: pass padding length */
    return constant_time_select_int(good, 1, -1);
}

/*-
 * tls1_cbc_remove_padding removes the CBC padding from the decrypted, TLS, CBC
 * record in |rec| in constant time and returns 1 if the padding is valid and
 * -1 otherwise. It also removes any explicit IV from the start of the record
 * without leaking any timing about whether there was enough space after the
 * padding was removed.
 *
 * block_size: the block size of the cipher used to encrypt the record.
 * returns:
 *   0: (in non-constant time) if the record is publicly invalid.
 *   1: if the padding was valid
 *  -1: otherwise.
 */
int tls1_cbc_remove_padding(const SSL *s,
                            SSL3_RECORD *rec,
                            unsigned block_size, unsigned mac_size)
{
    unsigned padding_length, good, to_check, i;
    const unsigned overhead = 1 /* padding length byte */  + mac_size;
    /* Check if version requires explicit IV */
    if (SSL_USE_EXPLICIT_IV(s)) {
        /*
         * These lengths are all public so we can test them in non-constant
         * time.
         */
        if (overhead + block_size > rec->length)
            return 0;
        /* We can now safely skip explicit IV */
        rec->data += block_size;
        rec->input += block_size;
        rec->length -= block_size;
    } else if (overhead > rec->length)
        return 0;

    padding_length = rec->data[rec->length - 1];

    /*
     * NB: if compression is in operation the first packet may not be of even
     * length so the padding bug check cannot be performed. This bug
     * workaround has been around since SSLeay so hopefully it is either
     * fixed now or no buggy implementation supports compression [steve]
     */
    if ((s->options & SSL_OP_TLS_BLOCK_PADDING_BUG) && !s->expand) {
        /* First packet is even in size, so check */
        if ((CRYPTO_memcmp(s->s3->read_sequence, "\0\0\0\0\0\0\0\0", 8) == 0) &&
            !(padding_length & 1)) {
            s->s3->flags |= TLS1_FLAGS_TLS_PADDING_BUG;
        }
        if ((s->s3->flags & TLS1_FLAGS_TLS_PADDING_BUG) && padding_length > 0) {
            padding_length--;
        }
    }

    if (EVP_CIPHER_flags(s->enc_read_ctx->cipher) & EVP_CIPH_FLAG_AEAD_CIPHER) {
        /* padding is already verified */
        rec->length -= padding_length + 1;
        return 1;
    }

    good = constant_time_ge(rec->length, overhead + padding_length);
    /*
     * The padding consists of a length byte at the end of the record and
     * then that many bytes of padding, all with the same value as the length
     * byte. Thus, with the length byte included, there are i+1 bytes of
     * padding. We can't check just |padding_length+1| bytes because that
     * leaks decrypted information. Therefore we always have to check the
     * maximum amount of padding possible. (Again, the length of the record
     * is public information so we can use it.)
     */
    to_check = 255;             /* maximum amount of padding. */
    if (to_check > rec->length - 1)
        to_check = rec->length - 1;

    for (i = 0; i < to_check; i++) {
        unsigned char mask = constant_time_ge_8(padding_length, i);
        unsigned char b = rec->data[rec->length - 1 - i];
        /*
         * The final |padding_length+1| bytes should all have the value
         * |padding_length|. Therefore the XOR should be zero.
         */
        good &= ~(mask & (padding_length ^ b));
    }

    /*
     * If any of the final |padding_length+1| bytes had the wrong value, one
     * or more of the lower eight bits of |good| will be cleared.
     */
    good = constant_time_eq(0xff, good & 0xff);
    padding_length = good & (padding_length + 1);
    rec->length -= padding_length;
    rec->type |= padding_length << 8; /* kludge: pass padding length */

    return constant_time_select_int(good, 1, -1);
}

/*-
 * ssl3_cbc_copy_mac copies |md_size| bytes from the end of |rec| to |out| in
 * constant time (independent of the concrete value of rec->length, which may
 * vary within a 256-byte window).
 *
 * ssl3_cbc_remove_padding or tls1_cbc_remove_padding must be called prior to
 * this function.
 *
 * On entry:
 *   rec->orig_len >= md_size
 *   md_size <= EVP_MAX_MD_SIZE
 *
 * If CBC_MAC_ROTATE_IN_PLACE is defined then the rotation is performed with
 * variable accesses in a 64-byte-aligned buffer. Assuming that this fits into
 * a single or pair of cache-lines, then the variable memory accesses don't
 * actually affect the timing. CPUs with smaller cache-lines [if any] are
 * not multi-core and are not considered vulnerable to cache-timing attacks.
 */
#define CBC_MAC_ROTATE_IN_PLACE

void ssl3_cbc_copy_mac(unsigned char *out,
                       const SSL3_RECORD *rec,
                       unsigned md_size, unsigned orig_len)
{
#if defined(CBC_MAC_ROTATE_IN_PLACE)
    unsigned char rotated_mac_buf[64 + EVP_MAX_MD_SIZE];
    unsigned char *rotated_mac;
#else
    unsigned char rotated_mac[EVP_MAX_MD_SIZE];
#endif

    /*
     * mac_end is the index of |rec->data| just after the end of the MAC.
     */
    unsigned mac_end = rec->length;
    unsigned mac_start = mac_end - md_size;
    /*
     * scan_start contains the number of bytes that we can ignore because the
     * MAC's position can only vary by 255 bytes.
     */
    unsigned scan_start = 0;
    unsigned i, j;
    unsigned div_spoiler;
    unsigned rotate_offset;

    OPENSSL_assert(orig_len >= md_size);
    OPENSSL_assert(md_size <= EVP_MAX_MD_SIZE);

#if defined(CBC_MAC_ROTATE_IN_PLACE)
    rotated_mac = rotated_mac_buf + ((0 - (size_t)rotated_mac_buf) & 63);
#endif

    /* This information is public so it's safe to branch based on it. */
    if (orig_len > md_size + 255 + 1)
        scan_start = orig_len - (md_size + 255 + 1);
    /*
     * div_spoiler contains a multiple of md_size that is used to cause the
     * modulo operation to be constant time. Without this, the time varies
     * based on the amount of padding when running on Intel chips at least.
     * The aim of right-shifting md_size is so that the compiler doesn't
     * figure out that it can remove div_spoiler as that would require it to
     * prove that md_size is always even, which I hope is beyond it.
     */
    div_spoiler = md_size >> 1;
    div_spoiler <<= (sizeof(div_spoiler) - 1) * 8;
    rotate_offset = (div_spoiler + mac_start - scan_start) % md_size;

    memset(rotated_mac, 0, md_size);
    for (i = scan_start, j = 0; i < orig_len; i++) {
        unsigned char mac_started = constant_time_ge_8(i, mac_start);
        unsigned char mac_ended = constant_time_ge_8(i, mac_end);
        unsigned char b = rec->data[i];
        rotated_mac[j++] |= b & mac_started & ~mac_ended;
        j &= constant_time_lt(j, md_size);
    }

    /* Now rotate the MAC */
#if defined(CBC_MAC_ROTATE_IN_PLACE)
    j = 0;
    for (i = 0; i < md_size; i++) {
        /* in case cache-line is 32 bytes, touch second line */
        ((volatile unsigned char *)rotated_mac)[rotate_offset ^ 32];
        out[j++] = rotated_mac[rotate_offset++];
        rotate_offset &= constant_time_lt(rotate_offset, md_size);
    }
#else
    memset(out, 0, md_size);
    rotate_offset = md_size - rotate_offset;
    rotate_offset &= constant_time_lt(rotate_offset, md_size);
    for (i = 0; i < md_size; i++) {
        for (j = 0; j < md_size; j++)
            out[j] |= rotated_mac[i] & constant_time_eq_8(j, rotate_offset);
        rotate_offset++;
        rotate_offset &= constant_time_lt(rotate_offset, md_size);
    }
#endif
}

/*
 * u32toLE serialises an unsigned, 32-bit number (n) as four bytes at (p) in
 * little-endian order. The value of p is advanced by four.
 */
#define u32toLE(n, p) \
        (*((p)++)=(unsigned char)(n), \
         *((p)++)=(unsigned char)(n>>8), \
         *((p)++)=(unsigned char)(n>>16), \
         *((p)++)=(unsigned char)(n>>24))

/*
 * These functions serialize the state of a hash and thus perform the
 * standard "final" operation without adding the padding and length that such
 * a function typically does.
 */
static void tls1_md5_final_raw(void *ctx, unsigned char *md_out)
{
    MD5_CTX *md5 = ctx;
    u32toLE(md5->A, md_out);
    u32toLE(md5->B, md_out);
    u32toLE(md5->C, md_out);
    u32toLE(md5->D, md_out);
}

static void tls1_sha1_final_raw(void *ctx, unsigned char *md_out)
{
    SHA_CTX *sha1 = ctx;
    l2n(sha1->h0, md_out);
    l2n(sha1->h1, md_out);
    l2n(sha1->h2, md_out);
    l2n(sha1->h3, md_out);
    l2n(sha1->h4, md_out);
}

#define LARGEST_DIGEST_CTX SHA_CTX

#ifndef OPENSSL_NO_SHA256
static void tls1_sha256_final_raw(void *ctx, unsigned char *md_out)
{
    SHA256_CTX *sha256 = ctx;
    unsigned i;

    for (i = 0; i < 8; i++) {
        l2n(sha256->h[i], md_out);
    }
}

# undef  LARGEST_DIGEST_CTX
# define LARGEST_DIGEST_CTX SHA256_CTX
#endif

#ifndef OPENSSL_NO_SHA512
static void tls1_sha512_final_raw(void *ctx, unsigned char *md_out)
{
    SHA512_CTX *sha512 = ctx;
    unsigned i;

    for (i = 0; i < 8; i++) {
        l2n8(sha512->h[i], md_out);
    }
}

# undef  LARGEST_DIGEST_CTX
# define LARGEST_DIGEST_CTX SHA512_CTX
#endif

/*
 * ssl3_cbc_record_digest_supported returns 1 iff |ctx| uses a hash function
 * which ssl3_cbc_digest_record supports.
 */
char ssl3_cbc_record_digest_supported(const EVP_MD_CTX *ctx)
{
#ifdef OPENSSL_FIPS
    if (FIPS_mode())
        return 0;
#endif
    switch (EVP_MD_CTX_type(ctx)) {
    case NID_md5:
    case NID_sha1:
#ifndef OPENSSL_NO_SHA256
    case NID_sha224:
    case NID_sha256:
#endif
#ifndef OPENSSL_NO_SHA512
    case NID_sha384:
    case NID_sha512:
#endif
        return 1;
    default:
        return 0;
    }
}

/*-
 * ssl3_cbc_digest_record computes the MAC of a decrypted, padded SSLv3/TLS
 * record.
 *
 *   ctx: the EVP_MD_CTX from which we take the hash function.
 *     ssl3_cbc_record_digest_supported must return true for this EVP_MD_CTX.
 *   md_out: the digest output. At most EVP_MAX_MD_SIZE bytes will be written.
 *   md_out_size: if non-NULL, the number of output bytes is written here.
 *   header: the 13-byte, TLS record header.
 *   data: the record data itself, less any preceeding explicit IV.
 *   data_plus_mac_size: the secret, reported length of the data and MAC
 *     once the padding has been removed.
 *   data_plus_mac_plus_padding_size: the public length of the whole
 *     record, including padding.
 *   is_sslv3: non-zero if we are to use SSLv3. Otherwise, TLS.
 *
 * On entry: by virtue of having been through one of the remove_padding
 * functions, above, we know that data_plus_mac_size is large enough to contain
 * a padding byte and MAC. (If the padding was invalid, it might contain the
 * padding too. )
 * Returns 1 on success or 0 on error
 */
int ssl3_cbc_digest_record(const EVP_MD_CTX *ctx,
                            unsigned char *md_out,
                            size_t *md_out_size,
                            const unsigned char header[13],
                            const unsigned char *data,
                            size_t data_plus_mac_size,
                            size_t data_plus_mac_plus_padding_size,
                            const unsigned char *mac_secret,
                            unsigned mac_secret_length, char is_sslv3)
{
    union {
        double align;
        unsigned char c[sizeof(LARGEST_DIGEST_CTX)];
    } md_state;
    void (*md_final_raw) (void *ctx, unsigned char *md_out);
    void (*md_transform) (void *ctx, const unsigned char *block);
    unsigned md_size, md_block_size = 64;
    unsigned sslv3_pad_length = 40, header_length, variance_blocks,
        len, max_mac_bytes, num_blocks,
        num_starting_blocks, k, mac_end_offset, c, index_a, index_b;
    unsigned int bits;          /* at most 18 bits */
    unsigned char length_bytes[MAX_HASH_BIT_COUNT_BYTES];
    /* hmac_pad is the masked HMAC key. */
    unsigned char hmac_pad[MAX_HASH_BLOCK_SIZE];
    unsigned char first_block[MAX_HASH_BLOCK_SIZE];
    unsigned char mac_out[EVP_MAX_MD_SIZE];
    unsigned i, j, md_out_size_u;
    EVP_MD_CTX md_ctx;
    /*
     * mdLengthSize is the number of bytes in the length field that
     * terminates * the hash.
     */
    unsigned md_length_size = 8;
    char length_is_big_endian = 1;

    /*
     * This is a, hopefully redundant, check that allows us to forget about
     * many possible overflows later in this function.
     */
    OPENSSL_assert(data_plus_mac_plus_padding_size < 1024 * 1024);

    switch (EVP_MD_CTX_type(ctx)) {
    case NID_md5:
        if (MD5_Init((MD5_CTX *)md_state.c) <= 0)
            return 0;
        md_final_raw = tls1_md5_final_raw;
        md_transform =
            (void (*)(void *ctx, const unsigned char *block))MD5_Transform;
        md_size = 16;
        sslv3_pad_length = 48;
        length_is_big_endian = 0;
        break;
    case NID_sha1:
        if (SHA1_Init((SHA_CTX *)md_state.c) <= 0)
            return 0;
        md_final_raw = tls1_sha1_final_raw;
        md_transform =
            (void (*)(void *ctx, const unsigned char *block))SHA1_Transform;
        md_size = 20;
        break;
#ifndef OPENSSL_NO_SHA256
    case NID_sha224:
        if (SHA224_Init((SHA256_CTX *)md_state.c) <= 0)
            return 0;
        md_final_raw = tls1_sha256_final_raw;
        md_transform =
            (void (*)(void *ctx, const unsigned char *block))SHA256_Transform;
        md_size = 224 / 8;
        break;
    case NID_sha256:
        if (SHA256_Init((SHA256_CTX *)md_state.c) <= 0)
            return 0;
        md_final_raw = tls1_sha256_final_raw;
        md_transform =
            (void (*)(void *ctx, const unsigned char *block))SHA256_Transform;
        md_size = 32;
        break;
#endif
#ifndef OPENSSL_NO_SHA512
    case NID_sha384:
        if (SHA384_Init((SHA512_CTX *)md_state.c) <= 0)
            return 0;
        md_final_raw = tls1_sha512_final_raw;
        md_transform =
            (void (*)(void *ctx, const unsigned char *block))SHA512_Transform;
        md_size = 384 / 8;
        md_block_size = 128;
        md_length_size = 16;
        break;
    case NID_sha512:
        if (SHA512_Init((SHA512_CTX *)md_state.c) <= 0)
            return 0;
        md_final_raw = tls1_sha512_final_raw;
        md_transform =
            (void (*)(void *ctx, const unsigned char *block))SHA512_Transform;
        md_size = 64;
        md_block_size = 128;
        md_length_size = 16;
        break;
#endif
    default:
        /*
         * ssl3_cbc_record_digest_supported should have been called first to
         * check that the hash function is supported.
         */
        OPENSSL_assert(0);
        if (md_out_size)
            *md_out_size = 0;
        return 0;
    }

    OPENSSL_assert(md_length_size <= MAX_HASH_BIT_COUNT_BYTES);
    OPENSSL_assert(md_block_size <= MAX_HASH_BLOCK_SIZE);
    OPENSSL_assert(md_size <= EVP_MAX_MD_SIZE);

    header_length = 13;
    if (is_sslv3) {
        header_length = mac_secret_length + sslv3_pad_length + 8 /* sequence
                                                                  * number */  +
            1 /* record type */  +
            2 /* record length */ ;
    }

    /*
     * variance_blocks is the number of blocks of the hash that we have to
     * calculate in constant time because they could be altered by the
     * padding value. In SSLv3, the padding must be minimal so the end of
     * the plaintext varies by, at most, 15+20 = 35 bytes. (We conservatively
     * assume that the MAC size varies from 0..20 bytes.) In case the 9 bytes
     * of hash termination (0x80 + 64-bit length) don't fit in the final
     * block, we say that the final two blocks can vary based on the padding.
     * TLSv1 has MACs up to 48 bytes long (SHA-384) and the padding is not
     * required to be minimal. Therefore we say that the final six blocks can
     * vary based on the padding. Later in the function, if the message is
     * short and there obviously cannot be this many blocks then
     * variance_blocks can be reduced.
     */
    variance_blocks = is_sslv3 ? 2 : 6;
    /*
     * From now on we're dealing with the MAC, which conceptually has 13
     * bytes of `header' before the start of the data (TLS) or 71/75 bytes
     * (SSLv3)
     */
    len = data_plus_mac_plus_padding_size + header_length;
    /*
     * max_mac_bytes contains the maximum bytes of bytes in the MAC,
     * including * |header|, assuming that there's no padding.
     */
    max_mac_bytes = len - md_size - 1;
    /* num_blocks is the maximum number of hash blocks. */
    num_blocks =
        (max_mac_bytes + 1 + md_length_size + md_block_size -
         1) / md_block_size;
    /*
     * In order to calculate the MAC in constant time we have to handle the
     * final blocks specially because the padding value could cause the end
     * to appear somewhere in the final |variance_blocks| blocks and we can't
     * leak where. However, |num_starting_blocks| worth of data can be hashed
     * right away because no padding value can affect whether they are
     * plaintext.
     */
    num_starting_blocks = 0;
    /*
     * k is the starting byte offset into the conceptual header||data where
     * we start processing.
     */
    k = 0;
    /*
     * mac_end_offset is the index just past the end of the data to be MACed.
     */
    mac_end_offset = data_plus_mac_size + header_length - md_size;
    /*
     * c is the index of the 0x80 byte in the final hash block that contains
     * application data.
     */
    c = mac_end_offset % md_block_size;
    /*
     * index_a is the hash block number that contains the 0x80 terminating
     * value.
     */
    index_a = mac_end_offset / md_block_size;
    /*
     * index_b is the hash block number that contains the 64-bit hash length,
     * in bits.
     */
    index_b = (mac_end_offset + md_length_size) / md_block_size;
    /*
     * bits is the hash-length in bits. It includes the additional hash block
     * for the masked HMAC key, or whole of |header| in the case of SSLv3.
     */

    /*
     * For SSLv3, if we're going to have any starting blocks then we need at
     * least two because the header is larger than a single block.
     */
    if (num_blocks > variance_blocks + (is_sslv3 ? 1 : 0)) {
        num_starting_blocks = num_blocks - variance_blocks;
        k = md_block_size * num_starting_blocks;
    }

    bits = 8 * mac_end_offset;
    if (!is_sslv3) {
        /*
         * Compute the initial HMAC block. For SSLv3, the padding and secret
         * bytes are included in |header| because they take more than a
         * single block.
         */
        bits += 8 * md_block_size;
        memset(hmac_pad, 0, md_block_size);
        OPENSSL_assert(mac_secret_length <= sizeof(hmac_pad));
        memcpy(hmac_pad, mac_secret, mac_secret_length);
        for (i = 0; i < md_block_size; i++)
            hmac_pad[i] ^= 0x36;

        md_transform(md_state.c, hmac_pad);
    }

    if (length_is_big_endian) {
        memset(length_bytes, 0, md_length_size - 4);
        length_bytes[md_length_size - 4] = (unsigned char)(bits >> 24);
        length_bytes[md_length_size - 3] = (unsigned char)(bits >> 16);
        length_bytes[md_length_size - 2] = (unsigned char)(bits >> 8);
        length_bytes[md_length_size - 1] = (unsigned char)bits;
    } else {
        memset(length_bytes, 0, md_length_size);
        length_bytes[md_length_size - 5] = (unsigned char)(bits >> 24);
        length_bytes[md_length_size - 6] = (unsigned char)(bits >> 16);
        length_bytes[md_length_size - 7] = (unsigned char)(bits >> 8);
        length_bytes[md_length_size - 8] = (unsigned char)bits;
    }

    if (k > 0) {
        if (is_sslv3) {
            unsigned overhang;

            /*
             * The SSLv3 header is larger than a single block. overhang is
             * the number of bytes beyond a single block that the header
             * consumes: either 7 bytes (SHA1) or 11 bytes (MD5). There are no
             * ciphersuites in SSLv3 that are not SHA1 or MD5 based and
             * therefore we can be confident that the header_length will be
             * greater than |md_block_size|. However we add a sanity check just
             * in case
             */
            if (header_length <= md_block_size) {
                /* Should never happen */
                return 0;
            }
            overhang = header_length - md_block_size;
            md_transform(md_state.c, header);
            memcpy(first_block, header + md_block_size, overhang);
            memcpy(first_block + overhang, data, md_block_size - overhang);
            md_transform(md_state.c, first_block);
            for (i = 1; i < k / md_block_size - 1; i++)
                md_transform(md_state.c, data + md_block_size * i - overhang);
        } else {
            /* k is a multiple of md_block_size. */
            memcpy(first_block, header, 13);
            memcpy(first_block + 13, data, md_block_size - 13);
            md_transform(md_state.c, first_block);
            for (i = 1; i < k / md_block_size; i++)
                md_transform(md_state.c, data + md_block_size * i - 13);
        }
    }

    memset(mac_out, 0, sizeof(mac_out));

    /*
     * We now process the final hash blocks. For each block, we construct it
     * in constant time. If the |i==index_a| then we'll include the 0x80
     * bytes and zero pad etc. For each block we selectively copy it, in
     * constant time, to |mac_out|.
     */
    for (i = num_starting_blocks; i <= num_starting_blocks + variance_blocks;
         i++) {
        unsigned char block[MAX_HASH_BLOCK_SIZE];
        unsigned char is_block_a = constant_time_eq_8(i, index_a);
        unsigned char is_block_b = constant_time_eq_8(i, index_b);
        for (j = 0; j < md_block_size; j++) {
            unsigned char b = 0, is_past_c, is_past_cp1;
            if (k < header_length)
                b = header[k];
            else if (k < data_plus_mac_plus_padding_size + header_length)
                b = data[k - header_length];
            k++;

            is_past_c = is_block_a & constant_time_ge_8(j, c);
            is_past_cp1 = is_block_a & constant_time_ge_8(j, c + 1);
            /*
             * If this is the block containing the end of the application
             * data, and we are at the offset for the 0x80 value, then
             * overwrite b with 0x80.
             */
            b = constant_time_select_8(is_past_c, 0x80, b);
            /*
             * If this the the block containing the end of the application
             * data and we're past the 0x80 value then just write zero.
             */
            b = b & ~is_past_cp1;
            /*
             * If this is index_b (the final block), but not index_a (the end
             * of the data), then the 64-bit length didn't fit into index_a
             * and we're having to add an extra block of zeros.
             */
            b &= ~is_block_b | is_block_a;

            /*
             * The final bytes of one of the blocks contains the length.
             */
            if (j >= md_block_size - md_length_size) {
                /* If this is index_b, write a length byte. */
                b = constant_time_select_8(is_block_b,
                                           length_bytes[j -
                                                        (md_block_size -
                                                         md_length_size)], b);
            }
            block[j] = b;
        }

        md_transform(md_state.c, block);
        md_final_raw(md_state.c, block);
        /* If this is index_b, copy the hash value to |mac_out|. */
        for (j = 0; j < md_size; j++)
            mac_out[j] |= block[j] & is_block_b;
    }

    EVP_MD_CTX_init(&md_ctx);
    if (EVP_DigestInit_ex(&md_ctx, ctx->digest, NULL /* engine */ ) <= 0)
        goto err;
    if (is_sslv3) {
        /* We repurpose |hmac_pad| to contain the SSLv3 pad2 block. */
        memset(hmac_pad, 0x5c, sslv3_pad_length);

        if (EVP_DigestUpdate(&md_ctx, mac_secret, mac_secret_length) <= 0
                || EVP_DigestUpdate(&md_ctx, hmac_pad, sslv3_pad_length) <= 0
                || EVP_DigestUpdate(&md_ctx, mac_out, md_size) <= 0)
            goto err;
    } else {
        /* Complete the HMAC in the standard manner. */
        for (i = 0; i < md_block_size; i++)
            hmac_pad[i] ^= 0x6a;

        if (EVP_DigestUpdate(&md_ctx, hmac_pad, md_block_size) <= 0
                || EVP_DigestUpdate(&md_ctx, mac_out, md_size) <= 0)
            goto err;
    }
    EVP_DigestFinal(&md_ctx, md_out, &md_out_size_u);
    if (md_out_size)
        *md_out_size = md_out_size_u;
    EVP_MD_CTX_cleanup(&md_ctx);

    return 1;
err:
    EVP_MD_CTX_cleanup(&md_ctx);
    return 0;
}

#ifdef OPENSSL_FIPS

/*
 * Due to the need to use EVP in FIPS mode we can't reimplement digests but
 * we can ensure the number of blocks processed is equal for all cases by
 * digesting additional data.
 */

void tls_fips_digest_extra(const EVP_CIPHER_CTX *cipher_ctx,
                           EVP_MD_CTX *mac_ctx, const unsigned char *data,
                           size_t data_len, size_t orig_len)
{
    size_t block_size, digest_pad, blocks_data, blocks_orig;
    if (EVP_CIPHER_CTX_mode(cipher_ctx) != EVP_CIPH_CBC_MODE)
        return;
    block_size = EVP_MD_CTX_block_size(mac_ctx);
    /*-
     * We are in FIPS mode if we get this far so we know we have only SHA*
     * digests and TLS to deal with.
     * Minimum digest padding length is 17 for SHA384/SHA512 and 9
     * otherwise.
     * Additional header is 13 bytes. To get the number of digest blocks
     * processed round up the amount of data plus padding to the nearest
     * block length. Block length is 128 for SHA384/SHA512 and 64 otherwise.
     * So we have:
     * blocks = (payload_len + digest_pad + 13 + block_size - 1)/block_size
     * equivalently:
     * blocks = (payload_len + digest_pad + 12)/block_size + 1
     * HMAC adds a constant overhead.
     * We're ultimately only interested in differences so this becomes
     * blocks = (payload_len + 29)/128
     * for SHA384/SHA512 and
     * blocks = (payload_len + 21)/64
     * otherwise.
     */
    digest_pad = block_size == 64 ? 21 : 29;
    blocks_orig = (orig_len + digest_pad) / block_size;
    blocks_data = (data_len + digest_pad) / block_size;
    /*
     * MAC enough blocks to make up the difference between the original and
     * actual lengths plus one extra block to ensure this is never a no op.
     * The "data" pointer should always have enough space to perform this
     * operation as it is large enough for a maximum length TLS buffer.
     */
    EVP_DigestSignUpdate(mac_ctx, data,
                         (blocks_orig - blocks_data + 1) * block_size);
}
#endif
/* ssl/s3_clnt.c */
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
/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 *
 * Portions of the attached software ("Contribution") are developed by
 * SUN MICROSYSTEMS, INC., and are contributed to the OpenSSL project.
 *
 * The Contribution is licensed pursuant to the OpenSSL open source
 * license provided above.
 *
 * ECC cipher suite support in OpenSSL originally written by
 * Vipul Gupta and Sumit Gupta of Sun Microsystems Laboratories.
 *
 */
/* ====================================================================
 * Copyright 2005 Nokia. All rights reserved.
 *
 * The portions of the attached software ("Contribution") is developed by
 * Nokia Corporation and is licensed pursuant to the OpenSSL open source
 * license.
 *
 * The Contribution, originally written by Mika Kousa and Pasi Eronen of
 * Nokia Corporation, consists of the "PSK" (Pre-Shared Key) ciphersuites
 * support (see RFC 4279) to OpenSSL.
 *
 * No patent licenses or other rights except those expressly stated in
 * the OpenSSL open source license shall be deemed granted or received
 * expressly, by implication, estoppel, or otherwise.
 *
 * No assurances are provided by Nokia that the Contribution does not
 * infringe the patent or other intellectual property rights of any third
 * party or that the license provides you with all the necessary rights
 * to make use of the Contribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND. IN
 * ADDITION TO THE DISCLAIMERS INCLUDED IN THE LICENSE, NOKIA
 * SPECIFICALLY DISCLAIMS ANY LIABILITY FOR CLAIMS BROUGHT BY YOU OR ANY
 * OTHER ENTITY BASED ON INFRINGEMENT OF INTELLECTUAL PROPERTY RIGHTS OR
 * OTHERWISE.
 */

#include <stdio.h>
// #include "ssl_locl.h"
#include "kssl_lcl.h"
// #include "buffer.h"
// #include "rand.h"
// #include "objects.h"
// #include "evp.h"
// #include "md5.h"
#ifdef OPENSSL_FIPS
# include <fips.h>
#endif
#ifndef OPENSSL_NO_DH
# include "dh.h"
#endif
#include "bn.h"
#ifndef OPENSSL_NO_ENGINE
# include "engine.h"
#endif

static int ca_dn_cmp(const X509_NAME *const *a, const X509_NAME *const *b);
#ifndef OPENSSL_NO_TLSEXT
static int ssl3_check_finished(SSL *s);
#endif

#ifndef OPENSSL_NO_SSL3_METHOD
static const SSL_METHOD *ssl3_get_client_method(int ver)
{
    if (ver == SSL3_VERSION)
        return (SSLv3_client_method());
    else
        return (NULL);
}

IMPLEMENT_ssl3_meth_func(SSLv3_client_method,
                         ssl_undefined_function,
                         ssl3_connect, ssl3_get_client_method)
#endif
int ssl3_connect(SSL *s)
{
    BUF_MEM *buf = NULL;
    unsigned long Time = (unsigned long)time(NULL);
    void (*cb) (const SSL *ssl, int type, int val) = NULL;
    int ret = -1;
    int new_state, state, skip = 0;

    RAND_add(&Time, sizeof(Time), 0);
    ERR_clear_error();
    clear_sys_error();

    if (s->info_callback != NULL)
        cb = s->info_callback;
    else if (s->ctx->info_callback != NULL)
        cb = s->ctx->info_callback;

    s->in_handshake++;
    if (!SSL_in_init(s) || SSL_in_before(s))
        SSL_clear(s);

#ifndef OPENSSL_NO_HEARTBEATS
    /*
     * If we're awaiting a HeartbeatResponse, pretend we already got and
     * don't await it anymore, because Heartbeats don't make sense during
     * handshakes anyway.
     */
    if (s->tlsext_hb_pending) {
        s->tlsext_hb_pending = 0;
        s->tlsext_hb_seq++;
    }
#endif

    for (;;) {
        state = s->state;

        switch (s->state) {
        case SSL_ST_RENEGOTIATE:
            s->renegotiate = 1;
            s->state = SSL_ST_CONNECT;
            s->ctx->stats.sess_connect_renegotiate++;
            /* break */
        case SSL_ST_BEFORE:
        case SSL_ST_CONNECT:
        case SSL_ST_BEFORE | SSL_ST_CONNECT:
        case SSL_ST_OK | SSL_ST_CONNECT:

            s->server = 0;
            if (cb != NULL)
                cb(s, SSL_CB_HANDSHAKE_START, 1);

            if ((s->version & 0xff00) != 0x0300) {
                SSLerr(SSL_F_SSL3_CONNECT, ERR_R_INTERNAL_ERROR);
                s->state = SSL_ST_ERR;
                ret = -1;
                goto end;
            }

            /* s->version=SSL3_VERSION; */
            s->type = SSL_ST_CONNECT;

            if (s->init_buf == NULL) {
                if ((buf = BUF_MEM_new()) == NULL) {
                    ret = -1;
                    s->state = SSL_ST_ERR;
                    goto end;
                }
                if (!BUF_MEM_grow(buf, SSL3_RT_MAX_PLAIN_LENGTH)) {
                    ret = -1;
                    s->state = SSL_ST_ERR;
                    goto end;
                }
                s->init_buf = buf;
                buf = NULL;
            }

            if (!ssl3_setup_buffers(s)) {
                ret = -1;
                s->state = SSL_ST_ERR;
                goto end;
            }

            /* setup buffing BIO */
            if (!ssl_init_wbio_buffer(s, 0)) {
                ret = -1;
                s->state = SSL_ST_ERR;
                goto end;
            }

            /* don't push the buffering BIO quite yet */

            if (!ssl3_init_finished_mac(s)) {
                ret = -1;
                s->state = SSL_ST_ERR;
                goto end;
            }

            s->state = SSL3_ST_CW_CLNT_HELLO_A;
            s->ctx->stats.sess_connect++;
            s->init_num = 0;
            s->s3->flags &= ~SSL3_FLAGS_CCS_OK;
            /*
             * Should have been reset by ssl3_get_finished, too.
             */
            s->s3->change_cipher_spec = 0;
            break;

        case SSL3_ST_CW_CLNT_HELLO_A:
        case SSL3_ST_CW_CLNT_HELLO_B:

            s->shutdown = 0;
            ret = ssl3_client_hello(s);
            if (ret <= 0)
                goto end;
            s->state = SSL3_ST_CR_SRVR_HELLO_A;
            s->init_num = 0;

            /* turn on buffering for the next lot of output */
            if (s->bbio != s->wbio)
                s->wbio = BIO_push(s->bbio, s->wbio);

            break;

        case SSL3_ST_CR_SRVR_HELLO_A:
        case SSL3_ST_CR_SRVR_HELLO_B:
            ret = ssl3_get_server_hello(s);
            if (ret <= 0)
                goto end;

            if (s->hit) {
                s->state = SSL3_ST_CR_FINISHED_A;
#ifndef OPENSSL_NO_TLSEXT
                if (s->tlsext_ticket_expected) {
                    /* receive renewed session ticket */
                    s->state = SSL3_ST_CR_SESSION_TICKET_A;
                }
#endif
            } else {
                s->state = SSL3_ST_CR_CERT_A;
            }
            s->init_num = 0;
            break;
        case SSL3_ST_CR_CERT_A:
        case SSL3_ST_CR_CERT_B:
#ifndef OPENSSL_NO_TLSEXT
            /* Noop (ret = 0) for everything but EAP-FAST. */
            ret = ssl3_check_finished(s);
            if (ret < 0)
                goto end;
            if (ret == 1) {
                s->hit = 1;
                s->state = SSL3_ST_CR_FINISHED_A;
                s->init_num = 0;
                break;
            }
#endif
            /* Check if it is anon DH/ECDH, SRP auth */
            /* or PSK */
            if (!
                (s->s3->tmp.
                 new_cipher->algorithm_auth & (SSL_aNULL | SSL_aSRP))
                    && !(s->s3->tmp.new_cipher->algorithm_mkey & SSL_kPSK)) {
                ret = ssl3_get_server_certificate(s);
                if (ret <= 0)
                    goto end;
#ifndef OPENSSL_NO_TLSEXT
                if (s->tlsext_status_expected)
                    s->state = SSL3_ST_CR_CERT_STATUS_A;
                else
                    s->state = SSL3_ST_CR_KEY_EXCH_A;
            } else {
                skip = 1;
                s->state = SSL3_ST_CR_KEY_EXCH_A;
            }
#else
            } else
                skip = 1;

            s->state = SSL3_ST_CR_KEY_EXCH_A;
#endif
            s->init_num = 0;
            break;

        case SSL3_ST_CR_KEY_EXCH_A:
        case SSL3_ST_CR_KEY_EXCH_B:
            ret = ssl3_get_key_exchange(s);
            if (ret <= 0)
                goto end;
            s->state = SSL3_ST_CR_CERT_REQ_A;
            s->init_num = 0;

            /*
             * at this point we check that we have the required stuff from
             * the server
             */
            if (!ssl3_check_cert_and_algorithm(s)) {
                ret = -1;
                s->state = SSL_ST_ERR;
                goto end;
            }
            break;

        case SSL3_ST_CR_CERT_REQ_A:
        case SSL3_ST_CR_CERT_REQ_B:
            ret = ssl3_get_certificate_request(s);
            if (ret <= 0)
                goto end;
            s->state = SSL3_ST_CR_SRVR_DONE_A;
            s->init_num = 0;
            break;

        case SSL3_ST_CR_SRVR_DONE_A:
        case SSL3_ST_CR_SRVR_DONE_B:
            ret = ssl3_get_server_done(s);
            if (ret <= 0)
                goto end;
#ifndef OPENSSL_NO_SRP
            if (s->s3->tmp.new_cipher->algorithm_mkey & SSL_kSRP) {
                if ((ret = SRP_Calc_A_param(s)) <= 0) {
                    SSLerr(SSL_F_SSL3_CONNECT, SSL_R_SRP_A_CALC);
                    ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_INTERNAL_ERROR);
                    s->state = SSL_ST_ERR;
                    goto end;
                }
            }
#endif
            if (s->s3->tmp.cert_req)
                s->state = SSL3_ST_CW_CERT_A;
            else
                s->state = SSL3_ST_CW_KEY_EXCH_A;
            s->init_num = 0;

            break;

        case SSL3_ST_CW_CERT_A:
        case SSL3_ST_CW_CERT_B:
        case SSL3_ST_CW_CERT_C:
        case SSL3_ST_CW_CERT_D:
            ret = ssl3_send_client_certificate(s);
            if (ret <= 0)
                goto end;
            s->state = SSL3_ST_CW_KEY_EXCH_A;
            s->init_num = 0;
            break;

        case SSL3_ST_CW_KEY_EXCH_A:
        case SSL3_ST_CW_KEY_EXCH_B:
            ret = ssl3_send_client_key_exchange(s);
            if (ret <= 0)
                goto end;
            /*
             * EAY EAY EAY need to check for DH fix cert sent back
             */
            /*
             * For TLS, cert_req is set to 2, so a cert chain of nothing is
             * sent, but no verify packet is sent
             */
            /*
             * XXX: For now, we do not support client authentication in ECDH
             * cipher suites with ECDH (rather than ECDSA) certificates. We
             * need to skip the certificate verify message when client's
             * ECDH public key is sent inside the client certificate.
             */
            if (s->s3->tmp.cert_req == 1) {
                s->state = SSL3_ST_CW_CERT_VRFY_A;
            } else {
                s->state = SSL3_ST_CW_CHANGE_A;
            }
            if (s->s3->flags & TLS1_FLAGS_SKIP_CERT_VERIFY) {
                s->state = SSL3_ST_CW_CHANGE_A;
            }

            s->init_num = 0;
            break;

        case SSL3_ST_CW_CERT_VRFY_A:
        case SSL3_ST_CW_CERT_VRFY_B:
            ret = ssl3_send_client_verify(s);
            if (ret <= 0)
                goto end;
            s->state = SSL3_ST_CW_CHANGE_A;
            s->init_num = 0;
            break;

        case SSL3_ST_CW_CHANGE_A:
        case SSL3_ST_CW_CHANGE_B:
            ret = ssl3_send_change_cipher_spec(s,
                                               SSL3_ST_CW_CHANGE_A,
                                               SSL3_ST_CW_CHANGE_B);
            if (ret <= 0)
                goto end;

#if defined(OPENSSL_NO_TLSEXT) || defined(OPENSSL_NO_NEXTPROTONEG)
            s->state = SSL3_ST_CW_FINISHED_A;
#else
            if (s->s3->next_proto_neg_seen)
                s->state = SSL3_ST_CW_NEXT_PROTO_A;
            else
                s->state = SSL3_ST_CW_FINISHED_A;
#endif
            s->init_num = 0;

            s->session->cipher = s->s3->tmp.new_cipher;
#ifdef OPENSSL_NO_COMP
            s->session->compress_meth = 0;
#else
            if (s->s3->tmp.new_compression == NULL)
                s->session->compress_meth = 0;
            else
                s->session->compress_meth = s->s3->tmp.new_compression->id;
#endif
            if (!s->method->ssl3_enc->setup_key_block(s)) {
                ret = -1;
                s->state = SSL_ST_ERR;
                goto end;
            }

            if (!s->method->ssl3_enc->change_cipher_state(s,
                                                          SSL3_CHANGE_CIPHER_CLIENT_WRITE))
            {
                ret = -1;
                s->state = SSL_ST_ERR;
                goto end;
            }

            break;

#if !defined(OPENSSL_NO_TLSEXT) && !defined(OPENSSL_NO_NEXTPROTONEG)
        case SSL3_ST_CW_NEXT_PROTO_A:
        case SSL3_ST_CW_NEXT_PROTO_B:
            ret = ssl3_send_next_proto(s);
            if (ret <= 0)
                goto end;
            s->state = SSL3_ST_CW_FINISHED_A;
            break;
#endif

        case SSL3_ST_CW_FINISHED_A:
        case SSL3_ST_CW_FINISHED_B:
            ret = ssl3_send_finished(s,
                                     SSL3_ST_CW_FINISHED_A,
                                     SSL3_ST_CW_FINISHED_B,
                                     s->method->
                                     ssl3_enc->client_finished_label,
                                     s->method->
                                     ssl3_enc->client_finished_label_len);
            if (ret <= 0)
                goto end;
            s->state = SSL3_ST_CW_FLUSH;

            /* clear flags */
            s->s3->flags &= ~SSL3_FLAGS_POP_BUFFER;
            if (s->hit) {
                s->s3->tmp.next_state = SSL_ST_OK;
                if (s->s3->flags & SSL3_FLAGS_DELAY_CLIENT_FINISHED) {
                    s->state = SSL_ST_OK;
                    s->s3->flags |= SSL3_FLAGS_POP_BUFFER;
                    s->s3->delay_buf_pop_ret = 0;
                }
            } else {
#ifndef OPENSSL_NO_TLSEXT
                /*
                 * Allow NewSessionTicket if ticket expected
                 */
                if (s->tlsext_ticket_expected)
                    s->s3->tmp.next_state = SSL3_ST_CR_SESSION_TICKET_A;
                else
#endif

                    s->s3->tmp.next_state = SSL3_ST_CR_FINISHED_A;
            }
            s->init_num = 0;
            break;

#ifndef OPENSSL_NO_TLSEXT
        case SSL3_ST_CR_SESSION_TICKET_A:
        case SSL3_ST_CR_SESSION_TICKET_B:
            ret = ssl3_get_new_session_ticket(s);
            if (ret <= 0)
                goto end;
            s->state = SSL3_ST_CR_FINISHED_A;
            s->init_num = 0;
            break;

        case SSL3_ST_CR_CERT_STATUS_A:
        case SSL3_ST_CR_CERT_STATUS_B:
            ret = ssl3_get_cert_status(s);
            if (ret <= 0)
                goto end;
            s->state = SSL3_ST_CR_KEY_EXCH_A;
            s->init_num = 0;
            break;
#endif

        case SSL3_ST_CR_FINISHED_A:
        case SSL3_ST_CR_FINISHED_B:
            if (!s->s3->change_cipher_spec)
                s->s3->flags |= SSL3_FLAGS_CCS_OK;
            ret = ssl3_get_finished(s, SSL3_ST_CR_FINISHED_A,
                                    SSL3_ST_CR_FINISHED_B);
            if (ret <= 0)
                goto end;

            if (s->hit)
                s->state = SSL3_ST_CW_CHANGE_A;
            else
                s->state = SSL_ST_OK;
            s->init_num = 0;
            break;

        case SSL3_ST_CW_FLUSH:
            s->rwstate = SSL_WRITING;
            if (BIO_flush(s->wbio) <= 0) {
                ret = -1;
                goto end;
            }
            s->rwstate = SSL_NOTHING;
            s->state = s->s3->tmp.next_state;
            break;

        case SSL_ST_OK:
            /* clean a few things up */
            ssl3_cleanup_key_block(s);

            if (s->init_buf != NULL) {
                BUF_MEM_free(s->init_buf);
                s->init_buf = NULL;
            }

            /*
             * If we are not 'joining' the last two packets, remove the
             * buffering now
             */
            if (!(s->s3->flags & SSL3_FLAGS_POP_BUFFER))
                ssl_free_wbio_buffer(s);
            /* else do it later in ssl3_write */

            s->init_num = 0;
            s->renegotiate = 0;
            s->new_session = 0;

            ssl_update_cache(s, SSL_SESS_CACHE_CLIENT);
            if (s->hit)
                s->ctx->stats.sess_hit++;

            ret = 1;
            /* s->server=0; */
            s->handshake_func = ssl3_connect;
            s->ctx->stats.sess_connect_good++;

            if (cb != NULL)
                cb(s, SSL_CB_HANDSHAKE_DONE, 1);

            goto end;
            /* break; */

        case SSL_ST_ERR:
        default:
            SSLerr(SSL_F_SSL3_CONNECT, SSL_R_UNKNOWN_STATE);
            ret = -1;
            goto end;
            /* break; */
        }

        /* did we do anything */
        if (!s->s3->tmp.reuse_message && !skip) {
            if (s->debug) {
                if ((ret = BIO_flush(s->wbio)) <= 0)
                    goto end;
            }

            if ((cb != NULL) && (s->state != state)) {
                new_state = s->state;
                s->state = state;
                cb(s, SSL_CB_CONNECT_LOOP, 1);
                s->state = new_state;
            }
        }
        skip = 0;
    }
 end:
    s->in_handshake--;
    if (buf != NULL)
        BUF_MEM_free(buf);
    if (cb != NULL)
        cb(s, SSL_CB_CONNECT_EXIT, ret);
    return (ret);
}

int ssl3_client_hello(SSL *s)
{
    unsigned char *buf;
    unsigned char *p, *d;
    int i;
    unsigned long l;
    int al = 0;
#ifndef OPENSSL_NO_COMP
    int j;
    SSL_COMP *comp;
#endif

    buf = (unsigned char *)s->init_buf->data;
    if (s->state == SSL3_ST_CW_CLNT_HELLO_A) {
        SSL_SESSION *sess = s->session;
        if ((sess == NULL) || (sess->ssl_version != s->version) ||
#ifdef OPENSSL_NO_TLSEXT
            !sess->session_id_length ||
#else
            /*
             * In the case of EAP-FAST, we can have a pre-shared
             * "ticket" without a session ID.
             */
            (!sess->session_id_length && !sess->tlsext_tick) ||
#endif
            (sess->not_resumable)) {
            if (!ssl_get_new_session(s, 0))
                goto err;
        }
        if (s->method->version == DTLS_ANY_VERSION) {
            /* Determine which DTLS version to use */
            int options = s->options;
            /* If DTLS 1.2 disabled correct the version number */
            if (options & SSL_OP_NO_DTLSv1_2) {
                if (tls1_suiteb(s)) {
                    SSLerr(SSL_F_SSL3_CLIENT_HELLO,
                           SSL_R_ONLY_DTLS_1_2_ALLOWED_IN_SUITEB_MODE);
                    goto err;
                }
                /*
                 * Disabling all versions is silly: return an error.
                 */
                if (options & SSL_OP_NO_DTLSv1) {
                    SSLerr(SSL_F_SSL3_CLIENT_HELLO, SSL_R_WRONG_SSL_VERSION);
                    goto err;
                }
                /*
                 * Update method so we don't use any DTLS 1.2 features.
                 */
                s->method = DTLSv1_client_method();
                s->version = DTLS1_VERSION;
            } else {
                /*
                 * We only support one version: update method
                 */
                if (options & SSL_OP_NO_DTLSv1)
                    s->method = DTLSv1_2_client_method();
                s->version = DTLS1_2_VERSION;
            }
            s->client_version = s->version;
        }
        /* else use the pre-loaded session */

        p = s->s3->client_random;

        /*
         * for DTLS if client_random is initialized, reuse it, we are
         * required to use same upon reply to HelloVerify
         */
        if (SSL_IS_DTLS(s)) {
            size_t idx;
            i = 1;
            for (idx = 0; idx < sizeof(s->s3->client_random); idx++) {
                if (p[idx]) {
                    i = 0;
                    break;
                }
            }
        } else
            i = 1;

        if (i && ssl_fill_hello_random(s, 0, p,
                                       sizeof(s->s3->client_random)) <= 0)
            goto err;

        /* Do the message type and length last */
        d = p = ssl_handshake_start(s);

        /*-
         * version indicates the negotiated version: for example from
         * an SSLv2/v3 compatible client hello). The client_version
         * field is the maximum version we permit and it is also
         * used in RSA encrypted premaster secrets. Some servers can
         * choke if we initially report a higher version then
         * renegotiate to a lower one in the premaster secret. This
         * didn't happen with TLS 1.0 as most servers supported it
         * but it can with TLS 1.1 or later if the server only supports
         * 1.0.
         *
         * Possible scenario with previous logic:
         *      1. Client hello indicates TLS 1.2
         *      2. Server hello says TLS 1.0
         *      3. RSA encrypted premaster secret uses 1.2.
         *      4. Handhaked proceeds using TLS 1.0.
         *      5. Server sends hello request to renegotiate.
         *      6. Client hello indicates TLS v1.0 as we now
         *         know that is maximum server supports.
         *      7. Server chokes on RSA encrypted premaster secret
         *         containing version 1.0.
         *
         * For interoperability it should be OK to always use the
         * maximum version we support in client hello and then rely
         * on the checking of version to ensure the servers isn't
         * being inconsistent: for example initially negotiating with
         * TLS 1.0 and renegotiating with TLS 1.2. We do this by using
         * client_version in client hello and not resetting it to
         * the negotiated version.
         */
#if 0
        *(p++) = s->version >> 8;
        *(p++) = s->version & 0xff;
        s->client_version = s->version;
#else
        *(p++) = s->client_version >> 8;
        *(p++) = s->client_version & 0xff;
#endif

        /* Random stuff */
        memcpy(p, s->s3->client_random, SSL3_RANDOM_SIZE);
        p += SSL3_RANDOM_SIZE;

        /* Session ID */
        if (s->new_session)
            i = 0;
        else
            i = s->session->session_id_length;
        *(p++) = i;
        if (i != 0) {
            if (i > (int)sizeof(s->session->session_id)) {
                SSLerr(SSL_F_SSL3_CLIENT_HELLO, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            memcpy(p, s->session->session_id, i);
            p += i;
        }

        /* cookie stuff for DTLS */
        if (SSL_IS_DTLS(s)) {
            if (s->d1->cookie_len > sizeof(s->d1->cookie)) {
                SSLerr(SSL_F_SSL3_CLIENT_HELLO, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            *(p++) = s->d1->cookie_len;
            memcpy(p, s->d1->cookie, s->d1->cookie_len);
            p += s->d1->cookie_len;
        }

        /* Ciphers supported */
        i = ssl_cipher_list_to_bytes(s, SSL_get_ciphers(s), &(p[2]), 0);
        if (i == 0) {
            SSLerr(SSL_F_SSL3_CLIENT_HELLO, SSL_R_NO_CIPHERS_AVAILABLE);
            goto err;
        }
#ifdef OPENSSL_MAX_TLS1_2_CIPHER_LENGTH
        /*
         * Some servers hang if client hello > 256 bytes as hack workaround
         * chop number of supported ciphers to keep it well below this if we
         * use TLS v1.2
         */
        if (TLS1_get_version(s) >= TLS1_2_VERSION
            && i > OPENSSL_MAX_TLS1_2_CIPHER_LENGTH)
            i = OPENSSL_MAX_TLS1_2_CIPHER_LENGTH & ~1;
#endif
        s2n(i, p);
        p += i;

        /* COMPRESSION */
#ifdef OPENSSL_NO_COMP
        *(p++) = 1;
#else

        if ((s->options & SSL_OP_NO_COMPRESSION)
            || !s->ctx->comp_methods)
            j = 0;
        else
            j = sk_SSL_COMP_num(s->ctx->comp_methods);
        *(p++) = 1 + j;
        for (i = 0; i < j; i++) {
            comp = sk_SSL_COMP_value(s->ctx->comp_methods, i);
            *(p++) = comp->id;
        }
#endif
        *(p++) = 0;             /* Add the NULL method */

#ifndef OPENSSL_NO_TLSEXT
        /* TLS extensions */
        if (ssl_prepare_clienthello_tlsext(s) <= 0) {
            SSLerr(SSL_F_SSL3_CLIENT_HELLO, SSL_R_CLIENTHELLO_TLSEXT);
            goto err;
        }
        if ((p =
             ssl_add_clienthello_tlsext(s, p, buf + SSL3_RT_MAX_PLAIN_LENGTH,
                                        &al)) == NULL) {
            ssl3_send_alert(s, SSL3_AL_FATAL, al);
            SSLerr(SSL_F_SSL3_CLIENT_HELLO, ERR_R_INTERNAL_ERROR);
            goto err;
        }
#endif

        l = p - d;
        ssl_set_handshake_header(s, SSL3_MT_CLIENT_HELLO, l);
        s->state = SSL3_ST_CW_CLNT_HELLO_B;
    }

    /* SSL3_ST_CW_CLNT_HELLO_B */
    return ssl_do_write(s);
 err:
    s->state = SSL_ST_ERR;
    return (-1);
}

int ssl3_get_server_hello(SSL *s)
{
    STACK_OF(SSL_CIPHER) *sk;
    const SSL_CIPHER *c;
    CERT *ct = s->cert;
    unsigned char *p, *d;
    int i, al = SSL_AD_INTERNAL_ERROR, ok;
    unsigned int j;
    long n;
#ifndef OPENSSL_NO_COMP
    SSL_COMP *comp;
#endif
    /*
     * Hello verify request and/or server hello version may not match so set
     * first packet if we're negotiating version.
     */
    if (SSL_IS_DTLS(s))
        s->first_packet = 1;

    n = s->method->ssl_get_message(s,
                                   SSL3_ST_CR_SRVR_HELLO_A,
                                   SSL3_ST_CR_SRVR_HELLO_B, -1, 20000, &ok);

    if (!ok)
        return ((int)n);

    if (SSL_IS_DTLS(s)) {
        s->first_packet = 0;
        if (s->s3->tmp.message_type == DTLS1_MT_HELLO_VERIFY_REQUEST) {
            if (s->d1->send_cookie == 0) {
                s->s3->tmp.reuse_message = 1;
                return 1;
            } else {            /* already sent a cookie */

                al = SSL_AD_UNEXPECTED_MESSAGE;
                SSLerr(SSL_F_SSL3_GET_SERVER_HELLO, SSL_R_BAD_MESSAGE_TYPE);
                goto f_err;
            }
        }
    }

    if (s->s3->tmp.message_type != SSL3_MT_SERVER_HELLO) {
        al = SSL_AD_UNEXPECTED_MESSAGE;
        SSLerr(SSL_F_SSL3_GET_SERVER_HELLO, SSL_R_BAD_MESSAGE_TYPE);
        goto f_err;
    }

    d = p = (unsigned char *)s->init_msg;
    if (s->method->version == DTLS_ANY_VERSION) {
        /* Work out correct protocol version to use */
        int hversion = (p[0] << 8) | p[1];
        int options = s->options;
        if (hversion == DTLS1_2_VERSION && !(options & SSL_OP_NO_DTLSv1_2))
            s->method = DTLSv1_2_client_method();
        else if (tls1_suiteb(s)) {
            SSLerr(SSL_F_SSL3_GET_SERVER_HELLO,
                   SSL_R_ONLY_DTLS_1_2_ALLOWED_IN_SUITEB_MODE);
            s->version = hversion;
            al = SSL_AD_PROTOCOL_VERSION;
            goto f_err;
        } else if (hversion == DTLS1_VERSION && !(options & SSL_OP_NO_DTLSv1))
            s->method = DTLSv1_client_method();
        else {
            SSLerr(SSL_F_SSL3_GET_SERVER_HELLO, SSL_R_WRONG_SSL_VERSION);
            s->version = hversion;
            al = SSL_AD_PROTOCOL_VERSION;
            goto f_err;
        }
        s->session->ssl_version = s->version = s->method->version;
    }

    if ((p[0] != (s->version >> 8)) || (p[1] != (s->version & 0xff))) {
        SSLerr(SSL_F_SSL3_GET_SERVER_HELLO, SSL_R_WRONG_SSL_VERSION);
        s->version = (s->version & 0xff00) | p[1];
        al = SSL_AD_PROTOCOL_VERSION;
        goto f_err;
    }
    p += 2;

    /* load the server hello data */
    /* load the server random */
    memcpy(s->s3->server_random, p, SSL3_RANDOM_SIZE);
    p += SSL3_RANDOM_SIZE;

    s->hit = 0;

    /* get the session-id */
    j = *(p++);

    if ((j > sizeof(s->session->session_id)) || (j > SSL3_SESSION_ID_SIZE)) {
        al = SSL_AD_ILLEGAL_PARAMETER;
        SSLerr(SSL_F_SSL3_GET_SERVER_HELLO, SSL_R_SSL3_SESSION_ID_TOO_LONG);
        goto f_err;
    }
#ifndef OPENSSL_NO_TLSEXT
    /*
     * Check if we can resume the session based on external pre-shared secret.
     * EAP-FAST (RFC 4851) supports two types of session resumption.
     * Resumption based on server-side state works with session IDs.
     * Resumption based on pre-shared Protected Access Credentials (PACs)
     * works by overriding the SessionTicket extension at the application
     * layer, and does not send a session ID. (We do not know whether EAP-FAST
     * servers would honour the session ID.) Therefore, the session ID alone
     * is not a reliable indicator of session resumption, so we first check if
     * we can resume, and later peek at the next handshake message to see if the
     * server wants to resume.
     */
    if (s->version >= TLS1_VERSION && s->tls_session_secret_cb &&
        s->session->tlsext_tick) {
        SSL_CIPHER *pref_cipher = NULL;
        s->session->master_key_length = sizeof(s->session->master_key);
        if (s->tls_session_secret_cb(s, s->session->master_key,
                                     &s->session->master_key_length,
                                     NULL, &pref_cipher,
                                     s->tls_session_secret_cb_arg)) {
            s->session->cipher = pref_cipher ?
                pref_cipher : ssl_get_cipher_by_char(s, p + j);
        } else {
            SSLerr(SSL_F_SSL3_GET_SERVER_HELLO, ERR_R_INTERNAL_ERROR);
            al = SSL_AD_INTERNAL_ERROR;
            goto f_err;
        }
    }
#endif                          /* OPENSSL_NO_TLSEXT */

    if (j != 0 && j == s->session->session_id_length
        && memcmp(p, s->session->session_id, j) == 0) {
        if (s->sid_ctx_length != s->session->sid_ctx_length
            || memcmp(s->session->sid_ctx, s->sid_ctx, s->sid_ctx_length)) {
            /* actually a client application bug */
            al = SSL_AD_ILLEGAL_PARAMETER;
            SSLerr(SSL_F_SSL3_GET_SERVER_HELLO,
                   SSL_R_ATTEMPT_TO_REUSE_SESSION_IN_DIFFERENT_CONTEXT);
            goto f_err;
        }
        s->hit = 1;
    } else {
        /*
         * If we were trying for session-id reuse but the server
         * didn't echo the ID, make a new SSL_SESSION.
         * In the case of EAP-FAST and PAC, we do not send a session ID,
         * so the PAC-based session secret is always preserved. It'll be
         * overwritten if the server refuses resumption.
         */
        if (s->session->session_id_length > 0) {
            if (!ssl_get_new_session(s, 0)) {
                goto f_err;
            }
        }
        s->session->session_id_length = j;
        memcpy(s->session->session_id, p, j); /* j could be 0 */
    }
    p += j;
    c = ssl_get_cipher_by_char(s, p);
    if (c == NULL) {
        /* unknown cipher */
        al = SSL_AD_ILLEGAL_PARAMETER;
        SSLerr(SSL_F_SSL3_GET_SERVER_HELLO, SSL_R_UNKNOWN_CIPHER_RETURNED);
        goto f_err;
    }
    /* Set version disabled mask now we know version */
    if (!SSL_USE_TLS1_2_CIPHERS(s))
        ct->mask_ssl = SSL_TLSV1_2;
    else
        ct->mask_ssl = 0;
    /*
     * If it is a disabled cipher we didn't send it in client hello, so
     * return an error.
     */
    if (c->algorithm_ssl & ct->mask_ssl ||
        c->algorithm_mkey & ct->mask_k || c->algorithm_auth & ct->mask_a) {
        al = SSL_AD_ILLEGAL_PARAMETER;
        SSLerr(SSL_F_SSL3_GET_SERVER_HELLO, SSL_R_WRONG_CIPHER_RETURNED);
        goto f_err;
    }
    p += ssl_put_cipher_by_char(s, NULL, NULL);

    sk = ssl_get_ciphers_by_id(s);
    i = sk_SSL_CIPHER_find(sk, c);
    if (i < 0) {
        /* we did not say we would use this cipher */
        al = SSL_AD_ILLEGAL_PARAMETER;
        SSLerr(SSL_F_SSL3_GET_SERVER_HELLO, SSL_R_WRONG_CIPHER_RETURNED);
        goto f_err;
    }

    /*
     * Depending on the session caching (internal/external), the cipher
     * and/or cipher_id values may not be set. Make sure that cipher_id is
     * set and use it for comparison.
     */
    if (s->session->cipher)
        s->session->cipher_id = s->session->cipher->id;
    if (s->hit && (s->session->cipher_id != c->id)) {
/* Workaround is now obsolete */
#if 0
        if (!(s->options & SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG))
#endif
        {
            al = SSL_AD_ILLEGAL_PARAMETER;
            SSLerr(SSL_F_SSL3_GET_SERVER_HELLO,
                   SSL_R_OLD_SESSION_CIPHER_NOT_RETURNED);
            goto f_err;
        }
    }
    s->s3->tmp.new_cipher = c;
    /*
     * Don't digest cached records if no sigalgs: we may need them for client
     * authentication.
     */
    if (!SSL_USE_SIGALGS(s) && !ssl3_digest_cached_records(s))
        goto f_err;
    /* lets get the compression algorithm */
    /* COMPRESSION */
#ifdef OPENSSL_NO_COMP
    if (*(p++) != 0) {
        al = SSL_AD_ILLEGAL_PARAMETER;
        SSLerr(SSL_F_SSL3_GET_SERVER_HELLO,
               SSL_R_UNSUPPORTED_COMPRESSION_ALGORITHM);
        goto f_err;
    }
    /*
     * If compression is disabled we'd better not try to resume a session
     * using compression.
     */
    if (s->session->compress_meth != 0) {
        SSLerr(SSL_F_SSL3_GET_SERVER_HELLO, SSL_R_INCONSISTENT_COMPRESSION);
        goto f_err;
    }
#else
    j = *(p++);
    if (s->hit && j != s->session->compress_meth) {
        al = SSL_AD_ILLEGAL_PARAMETER;
        SSLerr(SSL_F_SSL3_GET_SERVER_HELLO,
               SSL_R_OLD_SESSION_COMPRESSION_ALGORITHM_NOT_RETURNED);
        goto f_err;
    }
    if (j == 0)
        comp = NULL;
    else if (s->options & SSL_OP_NO_COMPRESSION) {
        al = SSL_AD_ILLEGAL_PARAMETER;
        SSLerr(SSL_F_SSL3_GET_SERVER_HELLO, SSL_R_COMPRESSION_DISABLED);
        goto f_err;
    } else
        comp = ssl3_comp_find(s->ctx->comp_methods, j);

    if ((j != 0) && (comp == NULL)) {
        al = SSL_AD_ILLEGAL_PARAMETER;
        SSLerr(SSL_F_SSL3_GET_SERVER_HELLO,
               SSL_R_UNSUPPORTED_COMPRESSION_ALGORITHM);
        goto f_err;
    } else {
        s->s3->tmp.new_compression = comp;
    }
#endif

#ifndef OPENSSL_NO_TLSEXT
    /* TLS extensions */
    if (!ssl_parse_serverhello_tlsext(s, &p, d, n)) {
        SSLerr(SSL_F_SSL3_GET_SERVER_HELLO, SSL_R_PARSE_TLSEXT);
        goto err;
    }
#endif

    if (p != (d + n)) {
        /* wrong packet length */
        al = SSL_AD_DECODE_ERROR;
        SSLerr(SSL_F_SSL3_GET_SERVER_HELLO, SSL_R_BAD_PACKET_LENGTH);
        goto f_err;
    }

    return (1);
 f_err:
    ssl3_send_alert(s, SSL3_AL_FATAL, al);
 err:
    s->state = SSL_ST_ERR;
    return (-1);
}

int ssl3_get_server_certificate(SSL *s)
{
    int al, i, ok, ret = -1;
    unsigned long n, nc, llen, l;
    X509 *x = NULL;
    const unsigned char *q, *p;
    unsigned char *d;
    STACK_OF(X509) *sk = NULL;
    SESS_CERT *sc;
    EVP_PKEY *pkey = NULL;
    int need_cert = 1;          /* VRS: 0=> will allow null cert if auth ==
                                 * KRB5 */

    n = s->method->ssl_get_message(s,
                                   SSL3_ST_CR_CERT_A,
                                   SSL3_ST_CR_CERT_B,
                                   -1, s->max_cert_list, &ok);

    if (!ok)
        return ((int)n);

    if ((s->s3->tmp.message_type == SSL3_MT_SERVER_KEY_EXCHANGE) ||
        ((s->s3->tmp.new_cipher->algorithm_auth & SSL_aKRB5) &&
         (s->s3->tmp.message_type == SSL3_MT_SERVER_DONE))) {
        s->s3->tmp.reuse_message = 1;
        return (1);
    }

    if (s->s3->tmp.message_type != SSL3_MT_CERTIFICATE) {
        al = SSL_AD_UNEXPECTED_MESSAGE;
        SSLerr(SSL_F_SSL3_GET_SERVER_CERTIFICATE, SSL_R_BAD_MESSAGE_TYPE);
        goto f_err;
    }
    p = d = (unsigned char *)s->init_msg;

    if ((sk = sk_X509_new_null()) == NULL) {
        SSLerr(SSL_F_SSL3_GET_SERVER_CERTIFICATE, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    n2l3(p, llen);
    if (llen + 3 != n) {
        al = SSL_AD_DECODE_ERROR;
        SSLerr(SSL_F_SSL3_GET_SERVER_CERTIFICATE, SSL_R_LENGTH_MISMATCH);
        goto f_err;
    }
    for (nc = 0; nc < llen;) {
        if (nc + 3 > llen) {
            al = SSL_AD_DECODE_ERROR;
            SSLerr(SSL_F_SSL3_GET_SERVER_CERTIFICATE,
                   SSL_R_CERT_LENGTH_MISMATCH);
            goto f_err;
        }
        n2l3(p, l);
        if ((l + nc + 3) > llen) {
            al = SSL_AD_DECODE_ERROR;
            SSLerr(SSL_F_SSL3_GET_SERVER_CERTIFICATE,
                   SSL_R_CERT_LENGTH_MISMATCH);
            goto f_err;
        }

        q = p;
        x = d2i_X509(NULL, &q, l);
        if (x == NULL) {
            al = SSL_AD_BAD_CERTIFICATE;
            SSLerr(SSL_F_SSL3_GET_SERVER_CERTIFICATE, ERR_R_ASN1_LIB);
            goto f_err;
        }
        if (q != (p + l)) {
            al = SSL_AD_DECODE_ERROR;
            SSLerr(SSL_F_SSL3_GET_SERVER_CERTIFICATE,
                   SSL_R_CERT_LENGTH_MISMATCH);
            goto f_err;
        }
        if (!sk_X509_push(sk, x)) {
            SSLerr(SSL_F_SSL3_GET_SERVER_CERTIFICATE, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        x = NULL;
        nc += l + 3;
        p = q;
    }

    i = ssl_verify_cert_chain(s, sk);
    if ((s->verify_mode != SSL_VERIFY_NONE) && (i <= 0)
#ifndef OPENSSL_NO_KRB5
        && !((s->s3->tmp.new_cipher->algorithm_mkey & SSL_kKRB5) &&
             (s->s3->tmp.new_cipher->algorithm_auth & SSL_aKRB5))
#endif                          /* OPENSSL_NO_KRB5 */
        ) {
        al = ssl_verify_alarm_type(s->verify_result);
        SSLerr(SSL_F_SSL3_GET_SERVER_CERTIFICATE,
               SSL_R_CERTIFICATE_VERIFY_FAILED);
        goto f_err;
    }
    ERR_clear_error();          /* but we keep s->verify_result */

    sc = ssl_sess_cert_new();
    if (sc == NULL)
        goto err;

    if (s->session->sess_cert)
        ssl_sess_cert_free(s->session->sess_cert);
    s->session->sess_cert = sc;

    sc->cert_chain = sk;
    /*
     * Inconsistency alert: cert_chain does include the peer's certificate,
     * which we don't include in s3_srvr.c
     */
    x = sk_X509_value(sk, 0);
    sk = NULL;
    /*
     * VRS 19990621: possible memory leak; sk=null ==> !sk_pop_free() @end
     */

    pkey = X509_get_pubkey(x);

    /* VRS: allow null cert if auth == KRB5 */
    need_cert = ((s->s3->tmp.new_cipher->algorithm_mkey & SSL_kKRB5) &&
                 (s->s3->tmp.new_cipher->algorithm_auth & SSL_aKRB5))
        ? 0 : 1;

#ifdef KSSL_DEBUG
    fprintf(stderr, "pkey,x = %p, %p\n", pkey, x);
    fprintf(stderr, "ssl_cert_type(x,pkey) = %d\n", ssl_cert_type(x, pkey));
    fprintf(stderr, "cipher, alg, nc = %s, %lx, %lx, %d\n",
            s->s3->tmp.new_cipher->name,
            s->s3->tmp.new_cipher->algorithm_mkey,
            s->s3->tmp.new_cipher->algorithm_auth, need_cert);
#endif                          /* KSSL_DEBUG */

    if (need_cert && ((pkey == NULL) || EVP_PKEY_missing_parameters(pkey))) {
        x = NULL;
        al = SSL3_AL_FATAL;
        SSLerr(SSL_F_SSL3_GET_SERVER_CERTIFICATE,
               SSL_R_UNABLE_TO_FIND_PUBLIC_KEY_PARAMETERS);
        goto f_err;
    }

    i = ssl_cert_type(x, pkey);
    if (need_cert && i < 0) {
        x = NULL;
        al = SSL3_AL_FATAL;
        SSLerr(SSL_F_SSL3_GET_SERVER_CERTIFICATE,
               SSL_R_UNKNOWN_CERTIFICATE_TYPE);
        goto f_err;
    }

    if (need_cert) {
        int exp_idx = ssl_cipher_get_cert_index(s->s3->tmp.new_cipher);
        if (exp_idx >= 0 && i != exp_idx) {
            x = NULL;
            al = SSL_AD_ILLEGAL_PARAMETER;
            SSLerr(SSL_F_SSL3_GET_SERVER_CERTIFICATE,
                   SSL_R_WRONG_CERTIFICATE_TYPE);
            goto f_err;
        }
        sc->peer_cert_type = i;
        CRYPTO_add(&x->references, 1, CRYPTO_LOCK_X509);
        /*
         * Why would the following ever happen? We just created sc a couple
         * of lines ago.
         */
        if (sc->peer_pkeys[i].x509 != NULL)
            X509_free(sc->peer_pkeys[i].x509);
        sc->peer_pkeys[i].x509 = x;
        sc->peer_key = &(sc->peer_pkeys[i]);

        if (s->session->peer != NULL)
            X509_free(s->session->peer);
        CRYPTO_add(&x->references, 1, CRYPTO_LOCK_X509);
        s->session->peer = x;
    } else {
        sc->peer_cert_type = i;
        sc->peer_key = NULL;

        if (s->session->peer != NULL)
            X509_free(s->session->peer);
        s->session->peer = NULL;
    }
    s->session->verify_result = s->verify_result;

    x = NULL;
    ret = 1;
    if (0) {
 f_err:
        ssl3_send_alert(s, SSL3_AL_FATAL, al);
 err:
        s->state = SSL_ST_ERR;
    }

    EVP_PKEY_free(pkey);
    X509_free(x);
    sk_X509_pop_free(sk, X509_free);
    return (ret);
}

int ssl3_get_key_exchange(SSL *s)
{
#ifndef OPENSSL_NO_RSA
    unsigned char *q, md_buf[EVP_MAX_MD_SIZE * 2];
#endif
    EVP_MD_CTX md_ctx;
    unsigned char *param, *p;
    int al, j, ok;
    long i, param_len, n, alg_k, alg_a;
    EVP_PKEY *pkey = NULL;
    const EVP_MD *md = NULL;
#ifndef OPENSSL_NO_RSA
    RSA *rsa = NULL;
#endif
#ifndef OPENSSL_NO_DH
    DH *dh = NULL;
#endif
#ifndef OPENSSL_NO_ECDH
    EC_KEY *ecdh = NULL;
    BN_CTX *bn_ctx = NULL;
    EC_POINT *srvr_ecpoint = NULL;
    int curve_nid = 0;
    int encoded_pt_len = 0;
#endif

    EVP_MD_CTX_init(&md_ctx);

    /*
     * use same message size as in ssl3_get_certificate_request() as
     * ServerKeyExchange message may be skipped
     */
    n = s->method->ssl_get_message(s,
                                   SSL3_ST_CR_KEY_EXCH_A,
                                   SSL3_ST_CR_KEY_EXCH_B,
                                   -1, s->max_cert_list, &ok);
    if (!ok)
        return ((int)n);

    alg_k = s->s3->tmp.new_cipher->algorithm_mkey;

    if (s->s3->tmp.message_type != SSL3_MT_SERVER_KEY_EXCHANGE) {
        /*
         * Can't skip server key exchange if this is an ephemeral
         * ciphersuite.
         */
        if (alg_k & (SSL_kDHE | SSL_kECDHE)) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_UNEXPECTED_MESSAGE);
            al = SSL_AD_UNEXPECTED_MESSAGE;
            goto f_err;
        }
#ifndef OPENSSL_NO_PSK
        /*
         * In plain PSK ciphersuite, ServerKeyExchange can be omitted if no
         * identity hint is sent. Set session->sess_cert anyway to avoid
         * problems later.
         */
        if (alg_k & SSL_kPSK) {
            s->session->sess_cert = ssl_sess_cert_new();
            if (s->ctx->psk_identity_hint)
                OPENSSL_free(s->ctx->psk_identity_hint);
            s->ctx->psk_identity_hint = NULL;
        }
#endif
        s->s3->tmp.reuse_message = 1;
        return (1);
    }

    param = p = (unsigned char *)s->init_msg;
    if (s->session->sess_cert != NULL) {
#ifndef OPENSSL_NO_RSA
        if (s->session->sess_cert->peer_rsa_tmp != NULL) {
            RSA_free(s->session->sess_cert->peer_rsa_tmp);
            s->session->sess_cert->peer_rsa_tmp = NULL;
        }
#endif
#ifndef OPENSSL_NO_DH
        if (s->session->sess_cert->peer_dh_tmp) {
            DH_free(s->session->sess_cert->peer_dh_tmp);
            s->session->sess_cert->peer_dh_tmp = NULL;
        }
#endif
#ifndef OPENSSL_NO_ECDH
        if (s->session->sess_cert->peer_ecdh_tmp) {
            EC_KEY_free(s->session->sess_cert->peer_ecdh_tmp);
            s->session->sess_cert->peer_ecdh_tmp = NULL;
        }
#endif
    } else {
        s->session->sess_cert = ssl_sess_cert_new();
    }

    /* Total length of the parameters including the length prefix */
    param_len = 0;

    alg_a = s->s3->tmp.new_cipher->algorithm_auth;

    al = SSL_AD_DECODE_ERROR;

#ifndef OPENSSL_NO_PSK
    if (alg_k & SSL_kPSK) {
        param_len = 2;
        if (param_len > n) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_LENGTH_TOO_SHORT);
            goto f_err;
        }
        n2s(p, i);

        /*
         * Store PSK identity hint for later use, hint is used in
         * ssl3_send_client_key_exchange.  Assume that the maximum length of
         * a PSK identity hint can be as long as the maximum length of a PSK
         * identity.
         */
        if (i > PSK_MAX_IDENTITY_LEN) {
            al = SSL_AD_HANDSHAKE_FAILURE;
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_DATA_LENGTH_TOO_LONG);
            goto f_err;
        }
        if (i > n - param_len) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,
                   SSL_R_BAD_PSK_IDENTITY_HINT_LENGTH);
            goto f_err;
        }
        param_len += i;

        s->session->psk_identity_hint = BUF_strndup((char *)p, i);
        if (s->session->psk_identity_hint == NULL) {
            al = SSL_AD_HANDSHAKE_FAILURE;
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, ERR_R_MALLOC_FAILURE);
            goto f_err;
        }

        p += i;
        n -= param_len;
    } else
#endif                          /* !OPENSSL_NO_PSK */
#ifndef OPENSSL_NO_SRP
    if (alg_k & SSL_kSRP) {
        param_len = 2;
        if (param_len > n) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_LENGTH_TOO_SHORT);
            goto f_err;
        }
        n2s(p, i);

        if (i > n - param_len) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_BAD_SRP_N_LENGTH);
            goto f_err;
        }
        param_len += i;

        if (!(s->srp_ctx.N = BN_bin2bn(p, i, NULL))) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, ERR_R_BN_LIB);
            goto err;
        }
        p += i;

        if (2 > n - param_len) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_LENGTH_TOO_SHORT);
            goto f_err;
        }
        param_len += 2;

        n2s(p, i);

        if (i > n - param_len) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_BAD_SRP_G_LENGTH);
            goto f_err;
        }
        param_len += i;

        if (!(s->srp_ctx.g = BN_bin2bn(p, i, NULL))) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, ERR_R_BN_LIB);
            goto err;
        }
        p += i;

        if (1 > n - param_len) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_LENGTH_TOO_SHORT);
            goto f_err;
        }
        param_len += 1;

        i = (unsigned int)(p[0]);
        p++;

        if (i > n - param_len) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_BAD_SRP_S_LENGTH);
            goto f_err;
        }
        param_len += i;

        if (!(s->srp_ctx.s = BN_bin2bn(p, i, NULL))) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, ERR_R_BN_LIB);
            goto err;
        }
        p += i;

        if (2 > n - param_len) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_LENGTH_TOO_SHORT);
            goto f_err;
        }
        param_len += 2;

        n2s(p, i);

        if (i > n - param_len) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_BAD_SRP_B_LENGTH);
            goto f_err;
        }
        param_len += i;

        if (!(s->srp_ctx.B = BN_bin2bn(p, i, NULL))) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, ERR_R_BN_LIB);
            goto err;
        }
        p += i;
        n -= param_len;

        if (!srp_verify_server_param(s, &al)) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_BAD_SRP_PARAMETERS);
            goto f_err;
        }

/* We must check if there is a certificate */
# ifndef OPENSSL_NO_RSA
        if (alg_a & SSL_aRSA)
            pkey =
                X509_get_pubkey(s->session->
                                sess_cert->peer_pkeys[SSL_PKEY_RSA_ENC].x509);
# else
        if (0) ;
# endif
# ifndef OPENSSL_NO_DSA
        else if (alg_a & SSL_aDSS)
            pkey =
                X509_get_pubkey(s->session->
                                sess_cert->peer_pkeys[SSL_PKEY_DSA_SIGN].
                                x509);
# endif
    } else
#endif                          /* !OPENSSL_NO_SRP */
#ifndef OPENSSL_NO_RSA
    if (alg_k & SSL_kRSA) {
        /* Temporary RSA keys only allowed in export ciphersuites */
        if (!SSL_C_IS_EXPORT(s->s3->tmp.new_cipher)) {
            al = SSL_AD_UNEXPECTED_MESSAGE;
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_UNEXPECTED_MESSAGE);
            goto f_err;
        }
        if ((rsa = RSA_new()) == NULL) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, ERR_R_MALLOC_FAILURE);
            goto err;
        }

        param_len = 2;
        if (param_len > n) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_LENGTH_TOO_SHORT);
            goto f_err;
        }
        n2s(p, i);

        if (i > n - param_len) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_BAD_RSA_MODULUS_LENGTH);
            goto f_err;
        }
        param_len += i;

        if (!(rsa->n = BN_bin2bn(p, i, rsa->n))) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, ERR_R_BN_LIB);
            goto err;
        }
        p += i;

        if (2 > n - param_len) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_LENGTH_TOO_SHORT);
            goto f_err;
        }
        param_len += 2;

        n2s(p, i);

        if (i > n - param_len) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_BAD_RSA_E_LENGTH);
            goto f_err;
        }
        param_len += i;

        if (!(rsa->e = BN_bin2bn(p, i, rsa->e))) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, ERR_R_BN_LIB);
            goto err;
        }
        p += i;
        n -= param_len;

        /* this should be because we are using an export cipher */
        if (alg_a & SSL_aRSA)
            pkey =
                X509_get_pubkey(s->session->
                                sess_cert->peer_pkeys[SSL_PKEY_RSA_ENC].x509);
        else {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, ERR_R_INTERNAL_ERROR);
            goto err;
        }

        if (EVP_PKEY_bits(pkey) <= SSL_C_EXPORT_PKEYLENGTH(s->s3->tmp.new_cipher)) {
            al = SSL_AD_UNEXPECTED_MESSAGE;
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_UNEXPECTED_MESSAGE);
            goto f_err;
        }

        s->session->sess_cert->peer_rsa_tmp = rsa;
        rsa = NULL;
    }
#else                           /* OPENSSL_NO_RSA */
    if (0) ;
#endif
#ifndef OPENSSL_NO_DH
    else if (alg_k & SSL_kEDH) {
        if ((dh = DH_new()) == NULL) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, ERR_R_DH_LIB);
            goto err;
        }

        param_len = 2;
        if (param_len > n) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_LENGTH_TOO_SHORT);
            goto f_err;
        }
        n2s(p, i);

        if (i > n - param_len) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_BAD_DH_P_LENGTH);
            goto f_err;
        }
        param_len += i;

        if (!(dh->p = BN_bin2bn(p, i, NULL))) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, ERR_R_BN_LIB);
            goto err;
        }
        p += i;

        if (2 > n - param_len) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_LENGTH_TOO_SHORT);
            goto f_err;
        }
        param_len += 2;

        n2s(p, i);

        if (i > n - param_len) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_BAD_DH_G_LENGTH);
            goto f_err;
        }
        param_len += i;

        if (!(dh->g = BN_bin2bn(p, i, NULL))) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, ERR_R_BN_LIB);
            goto err;
        }
        p += i;

        if (2 > n - param_len) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_LENGTH_TOO_SHORT);
            goto f_err;
        }
        param_len += 2;

        n2s(p, i);

        if (i > n - param_len) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_BAD_DH_PUB_KEY_LENGTH);
            goto f_err;
        }
        param_len += i;

        if (!(dh->pub_key = BN_bin2bn(p, i, NULL))) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, ERR_R_BN_LIB);
            goto err;
        }
        p += i;
        n -= param_len;

        if (BN_is_zero(dh->pub_key)) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_BAD_DH_PUB_KEY_VALUE);
            goto f_err;
        }

        /*-
         * Check that p and g are suitable enough
         *
         * p is odd
         * 1 < g < p - 1
         */
        {
            BIGNUM *tmp = NULL;

            if (!BN_is_odd(dh->p)) {
                SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_BAD_DH_P_VALUE);
                goto f_err;
            }
            if (BN_is_negative(dh->g) || BN_is_zero(dh->g)
                || BN_is_one(dh->g)) {
                SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_BAD_DH_G_VALUE);
                goto f_err;
            }
            if ((tmp = BN_new()) == NULL
                || BN_copy(tmp, dh->p) == NULL
                || !BN_sub_word(tmp, 1)) {
                BN_free(tmp);
                SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, ERR_R_BN_LIB);
                goto err;
            }
            if (BN_cmp(dh->g, tmp) >= 0) {
                BN_free(tmp);
                SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_BAD_DH_G_VALUE);
                goto f_err;
            }
            BN_free(tmp);
        }

# ifndef OPENSSL_NO_RSA
        if (alg_a & SSL_aRSA)
            pkey =
                X509_get_pubkey(s->session->
                                sess_cert->peer_pkeys[SSL_PKEY_RSA_ENC].x509);
# else
        if (0) ;
# endif
# ifndef OPENSSL_NO_DSA
        else if (alg_a & SSL_aDSS)
            pkey =
                X509_get_pubkey(s->session->
                                sess_cert->peer_pkeys[SSL_PKEY_DSA_SIGN].
                                x509);
# endif
        /* else anonymous DH, so no certificate or pkey. */

        s->session->sess_cert->peer_dh_tmp = dh;
        dh = NULL;
    } else if ((alg_k & SSL_kDHr) || (alg_k & SSL_kDHd)) {
        al = SSL_AD_ILLEGAL_PARAMETER;
        SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,
               SSL_R_TRIED_TO_USE_UNSUPPORTED_CIPHER);
        goto f_err;
    }
#endif                          /* !OPENSSL_NO_DH */

#ifndef OPENSSL_NO_ECDH
    else if (alg_k & SSL_kEECDH) {
        EC_GROUP *ngroup;
        const EC_GROUP *group;

        if ((ecdh = EC_KEY_new()) == NULL) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, ERR_R_MALLOC_FAILURE);
            goto err;
        }

        /*
         * Extract elliptic curve parameters and the server's ephemeral ECDH
         * public key. Keep accumulating lengths of various components in
         * param_len and make sure it never exceeds n.
         */

        /*
         * XXX: For now we only support named (not generic) curves and the
         * ECParameters in this case is just three bytes. We also need one
         * byte for the length of the encoded point
         */
        param_len = 4;
        if (param_len > n) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_LENGTH_TOO_SHORT);
            goto f_err;
        }
        /*
         * Check curve is one of our preferences, if not server has sent an
         * invalid curve. ECParameters is 3 bytes.
         */
        if (!tls1_check_curve(s, p, 3)) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_WRONG_CURVE);
            goto f_err;
        }

        if ((curve_nid = tls1_ec_curve_id2nid(*(p + 2))) == 0) {
            al = SSL_AD_INTERNAL_ERROR;
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,
                   SSL_R_UNABLE_TO_FIND_ECDH_PARAMETERS);
            goto f_err;
        }

        ngroup = EC_GROUP_new_by_curve_name(curve_nid);
        if (ngroup == NULL) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, ERR_R_EC_LIB);
            goto err;
        }
        if (EC_KEY_set_group(ecdh, ngroup) == 0) {
            EC_GROUP_free(ngroup);
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, ERR_R_EC_LIB);
            goto err;
        }
        EC_GROUP_free(ngroup);

        group = EC_KEY_get0_group(ecdh);

        if (SSL_C_IS_EXPORT(s->s3->tmp.new_cipher) &&
            (EC_GROUP_get_degree(group) > 163)) {
            al = SSL_AD_EXPORT_RESTRICTION;
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,
                   SSL_R_ECGROUP_TOO_LARGE_FOR_CIPHER);
            goto f_err;
        }

        p += 3;

        /* Next, get the encoded ECPoint */
        if (((srvr_ecpoint = EC_POINT_new(group)) == NULL) ||
            ((bn_ctx = BN_CTX_new()) == NULL)) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, ERR_R_MALLOC_FAILURE);
            goto err;
        }

        encoded_pt_len = *p;    /* length of encoded point */
        p += 1;

        if ((encoded_pt_len > n - param_len) ||
            (EC_POINT_oct2point(group, srvr_ecpoint,
                                p, encoded_pt_len, bn_ctx) == 0)) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_BAD_ECPOINT);
            goto f_err;
        }
        param_len += encoded_pt_len;

        n -= param_len;
        p += encoded_pt_len;

        /*
         * The ECC/TLS specification does not mention the use of DSA to sign
         * ECParameters in the server key exchange message. We do support RSA
         * and ECDSA.
         */
        if (0) ;
# ifndef OPENSSL_NO_RSA
        else if (alg_a & SSL_aRSA)
            pkey =
                X509_get_pubkey(s->session->
                                sess_cert->peer_pkeys[SSL_PKEY_RSA_ENC].x509);
# endif
# ifndef OPENSSL_NO_ECDSA
        else if (alg_a & SSL_aECDSA)
            pkey =
                X509_get_pubkey(s->session->
                                sess_cert->peer_pkeys[SSL_PKEY_ECC].x509);
# endif
        /* else anonymous ECDH, so no certificate or pkey. */
        EC_KEY_set_public_key(ecdh, srvr_ecpoint);
        s->session->sess_cert->peer_ecdh_tmp = ecdh;
        ecdh = NULL;
        BN_CTX_free(bn_ctx);
        bn_ctx = NULL;
        EC_POINT_free(srvr_ecpoint);
        srvr_ecpoint = NULL;
    } else if (alg_k) {
        al = SSL_AD_UNEXPECTED_MESSAGE;
        SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_UNEXPECTED_MESSAGE);
        goto f_err;
    }
#endif                          /* !OPENSSL_NO_ECDH */

    /* p points to the next byte, there are 'n' bytes left */

    /* if it was signed, check the signature */
    if (pkey != NULL) {
        if (SSL_USE_SIGALGS(s)) {
            int rv;
            if (2 > n) {
                SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_LENGTH_TOO_SHORT);
                goto f_err;
            }
            rv = tls12_check_peer_sigalg(&md, s, p, pkey);
            if (rv == -1)
                goto err;
            else if (rv == 0) {
                goto f_err;
            }
#ifdef SSL_DEBUG
            fprintf(stderr, "USING TLSv1.2 HASH %s\n", EVP_MD_name(md));
#endif
            p += 2;
            n -= 2;
        } else
            md = EVP_sha1();

        if (2 > n) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_LENGTH_TOO_SHORT);
            goto f_err;
        }
        n2s(p, i);
        n -= 2;
        j = EVP_PKEY_size(pkey);

        /*
         * Check signature length. If n is 0 then signature is empty
         */
        if ((i != n) || (n > j) || (n <= 0)) {
            /* wrong packet length */
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_WRONG_SIGNATURE_LENGTH);
            goto f_err;
        }
#ifndef OPENSSL_NO_RSA
        if (pkey->type == EVP_PKEY_RSA && !SSL_USE_SIGALGS(s)) {
            int num;
            unsigned int size;

            j = 0;
            q = md_buf;
            for (num = 2; num > 0; num--) {
                EVP_MD_CTX_set_flags(&md_ctx, EVP_MD_CTX_FLAG_NON_FIPS_ALLOW);
                if (EVP_DigestInit_ex(&md_ctx,
                                      (num == 2) ? s->ctx->md5 : s->ctx->sha1,
                                      NULL) <= 0
                        || EVP_DigestUpdate(&md_ctx, &(s->s3->client_random[0]),
                                            SSL3_RANDOM_SIZE) <= 0
                        || EVP_DigestUpdate(&md_ctx, &(s->s3->server_random[0]),
                                            SSL3_RANDOM_SIZE) <= 0
                        || EVP_DigestUpdate(&md_ctx, param, param_len) <= 0
                        || EVP_DigestFinal_ex(&md_ctx, q, &size) <= 0) {
                    SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,
                           ERR_R_INTERNAL_ERROR);
                    al = SSL_AD_INTERNAL_ERROR;
                    goto f_err;
                }
                q += size;
                j += size;
            }
            i = RSA_verify(NID_md5_sha1, md_buf, j, p, n, pkey->pkey.rsa);
            if (i < 0) {
                al = SSL_AD_DECRYPT_ERROR;
                SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_BAD_RSA_DECRYPT);
                goto f_err;
            }
            if (i == 0) {
                /* bad signature */
                al = SSL_AD_DECRYPT_ERROR;
                SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_BAD_SIGNATURE);
                goto f_err;
            }
        } else
#endif
        {
            if (EVP_VerifyInit_ex(&md_ctx, md, NULL) <= 0
                    || EVP_VerifyUpdate(&md_ctx, &(s->s3->client_random[0]),
                                        SSL3_RANDOM_SIZE) <= 0
                    || EVP_VerifyUpdate(&md_ctx, &(s->s3->server_random[0]),
                                        SSL3_RANDOM_SIZE) <= 0
                    || EVP_VerifyUpdate(&md_ctx, param, param_len) <= 0) {
                al = SSL_AD_INTERNAL_ERROR;
                SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, ERR_R_EVP_LIB);
                goto f_err;
            }
            if (EVP_VerifyFinal(&md_ctx, p, (int)n, pkey) <= 0) {
                /* bad signature */
                al = SSL_AD_DECRYPT_ERROR;
                SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_BAD_SIGNATURE);
                goto f_err;
            }
        }
    } else {
        /* aNULL, aSRP or kPSK do not need public keys */
        if (!(alg_a & (SSL_aNULL | SSL_aSRP)) && !(alg_k & SSL_kPSK)) {
            /* Might be wrong key type, check it */
            if (ssl3_check_cert_and_algorithm(s))
                /* Otherwise this shouldn't happen */
                SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        /* still data left over */
        if (n != 0) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_EXTRA_DATA_IN_MESSAGE);
            goto f_err;
        }
    }
    EVP_PKEY_free(pkey);
    EVP_MD_CTX_cleanup(&md_ctx);
    return (1);
 f_err:
    ssl3_send_alert(s, SSL3_AL_FATAL, al);
 err:
    EVP_PKEY_free(pkey);
#ifndef OPENSSL_NO_RSA
    if (rsa != NULL)
        RSA_free(rsa);
#endif
#ifndef OPENSSL_NO_DH
    if (dh != NULL)
        DH_free(dh);
#endif
#ifndef OPENSSL_NO_ECDH
    BN_CTX_free(bn_ctx);
    EC_POINT_free(srvr_ecpoint);
    if (ecdh != NULL)
        EC_KEY_free(ecdh);
#endif
    EVP_MD_CTX_cleanup(&md_ctx);
    s->state = SSL_ST_ERR;
    return (-1);
}

int ssl3_get_certificate_request(SSL *s)
{
    int ok, ret = 0;
    unsigned long n, nc, l;
    unsigned int llen, ctype_num, i;
    X509_NAME *xn = NULL;
    const unsigned char *p, *q;
    unsigned char *d;
    STACK_OF(X509_NAME) *ca_sk = NULL;

    n = s->method->ssl_get_message(s,
                                   SSL3_ST_CR_CERT_REQ_A,
                                   SSL3_ST_CR_CERT_REQ_B,
                                   -1, s->max_cert_list, &ok);

    if (!ok)
        return ((int)n);

    s->s3->tmp.cert_req = 0;

    if (s->s3->tmp.message_type == SSL3_MT_SERVER_DONE) {
        s->s3->tmp.reuse_message = 1;
        /*
         * If we get here we don't need any cached handshake records as we
         * wont be doing client auth.
         */
        if (s->s3->handshake_buffer) {
            if (!ssl3_digest_cached_records(s))
                goto err;
        }
        return (1);
    }

    if (s->s3->tmp.message_type != SSL3_MT_CERTIFICATE_REQUEST) {
        ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_UNEXPECTED_MESSAGE);
        SSLerr(SSL_F_SSL3_GET_CERTIFICATE_REQUEST, SSL_R_WRONG_MESSAGE_TYPE);
        goto err;
    }

    /* TLS does not like anon-DH with client cert */
    if (s->version > SSL3_VERSION) {
        if (s->s3->tmp.new_cipher->algorithm_auth & SSL_aNULL) {
            ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_UNEXPECTED_MESSAGE);
            SSLerr(SSL_F_SSL3_GET_CERTIFICATE_REQUEST,
                   SSL_R_TLS_CLIENT_CERT_REQ_WITH_ANON_CIPHER);
            goto err;
        }
    }

    p = d = (unsigned char *)s->init_msg;

    if ((ca_sk = sk_X509_NAME_new(ca_dn_cmp)) == NULL) {
        SSLerr(SSL_F_SSL3_GET_CERTIFICATE_REQUEST, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    /* get the certificate types */
    ctype_num = *(p++);
    if (s->cert->ctypes) {
        OPENSSL_free(s->cert->ctypes);
        s->cert->ctypes = NULL;
    }
    if (ctype_num > SSL3_CT_NUMBER) {
        /* If we exceed static buffer copy all to cert structure */
        s->cert->ctypes = OPENSSL_malloc(ctype_num);
        if (s->cert->ctypes == NULL) {
            SSLerr(SSL_F_SSL3_GET_CERTIFICATE_REQUEST, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        memcpy(s->cert->ctypes, p, ctype_num);
        s->cert->ctype_num = (size_t)ctype_num;
        ctype_num = SSL3_CT_NUMBER;
    }
    for (i = 0; i < ctype_num; i++)
        s->s3->tmp.ctype[i] = p[i];
    p += p[-1];
    if (SSL_USE_SIGALGS(s)) {
        n2s(p, llen);
        /*
         * Check we have enough room for signature algorithms and following
         * length value.
         */
        if ((unsigned long)(p - d + llen + 2) > n) {
            ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
            SSLerr(SSL_F_SSL3_GET_CERTIFICATE_REQUEST,
                   SSL_R_DATA_LENGTH_TOO_LONG);
            goto err;
        }
        /* Clear certificate digests and validity flags */
        for (i = 0; i < SSL_PKEY_NUM; i++) {
            s->cert->pkeys[i].digest = NULL;
            s->cert->pkeys[i].valid_flags = 0;
        }
        if ((llen & 1) || !tls1_save_sigalgs(s, p, llen)) {
            ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
            SSLerr(SSL_F_SSL3_GET_CERTIFICATE_REQUEST,
                   SSL_R_SIGNATURE_ALGORITHMS_ERROR);
            goto err;
        }
        if (!tls1_process_sigalgs(s)) {
            ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_INTERNAL_ERROR);
            SSLerr(SSL_F_SSL3_GET_CERTIFICATE_REQUEST, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        p += llen;
    }

    /* get the CA RDNs */
    n2s(p, llen);
#if 0
    {
        FILE *out;
        out = fopen("/tmp/vsign.der", "w");
        fwrite(p, 1, llen, out);
        fclose(out);
    }
#endif

    if ((unsigned long)(p - d + llen) != n) {
        ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
        SSLerr(SSL_F_SSL3_GET_CERTIFICATE_REQUEST, SSL_R_LENGTH_MISMATCH);
        goto err;
    }

    for (nc = 0; nc < llen;) {
        if (nc + 2 > llen) {
            ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
            SSLerr(SSL_F_SSL3_GET_CERTIFICATE_REQUEST, SSL_R_CA_DN_TOO_LONG);
            goto err;
        }
        n2s(p, l);
        if ((l + nc + 2) > llen) {
            if ((s->options & SSL_OP_NETSCAPE_CA_DN_BUG))
                goto cont;      /* netscape bugs */
            ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
            SSLerr(SSL_F_SSL3_GET_CERTIFICATE_REQUEST, SSL_R_CA_DN_TOO_LONG);
            goto err;
        }

        q = p;

        if ((xn = d2i_X509_NAME(NULL, &q, l)) == NULL) {
            /* If netscape tolerance is on, ignore errors */
            if (s->options & SSL_OP_NETSCAPE_CA_DN_BUG)
                goto cont;
            else {
                ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
                SSLerr(SSL_F_SSL3_GET_CERTIFICATE_REQUEST, ERR_R_ASN1_LIB);
                goto err;
            }
        }

        if (q != (p + l)) {
            ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
            SSLerr(SSL_F_SSL3_GET_CERTIFICATE_REQUEST,
                   SSL_R_CA_DN_LENGTH_MISMATCH);
            goto err;
        }
        if (!sk_X509_NAME_push(ca_sk, xn)) {
            SSLerr(SSL_F_SSL3_GET_CERTIFICATE_REQUEST, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        xn = NULL;

        p += l;
        nc += l + 2;
    }

    if (0) {
 cont:
        ERR_clear_error();
    }

    /* we should setup a certificate to return.... */
    s->s3->tmp.cert_req = 1;
    s->s3->tmp.ctype_num = ctype_num;
    if (s->s3->tmp.ca_names != NULL)
        sk_X509_NAME_pop_free(s->s3->tmp.ca_names, X509_NAME_free);
    s->s3->tmp.ca_names = ca_sk;
    ca_sk = NULL;

    ret = 1;
    goto done;
 err:
    s->state = SSL_ST_ERR;
 done:
    X509_NAME_free(xn);
    if (ca_sk != NULL)
        sk_X509_NAME_pop_free(ca_sk, X509_NAME_free);
    return (ret);
}

static int ca_dn_cmp(const X509_NAME *const *a, const X509_NAME *const *b)
{
    return (X509_NAME_cmp(*a, *b));
}

#ifndef OPENSSL_NO_TLSEXT
int ssl3_get_new_session_ticket(SSL *s)
{
    int ok, al, ret = 0, ticklen;
    long n;
    const unsigned char *p;
    unsigned char *d;
    unsigned long ticket_lifetime_hint;

    n = s->method->ssl_get_message(s,
                                   SSL3_ST_CR_SESSION_TICKET_A,
                                   SSL3_ST_CR_SESSION_TICKET_B,
                                   SSL3_MT_NEWSESSION_TICKET, 16384, &ok);

    if (!ok)
        return ((int)n);

    if (n < 6) {
        /* need at least ticket_lifetime_hint + ticket length */
        al = SSL_AD_DECODE_ERROR;
        SSLerr(SSL_F_SSL3_GET_NEW_SESSION_TICKET, SSL_R_LENGTH_MISMATCH);
        goto f_err;
    }

    p = d = (unsigned char *)s->init_msg;

    n2l(p, ticket_lifetime_hint);
    n2s(p, ticklen);
    /* ticket_lifetime_hint + ticket_length + ticket */
    if (ticklen + 6 != n) {
        al = SSL_AD_DECODE_ERROR;
        SSLerr(SSL_F_SSL3_GET_NEW_SESSION_TICKET, SSL_R_LENGTH_MISMATCH);
        goto f_err;
    }

    /* Server is allowed to change its mind and send an empty ticket. */
    if (ticklen == 0)
        return 1;

    if (s->session->session_id_length > 0) {
        int i = s->session_ctx->session_cache_mode;
        SSL_SESSION *new_sess;
        /*
         * We reused an existing session, so we need to replace it with a new
         * one
         */
        if (i & SSL_SESS_CACHE_CLIENT) {
            /*
             * Remove the old session from the cache
             */
            if (i & SSL_SESS_CACHE_NO_INTERNAL_STORE) {
                if (s->session_ctx->remove_session_cb != NULL)
                    s->session_ctx->remove_session_cb(s->session_ctx,
                                                      s->session);
            } else {
                /* We carry on if this fails */
                SSL_CTX_remove_session(s->session_ctx, s->session);
            }
        }

        if ((new_sess = ssl_session_dup(s->session, 0)) == 0) {
            al = SSL_AD_INTERNAL_ERROR;
            SSLerr(SSL_F_SSL3_GET_NEW_SESSION_TICKET, ERR_R_MALLOC_FAILURE);
            goto f_err;
        }

        SSL_SESSION_free(s->session);
        s->session = new_sess;
    }

    if (s->session->tlsext_tick) {
        OPENSSL_free(s->session->tlsext_tick);
        s->session->tlsext_ticklen = 0;
    }
    s->session->tlsext_tick = OPENSSL_malloc(ticklen);
    if (!s->session->tlsext_tick) {
        SSLerr(SSL_F_SSL3_GET_NEW_SESSION_TICKET, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    memcpy(s->session->tlsext_tick, p, ticklen);
    s->session->tlsext_tick_lifetime_hint = ticket_lifetime_hint;
    s->session->tlsext_ticklen = ticklen;
    /*
     * There are two ways to detect a resumed ticket session. One is to set
     * an appropriate session ID and then the server must return a match in
     * ServerHello. This allows the normal client session ID matching to work
     * and we know much earlier that the ticket has been accepted. The
     * other way is to set zero length session ID when the ticket is
     * presented and rely on the handshake to determine session resumption.
     * We choose the former approach because this fits in with assumptions
     * elsewhere in OpenSSL. The session ID is set to the SHA256 (or SHA1 is
     * SHA256 is disabled) hash of the ticket.
     */
    EVP_Digest(p, ticklen,
               s->session->session_id, &s->session->session_id_length,
# ifndef OPENSSL_NO_SHA256
               EVP_sha256(), NULL);
# else
               EVP_sha1(), NULL);
# endif
    ret = 1;
    return (ret);
 f_err:
    ssl3_send_alert(s, SSL3_AL_FATAL, al);
 err:
    s->state = SSL_ST_ERR;
    return (-1);
}

int ssl3_get_cert_status(SSL *s)
{
    int ok, al;
    unsigned long resplen, n;
    const unsigned char *p;

    n = s->method->ssl_get_message(s,
                                   SSL3_ST_CR_CERT_STATUS_A,
                                   SSL3_ST_CR_CERT_STATUS_B,
                                   -1, 16384, &ok);

    if (!ok)
        return ((int)n);

    if (s->s3->tmp.message_type != SSL3_MT_CERTIFICATE_STATUS) {
        /*
         * The CertificateStatus message is optional even if
         * tlsext_status_expected is set
         */
        s->s3->tmp.reuse_message = 1;
    } else {
        if (n < 4) {
            /* need at least status type + length */
            al = SSL_AD_DECODE_ERROR;
            SSLerr(SSL_F_SSL3_GET_CERT_STATUS, SSL_R_LENGTH_MISMATCH);
            goto f_err;
        }
        p = (unsigned char *)s->init_msg;
        if (*p++ != TLSEXT_STATUSTYPE_ocsp) {
            al = SSL_AD_DECODE_ERROR;
            SSLerr(SSL_F_SSL3_GET_CERT_STATUS, SSL_R_UNSUPPORTED_STATUS_TYPE);
            goto f_err;
        }
        n2l3(p, resplen);
        if (resplen + 4 != n) {
            al = SSL_AD_DECODE_ERROR;
            SSLerr(SSL_F_SSL3_GET_CERT_STATUS, SSL_R_LENGTH_MISMATCH);
            goto f_err;
        }
        s->tlsext_ocsp_resp = BUF_memdup(p, resplen);
        if (s->tlsext_ocsp_resp == NULL) {
            al = SSL_AD_INTERNAL_ERROR;
            SSLerr(SSL_F_SSL3_GET_CERT_STATUS, ERR_R_MALLOC_FAILURE);
            goto f_err;
        }
        s->tlsext_ocsp_resplen = resplen;
    }
    if (s->ctx->tlsext_status_cb) {
        int ret;
        ret = s->ctx->tlsext_status_cb(s, s->ctx->tlsext_status_arg);
        if (ret == 0) {
            al = SSL_AD_BAD_CERTIFICATE_STATUS_RESPONSE;
            SSLerr(SSL_F_SSL3_GET_CERT_STATUS, SSL_R_INVALID_STATUS_RESPONSE);
            goto f_err;
        }
        if (ret < 0) {
            al = SSL_AD_INTERNAL_ERROR;
            SSLerr(SSL_F_SSL3_GET_CERT_STATUS, ERR_R_MALLOC_FAILURE);
            goto f_err;
        }
    }
    return 1;
 f_err:
    ssl3_send_alert(s, SSL3_AL_FATAL, al);
    s->state = SSL_ST_ERR;
    return (-1);
}
#endif

int ssl3_get_server_done(SSL *s)
{
    int ok, ret = 0;
    long n;

    /* Second to last param should be very small, like 0 :-) */
    n = s->method->ssl_get_message(s,
                                   SSL3_ST_CR_SRVR_DONE_A,
                                   SSL3_ST_CR_SRVR_DONE_B,
                                   SSL3_MT_SERVER_DONE, 30, &ok);

    if (!ok)
        return ((int)n);
    if (n > 0) {
        /* should contain no data */
        ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
        SSLerr(SSL_F_SSL3_GET_SERVER_DONE, SSL_R_LENGTH_MISMATCH);
        s->state = SSL_ST_ERR;
        return -1;
    }
    ret = 1;
    return (ret);
}

#ifndef OPENSSL_NO_DH
static DH *get_server_static_dh_key(SESS_CERT *scert)
{
    DH *dh_srvr = NULL;
    EVP_PKEY *spkey = NULL;
    int idx = scert->peer_cert_type;

    if (idx >= 0)
        spkey = X509_get_pubkey(scert->peer_pkeys[idx].x509);
    if (spkey) {
        dh_srvr = EVP_PKEY_get1_DH(spkey);
        EVP_PKEY_free(spkey);
    }
    if (dh_srvr == NULL)
        SSLerr(SSL_F_GET_SERVER_STATIC_DH_KEY, ERR_R_INTERNAL_ERROR);
    return dh_srvr;
}
#endif

int ssl3_send_client_key_exchange(SSL *s)
{
    unsigned char *p;
    int n;
    unsigned long alg_k;
#ifndef OPENSSL_NO_RSA
    unsigned char *q;
    EVP_PKEY *pkey = NULL;
#endif
#ifndef OPENSSL_NO_KRB5
    KSSL_ERR kssl_err;
#endif                          /* OPENSSL_NO_KRB5 */
#ifndef OPENSSL_NO_ECDH
    EC_KEY *clnt_ecdh = NULL;
    const EC_POINT *srvr_ecpoint = NULL;
    EVP_PKEY *srvr_pub_pkey = NULL;
    unsigned char *encodedPoint = NULL;
    int encoded_pt_len = 0;
    BN_CTX *bn_ctx = NULL;
#endif

    if (s->state == SSL3_ST_CW_KEY_EXCH_A) {
        p = ssl_handshake_start(s);

        alg_k = s->s3->tmp.new_cipher->algorithm_mkey;

        /* Fool emacs indentation */
        if (0) {
        }
#ifndef OPENSSL_NO_RSA
        else if (alg_k & SSL_kRSA) {
            RSA *rsa;
            unsigned char tmp_buf[SSL_MAX_MASTER_KEY_LENGTH];

            if (s->session->sess_cert == NULL) {
                /*
                 * We should always have a server certificate with SSL_kRSA.
                 */
                SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
                       ERR_R_INTERNAL_ERROR);
                goto err;
            }

            if (s->session->sess_cert->peer_rsa_tmp != NULL)
                rsa = s->session->sess_cert->peer_rsa_tmp;
            else {
                pkey =
                    X509_get_pubkey(s->session->
                                    sess_cert->peer_pkeys[SSL_PKEY_RSA_ENC].
                                    x509);
                if ((pkey == NULL) || (pkey->type != EVP_PKEY_RSA)
                    || (pkey->pkey.rsa == NULL)) {
                    SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
                           ERR_R_INTERNAL_ERROR);
                    EVP_PKEY_free(pkey);
                    goto err;
                }
                rsa = pkey->pkey.rsa;
                EVP_PKEY_free(pkey);
            }

            tmp_buf[0] = s->client_version >> 8;
            tmp_buf[1] = s->client_version & 0xff;
            if (RAND_bytes(&(tmp_buf[2]), sizeof(tmp_buf) - 2) <= 0)
                goto err;

            s->session->master_key_length = sizeof(tmp_buf);

            q = p;
            /* Fix buf for TLS and beyond */
            if (s->version > SSL3_VERSION)
                p += 2;
            n = RSA_public_encrypt(sizeof(tmp_buf),
                                   tmp_buf, p, rsa, RSA_PKCS1_PADDING);
# ifdef PKCS1_CHECK
            if (s->options & SSL_OP_PKCS1_CHECK_1)
                p[1]++;
            if (s->options & SSL_OP_PKCS1_CHECK_2)
                tmp_buf[0] = 0x70;
# endif
            if (n <= 0) {
                SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
                       SSL_R_BAD_RSA_ENCRYPT);
                goto err;
            }

            /* Fix buf for TLS and beyond */
            if (s->version > SSL3_VERSION) {
                s2n(n, q);
                n += 2;
            }

            s->session->master_key_length =
                s->method->ssl3_enc->generate_master_secret(s,
                                                            s->
                                                            session->master_key,
                                                            tmp_buf,
                                                            sizeof(tmp_buf));
            OPENSSL_cleanse(tmp_buf, sizeof(tmp_buf));
        }
#endif
#ifndef OPENSSL_NO_KRB5
        else if (alg_k & SSL_kKRB5) {
            krb5_error_code krb5rc;
            KSSL_CTX *kssl_ctx = s->kssl_ctx;
            /*  krb5_data   krb5_ap_req;  */
            krb5_data *enc_ticket;
            krb5_data authenticator, *authp = NULL;
            EVP_CIPHER_CTX ciph_ctx;
            const EVP_CIPHER *enc = NULL;
            unsigned char iv[EVP_MAX_IV_LENGTH];
            unsigned char tmp_buf[SSL_MAX_MASTER_KEY_LENGTH];
            unsigned char epms[SSL_MAX_MASTER_KEY_LENGTH + EVP_MAX_IV_LENGTH];
            int padl, outl = sizeof(epms);

            EVP_CIPHER_CTX_init(&ciph_ctx);

# ifdef KSSL_DEBUG
            fprintf(stderr, "ssl3_send_client_key_exchange(%lx & %lx)\n",
                    alg_k, SSL_kKRB5);
# endif                         /* KSSL_DEBUG */

            authp = NULL;
# ifdef KRB5SENDAUTH
            if (KRB5SENDAUTH)
                authp = &authenticator;
# endif                         /* KRB5SENDAUTH */

            krb5rc = kssl_cget_tkt(kssl_ctx, &enc_ticket, authp, &kssl_err);
            enc = kssl_map_enc(kssl_ctx->enctype);
            if (enc == NULL)
                goto err;
# ifdef KSSL_DEBUG
            {
                fprintf(stderr, "kssl_cget_tkt rtn %d\n", krb5rc);
                if (krb5rc && kssl_err.text)
                    fprintf(stderr, "kssl_cget_tkt kssl_err=%s\n",
                            kssl_err.text);
            }
# endif                         /* KSSL_DEBUG */

            if (krb5rc) {
                ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_HANDSHAKE_FAILURE);
                SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE, kssl_err.reason);
                goto err;
            }

            /*-
             * 20010406 VRS - Earlier versions used KRB5 AP_REQ
             * in place of RFC 2712 KerberosWrapper, as in:
             *
             * Send ticket (copy to *p, set n = length)
             * n = krb5_ap_req.length;
             * memcpy(p, krb5_ap_req.data, krb5_ap_req.length);
             * if (krb5_ap_req.data)
             *   kssl_krb5_free_data_contents(NULL,&krb5_ap_req);
             *
             * Now using real RFC 2712 KerberosWrapper
             * (Thanks to Simon Wilkinson <sxw@sxw.org.uk>)
             * Note: 2712 "opaque" types are here replaced
             * with a 2-byte length followed by the value.
             * Example:
             * KerberosWrapper= xx xx asn1ticket 0 0 xx xx encpms
             * Where "xx xx" = length bytes.  Shown here with
             * optional authenticator omitted.
             */

            /*  KerberosWrapper.Ticket              */
            s2n(enc_ticket->length, p);
            memcpy(p, enc_ticket->data, enc_ticket->length);
            p += enc_ticket->length;
            n = enc_ticket->length + 2;

            /*  KerberosWrapper.Authenticator       */
            if (authp && authp->length) {
                s2n(authp->length, p);
                memcpy(p, authp->data, authp->length);
                p += authp->length;
                n += authp->length + 2;

                free(authp->data);
                authp->data = NULL;
                authp->length = 0;
            } else {
                s2n(0, p);      /* null authenticator length */
                n += 2;
            }

            tmp_buf[0] = s->client_version >> 8;
            tmp_buf[1] = s->client_version & 0xff;
            if (RAND_bytes(&(tmp_buf[2]), sizeof(tmp_buf) - 2) <= 0)
                goto err;

            /*-
             * 20010420 VRS.  Tried it this way; failed.
             *      EVP_EncryptInit_ex(&ciph_ctx,enc, NULL,NULL);
             *      EVP_CIPHER_CTX_set_key_length(&ciph_ctx,
             *                              kssl_ctx->length);
             *      EVP_EncryptInit_ex(&ciph_ctx,NULL, key,iv);
             */

            memset(iv, 0, sizeof(iv)); /* per RFC 1510 */
            EVP_EncryptInit_ex(&ciph_ctx, enc, NULL, kssl_ctx->key, iv);
            EVP_EncryptUpdate(&ciph_ctx, epms, &outl, tmp_buf,
                              sizeof(tmp_buf));
            EVP_EncryptFinal_ex(&ciph_ctx, &(epms[outl]), &padl);
            outl += padl;
            if (outl > (int)sizeof(epms)) {
                SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
                       ERR_R_INTERNAL_ERROR);
                goto err;
            }
            EVP_CIPHER_CTX_cleanup(&ciph_ctx);

            /*  KerberosWrapper.EncryptedPreMasterSecret    */
            s2n(outl, p);
            memcpy(p, epms, outl);
            p += outl;
            n += outl + 2;

            s->session->master_key_length =
                s->method->ssl3_enc->generate_master_secret(s,
                                                            s->
                                                            session->master_key,
                                                            tmp_buf,
                                                            sizeof(tmp_buf));

            OPENSSL_cleanse(tmp_buf, sizeof(tmp_buf));
            OPENSSL_cleanse(epms, outl);
        }
#endif
#ifndef OPENSSL_NO_DH
        else if (alg_k & (SSL_kEDH | SSL_kDHr | SSL_kDHd)) {
            DH *dh_srvr, *dh_clnt;
            SESS_CERT *scert = s->session->sess_cert;

            if (scert == NULL) {
                ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_UNEXPECTED_MESSAGE);
                SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
                       SSL_R_UNEXPECTED_MESSAGE);
                goto err;
            }

            if (scert->peer_dh_tmp != NULL) {
                dh_srvr = scert->peer_dh_tmp;
            } else {
                dh_srvr = get_server_static_dh_key(scert);
                if (dh_srvr == NULL)
                    goto err;
            }

            if (s->s3->flags & TLS1_FLAGS_SKIP_CERT_VERIFY) {
                /* Use client certificate key */
                EVP_PKEY *clkey = s->cert->key->privatekey;
                dh_clnt = NULL;
                if (clkey)
                    dh_clnt = EVP_PKEY_get1_DH(clkey);
                if (dh_clnt == NULL) {
                    SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
                           ERR_R_INTERNAL_ERROR);
                    goto err;
                }
            } else {
                /* generate a new random key */
                if ((dh_clnt = DHparams_dup(dh_srvr)) == NULL) {
                    SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE, ERR_R_DH_LIB);
                    goto err;
                }
                if (!DH_generate_key(dh_clnt)) {
                    SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE, ERR_R_DH_LIB);
                    DH_free(dh_clnt);
                    goto err;
                }
            }

            /*
             * use the 'p' output buffer for the DH key, but make sure to
             * clear it out afterwards
             */

            n = DH_compute_key(p, dh_srvr->pub_key, dh_clnt);
            if (scert->peer_dh_tmp == NULL)
                DH_free(dh_srvr);

            if (n <= 0) {
                SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE, ERR_R_DH_LIB);
                DH_free(dh_clnt);
                goto err;
            }

            /* generate master key from the result */
            s->session->master_key_length =
                s->method->ssl3_enc->generate_master_secret(s,
                                                            s->
                                                            session->master_key,
                                                            p, n);
            /* clean up */
            memset(p, 0, n);

            if (s->s3->flags & TLS1_FLAGS_SKIP_CERT_VERIFY)
                n = 0;
            else {
                /* send off the data */
                n = BN_num_bytes(dh_clnt->pub_key);
                s2n(n, p);
                BN_bn2bin(dh_clnt->pub_key, p);
                n += 2;
            }

            DH_free(dh_clnt);
        }
#endif

#ifndef OPENSSL_NO_ECDH
        else if (alg_k & (SSL_kEECDH | SSL_kECDHr | SSL_kECDHe)) {
            const EC_GROUP *srvr_group = NULL;
            EC_KEY *tkey;
            int ecdh_clnt_cert = 0;
            int field_size = 0;

            if (s->session->sess_cert == NULL) {
                ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_UNEXPECTED_MESSAGE);
                SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
                       SSL_R_UNEXPECTED_MESSAGE);
                goto err;
            }

            /*
             * Did we send out the client's ECDH share for use in premaster
             * computation as part of client certificate? If so, set
             * ecdh_clnt_cert to 1.
             */
            if ((alg_k & (SSL_kECDHr | SSL_kECDHe)) && (s->cert != NULL)) {
                /*-
                 * XXX: For now, we do not support client
                 * authentication using ECDH certificates.
                 * To add such support, one needs to add
                 * code that checks for appropriate
                 * conditions and sets ecdh_clnt_cert to 1.
                 * For example, the cert have an ECC
                 * key on the same curve as the server's
                 * and the key should be authorized for
                 * key agreement.
                 *
                 * One also needs to add code in ssl3_connect
                 * to skip sending the certificate verify
                 * message.
                 *
                 * if ((s->cert->key->privatekey != NULL) &&
                 *     (s->cert->key->privatekey->type ==
                 *      EVP_PKEY_EC) && ...)
                 * ecdh_clnt_cert = 1;
                 */
            }

            if (s->session->sess_cert->peer_ecdh_tmp != NULL) {
                tkey = s->session->sess_cert->peer_ecdh_tmp;
            } else {
                /* Get the Server Public Key from Cert */
                srvr_pub_pkey =
                    X509_get_pubkey(s->session->
                                    sess_cert->peer_pkeys[SSL_PKEY_ECC].x509);
                if ((srvr_pub_pkey == NULL)
                    || (srvr_pub_pkey->type != EVP_PKEY_EC)
                    || (srvr_pub_pkey->pkey.ec == NULL)) {
                    SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
                           ERR_R_INTERNAL_ERROR);
                    goto err;
                }

                tkey = srvr_pub_pkey->pkey.ec;
            }

            srvr_group = EC_KEY_get0_group(tkey);
            srvr_ecpoint = EC_KEY_get0_public_key(tkey);

            if ((srvr_group == NULL) || (srvr_ecpoint == NULL)) {
                SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
                       ERR_R_INTERNAL_ERROR);
                goto err;
            }

            if ((clnt_ecdh = EC_KEY_new()) == NULL) {
                SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
                       ERR_R_MALLOC_FAILURE);
                goto err;
            }

            if (!EC_KEY_set_group(clnt_ecdh, srvr_group)) {
                SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE, ERR_R_EC_LIB);
                goto err;
            }
            if (ecdh_clnt_cert) {
                /*
                 * Reuse key info from our certificate We only need our
                 * private key to perform the ECDH computation.
                 */
                const BIGNUM *priv_key;
                tkey = s->cert->key->privatekey->pkey.ec;
                priv_key = EC_KEY_get0_private_key(tkey);
                if (priv_key == NULL) {
                    SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
                           ERR_R_MALLOC_FAILURE);
                    goto err;
                }
                if (!EC_KEY_set_private_key(clnt_ecdh, priv_key)) {
                    SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE, ERR_R_EC_LIB);
                    goto err;
                }
            } else {
                /* Generate a new ECDH key pair */
                if (!(EC_KEY_generate_key(clnt_ecdh))) {
                    SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
                           ERR_R_ECDH_LIB);
                    goto err;
                }
            }

            /*
             * use the 'p' output buffer for the ECDH key, but make sure to
             * clear it out afterwards
             */

            field_size = EC_GROUP_get_degree(srvr_group);
            if (field_size <= 0) {
                SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE, ERR_R_ECDH_LIB);
                goto err;
            }
            n = ECDH_compute_key(p, (field_size + 7) / 8, srvr_ecpoint,
                                 clnt_ecdh, NULL);
            if (n <= 0) {
                SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE, ERR_R_ECDH_LIB);
                goto err;
            }

            /* generate master key from the result */
            s->session->master_key_length =
                s->method->ssl3_enc->generate_master_secret(s,
                                                            s->
                                                            session->master_key,
                                                            p, n);

            memset(p, 0, n);    /* clean up */

            if (ecdh_clnt_cert) {
                /* Send empty client key exch message */
                n = 0;
            } else {
                /*
                 * First check the size of encoding and allocate memory
                 * accordingly.
                 */
                encoded_pt_len =
                    EC_POINT_point2oct(srvr_group,
                                       EC_KEY_get0_public_key(clnt_ecdh),
                                       POINT_CONVERSION_UNCOMPRESSED,
                                       NULL, 0, NULL);

                encodedPoint = (unsigned char *)
                    OPENSSL_malloc(encoded_pt_len * sizeof(unsigned char));
                bn_ctx = BN_CTX_new();
                if ((encodedPoint == NULL) || (bn_ctx == NULL)) {
                    SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
                           ERR_R_MALLOC_FAILURE);
                    goto err;
                }

                /* Encode the public key */
                n = EC_POINT_point2oct(srvr_group,
                                       EC_KEY_get0_public_key(clnt_ecdh),
                                       POINT_CONVERSION_UNCOMPRESSED,
                                       encodedPoint, encoded_pt_len, bn_ctx);

                *p = n;         /* length of encoded point */
                /* Encoded point will be copied here */
                p += 1;
                /* copy the point */
                memcpy((unsigned char *)p, encodedPoint, n);
                /* increment n to account for length field */
                n += 1;
            }

            /* Free allocated memory */
            BN_CTX_free(bn_ctx);
            if (encodedPoint != NULL)
                OPENSSL_free(encodedPoint);
            if (clnt_ecdh != NULL)
                EC_KEY_free(clnt_ecdh);
            EVP_PKEY_free(srvr_pub_pkey);
        }
#endif                          /* !OPENSSL_NO_ECDH */
        else if (alg_k & SSL_kGOST) {
            /* GOST key exchange message creation */
            EVP_PKEY_CTX *pkey_ctx;
            X509 *peer_cert;
            size_t msglen;
            unsigned int md_len;
            int keytype;
            unsigned char premaster_secret[32], shared_ukm[32], tmp[256];
            EVP_MD_CTX *ukm_hash;
            EVP_PKEY *pub_key;

            /*
             * Get server sertificate PKEY and create ctx from it
             */
            peer_cert =
                s->session->
                sess_cert->peer_pkeys[(keytype = SSL_PKEY_GOST01)].x509;
            if (!peer_cert)
                peer_cert =
                    s->session->
                    sess_cert->peer_pkeys[(keytype = SSL_PKEY_GOST94)].x509;
            if (!peer_cert) {
                SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
                       SSL_R_NO_GOST_CERTIFICATE_SENT_BY_PEER);
                goto err;
            }

            pkey_ctx = EVP_PKEY_CTX_new(pub_key =
                                        X509_get_pubkey(peer_cert), NULL);
            if (pkey_ctx == NULL) {
                SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
                       ERR_R_MALLOC_FAILURE);
                goto err;
            }
            /*
             * If we have send a certificate, and certificate key
             *
             * * parameters match those of server certificate, use
             * certificate key for key exchange
             */

            /* Otherwise, generate ephemeral key pair */

            if (pkey_ctx == NULL
                    || EVP_PKEY_encrypt_init(pkey_ctx) <= 0
                    /* Generate session key */
                    || RAND_bytes(premaster_secret, 32) <= 0) {
                EVP_PKEY_CTX_free(pkey_ctx);
                SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
                       ERR_R_INTERNAL_ERROR);
                goto err;
            }
            /*
             * Compute shared IV and store it in algorithm-specific context
             * data
             */
            ukm_hash = EVP_MD_CTX_create();
            if (EVP_DigestInit(ukm_hash,
                               EVP_get_digestbynid(NID_id_GostR3411_94)) <= 0
                    || EVP_DigestUpdate(ukm_hash, s->s3->client_random,
                                        SSL3_RANDOM_SIZE) <= 0
                    || EVP_DigestUpdate(ukm_hash, s->s3->server_random,
                                        SSL3_RANDOM_SIZE) <= 0
                    || EVP_DigestFinal_ex(ukm_hash, shared_ukm, &md_len) <= 0) {
                EVP_MD_CTX_destroy(ukm_hash);
                SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
                       ERR_R_INTERNAL_ERROR);
                goto err;
            }
            EVP_MD_CTX_destroy(ukm_hash);
            if (EVP_PKEY_CTX_ctrl
                (pkey_ctx, -1, EVP_PKEY_OP_ENCRYPT, EVP_PKEY_CTRL_SET_IV, 8,
                 shared_ukm) < 0) {
                SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
                       SSL_R_LIBRARY_BUG);
                goto err;
            }
            /* Make GOST keytransport blob message */
            /*
             * Encapsulate it into sequence
             */
            *(p++) = V_ASN1_SEQUENCE | V_ASN1_CONSTRUCTED;
            msglen = 255;
            if (EVP_PKEY_encrypt(pkey_ctx, tmp, &msglen, premaster_secret, 32)
                <= 0) {
                SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
                       SSL_R_LIBRARY_BUG);
                goto err;
            }
            if (msglen >= 0x80) {
                *(p++) = 0x81;
                *(p++) = msglen & 0xff;
                n = msglen + 3;
            } else {
                *(p++) = msglen & 0xff;
                n = msglen + 2;
            }
            memcpy(p, tmp, msglen);
            EVP_PKEY_CTX_free(pkey_ctx);
            s->session->master_key_length =
                s->method->ssl3_enc->generate_master_secret(s,
                                                            s->
                                                            session->master_key,
                                                            premaster_secret,
                                                            32);
            EVP_PKEY_free(pub_key);

        }
#ifndef OPENSSL_NO_SRP
        else if (alg_k & SSL_kSRP) {
            if (s->srp_ctx.A != NULL) {
                /* send off the data */
                n = BN_num_bytes(s->srp_ctx.A);
                s2n(n, p);
                BN_bn2bin(s->srp_ctx.A, p);
                n += 2;
            } else {
                SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
                       ERR_R_INTERNAL_ERROR);
                goto err;
            }
            if (s->session->srp_username != NULL)
                OPENSSL_free(s->session->srp_username);
            s->session->srp_username = BUF_strdup(s->srp_ctx.login);
            if (s->session->srp_username == NULL) {
                SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
                       ERR_R_MALLOC_FAILURE);
                goto err;
            }

            if ((s->session->master_key_length =
                 SRP_generate_client_master_secret(s,
                                                   s->session->master_key)) <
                0) {
                SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
                       ERR_R_INTERNAL_ERROR);
                goto err;
            }
        }
#endif
#ifndef OPENSSL_NO_PSK
        else if (alg_k & SSL_kPSK) {
            /*
             * The callback needs PSK_MAX_IDENTITY_LEN + 1 bytes to return a
             * \0-terminated identity. The last byte is for us for simulating
             * strnlen.
             */
            char identity[PSK_MAX_IDENTITY_LEN + 2];
            size_t identity_len;
            unsigned char *t = NULL;
            unsigned char psk_or_pre_ms[PSK_MAX_PSK_LEN * 2 + 4];
            unsigned int pre_ms_len = 0, psk_len = 0;
            int psk_err = 1;

            n = 0;
            if (s->psk_client_callback == NULL) {
                SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
                       SSL_R_PSK_NO_CLIENT_CB);
                goto err;
            }

            memset(identity, 0, sizeof(identity));
            psk_len = s->psk_client_callback(s, s->session->psk_identity_hint,
                                             identity, sizeof(identity) - 1,
                                             psk_or_pre_ms,
                                             sizeof(psk_or_pre_ms));
            if (psk_len > PSK_MAX_PSK_LEN) {
                SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
                       ERR_R_INTERNAL_ERROR);
                goto psk_err;
            } else if (psk_len == 0) {
                SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
                       SSL_R_PSK_IDENTITY_NOT_FOUND);
                goto psk_err;
            }
            identity[PSK_MAX_IDENTITY_LEN + 1] = '\0';
            identity_len = strlen(identity);
            if (identity_len > PSK_MAX_IDENTITY_LEN) {
                SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
                       ERR_R_INTERNAL_ERROR);
                goto psk_err;
            }
            /* create PSK pre_master_secret */
            pre_ms_len = 2 + psk_len + 2 + psk_len;
            t = psk_or_pre_ms;
            memmove(psk_or_pre_ms + psk_len + 4, psk_or_pre_ms, psk_len);
            s2n(psk_len, t);
            memset(t, 0, psk_len);
            t += psk_len;
            s2n(psk_len, t);

            if (s->session->psk_identity_hint != NULL)
                OPENSSL_free(s->session->psk_identity_hint);
            s->session->psk_identity_hint =
                BUF_strdup(s->ctx->psk_identity_hint);
            if (s->ctx->psk_identity_hint != NULL
                && s->session->psk_identity_hint == NULL) {
                SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
                       ERR_R_MALLOC_FAILURE);
                goto psk_err;
            }

            if (s->session->psk_identity != NULL)
                OPENSSL_free(s->session->psk_identity);
            s->session->psk_identity = BUF_strdup(identity);
            if (s->session->psk_identity == NULL) {
                SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
                       ERR_R_MALLOC_FAILURE);
                goto psk_err;
            }

            s->session->master_key_length =
                s->method->ssl3_enc->generate_master_secret(s,
                                                            s->
                                                            session->master_key,
                                                            psk_or_pre_ms,
                                                            pre_ms_len);
            s2n(identity_len, p);
            memcpy(p, identity, identity_len);
            n = 2 + identity_len;
            psk_err = 0;
 psk_err:
            OPENSSL_cleanse(identity, sizeof(identity));
            OPENSSL_cleanse(psk_or_pre_ms, sizeof(psk_or_pre_ms));
            if (psk_err != 0) {
                ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_HANDSHAKE_FAILURE);
                goto err;
            }
        }
#endif
        else {
            ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_HANDSHAKE_FAILURE);
            SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE, ERR_R_INTERNAL_ERROR);
            goto err;
        }

        ssl_set_handshake_header(s, SSL3_MT_CLIENT_KEY_EXCHANGE, n);
        s->state = SSL3_ST_CW_KEY_EXCH_B;
    }

    /* SSL3_ST_CW_KEY_EXCH_B */
    return ssl_do_write(s);
 err:
#ifndef OPENSSL_NO_ECDH
    BN_CTX_free(bn_ctx);
    if (encodedPoint != NULL)
        OPENSSL_free(encodedPoint);
    if (clnt_ecdh != NULL)
        EC_KEY_free(clnt_ecdh);
    EVP_PKEY_free(srvr_pub_pkey);
#endif
    s->state = SSL_ST_ERR;
    return (-1);
}

int ssl3_send_client_verify(SSL *s)
{
    unsigned char *p;
    unsigned char data[MD5_DIGEST_LENGTH + SHA_DIGEST_LENGTH];
    EVP_PKEY *pkey;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_MD_CTX mctx;
    unsigned u = 0;
    unsigned long n;
    int j;

    EVP_MD_CTX_init(&mctx);

    if (s->state == SSL3_ST_CW_CERT_VRFY_A) {
        p = ssl_handshake_start(s);
        pkey = s->cert->key->privatekey;
/* Create context from key and test if sha1 is allowed as digest */
        pctx = EVP_PKEY_CTX_new(pkey, NULL);
        if (pctx == NULL || EVP_PKEY_sign_init(pctx) <= 0) {
            SSLerr(SSL_F_SSL3_SEND_CLIENT_VERIFY, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        if (EVP_PKEY_CTX_set_signature_md(pctx, EVP_sha1()) > 0) {
            if (!SSL_USE_SIGALGS(s))
                s->method->ssl3_enc->cert_verify_mac(s,
                                                     NID_sha1,
                                                     &(data
                                                       [MD5_DIGEST_LENGTH]));
        } else {
            ERR_clear_error();
        }
        /*
         * For TLS v1.2 send signature algorithm and signature using agreed
         * digest and cached handshake records.
         */
        if (SSL_USE_SIGALGS(s)) {
            long hdatalen = 0;
            void *hdata;
            const EVP_MD *md = s->cert->key->digest;
            hdatalen = BIO_get_mem_data(s->s3->handshake_buffer, &hdata);
            if (hdatalen <= 0 || !tls12_get_sigandhash(p, pkey, md)) {
                SSLerr(SSL_F_SSL3_SEND_CLIENT_VERIFY, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            p += 2;
#ifdef SSL_DEBUG
            fprintf(stderr, "Using TLS 1.2 with client alg %s\n",
                    EVP_MD_name(md));
#endif
            if (!EVP_SignInit_ex(&mctx, md, NULL)
                || !EVP_SignUpdate(&mctx, hdata, hdatalen)
                || !EVP_SignFinal(&mctx, p + 2, &u, pkey)) {
                SSLerr(SSL_F_SSL3_SEND_CLIENT_VERIFY, ERR_R_EVP_LIB);
                goto err;
            }
            s2n(u, p);
            n = u + 4;
            if (!ssl3_digest_cached_records(s))
                goto err;
        } else
#ifndef OPENSSL_NO_RSA
        if (pkey->type == EVP_PKEY_RSA) {
            s->method->ssl3_enc->cert_verify_mac(s, NID_md5, &(data[0]));
            if (RSA_sign(NID_md5_sha1, data,
                         MD5_DIGEST_LENGTH + SHA_DIGEST_LENGTH,
                         &(p[2]), &u, pkey->pkey.rsa) <= 0) {
                SSLerr(SSL_F_SSL3_SEND_CLIENT_VERIFY, ERR_R_RSA_LIB);
                goto err;
            }
            s2n(u, p);
            n = u + 2;
        } else
#endif
#ifndef OPENSSL_NO_DSA
        if (pkey->type == EVP_PKEY_DSA) {
            if (!DSA_sign(pkey->save_type,
                          &(data[MD5_DIGEST_LENGTH]),
                          SHA_DIGEST_LENGTH, &(p[2]),
                          (unsigned int *)&j, pkey->pkey.dsa)) {
                SSLerr(SSL_F_SSL3_SEND_CLIENT_VERIFY, ERR_R_DSA_LIB);
                goto err;
            }
            s2n(j, p);
            n = j + 2;
        } else
#endif
#ifndef OPENSSL_NO_ECDSA
        if (pkey->type == EVP_PKEY_EC) {
            if (!ECDSA_sign(pkey->save_type,
                            &(data[MD5_DIGEST_LENGTH]),
                            SHA_DIGEST_LENGTH, &(p[2]),
                            (unsigned int *)&j, pkey->pkey.ec)) {
                SSLerr(SSL_F_SSL3_SEND_CLIENT_VERIFY, ERR_R_ECDSA_LIB);
                goto err;
            }
            s2n(j, p);
            n = j + 2;
        } else
#endif
        if (pkey->type == NID_id_GostR3410_94
                || pkey->type == NID_id_GostR3410_2001) {
            unsigned char signbuf[64];
            int i;
            size_t sigsize = 64;
            s->method->ssl3_enc->cert_verify_mac(s,
                                                 NID_id_GostR3411_94, data);
            if (EVP_PKEY_sign(pctx, signbuf, &sigsize, data, 32) <= 0) {
                SSLerr(SSL_F_SSL3_SEND_CLIENT_VERIFY, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            for (i = 63, j = 0; i >= 0; j++, i--) {
                p[2 + j] = signbuf[i];
            }
            s2n(j, p);
            n = j + 2;
        } else {
            SSLerr(SSL_F_SSL3_SEND_CLIENT_VERIFY, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        ssl_set_handshake_header(s, SSL3_MT_CERTIFICATE_VERIFY, n);
        s->state = SSL3_ST_CW_CERT_VRFY_B;
    }
    EVP_MD_CTX_cleanup(&mctx);
    EVP_PKEY_CTX_free(pctx);
    return ssl_do_write(s);
 err:
    EVP_MD_CTX_cleanup(&mctx);
    EVP_PKEY_CTX_free(pctx);
    s->state = SSL_ST_ERR;
    return (-1);
}

/*
 * Check a certificate can be used for client authentication. Currently check
 * cert exists, if we have a suitable digest for TLS 1.2 if static DH client
 * certificates can be used and optionally checks suitability for Suite B.
 */
static int ssl3_check_client_certificate(SSL *s)
{
    unsigned long alg_k;
    if (!s->cert || !s->cert->key->x509 || !s->cert->key->privatekey)
        return 0;
    /* If no suitable signature algorithm can't use certificate */
    if (SSL_USE_SIGALGS(s) && !s->cert->key->digest)
        return 0;
    /*
     * If strict mode check suitability of chain before using it. This also
     * adjusts suite B digest if necessary.
     */
    if (s->cert->cert_flags & SSL_CERT_FLAGS_CHECK_TLS_STRICT &&
        !tls1_check_chain(s, NULL, NULL, NULL, -2))
        return 0;
    alg_k = s->s3->tmp.new_cipher->algorithm_mkey;
    /* See if we can use client certificate for fixed DH */
    if (alg_k & (SSL_kDHr | SSL_kDHd)) {
        SESS_CERT *scert = s->session->sess_cert;
        int i = scert->peer_cert_type;
        EVP_PKEY *clkey = NULL, *spkey = NULL;
        clkey = s->cert->key->privatekey;
        /* If client key not DH assume it can be used */
        if (EVP_PKEY_id(clkey) != EVP_PKEY_DH)
            return 1;
        if (i >= 0)
            spkey = X509_get_pubkey(scert->peer_pkeys[i].x509);
        if (spkey) {
            /* Compare server and client parameters */
            i = EVP_PKEY_cmp_parameters(clkey, spkey);
            EVP_PKEY_free(spkey);
            if (i != 1)
                return 0;
        }
        s->s3->flags |= TLS1_FLAGS_SKIP_CERT_VERIFY;
    }
    return 1;
}

int ssl3_send_client_certificate(SSL *s)
{
    X509 *x509 = NULL;
    EVP_PKEY *pkey = NULL;
    int i;

    if (s->state == SSL3_ST_CW_CERT_A) {
        /* Let cert callback update client certificates if required */
        if (s->cert->cert_cb) {
            i = s->cert->cert_cb(s, s->cert->cert_cb_arg);
            if (i < 0) {
                s->rwstate = SSL_X509_LOOKUP;
                return -1;
            }
            if (i == 0) {
                ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_INTERNAL_ERROR);
                s->state = SSL_ST_ERR;
                return 0;
            }
            s->rwstate = SSL_NOTHING;
        }
        if (ssl3_check_client_certificate(s))
            s->state = SSL3_ST_CW_CERT_C;
        else
            s->state = SSL3_ST_CW_CERT_B;
    }

    /* We need to get a client cert */
    if (s->state == SSL3_ST_CW_CERT_B) {
        /*
         * If we get an error, we need to ssl->rwstate=SSL_X509_LOOKUP;
         * return(-1); We then get retied later
         */
        i = ssl_do_client_cert_cb(s, &x509, &pkey);
        if (i < 0) {
            s->rwstate = SSL_X509_LOOKUP;
            return (-1);
        }
        s->rwstate = SSL_NOTHING;
        if ((i == 1) && (pkey != NULL) && (x509 != NULL)) {
            s->state = SSL3_ST_CW_CERT_B;
            if (!SSL_use_certificate(s, x509) || !SSL_use_PrivateKey(s, pkey))
                i = 0;
        } else if (i == 1) {
            i = 0;
            SSLerr(SSL_F_SSL3_SEND_CLIENT_CERTIFICATE,
                   SSL_R_BAD_DATA_RETURNED_BY_CALLBACK);
        }

        if (x509 != NULL)
            X509_free(x509);
        if (pkey != NULL)
            EVP_PKEY_free(pkey);
        if (i && !ssl3_check_client_certificate(s))
            i = 0;
        if (i == 0) {
            if (s->version == SSL3_VERSION) {
                s->s3->tmp.cert_req = 0;
                ssl3_send_alert(s, SSL3_AL_WARNING, SSL_AD_NO_CERTIFICATE);
                return (1);
            } else {
                s->s3->tmp.cert_req = 2;
            }
        }

        /* Ok, we have a cert */
        s->state = SSL3_ST_CW_CERT_C;
    }

    if (s->state == SSL3_ST_CW_CERT_C) {
        s->state = SSL3_ST_CW_CERT_D;
        if (!ssl3_output_cert_chain(s,
                                    (s->s3->tmp.cert_req ==
                                     2) ? NULL : s->cert->key)) {
            SSLerr(SSL_F_SSL3_SEND_CLIENT_CERTIFICATE, ERR_R_INTERNAL_ERROR);
            ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_INTERNAL_ERROR);
            s->state = SSL_ST_ERR;
            return 0;
        }
    }
    /* SSL3_ST_CW_CERT_D */
    return ssl_do_write(s);
}

#define has_bits(i,m)   (((i)&(m)) == (m))

int ssl3_check_cert_and_algorithm(SSL *s)
{
    int i, idx;
    long alg_k, alg_a;
    EVP_PKEY *pkey = NULL;
    int pkey_bits;
    SESS_CERT *sc;
#ifndef OPENSSL_NO_RSA
    RSA *rsa;
#endif
#ifndef OPENSSL_NO_DH
    DH *dh;
#endif
    int al = SSL_AD_HANDSHAKE_FAILURE;

    alg_k = s->s3->tmp.new_cipher->algorithm_mkey;
    alg_a = s->s3->tmp.new_cipher->algorithm_auth;

    /* we don't have a certificate */
    if ((alg_a & (SSL_aNULL | SSL_aKRB5)) || (alg_k & SSL_kPSK))
        return (1);

    sc = s->session->sess_cert;
    if (sc == NULL) {
        SSLerr(SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM, ERR_R_INTERNAL_ERROR);
        goto err;
    }
#ifndef OPENSSL_NO_RSA
    rsa = s->session->sess_cert->peer_rsa_tmp;
#endif
#ifndef OPENSSL_NO_DH
    dh = s->session->sess_cert->peer_dh_tmp;
#endif

    /* This is the passed certificate */

    idx = sc->peer_cert_type;
#ifndef OPENSSL_NO_ECDH
    if (idx == SSL_PKEY_ECC) {
        if (ssl_check_srvr_ecc_cert_and_alg(sc->peer_pkeys[idx].x509, s) == 0) {
            /* check failed */
            SSLerr(SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM, SSL_R_BAD_ECC_CERT);
            goto f_err;
        } else {
            return 1;
        }
    } else if (alg_a & SSL_aECDSA) {
        SSLerr(SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM,
               SSL_R_MISSING_ECDSA_SIGNING_CERT);
        goto f_err;
    } else if (alg_k & (SSL_kECDHr | SSL_kECDHe)) {
        SSLerr(SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM, SSL_R_MISSING_ECDH_CERT);
        goto f_err;
    }
#endif
    pkey = X509_get_pubkey(sc->peer_pkeys[idx].x509);
    pkey_bits = EVP_PKEY_bits(pkey);
    i = X509_certificate_type(sc->peer_pkeys[idx].x509, pkey);
    EVP_PKEY_free(pkey);

    /* Check that we have a certificate if we require one */
    if ((alg_a & SSL_aRSA) && !has_bits(i, EVP_PK_RSA | EVP_PKT_SIGN)) {
        SSLerr(SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM,
               SSL_R_MISSING_RSA_SIGNING_CERT);
        goto f_err;
    }
#ifndef OPENSSL_NO_DSA
    else if ((alg_a & SSL_aDSS) && !has_bits(i, EVP_PK_DSA | EVP_PKT_SIGN)) {
        SSLerr(SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM,
               SSL_R_MISSING_DSA_SIGNING_CERT);
        goto f_err;
    }
#endif
#ifndef OPENSSL_NO_RSA
    if (alg_k & SSL_kRSA) {
        if (!SSL_C_IS_EXPORT(s->s3->tmp.new_cipher) &&
            !has_bits(i, EVP_PK_RSA | EVP_PKT_ENC)) {
            SSLerr(SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM,
                   SSL_R_MISSING_RSA_ENCRYPTING_CERT);
            goto f_err;
        } else if (SSL_C_IS_EXPORT(s->s3->tmp.new_cipher)) {
            if (pkey_bits <= SSL_C_EXPORT_PKEYLENGTH(s->s3->tmp.new_cipher)) {
                if (!has_bits(i, EVP_PK_RSA | EVP_PKT_ENC)) {
                    SSLerr(SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM,
                           SSL_R_MISSING_RSA_ENCRYPTING_CERT);
                    goto f_err;
                }
                if (rsa != NULL) {
                    /* server key exchange is not allowed. */
                    al = SSL_AD_INTERNAL_ERROR;
                    SSLerr(SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM, ERR_R_INTERNAL_ERROR);
                    goto f_err;
                }
            }
        }
    }
#endif
#ifndef OPENSSL_NO_DH
    if ((alg_k & SSL_kEDH) && dh == NULL) {
        al = SSL_AD_INTERNAL_ERROR;
        SSLerr(SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM, ERR_R_INTERNAL_ERROR);
        goto f_err;
    }
    if ((alg_k & SSL_kDHr) && !SSL_USE_SIGALGS(s) &&
               !has_bits(i, EVP_PK_DH | EVP_PKS_RSA)) {
        SSLerr(SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM,
               SSL_R_MISSING_DH_RSA_CERT);
        goto f_err;
    }
# ifndef OPENSSL_NO_DSA
    if ((alg_k & SSL_kDHd) && !SSL_USE_SIGALGS(s) &&
        !has_bits(i, EVP_PK_DH | EVP_PKS_DSA)) {
        SSLerr(SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM,
               SSL_R_MISSING_DH_DSA_CERT);
        goto f_err;
    }
# endif

    if (alg_k & (SSL_kDHE | SSL_kDHr | SSL_kDHd)) {
        int dh_size;
        if (alg_k & SSL_kDHE) {
            dh_size = BN_num_bits(dh->p);
        } else {
            DH *dh_srvr = get_server_static_dh_key(sc);
            if (dh_srvr == NULL)
                goto f_err;
            dh_size = BN_num_bits(dh_srvr->p);
            DH_free(dh_srvr);
        }

        if ((!SSL_C_IS_EXPORT(s->s3->tmp.new_cipher) && dh_size < 1024)
            || (SSL_C_IS_EXPORT(s->s3->tmp.new_cipher) && dh_size < 512)) {
            SSLerr(SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM, SSL_R_DH_KEY_TOO_SMALL);
            goto f_err;
        }
    }
#endif  /* !OPENSSL_NO_DH */

    if (SSL_C_IS_EXPORT(s->s3->tmp.new_cipher) &&
        pkey_bits > SSL_C_EXPORT_PKEYLENGTH(s->s3->tmp.new_cipher)) {
#ifndef OPENSSL_NO_RSA
        if (alg_k & SSL_kRSA) {
            if (rsa == NULL) {
                SSLerr(SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM,
                       SSL_R_MISSING_EXPORT_TMP_RSA_KEY);
                goto f_err;
            } else if (BN_num_bits(rsa->n) >
                SSL_C_EXPORT_PKEYLENGTH(s->s3->tmp.new_cipher)) {
                /* We have a temporary RSA key but it's too large. */
                al = SSL_AD_EXPORT_RESTRICTION;
                SSLerr(SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM,
                       SSL_R_MISSING_EXPORT_TMP_RSA_KEY);
                goto f_err;
            }
        } else
#endif
#ifndef OPENSSL_NO_DH
        if (alg_k & SSL_kDHE) {
            if (BN_num_bits(dh->p) >
                SSL_C_EXPORT_PKEYLENGTH(s->s3->tmp.new_cipher)) {
                /* We have a temporary DH key but it's too large. */
                al = SSL_AD_EXPORT_RESTRICTION;
                SSLerr(SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM,
                       SSL_R_MISSING_EXPORT_TMP_DH_KEY);
                goto f_err;
            }
        } else if (alg_k & (SSL_kDHr | SSL_kDHd)) {
            /* The cert should have had an export DH key. */
            al = SSL_AD_EXPORT_RESTRICTION;
            SSLerr(SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM,
                   SSL_R_MISSING_EXPORT_TMP_DH_KEY);
                goto f_err;
        } else
#endif
        {
            SSLerr(SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM,
                   SSL_R_UNKNOWN_KEY_EXCHANGE_TYPE);
            goto f_err;
        }
    }
    return (1);
 f_err:
    ssl3_send_alert(s, SSL3_AL_FATAL, al);
 err:
    return (0);
}

#ifndef OPENSSL_NO_TLSEXT
/*
 * Normally, we can tell if the server is resuming the session from
 * the session ID. EAP-FAST (RFC 4851), however, relies on the next server
 * message after the ServerHello to determine if the server is resuming.
 * Therefore, we allow EAP-FAST to peek ahead.
 * ssl3_check_finished returns 1 if we are resuming from an external
 * pre-shared secret, we have a "ticket" and the next server handshake message
 * is Finished; and 0 otherwise. It returns -1 upon an error.
 */
static int ssl3_check_finished(SSL *s)
{
    int ok = 0;

    if (s->version < TLS1_VERSION || !s->tls_session_secret_cb ||
        !s->session->tlsext_tick)
        return 0;

    /* Need to permit this temporarily, in case the next message is Finished. */
    s->s3->flags |= SSL3_FLAGS_CCS_OK;
    /*
     * This function is called when we might get a Certificate message instead,
     * so permit appropriate message length.
     * We ignore the return value as we're only interested in the message type
     * and not its length.
     */
    s->method->ssl_get_message(s,
                               SSL3_ST_CR_CERT_A,
                               SSL3_ST_CR_CERT_B,
                               -1, s->max_cert_list, &ok);
    s->s3->flags &= ~SSL3_FLAGS_CCS_OK;

    if (!ok)
        return -1;

    s->s3->tmp.reuse_message = 1;

    if (s->s3->tmp.message_type == SSL3_MT_FINISHED)
        return 1;

    /* If we're not done, then the CCS arrived early and we should bail. */
    if (s->s3->change_cipher_spec) {
        SSLerr(SSL_F_SSL3_CHECK_FINISHED, SSL_R_CCS_RECEIVED_EARLY);
        ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_UNEXPECTED_MESSAGE);
        return -1;
    }

    return 0;
}

# ifndef OPENSSL_NO_NEXTPROTONEG
int ssl3_send_next_proto(SSL *s)
{
    unsigned int len, padding_len;
    unsigned char *d;

    if (s->state == SSL3_ST_CW_NEXT_PROTO_A) {
        len = s->next_proto_negotiated_len;
        padding_len = 32 - ((len + 2) % 32);
        d = (unsigned char *)s->init_buf->data;
        d[4] = len;
        memcpy(d + 5, s->next_proto_negotiated, len);
        d[5 + len] = padding_len;
        memset(d + 6 + len, 0, padding_len);
        *(d++) = SSL3_MT_NEXT_PROTO;
        l2n3(2 + len + padding_len, d);
        s->state = SSL3_ST_CW_NEXT_PROTO_B;
        s->init_num = 4 + 2 + len + padding_len;
        s->init_off = 0;
    }

    return ssl3_do_write(s, SSL3_RT_HANDSHAKE);
}
#endif                          /* !OPENSSL_NO_NEXTPROTONEG */
#endif                          /* !OPENSSL_NO_TLSEXT */

int ssl_do_client_cert_cb(SSL *s, X509 **px509, EVP_PKEY **ppkey)
{
    int i = 0;
#ifndef OPENSSL_NO_ENGINE
    if (s->ctx->client_cert_engine) {
        i = ENGINE_load_ssl_client_cert(s->ctx->client_cert_engine, s,
                                        SSL_get_client_CA_list(s),
                                        px509, ppkey, NULL, NULL, NULL);
        if (i != 0)
            return i;
    }
#endif
    if (s->ctx->client_cert_cb)
        i = s->ctx->client_cert_cb(s, px509, ppkey);
    return i;
}
/* ssl/s3_enc.c */
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
/* ====================================================================
 * Copyright 2005 Nokia. All rights reserved.
 *
 * The portions of the attached software ("Contribution") is developed by
 * Nokia Corporation and is licensed pursuant to the OpenSSL open source
 * license.
 *
 * The Contribution, originally written by Mika Kousa and Pasi Eronen of
 * Nokia Corporation, consists of the "PSK" (Pre-Shared Key) ciphersuites
 * support (see RFC 4279) to OpenSSL.
 *
 * No patent licenses or other rights except those expressly stated in
 * the OpenSSL open source license shall be deemed granted or received
 * expressly, by implication, estoppel, or otherwise.
 *
 * No assurances are provided by Nokia that the Contribution does not
 * infringe the patent or other intellectual property rights of any third
 * party or that the license provides you with all the necessary rights
 * to make use of the Contribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND. IN
 * ADDITION TO THE DISCLAIMERS INCLUDED IN THE LICENSE, NOKIA
 * SPECIFICALLY DISCLAIMS ANY LIABILITY FOR CLAIMS BROUGHT BY YOU OR ANY
 * OTHER ENTITY BASED ON INFRINGEMENT OF INTELLECTUAL PROPERTY RIGHTS OR
 * OTHERWISE.
 */

#include <stdio.h>
// #include "ssl_locl.h"
// #include "evp.h"
// #include "md5.h"

static unsigned char ssl3_pad_1[48] = {
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36
};

static unsigned char ssl3_pad_2[48] = {
    0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
    0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
    0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
    0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
    0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
    0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c
};

static int ssl3_handshake_mac(SSL *s, int md_nid,
                              const char *sender, int len, unsigned char *p);
static int ssl3_generate_key_block(SSL *s, unsigned char *km, int num)
{
    EVP_MD_CTX m5;
    EVP_MD_CTX s1;
    unsigned char buf[16], smd[SHA_DIGEST_LENGTH];
    unsigned char c = 'A';
    unsigned int i, j, k;

#ifdef CHARSET_EBCDIC
    c = os_toascii[c];          /* 'A' in ASCII */
#endif
    k = 0;
    EVP_MD_CTX_init(&m5);
    EVP_MD_CTX_set_flags(&m5, EVP_MD_CTX_FLAG_NON_FIPS_ALLOW);
    EVP_MD_CTX_init(&s1);
    for (i = 0; (int)i < num; i += MD5_DIGEST_LENGTH) {
        k++;
        if (k > sizeof(buf))
            /* bug: 'buf' is too small for this ciphersuite */
            goto err;

        for (j = 0; j < k; j++)
            buf[j] = c;
        c++;
        if (!EVP_DigestInit_ex(&s1, EVP_sha1(), NULL) ||
            !EVP_DigestUpdate(&s1, buf, k) ||
            !EVP_DigestUpdate(&s1, s->session->master_key,
                              s->session->master_key_length) ||
            !EVP_DigestUpdate(&s1, s->s3->server_random, SSL3_RANDOM_SIZE) ||
            !EVP_DigestUpdate(&s1, s->s3->client_random, SSL3_RANDOM_SIZE) ||
            !EVP_DigestFinal_ex(&s1, smd, NULL))
            goto err2;

        if (!EVP_DigestInit_ex(&m5, EVP_md5(), NULL) ||
            !EVP_DigestUpdate(&m5, s->session->master_key,
                              s->session->master_key_length) ||
            !EVP_DigestUpdate(&m5, smd, SHA_DIGEST_LENGTH))
            goto err2;
        if ((int)(i + MD5_DIGEST_LENGTH) > num) {
            if (!EVP_DigestFinal_ex(&m5, smd, NULL))
                goto err2;
            memcpy(km, smd, (num - i));
        } else
            if (!EVP_DigestFinal_ex(&m5, km, NULL))
                goto err2;

        km += MD5_DIGEST_LENGTH;
    }
    OPENSSL_cleanse(smd, SHA_DIGEST_LENGTH);
    EVP_MD_CTX_cleanup(&m5);
    EVP_MD_CTX_cleanup(&s1);
    return 1;
 err:
    SSLerr(SSL_F_SSL3_GENERATE_KEY_BLOCK, ERR_R_INTERNAL_ERROR);
 err2:
    EVP_MD_CTX_cleanup(&m5);
    EVP_MD_CTX_cleanup(&s1);
    return 0;
}

int ssl3_change_cipher_state(SSL *s, int which)
{
    unsigned char *p, *mac_secret;
    unsigned char exp_key[EVP_MAX_KEY_LENGTH];
    unsigned char exp_iv[EVP_MAX_IV_LENGTH];
    unsigned char *ms, *key, *iv, *er1, *er2;
    EVP_CIPHER_CTX *dd;
    const EVP_CIPHER *c;
#ifndef OPENSSL_NO_COMP
    COMP_METHOD *comp;
#endif
    const EVP_MD *m;
    EVP_MD_CTX md;
    int is_exp, n, i, j, k, cl;
    int reuse_dd = 0;

    is_exp = SSL_C_IS_EXPORT(s->s3->tmp.new_cipher);
    c = s->s3->tmp.new_sym_enc;
    m = s->s3->tmp.new_hash;
    /* m == NULL will lead to a crash later */
    OPENSSL_assert(m);
#ifndef OPENSSL_NO_COMP
    if (s->s3->tmp.new_compression == NULL)
        comp = NULL;
    else
        comp = s->s3->tmp.new_compression->method;
#endif

    if (which & SSL3_CC_READ) {
        if (s->enc_read_ctx != NULL)
            reuse_dd = 1;
        else if ((s->enc_read_ctx =
                  OPENSSL_malloc(sizeof(EVP_CIPHER_CTX))) == NULL)
            goto err;
        else
            /*
             * make sure it's intialized in case we exit later with an error
             */
            EVP_CIPHER_CTX_init(s->enc_read_ctx);
        dd = s->enc_read_ctx;

        if (ssl_replace_hash(&s->read_hash, m) == NULL) {
                SSLerr(SSL_F_SSL3_CHANGE_CIPHER_STATE, ERR_R_INTERNAL_ERROR);
                goto err2;
        }
#ifndef OPENSSL_NO_COMP
        /* COMPRESS */
        if (s->expand != NULL) {
            COMP_CTX_free(s->expand);
            s->expand = NULL;
        }
        if (comp != NULL) {
            s->expand = COMP_CTX_new(comp);
            if (s->expand == NULL) {
                SSLerr(SSL_F_SSL3_CHANGE_CIPHER_STATE,
                       SSL_R_COMPRESSION_LIBRARY_ERROR);
                goto err2;
            }
            if (s->s3->rrec.comp == NULL)
                s->s3->rrec.comp = (unsigned char *)
                    OPENSSL_malloc(SSL3_RT_MAX_PLAIN_LENGTH);
            if (s->s3->rrec.comp == NULL)
                goto err;
        }
#endif
        memset(&(s->s3->read_sequence[0]), 0, 8);
        mac_secret = &(s->s3->read_mac_secret[0]);
    } else {
        if (s->enc_write_ctx != NULL)
            reuse_dd = 1;
        else if ((s->enc_write_ctx =
                  OPENSSL_malloc(sizeof(EVP_CIPHER_CTX))) == NULL)
            goto err;
        else
            /*
             * make sure it's intialized in case we exit later with an error
             */
            EVP_CIPHER_CTX_init(s->enc_write_ctx);
        dd = s->enc_write_ctx;
        if (ssl_replace_hash(&s->write_hash, m) == NULL) {
                SSLerr(SSL_F_SSL3_CHANGE_CIPHER_STATE, ERR_R_INTERNAL_ERROR);
                goto err2;
        }
#ifndef OPENSSL_NO_COMP
        /* COMPRESS */
        if (s->compress != NULL) {
            COMP_CTX_free(s->compress);
            s->compress = NULL;
        }
        if (comp != NULL) {
            s->compress = COMP_CTX_new(comp);
            if (s->compress == NULL) {
                SSLerr(SSL_F_SSL3_CHANGE_CIPHER_STATE,
                       SSL_R_COMPRESSION_LIBRARY_ERROR);
                goto err2;
            }
        }
#endif
        memset(&(s->s3->write_sequence[0]), 0, 8);
        mac_secret = &(s->s3->write_mac_secret[0]);
    }

    if (reuse_dd)
        EVP_CIPHER_CTX_cleanup(dd);

    p = s->s3->tmp.key_block;
    i = EVP_MD_size(m);
    if (i < 0)
        goto err2;
    cl = EVP_CIPHER_key_length(c);
    j = is_exp ? (cl < SSL_C_EXPORT_KEYLENGTH(s->s3->tmp.new_cipher) ?
                  cl : SSL_C_EXPORT_KEYLENGTH(s->s3->tmp.new_cipher)) : cl;
    /* Was j=(is_exp)?5:EVP_CIPHER_key_length(c); */
    k = EVP_CIPHER_iv_length(c);
    if ((which == SSL3_CHANGE_CIPHER_CLIENT_WRITE) ||
        (which == SSL3_CHANGE_CIPHER_SERVER_READ)) {
        ms = &(p[0]);
        n = i + i;
        key = &(p[n]);
        n += j + j;
        iv = &(p[n]);
        n += k + k;
        er1 = &(s->s3->client_random[0]);
        er2 = &(s->s3->server_random[0]);
    } else {
        n = i;
        ms = &(p[n]);
        n += i + j;
        key = &(p[n]);
        n += j + k;
        iv = &(p[n]);
        n += k;
        er1 = &(s->s3->server_random[0]);
        er2 = &(s->s3->client_random[0]);
    }

    if (n > s->s3->tmp.key_block_length) {
        SSLerr(SSL_F_SSL3_CHANGE_CIPHER_STATE, ERR_R_INTERNAL_ERROR);
        goto err2;
    }

    EVP_MD_CTX_init(&md);
    memcpy(mac_secret, ms, i);
    if (is_exp) {
        /*
         * In here I set both the read and write key/iv to the same value
         * since only the correct one will be used :-).
         */
        if (!EVP_DigestInit_ex(&md, EVP_md5(), NULL) ||
            !EVP_DigestUpdate(&md, key, j) ||
            !EVP_DigestUpdate(&md, er1, SSL3_RANDOM_SIZE) ||
            !EVP_DigestUpdate(&md, er2, SSL3_RANDOM_SIZE) ||
            !EVP_DigestFinal_ex(&md, &(exp_key[0]), NULL)) {
            EVP_MD_CTX_cleanup(&md);
            goto err2;
        }
        key = &(exp_key[0]);

        if (k > 0) {
            if (!EVP_DigestInit_ex(&md, EVP_md5(), NULL) ||
                !EVP_DigestUpdate(&md, er1, SSL3_RANDOM_SIZE) ||
                !EVP_DigestUpdate(&md, er2, SSL3_RANDOM_SIZE) ||
                !EVP_DigestFinal_ex(&md, &(exp_iv[0]), NULL)) {
                EVP_MD_CTX_cleanup(&md);
                goto err2;
            }
            iv = &(exp_iv[0]);
        }
    }
    EVP_MD_CTX_cleanup(&md);

    s->session->key_arg_length = 0;

    if (!EVP_CipherInit_ex(dd, c, NULL, key, iv, (which & SSL3_CC_WRITE)))
        goto err2;

#ifdef OPENSSL_SSL_TRACE_CRYPTO
    if (s->msg_callback) {

        int wh = which & SSL3_CC_WRITE ?
            TLS1_RT_CRYPTO_WRITE : TLS1_RT_CRYPTO_READ;
        s->msg_callback(2, s->version, wh | TLS1_RT_CRYPTO_MAC,
                        mac_secret, EVP_MD_size(m), s, s->msg_callback_arg);
        if (c->key_len)
            s->msg_callback(2, s->version, wh | TLS1_RT_CRYPTO_KEY,
                            key, c->key_len, s, s->msg_callback_arg);
        if (k) {
            s->msg_callback(2, s->version, wh | TLS1_RT_CRYPTO_IV,
                            iv, k, s, s->msg_callback_arg);
        }
    }
#endif

    OPENSSL_cleanse(&(exp_key[0]), sizeof(exp_key));
    OPENSSL_cleanse(&(exp_iv[0]), sizeof(exp_iv));
    return (1);
 err:
    SSLerr(SSL_F_SSL3_CHANGE_CIPHER_STATE, ERR_R_MALLOC_FAILURE);
 err2:
    return (0);
}

int ssl3_setup_key_block(SSL *s)
{
    unsigned char *p;
    const EVP_CIPHER *c;
    const EVP_MD *hash;
    int num;
    int ret = 0;
    SSL_COMP *comp;

    if (s->s3->tmp.key_block_length != 0)
        return (1);

    if (!ssl_cipher_get_evp(s->session, &c, &hash, NULL, NULL, &comp)) {
        SSLerr(SSL_F_SSL3_SETUP_KEY_BLOCK, SSL_R_CIPHER_OR_HASH_UNAVAILABLE);
        return (0);
    }

    s->s3->tmp.new_sym_enc = c;
    s->s3->tmp.new_hash = hash;
#ifdef OPENSSL_NO_COMP
    s->s3->tmp.new_compression = NULL;
#else
    s->s3->tmp.new_compression = comp;
#endif

    num = EVP_MD_size(hash);
    if (num < 0)
        return 0;

    num = EVP_CIPHER_key_length(c) + num + EVP_CIPHER_iv_length(c);
    num *= 2;

    ssl3_cleanup_key_block(s);

    if ((p = OPENSSL_malloc(num)) == NULL)
        goto err;

    s->s3->tmp.key_block_length = num;
    s->s3->tmp.key_block = p;

    ret = ssl3_generate_key_block(s, p, num);

    if (!(s->options & SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS)) {
        /*
         * enable vulnerability countermeasure for CBC ciphers with known-IV
         * problem (http://www.openssl.org/~bodo/tls-cbc.txt)
         */
        s->s3->need_empty_fragments = 1;

        if (s->session->cipher != NULL) {
            if (s->session->cipher->algorithm_enc == SSL_eNULL)
                s->s3->need_empty_fragments = 0;

#ifndef OPENSSL_NO_RC4
            if (s->session->cipher->algorithm_enc == SSL_RC4)
                s->s3->need_empty_fragments = 0;
#endif
        }
    }

    return ret;

 err:
    SSLerr(SSL_F_SSL3_SETUP_KEY_BLOCK, ERR_R_MALLOC_FAILURE);
    return (0);
}

void ssl3_cleanup_key_block(SSL *s)
{
    if (s->s3->tmp.key_block != NULL) {
        OPENSSL_cleanse(s->s3->tmp.key_block, s->s3->tmp.key_block_length);
        OPENSSL_free(s->s3->tmp.key_block);
        s->s3->tmp.key_block = NULL;
    }
    s->s3->tmp.key_block_length = 0;
}

/*-
 * ssl3_enc encrypts/decrypts the record in |s->wrec| / |s->rrec|, respectively.
 *
 * Returns:
 *   0: (in non-constant time) if the record is publically invalid (i.e. too
 *       short etc).
 *   1: if the record's padding is valid / the encryption was successful.
 *   -1: if the record's padding is invalid or, if sending, an internal error
 *       occured.
 */
int ssl3_enc(SSL *s, int send)
{
    SSL3_RECORD *rec;
    EVP_CIPHER_CTX *ds;
    unsigned long l;
    int bs, i, mac_size = 0;
    const EVP_CIPHER *enc;

    if (send) {
        ds = s->enc_write_ctx;
        rec = &(s->s3->wrec);
        if (s->enc_write_ctx == NULL)
            enc = NULL;
        else
            enc = EVP_CIPHER_CTX_cipher(s->enc_write_ctx);
    } else {
        ds = s->enc_read_ctx;
        rec = &(s->s3->rrec);
        if (s->enc_read_ctx == NULL)
            enc = NULL;
        else
            enc = EVP_CIPHER_CTX_cipher(s->enc_read_ctx);
    }

    if ((s->session == NULL) || (ds == NULL) || (enc == NULL)) {
        memmove(rec->data, rec->input, rec->length);
        rec->input = rec->data;
    } else {
        l = rec->length;
        bs = EVP_CIPHER_block_size(ds->cipher);

        /* COMPRESS */

        if ((bs != 1) && send) {
            i = bs - ((int)l % bs);

            /* we need to add 'i-1' padding bytes */
            l += i;
            /*
             * the last of these zero bytes will be overwritten with the
             * padding length.
             */
            memset(&rec->input[rec->length], 0, i);
            rec->length += i;
            rec->input[l - 1] = (i - 1);
        }

        if (!send) {
            if (l == 0 || l % bs != 0)
                return 0;
            /* otherwise, rec->length >= bs */
        }

        if (EVP_Cipher(ds, rec->data, rec->input, l) < 1)
            return -1;

        if (EVP_MD_CTX_md(s->read_hash) != NULL)
            mac_size = EVP_MD_CTX_size(s->read_hash);
        if ((bs != 1) && !send)
            return ssl3_cbc_remove_padding(s, rec, bs, mac_size);
    }
    return 1;
}

int ssl3_init_finished_mac(SSL *s)
{
    if (s->s3->handshake_buffer)
        BIO_free(s->s3->handshake_buffer);
    if (s->s3->handshake_dgst)
        ssl3_free_digest_list(s);
    s->s3->handshake_buffer = BIO_new(BIO_s_mem());
    if (s->s3->handshake_buffer == NULL)
        return 0;
    (void)BIO_set_close(s->s3->handshake_buffer, BIO_CLOSE);
    return 1;
}

void ssl3_free_digest_list(SSL *s)
{
    int i;
    if (!s->s3->handshake_dgst)
        return;
    for (i = 0; i < SSL_MAX_DIGEST; i++) {
        if (s->s3->handshake_dgst[i])
            EVP_MD_CTX_destroy(s->s3->handshake_dgst[i]);
    }
    OPENSSL_free(s->s3->handshake_dgst);
    s->s3->handshake_dgst = NULL;
}

void ssl3_finish_mac(SSL *s, const unsigned char *buf, int len)
{
    if (s->s3->handshake_buffer
        && !(s->s3->flags & TLS1_FLAGS_KEEP_HANDSHAKE)) {
        BIO_write(s->s3->handshake_buffer, (void *)buf, len);
    } else {
        int i;
        for (i = 0; i < SSL_MAX_DIGEST; i++) {
            if (s->s3->handshake_dgst[i] != NULL)
                EVP_DigestUpdate(s->s3->handshake_dgst[i], buf, len);
        }
    }
}

int ssl3_digest_cached_records(SSL *s)
{
    int i;
    long mask;
    const EVP_MD *md;
    long hdatalen;
    void *hdata;

    /* Allocate handshake_dgst array */
    ssl3_free_digest_list(s);
    s->s3->handshake_dgst =
        OPENSSL_malloc(SSL_MAX_DIGEST * sizeof(EVP_MD_CTX *));
    if (s->s3->handshake_dgst == NULL) {
        SSLerr(SSL_F_SSL3_DIGEST_CACHED_RECORDS, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    memset(s->s3->handshake_dgst, 0, SSL_MAX_DIGEST * sizeof(EVP_MD_CTX *));
    hdatalen = BIO_get_mem_data(s->s3->handshake_buffer, &hdata);
    if (hdatalen <= 0) {
        SSLerr(SSL_F_SSL3_DIGEST_CACHED_RECORDS, SSL_R_BAD_HANDSHAKE_LENGTH);
        return 0;
    }

    /* Loop through bitso of algorithm2 field and create MD_CTX-es */
    for (i = 0; ssl_get_handshake_digest(i, &mask, &md); i++) {
        if ((mask & ssl_get_algorithm2(s)) && md) {
            s->s3->handshake_dgst[i] = EVP_MD_CTX_create();
            if (s->s3->handshake_dgst[i] == NULL) {
                SSLerr(SSL_F_SSL3_DIGEST_CACHED_RECORDS, ERR_R_MALLOC_FAILURE);
                return 0;
            }
#ifdef OPENSSL_FIPS
            if (EVP_MD_nid(md) == NID_md5) {
                EVP_MD_CTX_set_flags(s->s3->handshake_dgst[i],
                                     EVP_MD_CTX_FLAG_NON_FIPS_ALLOW);
            }
#endif
            if (!EVP_DigestInit_ex(s->s3->handshake_dgst[i], md, NULL)
                || !EVP_DigestUpdate(s->s3->handshake_dgst[i], hdata,
                                     hdatalen)) {
                SSLerr(SSL_F_SSL3_DIGEST_CACHED_RECORDS, ERR_R_INTERNAL_ERROR);
                return 0;
            }
        } else {
            s->s3->handshake_dgst[i] = NULL;
        }
    }
    if (!(s->s3->flags & TLS1_FLAGS_KEEP_HANDSHAKE)) {
        /* Free handshake_buffer BIO */
        BIO_free(s->s3->handshake_buffer);
        s->s3->handshake_buffer = NULL;
    }

    return 1;
}

int ssl3_cert_verify_mac(SSL *s, int md_nid, unsigned char *p)
{
    return (ssl3_handshake_mac(s, md_nid, NULL, 0, p));
}

int ssl3_final_finish_mac(SSL *s,
                          const char *sender, int len, unsigned char *p)
{
    int ret, sha1len;
    ret = ssl3_handshake_mac(s, NID_md5, sender, len, p);
    if (ret == 0)
        return 0;

    p += ret;

    sha1len = ssl3_handshake_mac(s, NID_sha1, sender, len, p);
    if (sha1len == 0)
        return 0;

    ret += sha1len;
    return (ret);
}

static int ssl3_handshake_mac(SSL *s, int md_nid,
                              const char *sender, int len, unsigned char *p)
{
    unsigned int ret;
    int npad, n;
    unsigned int i;
    unsigned char md_buf[EVP_MAX_MD_SIZE];
    EVP_MD_CTX ctx, *d = NULL;

    if (s->s3->handshake_buffer)
        if (!ssl3_digest_cached_records(s))
            return 0;

    /*
     * Search for digest of specified type in the handshake_dgst array
     */
    for (i = 0; i < SSL_MAX_DIGEST; i++) {
        if (s->s3->handshake_dgst[i]
            && EVP_MD_CTX_type(s->s3->handshake_dgst[i]) == md_nid) {
            d = s->s3->handshake_dgst[i];
            break;
        }
    }
    if (!d) {
        SSLerr(SSL_F_SSL3_HANDSHAKE_MAC, SSL_R_NO_REQUIRED_DIGEST);
        return 0;
    }
    EVP_MD_CTX_init(&ctx);
    EVP_MD_CTX_set_flags(&ctx, EVP_MD_CTX_FLAG_NON_FIPS_ALLOW);
    EVP_MD_CTX_copy_ex(&ctx, d);
    n = EVP_MD_CTX_size(&ctx);
    if (n < 0)
        return 0;

    npad = (48 / n) * n;
    if ((sender != NULL && EVP_DigestUpdate(&ctx, sender, len) <= 0)
            || EVP_DigestUpdate(&ctx, s->session->master_key,
                                s->session->master_key_length) <= 0
            || EVP_DigestUpdate(&ctx, ssl3_pad_1, npad) <= 0
            || EVP_DigestFinal_ex(&ctx, md_buf, &i) <= 0

            || EVP_DigestInit_ex(&ctx, EVP_MD_CTX_md(&ctx), NULL) <= 0
            || EVP_DigestUpdate(&ctx, s->session->master_key,
                                s->session->master_key_length) <= 0
            || EVP_DigestUpdate(&ctx, ssl3_pad_2, npad) <= 0
            || EVP_DigestUpdate(&ctx, md_buf, i) <= 0
            || EVP_DigestFinal_ex(&ctx, p, &ret) <= 0) {
        SSLerr(SSL_F_SSL3_HANDSHAKE_MAC, ERR_R_INTERNAL_ERROR);
        ret = 0;
    }

    EVP_MD_CTX_cleanup(&ctx);

    return ((int)ret);
}

int n_ssl3_mac(SSL *ssl, unsigned char *md, int send)
{
    SSL3_RECORD *rec;
    unsigned char *mac_sec, *seq;
    EVP_MD_CTX md_ctx;
    const EVP_MD_CTX *hash;
    unsigned char *p, rec_char;
    size_t md_size, orig_len;
    int npad;
    int t;

    if (send) {
        rec = &(ssl->s3->wrec);
        mac_sec = &(ssl->s3->write_mac_secret[0]);
        seq = &(ssl->s3->write_sequence[0]);
        hash = ssl->write_hash;
    } else {
        rec = &(ssl->s3->rrec);
        mac_sec = &(ssl->s3->read_mac_secret[0]);
        seq = &(ssl->s3->read_sequence[0]);
        hash = ssl->read_hash;
    }

    t = EVP_MD_CTX_size(hash);
    if (t < 0)
        return -1;
    md_size = t;
    npad = (48 / md_size) * md_size;

    /*
     * kludge: ssl3_cbc_remove_padding passes padding length in rec->type
     */
    orig_len = rec->length + md_size + ((unsigned int)rec->type >> 8);
    rec->type &= 0xff;

    if (!send &&
        EVP_CIPHER_CTX_mode(ssl->enc_read_ctx) == EVP_CIPH_CBC_MODE &&
        ssl3_cbc_record_digest_supported(hash)) {
        /*
         * This is a CBC-encrypted record. We must avoid leaking any
         * timing-side channel information about how many blocks of data we
         * are hashing because that gives an attacker a timing-oracle.
         */

        /*-
         * npad is, at most, 48 bytes and that's with MD5:
         *   16 + 48 + 8 (sequence bytes) + 1 + 2 = 75.
         *
         * With SHA-1 (the largest hash speced for SSLv3) the hash size
         * goes up 4, but npad goes down by 8, resulting in a smaller
         * total size.
         */
        unsigned char header[75];
        unsigned j = 0;
        memcpy(header + j, mac_sec, md_size);
        j += md_size;
        memcpy(header + j, ssl3_pad_1, npad);
        j += npad;
        memcpy(header + j, seq, 8);
        j += 8;
        header[j++] = rec->type;
        header[j++] = rec->length >> 8;
        header[j++] = rec->length & 0xff;

        /* Final param == is SSLv3 */
        if (ssl3_cbc_digest_record(hash,
                                   md, &md_size,
                                   header, rec->input,
                                   rec->length + md_size, orig_len,
                                   mac_sec, md_size, 1) <= 0)
            return -1;
    } else {
        unsigned int md_size_u;
        /* Chop the digest off the end :-) */
        EVP_MD_CTX_init(&md_ctx);

        rec_char = rec->type;
        p = md;
        s2n(rec->length, p);
        if (EVP_MD_CTX_copy_ex(&md_ctx, hash) <= 0
                || EVP_DigestUpdate(&md_ctx, mac_sec, md_size) <= 0
                || EVP_DigestUpdate(&md_ctx, ssl3_pad_1, npad) <= 0
                || EVP_DigestUpdate(&md_ctx, seq, 8) <= 0
                || EVP_DigestUpdate(&md_ctx, &rec_char, 1) <= 0
                || EVP_DigestUpdate(&md_ctx, md, 2) <= 0
                || EVP_DigestUpdate(&md_ctx, rec->input, rec->length) <= 0
                || EVP_DigestFinal_ex(&md_ctx, md, NULL) <= 0
                || EVP_MD_CTX_copy_ex(&md_ctx, hash) <= 0
                || EVP_DigestUpdate(&md_ctx, mac_sec, md_size) <= 0
                || EVP_DigestUpdate(&md_ctx, ssl3_pad_2, npad) <= 0
                || EVP_DigestUpdate(&md_ctx, md, md_size) <= 0
                || EVP_DigestFinal_ex(&md_ctx, md, &md_size_u) <= 0) {
            EVP_MD_CTX_cleanup(&md_ctx);
            return -1;
        }
        md_size = md_size_u;

        EVP_MD_CTX_cleanup(&md_ctx);
    }

    ssl3_record_sequence_update(seq);
    return (md_size);
}

void ssl3_record_sequence_update(unsigned char *seq)
{
    int i;

    for (i = 7; i >= 0; i--) {
        ++seq[i];
        if (seq[i] != 0)
            break;
    }
}

int ssl3_generate_master_secret(SSL *s, unsigned char *out, unsigned char *p,
                                int len)
{
    static const unsigned char *salt[3] = {
#ifndef CHARSET_EBCDIC
        (const unsigned char *)"A",
        (const unsigned char *)"BB",
        (const unsigned char *)"CCC",
#else
        (const unsigned char *)"\x41",
        (const unsigned char *)"\x42\x42",
        (const unsigned char *)"\x43\x43\x43",
#endif
    };
    unsigned char buf[EVP_MAX_MD_SIZE];
    EVP_MD_CTX ctx;
    int i, ret = 0;
    unsigned int n;
#ifdef OPENSSL_SSL_TRACE_CRYPTO
    unsigned char *tmpout = out;
#endif

    EVP_MD_CTX_init(&ctx);
    for (i = 0; i < 3; i++) {
        if (EVP_DigestInit_ex(&ctx, s->ctx->sha1, NULL) <= 0
                || EVP_DigestUpdate(&ctx, salt[i],
                                    strlen((const char *)salt[i])) <= 0
                || EVP_DigestUpdate(&ctx, p, len) <= 0
                || EVP_DigestUpdate(&ctx, &(s->s3->client_random[0]),
                                    SSL3_RANDOM_SIZE) <= 0
                || EVP_DigestUpdate(&ctx, &(s->s3->server_random[0]),
                                    SSL3_RANDOM_SIZE) <= 0
                || EVP_DigestFinal_ex(&ctx, buf, &n) <= 0

                || EVP_DigestInit_ex(&ctx, s->ctx->md5, NULL) <= 0
                || EVP_DigestUpdate(&ctx, p, len) <= 0
                || EVP_DigestUpdate(&ctx, buf, n) <= 0
                || EVP_DigestFinal_ex(&ctx, out, &n) <= 0) {
            SSLerr(SSL_F_SSL3_GENERATE_MASTER_SECRET, ERR_R_INTERNAL_ERROR);
            ret = 0;
            break;
        }
        out += n;
        ret += n;
    }
    EVP_MD_CTX_cleanup(&ctx);

#ifdef OPENSSL_SSL_TRACE_CRYPTO
    if (ret > 0 && s->msg_callback) {
        s->msg_callback(2, s->version, TLS1_RT_CRYPTO_PREMASTER,
                        p, len, s, s->msg_callback_arg);
        s->msg_callback(2, s->version, TLS1_RT_CRYPTO_CLIENT_RANDOM,
                        s->s3->client_random, SSL3_RANDOM_SIZE,
                        s, s->msg_callback_arg);
        s->msg_callback(2, s->version, TLS1_RT_CRYPTO_SERVER_RANDOM,
                        s->s3->server_random, SSL3_RANDOM_SIZE,
                        s, s->msg_callback_arg);
        s->msg_callback(2, s->version, TLS1_RT_CRYPTO_MASTER,
                        tmpout, SSL3_MASTER_SECRET_SIZE,
                        s, s->msg_callback_arg);
    }
#endif
    OPENSSL_cleanse(buf, sizeof(buf));
    return (ret);
}

int ssl3_alert_code(int code)
{
    switch (code) {
    case SSL_AD_CLOSE_NOTIFY:
        return (SSL3_AD_CLOSE_NOTIFY);
    case SSL_AD_UNEXPECTED_MESSAGE:
        return (SSL3_AD_UNEXPECTED_MESSAGE);
    case SSL_AD_BAD_RECORD_MAC:
        return (SSL3_AD_BAD_RECORD_MAC);
    case SSL_AD_DECRYPTION_FAILED:
        return (SSL3_AD_BAD_RECORD_MAC);
    case SSL_AD_RECORD_OVERFLOW:
        return (SSL3_AD_BAD_RECORD_MAC);
    case SSL_AD_DECOMPRESSION_FAILURE:
        return (SSL3_AD_DECOMPRESSION_FAILURE);
    case SSL_AD_HANDSHAKE_FAILURE:
        return (SSL3_AD_HANDSHAKE_FAILURE);
    case SSL_AD_NO_CERTIFICATE:
        return (SSL3_AD_NO_CERTIFICATE);
    case SSL_AD_BAD_CERTIFICATE:
        return (SSL3_AD_BAD_CERTIFICATE);
    case SSL_AD_UNSUPPORTED_CERTIFICATE:
        return (SSL3_AD_UNSUPPORTED_CERTIFICATE);
    case SSL_AD_CERTIFICATE_REVOKED:
        return (SSL3_AD_CERTIFICATE_REVOKED);
    case SSL_AD_CERTIFICATE_EXPIRED:
        return (SSL3_AD_CERTIFICATE_EXPIRED);
    case SSL_AD_CERTIFICATE_UNKNOWN:
        return (SSL3_AD_CERTIFICATE_UNKNOWN);
    case SSL_AD_ILLEGAL_PARAMETER:
        return (SSL3_AD_ILLEGAL_PARAMETER);
    case SSL_AD_UNKNOWN_CA:
        return (SSL3_AD_BAD_CERTIFICATE);
    case SSL_AD_ACCESS_DENIED:
        return (SSL3_AD_HANDSHAKE_FAILURE);
    case SSL_AD_DECODE_ERROR:
        return (SSL3_AD_HANDSHAKE_FAILURE);
    case SSL_AD_DECRYPT_ERROR:
        return (SSL3_AD_HANDSHAKE_FAILURE);
    case SSL_AD_EXPORT_RESTRICTION:
        return (SSL3_AD_HANDSHAKE_FAILURE);
    case SSL_AD_PROTOCOL_VERSION:
        return (SSL3_AD_HANDSHAKE_FAILURE);
    case SSL_AD_INSUFFICIENT_SECURITY:
        return (SSL3_AD_HANDSHAKE_FAILURE);
    case SSL_AD_INTERNAL_ERROR:
        return (SSL3_AD_HANDSHAKE_FAILURE);
    case SSL_AD_USER_CANCELLED:
        return (SSL3_AD_HANDSHAKE_FAILURE);
    case SSL_AD_NO_RENEGOTIATION:
        return (-1);            /* Don't send it :-) */
    case SSL_AD_UNSUPPORTED_EXTENSION:
        return (SSL3_AD_HANDSHAKE_FAILURE);
    case SSL_AD_CERTIFICATE_UNOBTAINABLE:
        return (SSL3_AD_HANDSHAKE_FAILURE);
    case SSL_AD_UNRECOGNIZED_NAME:
        return (SSL3_AD_HANDSHAKE_FAILURE);
    case SSL_AD_BAD_CERTIFICATE_STATUS_RESPONSE:
        return (SSL3_AD_HANDSHAKE_FAILURE);
    case SSL_AD_BAD_CERTIFICATE_HASH_VALUE:
        return (SSL3_AD_HANDSHAKE_FAILURE);
    case SSL_AD_UNKNOWN_PSK_IDENTITY:
        return (TLS1_AD_UNKNOWN_PSK_IDENTITY);
    case SSL_AD_INAPPROPRIATE_FALLBACK:
        return (TLS1_AD_INAPPROPRIATE_FALLBACK);
    default:
        return (-1);
    }
}
/* ssl/s3_lib.c */
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
/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 *
 * Portions of the attached software ("Contribution") are developed by
 * SUN MICROSYSTEMS, INC., and are contributed to the OpenSSL project.
 *
 * The Contribution is licensed pursuant to the OpenSSL open source
 * license provided above.
 *
 * ECC cipher suite support in OpenSSL originally written by
 * Vipul Gupta and Sumit Gupta of Sun Microsystems Laboratories.
 *
 */
/* ====================================================================
 * Copyright 2005 Nokia. All rights reserved.
 *
 * The portions of the attached software ("Contribution") is developed by
 * Nokia Corporation and is licensed pursuant to the OpenSSL open source
 * license.
 *
 * The Contribution, originally written by Mika Kousa and Pasi Eronen of
 * Nokia Corporation, consists of the "PSK" (Pre-Shared Key) ciphersuites
 * support (see RFC 4279) to OpenSSL.
 *
 * No patent licenses or other rights except those expressly stated in
 * the OpenSSL open source license shall be deemed granted or received
 * expressly, by implication, estoppel, or otherwise.
 *
 * No assurances are provided by Nokia that the Contribution does not
 * infringe the patent or other intellectual property rights of any third
 * party or that the license provides you with all the necessary rights
 * to make use of the Contribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND. IN
 * ADDITION TO THE DISCLAIMERS INCLUDED IN THE LICENSE, NOKIA
 * SPECIFICALLY DISCLAIMS ANY LIABILITY FOR CLAIMS BROUGHT BY YOU OR ANY
 * OTHER ENTITY BASED ON INFRINGEMENT OF INTELLECTUAL PROPERTY RIGHTS OR
 * OTHERWISE.
 */

#include <stdio.h>
// #include "objects.h"
// #include "ssl_locl.h"
// #include "kssl_lcl.h"
// #include "md5.h"
#ifndef OPENSSL_NO_DH
# include "dh.h"
#endif

const char ssl3_version_str[] = "SSLv3" OPENSSL_VERSION_PTEXT;

#define SSL3_NUM_CIPHERS        (sizeof(ssl3_ciphers)/sizeof(SSL_CIPHER))

/* list of available SSLv3 ciphers (sorted by id) */
OPENSSL_GLOBAL SSL_CIPHER ssl3_ciphers[] = {

/* The RSA ciphers */
/* Cipher 01 */
    {
     1,
     SSL3_TXT_RSA_NULL_MD5,
     SSL3_CK_RSA_NULL_MD5,
     SSL_kRSA,
     SSL_aRSA,
     SSL_eNULL,
     SSL_MD5,
     SSL_SSLV3,
     SSL_NOT_EXP | SSL_STRONG_NONE,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     0,
     0,
     },

/* Cipher 02 */
    {
     1,
     SSL3_TXT_RSA_NULL_SHA,
     SSL3_CK_RSA_NULL_SHA,
     SSL_kRSA,
     SSL_aRSA,
     SSL_eNULL,
     SSL_SHA1,
     SSL_SSLV3,
     SSL_NOT_EXP | SSL_STRONG_NONE | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     0,
     0,
     },

/* Cipher 03 */
#ifndef OPENSSL_NO_WEAK_SSL_CIPHERS
    {
     1,
     SSL3_TXT_RSA_RC4_40_MD5,
     SSL3_CK_RSA_RC4_40_MD5,
     SSL_kRSA,
     SSL_aRSA,
     SSL_RC4,
     SSL_MD5,
     SSL_SSLV3,
     SSL_NOT_DEFAULT | SSL_EXPORT | SSL_EXP40,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     40,
     128,
     },
#endif

/* Cipher 04 */
    {
     1,
     SSL3_TXT_RSA_RC4_128_MD5,
     SSL3_CK_RSA_RC4_128_MD5,
     SSL_kRSA,
     SSL_aRSA,
     SSL_RC4,
     SSL_MD5,
     SSL_SSLV3,
     SSL_NOT_EXP | SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },

/* Cipher 05 */
    {
     1,
     SSL3_TXT_RSA_RC4_128_SHA,
     SSL3_CK_RSA_RC4_128_SHA,
     SSL_kRSA,
     SSL_aRSA,
     SSL_RC4,
     SSL_SHA1,
     SSL_SSLV3,
     SSL_NOT_EXP | SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },

/* Cipher 06 */
#ifndef OPENSSL_NO_WEAK_SSL_CIPHERS
    {
     1,
     SSL3_TXT_RSA_RC2_40_MD5,
     SSL3_CK_RSA_RC2_40_MD5,
     SSL_kRSA,
     SSL_aRSA,
     SSL_RC2,
     SSL_MD5,
     SSL_SSLV3,
     SSL_NOT_DEFAULT | SSL_EXPORT | SSL_EXP40,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     40,
     128,
     },
#endif

/* Cipher 07 */
#ifndef OPENSSL_NO_IDEA
    {
     1,
     SSL3_TXT_RSA_IDEA_128_SHA,
     SSL3_CK_RSA_IDEA_128_SHA,
     SSL_kRSA,
     SSL_aRSA,
     SSL_IDEA,
     SSL_SHA1,
     SSL_SSLV3,
     SSL_NOT_EXP | SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
#endif

/* Cipher 08 */
#ifndef OPENSSL_NO_WEAK_SSL_CIPHERS
    {
     1,
     SSL3_TXT_RSA_DES_40_CBC_SHA,
     SSL3_CK_RSA_DES_40_CBC_SHA,
     SSL_kRSA,
     SSL_aRSA,
     SSL_DES,
     SSL_SHA1,
     SSL_SSLV3,
     SSL_NOT_DEFAULT | SSL_EXPORT | SSL_EXP40,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     40,
     56,
     },
#endif

/* Cipher 09 */
#ifndef OPENSSL_NO_WEAK_SSL_CIPHERS
    {
     1,
     SSL3_TXT_RSA_DES_64_CBC_SHA,
     SSL3_CK_RSA_DES_64_CBC_SHA,
     SSL_kRSA,
     SSL_aRSA,
     SSL_DES,
     SSL_SHA1,
     SSL_SSLV3,
     SSL_NOT_DEFAULT | SSL_NOT_EXP | SSL_LOW,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     56,
     56,
     },
#endif

/* Cipher 0A */
    {
     1,
     SSL3_TXT_RSA_DES_192_CBC3_SHA,
     SSL3_CK_RSA_DES_192_CBC3_SHA,
     SSL_kRSA,
     SSL_aRSA,
     SSL_3DES,
     SSL_SHA1,
     SSL_SSLV3,
     SSL_NOT_EXP | SSL_MEDIUM | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     112,
     168,
     },

/* The DH ciphers */
/* Cipher 0B */
#ifndef OPENSSL_NO_WEAK_SSL_CIPHERS
    {
     0,
     SSL3_TXT_DH_DSS_DES_40_CBC_SHA,
     SSL3_CK_DH_DSS_DES_40_CBC_SHA,
     SSL_kDHd,
     SSL_aDH,
     SSL_DES,
     SSL_SHA1,
     SSL_SSLV3,
     SSL_NOT_DEFAULT | SSL_EXPORT | SSL_EXP40,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     40,
     56,
     },
#endif

/* Cipher 0C */
#ifndef OPENSSL_NO_WEAK_SSL_CIPHERS
    {
     1,
     SSL3_TXT_DH_DSS_DES_64_CBC_SHA,
     SSL3_CK_DH_DSS_DES_64_CBC_SHA,
     SSL_kDHd,
     SSL_aDH,
     SSL_DES,
     SSL_SHA1,
     SSL_SSLV3,
     SSL_NOT_DEFAULT | SSL_NOT_EXP | SSL_LOW,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     56,
     56,
     },
#endif

/* Cipher 0D */
    {
     1,
     SSL3_TXT_DH_DSS_DES_192_CBC3_SHA,
     SSL3_CK_DH_DSS_DES_192_CBC3_SHA,
     SSL_kDHd,
     SSL_aDH,
     SSL_3DES,
     SSL_SHA1,
     SSL_SSLV3,
     SSL_NOT_EXP | SSL_MEDIUM | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     112,
     168,
     },

/* Cipher 0E */
#ifndef OPENSSL_NO_WEAK_SSL_CIPHERS
    {
     0,
     SSL3_TXT_DH_RSA_DES_40_CBC_SHA,
     SSL3_CK_DH_RSA_DES_40_CBC_SHA,
     SSL_kDHr,
     SSL_aDH,
     SSL_DES,
     SSL_SHA1,
     SSL_SSLV3,
     SSL_NOT_DEFAULT | SSL_EXPORT | SSL_EXP40,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     40,
     56,
     },
#endif

/* Cipher 0F */
#ifndef OPENSSL_NO_WEAK_SSL_CIPHERS
    {
     1,
     SSL3_TXT_DH_RSA_DES_64_CBC_SHA,
     SSL3_CK_DH_RSA_DES_64_CBC_SHA,
     SSL_kDHr,
     SSL_aDH,
     SSL_DES,
     SSL_SHA1,
     SSL_SSLV3,
     SSL_NOT_DEFAULT | SSL_NOT_EXP | SSL_LOW,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     56,
     56,
     },
#endif

/* Cipher 10 */
    {
     1,
     SSL3_TXT_DH_RSA_DES_192_CBC3_SHA,
     SSL3_CK_DH_RSA_DES_192_CBC3_SHA,
     SSL_kDHr,
     SSL_aDH,
     SSL_3DES,
     SSL_SHA1,
     SSL_SSLV3,
     SSL_NOT_EXP | SSL_MEDIUM | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     112,
     168,
     },

/* The Ephemeral DH ciphers */
/* Cipher 11 */
#ifndef OPENSSL_NO_WEAK_SSL_CIPHERS
    {
     1,
     SSL3_TXT_EDH_DSS_DES_40_CBC_SHA,
     SSL3_CK_EDH_DSS_DES_40_CBC_SHA,
     SSL_kEDH,
     SSL_aDSS,
     SSL_DES,
     SSL_SHA1,
     SSL_SSLV3,
     SSL_NOT_DEFAULT | SSL_EXPORT | SSL_EXP40,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     40,
     56,
     },
#endif

/* Cipher 12 */
#ifndef OPENSSL_NO_WEAK_SSL_CIPHERS
    {
     1,
     SSL3_TXT_EDH_DSS_DES_64_CBC_SHA,
     SSL3_CK_EDH_DSS_DES_64_CBC_SHA,
     SSL_kEDH,
     SSL_aDSS,
     SSL_DES,
     SSL_SHA1,
     SSL_SSLV3,
     SSL_NOT_DEFAULT | SSL_NOT_EXP | SSL_LOW,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     56,
     56,
     },
#endif

/* Cipher 13 */
    {
     1,
     SSL3_TXT_EDH_DSS_DES_192_CBC3_SHA,
     SSL3_CK_EDH_DSS_DES_192_CBC3_SHA,
     SSL_kEDH,
     SSL_aDSS,
     SSL_3DES,
     SSL_SHA1,
     SSL_SSLV3,
     SSL_NOT_EXP | SSL_MEDIUM | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     112,
     168,
     },

/* Cipher 14 */
#ifndef OPENSSL_NO_WEAK_SSL_CIPHERS
    {
     1,
     SSL3_TXT_EDH_RSA_DES_40_CBC_SHA,
     SSL3_CK_EDH_RSA_DES_40_CBC_SHA,
     SSL_kEDH,
     SSL_aRSA,
     SSL_DES,
     SSL_SHA1,
     SSL_SSLV3,
     SSL_NOT_DEFAULT | SSL_EXPORT | SSL_EXP40,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     40,
     56,
     },
#endif

/* Cipher 15 */
#ifndef OPENSSL_NO_WEAK_SSL_CIPHERS
    {
     1,
     SSL3_TXT_EDH_RSA_DES_64_CBC_SHA,
     SSL3_CK_EDH_RSA_DES_64_CBC_SHA,
     SSL_kEDH,
     SSL_aRSA,
     SSL_DES,
     SSL_SHA1,
     SSL_SSLV3,
     SSL_NOT_DEFAULT | SSL_NOT_EXP | SSL_LOW,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     56,
     56,
     },
#endif

/* Cipher 16 */
    {
     1,
     SSL3_TXT_EDH_RSA_DES_192_CBC3_SHA,
     SSL3_CK_EDH_RSA_DES_192_CBC3_SHA,
     SSL_kEDH,
     SSL_aRSA,
     SSL_3DES,
     SSL_SHA1,
     SSL_SSLV3,
     SSL_NOT_EXP | SSL_MEDIUM | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     112,
     168,
     },

/* Cipher 17 */
#ifndef OPENSSL_NO_WEAK_SSL_CIPHERS
    {
     1,
     SSL3_TXT_ADH_RC4_40_MD5,
     SSL3_CK_ADH_RC4_40_MD5,
     SSL_kEDH,
     SSL_aNULL,
     SSL_RC4,
     SSL_MD5,
     SSL_SSLV3,
     SSL_NOT_DEFAULT | SSL_EXPORT | SSL_EXP40,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     40,
     128,
     },
#endif

/* Cipher 18 */
    {
     1,
     SSL3_TXT_ADH_RC4_128_MD5,
     SSL3_CK_ADH_RC4_128_MD5,
     SSL_kEDH,
     SSL_aNULL,
     SSL_RC4,
     SSL_MD5,
     SSL_SSLV3,
     SSL_NOT_DEFAULT | SSL_NOT_EXP | SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },

/* Cipher 19 */
#ifndef OPENSSL_NO_WEAK_SSL_CIPHERS
    {
     1,
     SSL3_TXT_ADH_DES_40_CBC_SHA,
     SSL3_CK_ADH_DES_40_CBC_SHA,
     SSL_kEDH,
     SSL_aNULL,
     SSL_DES,
     SSL_SHA1,
     SSL_SSLV3,
     SSL_NOT_DEFAULT | SSL_EXPORT | SSL_EXP40,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     40,
     128,
     },
#endif

/* Cipher 1A */
#ifndef OPENSSL_NO_WEAK_SSL_CIPHERS
    {
     1,
     SSL3_TXT_ADH_DES_64_CBC_SHA,
     SSL3_CK_ADH_DES_64_CBC_SHA,
     SSL_kEDH,
     SSL_aNULL,
     SSL_DES,
     SSL_SHA1,
     SSL_SSLV3,
     SSL_NOT_DEFAULT | SSL_NOT_EXP | SSL_LOW,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     56,
     56,
     },
#endif

/* Cipher 1B */
    {
     1,
     SSL3_TXT_ADH_DES_192_CBC_SHA,
     SSL3_CK_ADH_DES_192_CBC_SHA,
     SSL_kEDH,
     SSL_aNULL,
     SSL_3DES,
     SSL_SHA1,
     SSL_SSLV3,
     SSL_NOT_DEFAULT | SSL_NOT_EXP | SSL_MEDIUM | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     112,
     168,
     },

/* Fortezza ciphersuite from SSL 3.0 spec */
#if 0
/* Cipher 1C */
    {
     0,
     SSL3_TXT_FZA_DMS_NULL_SHA,
     SSL3_CK_FZA_DMS_NULL_SHA,
     SSL_kFZA,
     SSL_aFZA,
     SSL_eNULL,
     SSL_SHA1,
     SSL_SSLV3,
     SSL_NOT_EXP | SSL_STRONG_NONE,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     0,
     0,
     },

/* Cipher 1D */
    {
     0,
     SSL3_TXT_FZA_DMS_FZA_SHA,
     SSL3_CK_FZA_DMS_FZA_SHA,
     SSL_kFZA,
     SSL_aFZA,
     SSL_eFZA,
     SSL_SHA1,
     SSL_SSLV3,
     SSL_NOT_EXP | SSL_STRONG_NONE,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     0,
     0,
     },

/* Cipher 1E */
    {
     0,
     SSL3_TXT_FZA_DMS_RC4_SHA,
     SSL3_CK_FZA_DMS_RC4_SHA,
     SSL_kFZA,
     SSL_aFZA,
     SSL_RC4,
     SSL_SHA1,
     SSL_SSLV3,
     SSL_NOT_EXP | SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
#endif

#ifndef OPENSSL_NO_KRB5
/* The Kerberos ciphers*/
/* Cipher 1E */
# ifndef OPENSSL_NO_WEAK_SSL_CIPHERS
    {
     1,
     SSL3_TXT_KRB5_DES_64_CBC_SHA,
     SSL3_CK_KRB5_DES_64_CBC_SHA,
     SSL_kKRB5,
     SSL_aKRB5,
     SSL_DES,
     SSL_SHA1,
     SSL_SSLV3,
     SSL_NOT_DEFAULT | SSL_NOT_EXP | SSL_LOW,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     56,
     56,
     },
# endif

/* Cipher 1F */
    {
     1,
     SSL3_TXT_KRB5_DES_192_CBC3_SHA,
     SSL3_CK_KRB5_DES_192_CBC3_SHA,
     SSL_kKRB5,
     SSL_aKRB5,
     SSL_3DES,
     SSL_SHA1,
     SSL_SSLV3,
     SSL_NOT_EXP | SSL_MEDIUM | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     112,
     168,
     },

/* Cipher 20 */
    {
     1,
     SSL3_TXT_KRB5_RC4_128_SHA,
     SSL3_CK_KRB5_RC4_128_SHA,
     SSL_kKRB5,
     SSL_aKRB5,
     SSL_RC4,
     SSL_SHA1,
     SSL_SSLV3,
     SSL_NOT_EXP | SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },

/* Cipher 21 */
    {
     1,
     SSL3_TXT_KRB5_IDEA_128_CBC_SHA,
     SSL3_CK_KRB5_IDEA_128_CBC_SHA,
     SSL_kKRB5,
     SSL_aKRB5,
     SSL_IDEA,
     SSL_SHA1,
     SSL_SSLV3,
     SSL_NOT_EXP | SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },

/* Cipher 22 */
# ifndef OPENSSL_NO_WEAK_SSL_CIPHERS
    {
     1,
     SSL3_TXT_KRB5_DES_64_CBC_MD5,
     SSL3_CK_KRB5_DES_64_CBC_MD5,
     SSL_kKRB5,
     SSL_aKRB5,
     SSL_DES,
     SSL_MD5,
     SSL_SSLV3,
     SSL_NOT_DEFAULT | SSL_NOT_EXP | SSL_LOW,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     56,
     56,
     },
# endif

/* Cipher 23 */
    {
     1,
     SSL3_TXT_KRB5_DES_192_CBC3_MD5,
     SSL3_CK_KRB5_DES_192_CBC3_MD5,
     SSL_kKRB5,
     SSL_aKRB5,
     SSL_3DES,
     SSL_MD5,
     SSL_SSLV3,
     SSL_NOT_EXP | SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     112,
     168,
     },

/* Cipher 24 */
    {
     1,
     SSL3_TXT_KRB5_RC4_128_MD5,
     SSL3_CK_KRB5_RC4_128_MD5,
     SSL_kKRB5,
     SSL_aKRB5,
     SSL_RC4,
     SSL_MD5,
     SSL_SSLV3,
     SSL_NOT_EXP | SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },

/* Cipher 25 */
    {
     1,
     SSL3_TXT_KRB5_IDEA_128_CBC_MD5,
     SSL3_CK_KRB5_IDEA_128_CBC_MD5,
     SSL_kKRB5,
     SSL_aKRB5,
     SSL_IDEA,
     SSL_MD5,
     SSL_SSLV3,
     SSL_NOT_EXP | SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },

/* Cipher 26 */
# ifndef OPENSSL_NO_WEAK_SSL_CIPHERS
    {
     1,
     SSL3_TXT_KRB5_DES_40_CBC_SHA,
     SSL3_CK_KRB5_DES_40_CBC_SHA,
     SSL_kKRB5,
     SSL_aKRB5,
     SSL_DES,
     SSL_SHA1,
     SSL_SSLV3,
     SSL_NOT_DEFAULT | SSL_EXPORT | SSL_EXP40,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     40,
     56,
     },
# endif

/* Cipher 27 */
# ifndef OPENSSL_NO_WEAK_SSL_CIPHERS
    {
     1,
     SSL3_TXT_KRB5_RC2_40_CBC_SHA,
     SSL3_CK_KRB5_RC2_40_CBC_SHA,
     SSL_kKRB5,
     SSL_aKRB5,
     SSL_RC2,
     SSL_SHA1,
     SSL_SSLV3,
     SSL_NOT_DEFAULT | SSL_EXPORT | SSL_EXP40,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     40,
     128,
     },
# endif

/* Cipher 28 */
# ifndef OPENSSL_NO_WEAK_SSL_CIPHERS
    {
     1,
     SSL3_TXT_KRB5_RC4_40_SHA,
     SSL3_CK_KRB5_RC4_40_SHA,
     SSL_kKRB5,
     SSL_aKRB5,
     SSL_RC4,
     SSL_SHA1,
     SSL_SSLV3,
     SSL_NOT_DEFAULT | SSL_EXPORT | SSL_EXP40,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     40,
     128,
     },
# endif

/* Cipher 29 */
# ifndef OPENSSL_NO_WEAK_SSL_CIPHERS
    {
     1,
     SSL3_TXT_KRB5_DES_40_CBC_MD5,
     SSL3_CK_KRB5_DES_40_CBC_MD5,
     SSL_kKRB5,
     SSL_aKRB5,
     SSL_DES,
     SSL_MD5,
     SSL_SSLV3,
     SSL_NOT_DEFAULT | SSL_EXPORT | SSL_EXP40,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     40,
     56,
     },
# endif

/* Cipher 2A */
# ifndef OPENSSL_NO_WEAK_SSL_CIPHERS
    {
     1,
     SSL3_TXT_KRB5_RC2_40_CBC_MD5,
     SSL3_CK_KRB5_RC2_40_CBC_MD5,
     SSL_kKRB5,
     SSL_aKRB5,
     SSL_RC2,
     SSL_MD5,
     SSL_SSLV3,
     SSL_NOT_DEFAULT | SSL_EXPORT | SSL_EXP40,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     40,
     128,
     },
# endif

/* Cipher 2B */
# ifndef OPENSSL_NO_WEAK_SSL_CIPHERS
    {
     1,
     SSL3_TXT_KRB5_RC4_40_MD5,
     SSL3_CK_KRB5_RC4_40_MD5,
     SSL_kKRB5,
     SSL_aKRB5,
     SSL_RC4,
     SSL_MD5,
     SSL_SSLV3,
     SSL_NOT_DEFAULT | SSL_EXPORT | SSL_EXP40,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     40,
     128,
     },
# endif
#endif                          /* OPENSSL_NO_KRB5 */

/* New AES ciphersuites */
/* Cipher 2F */
    {
     1,
     TLS1_TXT_RSA_WITH_AES_128_SHA,
     TLS1_CK_RSA_WITH_AES_128_SHA,
     SSL_kRSA,
     SSL_aRSA,
     SSL_AES128,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
/* Cipher 30 */
    {
     1,
     TLS1_TXT_DH_DSS_WITH_AES_128_SHA,
     TLS1_CK_DH_DSS_WITH_AES_128_SHA,
     SSL_kDHd,
     SSL_aDH,
     SSL_AES128,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
/* Cipher 31 */
    {
     1,
     TLS1_TXT_DH_RSA_WITH_AES_128_SHA,
     TLS1_CK_DH_RSA_WITH_AES_128_SHA,
     SSL_kDHr,
     SSL_aDH,
     SSL_AES128,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
/* Cipher 32 */
    {
     1,
     TLS1_TXT_DHE_DSS_WITH_AES_128_SHA,
     TLS1_CK_DHE_DSS_WITH_AES_128_SHA,
     SSL_kEDH,
     SSL_aDSS,
     SSL_AES128,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
/* Cipher 33 */
    {
     1,
     TLS1_TXT_DHE_RSA_WITH_AES_128_SHA,
     TLS1_CK_DHE_RSA_WITH_AES_128_SHA,
     SSL_kEDH,
     SSL_aRSA,
     SSL_AES128,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
/* Cipher 34 */
    {
     1,
     TLS1_TXT_ADH_WITH_AES_128_SHA,
     TLS1_CK_ADH_WITH_AES_128_SHA,
     SSL_kEDH,
     SSL_aNULL,
     SSL_AES128,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_DEFAULT | SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },

/* Cipher 35 */
    {
     1,
     TLS1_TXT_RSA_WITH_AES_256_SHA,
     TLS1_CK_RSA_WITH_AES_256_SHA,
     SSL_kRSA,
     SSL_aRSA,
     SSL_AES256,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },
/* Cipher 36 */
    {
     1,
     TLS1_TXT_DH_DSS_WITH_AES_256_SHA,
     TLS1_CK_DH_DSS_WITH_AES_256_SHA,
     SSL_kDHd,
     SSL_aDH,
     SSL_AES256,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },

/* Cipher 37 */
    {
     1,
     TLS1_TXT_DH_RSA_WITH_AES_256_SHA,
     TLS1_CK_DH_RSA_WITH_AES_256_SHA,
     SSL_kDHr,
     SSL_aDH,
     SSL_AES256,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },

/* Cipher 38 */
    {
     1,
     TLS1_TXT_DHE_DSS_WITH_AES_256_SHA,
     TLS1_CK_DHE_DSS_WITH_AES_256_SHA,
     SSL_kEDH,
     SSL_aDSS,
     SSL_AES256,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },

/* Cipher 39 */
    {
     1,
     TLS1_TXT_DHE_RSA_WITH_AES_256_SHA,
     TLS1_CK_DHE_RSA_WITH_AES_256_SHA,
     SSL_kEDH,
     SSL_aRSA,
     SSL_AES256,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },

    /* Cipher 3A */
    {
     1,
     TLS1_TXT_ADH_WITH_AES_256_SHA,
     TLS1_CK_ADH_WITH_AES_256_SHA,
     SSL_kEDH,
     SSL_aNULL,
     SSL_AES256,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_DEFAULT | SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },

    /* TLS v1.2 ciphersuites */
    /* Cipher 3B */
    {
     1,
     TLS1_TXT_RSA_WITH_NULL_SHA256,
     TLS1_CK_RSA_WITH_NULL_SHA256,
     SSL_kRSA,
     SSL_aRSA,
     SSL_eNULL,
     SSL_SHA256,
     SSL_TLSV1_2,
     SSL_NOT_EXP | SSL_STRONG_NONE | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     0,
     0,
     },

    /* Cipher 3C */
    {
     1,
     TLS1_TXT_RSA_WITH_AES_128_SHA256,
     TLS1_CK_RSA_WITH_AES_128_SHA256,
     SSL_kRSA,
     SSL_aRSA,
     SSL_AES128,
     SSL_SHA256,
     SSL_TLSV1_2,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },

    /* Cipher 3D */
    {
     1,
     TLS1_TXT_RSA_WITH_AES_256_SHA256,
     TLS1_CK_RSA_WITH_AES_256_SHA256,
     SSL_kRSA,
     SSL_aRSA,
     SSL_AES256,
     SSL_SHA256,
     SSL_TLSV1_2,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },

    /* Cipher 3E */
    {
     1,
     TLS1_TXT_DH_DSS_WITH_AES_128_SHA256,
     TLS1_CK_DH_DSS_WITH_AES_128_SHA256,
     SSL_kDHd,
     SSL_aDH,
     SSL_AES128,
     SSL_SHA256,
     SSL_TLSV1_2,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },

    /* Cipher 3F */
    {
     1,
     TLS1_TXT_DH_RSA_WITH_AES_128_SHA256,
     TLS1_CK_DH_RSA_WITH_AES_128_SHA256,
     SSL_kDHr,
     SSL_aDH,
     SSL_AES128,
     SSL_SHA256,
     SSL_TLSV1_2,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },

    /* Cipher 40 */
    {
     1,
     TLS1_TXT_DHE_DSS_WITH_AES_128_SHA256,
     TLS1_CK_DHE_DSS_WITH_AES_128_SHA256,
     SSL_kEDH,
     SSL_aDSS,
     SSL_AES128,
     SSL_SHA256,
     SSL_TLSV1_2,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },

#ifndef OPENSSL_NO_CAMELLIA
    /* Camellia ciphersuites from RFC4132 (128-bit portion) */

    /* Cipher 41 */
    {
     1,
     TLS1_TXT_RSA_WITH_CAMELLIA_128_CBC_SHA,
     TLS1_CK_RSA_WITH_CAMELLIA_128_CBC_SHA,
     SSL_kRSA,
     SSL_aRSA,
     SSL_CAMELLIA128,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_HIGH,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },

    /* Cipher 42 */
    {
     1,
     TLS1_TXT_DH_DSS_WITH_CAMELLIA_128_CBC_SHA,
     TLS1_CK_DH_DSS_WITH_CAMELLIA_128_CBC_SHA,
     SSL_kDHd,
     SSL_aDH,
     SSL_CAMELLIA128,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_HIGH,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },

    /* Cipher 43 */
    {
     1,
     TLS1_TXT_DH_RSA_WITH_CAMELLIA_128_CBC_SHA,
     TLS1_CK_DH_RSA_WITH_CAMELLIA_128_CBC_SHA,
     SSL_kDHr,
     SSL_aDH,
     SSL_CAMELLIA128,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_HIGH,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },

    /* Cipher 44 */
    {
     1,
     TLS1_TXT_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA,
     TLS1_CK_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA,
     SSL_kEDH,
     SSL_aDSS,
     SSL_CAMELLIA128,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_HIGH,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },

    /* Cipher 45 */
    {
     1,
     TLS1_TXT_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA,
     TLS1_CK_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA,
     SSL_kEDH,
     SSL_aRSA,
     SSL_CAMELLIA128,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_HIGH,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },

    /* Cipher 46 */
    {
     1,
     TLS1_TXT_ADH_WITH_CAMELLIA_128_CBC_SHA,
     TLS1_CK_ADH_WITH_CAMELLIA_128_CBC_SHA,
     SSL_kEDH,
     SSL_aNULL,
     SSL_CAMELLIA128,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_DEFAULT | SSL_NOT_EXP | SSL_HIGH,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
#endif                          /* OPENSSL_NO_CAMELLIA */

#if TLS1_ALLOW_EXPERIMENTAL_CIPHERSUITES
    /* New TLS Export CipherSuites from expired ID */
# if 0
    /* Cipher 60 */
    {
     1,
     TLS1_TXT_RSA_EXPORT1024_WITH_RC4_56_MD5,
     TLS1_CK_RSA_EXPORT1024_WITH_RC4_56_MD5,
     SSL_kRSA,
     SSL_aRSA,
     SSL_RC4,
     SSL_MD5,
     SSL_TLSV1,
     SSL_NOT_DEFAULT | SSL_EXPORT | SSL_EXP56,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     56,
     128,
     },

    /* Cipher 61 */
    {
     1,
     TLS1_TXT_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5,
     TLS1_CK_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5,
     SSL_kRSA,
     SSL_aRSA,
     SSL_RC2,
     SSL_MD5,
     SSL_TLSV1,
     SSL_NOT_DEFAULT | SSL_EXPORT | SSL_EXP56,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     56,
     128,
     },
# endif

    /* Cipher 62 */
# ifndef OPENSSL_NO_WEAK_SSL_CIPHERS
    {
     1,
     TLS1_TXT_RSA_EXPORT1024_WITH_DES_CBC_SHA,
     TLS1_CK_RSA_EXPORT1024_WITH_DES_CBC_SHA,
     SSL_kRSA,
     SSL_aRSA,
     SSL_DES,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_DEFAULT | SSL_EXPORT | SSL_EXP56,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     56,
     56,
     },
# endif

    /* Cipher 63 */
# ifndef OPENSSL_NO_WEAK_SSL_CIPHERS
    {
     1,
     TLS1_TXT_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA,
     TLS1_CK_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA,
     SSL_kEDH,
     SSL_aDSS,
     SSL_DES,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_DEFAULT | SSL_EXPORT | SSL_EXP56,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     56,
     56,
     },
# endif

    /* Cipher 64 */
# ifndef OPENSSL_NO_WEAK_SSL_CIPHERS
    {
     1,
     TLS1_TXT_RSA_EXPORT1024_WITH_RC4_56_SHA,
     TLS1_CK_RSA_EXPORT1024_WITH_RC4_56_SHA,
     SSL_kRSA,
     SSL_aRSA,
     SSL_RC4,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_DEFAULT | SSL_EXPORT | SSL_EXP56,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     56,
     128,
     },
# endif

    /* Cipher 65 */
# ifndef OPENSSL_NO_WEAK_SSL_CIPHERS
    {
     1,
     TLS1_TXT_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA,
     TLS1_CK_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA,
     SSL_kEDH,
     SSL_aDSS,
     SSL_RC4,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_DEFAULT | SSL_EXPORT | SSL_EXP56,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     56,
     128,
     },
# endif

    /* Cipher 66 */
    {
     1,
     TLS1_TXT_DHE_DSS_WITH_RC4_128_SHA,
     TLS1_CK_DHE_DSS_WITH_RC4_128_SHA,
     SSL_kEDH,
     SSL_aDSS,
     SSL_RC4,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
#endif

    /* TLS v1.2 ciphersuites */
    /* Cipher 67 */
    {
     1,
     TLS1_TXT_DHE_RSA_WITH_AES_128_SHA256,
     TLS1_CK_DHE_RSA_WITH_AES_128_SHA256,
     SSL_kEDH,
     SSL_aRSA,
     SSL_AES128,
     SSL_SHA256,
     SSL_TLSV1_2,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },

    /* Cipher 68 */
    {
     1,
     TLS1_TXT_DH_DSS_WITH_AES_256_SHA256,
     TLS1_CK_DH_DSS_WITH_AES_256_SHA256,
     SSL_kDHd,
     SSL_aDH,
     SSL_AES256,
     SSL_SHA256,
     SSL_TLSV1_2,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },

    /* Cipher 69 */
    {
     1,
     TLS1_TXT_DH_RSA_WITH_AES_256_SHA256,
     TLS1_CK_DH_RSA_WITH_AES_256_SHA256,
     SSL_kDHr,
     SSL_aDH,
     SSL_AES256,
     SSL_SHA256,
     SSL_TLSV1_2,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },

    /* Cipher 6A */
    {
     1,
     TLS1_TXT_DHE_DSS_WITH_AES_256_SHA256,
     TLS1_CK_DHE_DSS_WITH_AES_256_SHA256,
     SSL_kEDH,
     SSL_aDSS,
     SSL_AES256,
     SSL_SHA256,
     SSL_TLSV1_2,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },

    /* Cipher 6B */
    {
     1,
     TLS1_TXT_DHE_RSA_WITH_AES_256_SHA256,
     TLS1_CK_DHE_RSA_WITH_AES_256_SHA256,
     SSL_kEDH,
     SSL_aRSA,
     SSL_AES256,
     SSL_SHA256,
     SSL_TLSV1_2,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },

    /* Cipher 6C */
    {
     1,
     TLS1_TXT_ADH_WITH_AES_128_SHA256,
     TLS1_CK_ADH_WITH_AES_128_SHA256,
     SSL_kEDH,
     SSL_aNULL,
     SSL_AES128,
     SSL_SHA256,
     SSL_TLSV1_2,
     SSL_NOT_DEFAULT | SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },

    /* Cipher 6D */
    {
     1,
     TLS1_TXT_ADH_WITH_AES_256_SHA256,
     TLS1_CK_ADH_WITH_AES_256_SHA256,
     SSL_kEDH,
     SSL_aNULL,
     SSL_AES256,
     SSL_SHA256,
     SSL_TLSV1_2,
     SSL_NOT_DEFAULT | SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },

    /* GOST Ciphersuites */

    {
     1,
     "GOST94-GOST89-GOST89",
     0x3000080,
     SSL_kGOST,
     SSL_aGOST94,
     SSL_eGOST2814789CNT,
     SSL_GOST89MAC,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_HIGH,
     SSL_HANDSHAKE_MAC_GOST94 | TLS1_PRF_GOST94 | TLS1_STREAM_MAC,
     256,
     256},
    {
     1,
     "GOST2001-GOST89-GOST89",
     0x3000081,
     SSL_kGOST,
     SSL_aGOST01,
     SSL_eGOST2814789CNT,
     SSL_GOST89MAC,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_HIGH,
     SSL_HANDSHAKE_MAC_GOST94 | TLS1_PRF_GOST94 | TLS1_STREAM_MAC,
     256,
     256},
    {
     1,
     "GOST94-NULL-GOST94",
     0x3000082,
     SSL_kGOST,
     SSL_aGOST94,
     SSL_eNULL,
     SSL_GOST94,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_STRONG_NONE,
     SSL_HANDSHAKE_MAC_GOST94 | TLS1_PRF_GOST94,
     0,
     0},
    {
     1,
     "GOST2001-NULL-GOST94",
     0x3000083,
     SSL_kGOST,
     SSL_aGOST01,
     SSL_eNULL,
     SSL_GOST94,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_STRONG_NONE,
     SSL_HANDSHAKE_MAC_GOST94 | TLS1_PRF_GOST94,
     0,
     0},

#ifndef OPENSSL_NO_CAMELLIA
    /* Camellia ciphersuites from RFC4132 (256-bit portion) */

    /* Cipher 84 */
    {
     1,
     TLS1_TXT_RSA_WITH_CAMELLIA_256_CBC_SHA,
     TLS1_CK_RSA_WITH_CAMELLIA_256_CBC_SHA,
     SSL_kRSA,
     SSL_aRSA,
     SSL_CAMELLIA256,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_HIGH,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },
    /* Cipher 85 */
    {
     1,
     TLS1_TXT_DH_DSS_WITH_CAMELLIA_256_CBC_SHA,
     TLS1_CK_DH_DSS_WITH_CAMELLIA_256_CBC_SHA,
     SSL_kDHd,
     SSL_aDH,
     SSL_CAMELLIA256,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_HIGH,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },

    /* Cipher 86 */
    {
     1,
     TLS1_TXT_DH_RSA_WITH_CAMELLIA_256_CBC_SHA,
     TLS1_CK_DH_RSA_WITH_CAMELLIA_256_CBC_SHA,
     SSL_kDHr,
     SSL_aDH,
     SSL_CAMELLIA256,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_HIGH,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },

    /* Cipher 87 */
    {
     1,
     TLS1_TXT_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA,
     TLS1_CK_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA,
     SSL_kEDH,
     SSL_aDSS,
     SSL_CAMELLIA256,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_HIGH,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },

    /* Cipher 88 */
    {
     1,
     TLS1_TXT_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA,
     TLS1_CK_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA,
     SSL_kEDH,
     SSL_aRSA,
     SSL_CAMELLIA256,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_HIGH,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },

    /* Cipher 89 */
    {
     1,
     TLS1_TXT_ADH_WITH_CAMELLIA_256_CBC_SHA,
     TLS1_CK_ADH_WITH_CAMELLIA_256_CBC_SHA,
     SSL_kEDH,
     SSL_aNULL,
     SSL_CAMELLIA256,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_DEFAULT | SSL_NOT_EXP | SSL_HIGH,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },
#endif                          /* OPENSSL_NO_CAMELLIA */

#ifndef OPENSSL_NO_PSK
    /* Cipher 8A */
    {
     1,
     TLS1_TXT_PSK_WITH_RC4_128_SHA,
     TLS1_CK_PSK_WITH_RC4_128_SHA,
     SSL_kPSK,
     SSL_aPSK,
     SSL_RC4,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },

    /* Cipher 8B */
    {
     1,
     TLS1_TXT_PSK_WITH_3DES_EDE_CBC_SHA,
     TLS1_CK_PSK_WITH_3DES_EDE_CBC_SHA,
     SSL_kPSK,
     SSL_aPSK,
     SSL_3DES,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_MEDIUM | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     112,
     168,
     },

    /* Cipher 8C */
    {
     1,
     TLS1_TXT_PSK_WITH_AES_128_CBC_SHA,
     TLS1_CK_PSK_WITH_AES_128_CBC_SHA,
     SSL_kPSK,
     SSL_aPSK,
     SSL_AES128,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },

    /* Cipher 8D */
    {
     1,
     TLS1_TXT_PSK_WITH_AES_256_CBC_SHA,
     TLS1_CK_PSK_WITH_AES_256_CBC_SHA,
     SSL_kPSK,
     SSL_aPSK,
     SSL_AES256,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },
#endif                          /* OPENSSL_NO_PSK */

#ifndef OPENSSL_NO_SEED
    /* SEED ciphersuites from RFC4162 */

    /* Cipher 96 */
    {
     1,
     TLS1_TXT_RSA_WITH_SEED_SHA,
     TLS1_CK_RSA_WITH_SEED_SHA,
     SSL_kRSA,
     SSL_aRSA,
     SSL_SEED,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },

    /* Cipher 97 */
    {
     1,
     TLS1_TXT_DH_DSS_WITH_SEED_SHA,
     TLS1_CK_DH_DSS_WITH_SEED_SHA,
     SSL_kDHd,
     SSL_aDH,
     SSL_SEED,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },

    /* Cipher 98 */
    {
     1,
     TLS1_TXT_DH_RSA_WITH_SEED_SHA,
     TLS1_CK_DH_RSA_WITH_SEED_SHA,
     SSL_kDHr,
     SSL_aDH,
     SSL_SEED,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },

    /* Cipher 99 */
    {
     1,
     TLS1_TXT_DHE_DSS_WITH_SEED_SHA,
     TLS1_CK_DHE_DSS_WITH_SEED_SHA,
     SSL_kEDH,
     SSL_aDSS,
     SSL_SEED,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },

    /* Cipher 9A */
    {
     1,
     TLS1_TXT_DHE_RSA_WITH_SEED_SHA,
     TLS1_CK_DHE_RSA_WITH_SEED_SHA,
     SSL_kEDH,
     SSL_aRSA,
     SSL_SEED,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },

    /* Cipher 9B */
    {
     1,
     TLS1_TXT_ADH_WITH_SEED_SHA,
     TLS1_CK_ADH_WITH_SEED_SHA,
     SSL_kEDH,
     SSL_aNULL,
     SSL_SEED,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_DEFAULT | SSL_NOT_EXP | SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },

#endif                          /* OPENSSL_NO_SEED */

    /* GCM ciphersuites from RFC5288 */

    /* Cipher 9C */
    {
     1,
     TLS1_TXT_RSA_WITH_AES_128_GCM_SHA256,
     TLS1_CK_RSA_WITH_AES_128_GCM_SHA256,
     SSL_kRSA,
     SSL_aRSA,
     SSL_AES128GCM,
     SSL_AEAD,
     SSL_TLSV1_2,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },

    /* Cipher 9D */
    {
     1,
     TLS1_TXT_RSA_WITH_AES_256_GCM_SHA384,
     TLS1_CK_RSA_WITH_AES_256_GCM_SHA384,
     SSL_kRSA,
     SSL_aRSA,
     SSL_AES256GCM,
     SSL_AEAD,
     SSL_TLSV1_2,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },

    /* Cipher 9E */
    {
     1,
     TLS1_TXT_DHE_RSA_WITH_AES_128_GCM_SHA256,
     TLS1_CK_DHE_RSA_WITH_AES_128_GCM_SHA256,
     SSL_kEDH,
     SSL_aRSA,
     SSL_AES128GCM,
     SSL_AEAD,
     SSL_TLSV1_2,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },

    /* Cipher 9F */
    {
     1,
     TLS1_TXT_DHE_RSA_WITH_AES_256_GCM_SHA384,
     TLS1_CK_DHE_RSA_WITH_AES_256_GCM_SHA384,
     SSL_kEDH,
     SSL_aRSA,
     SSL_AES256GCM,
     SSL_AEAD,
     SSL_TLSV1_2,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },

    /* Cipher A0 */
    {
     1,
     TLS1_TXT_DH_RSA_WITH_AES_128_GCM_SHA256,
     TLS1_CK_DH_RSA_WITH_AES_128_GCM_SHA256,
     SSL_kDHr,
     SSL_aDH,
     SSL_AES128GCM,
     SSL_AEAD,
     SSL_TLSV1_2,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },

    /* Cipher A1 */
    {
     1,
     TLS1_TXT_DH_RSA_WITH_AES_256_GCM_SHA384,
     TLS1_CK_DH_RSA_WITH_AES_256_GCM_SHA384,
     SSL_kDHr,
     SSL_aDH,
     SSL_AES256GCM,
     SSL_AEAD,
     SSL_TLSV1_2,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },

    /* Cipher A2 */
    {
     1,
     TLS1_TXT_DHE_DSS_WITH_AES_128_GCM_SHA256,
     TLS1_CK_DHE_DSS_WITH_AES_128_GCM_SHA256,
     SSL_kEDH,
     SSL_aDSS,
     SSL_AES128GCM,
     SSL_AEAD,
     SSL_TLSV1_2,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },

    /* Cipher A3 */
    {
     1,
     TLS1_TXT_DHE_DSS_WITH_AES_256_GCM_SHA384,
     TLS1_CK_DHE_DSS_WITH_AES_256_GCM_SHA384,
     SSL_kEDH,
     SSL_aDSS,
     SSL_AES256GCM,
     SSL_AEAD,
     SSL_TLSV1_2,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },

    /* Cipher A4 */
    {
     1,
     TLS1_TXT_DH_DSS_WITH_AES_128_GCM_SHA256,
     TLS1_CK_DH_DSS_WITH_AES_128_GCM_SHA256,
     SSL_kDHd,
     SSL_aDH,
     SSL_AES128GCM,
     SSL_AEAD,
     SSL_TLSV1_2,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },

    /* Cipher A5 */
    {
     1,
     TLS1_TXT_DH_DSS_WITH_AES_256_GCM_SHA384,
     TLS1_CK_DH_DSS_WITH_AES_256_GCM_SHA384,
     SSL_kDHd,
     SSL_aDH,
     SSL_AES256GCM,
     SSL_AEAD,
     SSL_TLSV1_2,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },

    /* Cipher A6 */
    {
     1,
     TLS1_TXT_ADH_WITH_AES_128_GCM_SHA256,
     TLS1_CK_ADH_WITH_AES_128_GCM_SHA256,
     SSL_kEDH,
     SSL_aNULL,
     SSL_AES128GCM,
     SSL_AEAD,
     SSL_TLSV1_2,
     SSL_NOT_DEFAULT | SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },

    /* Cipher A7 */
    {
     1,
     TLS1_TXT_ADH_WITH_AES_256_GCM_SHA384,
     TLS1_CK_ADH_WITH_AES_256_GCM_SHA384,
     SSL_kEDH,
     SSL_aNULL,
     SSL_AES256GCM,
     SSL_AEAD,
     SSL_TLSV1_2,
     SSL_NOT_DEFAULT | SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },
#ifdef OPENSSL_SSL_DEBUG_BROKEN_PROTOCOL
    {
     1,
     "SCSV",
     SSL3_CK_SCSV,
     0,
     0,
     0,
     0,
     0,
     0,
     0,
     0,
     0},
#endif

#ifndef OPENSSL_NO_ECDH
    /* Cipher C001 */
    {
     1,
     TLS1_TXT_ECDH_ECDSA_WITH_NULL_SHA,
     TLS1_CK_ECDH_ECDSA_WITH_NULL_SHA,
     SSL_kECDHe,
     SSL_aECDH,
     SSL_eNULL,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_STRONG_NONE | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     0,
     0,
     },

    /* Cipher C002 */
    {
     1,
     TLS1_TXT_ECDH_ECDSA_WITH_RC4_128_SHA,
     TLS1_CK_ECDH_ECDSA_WITH_RC4_128_SHA,
     SSL_kECDHe,
     SSL_aECDH,
     SSL_RC4,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },

    /* Cipher C003 */
    {
     1,
     TLS1_TXT_ECDH_ECDSA_WITH_DES_192_CBC3_SHA,
     TLS1_CK_ECDH_ECDSA_WITH_DES_192_CBC3_SHA,
     SSL_kECDHe,
     SSL_aECDH,
     SSL_3DES,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_MEDIUM | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     112,
     168,
     },

    /* Cipher C004 */
    {
     1,
     TLS1_TXT_ECDH_ECDSA_WITH_AES_128_CBC_SHA,
     TLS1_CK_ECDH_ECDSA_WITH_AES_128_CBC_SHA,
     SSL_kECDHe,
     SSL_aECDH,
     SSL_AES128,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },

    /* Cipher C005 */
    {
     1,
     TLS1_TXT_ECDH_ECDSA_WITH_AES_256_CBC_SHA,
     TLS1_CK_ECDH_ECDSA_WITH_AES_256_CBC_SHA,
     SSL_kECDHe,
     SSL_aECDH,
     SSL_AES256,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },

    /* Cipher C006 */
    {
     1,
     TLS1_TXT_ECDHE_ECDSA_WITH_NULL_SHA,
     TLS1_CK_ECDHE_ECDSA_WITH_NULL_SHA,
     SSL_kEECDH,
     SSL_aECDSA,
     SSL_eNULL,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_STRONG_NONE | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     0,
     0,
     },

    /* Cipher C007 */
    {
     1,
     TLS1_TXT_ECDHE_ECDSA_WITH_RC4_128_SHA,
     TLS1_CK_ECDHE_ECDSA_WITH_RC4_128_SHA,
     SSL_kEECDH,
     SSL_aECDSA,
     SSL_RC4,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },

    /* Cipher C008 */
    {
     1,
     TLS1_TXT_ECDHE_ECDSA_WITH_DES_192_CBC3_SHA,
     TLS1_CK_ECDHE_ECDSA_WITH_DES_192_CBC3_SHA,
     SSL_kEECDH,
     SSL_aECDSA,
     SSL_3DES,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_MEDIUM | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     112,
     168,
     },

    /* Cipher C009 */
    {
     1,
     TLS1_TXT_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
     TLS1_CK_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
     SSL_kEECDH,
     SSL_aECDSA,
     SSL_AES128,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },

    /* Cipher C00A */
    {
     1,
     TLS1_TXT_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
     TLS1_CK_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
     SSL_kEECDH,
     SSL_aECDSA,
     SSL_AES256,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },

    /* Cipher C00B */
    {
     1,
     TLS1_TXT_ECDH_RSA_WITH_NULL_SHA,
     TLS1_CK_ECDH_RSA_WITH_NULL_SHA,
     SSL_kECDHr,
     SSL_aECDH,
     SSL_eNULL,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_STRONG_NONE | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     0,
     0,
     },

    /* Cipher C00C */
    {
     1,
     TLS1_TXT_ECDH_RSA_WITH_RC4_128_SHA,
     TLS1_CK_ECDH_RSA_WITH_RC4_128_SHA,
     SSL_kECDHr,
     SSL_aECDH,
     SSL_RC4,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },

    /* Cipher C00D */
    {
     1,
     TLS1_TXT_ECDH_RSA_WITH_DES_192_CBC3_SHA,
     TLS1_CK_ECDH_RSA_WITH_DES_192_CBC3_SHA,
     SSL_kECDHr,
     SSL_aECDH,
     SSL_3DES,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_MEDIUM | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     112,
     168,
     },

    /* Cipher C00E */
    {
     1,
     TLS1_TXT_ECDH_RSA_WITH_AES_128_CBC_SHA,
     TLS1_CK_ECDH_RSA_WITH_AES_128_CBC_SHA,
     SSL_kECDHr,
     SSL_aECDH,
     SSL_AES128,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },

    /* Cipher C00F */
    {
     1,
     TLS1_TXT_ECDH_RSA_WITH_AES_256_CBC_SHA,
     TLS1_CK_ECDH_RSA_WITH_AES_256_CBC_SHA,
     SSL_kECDHr,
     SSL_aECDH,
     SSL_AES256,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },

    /* Cipher C010 */
    {
     1,
     TLS1_TXT_ECDHE_RSA_WITH_NULL_SHA,
     TLS1_CK_ECDHE_RSA_WITH_NULL_SHA,
     SSL_kEECDH,
     SSL_aRSA,
     SSL_eNULL,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_STRONG_NONE | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     0,
     0,
     },

    /* Cipher C011 */
    {
     1,
     TLS1_TXT_ECDHE_RSA_WITH_RC4_128_SHA,
     TLS1_CK_ECDHE_RSA_WITH_RC4_128_SHA,
     SSL_kEECDH,
     SSL_aRSA,
     SSL_RC4,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },

    /* Cipher C012 */
    {
     1,
     TLS1_TXT_ECDHE_RSA_WITH_DES_192_CBC3_SHA,
     TLS1_CK_ECDHE_RSA_WITH_DES_192_CBC3_SHA,
     SSL_kEECDH,
     SSL_aRSA,
     SSL_3DES,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_MEDIUM | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     112,
     168,
     },

    /* Cipher C013 */
    {
     1,
     TLS1_TXT_ECDHE_RSA_WITH_AES_128_CBC_SHA,
     TLS1_CK_ECDHE_RSA_WITH_AES_128_CBC_SHA,
     SSL_kEECDH,
     SSL_aRSA,
     SSL_AES128,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },

    /* Cipher C014 */
    {
     1,
     TLS1_TXT_ECDHE_RSA_WITH_AES_256_CBC_SHA,
     TLS1_CK_ECDHE_RSA_WITH_AES_256_CBC_SHA,
     SSL_kEECDH,
     SSL_aRSA,
     SSL_AES256,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },

    /* Cipher C015 */
    {
     1,
     TLS1_TXT_ECDH_anon_WITH_NULL_SHA,
     TLS1_CK_ECDH_anon_WITH_NULL_SHA,
     SSL_kEECDH,
     SSL_aNULL,
     SSL_eNULL,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_STRONG_NONE | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     0,
     0,
     },

    /* Cipher C016 */
    {
     1,
     TLS1_TXT_ECDH_anon_WITH_RC4_128_SHA,
     TLS1_CK_ECDH_anon_WITH_RC4_128_SHA,
     SSL_kEECDH,
     SSL_aNULL,
     SSL_RC4,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_DEFAULT | SSL_NOT_EXP | SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },

    /* Cipher C017 */
    {
     1,
     TLS1_TXT_ECDH_anon_WITH_DES_192_CBC3_SHA,
     TLS1_CK_ECDH_anon_WITH_DES_192_CBC3_SHA,
     SSL_kEECDH,
     SSL_aNULL,
     SSL_3DES,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_DEFAULT | SSL_NOT_EXP | SSL_MEDIUM | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     112,
     168,
     },

    /* Cipher C018 */
    {
     1,
     TLS1_TXT_ECDH_anon_WITH_AES_128_CBC_SHA,
     TLS1_CK_ECDH_anon_WITH_AES_128_CBC_SHA,
     SSL_kEECDH,
     SSL_aNULL,
     SSL_AES128,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_DEFAULT | SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },

    /* Cipher C019 */
    {
     1,
     TLS1_TXT_ECDH_anon_WITH_AES_256_CBC_SHA,
     TLS1_CK_ECDH_anon_WITH_AES_256_CBC_SHA,
     SSL_kEECDH,
     SSL_aNULL,
     SSL_AES256,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_DEFAULT | SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },
#endif                          /* OPENSSL_NO_ECDH */

#ifndef OPENSSL_NO_SRP
    /* Cipher C01A */
    {
     1,
     TLS1_TXT_SRP_SHA_WITH_3DES_EDE_CBC_SHA,
     TLS1_CK_SRP_SHA_WITH_3DES_EDE_CBC_SHA,
     SSL_kSRP,
     SSL_aSRP,
     SSL_3DES,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     112,
     168,
     },

    /* Cipher C01B */
    {
     1,
     TLS1_TXT_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA,
     TLS1_CK_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA,
     SSL_kSRP,
     SSL_aRSA,
     SSL_3DES,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     112,
     168,
     },

    /* Cipher C01C */
    {
     1,
     TLS1_TXT_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA,
     TLS1_CK_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA,
     SSL_kSRP,
     SSL_aDSS,
     SSL_3DES,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     112,
     168,
     },

    /* Cipher C01D */
    {
     1,
     TLS1_TXT_SRP_SHA_WITH_AES_128_CBC_SHA,
     TLS1_CK_SRP_SHA_WITH_AES_128_CBC_SHA,
     SSL_kSRP,
     SSL_aSRP,
     SSL_AES128,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_HIGH,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },

    /* Cipher C01E */
    {
     1,
     TLS1_TXT_SRP_SHA_RSA_WITH_AES_128_CBC_SHA,
     TLS1_CK_SRP_SHA_RSA_WITH_AES_128_CBC_SHA,
     SSL_kSRP,
     SSL_aRSA,
     SSL_AES128,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_HIGH,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },

    /* Cipher C01F */
    {
     1,
     TLS1_TXT_SRP_SHA_DSS_WITH_AES_128_CBC_SHA,
     TLS1_CK_SRP_SHA_DSS_WITH_AES_128_CBC_SHA,
     SSL_kSRP,
     SSL_aDSS,
     SSL_AES128,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_HIGH,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },

    /* Cipher C020 */
    {
     1,
     TLS1_TXT_SRP_SHA_WITH_AES_256_CBC_SHA,
     TLS1_CK_SRP_SHA_WITH_AES_256_CBC_SHA,
     SSL_kSRP,
     SSL_aSRP,
     SSL_AES256,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_HIGH,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },

    /* Cipher C021 */
    {
     1,
     TLS1_TXT_SRP_SHA_RSA_WITH_AES_256_CBC_SHA,
     TLS1_CK_SRP_SHA_RSA_WITH_AES_256_CBC_SHA,
     SSL_kSRP,
     SSL_aRSA,
     SSL_AES256,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_HIGH,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },

    /* Cipher C022 */
    {
     1,
     TLS1_TXT_SRP_SHA_DSS_WITH_AES_256_CBC_SHA,
     TLS1_CK_SRP_SHA_DSS_WITH_AES_256_CBC_SHA,
     SSL_kSRP,
     SSL_aDSS,
     SSL_AES256,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_HIGH,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },
#endif                          /* OPENSSL_NO_SRP */
#ifndef OPENSSL_NO_ECDH

    /* HMAC based TLS v1.2 ciphersuites from RFC5289 */

    /* Cipher C023 */
    {
     1,
     TLS1_TXT_ECDHE_ECDSA_WITH_AES_128_SHA256,
     TLS1_CK_ECDHE_ECDSA_WITH_AES_128_SHA256,
     SSL_kEECDH,
     SSL_aECDSA,
     SSL_AES128,
     SSL_SHA256,
     SSL_TLSV1_2,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },

    /* Cipher C024 */
    {
     1,
     TLS1_TXT_ECDHE_ECDSA_WITH_AES_256_SHA384,
     TLS1_CK_ECDHE_ECDSA_WITH_AES_256_SHA384,
     SSL_kEECDH,
     SSL_aECDSA,
     SSL_AES256,
     SSL_SHA384,
     SSL_TLSV1_2,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },

    /* Cipher C025 */
    {
     1,
     TLS1_TXT_ECDH_ECDSA_WITH_AES_128_SHA256,
     TLS1_CK_ECDH_ECDSA_WITH_AES_128_SHA256,
     SSL_kECDHe,
     SSL_aECDH,
     SSL_AES128,
     SSL_SHA256,
     SSL_TLSV1_2,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },

    /* Cipher C026 */
    {
     1,
     TLS1_TXT_ECDH_ECDSA_WITH_AES_256_SHA384,
     TLS1_CK_ECDH_ECDSA_WITH_AES_256_SHA384,
     SSL_kECDHe,
     SSL_aECDH,
     SSL_AES256,
     SSL_SHA384,
     SSL_TLSV1_2,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },

    /* Cipher C027 */
    {
     1,
     TLS1_TXT_ECDHE_RSA_WITH_AES_128_SHA256,
     TLS1_CK_ECDHE_RSA_WITH_AES_128_SHA256,
     SSL_kEECDH,
     SSL_aRSA,
     SSL_AES128,
     SSL_SHA256,
     SSL_TLSV1_2,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },

    /* Cipher C028 */
    {
     1,
     TLS1_TXT_ECDHE_RSA_WITH_AES_256_SHA384,
     TLS1_CK_ECDHE_RSA_WITH_AES_256_SHA384,
     SSL_kEECDH,
     SSL_aRSA,
     SSL_AES256,
     SSL_SHA384,
     SSL_TLSV1_2,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },

    /* Cipher C029 */
    {
     1,
     TLS1_TXT_ECDH_RSA_WITH_AES_128_SHA256,
     TLS1_CK_ECDH_RSA_WITH_AES_128_SHA256,
     SSL_kECDHr,
     SSL_aECDH,
     SSL_AES128,
     SSL_SHA256,
     SSL_TLSV1_2,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },

    /* Cipher C02A */
    {
     1,
     TLS1_TXT_ECDH_RSA_WITH_AES_256_SHA384,
     TLS1_CK_ECDH_RSA_WITH_AES_256_SHA384,
     SSL_kECDHr,
     SSL_aECDH,
     SSL_AES256,
     SSL_SHA384,
     SSL_TLSV1_2,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },

    /* GCM based TLS v1.2 ciphersuites from RFC5289 */

    /* Cipher C02B */
    {
     1,
     TLS1_TXT_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
     TLS1_CK_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
     SSL_kEECDH,
     SSL_aECDSA,
     SSL_AES128GCM,
     SSL_AEAD,
     SSL_TLSV1_2,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },

    /* Cipher C02C */
    {
     1,
     TLS1_TXT_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
     TLS1_CK_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
     SSL_kEECDH,
     SSL_aECDSA,
     SSL_AES256GCM,
     SSL_AEAD,
     SSL_TLSV1_2,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },

    /* Cipher C02D */
    {
     1,
     TLS1_TXT_ECDH_ECDSA_WITH_AES_128_GCM_SHA256,
     TLS1_CK_ECDH_ECDSA_WITH_AES_128_GCM_SHA256,
     SSL_kECDHe,
     SSL_aECDH,
     SSL_AES128GCM,
     SSL_AEAD,
     SSL_TLSV1_2,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },

    /* Cipher C02E */
    {
     1,
     TLS1_TXT_ECDH_ECDSA_WITH_AES_256_GCM_SHA384,
     TLS1_CK_ECDH_ECDSA_WITH_AES_256_GCM_SHA384,
     SSL_kECDHe,
     SSL_aECDH,
     SSL_AES256GCM,
     SSL_AEAD,
     SSL_TLSV1_2,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },

    /* Cipher C02F */
    {
     1,
     TLS1_TXT_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
     TLS1_CK_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
     SSL_kEECDH,
     SSL_aRSA,
     SSL_AES128GCM,
     SSL_AEAD,
     SSL_TLSV1_2,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },

    /* Cipher C030 */
    {
     1,
     TLS1_TXT_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
     TLS1_CK_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
     SSL_kEECDH,
     SSL_aRSA,
     SSL_AES256GCM,
     SSL_AEAD,
     SSL_TLSV1_2,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },

    /* Cipher C031 */
    {
     1,
     TLS1_TXT_ECDH_RSA_WITH_AES_128_GCM_SHA256,
     TLS1_CK_ECDH_RSA_WITH_AES_128_GCM_SHA256,
     SSL_kECDHr,
     SSL_aECDH,
     SSL_AES128GCM,
     SSL_AEAD,
     SSL_TLSV1_2,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },

    /* Cipher C032 */
    {
     1,
     TLS1_TXT_ECDH_RSA_WITH_AES_256_GCM_SHA384,
     TLS1_CK_ECDH_RSA_WITH_AES_256_GCM_SHA384,
     SSL_kECDHr,
     SSL_aECDH,
     SSL_AES256GCM,
     SSL_AEAD,
     SSL_TLSV1_2,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },

#endif                          /* OPENSSL_NO_ECDH */

#ifdef TEMP_GOST_TLS
/* Cipher FF00 */
    {
     1,
     "GOST-MD5",
     0x0300ff00,
     SSL_kRSA,
     SSL_aRSA,
     SSL_eGOST2814789CNT,
     SSL_MD5,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_HIGH,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },
    {
     1,
     "GOST-GOST94",
     0x0300ff01,
     SSL_kRSA,
     SSL_aRSA,
     SSL_eGOST2814789CNT,
     SSL_GOST94,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_HIGH,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256},
    {
     1,
     "GOST-GOST89MAC",
     0x0300ff02,
     SSL_kRSA,
     SSL_aRSA,
     SSL_eGOST2814789CNT,
     SSL_GOST89MAC,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_HIGH,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256},
    {
     1,
     "GOST-GOST89STREAM",
     0x0300ff03,
     SSL_kRSA,
     SSL_aRSA,
     SSL_eGOST2814789CNT,
     SSL_GOST89MAC,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_HIGH,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF | TLS1_STREAM_MAC,
     256,
     256},
#endif

/* end of list */
};

SSL3_ENC_METHOD SSLv3_enc_data = {
    ssl3_enc,
    n_ssl3_mac,
    ssl3_setup_key_block,
    ssl3_generate_master_secret,
    ssl3_change_cipher_state,
    ssl3_final_finish_mac,
    MD5_DIGEST_LENGTH + SHA_DIGEST_LENGTH,
    ssl3_cert_verify_mac,
    SSL3_MD_CLIENT_FINISHED_CONST, 4,
    SSL3_MD_SERVER_FINISHED_CONST, 4,
    ssl3_alert_code,
    (int (*)(SSL *, unsigned char *, size_t, const char *,
             size_t, const unsigned char *, size_t,
             int use_context))ssl_undefined_function,
    0,
    SSL3_HM_HEADER_LENGTH,
    ssl3_set_handshake_header,
    ssl3_handshake_write
};

long ssl3_default_timeout(void)
{
    /*
     * 2 hours, the 24 hours mentioned in the SSLv3 spec is way too long for
     * http, the cache would over fill
     */
    return (60 * 60 * 2);
}

int ssl3_num_ciphers(void)
{
    return (SSL3_NUM_CIPHERS);
}

const SSL_CIPHER *ssl3_get_cipher(unsigned int u)
{
    if (u < SSL3_NUM_CIPHERS)
        return (&(ssl3_ciphers[SSL3_NUM_CIPHERS - 1 - u]));
    else
        return (NULL);
}

int ssl3_pending(const SSL *s)
{
    if (s->rstate == SSL_ST_READ_BODY)
        return 0;

    return (s->s3->rrec.type ==
            SSL3_RT_APPLICATION_DATA) ? s->s3->rrec.length : 0;
}

void ssl3_set_handshake_header(SSL *s, int htype, unsigned long len)
{
    unsigned char *p = (unsigned char *)s->init_buf->data;
    *(p++) = htype;
    l2n3(len, p);
    s->init_num = (int)len + SSL3_HM_HEADER_LENGTH;
    s->init_off = 0;
}

int ssl3_handshake_write(SSL *s)
{
    return ssl3_do_write(s, SSL3_RT_HANDSHAKE);
}

int ssl3_new(SSL *s)
{
    SSL3_STATE *s3;

    if ((s3 = OPENSSL_malloc(sizeof(*s3))) == NULL)
        goto err;
    memset(s3, 0, sizeof(*s3));
    memset(s3->rrec.seq_num, 0, sizeof(s3->rrec.seq_num));
    memset(s3->wrec.seq_num, 0, sizeof(s3->wrec.seq_num));

    s->s3 = s3;

#ifndef OPENSSL_NO_SRP
    SSL_SRP_CTX_init(s);
#endif
    s->method->ssl_clear(s);
    return (1);
 err:
    return (0);
}

void ssl3_free(SSL *s)
{
    if (s == NULL || s->s3 == NULL)
        return;

#ifdef TLSEXT_TYPE_opaque_prf_input
    if (s->s3->client_opaque_prf_input != NULL)
        OPENSSL_free(s->s3->client_opaque_prf_input);
    if (s->s3->server_opaque_prf_input != NULL)
        OPENSSL_free(s->s3->server_opaque_prf_input);
#endif

    ssl3_cleanup_key_block(s);
    if (s->s3->rbuf.buf != NULL)
        ssl3_release_read_buffer(s);
    if (s->s3->wbuf.buf != NULL)
        ssl3_release_write_buffer(s);
    if (s->s3->rrec.comp != NULL)
        OPENSSL_free(s->s3->rrec.comp);
#ifndef OPENSSL_NO_DH
    if (s->s3->tmp.dh != NULL)
        DH_free(s->s3->tmp.dh);
#endif
#ifndef OPENSSL_NO_ECDH
    if (s->s3->tmp.ecdh != NULL)
        EC_KEY_free(s->s3->tmp.ecdh);
#endif

    if (s->s3->tmp.ca_names != NULL)
        sk_X509_NAME_pop_free(s->s3->tmp.ca_names, X509_NAME_free);
    if (s->s3->handshake_buffer) {
        BIO_free(s->s3->handshake_buffer);
    }
    if (s->s3->handshake_dgst)
        ssl3_free_digest_list(s);
#ifndef OPENSSL_NO_TLSEXT
    if (s->s3->alpn_selected)
        OPENSSL_free(s->s3->alpn_selected);
#endif

#ifndef OPENSSL_NO_SRP
    SSL_SRP_CTX_free(s);
#endif
    OPENSSL_cleanse(s->s3, sizeof(*s->s3));
    OPENSSL_free(s->s3);
    s->s3 = NULL;
}

void ssl3_clear(SSL *s)
{
    unsigned char *rp, *wp;
    size_t rlen, wlen;
    int init_extra;

#ifdef TLSEXT_TYPE_opaque_prf_input
    if (s->s3->client_opaque_prf_input != NULL)
        OPENSSL_free(s->s3->client_opaque_prf_input);
    s->s3->client_opaque_prf_input = NULL;
    if (s->s3->server_opaque_prf_input != NULL)
        OPENSSL_free(s->s3->server_opaque_prf_input);
    s->s3->server_opaque_prf_input = NULL;
#endif

    ssl3_cleanup_key_block(s);
    if (s->s3->tmp.ca_names != NULL)
        sk_X509_NAME_pop_free(s->s3->tmp.ca_names, X509_NAME_free);

    if (s->s3->rrec.comp != NULL) {
        OPENSSL_free(s->s3->rrec.comp);
        s->s3->rrec.comp = NULL;
    }
#ifndef OPENSSL_NO_DH
    if (s->s3->tmp.dh != NULL) {
        DH_free(s->s3->tmp.dh);
        s->s3->tmp.dh = NULL;
    }
#endif
#ifndef OPENSSL_NO_ECDH
    if (s->s3->tmp.ecdh != NULL) {
        EC_KEY_free(s->s3->tmp.ecdh);
        s->s3->tmp.ecdh = NULL;
    }
#endif
#ifndef OPENSSL_NO_TLSEXT
# ifndef OPENSSL_NO_EC
    s->s3->is_probably_safari = 0;
# endif                         /* !OPENSSL_NO_EC */
#endif                          /* !OPENSSL_NO_TLSEXT */

    rp = s->s3->rbuf.buf;
    wp = s->s3->wbuf.buf;
    rlen = s->s3->rbuf.len;
    wlen = s->s3->wbuf.len;
    init_extra = s->s3->init_extra;
    if (s->s3->handshake_buffer) {
        BIO_free(s->s3->handshake_buffer);
        s->s3->handshake_buffer = NULL;
    }
    if (s->s3->handshake_dgst) {
        ssl3_free_digest_list(s);
    }
#if !defined(OPENSSL_NO_TLSEXT)
    if (s->s3->alpn_selected) {
        OPENSSL_free(s->s3->alpn_selected);
        s->s3->alpn_selected = NULL;
    }
#endif
    memset(s->s3, 0, sizeof(*s->s3));
    s->s3->rbuf.buf = rp;
    s->s3->wbuf.buf = wp;
    s->s3->rbuf.len = rlen;
    s->s3->wbuf.len = wlen;
    s->s3->init_extra = init_extra;

    ssl_free_wbio_buffer(s);

    s->packet_length = 0;
    s->s3->renegotiate = 0;
    s->s3->total_renegotiations = 0;
    s->s3->num_renegotiations = 0;
    s->s3->in_read_app_data = 0;
    s->version = SSL3_VERSION;

#if !defined(OPENSSL_NO_TLSEXT) && !defined(OPENSSL_NO_NEXTPROTONEG)
    if (s->next_proto_negotiated) {
        OPENSSL_free(s->next_proto_negotiated);
        s->next_proto_negotiated = NULL;
        s->next_proto_negotiated_len = 0;
    }
#endif
}

#ifndef OPENSSL_NO_SRP
static char *MS_CALLBACK srp_password_from_info_cb(SSL *s, void *arg)
{
    return BUF_strdup(s->srp_ctx.info);
}
#endif

static int ssl3_set_req_cert_type(CERT *c, const unsigned char *p,
                                  size_t len);

long ssl3_ctrl(SSL *s, int cmd, long larg, void *parg)
{
    int ret = 0;

#if !defined(OPENSSL_NO_DSA) || !defined(OPENSSL_NO_RSA)
    if (
# ifndef OPENSSL_NO_RSA
           cmd == SSL_CTRL_SET_TMP_RSA || cmd == SSL_CTRL_SET_TMP_RSA_CB ||
# endif
# ifndef OPENSSL_NO_DSA
           cmd == SSL_CTRL_SET_TMP_DH || cmd == SSL_CTRL_SET_TMP_DH_CB ||
# endif
           0) {
        if (!ssl_cert_inst(&s->cert)) {
            SSLerr(SSL_F_SSL3_CTRL, ERR_R_MALLOC_FAILURE);
            return (0);
        }
    }
#endif

    switch (cmd) {
    case SSL_CTRL_GET_SESSION_REUSED:
        ret = s->hit;
        break;
    case SSL_CTRL_GET_CLIENT_CERT_REQUEST:
        break;
    case SSL_CTRL_GET_NUM_RENEGOTIATIONS:
        ret = s->s3->num_renegotiations;
        break;
    case SSL_CTRL_CLEAR_NUM_RENEGOTIATIONS:
        ret = s->s3->num_renegotiations;
        s->s3->num_renegotiations = 0;
        break;
    case SSL_CTRL_GET_TOTAL_RENEGOTIATIONS:
        ret = s->s3->total_renegotiations;
        break;
    case SSL_CTRL_GET_FLAGS:
        ret = (int)(s->s3->flags);
        break;
#ifndef OPENSSL_NO_RSA
    case SSL_CTRL_NEED_TMP_RSA:
        if ((s->cert != NULL) && (s->cert->rsa_tmp == NULL) &&
            ((s->cert->pkeys[SSL_PKEY_RSA_ENC].privatekey == NULL) ||
             (EVP_PKEY_size(s->cert->pkeys[SSL_PKEY_RSA_ENC].privatekey) >
              (512 / 8))))
            ret = 1;
        break;
    case SSL_CTRL_SET_TMP_RSA:
        {
            RSA *rsa = (RSA *)parg;
            if (rsa == NULL) {
                SSLerr(SSL_F_SSL3_CTRL, ERR_R_PASSED_NULL_PARAMETER);
                return (ret);
            }
            if ((rsa = RSAPrivateKey_dup(rsa)) == NULL) {
                SSLerr(SSL_F_SSL3_CTRL, ERR_R_RSA_LIB);
                return (ret);
            }
            if (s->cert->rsa_tmp != NULL)
                RSA_free(s->cert->rsa_tmp);
            s->cert->rsa_tmp = rsa;
            ret = 1;
        }
        break;
    case SSL_CTRL_SET_TMP_RSA_CB:
        {
            SSLerr(SSL_F_SSL3_CTRL, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
            return (ret);
        }
        break;
#endif
#ifndef OPENSSL_NO_DH
    case SSL_CTRL_SET_TMP_DH:
        {
            DH *dh = (DH *)parg;
            if (dh == NULL) {
                SSLerr(SSL_F_SSL3_CTRL, ERR_R_PASSED_NULL_PARAMETER);
                return (ret);
            }
            if ((dh = DHparams_dup(dh)) == NULL) {
                SSLerr(SSL_F_SSL3_CTRL, ERR_R_DH_LIB);
                return (ret);
            }
            if (s->cert->dh_tmp != NULL)
                DH_free(s->cert->dh_tmp);
            s->cert->dh_tmp = dh;
            ret = 1;
        }
        break;
    case SSL_CTRL_SET_TMP_DH_CB:
        {
            SSLerr(SSL_F_SSL3_CTRL, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
            return (ret);
        }
        break;
#endif
#ifndef OPENSSL_NO_ECDH
    case SSL_CTRL_SET_TMP_ECDH:
        {
            EC_KEY *ecdh = NULL;

            if (parg == NULL) {
                SSLerr(SSL_F_SSL3_CTRL, ERR_R_PASSED_NULL_PARAMETER);
                return (ret);
            }
            if (!EC_KEY_up_ref((EC_KEY *)parg)) {
                SSLerr(SSL_F_SSL3_CTRL, ERR_R_ECDH_LIB);
                return (ret);
            }
            ecdh = (EC_KEY *)parg;
            if (!(s->options & SSL_OP_SINGLE_ECDH_USE)) {
                if (!EC_KEY_generate_key(ecdh)) {
                    EC_KEY_free(ecdh);
                    SSLerr(SSL_F_SSL3_CTRL, ERR_R_ECDH_LIB);
                    return (ret);
                }
            }
            if (s->cert->ecdh_tmp != NULL)
                EC_KEY_free(s->cert->ecdh_tmp);
            s->cert->ecdh_tmp = ecdh;
            ret = 1;
        }
        break;
    case SSL_CTRL_SET_TMP_ECDH_CB:
        {
            SSLerr(SSL_F_SSL3_CTRL, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
            return (ret);
        }
        break;
#endif                          /* !OPENSSL_NO_ECDH */
#ifndef OPENSSL_NO_TLSEXT
    case SSL_CTRL_SET_TLSEXT_HOSTNAME:
        if (larg == TLSEXT_NAMETYPE_host_name) {
            size_t len;

            if (s->tlsext_hostname != NULL)
                OPENSSL_free(s->tlsext_hostname);
            s->tlsext_hostname = NULL;

            ret = 1;
            if (parg == NULL)
                break;
            len = strlen((char *)parg);
            if (len == 0 || len > TLSEXT_MAXLEN_host_name) {
                SSLerr(SSL_F_SSL3_CTRL, SSL_R_SSL3_EXT_INVALID_SERVERNAME);
                return 0;
            }
            if ((s->tlsext_hostname = BUF_strdup((char *)parg)) == NULL) {
                SSLerr(SSL_F_SSL3_CTRL, ERR_R_INTERNAL_ERROR);
                return 0;
            }
        } else {
            SSLerr(SSL_F_SSL3_CTRL, SSL_R_SSL3_EXT_INVALID_SERVERNAME_TYPE);
            return 0;
        }
        break;
    case SSL_CTRL_SET_TLSEXT_DEBUG_ARG:
        s->tlsext_debug_arg = parg;
        ret = 1;
        break;

# ifdef TLSEXT_TYPE_opaque_prf_input
    case SSL_CTRL_SET_TLSEXT_OPAQUE_PRF_INPUT:
        if (larg > 12288) {     /* actual internal limit is 2^16 for the
                                 * complete hello message * (including the
                                 * cert chain and everything) */
            SSLerr(SSL_F_SSL3_CTRL, SSL_R_OPAQUE_PRF_INPUT_TOO_LONG);
            break;
        }
        if (s->tlsext_opaque_prf_input != NULL)
            OPENSSL_free(s->tlsext_opaque_prf_input);
        if ((size_t)larg == 0)
            s->tlsext_opaque_prf_input = OPENSSL_malloc(1); /* dummy byte
                                                             * just to get
                                                             * non-NULL */
        else
            s->tlsext_opaque_prf_input = BUF_memdup(parg, (size_t)larg);
        if (s->tlsext_opaque_prf_input != NULL) {
            s->tlsext_opaque_prf_input_len = (size_t)larg;
            ret = 1;
        } else
            s->tlsext_opaque_prf_input_len = 0;
        break;
# endif

    case SSL_CTRL_SET_TLSEXT_STATUS_REQ_TYPE:
        s->tlsext_status_type = larg;
        ret = 1;
        break;

    case SSL_CTRL_GET_TLSEXT_STATUS_REQ_EXTS:
        *(STACK_OF(X509_EXTENSION) **)parg = s->tlsext_ocsp_exts;
        ret = 1;
        break;

    case SSL_CTRL_SET_TLSEXT_STATUS_REQ_EXTS:
        s->tlsext_ocsp_exts = parg;
        ret = 1;
        break;

    case SSL_CTRL_GET_TLSEXT_STATUS_REQ_IDS:
        *(STACK_OF(OCSP_RESPID) **)parg = s->tlsext_ocsp_ids;
        ret = 1;
        break;

    case SSL_CTRL_SET_TLSEXT_STATUS_REQ_IDS:
        s->tlsext_ocsp_ids = parg;
        ret = 1;
        break;

    case SSL_CTRL_GET_TLSEXT_STATUS_REQ_OCSP_RESP:
        *(unsigned char **)parg = s->tlsext_ocsp_resp;
        return s->tlsext_ocsp_resplen;

    case SSL_CTRL_SET_TLSEXT_STATUS_REQ_OCSP_RESP:
        if (s->tlsext_ocsp_resp)
            OPENSSL_free(s->tlsext_ocsp_resp);
        s->tlsext_ocsp_resp = parg;
        s->tlsext_ocsp_resplen = larg;
        ret = 1;
        break;

# ifndef OPENSSL_NO_HEARTBEATS
    case SSL_CTRL_TLS_EXT_SEND_HEARTBEAT:
        if (SSL_IS_DTLS(s))
            ret = dtls1_heartbeat(s);
        else
            ret = tls1_heartbeat(s);
        break;

    case SSL_CTRL_GET_TLS_EXT_HEARTBEAT_PENDING:
        ret = s->tlsext_hb_pending;
        break;

    case SSL_CTRL_SET_TLS_EXT_HEARTBEAT_NO_REQUESTS:
        if (larg)
            s->tlsext_heartbeat |= SSL_TLSEXT_HB_DONT_RECV_REQUESTS;
        else
            s->tlsext_heartbeat &= ~SSL_TLSEXT_HB_DONT_RECV_REQUESTS;
        ret = 1;
        break;
# endif

#endif                          /* !OPENSSL_NO_TLSEXT */

    case SSL_CTRL_CHAIN:
        if (larg)
            return ssl_cert_set1_chain(s->cert, (STACK_OF(X509) *)parg);
        else
            return ssl_cert_set0_chain(s->cert, (STACK_OF(X509) *)parg);

    case SSL_CTRL_CHAIN_CERT:
        if (larg)
            return ssl_cert_add1_chain_cert(s->cert, (X509 *)parg);
        else
            return ssl_cert_add0_chain_cert(s->cert, (X509 *)parg);

    case SSL_CTRL_GET_CHAIN_CERTS:
        *(STACK_OF(X509) **)parg = s->cert->key->chain;
        break;

    case SSL_CTRL_SELECT_CURRENT_CERT:
        return ssl_cert_select_current(s->cert, (X509 *)parg);

    case SSL_CTRL_SET_CURRENT_CERT:
        if (larg == SSL_CERT_SET_SERVER) {
            CERT_PKEY *cpk;
            const SSL_CIPHER *cipher;
            if (!s->server)
                return 0;
            cipher = s->s3->tmp.new_cipher;
            if (!cipher)
                return 0;
            /*
             * No certificate for unauthenticated ciphersuites or using SRP
             * authentication
             */
            if (cipher->algorithm_auth & (SSL_aNULL | SSL_aSRP))
                return 2;
            cpk = ssl_get_server_send_pkey(s);
            if (!cpk)
                return 0;
            s->cert->key = cpk;
            return 1;
        }
        return ssl_cert_set_current(s->cert, larg);

#ifndef OPENSSL_NO_EC
    case SSL_CTRL_GET_CURVES:
        {
            unsigned char *clist;
            size_t clistlen;
            if (!s->session)
                return 0;
            clist = s->session->tlsext_ellipticcurvelist;
            clistlen = s->session->tlsext_ellipticcurvelist_length / 2;
            if (parg) {
                size_t i;
                int *cptr = parg;
                unsigned int cid, nid;
                for (i = 0; i < clistlen; i++) {
                    n2s(clist, cid);
                    nid = tls1_ec_curve_id2nid(cid);
                    if (nid != 0)
                        cptr[i] = nid;
                    else
                        cptr[i] = TLSEXT_nid_unknown | cid;
                }
            }
            return (int)clistlen;
        }

    case SSL_CTRL_SET_CURVES:
        return tls1_set_curves(&s->tlsext_ellipticcurvelist,
                               &s->tlsext_ellipticcurvelist_length,
                               parg, larg);

    case SSL_CTRL_SET_CURVES_LIST:
        return tls1_set_curves_list(&s->tlsext_ellipticcurvelist,
                                    &s->tlsext_ellipticcurvelist_length,
                                    parg);

    case SSL_CTRL_GET_SHARED_CURVE:
        return tls1_shared_curve(s, larg);

# ifndef OPENSSL_NO_ECDH
    case SSL_CTRL_SET_ECDH_AUTO:
        s->cert->ecdh_tmp_auto = larg;
        return 1;
# endif
#endif
    case SSL_CTRL_SET_SIGALGS:
        return tls1_set_sigalgs(s->cert, parg, larg, 0);

    case SSL_CTRL_SET_SIGALGS_LIST:
        return tls1_set_sigalgs_list(s->cert, parg, 0);

    case SSL_CTRL_SET_CLIENT_SIGALGS:
        return tls1_set_sigalgs(s->cert, parg, larg, 1);

    case SSL_CTRL_SET_CLIENT_SIGALGS_LIST:
        return tls1_set_sigalgs_list(s->cert, parg, 1);

    case SSL_CTRL_GET_CLIENT_CERT_TYPES:
        {
            const unsigned char **pctype = parg;
            if (s->server || !s->s3->tmp.cert_req)
                return 0;
            if (s->cert->ctypes) {
                if (pctype)
                    *pctype = s->cert->ctypes;
                return (int)s->cert->ctype_num;
            }
            if (pctype)
                *pctype = (unsigned char *)s->s3->tmp.ctype;
            return s->s3->tmp.ctype_num;
        }

    case SSL_CTRL_SET_CLIENT_CERT_TYPES:
        if (!s->server)
            return 0;
        return ssl3_set_req_cert_type(s->cert, parg, larg);

    case SSL_CTRL_BUILD_CERT_CHAIN:
        return ssl_build_cert_chain(s->cert, s->ctx->cert_store, larg);

    case SSL_CTRL_SET_VERIFY_CERT_STORE:
        return ssl_cert_set_cert_store(s->cert, parg, 0, larg);

    case SSL_CTRL_SET_CHAIN_CERT_STORE:
        return ssl_cert_set_cert_store(s->cert, parg, 1, larg);

    case SSL_CTRL_GET_PEER_SIGNATURE_NID:
        if (SSL_USE_SIGALGS(s)) {
            if (s->session && s->session->sess_cert) {
                const EVP_MD *sig;
                sig = s->session->sess_cert->peer_key->digest;
                if (sig) {
                    *(int *)parg = EVP_MD_type(sig);
                    return 1;
                }
            }
            return 0;
        }
        /* Might want to do something here for other versions */
        else
            return 0;

    case SSL_CTRL_GET_SERVER_TMP_KEY:
        if (s->server || !s->session || !s->session->sess_cert)
            return 0;
        else {
            SESS_CERT *sc;
            EVP_PKEY *ptmp;
            int rv = 0;
            sc = s->session->sess_cert;
#if !defined(OPENSSL_NO_RSA) && !defined(OPENSSL_NO_DH) && !defined(OPENSSL_NO_EC) && !defined(OPENSSL_NO_ECDH)
            if (!sc->peer_rsa_tmp && !sc->peer_dh_tmp && !sc->peer_ecdh_tmp)
                return 0;
#endif
            ptmp = EVP_PKEY_new();
            if (!ptmp)
                return 0;
            if (0) ;
#ifndef OPENSSL_NO_RSA
            else if (sc->peer_rsa_tmp)
                rv = EVP_PKEY_set1_RSA(ptmp, sc->peer_rsa_tmp);
#endif
#ifndef OPENSSL_NO_DH
            else if (sc->peer_dh_tmp)
                rv = EVP_PKEY_set1_DH(ptmp, sc->peer_dh_tmp);
#endif
#ifndef OPENSSL_NO_ECDH
            else if (sc->peer_ecdh_tmp)
                rv = EVP_PKEY_set1_EC_KEY(ptmp, sc->peer_ecdh_tmp);
#endif
            if (rv) {
                *(EVP_PKEY **)parg = ptmp;
                return 1;
            }
            EVP_PKEY_free(ptmp);
            return 0;
        }
#ifndef OPENSSL_NO_EC
    case SSL_CTRL_GET_EC_POINT_FORMATS:
        {
            SSL_SESSION *sess = s->session;
            const unsigned char **pformat = parg;
            if (!sess || !sess->tlsext_ecpointformatlist)
                return 0;
            *pformat = sess->tlsext_ecpointformatlist;
            return (int)sess->tlsext_ecpointformatlist_length;
        }
#endif

    case SSL_CTRL_CHECK_PROTO_VERSION:
        /*
         * For library-internal use; checks that the current protocol is the
         * highest enabled version (according to s->ctx->method, as version
         * negotiation may have changed s->method).
         */
        if (s->version == s->ctx->method->version)
            return 1;
        /*
         * Apparently we're using a version-flexible SSL_METHOD (not at its
         * highest protocol version).
         */
        if (s->ctx->method->version == SSLv23_method()->version) {
#if TLS_MAX_VERSION != TLS1_2_VERSION
# error Code needs update for SSLv23_method() support beyond TLS1_2_VERSION.
#endif
            if (!(s->options & SSL_OP_NO_TLSv1_2))
                return s->version == TLS1_2_VERSION;
            if (!(s->options & SSL_OP_NO_TLSv1_1))
                return s->version == TLS1_1_VERSION;
            if (!(s->options & SSL_OP_NO_TLSv1))
                return s->version == TLS1_VERSION;
            if (!(s->options & SSL_OP_NO_SSLv3))
                return s->version == SSL3_VERSION;
            if (!(s->options & SSL_OP_NO_SSLv2))
                return s->version == SSL2_VERSION;
        }
        return 0;               /* Unexpected state; fail closed. */

    default:
        break;
    }
    return (ret);
}

long ssl3_callback_ctrl(SSL *s, int cmd, void (*fp) (void))
{
    int ret = 0;

#if !defined(OPENSSL_NO_DSA) || !defined(OPENSSL_NO_RSA)
    if (
# ifndef OPENSSL_NO_RSA
           cmd == SSL_CTRL_SET_TMP_RSA_CB ||
# endif
# ifndef OPENSSL_NO_DSA
           cmd == SSL_CTRL_SET_TMP_DH_CB ||
# endif
           0) {
        if (!ssl_cert_inst(&s->cert)) {
            SSLerr(SSL_F_SSL3_CALLBACK_CTRL, ERR_R_MALLOC_FAILURE);
            return (0);
        }
    }
#endif

    switch (cmd) {
#ifndef OPENSSL_NO_RSA
    case SSL_CTRL_SET_TMP_RSA_CB:
        {
            s->cert->rsa_tmp_cb = (RSA *(*)(SSL *, int, int))fp;
        }
        break;
#endif
#ifndef OPENSSL_NO_DH
    case SSL_CTRL_SET_TMP_DH_CB:
        {
            s->cert->dh_tmp_cb = (DH *(*)(SSL *, int, int))fp;
        }
        break;
#endif
#ifndef OPENSSL_NO_ECDH
    case SSL_CTRL_SET_TMP_ECDH_CB:
        {
            s->cert->ecdh_tmp_cb = (EC_KEY *(*)(SSL *, int, int))fp;
        }
        break;
#endif
#ifndef OPENSSL_NO_TLSEXT
    case SSL_CTRL_SET_TLSEXT_DEBUG_CB:
        s->tlsext_debug_cb = (void (*)(SSL *, int, int,
                                       unsigned char *, int, void *))fp;
        break;
#endif
    default:
        break;
    }
    return (ret);
}

long ssl3_ctx_ctrl(SSL_CTX *ctx, int cmd, long larg, void *parg)
{
    CERT *cert;

    cert = ctx->cert;

    switch (cmd) {
#ifndef OPENSSL_NO_RSA
    case SSL_CTRL_NEED_TMP_RSA:
        if ((cert->rsa_tmp == NULL) &&
            ((cert->pkeys[SSL_PKEY_RSA_ENC].privatekey == NULL) ||
             (EVP_PKEY_size(cert->pkeys[SSL_PKEY_RSA_ENC].privatekey) >
              (512 / 8)))
            )
            return (1);
        else
            return (0);
        /* break; */
    case SSL_CTRL_SET_TMP_RSA:
        {
            RSA *rsa;
            int i;

            rsa = (RSA *)parg;
            i = 1;
            if (rsa == NULL)
                i = 0;
            else {
                if ((rsa = RSAPrivateKey_dup(rsa)) == NULL)
                    i = 0;
            }
            if (!i) {
                SSLerr(SSL_F_SSL3_CTX_CTRL, ERR_R_RSA_LIB);
                return (0);
            } else {
                if (cert->rsa_tmp != NULL)
                    RSA_free(cert->rsa_tmp);
                cert->rsa_tmp = rsa;
                return (1);
            }
        }
        /* break; */
    case SSL_CTRL_SET_TMP_RSA_CB:
        {
            SSLerr(SSL_F_SSL3_CTX_CTRL, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
            return (0);
        }
        break;
#endif
#ifndef OPENSSL_NO_DH
    case SSL_CTRL_SET_TMP_DH:
        {
            DH *new = NULL, *dh;

            dh = (DH *)parg;
            if ((new = DHparams_dup(dh)) == NULL) {
                SSLerr(SSL_F_SSL3_CTX_CTRL, ERR_R_DH_LIB);
                return 0;
            }
            if (cert->dh_tmp != NULL)
                DH_free(cert->dh_tmp);
            cert->dh_tmp = new;
            return 1;
        }
        /*
         * break;
         */
    case SSL_CTRL_SET_TMP_DH_CB:
        {
            SSLerr(SSL_F_SSL3_CTX_CTRL, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
            return (0);
        }
        break;
#endif
#ifndef OPENSSL_NO_ECDH
    case SSL_CTRL_SET_TMP_ECDH:
        {
            EC_KEY *ecdh = NULL;

            if (parg == NULL) {
                SSLerr(SSL_F_SSL3_CTX_CTRL, ERR_R_ECDH_LIB);
                return 0;
            }
            ecdh = EC_KEY_dup((EC_KEY *)parg);
            if (ecdh == NULL) {
                SSLerr(SSL_F_SSL3_CTX_CTRL, ERR_R_EC_LIB);
                return 0;
            }
            if (!(ctx->options & SSL_OP_SINGLE_ECDH_USE)) {
                if (!EC_KEY_generate_key(ecdh)) {
                    EC_KEY_free(ecdh);
                    SSLerr(SSL_F_SSL3_CTX_CTRL, ERR_R_ECDH_LIB);
                    return 0;
                }
            }

            if (cert->ecdh_tmp != NULL) {
                EC_KEY_free(cert->ecdh_tmp);
            }
            cert->ecdh_tmp = ecdh;
            return 1;
        }
        /* break; */
    case SSL_CTRL_SET_TMP_ECDH_CB:
        {
            SSLerr(SSL_F_SSL3_CTX_CTRL, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
            return (0);
        }
        break;
#endif                          /* !OPENSSL_NO_ECDH */
#ifndef OPENSSL_NO_TLSEXT
    case SSL_CTRL_SET_TLSEXT_SERVERNAME_ARG:
        ctx->tlsext_servername_arg = parg;
        break;
    case SSL_CTRL_SET_TLSEXT_TICKET_KEYS:
    case SSL_CTRL_GET_TLSEXT_TICKET_KEYS:
        {
            unsigned char *keys = parg;
            if (!keys)
                return 48;
            if (larg != 48) {
                SSLerr(SSL_F_SSL3_CTX_CTRL, SSL_R_INVALID_TICKET_KEYS_LENGTH);
                return 0;
            }
            if (cmd == SSL_CTRL_SET_TLSEXT_TICKET_KEYS) {
                memcpy(ctx->tlsext_tick_key_name, keys, 16);
                memcpy(ctx->tlsext_tick_hmac_key, keys + 16, 16);
                memcpy(ctx->tlsext_tick_aes_key, keys + 32, 16);
            } else {
                memcpy(keys, ctx->tlsext_tick_key_name, 16);
                memcpy(keys + 16, ctx->tlsext_tick_hmac_key, 16);
                memcpy(keys + 32, ctx->tlsext_tick_aes_key, 16);
            }
            return 1;
        }

# ifdef TLSEXT_TYPE_opaque_prf_input
    case SSL_CTRL_SET_TLSEXT_OPAQUE_PRF_INPUT_CB_ARG:
        ctx->tlsext_opaque_prf_input_callback_arg = parg;
        return 1;
# endif

    case SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB_ARG:
        ctx->tlsext_status_arg = parg;
        return 1;
        break;

# ifndef OPENSSL_NO_SRP
    case SSL_CTRL_SET_TLS_EXT_SRP_USERNAME:
        ctx->srp_ctx.srp_Mask |= SSL_kSRP;
        if (ctx->srp_ctx.login != NULL)
            OPENSSL_free(ctx->srp_ctx.login);
        ctx->srp_ctx.login = NULL;
        if (parg == NULL)
            break;
        if (strlen((const char *)parg) > 255
            || strlen((const char *)parg) < 1) {
            SSLerr(SSL_F_SSL3_CTX_CTRL, SSL_R_INVALID_SRP_USERNAME);
            return 0;
        }
        if ((ctx->srp_ctx.login = BUF_strdup((char *)parg)) == NULL) {
            SSLerr(SSL_F_SSL3_CTX_CTRL, ERR_R_INTERNAL_ERROR);
            return 0;
        }
        break;
    case SSL_CTRL_SET_TLS_EXT_SRP_PASSWORD:
        ctx->srp_ctx.SRP_give_srp_client_pwd_callback =
            srp_password_from_info_cb;
        ctx->srp_ctx.info = parg;
        break;
    case SSL_CTRL_SET_SRP_ARG:
        ctx->srp_ctx.srp_Mask |= SSL_kSRP;
        ctx->srp_ctx.SRP_cb_arg = parg;
        break;

    case SSL_CTRL_SET_TLS_EXT_SRP_STRENGTH:
        ctx->srp_ctx.strength = larg;
        break;
# endif

# ifndef OPENSSL_NO_EC
    case SSL_CTRL_SET_CURVES:
        return tls1_set_curves(&ctx->tlsext_ellipticcurvelist,
                               &ctx->tlsext_ellipticcurvelist_length,
                               parg, larg);

    case SSL_CTRL_SET_CURVES_LIST:
        return tls1_set_curves_list(&ctx->tlsext_ellipticcurvelist,
                                    &ctx->tlsext_ellipticcurvelist_length,
                                    parg);
#  ifndef OPENSSL_NO_ECDH
    case SSL_CTRL_SET_ECDH_AUTO:
        ctx->cert->ecdh_tmp_auto = larg;
        return 1;
#  endif
# endif
    case SSL_CTRL_SET_SIGALGS:
        return tls1_set_sigalgs(ctx->cert, parg, larg, 0);

    case SSL_CTRL_SET_SIGALGS_LIST:
        return tls1_set_sigalgs_list(ctx->cert, parg, 0);

    case SSL_CTRL_SET_CLIENT_SIGALGS:
        return tls1_set_sigalgs(ctx->cert, parg, larg, 1);

    case SSL_CTRL_SET_CLIENT_SIGALGS_LIST:
        return tls1_set_sigalgs_list(ctx->cert, parg, 1);

    case SSL_CTRL_SET_CLIENT_CERT_TYPES:
        return ssl3_set_req_cert_type(ctx->cert, parg, larg);

    case SSL_CTRL_BUILD_CERT_CHAIN:
        return ssl_build_cert_chain(ctx->cert, ctx->cert_store, larg);

    case SSL_CTRL_SET_VERIFY_CERT_STORE:
        return ssl_cert_set_cert_store(ctx->cert, parg, 0, larg);

    case SSL_CTRL_SET_CHAIN_CERT_STORE:
        return ssl_cert_set_cert_store(ctx->cert, parg, 1, larg);

#endif                          /* !OPENSSL_NO_TLSEXT */

        /* A Thawte special :-) */
    case SSL_CTRL_EXTRA_CHAIN_CERT:
        if (ctx->extra_certs == NULL) {
            if ((ctx->extra_certs = sk_X509_new_null()) == NULL)
                return (0);
        }
        sk_X509_push(ctx->extra_certs, (X509 *)parg);
        break;

    case SSL_CTRL_GET_EXTRA_CHAIN_CERTS:
        if (ctx->extra_certs == NULL && larg == 0)
            *(STACK_OF(X509) **)parg = ctx->cert->key->chain;
        else
            *(STACK_OF(X509) **)parg = ctx->extra_certs;
        break;

    case SSL_CTRL_CLEAR_EXTRA_CHAIN_CERTS:
        if (ctx->extra_certs) {
            sk_X509_pop_free(ctx->extra_certs, X509_free);
            ctx->extra_certs = NULL;
        }
        break;

    case SSL_CTRL_CHAIN:
        if (larg)
            return ssl_cert_set1_chain(ctx->cert, (STACK_OF(X509) *)parg);
        else
            return ssl_cert_set0_chain(ctx->cert, (STACK_OF(X509) *)parg);

    case SSL_CTRL_CHAIN_CERT:
        if (larg)
            return ssl_cert_add1_chain_cert(ctx->cert, (X509 *)parg);
        else
            return ssl_cert_add0_chain_cert(ctx->cert, (X509 *)parg);

    case SSL_CTRL_GET_CHAIN_CERTS:
        *(STACK_OF(X509) **)parg = ctx->cert->key->chain;
        break;

    case SSL_CTRL_SELECT_CURRENT_CERT:
        return ssl_cert_select_current(ctx->cert, (X509 *)parg);

    case SSL_CTRL_SET_CURRENT_CERT:
        return ssl_cert_set_current(ctx->cert, larg);

    default:
        return (0);
    }
    return (1);
}

long ssl3_ctx_callback_ctrl(SSL_CTX *ctx, int cmd, void (*fp) (void))
{
    CERT *cert;

    cert = ctx->cert;

    switch (cmd) {
#ifndef OPENSSL_NO_RSA
    case SSL_CTRL_SET_TMP_RSA_CB:
        {
            cert->rsa_tmp_cb = (RSA *(*)(SSL *, int, int))fp;
        }
        break;
#endif
#ifndef OPENSSL_NO_DH
    case SSL_CTRL_SET_TMP_DH_CB:
        {
            cert->dh_tmp_cb = (DH *(*)(SSL *, int, int))fp;
        }
        break;
#endif
#ifndef OPENSSL_NO_ECDH
    case SSL_CTRL_SET_TMP_ECDH_CB:
        {
            cert->ecdh_tmp_cb = (EC_KEY *(*)(SSL *, int, int))fp;
        }
        break;
#endif
#ifndef OPENSSL_NO_TLSEXT
    case SSL_CTRL_SET_TLSEXT_SERVERNAME_CB:
        ctx->tlsext_servername_callback = (int (*)(SSL *, int *, void *))fp;
        break;

# ifdef TLSEXT_TYPE_opaque_prf_input
    case SSL_CTRL_SET_TLSEXT_OPAQUE_PRF_INPUT_CB:
        ctx->tlsext_opaque_prf_input_callback =
            (int (*)(SSL *, void *, size_t, void *))fp;
        break;
# endif

    case SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB:
        ctx->tlsext_status_cb = (int (*)(SSL *, void *))fp;
        break;

    case SSL_CTRL_SET_TLSEXT_TICKET_KEY_CB:
        ctx->tlsext_ticket_key_cb = (int (*)(SSL *, unsigned char *,
                                             unsigned char *,
                                             EVP_CIPHER_CTX *,
                                             HMAC_CTX *, int))fp;
        break;

# ifndef OPENSSL_NO_SRP
    case SSL_CTRL_SET_SRP_VERIFY_PARAM_CB:
        ctx->srp_ctx.srp_Mask |= SSL_kSRP;
        ctx->srp_ctx.SRP_verify_param_callback = (int (*)(SSL *, void *))fp;
        break;
    case SSL_CTRL_SET_TLS_EXT_SRP_USERNAME_CB:
        ctx->srp_ctx.srp_Mask |= SSL_kSRP;
        ctx->srp_ctx.TLS_ext_srp_username_callback =
            (int (*)(SSL *, int *, void *))fp;
        break;
    case SSL_CTRL_SET_SRP_GIVE_CLIENT_PWD_CB:
        ctx->srp_ctx.srp_Mask |= SSL_kSRP;
        ctx->srp_ctx.SRP_give_srp_client_pwd_callback =
            (char *(*)(SSL *, void *))fp;
        break;
# endif
#endif
    default:
        return (0);
    }
    return (1);
}

/*
 * This function needs to check if the ciphers required are actually
 * available
 */
const SSL_CIPHER *ssl3_get_cipher_by_char(const unsigned char *p)
{
    SSL_CIPHER c;
    const SSL_CIPHER *cp;
    unsigned long id;

    id = 0x03000000L | ((unsigned long)p[0] << 8L) | (unsigned long)p[1];
    c.id = id;
    cp = OBJ_bsearch_ssl_cipher_id(&c, ssl3_ciphers, SSL3_NUM_CIPHERS);
#ifdef DEBUG_PRINT_UNKNOWN_CIPHERSUITES
    if (cp == NULL)
        fprintf(stderr, "Unknown cipher ID %x\n", (p[0] << 8) | p[1]);
#endif
    return cp;
}

int ssl3_put_cipher_by_char(const SSL_CIPHER *c, unsigned char *p)
{
    long l;

    if (p != NULL) {
        l = c->id;
        if ((l & 0xff000000) != 0x03000000)
            return (0);
        p[0] = ((unsigned char)(l >> 8L)) & 0xFF;
        p[1] = ((unsigned char)(l)) & 0xFF;
    }
    return (2);
}

SSL_CIPHER *ssl3_choose_cipher(SSL *s, STACK_OF(SSL_CIPHER) *clnt,
                               STACK_OF(SSL_CIPHER) *srvr)
{
    SSL_CIPHER *c, *ret = NULL;
    STACK_OF(SSL_CIPHER) *prio, *allow;
    int i, ii, ok;
    CERT *cert;
    unsigned long alg_k, alg_a, mask_k, mask_a, emask_k, emask_a;

    /* Let's see which ciphers we can support */
    cert = s->cert;

#if 0
    /*
     * Do not set the compare functions, because this may lead to a
     * reordering by "id". We want to keep the original ordering. We may pay
     * a price in performance during sk_SSL_CIPHER_find(), but would have to
     * pay with the price of sk_SSL_CIPHER_dup().
     */
    sk_SSL_CIPHER_set_cmp_func(srvr, ssl_cipher_ptr_id_cmp);
    sk_SSL_CIPHER_set_cmp_func(clnt, ssl_cipher_ptr_id_cmp);
#endif

#ifdef CIPHER_DEBUG
    fprintf(stderr, "Server has %d from %p:\n", sk_SSL_CIPHER_num(srvr),
            (void *)srvr);
    for (i = 0; i < sk_SSL_CIPHER_num(srvr); ++i) {
        c = sk_SSL_CIPHER_value(srvr, i);
        fprintf(stderr, "%p:%s\n", (void *)c, c->name);
    }
    fprintf(stderr, "Client sent %d from %p:\n", sk_SSL_CIPHER_num(clnt),
            (void *)clnt);
    for (i = 0; i < sk_SSL_CIPHER_num(clnt); ++i) {
        c = sk_SSL_CIPHER_value(clnt, i);
        fprintf(stderr, "%p:%s\n", (void *)c, c->name);
    }
#endif

    if (s->options & SSL_OP_CIPHER_SERVER_PREFERENCE || tls1_suiteb(s)) {
        prio = srvr;
        allow = clnt;
    } else {
        prio = clnt;
        allow = srvr;
    }

    tls1_set_cert_validity(s);

    for (i = 0; i < sk_SSL_CIPHER_num(prio); i++) {
        c = sk_SSL_CIPHER_value(prio, i);

        /* Skip TLS v1.2 only ciphersuites if not supported */
        if ((c->algorithm_ssl & SSL_TLSV1_2) && !SSL_USE_TLS1_2_CIPHERS(s))
            continue;

        ssl_set_cert_masks(cert, c);
        mask_k = cert->mask_k;
        mask_a = cert->mask_a;
        emask_k = cert->export_mask_k;
        emask_a = cert->export_mask_a;
#ifndef OPENSSL_NO_SRP
        if (s->srp_ctx.srp_Mask & SSL_kSRP) {
            mask_k |= SSL_kSRP;
            emask_k |= SSL_kSRP;
            mask_a |= SSL_aSRP;
            emask_a |= SSL_aSRP;
        }
#endif

#ifdef KSSL_DEBUG
        /*
         * fprintf(stderr,"ssl3_choose_cipher %d alg= %lx\n",
         * i,c->algorithms);
         */
#endif                          /* KSSL_DEBUG */

        alg_k = c->algorithm_mkey;
        alg_a = c->algorithm_auth;

#ifndef OPENSSL_NO_KRB5
        if (alg_k & SSL_kKRB5) {
            if (!kssl_keytab_is_available(s->kssl_ctx))
                continue;
        }
#endif                          /* OPENSSL_NO_KRB5 */
#ifndef OPENSSL_NO_PSK
        /* with PSK there must be server callback set */
        if ((alg_k & SSL_kPSK) && s->psk_server_callback == NULL)
            continue;
#endif                          /* OPENSSL_NO_PSK */

        if (SSL_C_IS_EXPORT(c)) {
            ok = (alg_k & emask_k) && (alg_a & emask_a);
#ifdef CIPHER_DEBUG
            fprintf(stderr, "%d:[%08lX:%08lX:%08lX:%08lX]%p:%s (export)\n",
                    ok, alg_k, alg_a, emask_k, emask_a, (void *)c, c->name);
#endif
        } else {
            ok = (alg_k & mask_k) && (alg_a & mask_a);
#ifdef CIPHER_DEBUG
            fprintf(stderr, "%d:[%08lX:%08lX:%08lX:%08lX]%p:%s\n", ok, alg_k,
                    alg_a, mask_k, mask_a, (void *)c, c->name);
#endif
        }

#ifndef OPENSSL_NO_TLSEXT
# ifndef OPENSSL_NO_EC
#  ifndef OPENSSL_NO_ECDH
        /*
         * if we are considering an ECC cipher suite that uses an ephemeral
         * EC key check it
         */
        if (alg_k & SSL_kEECDH)
            ok = ok && tls1_check_ec_tmp_key(s, c->id);
#  endif                        /* OPENSSL_NO_ECDH */
# endif                         /* OPENSSL_NO_EC */
#endif                          /* OPENSSL_NO_TLSEXT */

        if (!ok)
            continue;
        ii = sk_SSL_CIPHER_find(allow, c);
        if (ii >= 0) {
#if !defined(OPENSSL_NO_EC) && !defined(OPENSSL_NO_TLSEXT)
            if ((alg_k & SSL_kEECDH) && (alg_a & SSL_aECDSA)
                && s->s3->is_probably_safari) {
                if (!ret)
                    ret = sk_SSL_CIPHER_value(allow, ii);
                continue;
            }
#endif
            ret = sk_SSL_CIPHER_value(allow, ii);
            break;
        }
    }
    return (ret);
}

int ssl3_get_req_cert_type(SSL *s, unsigned char *p)
{
    int ret = 0;
    const unsigned char *sig;
    size_t i, siglen;
    int have_rsa_sign = 0, have_dsa_sign = 0;
#ifndef OPENSSL_NO_ECDSA
    int have_ecdsa_sign = 0;
#endif
#if !defined(OPENSSL_NO_DH) || !defined(OPENSSL_NO_ECDH)
    int nostrict = 1;
#endif
#if !defined(OPENSSL_NO_GOST) || !defined(OPENSSL_NO_DH) || \
    !defined(OPENSSL_NO_ECDH)
    unsigned long alg_k;
#endif

    /* If we have custom certificate types set, use them */
    if (s->cert->ctypes) {
        memcpy(p, s->cert->ctypes, s->cert->ctype_num);
        return (int)s->cert->ctype_num;
    }
    /* get configured sigalgs */
    siglen = tls12_get_psigalgs(s, 1, &sig);
#if !defined(OPENSSL_NO_DH) || !defined(OPENSSL_NO_ECDH)
    if (s->cert->cert_flags & SSL_CERT_FLAGS_CHECK_TLS_STRICT)
        nostrict = 0;
#endif
    for (i = 0; i < siglen; i += 2, sig += 2) {
        switch (sig[1]) {
        case TLSEXT_signature_rsa:
            have_rsa_sign = 1;
            break;

        case TLSEXT_signature_dsa:
            have_dsa_sign = 1;
            break;
#ifndef OPENSSL_NO_ECDSA
        case TLSEXT_signature_ecdsa:
            have_ecdsa_sign = 1;
            break;
#endif
        }
    }

#if !defined(OPENSSL_NO_GOST) || !defined(OPENSSL_NO_DH) || \
    !defined(OPENSSL_NO_ECDH)
    alg_k = s->s3->tmp.new_cipher->algorithm_mkey;
#endif

#ifndef OPENSSL_NO_GOST
    if (s->version >= TLS1_VERSION) {
        if (alg_k & SSL_kGOST) {
            p[ret++] = TLS_CT_GOST94_SIGN;
            p[ret++] = TLS_CT_GOST01_SIGN;
            return (ret);
        }
    }
#endif

#ifndef OPENSSL_NO_DH
    if (alg_k & (SSL_kDHr | SSL_kEDH)) {
# ifndef OPENSSL_NO_RSA
        /*
         * Since this refers to a certificate signed with an RSA algorithm,
         * only check for rsa signing in strict mode.
         */
        if (nostrict || have_rsa_sign)
            p[ret++] = SSL3_CT_RSA_FIXED_DH;
# endif
# ifndef OPENSSL_NO_DSA
        if (nostrict || have_dsa_sign)
            p[ret++] = SSL3_CT_DSS_FIXED_DH;
# endif
    }
    if ((s->version == SSL3_VERSION) &&
        (alg_k & (SSL_kEDH | SSL_kDHd | SSL_kDHr))) {
# ifndef OPENSSL_NO_RSA
        p[ret++] = SSL3_CT_RSA_EPHEMERAL_DH;
# endif
# ifndef OPENSSL_NO_DSA
        p[ret++] = SSL3_CT_DSS_EPHEMERAL_DH;
# endif
    }
#endif                          /* !OPENSSL_NO_DH */
#ifndef OPENSSL_NO_RSA
    if (have_rsa_sign)
        p[ret++] = SSL3_CT_RSA_SIGN;
#endif
#ifndef OPENSSL_NO_DSA
    if (have_dsa_sign)
        p[ret++] = SSL3_CT_DSS_SIGN;
#endif
#ifndef OPENSSL_NO_ECDH
    if ((alg_k & (SSL_kECDHr | SSL_kECDHe)) && (s->version >= TLS1_VERSION)) {
        if (nostrict || have_rsa_sign)
            p[ret++] = TLS_CT_RSA_FIXED_ECDH;
        if (nostrict || have_ecdsa_sign)
            p[ret++] = TLS_CT_ECDSA_FIXED_ECDH;
    }
#endif

#ifndef OPENSSL_NO_ECDSA
    /*
     * ECDSA certs can be used with RSA cipher suites as well so we don't
     * need to check for SSL_kECDH or SSL_kEECDH
     */
    if (s->version >= TLS1_VERSION) {
        if (have_ecdsa_sign)
            p[ret++] = TLS_CT_ECDSA_SIGN;
    }
#endif
    return (ret);
}

static int ssl3_set_req_cert_type(CERT *c, const unsigned char *p, size_t len)
{
    if (c->ctypes) {
        OPENSSL_free(c->ctypes);
        c->ctypes = NULL;
    }
    if (!p || !len)
        return 1;
    if (len > 0xff)
        return 0;
    c->ctypes = OPENSSL_malloc(len);
    if (!c->ctypes)
        return 0;
    memcpy(c->ctypes, p, len);
    c->ctype_num = len;
    return 1;
}

int ssl3_shutdown(SSL *s)
{
    int ret;

    /*
     * Don't do anything much if we have not done the handshake or we don't
     * want to send messages :-)
     */
    if ((s->quiet_shutdown) || (s->state == SSL_ST_BEFORE)) {
        s->shutdown = (SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
        return (1);
    }

    if (!(s->shutdown & SSL_SENT_SHUTDOWN)) {
        s->shutdown |= SSL_SENT_SHUTDOWN;
#if 1
        ssl3_send_alert(s, SSL3_AL_WARNING, SSL_AD_CLOSE_NOTIFY);
#endif
        /*
         * our shutdown alert has been sent now, and if it still needs to be
         * written, s->s3->alert_dispatch will be true
         */
        if (s->s3->alert_dispatch)
            return (-1);        /* return WANT_WRITE */
    } else if (s->s3->alert_dispatch) {
        /* resend it if not sent */
#if 1
        ret = s->method->ssl_dispatch_alert(s);
        if (ret == -1) {
            /*
             * we only get to return -1 here the 2nd/Nth invocation, we must
             * have already signalled return 0 upon a previous invoation,
             * return WANT_WRITE
             */
            return (ret);
        }
#endif
    } else if (!(s->shutdown & SSL_RECEIVED_SHUTDOWN)) {
        /*
         * If we are waiting for a close from our peer, we are closed
         */
        s->method->ssl_read_bytes(s, 0, NULL, 0, 0);
        if (!(s->shutdown & SSL_RECEIVED_SHUTDOWN)) {
            return (-1);        /* return WANT_READ */
        }
    }

    if ((s->shutdown == (SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN)) &&
        !s->s3->alert_dispatch)
        return (1);
    else
        return (0);
}

int ssl3_write(SSL *s, const void *buf, int len)
{
    int ret, n;

#if 0
    if (s->shutdown & SSL_SEND_SHUTDOWN) {
        s->rwstate = SSL_NOTHING;
        return (0);
    }
#endif
    clear_sys_error();
    if (s->s3->renegotiate)
        ssl3_renegotiate_check(s);

    /*
     * This is an experimental flag that sends the last handshake message in
     * the same packet as the first use data - used to see if it helps the
     * TCP protocol during session-id reuse
     */
    /* The second test is because the buffer may have been removed */
    if ((s->s3->flags & SSL3_FLAGS_POP_BUFFER) && (s->wbio == s->bbio)) {
        /* First time through, we write into the buffer */
        if (s->s3->delay_buf_pop_ret == 0) {
            ret = ssl3_write_bytes(s, SSL3_RT_APPLICATION_DATA, buf, len);
            if (ret <= 0)
                return (ret);

            s->s3->delay_buf_pop_ret = ret;
        }

        s->rwstate = SSL_WRITING;
        n = BIO_flush(s->wbio);
        if (n <= 0)
            return (n);
        s->rwstate = SSL_NOTHING;

        /* We have flushed the buffer, so remove it */
        ssl_free_wbio_buffer(s);
        s->s3->flags &= ~SSL3_FLAGS_POP_BUFFER;

        ret = s->s3->delay_buf_pop_ret;
        s->s3->delay_buf_pop_ret = 0;
    } else {
        ret = s->method->ssl_write_bytes(s, SSL3_RT_APPLICATION_DATA,
                                         buf, len);
        if (ret <= 0)
            return (ret);
    }

    return (ret);
}

static int ssl3_read_internal(SSL *s, void *buf, int len, int peek)
{
    int ret;

    clear_sys_error();
    if (s->s3->renegotiate)
        ssl3_renegotiate_check(s);
    s->s3->in_read_app_data = 1;
    ret =
        s->method->ssl_read_bytes(s, SSL3_RT_APPLICATION_DATA, buf, len,
                                  peek);
    if ((ret == -1) && (s->s3->in_read_app_data == 2)) {
        /*
         * ssl3_read_bytes decided to call s->handshake_func, which called
         * ssl3_read_bytes to read handshake data. However, ssl3_read_bytes
         * actually found application data and thinks that application data
         * makes sense here; so disable handshake processing and try to read
         * application data again.
         */
        s->in_handshake++;
        ret =
            s->method->ssl_read_bytes(s, SSL3_RT_APPLICATION_DATA, buf, len,
                                      peek);
        s->in_handshake--;
    } else
        s->s3->in_read_app_data = 0;

    return (ret);
}

int ssl3_read(SSL *s, void *buf, int len)
{
    return ssl3_read_internal(s, buf, len, 0);
}

int ssl3_peek(SSL *s, void *buf, int len)
{
    return ssl3_read_internal(s, buf, len, 1);
}

int ssl3_renegotiate(SSL *s)
{
    if (s->handshake_func == NULL)
        return (1);

    if (s->s3->flags & SSL3_FLAGS_NO_RENEGOTIATE_CIPHERS)
        return (0);

    s->s3->renegotiate = 1;
    return (1);
}

int ssl3_renegotiate_check(SSL *s)
{
    int ret = 0;

    if (s->s3->renegotiate) {
        if ((s->s3->rbuf.left == 0) &&
            (s->s3->wbuf.left == 0) && !SSL_in_init(s)) {
            /*
             * if we are the server, and we have sent a 'RENEGOTIATE'
             * message, we need to go to SSL_ST_ACCEPT.
             */
            /* SSL_ST_ACCEPT */
            s->state = SSL_ST_RENEGOTIATE;
            s->s3->renegotiate = 0;
            s->s3->num_renegotiations++;
            s->s3->total_renegotiations++;
            ret = 1;
        }
    }
    return (ret);
}

/*
 * If we are using default SHA1+MD5 algorithms switch to new SHA256 PRF and
 * handshake macs if required.
 */
long ssl_get_algorithm2(SSL *s)
{
    long alg2;
    if (s->s3 == NULL || s->s3->tmp.new_cipher == NULL)
        return -1;
    alg2 = s->s3->tmp.new_cipher->algorithm2;
    if (s->method->ssl3_enc->enc_flags & SSL_ENC_FLAG_SHA256_PRF
        && alg2 == (SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF))
        return SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256;
    return alg2;
}
/* ssl/s3_meth.c */
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
// #include "objects.h"
// #include "ssl_locl.h"

#ifndef OPENSSL_NO_SSL3_METHOD
static const SSL_METHOD *ssl3_get_method(int ver)
{
    if (ver == SSL3_VERSION)
        return (SSLv3_method());
    else
        return (NULL);
}

IMPLEMENT_ssl3_meth_func(SSLv3_method,
                         ssl3_accept, ssl3_connect, ssl3_get_method)
#endif
/* ssl/s3_pkt.c */
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

#include <stdio.h>
#include <limits.h>
#include <errno.h>
#define USE_SOCKETS
// #include "ssl_locl.h"
// #include "evp.h"
// #include "buffer.h"
// #include "rand.h"

#ifndef  EVP_CIPH_FLAG_TLS1_1_MULTIBLOCK
# define EVP_CIPH_FLAG_TLS1_1_MULTIBLOCK 0
#endif

#if     defined(OPENSSL_SMALL_FOOTPRINT) || \
        !(      defined(AES_ASM) &&     ( \
                defined(__x86_64)       || defined(__x86_64__)  || \
                defined(_M_AMD64)       || defined(_M_X64)      || \
                defined(__INTEL__)      ) \
        )
# undef EVP_CIPH_FLAG_TLS1_1_MULTIBLOCK
# define EVP_CIPH_FLAG_TLS1_1_MULTIBLOCK 0
#endif

static int do_ssl3_write(SSL *s, int type, const unsigned char *buf,
                         unsigned int len, int create_empty_fragment);
static int ssl3_get_record(SSL *s);

/*
 * Return values are as per SSL_read()
 */
int ssl3_read_n(SSL *s, int n, int max, int extend)
{
    /*
     * If extend == 0, obtain new n-byte packet; if extend == 1, increase
     * packet by another n bytes. The packet will be in the sub-array of
     * s->s3->rbuf.buf specified by s->packet and s->packet_length. (If
     * s->read_ahead is set, 'max' bytes may be stored in rbuf [plus
     * s->packet_length bytes if extend == 1].)
     */
    int i, len, left;
    long align = 0;
    unsigned char *pkt;
    SSL3_BUFFER *rb;

    if (n <= 0)
        return n;

    rb = &(s->s3->rbuf);
    if (rb->buf == NULL)
        if (!ssl3_setup_read_buffer(s))
            return -1;

    left = rb->left;
#if defined(SSL3_ALIGN_PAYLOAD) && SSL3_ALIGN_PAYLOAD!=0
    align = (long)rb->buf + SSL3_RT_HEADER_LENGTH;
    align = (-align) & (SSL3_ALIGN_PAYLOAD - 1);
#endif

    if (!extend) {
        /* start with empty packet ... */
        if (left == 0)
            rb->offset = align;
        else if (align != 0 && left >= SSL3_RT_HEADER_LENGTH) {
            /*
             * check if next packet length is large enough to justify payload
             * alignment...
             */
            pkt = rb->buf + rb->offset;
            if (pkt[0] == SSL3_RT_APPLICATION_DATA
                && (pkt[3] << 8 | pkt[4]) >= 128) {
                /*
                 * Note that even if packet is corrupted and its length field
                 * is insane, we can only be led to wrong decision about
                 * whether memmove will occur or not. Header values has no
                 * effect on memmove arguments and therefore no buffer
                 * overrun can be triggered.
                 */
                memmove(rb->buf + align, pkt, left);
                rb->offset = align;
            }
        }
        s->packet = rb->buf + rb->offset;
        s->packet_length = 0;
        /* ... now we can act as if 'extend' was set */
    }

    /*
     * For DTLS/UDP reads should not span multiple packets because the read
     * operation returns the whole packet at once (as long as it fits into
     * the buffer).
     */
    if (SSL_IS_DTLS(s)) {
        if (left == 0 && extend)
            return 0;
        if (left > 0 && n > left)
            n = left;
    }

    /* if there is enough in the buffer from a previous read, take some */
    if (left >= n) {
        s->packet_length += n;
        rb->left = left - n;
        rb->offset += n;
        return (n);
    }

    /* else we need to read more data */

    len = s->packet_length;
    pkt = rb->buf + align;
    /*
     * Move any available bytes to front of buffer: 'len' bytes already
     * pointed to by 'packet', 'left' extra ones at the end
     */
    if (s->packet != pkt) {     /* len > 0 */
        memmove(pkt, s->packet, len + left);
        s->packet = pkt;
        rb->offset = len + align;
    }

    if (n > (int)(rb->len - rb->offset)) { /* does not happen */
        SSLerr(SSL_F_SSL3_READ_N, ERR_R_INTERNAL_ERROR);
        return -1;
    }

    /* We always act like read_ahead is set for DTLS */
    if (!s->read_ahead && !SSL_IS_DTLS(s))
        /* ignore max parameter */
        max = n;
    else {
        if (max < n)
            max = n;
        if (max > (int)(rb->len - rb->offset))
            max = rb->len - rb->offset;
    }

    while (left < n) {
        /*
         * Now we have len+left bytes at the front of s->s3->rbuf.buf and
         * need to read in more until we have len+n (up to len+max if
         * possible)
         */

        clear_sys_error();
        if (s->rbio != NULL) {
            s->rwstate = SSL_READING;
            i = BIO_read(s->rbio, pkt + len + left, max - left);
        } else {
            SSLerr(SSL_F_SSL3_READ_N, SSL_R_READ_BIO_NOT_SET);
            i = -1;
        }

        if (i <= 0) {
            rb->left = left;
            if (s->mode & SSL_MODE_RELEASE_BUFFERS && !SSL_IS_DTLS(s))
                if (len + left == 0)
                    ssl3_release_read_buffer(s);
            return (i);
        }
        left += i;
        /*
         * reads should *never* span multiple packets for DTLS because the
         * underlying transport protocol is message oriented as opposed to
         * byte oriented as in the TLS case.
         */
        if (SSL_IS_DTLS(s)) {
            if (n > left)
                n = left;       /* makes the while condition false */
        }
    }

    /* done reading, now the book-keeping */
    rb->offset += n;
    rb->left = left - n;
    s->packet_length += n;
    s->rwstate = SSL_NOTHING;
    return (n);
}

/*
 * MAX_EMPTY_RECORDS defines the number of consecutive, empty records that
 * will be processed per call to ssl3_get_record. Without this limit an
 * attacker could send empty records at a faster rate than we can process and
 * cause ssl3_get_record to loop forever.
 */
#define MAX_EMPTY_RECORDS 32

/*-
 * Call this to get a new input record.
 * It will return <= 0 if more data is needed, normally due to an error
 * or non-blocking IO.
 * When it finishes, one packet has been decoded and can be found in
 * ssl->s3->rrec.type    - is the type of record
 * ssl->s3->rrec.data,   - data
 * ssl->s3->rrec.length, - number of bytes
 */
/* used only by ssl3_read_bytes */
static int ssl3_get_record(SSL *s)
{
    int ssl_major, ssl_minor, al;
    int enc_err, n, i, ret = -1;
    SSL3_RECORD *rr;
    SSL_SESSION *sess;
    unsigned char *p;
    unsigned char md[EVP_MAX_MD_SIZE];
    short version;
    unsigned mac_size, orig_len;
    size_t extra;
    unsigned empty_record_count = 0;

    rr = &(s->s3->rrec);
    sess = s->session;

    if (s->options & SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER)
        extra = SSL3_RT_MAX_EXTRA;
    else
        extra = 0;
    if (extra && !s->s3->init_extra) {
        /*
         * An application error: SLS_OP_MICROSOFT_BIG_SSLV3_BUFFER set after
         * ssl3_setup_buffers() was done
         */
        SSLerr(SSL_F_SSL3_GET_RECORD, ERR_R_INTERNAL_ERROR);
        return -1;
    }

 again:
    /* check if we have the header */
    if ((s->rstate != SSL_ST_READ_BODY) ||
        (s->packet_length < SSL3_RT_HEADER_LENGTH)) {
        n = ssl3_read_n(s, SSL3_RT_HEADER_LENGTH, s->s3->rbuf.len, 0);
        if (n <= 0)
            return (n);         /* error or non-blocking */
        s->rstate = SSL_ST_READ_BODY;

        p = s->packet;
        if (s->msg_callback)
            s->msg_callback(0, 0, SSL3_RT_HEADER, p, 5, s,
                            s->msg_callback_arg);

        /* Pull apart the header into the SSL3_RECORD */
        rr->type = *(p++);
        ssl_major = *(p++);
        ssl_minor = *(p++);
        version = (ssl_major << 8) | ssl_minor;
        n2s(p, rr->length);
#if 0
        fprintf(stderr, "Record type=%d, Length=%d\n", rr->type, rr->length);
#endif

        /* Lets check version */
        if (!s->first_packet) {
            if (version != s->version) {
                SSLerr(SSL_F_SSL3_GET_RECORD, SSL_R_WRONG_VERSION_NUMBER);
                if ((s->version & 0xFF00) == (version & 0xFF00)
                    && !s->enc_write_ctx && !s->write_hash) {
                    if (rr->type == SSL3_RT_ALERT) {
                        /*
                         * The record is using an incorrect version number, but
                         * what we've got appears to be an alert. We haven't
                         * read the body yet to check whether its a fatal or
                         * not - but chances are it is. We probably shouldn't
                         * send a fatal alert back. We'll just end.
                         */
                         goto err;
                    }
                    /*
                     * Send back error using their minor version number :-)
                     */
                    s->version = (unsigned short)version;
                }
                al = SSL_AD_PROTOCOL_VERSION;
                goto f_err;
            }
        }

        if ((version >> 8) != SSL3_VERSION_MAJOR) {
            SSLerr(SSL_F_SSL3_GET_RECORD, SSL_R_WRONG_VERSION_NUMBER);
            goto err;
        }

        if (rr->length > s->s3->rbuf.len - SSL3_RT_HEADER_LENGTH) {
            al = SSL_AD_RECORD_OVERFLOW;
            SSLerr(SSL_F_SSL3_GET_RECORD, SSL_R_PACKET_LENGTH_TOO_LONG);
            goto f_err;
        }

        /* now s->rstate == SSL_ST_READ_BODY */
    }

    /* s->rstate == SSL_ST_READ_BODY, get and decode the data */

    if (rr->length > s->packet_length - SSL3_RT_HEADER_LENGTH) {
        /* now s->packet_length == SSL3_RT_HEADER_LENGTH */
        i = rr->length;
        n = ssl3_read_n(s, i, i, 1);
        if (n <= 0)
            return (n);         /* error or non-blocking io */
        /*
         * now n == rr->length, and s->packet_length == SSL3_RT_HEADER_LENGTH
         * + rr->length
         */
    }

    s->rstate = SSL_ST_READ_HEADER; /* set state for later operations */

    /*
     * At this point, s->packet_length == SSL3_RT_HEADER_LNGTH + rr->length,
     * and we have that many bytes in s->packet
     */
    rr->input = &(s->packet[SSL3_RT_HEADER_LENGTH]);

    /*
     * ok, we can now read from 's->packet' data into 'rr' rr->input points
     * at rr->length bytes, which need to be copied into rr->data by either
     * the decryption or by the decompression When the data is 'copied' into
     * the rr->data buffer, rr->input will be pointed at the new buffer
     */

    /*
     * We now have - encrypted [ MAC [ compressed [ plain ] ] ] rr->length
     * bytes of encrypted compressed stuff.
     */

    /* check is not needed I believe */
    if (rr->length > SSL3_RT_MAX_ENCRYPTED_LENGTH + extra) {
        al = SSL_AD_RECORD_OVERFLOW;
        SSLerr(SSL_F_SSL3_GET_RECORD, SSL_R_ENCRYPTED_LENGTH_TOO_LONG);
        goto f_err;
    }

    /* decrypt in place in 'rr->input' */
    rr->data = rr->input;

    enc_err = s->method->ssl3_enc->enc(s, 0);
    /*-
     * enc_err is:
     *    0: (in non-constant time) if the record is publically invalid.
     *    1: if the padding is valid
     *    -1: if the padding is invalid
     */
    if (enc_err == 0) {
        al = SSL_AD_DECRYPTION_FAILED;
        SSLerr(SSL_F_SSL3_GET_RECORD, SSL_R_BLOCK_CIPHER_PAD_IS_WRONG);
        goto f_err;
    }
#ifdef TLS_DEBUG
    printf("dec %d\n", rr->length);
    {
        unsigned int z;
        for (z = 0; z < rr->length; z++)
            printf("%02X%c", rr->data[z], ((z + 1) % 16) ? ' ' : '\n');
    }
    printf("\n");
#endif

    /* r->length is now the compressed data plus mac */
    if ((sess != NULL) &&
        (s->enc_read_ctx != NULL) && (EVP_MD_CTX_md(s->read_hash) != NULL)) {
        /* s->read_hash != NULL => mac_size != -1 */
        unsigned char *mac = NULL;
        unsigned char mac_tmp[EVP_MAX_MD_SIZE];
        mac_size = EVP_MD_CTX_size(s->read_hash);
        OPENSSL_assert(mac_size <= EVP_MAX_MD_SIZE);

        /*
         * kludge: *_cbc_remove_padding passes padding length in rr->type
         */
        orig_len = rr->length + ((unsigned int)rr->type >> 8);

        /*
         * orig_len is the length of the record before any padding was
         * removed. This is public information, as is the MAC in use,
         * therefore we can safely process the record in a different amount
         * of time if it's too short to possibly contain a MAC.
         */
        if (orig_len < mac_size ||
            /* CBC records must have a padding length byte too. */
            (EVP_CIPHER_CTX_mode(s->enc_read_ctx) == EVP_CIPH_CBC_MODE &&
             orig_len < mac_size + 1)) {
            al = SSL_AD_DECODE_ERROR;
            SSLerr(SSL_F_SSL3_GET_RECORD, SSL_R_LENGTH_TOO_SHORT);
            goto f_err;
        }

        if (EVP_CIPHER_CTX_mode(s->enc_read_ctx) == EVP_CIPH_CBC_MODE) {
            /*
             * We update the length so that the TLS header bytes can be
             * constructed correctly but we need to extract the MAC in
             * constant time from within the record, without leaking the
             * contents of the padding bytes.
             */
            mac = mac_tmp;
            ssl3_cbc_copy_mac(mac_tmp, rr, mac_size, orig_len);
            rr->length -= mac_size;
        } else {
            /*
             * In this case there's no padding, so |orig_len| equals
             * |rec->length| and we checked that there's enough bytes for
             * |mac_size| above.
             */
            rr->length -= mac_size;
            mac = &rr->data[rr->length];
        }

        i = s->method->ssl3_enc->mac(s, md, 0 /* not send */ );
        if (i < 0 || mac == NULL
            || CRYPTO_memcmp(md, mac, (size_t)mac_size) != 0)
            enc_err = -1;
        if (rr->length > SSL3_RT_MAX_COMPRESSED_LENGTH + extra + mac_size)
            enc_err = -1;
    }

    if (enc_err < 0) {
        /*
         * A separate 'decryption_failed' alert was introduced with TLS 1.0,
         * SSL 3.0 only has 'bad_record_mac'.  But unless a decryption
         * failure is directly visible from the ciphertext anyway, we should
         * not reveal which kind of error occured -- this might become
         * visible to an attacker (e.g. via a logfile)
         */
        al = SSL_AD_BAD_RECORD_MAC;
        SSLerr(SSL_F_SSL3_GET_RECORD,
               SSL_R_DECRYPTION_FAILED_OR_BAD_RECORD_MAC);
        goto f_err;
    }

    /* r->length is now just compressed */
    if (s->expand != NULL) {
        if (rr->length > SSL3_RT_MAX_COMPRESSED_LENGTH + extra) {
            al = SSL_AD_RECORD_OVERFLOW;
            SSLerr(SSL_F_SSL3_GET_RECORD, SSL_R_COMPRESSED_LENGTH_TOO_LONG);
            goto f_err;
        }
        if (!ssl3_do_uncompress(s)) {
            al = SSL_AD_DECOMPRESSION_FAILURE;
            SSLerr(SSL_F_SSL3_GET_RECORD, SSL_R_BAD_DECOMPRESSION);
            goto f_err;
        }
    }

    if (rr->length > SSL3_RT_MAX_PLAIN_LENGTH + extra) {
        al = SSL_AD_RECORD_OVERFLOW;
        SSLerr(SSL_F_SSL3_GET_RECORD, SSL_R_DATA_LENGTH_TOO_LONG);
        goto f_err;
    }

    rr->off = 0;
    /*-
     * So at this point the following is true
     * ssl->s3->rrec.type   is the type of record
     * ssl->s3->rrec.length == number of bytes in record
     * ssl->s3->rrec.off    == offset to first valid byte
     * ssl->s3->rrec.data   == where to take bytes from, increment
     *                         after use :-).
     */

    /* we have pulled in a full packet so zero things */
    s->packet_length = 0;

    /* just read a 0 length packet */
    if (rr->length == 0) {
        empty_record_count++;
        if (empty_record_count > MAX_EMPTY_RECORDS) {
            al = SSL_AD_UNEXPECTED_MESSAGE;
            SSLerr(SSL_F_SSL3_GET_RECORD, SSL_R_RECORD_TOO_SMALL);
            goto f_err;
        }
        goto again;
    }
#if 0
    fprintf(stderr, "Ultimate Record type=%d, Length=%d\n", rr->type,
            rr->length);
#endif

    return (1);

 f_err:
    ssl3_send_alert(s, SSL3_AL_FATAL, al);
 err:
    return (ret);
}

int ssl3_do_uncompress(SSL *ssl)
{
#ifndef OPENSSL_NO_COMP
    int i;
    SSL3_RECORD *rr;

    rr = &(ssl->s3->rrec);
    i = COMP_expand_block(ssl->expand, rr->comp,
                          SSL3_RT_MAX_PLAIN_LENGTH, rr->data,
                          (int)rr->length);
    if (i < 0)
        return (0);
    else
        rr->length = i;
    rr->data = rr->comp;
#endif
    return (1);
}

int ssl3_do_compress(SSL *ssl)
{
#ifndef OPENSSL_NO_COMP
    int i;
    SSL3_RECORD *wr;

    wr = &(ssl->s3->wrec);
    i = COMP_compress_block(ssl->compress, wr->data,
                            SSL3_RT_MAX_COMPRESSED_LENGTH,
                            wr->input, (int)wr->length);
    if (i < 0)
        return (0);
    else
        wr->length = i;

    wr->input = wr->data;
#endif
    return (1);
}

/*
 * Call this to write data in records of type 'type' It will return <= 0 if
 * not all data has been sent or non-blocking IO.
 */
int ssl3_write_bytes(SSL *s, int type, const void *buf_, int len)
{
    const unsigned char *buf = buf_;
    int tot;
    unsigned int n, nw;
#if !defined(OPENSSL_NO_MULTIBLOCK) && EVP_CIPH_FLAG_TLS1_1_MULTIBLOCK
    unsigned int max_send_fragment;
#endif
    SSL3_BUFFER *wb = &(s->s3->wbuf);
    int i;

    s->rwstate = SSL_NOTHING;
    OPENSSL_assert(s->s3->wnum <= INT_MAX);
    tot = s->s3->wnum;
    s->s3->wnum = 0;

    if (SSL_in_init(s) && !s->in_handshake) {
        i = s->handshake_func(s);
        if (i < 0)
            return (i);
        if (i == 0) {
            SSLerr(SSL_F_SSL3_WRITE_BYTES, SSL_R_SSL_HANDSHAKE_FAILURE);
            return -1;
        }
    }

    /*
     * ensure that if we end up with a smaller value of data to write out
     * than the the original len from a write which didn't complete for
     * non-blocking I/O and also somehow ended up avoiding the check for
     * this in ssl3_write_pending/SSL_R_BAD_WRITE_RETRY as it must never be
     * possible to end up with (len-tot) as a large number that will then
     * promptly send beyond the end of the users buffer ... so we trap and
     * report the error in a way the user will notice
     */
    if ((len < tot) || ((wb->left != 0) && (len < (tot + s->s3->wpend_tot)))) {
        SSLerr(SSL_F_SSL3_WRITE_BYTES, SSL_R_BAD_LENGTH);
        return (-1);
    }

    /*
     * first check if there is a SSL3_BUFFER still being written out.  This
     * will happen with non blocking IO
     */
    if (wb->left != 0) {
        i = ssl3_write_pending(s, type, &buf[tot], s->s3->wpend_tot);
        if (i <= 0) {
            /* XXX should we ssl3_release_write_buffer if i<0? */
            s->s3->wnum = tot;
            return i;
        }
        tot += i;               /* this might be last fragment */
    }
#if !defined(OPENSSL_NO_MULTIBLOCK) && EVP_CIPH_FLAG_TLS1_1_MULTIBLOCK
    /*
     * Depending on platform multi-block can deliver several *times*
     * better performance. Downside is that it has to allocate
     * jumbo buffer to accomodate up to 8 records, but the
     * compromise is considered worthy.
     */
    if (type == SSL3_RT_APPLICATION_DATA &&
        len >= 4 * (int)(max_send_fragment = s->max_send_fragment) &&
        s->compress == NULL && s->msg_callback == NULL &&
        SSL_USE_EXPLICIT_IV(s) &&
        s->enc_write_ctx != NULL &&
        EVP_CIPHER_flags(s->enc_write_ctx->cipher) &
        EVP_CIPH_FLAG_TLS1_1_MULTIBLOCK) {
        unsigned char aad[13];
        EVP_CTRL_TLS1_1_MULTIBLOCK_PARAM mb_param;
        int packlen;

        /* minimize address aliasing conflicts */
        if ((max_send_fragment & 0xfff) == 0)
            max_send_fragment -= 512;

        if (tot == 0 || wb->buf == NULL) { /* allocate jumbo buffer */
            ssl3_release_write_buffer(s);

            packlen = EVP_CIPHER_CTX_ctrl(s->enc_write_ctx,
                                          EVP_CTRL_TLS1_1_MULTIBLOCK_MAX_BUFSIZE,
                                          max_send_fragment, NULL);

            if (len >= 8 * (int)max_send_fragment)
                packlen *= 8;
            else
                packlen *= 4;

            wb->buf = OPENSSL_malloc(packlen);
            if (!wb->buf) {
                SSLerr(SSL_F_SSL3_WRITE_BYTES, ERR_R_MALLOC_FAILURE);
                return -1;
            }
            wb->len = packlen;
        } else if (tot == len) { /* done? */
            OPENSSL_free(wb->buf); /* free jumbo buffer */
            wb->buf = NULL;
            return tot;
        }

        n = (len - tot);
        for (;;) {
            if (n < 4 * max_send_fragment) {
                OPENSSL_free(wb->buf); /* free jumbo buffer */
                wb->buf = NULL;
                break;
            }

            if (s->s3->alert_dispatch) {
                i = s->method->ssl_dispatch_alert(s);
                if (i <= 0) {
                    s->s3->wnum = tot;
                    return i;
                }
            }

            if (n >= 8 * max_send_fragment)
                nw = max_send_fragment * (mb_param.interleave = 8);
            else
                nw = max_send_fragment * (mb_param.interleave = 4);

            memcpy(aad, s->s3->write_sequence, 8);
            aad[8] = type;
            aad[9] = (unsigned char)(s->version >> 8);
            aad[10] = (unsigned char)(s->version);
            aad[11] = 0;
            aad[12] = 0;
            mb_param.out = NULL;
            mb_param.inp = aad;
            mb_param.len = nw;

            packlen = EVP_CIPHER_CTX_ctrl(s->enc_write_ctx,
                                          EVP_CTRL_TLS1_1_MULTIBLOCK_AAD,
                                          sizeof(mb_param), &mb_param);

            if (packlen <= 0 || packlen > (int)wb->len) { /* never happens */
                OPENSSL_free(wb->buf); /* free jumbo buffer */
                wb->buf = NULL;
                break;
            }

            mb_param.out = wb->buf;
            mb_param.inp = &buf[tot];
            mb_param.len = nw;

            if (EVP_CIPHER_CTX_ctrl(s->enc_write_ctx,
                                    EVP_CTRL_TLS1_1_MULTIBLOCK_ENCRYPT,
                                    sizeof(mb_param), &mb_param) <= 0)
                return -1;

            s->s3->write_sequence[7] += mb_param.interleave;
            if (s->s3->write_sequence[7] < mb_param.interleave) {
                int j = 6;
                while (j >= 0 && (++s->s3->write_sequence[j--]) == 0) ;
            }

            wb->offset = 0;
            wb->left = packlen;

            s->s3->wpend_tot = nw;
            s->s3->wpend_buf = &buf[tot];
            s->s3->wpend_type = type;
            s->s3->wpend_ret = nw;

            i = ssl3_write_pending(s, type, &buf[tot], nw);
            if (i <= 0) {
                if (i < 0 && (!s->wbio || !BIO_should_retry(s->wbio))) {
                    OPENSSL_free(wb->buf);
                    wb->buf = NULL;
                }
                s->s3->wnum = tot;
                return i;
            }
            if (i == (int)n) {
                OPENSSL_free(wb->buf); /* free jumbo buffer */
                wb->buf = NULL;
                return tot + i;
            }
            n -= i;
            tot += i;
        }
    } else
#endif
    if (tot == len) {           /* done? */
        if (s->mode & SSL_MODE_RELEASE_BUFFERS && !SSL_IS_DTLS(s))
            ssl3_release_write_buffer(s);

        return tot;
    }

    n = (len - tot);
    for (;;) {
        if (n > s->max_send_fragment)
            nw = s->max_send_fragment;
        else
            nw = n;

        i = do_ssl3_write(s, type, &(buf[tot]), nw, 0);
        if (i <= 0) {
            /* XXX should we ssl3_release_write_buffer if i<0? */
            s->s3->wnum = tot;
            return i;
        }

        if ((i == (int)n) ||
            (type == SSL3_RT_APPLICATION_DATA &&
             (s->mode & SSL_MODE_ENABLE_PARTIAL_WRITE))) {
            /*
             * next chunk of data should get another prepended empty fragment
             * in ciphersuites with known-IV weakness:
             */
            s->s3->empty_fragment_done = 0;

            if ((i == (int)n) && s->mode & SSL_MODE_RELEASE_BUFFERS &&
                !SSL_IS_DTLS(s))
                ssl3_release_write_buffer(s);

            return tot + i;
        }

        n -= i;
        tot += i;
    }
}

static int do_ssl3_write(SSL *s, int type, const unsigned char *buf,
                         unsigned int len, int create_empty_fragment)
{
    unsigned char *p, *plen;
    int i, mac_size, clear = 0;
    int prefix_len = 0;
    int eivlen;
    long align = 0;
    SSL3_RECORD *wr;
    SSL3_BUFFER *wb = &(s->s3->wbuf);
    SSL_SESSION *sess;

    /*
     * first check if there is a SSL3_BUFFER still being written out.  This
     * will happen with non blocking IO
     */
    if (wb->left != 0)
        return (ssl3_write_pending(s, type, buf, len));

    /* If we have an alert to send, lets send it */
    if (s->s3->alert_dispatch) {
        i = s->method->ssl_dispatch_alert(s);
        if (i <= 0)
            return (i);
        /* if it went, fall through and send more stuff */
    }

    if (wb->buf == NULL)
        if (!ssl3_setup_write_buffer(s))
            return -1;

    if (len == 0 && !create_empty_fragment)
        return 0;

    wr = &(s->s3->wrec);
    sess = s->session;

    if ((sess == NULL) ||
        (s->enc_write_ctx == NULL) ||
        (EVP_MD_CTX_md(s->write_hash) == NULL)) {
#if 1
        clear = s->enc_write_ctx ? 0 : 1; /* must be AEAD cipher */
#else
        clear = 1;
#endif
        mac_size = 0;
    } else {
        mac_size = EVP_MD_CTX_size(s->write_hash);
        if (mac_size < 0)
            goto err;
    }

    /*
     * 'create_empty_fragment' is true only when this function calls itself
     */
    if (!clear && !create_empty_fragment && !s->s3->empty_fragment_done) {
        /*
         * countermeasure against known-IV weakness in CBC ciphersuites (see
         * http://www.openssl.org/~bodo/tls-cbc.txt)
         */

        if (s->s3->need_empty_fragments && type == SSL3_RT_APPLICATION_DATA) {
            /*
             * recursive function call with 'create_empty_fragment' set; this
             * prepares and buffers the data for an empty fragment (these
             * 'prefix_len' bytes are sent out later together with the actual
             * payload)
             */
            prefix_len = do_ssl3_write(s, type, buf, 0, 1);
            if (prefix_len <= 0)
                goto err;

            if (prefix_len >
                (SSL3_RT_HEADER_LENGTH + SSL3_RT_SEND_MAX_ENCRYPTED_OVERHEAD))
            {
                /* insufficient space */
                SSLerr(SSL_F_DO_SSL3_WRITE, ERR_R_INTERNAL_ERROR);
                goto err;
            }
        }

        s->s3->empty_fragment_done = 1;
    }

    if (create_empty_fragment) {
#if defined(SSL3_ALIGN_PAYLOAD) && SSL3_ALIGN_PAYLOAD!=0
        /*
         * extra fragment would be couple of cipher blocks, which would be
         * multiple of SSL3_ALIGN_PAYLOAD, so if we want to align the real
         * payload, then we can just pretent we simply have two headers.
         */
        align = (long)wb->buf + 2 * SSL3_RT_HEADER_LENGTH;
        align = (-align) & (SSL3_ALIGN_PAYLOAD - 1);
#endif
        p = wb->buf + align;
        wb->offset = align;
    } else if (prefix_len) {
        p = wb->buf + wb->offset + prefix_len;
    } else {
#if defined(SSL3_ALIGN_PAYLOAD) && SSL3_ALIGN_PAYLOAD!=0
        align = (long)wb->buf + SSL3_RT_HEADER_LENGTH;
        align = (-align) & (SSL3_ALIGN_PAYLOAD - 1);
#endif
        p = wb->buf + align;
        wb->offset = align;
    }

    /* write the header */

    *(p++) = type & 0xff;
    wr->type = type;

    *(p++) = (s->version >> 8);
    /*
     * Some servers hang if iniatial client hello is larger than 256 bytes
     * and record version number > TLS 1.0
     */
    if (s->state == SSL3_ST_CW_CLNT_HELLO_B
        && !s->renegotiate && TLS1_get_version(s) > TLS1_VERSION)
        *(p++) = 0x1;
    else
        *(p++) = s->version & 0xff;

    /* field where we are to write out packet length */
    plen = p;
    p += 2;
    /* Explicit IV length, block ciphers appropriate version flag */
    if (s->enc_write_ctx && SSL_USE_EXPLICIT_IV(s)) {
        int mode = EVP_CIPHER_CTX_mode(s->enc_write_ctx);
        if (mode == EVP_CIPH_CBC_MODE) {
            eivlen = EVP_CIPHER_CTX_iv_length(s->enc_write_ctx);
            if (eivlen <= 1)
                eivlen = 0;
        }
        /* Need explicit part of IV for GCM mode */
        else if (mode == EVP_CIPH_GCM_MODE)
            eivlen = EVP_GCM_TLS_EXPLICIT_IV_LEN;
        else
            eivlen = 0;
    } else
        eivlen = 0;

    /* lets setup the record stuff. */
    wr->data = p + eivlen;
    wr->length = (int)len;
    wr->input = (unsigned char *)buf;

    /*
     * we now 'read' from wr->input, wr->length bytes into wr->data
     */

    /* first we compress */
    if (s->compress != NULL) {
        if (!ssl3_do_compress(s)) {
            SSLerr(SSL_F_DO_SSL3_WRITE, SSL_R_COMPRESSION_FAILURE);
            goto err;
        }
    } else {
        memcpy(wr->data, wr->input, wr->length);
        wr->input = wr->data;
    }

    /*
     * we should still have the output to wr->data and the input from
     * wr->input.  Length should be wr->length. wr->data still points in the
     * wb->buf
     */

    if (mac_size != 0) {
        if (s->method->ssl3_enc->mac(s, &(p[wr->length + eivlen]), 1) < 0)
            goto err;
        wr->length += mac_size;
    }

    wr->input = p;
    wr->data = p;

    if (eivlen) {
        /*
         * if (RAND_pseudo_bytes(p, eivlen) <= 0) goto err;
         */
        wr->length += eivlen;
    }

    if (s->method->ssl3_enc->enc(s, 1) < 1)
        goto err;

    /* record length after mac and block padding */
    s2n(wr->length, plen);

    if (s->msg_callback)
        s->msg_callback(1, 0, SSL3_RT_HEADER, plen - 5, 5, s,
                        s->msg_callback_arg);

    /*
     * we should now have wr->data pointing to the encrypted data, which is
     * wr->length long
     */
    wr->type = type;            /* not needed but helps for debugging */
    wr->length += SSL3_RT_HEADER_LENGTH;

    if (create_empty_fragment) {
        /*
         * we are in a recursive call; just return the length, don't write
         * out anything here
         */
        return wr->length;
    }

    /* now let's set up wb */
    wb->left = prefix_len + wr->length;

    /*
     * memorize arguments so that ssl3_write_pending can detect bad write
     * retries later
     */
    s->s3->wpend_tot = len;
    s->s3->wpend_buf = buf;
    s->s3->wpend_type = type;
    s->s3->wpend_ret = len;

    /* we now just need to write the buffer */
    return ssl3_write_pending(s, type, buf, len);
 err:
    return -1;
}

/* if s->s3->wbuf.left != 0, we need to call this
 *
 * Return values are as per SSL_write(), i.e.
 */
int ssl3_write_pending(SSL *s, int type, const unsigned char *buf,
                       unsigned int len)
{
    int i;
    SSL3_BUFFER *wb = &(s->s3->wbuf);

    if ((s->s3->wpend_tot > (int)len)
        || (!(s->mode & SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER)
            && (s->s3->wpend_buf != buf))
        || (s->s3->wpend_type != type)) {
        SSLerr(SSL_F_SSL3_WRITE_PENDING, SSL_R_BAD_WRITE_RETRY);
        return (-1);
    }

    for (;;) {
        clear_sys_error();
        if (s->wbio != NULL) {
            s->rwstate = SSL_WRITING;
            i = BIO_write(s->wbio,
                          (char *)&(wb->buf[wb->offset]),
                          (unsigned int)wb->left);
        } else {
            SSLerr(SSL_F_SSL3_WRITE_PENDING, SSL_R_BIO_NOT_SET);
            i = -1;
        }
        if (i == wb->left) {
            wb->left = 0;
            wb->offset += i;
            s->rwstate = SSL_NOTHING;
            return (s->s3->wpend_ret);
        } else if (i <= 0) {
            if (SSL_IS_DTLS(s)) {
                /*
                 * For DTLS, just drop it. That's kind of the whole point in
                 * using a datagram service
                 */
                wb->left = 0;
            }
            return i;
        }
        wb->offset += i;
        wb->left -= i;
    }
}

/*-
 * Return up to 'len' payload bytes received in 'type' records.
 * 'type' is one of the following:
 *
 *   -  SSL3_RT_HANDSHAKE (when ssl3_get_message calls us)
 *   -  SSL3_RT_APPLICATION_DATA (when ssl3_read calls us)
 *   -  0 (during a shutdown, no data has to be returned)
 *
 * If we don't have stored data to work from, read a SSL/TLS record first
 * (possibly multiple records if we still don't have anything to return).
 *
 * This function must handle any surprises the peer may have for us, such as
 * Alert records (e.g. close_notify), ChangeCipherSpec records (not really
 * a surprise, but handled as if it were), or renegotiation requests.
 * Also if record payloads contain fragments too small to process, we store
 * them until there is enough for the respective protocol (the record protocol
 * may use arbitrary fragmentation and even interleaving):
 *     Change cipher spec protocol
 *             just 1 byte needed, no need for keeping anything stored
 *     Alert protocol
 *             2 bytes needed (AlertLevel, AlertDescription)
 *     Handshake protocol
 *             4 bytes needed (HandshakeType, uint24 length) -- we just have
 *             to detect unexpected Client Hello and Hello Request messages
 *             here, anything else is handled by higher layers
 *     Application data protocol
 *             none of our business
 */
int ssl3_read_bytes(SSL *s, int type, unsigned char *buf, int len, int peek)
{
    int al, i, j, ret;
    unsigned int n;
    SSL3_RECORD *rr;
    void (*cb) (const SSL *ssl, int type2, int val) = NULL;

    if (s->s3->rbuf.buf == NULL) /* Not initialized yet */
        if (!ssl3_setup_read_buffer(s))
            return (-1);

    if ((type && (type != SSL3_RT_APPLICATION_DATA)
         && (type != SSL3_RT_HANDSHAKE)) || (peek
                                             && (type !=
                                                 SSL3_RT_APPLICATION_DATA))) {
        SSLerr(SSL_F_SSL3_READ_BYTES, ERR_R_INTERNAL_ERROR);
        return -1;
    }

    if ((type == SSL3_RT_HANDSHAKE) && (s->s3->handshake_fragment_len > 0))
        /* (partially) satisfy request from storage */
    {
        unsigned char *src = s->s3->handshake_fragment;
        unsigned char *dst = buf;
        unsigned int k;

        /* peek == 0 */
        n = 0;
        while ((len > 0) && (s->s3->handshake_fragment_len > 0)) {
            *dst++ = *src++;
            len--;
            s->s3->handshake_fragment_len--;
            n++;
        }
        /* move any remaining fragment bytes: */
        for (k = 0; k < s->s3->handshake_fragment_len; k++)
            s->s3->handshake_fragment[k] = *src++;
        return n;
    }

    /*
     * Now s->s3->handshake_fragment_len == 0 if type == SSL3_RT_HANDSHAKE.
     */

    if (!s->in_handshake && SSL_in_init(s)) {
        /* type == SSL3_RT_APPLICATION_DATA */
        i = s->handshake_func(s);
        if (i < 0)
            return (i);
        if (i == 0) {
            SSLerr(SSL_F_SSL3_READ_BYTES, SSL_R_SSL_HANDSHAKE_FAILURE);
            return (-1);
        }
    }
 start:
    s->rwstate = SSL_NOTHING;

    /*-
     * s->s3->rrec.type         - is the type of record
     * s->s3->rrec.data,    - data
     * s->s3->rrec.off,     - offset into 'data' for next read
     * s->s3->rrec.length,  - number of bytes.
     */
    rr = &(s->s3->rrec);

    /* get new packet if necessary */
    if ((rr->length == 0) || (s->rstate == SSL_ST_READ_BODY)) {
        ret = ssl3_get_record(s);
        if (ret <= 0)
            return (ret);
    }

    /*
     * Reset the count of consecutive warning alerts if we've got a non-empty
     * record that isn't an alert.
     */
    if (rr->type != SSL3_RT_ALERT && rr->length != 0)
        s->cert->alert_count = 0;

    /* we now have a packet which can be read and processed */

    if (s->s3->change_cipher_spec /* set when we receive ChangeCipherSpec,
                                   * reset by ssl3_get_finished */
        && (rr->type != SSL3_RT_HANDSHAKE)) {
        al = SSL_AD_UNEXPECTED_MESSAGE;
        SSLerr(SSL_F_SSL3_READ_BYTES, SSL_R_DATA_BETWEEN_CCS_AND_FINISHED);
        goto f_err;
    }

    /*
     * If the other end has shut down, throw anything we read away (even in
     * 'peek' mode)
     */
    if (s->shutdown & SSL_RECEIVED_SHUTDOWN) {
        rr->length = 0;
        s->rwstate = SSL_NOTHING;
        return (0);
    }

    if (type == rr->type) {     /* SSL3_RT_APPLICATION_DATA or
                                 * SSL3_RT_HANDSHAKE */
        /*
         * make sure that we are not getting application data when we are
         * doing a handshake for the first time
         */
        if (SSL_in_init(s) && (type == SSL3_RT_APPLICATION_DATA) &&
            (s->enc_read_ctx == NULL)) {
            al = SSL_AD_UNEXPECTED_MESSAGE;
            SSLerr(SSL_F_SSL3_READ_BYTES, SSL_R_APP_DATA_IN_HANDSHAKE);
            goto f_err;
        }

        if (len <= 0)
            return (len);

        if ((unsigned int)len > rr->length)
            n = rr->length;
        else
            n = (unsigned int)len;

        memcpy(buf, &(rr->data[rr->off]), n);
        if (!peek) {
            rr->length -= n;
            rr->off += n;
            if (rr->length == 0) {
                s->rstate = SSL_ST_READ_HEADER;
                rr->off = 0;
                if (s->mode & SSL_MODE_RELEASE_BUFFERS
                    && s->s3->rbuf.left == 0)
                    ssl3_release_read_buffer(s);
            }
        }
        return (n);
    }

    /*
     * If we get here, then type != rr->type; if we have a handshake message,
     * then it was unexpected (Hello Request or Client Hello).
     */

    /*
     * In case of record types for which we have 'fragment' storage, fill
     * that so that we can process the data at a fixed place.
     */
    {
        unsigned int dest_maxlen = 0;
        unsigned char *dest = NULL;
        unsigned int *dest_len = NULL;

        if (rr->type == SSL3_RT_HANDSHAKE) {
            dest_maxlen = sizeof(s->s3->handshake_fragment);
            dest = s->s3->handshake_fragment;
            dest_len = &s->s3->handshake_fragment_len;
        } else if (rr->type == SSL3_RT_ALERT) {
            dest_maxlen = sizeof(s->s3->alert_fragment);
            dest = s->s3->alert_fragment;
            dest_len = &s->s3->alert_fragment_len;
        }
#ifndef OPENSSL_NO_HEARTBEATS
        else if (rr->type == TLS1_RT_HEARTBEAT) {
            i = tls1_process_heartbeat(s);

            if (i < 0)
                return i;

            rr->length = 0;
            if (s->mode & SSL_MODE_AUTO_RETRY)
                goto start;

            /* Exit and notify application to read again */
            s->rwstate = SSL_READING;
            BIO_clear_retry_flags(SSL_get_rbio(s));
            BIO_set_retry_read(SSL_get_rbio(s));
            return (-1);
        }
#endif

        if (dest_maxlen > 0) {
            n = dest_maxlen - *dest_len; /* available space in 'dest' */
            if (rr->length < n)
                n = rr->length; /* available bytes */

            /* now move 'n' bytes: */
            while (n-- > 0) {
                dest[(*dest_len)++] = rr->data[rr->off++];
                rr->length--;
            }

            if (*dest_len < dest_maxlen)
                goto start;     /* fragment was too small */
        }
    }

    /*-
     * s->s3->handshake_fragment_len == 4  iff  rr->type == SSL3_RT_HANDSHAKE;
     * s->s3->alert_fragment_len == 2      iff  rr->type == SSL3_RT_ALERT.
     * (Possibly rr is 'empty' now, i.e. rr->length may be 0.)
     */

    /* If we are a client, check for an incoming 'Hello Request': */
    if ((!s->server) &&
        (s->s3->handshake_fragment_len >= 4) &&
        (s->s3->handshake_fragment[0] == SSL3_MT_HELLO_REQUEST) &&
        (s->session != NULL) && (s->session->cipher != NULL)) {
        s->s3->handshake_fragment_len = 0;

        if ((s->s3->handshake_fragment[1] != 0) ||
            (s->s3->handshake_fragment[2] != 0) ||
            (s->s3->handshake_fragment[3] != 0)) {
            al = SSL_AD_DECODE_ERROR;
            SSLerr(SSL_F_SSL3_READ_BYTES, SSL_R_BAD_HELLO_REQUEST);
            goto f_err;
        }

        if (s->msg_callback)
            s->msg_callback(0, s->version, SSL3_RT_HANDSHAKE,
                            s->s3->handshake_fragment, 4, s,
                            s->msg_callback_arg);

        if (SSL_is_init_finished(s) &&
            !(s->s3->flags & SSL3_FLAGS_NO_RENEGOTIATE_CIPHERS) &&
            !s->s3->renegotiate) {
            ssl3_renegotiate(s);
            if (ssl3_renegotiate_check(s)) {
                i = s->handshake_func(s);
                if (i < 0)
                    return (i);
                if (i == 0) {
                    SSLerr(SSL_F_SSL3_READ_BYTES,
                           SSL_R_SSL_HANDSHAKE_FAILURE);
                    return (-1);
                }

                if (!(s->mode & SSL_MODE_AUTO_RETRY)) {
                    if (s->s3->rbuf.left == 0) { /* no read-ahead left? */
                        BIO *bio;
                        /*
                         * In the case where we try to read application data,
                         * but we trigger an SSL handshake, we return -1 with
                         * the retry option set.  Otherwise renegotiation may
                         * cause nasty problems in the blocking world
                         */
                        s->rwstate = SSL_READING;
                        bio = SSL_get_rbio(s);
                        BIO_clear_retry_flags(bio);
                        BIO_set_retry_read(bio);
                        return (-1);
                    }
                }
            }
        }
        /*
         * we either finished a handshake or ignored the request, now try
         * again to obtain the (application) data we were asked for
         */
        goto start;
    }

    /*
     * If we are a server and get a client hello when renegotiation isn't
     * allowed send back a no renegotiation alert and carry on.
     */
    if (s->server
            && SSL_is_init_finished(s)
            && !s->s3->send_connection_binding
            && s->version > SSL3_VERSION
            && s->s3->handshake_fragment_len >= SSL3_HM_HEADER_LENGTH
            && s->s3->handshake_fragment[0] == SSL3_MT_CLIENT_HELLO
            && s->s3->previous_client_finished_len != 0
            && (s->options & SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION) == 0) {
        s->s3->handshake_fragment_len = 0;
        rr->length = 0;
        ssl3_send_alert(s, SSL3_AL_WARNING, SSL_AD_NO_RENEGOTIATION);
        goto start;
    }

    if (s->s3->alert_fragment_len >= 2) {
        int alert_level = s->s3->alert_fragment[0];
        int alert_descr = s->s3->alert_fragment[1];

        s->s3->alert_fragment_len = 0;

        if (s->msg_callback)
            s->msg_callback(0, s->version, SSL3_RT_ALERT,
                            s->s3->alert_fragment, 2, s, s->msg_callback_arg);

        if (s->info_callback != NULL)
            cb = s->info_callback;
        else if (s->ctx->info_callback != NULL)
            cb = s->ctx->info_callback;

        if (cb != NULL) {
            j = (alert_level << 8) | alert_descr;
            cb(s, SSL_CB_READ_ALERT, j);
        }

        if (alert_level == SSL3_AL_WARNING) {
            s->s3->warn_alert = alert_descr;

            s->cert->alert_count++;
            if (s->cert->alert_count == MAX_WARN_ALERT_COUNT) {
                al = SSL_AD_UNEXPECTED_MESSAGE;
                SSLerr(SSL_F_SSL3_READ_BYTES, SSL_R_TOO_MANY_WARN_ALERTS);
                goto f_err;
            }

            if (alert_descr == SSL_AD_CLOSE_NOTIFY) {
                s->shutdown |= SSL_RECEIVED_SHUTDOWN;
                return (0);
            }
            /*
             * This is a warning but we receive it if we requested
             * renegotiation and the peer denied it. Terminate with a fatal
             * alert because if application tried to renegotiatie it
             * presumably had a good reason and expects it to succeed. In
             * future we might have a renegotiation where we don't care if
             * the peer refused it where we carry on.
             */
            else if (alert_descr == SSL_AD_NO_RENEGOTIATION) {
                al = SSL_AD_HANDSHAKE_FAILURE;
                SSLerr(SSL_F_SSL3_READ_BYTES, SSL_R_NO_RENEGOTIATION);
                goto f_err;
            }
#ifdef SSL_AD_MISSING_SRP_USERNAME
            else if (alert_descr == SSL_AD_MISSING_SRP_USERNAME)
                return (0);
#endif
        } else if (alert_level == SSL3_AL_FATAL) {
            char tmp[16];

            s->rwstate = SSL_NOTHING;
            s->s3->fatal_alert = alert_descr;
            SSLerr(SSL_F_SSL3_READ_BYTES, SSL_AD_REASON_OFFSET + alert_descr);
            BIO_snprintf(tmp, sizeof(tmp), "%d", alert_descr);
            ERR_add_error_data(2, "SSL alert number ", tmp);
            s->shutdown |= SSL_RECEIVED_SHUTDOWN;
            SSL_CTX_remove_session(s->session_ctx, s->session);
            return (0);
        } else {
            al = SSL_AD_ILLEGAL_PARAMETER;
            SSLerr(SSL_F_SSL3_READ_BYTES, SSL_R_UNKNOWN_ALERT_TYPE);
            goto f_err;
        }

        goto start;
    }

    if (s->shutdown & SSL_SENT_SHUTDOWN) { /* but we have not received a
                                            * shutdown */
        s->rwstate = SSL_NOTHING;
        rr->length = 0;
        return (0);
    }

    if (rr->type == SSL3_RT_CHANGE_CIPHER_SPEC) {
        /*
         * 'Change Cipher Spec' is just a single byte, so we know exactly
         * what the record payload has to look like
         */
        if ((rr->length != 1) || (rr->off != 0) ||
            (rr->data[0] != SSL3_MT_CCS)) {
            al = SSL_AD_ILLEGAL_PARAMETER;
            SSLerr(SSL_F_SSL3_READ_BYTES, SSL_R_BAD_CHANGE_CIPHER_SPEC);
            goto f_err;
        }

        /* Check we have a cipher to change to */
        if (s->s3->tmp.new_cipher == NULL) {
            al = SSL_AD_UNEXPECTED_MESSAGE;
            SSLerr(SSL_F_SSL3_READ_BYTES, SSL_R_CCS_RECEIVED_EARLY);
            goto f_err;
        }

        if (!(s->s3->flags & SSL3_FLAGS_CCS_OK)) {
            al = SSL_AD_UNEXPECTED_MESSAGE;
            SSLerr(SSL_F_SSL3_READ_BYTES, SSL_R_CCS_RECEIVED_EARLY);
            goto f_err;
        }

        s->s3->flags &= ~SSL3_FLAGS_CCS_OK;

        rr->length = 0;

        if (s->msg_callback)
            s->msg_callback(0, s->version, SSL3_RT_CHANGE_CIPHER_SPEC,
                            rr->data, 1, s, s->msg_callback_arg);

        s->s3->change_cipher_spec = 1;
        if (!ssl3_do_change_cipher_spec(s))
            goto err;
        else
            goto start;
    }

    /*
     * Unexpected handshake message (Client Hello, or protocol violation)
     */
    if ((s->s3->handshake_fragment_len >= 4) && !s->in_handshake) {
        if (((s->state & SSL_ST_MASK) == SSL_ST_OK) &&
            !(s->s3->flags & SSL3_FLAGS_NO_RENEGOTIATE_CIPHERS)) {
#if 0                           /* worked only because C operator preferences
                                 * are not as expected (and because this is
                                 * not really needed for clients except for
                                 * detecting protocol violations): */
            s->state = SSL_ST_BEFORE | (s->server)
                ? SSL_ST_ACCEPT : SSL_ST_CONNECT;
#else
            s->state = s->server ? SSL_ST_ACCEPT : SSL_ST_CONNECT;
#endif
            s->renegotiate = 1;
            s->new_session = 1;
        }
        i = s->handshake_func(s);
        if (i < 0)
            return (i);
        if (i == 0) {
            SSLerr(SSL_F_SSL3_READ_BYTES, SSL_R_SSL_HANDSHAKE_FAILURE);
            return (-1);
        }

        if (!(s->mode & SSL_MODE_AUTO_RETRY)) {
            if (s->s3->rbuf.left == 0) { /* no read-ahead left? */
                BIO *bio;
                /*
                 * In the case where we try to read application data, but we
                 * trigger an SSL handshake, we return -1 with the retry
                 * option set.  Otherwise renegotiation may cause nasty
                 * problems in the blocking world
                 */
                s->rwstate = SSL_READING;
                bio = SSL_get_rbio(s);
                BIO_clear_retry_flags(bio);
                BIO_set_retry_read(bio);
                return (-1);
            }
        }
        goto start;
    }

    switch (rr->type) {
    default:
        /*
         * TLS 1.0 and 1.1 say you SHOULD ignore unrecognised record types, but
         * TLS 1.2 says you MUST send an unexpected message alert. We use the
         * TLS 1.2 behaviour for all protocol versions to prevent issues where
         * no progress is being made and the peer continually sends unrecognised
         * record types, using up resources processing them.
         */
        al = SSL_AD_UNEXPECTED_MESSAGE;
        SSLerr(SSL_F_SSL3_READ_BYTES, SSL_R_UNEXPECTED_RECORD);
        goto f_err;
    case SSL3_RT_CHANGE_CIPHER_SPEC:
    case SSL3_RT_ALERT:
    case SSL3_RT_HANDSHAKE:
        /*
         * we already handled all of these, with the possible exception of
         * SSL3_RT_HANDSHAKE when s->in_handshake is set, but that should not
         * happen when type != rr->type
         */
        al = SSL_AD_UNEXPECTED_MESSAGE;
        SSLerr(SSL_F_SSL3_READ_BYTES, ERR_R_INTERNAL_ERROR);
        goto f_err;
    case SSL3_RT_APPLICATION_DATA:
        /*
         * At this point, we were expecting handshake data, but have
         * application data.  If the library was running inside ssl3_read()
         * (i.e. in_read_app_data is set) and it makes sense to read
         * application data at this point (session renegotiation not yet
         * started), we will indulge it.
         */
        if (s->s3->in_read_app_data &&
            (s->s3->total_renegotiations != 0) &&
            (((s->state & SSL_ST_CONNECT) &&
              (s->state >= SSL3_ST_CW_CLNT_HELLO_A) &&
              (s->state <= SSL3_ST_CR_SRVR_HELLO_A)
             ) || ((s->state & SSL_ST_ACCEPT) &&
                   (s->state <= SSL3_ST_SW_HELLO_REQ_A) &&
                   (s->state >= SSL3_ST_SR_CLNT_HELLO_A)
             )
            )) {
            s->s3->in_read_app_data = 2;
            return (-1);
        } else {
            al = SSL_AD_UNEXPECTED_MESSAGE;
            SSLerr(SSL_F_SSL3_READ_BYTES, SSL_R_UNEXPECTED_RECORD);
            goto f_err;
        }
    }
    /* not reached */

 f_err:
    ssl3_send_alert(s, SSL3_AL_FATAL, al);
 err:
    return (-1);
}

int ssl3_do_change_cipher_spec(SSL *s)
{
    int i;
    const char *sender;
    int slen;

    if (s->state & SSL_ST_ACCEPT)
        i = SSL3_CHANGE_CIPHER_SERVER_READ;
    else
        i = SSL3_CHANGE_CIPHER_CLIENT_READ;

    if (s->s3->tmp.key_block == NULL) {
        if (s->session == NULL || s->session->master_key_length == 0) {
            /* might happen if dtls1_read_bytes() calls this */
            SSLerr(SSL_F_SSL3_DO_CHANGE_CIPHER_SPEC,
                   SSL_R_CCS_RECEIVED_EARLY);
            return (0);
        }

        s->session->cipher = s->s3->tmp.new_cipher;
        if (!s->method->ssl3_enc->setup_key_block(s))
            return (0);
    }

    if (!s->method->ssl3_enc->change_cipher_state(s, i))
        return (0);

    /*
     * we have to record the message digest at this point so we can get it
     * before we read the finished message
     */
    if (s->state & SSL_ST_CONNECT) {
        sender = s->method->ssl3_enc->server_finished_label;
        slen = s->method->ssl3_enc->server_finished_label_len;
    } else {
        sender = s->method->ssl3_enc->client_finished_label;
        slen = s->method->ssl3_enc->client_finished_label_len;
    }

    i = s->method->ssl3_enc->final_finish_mac(s,
                                              sender, slen,
                                              s->s3->tmp.peer_finish_md);
    if (i == 0) {
        SSLerr(SSL_F_SSL3_DO_CHANGE_CIPHER_SPEC, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    s->s3->tmp.peer_finish_md_len = i;

    return (1);
}

int ssl3_send_alert(SSL *s, int level, int desc)
{
    /* Map tls/ssl alert value to correct one */
    desc = s->method->ssl3_enc->alert_value(desc);
    if (s->version == SSL3_VERSION && desc == SSL_AD_PROTOCOL_VERSION)
        desc = SSL_AD_HANDSHAKE_FAILURE; /* SSL 3.0 does not have
                                          * protocol_version alerts */
    if (desc < 0)
        return -1;
    /* If a fatal one, remove from cache */
    if ((level == 2) && (s->session != NULL))
        SSL_CTX_remove_session(s->session_ctx, s->session);

    s->s3->alert_dispatch = 1;
    s->s3->send_alert[0] = level;
    s->s3->send_alert[1] = desc;
    if (s->s3->wbuf.left == 0)  /* data still being written out? */
        return s->method->ssl_dispatch_alert(s);
    /*
     * else data is still being written out, we will get written some time in
     * the future
     */
    return -1;
}

int ssl3_dispatch_alert(SSL *s)
{
    int i, j;
    void (*cb) (const SSL *ssl, int type, int val) = NULL;

    s->s3->alert_dispatch = 0;
    i = do_ssl3_write(s, SSL3_RT_ALERT, &s->s3->send_alert[0], 2, 0);
    if (i <= 0) {
        s->s3->alert_dispatch = 1;
    } else {
        /*
         * Alert sent to BIO.  If it is important, flush it now. If the
         * message does not get sent due to non-blocking IO, we will not
         * worry too much.
         */
        if (s->s3->send_alert[0] == SSL3_AL_FATAL)
            (void)BIO_flush(s->wbio);

        if (s->msg_callback)
            s->msg_callback(1, s->version, SSL3_RT_ALERT, s->s3->send_alert,
                            2, s, s->msg_callback_arg);

        if (s->info_callback != NULL)
            cb = s->info_callback;
        else if (s->ctx->info_callback != NULL)
            cb = s->ctx->info_callback;

        if (cb != NULL) {
            j = (s->s3->send_alert[0] << 8) | s->s3->send_alert[1];
            cb(s, SSL_CB_WRITE_ALERT, j);
        }
    }
    return (i);
}
/* ssl/s3_srvr.c */
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
/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 *
 * Portions of the attached software ("Contribution") are developed by
 * SUN MICROSYSTEMS, INC., and are contributed to the OpenSSL project.
 *
 * The Contribution is licensed pursuant to the OpenSSL open source
 * license provided above.
 *
 * ECC cipher suite support in OpenSSL originally written by
 * Vipul Gupta and Sumit Gupta of Sun Microsystems Laboratories.
 *
 */
/* ====================================================================
 * Copyright 2005 Nokia. All rights reserved.
 *
 * The portions of the attached software ("Contribution") is developed by
 * Nokia Corporation and is licensed pursuant to the OpenSSL open source
 * license.
 *
 * The Contribution, originally written by Mika Kousa and Pasi Eronen of
 * Nokia Corporation, consists of the "PSK" (Pre-Shared Key) ciphersuites
 * support (see RFC 4279) to OpenSSL.
 *
 * No patent licenses or other rights except those expressly stated in
 * the OpenSSL open source license shall be deemed granted or received
 * expressly, by implication, estoppel, or otherwise.
 *
 * No assurances are provided by Nokia that the Contribution does not
 * infringe the patent or other intellectual property rights of any third
 * party or that the license provides you with all the necessary rights
 * to make use of the Contribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND. IN
 * ADDITION TO THE DISCLAIMERS INCLUDED IN THE LICENSE, NOKIA
 * SPECIFICALLY DISCLAIMS ANY LIABILITY FOR CLAIMS BROUGHT BY YOU OR ANY
 * OTHER ENTITY BASED ON INFRINGEMENT OF INTELLECTUAL PROPERTY RIGHTS OR
 * OTHERWISE.
 */

#define REUSE_CIPHER_BUG
#define NETSCAPE_HANG_BUG

#include <stdio.h>
// #include "ssl_locl.h"
// #include "kssl_lcl.h"
// #include "constant_time_locl.h"
// #include "buffer.h"
// #include "rand.h"
// #include "objects.h"
// #include "evp.h"
#include "hmac.h"
// #include "x509.h"
#ifndef OPENSSL_NO_DH
# include "dh.h"
#endif
// #include "bn.h"
#ifndef OPENSSL_NO_KRB5
# include "krb5_asn.h"
#endif
// #include "md5.h"

#ifndef OPENSSL_NO_SSL3_METHOD
static const SSL_METHOD *ssl3_get_server_method(int ver);

static const SSL_METHOD *ssl3_get_server_method(int ver)
{
    if (ver == SSL3_VERSION)
        return (SSLv3_server_method());
    else
        return (NULL);
}

IMPLEMENT_ssl3_meth_func(SSLv3_server_method,
                         ssl3_accept,
                         ssl_undefined_function, ssl3_get_server_method)
#endif
#ifndef OPENSSL_NO_SRP
static int ssl_check_srp_ext_ClientHello(SSL *s, int *al)
{
    int ret = SSL_ERROR_NONE;

    *al = SSL_AD_UNRECOGNIZED_NAME;

    if ((s->s3->tmp.new_cipher->algorithm_mkey & SSL_kSRP) &&
        (s->srp_ctx.TLS_ext_srp_username_callback != NULL)) {
        if (s->srp_ctx.login == NULL) {
            /*
             * RFC 5054 says SHOULD reject, we do so if There is no srp
             * login name
             */
            ret = SSL3_AL_FATAL;
            *al = SSL_AD_UNKNOWN_PSK_IDENTITY;
        } else {
            ret = SSL_srp_server_param_with_username(s, al);
        }
    }
    return ret;
}
#endif

int ssl3_accept(SSL *s)
{
    BUF_MEM *buf;
    unsigned long alg_k, Time = (unsigned long)time(NULL);
    void (*cb) (const SSL *ssl, int type, int val) = NULL;
    int ret = -1;
    int new_state, state, skip = 0;

    RAND_add(&Time, sizeof(Time), 0);
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
        SSLerr(SSL_F_SSL3_ACCEPT, SSL_R_NO_CERTIFICATE_SET);
        return (-1);
    }
#ifndef OPENSSL_NO_HEARTBEATS
    /*
     * If we're awaiting a HeartbeatResponse, pretend we already got and
     * don't await it anymore, because Heartbeats don't make sense during
     * handshakes anyway.
     */
    if (s->tlsext_hb_pending) {
        s->tlsext_hb_pending = 0;
        s->tlsext_hb_seq++;
    }
#endif

    for (;;) {
        state = s->state;

        switch (s->state) {
        case SSL_ST_RENEGOTIATE:
            s->renegotiate = 1;
            /* s->state=SSL_ST_ACCEPT; */

        case SSL_ST_BEFORE:
        case SSL_ST_ACCEPT:
        case SSL_ST_BEFORE | SSL_ST_ACCEPT:
        case SSL_ST_OK | SSL_ST_ACCEPT:

            s->server = 1;
            if (cb != NULL)
                cb(s, SSL_CB_HANDSHAKE_START, 1);

            if ((s->version >> 8) != 3) {
                SSLerr(SSL_F_SSL3_ACCEPT, ERR_R_INTERNAL_ERROR);
                s->state = SSL_ST_ERR;
                return -1;
            }
            s->type = SSL_ST_ACCEPT;

            if (s->init_buf == NULL) {
                if ((buf = BUF_MEM_new()) == NULL) {
                    ret = -1;
                    s->state = SSL_ST_ERR;
                    goto end;
                }
                if (!BUF_MEM_grow(buf, SSL3_RT_MAX_PLAIN_LENGTH)) {
                    BUF_MEM_free(buf);
                    ret = -1;
                    s->state = SSL_ST_ERR;
                    goto end;
                }
                s->init_buf = buf;
            }

            if (!ssl3_setup_buffers(s)) {
                ret = -1;
                s->state = SSL_ST_ERR;
                goto end;
            }

            s->init_num = 0;
            s->s3->flags &= ~TLS1_FLAGS_SKIP_CERT_VERIFY;
            s->s3->flags &= ~SSL3_FLAGS_CCS_OK;
            /*
             * Should have been reset by ssl3_get_finished, too.
             */
            s->s3->change_cipher_spec = 0;

            if (s->state != SSL_ST_RENEGOTIATE) {
                /*
                 * Ok, we now need to push on a buffering BIO so that the
                 * output is sent in a way that TCP likes :-)
                 */
                if (!ssl_init_wbio_buffer(s, 1)) {
                    ret = -1;
                    s->state = SSL_ST_ERR;
                    goto end;
                }

                if (!ssl3_init_finished_mac(s)) {
                    ret = -1;
                    s->state = SSL_ST_ERR;
                    goto end;
                }

                s->state = SSL3_ST_SR_CLNT_HELLO_A;
                s->ctx->stats.sess_accept++;
            } else if (!s->s3->send_connection_binding &&
                       !(s->options &
                         SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION)) {
                /*
                 * Server attempting to renegotiate with client that doesn't
                 * support secure renegotiation.
                 */
                SSLerr(SSL_F_SSL3_ACCEPT,
                       SSL_R_UNSAFE_LEGACY_RENEGOTIATION_DISABLED);
                ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_HANDSHAKE_FAILURE);
                ret = -1;
                s->state = SSL_ST_ERR;
                goto end;
            } else {
                /*
                 * s->state == SSL_ST_RENEGOTIATE, we will just send a
                 * HelloRequest
                 */
                s->ctx->stats.sess_accept_renegotiate++;
                s->state = SSL3_ST_SW_HELLO_REQ_A;
            }
            break;

        case SSL3_ST_SW_HELLO_REQ_A:
        case SSL3_ST_SW_HELLO_REQ_B:

            s->shutdown = 0;
            ret = ssl3_send_hello_request(s);
            if (ret <= 0)
                goto end;
            s->s3->tmp.next_state = SSL3_ST_SW_HELLO_REQ_C;
            s->state = SSL3_ST_SW_FLUSH;
            s->init_num = 0;

            if (!ssl3_init_finished_mac(s)) {
                ret = -1;
                s->state = SSL_ST_ERR;
                goto end;
            }
            break;

        case SSL3_ST_SW_HELLO_REQ_C:
            s->state = SSL_ST_OK;
            break;

        case SSL3_ST_SR_CLNT_HELLO_A:
        case SSL3_ST_SR_CLNT_HELLO_B:
        case SSL3_ST_SR_CLNT_HELLO_C:

            s->shutdown = 0;
            ret = ssl3_get_client_hello(s);
            if (ret <= 0)
                goto end;
#ifndef OPENSSL_NO_SRP
            s->state = SSL3_ST_SR_CLNT_HELLO_D;
        case SSL3_ST_SR_CLNT_HELLO_D:
            {
                int al;
                if ((ret = ssl_check_srp_ext_ClientHello(s, &al)) < 0) {
                    /*
                     * callback indicates firther work to be done
                     */
                    s->rwstate = SSL_X509_LOOKUP;
                    goto end;
                }
                if (ret != SSL_ERROR_NONE) {
                    ssl3_send_alert(s, SSL3_AL_FATAL, al);
                    /*
                     * This is not really an error but the only means to for
                     * a client to detect whether srp is supported.
                     */
                    if (al != TLS1_AD_UNKNOWN_PSK_IDENTITY)
                        SSLerr(SSL_F_SSL3_ACCEPT, SSL_R_CLIENTHELLO_TLSEXT);
                    ret = -1;
                    s->state = SSL_ST_ERR;
                    goto end;
                }
            }
#endif

            s->renegotiate = 2;
            s->state = SSL3_ST_SW_SRVR_HELLO_A;
            s->init_num = 0;
            break;

        case SSL3_ST_SW_SRVR_HELLO_A:
        case SSL3_ST_SW_SRVR_HELLO_B:
            ret = ssl3_send_server_hello(s);
            if (ret <= 0)
                goto end;
#ifndef OPENSSL_NO_TLSEXT
            if (s->hit) {
                if (s->tlsext_ticket_expected)
                    s->state = SSL3_ST_SW_SESSION_TICKET_A;
                else
                    s->state = SSL3_ST_SW_CHANGE_A;
            }
#else
            if (s->hit)
                s->state = SSL3_ST_SW_CHANGE_A;
#endif
            else
                s->state = SSL3_ST_SW_CERT_A;
            s->init_num = 0;
            break;

        case SSL3_ST_SW_CERT_A:
        case SSL3_ST_SW_CERT_B:
            /* Check if it is anon DH or anon ECDH, */
            /* normal PSK or KRB5 or SRP */
            if (!
                (s->s3->tmp.
                 new_cipher->algorithm_auth & (SSL_aNULL | SSL_aKRB5 |
                                               SSL_aSRP))
&& !(s->s3->tmp.new_cipher->algorithm_mkey & SSL_kPSK)) {
                ret = ssl3_send_server_certificate(s);
                if (ret <= 0)
                    goto end;
#ifndef OPENSSL_NO_TLSEXT
                if (s->tlsext_status_expected)
                    s->state = SSL3_ST_SW_CERT_STATUS_A;
                else
                    s->state = SSL3_ST_SW_KEY_EXCH_A;
            } else {
                skip = 1;
                s->state = SSL3_ST_SW_KEY_EXCH_A;
            }
#else
            } else
                skip = 1;

            s->state = SSL3_ST_SW_KEY_EXCH_A;
#endif
            s->init_num = 0;
            break;

        case SSL3_ST_SW_KEY_EXCH_A:
        case SSL3_ST_SW_KEY_EXCH_B:
            alg_k = s->s3->tmp.new_cipher->algorithm_mkey;

            /*
             * clear this, it may get reset by
             * send_server_key_exchange
             */
            s->s3->tmp.use_rsa_tmp = 0;

            /*
             * only send if a DH key exchange, fortezza or RSA but we have a
             * sign only certificate PSK: may send PSK identity hints For
             * ECC ciphersuites, we send a serverKeyExchange message only if
             * the cipher suite is either ECDH-anon or ECDHE. In other cases,
             * the server certificate contains the server's public key for
             * key exchange.
             */
            if (0
                /*
                 * PSK: send ServerKeyExchange if PSK identity hint if
                 * provided
                 */
#ifndef OPENSSL_NO_PSK
                || ((alg_k & SSL_kPSK) && s->ctx->psk_identity_hint)
#endif
#ifndef OPENSSL_NO_SRP
                /* SRP: send ServerKeyExchange */
                || (alg_k & SSL_kSRP)
#endif
                || (alg_k & SSL_kEDH)
                || (alg_k & SSL_kEECDH)
                || ((alg_k & SSL_kRSA)
                    && (s->cert->pkeys[SSL_PKEY_RSA_ENC].privatekey == NULL
                        || (SSL_C_IS_EXPORT(s->s3->tmp.new_cipher)
                            && EVP_PKEY_size(s->cert->pkeys
                                             [SSL_PKEY_RSA_ENC].privatekey) *
                            8 > SSL_C_EXPORT_PKEYLENGTH(s->s3->tmp.new_cipher)
                        )
                    )
                )
                ) {
                ret = ssl3_send_server_key_exchange(s);
                if (ret <= 0)
                    goto end;
            } else
                skip = 1;

            s->state = SSL3_ST_SW_CERT_REQ_A;
            s->init_num = 0;
            break;

        case SSL3_ST_SW_CERT_REQ_A:
        case SSL3_ST_SW_CERT_REQ_B:
            if (                /* don't request cert unless asked for it: */
                   !(s->verify_mode & SSL_VERIFY_PEER) ||
                   /*
                    * if SSL_VERIFY_CLIENT_ONCE is set, don't request cert
                    * during re-negotiation:
                    */
                   (s->s3->tmp.finish_md_len != 0 &&
                    (s->verify_mode & SSL_VERIFY_CLIENT_ONCE)) ||
                   /*
                    * never request cert in anonymous ciphersuites (see
                    * section "Certificate request" in SSL 3 drafts and in
                    * RFC 2246):
                    */
                   ((s->s3->tmp.new_cipher->algorithm_auth & SSL_aNULL) &&
                    /*
                     * ... except when the application insists on
                     * verification (against the specs, but s3_clnt.c accepts
                     * this for SSL 3)
                     */
                    !(s->verify_mode & SSL_VERIFY_FAIL_IF_NO_PEER_CERT)) ||
                   /*
                    * never request cert in Kerberos ciphersuites
                    */
                   (s->s3->tmp.new_cipher->algorithm_auth & SSL_aKRB5) ||
                   /* don't request certificate for SRP auth */
                   (s->s3->tmp.new_cipher->algorithm_auth & SSL_aSRP)
                   /*
                    * With normal PSK Certificates and Certificate Requests
                    * are omitted
                    */
                   || (s->s3->tmp.new_cipher->algorithm_mkey & SSL_kPSK)) {
                /* no cert request */
                skip = 1;
                s->s3->tmp.cert_request = 0;
                s->state = SSL3_ST_SW_SRVR_DONE_A;
                if (s->s3->handshake_buffer) {
                    if (!ssl3_digest_cached_records(s)) {
                        s->state = SSL_ST_ERR;
                        return -1;
                    }
                }
            } else {
                s->s3->tmp.cert_request = 1;
                ret = ssl3_send_certificate_request(s);
                if (ret <= 0)
                    goto end;
#ifndef NETSCAPE_HANG_BUG
                s->state = SSL3_ST_SW_SRVR_DONE_A;
#else
                s->state = SSL3_ST_SW_FLUSH;
                s->s3->tmp.next_state = SSL3_ST_SR_CERT_A;
#endif
                s->init_num = 0;
            }
            break;

        case SSL3_ST_SW_SRVR_DONE_A:
        case SSL3_ST_SW_SRVR_DONE_B:
            ret = ssl3_send_server_done(s);
            if (ret <= 0)
                goto end;
            s->s3->tmp.next_state = SSL3_ST_SR_CERT_A;
            s->state = SSL3_ST_SW_FLUSH;
            s->init_num = 0;
            break;

        case SSL3_ST_SW_FLUSH:

            /*
             * This code originally checked to see if any data was pending
             * using BIO_CTRL_INFO and then flushed. This caused problems as
             * documented in PR#1939. The proposed fix doesn't completely
             * resolve this issue as buggy implementations of
             * BIO_CTRL_PENDING still exist. So instead we just flush
             * unconditionally.
             */

            s->rwstate = SSL_WRITING;
            if (BIO_flush(s->wbio) <= 0) {
                ret = -1;
                goto end;
            }
            s->rwstate = SSL_NOTHING;

            s->state = s->s3->tmp.next_state;
            break;

        case SSL3_ST_SR_CERT_A:
        case SSL3_ST_SR_CERT_B:
            if (s->s3->tmp.cert_request) {
                ret = ssl3_get_client_certificate(s);
                if (ret <= 0)
                    goto end;
            }
            s->init_num = 0;
            s->state = SSL3_ST_SR_KEY_EXCH_A;
            break;

        case SSL3_ST_SR_KEY_EXCH_A:
        case SSL3_ST_SR_KEY_EXCH_B:
            ret = ssl3_get_client_key_exchange(s);
            if (ret <= 0)
                goto end;
            if (ret == 2) {
                /*
                 * For the ECDH ciphersuites when the client sends its ECDH
                 * pub key in a certificate, the CertificateVerify message is
                 * not sent. Also for GOST ciphersuites when the client uses
                 * its key from the certificate for key exchange.
                 */
#if defined(OPENSSL_NO_TLSEXT) || defined(OPENSSL_NO_NEXTPROTONEG)
                s->state = SSL3_ST_SR_FINISHED_A;
#else
                if (s->s3->next_proto_neg_seen)
                    s->state = SSL3_ST_SR_NEXT_PROTO_A;
                else
                    s->state = SSL3_ST_SR_FINISHED_A;
#endif
                s->init_num = 0;
            } else if (SSL_USE_SIGALGS(s)) {
                s->state = SSL3_ST_SR_CERT_VRFY_A;
                s->init_num = 0;
                if (!s->session->peer)
                    break;
                /*
                 * For sigalgs freeze the handshake buffer at this point and
                 * digest cached records.
                 */
                if (!s->s3->handshake_buffer) {
                    SSLerr(SSL_F_SSL3_ACCEPT, ERR_R_INTERNAL_ERROR);
                    s->state = SSL_ST_ERR;
                    return -1;
                }
                s->s3->flags |= TLS1_FLAGS_KEEP_HANDSHAKE;
                if (!ssl3_digest_cached_records(s)) {
                    s->state = SSL_ST_ERR;
                    return -1;
                }
            } else {
                int offset = 0;
                int dgst_num;

                s->state = SSL3_ST_SR_CERT_VRFY_A;
                s->init_num = 0;

                /*
                 * We need to get hashes here so if there is a client cert,
                 * it can be verified FIXME - digest processing for
                 * CertificateVerify should be generalized. But it is next
                 * step
                 */
                if (s->s3->handshake_buffer) {
                    if (!ssl3_digest_cached_records(s)) {
                        s->state = SSL_ST_ERR;
                        return -1;
                    }
                }
                for (dgst_num = 0; dgst_num < SSL_MAX_DIGEST; dgst_num++)
                    if (s->s3->handshake_dgst[dgst_num]) {
                        int dgst_size;

                        s->method->ssl3_enc->cert_verify_mac(s,
                                                             EVP_MD_CTX_type
                                                             (s->
                                                              s3->handshake_dgst
                                                              [dgst_num]),
                                                             &(s->s3->
                                                               tmp.cert_verify_md
                                                               [offset]));
                        dgst_size =
                            EVP_MD_CTX_size(s->s3->handshake_dgst[dgst_num]);
                        if (dgst_size < 0) {
                            s->state = SSL_ST_ERR;
                            ret = -1;
                            goto end;
                        }
                        offset += dgst_size;
                    }
            }
            break;

        case SSL3_ST_SR_CERT_VRFY_A:
        case SSL3_ST_SR_CERT_VRFY_B:
            ret = ssl3_get_cert_verify(s);
            if (ret <= 0)
                goto end;

#if defined(OPENSSL_NO_TLSEXT) || defined(OPENSSL_NO_NEXTPROTONEG)
            s->state = SSL3_ST_SR_FINISHED_A;
#else
            if (s->s3->next_proto_neg_seen)
                s->state = SSL3_ST_SR_NEXT_PROTO_A;
            else
                s->state = SSL3_ST_SR_FINISHED_A;
#endif
            s->init_num = 0;
            break;

#if !defined(OPENSSL_NO_TLSEXT) && !defined(OPENSSL_NO_NEXTPROTONEG)
        case SSL3_ST_SR_NEXT_PROTO_A:
        case SSL3_ST_SR_NEXT_PROTO_B:
            /*
             * Enable CCS for NPN. Receiving a CCS clears the flag, so make
             * sure not to re-enable it to ban duplicates. This *should* be the
             * first time we have received one - but we check anyway to be
             * cautious.
             * s->s3->change_cipher_spec is set when a CCS is
             * processed in s3_pkt.c, and remains set until
             * the client's Finished message is read.
             */
            if (!s->s3->change_cipher_spec)
                s->s3->flags |= SSL3_FLAGS_CCS_OK;

            ret = ssl3_get_next_proto(s);
            if (ret <= 0)
                goto end;
            s->init_num = 0;
            s->state = SSL3_ST_SR_FINISHED_A;
            break;
#endif

        case SSL3_ST_SR_FINISHED_A:
        case SSL3_ST_SR_FINISHED_B:
            /*
             * Enable CCS for handshakes without NPN. In NPN the CCS flag has
             * already been set. Receiving a CCS clears the flag, so make
             * sure not to re-enable it to ban duplicates.
             * s->s3->change_cipher_spec is set when a CCS is
             * processed in s3_pkt.c, and remains set until
             * the client's Finished message is read.
             */
            if (!s->s3->change_cipher_spec)
                s->s3->flags |= SSL3_FLAGS_CCS_OK;
            ret = ssl3_get_finished(s, SSL3_ST_SR_FINISHED_A,
                                    SSL3_ST_SR_FINISHED_B);
            if (ret <= 0)
                goto end;
            if (s->hit)
                s->state = SSL_ST_OK;
#ifndef OPENSSL_NO_TLSEXT
            else if (s->tlsext_ticket_expected)
                s->state = SSL3_ST_SW_SESSION_TICKET_A;
#endif
            else
                s->state = SSL3_ST_SW_CHANGE_A;
            s->init_num = 0;
            break;

#ifndef OPENSSL_NO_TLSEXT
        case SSL3_ST_SW_SESSION_TICKET_A:
        case SSL3_ST_SW_SESSION_TICKET_B:
            ret = ssl3_send_newsession_ticket(s);
            if (ret <= 0)
                goto end;
            s->state = SSL3_ST_SW_CHANGE_A;
            s->init_num = 0;
            break;

        case SSL3_ST_SW_CERT_STATUS_A:
        case SSL3_ST_SW_CERT_STATUS_B:
            ret = ssl3_send_cert_status(s);
            if (ret <= 0)
                goto end;
            s->state = SSL3_ST_SW_KEY_EXCH_A;
            s->init_num = 0;
            break;

#endif

        case SSL3_ST_SW_CHANGE_A:
        case SSL3_ST_SW_CHANGE_B:

            s->session->cipher = s->s3->tmp.new_cipher;
            if (!s->method->ssl3_enc->setup_key_block(s)) {
                ret = -1;
                s->state = SSL_ST_ERR;
                goto end;
            }

            ret = ssl3_send_change_cipher_spec(s,
                                               SSL3_ST_SW_CHANGE_A,
                                               SSL3_ST_SW_CHANGE_B);

            if (ret <= 0)
                goto end;
            s->state = SSL3_ST_SW_FINISHED_A;
            s->init_num = 0;

            if (!s->method->ssl3_enc->change_cipher_state(s,
                                                          SSL3_CHANGE_CIPHER_SERVER_WRITE))
            {
                ret = -1;
                s->state = SSL_ST_ERR;
                goto end;
            }

            break;

        case SSL3_ST_SW_FINISHED_A:
        case SSL3_ST_SW_FINISHED_B:
            ret = ssl3_send_finished(s,
                                     SSL3_ST_SW_FINISHED_A,
                                     SSL3_ST_SW_FINISHED_B,
                                     s->method->
                                     ssl3_enc->server_finished_label,
                                     s->method->
                                     ssl3_enc->server_finished_label_len);
            if (ret <= 0)
                goto end;
            s->state = SSL3_ST_SW_FLUSH;
            if (s->hit) {
#if defined(OPENSSL_NO_TLSEXT) || defined(OPENSSL_NO_NEXTPROTONEG)
                s->s3->tmp.next_state = SSL3_ST_SR_FINISHED_A;
#else
                if (s->s3->next_proto_neg_seen) {
                    s->s3->tmp.next_state = SSL3_ST_SR_NEXT_PROTO_A;
                } else
                    s->s3->tmp.next_state = SSL3_ST_SR_FINISHED_A;
#endif
            } else
                s->s3->tmp.next_state = SSL_ST_OK;
            s->init_num = 0;
            break;

        case SSL_ST_OK:
            /* clean a few things up */
            ssl3_cleanup_key_block(s);

            BUF_MEM_free(s->init_buf);
            s->init_buf = NULL;

            /* remove buffering on output */
            ssl_free_wbio_buffer(s);

            s->init_num = 0;

            if (s->renegotiate == 2) { /* skipped if we just sent a
                                        * HelloRequest */
                s->renegotiate = 0;
                s->new_session = 0;

                ssl_update_cache(s, SSL_SESS_CACHE_SERVER);

                s->ctx->stats.sess_accept_good++;
                /* s->server=1; */
                s->handshake_func = ssl3_accept;

                if (cb != NULL)
                    cb(s, SSL_CB_HANDSHAKE_DONE, 1);
            }

            ret = 1;
            goto end;
            /* break; */

        case SSL_ST_ERR:
        default:
            SSLerr(SSL_F_SSL3_ACCEPT, SSL_R_UNKNOWN_STATE);
            ret = -1;
            goto end;
            /* break; */
        }

        if (!s->s3->tmp.reuse_message && !skip) {
            if (s->debug) {
                if ((ret = BIO_flush(s->wbio)) <= 0)
                    goto end;
            }

            if ((cb != NULL) && (s->state != state)) {
                new_state = s->state;
                s->state = state;
                cb(s, SSL_CB_ACCEPT_LOOP, 1);
                s->state = new_state;
            }
        }
        skip = 0;
    }
 end:
    /* BIO_flush(s->wbio); */

    s->in_handshake--;
    if (cb != NULL)
        cb(s, SSL_CB_ACCEPT_EXIT, ret);
    return (ret);
}

int ssl3_send_hello_request(SSL *s)
{

    if (s->state == SSL3_ST_SW_HELLO_REQ_A) {
        ssl_set_handshake_header(s, SSL3_MT_HELLO_REQUEST, 0);
        s->state = SSL3_ST_SW_HELLO_REQ_B;
    }

    /* SSL3_ST_SW_HELLO_REQ_B */
    return ssl_do_write(s);
}

int ssl3_get_client_hello(SSL *s)
{
    int i, j, ok, al = SSL_AD_INTERNAL_ERROR, ret = -1, cookie_valid = 0;
    unsigned int cookie_len;
    long n;
    unsigned long id;
    unsigned char *p, *d;
    SSL_CIPHER *c;
#ifndef OPENSSL_NO_COMP
    unsigned char *q;
    SSL_COMP *comp = NULL;
#endif
    STACK_OF(SSL_CIPHER) *ciphers = NULL;

    if (s->state == SSL3_ST_SR_CLNT_HELLO_C && !s->first_packet)
        goto retry_cert;

    /*
     * We do this so that we will respond with our native type. If we are
     * TLSv1 and we get SSLv3, we will respond with TLSv1, This down
     * switching should be handled by a different method. If we are SSLv3, we
     * will respond with SSLv3, even if prompted with TLSv1.
     */
    if (s->state == SSL3_ST_SR_CLNT_HELLO_A) {
        s->state = SSL3_ST_SR_CLNT_HELLO_B;
    }
    s->first_packet = 1;
    n = s->method->ssl_get_message(s,
                                   SSL3_ST_SR_CLNT_HELLO_B,
                                   SSL3_ST_SR_CLNT_HELLO_C,
                                   SSL3_MT_CLIENT_HELLO,
                                   SSL3_RT_MAX_PLAIN_LENGTH, &ok);

    if (!ok)
        return ((int)n);
    s->first_packet = 0;
    d = p = (unsigned char *)s->init_msg;

    /*
     * 2 bytes for client version, SSL3_RANDOM_SIZE bytes for random, 1 byte
     * for session id length
     */
    if (n < 2 + SSL3_RANDOM_SIZE + 1) {
        al = SSL_AD_DECODE_ERROR;
        SSLerr(SSL_F_SSL3_GET_CLIENT_HELLO, SSL_R_LENGTH_TOO_SHORT);
        goto f_err;
    }

    /*
     * use version from inside client hello, not from record header (may
     * differ: see RFC 2246, Appendix E, second paragraph)
     */
    s->client_version = (((int)p[0]) << 8) | (int)p[1];
    p += 2;

    if (SSL_IS_DTLS(s) ? (s->client_version > s->version &&
                          s->method->version != DTLS_ANY_VERSION)
        : (s->client_version < s->version)) {
        SSLerr(SSL_F_SSL3_GET_CLIENT_HELLO, SSL_R_WRONG_VERSION_NUMBER);
        if ((s->client_version >> 8) == SSL3_VERSION_MAJOR &&
            !s->enc_write_ctx && !s->write_hash) {
            /*
             * similar to ssl3_get_record, send alert using remote version
             * number
             */
            s->version = s->client_version;
        }
        al = SSL_AD_PROTOCOL_VERSION;
        goto f_err;
    }

    /*
     * If we require cookies and this ClientHello doesn't contain one, just
     * return since we do not want to allocate any memory yet. So check
     * cookie length...
     */
    if (SSL_get_options(s) & SSL_OP_COOKIE_EXCHANGE) {
        unsigned int session_length, cookie_length;

        session_length = *(p + SSL3_RANDOM_SIZE);

        if (SSL3_RANDOM_SIZE + session_length + 1
                >= (unsigned int)((d + n) - p)) {
            al = SSL_AD_DECODE_ERROR;
            SSLerr(SSL_F_SSL3_GET_CLIENT_HELLO, SSL_R_LENGTH_TOO_SHORT);
            goto f_err;
        }
        cookie_length = *(p + SSL3_RANDOM_SIZE + session_length + 1);

        if (cookie_length == 0)
            return 1;
    }

    /* load the client random */
    memcpy(s->s3->client_random, p, SSL3_RANDOM_SIZE);
    p += SSL3_RANDOM_SIZE;

    /* get the session-id */
    j = *(p++);

    if ((d + n) - p < j) {
        al = SSL_AD_DECODE_ERROR;
        SSLerr(SSL_F_SSL3_GET_CLIENT_HELLO, SSL_R_LENGTH_TOO_SHORT);
        goto f_err;
    }

    if ((j < 0) || (j > SSL_MAX_SSL_SESSION_ID_LENGTH)) {
        al = SSL_AD_DECODE_ERROR;
        SSLerr(SSL_F_SSL3_GET_CLIENT_HELLO, SSL_R_LENGTH_MISMATCH);
        goto f_err;
    }

    s->hit = 0;
    /*
     * Versions before 0.9.7 always allow clients to resume sessions in
     * renegotiation. 0.9.7 and later allow this by default, but optionally
     * ignore resumption requests with flag
     * SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION (it's a new flag rather
     * than a change to default behavior so that applications relying on this
     * for security won't even compile against older library versions).
     * 1.0.1 and later also have a function SSL_renegotiate_abbreviated() to
     * request renegotiation but not a new session (s->new_session remains
     * unset): for servers, this essentially just means that the
     * SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION setting will be ignored.
     */
    if ((s->new_session
         && (s->options & SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION))) {
        if (!ssl_get_new_session(s, 1))
            goto err;
    } else {
        i = ssl_get_prev_session(s, p, j, d + n);
        /*
         * Only resume if the session's version matches the negotiated
         * version.
         * RFC 5246 does not provide much useful advice on resumption
         * with a different protocol version. It doesn't forbid it but
         * the sanity of such behaviour would be questionable.
         * In practice, clients do not accept a version mismatch and
         * will abort the handshake with an error.
         */
        if (i == 1 && s->version == s->session->ssl_version) { /* previous
                                                                * session */
            s->hit = 1;
        } else if (i == -1)
            goto err;
        else {                  /* i == 0 */

            if (!ssl_get_new_session(s, 1))
                goto err;
        }
    }

    p += j;

    if (SSL_IS_DTLS(s)) {
        /* cookie stuff */
        if ((d + n) - p < 1) {
            al = SSL_AD_DECODE_ERROR;
            SSLerr(SSL_F_SSL3_GET_CLIENT_HELLO, SSL_R_LENGTH_TOO_SHORT);
            goto f_err;
        }
        cookie_len = *(p++);

        if ((unsigned int)((d + n ) - p) < cookie_len) {
            al = SSL_AD_DECODE_ERROR;
            SSLerr(SSL_F_SSL3_GET_CLIENT_HELLO, SSL_R_LENGTH_TOO_SHORT);
            goto f_err;
        }

        /*
         * The ClientHello may contain a cookie even if the
         * HelloVerify message has not been sent--make sure that it
         * does not cause an overflow.
         */
        if (cookie_len > sizeof(s->d1->rcvd_cookie)) {
            /* too much data */
            al = SSL_AD_DECODE_ERROR;
            SSLerr(SSL_F_SSL3_GET_CLIENT_HELLO, SSL_R_COOKIE_MISMATCH);
            goto f_err;
        }

        /* verify the cookie if appropriate option is set. */
        if ((SSL_get_options(s) & SSL_OP_COOKIE_EXCHANGE) && cookie_len > 0) {
            memcpy(s->d1->rcvd_cookie, p, cookie_len);

            if (s->ctx->app_verify_cookie_cb != NULL) {
                if (s->ctx->app_verify_cookie_cb(s, s->d1->rcvd_cookie,
                                                 cookie_len) == 0) {
                    al = SSL_AD_HANDSHAKE_FAILURE;
                    SSLerr(SSL_F_SSL3_GET_CLIENT_HELLO,
                           SSL_R_COOKIE_MISMATCH);
                    goto f_err;
                }
                /* else cookie verification succeeded */
            }
            /* default verification */
            else if (memcmp(s->d1->rcvd_cookie, s->d1->cookie,
                            s->d1->cookie_len) != 0) {
                al = SSL_AD_HANDSHAKE_FAILURE;
                SSLerr(SSL_F_SSL3_GET_CLIENT_HELLO, SSL_R_COOKIE_MISMATCH);
                goto f_err;
            }
            cookie_valid = 1;
        }

        p += cookie_len;
        if (s->method->version == DTLS_ANY_VERSION) {
            /* Select version to use */
            if (s->client_version <= DTLS1_2_VERSION &&
                !(s->options & SSL_OP_NO_DTLSv1_2)) {
                s->version = DTLS1_2_VERSION;
                s->method = DTLSv1_2_server_method();
            } else if (tls1_suiteb(s)) {
                SSLerr(SSL_F_SSL3_GET_CLIENT_HELLO,
                       SSL_R_ONLY_DTLS_1_2_ALLOWED_IN_SUITEB_MODE);
                s->version = s->client_version;
                al = SSL_AD_PROTOCOL_VERSION;
                goto f_err;
            } else if (s->client_version <= DTLS1_VERSION &&
                       !(s->options & SSL_OP_NO_DTLSv1)) {
                s->version = DTLS1_VERSION;
                s->method = DTLSv1_server_method();
            } else {
                SSLerr(SSL_F_SSL3_GET_CLIENT_HELLO,
                       SSL_R_WRONG_VERSION_NUMBER);
                s->version = s->client_version;
                al = SSL_AD_PROTOCOL_VERSION;
                goto f_err;
            }
            s->session->ssl_version = s->version;
        }
    }

    if ((d + n ) - p < 2) {
        al = SSL_AD_DECODE_ERROR;
        SSLerr(SSL_F_SSL3_GET_CLIENT_HELLO, SSL_R_LENGTH_TOO_SHORT);
        goto f_err;
    }
    n2s(p, i);

    if (i == 0) {
        al = SSL_AD_ILLEGAL_PARAMETER;
        SSLerr(SSL_F_SSL3_GET_CLIENT_HELLO, SSL_R_NO_CIPHERS_SPECIFIED);
        goto f_err;
    }

    /* i bytes of cipher data + 1 byte for compression length later */
    if ((d + n) - p < i + 1) {
        /* not enough data */
        al = SSL_AD_DECODE_ERROR;
        SSLerr(SSL_F_SSL3_GET_CLIENT_HELLO, SSL_R_LENGTH_MISMATCH);
        goto f_err;
    }
    if (ssl_bytes_to_cipher_list(s, p, i, &(ciphers)) == NULL) {
        goto err;
    }
    p += i;

    /* If it is a hit, check that the cipher is in the list */
    if (s->hit) {
        j = 0;
        id = s->session->cipher->id;

#ifdef CIPHER_DEBUG
        fprintf(stderr, "client sent %d ciphers\n",
                sk_SSL_CIPHER_num(ciphers));
#endif
        for (i = 0; i < sk_SSL_CIPHER_num(ciphers); i++) {
            c = sk_SSL_CIPHER_value(ciphers, i);
#ifdef CIPHER_DEBUG
            fprintf(stderr, "client [%2d of %2d]:%s\n",
                    i, sk_SSL_CIPHER_num(ciphers), SSL_CIPHER_get_name(c));
#endif
            if (c->id == id) {
                j = 1;
                break;
            }
        }
        /*
         * Disabled because it can be used in a ciphersuite downgrade attack:
         * CVE-2010-4180.
         */
#if 0
        if (j == 0 && (s->options & SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG)
            && (sk_SSL_CIPHER_num(ciphers) == 1)) {
            /*
             * Special case as client bug workaround: the previously used
             * cipher may not be in the current list, the client instead
             * might be trying to continue using a cipher that before wasn't
             * chosen due to server preferences.  We'll have to reject the
             * connection if the cipher is not enabled, though.
             */
            c = sk_SSL_CIPHER_value(ciphers, 0);
            if (sk_SSL_CIPHER_find(SSL_get_ciphers(s), c) >= 0) {
                s->session->cipher = c;
                j = 1;
            }
        }
#endif
        if (j == 0) {
            /*
             * we need to have the cipher in the cipher list if we are asked
             * to reuse it
             */
            al = SSL_AD_ILLEGAL_PARAMETER;
            SSLerr(SSL_F_SSL3_GET_CLIENT_HELLO,
                   SSL_R_REQUIRED_CIPHER_MISSING);
            goto f_err;
        }
    }

    /* compression */
    i = *(p++);
    if ((d + n) - p < i) {
        /* not enough data */
        al = SSL_AD_DECODE_ERROR;
        SSLerr(SSL_F_SSL3_GET_CLIENT_HELLO, SSL_R_LENGTH_MISMATCH);
        goto f_err;
    }
#ifndef OPENSSL_NO_COMP
    q = p;
#endif
    for (j = 0; j < i; j++) {
        if (p[j] == 0)
            break;
    }

    p += i;
    if (j >= i) {
        /* no compress */
        al = SSL_AD_DECODE_ERROR;
        SSLerr(SSL_F_SSL3_GET_CLIENT_HELLO, SSL_R_NO_COMPRESSION_SPECIFIED);
        goto f_err;
    }
#ifndef OPENSSL_NO_TLSEXT
    /* TLS extensions */
    if (s->version >= SSL3_VERSION) {
        if (!ssl_parse_clienthello_tlsext(s, &p, d + n)) {
            SSLerr(SSL_F_SSL3_GET_CLIENT_HELLO, SSL_R_PARSE_TLSEXT);
            goto err;
        }
    }

    /*
     * Check if we want to use external pre-shared secret for this handshake
     * for not reused session only. We need to generate server_random before
     * calling tls_session_secret_cb in order to allow SessionTicket
     * processing to use it in key derivation.
     */
    {
        unsigned char *pos;
        pos = s->s3->server_random;
        if (ssl_fill_hello_random(s, 1, pos, SSL3_RANDOM_SIZE) <= 0) {
            goto f_err;
        }
    }

    if (!s->hit && s->version >= TLS1_VERSION && s->tls_session_secret_cb) {
        SSL_CIPHER *pref_cipher = NULL;

        s->session->master_key_length = sizeof(s->session->master_key);
        if (s->tls_session_secret_cb(s, s->session->master_key,
                                     &s->session->master_key_length, ciphers,
                                     &pref_cipher,
                                     s->tls_session_secret_cb_arg)) {
            s->hit = 1;
            s->session->ciphers = ciphers;
            s->session->verify_result = X509_V_OK;

            ciphers = NULL;

            /* check if some cipher was preferred by call back */
            pref_cipher =
                pref_cipher ? pref_cipher : ssl3_choose_cipher(s,
                                                               s->
                                                               session->ciphers,
                                                               SSL_get_ciphers
                                                               (s));
            if (pref_cipher == NULL) {
                al = SSL_AD_HANDSHAKE_FAILURE;
                SSLerr(SSL_F_SSL3_GET_CLIENT_HELLO, SSL_R_NO_SHARED_CIPHER);
                goto f_err;
            }

            s->session->cipher = pref_cipher;

            if (s->cipher_list)
                sk_SSL_CIPHER_free(s->cipher_list);

            if (s->cipher_list_by_id)
                sk_SSL_CIPHER_free(s->cipher_list_by_id);

            s->cipher_list = sk_SSL_CIPHER_dup(s->session->ciphers);
            s->cipher_list_by_id = sk_SSL_CIPHER_dup(s->session->ciphers);
        }
    }
#endif

    /*
     * Worst case, we will use the NULL compression, but if we have other
     * options, we will now look for them.  We have i-1 compression
     * algorithms from the client, starting at q.
     */
    s->s3->tmp.new_compression = NULL;
#ifndef OPENSSL_NO_COMP
    /* This only happens if we have a cache hit */
    if (s->session->compress_meth != 0) {
        int m, comp_id = s->session->compress_meth;
        /* Perform sanity checks on resumed compression algorithm */
        /* Can't disable compression */
        if (s->options & SSL_OP_NO_COMPRESSION) {
            SSLerr(SSL_F_SSL3_GET_CLIENT_HELLO,
                   SSL_R_INCONSISTENT_COMPRESSION);
            goto f_err;
        }
        /* Look for resumed compression method */
        for (m = 0; m < sk_SSL_COMP_num(s->ctx->comp_methods); m++) {
            comp = sk_SSL_COMP_value(s->ctx->comp_methods, m);
            if (comp_id == comp->id) {
                s->s3->tmp.new_compression = comp;
                break;
            }
        }
        if (s->s3->tmp.new_compression == NULL) {
            SSLerr(SSL_F_SSL3_GET_CLIENT_HELLO,
                   SSL_R_INVALID_COMPRESSION_ALGORITHM);
            goto f_err;
        }
        /* Look for resumed method in compression list */
        for (m = 0; m < i; m++) {
            if (q[m] == comp_id)
                break;
        }
        if (m >= i) {
            al = SSL_AD_ILLEGAL_PARAMETER;
            SSLerr(SSL_F_SSL3_GET_CLIENT_HELLO,
                   SSL_R_REQUIRED_COMPRESSSION_ALGORITHM_MISSING);
            goto f_err;
        }
    } else if (s->hit)
        comp = NULL;
    else if (!(s->options & SSL_OP_NO_COMPRESSION) && s->ctx->comp_methods) {
        /* See if we have a match */
        int m, nn, o, v, done = 0;

        nn = sk_SSL_COMP_num(s->ctx->comp_methods);
        for (m = 0; m < nn; m++) {
            comp = sk_SSL_COMP_value(s->ctx->comp_methods, m);
            v = comp->id;
            for (o = 0; o < i; o++) {
                if (v == q[o]) {
                    done = 1;
                    break;
                }
            }
            if (done)
                break;
        }
        if (done)
            s->s3->tmp.new_compression = comp;
        else
            comp = NULL;
    }
#else
    /*
     * If compression is disabled we'd better not try to resume a session
     * using compression.
     */
    if (s->session->compress_meth != 0) {
        SSLerr(SSL_F_SSL3_GET_CLIENT_HELLO, SSL_R_INCONSISTENT_COMPRESSION);
        goto f_err;
    }
#endif

    /*
     * Given s->session->ciphers and SSL_get_ciphers, we must pick a cipher
     */

    if (!s->hit) {
#ifdef OPENSSL_NO_COMP
        s->session->compress_meth = 0;
#else
        s->session->compress_meth = (comp == NULL) ? 0 : comp->id;
#endif
        if (s->session->ciphers != NULL)
            sk_SSL_CIPHER_free(s->session->ciphers);
        s->session->ciphers = ciphers;
        if (ciphers == NULL) {
            al = SSL_AD_INTERNAL_ERROR;
            SSLerr(SSL_F_SSL3_GET_CLIENT_HELLO, ERR_R_INTERNAL_ERROR);
            goto f_err;
        }
        ciphers = NULL;
        if (!tls1_set_server_sigalgs(s)) {
            SSLerr(SSL_F_SSL3_GET_CLIENT_HELLO, SSL_R_CLIENTHELLO_TLSEXT);
            goto err;
        }
        /* Let cert callback update server certificates if required */
 retry_cert:
        if (s->cert->cert_cb) {
            int rv = s->cert->cert_cb(s, s->cert->cert_cb_arg);
            if (rv == 0) {
                al = SSL_AD_INTERNAL_ERROR;
                SSLerr(SSL_F_SSL3_GET_CLIENT_HELLO, SSL_R_CERT_CB_ERROR);
                goto f_err;
            }
            if (rv < 0) {
                s->rwstate = SSL_X509_LOOKUP;
                return -1;
            }
            s->rwstate = SSL_NOTHING;
        }
        c = ssl3_choose_cipher(s, s->session->ciphers, SSL_get_ciphers(s));

        if (c == NULL) {
            al = SSL_AD_HANDSHAKE_FAILURE;
            SSLerr(SSL_F_SSL3_GET_CLIENT_HELLO, SSL_R_NO_SHARED_CIPHER);
            goto f_err;
        }
        s->s3->tmp.new_cipher = c;
    } else {
        /* Session-id reuse */
#ifdef REUSE_CIPHER_BUG
        STACK_OF(SSL_CIPHER) *sk;
        SSL_CIPHER *nc = NULL;
        SSL_CIPHER *ec = NULL;

        if (s->options & SSL_OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG) {
            sk = s->session->ciphers;
            for (i = 0; i < sk_SSL_CIPHER_num(sk); i++) {
                c = sk_SSL_CIPHER_value(sk, i);
                if (c->algorithm_enc & SSL_eNULL)
                    nc = c;
                if (SSL_C_IS_EXPORT(c))
                    ec = c;
            }
            if (nc != NULL)
                s->s3->tmp.new_cipher = nc;
            else if (ec != NULL)
                s->s3->tmp.new_cipher = ec;
            else
                s->s3->tmp.new_cipher = s->session->cipher;
        } else
#endif
            s->s3->tmp.new_cipher = s->session->cipher;
    }

    if (!SSL_USE_SIGALGS(s) || !(s->verify_mode & SSL_VERIFY_PEER)) {
        if (!ssl3_digest_cached_records(s))
            goto f_err;
    }

    /*-
    * we now have the following setup.
     * client_random
     * cipher_list          - our prefered list of ciphers
     * ciphers              - the clients prefered list of ciphers
     * compression          - basically ignored right now
     * ssl version is set   - sslv3
     * s->session           - The ssl session has been setup.
     * s->hit               - session reuse flag
     * s->tmp.new_cipher    - the new cipher to use.
     */

    /* Handles TLS extensions that we couldn't check earlier */
    if (s->version >= SSL3_VERSION) {
        if (!ssl_check_clienthello_tlsext_late(s, &al)) {
            SSLerr(SSL_F_SSL3_GET_CLIENT_HELLO, SSL_R_CLIENTHELLO_TLSEXT);
            goto f_err;
        }
    }

    ret = cookie_valid ? 2 : 1;
    if (0) {
 f_err:
        ssl3_send_alert(s, SSL3_AL_FATAL, al);
 err:
        s->state = SSL_ST_ERR;
    }

    if (ciphers != NULL)
        sk_SSL_CIPHER_free(ciphers);
    return ret;
}

int ssl3_send_server_hello(SSL *s)
{
    unsigned char *buf;
    unsigned char *p, *d;
    int i, sl;
    int al = 0;
    unsigned long l;

    if (s->state == SSL3_ST_SW_SRVR_HELLO_A) {
        buf = (unsigned char *)s->init_buf->data;
#ifdef OPENSSL_NO_TLSEXT
        p = s->s3->server_random;
        if (ssl_fill_hello_random(s, 1, p, SSL3_RANDOM_SIZE) <= 0) {
            s->state = SSL_ST_ERR;
            return -1;
        }
#endif
        /* Do the message type and length last */
        d = p = ssl_handshake_start(s);

        *(p++) = s->version >> 8;
        *(p++) = s->version & 0xff;

        /* Random stuff */
        memcpy(p, s->s3->server_random, SSL3_RANDOM_SIZE);
        p += SSL3_RANDOM_SIZE;

        /*-
         * There are several cases for the session ID to send
         * back in the server hello:
         * - For session reuse from the session cache,
         *   we send back the old session ID.
         * - If stateless session reuse (using a session ticket)
         *   is successful, we send back the client's "session ID"
         *   (which doesn't actually identify the session).
         * - If it is a new session, we send back the new
         *   session ID.
         * - However, if we want the new session to be single-use,
         *   we send back a 0-length session ID.
         * s->hit is non-zero in either case of session reuse,
         * so the following won't overwrite an ID that we're supposed
         * to send back.
         */
        if (!(s->ctx->session_cache_mode & SSL_SESS_CACHE_SERVER)
            && !s->hit)
            s->session->session_id_length = 0;

        sl = s->session->session_id_length;
        if (sl > (int)sizeof(s->session->session_id)) {
            SSLerr(SSL_F_SSL3_SEND_SERVER_HELLO, ERR_R_INTERNAL_ERROR);
            s->state = SSL_ST_ERR;
            return -1;
        }
        *(p++) = sl;
        memcpy(p, s->session->session_id, sl);
        p += sl;

        /* put the cipher */
        i = ssl3_put_cipher_by_char(s->s3->tmp.new_cipher, p);
        p += i;

        /* put the compression method */
#ifdef OPENSSL_NO_COMP
        *(p++) = 0;
#else
        if (s->s3->tmp.new_compression == NULL)
            *(p++) = 0;
        else
            *(p++) = s->s3->tmp.new_compression->id;
#endif
#ifndef OPENSSL_NO_TLSEXT
        if (ssl_prepare_serverhello_tlsext(s) <= 0) {
            SSLerr(SSL_F_SSL3_SEND_SERVER_HELLO, SSL_R_SERVERHELLO_TLSEXT);
            s->state = SSL_ST_ERR;
            return -1;
        }
        if ((p =
             ssl_add_serverhello_tlsext(s, p, buf + SSL3_RT_MAX_PLAIN_LENGTH,
                                        &al)) == NULL) {
            ssl3_send_alert(s, SSL3_AL_FATAL, al);
            SSLerr(SSL_F_SSL3_SEND_SERVER_HELLO, ERR_R_INTERNAL_ERROR);
            s->state = SSL_ST_ERR;
            return -1;
        }
#endif
        /* do the header */
        l = (p - d);
        ssl_set_handshake_header(s, SSL3_MT_SERVER_HELLO, l);
        s->state = SSL3_ST_SW_SRVR_HELLO_B;
    }

    /* SSL3_ST_SW_SRVR_HELLO_B */
    return ssl_do_write(s);
}

int ssl3_send_server_done(SSL *s)
{

    if (s->state == SSL3_ST_SW_SRVR_DONE_A) {
        ssl_set_handshake_header(s, SSL3_MT_SERVER_DONE, 0);
        s->state = SSL3_ST_SW_SRVR_DONE_B;
    }

    /* SSL3_ST_SW_SRVR_DONE_B */
    return ssl_do_write(s);
}

int ssl3_send_server_key_exchange(SSL *s)
{
#ifndef OPENSSL_NO_RSA
    unsigned char *q;
    int j, num;
    RSA *rsa;
    unsigned char md_buf[MD5_DIGEST_LENGTH + SHA_DIGEST_LENGTH];
    unsigned int u;
#endif
#ifndef OPENSSL_NO_DH
# ifdef OPENSSL_NO_RSA
    int j;
# endif
    DH *dh = NULL, *dhp;
#endif
#ifndef OPENSSL_NO_ECDH
    EC_KEY *ecdh = NULL, *ecdhp;
    unsigned char *encodedPoint = NULL;
    int encodedlen = 0;
    int curve_id = 0;
    BN_CTX *bn_ctx = NULL;
#endif
    EVP_PKEY *pkey;
    const EVP_MD *md = NULL;
    unsigned char *p, *d;
    int al, i;
    unsigned long type;
    int n;
    CERT *cert;
    BIGNUM *r[4];
    int nr[4], kn;
    BUF_MEM *buf;
    EVP_MD_CTX md_ctx;

    EVP_MD_CTX_init(&md_ctx);
    if (s->state == SSL3_ST_SW_KEY_EXCH_A) {
        type = s->s3->tmp.new_cipher->algorithm_mkey;
        cert = s->cert;

        buf = s->init_buf;

        r[0] = r[1] = r[2] = r[3] = NULL;
        n = 0;
#ifndef OPENSSL_NO_RSA
        if (type & SSL_kRSA) {
            rsa = cert->rsa_tmp;
            if ((rsa == NULL) && (s->cert->rsa_tmp_cb != NULL)) {
                rsa = s->cert->rsa_tmp_cb(s,
                                          SSL_C_IS_EXPORT(s->s3->
                                                          tmp.new_cipher),
                                          SSL_C_EXPORT_PKEYLENGTH(s->s3->
                                                                  tmp.new_cipher));
                if (rsa == NULL) {
                    al = SSL_AD_HANDSHAKE_FAILURE;
                    SSLerr(SSL_F_SSL3_SEND_SERVER_KEY_EXCHANGE,
                           SSL_R_ERROR_GENERATING_TMP_RSA_KEY);
                    goto f_err;
                }
                RSA_up_ref(rsa);
                cert->rsa_tmp = rsa;
            }
            if (rsa == NULL) {
                al = SSL_AD_HANDSHAKE_FAILURE;
                SSLerr(SSL_F_SSL3_SEND_SERVER_KEY_EXCHANGE,
                       SSL_R_MISSING_TMP_RSA_KEY);
                goto f_err;
            }
            r[0] = rsa->n;
            r[1] = rsa->e;
            s->s3->tmp.use_rsa_tmp = 1;
        } else
#endif
#ifndef OPENSSL_NO_DH
        if (type & SSL_kEDH) {
            dhp = cert->dh_tmp;
            if ((dhp == NULL) && (s->cert->dh_tmp_cb != NULL))
                dhp = s->cert->dh_tmp_cb(s,
                                         SSL_C_IS_EXPORT(s->s3->
                                                         tmp.new_cipher),
                                         SSL_C_EXPORT_PKEYLENGTH(s->s3->
                                                                 tmp.new_cipher));
            if (dhp == NULL) {
                al = SSL_AD_HANDSHAKE_FAILURE;
                SSLerr(SSL_F_SSL3_SEND_SERVER_KEY_EXCHANGE,
                       SSL_R_MISSING_TMP_DH_KEY);
                goto f_err;
            }

            if (s->s3->tmp.dh != NULL) {
                SSLerr(SSL_F_SSL3_SEND_SERVER_KEY_EXCHANGE,
                       ERR_R_INTERNAL_ERROR);
                goto err;
            }

            if ((dh = DHparams_dup(dhp)) == NULL) {
                SSLerr(SSL_F_SSL3_SEND_SERVER_KEY_EXCHANGE, ERR_R_DH_LIB);
                goto err;
            }

            s->s3->tmp.dh = dh;
            if (!DH_generate_key(dh)) {
                SSLerr(SSL_F_SSL3_SEND_SERVER_KEY_EXCHANGE, ERR_R_DH_LIB);
                goto err;
            }
            r[0] = dh->p;
            r[1] = dh->g;
            r[2] = dh->pub_key;
        } else
#endif
#ifndef OPENSSL_NO_ECDH
        if (type & SSL_kEECDH) {
            const EC_GROUP *group;

            if (s->s3->tmp.ecdh != NULL) {
                SSLerr(SSL_F_SSL3_SEND_SERVER_KEY_EXCHANGE,
                       ERR_R_INTERNAL_ERROR);
                goto err;
            }

            ecdhp = cert->ecdh_tmp;
            if (s->cert->ecdh_tmp_auto) {
                /* Get NID of appropriate shared curve */
                int nid = tls1_shared_curve(s, -2);
                if (nid != NID_undef)
                    ecdhp = EC_KEY_new_by_curve_name(nid);
            } else if ((ecdhp == NULL) && s->cert->ecdh_tmp_cb) {
                ecdhp = s->cert->ecdh_tmp_cb(s,
                                             SSL_C_IS_EXPORT(s->s3->
                                                             tmp.new_cipher),
                                             SSL_C_EXPORT_PKEYLENGTH(s->
                                                                     s3->tmp.new_cipher));
            }
            if (ecdhp == NULL) {
                al = SSL_AD_HANDSHAKE_FAILURE;
                SSLerr(SSL_F_SSL3_SEND_SERVER_KEY_EXCHANGE,
                       SSL_R_MISSING_TMP_ECDH_KEY);
                goto f_err;
            }

            /* Duplicate the ECDH structure. */
            if (s->cert->ecdh_tmp_auto)
                ecdh = ecdhp;
            else if ((ecdh = EC_KEY_dup(ecdhp)) == NULL) {
                SSLerr(SSL_F_SSL3_SEND_SERVER_KEY_EXCHANGE, ERR_R_ECDH_LIB);
                goto err;
            }

            s->s3->tmp.ecdh = ecdh;
            if ((EC_KEY_get0_public_key(ecdh) == NULL) ||
                (EC_KEY_get0_private_key(ecdh) == NULL) ||
                (s->options & SSL_OP_SINGLE_ECDH_USE)) {
                if (!EC_KEY_generate_key(ecdh)) {
                    SSLerr(SSL_F_SSL3_SEND_SERVER_KEY_EXCHANGE,
                           ERR_R_ECDH_LIB);
                    goto err;
                }
            }

            if (((group = EC_KEY_get0_group(ecdh)) == NULL) ||
                (EC_KEY_get0_public_key(ecdh) == NULL) ||
                (EC_KEY_get0_private_key(ecdh) == NULL)) {
                SSLerr(SSL_F_SSL3_SEND_SERVER_KEY_EXCHANGE, ERR_R_ECDH_LIB);
                goto err;
            }

            if (SSL_C_IS_EXPORT(s->s3->tmp.new_cipher) &&
                (EC_GROUP_get_degree(group) > 163)) {
                SSLerr(SSL_F_SSL3_SEND_SERVER_KEY_EXCHANGE,
                       SSL_R_ECGROUP_TOO_LARGE_FOR_CIPHER);
                goto err;
            }

            /*
             * XXX: For now, we only support ephemeral ECDH keys over named
             * (not generic) curves. For supported named curves, curve_id is
             * non-zero.
             */
            if ((curve_id =
                 tls1_ec_nid2curve_id(EC_GROUP_get_curve_name(group)))
                == 0) {
                SSLerr(SSL_F_SSL3_SEND_SERVER_KEY_EXCHANGE,
                       SSL_R_UNSUPPORTED_ELLIPTIC_CURVE);
                goto err;
            }

            /*
             * Encode the public key. First check the size of encoding and
             * allocate memory accordingly.
             */
            encodedlen = EC_POINT_point2oct(group,
                                            EC_KEY_get0_public_key(ecdh),
                                            POINT_CONVERSION_UNCOMPRESSED,
                                            NULL, 0, NULL);

            encodedPoint = (unsigned char *)
                OPENSSL_malloc(encodedlen * sizeof(unsigned char));
            bn_ctx = BN_CTX_new();
            if ((encodedPoint == NULL) || (bn_ctx == NULL)) {
                SSLerr(SSL_F_SSL3_SEND_SERVER_KEY_EXCHANGE,
                       ERR_R_MALLOC_FAILURE);
                goto err;
            }

            encodedlen = EC_POINT_point2oct(group,
                                            EC_KEY_get0_public_key(ecdh),
                                            POINT_CONVERSION_UNCOMPRESSED,
                                            encodedPoint, encodedlen, bn_ctx);

            if (encodedlen == 0) {
                SSLerr(SSL_F_SSL3_SEND_SERVER_KEY_EXCHANGE, ERR_R_ECDH_LIB);
                goto err;
            }

            BN_CTX_free(bn_ctx);
            bn_ctx = NULL;

            /*
             * XXX: For now, we only support named (not generic) curves in
             * ECDH ephemeral key exchanges. In this situation, we need four
             * additional bytes to encode the entire ServerECDHParams
             * structure.
             */
            n = 4 + encodedlen;

            /*
             * We'll generate the serverKeyExchange message explicitly so we
             * can set these to NULLs
             */
            r[0] = NULL;
            r[1] = NULL;
            r[2] = NULL;
            r[3] = NULL;
        } else
#endif                          /* !OPENSSL_NO_ECDH */
#ifndef OPENSSL_NO_PSK
        if (type & SSL_kPSK) {
            /*
             * reserve size for record length and PSK identity hint
             */
            n += 2 + strlen(s->ctx->psk_identity_hint);
        } else
#endif                          /* !OPENSSL_NO_PSK */
#ifndef OPENSSL_NO_SRP
        if (type & SSL_kSRP) {
            if ((s->srp_ctx.N == NULL) ||
                (s->srp_ctx.g == NULL) ||
                (s->srp_ctx.s == NULL) || (s->srp_ctx.B == NULL)) {
                SSLerr(SSL_F_SSL3_SEND_SERVER_KEY_EXCHANGE,
                       SSL_R_MISSING_SRP_PARAM);
                goto err;
            }
            r[0] = s->srp_ctx.N;
            r[1] = s->srp_ctx.g;
            r[2] = s->srp_ctx.s;
            r[3] = s->srp_ctx.B;
        } else
#endif
        {
            al = SSL_AD_HANDSHAKE_FAILURE;
            SSLerr(SSL_F_SSL3_SEND_SERVER_KEY_EXCHANGE,
                   SSL_R_UNKNOWN_KEY_EXCHANGE_TYPE);
            goto f_err;
        }
        for (i = 0; i < 4 && r[i] != NULL; i++) {
            nr[i] = BN_num_bytes(r[i]);
#ifndef OPENSSL_NO_SRP
            if ((i == 2) && (type & SSL_kSRP))
                n += 1 + nr[i];
            else
#endif
#ifndef OPENSSL_NO_DH
            /*
             * for interoperability with some versions of the Microsoft TLS
             * stack, we need to zero pad the DHE pub key to the same length
             * as the prime, so use the length of the prime here
             */
            if ((i == 2) && (type & (SSL_kEDH)))
                n += 2 + nr[0];
            else
#endif
                n += 2 + nr[i];
        }

        if (!(s->s3->tmp.new_cipher->algorithm_auth & (SSL_aNULL | SSL_aSRP))
            && !(s->s3->tmp.new_cipher->algorithm_mkey & SSL_kPSK)) {
            if ((pkey = ssl_get_sign_pkey(s, s->s3->tmp.new_cipher, &md))
                == NULL) {
                al = SSL_AD_DECODE_ERROR;
                goto f_err;
            }
            kn = EVP_PKEY_size(pkey);
            /* Allow space for signature algorithm */
            if (SSL_USE_SIGALGS(s))
                kn += 2;
            /* Allow space for signature length */
            kn += 2;
        } else {
            pkey = NULL;
            kn = 0;
        }

        if (!BUF_MEM_grow_clean(buf, n + SSL_HM_HEADER_LENGTH(s) + kn)) {
            SSLerr(SSL_F_SSL3_SEND_SERVER_KEY_EXCHANGE, ERR_LIB_BUF);
            goto err;
        }
        d = p = ssl_handshake_start(s);

        for (i = 0; i < 4 && r[i] != NULL; i++) {
#ifndef OPENSSL_NO_SRP
            if ((i == 2) && (type & SSL_kSRP)) {
                *p = nr[i];
                p++;
            } else
#endif
#ifndef OPENSSL_NO_DH
            /*
             * for interoperability with some versions of the Microsoft TLS
             * stack, we need to zero pad the DHE pub key to the same length
             * as the prime
             */
            if ((i == 2) && (type & (SSL_kEDH))) {
                s2n(nr[0], p);
                for (j = 0; j < (nr[0] - nr[2]); ++j) {
                    *p = 0;
                    ++p;
                }
            } else
#endif
                s2n(nr[i], p);
            BN_bn2bin(r[i], p);
            p += nr[i];
        }

#ifndef OPENSSL_NO_ECDH
        if (type & SSL_kEECDH) {
            /*
             * XXX: For now, we only support named (not generic) curves. In
             * this situation, the serverKeyExchange message has: [1 byte
             * CurveType], [2 byte CurveName] [1 byte length of encoded
             * point], followed by the actual encoded point itself
             */
            *p = NAMED_CURVE_TYPE;
            p += 1;
            *p = 0;
            p += 1;
            *p = curve_id;
            p += 1;
            *p = encodedlen;
            p += 1;
            memcpy((unsigned char *)p,
                   (unsigned char *)encodedPoint, encodedlen);
            OPENSSL_free(encodedPoint);
            encodedPoint = NULL;
            p += encodedlen;
        }
#endif

#ifndef OPENSSL_NO_PSK
        if (type & SSL_kPSK) {
            size_t len = strlen(s->ctx->psk_identity_hint);

            /* copy PSK identity hint */
            s2n(len, p);
            memcpy(p, s->ctx->psk_identity_hint, len);
            p += len;
        }
#endif

        /* not anonymous */
        if (pkey != NULL) {
            /*
             * n is the length of the params, they start at &(d[4]) and p
             * points to the space at the end.
             */
#ifndef OPENSSL_NO_RSA
            if (pkey->type == EVP_PKEY_RSA && !SSL_USE_SIGALGS(s)) {
                q = md_buf;
                j = 0;
                for (num = 2; num > 0; num--) {
                    EVP_MD_CTX_set_flags(&md_ctx,
                                         EVP_MD_CTX_FLAG_NON_FIPS_ALLOW);
                    if (EVP_DigestInit_ex(&md_ctx,
                                          (num == 2) ? s->ctx->md5
                                                     : s->ctx->sha1,
                                          NULL) <= 0
                        || EVP_DigestUpdate(&md_ctx, &(s->s3->client_random[0]),
                                            SSL3_RANDOM_SIZE) <= 0
                        || EVP_DigestUpdate(&md_ctx, &(s->s3->server_random[0]),
                                            SSL3_RANDOM_SIZE) <= 0
                        || EVP_DigestUpdate(&md_ctx, d, n) <= 0
                        || EVP_DigestFinal_ex(&md_ctx, q,
                                              (unsigned int *)&i) <= 0) {
                        SSLerr(SSL_F_SSL3_SEND_SERVER_KEY_EXCHANGE,
                               ERR_LIB_EVP);
                        al = SSL_AD_INTERNAL_ERROR;
                        goto f_err;
                    }
                    q += i;
                    j += i;
                }
                if (RSA_sign(NID_md5_sha1, md_buf, j,
                             &(p[2]), &u, pkey->pkey.rsa) <= 0) {
                    SSLerr(SSL_F_SSL3_SEND_SERVER_KEY_EXCHANGE, ERR_LIB_RSA);
                    goto err;
                }
                s2n(u, p);
                n += u + 2;
            } else
#endif
            if (md) {
                /* send signature algorithm */
                if (SSL_USE_SIGALGS(s)) {
                    if (!tls12_get_sigandhash(p, pkey, md)) {
                        /* Should never happen */
                        al = SSL_AD_INTERNAL_ERROR;
                        SSLerr(SSL_F_SSL3_SEND_SERVER_KEY_EXCHANGE,
                               ERR_R_INTERNAL_ERROR);
                        goto f_err;
                    }
                    p += 2;
                }
#ifdef SSL_DEBUG
                fprintf(stderr, "Using hash %s\n", EVP_MD_name(md));
#endif
                if (EVP_SignInit_ex(&md_ctx, md, NULL) <= 0
                        || EVP_SignUpdate(&md_ctx, &(s->s3->client_random[0]),
                                          SSL3_RANDOM_SIZE) <= 0
                        || EVP_SignUpdate(&md_ctx, &(s->s3->server_random[0]),
                                          SSL3_RANDOM_SIZE) <= 0
                        || EVP_SignUpdate(&md_ctx, d, n) <= 0
                        || EVP_SignFinal(&md_ctx, &(p[2]),
                                         (unsigned int *)&i, pkey) <= 0) {
                    SSLerr(SSL_F_SSL3_SEND_SERVER_KEY_EXCHANGE, ERR_LIB_EVP);
                    al = SSL_AD_INTERNAL_ERROR;
                    goto f_err;
                }
                s2n(i, p);
                n += i + 2;
                if (SSL_USE_SIGALGS(s))
                    n += 2;
            } else {
                /* Is this error check actually needed? */
                al = SSL_AD_HANDSHAKE_FAILURE;
                SSLerr(SSL_F_SSL3_SEND_SERVER_KEY_EXCHANGE,
                       SSL_R_UNKNOWN_PKEY_TYPE);
                goto f_err;
            }
        }

        ssl_set_handshake_header(s, SSL3_MT_SERVER_KEY_EXCHANGE, n);
    }

    s->state = SSL3_ST_SW_KEY_EXCH_B;
    EVP_MD_CTX_cleanup(&md_ctx);
    return ssl_do_write(s);
 f_err:
    ssl3_send_alert(s, SSL3_AL_FATAL, al);
 err:
#ifndef OPENSSL_NO_ECDH
    if (encodedPoint != NULL)
        OPENSSL_free(encodedPoint);
    BN_CTX_free(bn_ctx);
#endif
    EVP_MD_CTX_cleanup(&md_ctx);
    s->state = SSL_ST_ERR;
    return (-1);
}

int ssl3_send_certificate_request(SSL *s)
{
    unsigned char *p, *d;
    int i, j, nl, off, n;
    STACK_OF(X509_NAME) *sk = NULL;
    X509_NAME *name;
    BUF_MEM *buf;

    if (s->state == SSL3_ST_SW_CERT_REQ_A) {
        buf = s->init_buf;

        d = p = ssl_handshake_start(s);

        /* get the list of acceptable cert types */
        p++;
        n = ssl3_get_req_cert_type(s, p);
        d[0] = n;
        p += n;
        n++;

        if (SSL_USE_SIGALGS(s)) {
            const unsigned char *psigs;
            nl = tls12_get_psigalgs(s, 1, &psigs);
            if (nl > SSL_MAX_2_BYTE_LEN) {
                SSLerr(SSL_F_SSL3_SEND_CERTIFICATE_REQUEST,
                       SSL_R_LENGTH_TOO_LONG);
                goto err;
            }
            s2n(nl, p);
            memcpy(p, psigs, nl);
            p += nl;
            n += nl + 2;
        }

        off = n;
        p += 2;
        n += 2;

        sk = SSL_get_client_CA_list(s);
        nl = 0;
        if (sk != NULL) {
            for (i = 0; i < sk_X509_NAME_num(sk); i++) {
                name = sk_X509_NAME_value(sk, i);
                j = i2d_X509_NAME(name, NULL);
                if (j > SSL_MAX_2_BYTE_LEN) {
                    SSLerr(SSL_F_SSL3_SEND_CERTIFICATE_REQUEST,
                           SSL_R_LENGTH_TOO_LONG);
                    goto err;
                }
                if (!BUF_MEM_grow_clean
                    (buf, SSL_HM_HEADER_LENGTH(s) + n + j + 2)) {
                    SSLerr(SSL_F_SSL3_SEND_CERTIFICATE_REQUEST,
                           ERR_R_BUF_LIB);
                    goto err;
                }
                p = ssl_handshake_start(s) + n;
                if (!(s->options & SSL_OP_NETSCAPE_CA_DN_BUG)) {
                    s2n(j, p);
                    i2d_X509_NAME(name, &p);
                    n += 2 + j;
                    nl += 2 + j;
                } else {
                    d = p;
                    i2d_X509_NAME(name, &p);
                    j -= 2;
                    s2n(j, d);
                    j += 2;
                    n += j;
                    nl += j;
                }
                if (nl > SSL_MAX_2_BYTE_LEN) {
                    SSLerr(SSL_F_SSL3_SEND_CERTIFICATE_REQUEST,
                           SSL_R_LENGTH_TOO_LONG);
                    goto err;
                }
            }
        }
        /* else no CA names */
        p = ssl_handshake_start(s) + off;
        s2n(nl, p);

        ssl_set_handshake_header(s, SSL3_MT_CERTIFICATE_REQUEST, n);

#ifdef NETSCAPE_HANG_BUG
        if (!SSL_IS_DTLS(s)) {
            if (!BUF_MEM_grow_clean(buf, s->init_num + 4)) {
                SSLerr(SSL_F_SSL3_SEND_CERTIFICATE_REQUEST, ERR_R_BUF_LIB);
                goto err;
            }
            p = (unsigned char *)s->init_buf->data + s->init_num;
            /* do the header */
            *(p++) = SSL3_MT_SERVER_DONE;
            *(p++) = 0;
            *(p++) = 0;
            *(p++) = 0;
            s->init_num += 4;
        }
#endif

        s->state = SSL3_ST_SW_CERT_REQ_B;
    }

    /* SSL3_ST_SW_CERT_REQ_B */
    return ssl_do_write(s);
 err:
    s->state = SSL_ST_ERR;
    return (-1);
}

int ssl3_get_client_key_exchange(SSL *s)
{
    int i, al, ok;
    long n;
    unsigned long alg_k;
    unsigned char *p;
#ifndef OPENSSL_NO_RSA
    RSA *rsa = NULL;
    EVP_PKEY *pkey = NULL;
#endif
#ifndef OPENSSL_NO_DH
    BIGNUM *pub = NULL;
    DH *dh_srvr, *dh_clnt = NULL;
#endif
#ifndef OPENSSL_NO_KRB5
    KSSL_ERR kssl_err;
#endif                          /* OPENSSL_NO_KRB5 */

#ifndef OPENSSL_NO_ECDH
    EC_KEY *srvr_ecdh = NULL;
    EVP_PKEY *clnt_pub_pkey = NULL;
    EC_POINT *clnt_ecpoint = NULL;
    BN_CTX *bn_ctx = NULL;
#endif

    n = s->method->ssl_get_message(s,
                                   SSL3_ST_SR_KEY_EXCH_A,
                                   SSL3_ST_SR_KEY_EXCH_B,
                                   SSL3_MT_CLIENT_KEY_EXCHANGE, 2048, &ok);

    if (!ok)
        return ((int)n);
    p = (unsigned char *)s->init_msg;

    alg_k = s->s3->tmp.new_cipher->algorithm_mkey;

#ifndef OPENSSL_NO_RSA
    if (alg_k & SSL_kRSA) {
        unsigned char rand_premaster_secret[SSL_MAX_MASTER_KEY_LENGTH];
        int decrypt_len;
        unsigned char decrypt_good, version_good;
        size_t j, padding_len;

        /* FIX THIS UP EAY EAY EAY EAY */
        if (s->s3->tmp.use_rsa_tmp) {
            if ((s->cert != NULL) && (s->cert->rsa_tmp != NULL))
                rsa = s->cert->rsa_tmp;
            /*
             * Don't do a callback because rsa_tmp should be sent already
             */
            if (rsa == NULL) {
                al = SSL_AD_HANDSHAKE_FAILURE;
                SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE,
                       SSL_R_MISSING_TMP_RSA_PKEY);
                goto f_err;

            }
        } else {
            pkey = s->cert->pkeys[SSL_PKEY_RSA_ENC].privatekey;
            if ((pkey == NULL) ||
                (pkey->type != EVP_PKEY_RSA) || (pkey->pkey.rsa == NULL)) {
                al = SSL_AD_HANDSHAKE_FAILURE;
                SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE,
                       SSL_R_MISSING_RSA_CERTIFICATE);
                goto f_err;
            }
            rsa = pkey->pkey.rsa;
        }

        /* TLS and [incidentally] DTLS{0xFEFF} */
        if (s->version > SSL3_VERSION && s->version != DTLS1_BAD_VER) {
            n2s(p, i);
            if (n != i + 2) {
                if (!(s->options & SSL_OP_TLS_D5_BUG)) {
                    al = SSL_AD_DECODE_ERROR;
                    SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE,
                           SSL_R_TLS_RSA_ENCRYPTED_VALUE_LENGTH_IS_WRONG);
                    goto f_err;
                } else
                    p -= 2;
            } else
                n = i;
        }

        /*
         * Reject overly short RSA ciphertext because we want to be sure
         * that the buffer size makes it safe to iterate over the entire
         * size of a premaster secret (SSL_MAX_MASTER_KEY_LENGTH). The
         * actual expected size is larger due to RSA padding, but the
         * bound is sufficient to be safe.
         */
        if (n < SSL_MAX_MASTER_KEY_LENGTH) {
            al = SSL_AD_DECRYPT_ERROR;
            SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE,
                   SSL_R_TLS_RSA_ENCRYPTED_VALUE_LENGTH_IS_WRONG);
            goto f_err;
        }

        /*
         * We must not leak whether a decryption failure occurs because of
         * Bleichenbacher's attack on PKCS #1 v1.5 RSA padding (see RFC 2246,
         * section 7.4.7.1). The code follows that advice of the TLS RFC and
         * generates a random premaster secret for the case that the decrypt
         * fails. See https://tools.ietf.org/html/rfc5246#section-7.4.7.1
         */

        if (RAND_bytes(rand_premaster_secret,
                       sizeof(rand_premaster_secret)) <= 0)
            goto err;

        /*
         * Decrypt with no padding. PKCS#1 padding will be removed as part of
         * the timing-sensitive code below.
         */
        decrypt_len =
            RSA_private_decrypt((int)n, p, p, rsa, RSA_NO_PADDING);
        if (decrypt_len < 0)
            goto err;

        /* Check the padding. See RFC 3447, section 7.2.2. */

        /*
         * The smallest padded premaster is 11 bytes of overhead. Small keys
         * are publicly invalid, so this may return immediately. This ensures
         * PS is at least 8 bytes.
         */
        if (decrypt_len < 11 + SSL_MAX_MASTER_KEY_LENGTH) {
            al = SSL_AD_DECRYPT_ERROR;
            SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE,
                   SSL_R_DECRYPTION_FAILED);
            goto f_err;
        }

        padding_len = decrypt_len - SSL_MAX_MASTER_KEY_LENGTH;
        decrypt_good = constant_time_eq_int_8(p[0], 0) &
                       constant_time_eq_int_8(p[1], 2);
        for (j = 2; j < padding_len - 1; j++) {
            decrypt_good &= ~constant_time_is_zero_8(p[j]);
        }
        decrypt_good &= constant_time_is_zero_8(p[padding_len - 1]);
        p += padding_len;

        /*
         * If the version in the decrypted pre-master secret is correct then
         * version_good will be 0xff, otherwise it'll be zero. The
         * Klima-Pokorny-Rosa extension of Bleichenbacher's attack
         * (http://eprint.iacr.org/2003/052/) exploits the version number
         * check as a "bad version oracle". Thus version checks are done in
         * constant time and are treated like any other decryption error.
         */
        version_good =
            constant_time_eq_8(p[0], (unsigned)(s->client_version >> 8));
        version_good &=
            constant_time_eq_8(p[1], (unsigned)(s->client_version & 0xff));

        /*
         * The premaster secret must contain the same version number as the
         * ClientHello to detect version rollback attacks (strangely, the
         * protocol does not offer such protection for DH ciphersuites).
         * However, buggy clients exist that send the negotiated protocol
         * version instead if the server does not support the requested
         * protocol version. If SSL_OP_TLS_ROLLBACK_BUG is set, tolerate such
         * clients.
         */
        if (s->options & SSL_OP_TLS_ROLLBACK_BUG) {
            unsigned char workaround_good;
            workaround_good =
                constant_time_eq_8(p[0], (unsigned)(s->version >> 8));
            workaround_good &=
                constant_time_eq_8(p[1], (unsigned)(s->version & 0xff));
            version_good |= workaround_good;
        }

        /*
         * Both decryption and version must be good for decrypt_good to
         * remain non-zero (0xff).
         */
        decrypt_good &= version_good;

        /*
         * Now copy rand_premaster_secret over from p using
         * decrypt_good_mask. If decryption failed, then p does not
         * contain valid plaintext, however, a check above guarantees
         * it is still sufficiently large to read from.
         */
        for (j = 0; j < sizeof(rand_premaster_secret); j++) {
            p[j] = constant_time_select_8(decrypt_good, p[j],
                                          rand_premaster_secret[j]);
        }

        s->session->master_key_length =
            s->method->ssl3_enc->generate_master_secret(s,
                                                        s->
                                                        session->master_key,
                                                        p,
                                                        sizeof
                                                        (rand_premaster_secret));
        OPENSSL_cleanse(p, sizeof(rand_premaster_secret));
    } else
#endif
#ifndef OPENSSL_NO_DH
    if (alg_k & (SSL_kEDH | SSL_kDHr | SSL_kDHd)) {
        int idx = -1;
        EVP_PKEY *skey = NULL;
        if (n > 1) {
            n2s(p, i);
        } else {
            if (alg_k & SSL_kDHE) {
                al = SSL_AD_HANDSHAKE_FAILURE;
                SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE,
                       SSL_R_DH_PUBLIC_VALUE_LENGTH_IS_WRONG);
                goto f_err;
            }
            i = 0;
        }
        if (n && n != i + 2) {
            if (!(s->options & SSL_OP_SSLEAY_080_CLIENT_DH_BUG)) {
                SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE,
                       SSL_R_DH_PUBLIC_VALUE_LENGTH_IS_WRONG);
                al = SSL_AD_HANDSHAKE_FAILURE;
                goto f_err;
            } else {
                p -= 2;
                i = (int)n;
            }
        }
        if (alg_k & SSL_kDHr)
            idx = SSL_PKEY_DH_RSA;
        else if (alg_k & SSL_kDHd)
            idx = SSL_PKEY_DH_DSA;
        if (idx >= 0) {
            skey = s->cert->pkeys[idx].privatekey;
            if ((skey == NULL) ||
                (skey->type != EVP_PKEY_DH) || (skey->pkey.dh == NULL)) {
                al = SSL_AD_HANDSHAKE_FAILURE;
                SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE,
                       SSL_R_MISSING_RSA_CERTIFICATE);
                goto f_err;
            }
            dh_srvr = skey->pkey.dh;
        } else if (s->s3->tmp.dh == NULL) {
            al = SSL_AD_HANDSHAKE_FAILURE;
            SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE,
                   SSL_R_MISSING_TMP_DH_KEY);
            goto f_err;
        } else
            dh_srvr = s->s3->tmp.dh;

        if (n == 0L) {
            /* Get pubkey from cert */
            EVP_PKEY *clkey = X509_get_pubkey(s->session->peer);
            if (clkey) {
                if (EVP_PKEY_cmp_parameters(clkey, skey) == 1)
                    dh_clnt = EVP_PKEY_get1_DH(clkey);
            }
            if (dh_clnt == NULL) {
                al = SSL_AD_HANDSHAKE_FAILURE;
                SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE,
                       SSL_R_MISSING_TMP_DH_KEY);
                goto f_err;
            }
            EVP_PKEY_free(clkey);
            pub = dh_clnt->pub_key;
        } else
            pub = BN_bin2bn(p, i, NULL);
        if (pub == NULL) {
            SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE, SSL_R_BN_LIB);
            goto err;
        }

        i = DH_compute_key(p, pub, dh_srvr);

        if (i <= 0) {
            al = SSL_AD_HANDSHAKE_FAILURE;
            SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE, ERR_R_DH_LIB);
            BN_clear_free(pub);
            goto f_err;
        }

        DH_free(s->s3->tmp.dh);
        s->s3->tmp.dh = NULL;
        if (dh_clnt)
            DH_free(dh_clnt);
        else
            BN_clear_free(pub);
        pub = NULL;
        s->session->master_key_length =
            s->method->ssl3_enc->generate_master_secret(s,
                                                        s->
                                                        session->master_key,
                                                        p, i);
        OPENSSL_cleanse(p, i);
        if (dh_clnt)
            return 2;
    } else
#endif
#ifndef OPENSSL_NO_KRB5
    if (alg_k & SSL_kKRB5) {
        krb5_error_code krb5rc;
        krb5_data enc_ticket;
        krb5_data authenticator;
        krb5_data enc_pms;
        KSSL_CTX *kssl_ctx = s->kssl_ctx;
        EVP_CIPHER_CTX ciph_ctx;
        const EVP_CIPHER *enc = NULL;
        unsigned char iv[EVP_MAX_IV_LENGTH];
        unsigned char pms[SSL_MAX_MASTER_KEY_LENGTH + EVP_MAX_BLOCK_LENGTH];
        int padl, outl;
        krb5_timestamp authtime = 0;
        krb5_ticket_times ttimes;
        int kerr = 0;

        EVP_CIPHER_CTX_init(&ciph_ctx);

        if (!kssl_ctx)
            kssl_ctx = kssl_ctx_new();

        n2s(p, i);
        enc_ticket.length = i;

        if (n < (long)(enc_ticket.length + 6)) {
            SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE,
                   SSL_R_DATA_LENGTH_TOO_LONG);
            goto err;
        }

        enc_ticket.data = (char *)p;
        p += enc_ticket.length;

        n2s(p, i);
        authenticator.length = i;

        if (n < (long)(enc_ticket.length + authenticator.length + 6)) {
            SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE,
                   SSL_R_DATA_LENGTH_TOO_LONG);
            goto err;
        }

        authenticator.data = (char *)p;
        p += authenticator.length;

        n2s(p, i);
        enc_pms.length = i;
        enc_pms.data = (char *)p;
        p += enc_pms.length;

        /*
         * Note that the length is checked again below, ** after decryption
         */
        if (enc_pms.length > sizeof(pms)) {
            SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE,
                   SSL_R_DATA_LENGTH_TOO_LONG);
            goto err;
        }

        if (n != (long)(enc_ticket.length + authenticator.length +
                        enc_pms.length + 6)) {
            SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE,
                   SSL_R_DATA_LENGTH_TOO_LONG);
            goto err;
        }

        if ((krb5rc = kssl_sget_tkt(kssl_ctx, &enc_ticket, &ttimes,
                                    &kssl_err)) != 0) {
# ifdef KSSL_DEBUG
            fprintf(stderr, "kssl_sget_tkt rtn %d [%d]\n",
                    krb5rc, kssl_err.reason);
            if (kssl_err.text)
                fprintf(stderr, "kssl_err text= %s\n", kssl_err.text);
# endif                         /* KSSL_DEBUG */
            SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE, kssl_err.reason);
            goto err;
        }

        /*
         * Note: no authenticator is not considered an error, ** but will
         * return authtime == 0.
         */
        if ((krb5rc = kssl_check_authent(kssl_ctx, &authenticator,
                                         &authtime, &kssl_err)) != 0) {
# ifdef KSSL_DEBUG
            fprintf(stderr, "kssl_check_authent rtn %d [%d]\n",
                    krb5rc, kssl_err.reason);
            if (kssl_err.text)
                fprintf(stderr, "kssl_err text= %s\n", kssl_err.text);
# endif                         /* KSSL_DEBUG */
            SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE, kssl_err.reason);
            goto err;
        }

        if ((krb5rc = kssl_validate_times(authtime, &ttimes)) != 0) {
            SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE, krb5rc);
            goto err;
        }
# ifdef KSSL_DEBUG
        kssl_ctx_show(kssl_ctx);
# endif                         /* KSSL_DEBUG */

        enc = kssl_map_enc(kssl_ctx->enctype);
        if (enc == NULL)
            goto err;

        memset(iv, 0, sizeof(iv)); /* per RFC 1510 */

        if (!EVP_DecryptInit_ex(&ciph_ctx, enc, NULL, kssl_ctx->key, iv)) {
            SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE,
                   SSL_R_DECRYPTION_FAILED);
            goto err;
        }
        if (!EVP_DecryptUpdate(&ciph_ctx, pms, &outl,
                               (unsigned char *)enc_pms.data, enc_pms.length))
        {
            SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE,
                   SSL_R_DECRYPTION_FAILED);
            kerr = 1;
            goto kclean;
        }
        if (outl > SSL_MAX_MASTER_KEY_LENGTH) {
            SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE,
                   SSL_R_DATA_LENGTH_TOO_LONG);
            kerr = 1;
            goto kclean;
        }
        if (!EVP_DecryptFinal_ex(&ciph_ctx, &(pms[outl]), &padl)) {
            SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE,
                   SSL_R_DECRYPTION_FAILED);
            kerr = 1;
            goto kclean;
        }
        outl += padl;
        if (outl > SSL_MAX_MASTER_KEY_LENGTH) {
            SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE,
                   SSL_R_DATA_LENGTH_TOO_LONG);
            kerr = 1;
            goto kclean;
        }
        if (!((pms[0] == (s->client_version >> 8))
              && (pms[1] == (s->client_version & 0xff)))) {
            /*
             * The premaster secret must contain the same version number as
             * the ClientHello to detect version rollback attacks (strangely,
             * the protocol does not offer such protection for DH
             * ciphersuites). However, buggy clients exist that send random
             * bytes instead of the protocol version. If
             * SSL_OP_TLS_ROLLBACK_BUG is set, tolerate such clients.
             * (Perhaps we should have a separate BUG value for the Kerberos
             * cipher)
             */
            if (!(s->options & SSL_OP_TLS_ROLLBACK_BUG)) {
                SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE,
                       SSL_AD_DECODE_ERROR);
                kerr = 1;
                goto kclean;
            }
        }

        EVP_CIPHER_CTX_cleanup(&ciph_ctx);

        s->session->master_key_length =
            s->method->ssl3_enc->generate_master_secret(s,
                                                        s->
                                                        session->master_key,
                                                        pms, outl);

        if (kssl_ctx->client_princ) {
            size_t len = strlen(kssl_ctx->client_princ);
            if (len < SSL_MAX_KRB5_PRINCIPAL_LENGTH) {
                s->session->krb5_client_princ_len = len;
                memcpy(s->session->krb5_client_princ, kssl_ctx->client_princ,
                       len);
            }
        }

        /*- Was doing kssl_ctx_free() here,
         *  but it caused problems for apache.
         *  kssl_ctx = kssl_ctx_free(kssl_ctx);
         *  if (s->kssl_ctx)  s->kssl_ctx = NULL;
         */

 kclean:
        OPENSSL_cleanse(pms, sizeof(pms));
        if (kerr)
            goto err;
    } else
#endif                          /* OPENSSL_NO_KRB5 */

#ifndef OPENSSL_NO_ECDH
    if (alg_k & (SSL_kEECDH | SSL_kECDHr | SSL_kECDHe)) {
        int ret = 1;
        int field_size = 0;
        const EC_KEY *tkey;
        const EC_GROUP *group;
        const BIGNUM *priv_key;

        /* initialize structures for server's ECDH key pair */
        if ((srvr_ecdh = EC_KEY_new()) == NULL) {
            SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE, ERR_R_MALLOC_FAILURE);
            goto err;
        }

        /* Let's get server private key and group information */
        if (alg_k & (SSL_kECDHr | SSL_kECDHe)) {
            /* use the certificate */
            tkey = s->cert->pkeys[SSL_PKEY_ECC].privatekey->pkey.ec;
        } else {
            /*
             * use the ephermeral values we saved when generating the
             * ServerKeyExchange msg.
             */
            tkey = s->s3->tmp.ecdh;
        }

        group = EC_KEY_get0_group(tkey);
        priv_key = EC_KEY_get0_private_key(tkey);

        if (!EC_KEY_set_group(srvr_ecdh, group) ||
            !EC_KEY_set_private_key(srvr_ecdh, priv_key)) {
            SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE, ERR_R_EC_LIB);
            goto err;
        }

        /* Let's get client's public key */
        if ((clnt_ecpoint = EC_POINT_new(group)) == NULL) {
            SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE, ERR_R_MALLOC_FAILURE);
            goto err;
        }

        if (n == 0L) {
            /* Client Publickey was in Client Certificate */

            if (alg_k & SSL_kEECDH) {
                al = SSL_AD_HANDSHAKE_FAILURE;
                SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE,
                       SSL_R_MISSING_TMP_ECDH_KEY);
                goto f_err;
            }
            if (((clnt_pub_pkey = X509_get_pubkey(s->session->peer))
                 == NULL) || (clnt_pub_pkey->type != EVP_PKEY_EC)) {
                /*
                 * XXX: For now, we do not support client authentication
                 * using ECDH certificates so this branch (n == 0L) of the
                 * code is never executed. When that support is added, we
                 * ought to ensure the key received in the certificate is
                 * authorized for key agreement. ECDH_compute_key implicitly
                 * checks that the two ECDH shares are for the same group.
                 */
                al = SSL_AD_HANDSHAKE_FAILURE;
                SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE,
                       SSL_R_UNABLE_TO_DECODE_ECDH_CERTS);
                goto f_err;
            }

            if (EC_POINT_copy(clnt_ecpoint,
                              EC_KEY_get0_public_key(clnt_pub_pkey->
                                                     pkey.ec)) == 0) {
                SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE, ERR_R_EC_LIB);
                goto err;
            }
            ret = 2;            /* Skip certificate verify processing */
        } else {
            /*
             * Get client's public key from encoded point in the
             * ClientKeyExchange message.
             */
            if ((bn_ctx = BN_CTX_new()) == NULL) {
                SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE,
                       ERR_R_MALLOC_FAILURE);
                goto err;
            }

            /* Get encoded point length */
            i = *p;
            p += 1;
            if (n != 1 + i) {
                SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE, SSL_R_LENGTH_MISMATCH);
                al = SSL_AD_DECODE_ERROR;
                goto f_err;
            }
            if (EC_POINT_oct2point(group, clnt_ecpoint, p, i, bn_ctx) == 0) {
                SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE, ERR_R_EC_LIB);
                al = SSL_AD_HANDSHAKE_FAILURE;
                goto f_err;
            }
            /*
             * p is pointing to somewhere in the buffer currently, so set it
             * to the start
             */
            p = (unsigned char *)s->init_buf->data;
        }

        /* Compute the shared pre-master secret */
        field_size = EC_GROUP_get_degree(group);
        if (field_size <= 0) {
            SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE, ERR_R_ECDH_LIB);
            goto err;
        }
        i = ECDH_compute_key(p, (field_size + 7) / 8, clnt_ecpoint, srvr_ecdh,
                             NULL);
        if (i <= 0) {
            SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE, ERR_R_ECDH_LIB);
            goto err;
        }

        EVP_PKEY_free(clnt_pub_pkey);
        EC_POINT_free(clnt_ecpoint);
        EC_KEY_free(srvr_ecdh);
        BN_CTX_free(bn_ctx);
        EC_KEY_free(s->s3->tmp.ecdh);
        s->s3->tmp.ecdh = NULL;

        /* Compute the master secret */
        s->session->master_key_length =
            s->method->ssl3_enc->generate_master_secret(s,
                                                        s->
                                                        session->master_key,
                                                        p, i);

        OPENSSL_cleanse(p, i);
        return (ret);
    } else
#endif
#ifndef OPENSSL_NO_PSK
    if (alg_k & SSL_kPSK) {
        unsigned char *t = NULL;
        unsigned char psk_or_pre_ms[PSK_MAX_PSK_LEN * 2 + 4];
        unsigned int pre_ms_len = 0, psk_len = 0;
        int psk_err = 1;
        char tmp_id[PSK_MAX_IDENTITY_LEN + 1];

        al = SSL_AD_HANDSHAKE_FAILURE;

        n2s(p, i);
        if (n != i + 2) {
            SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE, SSL_R_LENGTH_MISMATCH);
            goto psk_err;
        }
        if (i > PSK_MAX_IDENTITY_LEN) {
            SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE,
                   SSL_R_DATA_LENGTH_TOO_LONG);
            goto psk_err;
        }
        if (s->psk_server_callback == NULL) {
            SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE,
                   SSL_R_PSK_NO_SERVER_CB);
            goto psk_err;
        }

        /*
         * Create guaranteed NULL-terminated identity string for the callback
         */
        memcpy(tmp_id, p, i);
        memset(tmp_id + i, 0, PSK_MAX_IDENTITY_LEN + 1 - i);
        psk_len = s->psk_server_callback(s, tmp_id,
                                         psk_or_pre_ms,
                                         sizeof(psk_or_pre_ms));
        OPENSSL_cleanse(tmp_id, PSK_MAX_IDENTITY_LEN + 1);

        if (psk_len > PSK_MAX_PSK_LEN) {
            SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE, ERR_R_INTERNAL_ERROR);
            goto psk_err;
        } else if (psk_len == 0) {
            /*
             * PSK related to the given identity not found
             */
            SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE,
                   SSL_R_PSK_IDENTITY_NOT_FOUND);
            al = SSL_AD_UNKNOWN_PSK_IDENTITY;
            goto psk_err;
        }

        /* create PSK pre_master_secret */
        pre_ms_len = 2 + psk_len + 2 + psk_len;
        t = psk_or_pre_ms;
        memmove(psk_or_pre_ms + psk_len + 4, psk_or_pre_ms, psk_len);
        s2n(psk_len, t);
        memset(t, 0, psk_len);
        t += psk_len;
        s2n(psk_len, t);

        if (s->session->psk_identity != NULL)
            OPENSSL_free(s->session->psk_identity);
        s->session->psk_identity = BUF_strndup((char *)p, i);
        if (s->session->psk_identity == NULL) {
            SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE, ERR_R_MALLOC_FAILURE);
            goto psk_err;
        }

        if (s->session->psk_identity_hint != NULL)
            OPENSSL_free(s->session->psk_identity_hint);
        s->session->psk_identity_hint = BUF_strdup(s->ctx->psk_identity_hint);
        if (s->ctx->psk_identity_hint != NULL &&
            s->session->psk_identity_hint == NULL) {
            SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE, ERR_R_MALLOC_FAILURE);
            goto psk_err;
        }

        s->session->master_key_length =
            s->method->ssl3_enc->generate_master_secret(s,
                                                        s->
                                                        session->master_key,
                                                        psk_or_pre_ms,
                                                        pre_ms_len);
        psk_err = 0;
 psk_err:
        OPENSSL_cleanse(psk_or_pre_ms, sizeof(psk_or_pre_ms));
        if (psk_err != 0)
            goto f_err;
    } else
#endif
#ifndef OPENSSL_NO_SRP
    if (alg_k & SSL_kSRP) {
        int param_len;

        n2s(p, i);
        param_len = i + 2;
        if (param_len > n) {
            al = SSL_AD_DECODE_ERROR;
            SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE,
                   SSL_R_BAD_SRP_A_LENGTH);
            goto f_err;
        }
        if (!(s->srp_ctx.A = BN_bin2bn(p, i, NULL))) {
            SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE, ERR_R_BN_LIB);
            goto err;
        }
        if (BN_ucmp(s->srp_ctx.A, s->srp_ctx.N) >= 0
            || BN_is_zero(s->srp_ctx.A)) {
            al = SSL_AD_ILLEGAL_PARAMETER;
            SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE,
                   SSL_R_BAD_SRP_PARAMETERS);
            goto f_err;
        }
        if (s->session->srp_username != NULL)
            OPENSSL_free(s->session->srp_username);
        s->session->srp_username = BUF_strdup(s->srp_ctx.login);
        if (s->session->srp_username == NULL) {
            SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE, ERR_R_MALLOC_FAILURE);
            goto err;
        }

        if ((s->session->master_key_length =
             SRP_generate_server_master_secret(s,
                                               s->session->master_key)) < 0) {
            SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE, ERR_R_INTERNAL_ERROR);
            goto err;
        }

        p += i;
    } else
#endif                          /* OPENSSL_NO_SRP */
    if (alg_k & SSL_kGOST) {
        int ret = 0;
        EVP_PKEY_CTX *pkey_ctx;
        EVP_PKEY *client_pub_pkey = NULL, *pk = NULL;
        unsigned char premaster_secret[32], *start;
        size_t outlen = 32, inlen;
        unsigned long alg_a;
        int Ttag, Tclass;
        long Tlen;

        /* Get our certificate private key */
        alg_a = s->s3->tmp.new_cipher->algorithm_auth;
        if (alg_a & SSL_aGOST94)
            pk = s->cert->pkeys[SSL_PKEY_GOST94].privatekey;
        else if (alg_a & SSL_aGOST01)
            pk = s->cert->pkeys[SSL_PKEY_GOST01].privatekey;

        pkey_ctx = EVP_PKEY_CTX_new(pk, NULL);
        if (pkey_ctx == NULL) {
            al = SSL_AD_INTERNAL_ERROR;
            SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE, ERR_R_MALLOC_FAILURE);
            goto f_err;
        }
        if (EVP_PKEY_decrypt_init(pkey_ctx) <= 0) {
            SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE, ERR_R_INTERNAL_ERROR);
            goto gerr;
        }
        /*
         * If client certificate is present and is of the same type, maybe
         * use it for key exchange.  Don't mind errors from
         * EVP_PKEY_derive_set_peer, because it is completely valid to use a
         * client certificate for authorization only.
         */
        client_pub_pkey = X509_get_pubkey(s->session->peer);
        if (client_pub_pkey) {
            if (EVP_PKEY_derive_set_peer(pkey_ctx, client_pub_pkey) <= 0)
                ERR_clear_error();
        }
        /* Decrypt session key */
        if (ASN1_get_object
            ((const unsigned char **)&p, &Tlen, &Ttag, &Tclass,
             n) != V_ASN1_CONSTRUCTED || Ttag != V_ASN1_SEQUENCE
            || Tclass != V_ASN1_UNIVERSAL) {
            SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE,
                   SSL_R_DECRYPTION_FAILED);
            goto gerr;
        }
        start = p;
        inlen = Tlen;
        if (EVP_PKEY_decrypt
            (pkey_ctx, premaster_secret, &outlen, start, inlen) <= 0) {
            SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE,
                   SSL_R_DECRYPTION_FAILED);
            goto gerr;
        }
        /* Generate master secret */
        s->session->master_key_length =
            s->method->ssl3_enc->generate_master_secret(s,
                                                        s->
                                                        session->master_key,
                                                        premaster_secret, 32);
        OPENSSL_cleanse(premaster_secret, sizeof(premaster_secret));
        /* Check if pubkey from client certificate was used */
        if (EVP_PKEY_CTX_ctrl
            (pkey_ctx, -1, -1, EVP_PKEY_CTRL_PEER_KEY, 2, NULL) > 0)
            ret = 2;
        else
            ret = 1;
 gerr:
        EVP_PKEY_free(client_pub_pkey);
        EVP_PKEY_CTX_free(pkey_ctx);
        if (ret)
            return ret;
        else
            goto err;
    } else {
        al = SSL_AD_HANDSHAKE_FAILURE;
        SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE, SSL_R_UNKNOWN_CIPHER_TYPE);
        goto f_err;
    }

    return (1);
 f_err:
    ssl3_send_alert(s, SSL3_AL_FATAL, al);
#if !defined(OPENSSL_NO_DH) || !defined(OPENSSL_NO_RSA) || !defined(OPENSSL_NO_ECDH) || defined(OPENSSL_NO_SRP)
 err:
#endif
#ifndef OPENSSL_NO_ECDH
    EVP_PKEY_free(clnt_pub_pkey);
    EC_POINT_free(clnt_ecpoint);
    if (srvr_ecdh != NULL)
        EC_KEY_free(srvr_ecdh);
    BN_CTX_free(bn_ctx);
#endif
    s->state = SSL_ST_ERR;
    return (-1);
}

int ssl3_get_cert_verify(SSL *s)
{
    EVP_PKEY *pkey = NULL;
    unsigned char *p;
    int al, ok, ret = 0;
    long n;
    int type = 0, i, j;
    X509 *peer;
    const EVP_MD *md = NULL;
    EVP_MD_CTX mctx;
    EVP_MD_CTX_init(&mctx);

    /*
     * We should only process a CertificateVerify message if we have received
     * a Certificate from the client. If so then |s->session->peer| will be non
     * NULL. In some instances a CertificateVerify message is not required even
     * if the peer has sent a Certificate (e.g. such as in the case of static
     * DH). In that case the ClientKeyExchange processing will skip the
     * CertificateVerify state so we should not arrive here.
     */
    if (s->session->peer == NULL) {
        ret = 1;
        goto end;
    }

    n = s->method->ssl_get_message(s,
                                   SSL3_ST_SR_CERT_VRFY_A,
                                   SSL3_ST_SR_CERT_VRFY_B,
                                   SSL3_MT_CERTIFICATE_VERIFY,
                                   SSL3_RT_MAX_PLAIN_LENGTH, &ok);

    if (!ok)
        return ((int)n);

    peer = s->session->peer;
    pkey = X509_get_pubkey(peer);
    if (pkey == NULL) {
        al = SSL_AD_INTERNAL_ERROR;
        goto f_err;
    }

    type = X509_certificate_type(peer, pkey);

    if (!(type & EVP_PKT_SIGN)) {
        SSLerr(SSL_F_SSL3_GET_CERT_VERIFY,
               SSL_R_SIGNATURE_FOR_NON_SIGNING_CERTIFICATE);
        al = SSL_AD_ILLEGAL_PARAMETER;
        goto f_err;
    }

    /* we now have a signature that we need to verify */
    p = (unsigned char *)s->init_msg;
    /* Check for broken implementations of GOST ciphersuites */
    /*
     * If key is GOST and n is exactly 64, it is bare signature without
     * length field
     */
    if (n == 64 && (pkey->type == NID_id_GostR3410_94 ||
                    pkey->type == NID_id_GostR3410_2001)) {
        i = 64;
    } else {
        if (SSL_USE_SIGALGS(s)) {
            int rv = tls12_check_peer_sigalg(&md, s, p, pkey);
            if (rv == -1) {
                al = SSL_AD_INTERNAL_ERROR;
                goto f_err;
            } else if (rv == 0) {
                al = SSL_AD_DECODE_ERROR;
                goto f_err;
            }
#ifdef SSL_DEBUG
            fprintf(stderr, "USING TLSv1.2 HASH %s\n", EVP_MD_name(md));
#endif
            p += 2;
            n -= 2;
        }
        n2s(p, i);
        n -= 2;
        if (i > n) {
            SSLerr(SSL_F_SSL3_GET_CERT_VERIFY, SSL_R_LENGTH_MISMATCH);
            al = SSL_AD_DECODE_ERROR;
            goto f_err;
        }
    }
    j = EVP_PKEY_size(pkey);
    if ((i > j) || (n > j) || (n <= 0)) {
        SSLerr(SSL_F_SSL3_GET_CERT_VERIFY, SSL_R_WRONG_SIGNATURE_SIZE);
        al = SSL_AD_DECODE_ERROR;
        goto f_err;
    }

    if (SSL_USE_SIGALGS(s)) {
        long hdatalen = 0;
        void *hdata;
        hdatalen = BIO_get_mem_data(s->s3->handshake_buffer, &hdata);
        if (hdatalen <= 0) {
            SSLerr(SSL_F_SSL3_GET_CERT_VERIFY, ERR_R_INTERNAL_ERROR);
            al = SSL_AD_INTERNAL_ERROR;
            goto f_err;
        }
#ifdef SSL_DEBUG
        fprintf(stderr, "Using TLS 1.2 with client verify alg %s\n",
                EVP_MD_name(md));
#endif
        if (!EVP_VerifyInit_ex(&mctx, md, NULL)
            || !EVP_VerifyUpdate(&mctx, hdata, hdatalen)) {
            SSLerr(SSL_F_SSL3_GET_CERT_VERIFY, ERR_R_EVP_LIB);
            al = SSL_AD_INTERNAL_ERROR;
            goto f_err;
        }

        if (EVP_VerifyFinal(&mctx, p, i, pkey) <= 0) {
            al = SSL_AD_DECRYPT_ERROR;
            SSLerr(SSL_F_SSL3_GET_CERT_VERIFY, SSL_R_BAD_SIGNATURE);
            goto f_err;
        }
    } else
#ifndef OPENSSL_NO_RSA
    if (pkey->type == EVP_PKEY_RSA) {
        i = RSA_verify(NID_md5_sha1, s->s3->tmp.cert_verify_md,
                       MD5_DIGEST_LENGTH + SHA_DIGEST_LENGTH, p, i,
                       pkey->pkey.rsa);
        if (i < 0) {
            al = SSL_AD_DECRYPT_ERROR;
            SSLerr(SSL_F_SSL3_GET_CERT_VERIFY, SSL_R_BAD_RSA_DECRYPT);
            goto f_err;
        }
        if (i == 0) {
            al = SSL_AD_DECRYPT_ERROR;
            SSLerr(SSL_F_SSL3_GET_CERT_VERIFY, SSL_R_BAD_RSA_SIGNATURE);
            goto f_err;
        }
    } else
#endif
#ifndef OPENSSL_NO_DSA
    if (pkey->type == EVP_PKEY_DSA) {
        j = DSA_verify(pkey->save_type,
                       &(s->s3->tmp.cert_verify_md[MD5_DIGEST_LENGTH]),
                       SHA_DIGEST_LENGTH, p, i, pkey->pkey.dsa);
        if (j <= 0) {
            /* bad signature */
            al = SSL_AD_DECRYPT_ERROR;
            SSLerr(SSL_F_SSL3_GET_CERT_VERIFY, SSL_R_BAD_DSA_SIGNATURE);
            goto f_err;
        }
    } else
#endif
#ifndef OPENSSL_NO_ECDSA
    if (pkey->type == EVP_PKEY_EC) {
        j = ECDSA_verify(pkey->save_type,
                         &(s->s3->tmp.cert_verify_md[MD5_DIGEST_LENGTH]),
                         SHA_DIGEST_LENGTH, p, i, pkey->pkey.ec);
        if (j <= 0) {
            /* bad signature */
            al = SSL_AD_DECRYPT_ERROR;
            SSLerr(SSL_F_SSL3_GET_CERT_VERIFY, SSL_R_BAD_ECDSA_SIGNATURE);
            goto f_err;
        }
    } else
#endif
    if (pkey->type == NID_id_GostR3410_94
            || pkey->type == NID_id_GostR3410_2001) {
        unsigned char signature[64];
        int idx;
        EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new(pkey, NULL);
        if (pctx == NULL) {
            al = SSL_AD_INTERNAL_ERROR;
            SSLerr(SSL_F_SSL3_GET_CERT_VERIFY, ERR_R_MALLOC_FAILURE);
            goto f_err;
        }
        if (EVP_PKEY_verify_init(pctx) <= 0) {
            EVP_PKEY_CTX_free(pctx);
            al = SSL_AD_INTERNAL_ERROR;
            SSLerr(SSL_F_SSL3_GET_CERT_VERIFY, ERR_R_INTERNAL_ERROR);
            goto f_err;
        }
        if (i != 64) {
#ifdef SSL_DEBUG
            fprintf(stderr, "GOST signature length is %d", i);
#endif
        }
        for (idx = 0; idx < 64; idx++) {
            signature[63 - idx] = p[idx];
        }
        j = EVP_PKEY_verify(pctx, signature, 64, s->s3->tmp.cert_verify_md,
                            32);
        EVP_PKEY_CTX_free(pctx);
        if (j <= 0) {
            al = SSL_AD_DECRYPT_ERROR;
            SSLerr(SSL_F_SSL3_GET_CERT_VERIFY, SSL_R_BAD_ECDSA_SIGNATURE);
            goto f_err;
        }
    } else {
        SSLerr(SSL_F_SSL3_GET_CERT_VERIFY, ERR_R_INTERNAL_ERROR);
        al = SSL_AD_UNSUPPORTED_CERTIFICATE;
        goto f_err;
    }

    ret = 1;
    if (0) {
 f_err:
        ssl3_send_alert(s, SSL3_AL_FATAL, al);
        s->state = SSL_ST_ERR;
    }
 end:
    if (s->s3->handshake_buffer) {
        BIO_free(s->s3->handshake_buffer);
        s->s3->handshake_buffer = NULL;
        s->s3->flags &= ~TLS1_FLAGS_KEEP_HANDSHAKE;
    }
    EVP_MD_CTX_cleanup(&mctx);
    EVP_PKEY_free(pkey);
    return (ret);
}

int ssl3_get_client_certificate(SSL *s)
{
    int i, ok, al, ret = -1;
    X509 *x = NULL;
    unsigned long l, nc, llen, n;
    const unsigned char *p, *q;
    unsigned char *d;
    STACK_OF(X509) *sk = NULL;

    n = s->method->ssl_get_message(s,
                                   SSL3_ST_SR_CERT_A,
                                   SSL3_ST_SR_CERT_B,
                                   -1, s->max_cert_list, &ok);

    if (!ok)
        return ((int)n);

    if (s->s3->tmp.message_type == SSL3_MT_CLIENT_KEY_EXCHANGE) {
        if ((s->verify_mode & SSL_VERIFY_PEER) &&
            (s->verify_mode & SSL_VERIFY_FAIL_IF_NO_PEER_CERT)) {
            SSLerr(SSL_F_SSL3_GET_CLIENT_CERTIFICATE,
                   SSL_R_PEER_DID_NOT_RETURN_A_CERTIFICATE);
            al = SSL_AD_HANDSHAKE_FAILURE;
            goto f_err;
        }
        /*
         * If tls asked for a client cert, the client must return a 0 list
         */
        if ((s->version > SSL3_VERSION) && s->s3->tmp.cert_request) {
            SSLerr(SSL_F_SSL3_GET_CLIENT_CERTIFICATE,
                   SSL_R_TLS_PEER_DID_NOT_RESPOND_WITH_CERTIFICATE_LIST);
            al = SSL_AD_UNEXPECTED_MESSAGE;
            goto f_err;
        }
        s->s3->tmp.reuse_message = 1;
        return (1);
    }

    if (s->s3->tmp.message_type != SSL3_MT_CERTIFICATE) {
        al = SSL_AD_UNEXPECTED_MESSAGE;
        SSLerr(SSL_F_SSL3_GET_CLIENT_CERTIFICATE, SSL_R_WRONG_MESSAGE_TYPE);
        goto f_err;
    }
    p = d = (unsigned char *)s->init_msg;

    if ((sk = sk_X509_new_null()) == NULL) {
        SSLerr(SSL_F_SSL3_GET_CLIENT_CERTIFICATE, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    n2l3(p, llen);
    if (llen + 3 != n) {
        al = SSL_AD_DECODE_ERROR;
        SSLerr(SSL_F_SSL3_GET_CLIENT_CERTIFICATE, SSL_R_LENGTH_MISMATCH);
        goto f_err;
    }
    for (nc = 0; nc < llen;) {
        if (nc + 3 > llen) {
            al = SSL_AD_DECODE_ERROR;
            SSLerr(SSL_F_SSL3_GET_CLIENT_CERTIFICATE,
                   SSL_R_CERT_LENGTH_MISMATCH);
            goto f_err;
        }
        n2l3(p, l);
        if ((l + nc + 3) > llen) {
            al = SSL_AD_DECODE_ERROR;
            SSLerr(SSL_F_SSL3_GET_CLIENT_CERTIFICATE,
                   SSL_R_CERT_LENGTH_MISMATCH);
            goto f_err;
        }

        q = p;
        x = d2i_X509(NULL, &p, l);
        if (x == NULL) {
            SSLerr(SSL_F_SSL3_GET_CLIENT_CERTIFICATE, ERR_R_ASN1_LIB);
            goto err;
        }
        if (p != (q + l)) {
            al = SSL_AD_DECODE_ERROR;
            SSLerr(SSL_F_SSL3_GET_CLIENT_CERTIFICATE,
                   SSL_R_CERT_LENGTH_MISMATCH);
            goto f_err;
        }
        if (!sk_X509_push(sk, x)) {
            SSLerr(SSL_F_SSL3_GET_CLIENT_CERTIFICATE, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        x = NULL;
        nc += l + 3;
    }

    if (sk_X509_num(sk) <= 0) {
        /* TLS does not mind 0 certs returned */
        if (s->version == SSL3_VERSION) {
            al = SSL_AD_HANDSHAKE_FAILURE;
            SSLerr(SSL_F_SSL3_GET_CLIENT_CERTIFICATE,
                   SSL_R_NO_CERTIFICATES_RETURNED);
            goto f_err;
        }
        /* Fail for TLS only if we required a certificate */
        else if ((s->verify_mode & SSL_VERIFY_PEER) &&
                 (s->verify_mode & SSL_VERIFY_FAIL_IF_NO_PEER_CERT)) {
            SSLerr(SSL_F_SSL3_GET_CLIENT_CERTIFICATE,
                   SSL_R_PEER_DID_NOT_RETURN_A_CERTIFICATE);
            al = SSL_AD_HANDSHAKE_FAILURE;
            goto f_err;
        }
        /* No client certificate so digest cached records */
        if (s->s3->handshake_buffer && !ssl3_digest_cached_records(s)) {
            al = SSL_AD_INTERNAL_ERROR;
            goto f_err;
        }
    } else {
        i = ssl_verify_cert_chain(s, sk);
        if (i <= 0) {
            al = ssl_verify_alarm_type(s->verify_result);
            SSLerr(SSL_F_SSL3_GET_CLIENT_CERTIFICATE,
                   SSL_R_CERTIFICATE_VERIFY_FAILED);
            goto f_err;
        }
    }

    if (s->session->peer != NULL) /* This should not be needed */
        X509_free(s->session->peer);
    s->session->peer = sk_X509_shift(sk);
    s->session->verify_result = s->verify_result;

    /*
     * With the current implementation, sess_cert will always be NULL when we
     * arrive here.
     */
    if (s->session->sess_cert == NULL) {
        s->session->sess_cert = ssl_sess_cert_new();
        if (s->session->sess_cert == NULL) {
            SSLerr(SSL_F_SSL3_GET_CLIENT_CERTIFICATE, ERR_R_MALLOC_FAILURE);
            goto err;
        }
    }
    if (s->session->sess_cert->cert_chain != NULL)
        sk_X509_pop_free(s->session->sess_cert->cert_chain, X509_free);
    s->session->sess_cert->cert_chain = sk;
    /*
     * Inconsistency alert: cert_chain does *not* include the peer's own
     * certificate, while we do include it in s3_clnt.c
     */

    sk = NULL;

    ret = 1;
    if (0) {
 f_err:
        ssl3_send_alert(s, SSL3_AL_FATAL, al);
 err:
        s->state = SSL_ST_ERR;
    }

    if (x != NULL)
        X509_free(x);
    if (sk != NULL)
        sk_X509_pop_free(sk, X509_free);
    return (ret);
}

int ssl3_send_server_certificate(SSL *s)
{
    CERT_PKEY *cpk;

    if (s->state == SSL3_ST_SW_CERT_A) {
        cpk = ssl_get_server_send_pkey(s);
        if (cpk == NULL) {
            /* VRS: allow null cert if auth == KRB5 */
            if ((s->s3->tmp.new_cipher->algorithm_auth != SSL_aKRB5) ||
                (s->s3->tmp.new_cipher->algorithm_mkey & SSL_kKRB5)) {
                SSLerr(SSL_F_SSL3_SEND_SERVER_CERTIFICATE,
                       ERR_R_INTERNAL_ERROR);
                s->state = SSL_ST_ERR;
                return (0);
            }
        }

        if (!ssl3_output_cert_chain(s, cpk)) {
            SSLerr(SSL_F_SSL3_SEND_SERVER_CERTIFICATE, ERR_R_INTERNAL_ERROR);
            s->state = SSL_ST_ERR;
            return (0);
        }
        s->state = SSL3_ST_SW_CERT_B;
    }

    /* SSL3_ST_SW_CERT_B */
    return ssl_do_write(s);
}

#ifndef OPENSSL_NO_TLSEXT
/* send a new session ticket (not necessarily for a new session) */
int ssl3_send_newsession_ticket(SSL *s)
{
    unsigned char *senc = NULL;
    EVP_CIPHER_CTX ctx;
    HMAC_CTX hctx;

    if (s->state == SSL3_ST_SW_SESSION_TICKET_A) {
        unsigned char *p, *macstart;
        const unsigned char *const_p;
        int len, slen_full, slen;
        SSL_SESSION *sess;
        unsigned int hlen;
        SSL_CTX *tctx = s->initial_ctx;
        unsigned char iv[EVP_MAX_IV_LENGTH];
        unsigned char key_name[16];

        /* get session encoding length */
        slen_full = i2d_SSL_SESSION(s->session, NULL);
        /*
         * Some length values are 16 bits, so forget it if session is too
         * long
         */
        if (slen_full == 0 || slen_full > 0xFF00) {
            s->state = SSL_ST_ERR;
            return -1;
        }
        senc = OPENSSL_malloc(slen_full);
        if (!senc) {
            s->state = SSL_ST_ERR;
            return -1;
        }

        EVP_CIPHER_CTX_init(&ctx);
        HMAC_CTX_init(&hctx);

        p = senc;
        if (!i2d_SSL_SESSION(s->session, &p))
            goto err;

        /*
         * create a fresh copy (not shared with other threads) to clean up
         */
        const_p = senc;
        sess = d2i_SSL_SESSION(NULL, &const_p, slen_full);
        if (sess == NULL)
            goto err;
        sess->session_id_length = 0; /* ID is irrelevant for the ticket */

        slen = i2d_SSL_SESSION(sess, NULL);
        if (slen == 0 || slen > slen_full) { /* shouldn't ever happen */
            SSL_SESSION_free(sess);
            goto err;
        }
        p = senc;
        if (!i2d_SSL_SESSION(sess, &p)) {
            SSL_SESSION_free(sess);
            goto err;
        }
        SSL_SESSION_free(sess);

        /*-
         * Grow buffer if need be: the length calculation is as
         * follows handshake_header_length +
         * 4 (ticket lifetime hint) + 2 (ticket length) +
         * 16 (key name) + max_iv_len (iv length) +
         * session_length + max_enc_block_size (max encrypted session
         * length) + max_md_size (HMAC).
         */
        if (!BUF_MEM_grow(s->init_buf,
                          SSL_HM_HEADER_LENGTH(s) + 22 + EVP_MAX_IV_LENGTH +
                          EVP_MAX_BLOCK_LENGTH + EVP_MAX_MD_SIZE + slen))
            goto err;

        p = ssl_handshake_start(s);
        /*
         * Initialize HMAC and cipher contexts. If callback present it does
         * all the work otherwise use generated values from parent ctx.
         */
        if (tctx->tlsext_ticket_key_cb) {
            /* if 0 is returned, write en empty ticket */
            int ret = tctx->tlsext_ticket_key_cb(s, key_name, iv, &ctx,
                                                 &hctx, 1);

            if (ret == 0) {
                l2n(0, p); /* timeout */
                s2n(0, p); /* length */
                ssl_set_handshake_header(s, SSL3_MT_NEWSESSION_TICKET,
                                         p - ssl_handshake_start(s));
                s->state = SSL3_ST_SW_SESSION_TICKET_B;
                OPENSSL_free(senc);
                EVP_CIPHER_CTX_cleanup(&ctx);
                HMAC_CTX_cleanup(&hctx);
                return ssl_do_write(s);
            }
            if (ret < 0)
                goto err;
        } else {
            if (RAND_bytes(iv, 16) <= 0)
                goto err;
            if (!EVP_EncryptInit_ex(&ctx, EVP_aes_128_cbc(), NULL,
                                    tctx->tlsext_tick_aes_key, iv))
                goto err;
            if (!HMAC_Init_ex(&hctx, tctx->tlsext_tick_hmac_key, 16,
                              tlsext_tick_md(), NULL))
                goto err;
            memcpy(key_name, tctx->tlsext_tick_key_name, 16);
        }

        /*
         * Ticket lifetime hint (advisory only): We leave this unspecified
         * for resumed session (for simplicity), and guess that tickets for
         * new sessions will live as long as their sessions.
         */
        l2n(s->hit ? 0 : s->session->timeout, p);

        /* Skip ticket length for now */
        p += 2;
        /* Output key name */
        macstart = p;
        memcpy(p, key_name, 16);
        p += 16;
        /* output IV */
        memcpy(p, iv, EVP_CIPHER_CTX_iv_length(&ctx));
        p += EVP_CIPHER_CTX_iv_length(&ctx);
        /* Encrypt session data */
        if (!EVP_EncryptUpdate(&ctx, p, &len, senc, slen))
            goto err;
        p += len;
        if (!EVP_EncryptFinal(&ctx, p, &len))
            goto err;
        p += len;

        if (!HMAC_Update(&hctx, macstart, p - macstart))
            goto err;
        if (!HMAC_Final(&hctx, p, &hlen))
            goto err;

        EVP_CIPHER_CTX_cleanup(&ctx);
        HMAC_CTX_cleanup(&hctx);

        p += hlen;
        /* Now write out lengths: p points to end of data written */
        /* Total length */
        len = p - ssl_handshake_start(s);
        /* Skip ticket lifetime hint */
        p = ssl_handshake_start(s) + 4;
        s2n(len - 6, p);
        ssl_set_handshake_header(s, SSL3_MT_NEWSESSION_TICKET, len);
        s->state = SSL3_ST_SW_SESSION_TICKET_B;
        OPENSSL_free(senc);
    }

    /* SSL3_ST_SW_SESSION_TICKET_B */
    return ssl_do_write(s);
 err:
    if (senc)
        OPENSSL_free(senc);
    EVP_CIPHER_CTX_cleanup(&ctx);
    HMAC_CTX_cleanup(&hctx);
    s->state = SSL_ST_ERR;
    return -1;
}

int ssl3_send_cert_status(SSL *s)
{
    if (s->state == SSL3_ST_SW_CERT_STATUS_A) {
        unsigned char *p;
        size_t msglen;

        /*-
         * Grow buffer if need be: the length calculation is as
         * follows handshake_header_length +
         * 1 (ocsp response type) + 3 (ocsp response length)
         * + (ocsp response)
         */
        msglen = 4 + s->tlsext_ocsp_resplen;
        if (!BUF_MEM_grow(s->init_buf, SSL_HM_HEADER_LENGTH(s) + msglen)) {
            s->state = SSL_ST_ERR;
            return -1;
        }

        p = ssl_handshake_start(s);

        /* status type */
        *(p++) = s->tlsext_status_type;
        /* length of OCSP response */
        l2n3(s->tlsext_ocsp_resplen, p);
        /* actual response */
        memcpy(p, s->tlsext_ocsp_resp, s->tlsext_ocsp_resplen);

        ssl_set_handshake_header(s, SSL3_MT_CERTIFICATE_STATUS, msglen);
    }

    /* SSL3_ST_SW_CERT_STATUS_B */
    return (ssl_do_write(s));
}

# ifndef OPENSSL_NO_NEXTPROTONEG
/*
 * ssl3_get_next_proto reads a Next Protocol Negotiation handshake message.
 * It sets the next_proto member in s if found
 */
int ssl3_get_next_proto(SSL *s)
{
    int ok;
    int proto_len, padding_len;
    long n;
    const unsigned char *p;

    /*
     * Clients cannot send a NextProtocol message if we didn't see the
     * extension in their ClientHello
     */
    if (!s->s3->next_proto_neg_seen) {
        SSLerr(SSL_F_SSL3_GET_NEXT_PROTO,
               SSL_R_GOT_NEXT_PROTO_WITHOUT_EXTENSION);
        s->state = SSL_ST_ERR;
        return -1;
    }

    /* See the payload format below */
    n = s->method->ssl_get_message(s,
                                   SSL3_ST_SR_NEXT_PROTO_A,
                                   SSL3_ST_SR_NEXT_PROTO_B,
                                   SSL3_MT_NEXT_PROTO, 514, &ok);

    if (!ok)
        return ((int)n);

    /*
     * s->state doesn't reflect whether ChangeCipherSpec has been received in
     * this handshake, but s->s3->change_cipher_spec does (will be reset by
     * ssl3_get_finished).
     */
    if (!s->s3->change_cipher_spec) {
        SSLerr(SSL_F_SSL3_GET_NEXT_PROTO, SSL_R_GOT_NEXT_PROTO_BEFORE_A_CCS);
        s->state = SSL_ST_ERR;
        return -1;
    }

    if (n < 2) {
        s->state = SSL_ST_ERR;
        return 0;               /* The body must be > 1 bytes long */
    }

    p = (unsigned char *)s->init_msg;

    /*-
     * The payload looks like:
     *   uint8 proto_len;
     *   uint8 proto[proto_len];
     *   uint8 padding_len;
     *   uint8 padding[padding_len];
     */
    proto_len = p[0];
    if (proto_len + 2 > s->init_num) {
        s->state = SSL_ST_ERR;
        return 0;
    }
    padding_len = p[proto_len + 1];
    if (proto_len + padding_len + 2 != s->init_num) {
        s->state = SSL_ST_ERR;
        return 0;
    }

    s->next_proto_negotiated = OPENSSL_malloc(proto_len);
    if (!s->next_proto_negotiated) {
        SSLerr(SSL_F_SSL3_GET_NEXT_PROTO, ERR_R_MALLOC_FAILURE);
        s->state = SSL_ST_ERR;
        return 0;
    }
    memcpy(s->next_proto_negotiated, p + 1, proto_len);
    s->next_proto_negotiated_len = proto_len;

    return 1;
}
# endif

#endif
